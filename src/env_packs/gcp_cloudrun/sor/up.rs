//! Bringing SoR units up on Cloud Run. Order, and why: every unit is staged
//! and deployed first (their cold starts overlap), then each is waited on; a
//! unit is opened to `allUsers` only once ready, and its route document is
//! produced only from the URL of a ready service. The caller writes the route
//! documents and only then warms workers.

use std::time::{Duration, Instant};

use super::spec::{
    AR_READER_ROLE, SorReadyTiming, SorServiceInputs, StagedVersions, ar_reader_remediation,
    ar_repository, cloud_run_route_document, sor_intent, sor_service_ref, sor_service_spec,
};
use super::target::{SorServiceRef, SorServiceSpec, SorServiceStatus, SorServiceTarget};
use crate::env_packs::deployer::DeployerError;
use crate::env_packs::gcp_cloudrun::deploy_target::{
    CloudRunTarget, CloudRunTargetError, EnsuredSecret,
};
use crate::env_packs::gcp_cloudrun::deployer::{
    SecretOwnership, classify_owner, env_owner_stamp, provider, secret_conflict,
};
use crate::env_packs::k8s::sor_reconcile::{RouteDocument, SorUnitRender, SorUnitStatus};
use crate::environment::sor_units::{CloudRunSorPlacement, SorUnit};

const MAX_ETAG_RETRIES: u32 = 5;

pub struct PlacedSorUnit<'a> {
    pub render: &'a SorUnitRender,
    pub placement: &'a CloudRunSorPlacement,
}

pub struct SorUpContext<'a> {
    pub env_id: &'a str,
    pub runtime_service_account: &'a str,
    pub timing: SorReadyTiming,
}

#[derive(Debug, Default)]
pub struct SorUpOutcome {
    pub statuses: Vec<SorUnitStatus>,
    /// Carry the shared secret; written only to the dev store by the caller.
    pub routes: Vec<RouteDocument>,
    pub notes: Vec<String>,
}

pub async fn bring_up(
    secrets: &dyn CloudRunTarget,
    services: &dyn SorServiceTarget,
    ctx: &SorUpContext<'_>,
    units: &[PlacedSorUnit<'_>],
) -> Result<SorUpOutcome, DeployerError> {
    let owner = env_owner_stamp(ctx.env_id);
    let mut outcome = SorUpOutcome::default();
    for unit in units {
        converge(secrets, services, ctx, &owner, unit, &mut outcome.notes).await?;
    }
    for unit in units {
        let service = sor_service_ref(unit.placement);
        let status = wait_ready(services, &service, ctx).await?;
        services
            .set_sor_invoker_public(&service)
            .await
            .map_err(provider)?;
        let url = status
            .url
            .as_deref()
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                DeployerError::Provider(format!(
                    "Cloud Run reports SoR service `{}` ready but gives it no URL",
                    service.name
                ))
            })?;
        let sor_unit = &unit.render.unit;
        outcome.routes.push(RouteDocument {
            sor: sor_unit.sor.clone(),
            value: cloud_run_route_document(sor_unit, &unit.render.inputs, &url),
        });
        outcome.statuses.push(SorUnitStatus {
            unit_id: sor_unit.unit_id.clone(),
            sor: sor_unit.sor.clone(),
            service: service.name.clone(),
            url,
            ready: true,
        });
    }
    Ok(outcome)
}

/// Deploy one unit unless the live service already runs exactly this intent.
/// A live service whose latest revision FAILED is redeployed, never trusted.
async fn converge(
    secrets: &dyn CloudRunTarget,
    services: &dyn SorServiceTarget,
    ctx: &SorUpContext<'_>,
    owner: &str,
    unit: &PlacedSorUnit<'_>,
    notes: &mut Vec<String>,
) -> Result<(), DeployerError> {
    let sor_unit = &unit.render.unit;
    let service = sor_service_ref(unit.placement);
    let intent = sor_intent(
        sor_unit,
        &unit.render.inputs,
        ctx.runtime_service_account,
        unit.placement,
    );
    if let Some(live) = services.get_sor_service(&service).await.map_err(provider)? {
        if live.owner.as_deref() != Some(owner) {
            return Err(service_conflict(
                &service.name,
                live.owner.as_deref(),
                owner,
            ));
        }
        if live.intent.as_deref() == Some(intent.as_str()) && !live.failed() {
            return Ok(());
        }
    }
    let staged = stage_inputs(secrets, ctx, owner, unit).await?;
    grant_pack_read(services, ctx, sor_unit, notes).await;
    let spec = sor_service_spec(&SorServiceInputs {
        unit: sor_unit,
        placement: unit.placement,
        runtime_service_account: ctx.runtime_service_account,
        owner,
        intent: &intent,
        staged: &staged,
    });
    upsert(services, &spec).await
}

/// Claim the unit's secret (one create-or-report operation, as for the seed),
/// add one version per input, and let the runtime identity read them.
async fn stage_inputs(
    secrets: &dyn CloudRunTarget,
    ctx: &SorUpContext<'_>,
    owner: &str,
    unit: &PlacedSorUnit<'_>,
) -> Result<StagedVersions, DeployerError> {
    let name = unit.placement.secret.as_str();
    if let EnsuredSecret::Existed { owner: live } =
        secrets.ensure_secret(name, owner).await.map_err(provider)?
    {
        match classify_owner(live, ctx.env_id) {
            SecretOwnership::Ours | SecretOwnership::Absent => {}
            SecretOwnership::Conflict { owner } => {
                return Err(secret_conflict(name, &owner, ctx.env_id));
            }
            // A SoR secret has no pre-stamping era to adopt: an unstamped one
            // was not created by this deployer.
            SecretOwnership::Legacy => {
                return Err(DeployerError::Provider(format!(
                    "Secret Manager secret `{name}` exists without an owner stamp, so this \
                     deployer did not create it; refusing to write a SoR unit's database \
                     credential into it. Delete it or change the `secret_prefix` answer."
                )));
            }
        }
    }
    let inputs = &unit.render.inputs;
    let answers = add_version(secrets, name, inputs.answers.expose()).await?;
    let postgres_url = add_version(secrets, name, inputs.postgres_url.expose()).await?;
    let shared_secret = add_version(secrets, name, inputs.shared_secret.expose()).await?;
    let postgres_ca = match &inputs.postgres_ca {
        Some(ca) => Some(add_version(secrets, name, ca.expose()).await?),
        None => None,
    };
    // Load-bearing: Cloud Run rejects a revision whose identity cannot read a
    // referenced secret version.
    secrets
        .grant_secret_accessor(name, ctx.runtime_service_account)
        .await
        .map_err(provider)?;
    Ok(StagedVersions {
        answers,
        postgres_url,
        shared_secret,
        postgres_ca,
    })
}

async fn add_version(
    secrets: &dyn CloudRunTarget,
    name: &str,
    value: &str,
) -> Result<String, DeployerError> {
    Ok(secrets
        .add_secret_version(name, value.as_bytes())
        .await
        .map_err(provider)?
        .version)
}

/// Best effort (spec §4): a refusal is a note carrying the command, never a
/// failed deploy — the grant may already exist, or the pack may be public.
async fn grant_pack_read(
    services: &dyn SorServiceTarget,
    ctx: &SorUpContext<'_>,
    unit: &SorUnit,
    notes: &mut Vec<String>,
) {
    let Some(repo) = ar_repository(&unit.pack_ref) else {
        return;
    };
    if let Err(e) = services
        .grant_artifact_registry_reader(&repo, ctx.runtime_service_account)
        .await
    {
        notes.push(format!(
            "SoR unit `{}`: could not grant `{}` read on Artifact Registry repository `{}` \
             ({e}). If the SoR service cannot pull its pack, run: {}",
            unit.unit_id,
            ctx.runtime_service_account,
            repo.repository,
            ar_reader_remediation(&repo, ctx.runtime_service_account),
        ));
    }
}

async fn upsert(
    services: &dyn SorServiceTarget,
    spec: &SorServiceSpec,
) -> Result<(), DeployerError> {
    let mut attempt = 0;
    loop {
        let etag = services
            .get_sor_service(&spec.service)
            .await
            .map_err(provider)?
            .map(|s| s.etag);
        match services.upsert_sor_service(spec, etag.as_deref()).await {
            Ok(_) => return Ok(()),
            Err(CloudRunTargetError::PreconditionFailed) if attempt < MAX_ETAG_RETRIES => {
                attempt += 1;
            }
            Err(CloudRunTargetError::PreconditionFailed) => {
                return Err(DeployerError::Provider(format!(
                    "Cloud Run SoR service `{}` kept losing the etag race after \
                     {MAX_ETAG_RETRIES} retries",
                    spec.service.name
                )));
            }
            Err(e) => return Err(provider(e)),
        }
    }
}

async fn wait_ready(
    services: &dyn SorServiceTarget,
    service: &SorServiceRef,
    ctx: &SorUpContext<'_>,
) -> Result<SorServiceStatus, DeployerError> {
    let deadline = Instant::now() + ctx.timing.timeout;
    loop {
        let status = services
            .get_sor_service(service)
            .await
            .map_err(provider)?
            .ok_or_else(|| {
                DeployerError::Provider(format!(
                    "Cloud Run SoR service `{}` disappeared while waiting for it to become ready",
                    service.name
                ))
            })?;
        if status.ready {
            return Ok(status);
        }
        if status.failed() {
            return Err(not_ready(service, &status, ctx, None));
        }
        if Instant::now() >= deadline {
            return Err(not_ready(service, &status, ctx, Some(ctx.timing.timeout)));
        }
        tokio::time::sleep(ctx.timing.poll).await;
    }
}

/// Carries Cloud Run's own reason and log link; names the commonest cause.
fn not_ready(
    service: &SorServiceRef,
    status: &SorServiceStatus,
    ctx: &SorUpContext<'_>,
    timed_out: Option<Duration>,
) -> DeployerError {
    let mut message = match timed_out {
        Some(t) => format!(
            "Cloud Run SoR service `{}` did not become ready within {}s",
            service.name,
            t.as_secs()
        ),
        None => format!(
            "Cloud Run SoR service `{}` failed to become ready",
            service.name
        ),
    };
    if let Some(reason) = &status.not_ready_reason {
        message.push_str(&format!(". Cloud Run reports: {reason}"));
    }
    if let Some(uri) = &status.log_uri {
        message.push_str(&format!(". Revision logs: {uri}"));
    }
    message.push_str(&format!(
        ". No worker was deployed. A pack sorx cannot pull usually means `{}` lacks \
         `{AR_READER_ROLE}` on the pack's repository",
        ctx.runtime_service_account
    ));
    DeployerError::Provider(message)
}

/// Who holds a live SoR service, in the words both the refusal here and the
/// retirement note use — one phrasing, so the two cannot drift apart.
pub(super) fn service_holder(live_owner: Option<&str>) -> String {
    match live_owner {
        Some(o) => format!("belongs to environment `{o}`"),
        None => "carries no owner stamp".to_string(),
    }
}

fn service_conflict(name: &str, live_owner: Option<&str>, ours: &str) -> DeployerError {
    let held = service_holder(live_owner);
    DeployerError::Provider(format!(
        "Cloud Run service `{name}` already exists and {held}; this is environment `{ours}`. A \
         SoR unit's service is `gtc-sor-<unit_id>` per project and region, so two environments \
         cannot deploy the same unit_id there — rename the unit or use another project or region"
    ))
}

#[cfg(test)]
#[path = "up_tests.rs"]
mod tests;
