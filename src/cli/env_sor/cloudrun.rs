//! The Cloud Run half of the SoR phase (SoRLa phase 3E): resolving what to
//! deploy and refusing what cannot work on Cloud Run, bringing every declared
//! unit up before the workers ([`up`]), and retiring what the manifest no
//! longer declares after them ([`finish`]).
//!
//! Every entry point here is called only by the CLI's live Cloud Run glue
//! (`deploy-gcp-cloudrun`), so a `creds-gcp`-only build allows them dead (P7).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::Arc;

use async_trait::async_trait;
use greentic_deploy_spec::{CapabilitySlot, EnvId, Environment};
use serde_json::{Value, json};

use super::prepare::{PreparedSor, SorLanePlacement, prepare_inner, record_applied};
use super::publish::StoreRoutePublisher;
use crate::cli::OpError;
use crate::cli::secrets::DEV_SECRETS_PATH_ENV;
use crate::env_packs::gcp_cloudrun::deploy_target::CloudRunTarget;
use crate::env_packs::gcp_cloudrun::deployer::GcpCloudRunParams;
use crate::env_packs::gcp_cloudrun::sor::retire::{SorRetireOutcome, retire};
use crate::env_packs::gcp_cloudrun::sor::spec::SorReadyTiming;
use crate::env_packs::gcp_cloudrun::sor::target::SorServiceTarget;
use crate::env_packs::gcp_cloudrun::sor::up::{
    PlacedSorUnit, SorUpContext, SorUpOutcome, bring_up,
};
use crate::env_packs::k8s::manifests::SecretsBackend;
use crate::env_packs::k8s::manifests::sor::SOR_PORT;
use crate::env_packs::k8s::sor_reconcile::{SorRoutePublisher as _, SorUnitRender};
use crate::environment::LocalFsStore;
use crate::environment::sor_units::CloudRunSorPlacement;

/// The only auth mode a publicly reachable SoR may run with (E5).
const REQUIRED_AUTH_MODE: &str = "shared_secret";

/// Resolve the Cloud Run SoR phase. `None` when nothing is declared and
/// nothing was ever deployed, so an environment without SoR units runs
/// exactly as before.
///
/// Called by [`up`]; no non-test caller in a `creds-gcp`-only build (P7).
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) fn prepare_cloud_run(
    store: &LocalFsStore,
    env: &Environment,
    project: &str,
    region: &str,
    secret_prefix: &str,
    backend: &SecretsBackend,
) -> Result<Option<PreparedSor>, OpError> {
    prepare_cloud_run_with_override(
        store,
        env,
        project,
        region,
        secret_prefix,
        backend,
        std::env::var_os(DEV_SECRETS_PATH_ENV),
    )
}

pub(super) fn prepare_cloud_run_with_override(
    store: &LocalFsStore,
    env: &Environment,
    project: &str,
    region: &str,
    secret_prefix: &str,
    backend: &SecretsBackend,
    dev_secrets_path_override: Option<OsString>,
) -> Result<Option<PreparedSor>, OpError> {
    // Before any input is read: without a secrets pack the dev store is not
    // staged into worker seeds, so no worker could ever find a route document.
    if !store.load_sor_units(&env.environment_id)?.is_empty() {
        require_secrets_binding(env)?;
    }
    let placement = || {
        Ok(SorLanePlacement::CloudRun {
            project: project.to_string(),
            region: region.to_string(),
            secret_prefix: secret_prefix.to_string(),
        })
    };
    prepare_inner(
        store,
        env,
        &placement,
        backend,
        dev_secrets_path_override,
        &|renders| renders.iter().try_for_each(check_cloud_run_answers),
    )
}

/// On Cloud Run a worker reaches its SoR only through the route document in
/// its seed, and `op env up` stages the dev store as a seed only when the env
/// binds a `Secrets`-slot pack (`env::cloudrun_stages_dev_secrets`).
fn require_secrets_binding(env: &Environment) -> Result<(), OpError> {
    if env.pack_for_slot(CapabilitySlot::Secrets).is_some() {
        return Ok(());
    }
    Err(OpError::Conflict(format!(
        "environment `{}` declares SoR units but binds no secrets pack; on Cloud Run a worker \
         finds its SoR only through the staged dev-store seed — bind \
         `greentic.secrets.dev-store` in the manifest's `packs`",
        env.environment_id.as_str()
    )))
}

/// Cloud Run routes to and probes only the container port, and the service is
/// reachable from the internet (E5). Names the field and the expected value;
/// neither a bind address nor an auth mode is a secret.
fn check_cloud_run_answers(render: &SorUnitRender) -> Result<(), OpError> {
    let unit_id = &render.unit.unit_id;
    // `resolve_sor_inputs` already refused answers that are not a JSON object.
    let parsed: Value = serde_json::from_str(render.inputs.answers.expose()).unwrap_or(Value::Null);
    let root = parsed
        .get("answers")
        .filter(|a| a.is_object())
        .unwrap_or(&parsed);

    let bind = root.pointer("/server/bind").and_then(Value::as_str);
    let bind_ok = bind
        .and_then(|b| b.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|a| a.port() == SOR_PORT && a.ip().is_unspecified());
    if !bind_ok {
        return Err(OpError::Conflict(format!(
            "SoR unit `{unit_id}`: on Cloud Run its answers must set `server.bind` to \
             `0.0.0.0:{SOR_PORT}`, the only port Cloud Run routes to and probes (found {})",
            bind.map_or_else(|| "no bind".to_string(), |b| format!("`{b}`"))
        )));
    }

    let mode = root.pointer("/server/auth/mode").and_then(Value::as_str);
    if mode != Some(REQUIRED_AUTH_MODE) {
        return Err(OpError::Conflict(format!(
            "SoR unit `{unit_id}`: on Cloud Run its service is reachable from the internet, so \
             its answers must set `server.auth.mode` to `{REQUIRED_AUTH_MODE}` (found {})",
            mode.map_or_else(|| "none".to_string(), |m| format!("`{m}`"))
        )));
    }
    Ok(())
}

/// The two seams for one `(project, region)`.
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) type SorTargetPair = (Arc<dyn CloudRunTarget>, Arc<dyn SorServiceTarget>);

/// Hands out the seams for a place. The real resolver builds regional clients;
/// the tests hand out fakes. A retired unit may live in another project or
/// region than the one the answers name now, so targets are asked per place.
#[async_trait]
pub(crate) trait SorTargets: Send + Sync {
    async fn at(&self, project: &str, region: &str) -> Result<SorTargetPair, OpError>;
}

/// What the SoR phase did before the workers, kept for [`finish`].
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) struct CloudRunSorRun {
    pub(crate) prepared: PreparedSor,
    pub(crate) up: SorUpOutcome,
}

/// Before the workers: resolve (refusing what cannot work), bring every
/// declared unit up, then write its route document and delete retired route
/// documents and stale inputs. `None` = no SoR phase at all, and no target is
/// asked for.
///
/// A unit that never becomes ready fails the run before any route document is
/// written; the ledger stays widened, so the next run can still retire it.
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) async fn up(
    store: &LocalFsStore,
    env: &Environment,
    params: &GcpCloudRunParams,
    backend: &SecretsBackend,
    targets: &dyn SorTargets,
    timing: SorReadyTiming,
) -> Result<Option<CloudRunSorRun>, OpError> {
    let Some(prepared) = prepare_cloud_run(
        store,
        env,
        &params.project,
        &params.region,
        &params.secret_prefix,
        backend,
    )?
    else {
        return Ok(None);
    };
    let placed: Vec<PlacedSorUnit<'_>> = prepared
        .placed_units()
        .filter_map(|(render, entry)| {
            entry
                .cloud_run
                .as_ref()
                .map(|placement| PlacedSorUnit { render, placement })
        })
        .collect();
    let outcome = if placed.is_empty() {
        SorUpOutcome::default()
    } else {
        let (secrets, services) = targets.at(&params.project, &params.region).await?;
        let env_id = env.environment_id.as_str();
        let runtime_service_account = params.runtime_service_account(env_id);
        let ctx = SorUpContext {
            env_id,
            runtime_service_account: &runtime_service_account,
            timing,
        };
        bring_up(secrets.as_ref(), services.as_ref(), &ctx, &placed)
            .await
            .map_err(|e| OpError::Conflict(e.to_string()))?
    };
    StoreRoutePublisher::new(store, env)
        .publish(
            &outcome.routes,
            &prepared.retired_sors,
            &prepared.stale_input_refs,
        )
        .map_err(OpError::Conflict)?;
    Ok(Some(CloudRunSorRun {
        prepared,
        up: outcome,
    }))
}

/// After the workers and their traffic: retire what the manifest no longer
/// declares, then narrow the ledger. A failure keeps the WHOLE widened ledger,
/// so the next `op env up` retries every retirement (an already-deleted one is
/// a no-op).
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) async fn finish(
    store: &LocalFsStore,
    env_id: &EnvId,
    run: &CloudRunSorRun,
    targets: &dyn SorTargets,
) -> Result<Vec<String>, OpError> {
    let retired: Vec<CloudRunSorPlacement> = run
        .prepared
        .retired_units
        .iter()
        .filter_map(|a| a.cloud_run.clone())
        .collect();
    let keep: Vec<CloudRunSorPlacement> = run
        .prepared
        .placed_units()
        .filter_map(|(_, a)| a.cloud_run.clone())
        .collect();
    let out = retire_all(env_id.as_str(), &retired, &keep, targets).await?;
    record_applied(store, env_id, &run.prepared)?;
    Ok(out.notes)
}

/// Retire `retired`, grouped by `(project, region)`: each group goes through a
/// target built for THAT place, never the place the answers name now — a
/// same-named secret in the new project is another secret. Never touches what
/// `keep` still uses. Also used by `op env destroy` with an empty `keep`.
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) async fn retire_all(
    env_id: &str,
    retired: &[CloudRunSorPlacement],
    keep: &[CloudRunSorPlacement],
    targets: &dyn SorTargets,
) -> Result<SorRetireOutcome, OpError> {
    let mut groups: BTreeMap<(String, String), Vec<CloudRunSorPlacement>> = BTreeMap::new();
    for place in retired {
        groups
            .entry((place.project.clone(), place.region.clone()))
            .or_default()
            .push(place.clone());
    }
    let mut all = SorRetireOutcome::default();
    for ((project, region), places) in groups {
        let (secrets, services) = targets.at(&project, &region).await?;
        let out = retire(secrets.as_ref(), services.as_ref(), env_id, &places, keep)
            .await
            .map_err(|e| OpError::Conflict(e.to_string()))?;
        all.deleted_services.extend(out.deleted_services);
        all.deleted_secrets.extend(out.deleted_secrets);
        all.notes.extend(out.notes);
    }
    Ok(all)
}

/// Adds `sor_units`, `sor_notes` and `sor_skipped_input_refs` to the `op env
/// up` result, each only when non-empty — an env without SoR units prints what
/// it printed before. Never a value: statuses carry names and URLs only.
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) fn add_to_result(result: &mut Value, run: &CloudRunSorRun, finish_notes: Vec<String>) {
    if !run.up.statuses.is_empty() {
        result["sor_units"] = json!(run.up.statuses);
    }
    let notes: Vec<String> = run.up.notes.iter().cloned().chain(finish_notes).collect();
    if !notes.is_empty() {
        result["sor_notes"] = json!(notes);
    }
    if !run.prepared.skipped_input_refs.is_empty() {
        result["sor_skipped_input_refs"] = json!(run.prepared.skipped_input_refs);
    }
}

#[cfg(test)]
#[path = "cloudrun_prepare_tests.rs"]
mod prepare_tests;

#[cfg(test)]
#[path = "cloudrun_tests.rs"]
mod tests;
