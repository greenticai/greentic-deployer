//! [`Deployer`] impl for the Azure Container Apps env-pack.
//!
//! | Verb | Provider side-effect |
//! |---|---|
//! | `stage_revision` | None. |
//! | `warm_revision` | See [`deployer_warm`](super::deployer_warm): claim check, content-addressed secrets, one PUT with an explicit traffic list (new revision at 0 % unless first), wait for `Running`. |
//! | `drain_revision` | None; routing-side. |
//! | `archive_revision` | Deactivate the revision; delete the whole app when its bundle is retiring. |
//! | `apply_traffic_split` | Rewrite `ingress.traffic` only; weights are whole percents; every named revision must be `Running`. |

use async_trait::async_trait;
use greentic_deploy_spec::{BundleDeploymentStatus, DeploymentId, Environment, Revision, RevisionId};
use serde_json::Value;

use super::AzureAcaDeployerHandler;
use super::arm_types::TrafficEntry;
use super::deploy_target::{AppRef, RevisionRef, RevisionStatus};
use super::deployer_warm::{provider, warm_timeout};
use super::naming::{app_name, revision_name, revision_suffix};
use super::params::AcaParams;
use crate::env_packs::deployer::{
    AdapterCapabilities, ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome,
    TrafficSplitOutcome, WarmOutcome, enforce_split_invariants, require_revision,
};

const WARM_POLL: std::time::Duration = std::time::Duration::from_secs(5);
/// Whole-percent traffic weights: a split must be a multiple of this many bps.
pub(crate) const WEIGHT_GRANULARITY_BPS: u32 = 100;

fn params_from(answers: Option<&Value>) -> Result<AcaParams, DeployerError> {
    AcaParams::from_answers(answers)
        .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))
}

fn revision_of(env: &Environment, id: RevisionId) -> Result<&Revision, DeployerError> {
    env.revisions
        .iter()
        .find(|r| r.revision_id == id)
        .ok_or_else(|| DeployerError::RevisionNotFound {
            env_id: env.environment_id.clone(),
            revision_id: id,
        })
}

fn whole_bundle_retiring(env: &Environment, revision: &Revision) -> bool {
    env.bundles.iter().any(|b| {
        b.deployment_id == revision.deployment_id && b.status == BundleDeploymentStatus::Archived
    })
}

/// Percent weight for a bps weight; refuses a split Container Apps cannot express.
pub(crate) fn percent(weight_bps: u32) -> Result<u32, DeployerError> {
    if weight_bps % WEIGHT_GRANULARITY_BPS != 0 {
        return Err(DeployerError::Provider(format!(
            "traffic weight {weight_bps} bps is not expressible: Container Apps weights are whole \
             percents (multiples of {WEIGHT_GRANULARITY_BPS} bps)"
        )));
    }
    Ok(weight_bps / WEIGHT_GRANULARITY_BPS)
}

#[async_trait]
impl Deployer for AzureAcaDeployerHandler {
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            drain: false,
            traffic_split: true,
            ingress_managed: true,
            private_registry_auth: true,
            multi_instance_safe: false,
            remove: true,
            runtime_pin: true,
        }
    }

    fn capability_notes(&self) -> &'static [&'static str] {
        &[
            "scale: scale to zero by default (min_instances 0, no usage charge); min_instances 1 \
             keeps one replica warm; max_instances is fixed at 1 (single writer of the seed)",
            "ingress_managed: public HTTPS on the platform *.azurecontainerapps.io domain; no \
             custom domain or certificate handling",
            "traffic_split: native weights on one Container App; whole percents only (multiples of \
             100 bps)",
            "private_registry_auth: `oci_username` / `oci_password` answers (an ACR \
             repository-scoped token); the password is an ACA secret injected as OCI_PASSWORD",
            "drain: not implemented -- a retire that needs a drain window is refused",
            "runtime_pin: each revision runs the runtime image its manifest pinned",
            "not verified against Azure: see docs/azure-aca-seed-and-bundle-delivery.md",
        ]
    }

    async fn stage_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<StageOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        Ok(StageOutcome::default())
    }

    async fn warm_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<WarmOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let params = params_from(answers)?;
        self.warm(env, revision_id, &params, warm_timeout(), WARM_POLL).await
    }

    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        _answers: Option<&Value>,
    ) -> Result<DrainOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        Ok(DrainOutcome::default())
    }

    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ArchiveOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = revision_of(env, revision_id)?;
        let _ = params_from(answers)?;
        let name = app_name(&revision.deployment_id);
        let app = AppRef { name: name.as_str().to_string() };
        if whole_bundle_retiring(env, revision) {
            // Deleting the app removes every revision and secret in one call, so
            // no per-revision deactivation runs (it would fail after the first).
            self.target.delete_app(&app).await.map_err(provider)?;
        } else {
            let rev = RevisionRef {
                app,
                name: revision_name(&name, &revision_suffix(&revision_id)),
            };
            self.target.deactivate_revision(&rev).await.map_err(provider)?;
        }
        Ok(ArchiveOutcome::default())
    }

    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
        answers: Option<&Value>,
    ) -> Result<TrafficSplitOutcome, DeployerError> {
        let outcome = enforce_split_invariants(env, deployment_id)?;
        let _ = params_from(answers)?;
        let name = app_name(&deployment_id);
        let app = AppRef { name: name.as_str().to_string() };
        let mut weights = Vec::with_capacity(outcome.applied_entries.len());
        for entry in &outcome.applied_entries {
            let weight = percent(entry.weight_bps)?;
            let rev_name = revision_name(&name, &revision_suffix(&entry.revision_id));
            let rev = RevisionRef { app: app.clone(), name: rev_name.clone() };
            match self.target.revision_status(&rev).await.map_err(provider)? {
                RevisionStatus::Running { .. } => {}
                other => {
                    return Err(DeployerError::Provider(format!(
                        "cannot route traffic to Container Apps revision `{rev_name}`: it is {other:?}"
                    )));
                }
            }
            weights.push(TrafficEntry { revision_name: rev_name, weight });
        }
        self.target.set_traffic(&app, &weights).await.map_err(provider)?;
        Ok(outcome)
    }
}

#[cfg(test)]
#[path = "deployer_tests.rs"]
mod tests;
