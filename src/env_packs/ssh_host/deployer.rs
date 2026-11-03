//! [`Deployer`] impl for the ssh-host env-pack.
//!
//! One VM runs ONE greentic-start instance serving the whole env store, so there
//! is no per-revision process and no traffic split: `warm_revision` synchronizes
//! the store and (re)starts the service, `drain_revision` stops it only when the
//! env routes no traffic at all, `archive_revision` and `apply_traffic_split`
//! touch nothing on the VM. See [`super::steps`] for the warm procedure and its
//! idempotency / atomicity properties.

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, RevisionId};
use serde_json::Value;

use super::params::SshHostParams;
use super::steps::{self, Session, WarmInput};
use super::{SshHostDeployerHandler, WarmReport};
use crate::env_packs::deployer::{
    AdapterCapabilities, ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome,
    TrafficSplitOutcome, WarmOutcome, enforce_split_invariants, require_revision,
};

impl SshHostDeployerHandler {
    /// The binding's answers win; otherwise the injected fallback; otherwise a
    /// clear error (an SSH target cannot be defaulted).
    fn params_for(
        &self,
        env: &Environment,
        answers: Option<&Value>,
    ) -> Result<SshHostParams, DeployerError> {
        match (answers, &self.fallback_params) {
            (Some(answers), _) => SshHostParams::from_answers(env, answers)
                .map_err(|e| DeployerError::Provider(e.to_string())),
            (None, Some(params)) => Ok(params.clone()),
            (None, None) => Err(DeployerError::Provider(
                "ssh-host: answers are required (at least `host` and `user`); the binding \
                 recorded none"
                    .to_string(),
            )),
        }
    }
}

impl SshHostDeployerHandler {
    /// Warm the VM for `revision_ids` (at least one) and report what happened.
    ///
    /// The VM runs ONE service that serves the whole env store, so every
    /// revision the env serves belongs in one synchronization (the shipped
    /// `environment.json` keeps exactly those, plus what a traffic split
    /// names). `Deployer::warm_revision` is the one-revision case of this.
    /// `Deployer::warm_revision` is this with a single id.
    ///
    /// With `read_slot` the report also names the live store slot, at the cost
    /// of one extra `readlink` after the warm.
    pub async fn warm_with_report(
        &self,
        env: &Environment,
        revision_ids: &[RevisionId],
        answers: Option<&Value>,
    ) -> Result<WarmReport, DeployerError> {
        self.warm(env, revision_ids, answers, true).await
    }

    async fn warm(
        &self,
        env: &Environment,
        revision_ids: &[RevisionId],
        answers: Option<&Value>,
        read_slot: bool,
    ) -> Result<WarmReport, DeployerError> {
        if revision_ids.is_empty() {
            return Err(DeployerError::Provider(
                "ssh-host: warm needs at least one revision".to_string(),
            ));
        }
        for revision_id in revision_ids {
            require_revision(env, *revision_id)?;
        }
        let params = self.params_for(env, answers)?;
        let Some(store_root) = self.store_root.clone() else {
            return Err(DeployerError::Provider(
                "ssh-host: no local store is bound to this deployer, so there is nothing to \
                 synchronize (the CLI must pass the store root and the filtered dev-store)"
                    .to_string(),
            ));
        };
        let remote = std::sync::Arc::clone(&self.remote);
        let tunnels = std::sync::Arc::clone(&self.tunnels);
        let input = WarmInput {
            env: env.clone(),
            revision_ids: revision_ids.to_vec(),
            store_root,
            dev_secrets: self.dev_secrets.clone(),
        };
        // ssh is blocking I/O that can take minutes; keep it off the executor.
        tokio::task::spawn_blocking(move || {
            let session = Session::open(remote.as_ref(), &params, &tunnels)?;
            let mut report = steps::warm(&session, &input)?;
            if read_slot {
                report.active_slot = steps::active_slot_name(&session)?;
            }
            Ok(report)
        })
        .await
        .map_err(|e| DeployerError::Provider(format!("ssh-host: warm task failed: {e}")))?
    }
}

/// Whether the env's recorded splits still route any traffic anywhere.
fn routes_any_traffic(env: &Environment) -> bool {
    env.traffic_splits
        .iter()
        .flat_map(|s| s.entries.iter())
        .any(|e| e.weight_bps > 0)
}

#[async_trait]
impl Deployer for SshHostDeployerHandler {
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
        let report = self.warm(env, &[revision_id], answers, false).await?;
        Ok(WarmOutcome {
            endpoint_url: report.endpoint_url,
        })
    }

    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        // The one service serves every routed revision of the env: stopping it
        // for one drained revision would cut the others. Only an env that
        // routes nothing at all has anything to stop.
        if routes_any_traffic(env) {
            return Ok(DrainOutcome::default());
        }
        let params = self.params_for(env, answers)?;
        let remote = std::sync::Arc::clone(&self.remote);
        let tunnels = std::sync::Arc::clone(&self.tunnels);
        tokio::task::spawn_blocking(move || {
            let session = Session::open(remote.as_ref(), &params, &tunnels)?;
            steps::stop(&session)
        })
        .await
        .map_err(|e| DeployerError::Provider(format!("ssh-host: drain task failed: {e}")))??;
        // The adapter does not claim `drain`: nothing here confirms in-flight
        // sessions completed, so the evidence stays `Unsupported`.
        Ok(DrainOutcome::default())
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::NONE
    }

    fn capability_notes(&self) -> &'static [&'static str] {
        &[
            "one instance per VM: a single greentic-start serves the whole env store, so there \
             is no traffic_split and no multi_instance_safe",
            "drain: not confirmed — the service is stopped only when the env routes no traffic, \
             and nothing checks that in-flight sessions finished",
            "remove: archive does not touch the VM; the next warm re-synchronizes the store",
            "ingress_managed: the service listens on listen_port over plain HTTP; TLS and DNS \
             are the operator's",
            "private_registry_auth / runtime_pin: not applicable — the binary is the one \
             installed (or copied via start_binary), not an image",
        ]
    }

    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        _answers: Option<&Value>,
    ) -> Result<ArchiveOutcome, DeployerError> {
        // Deliberately a no-op: nothing on the VM is per-revision, and deleting
        // data from a machine we do not own is never the safe default.
        require_revision(env, revision_id)?;
        Ok(ArchiveOutcome::default())
    }

    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
        _answers: Option<&Value>,
    ) -> Result<TrafficSplitOutcome, DeployerError> {
        enforce_split_invariants(env, deployment_id)
    }
}
