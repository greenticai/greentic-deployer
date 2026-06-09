//! [`Deployer`] impl for the local-process env-pack.
//!
//! The local-process deployer has **no provider side**. Bundles live on
//! the operator's filesystem; `greentic-start` reads them directly; the
//! in-process dispatcher reads `runtime-config.v1`; nothing is uploaded,
//! provisioned, or torn down. Every verb on the trait is therefore a
//! pure-spec precondition check followed by `Ok(...)`.
//!
//! This impl is the reference shape Phase D's K8s/AWS/GCP/Azure slices
//! follow: validate the pure preconditions explicitly (revision exists,
//! split sums to 10000bps, split exists for the deployment) and ONLY
//! then perform provider work. Reusing the conformance bench
//! ([`crate::env_packs::deployer::run_conformance`]) catches a future
//! deployer that forgets one of the precondition checks.

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, RevisionId};

use super::LocalProcessDeployerHandler;
use crate::env_packs::deployer::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome,
};

#[async_trait]
impl Deployer for LocalProcessDeployerHandler {
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
    ) -> Result<WarmOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        Ok(WarmOutcome::default())
    }

    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<DrainOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        Ok(DrainOutcome::default())
    }

    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<ArchiveOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        Ok(ArchiveOutcome::default())
    }

    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
    ) -> Result<TrafficSplitOutcome, DeployerError> {
        let split = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id == deployment_id)
            .ok_or_else(|| DeployerError::SplitNotFound {
                env_id: env.environment_id.clone(),
                deployment_id,
            })?;
        let sum: u64 = split.entries.iter().map(|e| u64::from(e.weight_bps)).sum();
        if sum != 10_000 {
            return Err(DeployerError::InvalidSplit { deployment_id, sum });
        }
        // No provider side — the in-process dispatcher reads the
        // runtime-config materialization on its own.
        Ok(TrafficSplitOutcome {
            applied_deployment_id: deployment_id,
            applied_entries: split.entries.clone(),
        })
    }
}

fn require_revision(env: &Environment, revision_id: RevisionId) -> Result<(), DeployerError> {
    if env.revisions.iter().any(|r| r.revision_id == revision_id) {
        Ok(())
    } else {
        Err(DeployerError::RevisionNotFound {
            env_id: env.environment_id.clone(),
            revision_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::deployer::run_conformance;

    #[tokio::test]
    async fn local_process_passes_conformance() {
        let handler = LocalProcessDeployerHandler::default();
        run_conformance(&handler)
            .await
            .expect("local-process deployer satisfies the Phase D conformance contract");
    }

    /// Belt-and-braces: verify the handler exposes its `Deployer` impl
    /// through the `EnvPackHandler::as_deployer` seam. A future
    /// refactor that breaks this binding would otherwise leave the
    /// conformance test passing while the registry returns `None`.
    #[test]
    fn handler_exposes_deployer_via_trait_method() {
        use crate::env_packs::slot::EnvPackHandler;
        let h = LocalProcessDeployerHandler::default();
        assert!(
            (&h as &dyn EnvPackHandler).as_deployer().is_some(),
            "EnvPackHandler::as_deployer must surface the local-process Deployer impl",
        );
    }
}
