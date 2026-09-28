//! Enforced drain for the K8s env-pack (P5-R2).
//!
//! The router (greentic-start) exposes no per-revision in-flight or session
//! count, so the K8s drain confirms on the next-best observable signal: the
//! revision's worker has **zero ready endpoints**. The sequence is
//!
//! 1. refuse a revision the recorded split still routes to
//!    ([`require_unrouted`]) — before any cluster call;
//! 2. wait the drain window (`drain_seconds`, capped by the policy) so
//!    in-flight sessions on the worker finish;
//! 3. scale the worker Deployment to 0 replicas — nothing new can land on
//!    it (the router stopped sending when the split moved) and nothing old
//!    stays up past the window;
//! 4. poll the Deployment until it runs no pod (`status.replicas == 0`,
//!    `availableReplicas == 0`), which is exactly "its Service has zero ready
//!    endpoints". An absent Deployment is drained.
//!
//! The Deployment status is read rather than the Service's EndpointSlices
//! because `deployments get` is already in the bound Role, while
//! `endpointslices list` is not — an env bound before this shipped keeps
//! working. A later `op env reconcile` of a still-`Draining` revision
//! re-applies its replica count; the archive gate then refuses it until it is
//! drained again, which is the correct reading of a resurrected worker.

use tokio::time::sleep;

use greentic_deploy_spec::{Environment, RevisionId};
use serde_json::Value;

use super::K8sDeployerHandler;
use super::cluster::ObjectRef;
use super::deployer::{params_from_answers, provider};
use super::manifests::render_worker_manifests;
use crate::env_packs::deployer::drain::{confirm_within, require_unrouted};
use crate::env_packs::deployer::{
    DeployerError, DrainEvidence, DrainOutcome, DrainPolicy, DrainProbe, require_revision,
};

impl K8sDeployerHandler {
    /// The revision's worker Deployment, addressed exactly as warm/archive
    /// render it (same answers → same namespace).
    fn worker_deployment(
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ObjectRef, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = env
            .revisions
            .iter()
            .find(|r| r.revision_id == revision_id)
            .ok_or_else(|| DeployerError::RevisionNotFound {
                env_id: env.environment_id.clone(),
                revision_id,
            })?;
        let params = params_from_answers(env, answers)?;
        let manifests = render_worker_manifests(env, revision, &params);
        let deployment = manifests
            .iter()
            .find(|m| m.get("kind").and_then(Value::as_str) == Some("Deployment"))
            .ok_or_else(|| DeployerError::Provider("worker render has no Deployment".into()))?;
        ObjectRef::from_manifest(deployment).map_err(provider)
    }

    async fn probe_drained(&self, deployment: &ObjectRef) -> Result<DrainProbe, DeployerError> {
        let status = self
            .cluster
            .get_rollout_status_opt(deployment)
            .await
            .map_err(provider)?;
        Ok(match status {
            None => DrainProbe::Drained(DrainEvidence::ZeroReadyEndpoints {
                deployment: deployment.name.clone(),
                absent: true,
            }),
            Some(s) if s.replicas == 0 && s.available_replicas == 0 => {
                DrainProbe::Drained(DrainEvidence::ZeroReadyEndpoints {
                    deployment: deployment.name.clone(),
                    absent: false,
                })
            }
            Some(s) => DrainProbe::Pending(format!(
                "worker `{}` still runs {} pod(s), {} ready",
                deployment.name, s.replicas, s.available_replicas
            )),
        })
    }

    pub(super) async fn drain_enforced(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainOutcome, DeployerError> {
        let deployment = Self::worker_deployment(env, revision_id, answers)?;
        require_unrouted(env, revision_id)?;
        let window = env
            .revisions
            .iter()
            .find(|r| r.revision_id == revision_id)
            .map(|r| self.drain_policy.window(r))
            .unwrap_or_default();
        sleep(window).await;
        self.cluster
            .scale_deployment(&deployment, 0)
            .await
            .map_err(provider)?;
        let evidence = confirm_within(revision_id, &self.drain_policy, || {
            self.probe_drained(&deployment)
        })
        .await?;
        Ok(DrainOutcome {
            waited_seconds: window.as_secs(),
            evidence,
        })
    }

    pub(super) async fn confirm_drained_now(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainEvidence, DeployerError> {
        let deployment = Self::worker_deployment(env, revision_id, answers)?;
        confirm_within(revision_id, &DrainPolicy::immediate(), || {
            self.probe_drained(&deployment)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::cluster::{
        InMemoryCluster, K8sCluster, K8sClusterError, RolloutStatus, ServiceStatus,
    };

    fn handler(cluster: Arc<dyn K8sCluster>) -> K8sDeployerHandler {
        K8sDeployerHandler::with_cluster(cluster).with_drain_policy(DrainPolicy::immediate())
    }

    /// Fixture env with revision 1's weight moved to revision 0.
    fn unrouted_env() -> Environment {
        let mut env = build_fixture_env();
        env.traffic_splits[0].entries[0].weight_bps = 10_000;
        env.traffic_splits[0].entries[1].weight_bps = 0;
        env
    }

    #[tokio::test]
    async fn drain_refuses_a_routed_revision_before_touching_the_cluster() {
        // Unconfigured cluster: any cluster call would surface as Provider.
        let h = handler(Arc::new(crate::env_packs::k8s::UnconfiguredCluster));
        let env = build_fixture_env();
        let r = env.revisions[1].revision_id;
        let err = h.drain_revision(&env, r, None).await.unwrap_err();
        assert!(
            matches!(err, DeployerError::NotDrained { revision_id, .. } if revision_id == r),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn drain_scales_the_worker_to_zero_and_confirms_zero_endpoints() {
        let cluster = Arc::new(InMemoryCluster::default());
        let h = handler(cluster.clone());
        let env = unrouted_env();
        let r = env.revisions[1].revision_id;
        h.warm_revision(&env, r, None).await.unwrap();
        let dep = K8sDeployerHandler::worker_deployment(&env, r, None).unwrap();
        assert_eq!(cluster.replicas_of(&dep), Some(1));
        // Still running → the archive gate refuses.
        let gate = h.confirm_drained(&env, r, None).await.unwrap_err();
        assert!(matches!(gate, DeployerError::NotDrained { .. }), "{gate:?}");

        let out = h.drain_revision(&env, r, None).await.unwrap();
        assert_eq!(cluster.replicas_of(&dep), Some(0));
        assert_eq!(
            out.evidence,
            DrainEvidence::ZeroReadyEndpoints {
                deployment: dep.name.clone(),
                absent: false
            }
        );
        // Drained → the gate passes; idempotent second drain too.
        h.confirm_drained(&env, r, None).await.unwrap();
        h.drain_revision(&env, r, None).await.unwrap();
    }

    #[tokio::test]
    async fn a_never_warmed_revision_is_drained_as_absent() {
        let h = handler(Arc::new(InMemoryCluster::default()));
        let env = unrouted_env();
        let r = env.revisions[1].revision_id;
        let out = h.drain_revision(&env, r, None).await.unwrap();
        assert!(matches!(
            out.evidence,
            DrainEvidence::ZeroReadyEndpoints { absent: true, .. }
        ));
    }

    /// A cluster whose pods never terminate.
    #[derive(Debug, Default)]
    struct StuckPods(InMemoryCluster);

    #[async_trait]
    impl K8sCluster for StuckPods {
        async fn apply(&self, m: &Value) -> Result<(), K8sClusterError> {
            self.0.apply(m).await
        }
        async fn delete(&self, o: &ObjectRef) -> Result<(), K8sClusterError> {
            self.0.delete(o).await
        }
        async fn get_rollout_status(
            &self,
            o: &ObjectRef,
        ) -> Result<RolloutStatus, K8sClusterError> {
            self.0.get_rollout_status(o).await
        }
        async fn get_service_status(
            &self,
            o: &ObjectRef,
        ) -> Result<ServiceStatus, K8sClusterError> {
            self.0.get_service_status(o).await
        }
        async fn scale_deployment(&self, _: &ObjectRef, _: i32) -> Result<bool, K8sClusterError> {
            Ok(true)
        }
        async fn get_rollout_status_opt(
            &self,
            _: &ObjectRef,
        ) -> Result<Option<RolloutStatus>, K8sClusterError> {
            Ok(Some(RolloutStatus {
                generation: 1,
                observed_generation: Some(1),
                replicas: 1,
                updated_replicas: 1,
                available_replicas: 1,
            }))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn drain_waits_the_capped_window_then_times_out_on_stuck_pods() {
        let policy = DrainPolicy {
            max_wait: Duration::from_secs(10),
            confirm_timeout: Duration::from_secs(6),
            poll_interval: Duration::from_secs(2),
        };
        let h = K8sDeployerHandler::with_cluster(Arc::new(StuckPods::default()))
            .with_drain_policy(policy);
        let env = unrouted_env(); // revision drain_seconds = 30 → capped to 10
        let r = env.revisions[1].revision_id;
        let started = tokio::time::Instant::now();
        let err = h.drain_revision(&env, r, None).await.unwrap_err();
        assert!(
            matches!(err, DeployerError::NotDrained { ref reason, .. } if reason.contains("1 pod")),
            "{err:?}"
        );
        assert!(
            started.elapsed() >= Duration::from_secs(16),
            "window + confirm"
        );
        assert!(started.elapsed() < Duration::from_secs(30), "window capped");
    }
}
