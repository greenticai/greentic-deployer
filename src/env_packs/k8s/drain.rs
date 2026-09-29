//! Enforced drain for the K8s env-pack (P5-R2).
//!
//! The router (greentic-start) exposes no per-revision in-flight or session
//! count, so the K8s drain confirms on the next-best observable signal: the
//! revision's worker has **zero ready endpoints**. The sequence is
//!
//! 1. refuse a revision the recorded split still routes to
//!    ([`require_unrouted`]) — before any cluster call;
//! 2. project the store's split into the router's runtime-config ConfigMap,
//!    then read the ConfigMap back and refuse if the LIVE router config still
//!    weights the revision (a split recorded but never pushed still routes);
//! 3. wait the drain window (`drain_seconds`, capped by the policy) so
//!    sessions in flight at the cut finish;
//! 4. scale the worker Deployment to 0 replicas — nothing new can land on
//!    it (the router stopped sending when the split moved) and nothing old
//!    stays up past the window;
//! 5. poll the Deployment until it runs no pod (`status.replicas == 0`,
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
use super::manifests::{render_runtime_config_map, render_worker_manifests};
use greentic_deploy_spec::RuntimeConfig;

/// Key the runtime-config JSON lives under in the router's ConfigMap.
const RUNTIME_CONFIG_KEY: &str = "runtime-config.json";
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

    /// `endpoints_only` (the archive gate): drained once no pod is READY, i.e.
    /// the Service has zero ready endpoints — a worker whose pods never became
    /// ready (a failed warm) serves nothing and can be archived. The drain
    /// itself (`false`) also waits for the scaled-down pods to be gone.
    async fn probe_drained(
        &self,
        deployment: &ObjectRef,
        endpoints_only: bool,
    ) -> Result<DrainProbe, DeployerError> {
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
            Some(s) if s.available_replicas == 0 && (endpoints_only || s.replicas == 0) => {
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

    /// The router's LIVE routing: read the runtime-config ConfigMap it reloads
    /// back from the cluster and refuse if it still weights the revision. An
    /// absent ConfigMap routes nothing; an unreadable one fails closed.
    async fn require_router_unrouted(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<(), DeployerError> {
        let params = params_from_answers(env, answers)?;
        let config_map =
            ObjectRef::from_manifest(&render_runtime_config_map(env, &params)).map_err(provider)?;
        let Some(live) = self
            .cluster
            .get_object(&config_map)
            .await
            .map_err(provider)?
        else {
            return Ok(());
        };
        let not_drained = |reason: String| DeployerError::NotDrained {
            revision_id,
            reason,
        };
        let raw = live
            .pointer(&format!("/data/{RUNTIME_CONFIG_KEY}"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                not_drained(format!(
                    "the router's `{config_map}` has no `{RUNTIME_CONFIG_KEY}`; cannot prove \
                     it no longer routes here"
                ))
            })?;
        let config: RuntimeConfig = serde_json::from_str(raw)
            .map_err(|e| not_drained(format!("the router's `{config_map}` is unreadable ({e})")))?;
        let weight: u32 = config
            .revisions
            .iter()
            .filter(|b| b.revision_id == revision_id)
            .map(|b| b.weight_bps)
            .sum();
        if weight == 0 {
            Ok(())
        } else {
            Err(not_drained(format!(
                "the router's live runtime-config (`{config_map}`) still routes {weight} bps to it"
            )))
        }
    }

    /// Enforced drain: stop routing and CONFIRM it (store split at 0, the
    /// store's split projected into the router's ConfigMap, the live
    /// ConfigMap read back at 0), THEN wait the window as grace for sessions
    /// in flight at the cut, THEN stop the worker and confirm zero ready
    /// endpoints.
    pub(super) async fn drain_enforced(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainOutcome, DeployerError> {
        let deployment = Self::worker_deployment(env, revision_id, answers)?;
        require_unrouted(env, revision_id)?;
        // Project the store's split into the router (the same idempotent write
        // `apply_traffic_split` makes). Without it a split recorded — or
        // cleared by `op bundles retire` — but never pushed keeps routing.
        let params = params_from_answers(env, answers)?;
        self.cluster
            .apply(&render_runtime_config_map(env, &params))
            .await
            .map_err(provider)?;
        self.require_router_unrouted(env, revision_id, answers)
            .await?;
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
            self.probe_drained(&deployment, false)
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
        self.require_router_unrouted(env, revision_id, answers)
            .await?;
        confirm_within(revision_id, &DrainPolicy::immediate(), || {
            self.probe_drained(&deployment, true)
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

    #[tokio::test]
    async fn drain_pushes_the_moved_split_into_the_router_before_stopping_the_worker() {
        let cluster = Arc::new(InMemoryCluster::default());
        let h = handler(cluster.clone());
        let routed = build_fixture_env();
        let r = routed.revisions[1].revision_id;
        // The router still has the OLD split (5000 bps to r) live.
        let params = params_from_answers(&routed, None).unwrap();
        cluster
            .apply(&render_runtime_config_map(&routed, &params))
            .await
            .unwrap();
        let env = unrouted_env();
        // Archive gate (no push): the live router config still routes r.
        let gate = h.confirm_drained(&env, r, None).await.unwrap_err();
        assert!(
            matches!(gate, DeployerError::NotDrained { ref reason, .. }
                if reason.contains("live runtime-config") && reason.contains("5000")),
            "{gate:?}"
        );
        // The drain projects the moved split, reads it back at 0, then drains.
        h.drain_revision(&env, r, None).await.unwrap();
        h.confirm_drained(&env, r, None).await.unwrap();
    }

    #[tokio::test]
    async fn an_unreadable_router_config_fails_closed() {
        let cluster = Arc::new(InMemoryCluster::default());
        let h = handler(cluster.clone());
        let env = unrouted_env();
        let params = params_from_answers(&env, None).unwrap();
        let mut cm = render_runtime_config_map(&env, &params);
        cm["data"]["runtime-config.json"] = serde_json::json!("{not json");
        cluster.apply(&cm).await.unwrap();
        let err = h
            .confirm_drained(&env, env.revisions[1].revision_id, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DeployerError::NotDrained { ref reason, .. } if reason.contains("unreadable")),
            "{err:?}"
        );
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
        async fn get_object(&self, o: &ObjectRef) -> Result<Option<Value>, K8sClusterError> {
            self.0.get_object(o).await
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

    /// A worker whose only pod never became ready (a failed warm).
    #[derive(Debug, Default)]
    struct NeverReady(InMemoryCluster);

    #[async_trait]
    impl K8sCluster for NeverReady {
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
        async fn get_object(&self, o: &ObjectRef) -> Result<Option<Value>, K8sClusterError> {
            self.0.get_object(o).await
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
                available_replicas: 0,
            }))
        }
    }

    #[tokio::test]
    async fn the_archive_gate_passes_a_worker_with_zero_ready_endpoints() {
        let h = K8sDeployerHandler::with_cluster(Arc::new(NeverReady::default()))
            .with_drain_policy(DrainPolicy::immediate());
        let env = unrouted_env();
        let evidence = h
            .confirm_drained(&env, env.revisions[1].revision_id, None)
            .await
            .unwrap();
        assert!(matches!(
            evidence,
            DrainEvidence::ZeroReadyEndpoints { absent: false, .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn drain_waits_the_capped_window_then_times_out_on_stuck_pods() {
        let policy = DrainPolicy {
            max_wait: Duration::from_secs(10),
            confirm_timeout: Duration::from_secs(6),
            poll_interval: Duration::from_secs(2),
            window_override: None,
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

    /// `op bundles retire --drain-seconds`: the override replaces the
    /// revision's own 30 s (and is not capped by `max_wait`).
    #[tokio::test(start_paused = true)]
    async fn drain_waits_the_override_window_instead_of_the_recorded_one() {
        let policy = DrainPolicy {
            max_wait: Duration::from_secs(10),
            ..DrainPolicy::immediate()
        };
        for (override_secs, expected) in [(Some(45), 45), (Some(2), 2), (None, 10)] {
            let h = K8sDeployerHandler::with_cluster(Arc::new(InMemoryCluster::default()))
                .with_drain_policy(
                    policy.with_window_override(override_secs.map(Duration::from_secs)),
                );
            let env = unrouted_env(); // revision drain_seconds = 30
            let started = tokio::time::Instant::now();
            let out = h
                .drain_revision(&env, env.revisions[1].revision_id, None)
                .await
                .unwrap();
            assert_eq!(out.waited_seconds, expected, "{override_secs:?}");
            assert!(started.elapsed() >= Duration::from_secs(expected));
        }
    }
}
