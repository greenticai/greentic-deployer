//! [`Deployer`] impl for the K8s env-pack.
//!
//! Verbs follow the contract's required order: pure-spec preconditions
//! first (shared helpers — `require_revision`, `enforce_split_invariants`),
//! provider work second. The provider work is "render the deterministic
//! desired state, hand it to the [`K8sCluster`](super::cluster::K8sCluster)
//! seam".
//!
//! **Answers:** `warm_revision` / `archive_revision` / `apply_traffic_split`
//! take the binding's wizard answers and render through
//! [`K8sParams::from_answers`] (`None` → [`K8sParams::for_env`] sandbox
//! defaults), so a verb lands the same namespace / image / replicas
//! `op env render` and `op env reconcile` show. The CLI passes the answers
//! it loads from the deployer binding; the per-revision dispatch entry point
//! is `op env apply-revision`.
//!
//! | Verb | Provider side-effect |
//! |---|---|
//! | `stage_revision` | None today. The bundle artifact is delivered to the pod at warm time (delivery mechanism is a PR-5.3 decision); there is no per-revision registry upload step yet. |
//! | `warm_revision` | Apply the revision's worker Deployment + ClusterIP Service. |
//! | `drain_revision` | None — drain semantics are routing-side. The router stops dispatching NEW sessions when the `TrafficSplit` changes (`apply_traffic_split`); provider resources stay up through the drain window so in-flight sessions finish. Teardown is `archive_revision`'s job. |
//! | `archive_revision` | Delete the worker Deployment + Service (idempotent against absent). |
//! | `apply_traffic_split` | Upsert the runtime-config ConfigMap — the router reloads it and enforces the split in-process. Never a `kubectl rollout`. |
//!
//! Idempotency falls out of the seam's contract: `apply` is a
//! declarative upsert, `delete` of an absent object is `Ok`. The
//! conformance bench runs against an in-memory fake cluster (the verbs +
//! rendering are fully exercised); the real kube-rs-backed seam
//! ([`KubeCluster`](super::kube_client::KubeCluster)) inherits the same
//! verbs unchanged once the PR-5.3 wiring binds it.

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, Revision, RevisionId};
use serde_json::Value;

use super::K8sDeployerHandler;
use super::cluster::{K8sClusterError, ObjectRef};
use super::manifests::{
    K8sParams, has_cluster_presence, render_runtime_config_map, render_worker_manifests,
};
use crate::env_packs::deployer::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome, enforce_split_invariants, require_revision,
};
use crate::env_packs::render::ManifestRenderer;

/// Cluster failures surface as provider failures — the verb's
/// preconditions have already passed by the time the seam is touched.
fn provider(err: K8sClusterError) -> DeployerError {
    DeployerError::Provider(err.to_string())
}

/// Build render params from the binding's wizard answers (namespace / image
/// / replicas), so a verb lands the same objects `op env render` shows. `None`
/// → sandbox defaults. A malformed answers blob fails here — before any
/// cluster call, so no partial state — surfaced as a provider error (there is
/// no typed answers-rejection variant; this mirrors `reconcile`).
fn params_from_answers(
    env: &Environment,
    answers: Option<&Value>,
) -> Result<K8sParams, DeployerError> {
    K8sParams::from_answers(env, answers)
        .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))
}

impl K8sDeployerHandler {
    /// Locate the revision (the caller already passed `require_revision`,
    /// so the lookup is infallible by construction — keep it total anyway).
    fn revision(env: &Environment, revision_id: RevisionId) -> Option<&Revision> {
        env.revisions.iter().find(|r| r.revision_id == revision_id)
    }

    async fn apply_all(&self, manifests: &[Value]) -> Result<(), DeployerError> {
        for manifest in manifests {
            self.cluster.apply(manifest).await.map_err(provider)?;
        }
        Ok(())
    }

    /// Converge the cluster on the env's full desired state.
    ///
    /// This is the provider-side effect that `gtc op env reconcile` drives
    /// (the first caller of a connected [`K8sCluster`](super::cluster::K8sCluster)).
    /// Unlike the per-revision lifecycle verbs, it owns the WHOLE env:
    ///
    /// 1. **Apply** the rendered desired state — the env-level set (Namespace,
    ///    router, runtime-config ConfigMap, NetworkPolicies) plus the worker
    ///    pair of every revision with cluster presence. The manifest set comes
    ///    from [`render_environment`](crate::env_packs::render::ManifestRenderer::render_environment),
    ///    so reconcile applies EXACTLY what `op env render` shows — render and
    ///    apply converge by construction.
    /// 2. **Prune** the worker pair of every revision WITHOUT cluster presence
    ///    (archived / failed / post-drain inactive). `delete` of an absent
    ///    object is `Ok`, so pruning is idempotent and safe against a partial
    ///    prior teardown.
    ///
    /// Env-level objects are never pruned here — tearing down the namespace /
    /// router is env destruction, a separate verb. Reconcile only converges a
    /// live env.
    ///
    /// # Known gaps (Phase D later slices)
    ///
    /// - **Identity / Namespace RBAC.** The applied set includes the
    ///   cluster-scoped `Namespace`, so reconcile assumes an identity with
    ///   namespace-create authority — true for today's ambient identity, but
    ///   the bound-ServiceAccount model (Phase D secrets sink) must reconcile
    ///   Namespace handling with the bootstrap pack's namespaced-only RBAC.
    /// - **Adoption of unlabeled objects.** [`KubeCluster::apply`](super::kube_client::KubeCluster)'s
    ///   ownership guard only conflicts on a *differing* env label; a
    ///   preexisting object with a managed name but no label is force-adopted.
    ///   The fresh namespace reconcile creates never hits this — hardening
    ///   adoption in a customer-provided namespace rides the real-cluster slice.
    /// - **Prune scope.** Pruning iterates `env.revisions`, so the workers of a
    ///   revision already compacted out of the Vec (`remove_bundle` after
    ///   archive) are not reachable here — reclaiming those orphans needs
    ///   label-based GC via a future `K8sCluster::list` seam.
    pub async fn reconcile(
        &self,
        env: &Environment,
        answers: Option<&Value>,
    ) -> Result<ReconcileReport, DeployerError> {
        let desired = self
            .render_environment(env, answers)
            .map_err(|e| DeployerError::Provider(e.to_string()))?;
        let mut applied = Vec::with_capacity(desired.len());
        for manifest in &desired {
            self.cluster.apply(manifest).await.map_err(provider)?;
            applied.push(ObjectRef::from_manifest(manifest).map_err(provider)?);
        }

        // `params` is recomputed (pure, cheap) only to render the prune set;
        // the present set already came from `render_environment` above.
        let params = K8sParams::from_answers(env, answers)
            .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))?;
        let mut pruned = Vec::new();
        for revision in &env.revisions {
            if !has_cluster_presence(revision.lifecycle) {
                for manifest in render_worker_manifests(env, revision, &params) {
                    let object = ObjectRef::from_manifest(&manifest).map_err(provider)?;
                    self.cluster.delete(&object).await.map_err(provider)?;
                    pruned.push(object);
                }
            }
        }
        Ok(ReconcileReport { applied, pruned })
    }
}

/// Outcome of [`K8sDeployerHandler::reconcile`].
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReconcileReport {
    /// Objects upserted to converge desired state (env-level set +
    /// present-revision workers), in apply order.
    pub applied: Vec<ObjectRef>,
    /// Worker objects deleted for revisions without cluster presence.
    pub pruned: Vec<ObjectRef>,
}

#[async_trait]
impl Deployer for K8sDeployerHandler {
    async fn stage_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<StageOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        // No cluster work at stage time — see the module table.
        Ok(StageOutcome::default())
    }

    async fn warm_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<WarmOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = Self::revision(env, revision_id).expect("require_revision passed");
        let params = params_from_answers(env, answers)?;
        self.apply_all(&render_worker_manifests(env, revision, &params))
            .await?;
        // warm returns once the API server has accepted the worker manifests.
        // The live-cluster readiness wait (observed `.status.observedGeneration`
        // + available replicas + the per-revision `/healthz/<revision_id>`
        // probe before the revision is promoted Warming → Ready) is a later
        // PR-5.3 slice via the RevisionHealthGate seam (cross-repo) — it is
        // intentionally NOT performed inside the upsert primitive.
        Ok(WarmOutcome::default())
    }

    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<DrainOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        // Routing-side only — see the module table. Worker resources stay
        // up so in-flight sessions complete; archive tears them down.
        Ok(DrainOutcome::default())
    }

    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ArchiveOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = Self::revision(env, revision_id).expect("require_revision passed");
        let params = params_from_answers(env, answers)?;
        for manifest in render_worker_manifests(env, revision, &params) {
            let object = ObjectRef::from_manifest(&manifest).map_err(provider)?;
            self.cluster.delete(&object).await.map_err(provider)?;
        }
        Ok(ArchiveOutcome::default())
    }

    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
        answers: Option<&Value>,
    ) -> Result<TrafficSplitOutcome, DeployerError> {
        // Preconditions + outcome construction BEFORE any cluster call.
        let outcome = enforce_split_invariants(env, deployment_id)?;
        let params = params_from_answers(env, answers)?;
        self.cluster
            .apply(&render_runtime_config_map(env, &params))
            .await
            .map_err(provider)?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::deployer::run_conformance;
    use crate::env_packs::k8s::cluster::{InMemoryCluster, K8sCluster};
    use crate::env_packs::k8s::manifests::{RUNTIME_CONFIG_MAP_NAME, worker_name};

    fn handler_with_fake() -> (K8sDeployerHandler, Arc<InMemoryCluster>) {
        let cluster = Arc::new(InMemoryCluster::default());
        (K8sDeployerHandler::with_cluster(cluster.clone()), cluster)
    }

    /// The Phase D entry gate: the K8s impl satisfies the shared
    /// deployer contract (idempotency on every verb, typed precondition
    /// rejection, cross-deployment independence, projection consistency).
    #[tokio::test]
    async fn k8s_deployer_passes_conformance() {
        let (handler, _cluster) = handler_with_fake();
        run_conformance(&handler)
            .await
            .expect("K8s deployer satisfies the Phase D conformance contract");
    }

    #[tokio::test]
    async fn warm_applies_the_worker_deployment_and_service() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();

        let objects = cluster.objects();
        assert_eq!(objects.len(), 2, "Deployment + Service");
        let name = worker_name(rev);
        let kinds: Vec<(String, String)> = objects
            .keys()
            .map(|o| (o.kind.clone(), o.name.clone()))
            .collect();
        assert!(kinds.contains(&("Deployment".into(), name.clone())));
        assert!(kinds.contains(&("Service".into(), name)));

        // Warm again: declarative upsert, still exactly two objects.
        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert_eq!(cluster.objects().len(), 2);
    }

    /// Answers thread through to the rendered objects: a custom `namespace`
    /// answer lands the worker pair in that namespace, not the sandbox
    /// default — render↔apply parity with `op env render`/`reconcile`.
    #[tokio::test]
    async fn warm_honors_the_namespace_answer() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];
        let answers = serde_json::json!({ "namespace": "custom-ns" });

        handler
            .warm_revision(&env, rev.revision_id, Some(&answers))
            .await
            .unwrap();

        let namespaces: Vec<String> = cluster
            .objects()
            .keys()
            .filter_map(|o| o.namespace.clone())
            .collect();
        assert!(
            !namespaces.is_empty() && namespaces.iter().all(|ns| ns == "custom-ns"),
            "worker objects land in the answer namespace, got {namespaces:?}"
        );
    }

    /// A malformed answers blob fails before any cluster call (no partial
    /// state), surfaced as a provider error.
    #[tokio::test]
    async fn warm_rejects_invalid_answers_before_touching_the_cluster() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];
        let answers = serde_json::json!({ "unknown_key": "x" });

        let err = handler
            .warm_revision(&env, rev.revision_id, Some(&answers))
            .await
            .unwrap_err();
        match err {
            DeployerError::Provider(msg) => assert!(msg.contains("invalid answers"), "msg: {msg}"),
            other => panic!("expected Provider, got {other:?}"),
        }
        assert!(
            cluster.objects().is_empty(),
            "invalid answers must not touch the cluster"
        );
    }

    #[tokio::test]
    async fn archive_removes_the_worker_objects_and_tolerates_absence() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert_eq!(cluster.objects().len(), 2);

        handler
            .archive_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert!(cluster.objects().is_empty());

        // Retried archive against already-torn-down resources is Ok.
        handler
            .archive_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn traffic_split_upserts_the_runtime_config_map() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();
        let dep = env.bundles[0].deployment_id;

        let outcome = handler.apply_traffic_split(&env, dep, None).await.unwrap();
        assert_eq!(outcome.applied_deployment_id, dep);

        let objects = cluster.objects();
        assert_eq!(objects.len(), 1);
        let (object, manifest) = objects.iter().next().unwrap();
        assert_eq!(object.kind, "ConfigMap");
        assert_eq!(object.name, RUNTIME_CONFIG_MAP_NAME);
        // The ConfigMap payload is the exact runtime-config projection.
        let payload = manifest["data"]["runtime-config.json"].as_str().unwrap();
        let expected = serde_json::to_string(
            &crate::environment::runtime_config::materialize_runtime_config(&env),
        )
        .unwrap();
        assert_eq!(payload, expected);
    }

    #[tokio::test]
    async fn reconcile_applies_desired_state_and_is_idempotent() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();

        let report = handler.reconcile(&env, None).await.unwrap();

        // The applied set IS the renderer's desired state (render↔apply
        // convergence) and every object landed in the cluster.
        let desired = handler.render_environment(&env, None).unwrap();
        assert_eq!(report.applied.len(), desired.len());
        assert_eq!(cluster.objects().len(), desired.len());

        // Prune touches the worker pair of every NOT-present revision.
        let absent = env
            .revisions
            .iter()
            .filter(|r| !has_cluster_presence(r.lifecycle))
            .count();
        assert_eq!(report.pruned.len(), absent * 2);

        // Reconcile again: declarative upsert leaves identical cluster state.
        let before = cluster.objects();
        let report2 = handler.reconcile(&env, None).await.unwrap();
        assert_eq!(report2.applied.len(), desired.len());
        assert_eq!(cluster.objects(), before, "reconcile is idempotent");
    }

    #[tokio::test]
    async fn reconcile_prunes_workers_left_over_from_a_now_absent_revision() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);

        // A non-present revision whose worker objects still linger on the
        // cluster (e.g. it was Ready, got archived after the last reconcile).
        let absent = env
            .revisions
            .iter()
            .find(|r| !has_cluster_presence(r.lifecycle))
            .expect("fixture has a non-present revision");
        for manifest in render_worker_manifests(&env, absent, &params) {
            cluster.apply(&manifest).await.unwrap();
        }
        let lingering = worker_name(absent);
        assert!(
            cluster.objects().keys().any(|o| o.name == lingering),
            "precondition: the absent revision's workers are on the cluster"
        );

        handler.reconcile(&env, None).await.unwrap();

        assert!(
            !cluster.objects().keys().any(|o| o.name == lingering),
            "reconcile prunes the now-absent revision's workers"
        );
    }

    /// Preconditions run BEFORE any cluster call: an unknown revision or
    /// an invalid split must leave the cluster untouched.
    #[tokio::test]
    async fn preconditions_reject_before_any_cluster_call() {
        let (handler, cluster) = handler_with_fake();
        let mut env = build_fixture_env();
        let unknown = RevisionId(ulid::Ulid::from(0xFFFF_u128));

        let err = handler
            .warm_revision(&env, unknown, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DeployerError::RevisionNotFound { .. }));

        // Invalid split (sum != 10000) on deployment A.
        env.traffic_splits[0].entries[0].weight_bps = 1;
        let dep = env.bundles[0].deployment_id;
        let err = handler
            .apply_traffic_split(&env, dep, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DeployerError::InvalidSplit { .. }));

        assert!(
            cluster.objects().is_empty(),
            "rejected preconditions must not touch the cluster"
        );
    }

    /// The default handler (no cluster client wired) fails provider verbs
    /// honestly instead of pretending the work happened.
    #[tokio::test]
    async fn unconfigured_cluster_surfaces_a_provider_error() {
        let handler = K8sDeployerHandler::default();
        let env = build_fixture_env();
        let err = handler
            .warm_revision(&env, env.revisions[0].revision_id, None)
            .await
            .unwrap_err();
        match err {
            DeployerError::Provider(msg) => {
                assert!(msg.contains("no Kubernetes API client"), "msg: {msg}");
            }
            other => panic!("expected Provider, got {other:?}"),
        }
        // Pure preconditions still come first even unconfigured.
        let unknown = RevisionId(ulid::Ulid::from(0xFFFF_u128));
        assert!(matches!(
            handler
                .warm_revision(&env, unknown, None)
                .await
                .unwrap_err(),
            DeployerError::RevisionNotFound { .. }
        ));
    }
}
