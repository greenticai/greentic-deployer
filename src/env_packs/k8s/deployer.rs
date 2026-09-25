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

use std::time::Duration;

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, Revision, RevisionId};
use serde_json::Value;
use tokio::time::{Instant, sleep};

use super::K8sDeployerHandler;
use super::cluster::{K8sCluster, K8sClusterError, ObjectRef, ServiceStatus};
use super::manifests::{
    DEV_SECRETS_SECRET_NAME, K8sParams, ROUTER_NAME, SecretsBackend, ServiceType,
    has_cluster_presence, render_router_service, render_runtime_config_map,
    render_worker_manifests,
};
use crate::env_packs::deployer::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome, enforce_split_invariants, require_revision,
};
use crate::env_packs::render::ManifestRenderer;

/// Cluster failures surface as provider failures — the verb's
/// preconditions have already passed by the time the seam is touched.
pub(super) fn provider(err: K8sClusterError) -> DeployerError {
    DeployerError::Provider(err.to_string())
}

/// True for the env-level objects a namespace-scoped (bound ServiceAccount)
/// identity must not apply during reconcile: today only the cluster-scoped
/// `Namespace`. The bound deployer Role aggregates the namespaced
/// [`VALIDATED_K8S_OPERATIONS`](super::credentials::VALIDATED_K8S_OPERATIONS)
/// and grants no cluster-scoped verbs, so applying these would 403 — yet the
/// bootstrap pack already created the namespace, so dropping them is correct,
/// not a loss of desired state.
pub(super) fn is_cluster_scoped(manifest: &Value) -> bool {
    manifest.get("kind").and_then(Value::as_str) == Some("Namespace")
}

/// Build render params from the binding's wizard answers (namespace / image
/// / replicas), so a verb lands the same objects `op env render` shows. `None`
/// → sandbox defaults. A malformed answers blob fails here — before any
/// cluster call, so no partial state — surfaced as a provider error (there is
/// no typed answers-rejection variant; this mirrors `reconcile`).
pub(super) fn params_from_answers(
    env: &Environment,
    answers: Option<&Value>,
) -> Result<K8sParams, DeployerError> {
    K8sParams::from_answers(env, answers)
        .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))
}

/// Default upper bound on the warm readiness wait. A worker that has not
/// rolled out within this window fails the warm rather than letting a
/// revision promote `Warming → Ready` over a pod that never became available.
const WARM_ROLLOUT_TIMEOUT: Duration = Duration::from_secs(300);

/// Env override for [`WARM_ROLLOUT_TIMEOUT`] (whole seconds). Operators tune
/// the readiness window per workload; the kind E2E sets a short value so the
/// gate's failure path is observable without a multi-minute hang. An unset or
/// unparseable value falls back to the default.
const WARM_ROLLOUT_TIMEOUT_ENV: &str = "GREENTIC_K8S_WARM_READY_TIMEOUT_SECS";

/// Poll cadence while waiting for the worker Deployment to roll out.
const WARM_ROLLOUT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Resolve the warm readiness timeout: [`WARM_ROLLOUT_TIMEOUT_ENV`] when set
/// to a parseable seconds value, otherwise [`WARM_ROLLOUT_TIMEOUT`].
fn warm_rollout_timeout() -> Duration {
    std::env::var(WARM_ROLLOUT_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(WARM_ROLLOUT_TIMEOUT)
}

/// Block until the worker Deployment has rolled out, or fail on timeout.
///
/// "Rolled out" = the Deployment controller has observed the latest spec
/// generation AND at least `desired_replicas` are available (see
/// [`RolloutStatus::is_complete`](super::cluster::RolloutStatus::is_complete)).
/// Availability is gated by the worker pod's `/healthz` readiness probe, so
/// this one kube-level signal also covers application health — no separate
/// HTTP probe is needed here.
///
/// `timeout` / `poll_interval` are parameters (not the module consts) so the
/// unit tests can drive the loop deterministically under a paused clock.
pub(super) async fn wait_for_worker_rollout(
    cluster: &dyn K8sCluster,
    deployment: &ObjectRef,
    desired_replicas: i32,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), DeployerError> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = cluster
            .get_rollout_status(deployment)
            .await
            .map_err(provider)?;
        if status.is_complete(desired_replicas) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DeployerError::Provider(format!(
                "worker `{deployment}` did not become ready within {}s \
                 (observedGeneration {:?}/{}, updatedReplicas {}/{}, \
                 availableReplicas {}/{}, lingering old replicas {})",
                timeout.as_secs(),
                status.observed_generation,
                status.generation,
                status.updated_replicas,
                desired_replicas,
                status.available_replicas,
                desired_replicas,
                (status.replicas - status.updated_replicas).max(0),
            )));
        }
        sleep(poll_interval).await;
    }
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
    ///    apply converge by construction. The one exception is the
    ///    cluster-scoped `Namespace`: it is dropped from the applied set when
    ///    `manage_namespace` is false (a bound, namespace-scoped identity), see
    ///    below.
    /// 2. **Prune** the worker pair of every revision WITHOUT cluster presence
    ///    (archived / failed / post-drain inactive). `delete` of an absent
    ///    object is `Ok`, so pruning is idempotent and safe against a partial
    ///    prior teardown.
    ///
    /// Env-level objects are never pruned here — tearing down the namespace /
    /// router is env destruction, a separate verb. Reconcile only converges a
    /// live env.
    ///
    /// # Identity / Namespace RBAC (`manage_namespace`)
    ///
    /// The env-level set leads with the cluster-scoped `Namespace`. An ambient
    /// admin identity (`manage_namespace == true`) upserts it like everything
    /// else — the historical behaviour, so reconcile bootstraps a fresh env. A
    /// **bound** deployer identity (`op credentials bootstrap --bind`) carries a
    /// namespace-scoped Role that grants no cluster-scoped verbs, so it passes
    /// `op credentials requirements` yet would 403 on the Namespace. The CLI
    /// passes `manage_namespace == bound_token.is_none()`: when bound, the
    /// Namespace is dropped from the applied set, which is safe because a
    /// resolvable bound credential implies `bootstrap --bind` already created
    /// the namespace (its RBAC pack carries the Namespace doc). This closes the
    /// previously-documented namespace-apply-trust gap.
    ///
    /// Dropping the Namespace apply also forgoes *its* `KubeCluster::apply`
    /// ownership guard (the per-object `greentic.ai/env` label check). That is
    /// not the env's only owner check, so a bound reconcile does not fail open:
    /// the bound credential can only exist because `bootstrap --bind` already
    /// applied the Namespace through the same guard (a cross-env target
    /// fail-closes there), the minted token's RBAC confines writes to that one
    /// namespace, and every namespaced object reconcile applies still runs the
    /// guard (the bound Role grants `get`). The residual — a bound credential
    /// hand-pointed at another env's not-yet-populated namespace, bypassing
    /// `bootstrap --bind` — would need a bound-readable owner signal (e.g. a
    /// bootstrap-created ConfigMap) to preflight; that is a separate hardening
    /// slice, since the bound SA cannot read the cluster-scoped Namespace label.
    ///
    /// # Known gaps (Phase D later slices)
    ///
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
        manage_namespace: bool,
    ) -> Result<ReconcileReport, DeployerError> {
        let mut desired = self
            .render_environment(env, answers)
            .map_err(|e| DeployerError::Provider(e.to_string()))?;
        // A bound, namespace-scoped identity cannot — and need not — apply the
        // cluster-scoped Namespace (`bootstrap --bind` already created it). Drop
        // it so the bound identity can drive reconcile; the ambient admin keeps
        // upserting it. `render_environment` itself stays whole, so `op env
        // render` (GitOps handoff) still emits the full desired state.
        if !manage_namespace {
            desired.retain(|manifest| !is_cluster_scoped(manifest));
        }
        let mut applied = Vec::with_capacity(desired.len());
        for manifest in &desired {
            self.cluster.apply(manifest).await.map_err(provider)?;
            applied.push(ObjectRef::from_manifest(manifest).map_err(provider)?);
        }

        // `params` is recomputed (pure, cheap) only to render the prune set;
        // the present set already came from `render_environment` above.
        let params = params_from_answers(env, answers)?;
        let pruned = self.prune_absent(env, &params).await?;
        let router_address = self.read_router_address(env, &params).await;
        Ok(ReconcileReport {
            applied,
            pruned,
            router_address,
            sor_units: Vec::new(),
            sor_skipped_input_refs: Vec::new(),
        })
    }

    /// Delete what must not survive a converge: the stale dev-store Secret of a
    /// Vault env, and the worker pair of every revision without cluster
    /// presence. Shared by [`Self::reconcile`] and the SoR reconcile.
    pub(super) async fn prune_absent(
        &self,
        env: &Environment,
        params: &K8sParams,
    ) -> Result<Vec<ObjectRef>, DeployerError> {
        let mut pruned = Vec::new();
        // A Vault-backed env ships no secret material into the cluster, so a
        // DevStore→Vault migration must remove the stale `gtc-dev-secrets`
        // Secret — env-level objects are otherwise never pruned. Idempotent:
        // `delete` of an absent object is `Ok`, so a fresh Vault env is a no-op.
        if matches!(self.secrets_backend, SecretsBackend::Vault(_)) {
            let stale_secret = ObjectRef::from_manifest(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": DEV_SECRETS_SECRET_NAME,
                    "namespace": params.namespace,
                },
            }))
            .map_err(provider)?;
            self.cluster.delete(&stale_secret).await.map_err(provider)?;
            pruned.push(stale_secret);
        }
        for revision in &env.revisions {
            if !has_cluster_presence(revision.lifecycle) {
                for manifest in render_worker_manifests(env, revision, params) {
                    let object = ObjectRef::from_manifest(&manifest).map_err(provider)?;
                    self.cluster.delete(&object).await.map_err(provider)?;
                    pruned.push(object);
                }
            }
        }
        Ok(pruned)
    }

    /// Read the router Service back so the report can say where the env is
    /// reachable. `None` for the default `ClusterIP` — there is no external
    /// address to report, and skipping the read keeps the default path at
    /// exactly the API calls it made before this existed.
    ///
    /// Never fails the reconcile: the convergence has already succeeded by the
    /// time this runs, so a failed status read is downgraded to
    /// [`RouterAddress::Unknown`] carrying the reason. The `ObjectRef` is built
    /// from the same [`render_router_service`] the apply used, so the object
    /// read is the object written.
    pub(super) async fn read_router_address(
        &self,
        env: &Environment,
        params: &K8sParams,
    ) -> Option<RouterAddress> {
        if params.service_type == ServiceType::ClusterIp {
            return None;
        }
        let service = match ObjectRef::from_manifest(&render_router_service(env, params)) {
            Ok(object) => object,
            Err(e) => {
                return Some(RouterAddress::Unknown {
                    reason: e.to_string(),
                });
            }
        };
        Some(match self.cluster.get_service_status(&service).await {
            Ok(status) => RouterAddress::from_status(&status),
            Err(e) => RouterAddress::Unknown {
                reason: format!("could not read Service `{ROUTER_NAME}`: {e}"),
            },
        })
    }

    /// Converge, then optionally block until every applied Deployment has
    /// rolled out.
    ///
    /// `ReconcileReport` carries only `ObjectRef`s, so the desired replica
    /// count is recovered by re-rendering — pure and cheap, the same reason
    /// `reconcile` recomputes `params` for the prune set.
    pub async fn reconcile_and_wait(
        &self,
        env: &Environment,
        answers: Option<&Value>,
        manage_namespace: bool,
        wait_for_rollout: bool,
        sor: Option<&super::sor_reconcile::SorReconcile<'_>>,
    ) -> Result<ReconcileReport, DeployerError> {
        let report = match sor {
            Some(sor) => {
                self.reconcile_with_sor(env, answers, manage_namespace, sor)
                    .await?
            }
            None => self.reconcile(env, answers, manage_namespace).await?,
        };
        if !wait_for_rollout {
            return Ok(report);
        }
        let desired = self
            .render_environment(env, answers)
            .map_err(|e| DeployerError::Provider(e.to_string()))?;
        for manifest in &desired {
            if manifest.get("kind").and_then(Value::as_str) != Some("Deployment") {
                continue;
            }
            let object = ObjectRef::from_manifest(manifest).map_err(provider)?;
            if !report.applied.contains(&object) {
                continue;
            }
            let replicas = manifest
                .pointer("/spec/replicas")
                .and_then(Value::as_i64)
                .unwrap_or(1);
            wait_for_worker_rollout(
                self.cluster.as_ref(),
                &object,
                replicas as i32,
                warm_rollout_timeout(),
                WARM_ROLLOUT_POLL_INTERVAL,
            )
            .await?;
        }
        Ok(report)
    }
}

/// Where the env's router is reachable from outside the cluster, as the cluster
/// itself reports it after the reconcile's apply.
///
/// Serializes as an internally-tagged object (`{"state": "...", ...}`) so every
/// arm is a distinguishable answer rather than a string a caller has to guess
/// the meaning of. The distinction that matters, and the reason this is not an
/// `Option<String>`: a load balancer is provisioned ASYNCHRONOUSLY, so "no
/// address yet, keep asking" and "no address will ever appear here" are
/// routinely both true of the same env minutes apart, and an empty string
/// cannot tell them apart. `ClusterIP` reports nothing at all — see
/// [`ReconcileReport::router_address`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RouterAddress {
    /// The API server allocated a node port. The host half is the operator's
    /// to supply — any node's reachable IP — so only the port is reported;
    /// this deployer does not list nodes and would have to guess which of a
    /// node's addresses a caller can route to.
    NodePort { node_port: i32 },
    /// The cloud controller assigned an ingress. At least one of `hostname` /
    /// `ip` is set (AWS-style load balancers return a hostname, GCP-style an
    /// IP); both are carried rather than collapsed into one string so a caller
    /// keeps whichever its own DNS or firewall config needs.
    LoadBalancer {
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ip: Option<String>,
    },
    /// The Service was accepted and no address is assigned YET. Expected for
    /// the first seconds-to-minutes of a `LoadBalancer`; re-run `op env
    /// reconcile` (or read the Service) rather than treating it as "none".
    Pending,
    /// The Service was applied but its status could not be read back. Reported
    /// rather than raised, because the convergence itself SUCCEEDED — failing a
    /// completed reconcile over a status read would tell an operator their
    /// deploy failed when it did not. Reported rather than omitted, because
    /// silently answering "no address" for a read that never happened is the
    /// failure this whole report exists to end.
    Unknown { reason: String },
}

impl RouterAddress {
    /// Interpret a read-back [`ServiceStatus`] into one named state.
    ///
    /// `Pending` is the answer for every type whose address the cluster has not
    /// assigned — including a `NodePort` with no allocated port, which is a
    /// transient the API server closes on its own, not a permanent "none".
    pub fn from_status(status: &ServiceStatus) -> Self {
        match status.service_type.as_str() {
            "NodePort" => match status.node_port {
                Some(node_port) => Self::NodePort { node_port },
                None => Self::Pending,
            },
            "LoadBalancer" => {
                if status.ingress_hostname.is_some() || status.ingress_ip.is_some() {
                    Self::LoadBalancer {
                        hostname: status.ingress_hostname.clone(),
                        ip: status.ingress_ip.clone(),
                    }
                } else {
                    Self::Pending
                }
            }
            // Includes `ClusterIP` and any type this build does not model: the
            // caller only asks after selecting an externally-exposed type, so
            // reaching here means the live object disagrees with what was
            // applied. That is worth naming, not silently reporting as pending.
            other => Self::Unknown {
                reason: format!("router Service reports spec.type `{other}`"),
            },
        }
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
    /// Where the router is reachable from outside the cluster, when the env
    /// asked to be ([`ServiceType::NodePort`] / [`ServiceType::LoadBalancer`]).
    ///
    /// `None` for the default [`ServiceType::ClusterIp`], and it is
    /// skipped on the wire: an env that never answered `service_type` produces
    /// a byte-identical reconcile report to the one it produced before this
    /// field existed. `None` therefore means "no external address was asked
    /// for" — never "asked for and not found", which is
    /// [`RouterAddress::Pending`], nor "asked for and unreadable", which is
    /// [`RouterAddress::Unknown`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router_address: Option<RouterAddress>,
    /// The SoR units this reconcile brought up (contract C3). Skipped on the
    /// wire when empty, so an env without SoR units reports exactly what it
    /// reported before. `ready` is always `true` here: a unit that is not
    /// Available fails the reconcile instead.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sor_units: Vec<super::sor_reconcile::SorUnitStatus>,
    /// Stale SoR input rel-paths reconcile did NOT delete because they lie
    /// outside their unit's own `sor-<unit_id>/` segment. Paths only, never a
    /// value; skipped on the wire when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sor_skipped_input_refs: Vec<String>,
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
        let mut params = params_from_answers(env, answers)?;
        // A single-revision warm renders the worker's secrets identity from the
        // handler's resolved backend (the CLI injects it via
        // `with_secrets_backend`), matching `reconcile` / `op env render` —
        // otherwise a Vault env's warm would emit a DevStore-shaped worker.
        params.secrets_backend = self.secrets_backend.clone();
        let manifests = render_worker_manifests(env, revision, &params);
        self.apply_all(&manifests).await?;

        // The API server has accepted the worker manifests; the revision is
        // only Ready once the Deployment has actually rolled out. Wait on the
        // worker Deployment's status — observed generation caught up + the pod
        // available (which means it passed its `/healthz` readiness probe) —
        // before reporting warm complete. A worker that never becomes
        // available fails the warm, so the operator sees the rollout stall
        // instead of a revision silently promoted Warming → Ready over a
        // non-serving pod. `op env reconcile` and `op env apply-revision` both
        // inherit this wait through the verb.
        // `render_worker_manifests` yields the worker Deployment first, then
        // its Service (its documented, tested order), so index 0 is the
        // rollout-bearing object.
        let deployment = &manifests[0];
        // The worker Deployment renders a fixed replica count; a Deployment
        // with no `spec.replicas` defaults to 1 under K8s semantics.
        let desired_replicas = deployment
            .pointer("/spec/replicas")
            .and_then(Value::as_i64)
            .unwrap_or(1) as i32;
        let deployment_ref = ObjectRef::from_manifest(deployment).map_err(provider)?;
        wait_for_worker_rollout(
            self.cluster.as_ref(),
            &deployment_ref,
            desired_replicas,
            warm_rollout_timeout(),
            WARM_ROLLOUT_POLL_INTERVAL,
        )
        .await?;

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
    use crate::env_packs::k8s::cluster::{InMemoryCluster, K8sCluster, RolloutStatus};
    use crate::env_packs::k8s::manifests::{RUNTIME_CONFIG_MAP_NAME, worker_name};

    fn handler_with_fake() -> (K8sDeployerHandler, Arc<InMemoryCluster>) {
        let cluster = Arc::new(InMemoryCluster::default());
        (K8sDeployerHandler::with_cluster(cluster.clone()), cluster)
    }

    /// A cluster fake whose rollout reports "not ready" for the first
    /// `ready_after` polls of `get_rollout_status`, then complete. apply /
    /// delete are no-ops — these tests exercise only the readiness wait.
    #[derive(Debug)]
    struct ScriptedRolloutCluster {
        ready_after: usize,
        polls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl K8sCluster for ScriptedRolloutCluster {
        async fn apply(&self, _manifest: &Value) -> Result<(), K8sClusterError> {
            Ok(())
        }

        async fn delete(&self, _object: &ObjectRef) -> Result<(), K8sClusterError> {
            Ok(())
        }

        async fn get_rollout_status(
            &self,
            _deployment: &ObjectRef,
        ) -> Result<RolloutStatus, K8sClusterError> {
            let n = self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // The new worker pod is created (updated == 1, no old replicas
            // linger); it only flips to available after `ready_after` polls.
            let available = if n >= self.ready_after { 1 } else { 0 };
            Ok(RolloutStatus {
                generation: 1,
                observed_generation: Some(1),
                replicas: 1,
                updated_replicas: 1,
                available_replicas: available,
            })
        }

        async fn get_service_status(
            &self,
            _service: &ObjectRef,
        ) -> Result<ServiceStatus, K8sClusterError> {
            // These tests exercise only the readiness wait.
            unreachable!("the rollout-wait tests never read a Service status")
        }
    }

    fn worker_deployment_ref() -> ObjectRef {
        ObjectRef {
            api_version: "apps/v1".into(),
            kind: "Deployment".into(),
            namespace: Some("gtc-local".into()),
            name: "gtc-worker-x".into(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn warm_rollout_wait_resolves_once_the_worker_becomes_available() {
        let cluster = ScriptedRolloutCluster {
            ready_after: 3,
            polls: std::sync::atomic::AtomicUsize::new(0),
        };
        wait_for_worker_rollout(
            &cluster,
            &worker_deployment_ref(),
            1,
            Duration::from_secs(60),
            Duration::from_secs(2),
        )
        .await
        .expect("rollout completes once the replica is available");
        assert!(
            cluster.polls.load(std::sync::atomic::Ordering::SeqCst) >= 4,
            "must keep polling until the worker reports available"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn warm_rollout_wait_fails_when_the_worker_never_becomes_ready() {
        let cluster = ScriptedRolloutCluster {
            ready_after: usize::MAX,
            polls: std::sync::atomic::AtomicUsize::new(0),
        };
        let err = wait_for_worker_rollout(
            &cluster,
            &worker_deployment_ref(),
            1,
            Duration::from_secs(10),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        match err {
            DeployerError::Provider(msg) => {
                assert!(msg.contains("did not become ready"), "msg: {msg}");
                assert!(msg.contains("availableReplicas 0/1"), "msg: {msg}");
            }
            other => panic!("expected a Provider timeout error, got {other:?}"),
        }
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

        let report = handler.reconcile(&env, None, true).await.unwrap();

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
        let report2 = handler.reconcile(&env, None, true).await.unwrap();
        assert_eq!(report2.applied.len(), desired.len());
        assert_eq!(cluster.objects(), before, "reconcile is idempotent");
    }

    #[tokio::test]
    async fn reconcile_bound_identity_skips_the_cluster_scoped_namespace() {
        let (handler, cluster) = handler_with_fake();
        let env = build_fixture_env();

        // A bound, namespace-scoped identity (`manage_namespace == false`) applies
        // the full desired state minus exactly the cluster-scoped Namespace.
        let full = handler.render_environment(&env, None).unwrap();
        assert!(
            full.iter().any(is_cluster_scoped),
            "precondition: the env-level set carries a cluster-scoped Namespace to drop"
        );
        let report = handler.reconcile(&env, None, false).await.unwrap();
        assert_eq!(report.applied.len(), full.len() - 1);

        // Ground truth: the cluster never received a Namespace apply, so the
        // bound identity drove the rest of reconcile without the one object its
        // Role cannot touch.
        assert!(
            !cluster.objects().keys().any(|o| o.kind == "Namespace"),
            "a bound identity must not apply the cluster-scoped Namespace"
        );

        // Idempotent: a second bound reconcile leaves identical cluster state.
        let before = cluster.objects();
        let report2 = handler.reconcile(&env, None, false).await.unwrap();
        assert_eq!(report2.applied.len(), full.len() - 1);
        assert_eq!(cluster.objects(), before, "bound reconcile is idempotent");
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

        handler.reconcile(&env, None, true).await.unwrap();

        assert!(
            !cluster.objects().keys().any(|o| o.name == lingering),
            "reconcile prunes the now-absent revision's workers"
        );
    }

    /// A cluster fake that applies/deletes normally (delegating to the
    /// in-memory store) but answers `get_service_status` from a script — the
    /// allocated nodePort and the LB ingress are assigned by the API server and
    /// the cloud controller, so nothing in an applied manifest can produce them.
    #[derive(Debug)]
    struct AddressedCluster {
        inner: InMemoryCluster,
        status: ServiceStatus,
    }

    #[async_trait]
    impl K8sCluster for AddressedCluster {
        async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError> {
            self.inner.apply(manifest).await
        }

        async fn delete(&self, object: &ObjectRef) -> Result<(), K8sClusterError> {
            self.inner.delete(object).await
        }

        async fn get_rollout_status(
            &self,
            deployment: &ObjectRef,
        ) -> Result<RolloutStatus, K8sClusterError> {
            self.inner.get_rollout_status(deployment).await
        }

        async fn get_service_status(
            &self,
            _service: &ObjectRef,
        ) -> Result<ServiceStatus, K8sClusterError> {
            Ok(self.status.clone())
        }
    }

    /// A cluster fake whose status read always fails, for the
    /// "convergence succeeded, the address read did not" path.
    #[derive(Debug)]
    struct UnreadableServiceCluster(InMemoryCluster);

    #[async_trait]
    impl K8sCluster for UnreadableServiceCluster {
        async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError> {
            self.0.apply(manifest).await
        }

        async fn delete(&self, object: &ObjectRef) -> Result<(), K8sClusterError> {
            self.0.delete(object).await
        }

        async fn get_rollout_status(
            &self,
            deployment: &ObjectRef,
        ) -> Result<RolloutStatus, K8sClusterError> {
            self.0.get_rollout_status(deployment).await
        }

        async fn get_service_status(
            &self,
            _service: &ObjectRef,
        ) -> Result<ServiceStatus, K8sClusterError> {
            Err(K8sClusterError::Api("connection reset".to_string()))
        }
    }

    fn service_type_answers(service_type: &str) -> Value {
        serde_json::json!({"service_type": service_type})
    }

    #[test]
    fn router_address_reads_an_allocated_node_port() {
        let status = ServiceStatus {
            service_type: "NodePort".to_string(),
            node_port: Some(31234),
            ..Default::default()
        };
        assert_eq!(
            RouterAddress::from_status(&status),
            RouterAddress::NodePort { node_port: 31234 }
        );
    }

    #[test]
    fn router_address_reads_both_load_balancer_ingress_shapes() {
        // AWS-style load balancers assign a hostname, GCP-style an IP; both are
        // carried through rather than collapsed into one string.
        let hostname = ServiceStatus {
            service_type: "LoadBalancer".to_string(),
            ingress_hostname: Some("a1b2.elb.amazonaws.com".to_string()),
            ..Default::default()
        };
        assert_eq!(
            RouterAddress::from_status(&hostname),
            RouterAddress::LoadBalancer {
                hostname: Some("a1b2.elb.amazonaws.com".to_string()),
                ip: None,
            }
        );
        let ip = ServiceStatus {
            service_type: "LoadBalancer".to_string(),
            ingress_ip: Some("34.1.2.3".to_string()),
            ..Default::default()
        };
        assert_eq!(
            RouterAddress::from_status(&ip),
            RouterAddress::LoadBalancer {
                hostname: None,
                ip: Some("34.1.2.3".to_string()),
            }
        );
    }

    /// The distinction the whole report exists for: an address that has not
    /// been assigned YET must not read as an address that will never exist.
    #[test]
    fn router_address_reports_an_unassigned_address_as_pending() {
        for service_type in ["LoadBalancer", "NodePort"] {
            let status = ServiceStatus {
                service_type: service_type.to_string(),
                ..Default::default()
            };
            assert_eq!(
                RouterAddress::from_status(&status),
                RouterAddress::Pending,
                "{service_type} with nothing assigned is pending"
            );
        }
    }

    /// Reaching here means the live object disagrees with the type that was
    /// applied — worth naming rather than silently reporting as pending.
    #[test]
    fn router_address_names_an_unexposed_live_service() {
        let status = ServiceStatus {
            service_type: "ClusterIP".to_string(),
            ..Default::default()
        };
        assert!(matches!(
            RouterAddress::from_status(&status),
            RouterAddress::Unknown { .. }
        ));
    }

    /// The default path must make no extra API call and add no wire field, so a
    /// reconcile that never answered `service_type` is byte-identical to the
    /// one it produced before this shipped.
    #[tokio::test]
    async fn reconcile_reports_no_router_address_by_default() {
        let (handler, _cluster) = handler_with_fake();
        let env = build_fixture_env();
        let report = handler.reconcile(&env, None, true).await.unwrap();
        assert_eq!(report.router_address, None);
        let wire = serde_json::to_value(&report).unwrap();
        assert!(
            wire.get("router_address").is_none(),
            "the default report carries no router_address key: {wire}"
        );
    }

    #[tokio::test]
    async fn reconcile_reports_the_routers_allocated_node_port() {
        let cluster = Arc::new(AddressedCluster {
            inner: InMemoryCluster::default(),
            status: ServiceStatus {
                service_type: "NodePort".to_string(),
                node_port: Some(30987),
                ..Default::default()
            },
        });
        let handler = K8sDeployerHandler::with_cluster(cluster);
        let env = build_fixture_env();
        let report = handler
            .reconcile(&env, Some(&service_type_answers("NodePort")), true)
            .await
            .unwrap();
        assert_eq!(
            report.router_address,
            Some(RouterAddress::NodePort { node_port: 30987 })
        );
    }

    /// End-to-end through the in-memory fake, which applies the `LoadBalancer`
    /// Service and provisions nothing — exactly the state of a real cluster for
    /// the first seconds-to-minutes after the apply.
    #[tokio::test]
    async fn reconcile_reports_a_not_yet_provisioned_load_balancer_as_pending() {
        let (handler, _cluster) = handler_with_fake();
        let env = build_fixture_env();
        let report = handler
            .reconcile(&env, Some(&service_type_answers("LoadBalancer")), true)
            .await
            .unwrap();
        assert_eq!(report.router_address, Some(RouterAddress::Pending));
        let wire = serde_json::to_value(&report).unwrap();
        assert_eq!(
            wire.pointer("/router_address/state")
                .and_then(Value::as_str),
            Some("pending"),
            "pending must be a distinguishable wire state: {wire}"
        );
    }

    /// A failed status read must not fail a convergence that succeeded — and
    /// must not be reported as "no address" either.
    #[tokio::test]
    async fn an_unreadable_router_service_is_reported_not_raised() {
        let cluster = Arc::new(UnreadableServiceCluster(InMemoryCluster::default()));
        let handler = K8sDeployerHandler::with_cluster(cluster);
        let env = build_fixture_env();
        let report = handler
            .reconcile(&env, Some(&service_type_answers("LoadBalancer")), true)
            .await
            .expect("a failed address read must not fail the reconcile");
        match report.router_address {
            Some(RouterAddress::Unknown { reason }) => {
                assert!(
                    reason.contains(ROUTER_NAME),
                    "reason names the object: {reason}"
                );
                assert!(
                    reason.contains("connection reset"),
                    "reason carries the cause: {reason}"
                );
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    /// A Vault backend whose connection config matches the provider defaults.
    fn vault_secrets_backend() -> SecretsBackend {
        use crate::env_packs::k8s::manifests::VaultBackend;
        SecretsBackend::Vault(VaultBackend {
            addr: "http://vault.vault.svc:8200".to_string(),
            k8s_role: "greentic-worker".to_string(),
            kv_mount: "secret".to_string(),
            kv_prefix: "greentic".to_string(),
            auth_mount: "kubernetes".to_string(),
            transit_mount: "transit".to_string(),
            transit_key: "greentic".to_string(),
            namespace: None,
        })
    }

    #[tokio::test]
    async fn warm_revision_renders_the_vault_worker_identity() {
        let (handler, cluster) = handler_with_fake();
        let handler = handler.with_secrets_backend(vault_secrets_backend());
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();

        // The single-revision warm must render the Vault worker (SA + selector),
        // not a default DevStore-shaped worker.
        let objects = cluster.objects();
        let (_, deployment) = objects
            .iter()
            .find(|(o, _)| o.kind == "Deployment")
            .expect("worker Deployment applied");
        let pod = &deployment["spec"]["template"]["spec"];
        assert_eq!(
            pod["serviceAccountName"],
            crate::env_packs::k8s::manifests::WORKER_SERVICE_ACCOUNT
        );
        let envs = pod["containers"][0]["env"].as_array().unwrap();
        assert!(
            envs.iter()
                .any(|e| e["name"] == "GREENTIC_SECRETS_BACKEND" && e["value"] == "vault"),
            "warm worker must carry the Vault backend selector"
        );
    }

    #[tokio::test]
    async fn vault_reconcile_removes_a_stale_dev_store_secret() {
        use crate::env_packs::k8s::manifests::DEV_SECRETS_SECRET_NAME;
        let (handler, cluster) = handler_with_fake();
        let handler = handler.with_secrets_backend(vault_secrets_backend());
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);

        // Simulate a prior DevStore reconcile that left the dev-store Secret
        // (with material) behind; migrating to Vault must remove it.
        cluster
            .apply(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": DEV_SECRETS_SECRET_NAME,
                    "namespace": params.namespace,
                    "labels": {"greentic.ai/env": env.environment_id.as_str()},
                },
                "data": {".dev.secrets.env": "c2VjcmV0"},
            }))
            .await
            .unwrap();
        assert!(
            cluster
                .objects()
                .keys()
                .any(|o| o.kind == "Secret" && o.name == DEV_SECRETS_SECRET_NAME),
            "precondition: the stale dev-store Secret is on the cluster"
        );

        let report = handler.reconcile(&env, None, true).await.unwrap();

        assert!(
            !cluster.objects().keys().any(|o| o.kind == "Secret"),
            "a Vault reconcile must remove the stale dev-store Secret (no material lingers)"
        );
        assert!(
            report
                .pruned
                .iter()
                .any(|o| o.kind == "Secret" && o.name == DEV_SECRETS_SECRET_NAME),
            "the Secret deletion is reported in the prune set"
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

    #[tokio::test]
    async fn reconcile_and_wait_skips_polling_when_wait_is_false() {
        let cluster = Arc::new(ScriptedRolloutCluster {
            ready_after: usize::MAX,
            polls: std::sync::atomic::AtomicUsize::new(0),
        });
        let handler = K8sDeployerHandler::with_cluster(cluster.clone());
        let env = build_fixture_env();

        let report = handler
            .reconcile_and_wait(&env, None, true, false, None)
            .await
            .expect("wait_for_rollout=false must not poll");
        assert!(
            !report.applied.is_empty(),
            "reconcile still applies the desired state"
        );
        assert_eq!(
            cluster.polls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no rollout polls when wait_for_rollout is false"
        );
    }

    #[tokio::test]
    async fn reconcile_and_wait_returns_immediately_when_already_ready() {
        // InMemoryCluster reports i32::MAX for all replica fields, so every
        // Deployment is "already ready" and the rollout wait resolves on the
        // first poll without spinning.
        let (handler, _cluster) = handler_with_fake();
        let env = build_fixture_env();

        let report = handler
            .reconcile_and_wait(&env, None, true, true, None)
            .await
            .expect("already-ready Deployments resolve on the first poll");
        assert!(
            !report.applied.is_empty(),
            "reconcile applies desired state"
        );
        assert!(
            report.applied.iter().any(|o| o.kind == "Deployment"),
            "at least one Deployment was applied and waited on"
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
