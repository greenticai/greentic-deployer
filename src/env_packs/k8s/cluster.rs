//! Cluster-side-effect seam for the K8s deployer env-pack.
//!
//! [`K8sCluster`] is the narrow surface the [`Deployer`](super::deployer)
//! verbs mutate Kubernetes through: declarative `apply` (server-side
//! upsert) and idempotent `delete`. Keeping the seam this small does two
//! things:
//!
//! - The manifest computation in [`super::manifests`] stays pure and
//!   testable without a cluster — the conformance bench runs against an
//!   in-memory fake and exercises the REAL desired-state logic.
//! - The typed Kubernetes client lands as one impl of this trait
//!   ([`KubeCluster`](super::kube_client::KubeCluster), `k8s-client`
//!   feature) without touching the verbs.
//!
//! The default binding is [`UnconfiguredCluster`]: every call fails with
//! [`K8sClusterError::Unconfigured`]. That is the honest answer until
//! the PR-5.3 orchestration wiring constructs a connected client from
//! the binding's answers — a `revisions warm` against a K8s-bound env
//! surfaces "no cluster client configured" instead of pretending
//! provider work happened.

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

/// Identity of one Kubernetes object — enough to delete it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct ObjectRef {
    pub api_version: String,
    pub kind: String,
    /// `None` for cluster-scoped objects (e.g. the env's `Namespace`).
    pub namespace: Option<String>,
    pub name: String,
}

impl ObjectRef {
    /// Extract the identity fields from a rendered manifest.
    ///
    /// `apiVersion`, `kind`, and `metadata.name` are required — a manifest
    /// missing one is a render bug, surfaced as
    /// [`K8sClusterError::InvalidManifest`] rather than panicking inside a
    /// deployer verb. `metadata.namespace` is OPTIONAL: cluster-scoped kinds
    /// (the env's `Namespace`) legitimately omit it, so an absent namespace
    /// is recorded as `None`, not an error. Namespaced kinds always carry it
    /// (renderer-guaranteed), and the real client's apply re-reads it for
    /// namespaced scope, so the render-bug guard is preserved where it bites.
    pub fn from_manifest(manifest: &Value) -> Result<Self, K8sClusterError> {
        Ok(Self {
            api_version: manifest_field(manifest, &["apiVersion"])?,
            kind: manifest_field(manifest, &["kind"])?,
            namespace: manifest
                .get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(Value::as_str)
                .map(str::to_string),
            name: manifest_field(manifest, &["metadata", "name"])?,
        })
    }
}

/// Read a required string field from a rendered manifest by JSON path.
///
/// Shared by [`ObjectRef::from_manifest`] and the kube client's
/// `api_for`; a missing or non-string field is a render bug, surfaced as
/// [`K8sClusterError::InvalidManifest`].
pub(super) fn manifest_field(manifest: &Value, path: &[&str]) -> Result<String, K8sClusterError> {
    let mut cur = manifest;
    for p in path {
        cur = cur.get(p).ok_or_else(|| {
            K8sClusterError::InvalidManifest(format!("manifest is missing `{}`", path.join(".")))
        })?;
    }
    cur.as_str().map(str::to_string).ok_or_else(|| {
        K8sClusterError::InvalidManifest(format!("`{}` is not a string", path.join(".")))
    })
}

impl std::fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.namespace {
            Some(ns) => write!(f, "{}/{} {}/{}", self.api_version, self.kind, ns, self.name),
            None => write!(f, "{}/{} {}", self.api_version, self.kind, self.name),
        }
    }
}

/// What can go wrong talking to the cluster. All variants flow into
/// [`DeployerError::Provider`](crate::env_packs::deployer::DeployerError::Provider)
/// at the verb boundary — the trait does not distinguish transport from
/// auth failures because the operator's fix path is the same (fix the
/// client config / cluster access, re-run the verb).
#[derive(Debug, Error)]
pub enum K8sClusterError {
    /// No API client is bound. The handler's default — the typed client
    /// exists ([`KubeCluster`](super::kube_client::KubeCluster)) but the
    /// PR-5.3 orchestration wiring constructs and binds it.
    #[error(
        "no Kubernetes API client is bound to the K8s deployer env-pack; \
         binding a connected cluster client rides the Phase D orchestration \
         wiring (PR-5.3) — until then K8s provider verbs cannot run"
    )]
    Unconfigured,
    /// The rendered manifest was missing identity fields — a render bug.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    /// The Kubernetes API rejected the call.
    #[error("Kubernetes API error: {0}")]
    Api(String),
    /// Refusing to overwrite an object owned by a different environment.
    #[error(
        "refusing to apply `{object}` in namespace `{namespace}`: \
         it is owned by env `{existing_env}` but this apply belongs to env `{incoming_env}`"
    )]
    OwnershipConflict {
        object: String,
        namespace: String,
        existing_env: String,
        incoming_env: String,
    },
    /// Refusing to take over an object this deployer did not create (it lacks
    /// the deployer's owner labels). Raised for kinds a forced apply must never
    /// adopt (`refuse_adoption`).
    #[error(
        "refusing to apply {kind} `{object}` in namespace `{namespace}`: an object of that \
         name already exists that this deployer did not create (it lacks the deployer's \
         owner labels) — rename or remove it, or clear the answer that renders it \
         (`ingress_host` for the Ingress)"
    )]
    UnmanagedObject {
        kind: String,
        object: String,
        namespace: String,
    },
}

/// Kinds a forced server-side apply must never adopt from someone else. The
/// Ingress publishes the environment on a public hostname, and adopting an
/// operator's `gtc-router` Ingress would replace their routing wholesale and
/// stamp our owner labels on it — making it deletable by
/// `ingress_prune` later.
#[cfg(any(test, feature = "k8s-client"))]
const NEVER_ADOPTED_KINDS: &[&str] = &["Ingress"];

/// Refuse to apply `manifest` over an existing object of a never-adopted kind
/// unless the existing object already carries every label `manifest` does
/// (i.e. this deployer created it). `existing_labels` is the existing object's
/// `metadata.labels` (`None`/`null` when it has none). Shared by every
/// [`K8sCluster`] impl so the fake and the real client refuse identically.
#[cfg(any(test, feature = "k8s-client"))]
pub(crate) fn refuse_adoption(
    manifest: &Value,
    existing_labels: Option<&Value>,
) -> Result<(), K8sClusterError> {
    let kind = manifest
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !NEVER_ADOPTED_KINDS.contains(&kind) {
        return Ok(());
    }
    let incoming = manifest
        .pointer("/metadata/labels")
        .and_then(Value::as_object);
    let owned = incoming.is_some_and(|incoming| {
        incoming
            .iter()
            .all(|(key, value)| existing_labels.and_then(|labels| labels.get(key)) == Some(value))
    });
    if owned {
        return Ok(());
    }
    let field = |pointer: &str| {
        manifest
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Err(K8sClusterError::UnmanagedObject {
        kind: kind.to_string(),
        object: field("/metadata/name"),
        namespace: field("/metadata/namespace"),
    })
}

/// A worker Deployment's rollout progress, read for the warm readiness wait.
///
/// The fields mirror what `kubectl rollout status` inspects: the controller
/// must have observed the latest spec generation, the NEW pod template must
/// have produced and made available enough replicas, and no old-ReplicaSet
/// replicas may linger. Availability is the count of pods passing their
/// readiness probe — for the worker pod that probe is its `/healthz`
/// endpoint, so this kube-level signal also covers application health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolloutStatus {
    /// `.metadata.generation` — the spec generation the API server persisted.
    pub generation: i64,
    /// `.status.observedGeneration` — the generation the Deployment
    /// controller has reconciled up to. `None` until it first writes status.
    pub observed_generation: Option<i64>,
    /// `.status.replicas` — total non-terminated pods the Deployment manages,
    /// across the old and new ReplicaSets. An absent field reads as `0`.
    pub replicas: i32,
    /// `.status.updatedReplicas` — pods produced by the CURRENT pod template.
    /// During a rolling update this lags `replicas` until the new ReplicaSet
    /// has fully scaled up; it is what proves a changed worker spec is live.
    /// An absent field reads as `0`.
    pub updated_replicas: i32,
    /// `.status.availableReplicas` — replicas passing their readiness probe.
    /// An absent field reads as `0`.
    pub available_replicas: i32,
}

impl RolloutStatus {
    /// A rollout is complete on the same terms as `kubectl rollout status`:
    /// - the controller has observed the latest spec generation (a status
    ///   with no `observedGeneration` yet is never complete),
    /// - the new pod template has produced at least `desired` replicas
    ///   (`updated_replicas`), so a changed image/template is actually live,
    /// - no old-ReplicaSet replicas linger (`replicas <= updated_replicas`),
    ///   so `available_replicas` cannot be satisfied by stale pods, and
    /// - at least `desired` replicas are available (readiness-probe-passing).
    ///
    /// The `updated_replicas` / `replicas` checks are what stop a re-warm with
    /// a changed worker spec from reporting success while the old ReplicaSet is
    /// still the only thing serving (surge brings the new pod up before the old
    /// one is torn down, so `available_replicas` alone is not enough).
    pub fn is_complete(&self, desired: i32) -> bool {
        self.observed_generation
            .is_some_and(|observed| observed >= self.generation)
            && self.updated_replicas >= desired
            && self.replicas <= self.updated_replicas
            && self.available_replicas >= desired
    }
}

/// What the API server reports about a Service's exposure, read back after the
/// apply so the reconcile can tell the operator where the env is reachable.
///
/// The fields are the raw readback, not a verdict: the `NodePort` allocation
/// and the `LoadBalancer` ingress are assigned by the API server and the cloud
/// controller respectively, so neither is knowable from the manifest that was
/// applied. Turning them into one named state is
/// [`RouterAddress::from_status`](super::deployer::RouterAddress::from_status) —
/// the same split as [`RolloutStatus`] and its `is_complete` policy, so the
/// interpretation stays pure and unit-testable without a cluster.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceStatus {
    /// `.spec.type` as the API server recorded it. Read back rather than
    /// assumed from the applied manifest: a Service that already existed under
    /// a different type is reconciled by the apply, and reporting the type we
    /// SENT would describe an object we had not confirmed.
    pub service_type: String,
    /// `.spec.ports[].nodePort` for the `http` port — allocated by the API
    /// server for `NodePort` and `LoadBalancer`, absent for `ClusterIP`.
    pub node_port: Option<i32>,
    /// `.status.loadBalancer.ingress[0].hostname` — what AWS-style load
    /// balancers assign. `None` while provisioning, and for non-LB types.
    pub ingress_hostname: Option<String>,
    /// `.status.loadBalancer.ingress[0].ip` — what GCP-style load balancers
    /// assign. `None` while provisioning, and for non-LB types.
    pub ingress_ip: Option<String>,
}

/// One object [`K8sCluster::list`] returned, with the labels it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabeledObject {
    pub object: ObjectRef,
    pub labels: std::collections::BTreeMap<String, String>,
}

/// Declarative mutation surface against one cluster.
///
/// ## Idempotency contract
///
/// - [`apply`](Self::apply) is an upsert: applying the same manifest
///   twice MUST succeed twice and leave the cluster equivalent
///   (server-side apply semantics).
/// - [`delete`](Self::delete) of an absent object MUST return `Ok(())` —
///   a retried `archive_revision` is safe against already-torn-down
///   resources (the trait-level contract on
///   [`Deployer::archive_revision`](crate::env_packs::deployer::Deployer::archive_revision)).
#[async_trait]
pub trait K8sCluster: std::fmt::Debug + Send + Sync {
    /// Upsert one rendered manifest.
    async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError>;

    /// Delete one object; absent is `Ok`.
    async fn delete(&self, object: &ObjectRef) -> Result<(), K8sClusterError>;

    /// Delete `object` ONLY if it exists and carries every `(key, value)` in
    /// `labels`; `Ok(true)` when something was deleted. An absent object, one
    /// missing any label (e.g. created by an operator), or one this identity
    /// may not read is left alone and answers `Ok(false)`.
    ///
    /// The default never deletes: a cluster that cannot read labels must not
    /// remove anything on their strength.
    async fn delete_if_labeled(
        &self,
        _object: &ObjectRef,
        _labels: &[(&str, &str)],
    ) -> Result<bool, K8sClusterError> {
        Ok(false)
    }

    /// Read a worker Deployment's [`RolloutStatus`] for the warm readiness
    /// wait. Called only after [`apply`](Self::apply) has accepted the
    /// Deployment, so the object is expected to exist.
    async fn get_rollout_status(
        &self,
        deployment: &ObjectRef,
    ) -> Result<RolloutStatus, K8sClusterError>;

    /// Read a Service's [`ServiceStatus`] so the reconcile can report where the
    /// env is reachable. Called only after [`apply`](Self::apply) has accepted
    /// the Service, so the object is expected to exist.
    ///
    /// Needs no RBAC beyond what the deployer already holds: `services` `get`
    /// is in
    /// [`VALIDATED_K8S_OPERATIONS`](super::credentials::VALIDATED_K8S_OPERATIONS)
    /// and in the Role the bootstrap rules pack mints, so an env bound before
    /// this method existed can serve it with its existing credential.
    async fn get_service_status(
        &self,
        service: &ObjectRef,
    ) -> Result<ServiceStatus, K8sClusterError>;

    /// List the worker `Deployment`s and `Service`s in `namespace` matching
    /// `label_selector` (a Kubernetes equality selector, `k=v,k2=v2`). The
    /// orphan sweep's read: it only ever asks for the deployer's own labels,
    /// so an unlabeled object can never be returned. Needs `list` on
    /// `deployments` / `services`, which the bootstrap Role does not grant —
    /// see `op env sweep`. Default: unconfigured.
    async fn list(
        &self,
        namespace: &str,
        label_selector: &str,
    ) -> Result<Vec<LabeledObject>, K8sClusterError> {
        let _ = (namespace, label_selector);
        Err(K8sClusterError::Unconfigured)
    }

    /// Set a Deployment's `spec.replicas` (the drain's stop step). `Ok(false)`
    /// when the Deployment does not exist — nothing to stop. Default:
    /// unconfigured.
    async fn scale_deployment(
        &self,
        deployment: &ObjectRef,
        replicas: i32,
    ) -> Result<bool, K8sClusterError> {
        let _ = (deployment, replicas);
        Err(K8sClusterError::Unconfigured)
    }

    /// Read one object back as JSON; `None` when absent. The drain reads the
    /// router's runtime-config ConfigMap through it (`configmaps get` is in
    /// the bound Role). Default: unconfigured.
    async fn get_object(&self, object: &ObjectRef) -> Result<Option<Value>, K8sClusterError> {
        let _ = object;
        Err(K8sClusterError::Unconfigured)
    }

    /// [`Self::get_rollout_status`] that reports an absent Deployment as
    /// `None` rather than an error — the drain probe, where "gone" is a
    /// drained answer. Default: unconfigured.
    async fn get_rollout_status_opt(
        &self,
        deployment: &ObjectRef,
    ) -> Result<Option<RolloutStatus>, K8sClusterError> {
        let _ = deployment;
        Err(K8sClusterError::Unconfigured)
    }
}

/// The scaffold default: no client wired, every call fails honestly.
#[derive(Debug, Default)]
pub struct UnconfiguredCluster;

#[async_trait]
impl K8sCluster for UnconfiguredCluster {
    async fn apply(&self, _manifest: &Value) -> Result<(), K8sClusterError> {
        Err(K8sClusterError::Unconfigured)
    }

    async fn delete(&self, _object: &ObjectRef) -> Result<(), K8sClusterError> {
        Err(K8sClusterError::Unconfigured)
    }

    async fn get_rollout_status(
        &self,
        _deployment: &ObjectRef,
    ) -> Result<RolloutStatus, K8sClusterError> {
        Err(K8sClusterError::Unconfigured)
    }

    async fn get_service_status(
        &self,
        _service: &ObjectRef,
    ) -> Result<ServiceStatus, K8sClusterError> {
        Err(K8sClusterError::Unconfigured)
    }
}

#[cfg(test)]
pub use super::cluster_fake::InMemoryCluster;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "svc-a", "namespace": "ns-a"},
        })
    }

    #[test]
    fn rollout_complete_when_observed_and_replicas_meet_desired() {
        let s = RolloutStatus {
            generation: 3,
            observed_generation: Some(3),
            replicas: 1,
            updated_replicas: 1,
            available_replicas: 1,
        };
        assert!(s.is_complete(1));
    }

    #[test]
    fn rollout_incomplete_until_controller_observes_latest_generation() {
        // A fresh apply bumped generation to 4; the controller is still on 3.
        let s = RolloutStatus {
            generation: 4,
            observed_generation: Some(3),
            replicas: 1,
            updated_replicas: 1,
            available_replicas: 1,
        };
        assert!(!s.is_complete(1));
    }

    #[test]
    fn rollout_incomplete_when_no_status_written_yet() {
        let s = RolloutStatus {
            generation: 1,
            observed_generation: None,
            replicas: 0,
            updated_replicas: 0,
            available_replicas: 0,
        };
        assert!(!s.is_complete(1));
    }

    #[test]
    fn rollout_incomplete_when_available_replicas_below_desired() {
        let s = RolloutStatus {
            generation: 2,
            observed_generation: Some(2),
            replicas: 1,
            updated_replicas: 1,
            available_replicas: 0,
        };
        assert!(!s.is_complete(1));
    }

    #[test]
    fn rollout_incomplete_when_only_old_replicaset_is_available() {
        // Rolling update in flight: the controller is current and one OLD-RS
        // pod is still available, but the new template has produced no replicas
        // (`updated_replicas == 0`). Availability from the old ReplicaSet must
        // NOT pass the gate — the new worker spec is not live yet.
        let s = RolloutStatus {
            generation: 2,
            observed_generation: Some(2),
            replicas: 1,
            updated_replicas: 0,
            available_replicas: 1,
        };
        assert!(!s.is_complete(1));
    }

    #[test]
    fn rollout_incomplete_while_old_replicas_linger_during_surge() {
        // maxSurge brought the new pod up (updated + available) but the old pod
        // has not been torn down yet (`replicas` 2 > `updated_replicas` 1), so
        // some availability is still stale capacity.
        let s = RolloutStatus {
            generation: 3,
            observed_generation: Some(3),
            replicas: 2,
            updated_replicas: 1,
            available_replicas: 2,
        };
        assert!(!s.is_complete(1));
    }

    #[test]
    fn object_ref_extracts_identity_from_manifest() {
        let r = ObjectRef::from_manifest(&manifest()).unwrap();
        assert_eq!(
            r,
            ObjectRef {
                api_version: "v1".into(),
                kind: "Service".into(),
                namespace: Some("ns-a".into()),
                name: "svc-a".into(),
            }
        );
    }

    #[test]
    fn object_ref_without_namespace_is_cluster_scoped() {
        // The env's cluster-scoped Namespace object legitimately omits
        // `metadata.namespace` — recorded as `None`, not a render bug.
        let m = json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "gtc-zain"}});
        let r = ObjectRef::from_manifest(&m).unwrap();
        assert_eq!(r.namespace, None);
        assert_eq!(r.kind, "Namespace");
    }

    #[test]
    fn object_ref_rejects_manifest_without_name() {
        // A missing required field (name) IS a render bug.
        let m = json!({"apiVersion": "v1", "kind": "Service", "metadata": {"namespace": "ns"}});
        let err = ObjectRef::from_manifest(&m).unwrap_err();
        assert!(
            matches!(err, K8sClusterError::InvalidManifest(ref msg) if msg.contains("metadata.name")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn unconfigured_cluster_fails_both_verbs() {
        let c = UnconfiguredCluster;
        assert!(matches!(
            c.apply(&manifest()).await.unwrap_err(),
            K8sClusterError::Unconfigured
        ));
        let r = ObjectRef::from_manifest(&manifest()).unwrap();
        assert!(matches!(
            c.delete(&r).await.unwrap_err(),
            K8sClusterError::Unconfigured
        ));
    }

    #[tokio::test]
    async fn unconfigured_cluster_cannot_read_a_service_status() {
        let c = UnconfiguredCluster;
        let r = ObjectRef::from_manifest(&manifest()).unwrap();
        assert!(matches!(
            c.get_service_status(&r).await.unwrap_err(),
            K8sClusterError::Unconfigured
        ));
    }
}
