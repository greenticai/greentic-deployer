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

/// In-memory fake honoring the [`K8sCluster`] idempotency contract.
/// Backs the conformance run and the verb-behavior tests; integration
/// against a real cluster is the PR-5.3 kind E2E.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct InMemoryCluster {
    objects: std::sync::Mutex<std::collections::BTreeMap<ObjectRef, Value>>,
}

#[cfg(test)]
impl InMemoryCluster {
    pub fn objects(&self) -> std::collections::BTreeMap<ObjectRef, Value> {
        self.objects.lock().expect("mutex not poisoned").clone()
    }
}

#[cfg(test)]
#[async_trait]
impl K8sCluster for InMemoryCluster {
    async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError> {
        let object = ObjectRef::from_manifest(manifest)?;
        self.objects
            .lock()
            .expect("mutex not poisoned")
            .insert(object, manifest.clone());
        Ok(())
    }

    async fn delete(&self, object: &ObjectRef) -> Result<(), K8sClusterError> {
        // Absent => Ok: deleting twice is the retried-archive path.
        self.objects
            .lock()
            .expect("mutex not poisoned")
            .remove(object);
        Ok(())
    }

    async fn get_rollout_status(
        &self,
        _deployment: &ObjectRef,
    ) -> Result<RolloutStatus, K8sClusterError> {
        // The fake has no rollout controller; report a fully-rolled-out
        // Deployment (all replicas updated and available, none lingering) so
        // warm's readiness wait resolves on the first poll for any desired
        // count.
        Ok(RolloutStatus {
            generation: 0,
            observed_generation: Some(0),
            replicas: i32::MAX,
            updated_replicas: i32::MAX,
            available_replicas: i32::MAX,
        })
    }

    async fn get_service_status(
        &self,
        service: &ObjectRef,
    ) -> Result<ServiceStatus, K8sClusterError> {
        let stored = self
            .objects
            .lock()
            .expect("mutex not poisoned")
            .get(service)
            .cloned()
            .ok_or_else(|| K8sClusterError::Api(format!("`{service}` not found")))?;
        // The fake has no API server and no cloud controller, so it reports
        // exactly what an apply would have persisted and nothing either of them
        // would have assigned: no allocated nodePort, no LB ingress. A
        // `LoadBalancer` therefore reads as PENDING here, which is the honest
        // fake of a load balancer that has been requested and not yet
        // provisioned — and the state a caller most needs to be able to see.
        Ok(ServiceStatus {
            service_type: stored
                .pointer("/spec/type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            node_port: None,
            ingress_hostname: None,
            ingress_ip: None,
        })
    }
}

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

    #[tokio::test]
    async fn in_memory_service_status_reports_the_applied_type_and_no_assigned_address() {
        let c = InMemoryCluster::default();
        let lb = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "svc-a", "namespace": "ns-a"},
            "spec": {"type": "LoadBalancer"},
        });
        c.apply(&lb).await.unwrap();
        let status = c
            .get_service_status(&ObjectRef::from_manifest(&lb).unwrap())
            .await
            .unwrap();
        assert_eq!(status.service_type, "LoadBalancer");
        // The fake has no cloud controller, so it assigns nothing — the honest
        // fake of a load balancer that has been requested and not provisioned.
        assert_eq!(status.node_port, None);
        assert_eq!(status.ingress_hostname, None);
        assert_eq!(status.ingress_ip, None);
    }

    #[tokio::test]
    async fn in_memory_service_status_of_an_absent_object_is_an_error() {
        // Never a default-shaped `ServiceStatus`: a Service that is not there
        // and a Service with no address assigned are different answers, and
        // only one of them means "keep waiting".
        let c = InMemoryCluster::default();
        let r = ObjectRef::from_manifest(&manifest()).unwrap();
        assert!(c.get_service_status(&r).await.is_err());
    }

    #[tokio::test]
    async fn in_memory_cluster_upserts_and_deletes_idempotently() {
        let c = InMemoryCluster::default();
        c.apply(&manifest()).await.unwrap();
        c.apply(&manifest()).await.unwrap();
        assert_eq!(c.objects().len(), 1, "apply is an upsert");
        let r = ObjectRef::from_manifest(&manifest()).unwrap();
        c.delete(&r).await.unwrap();
        c.delete(&r).await.unwrap();
        assert!(c.objects().is_empty(), "delete of absent is Ok");
    }
}
