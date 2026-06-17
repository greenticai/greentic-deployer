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
/// The three fields are exactly what decides whether a `kubectl rollout`
/// has converged: the controller must have observed the latest spec
/// generation, and enough replicas must be available. Availability is the
/// count of pods passing their readiness probe — for the worker pod that
/// probe is its `/healthz` endpoint, so this single kube-level signal also
/// covers application health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolloutStatus {
    /// `.metadata.generation` — the spec generation the API server persisted.
    pub generation: i64,
    /// `.status.observedGeneration` — the generation the Deployment
    /// controller has reconciled up to. `None` until it first writes status.
    pub observed_generation: Option<i64>,
    /// `.status.availableReplicas` — replicas passing their readiness probe.
    /// An absent field reads as `0`.
    pub available_replicas: i32,
}

impl RolloutStatus {
    /// A rollout is complete when the controller has observed the latest
    /// spec generation AND at least `desired` replicas are available. A
    /// status with no `observedGeneration` yet is never complete (the
    /// controller has not started reconciling the applied spec).
    pub fn is_complete(&self, desired: i32) -> bool {
        self.observed_generation
            .is_some_and(|observed| observed >= self.generation)
            && self.available_replicas >= desired
    }
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
        // The fake has no rollout controller; report a complete rollout
        // (`i32::MAX` available is "all replicas ready" for any desired
        // count) so warm's readiness wait resolves on the first poll.
        Ok(RolloutStatus {
            generation: 0,
            observed_generation: Some(0),
            available_replicas: i32::MAX,
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
            available_replicas: 1,
        };
        assert!(!s.is_complete(1));
    }

    #[test]
    fn rollout_incomplete_when_no_status_written_yet() {
        let s = RolloutStatus {
            generation: 1,
            observed_generation: None,
            available_replicas: 0,
        };
        assert!(!s.is_complete(1));
    }

    #[test]
    fn rollout_incomplete_when_available_replicas_below_desired() {
        let s = RolloutStatus {
            generation: 2,
            observed_generation: Some(2),
            available_replicas: 0,
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
