//! In-memory [`K8sCluster`] fake (tests only). Honors the seam's idempotency
//! contract and models just enough of a controller for the drain + sweep
//! tests: pods follow `spec.replicas` instantly, labels are read back from the
//! stored manifest.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde_json::Value;

use super::cluster::{
    K8sCluster, K8sClusterError, LabeledObject, ObjectRef, RolloutStatus, ServiceStatus,
    refuse_adoption,
};

/// In-memory fake honoring the [`K8sCluster`] idempotency contract.
/// Backs the conformance run and the verb-behavior tests; integration
/// against a real cluster is the PR-5.3 kind E2E.
#[derive(Debug, Default)]
pub struct InMemoryCluster {
    objects: std::sync::Mutex<std::collections::BTreeMap<ObjectRef, Value>>,
}

impl InMemoryCluster {
    pub fn objects(&self) -> std::collections::BTreeMap<ObjectRef, Value> {
        self.objects.lock().expect("mutex not poisoned").clone()
    }

    /// Stored `spec.replicas` of a Deployment (absent field → 1).
    pub fn replicas_of(&self, deployment: &ObjectRef) -> Option<i64> {
        self.objects
            .lock()
            .expect("mutex not poisoned")
            .get(deployment)
            .map(|m| {
                m.pointer("/spec/replicas")
                    .and_then(Value::as_i64)
                    .unwrap_or(1)
            })
    }
}

/// Labels a stored manifest carries.
fn labels_of(manifest: &Value) -> BTreeMap<String, String> {
    manifest
        .pointer("/metadata/labels")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Equality-selector match (`k=v,k2=v2`), the only form the sweep sends.
fn selector_matches(selector: &str, labels: &BTreeMap<String, String>) -> bool {
    selector
        .split(',')
        .filter(|term| !term.trim().is_empty())
        .all(|term| match term.split_once('=') {
            Some((k, v)) => labels.get(k.trim()).map(String::as_str) == Some(v.trim()),
            None => false,
        })
}

#[async_trait]
impl K8sCluster for InMemoryCluster {
    async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError> {
        let object = ObjectRef::from_manifest(manifest)?;
        let mut objects = self.objects.lock().expect("mutex not poisoned");
        if let Some(existing) = objects.get(&object) {
            refuse_adoption(manifest, existing.pointer("/metadata/labels"))?;
        }
        objects.insert(object, manifest.clone());
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

    async fn delete_if_labeled(
        &self,
        object: &ObjectRef,
        labels: &[(&str, &str)],
    ) -> Result<bool, K8sClusterError> {
        let mut objects = self.objects.lock().expect("mutex not poisoned");
        let owned = objects.get(object).is_some_and(|stored| {
            labels.iter().all(|(key, value)| {
                stored
                    .pointer("/metadata/labels")
                    .and_then(|l| l.get(*key))
                    .and_then(Value::as_str)
                    == Some(*value)
            })
        });
        if owned {
            objects.remove(object);
        }
        Ok(owned)
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

    async fn list(
        &self,
        namespace: &str,
        label_selector: &str,
    ) -> Result<Vec<LabeledObject>, K8sClusterError> {
        let objects = self.objects.lock().expect("mutex not poisoned");
        Ok(objects
            .iter()
            .filter(|(r, _)| {
                r.namespace.as_deref() == Some(namespace)
                    && matches!(r.kind.as_str(), "Deployment" | "Service")
            })
            .map(|(r, m)| LabeledObject {
                object: r.clone(),
                labels: labels_of(m),
            })
            .filter(|o| selector_matches(label_selector, &o.labels))
            .collect())
    }

    async fn scale_deployment(
        &self,
        deployment: &ObjectRef,
        replicas: i32,
    ) -> Result<bool, K8sClusterError> {
        let mut objects = self.objects.lock().expect("mutex not poisoned");
        match objects.get_mut(deployment) {
            Some(manifest) => {
                manifest["spec"]["replicas"] = serde_json::json!(replicas);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn get_rollout_status_opt(
        &self,
        deployment: &ObjectRef,
    ) -> Result<Option<RolloutStatus>, K8sClusterError> {
        // The fake's pods follow `spec.replicas` instantly: a Deployment scaled
        // to 0 has no pod and no ready endpoint on the next read.
        Ok(self.replicas_of(deployment).map(|n| {
            let n = i32::try_from(n).unwrap_or(i32::MAX);
            RolloutStatus {
                generation: 0,
                observed_generation: Some(0),
                replicas: n,
                updated_replicas: n,
                available_replicas: n,
            }
        }))
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

    #[tokio::test]
    async fn list_matches_only_labeled_objects_in_the_namespace() {
        let c = InMemoryCluster::default();
        let labeled = json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "w", "namespace": "ns", "labels": {"a": "1", "b": "2"}}});
        let bare = json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "x", "namespace": "ns"}});
        let other_ns = json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "y", "namespace": "other", "labels": {"a": "1"}}});
        for m in [&labeled, &bare, &other_ns] {
            c.apply(m).await.unwrap();
        }
        let got = c.list("ns", "a=1").await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].object.name, "w");
        assert!(c.list("ns", "a=1,b=3").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn scale_reports_absence_and_status_follows_replicas() {
        let c = InMemoryCluster::default();
        let d = json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "w", "namespace": "ns"}, "spec": {"replicas": 2}});
        c.apply(&d).await.unwrap();
        let r = ObjectRef::from_manifest(&d).unwrap();
        assert_eq!(
            c.get_rollout_status_opt(&r)
                .await
                .unwrap()
                .unwrap()
                .replicas,
            2
        );
        assert!(c.scale_deployment(&r, 0).await.unwrap());
        assert_eq!(
            c.get_rollout_status_opt(&r)
                .await
                .unwrap()
                .unwrap()
                .replicas,
            0
        );
        c.delete(&r).await.unwrap();
        assert!(!c.scale_deployment(&r, 0).await.unwrap());
        assert!(c.get_rollout_status_opt(&r).await.unwrap().is_none());
    }
}
