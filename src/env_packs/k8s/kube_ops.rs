//! kube-rs bodies for the drain + sweep seam methods of
//! [`KubeCluster`](super::kube_client::KubeCluster): label-scoped `list`,
//! `scale_deployment`, and the absent-tolerant rollout-status read. Kept out
//! of `kube_client.rs` so that file does not grow further; the impl there
//! delegates here.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Service;
use kube::api::{Api, ListParams, ObjectMeta, Patch, PatchParams};

use super::cluster::{K8sClusterError, LabeledObject, ObjectRef, RolloutStatus};

fn map_err(e: kube::Error) -> K8sClusterError {
    match e {
        kube::Error::Api(status) => {
            K8sClusterError::Api(format!("{} (status {})", status.message, status.code))
        }
        other => K8sClusterError::Api(other.to_string()),
    }
}

fn labeled(api_version: &str, kind: &str, namespace: &str, meta: ObjectMeta) -> LabeledObject {
    LabeledObject {
        object: ObjectRef {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            namespace: Some(meta.namespace.unwrap_or_else(|| namespace.to_string())),
            name: meta.name.unwrap_or_default(),
        },
        labels: meta
            .labels
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
    }
}

/// Deployments then Services in `namespace` matching `label_selector`.
pub(super) async fn list_labeled(
    client: &kube::Client,
    namespace: &str,
    label_selector: &str,
) -> Result<Vec<LabeledObject>, K8sClusterError> {
    let params = ListParams::default().labels(label_selector);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let mut out = Vec::new();
    for d in deployments.list(&params).await.map_err(map_err)?.items {
        out.push(labeled("apps/v1", "Deployment", namespace, d.metadata));
    }
    for s in services.list(&params).await.map_err(map_err)?.items {
        out.push(labeled("v1", "Service", namespace, s.metadata));
    }
    Ok(out)
}

/// Merge-patch `spec.replicas`. `Ok(false)` on 404.
pub(super) async fn scale_deployment(
    client: &kube::Client,
    deployment: &ObjectRef,
    replicas: i32,
) -> Result<bool, K8sClusterError> {
    let namespace = deployment.namespace.as_deref().unwrap_or_default();
    let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({"spec": {"replicas": replicas}});
    match api
        .patch(
            &deployment.name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(status)) if status.code == 404 => Ok(false),
        Err(e) => Err(map_err(e)),
    }
}

/// Rollout status, `None` when the Deployment is absent.
pub(super) async fn rollout_status_opt(
    client: &kube::Client,
    deployment: &ObjectRef,
) -> Result<Option<RolloutStatus>, K8sClusterError> {
    let namespace = deployment.namespace.as_deref().unwrap_or_default();
    let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let Some(dep) = api.get_opt(&deployment.name).await.map_err(map_err)? else {
        return Ok(None);
    };
    let status = dep.status.as_ref();
    Ok(Some(RolloutStatus {
        generation: dep.metadata.generation.unwrap_or(0),
        observed_generation: status.and_then(|s| s.observed_generation),
        replicas: status.and_then(|s| s.replicas).unwrap_or(0),
        updated_replicas: status.and_then(|s| s.updated_replicas).unwrap_or(0),
        available_replicas: status.and_then(|s| s.available_replicas).unwrap_or(0),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response};
    use kube::client::Body;
    use serde_json::{Value, json};
    use tower_test::mock::{self, Handle};

    type MockHandle = Handle<Request<Body>, Response<Body>>;

    fn mock_client() -> (kube::Client, MockHandle) {
        let (service, handle) = mock::pair::<Request<Body>, Response<Body>>();
        (kube::Client::new(service, "default"), handle)
    }

    async fn respond(handle: &mut MockHandle, status: u16, body: Value) -> Request<Body> {
        let (request, send) = handle.next_request().await.expect("a request is sent");
        send.send_response(
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("json")))
                .expect("response"),
        );
        request
    }

    fn worker() -> ObjectRef {
        ObjectRef {
            api_version: "apps/v1".into(),
            kind: "Deployment".into(),
            namespace: Some("gtc-zain".into()),
            name: "gtc-worker-a".into(),
        }
    }

    fn not_found() -> Value {
        json!({"kind": "Status", "apiVersion": "v1", "status": "Failure",
            "reason": "NotFound", "code": 404, "message": "not found"})
    }

    #[tokio::test]
    async fn list_sends_the_label_selector_to_both_kinds() {
        let (client, mut handle) = mock_client();
        let task =
            tokio::spawn(
                async move { list_labeled(&client, "gtc-zain", "greentic.ai/env=zain").await },
            );
        let d = respond(
            &mut handle,
            200,
            json!({"apiVersion": "apps/v1", "kind": "DeploymentList", "metadata": {},
                "items": [{"metadata": {"name": "gtc-worker-a", "namespace": "gtc-zain",
                    "labels": {"greentic.ai/revision": "A"}}}]}),
        )
        .await;
        assert_eq!(
            d.uri().path(),
            "/apis/apps/v1/namespaces/gtc-zain/deployments"
        );
        assert!(
            d.uri()
                .query()
                .unwrap_or_default()
                .contains("labelSelector=greentic.ai%2Fenv%3Dzain"),
            "{:?}",
            d.uri().query()
        );
        let s = respond(
            &mut handle,
            200,
            json!({"apiVersion": "v1", "kind": "ServiceList", "metadata": {}, "items": []}),
        )
        .await;
        assert_eq!(s.uri().path(), "/api/v1/namespaces/gtc-zain/services");
        let got = task.await.unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].object.kind, "Deployment");
        assert_eq!(got[0].labels["greentic.ai/revision"], "A");
    }

    #[tokio::test]
    async fn scale_merge_patches_replicas_and_tolerates_404() {
        let (client, mut handle) = mock_client();
        let w = worker();
        let c2 = client.clone();
        let (res, req) = tokio::join!(
            scale_deployment(&client, &w, 0),
            respond(
                &mut handle,
                200,
                json!({"apiVersion": "apps/v1", "kind": "Deployment",
                    "metadata": {"name": "gtc-worker-a", "namespace": "gtc-zain"}})
            )
        );
        assert!(res.unwrap());
        assert_eq!(req.method(), http::Method::PATCH);
        assert_eq!(
            req.headers()["content-type"],
            "application/merge-patch+json"
        );
        let (res, _) = tokio::join!(
            scale_deployment(&c2, &w, 0),
            respond(&mut handle, 404, not_found())
        );
        assert!(!res.unwrap());
    }

    #[tokio::test]
    async fn rollout_status_opt_maps_404_to_none() {
        let (client, mut handle) = mock_client();
        let w = worker();
        let (res, _) = tokio::join!(
            rollout_status_opt(&client, &w),
            respond(&mut handle, 404, not_found())
        );
        assert!(res.unwrap().is_none());
    }
}
