//! kube-rs-backed implementations of the K8s client seams (PR-5.2).
//!
//! Fills the two pluggable seams the scaffold (PR-5.0) defined, one type
//! per seam:
//!
//! - [`KubeCluster`] — [`K8sCluster`](super::cluster::K8sCluster) over a
//!   typed [`kube::Client`]: declarative **server-side apply** (field
//!   manager [`FIELD_MANAGER`], forced) and idempotent delete (404 ⇒
//!   `Ok`, honoring the retried-`archive_revision` contract).
//! - [`KubeValidatorClient`] —
//!   [`K8sValidatorClient`](super::credentials::K8sValidatorClient) over
//!   the same client: `SelfSubjectReview` for identity, one
//!   `SelfSubjectAccessReview` per validated operation, in request order.
//!
//! Construction is explicit ([`connect`]): a kubeconfig-context override
//! (the wizard's `kubeconfig_context` answer — a client-targeting knob,
//! deliberately not a manifest input) or ambient inference (kubeconfig
//! current-context, then in-cluster service account). The handler default
//! stays [`UnconfiguredCluster`](super::cluster::UnconfiguredCluster) —
//! reading the binding's answer and binding a connected client to verb
//! dispatch is the PR-5.3 orchestration wiring.
//!
//! Resource routing is a **closed table** ([`api_route_for`]) covering
//! exactly the kinds [`super::manifests`] renders. Kubernetes plurals are
//! irregular (`networkpolicies`, `poddisruptionbudgets`), so a naive
//! pluralizer would silently build wrong URLs; an unrendered kind is a
//! render bug and surfaces as `InvalidManifest`, never a guessed request.

use async_trait::async_trait;
use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams, PostParams};
use kube::config::KubeConfigOptions;
use serde_json::Value;

use super::cluster::{K8sCluster, K8sClusterError, ObjectRef};
use super::credentials::{
    AccessDecision, ClusterIdentity, K8sClientError, K8sOperation, K8sValidatorClient,
    OperationDecision,
};

/// Server-side-apply field manager identifying the deployer's writes.
/// Forced conflicts are correct for a controller-style owner: the
/// deployer's rendered manifests ARE the desired state for the fields
/// they set.
pub const FIELD_MANAGER: &str = "greentic-deployer";

/// Build a typed client from the operator's ambient Kubernetes access.
///
/// `kubeconfig_context` is the binding's wizard answer: `Some` selects
/// that named kubeconfig context; `None` infers (kubeconfig
/// current-context first, in-cluster service account second — kube-rs
/// `Config::infer` semantics). All failures fold into
/// [`K8sClientError::NoClusterAccess`] — the operator's fix path is the
/// same regardless (fix kubeconfig / cluster access).
pub async fn connect(kubeconfig_context: Option<&str>) -> Result<kube::Client, K8sClientError> {
    let config = match kubeconfig_context {
        Some(context) => kube::Config::from_kubeconfig(&KubeConfigOptions {
            context: Some(context.to_string()),
            ..Default::default()
        })
        .await
        .map_err(|e| {
            K8sClientError::NoClusterAccess(format!("kubeconfig context `{context}`: {e}"))
        })?,
        None => kube::Config::infer()
            .await
            .map_err(|e| K8sClientError::NoClusterAccess(e.to_string()))?,
    };
    kube::Client::try_from(config).map_err(|e| K8sClientError::NoClusterAccess(e.to_string()))
}

/// Whether a kind lives in a namespace or at cluster scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Namespaced,
    Cluster,
}

/// Closed routing table for the kinds the renderer emits.
///
/// Returns the [`ApiResource`] (group/version/plural drive the request
/// URL) and the kind's scope. Extending the renderer with a new kind
/// REQUIRES a row here — `apply`/`delete` refuse unknown kinds instead
/// of guessing a plural.
fn api_route_for(api_version: &str, kind: &str) -> Result<(ApiResource, Scope), K8sClusterError> {
    let (plural, scope) = match (api_version, kind) {
        ("v1", "Namespace") => ("namespaces", Scope::Cluster),
        ("v1", "Service") => ("services", Scope::Namespaced),
        ("v1", "ConfigMap") => ("configmaps", Scope::Namespaced),
        ("apps/v1", "Deployment") => ("deployments", Scope::Namespaced),
        ("policy/v1", "PodDisruptionBudget") => ("poddisruptionbudgets", Scope::Namespaced),
        ("networking.k8s.io/v1", "NetworkPolicy") => ("networkpolicies", Scope::Namespaced),
        _ => {
            return Err(K8sClusterError::InvalidManifest(format!(
                "unsupported object `{api_version}/{kind}` — the deployer's routing table \
                 covers exactly the kinds the manifest renderer emits; extend \
                 `api_route_for` alongside the renderer"
            )));
        }
    };
    let (group, version) = match api_version.split_once('/') {
        Some((group, version)) => (group, version),
        None => ("", api_version),
    };
    Ok((
        ApiResource {
            group: group.to_string(),
            version: version.to_string(),
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            plural: plural.to_string(),
        },
        scope,
    ))
}

/// Cluster failures at the kube transport boundary. The seam does not
/// distinguish transport from auth (same operator fix path), so
/// everything folds into [`K8sClusterError::Api`] with the server's
/// message + code where available.
fn map_cluster_error(e: kube::Error) -> K8sClusterError {
    match e {
        kube::Error::Api(status) => {
            K8sClusterError::Api(format!("{} (status {})", status.message, status.code))
        }
        other => K8sClusterError::Api(other.to_string()),
    }
}

/// Production [`K8sCluster`]: declarative mutation through a typed
/// [`kube::Client`].
pub struct KubeCluster {
    client: kube::Client,
}

impl KubeCluster {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }

    /// Resolve the dynamic API + object name for one rendered manifest.
    fn api_for(&self, manifest: &Value) -> Result<(Api<DynamicObject>, String), K8sClusterError> {
        let field = |path: &[&str]| -> Result<String, K8sClusterError> {
            let mut cur = manifest;
            for p in path {
                cur = cur.get(p).ok_or_else(|| {
                    K8sClusterError::InvalidManifest(format!(
                        "manifest is missing `{}`",
                        path.join(".")
                    ))
                })?;
            }
            cur.as_str().map(str::to_string).ok_or_else(|| {
                K8sClusterError::InvalidManifest(format!("`{}` is not a string", path.join(".")))
            })
        };
        let api_version = field(&["apiVersion"])?;
        let kind = field(&["kind"])?;
        let name = field(&["metadata", "name"])?;
        let (resource, scope) = api_route_for(&api_version, &kind)?;
        let api = match scope {
            // The Namespace object itself carries no `metadata.namespace`
            // — cluster-scoped kinds route through the all-cluster API.
            Scope::Cluster => Api::all_with(self.client.clone(), &resource),
            Scope::Namespaced => {
                let namespace = field(&["metadata", "namespace"])?;
                Api::namespaced_with(self.client.clone(), &namespace, &resource)
            }
        };
        Ok((api, name))
    }
}

impl std::fmt::Debug for KubeCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // kube::Client carries no Debug impl (it wraps a tower service).
        f.debug_struct("KubeCluster").finish_non_exhaustive()
    }
}

#[async_trait]
impl K8sCluster for KubeCluster {
    async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError> {
        let (api, name) = self.api_for(manifest)?;
        // Server-side apply IS the trait's upsert contract: same manifest
        // twice succeeds twice and converges. Forced — the deployer owns
        // every field it renders.
        let params = PatchParams::apply(FIELD_MANAGER).force();
        api.patch(&name, &params, &Patch::Apply(manifest))
            .await
            .map_err(map_cluster_error)?;
        Ok(())
    }

    async fn delete(&self, object: &ObjectRef) -> Result<(), K8sClusterError> {
        let (resource, scope) = api_route_for(&object.api_version, &object.kind)?;
        let api: Api<DynamicObject> = match scope {
            Scope::Cluster => Api::all_with(self.client.clone(), &resource),
            Scope::Namespaced => {
                Api::namespaced_with(self.client.clone(), &object.namespace, &resource)
            }
        };
        match api.delete(&object.name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            // Absent => Ok: the trait's retried-archive contract.
            Err(kube::Error::Api(status)) if status.code == 404 => Ok(()),
            Err(e) => Err(map_cluster_error(e)),
        }
    }
}

/// Validator failures: auth-shaped problems map to `NoClusterAccess`,
/// API rejections keep the server's message, everything else is
/// transport.
fn map_validator_error(e: kube::Error) -> K8sClientError {
    match e {
        kube::Error::Api(status) => {
            K8sClientError::ApiRejected(format!("{} (status {})", status.message, status.code))
        }
        kube::Error::Auth(e) => K8sClientError::NoClusterAccess(e.to_string()),
        other => K8sClientError::Transport(other.to_string()),
    }
}

/// Production [`K8sValidatorClient`]: identity + RBAC probes through a
/// typed [`kube::Client`].
pub struct KubeValidatorClient {
    client: kube::Client,
}

impl KubeValidatorClient {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

impl std::fmt::Debug for KubeValidatorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeValidatorClient")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl K8sValidatorClient for KubeValidatorClient {
    async fn who_am_i(&self) -> Result<ClusterIdentity, K8sClientError> {
        let api: Api<SelfSubjectReview> = Api::all(self.client.clone());
        let created = api
            .create(&PostParams::default(), &SelfSubjectReview::default())
            .await
            .map_err(map_validator_error)?;
        let user = created
            .status
            .and_then(|s| s.user_info)
            .and_then(|u| u.username)
            .ok_or_else(|| {
                K8sClientError::ApiRejected(
                    "SelfSubjectReview response carried no user identity".to_string(),
                )
            })?;
        Ok(ClusterIdentity { user })
    }

    async fn review_access<'a>(
        &'a self,
        namespace: &'a str,
        operations: &'a [K8sOperation],
    ) -> Result<Vec<OperationDecision>, K8sClientError> {
        let api: Api<SelfSubjectAccessReview> = Api::all(self.client.clone());
        let mut decisions = Vec::with_capacity(operations.len());
        for operation in operations {
            let review = SelfSubjectAccessReview {
                spec: SelfSubjectAccessReviewSpec {
                    resource_attributes: Some(ResourceAttributes {
                        namespace: Some(namespace.to_string()),
                        group: Some(operation.group.to_string()),
                        resource: Some(operation.resource.to_string()),
                        verb: Some(operation.verb.to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            };
            let created = api
                .create(&PostParams::default(), &review)
                .await
                .map_err(map_validator_error)?;
            // Fail closed: a response without a status authorizes
            // nothing — surfacing an error beats fabricating a decision.
            let status = created.status.ok_or_else(|| {
                K8sClientError::ApiRejected(
                    "SelfSubjectAccessReview response carried no status".to_string(),
                )
            })?;
            let decision = if status.allowed {
                AccessDecision::Allowed
            } else {
                AccessDecision::Denied(
                    status
                        .reason
                        .unwrap_or_else(|| "no reason supplied".to_string()),
                )
            };
            decisions.push(OperationDecision {
                operation: *operation,
                decision,
            });
        }
        Ok(decisions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response};
    use http_body_util::BodyExt;
    use kube::client::Body;
    use serde_json::json;
    use tower_test::mock::{self, Handle};

    type MockHandle = Handle<Request<Body>, Response<Body>>;

    /// Real `kube::Client` over a mocked HTTP service — the impls are
    /// asserted at the wire layer (method, URL, body) without a cluster.
    fn mock_client() -> (kube::Client, MockHandle) {
        let (service, handle) = mock::pair::<Request<Body>, Response<Body>>();
        (kube::Client::new(service, "default"), handle)
    }

    /// Answer the next request with `status` + JSON `body`; returns the
    /// captured request for assertions.
    async fn respond_json(handle: &mut MockHandle, status: u16, body: Value) -> Request<Body> {
        let (request, send) = handle.next_request().await.expect("a request is sent");
        send.send_response(
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("serializable")))
                .expect("valid response"),
        );
        request
    }

    async fn request_body_json(request: Request<Body>) -> Value {
        let bytes = request
            .into_body()
            .collect()
            .await
            .expect("request body readable")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("request body is JSON")
    }

    fn deployment_manifest() -> Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "gtc-worker-a", "namespace": "gtc-zain"},
            "spec": {"replicas": 1},
        })
    }

    #[tokio::test]
    async fn apply_is_forced_server_side_apply_with_field_manager() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let manifest = deployment_manifest();

        let (result, request) = tokio::join!(
            cluster.apply(&manifest),
            respond_json(&mut handle, 200, manifest.clone()),
        );
        result.unwrap();

        assert_eq!(request.method(), http::Method::PATCH);
        assert_eq!(
            request.uri().path(),
            "/apis/apps/v1/namespaces/gtc-zain/deployments/gtc-worker-a"
        );
        let query = request.uri().query().expect("apply carries query params");
        assert!(
            query.contains("fieldManager=greentic-deployer"),
            "field manager must identify the deployer: {query}"
        );
        assert!(query.contains("force=true"), "apply must force: {query}");
        assert_eq!(
            request
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/apply-patch+yaml"),
            "server-side apply content type"
        );
        assert_eq!(
            request_body_json(request).await,
            manifest,
            "the rendered manifest IS the patch body"
        );
    }

    #[tokio::test]
    async fn apply_routes_cluster_scoped_namespace_via_core_api() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        // The rendered Namespace carries no `metadata.namespace`.
        let manifest = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "gtc-zain"},
        });

        let (result, request) = tokio::join!(
            cluster.apply(&manifest),
            respond_json(&mut handle, 200, manifest.clone()),
        );
        result.unwrap();
        assert_eq!(request.uri().path(), "/api/v1/namespaces/gtc-zain");
    }

    #[tokio::test]
    async fn apply_uses_the_irregular_plurals() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);

        let netpol = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "deny-all", "namespace": "gtc-zain"},
        });
        let (result, request) = tokio::join!(
            cluster.apply(&netpol),
            respond_json(&mut handle, 200, netpol.clone()),
        );
        result.unwrap();
        assert_eq!(
            request.uri().path(),
            "/apis/networking.k8s.io/v1/namespaces/gtc-zain/networkpolicies/deny-all"
        );

        let pdb = json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "router", "namespace": "gtc-zain"},
        });
        let (result, request) = tokio::join!(
            cluster.apply(&pdb),
            respond_json(&mut handle, 200, pdb.clone()),
        );
        result.unwrap();
        assert_eq!(
            request.uri().path(),
            "/apis/policy/v1/namespaces/gtc-zain/poddisruptionbudgets/router"
        );
    }

    #[tokio::test]
    async fn apply_rejects_a_kind_outside_the_routing_table() {
        let (client, _handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let manifest = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"name": "x", "namespace": "ns"},
        });
        let err = cluster.apply(&manifest).await.unwrap_err();
        assert!(
            matches!(err, K8sClusterError::InvalidManifest(ref msg)
                if msg.contains("unsupported object `networking.k8s.io/v1/Ingress`")),
            "no request may be guessed for an unrendered kind, got {err:?}"
        );
    }

    #[tokio::test]
    async fn apply_requires_namespace_on_namespaced_kinds() {
        let (client, _handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let manifest = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "svc"},
        });
        let err = cluster.apply(&manifest).await.unwrap_err();
        assert!(
            matches!(err, K8sClusterError::InvalidManifest(ref msg)
                if msg.contains("metadata.namespace")),
            "got {err:?}"
        );
    }

    fn worker_object_ref() -> ObjectRef {
        ObjectRef {
            api_version: "apps/v1".into(),
            kind: "Deployment".into(),
            namespace: "gtc-zain".into(),
            name: "gtc-worker-a".into(),
        }
    }

    #[tokio::test]
    async fn delete_sends_delete_to_the_object_url() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let object = worker_object_ref();
        let (result, request) = tokio::join!(
            cluster.delete(&object),
            respond_json(
                &mut handle,
                200,
                json!({"kind": "Status", "apiVersion": "v1", "status": "Success"}),
            ),
        );
        result.unwrap();
        assert_eq!(request.method(), http::Method::DELETE);
        assert_eq!(
            request.uri().path(),
            "/apis/apps/v1/namespaces/gtc-zain/deployments/gtc-worker-a"
        );
    }

    #[tokio::test]
    async fn delete_of_an_absent_object_is_ok() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let object = worker_object_ref();
        let (result, _request) = tokio::join!(
            cluster.delete(&object),
            respond_json(
                &mut handle,
                404,
                json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "deployments.apps \"gtc-worker-a\" not found",
                    "reason": "NotFound",
                    "code": 404,
                }),
            ),
        );
        result.unwrap();
    }

    #[tokio::test]
    async fn delete_surfaces_non_404_api_rejections() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let object = worker_object_ref();
        let (result, _request) = tokio::join!(
            cluster.delete(&object),
            respond_json(
                &mut handle,
                403,
                json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "forbidden",
                    "reason": "Forbidden",
                    "code": 403,
                }),
            ),
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, K8sClusterError::Api(ref msg) if msg.contains("forbidden")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn who_am_i_resolves_the_cluster_identity() {
        let (client, mut handle) = mock_client();
        let validator = KubeValidatorClient::new(client);
        let (result, request) = tokio::join!(
            validator.who_am_i(),
            respond_json(
                &mut handle,
                201,
                json!({
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "SelfSubjectReview",
                    "metadata": {},
                    "status": {"userInfo": {
                        "username": "system:serviceaccount:gtc-zain:greentic-deployer",
                    }},
                }),
            ),
        );
        assert_eq!(
            result.unwrap(),
            ClusterIdentity {
                user: "system:serviceaccount:gtc-zain:greentic-deployer".into()
            }
        );
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.uri().path(),
            "/apis/authentication.k8s.io/v1/selfsubjectreviews"
        );
    }

    #[tokio::test]
    async fn who_am_i_without_identity_fails() {
        let (client, mut handle) = mock_client();
        let validator = KubeValidatorClient::new(client);
        let (result, _request) = tokio::join!(
            validator.who_am_i(),
            respond_json(
                &mut handle,
                201,
                json!({
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "SelfSubjectReview",
                    "metadata": {},
                }),
            ),
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, K8sClientError::ApiRejected(ref msg)
                if msg.contains("no user identity")),
            "got {err:?}"
        );
    }

    fn ssar_response(allowed: bool, reason: Option<&str>) -> Value {
        let mut status = json!({"allowed": allowed});
        if let Some(reason) = reason {
            status["reason"] = json!(reason);
        }
        json!({
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "metadata": {},
            "spec": {},
            "status": status,
        })
    }

    #[tokio::test]
    async fn review_access_sends_one_ssar_per_operation_in_order() {
        let (client, mut handle) = mock_client();
        let validator = KubeValidatorClient::new(client);
        let operations = [
            K8sOperation {
                group: "apps",
                resource: "deployments",
                verb: "create",
            },
            K8sOperation {
                group: "",
                resource: "services",
                verb: "delete",
            },
        ];

        let respond_both = async {
            let first = respond_json(&mut handle, 201, ssar_response(true, None)).await;
            let second =
                respond_json(&mut handle, 201, ssar_response(false, Some("RBAC: no"))).await;
            (first, second)
        };
        let (result, (first, second)) = tokio::join!(
            validator.review_access("gtc-zain", &operations),
            respond_both
        );

        let decisions = result.unwrap();
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].operation, operations[0]);
        assert_eq!(decisions[0].decision, AccessDecision::Allowed);
        assert_eq!(decisions[1].operation, operations[1]);
        assert_eq!(
            decisions[1].decision,
            AccessDecision::Denied("RBAC: no".to_string())
        );

        for request in [&first, &second] {
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.uri().path(),
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
            );
        }
        let first_body = request_body_json(first).await;
        assert_eq!(
            first_body["spec"]["resourceAttributes"],
            json!({
                "namespace": "gtc-zain",
                "group": "apps",
                "resource": "deployments",
                "verb": "create",
            }),
            "the SSAR must probe the exact declared operation"
        );
        let second_body = request_body_json(second).await;
        assert_eq!(
            second_body["spec"]["resourceAttributes"]["group"],
            json!("")
        );
        assert_eq!(
            second_body["spec"]["resourceAttributes"]["verb"],
            json!("delete")
        );
    }

    #[tokio::test]
    async fn review_access_without_status_fails_closed() {
        let (client, mut handle) = mock_client();
        let validator = KubeValidatorClient::new(client);
        let operations = [K8sOperation {
            group: "apps",
            resource: "deployments",
            verb: "get",
        }];
        let (result, _request) = tokio::join!(
            validator.review_access("gtc-zain", &operations),
            respond_json(
                &mut handle,
                201,
                json!({
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectAccessReview",
                    "metadata": {},
                    "spec": {},
                }),
            ),
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, K8sClientError::ApiRejected(ref msg) if msg.contains("no status")),
            "a status-less review must never authorize, got {err:?}"
        );
    }

    #[tokio::test]
    async fn review_access_denied_without_reason_gets_a_placeholder() {
        let (client, mut handle) = mock_client();
        let validator = KubeValidatorClient::new(client);
        let operations = [K8sOperation {
            group: "",
            resource: "configmaps",
            verb: "patch",
        }];
        let (result, _request) = tokio::join!(
            validator.review_access("gtc-zain", &operations),
            respond_json(&mut handle, 201, ssar_response(false, None)),
        );
        let decisions = result.unwrap();
        assert_eq!(
            decisions[0].decision,
            AccessDecision::Denied("no reason supplied".to_string())
        );
    }
}
