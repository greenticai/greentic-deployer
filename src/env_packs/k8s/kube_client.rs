//! kube-rs-backed implementations of the K8s client seams (PR-5.2).
//!
//! Fills the two pluggable seams the scaffold (PR-5.0) defined, one type
//! per seam:
//!
//! - [`KubeCluster`] — [`K8sCluster`] over a typed [`kube::Client`]:
//!   declarative **server-side apply** (field manager [`FIELD_MANAGER`],
//!   forced) and idempotent delete (404 ⇒ `Ok`, honoring the
//!   retried-`archive_revision` contract).
//! - [`KubeValidatorClient`] — [`K8sValidatorClient`] over the same
//!   client: `SelfSubjectReview` for identity, one
//!   `SelfSubjectAccessReview` per validated operation, in request order.
//!
//! Construction is explicit ([`connect`]): the deployer authenticates as
//! its **bound ServiceAccount credential** when `bound_token` is
//! provided, overriding the resolved kubeconfig/in-cluster context's auth
//! while keeping that context's endpoint + CA.  `kubeconfig_context`
//! selects which context supplies endpoint/CA; passing `None` for
//! `bound_token` falls back to the ambient context identity (dev /
//! in-cluster).  Resolving `Environment.credentials_ref` into a token is
//! the caller's job in the PR-5.3 orchestration wiring.  The handler
//! default stays
//! [`UnconfiguredCluster`](super::cluster::UnconfiguredCluster).
//!
//! Resource routing is a **closed table** (`api_route_for`) covering
//! exactly the kinds [`super::manifests`] renders. Kubernetes plurals are
//! irregular (`networkpolicies`, `poddisruptionbudgets`), so a naive
//! pluralizer would silently build wrong URLs; an unrendered kind is a
//! render bug and surfaces as `InvalidManifest`, never a guessed request.

use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::authentication::v1::{SelfSubjectReview, TokenRequest, TokenRequestSpec};
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use k8s_openapi::api::core::v1::{Secret, ServiceAccount};
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams, PostParams};
use kube::config::KubeConfigOptions;
use serde_json::Value;

use super::bootstrap::DEPLOYER_IDENTITY_BEARER_KEY;
use super::cluster::{K8sCluster, K8sClusterError, ObjectRef, RolloutStatus, manifest_field};
use super::credentials::{
    AccessDecision, ClusterIdentity, K8sBootstrapClient, K8sClientError, K8sOperation,
    K8sValidatorClient, MintedToken, OperationDecision,
};
use super::manifests::ENV_LABEL;

/// Server-side-apply field manager identifying the deployer's writes.
/// Forced conflicts are correct for a controller-style owner: the
/// deployer's rendered manifests ARE the desired state for the fields
/// they set.
pub const FIELD_MANAGER: &str = "greentic-deployer";

/// Build a typed client from the operator's Kubernetes access.
///
/// `kubeconfig_context` selects which kubeconfig context supplies the
/// endpoint + CA: `Some` picks that named context; `None` infers
/// (kubeconfig current-context first, in-cluster service account
/// second — kube-rs `Config::infer` semantics).
///
/// `bound_token`, when `Some`, **overrides** the resolved context's auth
/// with the deployer's bound ServiceAccount credential (keeping the
/// context's endpoint + CA).  This is the correct-by-construction seam:
/// credential *resolution* (`Environment.credentials_ref` → token) stays
/// caller-side in the PR-5.3 orchestration wiring; passing `None` falls
/// back to the ambient context identity (dev / in-cluster).
///
/// All failures fold into [`K8sClientError::NoClusterAccess`] — the
/// operator's fix path is the same regardless (fix kubeconfig / cluster
/// access).
pub async fn connect(
    kubeconfig_context: Option<&str>,
    bound_token: Option<&str>,
) -> Result<kube::Client, K8sClientError> {
    install_default_crypto_provider();
    let mut config = match kubeconfig_context {
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
    apply_bound_token(&mut config, bound_token);
    kube::Client::try_from(config).map_err(|e| K8sClientError::NoClusterAccess(e.to_string()))
}

/// Pin a process-default rustls `CryptoProvider` before any TLS handshake.
///
/// rustls 0.23 refuses to auto-select a provider when more than one is
/// compiled in, and this workspace links both: `ring` (kube's bundled TLS)
/// and `aws-lc-rs` (the AWS SDK's). Without an explicit default the first
/// real cluster connection panics inside rustls — a failure invisible to the
/// unit tests, which drive a pre-built `kube::Client` over a `tower-test`
/// mock and never open a socket. Install `ring` (kube's choice) once; if a
/// provider is already set (another caller, or a future dependency default),
/// that one wins and this is a no-op.
fn install_default_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// Override the resolved config's auth with a bound ServiceAccount token.
///
/// Pure helper — unit-testable without a live cluster. When `token` is `None`
/// the config is left unchanged (ambient identity fallback).
///
/// When `Some`, the bearer token becomes the *sole* client credential AND the
/// effective identity. Two things are cleared:
///
/// 1. Every competing **authentication** method the context supplied (client
///    cert/key, exec plugin, auth provider, basic auth, token file) — so the
///    API server authenticates as the ServiceAccount, not the kubeconfig
///    identity. Without this, a context whose client credential is a TLS cert
///    (e.g. kind's default kubeconfig) would present that cert at the handshake
///    and the API server would authenticate as the cert identity, silently
///    ignoring the bearer token — the bound credential would be a no-op.
/// 2. Any **impersonation** (`impersonate` / `impersonate_groups`) the context
///    carried — kube-rs sends those as `Impersonate-*` headers on every
///    request, so leaving them would re-attribute calls to the impersonated
///    user (or fail if the SA cannot impersonate) while the verb still reports
///    `identity: bound`, hiding the drift.
///
/// The endpoint + cluster CA (server trust) come from the context and are
/// untouched.
fn apply_bound_token(config: &mut kube::Config, token: Option<&str>) {
    if let Some(tok) = token {
        // Wholesale reset via struct-spread (not field-by-field clears): any
        // auth field a future kube-rs adds is reset to its default too, so a
        // new auth method can't silently survive and shadow the token —
        // reviving this very bug class. Endpoint + cluster CA live on `Config`,
        // not `auth_info`, so they are untouched.
        config.auth_info = kube::config::AuthInfo {
            token: Some(tok.into()),
            ..Default::default()
        };
    }
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
        // The `--bind` path stores the deployer's bound bearer in a Secret
        // (via `KubeBootstrapClient::apply_identity_secret` → `KubeCluster::apply`).
        ("v1", "Secret") => ("secrets", Scope::Namespaced),
        ("v1", "ServiceAccount") => ("serviceaccounts", Scope::Namespaced),
        ("apps/v1", "Deployment") => ("deployments", Scope::Namespaced),
        ("policy/v1", "PodDisruptionBudget") => ("poddisruptionbudgets", Scope::Namespaced),
        ("networking.k8s.io/v1", "NetworkPolicy") => ("networkpolicies", Scope::Namespaced),
        // RBAC kinds the bootstrap `--bind` path applies (via
        // `KubeBootstrapClient::apply_rbac` → `KubeCluster::apply`); the
        // steady-state reconcile renderer does not emit these.
        ("rbac.authorization.k8s.io/v1", "Role") => ("roles", Scope::Namespaced),
        ("rbac.authorization.k8s.io/v1", "RoleBinding") => ("rolebindings", Scope::Namespaced),
        // Cluster-scoped: the in-cluster dev Vault's `system:auth-delegator`
        // binding (rendered by `vault_infra`, applied only on the cluster-admin
        // `env up` path — see its cluster-scoped SSAR preflight).
        ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding") => {
            ("clusterrolebindings", Scope::Cluster)
        }
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

/// Build the dynamic API for one routed `(resource, scope)`. Cluster-scoped
/// kinds ignore `namespace`. Shared by `apply`/`api_for` and `delete` so
/// both route identically.
fn dynamic_api(
    client: &kube::Client,
    resource: &ApiResource,
    scope: Scope,
    namespace: &str,
) -> Api<DynamicObject> {
    match scope {
        Scope::Cluster => Api::all_with(client.clone(), resource),
        Scope::Namespaced => Api::namespaced_with(client.clone(), namespace, resource),
    }
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
        let api_version = manifest_field(manifest, &["apiVersion"])?;
        let kind = manifest_field(manifest, &["kind"])?;
        let name = manifest_field(manifest, &["metadata", "name"])?;
        let (resource, scope) = api_route_for(&api_version, &kind)?;
        // The Namespace object itself carries no `metadata.namespace` —
        // cluster-scoped kinds ignore it in `dynamic_api`.
        let namespace = match scope {
            Scope::Cluster => String::new(),
            Scope::Namespaced => manifest_field(manifest, &["metadata", "namespace"])?,
        };
        Ok((
            dynamic_api(&self.client, &resource, scope, &namespace),
            name,
        ))
    }
}

impl std::fmt::Debug for KubeCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // kube::Client carries no Debug impl (it wraps a tower service).
        f.debug_struct("KubeCluster").finish_non_exhaustive()
    }
}

/// Read a manifest's owning-environment label (`metadata.labels[ENV_LABEL]`).
fn manifest_env_label(manifest: &Value) -> Option<&str> {
    manifest
        .get("metadata")
        .and_then(|m| m.get("labels"))
        .and_then(|l| l.get(ENV_LABEL))
        .and_then(Value::as_str)
}

#[async_trait]
impl K8sCluster for KubeCluster {
    async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError> {
        let (api, name) = self.api_for(manifest)?;
        let incoming_env = manifest_env_label(manifest);

        // Ownership guard: if an object already exists and carries a
        // different env label, refuse the apply — two envs sharing a
        // namespace with fixed env-level names (gtc-router,
        // gtc-runtime-config) would clobber each other otherwise.
        if let Some(existing) = api.get_opt(&name).await.map_err(map_cluster_error)? {
            let existing_env = existing
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(ENV_LABEL))
                .map(String::as_str);
            if let (Some(inc), Some(ext)) = (incoming_env, existing_env)
                && inc != ext
            {
                let namespace = manifest
                    .pointer("/metadata/namespace")
                    .and_then(Value::as_str)
                    .unwrap_or("<cluster-scoped>");
                return Err(K8sClusterError::OwnershipConflict {
                    object: name,
                    namespace: namespace.to_string(),
                    existing_env: ext.to_string(),
                    incoming_env: inc.to_string(),
                });
            }
        }

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
        // Cluster-scoped objects carry no namespace; `dynamic_api` ignores it.
        let namespace = object.namespace.as_deref().unwrap_or_default();
        let api = dynamic_api(&self.client, &resource, scope, namespace);
        match api.delete(&object.name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            // Absent => Ok: the trait's retried-archive contract.
            Err(kube::Error::Api(status)) if status.code == 404 => Ok(()),
            Err(e) => Err(map_cluster_error(e)),
        }
    }

    async fn get_rollout_status(
        &self,
        deployment: &ObjectRef,
    ) -> Result<RolloutStatus, K8sClusterError> {
        // The worker Deployment is namespaced; read it through the typed
        // apps/v1 API so `.status` parses without a hand-written schema.
        let namespace = deployment.namespace.as_deref().unwrap_or_default();
        let api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let dep = api.get(&deployment.name).await.map_err(map_cluster_error)?;
        let status = dep.status.as_ref();
        Ok(RolloutStatus {
            generation: dep.metadata.generation.unwrap_or(0),
            observed_generation: status.and_then(|s| s.observed_generation),
            replicas: status.and_then(|s| s.replicas).unwrap_or(0),
            updated_replicas: status.and_then(|s| s.updated_replicas).unwrap_or(0),
            available_replicas: status.and_then(|s| s.available_replicas).unwrap_or(0),
        })
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

    /// Run one `SelfSubjectAccessReview` per operation at the given scope:
    /// `Some(ns)` sets `resourceAttributes.namespace` (namespaced authz),
    /// `None` leaves it unset (cluster-scoped authz — the only way to ask
    /// about a cluster-scoped verb like `clusterrolebindings.create`). Shared
    /// by the namespaced [`Self::review_access`] and the cluster-scoped
    /// [`Self::review_cluster_access`] so both build the request identically.
    async fn review_scoped(
        &self,
        namespace: Option<&str>,
        operations: &[K8sOperation],
    ) -> Result<Vec<OperationDecision>, K8sClientError> {
        let api: Api<SelfSubjectAccessReview> = Api::all(self.client.clone());
        let mut decisions = Vec::with_capacity(operations.len());
        for operation in operations {
            let review = SelfSubjectAccessReview {
                spec: SelfSubjectAccessReviewSpec {
                    resource_attributes: Some(ResourceAttributes {
                        namespace: namespace.map(str::to_string),
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
        self.review_scoped(Some(namespace), operations).await
    }

    async fn review_cluster_access<'a>(
        &'a self,
        operations: &'a [K8sOperation],
    ) -> Result<Vec<OperationDecision>, K8sClientError> {
        self.review_scoped(None, operations).await
    }
}

/// Production [`K8sBootstrapClient`]: applies the rendered RBAC and mints
/// the deployer ServiceAccount's token through a typed [`kube::Client`]
/// connected AS THE ADMIN — the identity with rights to create the SA/Role/
/// RoleBinding and call the TokenRequest subresource.
pub struct KubeBootstrapClient {
    client: kube::Client,
}

impl KubeBootstrapClient {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

impl std::fmt::Debug for KubeBootstrapClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeBootstrapClient")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl K8sBootstrapClient for KubeBootstrapClient {
    async fn apply_rbac(&self, manifest_yaml: &str) -> Result<(), K8sClientError> {
        // The rendered RBAC pack is a multi-document YAML (Namespace + SA +
        // Role + RoleBinding). Parse each document and server-side-apply it
        // through the SAME `KubeCluster::apply` reconcile uses — the
        // env-ownership guard and forced field-manager apply come for free,
        // and a re-bind converges (idempotent).
        let docs: Vec<Value> = serde_yaml_bw::from_multiple(manifest_yaml).map_err(|e| {
            K8sClientError::ApiRejected(format!("rendered RBAC manifest is not valid YAML: {e}"))
        })?;
        let cluster = KubeCluster::new(self.client.clone());
        for doc in &docs {
            cluster
                .apply(doc)
                .await
                .map_err(|e| K8sClientError::ApiRejected(e.to_string()))?;
        }
        Ok(())
    }

    async fn mint_service_account_token(
        &self,
        namespace: &str,
        service_account: &str,
        expiration_seconds: i64,
    ) -> Result<MintedToken, K8sClientError> {
        let api: Api<ServiceAccount> = Api::namespaced(self.client.clone(), namespace);
        // Empty `audiences` ⇒ the API server's default audience (the
        // apiserver itself), so the token authenticates the SA back to the
        // cluster. The server clamps `expiration_seconds` to its configured
        // max; the GRANTED expiry is read back from the status.
        let request = TokenRequest {
            spec: TokenRequestSpec {
                expiration_seconds: Some(expiration_seconds),
                ..Default::default()
            },
            ..Default::default()
        };
        let created = api
            .create_token_request(service_account, &PostParams::default(), &request)
            .await
            .map_err(map_validator_error)?;
        let status = created.status.ok_or_else(|| {
            K8sClientError::ApiRejected(
                "TokenRequest succeeded but returned no status/token".to_string(),
            )
        })?;
        // k8s-openapi 0.27's time backend is `jiff::Timestamp`; the
        // deployer's domain types (`CredentialsExpiry`) use
        // `chrono::DateTime<Utc>`, so convert at this boundary. `None` only
        // on an out-of-chrono-range timestamp, which a real cluster never
        // returns for a token expiry.
        let granted = status.expiration_timestamp.0;
        Ok(MintedToken {
            token: status.token,
            expiration: chrono::DateTime::from_timestamp(
                granted.as_second(),
                granted.subsec_nanosecond() as u32,
            ),
        })
    }

    async fn apply_identity_secret(
        &self,
        namespace: &str,
        name: &str,
        env_id: &str,
        bearer: &str,
    ) -> Result<(), K8sClientError> {
        // Apply the `core/v1 Secret` through the SAME guarded
        // `KubeCluster::apply` as the RBAC: the env-ownership label fail-
        // closes against another env's Secret of this name, the forced
        // field-manager apply overwrites our own field, and a re-bind
        // converges in place. `stringData` lets the apiserver own the
        // base64 encoding; `read_deployer_identity_bearer` reads it back
        // through `data`.
        let manifest = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "greentic",
                    "app.kubernetes.io/component": "deployer-identity",
                    ENV_LABEL: env_id,
                },
            },
            "type": "Opaque",
            "stringData": { DEPLOYER_IDENTITY_BEARER_KEY: bearer },
        });
        KubeCluster::new(self.client.clone())
            .apply(&manifest)
            .await
            .map_err(|e| K8sClientError::ApiRejected(e.to_string()))
    }

    async fn delete_identity_secret(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), K8sClientError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        match api.delete(name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            // Already gone (never written, or a prior cleanup) — idempotent.
            Err(kube::Error::Api(status)) if status.code == 404 => Ok(()),
            Err(e) => Err(map_validator_error(e)),
        }
    }
}

/// Read the deployer's bound bearer back from its in-cluster Secret using an
/// **ambient** connection (`bound_token = None`) — the credential resolver's
/// last-resort source when no local (env-var / dev-store) material is
/// present, e.g. on a fresh operator machine that did not run `--bind`.
///
/// `Ok(None)` when the Secret is absent or carries no non-empty bearer key
/// (treated as "not stored" — the caller fails closed on the original
/// unresolved-credential error). A Secret whose `greentic.ai/env` ownership
/// label is missing or names a DIFFERENT env is a foreign/stale credential and
/// fails closed with [`K8sClientError::IdentityMismatch`] — never trusted.
/// Connection / transport errors propagate so a real cluster-access problem is
/// never silently swallowed.
pub async fn read_deployer_identity_bearer(
    kubeconfig_context: Option<&str>,
    namespace: &str,
    name: &str,
    expected_env: &str,
) -> Result<Option<String>, K8sClientError> {
    let client = connect(kubeconfig_context, None).await?;
    read_identity_bearer_with(&client, namespace, name, expected_env).await
}

/// Read + decode the bearer from an already-connected client. Split from
/// [`read_deployer_identity_bearer`] so the get / label-check / base64-decode
/// path is wire-testable against a mocked client without a kubeconfig.
async fn read_identity_bearer_with(
    client: &kube::Client,
    namespace: &str,
    name: &str,
    expected_env: &str,
) -> Result<Option<String>, K8sClientError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let Some(secret) = api.get_opt(name).await.map_err(map_validator_error)? else {
        return Ok(None);
    };
    // Trust boundary: the Secret MUST carry our env-ownership label and name
    // THIS env, or it is a foreign/stale credential we refuse to bind to (the
    // read mirrors the same `ENV_LABEL` check `KubeCluster::apply` enforces on
    // write). A mismatch is a hard error, not absence, so drift is surfaced
    // rather than silently selecting the wrong identity.
    let owner = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(ENV_LABEL))
        .map(String::as_str);
    if owner != Some(expected_env) {
        return Err(K8sClientError::IdentityMismatch(format!(
            "Secret `{name}` in `{namespace}` is labelled `{ENV_LABEL}={}`, not `{expected_env}`",
            owner.unwrap_or("<unset>")
        )));
    }
    let bearer = secret
        .data
        .and_then(|mut data| data.remove(DEPLOYER_IDENTITY_BEARER_KEY))
        .and_then(|bytes| String::from_utf8(bytes.0).ok())
        .filter(|value| !value.is_empty());
    Ok(bearer)
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
            "metadata": {
                "name": "gtc-worker-a",
                "namespace": "gtc-zain",
                "labels": {"greentic.ai/env": "gtc-zain"},
            },
            "spec": {"replicas": 1},
        })
    }

    /// 404 Status body — `get_opt` interprets this as `Ok(None)`.
    fn not_found_status() -> Value {
        json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "code": 404,
            "reason": "NotFound",
            "message": "not found",
        })
    }

    /// Drive a happy-path `apply`: answer the ownership GET with a 404
    /// (no existing object) then the PATCH with 200, asserting success.
    /// Returns the captured PATCH request for the caller's assertions.
    async fn apply_ok(
        cluster: &KubeCluster,
        handle: &mut MockHandle,
        manifest: &Value,
    ) -> Request<Body> {
        let respond = async {
            let _get = respond_json(handle, 404, not_found_status()).await;
            respond_json(handle, 200, manifest.clone()).await
        };
        let (result, patch) = tokio::join!(cluster.apply(manifest), respond);
        result.unwrap();
        patch
    }

    #[tokio::test]
    async fn apply_is_forced_server_side_apply_with_field_manager() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let manifest = deployment_manifest();

        let request = apply_ok(&cluster, &mut handle, &manifest).await;

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

        let request = apply_ok(&cluster, &mut handle, &manifest).await;
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
        let request = apply_ok(&cluster, &mut handle, &netpol).await;
        assert_eq!(
            request.uri().path(),
            "/apis/networking.k8s.io/v1/namespaces/gtc-zain/networkpolicies/deny-all"
        );

        let pdb = json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {"name": "router", "namespace": "gtc-zain"},
        });
        let request = apply_ok(&cluster, &mut handle, &pdb).await;
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
            namespace: Some("gtc-zain".into()),
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
    async fn get_rollout_status_reads_generation_and_available_replicas() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let object = worker_object_ref();
        let (result, request) = tokio::join!(
            cluster.get_rollout_status(&object),
            respond_json(
                &mut handle,
                200,
                json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "gtc-worker-a", "namespace": "gtc-zain", "generation": 3},
                    "spec": {"replicas": 1},
                    "status": {
                        "observedGeneration": 3,
                        "replicas": 1,
                        "updatedReplicas": 1,
                        "availableReplicas": 1,
                    },
                }),
            ),
        );
        let status = result.unwrap();
        assert_eq!(status.generation, 3);
        assert_eq!(status.observed_generation, Some(3));
        assert_eq!(status.replicas, 1);
        assert_eq!(status.updated_replicas, 1);
        assert_eq!(status.available_replicas, 1);
        assert!(
            status.is_complete(1),
            "observed caught up + the updated replica available, none lingering"
        );
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(
            request.uri().path(),
            "/apis/apps/v1/namespaces/gtc-zain/deployments/gtc-worker-a"
        );
    }

    #[tokio::test]
    async fn get_rollout_status_treats_missing_status_as_not_yet_available() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let object = worker_object_ref();
        let (result, _request) = tokio::join!(
            cluster.get_rollout_status(&object),
            respond_json(
                &mut handle,
                200,
                json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "gtc-worker-a", "namespace": "gtc-zain", "generation": 1},
                    "spec": {"replicas": 1},
                }),
            ),
        );
        let status = result.unwrap();
        assert_eq!(status.observed_generation, None);
        assert_eq!(status.replicas, 0);
        assert_eq!(status.updated_replicas, 0);
        assert_eq!(status.available_replicas, 0);
        assert!(
            !status.is_complete(1),
            "a Deployment with no status yet is not ready"
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

    #[tokio::test]
    async fn review_cluster_access_omits_the_namespace_for_a_cluster_scoped_verb() {
        let (client, mut handle) = mock_client();
        let validator = KubeValidatorClient::new(client);
        let operations = [K8sOperation {
            group: "rbac.authorization.k8s.io",
            resource: "clusterrolebindings",
            verb: "create",
        }];
        let (result, request) = tokio::join!(
            validator.review_cluster_access(&operations),
            respond_json(&mut handle, 201, ssar_response(true, None)),
        );
        let decisions = result.unwrap();
        assert_eq!(decisions[0].operation, operations[0]);
        assert_eq!(decisions[0].decision, AccessDecision::Allowed);

        let body = request_body_json(request).await;
        let attrs = &body["spec"]["resourceAttributes"];
        // A cluster-scoped review must NOT carry a namespace — otherwise the
        // API server answers a namespaced question and a cluster-admin-less
        // token could look "allowed" for the wrong scope.
        assert!(
            attrs.get("namespace").is_none() || attrs["namespace"].is_null(),
            "cluster-scoped SSAR must omit namespace, got {attrs}"
        );
        assert_eq!(attrs["resource"], json!("clusterrolebindings"));
        assert_eq!(attrs["verb"], json!("create"));
    }

    // ── apply_bound_token ──────────────────────────────────────────

    #[test]
    fn apply_bound_token_sets_token_when_some() {
        let mut cfg = kube::Config::new("https://example.invalid/".parse().unwrap());
        assert!(cfg.auth_info.token.is_none());
        apply_bound_token(&mut cfg, Some("tok"));
        assert!(cfg.auth_info.token.is_some());
    }

    #[test]
    fn apply_bound_token_clears_competing_auth_and_impersonation() {
        // A cert-based context (kind's default) that also impersonates: the
        // bound token must become the sole credential AND the effective
        // identity — else the cert shadows the bearer at the handshake, or the
        // Impersonate-* headers re-attribute the request to another user.
        let mut cfg = kube::Config::new("https://example.invalid/".parse().unwrap());
        cfg.auth_info.client_certificate_data = Some("cert".to_string());
        cfg.auth_info.client_key_data = Some("key".to_string().into());
        cfg.auth_info.impersonate = Some("admin-user".to_string());
        cfg.auth_info.impersonate_groups = Some(vec!["system:masters".to_string()]);
        apply_bound_token(&mut cfg, Some("tok"));
        assert!(cfg.auth_info.token.is_some());
        assert!(cfg.auth_info.client_certificate_data.is_none());
        assert!(cfg.auth_info.client_key_data.is_none());
        assert!(cfg.auth_info.impersonate.is_none());
        assert!(cfg.auth_info.impersonate_groups.is_none());
    }

    #[test]
    fn apply_bound_token_leaves_none_when_none() {
        let mut cfg = kube::Config::new("https://example.invalid/".parse().unwrap());
        apply_bound_token(&mut cfg, None);
        assert!(cfg.auth_info.token.is_none());
    }

    // ── ownership guard ────────────────────────────────────────────

    #[tokio::test]
    async fn apply_rejects_a_foreign_owned_object() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let manifest = deployment_manifest(); // env label = "gtc-zain"

        // Existing object belongs to a different env.
        let existing = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "gtc-worker-a",
                "namespace": "gtc-zain",
                "labels": {"greentic.ai/env": "other-env"},
            },
        });

        let respond = async {
            // GET returns the foreign-owned object.
            respond_json(&mut handle, 200, existing).await
            // No PATCH must follow — the guard rejects before patching.
        };
        let (result, _get_request) = tokio::join!(cluster.apply(&manifest), respond);
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                K8sClusterError::OwnershipConflict {
                    ref existing_env,
                    ref incoming_env,
                    ..
                } if existing_env == "other-env" && incoming_env == "gtc-zain"
            ),
            "expected OwnershipConflict, got {err:?}"
        );
    }

    #[tokio::test]
    async fn apply_proceeds_when_existing_object_is_same_env() {
        let (client, mut handle) = mock_client();
        let cluster = KubeCluster::new(client);
        let manifest = deployment_manifest(); // env label = "gtc-zain"

        // Existing object has the SAME env label.
        let existing = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "gtc-worker-a",
                "namespace": "gtc-zain",
                "labels": {"greentic.ai/env": "gtc-zain"},
            },
        });

        let respond = async {
            let _get = respond_json(&mut handle, 200, existing).await;
            respond_json(&mut handle, 200, manifest.clone()).await
        };
        let (result, patch_request) = tokio::join!(cluster.apply(&manifest), respond);
        result.unwrap();
        // The PATCH was actually sent.
        assert_eq!(patch_request.method(), http::Method::PATCH);
    }

    #[tokio::test]
    async fn mint_service_account_token_posts_tokenrequest_and_reads_back_status() {
        let (client, mut handle) = mock_client();
        let bootstrap = KubeBootstrapClient::new(client);

        // The API server answers the TokenRequest subresource POST with a
        // populated status (token + granted expiry, RFC3339).
        let body = json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "metadata": {},
            "spec": {"expirationSeconds": 3600},
            "status": {"token": "MINTED_SA_TOKEN", "expirationTimestamp": "2033-05-18T03:33:20Z"}
        });
        let respond = respond_json(&mut handle, 201, body);
        let (result, request) = tokio::join!(
            bootstrap.mint_service_account_token("gtc-local", "greentic-deployer", 3600),
            respond
        );
        let minted = result.expect("mint ok");

        assert_eq!(minted.token, "MINTED_SA_TOKEN");
        // The granted expiry round-trips through the jiff→chrono conversion.
        assert!(
            minted
                .expiration
                .expect("expiry present")
                .to_rfc3339()
                .starts_with("2033-05-18T03:33:20"),
            "unexpected expiry: {:?}",
            minted.expiration
        );
        // POST to the ServiceAccount's `token` subresource.
        assert_eq!(request.method(), http::Method::POST);
        assert!(
            request
                .uri()
                .path()
                .ends_with("/namespaces/gtc-local/serviceaccounts/greentic-deployer/token"),
            "unexpected path: {}",
            request.uri().path()
        );
    }

    #[tokio::test]
    async fn apply_rbac_applies_each_rendered_document() {
        let (client, mut handle) = mock_client();
        let bootstrap = KubeBootstrapClient::new(client);

        // A two-document RBAC manifest (ServiceAccount + Role) — exercises
        // the new SA/Role routing rows and the multi-document YAML split.
        let manifest = "\
apiVersion: v1
kind: ServiceAccount
metadata:
  name: greentic-deployer
  namespace: gtc-local
  labels:
    greentic.ai/env: \"local\"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: greentic-deployer-min
  namespace: gtc-local
  labels:
    greentic.ai/env: \"local\"
rules:
  - apiGroups: [\"apps\"]
    resources: [\"deployments\"]
    verbs: [get]
";
        // Each document applies as ownership GET (404 ⇒ create) then a forced
        // PATCH; two documents ⇒ four requests, in order.
        let respond = async {
            for _ in 0..2 {
                let applied = json!({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "x"}});
                let _get = respond_json(&mut handle, 404, not_found_status()).await;
                let _patch = respond_json(&mut handle, 200, applied).await;
            }
        };
        let (result, ()) = tokio::join!(bootstrap.apply_rbac(manifest), respond);
        result.expect("apply_rbac applies both documents");
    }

    #[tokio::test]
    async fn apply_identity_secret_applies_a_labelled_namespaced_secret() {
        let (client, mut handle) = mock_client();
        let bootstrap = KubeBootstrapClient::new(client);

        // `KubeCluster::apply` does ownership GET (404 ⇒ create) then forced
        // PATCH — assert the PATCH targets the namespaced Secret and carries
        // the env-ownership label + the bearer in `stringData`.
        let respond = async {
            let _get = respond_json(&mut handle, 404, not_found_status()).await;
            let applied = json!({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "x"}});
            respond_json(&mut handle, 200, applied).await
        };
        let (result, patch_request) = tokio::join!(
            bootstrap.apply_identity_secret(
                "gtc-local",
                "greentic-deployer-identity",
                "local",
                "MINTED_SA_TOKEN",
            ),
            respond
        );
        result.expect("apply_identity_secret applies the Secret");

        assert_eq!(patch_request.method(), http::Method::PATCH);
        assert!(
            patch_request
                .uri()
                .path()
                .ends_with("/namespaces/gtc-local/secrets/greentic-deployer-identity"),
            "unexpected path: {}",
            patch_request.uri().path()
        );
        let body = request_body_json(patch_request).await;
        assert_eq!(
            body["metadata"]["labels"]["greentic.ai/env"],
            json!("local")
        );
        assert_eq!(body["stringData"]["bearer"], json!("MINTED_SA_TOKEN"));
        // The bearer must NOT leak into a plaintext `data` field on the wire.
        assert!(
            body.get("data").is_none(),
            "bearer should ride in stringData"
        );
    }

    #[tokio::test]
    async fn read_identity_bearer_with_decodes_the_stored_bearer() {
        let (client, mut handle) = mock_client();
        // k8s returns Secret `data` base64-encoded; kube-rs decodes to bytes.
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "MINTED_SA_TOKEN",
        );
        let body = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "greentic-deployer-identity",
                "namespace": "gtc-local",
                "labels": {"greentic.ai/env": "local"},
            },
            "data": {"bearer": encoded},
        });
        let respond = respond_json(&mut handle, 200, body);
        let (result, request) = tokio::join!(
            read_identity_bearer_with(&client, "gtc-local", "greentic-deployer-identity", "local"),
            respond
        );
        assert_eq!(
            result.expect("read ok"),
            Some("MINTED_SA_TOKEN".to_string())
        );
        assert_eq!(request.method(), http::Method::GET);
        assert!(
            request
                .uri()
                .path()
                .ends_with("/namespaces/gtc-local/secrets/greentic-deployer-identity"),
            "unexpected path: {}",
            request.uri().path()
        );
    }

    #[tokio::test]
    async fn read_identity_bearer_with_rejects_a_foreign_env_labelled_secret() {
        let (client, mut handle) = mock_client();
        // A Secret of the right name but labelled for a DIFFERENT env (or
        // unlabelled) is a foreign/stale credential — fail closed, never trust.
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "FOREIGN_TOKEN");
        let body = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "greentic-deployer-identity",
                "namespace": "gtc-local",
                "labels": {"greentic.ai/env": "other-env"},
            },
            "data": {"bearer": encoded},
        });
        let respond = respond_json(&mut handle, 200, body);
        let (result, _request) = tokio::join!(
            read_identity_bearer_with(&client, "gtc-local", "greentic-deployer-identity", "local"),
            respond
        );
        assert!(
            matches!(result, Err(K8sClientError::IdentityMismatch(_))),
            "a wrong-env-labelled Secret must fail closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn read_identity_bearer_with_is_none_when_the_secret_is_absent() {
        let (client, mut handle) = mock_client();
        let respond = respond_json(&mut handle, 404, not_found_status());
        let (result, _request) = tokio::join!(
            read_identity_bearer_with(&client, "gtc-local", "greentic-deployer-identity", "local"),
            respond
        );
        assert_eq!(result.expect("absent secret is Ok(None)"), None);
    }
}
