//! [`DeployerCredentials`] impl for the K8s deployer env-pack (Phase D
//! plan §6 step 6).
//!
//! Three trust boundaries stay separate (Q3): human cluster access,
//! deployer API access, pod workload identity. This contract covers the
//! middle one — the identity the DEPLOYER calls the Kubernetes API with.
//!
//! Validation is `SelfSubjectAccessReview` against the EXACT operations
//! the deployer performs ([`VALIDATED_K8S_OPERATIONS`]) — the same list
//! the bootstrap rules pack derives its Role rules from, so the
//! bootstrap-then-validate loop converges exactly like the AWS-ECS
//! `VALIDATED_IAM_VERBS` precedent.
//!
//! ## Default posture: probes FAIL CLOSED until a client is bound
//!
//! The typed Kubernetes API client exists
//! ([`KubeValidatorClient`](super::kube_client::KubeValidatorClient),
//! `k8s-client` feature); the `op credentials requirements` CLI connects
//! it from the binding's answers (ambient identity, like `reconcile`) and
//! injects it via [`with_client`](K8sDeployerCredentials::with_client) — the
//! runner's `creds_override` seam. [`K8sDeployerCredentials::default`] holds
//! no client (the fail-closed posture for any caller that doesn't inject one,
//! e.g. a `--no-default-features` build) and
//! every probe reports [`CapabilityStatus::Fail`] — NOT `Skipped`,
//! because `RequirementsReport::passed()` treats `Skipped` as non-
//! blocking (it only checks for `Fail`), so an all-`Skipped` report
//! would persist `CredentialsValidationResult::Pass` with zero actual
//! checks. Failing closed matches the AWS credential-chain-missing
//! precedent and ensures `gtc op credentials requirements` never
//! reports a false pass. The decision logic (reachable → per-op SSAR →
//! Pass/Fail mapping) is fully implemented and pinned by mock-client
//! tests, so the real client plugs into [`K8sValidatorClient`] without
//! touching `validate`.
//!
//! ## Bootstrap
//!
//! [`bootstrap`](DeployerCredentials::bootstrap) emits a minimum-privilege
//! Namespace + ServiceAccount + Role + RoleBinding rules pack
//! ([`super::bootstrap`]) for the customer's cluster admin to review and
//! `kubectl apply` offline. `bound_credentials_ref: None` — the admin
//! applies the pack, mints a short-lived token for the ServiceAccount
//! (`kubectl create token`, per the plan's no-long-lived-bearer-token
//! rule), and binds it via `op credentials rotate`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use greentic_deploy_spec::SecretRef;
use zeroize::Zeroizing;

use crate::credentials::{
    BootstrapError, BootstrapInput, BootstrapOutcome, Capability, CapabilityCheck,
    CapabilityStatus, DeployerCredentials, RequirementsReport, RulesPack, ValidationContext,
};

use super::async_bridge::run_k8s_async;
use super::bootstrap::{
    DEPLOYER_IDENTITY_SECRET_NAME, DEPLOYER_SERVICE_ACCOUNT, DEPLOYER_TOKEN_STORE_PATH,
    K8S_RBAC_MANIFEST_FILENAME, K8sRulesPackInput, render_min_rbac_rules_pack,
};
use super::manifests::namespace_for_env;

/// Lifetime requested for the bound ServiceAccount token (1 year). The API
/// server clamps this to its `--service-account-max-token-expiration`, so
/// the GRANTED expiry (read back from the TokenRequest status) may be
/// sooner — the runner records it as the re-bind deadline. `op credentials
/// rotate --if-needed` re-mints in place once the token passes 80% of its
/// (clamped) lifetime, so a scheduled job keeps it fresh without a full
/// re-bind.
const BIND_TOKEN_EXPIRATION_SECONDS: i64 = 365 * 24 * 60 * 60;

/// Stable ID for the API-reachability probe (identity resolves against
/// the cluster — the K8s analogue of `aws.sts.caller-identity`).
pub const K8S_API_REACHABLE_CAP: &str = "k8s.api.reachable";

/// One namespaced Kubernetes operation the deployer performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct K8sOperation {
    /// API group (`""` = core).
    pub group: &'static str,
    pub resource: &'static str,
    pub verb: &'static str,
}

impl K8sOperation {
    /// Canonical capability ID: `k8s.rbac.allow:<group|core>/<resource>:<verb>`.
    pub fn capability_id(&self) -> String {
        let group = if self.group.is_empty() {
            "core"
        } else {
            self.group
        };
        format!("k8s.rbac.allow:{group}/{}:{}", self.resource, self.verb)
    }
}

/// Convenience constructor keeping the operations table readable.
const fn op(group: &'static str, resource: &'static str, verb: &'static str) -> K8sOperation {
    K8sOperation {
        group,
        resource,
        verb,
    }
}

/// The exact namespaced operations the deployer's verbs + renderer touch.
/// Order is stable — `required_capabilities` renders them in this order,
/// the bootstrap Role rules aggregate from this list, and validate's
/// SSAR probes iterate it 1:1.
///
/// Deployments/Services carry `delete` (archive tears workers down); Secrets
/// also carry `delete` (a DevStore→Vault reconcile removes the stale dev-store
/// Secret). ConfigMaps/PDBs/NetworkPolicies/ServiceAccounts are env-lifetime
/// objects the deployer only upserts.
///
/// This list is namespaced-only and aggregates exactly the verbs a bound
/// (namespace-scoped) deployer ServiceAccount needs to drive `op env reconcile`.
/// The one object reconcile would otherwise apply outside this scope — the
/// cluster-scoped Namespace — is dropped from the applied set for a bound
/// identity (`K8sDeployerHandler::reconcile`'s `manage_namespace`), since
/// `bootstrap --bind` already creates the namespace. So passing `requirements`
/// now implies a bound identity can also reconcile; the earlier namespace-apply
/// trust gap is closed.
pub const VALIDATED_K8S_OPERATIONS: &[K8sOperation] = &[
    op("apps", "deployments", "get"),
    op("apps", "deployments", "create"),
    op("apps", "deployments", "patch"),
    op("apps", "deployments", "delete"),
    op("", "services", "get"),
    op("", "services", "create"),
    op("", "services", "patch"),
    op("", "services", "delete"),
    op("", "configmaps", "get"),
    op("", "configmaps", "create"),
    op("", "configmaps", "patch"),
    // The dev-store Secret (env-lifetime) delivers the operator's
    // `.dev.secrets.env` so workers resolve `secret://` refs in-pod. `delete`
    // lets a DevStore→Vault reconcile remove the stale Secret so no secret
    // material lingers once the env resolves under workload identity. Without
    // these verbs a bound identity 403s on reconcile.
    op("", "secrets", "get"),
    op("", "secrets", "create"),
    op("", "secrets", "patch"),
    op("", "secrets", "delete"),
    // The worker ServiceAccount the Vault backend authenticates as
    // (env-lifetime, upsert-only). Rendered only for Vault envs, but the bound
    // Role grants these unconditionally so a Vault reconcile never 403s
    // applying it.
    op("", "serviceaccounts", "get"),
    op("", "serviceaccounts", "create"),
    op("", "serviceaccounts", "patch"),
    op("policy", "poddisruptionbudgets", "get"),
    op("policy", "poddisruptionbudgets", "create"),
    op("policy", "poddisruptionbudgets", "patch"),
    op("networking.k8s.io", "networkpolicies", "get"),
    op("networking.k8s.io", "networkpolicies", "create"),
    op("networking.k8s.io", "networkpolicies", "patch"),
];

/// Identity the cluster resolved for the deployer's credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterIdentity {
    /// e.g. `system:serviceaccount:gtc-zain-prod:greentic-deployer`.
    pub user: String,
}

/// One `SelfSubjectAccessReview` outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Allowed,
    /// Carries the API server's reason when it supplies one.
    Denied(String),
}

/// Per-operation review result, in request order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationDecision {
    pub operation: K8sOperation,
    pub decision: AccessDecision,
}

/// Errors the validator client can surface. All variants flow into
/// `CapabilityStatus::Fail { reason }` — transport vs. auth is not
/// distinguished because the operator's fix path is the same (fix
/// kubeconfig / cluster access, re-run requirements).
#[derive(Debug, thiserror::Error)]
pub enum K8sClientError {
    #[error("no usable Kubernetes credentials: {0}")]
    NoClusterAccess(String),
    #[error("Kubernetes API rejected the call: {0}")]
    ApiRejected(String),
    #[error("Kubernetes API transport error: {0}")]
    Transport(String),
    /// A cluster object claimed to hold a credential but its env-ownership
    /// label does not match the env resolving it — refuse to trust a
    /// foreign/stale identity Secret rather than silently binding to it.
    #[error("in-cluster identity mismatch: {0}")]
    IdentityMismatch(String),
}

/// Pluggable validator client. Unit tests mock this; the production
/// impl is [`KubeValidatorClient`](super::kube_client::KubeValidatorClient).
#[async_trait::async_trait]
pub trait K8sValidatorClient: std::fmt::Debug + Send + Sync {
    /// Resolve the credential's cluster identity (SelfSubjectReview).
    async fn who_am_i(&self) -> Result<ClusterIdentity, K8sClientError>;

    /// Run one `SelfSubjectAccessReview` per operation, scoped to
    /// `namespace`. Returns one decision per operation, in the SAME order
    /// as the input `operations` slice — `validate()` enforces both the
    /// count and per-index operation identity defensively (a partial or
    /// re-ordered response must never authorize).
    async fn review_access<'a>(
        &'a self,
        namespace: &'a str,
        operations: &'a [K8sOperation],
    ) -> Result<Vec<OperationDecision>, K8sClientError>;

    /// Run one `SelfSubjectAccessReview` per operation at CLUSTER scope (no
    /// namespace). Same ordering/decision contract as [`Self::review_access`].
    /// The `env up` Vault phase uses this to preflight
    /// `clusterrolebindings.create` before applying the dev Vault's
    /// cluster-scoped `system:auth-delegator` binding — a namespaced SSAR
    /// cannot express a cluster-scoped verb.
    async fn review_cluster_access<'a>(
        &'a self,
        operations: &'a [K8sOperation],
    ) -> Result<Vec<OperationDecision>, K8sClientError>;
}

/// Future yielded by a [`K8sValidatorConnector`].
pub type K8sValidatorConnectFut =
    Pin<Box<dyn Future<Output = Result<Arc<dyn K8sValidatorClient>, K8sClientError>> + Send>>;

/// Lazily produces a connected validator client INSIDE the probe runtime.
///
/// A `kube::Client`'s tower `Buffer` worker is spawned on whichever runtime
/// first drives the connect future and is aborted when that runtime is
/// dropped. [`run_k8s_async`] runs each future on a dedicated thread with its
/// own current-thread runtime and drops it on return, so the connect and the
/// probes MUST share a single `run_k8s_async` call — a client connected in an
/// earlier bridge call would hand `validate` a dead worker (`buffer's worker
/// closed unexpectedly`). The connector defers the connect into the probe
/// runtime; tests supply one that just returns a mock.
pub type K8sValidatorConnector = Arc<dyn Fn() -> K8sValidatorConnectFut + Send + Sync>;

/// A freshly minted ServiceAccount token and the absolute expiry the
/// cluster granted. The API server clamps the requested lifetime to its
/// `--service-account-max-token-expiration`, so `expiration` (read back
/// from the TokenRequest status) is the authoritative re-bind deadline —
/// it may be sooner than requested.
pub struct MintedToken {
    pub token: String,
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render `token` — it is live bearer material.
        f.debug_struct("MintedToken")
            .field("token", &"<redacted>")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Future yielded by a [`K8sBootstrapConnector`].
pub type K8sBootstrapConnectFut =
    Pin<Box<dyn Future<Output = Result<Arc<dyn K8sBootstrapClient>, K8sClientError>> + Send>>;

/// Lazily produces a connected bootstrap client INSIDE the bind runtime —
/// same `kube::Client` Buffer-worker runtime constraint as
/// [`K8sValidatorConnector`] (connect + apply + mint MUST share one
/// [`run_k8s_async`] call).
pub type K8sBootstrapConnector = Arc<dyn Fn() -> K8sBootstrapConnectFut + Send + Sync>;

/// Provider-side client for the `--bind` bootstrap path: applies the
/// rendered RBAC and mints the deployer ServiceAccount's token, connected
/// AS THE ADMIN identity (the one with rights to create the SA/Role/
/// RoleBinding and call TokenRequest). The production impl is
/// [`KubeBootstrapClient`](super::kube_client::KubeBootstrapClient); unit
/// tests mock it.
#[async_trait::async_trait]
pub trait K8sBootstrapClient: std::fmt::Debug + Send + Sync {
    /// Server-side-apply the rendered RBAC manifest (a multi-document YAML
    /// of Namespace + ServiceAccount + Role + RoleBinding). Idempotent —
    /// re-applying the same manifest converges, so a retried bind is safe.
    async fn apply_rbac(&self, manifest_yaml: &str) -> Result<(), K8sClientError>;

    /// Mint a ServiceAccount token via the TokenRequest subresource,
    /// scoped to `namespace`/`service_account`, requesting
    /// `expiration_seconds` of lifetime (the cluster may grant less).
    async fn mint_service_account_token(
        &self,
        namespace: &str,
        service_account: &str,
        expiration_seconds: i64,
    ) -> Result<MintedToken, K8sClientError>;

    /// Server-side-apply a `core/v1 Secret` (named `name`, env-ownership
    /// labelled `env_id`) holding the minted `bearer` in `namespace` — the
    /// durable in-cluster home for the bound identity. Goes through the SAME
    /// guarded `KubeCluster::apply` as `apply_rbac`, so the ownership guard
    /// fail-closes against a different env's Secret of this name and a
    /// re-bind overwrites the bearer in place (idempotent).
    async fn apply_identity_secret(
        &self,
        namespace: &str,
        name: &str,
        env_id: &str,
        bearer: &str,
    ) -> Result<(), K8sClientError>;

    /// Delete the bound identity Secret — the compensating-cleanup path when a
    /// `--bind` bootstrap fails after the Secret was written. Idempotent: a
    /// missing Secret (404) is `Ok(())`.
    async fn delete_identity_secret(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), K8sClientError>;
}

/// K8s deployer credentials handler.
///
/// `Default` holds no connector (every probe fails closed);
/// [`with_client`](Self::with_client) injects a mock in tests and
/// [`with_connector`](Self::with_connector) defers a live
/// [`KubeValidatorClient`](super::kube_client::KubeValidatorClient) connect
/// into the probe runtime.
#[derive(Default)]
pub struct K8sDeployerCredentials {
    connect: Option<K8sValidatorConnector>,
    /// Namespace the SSAR sweep is scoped to. `None` ⇒ the env-derived
    /// `namespace_for_env`; the CLI sets it from the binding answers'
    /// resolved `K8sParams::namespace` so requirements probes the EXACT
    /// namespace reconcile / apply-revision deploy into (a custom
    /// `namespace` answer would otherwise be probed at `gtc-<env>`).
    namespace: Option<String>,
    /// Bootstrap (`--bind`) connector: when `Some`, `bootstrap` applies the
    /// rendered RBAC live and mints the ServiceAccount token instead of
    /// emitting a render-only pack. The CLI wires this (admin-connected)
    /// only for `op credentials bootstrap … bind: true`; it is independent
    /// of `connect` (the validator probe seam) — the two paths never run
    /// together.
    bind: Option<K8sBootstrapConnector>,
}

impl std::fmt::Debug for K8sDeployerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connector is a closure (no `Debug`); surface only whether one
        // is bound — that's all any caller diagnoses on.
        f.debug_struct("K8sDeployerCredentials")
            .field("connect", &self.connect.is_some())
            .field("namespace", &self.namespace)
            .field("bind", &self.bind.is_some())
            .finish()
    }
}

impl K8sDeployerCredentials {
    /// Inject an already-connected validator (tests / mock). The connector
    /// simply hands it back inside the probe runtime.
    pub fn with_client(client: Arc<dyn K8sValidatorClient>) -> Self {
        Self::with_connector(Arc::new(move || -> K8sValidatorConnectFut {
            let client = client.clone();
            Box::pin(async move { Ok(client) })
        }))
    }

    /// Connect a live validator lazily, inside the probe runtime. See
    /// [`K8sValidatorConnector`] for why connect + probes must share a
    /// runtime.
    pub fn with_connector(connect: K8sValidatorConnector) -> Self {
        Self {
            connect: Some(connect),
            namespace: None,
            bind: None,
        }
    }

    /// Build credentials wired for the `--bind` bootstrap path: a connector
    /// that connects AS THE ADMIN (no bound SA token) and applies the
    /// rendered RBAC + mints the deployer ServiceAccount's token. Holds no
    /// validator connector — `validate` is not the bind path's concern, and
    /// the two never run on the same instance.
    pub fn with_bootstrap_connector(bind: K8sBootstrapConnector) -> Self {
        Self {
            connect: None,
            namespace: None,
            bind: Some(bind),
        }
    }

    /// Scope the SSAR sweep to `namespace` instead of the env-derived
    /// default — the namespace reconcile actually deploys into.
    pub fn in_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    fn reachable_capability(&self) -> Capability {
        Capability::new(
            K8S_API_REACHABLE_CAP,
            "Kubernetes API is reachable and the credential resolves to an identity \
             (SelfSubjectReview)",
        )
    }

    fn operation_capability(&self, operation: &K8sOperation) -> Capability {
        Capability::new(
            operation.capability_id(),
            format!(
                "RBAC allows `{}` on `{}` in the env namespace",
                operation.verb, operation.resource
            ),
        )
    }

    /// Reachability passed but the SSAR sweep itself errored: the
    /// reachable cap passes, every operation cap fails with the same
    /// reason (mirror of the AWS `sts_pass_verbs_failed` shape).
    fn reachable_pass_ops_failed(&self, reason: &str) -> RequirementsReport {
        let mut checks = Vec::with_capacity(1 + VALIDATED_K8S_OPERATIONS.len());
        checks.push(CapabilityCheck {
            capability: self.reachable_capability(),
            status: CapabilityStatus::Pass,
        });
        for operation in VALIDATED_K8S_OPERATIONS {
            checks.push(CapabilityCheck {
                capability: self.operation_capability(operation),
                status: CapabilityStatus::Fail {
                    reason: reason.to_string(),
                },
            });
        }
        RequirementsReport::new(checks)
    }
}

/// Decode a JWT bearer's `iat`/`exp` claims (the projected ServiceAccount
/// token is a signed JWT). Signature is NOT verified — this reads the token's
/// self-reported lifetime to schedule a proactive re-mint, never to authorize
/// anything. Returns `None` on any structural failure.
fn decode_token_lifetime(bearer: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let payload_b64 = bearer.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let iat = DateTime::from_timestamp(claims.get("iat")?.as_i64()?, 0)?;
    let exp = DateTime::from_timestamp(claims.get("exp")?.as_i64()?, 0)?;
    Some((iat, exp))
}

impl DeployerCredentials for K8sDeployerCredentials {
    fn requires_credentials_material(&self) -> bool {
        true
    }

    /// The projected ServiceAccount token is a JWT; decode its self-reported
    /// `iat`/`exp` and schedule the re-mint at 80% of lifetime (the shared
    /// policy in [`rotate_at_from_window`](crate::credentials::rotate)).
    /// `None` for material that isn't a JWT with both claims — the caller then
    /// fails open and rotates.
    fn rotate_at(&self, material: &str) -> Option<DateTime<Utc>> {
        let (iat, exp) = decode_token_lifetime(material)?;
        Some(crate::credentials::rotate::rotate_at_from_window(iat, exp))
    }

    fn required_capabilities(&self) -> Vec<Capability> {
        let mut caps = Vec::with_capacity(1 + VALIDATED_K8S_OPERATIONS.len());
        caps.push(self.reachable_capability());
        for operation in VALIDATED_K8S_OPERATIONS {
            caps.push(self.operation_capability(operation));
        }
        caps
    }

    fn validate(&self, ctx: &ValidationContext<'_>) -> RequirementsReport {
        let caps = self.required_capabilities();

        let Some(connect) = self.connect.as_ref() else {
            // No connector bound — Fail, not Skipped.
            // `RequirementsReport::passed()` treats Skipped as
            // non-blocking, so an all-Skipped report would persist
            // `result: pass` even though zero capabilities were actually
            // verified. Failing closed matches the AWS precedent (chain-
            // missing → every cap Fail) and ensures `gtc op credentials
            // requirements` never reports a false pass.
            return RequirementsReport::new(
                caps.into_iter()
                    .map(|capability| CapabilityCheck {
                        capability,
                        status: CapabilityStatus::Fail {
                            reason: "no Kubernetes API client is bound to these \
                                     credentials; `gtc op credentials requirements` \
                                     connects a live client when built with the \
                                     `k8s-client` feature — failing closed"
                                .to_string(),
                        },
                    })
                    .collect(),
            );
        };

        // Scope the SSARs to the namespace reconcile actually deploys into
        // (the binding answers' resolved namespace), falling back to the
        // env-derived default when the caller did not supply one.
        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| namespace_for_env(ctx.env_id));

        // Connect + identity + access probes all run on ONE runtime. A
        // kube::Client's tower Buffer worker is bound to the runtime that
        // spawned it, and `run_k8s_async` drops its runtime after each call —
        // connecting in a separate bridge call would hand us a dead worker
        // (`buffer's worker closed unexpectedly`). See `K8sValidatorConnector`.
        let connector = Arc::clone(connect);
        let decisions = match run_k8s_async(async move {
            let connect_fn = connector.as_ref();
            let client = connect_fn().await.map_err(K8sProbeError::Connect)?;
            client.who_am_i().await.map_err(K8sProbeError::Identity)?;
            client
                .review_access(&namespace, VALIDATED_K8S_OPERATIONS)
                .await
                .map_err(K8sProbeError::Access)
        }) {
            Ok(v) => v,
            Err(K8sProbeError::Connect(e)) => {
                // Couldn't even reach/authenticate — the reachability cap
                // (and every op) fails closed, same posture as a failed
                // identity probe.
                return all_failed(&caps, &format!("Kubernetes API unreachable: {e}"));
            }
            Err(K8sProbeError::Identity(e)) => {
                // No usable identity — fail every cap (a deployer that
                // requires credential material treats this as auth failure,
                // not a skip), mirroring the AWS chain-missing posture.
                return all_failed(&caps, &format!("SelfSubjectReview failed: {e}"));
            }
            Err(K8sProbeError::Access(e)) => {
                return self
                    .reachable_pass_ops_failed(&format!("SelfSubjectAccessReview failed: {e}"));
            }
        };

        // Validate response shape BEFORE building per-op checks: a
        // partial or mis-ordered response must never authorize.
        if decisions.len() != VALIDATED_K8S_OPERATIONS.len() {
            return self.reachable_pass_ops_failed(&format!(
                "SelfSubjectAccessReview returned {} decisions for {} operations",
                decisions.len(),
                VALIDATED_K8S_OPERATIONS.len()
            ));
        }
        for (i, (expected, actual)) in VALIDATED_K8S_OPERATIONS
            .iter()
            .zip(decisions.iter())
            .enumerate()
        {
            if actual.operation != *expected {
                return self.reachable_pass_ops_failed(&format!(
                    "SelfSubjectAccessReview decision[{i}] operation mismatch: \
                     expected `{}`, got `{}`",
                    expected.capability_id(),
                    actual.operation.capability_id()
                ));
            }
        }

        let mut checks = Vec::with_capacity(1 + decisions.len());
        checks.push(CapabilityCheck {
            capability: self.reachable_capability(),
            status: CapabilityStatus::Pass,
        });
        for (operation, decision) in VALIDATED_K8S_OPERATIONS.iter().zip(decisions.iter()) {
            let status = match &decision.decision {
                AccessDecision::Allowed => CapabilityStatus::Pass,
                AccessDecision::Denied(reason) => CapabilityStatus::Fail {
                    reason: format!(
                        "RBAC denied `{}` on `{}` ({reason})",
                        operation.verb, operation.resource
                    ),
                },
            };
            checks.push(CapabilityCheck {
                capability: self.operation_capability(operation),
                status,
            });
        }
        RequirementsReport::new(checks)
    }

    fn bootstrap(&self, input: &BootstrapInput<'_>) -> Result<BootstrapOutcome, BootstrapError> {
        // The admin "profile" is the kubeconfig context / admin identity
        // hint recorded in the rules pack's README — and, on the `--bind`
        // path, the context the bind connector authenticates as.
        let admin_context = input.admin.profile();
        if admin_context.is_empty() {
            return Err(BootstrapError::AdminRejected(
                "K8s bootstrap requires --admin-profile to identify the kubeconfig context \
                 (or admin identity) that will apply the rules pack."
                    .to_string(),
            ));
        }

        // Scope the RBAC + token mint to the namespace the deployer actually
        // deploys into — the binding answers' resolved `K8sParams::namespace`
        // when set (the CLI threads it via `in_namespace`), else the
        // env-derived default. This MUST match the namespace `requirements`
        // probes and `reconcile` deploys into (both use `K8sParams`), or the
        // bound token would be RoleBound in the wrong namespace. Mirrors the
        // `self.namespace` fallback in `validate`.
        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| namespace_for_env(input.env_id));
        let rules_pack = render_min_rbac_rules_pack(&K8sRulesPackInput {
            env_id: input.env_id.as_str(),
            namespace: &namespace,
            admin_context_hint: admin_context,
            operations: VALIDATED_K8S_OPERATIONS,
        });

        // Render-only (default): no live cluster calls. The admin reviews
        // and applies the pack offline, mints a token for the
        // ServiceAccount, and binds it via `op credentials rotate`.
        let Some(bind) = self.bind.as_ref() else {
            return Ok(BootstrapOutcome {
                rules_pack,
                bound_credentials_ref: None,
                bound_expiry: None,
                bound_secret_material: None,
            });
        };

        // `--bind`: apply the SAME rendered RBAC live (one source of truth —
        // the live apply and the offline `kubectl apply -f` can never
        // diverge) AS THE ADMIN, then mint the deployer ServiceAccount's
        // token. Connect + apply + mint share one `run_k8s_async` call (the
        // `kube::Client` Buffer-worker runtime constraint — see
        // `K8sBootstrapConnector`).
        let manifest_yaml = rbac_manifest_from_pack(&rules_pack).ok_or_else(|| {
            BootstrapError::ProvisioningFailed {
                step: "render-rbac".to_string(),
                message: format!(
                    "rendered rules pack is missing the `{K8S_RBAC_MANIFEST_FILENAME}` entry"
                ),
            }
        })?;
        let connector = Arc::clone(bind);
        let env_id_label = input.env_id.as_str().to_string();
        let minted = run_k8s_async(async move {
            let client = connector().await?;
            client.apply_rbac(&manifest_yaml).await?;
            let minted = client
                .mint_service_account_token(
                    &namespace,
                    DEPLOYER_SERVICE_ACCOUNT,
                    BIND_TOKEN_EXPIRATION_SECONDS,
                )
                .await?;
            // Persist the bearer into its durable in-cluster Secret on the
            // same connection (so a fresh operator machine can resolve it
            // from the cluster). The dev-store write the CLI sink performs
            // stays as the bootstrapping machine's fast local cache.
            client
                .apply_identity_secret(
                    &namespace,
                    DEPLOYER_IDENTITY_SECRET_NAME,
                    &env_id_label,
                    &minted.token,
                )
                .await?;
            Ok(minted)
        })
        .map_err(|e: K8sClientError| BootstrapError::ProvisioningFailed {
            step: "k8s-bind".to_string(),
            message: e.to_string(),
        })?;

        let bound_ref = SecretRef::try_new(format!(
            "secret://{}/{}",
            input.env_id.as_str(),
            DEPLOYER_TOKEN_STORE_PATH
        ))
        .map_err(|e| BootstrapError::ProvisioningFailed {
            step: "bind-ref".to_string(),
            message: format!("bound credentials ref is not well-formed: {e}"),
        })?;

        Ok(BootstrapOutcome {
            rules_pack,
            bound_credentials_ref: Some(bound_ref),
            bound_expiry: minted.expiration,
            bound_secret_material: Some(Zeroizing::new(minted.token)),
        })
    }

    fn rollback_bound_material(&self, env_id: &greentic_deploy_spec::EnvId) {
        // Only the `--bind` path writes a remote Secret; nothing else to undo.
        let Some(bind) = self.bind.as_ref() else {
            return;
        };
        // The namespace the bind path wrote into: the binding's resolved
        // override, else the env-derived default (mirrors `bootstrap`).
        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| namespace_for_env(env_id));
        let connector = Arc::clone(bind);
        // Best-effort: reconnect (the bootstrap connection is long gone) and
        // delete. EVERY error is swallowed — the caller already has a bootstrap
        // failure to report, and cleanup must never mask it or panic. The
        // delete is idempotent (a never-written Secret 404s harmlessly).
        let _ = run_k8s_async(async move {
            let client = connector().await?;
            client
                .delete_identity_secret(&namespace, DEPLOYER_IDENTITY_SECRET_NAME)
                .await
        });
    }
}

/// Extract the RBAC YAML entry from a rendered rules pack — the exact bytes
/// the `--bind` path applies live, so the live apply and the offline
/// `kubectl apply -f` stay byte-identical.
fn rbac_manifest_from_pack(rules_pack: &RulesPack) -> Option<String> {
    rules_pack
        .entries
        .iter()
        .find(|entry| entry.filename == K8S_RBAC_MANIFEST_FILENAME)
        .map(|entry| entry.content.clone())
}

/// Where the live K8s probe sequence failed. `Connect`/`Identity` mean the
/// API was unreachable or the credential resolves to no identity → every cap
/// fails closed; `Access` means reachability passed but the SSAR sweep itself
/// errored → reachability passes, ops fail.
enum K8sProbeError {
    Connect(K8sClientError),
    Identity(K8sClientError),
    Access(K8sClientError),
}

/// Every-capability-failed report with one shared reason.
fn all_failed(caps: &[Capability], reason: &str) -> RequirementsReport {
    RequirementsReport::new(
        caps.iter()
            .map(|c| CapabilityCheck {
                capability: c.clone(),
                status: CapabilityStatus::Fail {
                    reason: reason.to_string(),
                },
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::ZeroizedAdmin;
    use greentic_deploy_spec::{EnvId, EnvironmentHostConfig};
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::tempdir;

    fn default_host_config(env_id: &EnvId) -> EnvironmentHostConfig {
        EnvironmentHostConfig {
            env_id: env_id.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
            default_bundle: None,
        }
    }

    fn ctx<'a>(
        env_root: &'a Path,
        env_id: &'a EnvId,
        host_config: &'a EnvironmentHostConfig,
    ) -> ValidationContext<'a> {
        ValidationContext {
            env_id,
            env_root,
            host_config,
        }
    }

    #[derive(Debug, Default)]
    struct MockK8sClient {
        identity_response: Mutex<Option<Result<ClusterIdentity, K8sClientError>>>,
        review_response: Mutex<Option<Result<Vec<OperationDecision>, K8sClientError>>>,
        review_calls: Mutex<Vec<(String, usize)>>,
    }

    impl MockK8sClient {
        fn with_identity(self, r: Result<ClusterIdentity, K8sClientError>) -> Self {
            *self.identity_response.lock().unwrap() = Some(r);
            self
        }
        fn with_review(self, r: Result<Vec<OperationDecision>, K8sClientError>) -> Self {
            *self.review_response.lock().unwrap() = Some(r);
            self
        }
    }

    #[async_trait::async_trait]
    impl K8sValidatorClient for MockK8sClient {
        async fn who_am_i(&self) -> Result<ClusterIdentity, K8sClientError> {
            self.identity_response
                .lock()
                .unwrap()
                .take()
                .expect("test must wire identity_response")
        }

        async fn review_access<'a>(
            &'a self,
            namespace: &'a str,
            operations: &'a [K8sOperation],
        ) -> Result<Vec<OperationDecision>, K8sClientError> {
            self.review_calls
                .lock()
                .unwrap()
                .push((namespace.to_string(), operations.len()));
            self.review_response
                .lock()
                .unwrap()
                .take()
                .expect("test must wire review_response")
        }

        async fn review_cluster_access<'a>(
            &'a self,
            _operations: &'a [K8sOperation],
        ) -> Result<Vec<OperationDecision>, K8sClientError> {
            // The credentials `validate` path is namespace-scoped only; the
            // cluster-scoped review is exercised against the production client's
            // HTTP mock (`kube_client.rs`), never through this validate mock.
            unimplemented!("MockK8sClient does not drive the cluster-scoped review")
        }
    }

    fn identity() -> ClusterIdentity {
        ClusterIdentity {
            user: "system:serviceaccount:gtc-zain-prod:greentic-deployer".into(),
        }
    }

    fn all_allowed() -> Vec<OperationDecision> {
        VALIDATED_K8S_OPERATIONS
            .iter()
            .map(|operation| OperationDecision {
                operation: *operation,
                decision: AccessDecision::Allowed,
            })
            .collect()
    }

    #[test]
    fn required_capabilities_cover_reachable_plus_every_operation() {
        let creds = K8sDeployerCredentials::default();
        let ids: Vec<String> = creds
            .required_capabilities()
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(ids.len(), 1 + VALIDATED_K8S_OPERATIONS.len());
        assert_eq!(ids[0], K8S_API_REACHABLE_CAP);
        // Core-group ops render `core`, named groups render verbatim.
        assert!(ids.contains(&"k8s.rbac.allow:core/services:create".to_string()));
        assert!(ids.contains(&"k8s.rbac.allow:apps/deployments:delete".to_string()));
        assert!(
            ids.contains(&"k8s.rbac.allow:networking.k8s.io/networkpolicies:patch".to_string())
        );
    }

    /// Scaffold posture: no client wired — every probe Fail (fail closed).
    /// `RequirementsReport::passed()` treats Skipped as non-blocking, so
    /// an all-Skipped report would persist `result: pass` — Fail prevents
    /// that.
    #[test]
    fn validate_without_a_client_fails_closed() {
        let creds = K8sDeployerCredentials::default();
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed(), "no-client report must NOT pass");
        assert_eq!(
            report.missing().len(),
            creds.required_capabilities().len(),
            "every Fail cap must be recorded as missing"
        );
        for check in &report.checks {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(
                        reason.contains("no Kubernetes API client is bound"),
                        "reason must mention the missing client: {reason}"
                    );
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_passes_when_identity_resolves_and_all_ops_allowed() {
        let mock = Arc::new(
            MockK8sClient::default()
                .with_identity(Ok(identity()))
                .with_review(Ok(all_allowed())),
        );
        let creds = K8sDeployerCredentials::with_client(mock.clone());
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(report.passed(), "report: {report:?}");
        assert!(report.missing().is_empty());
        // The SSAR sweep scoped to the env's derived namespace, one
        // review per validated operation.
        let calls = mock.review_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "gtc-zain-prod");
        assert_eq!(calls[0].1, VALIDATED_K8S_OPERATIONS.len());
    }

    /// `in_namespace` scopes the SSAR sweep to the binding answers' resolved
    /// namespace (what reconcile deploys into), not the env-derived default —
    /// otherwise a custom-namespace env probes the wrong namespace.
    #[test]
    fn validate_scopes_ssars_to_the_overridden_namespace() {
        let mock = Arc::new(
            MockK8sClient::default()
                .with_identity(Ok(identity()))
                .with_review(Ok(all_allowed())),
        );
        let creds = K8sDeployerCredentials::with_client(mock.clone()).in_namespace("custom-ns");
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(report.passed(), "report: {report:?}");
        let calls = mock.review_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0, "custom-ns",
            "SSARs must target the deploy namespace, not gtc-zain-prod"
        );
    }

    #[test]
    fn validate_fails_the_specific_denied_operation() {
        let decisions: Vec<OperationDecision> = VALIDATED_K8S_OPERATIONS
            .iter()
            .map(|operation| OperationDecision {
                operation: *operation,
                decision: if operation.resource == "deployments" && operation.verb == "delete" {
                    AccessDecision::Denied("no RBAC rule matched".into())
                } else {
                    AccessDecision::Allowed
                },
            })
            .collect();
        let mock = Arc::new(
            MockK8sClient::default()
                .with_identity(Ok(identity()))
                .with_review(Ok(decisions)),
        );
        let creds = K8sDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed());
        assert_eq!(
            report.missing(),
            vec!["k8s.rbac.allow:apps/deployments:delete".to_string()]
        );
        let denied = report
            .checks
            .iter()
            .find(|c| c.capability.id == "k8s.rbac.allow:apps/deployments:delete")
            .unwrap();
        match &denied.status {
            CapabilityStatus::Fail { reason } => {
                assert!(reason.contains("no RBAC rule matched"), "reason: {reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn validate_fails_every_cap_when_identity_does_not_resolve() {
        let mock = Arc::new(MockK8sClient::default().with_identity(Err(
            K8sClientError::NoClusterAccess("kubeconfig has no current context".into()),
        )));
        let creds = K8sDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed());
        for check in &report.checks {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(reason.contains("kubeconfig has no current context"));
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_passes_reachable_but_fails_ops_when_review_errors() {
        let mock = Arc::new(
            MockK8sClient::default()
                .with_identity(Ok(identity()))
                .with_review(Err(K8sClientError::Transport("connection reset".into()))),
        );
        let creds = K8sDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed());
        let reachable = report
            .checks
            .iter()
            .find(|c| c.capability.id == K8S_API_REACHABLE_CAP)
            .unwrap();
        assert!(matches!(reachable.status, CapabilityStatus::Pass));
        for check in report.checks.iter().skip(1) {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(reason.contains("connection reset"), "reason: {reason}");
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    /// FIX 3: a truncated (empty) decisions vec must fail closed — zip
    /// would silently skip every operation.
    #[test]
    fn validate_fails_closed_on_truncated_review_response() {
        let mock = Arc::new(
            MockK8sClient::default()
                .with_identity(Ok(identity()))
                .with_review(Ok(vec![])),
        );
        let creds = K8sDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed(), "truncated response must not pass");
        // Reachable passes (identity resolved), every op fails.
        let reachable = report
            .checks
            .iter()
            .find(|c| c.capability.id == K8S_API_REACHABLE_CAP)
            .unwrap();
        assert!(matches!(reachable.status, CapabilityStatus::Pass));
        let op_checks: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.capability.id != K8S_API_REACHABLE_CAP)
            .collect();
        assert_eq!(op_checks.len(), VALIDATED_K8S_OPERATIONS.len());
        for check in &op_checks {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(
                        reason.contains("0 decisions for"),
                        "reason must mention the count mismatch: {reason}"
                    );
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
        assert_eq!(
            report.missing().len(),
            VALIDATED_K8S_OPERATIONS.len(),
            "every operation cap must be missing"
        );
    }

    /// FIX 3: decisions returned in wrong order must fail closed.
    #[test]
    fn validate_fails_closed_on_mismatched_operation_order() {
        let mut decisions = all_allowed();
        // Swap the first two decisions so the operations don't match.
        decisions.swap(0, 1);
        let mock = Arc::new(
            MockK8sClient::default()
                .with_identity(Ok(identity()))
                .with_review(Ok(decisions)),
        );
        let creds = K8sDeployerCredentials::with_client(mock);
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let hc = default_host_config(&env_id);
        let dir = tempdir().unwrap();
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(!report.passed(), "mismatched operations must not pass");
        let reachable = report
            .checks
            .iter()
            .find(|c| c.capability.id == K8S_API_REACHABLE_CAP)
            .unwrap();
        assert!(matches!(reachable.status, CapabilityStatus::Pass));
        // Every operation cap fails with a reason mentioning the mismatch.
        let op_checks: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.capability.id != K8S_API_REACHABLE_CAP)
            .collect();
        assert_eq!(op_checks.len(), VALIDATED_K8S_OPERATIONS.len());
        for check in &op_checks {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(
                        reason.contains("mismatch"),
                        "reason must mention the mismatch: {reason}"
                    );
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn bootstrap_rejects_empty_admin_profile() {
        let creds = K8sDeployerCredentials::default();
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new("", "irrelevant".to_string());
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let err = creds.bootstrap(&input).unwrap_err();
        match err {
            BootstrapError::AdminRejected(msg) => {
                assert!(msg.contains("--admin-profile"), "msg: {msg}");
            }
            other => panic!("expected AdminRejected, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_returns_rules_pack_without_binding_credentials() {
        let creds = K8sDeployerCredentials::default();
        let env_id = EnvId::try_from("zain-prod").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new("zain-admin@nonprod-cluster", String::new());
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let outcome = creds.bootstrap(&input).expect("bootstrap renders");
        assert!(
            outcome.bound_credentials_ref.is_none(),
            "K8s bootstrap must not bind credentials directly — the admin \
             applies the rules pack and binds via rotate"
        );
        assert!(!outcome.rules_pack.is_empty());
        let combined: String = outcome
            .rules_pack
            .entries
            .iter()
            .map(|e| e.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        // Every validated verb shows up in the Role rules, and the admin
        // hint shows up in the README.
        for operation in VALIDATED_K8S_OPERATIONS {
            assert!(
                combined.contains(operation.verb),
                "rules pack must mention verb `{}`",
                operation.verb
            );
        }
        assert!(combined.contains("zain-admin@nonprod-cluster"));
        assert!(combined.contains("gtc-zain-prod"));
    }

    /// Records what `apply_rbac` was handed and the namespace the mint
    /// targeted, and hands back a canned token.
    #[derive(Debug, Default)]
    struct MockBootstrapClient {
        applied_manifests: Mutex<Vec<String>>,
        minted_namespace: Mutex<Option<String>>,
        mint_response: Mutex<Option<Result<MintedToken, K8sClientError>>>,
        /// `(namespace, name, env_id, bearer)` captured from
        /// `apply_identity_secret` — `None` until the bind path stores it.
        identity_secret: Mutex<Option<(String, String, String, String)>>,
        /// `(namespace, name)` captured from `delete_identity_secret` — `None`
        /// until the compensating-cleanup path deletes it.
        deleted_identity_secret: Mutex<Option<(String, String)>>,
    }

    impl MockBootstrapClient {
        fn with_mint(self, r: Result<MintedToken, K8sClientError>) -> Self {
            *self.mint_response.lock().unwrap() = Some(r);
            self
        }
    }

    #[async_trait::async_trait]
    impl K8sBootstrapClient for MockBootstrapClient {
        async fn apply_rbac(&self, manifest_yaml: &str) -> Result<(), K8sClientError> {
            self.applied_manifests
                .lock()
                .unwrap()
                .push(manifest_yaml.to_string());
            Ok(())
        }

        async fn mint_service_account_token(
            &self,
            namespace: &str,
            _service_account: &str,
            _expiration_seconds: i64,
        ) -> Result<MintedToken, K8sClientError> {
            *self.minted_namespace.lock().unwrap() = Some(namespace.to_string());
            self.mint_response
                .lock()
                .unwrap()
                .take()
                .expect("test must wire mint_response")
        }

        async fn apply_identity_secret(
            &self,
            namespace: &str,
            name: &str,
            env_id: &str,
            bearer: &str,
        ) -> Result<(), K8sClientError> {
            *self.identity_secret.lock().unwrap() = Some((
                namespace.to_string(),
                name.to_string(),
                env_id.to_string(),
                bearer.to_string(),
            ));
            Ok(())
        }

        async fn delete_identity_secret(
            &self,
            namespace: &str,
            name: &str,
        ) -> Result<(), K8sClientError> {
            *self.deleted_identity_secret.lock().unwrap() =
                Some((namespace.to_string(), name.to_string()));
            Ok(())
        }
    }

    fn bind_creds(mock: Arc<MockBootstrapClient>) -> K8sDeployerCredentials {
        let connector: K8sBootstrapConnector = Arc::new(move || -> K8sBootstrapConnectFut {
            let client = mock.clone();
            Box::pin(async move { Ok(client as Arc<dyn K8sBootstrapClient>) })
        });
        K8sDeployerCredentials::with_bootstrap_connector(connector)
    }

    #[test]
    fn bind_applies_the_rendered_rbac_and_returns_the_minted_credential() {
        let expiry = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        let mock = Arc::new(MockBootstrapClient::default().with_mint(Ok(MintedToken {
            token: "MINTED_SA_TOKEN".to_string(),
            expiration: Some(expiry),
        })));
        let creds = bind_creds(mock.clone());

        let env_id = EnvId::try_from("zain-prod").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new("zain-admin@cluster", String::new());
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let outcome = creds.bootstrap(&input).expect("bind succeeds");

        // The credential is bound at the store-aligned deployer token path.
        assert_eq!(
            outcome.bound_credentials_ref.as_ref().map(|r| r.as_str()),
            Some("secret://zain-prod/default/_/k8s-deployer/deployer_token")
        );
        // Granted expiry + minted material flow back to the runner.
        assert_eq!(outcome.bound_expiry, Some(expiry));
        assert_eq!(
            outcome.bound_secret_material.as_ref().map(|m| m.as_str()),
            Some("MINTED_SA_TOKEN")
        );

        // The bytes applied live are EXACTLY the rules-pack RBAC entry — no
        // drift between the live apply and the offline `kubectl apply -f`.
        let applied = mock.applied_manifests.lock().unwrap();
        assert_eq!(applied.len(), 1, "RBAC applied exactly once");
        assert_eq!(
            applied[0],
            rbac_manifest_from_pack(&outcome.rules_pack).expect("pack has the RBAC entry")
        );
        assert!(applied[0].contains("kind: ServiceAccount"));
        assert!(applied[0].contains(DEPLOYER_SERVICE_ACCOUNT));
        // With no namespace override, the mint targets the env-derived default.
        assert_eq!(
            mock.minted_namespace.lock().unwrap().as_deref(),
            Some("gtc-zain-prod")
        );

        // The minted bearer is ALSO persisted into its durable in-cluster
        // Secret: same namespace as the mint, the env-ownership label, and the
        // bearer verbatim — so a fresh operator machine resolves it.
        let identity = mock.identity_secret.lock().unwrap();
        let (ns, name, env_label, bearer) = identity.as_ref().expect("identity Secret was stored");
        assert_eq!(ns, "gtc-zain-prod");
        assert_eq!(name, DEPLOYER_IDENTITY_SECRET_NAME);
        assert_eq!(env_label, "zain-prod");
        assert_eq!(bearer, "MINTED_SA_TOKEN");
    }

    #[test]
    fn rollback_bound_material_deletes_the_in_cluster_identity_secret() {
        let mock = Arc::new(MockBootstrapClient::default());
        let creds = bind_creds(mock.clone());
        let env_id = EnvId::try_from("zain-prod").unwrap();
        // The CLI calls this on a FAILED `--bind` bootstrap; it must delete the
        // durable Secret (in the env-derived namespace, no override here) so no
        // live bearer is left behind.
        creds.rollback_bound_material(&env_id);
        let deleted = mock.deleted_identity_secret.lock().unwrap();
        let (ns, name) = deleted
            .as_ref()
            .expect("cleanup deleted the identity Secret");
        assert_eq!(ns, "gtc-zain-prod");
        assert_eq!(name, DEPLOYER_IDENTITY_SECRET_NAME);
    }

    #[test]
    fn rollback_bound_material_is_a_noop_without_a_bind_connector() {
        // A non-bind K8s credentials instance (the validator path) wrote no
        // remote Secret — cleanup must do nothing and never panic.
        let env_id = EnvId::try_from("zain-prod").unwrap();
        K8sDeployerCredentials::default().rollback_bound_material(&env_id);
    }

    #[test]
    fn bind_scopes_rbac_and_mint_to_the_configured_namespace() {
        let mock = Arc::new(MockBootstrapClient::default().with_mint(Ok(MintedToken {
            token: "MINTED_SA_TOKEN".to_string(),
            expiration: None,
        })));
        // The CLI threads the answers-resolved namespace via `in_namespace`;
        // bind must apply RBAC + mint THERE, not in the env-derived default —
        // else the token is RoleBound where reconcile never deploys.
        let creds = bind_creds(mock.clone()).in_namespace("custom-ns");

        let env_id = EnvId::try_from("zain-prod").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new("zain-admin@cluster", String::new());
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let outcome = creds.bootstrap(&input).expect("bind succeeds");

        // RBAC rendered + applied in the custom namespace, not `gtc-zain-prod`.
        let applied = mock.applied_manifests.lock().unwrap();
        assert!(
            applied[0].contains("namespace: custom-ns"),
            "applied: {}",
            applied[0]
        );
        assert!(!applied[0].contains("namespace: gtc-zain-prod"));
        // Token minted in the same namespace.
        assert_eq!(
            mock.minted_namespace.lock().unwrap().as_deref(),
            Some("custom-ns")
        );
        // The bound secret ref stays env-scoped (its store path is env-derived).
        assert_eq!(
            outcome.bound_credentials_ref.as_ref().map(|r| r.as_str()),
            Some("secret://zain-prod/default/_/k8s-deployer/deployer_token")
        );
    }

    #[test]
    fn bind_surfaces_a_mint_failure_as_provisioning_failed_without_binding() {
        let mock = Arc::new(MockBootstrapClient::default().with_mint(Err(
            K8sClientError::ApiRejected("forbidden: cannot create tokenrequests".to_string()),
        )));
        let creds = bind_creds(mock);

        let env_id = EnvId::try_from("zain-prod").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new("zain-admin@cluster", String::new());
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let err = creds.bootstrap(&input).unwrap_err();
        match err {
            BootstrapError::ProvisioningFailed { step, message } => {
                assert_eq!(step, "k8s-bind");
                assert!(message.contains("forbidden"), "message: {message}");
            }
            other => panic!("expected ProvisioningFailed, got {other:?}"),
        }
    }

    /// Build a JWT-shaped bearer carrying the given `iat`/`exp` unix seconds
    /// (header + signature are inert — only the payload is decoded).
    fn fake_jwt(iat: i64, exp: i64) -> String {
        let payload = serde_json::json!({ "iat": iat, "exp": exp, "sub": "system:serviceaccount" });
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("aGVhZGVy.{body}.c2ln")
    }

    #[test]
    fn rotate_at_decodes_the_jwt_and_lands_at_eighty_percent() {
        // 1000s lifetime ⇒ rotate at iat + 800s, read from the token's claims.
        let iat = 1_000_000;
        let creds = K8sDeployerCredentials::default();
        let rotate_at = creds
            .rotate_at(&fake_jwt(iat, iat + 1000))
            .expect("decodable JWT");
        assert_eq!(rotate_at, DateTime::from_timestamp(iat + 800, 0).unwrap());
    }

    #[test]
    fn rotation_due_tracks_the_eighty_percent_threshold() {
        let iat = 2_000_000;
        let creds = K8sDeployerCredentials::default();
        let bearer = fake_jwt(iat, iat + 1000); // rotate_at = iat + 800
        let before = DateTime::from_timestamp(iat + 799, 0).unwrap();
        let at = DateTime::from_timestamp(iat + 800, 0).unwrap();
        assert!(!creds.rotation_due(&bearer, before), "799s in: not due");
        assert!(
            creds.rotation_due(&bearer, at),
            "800s in: due (>= threshold)"
        );
    }

    #[test]
    fn rotate_at_is_none_and_rotation_due_fails_open_for_opaque_material() {
        // Not a JWT, empty, or a non-base64 payload — `rotate_at` can't decode
        // a lifetime, so `rotation_due` treats every shape as due and
        // `--if-needed` never silently skips an undecodable token.
        let creds = K8sDeployerCredentials::default();
        let now = Utc::now();
        for material in ["not-a-jwt", "", "a.b.c"] {
            assert!(
                creds.rotate_at(material).is_none(),
                "{material:?} is undecodable"
            );
            assert!(
                creds.rotation_due(material, now),
                "{material:?} fails open to due"
            );
        }
    }
}
