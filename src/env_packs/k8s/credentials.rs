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
//! `k8s-client` feature), but constructing it from the binding's answers
//! and handing it to this handler is the PR-5.3 orchestration wiring.
//! Until then [`K8sDeployerCredentials::default`] holds no client and
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

use std::sync::Arc;

use crate::credentials::{
    BootstrapError, BootstrapInput, BootstrapOutcome, Capability, CapabilityCheck,
    CapabilityStatus, DeployerCredentials, RequirementsReport, ValidationContext,
};

use super::async_bridge::run_k8s_async;
use super::bootstrap::{K8sRulesPackInput, render_min_rbac_rules_pack};
use super::manifests::namespace_for_env;

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
/// Deployments/Services carry `delete` (archive tears workers down);
/// ConfigMaps/PDBs/NetworkPolicies are env-lifetime objects the deployer
/// only upserts.
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
}

/// K8s deployer credentials handler.
///
/// `Default` holds no client (every probe fails closed);
/// [`with_client`](Self::with_client) injects a mock in tests and a
/// connected [`KubeValidatorClient`](super::kube_client::KubeValidatorClient)
/// once the PR-5.3 wiring constructs one.
#[derive(Debug, Default)]
pub struct K8sDeployerCredentials {
    client: Option<Arc<dyn K8sValidatorClient>>,
}

impl K8sDeployerCredentials {
    pub fn with_client(client: Arc<dyn K8sValidatorClient>) -> Self {
        Self {
            client: Some(client),
        }
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

impl DeployerCredentials for K8sDeployerCredentials {
    fn requires_credentials_material(&self) -> bool {
        true
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

        let Some(client) = self.client.as_ref() else {
            // No client bound — Fail, not Skipped.
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
                            reason: "no Kubernetes API client is bound to the K8s \
                                     deployer env-pack (binding one rides the Phase D \
                                     orchestration wiring, PR-5.3); credentials cannot \
                                     be validated — failing closed"
                                .to_string(),
                        },
                    })
                    .collect(),
            );
        };

        if let Err(e) = run_k8s_async(client.who_am_i()) {
            // No usable identity — fail every cap (a deployer that
            // requires credential material treats this as auth failure,
            // not a skip), mirroring the AWS chain-missing posture.
            return all_failed(&caps, &format!("SelfSubjectReview failed: {e}"));
        }

        let namespace = namespace_for_env(ctx.env_id);
        let decisions =
            match run_k8s_async(client.review_access(&namespace, VALIDATED_K8S_OPERATIONS)) {
                Ok(v) => v,
                Err(e) => {
                    return self.reachable_pass_ops_failed(&format!(
                        "SelfSubjectAccessReview failed: {e}"
                    ));
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
        // hint recorded in the rules pack's README. No live cluster calls
        // here — the customer's admin reviews and applies the YAML.
        let admin_context = input.admin.profile();
        if admin_context.is_empty() {
            return Err(BootstrapError::AdminRejected(
                "K8s bootstrap requires --admin-profile to identify the kubeconfig context \
                 (or admin identity) that will apply the rules pack."
                    .to_string(),
            ));
        }

        let namespace = namespace_for_env(input.env_id);
        let rules_pack = render_min_rbac_rules_pack(&K8sRulesPackInput {
            env_id: input.env_id.as_str(),
            namespace: &namespace,
            admin_context_hint: admin_context,
            operations: VALIDATED_K8S_OPERATIONS,
        });

        // The admin applies the pack offline, mints a short-lived token
        // for the ServiceAccount, and binds it via `op credentials
        // rotate` — no credentials are minted here.
        Ok(BootstrapOutcome {
            rules_pack,
            bound_credentials_ref: None,
        })
    }
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
}
