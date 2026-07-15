//! [`DeployerCredentials`] impl for the GCP Cloud Run env-pack.
//!
//! Mirrors the AWS-ECS [`credentials`](crate::env_packs::aws::credentials)
//! structure with GCP primitives:
//!
//! - **`gcp.iam.caller-identity`** — the ADC principal resolves (an email +
//!   quota project). Analogue of STS `GetCallerIdentity`.
//! - **One capability per validated IAM permission**, evaluated via
//!   `projects.testIamPermissions` over [`VALIDATED_GCP_PERMISSIONS`] — the
//!   full Cloud Run + Secret Manager + IAM surface the real target exercises,
//!   so a service account that passes `gtc op credentials requirements` does
//!   not then fail on the first live `op env up`.
//!
//! ## Scope of this PR (scaffold)
//!
//! The **real** ADC/WIF-backed [`GcpValidatorClient`] (a `google-cloud-auth`
//! token + a `projects.testIamPermissions` REST call) lands with the real
//! target behind the `deploy-gcp-cloudrun` feature. Until then
//! `resolve_client` fails closed with
//! [`GcpClientError::NoCredentialChain`], so `validate` on an un-injected
//! handler reports every capability as failed — the honest answer for a build
//! whose live deploy path is not yet wired. Tests inject a mock via
//! [`with_client`](GcpDeployerCredentials::with_client). `bootstrap` is fully
//! wired here: it renders the minimum-privilege Terraform pack.
//!
//! ## Sync trait + async client
//!
//! [`DeployerCredentials::validate`] is sync; the client seam is async (the
//! real client will do HTTP). `run_gcp_async` bridges via a dedicated thread
//! running its own current-thread runtime, the same pattern the AWS handler
//! uses to avoid `block_in_place` panicking on a current-thread operator
//! runtime.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::credentials::{
    BootstrapError, BootstrapInput, BootstrapOutcome, Capability, CapabilityCheck,
    CapabilityStatus, DeployerCredentials, RequirementsReport, ValidationContext,
};

use super::bootstrap::{GcpBootstrapInput, render_bootstrap_rules_pack};

/// Stable ID for the ADC caller-identity probe.
pub const GCP_CALLER_IDENTITY_CAP: &str = "gcp.iam.caller-identity";

/// IAM permissions this handler validates (one capability each, rendered by
/// `required_capabilities` in this order). Covers the full Cloud Run deploy
/// surface the real target exercises — service + revision lifecycle, invoker
/// IAM (plan D12), Secret Manager staging (plan D6), `actAs` on the runtime SA,
/// and the Artifact Registry read verbs used only when an `ar_repo` remote repo
/// is configured (plan D3). Each maps to a capability ID
/// `gcp.iam.allow:<permission>`.
pub const VALIDATED_GCP_PERMISSIONS: &[&str] = &[
    // Cloud Run service lifecycle (create/update/get/delete + invoker IAM).
    "run.services.get",
    "run.services.create",
    "run.services.update",
    "run.services.delete",
    "run.services.setIamPolicy",
    // Cloud Run revision lifecycle.
    "run.revisions.get",
    "run.revisions.list",
    "run.revisions.delete",
    // Long-running-operation polling for the deploy/readiness waits.
    "run.operations.get",
    // Pass the least-privilege runtime service account to the revision.
    "iam.serviceAccounts.actAs",
    // Secret Manager: env-store + dev-secrets staging (version-pinned, plan D6).
    "secretmanager.secrets.get",
    "secretmanager.secrets.create",
    "secretmanager.secrets.update",
    "secretmanager.versions.add",
    "secretmanager.versions.access",
    // Artifact Registry read — only exercised when an `ar_repo` remote repo is
    // configured (plan D3); harmless to validate when it is not.
    "artifactregistry.repositories.get",
    "artifactregistry.repositories.downloadArtifacts",
];

/// Returns the canonical capability ID for a GCP IAM permission.
fn gcp_permission_capability_id(permission: &str) -> String {
    format!("gcp.iam.allow:{permission}")
}

/// Caller identity returned by [`GcpValidatorClient::get_caller_identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpCallerIdentity {
    /// The ADC principal (service-account or user email).
    pub email: String,
    /// The quota/target project `testIamPermissions` runs against, when the
    /// credential chain resolves one.
    pub project: Option<String>,
}

/// Errors the client can surface to validate. All flow into a
/// `CapabilityStatus::Fail { reason }`.
#[derive(Debug, thiserror::Error)]
pub enum GcpClientError {
    #[error("GCP credential chain (ADC) resolved no usable credentials: {0}")]
    NoCredentialChain(String),
    #[error("GCP rejected the caller identity: {0}")]
    IdentityRejected(String),
    #[error("GCP IAM rejected the permission test: {0}")]
    IamRejected(String),
    #[error("GCP transport error: {0}")]
    Transport(String),
}

/// Pluggable GCP client used by [`GcpDeployerCredentials::validate`]. Unit
/// tests mock this; the real ADC/WIF-backed impl lands with the real target
/// (`deploy-gcp-cloudrun`).
///
/// `async_trait` because the real client does HTTP; the validate path bridges
/// sync→async via `run_gcp_async`.
#[async_trait::async_trait]
pub trait GcpValidatorClient: std::fmt::Debug + Send + Sync {
    /// Resolve the ADC principal + its quota/target project.
    async fn get_caller_identity(&self) -> Result<GcpCallerIdentity, GcpClientError>;

    /// Evaluate `permissions` against `project` via
    /// `projects.testIamPermissions`. Returns the **granted subset** (GCP's
    /// API returns only the permissions the caller actually holds).
    async fn test_iam_permissions<'a>(
        &'a self,
        project: &'a str,
        permissions: &'a [&'a str],
    ) -> Result<Vec<String>, GcpClientError>;
}

/// GCP Cloud Run deployer credentials handler.
///
/// Holds a pluggable validator client behind an `Arc<Mutex<...>>`. Tests inject
/// a mock via [`with_client`](Self::with_client); the default constructor holds
/// no client, so `validate` fails closed until the real ADC-backed client is
/// wired (see the module docstring).
#[derive(Default)]
pub struct GcpDeployerCredentials {
    client: Mutex<Option<Arc<dyn GcpValidatorClient>>>,
}

impl std::fmt::Debug for GcpDeployerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpDeployerCredentials")
            .field(
                "client",
                &if self.client.lock().expect("mutex").is_some() {
                    "<injected>"
                } else {
                    "<none>"
                },
            )
            .finish()
    }
}

impl GcpDeployerCredentials {
    /// Construct with a pre-built (mock or real) validator client.
    pub fn with_client(client: Arc<dyn GcpValidatorClient>) -> Self {
        Self {
            client: Mutex::new(Some(client)),
        }
    }

    /// Return the injected client, or fail closed. The real ADC-backed client
    /// is built here once the `deploy-gcp-cloudrun` real target lands.
    fn resolve_client(&self) -> Result<Arc<dyn GcpValidatorClient>, GcpClientError> {
        if let Some(c) = self.client.lock().expect("mutex not poisoned").as_ref() {
            return Ok(Arc::clone(c));
        }
        Err(GcpClientError::NoCredentialChain(
            "no GCP validator client wired; the ADC-backed client lands with the real target \
             (deploy-gcp-cloudrun). Inject one via GcpDeployerCredentials::with_client for testing."
                .to_string(),
        ))
    }

    fn caller_identity_capability(&self) -> Capability {
        Capability::new(
            GCP_CALLER_IDENTITY_CAP,
            "GCP Application Default Credentials resolve to a caller identity",
        )
    }

    fn permission_capability(&self, permission: &str) -> Capability {
        Capability::new(
            gcp_permission_capability_id(permission),
            format!("IAM principal is allowed to perform `{permission}`"),
        )
    }

    /// Report for the case where the identity resolved but the downstream
    /// permission test could not run: identity passes, every permission fails
    /// with the same reason.
    fn identity_pass_permissions_failed(&self, reason: &str) -> RequirementsReport {
        let mut checks = Vec::with_capacity(1 + VALIDATED_GCP_PERMISSIONS.len());
        checks.push(CapabilityCheck {
            capability: self.caller_identity_capability(),
            status: CapabilityStatus::Pass,
        });
        for perm in VALIDATED_GCP_PERMISSIONS {
            checks.push(CapabilityCheck {
                capability: self.permission_capability(perm),
                status: CapabilityStatus::Fail {
                    reason: reason.to_string(),
                },
            });
        }
        RequirementsReport::new(checks)
    }
}

impl DeployerCredentials for GcpDeployerCredentials {
    fn requires_credentials_material(&self) -> bool {
        true
    }

    fn required_capabilities(&self) -> Vec<Capability> {
        let mut caps = Vec::with_capacity(1 + VALIDATED_GCP_PERMISSIONS.len());
        caps.push(self.caller_identity_capability());
        for perm in VALIDATED_GCP_PERMISSIONS {
            caps.push(self.permission_capability(perm));
        }
        caps
    }

    fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
        let caps = self.required_capabilities();

        let client = match self.resolve_client() {
            Ok(c) => c,
            Err(e) => return all_failed(&caps, &e.to_string()),
        };

        let identity = match run_gcp_async(client.get_caller_identity()) {
            Ok(id) => id,
            Err(e) => return all_failed(&caps, &format!("ADC caller identity failed: {e}")),
        };

        let Some(project) = identity.project.clone() else {
            return self.identity_pass_permissions_failed(
                "ADC resolved no quota/target project to run projects.testIamPermissions against; \
                 set a quota project or bind a service account scoped to the target project",
            );
        };

        let granted =
            match run_gcp_async(client.test_iam_permissions(&project, VALIDATED_GCP_PERMISSIONS)) {
                Ok(g) => g,
                Err(e) => {
                    return self.identity_pass_permissions_failed(&format!(
                        "projects.testIamPermissions failed: {e}"
                    ));
                }
            };
        let granted: HashSet<&str> = granted.iter().map(String::as_str).collect();

        let mut checks = Vec::with_capacity(1 + VALIDATED_GCP_PERMISSIONS.len());
        checks.push(CapabilityCheck {
            capability: self.caller_identity_capability(),
            status: CapabilityStatus::Pass,
        });
        for perm in VALIDATED_GCP_PERMISSIONS {
            let status = if granted.contains(perm) {
                CapabilityStatus::Pass
            } else {
                CapabilityStatus::Fail {
                    reason: format!("IAM did not grant `{perm}` to the deployer identity"),
                }
            };
            checks.push(CapabilityCheck {
                capability: self.permission_capability(perm),
                status,
            });
        }
        RequirementsReport::new(checks)
    }

    fn bootstrap(&self, input: &BootstrapInput<'_>) -> Result<BootstrapOutcome, BootstrapError> {
        let admin_hint = input.admin.profile();
        if admin_hint.is_empty() {
            return Err(BootstrapError::AdminRejected(
                "GCP bootstrap requires --admin-profile to identify the admin that will run \
                 `terraform apply`; pass a gcloud config name or the admin identity email."
                    .to_string(),
            ));
        }

        let rules_pack = render_bootstrap_rules_pack(&GcpBootstrapInput {
            env_id: input.env_id.as_str(),
            admin_identity_hint: admin_hint,
            permissions: VALIDATED_GCP_PERMISSIONS,
        });

        // Render-only: the admin applies the Terraform offline, then binds the
        // resulting service account via `op credentials rotate`. No credentials
        // are minted here — the WIF/SA-key bind path lands with the real target.
        Ok(BootstrapOutcome {
            rules_pack,
            bound_credentials_ref: None,
            bound_expiry: None,
            bound_secret_material: None,
        })
    }
}

/// Build an every-capability-failed report with the same reason.
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

/// Run an async block on a dedicated thread with its own current-thread tokio
/// runtime — the sync-trait → async-client bridge. See the AWS handler's
/// `run_aws_async` for why `block_in_place` / `Handle::block_on` are unsafe on
/// the operator's current-thread runtime.
pub(crate) fn run_gcp_async<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread tokio runtime");
                rt.block_on(fut)
            })
            .join()
            .expect("GCP validate thread did not panic")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct MockGcpClient {
        identity: Mutex<Option<Result<GcpCallerIdentity, GcpClientError>>>,
        permissions: Mutex<Option<Result<Vec<String>, GcpClientError>>>,
        test_calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockGcpClient {
        fn new(
            identity: Result<GcpCallerIdentity, GcpClientError>,
            permissions: Result<Vec<String>, GcpClientError>,
        ) -> Self {
            Self {
                identity: Mutex::new(Some(identity)),
                permissions: Mutex::new(Some(permissions)),
                test_calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl GcpValidatorClient for MockGcpClient {
        async fn get_caller_identity(&self) -> Result<GcpCallerIdentity, GcpClientError> {
            self.identity
                .lock()
                .unwrap()
                .take()
                .expect("identity scripted once")
        }

        async fn test_iam_permissions<'a>(
            &'a self,
            project: &'a str,
            permissions: &'a [&'a str],
        ) -> Result<Vec<String>, GcpClientError> {
            self.test_calls.lock().unwrap().push((
                project.to_string(),
                permissions.iter().map(|p| p.to_string()).collect(),
            ));
            self.permissions
                .lock()
                .unwrap()
                .take()
                .expect("permissions scripted once")
        }
    }

    fn identity() -> GcpCallerIdentity {
        GcpCallerIdentity {
            email: "gtc-local-deployer@proj.iam.gserviceaccount.com".to_string(),
            project: Some("proj".to_string()),
        }
    }

    fn all_granted() -> Vec<String> {
        VALIDATED_GCP_PERMISSIONS
            .iter()
            .map(|p| p.to_string())
            .collect()
    }

    fn ctx() -> ValidationContext<'static> {
        // validate ignores ctx; a leaked minimal context keeps the test terse.
        use greentic_deploy_spec::{EnvId, EnvironmentHostConfig};
        use std::path::Path;
        let env_id: &'static EnvId = Box::leak(Box::new(EnvId::try_from("local").unwrap()));
        let host: &'static EnvironmentHostConfig = Box::leak(Box::new(EnvironmentHostConfig {
            env_id: env_id.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
        }));
        ValidationContext {
            env_id,
            env_root: Path::new("/tmp/gcp-cloudrun-validate-test"),
            host_config: host,
        }
    }

    #[test]
    fn required_capabilities_listed_in_documented_order() {
        let creds = GcpDeployerCredentials::default();
        let caps = creds.required_capabilities();
        assert_eq!(caps.len(), 1 + VALIDATED_GCP_PERMISSIONS.len());
        assert_eq!(caps[0].id, GCP_CALLER_IDENTITY_CAP);
        for (cap, perm) in caps[1..].iter().zip(VALIDATED_GCP_PERMISSIONS) {
            assert_eq!(cap.id, format!("gcp.iam.allow:{perm}"));
        }
    }

    #[test]
    fn requires_credentials_material_is_true() {
        assert!(GcpDeployerCredentials::default().requires_credentials_material());
    }

    #[test]
    fn validate_passes_when_identity_and_all_permissions_granted() {
        let client = Arc::new(MockGcpClient::new(Ok(identity()), Ok(all_granted())));
        let creds = GcpDeployerCredentials::with_client(client.clone());
        let report = creds.validate(&ctx());
        assert!(
            report.passed(),
            "all granted → pass; missing: {:?}",
            report.missing()
        );
        let calls = client.test_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "proj");
        assert_eq!(calls[0].1.len(), VALIDATED_GCP_PERMISSIONS.len());
    }

    #[test]
    fn validate_fails_specific_permission_when_iam_omits_it() {
        let mut granted = all_granted();
        granted.retain(|p| p != "run.services.setIamPolicy");
        let client = Arc::new(MockGcpClient::new(Ok(identity()), Ok(granted)));
        let creds = GcpDeployerCredentials::with_client(client);
        let report = creds.validate(&ctx());
        assert!(!report.passed());
        let missing = report.missing();
        assert_eq!(missing.len(), 1);
        assert!(missing[0].ends_with("run.services.setIamPolicy"));
    }

    #[test]
    fn validate_fails_every_capability_when_no_client_wired() {
        let creds = GcpDeployerCredentials::default();
        let report = creds.validate(&ctx());
        assert!(!report.passed());
        assert_eq!(report.missing().len(), 1 + VALIDATED_GCP_PERMISSIONS.len());
    }

    #[test]
    fn validate_fails_every_capability_when_identity_rejected() {
        let client = Arc::new(MockGcpClient::new(
            Err(GcpClientError::IdentityRejected("expired".to_string())),
            Ok(all_granted()),
        ));
        let creds = GcpDeployerCredentials::with_client(client);
        let report = creds.validate(&ctx());
        assert!(!report.passed());
        assert_eq!(report.missing().len(), 1 + VALIDATED_GCP_PERMISSIONS.len());
    }

    #[test]
    fn validate_passes_identity_but_fails_permissions_when_test_errors() {
        let client = Arc::new(MockGcpClient::new(
            Ok(identity()),
            Err(GcpClientError::IamRejected("throttled".to_string())),
        ));
        let creds = GcpDeployerCredentials::with_client(client);
        let report = creds.validate(&ctx());
        assert!(!report.passed());
        // Identity passed, every permission failed → exactly N missing.
        assert_eq!(report.missing().len(), VALIDATED_GCP_PERMISSIONS.len());
        assert_eq!(report.checks[0].status, CapabilityStatus::Pass);
    }

    #[test]
    fn bootstrap_rejects_empty_admin_profile() {
        use crate::credentials::ZeroizedAdmin;
        use greentic_deploy_spec::EnvId;
        let creds = GcpDeployerCredentials::default();
        let env_id = EnvId::try_from("local").unwrap();
        let admin = ZeroizedAdmin::sentinel("");
        let err = creds
            .bootstrap(&BootstrapInput {
                env_id: &env_id,
                env_root: std::path::Path::new("/tmp"),
                admin: &admin,
            })
            .expect_err("empty admin profile must be rejected");
        assert!(
            matches!(err, BootstrapError::AdminRejected(ref m) if m.contains("--admin-profile"))
        );
    }

    #[test]
    fn bootstrap_renders_rules_pack_without_binding_credentials() {
        use crate::credentials::ZeroizedAdmin;
        use greentic_deploy_spec::EnvId;
        let creds = GcpDeployerCredentials::default();
        let env_id = EnvId::try_from("prod-eu").unwrap();
        let admin = ZeroizedAdmin::new("admin@example.com", String::new());
        let outcome = creds
            .bootstrap(&BootstrapInput {
                env_id: &env_id,
                env_root: std::path::Path::new("/tmp"),
                admin: &admin,
            })
            .expect("bootstrap renders");
        assert!(outcome.bound_credentials_ref.is_none());
        assert_eq!(outcome.rules_pack.entries.len(), 2);
        let tf = outcome
            .rules_pack
            .entries
            .iter()
            .find(|e| e.filename.ends_with(".tf"))
            .unwrap();
        for perm in VALIDATED_GCP_PERMISSIONS {
            assert!(tf.content.contains(&format!("\"{perm}\"")));
        }
    }
}
