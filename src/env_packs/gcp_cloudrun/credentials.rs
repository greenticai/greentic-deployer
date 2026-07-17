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
    // Invoker IAM (D12) is a read-modify-write, so BOTH get + set are needed;
    // set_invoker_policy calls get_iam_policy before set_iam_policy.
    "run.services.getIamPolicy",
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
    // Grant the runtime SA `secretAccessor` on each staged secret (get→set RMW)
    // and delete secrets on `op env destroy` teardown (plan D6).
    "secretmanager.secrets.getIamPolicy",
    "secretmanager.secrets.setIamPolicy",
    "secretmanager.secrets.delete",
    // Artifact Registry read — only exercised when an `ar_repo` remote repo is
    // configured (plan D3); harmless to validate when it is not.
    "artifactregistry.repositories.get",
    "artifactregistry.repositories.downloadArtifacts",
];

/// The one permission validated against the *runtime service-account resource*
/// rather than the project: the deployer needs `actAs` on the specific runtime
/// SA it attaches to each revision (plan D7), and scoping the probe to that SA —
/// not the project — lets the bootstrap grant `actAs` on just that SA instead of
/// project-wide (PR-2 Codex review). Split out of the project-scoped
/// `testIamPermissions` call in [`validate`].
pub const ACT_AS_PERMISSION: &str = "iam.serviceAccounts.actAs";

/// Returns the canonical capability ID for a GCP IAM permission.
fn gcp_permission_capability_id(permission: &str) -> String {
    format!("gcp.iam.allow:{permission}")
}

/// The IAM resource name for a service account, used as the
/// `iam.serviceAccounts.testIamPermissions` / `setIamPolicy` resource. The `-`
/// project wildcard lets the API resolve the SA by email without the caller
/// re-stating its project.
fn service_account_resource(sa_email: &str) -> String {
    format!("projects/-/serviceAccounts/{sa_email}")
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

    /// Evaluate `permissions` against a **service-account resource**
    /// (`projects/-/serviceAccounts/<email>`) via
    /// `iam.serviceAccounts.testIamPermissions`. Used to probe
    /// [`ACT_AS_PERMISSION`] scoped to the runtime SA the revision runs as, not
    /// the project (plan D7 / PR-2 Codex review). Returns the granted subset.
    async fn test_sa_permissions<'a>(
        &'a self,
        sa_resource: &'a str,
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
    /// Target project the `projects.testIamPermissions` probe runs against, from
    /// the binding's `project` answer. `None` → fall back to the ADC-resolved
    /// project (the un-connected default / test path). Set by the CLI's
    /// `connected_cloudrun_credentials` so `requirements` probes the project the
    /// deployer actually targets, not just whatever the ambient chain resolves —
    /// a WIF/external-account credential often resolves no project at all.
    project: Option<String>,
    /// Runtime service account the `iam.serviceAccounts.actAs` probe targets, from
    /// the binding's resolved `runtime_service_account`. `None` → the default
    /// `gtc-{env}-runtime@{project}` formula. Set by the CLI so the probe matches
    /// the SA a live `op env up` attaches to the revision (a `service_account`
    /// answer override honored).
    service_account: Option<String>,
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
            ..Default::default()
        }
    }

    /// Target the binding's `project` for the IAM probes instead of the
    /// ADC-resolved project. Set by the connected CLI path; see [`Self::project`].
    pub fn with_project(mut self, project: impl Into<String>) -> Self {
        self.project = Some(project.into());
        self
    }

    /// Target the binding's resolved runtime service account for the `actAs`
    /// probe instead of the default `gtc-{env}-runtime@{project}` formula. Set by
    /// the connected CLI path; see [`Self::service_account`].
    pub fn with_service_account(mut self, service_account: impl Into<String>) -> Self {
        self.service_account = Some(service_account.into());
        self
    }

    /// Return the injected client, or build the real ADC-backed one.
    ///
    /// With `deploy-gcp-cloudrun`, an un-injected handler builds
    /// [`RealGcpClient`] (ambient ADC + raw `testIamPermissions` REST). Without
    /// the feature there is no real client, so an un-injected handler fails
    /// closed — the honest answer for a binary whose live GCP path is not
    /// compiled in. Tests always inject via [`with_client`](Self::with_client).
    #[cfg(feature = "deploy-gcp-cloudrun")]
    fn resolve_client(&self) -> Result<Arc<dyn GcpValidatorClient>, GcpClientError> {
        if let Some(c) = self.client.lock().expect("mutex not poisoned").as_ref() {
            return Ok(Arc::clone(c));
        }
        let built: Arc<dyn GcpValidatorClient> = Arc::new(RealGcpClient::resolve()?);
        let mut slot = self.client.lock().expect("mutex not poisoned");
        // Another thread may have raced us — keep their client.
        if let Some(c) = slot.as_ref() {
            return Ok(Arc::clone(c));
        }
        *slot = Some(Arc::clone(&built));
        Ok(built)
    }

    /// Without the real target compiled in, only an injected client can be used.
    #[cfg(not(feature = "deploy-gcp-cloudrun"))]
    fn resolve_client(&self) -> Result<Arc<dyn GcpValidatorClient>, GcpClientError> {
        if let Some(c) = self.client.lock().expect("mutex not poisoned").as_ref() {
            return Ok(Arc::clone(c));
        }
        Err(GcpClientError::NoCredentialChain(
            "no GCP validator client wired; this binary was built without `deploy-gcp-cloudrun`, \
             so the live ADC-backed validator is not available. Rebuild with the feature, or \
             inject a client via GcpDeployerCredentials::with_client for testing."
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
    /// Render-only: `bootstrap` emits a Terraform rules pack and returns
    /// `bound_credentials_ref: None` — the admin applies it out of band and
    /// binds the resulting service account afterwards. No material is ever
    /// written here, so there is nothing a crashed bootstrap could orphan.
    fn bound_credential_store_path(&self) -> Option<&'static str> {
        None
    }

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

    fn validate(&self, ctx: &ValidationContext<'_>) -> RequirementsReport {
        let caps = self.required_capabilities();

        let client = match self.resolve_client() {
            Ok(c) => c,
            Err(e) => return all_failed(&caps, &e.to_string()),
        };

        let identity = match run_gcp_async(client.get_caller_identity()) {
            Ok(id) => id,
            Err(e) => return all_failed(&caps, &format!("ADC caller identity failed: {e}")),
        };

        // Prefer the binding's target `project` (set by the connected CLI path)
        // over whatever the credential chain resolves: a WIF/external-account
        // credential often resolves no project, and even a keyed SA's home
        // project may differ from the project Cloud Run deploys into.
        let Some(project) = self.project.clone().or_else(|| identity.project.clone()) else {
            return self.identity_pass_permissions_failed(
                "no target project to run projects.testIamPermissions against; set the binding's \
                 `project` answer, or bind a service account scoped to the target project",
            );
        };

        // Project-scoped permissions: everything except `actAs`, which is probed
        // against the runtime SA resource (below) rather than the project (D7).
        let project_perms: Vec<&str> = VALIDATED_GCP_PERMISSIONS
            .iter()
            .copied()
            .filter(|p| *p != ACT_AS_PERMISSION)
            .collect();
        let project_granted =
            match run_gcp_async(client.test_iam_permissions(&project, &project_perms)) {
                Ok(g) => g,
                Err(e) => {
                    return self.identity_pass_permissions_failed(&format!(
                        "projects.testIamPermissions failed: {e}"
                    ));
                }
            };
        let project_granted: HashSet<&str> = project_granted.iter().map(String::as_str).collect();

        // `actAs` is validated against the runtime SA the revision impersonates,
        // scoped to that SA resource — not the project. Prefer the binding's
        // resolved runtime SA (set by the connected CLI path, honoring a
        // `service_account` answer override) so the probe matches the SA a live
        // `op env up` attaches; fall back to the default `gtc-{env}-runtime`
        // formula for the un-connected path. The failure reason spells out the SA.
        let sa_email = self.service_account.clone().unwrap_or_else(|| {
            super::deployer::default_runtime_service_account(ctx.env_id.as_str(), &project)
        });
        let act_as_probe: Result<bool, String> = match run_gcp_async(
            client.test_sa_permissions(&service_account_resource(&sa_email), &[ACT_AS_PERMISSION]),
        ) {
            Ok(granted) => Ok(granted.iter().any(|p| p == ACT_AS_PERMISSION)),
            Err(e) => Err(format!(
                "serviceAccounts.testIamPermissions on `{sa_email}` failed: {e}"
            )),
        };

        let mut checks = Vec::with_capacity(1 + VALIDATED_GCP_PERMISSIONS.len());
        checks.push(CapabilityCheck {
            capability: self.caller_identity_capability(),
            status: CapabilityStatus::Pass,
        });
        for perm in VALIDATED_GCP_PERMISSIONS {
            let status = if *perm == ACT_AS_PERMISSION {
                match &act_as_probe {
                    Ok(true) => CapabilityStatus::Pass,
                    Ok(false) => CapabilityStatus::Fail {
                        reason: format!(
                            "IAM did not grant `{ACT_AS_PERMISSION}` on the runtime service \
                             account `{sa_email}`; grant the deployer \
                             `roles/iam.serviceAccountUser` on that SA"
                        ),
                    },
                    Err(reason) => CapabilityStatus::Fail {
                        reason: reason.clone(),
                    },
                }
            } else if project_granted.contains(perm) {
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

/// Production ADC-backed validator client (feature `deploy-gcp-cloudrun`).
///
/// Resolves the ambient Application Default Credentials for the auth token, then
/// runs `projects.testIamPermissions` / `serviceAccounts.testIamPermissions` as
/// raw authenticated REST calls. The google-cloud-rust generated clients cover
/// Cloud Run + Secret Manager but not Resource Manager / IAM Admin, and a flat
/// `{"permissions":[...]}` POST needs no extra generated client — so this reuses
/// the existing `reqwest` dep with the ADC bearer token rather than pulling two
/// more SDK crates. The caller identity is read from the ADC service-account key
/// JSON (google-cloud-auth exposes a token, not a principal), degrading to the
/// ambient project env when ADC is not a key file.
#[cfg(feature = "deploy-gcp-cloudrun")]
#[derive(Debug)]
struct RealGcpClient {
    credentials: google_cloud_auth::credentials::Credentials,
    http: reqwest::Client,
    email: String,
    project: Option<String>,
}

#[cfg(feature = "deploy-gcp-cloudrun")]
impl RealGcpClient {
    const CRM_HOST: &'static str = "https://cloudresourcemanager.googleapis.com/v1";
    const IAM_HOST: &'static str = "https://iam.googleapis.com/v1";

    fn resolve() -> Result<Self, GcpClientError> {
        let credentials = super::bound_session::ambient_adc_credentials()
            .map_err(GcpClientError::NoCredentialChain)?;
        let (email, project) = resolve_adc_identity();
        Ok(Self {
            credentials,
            http: reqwest::Client::new(),
            email,
            project,
        })
    }

    /// Build from the env's bound deployer material (a service-account key or WIF
    /// config) so `requirements` authenticates + probes IAM AS THE BOUND DEPLOYER
    /// identity — the identity a live `op env up` deploys as — not the ambient ADC
    /// principal. Email/project are read straight off the material (both absent
    /// for a WIF external-account, whose target project the caller supplies via
    /// the binding's `project` answer, threaded into [`GcpDeployerCredentials`]).
    fn from_bound(
        material: &super::bound_session::GcpCredentialMaterial,
    ) -> Result<Self, GcpClientError> {
        let credentials = material
            .build_credentials()
            .map_err(GcpClientError::NoCredentialChain)?;
        Ok(Self {
            credentials,
            http: reqwest::Client::new(),
            email: material
                .client_email
                .clone()
                .unwrap_or_else(|| ADC_PRINCIPAL_UNKNOWN.to_string()),
            project: material.project_id.clone(),
        })
    }

    /// Fetch the ADC auth headers (mints/refreshes the token), returning the
    /// `http::HeaderMap` forwardable straight onto the reqwest request.
    async fn auth_headers(&self) -> Result<http::HeaderMap, GcpClientError> {
        use google_cloud_auth::credentials::CacheableResource;
        match self
            .credentials
            .headers(http::Extensions::new())
            .await
            .map_err(|e| GcpClientError::Transport(e.to_string()))?
        {
            CacheableResource::New { data, .. } => Ok(data),
            CacheableResource::NotModified => Err(GcpClientError::Transport(
                "ADC returned NotModified for a fresh header request".to_string(),
            )),
        }
    }

    /// POST `{"permissions":[...]}` to a `:testIamPermissions` URL and return the
    /// granted subset (the API echoes only the permissions the caller holds).
    async fn post_test_iam(
        &self,
        url: &str,
        permissions: &[&str],
    ) -> Result<Vec<String>, GcpClientError> {
        let headers = self.auth_headers().await?;
        let resp = self
            .http
            .post(url)
            .headers(headers)
            .json(&test_iam_body(permissions))
            .send()
            .await
            .map_err(|e| GcpClientError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| GcpClientError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(GcpClientError::IamRejected(format!(
                "testIamPermissions {url} → HTTP {status}: {body}"
            )));
        }
        let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            GcpClientError::Transport(format!("malformed testIamPermissions response: {e}"))
        })?;
        Ok(parse_test_iam_response(&json))
    }
}

#[cfg(feature = "deploy-gcp-cloudrun")]
#[async_trait::async_trait]
impl GcpValidatorClient for RealGcpClient {
    async fn get_caller_identity(&self) -> Result<GcpCallerIdentity, GcpClientError> {
        // Prove the credential actually mints a token (the GCP analogue of STS
        // GetCallerIdentity) before reporting the parsed identity.
        self.auth_headers().await.map_err(|e| {
            GcpClientError::IdentityRejected(format!("ADC token could not be minted: {e}"))
        })?;
        Ok(GcpCallerIdentity {
            email: self.email.clone(),
            project: self.project.clone(),
        })
    }

    async fn test_iam_permissions<'a>(
        &'a self,
        project: &'a str,
        permissions: &'a [&'a str],
    ) -> Result<Vec<String>, GcpClientError> {
        self.post_test_iam(&project_test_iam_url(project), permissions)
            .await
    }

    async fn test_sa_permissions<'a>(
        &'a self,
        sa_resource: &'a str,
        permissions: &'a [&'a str],
    ) -> Result<Vec<String>, GcpClientError> {
        self.post_test_iam(&sa_test_iam_url(sa_resource), permissions)
            .await
    }
}

/// Build the validator client the connected `op credentials requirements` path
/// injects: authenticate + probe IAM AS THE BOUND deployer credential. The
/// crate-visible entry point that lets `cli::credentials` build a real client
/// without exposing [`RealGcpClient`]. Mirrors the AWS/K8s connected-requirements
/// pattern so the probes reflect the deployer's real identity, not the ambient
/// one. (No ambient branch: `requirements` on a material-requiring deployer is
/// rejected upstream when no credential is bound, so this is only ever reached
/// with resolved bound material.)
#[cfg(feature = "deploy-gcp-cloudrun")]
pub(crate) fn build_validator_client(
    material: &super::bound_session::GcpCredentialMaterial,
) -> Result<Arc<dyn GcpValidatorClient>, GcpClientError> {
    Ok(Arc::new(RealGcpClient::from_bound(material)?))
}

// ---- Pure REST helpers (unit-tested; no HTTP) ----

/// The sentinel principal reported when ADC is not a legible service-account key
/// (gcloud user creds / metadata server expose no principal to the SDK).
#[cfg(feature = "deploy-gcp-cloudrun")]
const ADC_PRINCIPAL_UNKNOWN: &str = "(ADC principal)";

#[cfg(feature = "deploy-gcp-cloudrun")]
fn project_test_iam_url(project: &str) -> String {
    format!(
        "{}/projects/{project}:testIamPermissions",
        RealGcpClient::CRM_HOST
    )
}

#[cfg(feature = "deploy-gcp-cloudrun")]
fn sa_test_iam_url(sa_resource: &str) -> String {
    format!(
        "{}/{sa_resource}:testIamPermissions",
        RealGcpClient::IAM_HOST
    )
}

#[cfg(feature = "deploy-gcp-cloudrun")]
fn test_iam_body(permissions: &[&str]) -> serde_json::Value {
    serde_json::json!({ "permissions": permissions })
}

/// Parse the `permissions` array (the granted subset) from a
/// `testIamPermissions` response body.
#[cfg(feature = "deploy-gcp-cloudrun")]
fn parse_test_iam_response(body: &serde_json::Value) -> Vec<String> {
    body.get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve the ADC caller identity for display + project targeting. Reads the
/// service-account key JSON `GOOGLE_APPLICATION_CREDENTIALS` points at (its
/// `client_email` + `project_id`) — google-cloud-auth exposes only a token, so a
/// key file is the one place the principal is legible. Degrades to the ambient
/// project env vars when ADC is not a key file (gcloud user creds / metadata
/// server), reporting the principal as unknown.
#[cfg(feature = "deploy-gcp-cloudrun")]
fn resolve_adc_identity() -> (String, Option<String>) {
    if let Ok(path) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        && let Ok(content) = std::fs::read_to_string(&path)
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
    {
        let (email, project) = parse_sa_key_identity(&json);
        return (email, project.or_else(ambient_project_env));
    }
    (ADC_PRINCIPAL_UNKNOWN.to_string(), ambient_project_env())
}

/// Extract `(client_email, project_id)` from a service-account key JSON. A
/// non-service-account JSON yields the unknown-principal sentinel.
#[cfg(feature = "deploy-gcp-cloudrun")]
fn parse_sa_key_identity(json: &serde_json::Value) -> (String, Option<String>) {
    let email = json
        .get("client_email")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| ADC_PRINCIPAL_UNKNOWN.to_string());
    let project = json
        .get("project_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    (email, project)
}

#[cfg(feature = "deploy-gcp-cloudrun")]
fn ambient_project_env() -> Option<String> {
    std::env::var("GOOGLE_CLOUD_PROJECT")
        .ok()
        .or_else(|| std::env::var("GCLOUD_PROJECT").ok())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockGcpClient {
        identity: Mutex<Option<Result<GcpCallerIdentity, GcpClientError>>>,
        permissions: Mutex<Option<Result<Vec<String>, GcpClientError>>>,
        sa_permissions: Mutex<Option<Result<Vec<String>, GcpClientError>>>,
        test_calls: Mutex<Vec<(String, Vec<String>)>>,
        sa_calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockGcpClient {
        fn new(
            identity: Result<GcpCallerIdentity, GcpClientError>,
            permissions: Result<Vec<String>, GcpClientError>,
        ) -> Self {
            Self {
                identity: Mutex::new(Some(identity)),
                permissions: Mutex::new(Some(permissions)),
                // Default: actAs granted on the runtime SA (the common case).
                // Tests that vary the SA probe override via `with_sa_permissions`.
                sa_permissions: Mutex::new(Some(Ok(vec![ACT_AS_PERMISSION.to_string()]))),
                test_calls: Mutex::new(Vec::new()),
                sa_calls: Mutex::new(Vec::new()),
            }
        }

        fn with_sa_permissions(self, sa: Result<Vec<String>, GcpClientError>) -> Self {
            *self.sa_permissions.lock().unwrap() = Some(sa);
            self
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

        async fn test_sa_permissions<'a>(
            &'a self,
            sa_resource: &'a str,
            permissions: &'a [&'a str],
        ) -> Result<Vec<String>, GcpClientError> {
            self.sa_calls.lock().unwrap().push((
                sa_resource.to_string(),
                permissions.iter().map(|p| p.to_string()).collect(),
            ));
            self.sa_permissions
                .lock()
                .unwrap()
                .take()
                .expect("sa permissions scripted once")
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
        // `env_id` = "local" here — validate derives the runtime SA resource from
        // it (`gtc-local-runtime@{project}...`). A leaked minimal context keeps
        // the test terse.
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
        // The project-scoped probe carries every permission EXCEPT actAs, which
        // is split out to the SA-resource probe.
        let calls = client.test_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "proj");
        assert_eq!(calls[0].1.len(), VALIDATED_GCP_PERMISSIONS.len() - 1);
        assert!(
            !calls[0].1.iter().any(|p| p == ACT_AS_PERMISSION),
            "actAs must not ride the project-scoped call"
        );
    }

    /// The owed PR-2 hardening: `actAs` is probed against the *runtime SA
    /// resource* (`projects/-/serviceAccounts/gtc-{env}-runtime@{project}...`),
    /// not the project — so the bootstrap can scope the grant to that SA.
    #[test]
    fn validate_probes_act_as_against_the_runtime_sa_resource() {
        let client = Arc::new(MockGcpClient::new(Ok(identity()), Ok(all_granted())));
        let creds = GcpDeployerCredentials::with_client(client.clone());
        assert!(creds.validate(&ctx()).passed());
        let sa_calls = client.sa_calls.lock().unwrap();
        assert_eq!(sa_calls.len(), 1);
        assert_eq!(
            sa_calls[0].0,
            "projects/-/serviceAccounts/gtc-local-runtime@proj.iam.gserviceaccount.com",
        );
        assert_eq!(sa_calls[0].1, vec![ACT_AS_PERMISSION.to_string()]);
    }

    /// A denied SA-scoped actAs fails ONLY the actAs capability, not the whole
    /// report — the project permissions all passed.
    #[test]
    fn validate_fails_only_act_as_when_sa_probe_denies_it() {
        let client = Arc::new(
            MockGcpClient::new(Ok(identity()), Ok(all_granted()))
                .with_sa_permissions(Ok(Vec::new())),
        );
        let creds = GcpDeployerCredentials::with_client(client);
        let report = creds.validate(&ctx());
        assert!(!report.passed());
        let missing = report.missing();
        assert_eq!(missing.len(), 1);
        assert!(missing[0].ends_with(ACT_AS_PERMISSION), "{missing:?}");
    }

    /// An erroring SA probe (e.g. the SA does not exist yet) fails only actAs,
    /// with the transport reason, and never poisons the project permissions.
    #[test]
    fn validate_fails_only_act_as_when_sa_probe_errors() {
        let client = Arc::new(
            MockGcpClient::new(Ok(identity()), Ok(all_granted())).with_sa_permissions(Err(
                GcpClientError::IamRejected("service account not found".to_string()),
            )),
        );
        let creds = GcpDeployerCredentials::with_client(client);
        let report = creds.validate(&ctx());
        assert!(!report.passed());
        assert_eq!(report.missing().len(), 1);
    }

    /// 5d: the connected CLI path threads the binding's target `project` in. It
    /// overrides the ADC-resolved project for the project-scoped probe AND flows
    /// into the default runtime-SA formula the `actAs` probe derives.
    #[test]
    fn validate_targets_the_configured_project_over_the_adc_project() {
        let client = Arc::new(MockGcpClient::new(Ok(identity()), Ok(all_granted())));
        let creds =
            GcpDeployerCredentials::with_client(client.clone()).with_project("override-proj");
        assert!(creds.validate(&ctx()).passed());
        // Project-scoped probe hits the override, not the ADC identity's "proj".
        let calls = client.test_calls.lock().unwrap();
        assert_eq!(calls[0].0, "override-proj");
        // The default runtime SA is derived from the overridden project.
        let sa_calls = client.sa_calls.lock().unwrap();
        assert_eq!(
            sa_calls[0].0,
            "projects/-/serviceAccounts/gtc-local-runtime@override-proj.iam.gserviceaccount.com",
        );
    }

    /// 5d: the connected CLI path threads the binding's resolved runtime SA in
    /// (honoring a `service_account` answer override), so the `actAs` probe hits
    /// exactly the SA a live `op env up` attaches — not the default formula. The
    /// project-scoped probe is unaffected (still the ADC-resolved project).
    #[test]
    fn validate_probes_the_configured_service_account() {
        let client = Arc::new(MockGcpClient::new(Ok(identity()), Ok(all_granted())));
        let creds = GcpDeployerCredentials::with_client(client.clone())
            .with_service_account("custom-runtime@other.iam.gserviceaccount.com");
        assert!(creds.validate(&ctx()).passed());
        let sa_calls = client.sa_calls.lock().unwrap();
        assert_eq!(
            sa_calls[0].0,
            "projects/-/serviceAccounts/custom-runtime@other.iam.gserviceaccount.com",
        );
        assert_eq!(client.test_calls.lock().unwrap()[0].0, "proj");
    }

    /// 5d: a WIF/external-account credential resolves no project, but the binding
    /// supplies one — so a configured `project` lets `validate` run the probes
    /// instead of short-circuiting to "no target project" as it would on the
    /// un-connected ADC path.
    #[test]
    fn validate_uses_configured_project_when_the_credential_resolves_none() {
        let identity_no_project = GcpCallerIdentity {
            // A WIF external-account resolves no legible principal/project; the
            // email is display-only here, so any placeholder does.
            email: "wif-federated-subject".to_string(),
            project: None,
        };
        let client = Arc::new(MockGcpClient::new(
            Ok(identity_no_project),
            Ok(all_granted()),
        ));
        let creds = GcpDeployerCredentials::with_client(client.clone()).with_project("proj");
        let report = creds.validate(&ctx());
        assert!(report.passed(), "configured project must drive the probe");
        assert_eq!(client.test_calls.lock().unwrap()[0].0, "proj");
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

    /// Only meaningful without the real client compiled in: with
    /// `deploy-gcp-cloudrun`, an un-injected handler builds the real ADC client
    /// (and would do live credential I/O), so the fail-closed contract this test
    /// asserts holds only for the feature-off build.
    #[cfg(not(feature = "deploy-gcp-cloudrun"))]
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

    #[test]
    fn service_account_resource_uses_the_project_wildcard() {
        assert_eq!(
            service_account_resource("gtc-local-runtime@proj.iam.gserviceaccount.com"),
            "projects/-/serviceAccounts/gtc-local-runtime@proj.iam.gserviceaccount.com",
        );
    }

    // ---- Real-client pure REST helpers (feature `deploy-gcp-cloudrun`) ----

    #[cfg(feature = "deploy-gcp-cloudrun")]
    #[test]
    fn test_iam_urls_target_resource_manager_and_iam() {
        assert_eq!(
            project_test_iam_url("proj"),
            "https://cloudresourcemanager.googleapis.com/v1/projects/proj:testIamPermissions",
        );
        assert_eq!(
            sa_test_iam_url(
                "projects/-/serviceAccounts/gtc-local-runtime@proj.iam.gserviceaccount.com"
            ),
            "https://iam.googleapis.com/v1/projects/-/serviceAccounts/gtc-local-runtime@proj.iam.gserviceaccount.com:testIamPermissions",
        );
    }

    #[cfg(feature = "deploy-gcp-cloudrun")]
    #[test]
    fn test_iam_body_wraps_the_permission_list() {
        let body = test_iam_body(&["run.services.create", "run.services.get"]);
        assert_eq!(
            body,
            serde_json::json!({ "permissions": ["run.services.create", "run.services.get"] }),
        );
    }

    #[cfg(feature = "deploy-gcp-cloudrun")]
    #[test]
    fn parse_test_iam_response_reads_granted_subset_or_empty() {
        let granted = parse_test_iam_response(&serde_json::json!({
            "permissions": ["run.services.get", "run.services.create"]
        }));
        assert_eq!(granted, vec!["run.services.get", "run.services.create"]);
        // A GCP "no permissions granted" response omits the array entirely.
        assert!(parse_test_iam_response(&serde_json::json!({})).is_empty());
    }

    #[cfg(feature = "deploy-gcp-cloudrun")]
    #[test]
    fn parse_sa_key_identity_reads_email_and_project() {
        let (email, project) = parse_sa_key_identity(&serde_json::json!({
            "type": "service_account",
            "client_email": "gtc-local-deployer@proj.iam.gserviceaccount.com",
            "project_id": "proj",
        }));
        assert_eq!(email, "gtc-local-deployer@proj.iam.gserviceaccount.com");
        assert_eq!(project.as_deref(), Some("proj"));
        // A non-key JSON degrades to the unknown-principal sentinel.
        let (email, project) =
            parse_sa_key_identity(&serde_json::json!({ "type": "authorized_user" }));
        assert_eq!(email, ADC_PRINCIPAL_UNKNOWN);
        assert!(project.is_none());
    }
}
