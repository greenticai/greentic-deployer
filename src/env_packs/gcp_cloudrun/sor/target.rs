//! The side-effect seam for a SoR unit's Cloud Run service.

use async_trait::async_trait;

use crate::env_packs::gcp_cloudrun::deploy_target::{
    CloudRunTargetError, ScalingSpec, SecretEnvVar, SecretMount,
};

/// A Cloud Run service addressed by name (`gtc-sor-<unit_id>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorServiceRef {
    pub project: String,
    pub region: String,
    pub name: String,
}

/// Labels stamped on the service. Never a value: the owner stamp is a digest
/// of the env id, the intent a digest of the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorServiceLabels {
    pub owner: String,
    pub unit_id: String,
    pub intent: String,
}

/// Desired state of a SoR unit's service. Carries secret NAMES and VERSION
/// numbers only; its `Debug` is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorServiceSpec {
    pub service: SorServiceRef,
    pub image: String,
    pub args: Vec<String>,
    pub port: u16,
    pub runtime_service_account: String,
    /// Literal env vars (`HOME`, `SORX_POSTGRES_CA_FILE`) — never a value.
    pub env: Vec<(String, String)>,
    /// `SORX_ANSWERS` / `SORX_POSTGRES_URL` / `SORX_SHARED_SECRET`, each one
    /// pinned version of the unit's secret.
    pub secret_env: Vec<SecretEnvVar>,
    /// The optional CA as a read-only file.
    pub secret_mounts: Vec<SecretMount>,
    pub scaling: ScalingSpec,
    /// Startup probe path on `port`.
    pub health_path: String,
    pub labels: SorServiceLabels,
}

/// Live state of a SoR unit's service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorServiceStatus {
    pub etag: String,
    /// The `greentic-env` label; `None` for a service this deployer did not create.
    pub owner: Option<String>,
    /// The `greentic-sor-intent` label.
    pub intent: Option<String>,
    /// The latest revision is ready and serving.
    pub ready: bool,
    /// Cloud Run is still rolling a revision out.
    pub reconciling: bool,
    pub url: Option<String>,
    /// Cloud Run's own words for why the latest revision is not ready.
    pub not_ready_reason: Option<String>,
    pub log_uri: Option<String>,
}

impl SorServiceStatus {
    /// Settled and not ready: the latest revision failed. Distinct from a
    /// rollout still in progress, which is worth waiting for.
    pub fn failed(&self) -> bool {
        !self.ready && !self.reconciling
    }
}

/// An Artifact Registry repository (`<location>-docker.pkg.dev/<project>/<repository>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArRepository {
    pub project: String,
    pub location: String,
    pub repository: String,
}

impl ArRepository {
    pub fn resource(&self) -> String {
        format!(
            "projects/{}/locations/{}/repositories/{}",
            self.project, self.location, self.repository
        )
    }
}

/// Every method is idempotent; mutations of a live service carry its etag.
#[async_trait]
pub trait SorServiceTarget: std::fmt::Debug + Send + Sync {
    /// `None` when the service does not exist.
    async fn get_sor_service(
        &self,
        service: &SorServiceRef,
    ) -> Result<Option<SorServiceStatus>, CloudRunTargetError>;

    /// `etag = None` creates; `Some` is a conditional update that fails with
    /// `PreconditionFailed` on a stale token.
    async fn upsert_sor_service(
        &self,
        spec: &SorServiceSpec,
        etag: Option<&str>,
    ) -> Result<SorServiceStatus, CloudRunTargetError>;

    /// Grant `roles/run.invoker` to `allUsers` (E5: the shared secret, not IAM,
    /// is the boundary). Preserves every other binding.
    async fn set_sor_invoker_public(
        &self,
        service: &SorServiceRef,
    ) -> Result<(), CloudRunTargetError>;

    /// Idempotent against an absent service.
    async fn delete_sor_service(&self, service: &SorServiceRef) -> Result<(), CloudRunTargetError>;

    /// Grant `roles/artifactregistry.reader` on `repo` to `service_account`
    /// (unconditional binding; idempotent).
    async fn grant_artifact_registry_reader(
        &self,
        repo: &ArRepository,
        service_account: &str,
    ) -> Result<(), CloudRunTargetError>;
}

/// Default: every verb fails honestly.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconfiguredSorTarget;

#[async_trait]
impl SorServiceTarget for UnconfiguredSorTarget {
    async fn get_sor_service(
        &self,
        _service: &SorServiceRef,
    ) -> Result<Option<SorServiceStatus>, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn upsert_sor_service(
        &self,
        _spec: &SorServiceSpec,
        _etag: Option<&str>,
    ) -> Result<SorServiceStatus, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn set_sor_invoker_public(
        &self,
        _service: &SorServiceRef,
    ) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn delete_sor_service(
        &self,
        _service: &SorServiceRef,
    ) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn grant_artifact_registry_reader(
        &self,
        _repo: &ArRepository,
        _service_account: &str,
    ) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
}
