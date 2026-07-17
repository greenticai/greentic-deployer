//! Cloud Run deploy-target seam for the GCP Cloud Run env-pack.
//!
//! Mirrors the AWS-ECS [`EcsDeployTarget`](crate::env_packs::aws::deploy_target)
//! pattern: a mockable side-effect trait the [`Deployer`](super::deployer)
//! verbs drive, an in-memory fake for the conformance bench + unit tests, and
//! an [`UnconfiguredCloudRunTarget`] that fails honestly when no real client is
//! wired. The real `google-cloud-run-v2` / `google-cloud-secretmanager-v1`
//! backed impl lands in a follow-up PR behind the `deploy-gcp-cloudrun`
//! feature.
//!
//! ## Why the seam differs from ECS
//!
//! Cloud Run collapses ECS's service + task-set + ALB listener into a single
//! `Service` resource whose `traffic[]` array is a field on the service, under
//! optimistic-concurrency `etag` control. So this seam has a read path
//! ([`get_service`](CloudRunTarget::get_service) returning the live `traffic[]`
//! and `etag`), and every mutation is a read-modify-write: the caller passes
//! the `etag` it read back, and a stale write is rejected with
//! [`CloudRunTargetError::PreconditionFailed`] rather than silently clobbering
//! a concurrent traffic change (plan D4).

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, RevisionId};

/// Whether a Cloud Run Service admits unauthenticated traffic.
///
/// Cloud Run Services are **private by default** — no request is served unless
/// `roles/run.invoker` is granted (plan D12). The one-command flow returns a
/// `run.app` URL that a `curl /healthz` probe and webhook callbacks
/// (Telegram, …) must reach, so the wizard carries an explicit choice rather
/// than leaving reachability implicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Grant `roles/run.invoker` to `allUsers` — the service is reachable
    /// without a Google identity token. Default for the webhook/demo flow.
    Public,
    /// Leave the service private; only callers presenting an ADC identity
    /// token can invoke it.
    Authenticated,
}

/// Scaling + sizing knobs rendered onto the Service (plan D5/D6).
///
/// `min_instances = 0` + request-based billing is what makes an idle env cost
/// nothing; `max_instances = 1` keeps a single writer for the ephemeral,
/// per-instance seeded dev store (plan D6). Carried on [`ServiceSpec`] so the
/// real target consumes it without a spec change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalingSpec {
    pub cpu: String,
    pub memory: String,
    pub min_instances: u32,
    pub max_instances: u32,
    pub concurrency: u32,
}

/// Identity of a Cloud Run Service for reads/deletes (no desired state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRef {
    pub deployment_id: DeploymentId,
    pub project: String,
    pub region: String,
}

/// Identity of a single Cloud Run revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRef {
    pub deployment_id: DeploymentId,
    pub revision_id: RevisionId,
    pub project: String,
    pub region: String,
}

/// One weighted revision in the Service's `traffic[]` array.
///
/// `percent` is a whole integer 0..=100 — Cloud Run cannot represent basis
/// points faithfully, so [`super::deployer`] rejects splits that are not whole
/// multiples of 100 bps and converts the rest to integer percent (plan D1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficTarget {
    pub revision_id: RevisionId,
    pub percent: u32,
}

/// A single Secret Manager secret projected as a read-only volume at `mount_dir`
/// (plan D6). Each item maps an immutable numeric `version` to a file at a
/// subdirectory-capable `rel_path` under `mount_dir`; greentic-start's
/// `GREENTIC_SEED_DIR` boot-copy reads the tree into the writable env store.
/// One secret → one volume: Cloud Run **forbids nested volume mounts**, so both
/// seed files (`environment.json` and `.greentic/dev/.dev.secrets.env`) ride
/// distinct versions of the SAME secret under one `/seed` mount rather than two
/// nested mounts. Env-var secret sources were rejected: the dev store needs a
/// writable file, and env-var payloads hit the 32 KB limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMount {
    /// Absolute container directory the secret volume mounts at (e.g. `/seed`).
    pub mount_dir: String,
    pub secret_name: String,
    /// Version→relative-path items projected into `mount_dir`.
    pub items: Vec<SecretMountItem>,
}

/// One `(version, rel_path)` file within a [`SecretMount`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMountItem {
    /// The immutable numeric version (never the `latest` alias — plan D6).
    pub version: String,
    /// Path relative to [`SecretMount::mount_dir`]; may contain subdirectories
    /// (Cloud Run projects `a/b/c` by creating the intermediate directories).
    pub rel_path: String,
}

/// Desired state of a Cloud Run Service + the one revision being created.
///
/// Merges what ECS split across `ServiceSpec` + `TaskSetSpec` + the ALB
/// listener: Cloud Run's single-resource model carries image, traffic, scaling,
/// access mode, and secret mounts in one upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub deployment_id: DeploymentId,
    pub project: String,
    pub region: String,
    /// The single runtime image all revisions run (plan D2); new revisions
    /// differ only by revision-scoped env vars, not image tag.
    pub image: String,
    /// The revision this upsert creates.
    pub revision_id: RevisionId,
    /// The least-privilege runtime service account the revision runs as
    /// (resolved from the `service_account` answer, or the bootstrap default).
    /// Empty is invalid — the deployer always resolves a concrete identity so a
    /// revision never silently runs under the Compute Engine default SA.
    pub runtime_service_account: String,
    /// Traffic pinned to *named* revisions in the same call (plan D4) — never
    /// `LATEST`, never a single-entry 0% array.
    pub traffic: Vec<TrafficTarget>,
    pub scaling: ScalingSpec,
    pub access_mode: AccessMode,
    /// Cloud Run `sessionAffinity` (plan D11).
    pub session_affinity: bool,
    pub secrets: Vec<SecretMount>,
    /// Literal boot environment variables projected onto the container (plan D6
    /// activation). `GREENTIC_SEED_DIR` triggers greentic-start's seed boot-copy
    /// of the mounted `environment.json` into the writable env store rooted at
    /// `HOME`; `GREENTIC_ENV` selects the env dir the seed lands in;
    /// `GREENTIC_GATEWAY_LISTEN_ADDR` makes the gateway reachable on Cloud Run;
    /// and the revision-identity vars tell the runtime which revision to serve.
    /// Order-preserving so the rendered Service is deterministic.
    pub env: Vec<(String, String)>,
}

/// The subset of [`ServiceSpec`] Cloud Run renders into the **immutable**
/// revision (`Service.template`).
///
/// Everything else on the spec is Service-level and freely mutable: `traffic`
/// is an array on the Service, and `access_mode` is not on the Service at all
/// (it is a separate IAM policy). Two upserts naming the same revision must
/// agree on every field here — Cloud Run rejects the second otherwise, with
/// *"Revision named 'X' with different configuration already exists"* (HTTP
/// 409). Used by [`InMemoryCloudRun`] to model that rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RevisionTemplate {
    image: String,
    runtime_service_account: String,
    scaling: ScalingSpec,
    session_affinity: bool,
    secrets: Vec<SecretMount>,
    env: Vec<(String, String)>,
}

impl RevisionTemplate {
    fn of(spec: &ServiceSpec) -> Self {
        Self {
            image: spec.image.clone(),
            runtime_service_account: spec.runtime_service_account.clone(),
            scaling: spec.scaling.clone(),
            session_affinity: spec.session_affinity,
            secrets: spec.secrets.clone(),
            env: spec.env.clone(),
        }
    }
}

/// Live state of a Cloud Run Service returned by [`CloudRunTarget::get_service`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub ready: bool,
    pub url: Option<String>,
    /// The live traffic allocation (named revisions).
    pub traffic: Vec<TrafficTarget>,
    /// Optimistic-concurrency token; sent back as the precondition on the next
    /// mutation (plan D4).
    pub etag: String,
}

/// Readiness of a single revision, polled during the warm wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionStatus {
    pub ready: bool,
    pub active: bool,
}

/// Return of [`CloudRunTarget::upsert_secret`]: the immutable numeric version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVersion {
    pub version: String,
}

/// Errors the Cloud Run target can surface. All flow into
/// [`DeployerError::Provider`](crate::env_packs::deployer::DeployerError::Provider)
/// at the [`Deployer`](super::deployer) boundary.
#[derive(Debug, thiserror::Error)]
pub enum CloudRunTargetError {
    /// A GCP API call failed.
    #[error("Cloud Run API failure: {0}")]
    Api(String),
    /// The named resource does not exist (e.g. `set_traffic` on a service that
    /// was never created).
    #[error("Cloud Run resource not found: {0}")]
    NotFound(String),
    /// The `etag` precondition did not match the live resource — a concurrent
    /// mutation moved it. The caller re-reads and recomputes (plan D4).
    #[error("Cloud Run precondition failed (etag mismatch); re-read and retry")]
    PreconditionFailed,
    /// No GCP client is wired (the default [`UnconfiguredCloudRunTarget`]).
    #[error("Cloud Run target is not configured (no GCP client wired)")]
    Unconfigured,
}

/// Side-effect seam the Cloud Run [`Deployer`](super::deployer) verbs drive.
///
/// Every method is idempotent. Mutations are read-modify-write under `etag`
/// optimistic concurrency (plan D4). Tests use [`InMemoryCloudRun`]; production
/// wires the `google-cloud-*`-backed impl (follow-up PR).
#[async_trait]
pub trait CloudRunTarget: std::fmt::Debug + Send + Sync {
    /// Read the live Service — its `traffic[]`, readiness, and `etag`. Returns
    /// `None` when the Service does not yet exist (first-create path).
    async fn get_service(
        &self,
        service: &ServiceRef,
    ) -> Result<Option<ServiceStatus>, CloudRunTargetError>;

    /// Create-or-update the Service, producing the revision named by
    /// `spec.revision_id` and pinning `spec.traffic`. `etag = None` creates;
    /// `etag = Some(_)` is a conditional update that fails with
    /// [`PreconditionFailed`](CloudRunTargetError::PreconditionFailed) on a
    /// stale token.
    async fn upsert_service(
        &self,
        spec: &ServiceSpec,
        etag: Option<&str>,
    ) -> Result<ServiceStatus, CloudRunTargetError>;

    /// Poll a single revision's readiness for the warm wait.
    async fn get_revision_status(
        &self,
        revision: &RevisionRef,
    ) -> Result<RevisionStatus, CloudRunTargetError>;

    /// Set the Service's traffic split under `etag` optimistic concurrency.
    async fn set_traffic(
        &self,
        service: &ServiceRef,
        traffic: &[TrafficTarget],
        etag: &str,
    ) -> Result<ServiceStatus, CloudRunTargetError>;

    /// Apply the invoker IAM binding for the requested access mode (plan D12).
    async fn set_invoker_policy(
        &self,
        service: &ServiceRef,
        access_mode: AccessMode,
    ) -> Result<(), CloudRunTargetError>;

    /// Delete a single revision. Idempotent against an absent revision.
    async fn delete_revision(&self, revision: &RevisionRef) -> Result<(), CloudRunTargetError>;

    /// Delete the whole Service + its revisions. Idempotent against an absent
    /// service. Used by the mandatory `op env destroy` teardown (follow-up PR).
    async fn delete_service(&self, service: &ServiceRef) -> Result<(), CloudRunTargetError>;

    /// The Service's auto-assigned `*.run.app` URL, or `None` if not ready.
    async fn get_service_url(
        &self,
        service: &ServiceRef,
    ) -> Result<Option<String>, CloudRunTargetError>;

    /// Create-or-update a Secret Manager secret and add a new version,
    /// returning the immutable numeric version resource (plan D6). Never the
    /// `latest` alias.
    async fn upsert_secret(
        &self,
        name: &str,
        payload: &[u8],
    ) -> Result<SecretVersion, CloudRunTargetError>;

    /// Grant `roles/secretmanager.secretAccessor` on `secret_name` to
    /// `service_account` (plan D6). Load-bearing: Cloud Run rejects a revision
    /// whose runtime SA cannot read a mounted secret version, so the deploy must
    /// grant access before mounting. Idempotent (a re-grant is a no-op).
    async fn grant_secret_accessor(
        &self,
        secret_name: &str,
        service_account: &str,
    ) -> Result<(), CloudRunTargetError>;

    /// Delete a Secret Manager secret and all its versions. Idempotent against
    /// an absent secret. Used by the `op env destroy` teardown.
    async fn delete_secret(&self, name: &str) -> Result<(), CloudRunTargetError>;
}

/// Default target: every verb fails with [`CloudRunTargetError::Unconfigured`]
/// so an unwired deployer fails honestly instead of silently succeeding.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconfiguredCloudRunTarget;

#[async_trait]
impl CloudRunTarget for UnconfiguredCloudRunTarget {
    async fn get_service(
        &self,
        _service: &ServiceRef,
    ) -> Result<Option<ServiceStatus>, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn upsert_service(
        &self,
        _spec: &ServiceSpec,
        _etag: Option<&str>,
    ) -> Result<ServiceStatus, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn get_revision_status(
        &self,
        _revision: &RevisionRef,
    ) -> Result<RevisionStatus, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn set_traffic(
        &self,
        _service: &ServiceRef,
        _traffic: &[TrafficTarget],
        _etag: &str,
    ) -> Result<ServiceStatus, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn set_invoker_policy(
        &self,
        _service: &ServiceRef,
        _access_mode: AccessMode,
    ) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn delete_revision(&self, _revision: &RevisionRef) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn delete_service(&self, _service: &ServiceRef) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn get_service_url(
        &self,
        _service: &ServiceRef,
    ) -> Result<Option<String>, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn upsert_secret(
        &self,
        _name: &str,
        _payload: &[u8],
    ) -> Result<SecretVersion, CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn grant_secret_accessor(
        &self,
        _secret_name: &str,
        _service_account: &str,
    ) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
    async fn delete_secret(&self, _name: &str) -> Result<(), CloudRunTargetError> {
        Err(CloudRunTargetError::Unconfigured)
    }
}

/// In-memory fake modelling Cloud Run's single-resource + etag semantics.
///
/// Mirrors `InMemoryEcs`: `Mutex`-wrapped `BTreeMap`s plus snapshot accessors
/// for test assertions. Readiness is instant (revisions report `ready` the
/// moment they are created) so the warm wait resolves on the first poll.
///
/// **Revisions are immutable here, as they are in Cloud Run** — see
/// [`upsert_service`](InMemoryCloudRun::upsert_service). A fake that silently
/// accepted a re-render of a live revision would make the conformance suite's
/// idempotency check vacuous for the one way Cloud Run's warm can realistically
/// fail to be idempotent.
#[derive(Debug, Default)]
pub struct InMemoryCloudRun {
    services: Mutex<BTreeMap<DeploymentId, ServiceStatus>>,
    /// Each live revision plus the template it was rendered from, so a
    /// re-upsert can be checked against Cloud Run's immutability rule.
    revisions: Mutex<BTreeMap<(DeploymentId, RevisionId), (RevisionStatus, RevisionTemplate)>>,
    secrets: Mutex<BTreeMap<String, (Vec<u8>, u64)>>,
    /// Service accounts granted `secretAccessor` on each secret, so tests can
    /// assert the deployer grants the runtime SA before mounting.
    secret_accessors: Mutex<BTreeMap<String, Vec<String>>>,
    invoker_policies: Mutex<BTreeMap<DeploymentId, AccessMode>>,
    /// Last runtime service account each Service was upserted with, so tests can
    /// assert the deployer threads the resolved identity through the seam.
    runtime_service_accounts: Mutex<BTreeMap<DeploymentId, String>>,
    /// Boot env vars each Service was upserted with, so tests can assert the
    /// deployer projects the seed-activation + identity vars onto the container.
    service_env: Mutex<BTreeMap<DeploymentId, Vec<(String, String)>>>,
    /// Secret mounts each Service was upserted with, so tests can assert the
    /// deployer projects both seed files under one `/seed` volume.
    service_secrets: Mutex<BTreeMap<DeploymentId, Vec<SecretMount>>>,
    etag_counter: Mutex<u64>,
}

impl InMemoryCloudRun {
    fn next_etag(&self) -> String {
        let mut c = self.etag_counter.lock().expect("etag mutex not poisoned");
        *c += 1;
        format!("etag-{c}")
    }

    fn deterministic_url(deployment_id: DeploymentId) -> String {
        // Reuse the canonical service-name format so the fake URL can't drift
        // from the real Cloud Run naming scheme.
        format!(
            "https://{}-000000.run.app",
            super::deployer::service_name(deployment_id)
        )
    }

    // ---- Snapshot accessors (for test assertions) ----

    /// Snapshot of every live Service keyed by deployment.
    pub fn services(&self) -> BTreeMap<DeploymentId, ServiceStatus> {
        self.services.lock().expect("services mutex").clone()
    }

    /// Snapshot of every live revision.
    pub fn revisions(&self) -> BTreeMap<(DeploymentId, RevisionId), RevisionStatus> {
        self.revisions
            .lock()
            .expect("revisions mutex")
            .iter()
            .map(|(key, (status, _template))| (*key, *status))
            .collect()
    }

    /// Snapshot of every staged secret: name → (payload, version count).
    pub fn secrets(&self) -> BTreeMap<String, (Vec<u8>, u64)> {
        self.secrets.lock().expect("secrets mutex").clone()
    }

    /// Service accounts granted `secretAccessor` on `secret_name`, if any.
    pub fn secret_accessors_for(&self, secret_name: &str) -> Option<Vec<String>> {
        self.secret_accessors
            .lock()
            .expect("secret-accessors mutex")
            .get(secret_name)
            .cloned()
    }

    /// Last-applied traffic for a deployment's Service, if it exists.
    pub fn traffic_for(&self, deployment_id: DeploymentId) -> Option<Vec<TrafficTarget>> {
        self.services
            .lock()
            .expect("services mutex")
            .get(&deployment_id)
            .map(|s| s.traffic.clone())
    }

    /// Last-applied invoker access mode for a deployment, if `set_invoker_policy`
    /// was called.
    pub fn invoker_policy_for(&self, deployment_id: DeploymentId) -> Option<AccessMode> {
        self.invoker_policies
            .lock()
            .expect("invoker mutex")
            .get(&deployment_id)
            .copied()
    }

    /// Runtime service account the deployment's Service was last upserted with.
    pub fn runtime_service_account_for(&self, deployment_id: DeploymentId) -> Option<String> {
        self.runtime_service_accounts
            .lock()
            .expect("runtime-sa mutex")
            .get(&deployment_id)
            .cloned()
    }

    /// Boot env vars the last upsert projected onto `deployment_id`'s container.
    pub fn service_env_for(&self, deployment_id: DeploymentId) -> Option<Vec<(String, String)>> {
        self.service_env
            .lock()
            .expect("service-env mutex")
            .get(&deployment_id)
            .cloned()
    }

    /// Secret mounts the last upsert projected onto `deployment_id`'s container.
    pub fn service_secrets_for(&self, deployment_id: DeploymentId) -> Option<Vec<SecretMount>> {
        self.service_secrets
            .lock()
            .expect("service-secrets mutex")
            .get(&deployment_id)
            .cloned()
    }
}

#[async_trait]
impl CloudRunTarget for InMemoryCloudRun {
    async fn get_service(
        &self,
        service: &ServiceRef,
    ) -> Result<Option<ServiceStatus>, CloudRunTargetError> {
        Ok(self
            .services
            .lock()
            .expect("services mutex")
            .get(&service.deployment_id)
            .cloned())
    }

    async fn upsert_service(
        &self,
        spec: &ServiceSpec,
        etag: Option<&str>,
    ) -> Result<ServiceStatus, CloudRunTargetError> {
        let mut services = self.services.lock().expect("services mutex");
        match (services.get(&spec.deployment_id), etag) {
            // Conditional update: the etag must match the live resource.
            (Some(live), Some(sent)) if live.etag != sent => {
                return Err(CloudRunTargetError::PreconditionFailed);
            }
            // Create requested (etag None) but the service already exists —
            // Cloud Run rejects a create-over-existing. The warm flow always
            // reads first, so this only fires on a genuine stale create.
            (Some(_), None) => return Err(CloudRunTargetError::PreconditionFailed),
            _ => {}
        }
        let mut revisions = self.revisions.lock().expect("revisions mutex");
        let template = RevisionTemplate::of(spec);
        // Cloud Run revisions are immutable. Re-rendering a live revision name
        // with any different template is rejected 409 ("Revision named 'X' with
        // different configuration already exists") — which `real_target`'s
        // `classify` maps onto `PreconditionFailed`, exactly as returned here.
        // The collapse is faithful, and it is why the deployer cannot tell this
        // apart from a stale-etag race by error alone: only the revision's
        // existence distinguishes them. Re-rendering the SAME template is a
        // no-op that succeeds, which is what makes a warm retry idempotent.
        if let Some((_, live_template)) = revisions.get(&(spec.deployment_id, spec.revision_id))
            && *live_template != template
        {
            return Err(CloudRunTargetError::PreconditionFailed);
        }
        let status = ServiceStatus {
            ready: true,
            url: Some(Self::deterministic_url(spec.deployment_id)),
            traffic: spec.traffic.clone(),
            etag: self.next_etag(),
        };
        services.insert(spec.deployment_id, status.clone());
        revisions.insert(
            (spec.deployment_id, spec.revision_id),
            (
                RevisionStatus {
                    ready: true,
                    active: true,
                },
                template,
            ),
        );
        drop(revisions);
        self.runtime_service_accounts
            .lock()
            .expect("runtime-sa mutex")
            .insert(spec.deployment_id, spec.runtime_service_account.clone());
        self.service_env
            .lock()
            .expect("service-env mutex")
            .insert(spec.deployment_id, spec.env.clone());
        self.service_secrets
            .lock()
            .expect("service-secrets mutex")
            .insert(spec.deployment_id, spec.secrets.clone());
        Ok(status)
    }

    async fn get_revision_status(
        &self,
        revision: &RevisionRef,
    ) -> Result<RevisionStatus, CloudRunTargetError> {
        self.revisions
            .lock()
            .expect("revisions mutex")
            .get(&(revision.deployment_id, revision.revision_id))
            .map(|(status, _template)| *status)
            .ok_or_else(|| {
                CloudRunTargetError::NotFound(format!(
                    "revision {} not found",
                    revision.revision_id
                ))
            })
    }

    async fn set_traffic(
        &self,
        service: &ServiceRef,
        traffic: &[TrafficTarget],
        etag: &str,
    ) -> Result<ServiceStatus, CloudRunTargetError> {
        let mut services = self.services.lock().expect("services mutex");
        let live = services
            .get(&service.deployment_id)
            .ok_or_else(|| CloudRunTargetError::NotFound("service not found".to_string()))?;
        if live.etag != etag {
            return Err(CloudRunTargetError::PreconditionFailed);
        }
        let status = ServiceStatus {
            ready: live.ready,
            url: live.url.clone(),
            traffic: traffic.to_vec(),
            etag: self.next_etag(),
        };
        services.insert(service.deployment_id, status.clone());
        Ok(status)
    }

    async fn set_invoker_policy(
        &self,
        service: &ServiceRef,
        access_mode: AccessMode,
    ) -> Result<(), CloudRunTargetError> {
        self.invoker_policies
            .lock()
            .expect("invoker mutex")
            .insert(service.deployment_id, access_mode);
        Ok(())
    }

    async fn delete_revision(&self, revision: &RevisionRef) -> Result<(), CloudRunTargetError> {
        self.revisions
            .lock()
            .expect("revisions mutex")
            .remove(&(revision.deployment_id, revision.revision_id));
        Ok(())
    }

    async fn delete_service(&self, service: &ServiceRef) -> Result<(), CloudRunTargetError> {
        self.services
            .lock()
            .expect("services mutex")
            .remove(&service.deployment_id);
        self.revisions
            .lock()
            .expect("revisions mutex")
            .retain(|(dep, _), _| *dep != service.deployment_id);
        self.invoker_policies
            .lock()
            .expect("invoker mutex")
            .remove(&service.deployment_id);
        self.runtime_service_accounts
            .lock()
            .expect("runtime-sa mutex")
            .remove(&service.deployment_id);
        Ok(())
    }

    async fn get_service_url(
        &self,
        service: &ServiceRef,
    ) -> Result<Option<String>, CloudRunTargetError> {
        Ok(self
            .services
            .lock()
            .expect("services mutex")
            .get(&service.deployment_id)
            .and_then(|s| s.url.clone()))
    }

    async fn upsert_secret(
        &self,
        name: &str,
        payload: &[u8],
    ) -> Result<SecretVersion, CloudRunTargetError> {
        let mut secrets = self.secrets.lock().expect("secrets mutex");
        let entry = secrets
            .entry(name.to_string())
            .or_insert_with(|| (Vec::new(), 0));
        entry.0 = payload.to_vec();
        entry.1 += 1;
        Ok(SecretVersion {
            version: entry.1.to_string(),
        })
    }

    async fn grant_secret_accessor(
        &self,
        secret_name: &str,
        service_account: &str,
    ) -> Result<(), CloudRunTargetError> {
        let mut grants = self
            .secret_accessors
            .lock()
            .expect("secret-accessors mutex");
        let members = grants.entry(secret_name.to_string()).or_default();
        if !members.iter().any(|m| m == service_account) {
            members.push(service_account.to_string());
        }
        Ok(())
    }

    async fn delete_secret(&self, name: &str) -> Result<(), CloudRunTargetError> {
        self.secrets.lock().expect("secrets mutex").remove(name);
        self.secret_accessors
            .lock()
            .expect("secret-accessors mutex")
            .remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn dep(seed: u128) -> DeploymentId {
        DeploymentId(Ulid::from(seed))
    }
    fn rev(seed: u128) -> RevisionId {
        RevisionId(Ulid::from(seed))
    }

    fn service_ref(deployment_id: DeploymentId) -> ServiceRef {
        ServiceRef {
            deployment_id,
            project: "proj".to_string(),
            region: "us-central1".to_string(),
        }
    }

    fn spec(
        deployment_id: DeploymentId,
        revision_id: RevisionId,
        traffic: Vec<TrafficTarget>,
    ) -> ServiceSpec {
        ServiceSpec {
            deployment_id,
            project: "proj".to_string(),
            region: "us-central1".to_string(),
            image: "ghcr.io/greenticai/greentic-start-distroless:develop".to_string(),
            revision_id,
            runtime_service_account: "gtc-local-runtime@proj.iam.gserviceaccount.com".to_string(),
            traffic,
            scaling: ScalingSpec {
                cpu: "1".to_string(),
                memory: "512Mi".to_string(),
                min_instances: 0,
                max_instances: 1,
                concurrency: 80,
            },
            access_mode: AccessMode::Public,
            session_affinity: true,
            secrets: Vec::new(),
            env: Vec::new(),
        }
    }

    #[tokio::test]
    async fn unconfigured_target_fails_every_verb() {
        let t = UnconfiguredCloudRunTarget;
        assert!(matches!(
            t.get_service(&service_ref(dep(1))).await,
            Err(CloudRunTargetError::Unconfigured)
        ));
        assert!(matches!(
            t.upsert_service(&spec(dep(1), rev(1), vec![]), None).await,
            Err(CloudRunTargetError::Unconfigured)
        ));
        assert!(matches!(
            t.upsert_secret("s", b"x").await,
            Err(CloudRunTargetError::Unconfigured)
        ));
    }

    #[tokio::test]
    async fn upsert_creates_then_reads_back_with_etag() {
        let t = InMemoryCloudRun::default();
        let d = dep(1);
        assert!(t.get_service(&service_ref(d)).await.unwrap().is_none());

        let created = t
            .upsert_service(
                &spec(
                    d,
                    rev(1),
                    vec![TrafficTarget {
                        revision_id: rev(1),
                        percent: 100,
                    }],
                ),
                None,
            )
            .await
            .unwrap();
        assert!(created.ready);
        assert_eq!(
            created.traffic,
            vec![TrafficTarget {
                revision_id: rev(1),
                percent: 100
            }]
        );

        let read = t.get_service(&service_ref(d)).await.unwrap().unwrap();
        assert_eq!(read.etag, created.etag);
        assert!(read.url.is_some());
    }

    #[tokio::test]
    async fn upsert_with_stale_etag_is_precondition_failed() {
        let t = InMemoryCloudRun::default();
        let d = dep(1);
        t.upsert_service(
            &spec(
                d,
                rev(1),
                vec![TrafficTarget {
                    revision_id: rev(1),
                    percent: 100,
                }],
            ),
            None,
        )
        .await
        .unwrap();
        // A create-over-existing (etag None) is rejected...
        assert!(matches!(
            t.upsert_service(&spec(d, rev(2), vec![]), None).await,
            Err(CloudRunTargetError::PreconditionFailed)
        ));
        // ...and so is an update with a stale etag.
        assert!(matches!(
            t.upsert_service(&spec(d, rev(2), vec![]), Some("etag-999"))
                .await,
            Err(CloudRunTargetError::PreconditionFailed)
        ));
    }

    #[tokio::test]
    async fn set_traffic_requires_matching_etag() {
        let t = InMemoryCloudRun::default();
        let d = dep(1);
        let status = t
            .upsert_service(
                &spec(
                    d,
                    rev(1),
                    vec![TrafficTarget {
                        revision_id: rev(1),
                        percent: 100,
                    }],
                ),
                None,
            )
            .await
            .unwrap();
        let new_traffic = vec![
            TrafficTarget {
                revision_id: rev(1),
                percent: 50,
            },
            TrafficTarget {
                revision_id: rev(2),
                percent: 50,
            },
        ];
        assert!(matches!(
            t.set_traffic(&service_ref(d), &new_traffic, "etag-stale")
                .await,
            Err(CloudRunTargetError::PreconditionFailed)
        ));
        let updated = t
            .set_traffic(&service_ref(d), &new_traffic, &status.etag)
            .await
            .unwrap();
        assert_eq!(updated.traffic, new_traffic);
        assert_ne!(updated.etag, status.etag, "etag rotates on every mutation");
    }

    #[tokio::test]
    async fn upsert_secret_returns_incrementing_versions() {
        let t = InMemoryCloudRun::default();
        let v1 = t
            .upsert_secret("gtc-local-environment", b"one")
            .await
            .unwrap();
        let v2 = t
            .upsert_secret("gtc-local-environment", b"two")
            .await
            .unwrap();
        assert_eq!(v1.version, "1");
        assert_eq!(v2.version, "2", "each upsert adds a new immutable version");
        assert_eq!(t.secrets()["gtc-local-environment"].0, b"two");
    }

    #[tokio::test]
    async fn grant_secret_accessor_is_idempotent_and_delete_removes_secret() {
        let t = InMemoryCloudRun::default();
        t.upsert_secret("gtc-local-environment", b"cfg")
            .await
            .unwrap();
        let sa = "gtc-local-runtime@proj.iam.gserviceaccount.com";
        t.grant_secret_accessor("gtc-local-environment", sa)
            .await
            .unwrap();
        t.grant_secret_accessor("gtc-local-environment", sa)
            .await
            .unwrap();
        assert_eq!(
            t.secret_accessors_for("gtc-local-environment"),
            Some(vec![sa.to_string()]),
            "re-grant adds the member once"
        );

        t.delete_secret("gtc-local-environment").await.unwrap();
        assert!(!t.secrets().contains_key("gtc-local-environment"));
        assert_eq!(t.secret_accessors_for("gtc-local-environment"), None);
        // Idempotent against an already-gone secret.
        t.delete_secret("gtc-local-environment").await.unwrap();
    }

    #[tokio::test]
    async fn set_invoker_policy_and_delete_service_are_recorded() {
        let t = InMemoryCloudRun::default();
        let d = dep(1);
        t.upsert_service(
            &spec(
                d,
                rev(1),
                vec![TrafficTarget {
                    revision_id: rev(1),
                    percent: 100,
                }],
            ),
            None,
        )
        .await
        .unwrap();
        t.set_invoker_policy(&service_ref(d), AccessMode::Public)
            .await
            .unwrap();
        assert_eq!(t.invoker_policy_for(d), Some(AccessMode::Public));

        t.delete_service(&service_ref(d)).await.unwrap();
        assert!(t.get_service(&service_ref(d)).await.unwrap().is_none());
        assert!(t.revisions().is_empty());
        // Deleting an absent service is idempotent.
        t.delete_service(&service_ref(d)).await.unwrap();
    }
}
