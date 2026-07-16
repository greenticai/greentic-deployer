//! [`Deployer`] impl for the GCP Cloud Run env-pack.
//!
//! Drives the Cloud Run revision lifecycle through the
//! [`CloudRunTarget`](super::deploy_target) seam, mirroring the AWS-ECS
//! [`deployer`](crate::env_packs::aws::deployer) structure but against Cloud
//! Run's single-resource + `etag` model:
//!
//! - **`warm`** reads the live Service (for its `etag`), then upserts the new
//!   revision at 0% traffic when the Service already exists, or creates the
//!   Service with 100% pinned to the *named* first revision when it does not
//!   (plan D4), and waits for the revision to report `Ready`.
//! - **`apply_traffic_split`** enforces the shared `sum == 10000 bps`
//!   invariant, then rejects any weight that is not a whole multiple of 100 bps
//!   (Cloud Run's `percent` is an integer 0..=100 and cannot represent basis
//!   points faithfully — plan D1), converts the rest to integer percent, and
//!   sets the Service traffic under `etag` optimistic concurrency.
//! - **`stage`/`drain`** are guarded no-ops; **`archive`** is an idempotent
//!   revision delete.
//!
//! Pure-spec preconditions (`require_revision`, `enforce_split_invariants`, the
//! bps-granularity check) run BEFORE any provider call. The bps-granularity
//! rejection surfaces as [`DeployerError::Provider`] — the same channel the
//! AWS impl uses for its pre-provider `params_from_answers` failures; the typed
//! `InvalidSplit` variant stays reserved for the shared `sum != 10000`
//! invariant it documents.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, Revision, RevisionId, TrafficSplitEntry};
use serde_json::Value;

use crate::cli::secrets::DEV_STORE_RELATIVE;
use crate::env_packs::deployer::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome, enforce_split_invariants, require_revision,
};

use super::GcpCloudRunDeployerHandler;
use super::deploy_target::{
    AccessMode, CloudRunTargetError, RevisionRef, ScalingSpec, SecretMount, SecretMountItem,
    ServiceRef, ServiceSpec, TrafficTarget,
};

/// Default runtime image (plan D2/D3): the public GHCR distroless image Cloud
/// Run pulls directly. `:develop` matches this lane; digest-pinning is
/// recommended in the answers to defeat the ≤1h tag cache.
const DEFAULT_RUNTIME_IMAGE: &str = "ghcr.io/greenticai/greentic-start-distroless";
const DEFAULT_RUNTIME_IMAGE_TAG: &str = "develop";

/// Warm-readiness poll deadline (plan D4). Overridable via the env var so a
/// slow first cold-start image pull does not trip a fixed budget.
const WARM_READY_TIMEOUT: Duration = Duration::from_secs(300);
const WARM_READY_TIMEOUT_ENV: &str = "GREENTIC_GCP_WARM_READY_TIMEOUT_SECS";
const WARM_READY_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Bounded retries for an `etag` optimistic-concurrency conflict (plan D4: on a
/// precondition failure the adapter re-reads and recomputes rather than
/// replaying stale state). A concurrent warm/traffic mutation should resolve
/// well within this budget; exceeding it is surfaced as a provider error.
const MAX_ETAG_RETRIES: u32 = 5;

fn warm_ready_timeout() -> Duration {
    std::env::var(WARM_READY_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(WARM_READY_TIMEOUT)
}

/// Operator-facing knobs the Cloud Run deployer reads from the binding's wizard
/// answers (`answers_ref`, flat JSON keyed by question id). `None` answers use
/// the sandbox defaults from [`GcpCloudRunParams::for_env`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpCloudRunParams {
    pub project: String,
    pub region: String,
    pub access_mode: AccessMode,
    /// Optional Artifact Registry *remote repository* proxying ghcr.io for the
    /// higher-availability case (plan D3). Empty = deploy the public GHCR image
    /// directly (the free-when-idle default).
    pub ar_repo: Option<String>,
    pub runtime_image_tag: String,
    /// When set, the image is pinned by digest (recommended — plan D3).
    pub runtime_image_digest: Option<String>,
    pub service_account: Option<String>,
    pub secret_prefix: String,
    pub cpu: String,
    pub memory: String,
    pub max_instances: u32,
    pub min_instances: u32,
    pub concurrency: u32,
}

impl GcpCloudRunParams {
    /// Sandbox defaults for an env with no (or partial) wizard answers. Project
    /// and region get placeholders so the conformance bench + local dev run
    /// without answers; the real `op env up` path validates they are set.
    pub fn for_env(env: &Environment) -> Self {
        let env_id = env.environment_id.as_str();
        Self {
            project: format!("greentic-{env_id}"),
            region: env
                .host_config
                .region
                .clone()
                .unwrap_or_else(|| "us-central1".to_string()),
            access_mode: AccessMode::Public,
            ar_repo: None,
            runtime_image_tag: DEFAULT_RUNTIME_IMAGE_TAG.to_string(),
            runtime_image_digest: None,
            service_account: None,
            secret_prefix: format!("gtc-{env_id}"),
            cpu: "1".to_string(),
            memory: "512Mi".to_string(),
            max_instances: 1,
            min_instances: 0,
            concurrency: 80,
        }
    }

    /// Parse the binding's wizard answers over the sandbox defaults. Unknown
    /// keys are rejected (deny-by-default, per the AWS precedent).
    pub fn from_answers(
        env: &Environment,
        answers: Option<&Value>,
    ) -> Result<Self, GcpCloudRunParamsError> {
        let mut params = Self::for_env(env);
        let Some(answers) = answers else {
            return Ok(params);
        };
        let obj = answers
            .as_object()
            .ok_or(GcpCloudRunParamsError::NotAnObject)?;
        for (key, value) in obj {
            match key.as_str() {
                "project" => params.project = answer_string(key, value)?,
                "region" => params.region = answer_string(key, value)?,
                "access_mode" => params.access_mode = parse_access_mode(key, value)?,
                "ar_repo" => params.ar_repo = optional_string(key, value)?,
                "runtime_image_tag" => params.runtime_image_tag = answer_string(key, value)?,
                "runtime_image_digest" => {
                    params.runtime_image_digest = optional_string(key, value)?
                }
                "service_account" => params.service_account = optional_string(key, value)?,
                "secret_prefix" => params.secret_prefix = answer_string(key, value)?,
                "cpu" => params.cpu = answer_string(key, value)?,
                "memory" => params.memory = answer_string(key, value)?,
                "max_instances" => params.max_instances = parse_u32(key, value)?,
                "min_instances" => params.min_instances = parse_u32(key, value)?,
                "concurrency" => params.concurrency = parse_u32(key, value)?,
                other => return Err(GcpCloudRunParamsError::UnknownKey(other.to_string())),
            }
        }
        Ok(params)
    }

    /// The single runtime image ref all revisions run (plan D2). Digest-pinned
    /// when supplied; otherwise tag-based. Routed through the Artifact Registry
    /// remote repo when `ar_repo` is set, else the direct public GHCR ref
    /// (plan D3).
    pub fn image_ref(&self) -> String {
        let base = match &self.ar_repo {
            Some(repo) => format!(
                "{region}-docker.pkg.dev/{project}/{repo}/greenticai/greentic-start-distroless",
                region = self.region,
                project = self.project,
            ),
            None => DEFAULT_RUNTIME_IMAGE.to_string(),
        };
        match &self.runtime_image_digest {
            Some(digest) => format!("{base}@{digest}"),
            None => format!("{base}:{tag}", tag = self.runtime_image_tag),
        }
    }

    fn scaling(&self) -> ScalingSpec {
        ScalingSpec {
            cpu: self.cpu.clone(),
            memory: self.memory.clone(),
            min_instances: self.min_instances,
            max_instances: self.max_instances,
            concurrency: self.concurrency,
        }
    }

    /// The least-privilege runtime service account the revision runs as: the
    /// `service_account` answer when set, otherwise the default the bootstrap
    /// Terraform provisions (`gtc-{env}-runtime@{project}.iam.gserviceaccount.com`).
    /// Never empty — a revision must never fall back to the Compute Engine
    /// default identity.
    pub fn runtime_service_account(&self, env_id: &str) -> String {
        self.service_account
            .clone()
            .unwrap_or_else(|| default_runtime_service_account(env_id, &self.project))
    }
}

/// The bootstrap-provisioned default runtime service-account email for an env in
/// a project. The single source of the formula: both the deployer (threading the
/// identity onto the revision) and the credentials validator (probing
/// `iam.serviceAccounts.actAs` against this resource, when no `service_account`
/// override is set) must agree on it, or the preflight validates the wrong SA.
pub(crate) fn default_runtime_service_account(env_id: &str, project: &str) -> String {
    format!("gtc-{env_id}-runtime@{project}.iam.gserviceaccount.com")
}

/// Deterministic Cloud Run Service name for a deployment: `gtc-svc-{ulid}`
/// (lowercased; RFC1123 DNS-label safe). Plan D1.
pub fn service_name(deployment_id: DeploymentId) -> String {
    format!("gtc-svc-{}", deployment_id.0.to_string().to_lowercase())
}

/// Container directory the env-store seed secrets are volume-mounted under
/// (plan D6). Exported to the runtime as `GREENTIC_SEED_DIR` (see
/// [`runtime_boot_env`]) so greentic-start's boot-copy reads this tree into the
/// writable env store.
const SEED_MOUNT_DIR: &str = "/seed";
/// The `environment.json` seed file name under [`SEED_MOUNT_DIR`].
const ENVIRONMENT_SEED_FILE: &str = "environment.json";
/// Writable env-store root for the runtime container, exported as `HOME`. Cloud
/// Run's root filesystem is read-only except `/tmp` (in-memory, world-writable)
/// on the gen1 execution environment, so `LocalFsStore` (`$HOME/.greentic/
/// environments`) must root there to be creatable under the distroless nonroot
/// uid. The seed is re-copied on every cold start, matching this ephemeral root.
const RUNTIME_HOME: &str = "/tmp";

/// The Secret Manager secret name carrying an env's `environment.json` seed
/// (plan D6): `<secret_prefix>-environment` (default `gtc-{env}-environment`).
/// Shared so `op env destroy` teardown deletes exactly what `warm` staged.
pub fn environment_secret_name(secret_prefix: &str) -> String {
    format!("{secret_prefix}-environment")
}

/// Literal boot env vars projected onto every Cloud Run revision (plan D6
/// activation + runtime identity). `GREENTIC_SEED_DIR` triggers greentic-start's
/// boot-copy of the mounted `environment.json` into the writable store rooted at
/// `HOME`; `GREENTIC_ENV` selects the env dir the seed lands in (greentic-start's
/// `resolve_env` reads it, and it must agree with where the store opens);
/// `GREENTIC_GATEWAY_LISTEN_ADDR=0.0.0.0` makes the gateway reachable (greentic-
/// start otherwise binds loopback and Cloud Run's health check never passes);
/// and the revision-identity vars mirror the k8s pack-pull contract so the
/// runtime knows which revision to serve. The bundle *source* URI is read from
/// the seeded `environment.json`, not an env var, so none is set here.
fn runtime_boot_env(env: &Environment, revision: &Revision) -> Vec<(String, String)> {
    let env_id = env.environment_id.as_str();
    vec![
        ("GREENTIC_ENV".to_string(), env_id.to_string()),
        ("GREENTIC_ENV_ID".to_string(), env_id.to_string()),
        ("GREENTIC_SEED_DIR".to_string(), SEED_MOUNT_DIR.to_string()),
        ("HOME".to_string(), RUNTIME_HOME.to_string()),
        (
            "GREENTIC_GATEWAY_LISTEN_ADDR".to_string(),
            "0.0.0.0".to_string(),
        ),
        (
            "GREENTIC_REVISION_ID".to_string(),
            revision.revision_id.0.to_string(),
        ),
        (
            "GREENTIC_DEPLOYMENT_ID".to_string(),
            revision.deployment_id.0.to_string(),
        ),
        (
            "GREENTIC_BUNDLE_ID".to_string(),
            revision.bundle_id.as_str().to_string(),
        ),
        (
            "GREENTIC_BUNDLE_DIGEST".to_string(),
            revision.bundle_digest.clone(),
        ),
    ]
}

/// Deterministic Cloud Run revision name: `gtc-svc-{dep}-{rev}` (61 chars ≤ the
/// 63-char limit; Cloud Run requires the service-name prefix). Plan D1.
pub fn revision_name(deployment_id: DeploymentId, revision_id: RevisionId) -> String {
    format!(
        "gtc-svc-{}-{}",
        deployment_id.0.to_string().to_lowercase(),
        revision_id.0.to_string().to_lowercase()
    )
}

/// Errors parsing the binding's wizard answers.
#[derive(Debug, thiserror::Error)]
pub enum GcpCloudRunParamsError {
    #[error("answers must be a JSON object")]
    NotAnObject,
    #[error("answer `{0}` must be a string")]
    NotAString(String),
    #[error("unknown answer key `{0}`")]
    UnknownKey(String),
    #[error("answer `{key}` is invalid: {detail}")]
    Invalid { key: String, detail: String },
}

fn answer_string(key: &str, value: &Value) -> Result<String, GcpCloudRunParamsError> {
    value
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| GcpCloudRunParamsError::NotAString(key.to_string()))
}

fn optional_string(key: &str, value: &Value) -> Result<Option<String>, GcpCloudRunParamsError> {
    let s = answer_string(key, value)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    })
}

fn parse_u32(key: &str, value: &Value) -> Result<u32, GcpCloudRunParamsError> {
    // Accept both a JSON number and a numeric string (qa-spec answers are
    // flat strings; a caller-built JSON may use a number).
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).map_err(|_| GcpCloudRunParamsError::Invalid {
            key: key.to_string(),
            detail: format!("{n} is out of range for a u32"),
        });
    }
    let s = answer_string(key, value)?;
    s.trim()
        .parse::<u32>()
        .map_err(|e| GcpCloudRunParamsError::Invalid {
            key: key.to_string(),
            detail: format!("`{s}` is not a non-negative integer: {e}"),
        })
}

fn parse_access_mode(key: &str, value: &Value) -> Result<AccessMode, GcpCloudRunParamsError> {
    match answer_string(key, value)?.as_str() {
        "public" => Ok(AccessMode::Public),
        "authenticated" => Ok(AccessMode::Authenticated),
        other => Err(GcpCloudRunParamsError::Invalid {
            key: key.to_string(),
            detail: format!("`{other}` is not one of `public` | `authenticated`"),
        }),
    }
}

/// Wrap a [`CloudRunTargetError`] as a [`DeployerError::Provider`].
fn provider(err: CloudRunTargetError) -> DeployerError {
    DeployerError::Provider(err.to_string())
}

/// Wrap answer-parse failures as a pre-provider [`DeployerError::Provider`]
/// (mirrors the AWS `params_from_answers` precedent).
fn params_from_answers(
    env: &Environment,
    answers: Option<&Value>,
) -> Result<GcpCloudRunParams, DeployerError> {
    GcpCloudRunParams::from_answers(env, answers)
        .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))
}

/// Convert a spec-side (basis-point) split into Cloud Run integer-percent
/// targets. Rejects any weight that is not a whole multiple of 100 bps — Cloud
/// Run cannot represent sub-1% or non-round-percent weights (plan D1). The
/// caller has already enforced `sum == 10000`, so the resulting percents sum to
/// exactly 100.
fn split_to_traffic_targets(
    entries: &[TrafficSplitEntry],
) -> Result<Vec<TrafficTarget>, DeployerError> {
    let mut targets = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.weight_bps % 100 != 0 {
            return Err(DeployerError::Provider(format!(
                "Cloud Run cannot faithfully represent traffic weight {bps} bps for revision \
                 `{rev}`; weights must be whole multiples of 100 bps (1%)",
                bps = entry.weight_bps,
                rev = entry.revision_id,
            )));
        }
        targets.push(TrafficTarget {
            revision_id: entry.revision_id,
            percent: entry.weight_bps / 100,
        });
    }
    Ok(targets)
}

fn find_revision(env: &Environment, revision_id: RevisionId) -> Option<&Revision> {
    env.revisions.iter().find(|r| r.revision_id == revision_id)
}

async fn wait_for_revision_ready(
    target: &dyn super::deploy_target::CloudRunTarget,
    revision: &RevisionRef,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), DeployerError> {
    let deadline = Instant::now() + timeout;
    loop {
        match target.get_revision_status(revision).await {
            Ok(status) if status.ready => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(provider(e)),
        }
        if Instant::now() >= deadline {
            return Err(DeployerError::Provider(format!(
                "Cloud Run revision `{}` did not become ready within {}s",
                revision.revision_id,
                timeout.as_secs()
            )));
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[async_trait]
impl Deployer for GcpCloudRunDeployerHandler {
    async fn stage_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<StageOutcome, DeployerError> {
        // No provider work: bundle + secret staging happens on the `op env up`
        // path (follow-up PR). Cloud Run OCI-pulls the bundle at boot.
        require_revision(env, revision_id)?;
        Ok(StageOutcome::default())
    }

    async fn warm_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<WarmOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = find_revision(env, revision_id).expect("require_revision passed");
        let deployment_id = revision.deployment_id;
        let params = params_from_answers(env, answers)?;

        let service_ref = ServiceRef {
            deployment_id,
            project: params.project.clone(),
            region: params.region.clone(),
        };
        let runtime_service_account = params.runtime_service_account(env.environment_id.as_str());

        // Stage the env-store seed (plan D6): upload environment.json to a
        // version-pinned Secret Manager secret and grant the runtime SA read
        // access, then mount that exact version read-only. The grant is
        // load-bearing — Cloud Run rejects a revision whose SA cannot read a
        // mounted secret version. Staged ONCE, before the etag retry loop, so a
        // precondition retry does not add a redundant secret version. The
        // revision's boot env (`runtime_boot_env`) sets `GREENTIC_SEED_DIR`, so
        // greentic-start copies this mount into its writable store at boot. When
        // the env carries dev-store material, the CLI injected the raw bytes and
        // they are staged as a SECOND version of the same secret below.
        let environment_json = serde_json::to_vec(env).map_err(|e| {
            DeployerError::Provider(format!(
                "serializing environment.json for seed staging: {e}"
            ))
        })?;
        let secret_name = environment_secret_name(&params.secret_prefix);
        let env_version = self
            .target
            .upsert_secret(&secret_name, &environment_json)
            .await
            .map_err(provider)?;
        let mut secret_items = vec![SecretMountItem {
            version: env_version.version,
            rel_path: ENVIRONMENT_SEED_FILE.to_string(),
        }];
        // Stage the operator's encrypted dev-store (`.dev.secrets.env`) as a
        // second version of the SAME secret, projected at a subdirectory item
        // path under the one `/seed` volume — Cloud Run forbids nested mounts, so
        // the two seed files cannot be two volumes. Absent for envs with no
        // `Secrets`-slot pack (the CLI passes `None`).
        if let Some(dev_bytes) = &self.dev_secrets {
            let dev_version = self
                .target
                .upsert_secret(&secret_name, dev_bytes)
                .await
                .map_err(provider)?;
            secret_items.push(SecretMountItem {
                version: dev_version.version,
                // The seed tree mirrors the on-disk store, so the dev-store's
                // store-relative path is also its path under `/seed`, projected
                // as a subdirectory item (Cloud Run forbids a nested mount).
                rel_path: DEV_STORE_RELATIVE.to_string(),
            });
        }
        // Grant the runtime SA read on the secret (covers every version) —
        // load-bearing: Cloud Run rejects a revision whose SA cannot read a
        // mounted version. Idempotent, so a re-warm is a no-op.
        self.target
            .grant_secret_accessor(&secret_name, &runtime_service_account)
            .await
            .map_err(provider)?;
        let secret_mounts = vec![SecretMount {
            mount_dir: SEED_MOUNT_DIR.to_string(),
            secret_name,
            items: secret_items,
        }];
        // Revision-scoped, deterministic — built once and reused across etag
        // retries so a re-upsert never renders a different container.
        let boot_env = runtime_boot_env(env, revision);

        // Read-modify-write under etag optimistic concurrency with bounded
        // retries on a precondition conflict (plan D4): re-read, recompute
        // traffic from the fresh state, and retry rather than replaying a stale
        // etag. Traffic is pinned to NAMED revisions in the same upsert — first
        // create is 100% to the named first revision (never LATEST, never a
        // 0%-only array); an update keeps the existing distribution and adds
        // this revision at 0% if it is new, so warm never moves traffic.
        let mut attempt = 0;
        // The Service's `*.run.app` URL rides back on the upsert response (it is
        // assigned at Service-create time and is immutable after), so take it as
        // the loop's break value — the caller needs no extra `get_service`.
        let endpoint_url = loop {
            let existing = self
                .target
                .get_service(&service_ref)
                .await
                .map_err(provider)?;
            let (traffic, etag) = match &existing {
                None => (
                    vec![TrafficTarget {
                        revision_id,
                        percent: 100,
                    }],
                    None,
                ),
                Some(status) => {
                    let mut traffic = status.traffic.clone();
                    if !traffic.iter().any(|t| t.revision_id == revision_id) {
                        traffic.push(TrafficTarget {
                            revision_id,
                            percent: 0,
                        });
                    }
                    (traffic, Some(status.etag.clone()))
                }
            };
            let spec = ServiceSpec {
                deployment_id,
                project: params.project.clone(),
                region: params.region.clone(),
                image: params.image_ref(),
                revision_id,
                runtime_service_account: runtime_service_account.clone(),
                traffic,
                scaling: params.scaling(),
                access_mode: params.access_mode,
                session_affinity: true,
                secrets: secret_mounts.clone(),
                env: boot_env.clone(),
            };
            match self.target.upsert_service(&spec, etag.as_deref()).await {
                Ok(status) => break status.url,
                Err(CloudRunTargetError::PreconditionFailed) => {
                    attempt += 1;
                    if attempt > MAX_ETAG_RETRIES {
                        return Err(DeployerError::Provider(format!(
                            "Cloud Run service for deployment `{deployment_id}` kept losing the \
                             etag race after {MAX_ETAG_RETRIES} retries"
                        )));
                    }
                }
                Err(e) => return Err(provider(e)),
            }
        };

        let revision_ref = RevisionRef {
            deployment_id,
            revision_id,
            project: params.project,
            region: params.region,
        };
        wait_for_revision_ready(
            self.target.as_ref(),
            &revision_ref,
            warm_ready_timeout(),
            WARM_READY_POLL_INTERVAL,
        )
        .await?;

        // Apply the invoker IAM binding for the requested access mode (plan D12)
        // as the FINAL commit step — only after the new revision is proven ready.
        // The invoker policy is service-WIDE (it governs every revision at once),
        // so mutating it before readiness would change access on the currently-
        // serving revision even when this deploy then fails or times out: a
        // `public`→`authenticated` flip is an outage, the inverse exposes prod on
        // a failed deploy. Deferring it past the readiness wait means a failed
        // revision never touches live access. The Service upsert alone does NOT
        // set the policy (it is a separate IAM resource, so a `Public` service's
        // `run.app` URL 403s without this), and re-applying the same binding on a
        // second-revision warm is a harmless idempotent no-op.
        self.target
            .set_invoker_policy(&service_ref, params.access_mode)
            .await
            .map_err(provider)?;
        Ok(WarmOutcome { endpoint_url })
    }

    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<DrainOutcome, DeployerError> {
        // Traffic shifts via `apply_traffic_split`; Cloud Run scales the
        // drained revision to zero on its own once it stops receiving traffic.
        require_revision(env, revision_id)?;
        Ok(DrainOutcome::default())
    }

    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ArchiveOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = find_revision(env, revision_id).expect("require_revision passed");
        let deployment_id = revision.deployment_id;
        let params = params_from_answers(env, answers)?;
        self.target
            .delete_revision(&RevisionRef {
                deployment_id,
                revision_id,
                project: params.project,
                region: params.region,
            })
            .await
            .map_err(provider)?;
        Ok(ArchiveOutcome::default())
    }

    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
        answers: Option<&Value>,
    ) -> Result<TrafficSplitOutcome, DeployerError> {
        // Pure-spec precondition first: sum == 10000 bps + the CR-specific
        // whole-multiple-of-100-bps rejection, both BEFORE any provider call.
        let outcome = enforce_split_invariants(env, deployment_id)?;
        let targets = split_to_traffic_targets(&outcome.applied_entries)?;
        let params = params_from_answers(env, answers)?;

        let service_ref = ServiceRef {
            deployment_id,
            project: params.project,
            region: params.region,
        };
        // When the Service exists, set traffic under its live etag (read-modify-
        // write) with bounded retries on an etag conflict (plan D4). When it
        // does not (no revision warmed yet), the recorded split is authoritative
        // and projects at the next warm — mirroring the AWS impl's "no provider
        // mirror configured" no-op so the spec stays the source of truth. In the
        // real `op env up` flow the deployment is always warmed before its split
        // is applied, so the Service exists whenever enforcement matters.
        let mut attempt = 0;
        loop {
            let Some(status) = self
                .target
                .get_service(&service_ref)
                .await
                .map_err(provider)?
            else {
                break;
            };
            match self
                .target
                .set_traffic(&service_ref, &targets, &status.etag)
                .await
            {
                Ok(_) => break,
                Err(CloudRunTargetError::PreconditionFailed) => {
                    attempt += 1;
                    if attempt > MAX_ETAG_RETRIES {
                        return Err(DeployerError::Provider(format!(
                            "Cloud Run traffic split for deployment `{deployment_id}` kept losing \
                             the etag race after {MAX_ETAG_RETRIES} retries"
                        )));
                    }
                }
                Err(e) => return Err(provider(e)),
            }
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use greentic_deploy_spec::TrafficSplitEntry;

    use async_trait::async_trait;

    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::deployer::run_conformance;
    use crate::env_packs::gcp_cloudrun::deploy_target::{
        CloudRunTarget, InMemoryCloudRun, RevisionStatus, SecretVersion, ServiceStatus,
    };

    fn handler_with_fake() -> (GcpCloudRunDeployerHandler, Arc<InMemoryCloudRun>) {
        let target = Arc::new(InMemoryCloudRun::default());
        (
            GcpCloudRunDeployerHandler::with_target(target.clone()),
            target,
        )
    }

    /// Target that injects a fixed number of etag conflicts before delegating to
    /// a real in-memory backend — proves the deployer's bounded read-modify-write
    /// retry (plan D4). Only `upsert_service` / `set_traffic` are intercepted;
    /// every other verb passes straight through.
    #[derive(Debug)]
    struct ConflictInjector {
        inner: InMemoryCloudRun,
        upsert_conflicts: std::sync::Mutex<u32>,
        set_traffic_conflicts: std::sync::Mutex<u32>,
    }

    impl ConflictInjector {
        fn new(upsert_conflicts: u32, set_traffic_conflicts: u32) -> Self {
            Self {
                inner: InMemoryCloudRun::default(),
                upsert_conflicts: std::sync::Mutex::new(upsert_conflicts),
                set_traffic_conflicts: std::sync::Mutex::new(set_traffic_conflicts),
            }
        }

        fn take_conflict(slot: &std::sync::Mutex<u32>) -> bool {
            let mut n = slot.lock().unwrap();
            if *n > 0 {
                *n -= 1;
                true
            } else {
                false
            }
        }
    }

    #[async_trait]
    impl CloudRunTarget for ConflictInjector {
        async fn get_service(
            &self,
            service: &ServiceRef,
        ) -> Result<Option<ServiceStatus>, CloudRunTargetError> {
            self.inner.get_service(service).await
        }
        async fn upsert_service(
            &self,
            spec: &ServiceSpec,
            etag: Option<&str>,
        ) -> Result<ServiceStatus, CloudRunTargetError> {
            if Self::take_conflict(&self.upsert_conflicts) {
                return Err(CloudRunTargetError::PreconditionFailed);
            }
            self.inner.upsert_service(spec, etag).await
        }
        async fn get_revision_status(
            &self,
            revision: &RevisionRef,
        ) -> Result<RevisionStatus, CloudRunTargetError> {
            self.inner.get_revision_status(revision).await
        }
        async fn set_traffic(
            &self,
            service: &ServiceRef,
            traffic: &[TrafficTarget],
            etag: &str,
        ) -> Result<ServiceStatus, CloudRunTargetError> {
            if Self::take_conflict(&self.set_traffic_conflicts) {
                return Err(CloudRunTargetError::PreconditionFailed);
            }
            self.inner.set_traffic(service, traffic, etag).await
        }
        async fn set_invoker_policy(
            &self,
            service: &ServiceRef,
            access_mode: AccessMode,
        ) -> Result<(), CloudRunTargetError> {
            self.inner.set_invoker_policy(service, access_mode).await
        }
        async fn delete_revision(&self, revision: &RevisionRef) -> Result<(), CloudRunTargetError> {
            self.inner.delete_revision(revision).await
        }
        async fn delete_service(&self, service: &ServiceRef) -> Result<(), CloudRunTargetError> {
            self.inner.delete_service(service).await
        }
        async fn get_service_url(
            &self,
            service: &ServiceRef,
        ) -> Result<Option<String>, CloudRunTargetError> {
            self.inner.get_service_url(service).await
        }
        async fn upsert_secret(
            &self,
            name: &str,
            payload: &[u8],
        ) -> Result<SecretVersion, CloudRunTargetError> {
            self.inner.upsert_secret(name, payload).await
        }
        async fn grant_secret_accessor(
            &self,
            secret_name: &str,
            service_account: &str,
        ) -> Result<(), CloudRunTargetError> {
            self.inner
                .grant_secret_accessor(secret_name, service_account)
                .await
        }
        async fn delete_secret(&self, name: &str) -> Result<(), CloudRunTargetError> {
            self.inner.delete_secret(name).await
        }
    }

    #[tokio::test]
    async fn gcp_cloudrun_deployer_passes_conformance() {
        let (handler, _target) = handler_with_fake();
        run_conformance(&handler)
            .await
            .expect("GCP Cloud Run deployer satisfies the Phase D conformance contract");
    }

    #[tokio::test]
    async fn warm_first_create_pins_100_percent_to_named_revision() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let dep_a = env.bundles[0].deployment_id;

        handler.warm_revision(&env, r_warm, None).await.unwrap();

        let traffic = target.traffic_for(dep_a).expect("service created");
        assert_eq!(
            traffic,
            vec![TrafficTarget {
                revision_id: r_warm,
                percent: 100
            }],
            "first create pins 100% to the named first revision (never LATEST)"
        );
    }

    #[tokio::test]
    async fn warm_existing_service_adds_new_revision_at_zero() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let r_drain = env.revisions[1].revision_id; // same deployment as r_warm
        let dep_a = env.bundles[0].deployment_id;

        handler.warm_revision(&env, r_warm, None).await.unwrap();
        handler.warm_revision(&env, r_drain, None).await.unwrap();

        let traffic = target.traffic_for(dep_a).unwrap();
        assert_eq!(
            traffic,
            vec![
                TrafficTarget {
                    revision_id: r_warm,
                    percent: 100
                },
                TrafficTarget {
                    revision_id: r_drain,
                    percent: 0
                },
            ],
            "warming a second revision adds it at 0% without moving traffic"
        );
    }

    #[tokio::test]
    async fn apply_traffic_split_converts_bps_to_integer_percent() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let r_drain = env.revisions[1].revision_id;
        let dep_a = env.bundles[0].deployment_id;

        // Service must exist before a split can be projected onto it.
        handler.warm_revision(&env, r_warm, None).await.unwrap();
        handler
            .apply_traffic_split(&env, dep_a, None)
            .await
            .unwrap();

        let traffic = target.traffic_for(dep_a).unwrap();
        assert_eq!(
            traffic,
            vec![
                TrafficTarget {
                    revision_id: r_warm,
                    percent: 50
                },
                TrafficTarget {
                    revision_id: r_drain,
                    percent: 50
                },
            ],
            "5000/5000 bps projects to 50/50 integer percent"
        );
    }

    #[tokio::test]
    async fn apply_traffic_split_rejects_non_whole_percent_weights() {
        let (handler, _target) = handler_with_fake();
        let mut env = build_fixture_env();
        let dep_a = env.bundles[0].deployment_id;
        let r_warm = env.revisions[0].revision_id;
        let r_drain = env.revisions[1].revision_id;
        // 3333 + 6667 = 10000 (passes the sum invariant) but neither is a whole
        // multiple of 100 bps, so Cloud Run cannot represent it.
        env.traffic_splits[0].entries = vec![
            TrafficSplitEntry {
                revision_id: r_warm,
                weight_bps: 3333,
            },
            TrafficSplitEntry {
                revision_id: r_drain,
                weight_bps: 6667,
            },
        ];
        let err = handler
            .apply_traffic_split(&env, dep_a, None)
            .await
            .expect_err("non-whole-percent split must be rejected");
        assert!(
            matches!(err, DeployerError::Provider(ref m) if m.contains("multiples of 100 bps")),
            "expected a whole-percent rejection, got {err:?}"
        );
    }

    #[tokio::test]
    async fn apply_traffic_split_noops_when_service_absent() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let dep_b = env.bundles[1].deployment_id; // never warmed

        let outcome = handler
            .apply_traffic_split(&env, dep_b, None)
            .await
            .unwrap();
        assert_eq!(outcome.applied_deployment_id, dep_b);
        assert!(
            target.traffic_for(dep_b).is_none(),
            "no Service is created just to record a split; the spec stays authoritative"
        );
    }

    #[test]
    fn image_ref_defaults_to_direct_ghcr_and_honors_ar_repo_and_digest() {
        let env = build_fixture_env();
        let mut params = GcpCloudRunParams::for_env(&env);
        assert_eq!(
            params.image_ref(),
            "ghcr.io/greenticai/greentic-start-distroless:develop",
            "default is the direct public GHCR ref (free-when-idle)"
        );
        params.runtime_image_digest = Some("sha256:abc".to_string());
        assert_eq!(
            params.image_ref(),
            "ghcr.io/greenticai/greentic-start-distroless@sha256:abc"
        );
        params.runtime_image_digest = None;
        params.ar_repo = Some("gtc-mirror".to_string());
        params.project = "my-proj".to_string();
        params.region = "europe-west1".to_string();
        assert_eq!(
            params.image_ref(),
            "europe-west1-docker.pkg.dev/my-proj/gtc-mirror/greenticai/greentic-start-distroless:develop"
        );
    }

    #[test]
    fn from_answers_rejects_unknown_keys_and_parses_known_ones() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "project": "prod-proj",
            "region": "us-east1",
            "access_mode": "authenticated",
            "max_instances": "3",
            "min_instances": "0",
        });
        let params = GcpCloudRunParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.project, "prod-proj");
        assert_eq!(params.region, "us-east1");
        assert_eq!(params.access_mode, AccessMode::Authenticated);
        assert_eq!(params.max_instances, 3);

        let bad = serde_json::json!({ "nope": "x" });
        assert!(matches!(
            GcpCloudRunParams::from_answers(&env, Some(&bad)),
            Err(GcpCloudRunParamsError::UnknownKey(_))
        ));
    }

    #[test]
    fn service_and_revision_names_are_deterministic_and_within_limits() {
        let env = build_fixture_env();
        let dep = env.bundles[0].deployment_id;
        let rev = env.revisions[0].revision_id;
        let svc = service_name(dep);
        let revn = revision_name(dep, rev);
        assert!(svc.starts_with("gtc-svc-"));
        assert_eq!(svc, svc.to_lowercase(), "service name must be lowercase");
        assert!(revn.starts_with(&format!("{svc}-")));
        assert!(
            revn.len() <= 63,
            "revision name `{revn}` ({}) must fit the 63-char Cloud Run limit",
            revn.len()
        );
    }

    #[tokio::test]
    async fn default_handler_target_is_unconfigured() {
        // The default handler wires the Unconfigured target: a warm must fail
        // honestly rather than silently succeed.
        let handler = GcpCloudRunDeployerHandler::default();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let err = handler
            .warm_revision(&env, r_warm, None)
            .await
            .expect_err("unconfigured target must fail warm");
        assert!(matches!(err, DeployerError::Provider(_)));
    }

    #[tokio::test]
    async fn warm_threads_runtime_service_account_default_then_override() {
        // Default: derived from the env id + project (the SA the bootstrap
        // Terraform provisions), never blank.
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let dep_a = env.bundles[0].deployment_id;
        handler.warm_revision(&env, r_warm, None).await.unwrap();
        let sa = target
            .runtime_service_account_for(dep_a)
            .expect("warm records the runtime SA");
        assert!(
            sa.starts_with("gtc-conformance-runtime@"),
            "default runtime SA is derived from the env, got {sa}"
        );

        // Override: the `service_account` answer wins and is threaded through.
        let (handler2, target2) = handler_with_fake();
        let answers =
            serde_json::json!({ "service_account": "custom-runtime@acme.iam.gserviceaccount.com" });
        handler2
            .warm_revision(&env, r_warm, Some(&answers))
            .await
            .unwrap();
        assert_eq!(
            target2.runtime_service_account_for(dep_a).unwrap(),
            "custom-runtime@acme.iam.gserviceaccount.com"
        );
    }

    #[tokio::test]
    async fn warm_applies_invoker_policy_for_the_requested_access_mode() {
        // F5 (plan D12): a warm must apply the invoker IAM binding, not just the
        // Service upsert — the IAM policy is a separate resource, so without this
        // a Public service's `run.app` URL 403s every request. Default is Public.
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let dep_a = env.bundles[0].deployment_id;
        handler.warm_revision(&env, r_warm, None).await.unwrap();
        assert_eq!(
            target.invoker_policy_for(dep_a),
            Some(AccessMode::Public),
            "warm applies the default Public invoker binding"
        );

        // An `authenticated` answer leaves the service private.
        let (handler2, target2) = handler_with_fake();
        let answers = serde_json::json!({ "access_mode": "authenticated" });
        handler2
            .warm_revision(&env, r_warm, Some(&answers))
            .await
            .unwrap();
        assert_eq!(
            target2.invoker_policy_for(dep_a),
            Some(AccessMode::Authenticated),
            "an authenticated env applies the Authenticated invoker binding"
        );
    }

    #[tokio::test]
    async fn warm_returns_the_service_endpoint_url() {
        // The Service's `*.run.app` URL rides back on the warm outcome (read from
        // the upsert response), so the CLI needs no extra get_service round-trip.
        let (handler, _target) = handler_with_fake();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let dep_a = env.bundles[0].deployment_id;
        let outcome = handler.warm_revision(&env, r_warm, None).await.unwrap();
        let url = outcome
            .endpoint_url
            .expect("warm surfaces the Service's *.run.app URL from the upsert response");
        assert!(
            url.contains(&service_name(dep_a)) && url.ends_with(".run.app"),
            "endpoint URL should be the Service's run.app URL, got {url}"
        );
    }

    #[tokio::test]
    async fn warm_retries_on_etag_conflict_then_succeeds() {
        // Two conflicts, then success — within the retry budget (plan D4).
        let target = Arc::new(ConflictInjector::new(2, 0));
        let handler = GcpCloudRunDeployerHandler::with_target(target.clone());
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let dep_a = env.bundles[0].deployment_id;
        handler
            .warm_revision(&env, r_warm, None)
            .await
            .expect("warm re-reads and retries past etag conflicts");
        assert!(
            target.inner.traffic_for(dep_a).is_some(),
            "the service is created once the retry wins the etag race"
        );
    }

    #[tokio::test]
    async fn warm_stages_environment_secret_and_grants_runtime_sa() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;

        handler.warm_revision(&env, r_warm, None).await.unwrap();

        // environment.json is staged as a version-pinned Secret Manager secret (D6).
        let params = params_from_answers(&env, None).unwrap();
        let secret_name = environment_secret_name(&params.secret_prefix);
        let secrets = target.secrets();
        let (payload, version) = secrets
            .get(&secret_name)
            .expect("warm stages the environment.json seed secret");
        assert_eq!(payload, &serde_json::to_vec(&env).unwrap());
        assert_eq!(*version, 1, "first warm adds version 1");

        // The runtime SA is granted secretAccessor so the mounted version is
        // readable — Cloud Run rejects a revision whose SA cannot read it.
        let sa = params.runtime_service_account(env.environment_id.as_str());
        let accessors = target
            .secret_accessors_for(&secret_name)
            .expect("secretAccessor grant recorded");
        assert!(
            accessors.contains(&sa),
            "runtime SA {sa} must be granted secretAccessor"
        );
    }

    #[test]
    fn runtime_boot_env_activates_seed_and_carries_revision_identity() {
        let env = build_fixture_env();
        let revision = &env.revisions[0];
        let vars = runtime_boot_env(&env, revision);
        let get = |k: &str| {
            vars.iter()
                .find(|(name, _)| name == k)
                .map(|(_, v)| v.as_str())
        };

        // Seed activation + writable store root: the exact contract greentic-
        // start's boot-copy and `resolve_env` read.
        assert_eq!(get("GREENTIC_SEED_DIR"), Some(SEED_MOUNT_DIR));
        assert_eq!(get("HOME"), Some(RUNTIME_HOME));
        assert_eq!(get("GREENTIC_ENV"), Some(env.environment_id.as_str()));
        // Reachable on Cloud Run — greentic-start binds loopback by default.
        assert_eq!(get("GREENTIC_GATEWAY_LISTEN_ADDR"), Some("0.0.0.0"));
        // Revision identity (k8s pack-pull parity).
        assert_eq!(get("GREENTIC_ENV_ID"), Some(env.environment_id.as_str()));
        assert_eq!(
            get("GREENTIC_REVISION_ID"),
            Some(revision.revision_id.0.to_string().as_str())
        );
        assert_eq!(
            get("GREENTIC_DEPLOYMENT_ID"),
            Some(revision.deployment_id.0.to_string().as_str())
        );
        assert_eq!(get("GREENTIC_BUNDLE_ID"), Some(revision.bundle_id.as_str()));
        assert_eq!(
            get("GREENTIC_BUNDLE_DIGEST"),
            Some(revision.bundle_digest.as_str())
        );
        // No bundle-source var — the source URI rides in the seeded environment.json.
        assert!(get("GREENTIC_BUNDLE_SOURCE_URI").is_none());
    }

    #[tokio::test]
    async fn warm_threads_boot_env_onto_the_service() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let revision = &env.revisions[0];
        let r_warm = revision.revision_id;

        handler.warm_revision(&env, r_warm, None).await.unwrap();

        // warm builds boot env once and projects it onto the upserted Service,
        // so the running container actually boots from the staged seed.
        let recorded = target
            .service_env_for(revision.deployment_id)
            .expect("warm upserts the Service with boot env");
        assert_eq!(recorded, runtime_boot_env(&env, revision));
        assert!(
            recorded
                .iter()
                .any(|(k, v)| k == "GREENTIC_SEED_DIR" && v == SEED_MOUNT_DIR),
            "the seed boot-copy is activated"
        );
    }

    #[tokio::test]
    async fn warm_without_dev_secrets_mounts_only_environment_json() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let revision = &env.revisions[0];

        handler
            .warm_revision(&env, revision.revision_id, None)
            .await
            .unwrap();

        let mounts = target
            .service_secrets_for(revision.deployment_id)
            .expect("warm upserts the Service with a seed mount");
        assert_eq!(mounts.len(), 1, "one /seed volume");
        assert_eq!(mounts[0].mount_dir, SEED_MOUNT_DIR);
        assert_eq!(mounts[0].items.len(), 1, "no dev-store → env.json only");
        assert_eq!(mounts[0].items[0].rel_path, ENVIRONMENT_SEED_FILE);
    }

    #[tokio::test]
    async fn warm_stages_dev_store_as_second_version_under_one_seed_volume() {
        let target = Arc::new(InMemoryCloudRun::default());
        let handler = GcpCloudRunDeployerHandler::with_target_and_dev_secrets(
            target.clone(),
            Some(b"ENC-DEV-STORE".to_vec()),
        );
        let env = build_fixture_env();
        let revision = &env.revisions[0];

        handler
            .warm_revision(&env, revision.revision_id, None)
            .await
            .unwrap();

        // Both seed files ride ONE secret's two versions under ONE /seed volume
        // (Cloud Run forbids nested mounts): env.json at the root, dev-store at
        // its on-disk subdirectory path.
        let params = params_from_answers(&env, None).unwrap();
        let secret_name = environment_secret_name(&params.secret_prefix);
        let (_, version_count) = target
            .secrets()
            .get(&secret_name)
            .cloned()
            .expect("seed secret staged");
        assert_eq!(version_count, 2, "env.json v1 + dev-store v2 on one secret");

        let mounts = target
            .service_secrets_for(revision.deployment_id)
            .expect("warm upserts the Service with a seed mount");
        assert_eq!(
            mounts.len(),
            1,
            "one secret → one /seed volume, never nested"
        );
        assert_eq!(mounts[0].mount_dir, SEED_MOUNT_DIR);
        assert_eq!(mounts[0].secret_name, secret_name);
        assert_eq!(mounts[0].items.len(), 2);
        assert_eq!(mounts[0].items[0].rel_path, ENVIRONMENT_SEED_FILE);
        assert_eq!(mounts[0].items[0].version, "1");
        assert_eq!(mounts[0].items[1].rel_path, DEV_STORE_RELATIVE);
        assert_eq!(mounts[0].items[1].version, "2");

        // The runtime SA can read the mounted versions.
        let sa = params.runtime_service_account(env.environment_id.as_str());
        assert!(
            target
                .secret_accessors_for(&secret_name)
                .expect("grant recorded")
                .contains(&sa)
        );
    }

    #[tokio::test]
    async fn warm_stages_secret_once_across_etag_retries() {
        // Two upsert_service conflicts before success: staging happens BEFORE the
        // retry loop, so the seed secret gets exactly one version, not one per retry.
        let target = Arc::new(ConflictInjector::new(2, 0));
        let handler = GcpCloudRunDeployerHandler::with_target(target.clone());
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;

        handler.warm_revision(&env, r_warm, None).await.unwrap();

        let params = params_from_answers(&env, None).unwrap();
        let secret_name = environment_secret_name(&params.secret_prefix);
        let version = target
            .inner
            .secrets()
            .get(&secret_name)
            .expect("seed secret staged")
            .1;
        assert_eq!(
            version, 1,
            "the seed secret is staged once, before the etag loop"
        );
    }

    #[tokio::test]
    async fn warm_gives_up_after_max_etag_retries() {
        let target = Arc::new(ConflictInjector::new(MAX_ETAG_RETRIES + 1, 0));
        let handler = GcpCloudRunDeployerHandler::with_target(target);
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let err = handler
            .warm_revision(&env, r_warm, None)
            .await
            .expect_err("unbounded etag conflicts must surface a provider error");
        assert!(matches!(err, DeployerError::Provider(ref m) if m.contains("etag race")));
    }

    #[tokio::test]
    async fn apply_traffic_split_retries_on_etag_conflict() {
        let target = Arc::new(ConflictInjector::new(0, 1));
        let handler = GcpCloudRunDeployerHandler::with_target(target.clone());
        let env = build_fixture_env();
        let r_warm = env.revisions[0].revision_id;
        let dep_a = env.bundles[0].deployment_id;
        handler.warm_revision(&env, r_warm, None).await.unwrap();
        handler
            .apply_traffic_split(&env, dep_a, None)
            .await
            .expect("traffic apply re-reads and retries past the etag conflict");
        assert_eq!(
            target.inner.traffic_for(dep_a).unwrap().len(),
            2,
            "the 50/50 split lands after the retry"
        );
    }
}
