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

use crate::env_packs::deployer::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome, enforce_split_invariants, require_revision,
};

use super::GcpCloudRunDeployerHandler;
use super::deploy_target::{
    AccessMode, CloudRunTargetError, RevisionRef, ScalingSpec, ServiceRef, ServiceSpec,
    TrafficTarget,
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
        self.service_account.clone().unwrap_or_else(|| {
            format!(
                "gtc-{env_id}-runtime@{project}.iam.gserviceaccount.com",
                project = self.project,
            )
        })
    }
}

/// Deterministic Cloud Run Service name for a deployment: `gtc-svc-{ulid}`
/// (lowercased; RFC1123 DNS-label safe). Plan D1.
pub fn service_name(deployment_id: DeploymentId) -> String {
    format!("gtc-svc-{}", deployment_id.0.to_string().to_lowercase())
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

        // Read-modify-write under etag optimistic concurrency with bounded
        // retries on a precondition conflict (plan D4): re-read, recompute
        // traffic from the fresh state, and retry rather than replaying a stale
        // etag. Traffic is pinned to NAMED revisions in the same upsert — first
        // create is 100% to the named first revision (never LATEST, never a
        // 0%-only array); an update keeps the existing distribution and adds
        // this revision at 0% if it is new, so warm never moves traffic.
        let mut attempt = 0;
        loop {
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
                secrets: Vec::new(),
            };
            match self.target.upsert_service(&spec, etag.as_deref()).await {
                Ok(_) => break,
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
        }

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
        Ok(WarmOutcome::default())
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
