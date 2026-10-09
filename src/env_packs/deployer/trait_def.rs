//! [`Deployer`] trait + error/outcome types.
//!
//! The trait is object-safe via `async_trait`: the env-pack registry
//! returns `&dyn Deployer` so plug-in handlers compiled outside this
//! crate (Phase D K8s/AWS) can be resolved by descriptor.

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, RevisionId, RuntimeConfig};
use serde_json::Value;
use thiserror::Error;

use super::capabilities::AdapterCapabilities;
use super::drain::DrainEvidence;
use crate::environment::runtime_config::materialize_runtime_config;

/// Side-effect outcome of [`Deployer::stage_revision`].
///
/// Empty for the v1 trait; K8s/AWS impls may extend with provider-
/// discovered artifacts (uploaded digests, signed manifest refs, …)
/// once the second concrete deployer lands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StageOutcome {}

/// Side-effect outcome of [`Deployer::warm_revision`].
///
/// `endpoint_url` carries a provider-discovered public endpoint when the backend
/// assigns one — Cloud Run returns the Service's `*.run.app` URL here (read from
/// the upsert response, so no extra round-trip). `None` for backends with no
/// deployer-discovered endpoint (a K8s ingress host / the AWS-ECS ALB DNS are
/// operator-supplied, not discovered by the warm).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WarmOutcome {
    pub endpoint_url: Option<String>,
}

/// Side-effect outcome of [`Deployer::drain_revision`].
///
/// `evidence` is what the provider showed that proves the drain;
/// [`DrainEvidence::Unsupported`] (the default) means the adapter did not
/// confirm anything — its `drain` capability is false.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Seconds the drain window actually waited (after the policy cap).
    pub waited_seconds: u64,
    pub evidence: DrainEvidence,
}

/// Side-effect outcome of [`Deployer::archive_revision`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveOutcome {}

/// Side-effect outcome of [`Deployer::apply_traffic_split`].
///
/// The conformance bench asserts both fields so a deployer that
/// quietly applies the wrong deployment or silently mutates a
/// sibling deployment's split cannot pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSplitOutcome {
    /// The deployment whose split this call enforced. MUST equal the
    /// `deployment_id` argument to [`Deployer::apply_traffic_split`].
    pub applied_deployment_id: DeploymentId,
    /// The exact entries the impl applied. MUST equal
    /// `env.traffic_splits.iter().find(|s| s.deployment_id == deployment_id).unwrap().entries`.
    pub applied_entries: Vec<greentic_deploy_spec::TrafficSplitEntry>,
}

/// Errors a [`Deployer`] impl may return.
///
/// Pure-spec rejections (sum != 10000bps, revision not in env, mismatched
/// deployment) MUST be returned BEFORE any provider call so a failing
/// precondition is cheap and deterministic. Provider-side failures
/// (`kubectl apply` errored, ECS API rejected the task-set) surface as
/// [`DeployerError::Provider`] carrying the underlying message.
#[derive(Debug, Error)]
pub enum DeployerError {
    /// The targeted revision is not present in the env passed in.
    #[error("revision `{revision_id}` not found in env `{env_id}`")]
    RevisionNotFound {
        env_id: greentic_deploy_spec::EnvId,
        revision_id: RevisionId,
    },

    /// `apply_traffic_split` was called for a `deployment_id` that has no
    /// `TrafficSplit` recorded in the env.
    #[error("no TrafficSplit recorded for deployment `{deployment_id}` in env `{env_id}`")]
    SplitNotFound {
        env_id: greentic_deploy_spec::EnvId,
        deployment_id: DeploymentId,
    },

    /// The env's `TrafficSplit` for this deployment has weights that do not
    /// sum to 10000 basis points. The deployer refuses to enforce a split
    /// that violates the spec invariant.
    #[error(
        "TrafficSplit for deployment `{deployment_id}` violates the sum=10000bps invariant: actual={sum}"
    )]
    InvalidSplit {
        deployment_id: DeploymentId,
        sum: u64,
    },

    /// The revision is still serving: its drain did not confirm (or it was
    /// never drained) and archiving it now would cut live sessions. Pass
    /// `--force-drain` to archive anyway.
    #[error("revision `{revision_id}` is not drained: {reason}")]
    NotDrained {
        revision_id: RevisionId,
        reason: String,
    },

    /// Provider-side failure. The trait does not constrain the message
    /// shape; impls SHOULD include actionable detail (the kubectl/aws
    /// command that failed, the response body, …) so operators can act.
    #[error("provider failure: {0}")]
    Provider(String),
}

/// Shared precondition helper: rejects a revision_id that isn't in the env.
///
/// Every [`Deployer`] verb starts with this check. Lives here (not on each
/// impl) so a future Phase D handler can't accidentally drop it; the
/// conformance bench exercises it via
/// [`super::conformance::ConformanceFailure::UnknownRevisionAccepted`].
pub fn require_revision(env: &Environment, revision_id: RevisionId) -> Result<(), DeployerError> {
    if env.revisions.iter().any(|r| r.revision_id == revision_id) {
        Ok(())
    } else {
        Err(DeployerError::RevisionNotFound {
            env_id: env.environment_id.clone(),
            revision_id,
        })
    }
}

/// Shared precondition helper: locates the recorded `TrafficSplit` for
/// `deployment_id`, enforces the `sum == 10000bps` invariant, and returns a
/// [`TrafficSplitOutcome`] populated against the env's recorded entries.
///
/// Every [`Deployer::apply_traffic_split`] impl wraps this with its own
/// provider work (kubectl apply, ALB rule update, ...). Pulling the
/// precondition + outcome construction here keeps the 4-stub conformance
/// bench and every Phase D impl on one source of truth — and is what the
/// conformance bench's `CrossDeploymentInterference` check trusts.
pub fn enforce_split_invariants(
    env: &Environment,
    deployment_id: DeploymentId,
) -> Result<TrafficSplitOutcome, DeployerError> {
    let split = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == deployment_id)
        .ok_or_else(|| DeployerError::SplitNotFound {
            env_id: env.environment_id.clone(),
            deployment_id,
        })?;
    let sum: u64 = split.entries.iter().map(|e| u64::from(e.weight_bps)).sum();
    if sum != 10_000 {
        return Err(DeployerError::InvalidSplit { deployment_id, sum });
    }
    Ok(TrafficSplitOutcome {
        applied_deployment_id: deployment_id,
        applied_entries: split.entries.clone(),
    })
}

/// Contract every deployer env-pack implements.
///
/// Trait methods model **provider-side effects** — the work that brings
/// real infrastructure into agreement with the env's recorded intent.
/// The corresponding lifecycle state transition
/// (`Inactive→Staged→Warming→Ready→Draining→Inactive→Archived`) is
/// applied by the operator CLI via
/// [`crate::environment::lifecycle::apply_revision_transition`] AFTER
/// the deployer's side-effects succeed. Keeping these orthogonal means a
/// deployer impl does not own state mutation, and the conformance suite
/// in [`super::conformance`] stays storage-agnostic.
///
/// ## Idempotency
///
/// Every verb MUST be idempotent: calling `warm_revision(env, r)` twice
/// against the same input MUST succeed twice and leave provider state
/// equivalent. The conformance suite verifies this contract.
///
/// ## Returning errors
///
/// Pure-spec preconditions (revision not in env, split sum != 10000bps,
/// no split for the deployment) MUST be checked BEFORE any provider call
/// and surfaced via the typed [`DeployerError`] variants — never as
/// [`DeployerError::Provider`]. Provider-side failures use `Provider(...)`.
///
/// ## Provider answers
///
/// The verbs that materialize parametrized infrastructure — `warm_revision`,
/// `archive_revision`, `apply_traffic_split` — take `answers: Option<&Value>`:
/// the deployer binding's recorded wizard answers (flat JSON keyed by question
/// id, the qa-spec convention). `None` means "use the env-pack's sandbox
/// defaults". K8s reads namespace / image / replica overrides from it so an
/// operator's custom binding lands the same objects `op env render` /
/// `op env reconcile` show. `stage_revision` is a no-op that
/// renders nothing, so it carries no answers; a future provider whose stage
/// uploads to an answer-derived registry adds the param when it grows a body.
/// `drain_revision` takes answers because its probe must address the live
/// objects (K8s namespace, Cloud Run project/region).
#[async_trait]
pub trait Deployer: std::fmt::Debug + Send + Sync {
    /// Stage-time side effects: upload bundle to registry/storage,
    /// pre-pull images, validate trust-root signatures, etc.
    ///
    /// Returns once the revision can transition `Inactive → Staged`.
    /// Local-process has no upload / no registry — its impl is a no-op.
    async fn stage_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<StageOutcome, DeployerError>;

    /// Warm-time side effects: create the cloud resources that serve the
    /// revision (K8s Deployment, ECS task-set, systemd unit, …), wait
    /// until reachable.
    ///
    /// Returns once the revision can transition `Staged → Warming → Ready`.
    /// `answers` carries the binding's wizard answers (see the trait-level
    /// "Provider answers" note); `None` uses sandbox defaults.
    async fn warm_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<WarmOutcome, DeployerError>;

    /// Drain-time side effects (P5-R2): wait the revision's `drain_seconds`
    /// (capped by the adapter's drain policy) for existing sessions to
    /// complete, then CONFIRM the revision serves nothing. An adapter that
    /// cannot confirm returns [`DrainEvidence::Unsupported`]; one that can
    /// but finds the revision still serving returns
    /// [`DeployerError::NotDrained`] naming the revision.
    ///
    /// Returns once the revision can transition `Ready → Draining → Inactive`.
    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainOutcome, DeployerError>;

    /// Point-in-time drain check with no wait — the archive gate. `Ok` with
    /// evidence when the revision serves nothing; [`DeployerError::NotDrained`]
    /// when it still does. The default reports
    /// [`DrainEvidence::Unsupported`]: an adapter without the `drain`
    /// capability cannot gate, and says so rather than claiming a drain.
    async fn confirm_drained(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainEvidence, DeployerError> {
        require_revision(env, revision_id)?;
        let _ = answers;
        Ok(DrainEvidence::Unsupported)
    }

    /// What this adapter can do (P5-R3). Default: nothing claimed.
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::NONE
    }

    /// Caveats behind [`Self::capabilities`], for report output.
    fn capability_notes(&self) -> &'static [&'static str] {
        &[]
    }

    /// Archive-time side effects: tear down the provider resources for
    /// this revision (delete the K8s Deployment, deregister the ECS task-
    /// set, remove the systemd unit, …).
    ///
    /// Returns once the revision can transition `Inactive → Archived`.
    /// The operator CLI's archive guard (active-traffic check) runs at
    /// the storage layer; the deployer is only responsible for the
    /// provider side. Impls MUST be idempotent against an already-torn-
    /// down revision so a retried archive is safe.
    /// `answers` carries the binding's wizard answers (see the trait-level
    /// "Provider answers" note); `None` uses sandbox defaults.
    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ArchiveOutcome, DeployerError>;

    /// Project the env's `TrafficSplit` for `deployment_id` into a
    /// provider-native shape (K8s router runtime-config bump, ALB rule
    /// weights, Cloud Run traffic targets, …) and enforce it.
    ///
    /// MUST reject `sum != 10000bps` with [`DeployerError::InvalidSplit`]
    /// BEFORE any provider call. MUST treat splits for sibling
    /// deployments as independent — applying a split for deployment A
    /// MUST NOT perturb deployment B's recorded or enforced split.
    /// `answers` carries the binding's wizard answers (see the trait-level
    /// "Provider answers" note); `None` uses sandbox defaults.
    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
        answers: Option<&Value>,
    ) -> Result<TrafficSplitOutcome, DeployerError>;

    /// The deployer's view of the runtime-config projection.
    ///
    /// Default delegates to [`materialize_runtime_config`] — the pure
    /// projection of the env's `traffic_splits + revisions` into the
    /// `greentic.runtime-config.v1` shape that `greentic-start` loads.
    /// Provider impls MAY override to splice in provider-discovered
    /// values (the K8s router's ClusterIP, the ALB DNS, …) once those
    /// values exist on the spec side; today the projection is pure.
    fn report_runtime_config(&self, env: &Environment) -> RuntimeConfig {
        materialize_runtime_config(env)
    }
}
