//! [`Deployer`] trait + error/outcome types.
//!
//! The trait is object-safe via `async_trait`: the env-pack registry
//! returns `&dyn Deployer` so plug-in handlers compiled outside this
//! crate (Phase D K8s/AWS) can be resolved by descriptor.

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, RevisionId, RuntimeConfig};
use thiserror::Error;

use crate::environment::runtime_config::materialize_runtime_config;

/// Side-effect outcome of [`Deployer::stage_revision`].
///
/// Empty for the v1 trait; K8s/AWS impls may extend with provider-
/// discovered artifacts (uploaded digests, signed manifest refs, …)
/// once the second concrete deployer lands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StageOutcome {}

/// Side-effect outcome of [`Deployer::warm_revision`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WarmOutcome {}

/// Side-effect outcome of [`Deployer::drain_revision`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainOutcome {}

/// Side-effect outcome of [`Deployer::archive_revision`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveOutcome {}

/// Side-effect outcome of [`Deployer::apply_traffic_split`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficSplitOutcome {}

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

    /// Provider-side failure. The trait does not constrain the message
    /// shape; impls SHOULD include actionable detail (the kubectl/aws
    /// command that failed, the response body, …) so operators can act.
    #[error("provider failure: {0}")]
    Provider(String),
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
    async fn warm_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<WarmOutcome, DeployerError>;

    /// Drain-time side effects: stop accepting new sessions and wait up
    /// to `drain_seconds` for existing sessions to complete.
    ///
    /// Returns once the revision can transition `Ready → Draining → Inactive`.
    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<DrainOutcome, DeployerError>;

    /// Archive-time side effects: tear down the provider resources for
    /// this revision (delete the K8s Deployment, deregister the ECS task-
    /// set, remove the systemd unit, …).
    ///
    /// Returns once the revision can transition `Inactive → Archived`.
    /// The operator CLI's archive guard (active-traffic check) runs at
    /// the storage layer; the deployer is only responsible for the
    /// provider side. Impls MUST be idempotent against an already-torn-
    /// down revision so a retried archive is safe.
    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<ArchiveOutcome, DeployerError>;

    /// Project the env's `TrafficSplit` for `deployment_id` into a
    /// provider-native shape (K8s router runtime-config bump, ALB rule
    /// weights, Cloud Run traffic targets, …) and enforce it.
    ///
    /// MUST reject `sum != 10000bps` with [`DeployerError::InvalidSplit`]
    /// BEFORE any provider call. MUST treat splits for sibling
    /// deployments as independent — applying a split for deployment A
    /// MUST NOT perturb deployment B's recorded or enforced split.
    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
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
