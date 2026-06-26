//! Declarative manifest rendering seam (plan §6 step 10).
//!
//! [`ManifestRenderer`] is the deployer-side contract behind
//! `gtc op env render`: it turns an [`Environment`] (plus optional wizard
//! answers) into the ordered list of declarative manifest documents the
//! deployer would apply, without applying anything. This is what lets an
//! operator choose direct apply, GitOps repository handoff, or rendered-
//! manifest handoff — the rendered artifact and the applied resources come
//! from the same functions.
//!
//! The trait deliberately sits NEXT TO [`Deployer`](super::deployer::Deployer)
//! rather than on it: rendering only makes sense for deployers whose
//! desired state is expressible as declarative documents (K8s). Imperative
//! deployers (local-process, AWS-ECS) simply don't implement it — their
//! handlers return `None` from
//! [`EnvPackHandler::as_manifest_renderer`](super::slot::EnvPackHandler::as_manifest_renderer)
//! and `op env render` reports the kind as non-renderable.

use greentic_deploy_spec::Environment;
use serde_json::Value;

/// Renders an environment's full declarative desired state.
///
/// Contract:
/// - **Pure and deterministic** — same `(env, answers)` pair, same
///   documents, same order. No I/O, no provider calls, no clock.
/// - **Apply order** — consumers may feed the list to `kubectl apply -f`
///   (or commit it to a GitOps repo) as-is; dependencies come before
///   dependents (e.g. Namespace before namespaced objects).
/// - Each [`Value`] is one manifest document following the K8s object
///   convention (`apiVersion` / `kind` / `metadata.name`).
/// - The set covers environment-level objects AND per-revision workload
///   objects for revisions whose persisted lifecycle implies presence in
///   the desired state — the exact lifecycle policy is the impl's to
///   define and document.
pub trait ManifestRenderer: Send + Sync {
    /// Render the env's declarative desired state, in apply order.
    ///
    /// `answers` is the deployer binding's recorded wizard answers as a
    /// flat JSON object keyed by wizard question id (the ecosystem's
    /// qa-spec answers convention). `None` when the binding records no
    /// answers — the impl must fall back to sandbox defaults.
    fn render_environment(
        &self,
        env: &Environment,
        answers: Option<&serde_json::Value>,
    ) -> Result<Vec<Value>, RenderError>;
}

/// Errors from [`ManifestRenderer::render_environment`].
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// The binding's recorded answers are malformed or fail validation.
    #[error("invalid binding answers: {0}")]
    InvalidAnswers(String),
}
