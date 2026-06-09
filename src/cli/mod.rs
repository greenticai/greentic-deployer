//! `gtc op` command surface (`A3` of `plans/next-gen-deployment.md`).
//!
//! Library-level command implementations for the operator wizard. Each
//! submodule exposes one noun:
//!
//! - [`mod@env`] — Environment CRUD (`create`, `update`, `list`, `show`, `doctor`, `destroy`)
//! - [`env_packs`] — Env-pack bindings (`add`, `update`, `remove`, `rollback`, `list`)
//! - [`bundles`] — Application bundle deployments (`add`, `update`, `remove`, `list`)
//! - [`revisions`] — Revision lifecycle (`stage`, `warm`, `drain`, `archive`, `list`)
//! - [`traffic`] — Traffic-split management (`set`, `show`, `rollback`)
//! - [`config`] — Host/setup/runtime config inspection (`show`, `set`)
//! - [`credentials`] — Credential modes (`requirements`, `bootstrap`, `rotate`)
//! - [`secrets`] — Secrets management (`list`, `put`, `get`, `rotate`)
//!
//! Every command pair honors:
//!
//! - `--schema` — dump the JSON schema of the input payload it would accept,
//!   then exit `0`. Useful for non-interactive callers wanting to generate an
//!   `--answers` payload programmatically.
//! - `--answers <path>` — read a JSON/YAML payload from disk for a
//!   non-interactive replay. Interactive prompting is out of scope for A3;
//!   wizard rendering lands in A10.
//!
//! Heavy logic that depends on env-pack handlers (deployer dispatch, secrets
//! backend, telemetry exporter, etc.) is deferred to later Phase A gates (A5,
//! A7, A9) and Phase C. A3 wires the command *surface* against the
//! `EnvironmentStore` from A2 and intentionally stubs paths that would
//! require those gates with a clear `not-yet-implemented` error.
//!
//! ## Output
//!
//! Every command writes structured JSON to a `Write` sink chosen by the
//! caller. Stable schema: `{ "op": "<verb>", "noun": "<noun>", "result": ... }`
//! for success; `{ "op": "<verb>", "noun": "<noun>", "error": { ... } }` for
//! failure. Human-readable rendering is layered on by the caller (operator
//! binary or `gtc op` passthrough); the library stays output-format-neutral.

use std::path::PathBuf;

pub mod bootstrap;
pub mod bundle_stage;
pub mod bundles;
pub mod config;
pub mod credentials;
pub mod deploy;
pub mod dispatch;
pub mod env;
pub mod env_packs;
pub mod extensions;
pub mod messaging;
pub mod migrate;
pub mod migrate_state;
pub mod pack_config_stage;
pub mod revisions;
pub mod secrets;
pub mod traffic;
pub mod trust_root;
// pub mod bundles;
// pub mod revisions;
// pub mod traffic;
// pub mod config;
// pub mod credentials;
// pub mod secrets;

#[cfg(test)]
mod tests_common;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::environment::{
    AuditDecision, AuditEvent, AuditLog, AuditResult, LifecycleError, LocalFsStore, StoreError,
    authorize_local_only, current_local_actor,
};
use greentic_deploy_spec::{EnvId, SpecError};

/// Top-level error shared across `op` command implementations.
#[derive(Debug, Error)]
pub enum OpError {
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    #[error("spec validation failed: {0}")]
    Spec(#[from] SpecError),
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid json/yaml in {path}: {message}")]
    AnswersParse { path: PathBuf, message: String },
    #[error("schema generation failed: {0}")]
    SchemaGeneration(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("not yet implemented in Phase A: {0}")]
    NotYetImplemented(&'static str),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unauthorized: {policy} — {reason}")]
    Unauthorized { policy: String, reason: String },
    #[error("audit log write failed after the mutation committed: {0}")]
    Audit(String),
    #[error("revenue policy: {0}")]
    RevenuePolicy(#[from] crate::environment::BundleDeploymentError),
    #[error("trust root: {0}")]
    TrustRoot(#[from] crate::environment::TrustRootError),
    /// Operator-key load or generation failed. Distinct from `RevenuePolicy`
    /// so trust-root / bundle verbs surface the right noun in their error
    /// envelopes.
    #[error("operator key: {0}")]
    OperatorKey(#[from] crate::operator_key::OperatorKeyError),
}

impl From<LifecycleError> for OpError {
    fn from(err: LifecycleError) -> Self {
        match err {
            LifecycleError::NotFound {
                env_id,
                revision_id,
            } => OpError::NotFound(format!(
                "revision `{revision_id}` not found in env `{env_id}`"
            )),
            LifecycleError::InvalidTransition { from, to } => {
                OpError::Conflict(format!("spec rejects transition `{from:?} → {to:?}`"))
            }
            LifecycleError::Conflict {
                revision_id,
                actual,
                expected_starts,
            } => OpError::Conflict(format!(
                "revision `{revision_id}` is in `{actual:?}`; expected one of {expected_starts:?}"
            )),
            LifecycleError::EmptyChain => {
                OpError::InvalidArgument("empty transition chain".to_string())
            }
            LifecycleError::ActiveTrafficReference {
                revision_id,
                splits,
            } => {
                let detail = splits
                    .iter()
                    .map(|s| {
                        format!(
                            "deployment `{}` / bundle `{}` ({}bps)",
                            s.deployment_id, s.bundle_id, s.weight_bps
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                OpError::Conflict(format!(
                    "revision `{revision_id}` is still referenced by live traffic split(s): [{detail}]; rebalance via `gtc op traffic set` before archiving"
                ))
            }
            LifecycleError::HealthGateFailed {
                revision_id,
                failed_checks,
                message,
            } => {
                let checks = if failed_checks.is_empty() {
                    String::from("none reported")
                } else {
                    failed_checks
                        .iter()
                        .map(|c| format!("{c:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                OpError::Conflict(format!(
                    "revision `{revision_id}` failed warm/ready health gate (checks: [{checks}]): {message}"
                ))
            }
            LifecycleError::Store(source) => OpError::Store(source),
        }
    }
}

impl OpError {
    /// Short machine code for the error envelope (`error.kind`).
    pub fn kind(&self) -> &'static str {
        match self {
            OpError::Store(_) => "store",
            OpError::Spec(_) => "spec",
            OpError::Io { .. } => "io",
            OpError::AnswersParse { .. } => "answers-parse",
            OpError::SchemaGeneration(_) => "schema-generation",
            OpError::InvalidArgument(_) => "invalid-argument",
            OpError::NotFound(_) => "not-found",
            OpError::NotYetImplemented(_) => "not-yet-implemented",
            OpError::Conflict(_) => "conflict",
            OpError::Unauthorized { .. } => "unauthorized",
            OpError::Audit(_) => "audit",
            OpError::RevenuePolicy(_) => "revenue-policy",
            OpError::TrustRoot(_) => "trust-root",
            OpError::OperatorKey(_) => "operator-key",
        }
    }
}

/// Context for [`audit_and_record`] — everything the helper needs to build an
/// [`AuditEvent`] except the mutation's generations (which the closure
/// returns as [`AuditGens`]).
#[derive(Debug)]
pub(crate) struct AuditCtx {
    pub env_id: EnvId,
    pub noun: &'static str,
    pub verb: &'static str,
    pub target: Value,
    pub idempotency_key: Option<String>,
}

/// Closure-callable handle for signalling "this mutation persisted state to
/// disk even though it's returning Err."
///
/// `audit_and_record` is fail-closed for committed mutations: if the audit
/// append fails, a committed mutation's success is downgraded to
/// [`OpError::Audit`]. The old default was "Ok = committed, Err = not
/// committed," which is wrong for verbs that persist state on an error
/// path (the B9 warm/ready gate flips a revision to `Failed` and saves
/// before surfacing [`LifecycleError::HealthGateFailed`]). Callers on
/// such paths invoke [`CommitMarker::mark_committed`] before returning
/// `Err`, and the audit boundary then treats the audit-append failure as
/// fail-closed instead of demoting it to `tracing::warn!`.
///
/// Default behavior is preserved for every other caller: ignore the
/// parameter (idiomatic `|_committed| { ... }`) and the marker stays
/// unset, so non-committing errors keep their existing demote-to-warn
/// semantics.
pub(crate) struct CommitMarker(std::cell::Cell<bool>);

impl CommitMarker {
    pub(crate) fn new() -> Self {
        Self(std::cell::Cell::new(false))
    }

    /// Mark the mutation as having persisted state before its (forthcoming)
    /// `Err` return. Calling this on the Ok path is harmless but
    /// redundant — `Ok(_)` already implies committed.
    pub fn mark_committed(&self) {
        self.0.set(true);
    }

    pub(crate) fn is_committed(&self) -> bool {
        self.0.get()
    }
}

/// Closure return — the pre- and post-mutation generations.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AuditGens {
    pub previous: Option<u64>,
    pub new: Option<u64>,
}

impl AuditGens {
    pub const NONE: Self = Self {
        previous: None,
        new: None,
    };
}

/// Wrap a mutating verb body in local-only authorization + append-only audit.
///
/// 1. Runs [`authorize_local_only`] against `ctx.env_id`.
/// 2. On `Deny`: returns `OpError::Unauthorized` without calling `mutate`.
/// 3. On `Allow`: runs `mutate` and records the outcome.
/// 4. Always appends an [`AuditEvent`] to `<store_root>/<env_id>/audit/events.jsonl`.
///
/// Audit persistence is **fail-closed for committed mutations**: if `mutate`
/// returned `Ok` (state committed) but the audit event could not be appended,
/// the helper discards the success and returns [`OpError::Audit`]. A
/// state-changing op never reports success without a durable audit record.
///
/// `mutate` receives a [`CommitMarker`]; closures whose error path *also*
/// persists state (e.g. the B9 health gate flipping a revision to `Failed`
/// before surfacing `LifecycleError::HealthGateFailed`) must call
/// [`CommitMarker::mark_committed`] before returning `Err`, so an
/// audit-append failure on that path is treated as fail-closed too.
/// Closures that never persist state on the `Err` path simply ignore the
/// marker (idiomatic `|_committed| { ... }`) — `Ok` already implies
/// committed.
///
/// For non-committing outcomes (authorization denials, mutation errors that
/// didn't persist, `NotYetImplemented` stubs) there is no committed state
/// to protect, so an audit-append failure is demoted to `tracing::warn!`
/// and the original (error) result is returned unchanged.
///
/// Note this closes the "unwritable/full audit dir" gap but not the
/// process-death-between-write-and-append window — durable write-ahead intent
/// belongs to A8's transactional remote store.
///
/// The closure returns `(OpOutcome, AuditGens)` where `AuditGens` carries the
/// `previous_generation` (read under the env flock inside the closure, when
/// applicable) and `new_generation` (the post-mutation value). Both default
/// to `None` for verbs that don't track generations (env/bundles/revisions/
/// credentials/secrets/config/migrate-*). When the closure returns a
/// `previous_generation`, it overrides the value passed in via `AuditCtx`
/// (which is treated as a default).
pub(crate) fn audit_and_record<F>(
    store: &LocalFsStore,
    ctx: AuditCtx,
    mutate: F,
) -> Result<OpOutcome, OpError>
where
    F: FnOnce(&CommitMarker) -> Result<(OpOutcome, AuditGens), OpError>,
{
    let decision = authorize_local_only(&ctx.env_id);
    let commit_marker = CommitMarker::new();
    let (result, gens) = match &decision {
        AuditDecision::Deny { policy, reason } => (
            Err(OpError::Unauthorized {
                policy: policy.clone(),
                reason: reason.clone(),
            }),
            AuditGens::default(),
        ),
        AuditDecision::Allow { .. } => match mutate(&commit_marker) {
            Ok((outcome, g)) => (Ok(outcome), g),
            Err(err) => (Err(err), AuditGens::default()),
        },
    };
    // Either path can commit: `Ok` implies committed by definition; the
    // closure also signals committed-on-`Err` (B9 health-gate Failed
    // persistence) via the CommitMarker.
    let committed = result.is_ok() || commit_marker.is_committed();

    let audit_result = match &result {
        Ok(_) => AuditResult::Ok,
        Err(OpError::NotYetImplemented(detail)) => AuditResult::NotYetImplemented {
            detail: (*detail).to_string(),
        },
        Err(err) => AuditResult::Error {
            kind: err.kind().to_string(),
            message: err.to_string(),
        },
    };

    let event = AuditEvent {
        schema: crate::environment::AUDIT_EVENT_SCHEMA_V1.into(),
        event_id: ulid::Ulid::new().to_string(),
        ts: chrono::Utc::now(),
        actor: current_local_actor(),
        env_id: ctx.env_id.as_str().to_string(),
        noun: ctx.noun.to_string(),
        verb: ctx.verb.to_string(),
        target: ctx.target,
        previous_generation: gens.previous,
        new_generation: gens.new,
        idempotency_key: ctx.idempotency_key,
        authorization: decision,
        result: audit_result,
    };

    let append_outcome = AuditLog::for_env(store, &ctx.env_id).and_then(|log| log.append(&event));
    if let Err(e) = append_outcome {
        if committed {
            // Fail-closed: a committed mutation must not report success without
            // a durable audit record. Surface the failure so the operator can
            // reconcile the (already-persisted) state change.
            return Err(OpError::Audit(format!(
                "{e} (event_id={}, {}.{} on env `{}`)",
                event.event_id, event.noun, event.verb, event.env_id
            )));
        }
        tracing::warn!(
            target: "greentic.audit",
            error = %e,
            event_id = %event.event_id,
            "failed to append audit event for a non-committing op; continuing with op result"
        );
    }

    result
}

/// Mode flags shared by every `op` subcommand.
#[derive(Debug, Clone, Default)]
pub struct OpFlags {
    /// When set, the command prints the JSON schema of its input payload and
    /// exits without touching the store.
    pub schema_only: bool,
    /// When set, the command reads its payload from this path (JSON or YAML)
    /// instead of prompting interactively.
    pub answers: Option<PathBuf>,
}

/// Standard success envelope.
#[derive(Debug, Clone, Serialize)]
pub struct OpOutcome {
    pub op: &'static str,
    pub noun: &'static str,
    pub result: Value,
}

impl OpOutcome {
    pub fn new(noun: &'static str, op: &'static str, result: Value) -> Self {
        Self { op, noun, result }
    }
}

/// Read an answers payload from disk as JSON or YAML. The path extension
/// disambiguates: `.json` → JSON, `.yaml`/`.yml` → YAML. Other extensions
/// fall back to JSON (with a YAML retry on parse failure) so callers can pipe
/// `gtc … --schema | jq … > answers.txt` without re-extensioning.
pub fn load_answers<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T, OpError> {
    let bytes = std::fs::read(path).map_err(|source| OpError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("yaml") | Some("yml") => {
            serde_yaml_bw::from_slice(&bytes).map_err(|e| OpError::AnswersParse {
                path: path.to_path_buf(),
                message: format!("yaml: {e}"),
            })
        }
        Some("json") => serde_json::from_slice(&bytes).map_err(|e| OpError::AnswersParse {
            path: path.to_path_buf(),
            message: format!("json: {e}"),
        }),
        _ => {
            // Heuristic: try JSON first, then YAML.
            serde_json::from_slice(&bytes).or_else(|json_err| {
                serde_yaml_bw::from_slice(&bytes).map_err(|yaml_err| OpError::AnswersParse {
                    path: path.to_path_buf(),
                    message: format!("json: {json_err}; yaml: {yaml_err}"),
                })
            })
        }
    }
}

/// Render an `OpError` into the standard JSON error envelope.
pub fn render_error(noun: &'static str, op: &'static str, err: &OpError) -> Value {
    serde_json::json!({
        "op": op,
        "noun": noun,
        "error": {
            "kind": err.kind(),
            "message": err.to_string(),
        }
    })
}
