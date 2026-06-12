//! A8 route handlers — environment-lifecycle verb group (PR-4.2a).
//!
//! Each mutation handler follows the same shape the remaining verb groups
//! will reuse:
//!
//! 1. decode the shared wire payload (`greentic_deploy_spec::engine` types —
//!    the SAME structs the `HttpEnvironmentStore` client serializes);
//! 2. load current state from [`EnvironmentStorage`];
//! 3. apply the pure `greentic_deploy_spec::engine` transform (identical to
//!    what `LocalFsStore` runs);
//! 4. persist under a CAS precondition pinned to the loaded revision;
//! 5. reply with the A8 mutation envelope `{result, etag, generation,
//!    idempotency, audit}` — the PR-4.0 client rejects any 2xx whose audit
//!    record is missing, denied, non-ok, or names the wrong env/key.
//!
//! Errors travel as [`RemoteStoreError`] JSON with the matching HTTP status
//! (the client enforces status↔body consistency).
//!
//! Not yet here (intentional follow-ups): idempotency replay (PR-4.3 — keys
//! are required on every mutation and echoed into the audit record, not yet
//! cached for replay), RBAC (PR-4.4 — every decision is an honest
//! `Allow{policy: "open-dev"}`), and the audit log's durable append
//! (PR-4.3).

use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use greentic_deploy_spec::engine::{
    self, BindingError, BundleError, EngineError, RevisionLifecycleError, TrafficSplitError,
};
use greentic_deploy_spec::{
    Actor, AddTrustedKeyPayload, ApplyTrafficSplitOutcome, AuditDecision, AuditEvent, AuditResult,
    BindingGenerationOutcome, BundleDeployment, CapabilitySlot, ConcurrencyConflict,
    CreateEnvironmentPayload, DeploymentId, EnvId, Environment, ExtensionBindingPayload,
    ExtensionKeyedPayload, HealthStatus, IdempotencyKey, IdempotencyOutcome, MigrateMergePayload,
    PackBindingPayload, Precondition, RemoteStoreError, RetentionPolicy, RevisionId,
    RevisionTransitionOutcome, RevocationConfig, RollbackTrafficSplitOutcome,
    RollbackTrafficSplitPayload, SchemaVersion, SetTrafficSplitPayload, StageRevisionPayload,
    StateEtag, TrustRootAddOutcome, TrustRootRemoveOutcome, TrustRootSeed,
    UpdateEnvironmentPayload, WarmRevisionPayload,
};
use greentic_operator_trust::operator_key::{self, OperatorKey};
use greentic_operator_trust::revenue_policy::{self, RevenuePolicyError};
use greentic_operator_trust::trust_root::{
    self, TrustRoot, TrustRootDocError, TrustRootDocument, TrustedKey,
};

use crate::http::AppState;
use crate::storage::{
    EnvRevision, EnvironmentStorage, LoadedTrustRoot, RevenuePolicyArtifact, StorageError,
};

/// `AuditDecision.policy` value while RBAC is not yet enforced (PR-4.4).
/// Honest about what it is — every request is allowed.
const POLICY_OPEN_DEV: &str = "open-dev";

// ---------------------------------------------------------------------------
// Error surface
// ---------------------------------------------------------------------------

/// Handler error: a [`RemoteStoreError`] rendered as `http_status()` + the
/// A8 JSON body. Wrapping (rather than `impl IntoResponse for
/// RemoteStoreError` in deploy-spec) keeps the axum dependency out of the
/// spec crate.
#[derive(Debug)]
pub struct ApiError(pub RemoteStoreError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.0)).into_response()
    }
}

impl From<StorageError> for ApiError {
    fn from(err: StorageError) -> Self {
        Self(map_storage_error(err))
    }
}

impl From<EngineError> for ApiError {
    fn from(err: EngineError) -> Self {
        Self(match err {
            EngineError::NotFound(_) => RemoteStoreError::NotFound,
        })
    }
}

/// Map a pure revision-lifecycle failure onto the A8 wire vocabulary.
/// `HealthGateFailed` is the committed-on-error case: the warm handler
/// persists the `Failed` flip BEFORE this conversion runs (the engine's
/// persist rule), so the typed 422 always describes durable state.
impl From<RevisionLifecycleError> for ApiError {
    fn from(err: RevisionLifecycleError) -> Self {
        Self(match err {
            // The environment itself was loaded — only the dependent
            // (revision / deployment) is missing.
            RevisionLifecycleError::NotFound { .. }
            | RevisionLifecycleError::DeploymentNotFound { .. } => {
                RemoteStoreError::DependentNotFound {
                    detail: err.to_string(),
                }
            }
            RevisionLifecycleError::Conflict { .. }
            | RevisionLifecycleError::ActiveTrafficReference { .. } => RemoteStoreError::Conflict {
                detail: err.to_string(),
            },
            RevisionLifecycleError::HealthGateFailed {
                revision_id,
                failed_checks,
                message,
            } => RemoteStoreError::HealthGateFailed {
                revision_id,
                failed_checks,
                message,
            },
            err @ RevisionLifecycleError::DuplicateRevision { .. } => {
                RemoteStoreError::AlreadyExists {
                    detail: err.to_string(),
                }
            }
            // The chains are server-side constants — a client request can
            // never legitimately produce these. Programming error, 500.
            internal @ (RevisionLifecycleError::InvalidTransition { .. }
            | RevisionLifecycleError::EmptyChain) => {
                tracing::error!(error = %internal, "revision chain constant rejected by spec");
                RemoteStoreError::Internal {
                    message: "revision lifecycle chain misconfigured".to_string(),
                }
            }
        })
    }
}

/// Map a pure traffic-split failure onto the A8 wire vocabulary. No
/// committed-on-error path here — the engine mutates only after every
/// check passes, so any error means nothing was persisted.
impl From<TrafficSplitError> for ApiError {
    fn from(err: TrafficSplitError) -> Self {
        Self(match err {
            // The environment itself was loaded — the dependent
            // (deployment / routed revision / stash payload) is missing.
            TrafficSplitError::DeploymentNotFound { .. }
            | TrafficSplitError::RevisionNotFound { .. }
            | TrafficSplitError::NoSplit { .. }
            | TrafficSplitError::SnapshotMissing { .. } => RemoteStoreError::DependentNotFound {
                detail: err.to_string(),
            },
            // A8 §2 protocol violation: the key was reused with different
            // entries — the canonical `idempotency-conflict` kind, not a
            // generic domain conflict.
            TrafficSplitError::IdempotencyKeyReused { .. } => {
                RemoteStoreError::IdempotencyConflict {
                    reason: err.to_string(),
                }
            }
            // State conflicts the operator resolves before retrying
            // (rebalance, warm the revision, forward-fix instead of a
            // second rollback).
            TrafficSplitError::WrongDeployment { .. }
            | TrafficSplitError::AdmissionRevisionMissing { .. }
            | TrafficSplitError::NotReady { .. }
            | TrafficSplitError::SnapshotEncode { .. }
            | TrafficSplitError::NoPreviousSnapshot { .. }
            | TrafficSplitError::SnapshotDecode { .. } => RemoteStoreError::Conflict {
                detail: err.to_string(),
            },
            // Spec validation (10,000 bps sum / schema discriminator): the
            // request body named an invalid split — 400, before any state
            // was touched.
            TrafficSplitError::Invalid(spec) => RemoteStoreError::InvalidRequest {
                detail: spec.to_string(),
            },
        })
    }
}

/// Map a pure binding failure onto the A8 wire vocabulary. The simplest
/// persist rule of the verb groups: every check runs before the single
/// mutation, so any error means nothing was persisted.
impl From<BindingError> for ApiError {
    fn from(err: BindingError) -> Self {
        Self(match err {
            // The environment itself was loaded — the dependent
            // (slot / extension key / stash payload) is missing.
            BindingError::SlotNotBound { .. }
            | BindingError::ExtensionNotBound { .. }
            | BindingError::SlotSnapshotMissing { .. }
            | BindingError::ExtensionSnapshotMissing { .. } => {
                RemoteStoreError::DependentNotFound {
                    detail: err.to_string(),
                }
            }
            // `add` on an occupied slot/key: the resource exists — same
            // kind the create/stage verbs use (client folds both kinds
            // into the local impl's `Conflict` noun).
            BindingError::SlotAlreadyBound { .. } | BindingError::ExtensionAlreadyBound { .. } => {
                RemoteStoreError::AlreadyExists {
                    detail: err.to_string(),
                }
            }
            // The request body named an N-per-env slot — invalid before
            // any state was touched. Unreachable through the deployer CLI
            // (rejected upstream); this guards the raw wire surface.
            BindingError::NotPackSlot { .. } => RemoteStoreError::InvalidRequest {
                detail: err.to_string(),
            },
            // State conflicts the operator resolves before retrying.
            BindingError::SlotMismatch { .. }
            | BindingError::ExtensionKeyMismatch { .. }
            | BindingError::SlotNoPrevious { .. }
            | BindingError::ExtensionNoPrevious { .. }
            | BindingError::SlotGenerationOverflow { .. }
            | BindingError::ExtensionGenerationOverflow { .. }
            | BindingError::SnapshotEncode { .. }
            | BindingError::SnapshotDecode { .. } => RemoteStoreError::Conflict {
                detail: err.to_string(),
            },
        })
    }
}

/// Map a trust-root document failure onto the A8 wire vocabulary. The
/// validation variants describe the request input (a supplied key_id/PEM
/// pair, or the server's own operator key) — 400 before any state is
/// touched. `BadSchema` is only produced when unwrapping a STORED
/// document, which the storage layer already schema-checks on load —
/// reaching it here is a programming error, 500.
impl From<TrustRootDocError> for ApiError {
    fn from(err: TrustRootDocError) -> Self {
        Self(match err {
            invalid @ (TrustRootDocError::Key(_)
            | TrustRootDocError::KeyIdMismatch { .. }
            | TrustRootDocError::EmptyKeyId(_)) => RemoteStoreError::InvalidRequest {
                detail: invalid.to_string(),
            },
            bad @ TrustRootDocError::BadSchema { .. } => {
                tracing::error!(error = %bad, "trust-root schema rejected outside storage");
                RemoteStoreError::Internal {
                    message: "trust-root document schema misconfigured".to_string(),
                }
            }
        })
    }
}

/// A malformed request body is a typed A8 `invalid-request` (400), not
/// axum's default plaintext rejection — the client parses the JSON body.
impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        Self(RemoteStoreError::InvalidRequest {
            detail: rejection.body_text(),
        })
    }
}

/// Map a backend [`StorageError`] onto the A8 wire error vocabulary,
/// implementing the status table documented on [`StorageError`].
fn map_storage_error(err: StorageError) -> RemoteStoreError {
    match err {
        StorageError::NotFound(_) => RemoteStoreError::NotFound,
        StorageError::AlreadyExists { env_id, .. } => RemoteStoreError::AlreadyExists {
            detail: format!("environment `{env_id}` already exists"),
        },
        StorageError::PreconditionRequired => RemoteStoreError::PreconditionRequired {
            detail: "a conditional write must pin If-Match and/or expected generation".to_string(),
        },
        StorageError::PreconditionFailed { conflict, .. } => {
            RemoteStoreError::PreconditionFailed(conflict)
        }
        StorageError::IntegrityMismatch {
            stored, recomputed, ..
        } => RemoteStoreError::IntegrityMismatch {
            expected: stored,
            actual: recomputed,
        },
        StorageError::Spec(err) => RemoteStoreError::InvalidRequest {
            detail: err.to_string(),
        },
        StorageError::EnvIdMismatch { keyed, payload } => RemoteStoreError::InvalidRequest {
            detail: format!("environment_id mismatch: keyed `{keyed}`, payload `{payload}`"),
        },
        // Backend/serde internals stay opaque — no driver details on the wire.
        StorageError::Integrity(_) | StorageError::Json(_) | StorageError::Backend(_) => {
            RemoteStoreError::Internal {
                message: "internal store error".to_string(),
            }
        }
    }
}

/// `Json<T>` with the rejection mapped to the typed A8 400 body.
#[derive(FromRequest)]
#[from_request(via(Json), rejection(ApiError))]
pub(crate) struct ApiJson<T>(pub(crate) T);

/// Parse a path segment into an [`EnvId`], rejecting invalid ids with a
/// typed 400 instead of a 500 from a downstream `try_from`.
fn parse_env_id(raw: &str) -> Result<EnvId, ApiError> {
    EnvId::try_from(raw).map_err(|err| {
        ApiError(RemoteStoreError::InvalidRequest {
            detail: format!("invalid env id `{raw}`: {err}"),
        })
    })
}

// ---------------------------------------------------------------------------
// Mutation envelope
// ---------------------------------------------------------------------------

/// The A8 success envelope for mutating calls — the serialize side of the
/// client's `MutationEnvelope` in the deployer's `environment::http_store`.
#[derive(Debug, Serialize)]
struct MutationEnvelope<T> {
    result: T,
    etag: StateEtag,
    generation: u64,
    idempotency: IdempotencyOutcome,
    audit: AuditEvent,
}

/// Build the 2xx mutation response: the audit record (bound to the request
/// via `env_id` + the `Idempotency-Key` the client sent — the PR-4.0 client
/// validates both) wrapped in the A8 envelope. One call per handler so
/// every verb group shares the exact shape; when PR-4.3 lands replay, the
/// [`IdempotencyOutcome`] switch happens here, not in N handlers.
#[allow(clippy::too_many_arguments)]
fn mutation_response<T: Serialize>(
    result: T,
    env_id: &EnvId,
    noun: &str,
    verb: &str,
    target: Value,
    idempotency_key: String,
    previous_generation: Option<u64>,
    revision: EnvRevision,
) -> Response {
    let audit = AuditEvent {
        schema: SchemaVersion::AUDIT_EVENT_V1.into(),
        event_id: ulid::Ulid::new().to_string(),
        ts: Utc::now(),
        actor: Actor {
            kind: "store-server".to_string(),
            user: None,
            uid: None,
        },
        env_id: env_id.as_str().to_string(),
        noun: noun.to_string(),
        verb: verb.to_string(),
        target,
        previous_generation,
        new_generation: Some(revision.generation),
        idempotency_key: Some(idempotency_key),
        authorization: AuditDecision::Allow {
            policy: POLICY_OPEN_DEV.to_string(),
            reason: "RBAC not yet enforced (PR-4.4)".to_string(),
        },
        result: AuditResult::Ok,
    };
    Json(MutationEnvelope {
        result,
        etag: revision.etag,
        generation: revision.generation,
        idempotency: IdempotencyOutcome::Applied,
        audit,
    })
    .into_response()
}

/// Require a non-empty `Idempotency-Key` on every mutation (A8 §2). PR-4.3
/// adds replay; today the key is echoed into the audit record so the
/// client's binding check passes.
fn require_idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty());
    match key {
        Some(k) => Ok(k),
        None => Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: "missing or empty Idempotency-Key header \
                     (A8 §2: every mutating request must carry one)"
                .to_string(),
        })),
    }
}

/// Parse an optional `If-Match` header into `Option<StateEtag>`. Accepts
/// the strong quoted form (`"<hex>"`) and bare hex; rejects weak validators
/// (`W/"…"`) and the wildcard `*` with a typed 400.
fn parse_if_match(headers: &HeaderMap) -> Result<Option<StateEtag>, ApiError> {
    let Some(raw) = headers.get("If-Match") else {
        return Ok(None);
    };
    let s = raw.to_str().map_err(|_| {
        ApiError(RemoteStoreError::InvalidRequest {
            detail: "If-Match header is not valid ASCII".to_string(),
        })
    })?;
    let s = s.trim();
    if s.starts_with("W/") || s.starts_with("w/") {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: "strong ETag required (weak validators `W/` are not accepted)".to_string(),
        }));
    }
    if s == "*" {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: "strong ETag required (`*` wildcard is not accepted)".to_string(),
        }));
    }
    // Strip surrounding double quotes if present.
    let inner = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s);
    Ok(Some(StateEtag(inner.to_string())))
}

/// Map a [`StorageError`] raised by LOADING persisted state — `Spec`,
/// `EnvIdMismatch`, and `Json` on a stored row indicate corruption, not a
/// client error. Write-path callers keep the existing `From<StorageError>`
/// mapping where `Spec` → 400 is correct (the request payload caused it).
fn load_storage_error(err: StorageError) -> ApiError {
    match err {
        // The Display impls already carry the variant detail (spec reason,
        // keyed/payload ids, serde message) — one arm, one log line.
        corrupt @ (StorageError::Spec(_)
        | StorageError::EnvIdMismatch { .. }
        | StorageError::Json(_)) => {
            tracing::error!(error = %corrupt, "stored environment state failed validation");
            ApiError(RemoteStoreError::Internal {
                message: "stored environment state failed validation".to_string(),
            })
        }
        other => ApiError(map_storage_error(other)),
    }
}

/// CAS precondition for a load-then-write handler: a client-supplied
/// `If-Match` wins (server side of A8 #1; client wiring stays PR-3b-fu);
/// otherwise pin the revision the handler just loaded — a torn-write guard
/// only, not true client CAS.
fn resolve_precondition(client_etag: Option<StateEtag>, loaded: &EnvRevision) -> Precondition {
    match client_etag {
        Some(etag) => Precondition {
            if_match: Some(etag),
            expected_generation: None,
        },
        None => Precondition::matching(loaded.etag.clone(), loaded.generation),
    }
}

// ---------------------------------------------------------------------------
// Handlers — environment lifecycle
// ---------------------------------------------------------------------------

/// `POST /environments` — create-if-absent (A8 route 1).
pub(crate) async fn create_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<CreateEnvironmentPayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let env = engine::fresh_environment(
        &payload.env_id,
        payload.name,
        payload.host_config,
        RevocationConfig::default(),
        RetentionPolicy::default(),
        HealthStatus::default(),
    );
    // Existence is enforced by the storage layer's atomic create
    // (`AlreadyExists` → 409) — no load-then-check race.
    let revision = state.storage.create_env(&env).await?;
    let env_id = env.environment_id.clone();
    Ok(mutation_response(
        env,
        &env_id,
        "env",
        "create",
        json!({"environment_id": env_id}),
        idem_key,
        None,
        revision,
    ))
}

/// `PATCH /environments/{env_id}` — tri-state field patch (A8 route 2).
pub(crate) async fn update_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(patch): ApiJson<UpdateEnvironmentPayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    engine::apply_environment_update(&mut env, patch);
    let precondition = resolve_precondition(client_etag, &loaded.revision);
    let revision = state.storage.update_env(&env, &precondition).await?;
    Ok(mutation_response(
        env,
        &env_id,
        "env",
        "update",
        json!({"environment_id": env_id}),
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

/// `POST /environments/{env_id}/migrate-bindings` — merge pack/extension
/// bindings, optionally seeding a missing target (A8 route 3).
pub(crate) async fn migrate_bindings<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<MigrateMergePayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let existing = match state.storage.load_env(&env_id).await {
        Ok(loaded) => Some(loaded),
        Err(StorageError::NotFound(_)) => None,
        Err(err) => return Err(load_storage_error(err)),
    };
    let prior_revision = existing.as_ref().map(|l| l.revision.clone());
    let mut env =
        engine::seed_or_existing(existing.map(|l| l.value), &env_id, payload.seed_if_missing)?;
    let report = engine::merge_bindings(&mut env, payload.packs, payload.extensions);
    let revision = match &prior_revision {
        Some(prior) => {
            let precondition = resolve_precondition(client_etag.clone(), prior);
            state.storage.update_env(&env, &precondition).await?
        }
        None => {
            // Seed/create branch: If-Match on a resource that doesn't exist
            // yet is a precondition failure per RFC 9110.
            if let Some(client_etag) = &client_etag {
                return Err(ApiError(RemoteStoreError::PreconditionFailed(
                    ConcurrencyConflict {
                        expected_etag: Some(client_etag.0.clone()),
                        actual_etag: String::new(),
                        expected_generation: None,
                        actual_generation: 0,
                    },
                )));
            }
            state.storage.create_env(&env).await?
        }
    };
    let target = json!({
        "environment_id": env_id,
        "merged_slots": report.merged_slots,
        "merged_extensions": report.merged_extensions,
    });
    Ok(mutation_response(
        report,
        &env_id,
        "env",
        "migrate-bindings",
        target,
        idem_key,
        prior_revision.map(|r| r.generation),
        revision,
    ))
}

// ---------------------------------------------------------------------------
// Handlers — revision lifecycle (PR-4.2b)
// ---------------------------------------------------------------------------

/// Parse a path segment into a [`RevisionId`] (ULID), rejecting malformed
/// ids with a typed 400.
fn parse_revision_id(raw: &str) -> Result<RevisionId, ApiError> {
    raw.parse::<ulid::Ulid>().map(RevisionId).map_err(|err| {
        ApiError(RemoteStoreError::InvalidRequest {
            detail: format!("invalid revision id `{raw}`: {err}"),
        })
    })
}

/// `POST /environments/{env_id}/revisions` — stage a fresh revision under
/// an existing deployment (A8 route 4).
pub(crate) async fn stage_revision<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<StageRevisionPayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    let staged = engine::stage_revision(&mut env, payload, Utc::now())?;
    let precondition = resolve_precondition(client_etag, &loaded.revision);
    let revision = state.storage.update_env(&env, &precondition).await?;
    let target = json!({
        "environment_id": env_id,
        "revision_id": staged.revision_id.to_string(),
        "deployment_id": staged.deployment_id.to_string(),
        "lifecycle_to": "staged",
    });
    Ok(mutation_response(
        staged,
        &env_id,
        "revisions",
        "stage",
        target,
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

/// `POST /environments/{env_id}/revisions/{revision_id}/warm` — drive
/// `Staged → Warming → Ready`, applying the client-evaluated health-gate
/// outcome from the body (A8 route 5). The body's `revision_id` must match
/// the URL's.
pub(crate) async fn warm_revision<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, revision_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<WarmRevisionPayload>,
) -> Result<Response, ApiError> {
    let revision_id = parse_revision_id(&revision_id)?;
    if payload.revision_id != revision_id {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: format!(
                "body revision_id `{}` contradicts URL revision id `{revision_id}`",
                payload.revision_id
            ),
        }));
    }
    revision_transition(&state, &env_id, &headers, "warm", |env| {
        engine::warm_revision(env, payload, Utc::now())
    })
    .await
}

/// `POST /environments/{env_id}/revisions/{revision_id}/drain` —
/// `Ready → Draining` (A8 route 6).
pub(crate) async fn drain_revision<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, revision_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let revision_id = parse_revision_id(&revision_id)?;
    revision_transition(&state, &env_id, &headers, "drain", |env| {
        engine::drain_revision(env, revision_id)
    })
    .await
}

/// `POST /environments/{env_id}/revisions/{revision_id}/archive` — walk the
/// revision to `Archived`, refusing while live traffic still references it
/// (A8 route 7).
pub(crate) async fn archive_revision<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, revision_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let revision_id = parse_revision_id(&revision_id)?;
    revision_transition(&state, &env_id, &headers, "archive", |env| {
        engine::archive_revision(env, revision_id)
    })
    .await
}

/// Shared warm/drain/archive body: load → pure engine transform → persist
/// per the engine's rule → A8 envelope around [`RevisionTransitionOutcome`].
///
/// Persist rule: `Ok` persists and responds 2xx; an `env_mutated` error (the
/// warm gate's flip to `Failed`) persists FIRST and then surfaces the typed
/// 422 — committed-on-error, mirroring `LocalFsStore`. A persist failure on
/// that path takes precedence (the client must not be told the gate failure
/// is durable when it isn't). Every other error discards the in-memory env.
///
async fn revision_transition<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &str,
    headers: &HeaderMap,
    verb: &'static str,
    apply: impl FnOnce(&mut Environment) -> Result<engine::RevisionTransition, RevisionLifecycleError>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(headers)?;
    let client_etag = parse_if_match(headers)?;
    let env_id = parse_env_id(env_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    match apply(&mut env) {
        Ok(transition) => {
            let precondition = resolve_precondition(client_etag, &loaded.revision);
            let revision = state.storage.update_env(&env, &precondition).await?;
            let target = json!({
                "environment_id": env_id,
                "revision_id": transition.revision.revision_id.to_string(),
                "lifecycle_to": transition.revision.lifecycle,
            });
            let outcome = RevisionTransitionOutcome {
                revision: transition.revision,
                environment: env,
                starting_lifecycle: transition.starting_lifecycle,
            };
            Ok(mutation_response(
                outcome,
                &env_id,
                "revisions",
                verb,
                target,
                idem_key,
                Some(previous_generation),
                revision,
            ))
        }
        Err(err) if err.env_mutated() => {
            // Health-gate failure: the engine flipped the revision to
            // `Failed` in memory — persist before surfacing the typed 422.
            let precondition = resolve_precondition(client_etag, &loaded.revision);
            state.storage.update_env(&env, &precondition).await?;
            Err(err.into())
        }
        Err(err) => Err(err.into()),
    }
}

/// `POST /environments/{env_id}/traffic` — replace the traffic-split entry
/// list for one deployment (A8 route 8).
///
/// The `Idempotency-Key` header is handed to the engine, not just audited:
/// the traffic group persists it into `TrafficSplit::idempotency_key` (it
/// preserves the rollback target across same-key retries), and the engine's
/// same-key-same-entries replay is a 200 with `new_generation: null` and
/// nothing persisted. `runtime-config.json` materialization is a
/// `LocalFsStore` projection of `traffic_splits` and deliberately does NOT
/// happen here — remote consumers project it from the env document.
pub(crate) async fn set_traffic_split<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<SetTrafficSplitPayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let engine_key = IdempotencyKey::new(idem_key.clone())
        .expect("require_idempotency_key guarantees non-empty");
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    let transition = engine::set_traffic_split(&mut env, payload, &engine_key, Utc::now())?;
    let revision = if transition.mutated() {
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        state.storage.update_env(&env, &precondition).await?
    } else {
        // Idempotent replay: nothing changed — echo the loaded CAS
        // coordinates so the client can keep chaining writes.
        loaded.revision
    };
    let target = json!({
        "environment_id": env_id,
        "deployment_id": transition.split.deployment_id.to_string(),
        "split_generation": transition.new_generation,
    });
    let outcome = ApplyTrafficSplitOutcome {
        split: transition.split,
        previous_generation: transition.previous_generation,
        new_generation: transition.new_generation,
        environment: env,
    };
    Ok(mutation_response(
        outcome,
        &env_id,
        "traffic",
        "set",
        target,
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

/// `POST /environments/{env_id}/traffic/rollback` — restore a deployment's
/// one-step-previous split (A8 route 9). Always a genuine mutation (the
/// generation advances, never rewinds), so unlike `set` there is no replay
/// short-circuit.
pub(crate) async fn rollback_traffic_split<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<RollbackTrafficSplitPayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    let transition = engine::rollback_traffic_split(&mut env, payload.deployment_id, Utc::now())?;
    let precondition = resolve_precondition(client_etag, &loaded.revision);
    let revision = state.storage.update_env(&env, &precondition).await?;
    let target = json!({
        "environment_id": env_id,
        "deployment_id": transition.restored.deployment_id.to_string(),
        "split_generation": transition.new_generation,
    });
    let outcome = RollbackTrafficSplitOutcome {
        restored: transition.restored,
        previous_generation: transition.previous_generation,
        new_generation: transition.new_generation,
        environment: env,
    };
    Ok(mutation_response(
        outcome,
        &env_id,
        "traffic",
        "rollback",
        target,
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

// ---------------------------------------------------------------------------
// Handlers — pack / extension bindings (PR-4.2d)
// ---------------------------------------------------------------------------

/// Parse a path segment into a [`CapabilitySlot`], rejecting unknown slots
/// with a typed 400 (the URL form is the lowercase `as_str` rendering the
/// client emits).
fn parse_capability_slot(raw: &str) -> Result<CapabilitySlot, ApiError> {
    CapabilitySlot::ALL
        .iter()
        .copied()
        .find(|slot| slot.as_str() == raw)
        .ok_or_else(|| {
            ApiError(RemoteStoreError::InvalidRequest {
                detail: format!("invalid capability slot `{raw}`"),
            })
        })
}

/// Shared load → pure-engine transform → persist → A8 envelope cycle for
/// the eight binding verbs. The binding group's persist rule is the
/// simplest of the verb groups — every `Ok` is a mutation, every `Err`
/// leaves the env untouched — so one helper serves all of them (the
/// analogue of `revision_transition` for the revision group). `apply`
/// returns the response body plus the audit-target fragment;
/// `environment_id` is injected here so every verb's target carries it.
async fn binding_mutation<S, T, F>(
    state: AppState<S>,
    raw_env_id: String,
    headers: HeaderMap,
    verb: &'static str,
    noun: &'static str,
    apply: F,
) -> Result<Response, ApiError>
where
    S: EnvironmentStorage,
    T: Serialize,
    F: FnOnce(&mut Environment) -> Result<(T, Value), ApiError>,
{
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&raw_env_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    let (result, mut target) = apply(&mut env)?;
    let precondition = resolve_precondition(client_etag, &loaded.revision);
    let revision = state.storage.update_env(&env, &precondition).await?;
    if let Value::Object(map) = &mut target {
        map.insert("environment_id".to_string(), json!(env_id));
    }
    Ok(mutation_response(
        result,
        &env_id,
        noun,
        verb,
        target,
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

/// `POST /environments/{env_id}/packs` — bind a new env-pack slot
/// (A8 route 10).
pub(crate) async fn add_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<PackBindingPayload>,
) -> Result<Response, ApiError> {
    binding_mutation(state, env_id, headers, "add", "env-packs", |env| {
        let added = engine::add_pack_binding(env, payload.binding)?;
        let target = json!({"slot": added.slot, "kind": added.kind});
        Ok((added, target))
    })
    .await
}

/// `PATCH /environments/{env_id}/packs/{slot}` — replace the binding on an
/// existing slot, stashing the prior one for one-step rollback (A8 route 11).
pub(crate) async fn update_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, slot)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<PackBindingPayload>,
) -> Result<Response, ApiError> {
    let slot = parse_capability_slot(&slot)?;
    binding_mutation(state, env_id, headers, "update", "env-packs", |env| {
        let (binding, generation) = engine::update_pack_binding(env, slot, payload.binding)?;
        let target = json!({"slot": binding.slot, "kind": binding.kind});
        Ok((
            BindingGenerationOutcome {
                binding,
                generation,
            },
            target,
        ))
    })
    .await
}

/// `DELETE /environments/{env_id}/packs/{slot}` — remove a pack-binding
/// slot (A8 route 12).
pub(crate) async fn remove_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, slot)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let slot = parse_capability_slot(&slot)?;
    binding_mutation(state, env_id, headers, "remove", "env-packs", |env| {
        let (binding, generation) = engine::remove_pack_binding(env, slot)?;
        let target = json!({"slot": slot});
        Ok((
            BindingGenerationOutcome {
                binding,
                generation,
            },
            target,
        ))
    })
    .await
}

/// `POST /environments/{env_id}/packs/{slot}/rollback` — restore a slot's
/// one-step-previous binding (A8 route 13).
pub(crate) async fn rollback_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, slot)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let slot = parse_capability_slot(&slot)?;
    binding_mutation(state, env_id, headers, "rollback", "env-packs", |env| {
        let (binding, generation) = engine::rollback_pack_binding(env, slot)?;
        let target = json!({"slot": slot});
        Ok((
            BindingGenerationOutcome {
                binding,
                generation,
            },
            target,
        ))
    })
    .await
}

/// `POST /environments/{env_id}/extensions` — add a new extension binding
/// (A8 route 14).
pub(crate) async fn add_extension_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<ExtensionBindingPayload>,
) -> Result<Response, ApiError> {
    binding_mutation(state, env_id, headers, "add", "extensions", |env| {
        let added = engine::add_extension_binding(env, payload.binding)?;
        let target = json!({"kind_path": added.kind.path(), "instance_id": added.instance_id});
        Ok((added, target))
    })
    .await
}

/// `PATCH /environments/{env_id}/extensions` — replace an existing
/// extension binding identified by the body's key (A8 route 15). The
/// keyed extension verbs carry the key in the body rather than the URL
/// because `kind_path` contains `/` (the PR-3b client pinned this shape).
pub(crate) async fn update_extension_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<ExtensionKeyedPayload>,
) -> Result<Response, ApiError> {
    let Some(binding) = payload.binding else {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: "update requires `binding` in the request body".to_string(),
        }));
    };
    let key = payload.key;
    binding_mutation(state, env_id, headers, "update", "extensions", |env| {
        let target = json!({"kind_path": key.kind_path, "instance_id": key.instance_id});
        let (binding, generation) = engine::update_extension_binding(env, &key, binding)?;
        Ok((
            BindingGenerationOutcome {
                binding,
                generation,
            },
            target,
        ))
    })
    .await
}

/// `DELETE /environments/{env_id}/extensions` — remove an extension
/// binding identified by the body's key (A8 route 16).
pub(crate) async fn remove_extension_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<ExtensionKeyedPayload>,
) -> Result<Response, ApiError> {
    let key = payload.key;
    binding_mutation(state, env_id, headers, "remove", "extensions", |env| {
        let target = json!({"kind_path": key.kind_path, "instance_id": key.instance_id});
        let (binding, generation) = engine::remove_extension_binding(env, &key)?;
        Ok((
            BindingGenerationOutcome {
                binding,
                generation,
            },
            target,
        ))
    })
    .await
}

/// `POST /environments/{env_id}/extensions/rollback` — restore an
/// extension binding's one-step-previous snapshot (A8 route 17).
pub(crate) async fn rollback_extension_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<ExtensionKeyedPayload>,
) -> Result<Response, ApiError> {
    let key = payload.key;
    binding_mutation(state, env_id, headers, "rollback", "extensions", |env| {
        let target = json!({"kind_path": key.kind_path, "instance_id": key.instance_id});
        let (binding, generation) = engine::rollback_extension_binding(env, &key)?;
        Ok((
            BindingGenerationOutcome {
                binding,
                generation,
            },
            target,
        ))
    })
    .await
}

// ---------------------------------------------------------------------------
// Handlers — bundle deployments (PR-4.2g)
// ---------------------------------------------------------------------------
//
// `add` and `update --revenue-share` carry the verb group's side effect:
// the signed, versioned revenue-policy artifact (B10). The server drives
// the SAME pure builder the LocalFS backend does
// (`greentic_operator_trust::revenue_policy::build_revenue_policy_version`)
// and stores the produced bytes in the `revenue_policies` table, with the
// trust root coming from the env's trust-root ROW (closed by default: no
// row ⇒ empty trust root ⇒ the builder refuses — run
// `POST …/trust-root/bootstrap` first) and the signature coming from the
// SERVER's operator key. Write order mirrors the LocalFS flock sequence:
// policy artifact first, env document (with the pinned ref) second — a CAS
// failure on the env write leaves an orphan policy row at the same
// version, which the retry overwrites (versions derive from the COMMITTED
// ref).

/// Map the shared revenue-policy builder's refusals onto the A8 wire
/// vocabulary. `env_id` contextualizes the not-trusted message the
/// backend-neutral builder cannot know.
fn map_revenue_policy_error(err: RevenuePolicyError, env_id: &EnvId) -> ApiError {
    ApiError(match err {
        RevenuePolicyError::OperatorKeyNotTrusted { key_id } => RemoteStoreError::Conflict {
            detail: format!(
                "operator key `{key_id}` is not trusted in env `{env_id}`; \
                 run the trust-root bootstrap verb first (`POST \
                 /environments/{env_id}/trust-root/bootstrap`)"
            ),
        },
        RevenuePolicyError::UnsafeSegment(_) | RevenuePolicyError::Spec(_) => {
            RemoteStoreError::InvalidRequest {
                detail: err.to_string(),
            }
        }
        RevenuePolicyError::VersionOverflow => RemoteStoreError::Conflict {
            detail: err.to_string(),
        },
        // Signing/serialization failures are server-side configuration or
        // bug territory, never the caller's fault.
        RevenuePolicyError::Sign(_) | RevenuePolicyError::Serialize(_) => {
            RemoteStoreError::Internal {
                message: err.to_string(),
            }
        }
    })
}

impl From<BundleError> for ApiError {
    fn from(err: BundleError) -> Self {
        Self(match err {
            // Create-shaped duplicate: resolve with `bundles update`.
            BundleError::AlreadyDeployed { .. } => RemoteStoreError::AlreadyExists {
                detail: err.to_string(),
            },
            // The environment was loaded; only the deployment is missing.
            BundleError::DeploymentNotFound { .. } => RemoteStoreError::DependentNotFound {
                detail: err.to_string(),
            },
            BundleError::StillLive { .. } => RemoteStoreError::Conflict {
                detail: err.to_string(),
            },
        })
    }
}

fn parse_deployment_id(raw: &str) -> Result<DeploymentId, ApiError> {
    raw.parse::<ulid::Ulid>().map(DeploymentId).map_err(|err| {
        ApiError(RemoteStoreError::InvalidRequest {
            detail: format!("invalid deployment id `{raw}`: {err}"),
        })
    })
}

/// Build + persist the next revenue-policy version for `deployment` and
/// return the built artifact (the caller pins `policy_ref` on the
/// deployment before persisting the env). Trust root comes from the env's
/// row — absent row decodes to an EMPTY trust root, so the shared builder
/// refuses closed-by-default until the env is bootstrapped.
async fn write_revenue_policy<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    deployment: &BundleDeployment,
    created_at: chrono::DateTime<Utc>,
) -> Result<revenue_policy::BuiltRevenuePolicyVersion, ApiError> {
    let trust_root = match state
        .storage
        .load_trust_root(env_id)
        .await
        .map_err(load_storage_error)?
    {
        Some(loaded) => loaded.value.into_trust_root()?,
        None => TrustRoot::default(),
    };
    let operator_key = load_server_operator_key(state.operator_key_path.clone()).await?;
    let built = revenue_policy::build_revenue_policy_version(
        deployment,
        &deployment.revenue_share,
        created_at,
        &operator_key,
        &trust_root,
    )
    .map_err(|err| map_revenue_policy_error(err, env_id))?;
    state
        .storage
        .upsert_revenue_policy(
            env_id,
            &RevenuePolicyArtifact {
                bundle_id: deployment.bundle_id.clone(),
                customer_id: deployment.customer_id.clone(),
                version: built.version,
                policy_ref: built.policy_ref.to_string_lossy().replace('\\', "/"),
                doc: built.doc_bytes.clone(),
                envelope: built.envelope_bytes.clone(),
                doc_sha256: built.doc_sha256.clone(),
                key_id: built.key_id.clone(),
            },
        )
        .await?;
    Ok(built)
}

/// `POST /environments/{env_id}/bundles` — deploy a bundle for a customer
/// (A8 route 7). The server mints the [`DeploymentId`] (the wire payload
/// carries none) and writes the v1 revenue-policy artifact.
pub(crate) async fn add_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<engine::AddBundlePayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    let now = Utc::now();
    let idx = engine::add_bundle(&mut env, payload, DeploymentId::new(), now)?;
    let built = write_revenue_policy(&state, &env_id, &env.bundles[idx], now).await?;
    env.bundles[idx].revenue_policy_ref = built.policy_ref;
    let precondition = resolve_precondition(client_etag, &loaded.revision);
    let revision = state.storage.update_env(&env, &precondition).await?;
    let deployment = env.bundles[idx].clone();
    let target = json!({
        "environment_id": env_id,
        "deployment_id": deployment.deployment_id,
        "bundle_id": deployment.bundle_id,
        "customer_id": deployment.customer_id,
        "revenue_policy_version": built.version,
    });
    Ok(mutation_response(
        deployment,
        &env_id,
        "bundles",
        "add",
        target,
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

/// `PATCH /environments/{env_id}/bundles/{deployment_id}` — patch a
/// deployment's scalar fields (A8 route 8). A `revenue_share` patch writes
/// the next chained revenue-policy version. The body's `deployment_id` is
/// cross-checked against the URL segment (the warm-revision precedent).
pub(crate) async fn update_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, deployment_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<engine::UpdateBundlePayload>,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let url_deployment_id = parse_deployment_id(&deployment_id)?;
    if payload.deployment_id != url_deployment_id {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: format!(
                "body deployment_id `{}` does not match URL deployment_id `{url_deployment_id}`",
                payload.deployment_id
            ),
        }));
    }
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    let applied = engine::update_bundle(&mut env, payload)?;
    let idx = applied.index;
    let mut policy_version = None;
    if applied.revenue_share_changed {
        let built = write_revenue_policy(&state, &env_id, &env.bundles[idx], Utc::now()).await?;
        policy_version = Some(built.version);
        env.bundles[idx].revenue_policy_ref = built.policy_ref;
    }
    let precondition = resolve_precondition(client_etag, &loaded.revision);
    let revision = state.storage.update_env(&env, &precondition).await?;
    let deployment = env.bundles[idx].clone();
    let target = json!({
        "environment_id": env_id,
        "deployment_id": deployment.deployment_id,
        "revenue_policy_version": policy_version,
    });
    Ok(mutation_response(
        deployment,
        &env_id,
        "bundles",
        "update",
        target,
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

/// `DELETE /environments/{env_id}/bundles/{deployment_id}` — remove a
/// quiesced deployment (A8 route 9). Refuses while live state remains;
/// the pruned archived-revision ids ride the outcome AND the audit target
/// so the destructive compaction is explicit.
pub(crate) async fn remove_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, deployment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let env_id = parse_env_id(&env_id)?;
    let deployment_id = parse_deployment_id(&deployment_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    let outcome = engine::remove_bundle(&mut env, deployment_id)?;
    let precondition = resolve_precondition(client_etag, &loaded.revision);
    let revision = state.storage.update_env(&env, &precondition).await?;
    let target = json!({
        "environment_id": env_id,
        "deployment_id": deployment_id,
        "pruned_revision_ids": outcome.pruned_revision_ids,
    });
    Ok(mutation_response(
        outcome,
        &env_id,
        "bundles",
        "remove",
        target,
        idem_key,
        Some(previous_generation),
        revision,
    ))
}

// ---------------------------------------------------------------------------
// Handlers — trust root (PR-4.2f)
// ---------------------------------------------------------------------------
//
// The trust root is an env-scoped sidecar resource (the server analogue of
// the LocalFS `<env_dir>/trust-root.json`): its verbs never touch the
// environment document. The mutation envelope therefore echoes the ENV's
// unchanged CAS coordinates (previous == new generation — mirroring the
// local path, whose trust-root audit records carry no generations), while
// the trust-root row's OWN generation/etag pins the upsert internally so
// concurrent trust-root mutations that carry a CAS pin conflict with a 412
// like every other verb group. First-write races (load returns None,
// concurrent writer inserts before this writer) are detected as
// `PreconditionRequired` with no precondition — an unambiguous signal
// because trust-root rows are never deleted — and converge
// deterministically via a single reload-and-retry (the retry carries a CAS
// pin, so a second conflict surfaces as an honest 412). The pure semantics
// (key-id canonicalization, validation, add/remove transforms) come from
// `greentic-operator-trust` — the same functions `LocalFsStore` drives,
// per the same-derivation rule.

/// Decoded preamble shared by the four trust-root mutations: the
/// idempotency key, the parsed env id, the env's CAS coordinates (the
/// `load_env` doubles as the 404 existence gate), and the current
/// trust-root row if one exists.
struct TrustRootRequest {
    idem_key: String,
    env_id: EnvId,
    env_revision: EnvRevision,
    current: Option<LoadedTrustRoot>,
}

async fn load_trust_root_request<S: EnvironmentStorage>(
    state: &AppState<S>,
    raw_env_id: &str,
    headers: &HeaderMap,
) -> Result<TrustRootRequest, ApiError> {
    let idem_key = require_idempotency_key(headers)?;
    let env_id = parse_env_id(raw_env_id)?;
    let env = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    let current = state
        .storage
        .load_trust_root(&env_id)
        .await
        .map_err(load_storage_error)?;
    Ok(TrustRootRequest {
        idem_key,
        env_id,
        env_revision: env.revision,
        current,
    })
}

/// Split the loaded row into a workable document plus the CAS pin for the
/// follow-up upsert (`None` = create-if-absent first write).
fn doc_and_precondition(
    current: Option<LoadedTrustRoot>,
) -> (TrustRootDocument, Option<Precondition>) {
    match current {
        Some(loaded) => (
            loaded.value,
            Some(Precondition::matching(
                loaded.revision.etag,
                loaded.revision.generation,
            )),
        ),
        None => (TrustRootDocument::v1(Vec::new()), None),
    }
}

/// Load (or first-time generate) the SERVER's operator signing key — the
/// remote analogue of the CLI's `operator_key::load_or_generate`. The
/// PR-3b wire contract sends NO body on bootstrap/seed: the key is the
/// server's identity, never the caller's. Key-file I/O (and a possible
/// keygen) runs on the blocking pool.
async fn load_server_operator_key(path: Option<Arc<PathBuf>>) -> Result<OperatorKey, ApiError> {
    let loaded = tokio::task::spawn_blocking(move || match path {
        Some(path) => operator_key::load_or_generate_at(&path),
        None => operator_key::load_or_generate(),
    })
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "operator-key loader task failed");
        operator_key_unavailable()
    })?;
    loaded.map_err(|err| {
        // Filesystem detail stays in the log, not on the wire.
        tracing::error!(error = %err, "server operator key unavailable");
        operator_key_unavailable()
    })
}

fn operator_key_unavailable() -> ApiError {
    ApiError(RemoteStoreError::Internal {
        message: "server operator key unavailable".to_string(),
    })
}

/// What a trust-root writer does when its first write races a concurrent
/// creator (the row appeared between load and write).
enum FirstWriteRace {
    /// `bootstrap` / `add` — reload and reapply under the CAS pin (the
    /// local flock-serialized backend converges the same way).
    Retry,
    /// `seed` — the gate flipped concurrently; the verb's contract is
    /// the silent `null` no-op, exactly as if the row had existed at
    /// load time.
    NoOp,
}

/// Apply `mutate` to the current document and persist it, converging
/// concurrent first writes. `PreconditionRequired` from an unpinned upsert
/// can only mean the row appeared between the handler's load and this
/// write (see `doc_and_precondition`); on that signal `Retry` reloads and
/// reapplies, `NoOp` returns `None`. Terminates after at most 2
/// iterations: trust-root rows are never deleted, so after a race the
/// reload returns `Some` → the retry carries a CAS pin → the race guard
/// cannot fire again, and a second conflict surfaces as an honest 412.
async fn persist_trust_root_mutation<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    mut current: Option<LoadedTrustRoot>,
    on_race: FirstWriteRace,
    mutate: impl Fn(&mut TrustRootDocument),
) -> Result<Option<TrustRootDocument>, ApiError> {
    loop {
        let (mut doc, precondition) = doc_and_precondition(current);
        mutate(&mut doc);
        match state
            .storage
            .upsert_trust_root(env_id, &doc, precondition.as_ref())
            .await
        {
            Ok(_revision) => return Ok(Some(doc)),
            Err(StorageError::PreconditionRequired) if precondition.is_none() => match on_race {
                FirstWriteRace::NoOp => return Ok(None),
                FirstWriteRace::Retry => {
                    current = state
                        .storage
                        .load_trust_root(env_id)
                        .await
                        .map_err(load_storage_error)?;
                }
            },
            Err(err) => return Err(err.into()),
        }
    }
}

/// Shared body of bootstrap/seed: add the server operator key to the
/// (possibly fresh) document — idempotent re-grant on case-insensitive
/// `key_id` collision — and persist under the row's CAS pin. Returns
/// `None` only when a [`FirstWriteRace::NoOp`] seed observes the
/// concurrent first write (the row it could not see at load time).
async fn grant_operator_key<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    current: Option<LoadedTrustRoot>,
    on_race: FirstWriteRace,
) -> Result<Option<TrustRootSeed>, ApiError> {
    let op_key = load_server_operator_key(state.operator_key_path.clone()).await?;
    let entry = trust_root::validate_trusted_key(TrustedKey {
        key_id: op_key.key_id.clone(),
        public_key_pem: op_key.public_pem.clone(),
    })?;
    let Some(doc) = persist_trust_root_mutation(state, env_id, current, on_race, |doc| {
        trust_root::apply_add(&mut doc.keys, entry.clone());
    })
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(TrustRootSeed {
        key_id: op_key.key_id,
        public_key_pem: op_key.public_pem,
        trusted_key_count: doc.keys.len(),
    }))
}

/// `POST /environments/{env_id}/trust-root/bootstrap` — load (or generate)
/// the server operator key and grant it on the env trust root (A8 route
/// 18). Idempotent re-grant, mirroring `LocalFsStore::bootstrap_trust_root`.
pub(crate) async fn bootstrap_trust_root<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let req = load_trust_root_request(&state, &env_id, &headers).await?;
    let seed = grant_operator_key(&state, &req.env_id, req.current, FirstWriteRace::Retry)
        .await?
        .expect("Retry mode always grants");
    let target = json!({"environment_id": req.env_id, "key_id": seed.key_id});
    Ok(mutation_response(
        seed,
        &req.env_id,
        "trust-root",
        "bootstrap",
        target,
        req.idem_key,
        Some(req.env_revision.generation),
        req.env_revision,
    ))
}

/// `POST /environments/{env_id}/trust-root/seed` — first-init-only variant
/// (A8 route 19): a `null` result when a trust root already exists
/// (operator has touched it via bootstrap/add/remove), the freshly granted
/// seed otherwise. Row existence is the gate — the server analogue of the
/// LocalFS `trust-root.json` existence check.
pub(crate) async fn seed_trust_root<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let req = load_trust_root_request(&state, &env_id, &headers).await?;
    let seed = match req.current {
        Some(_) => None,
        None => grant_operator_key(&state, &req.env_id, None, FirstWriteRace::NoOp).await?,
    };
    let mut target = json!({"environment_id": req.env_id});
    if let (Some(seed), Value::Object(map)) = (&seed, &mut target) {
        map.insert("key_id".to_string(), json!(seed.key_id));
    }
    Ok(mutation_response(
        seed,
        &req.env_id,
        "trust-root",
        "seed",
        target,
        req.idem_key,
        Some(req.env_revision.generation),
        req.env_revision,
    ))
}

/// `POST /environments/{env_id}/trust-root/keys` — validate and add a
/// caller-supplied `(key_id, public_key_pem)` entry (A8 route 20).
/// Idempotent on case-insensitive `key_id` collision (the PEM is
/// replaced). The stored entry carries the canonical lowercase id; the
/// outcome echoes the caller's form, mirroring `LocalFsStore`.
pub(crate) async fn add_trusted_key<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<AddTrustedKeyPayload>,
) -> Result<Response, ApiError> {
    let req = load_trust_root_request(&state, &env_id, &headers).await?;
    let supplied_key_id = payload.key_id.clone();
    let entry = trust_root::validate_trusted_key(TrustedKey {
        key_id: payload.key_id,
        public_key_pem: payload.public_key_pem,
    })?;
    // The audit target carries the full PEM so a later-removed key can be
    // reconstructed from the audit log alone — same recovery rationale as
    // the local CLI's audit target.
    let target = json!({
        "environment_id": req.env_id,
        "key_id": supplied_key_id,
        "public_key_pem": entry.public_key_pem,
    });

    let doc = persist_trust_root_mutation(
        &state,
        &req.env_id,
        req.current,
        FirstWriteRace::Retry,
        |doc| {
            trust_root::apply_add(&mut doc.keys, entry.clone());
        },
    )
    .await?
    .expect("Retry mode always persists");
    let outcome = TrustRootAddOutcome {
        added_key_id: supplied_key_id,
        trusted_key_count: doc.keys.len(),
    };
    Ok(mutation_response(
        outcome,
        &req.env_id,
        "trust-root",
        "add",
        target,
        req.idem_key,
        Some(req.env_revision.generation),
        req.env_revision,
    ))
}

/// `DELETE /environments/{env_id}/trust-root/keys/{key_id}` — remove a
/// trusted key by case-insensitive id (A8 route 21). Silent no-op when the
/// id is absent; the pre-removal PEM is captured for the outcome's
/// recovery material. A no-op never persists — it must not materialize a
/// trust-root row where none existed (row absence is the seed gate).
pub(crate) async fn remove_trusted_key<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let req = load_trust_root_request(&state, &env_id, &headers).await?;
    let (mut doc, precondition) = doc_and_precondition(req.current);
    let removed_public_key_pem = doc
        .keys
        .iter()
        .find(|k| k.key_id.eq_ignore_ascii_case(&key_id))
        .map(|k| k.public_key_pem.clone());
    if trust_root::apply_remove(&mut doc.keys, &key_id) {
        state
            .storage
            .upsert_trust_root(&req.env_id, &doc, precondition.as_ref())
            .await?;
    }
    let target = json!({"environment_id": req.env_id, "key_id": key_id});
    let outcome = TrustRootRemoveOutcome {
        removed_key_id: key_id,
        removed_public_key_pem,
        trusted_key_count: doc.keys.len(),
    };
    Ok(mutation_response(
        outcome,
        &req.env_id,
        "trust-root",
        "remove",
        target,
        req.idem_key,
        Some(req.env_revision.generation),
        req.env_revision,
    ))
}

// ---------------------------------------------------------------------------
// Handlers — reads
// ---------------------------------------------------------------------------

/// `GET /environments` — list persisted env ids. Plain JSON (reads carry no
/// mutation envelope or audit record).
pub(crate) async fn list_environments<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
) -> Result<Json<Value>, ApiError> {
    let envs = state.storage.list_envs().await?;
    Ok(Json(json!({ "environments": envs })))
}

/// `GET /environments/{env_id}` — load one env with its CAS coordinates,
/// so a client can build the `Precondition` for its next write. This is
/// the "GET-env read endpoint" the remote dispatch's blocked verbs
/// (`revisions stage`/`warm`) name as their missing prerequisite.
pub(crate) async fn get_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
) -> Result<Json<GetEnvironmentResponse>, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let loaded = state
        .storage
        .load_env(&env_id)
        .await
        .map_err(load_storage_error)?;
    Ok(Json(GetEnvironmentResponse {
        environment: loaded.value,
        etag: loaded.revision.etag,
        generation: loaded.revision.generation,
    }))
}

/// `GET /environments/{env_id}` response body.
#[derive(Debug, Serialize)]
pub struct GetEnvironmentResponse {
    pub environment: Environment,
    pub etag: StateEtag,
    pub generation: u64,
}

/// `GET /environments/{env_id}/trust-root` — list the env's trusted keys.
/// An absent row reads as an empty key set (closed-by-default, mirroring
/// the LocalFS `load`), while a missing ENV is still a 404. Plain JSON in
/// the local CLI's `trust-root list` shape; the remote-dispatch `list`
/// verb wires up to this in the read-verbs follow-up.
pub(crate) async fn get_trust_root<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    if !state.storage.exists(&env_id).await? {
        return Err(ApiError(RemoteStoreError::NotFound));
    }
    let keys = state
        .storage
        .load_trust_root(&env_id)
        .await
        .map_err(load_storage_error)?
        .map(|loaded| loaded.value.keys)
        .unwrap_or_default();
    Ok(Json(json!({"environment_id": env_id, "keys": keys})))
}
