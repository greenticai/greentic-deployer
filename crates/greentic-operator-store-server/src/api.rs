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

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use greentic_deploy_spec::engine::{self, EngineError};
use greentic_deploy_spec::{
    Actor, AuditDecision, AuditEvent, AuditResult, ConcurrencyConflict, CreateEnvironmentPayload,
    EnvId, Environment, HealthStatus, IdempotencyOutcome, MigrateMergePayload, Precondition,
    RemoteStoreError, RetentionPolicy, RevocationConfig, SchemaVersion, StateEtag,
    UpdateEnvironmentPayload,
};

use crate::http::AppState;
use crate::storage::{EnvRevision, EnvironmentStorage, StorageError};

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
