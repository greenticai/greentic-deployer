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
//! are accepted and echoed into the audit record, not yet cached), RBAC
//! (PR-4.4 — every decision is an honest `Allow{policy: "open-dev"}`), and
//! the audit log's durable append (PR-4.3).

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
    Actor, AuditDecision, AuditEvent, AuditResult, CreateEnvironmentPayload, EnvId, Environment,
    HealthStatus, IdempotencyOutcome, MigrateMergePayload, Precondition, RemoteStoreError,
    RetentionPolicy, RevocationConfig, SchemaVersion, StateEtag, UpdateEnvironmentPayload,
};

use crate::http::AppState;
use crate::storage::{EnvironmentStorage, StorageError};

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

/// Build the audit record embedded in every 2xx mutation response. The
/// client binds it back to the request: `env_id` must match the target env
/// and `idempotency_key` must equal the request's `Idempotency-Key` header.
#[allow(clippy::too_many_arguments)]
fn audit_event(
    env_id: &EnvId,
    noun: &str,
    verb: &str,
    target: Value,
    idempotency_key: Option<String>,
    previous_generation: Option<u64>,
    new_generation: u64,
) -> AuditEvent {
    AuditEvent {
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
        new_generation: Some(new_generation),
        idempotency_key,
        authorization: AuditDecision::Allow {
            policy: POLICY_OPEN_DEV.to_string(),
            reason: "RBAC not yet enforced (PR-4.4)".to_string(),
        },
        result: AuditResult::Ok,
    }
}

/// Pull the `Idempotency-Key` header (PR-4.3 adds replay; today the key is
/// echoed into the audit record so the client's binding check passes).
fn idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
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
    let audit = audit_event(
        &env.environment_id,
        "env",
        "create",
        json!({"environment_id": env.environment_id}),
        idempotency_key(&headers),
        None,
        revision.generation,
    );
    Ok(Json(MutationEnvelope {
        result: env,
        etag: revision.etag,
        generation: revision.generation,
        idempotency: IdempotencyOutcome::Applied,
        audit,
    })
    .into_response())
}

/// `PATCH /environments/{env_id}` — tri-state field patch (A8 route 2).
pub(crate) async fn update_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(patch): ApiJson<UpdateEnvironmentPayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let loaded = state.storage.load_env(&env_id).await?;
    let previous_generation = loaded.revision.generation;
    let mut env = loaded.value;
    engine::apply_environment_update(&mut env, patch);
    // CAS against the revision we just loaded: a concurrent writer between
    // our load and this update surfaces as 412 instead of a lost update.
    let precondition = Precondition::matching(loaded.revision.etag, previous_generation);
    let revision = state.storage.update_env(&env, &precondition).await?;
    let audit = audit_event(
        &env_id,
        "env",
        "update",
        json!({"environment_id": env_id}),
        idempotency_key(&headers),
        Some(previous_generation),
        revision.generation,
    );
    Ok(Json(MutationEnvelope {
        result: env,
        etag: revision.etag,
        generation: revision.generation,
        idempotency: IdempotencyOutcome::Applied,
        audit,
    })
    .into_response())
}

/// `POST /environments/{env_id}/migrate-bindings` — merge pack/extension
/// bindings, optionally seeding a missing target (A8 route 3).
pub(crate) async fn migrate_bindings<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<MigrateMergePayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let existing = match state.storage.load_env(&env_id).await {
        Ok(loaded) => Some(loaded),
        Err(StorageError::NotFound(_)) => None,
        Err(err) => return Err(err.into()),
    };
    let prior_revision = existing.as_ref().map(|l| l.revision.clone());
    let mut env =
        engine::seed_or_existing(existing.map(|l| l.value), &env_id, payload.seed_if_missing)?;
    let report = engine::merge_bindings(&mut env, payload.packs, payload.extensions);
    let revision = match &prior_revision {
        Some(prior) => {
            let precondition = Precondition::matching(prior.etag.clone(), prior.generation);
            state.storage.update_env(&env, &precondition).await?
        }
        None => state.storage.create_env(&env).await?,
    };
    let audit = audit_event(
        &env_id,
        "env",
        "migrate-bindings",
        json!({
            "environment_id": env_id,
            "merged_slots": report.merged_slots,
            "merged_extensions": report.merged_extensions,
        }),
        idempotency_key(&headers),
        prior_revision.map(|r| r.generation),
        revision.generation,
    );
    Ok(Json(MutationEnvelope {
        result: report,
        etag: revision.etag,
        generation: revision.generation,
        idempotency: IdempotencyOutcome::Applied,
        audit,
    })
    .into_response())
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
    let loaded = state.storage.load_env(&env_id).await?;
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
