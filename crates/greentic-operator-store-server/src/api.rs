//! A8 route handlers — environment-lifecycle verb group (PR-4.2a).
//!
//! Each mutation handler follows the same shape across every verb group:
//!
//! 1. decode the shared wire payload (`greentic_deploy_spec::engine` types —
//!    the SAME structs the `HttpEnvironmentStore` client serializes),
//!    capturing the request's [`RequestFingerprint`] on the way through;
//! 2. run [`authorize_mutation`] (A8 #3, PR-4.4): the
//!    [`crate::rbac::RbacEngine`] authenticates the bearer token and checks
//!    the role against `noun.verb`. A denial is a typed 403 whose audit
//!    record is STILL appended durably ("the rejected attempt is still
//!    audited") — but never ledgered, so the key stays free. Authorization
//!    runs BEFORE the replay gate: an unauthorized caller can replay
//!    nothing;
//! 3. run the [`replay_gate`] (A8 §2, PR-4.3): a key already consumed by a
//!    committed mutation replays its ledgered response verbatim (marker
//!    flipped to `replayed`), any other reuse is a typed 409;
//! 4. load current state from [`EnvironmentStorage`];
//! 5. apply the pure `greentic_deploy_spec::engine` transform (identical to
//!    what `LocalFsStore` runs);
//! 6. build the A8 mutation envelope `{result, etag, generation,
//!    idempotency, audit}` BEFORE the commit (sound because the post-commit
//!    revision is deterministic under the fully pinned precondition — see
//!    [`next_revision`]) — the PR-4.0 client rejects any 2xx whose audit
//!    record is missing, denied, non-ok, or names the wrong env/key;
//! 7. persist under a CAS precondition pinned to the loaded revision,
//!    with the [`MutationJournal`] (the ledger row + the durable audit-log
//!    append) committing in the SAME transaction — a committed mutation can
//!    never lack its replay entry or its audit row, and a rolled-back one
//!    never leaves either.
//!
//! Errors travel as [`RemoteStoreError`] JSON with the matching HTTP status
//! (the client enforces status↔body consistency); they are never ledgered —
//! except the warm health gate's committed-on-error 422, whose persisted
//! `Failed` flip consumes the key like any commit.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use greentic_deploy_spec::engine::{
    self, BindingError, BundleError, EngineError, MessagingError, RevisionLifecycleError,
    TrafficSplitError,
};
use greentic_deploy_spec::{
    AddMessagingEndpointPayload, AddTrustedKeyPayload, ApplyTrafficSplitOutcome, AuditDecision,
    AuditEvent, AuditResult, BackupArtifact, BackupManifest, BindingGenerationOutcome,
    BundleDeployment, CapabilitySlot, ConcurrencyConflict, CreateEnvironmentPayload, DeploymentId,
    EnvId, Environment, EnvironmentRuntime, ExtensionBindingPayload, ExtensionKeyedPayload,
    HealthStatus, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord, ImportOutcome,
    ImportRequest, MessagingBundleLinkPayload, MessagingEndpointId, MigrateMergePayload,
    PackBindingPayload, Precondition, RemoteStoreError, RestoreOutcome, RestoreRequest,
    RetentionPolicy, RevisionId, RevisionTransitionOutcome, RevocationConfig,
    RollbackTrafficSplitOutcome, RollbackTrafficSplitPayload, RotateWebhookSecretPayload,
    SchemaVersion, SecretRef, SetMessagingWelcomeFlowPayload, SetTrafficSplitPayload,
    StageRevisionPayload, StateEtag, StateIntegrity, TrustRootAddOutcome, TrustRootRemoveOutcome,
    TrustRootSeed, UpdateEnvironmentPayload, WarmRevisionPayload,
};
use greentic_operator_trust::operator_key::{self, OperatorKey};
use greentic_operator_trust::revenue_policy::{self, RevenuePolicyError};
use greentic_operator_trust::trust_root::{
    self, TrustRoot, TrustRootDocError, TrustRootDocument, TrustedKey,
};

use crate::http::AppState;
use crate::rbac::{AuthContext, RbacDenial};
use crate::storage::{
    EnvRevision, EnvironmentStorage, LoadedTrustRoot, MutationJournal, RevenuePolicyArtifact,
    StorageError, StoredBackup,
};

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
        // Retryable: a concurrent trust-root mutation (e.g. revocation)
        // raced a signing commit; the caller reloads and re-evaluates.
        err @ StorageError::TrustRootChanged { .. } => RemoteStoreError::Conflict {
            detail: err.to_string(),
        },
        // A concurrent request committed the same key first (the ledger
        // insert lost the race); the retry replays its stored response.
        err @ StorageError::IdempotencyKeyCommitted { .. } => {
            RemoteStoreError::IdempotencyConflict {
                reason: err.to_string(),
            }
        }
        // The backup cap refuses new creates instead of evicting recovery
        // points; the operator deletes old backups and retries.
        err @ StorageError::BackupLimitReached { .. } => RemoteStoreError::Conflict {
            detail: err.to_string(),
        },
        // Backend/serde internals stay opaque — no driver details on the wire.
        StorageError::Integrity(_) | StorageError::Json(_) | StorageError::Backend(_) => {
            RemoteStoreError::Internal {
                message: "internal store error".to_string(),
            }
        }
    }
}

/// Canonical request identity for the replay ledger (A8 §2): SHA-256 over
/// `{method, path, body}` via the contract's hashing helper
/// ([`IdempotencyRecord::fingerprint`]), so a same-key retry of the same
/// request replays regardless of JSON formatting, while the same key on a
/// different body, path, or method is a `409 idempotency-conflict`.
/// Headers — `If-Match` included — are deliberately excluded: a replay
/// returns an already-committed response whose precondition was enforced
/// at first execution.
#[derive(Debug, Clone)]
pub(crate) struct RequestFingerprint(String);

impl RequestFingerprint {
    /// Bodyless requests hash the body as JSON `null`, matching the
    /// client's body-free sends.
    fn compute(method: &Method, path: &str, body: &Value) -> Result<Self, ApiError> {
        let canonical = json!({"method": method.as_str(), "path": path, "body": body});
        IdempotencyRecord::fingerprint(&canonical)
            .map(Self)
            .map_err(|err| {
                tracing::error!(error = %err, "request fingerprint hashing failed");
                ApiError(RemoteStoreError::Internal {
                    message: "request fingerprint hashing failed".to_string(),
                })
            })
    }
}

/// `Json<T>` with the rejection mapped to the typed A8 400 body, capturing
/// the request's [`RequestFingerprint`] on the way through — extraction
/// consumes the body, so this is the one place its canonical `Value` is
/// available.
pub(crate) struct ApiJson<T>(pub(crate) T, pub(crate) RequestFingerprint);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let Json(body): Json<Value> = Json::from_request(req, state).await?;
        let fingerprint = RequestFingerprint::compute(&method, &path, &body)?;
        let payload: T = serde_json::from_value(body).map_err(|err| {
            ApiError(RemoteStoreError::InvalidRequest {
                detail: format!("invalid request body: {err}"),
            })
        })?;
        Ok(ApiJson(payload, fingerprint))
    }
}

/// [`RequestFingerprint`] extractor for bodyless mutations (DELETEs and the
/// body-free POST verbs).
pub(crate) struct Fingerprint(pub(crate) RequestFingerprint);

impl<S: Send + Sync> FromRequestParts<S> for Fingerprint {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        RequestFingerprint::compute(&parts.method, parts.uri.path(), &Value::Null).map(Self)
    }
}

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

/// A mutation response built BEFORE its commit: the response to send plus
/// the [`MutationJournal`] (ledger + audit rows) that must land inside the
/// commit's transaction. Building first is what makes the ledgered
/// response exact — and it is sound because the post-commit revision is
/// deterministic under the fully pinned [`resolve_precondition`] CAS
/// (see [`next_revision`]).
struct PreparedMutation {
    status: StatusCode,
    body: Value,
    journal: MutationJournal,
}

impl PreparedMutation {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

/// Build the 2xx mutation envelope (the audit record — bound to the
/// request via `env_id` + the `Idempotency-Key`, which the PR-4.0 client
/// validates — wrapped in the A8 `{result, etag, generation, idempotency,
/// audit}` shape) together with its journal rows. One call per handler so
/// every verb group shares the exact shape.
#[allow(clippy::too_many_arguments)]
fn prepare_mutation<T: Serialize>(
    result: T,
    env_id: &EnvId,
    noun: &str,
    verb: &str,
    target: Value,
    idempotency_key: String,
    fingerprint: &RequestFingerprint,
    auth: &AuthContext,
    previous_generation: Option<u64>,
    revision: EnvRevision,
) -> Result<PreparedMutation, ApiError> {
    let audit = AuditEvent {
        schema: SchemaVersion::AUDIT_EVENT_V1.into(),
        event_id: ulid::Ulid::new().to_string(),
        ts: Utc::now(),
        actor: auth.actor.clone(),
        env_id: env_id.as_str().to_string(),
        noun: noun.to_string(),
        verb: verb.to_string(),
        target,
        previous_generation,
        new_generation: Some(revision.generation),
        idempotency_key: Some(idempotency_key.clone()),
        authorization: auth.decision.clone(),
        result: AuditResult::Ok,
    };
    let audit_event = serde_json::to_value(&audit).map_err(envelope_encode_error)?;
    let audit_event_id = audit.event_id.clone();
    let body = serde_json::to_value(MutationEnvelope {
        result,
        etag: revision.etag,
        generation: revision.generation,
        idempotency: IdempotencyOutcome::Applied,
        audit,
    })
    .map_err(envelope_encode_error)?;
    Ok(PreparedMutation {
        status: StatusCode::OK,
        body: body.clone(),
        journal: MutationJournal {
            env_id: env_id.clone(),
            idempotency_key,
            operation: format!("{noun}.{verb}"),
            request_fingerprint: fingerprint.0.clone(),
            response_status: StatusCode::OK.as_u16(),
            response_body: body,
            audit_event,
            audit_event_id,
        },
    })
}

/// Build a COMMITTED-on-error response (the warm health gate's `Failed`
/// flip): the mutation persists, so the key is consumed, the typed error
/// body becomes the ledgered response — replayed verbatim, it carries no
/// `idempotency` field — and the audit append records the non-ok outcome.
#[allow(clippy::too_many_arguments)]
fn prepare_committed_error(
    error: &RemoteStoreError,
    env_id: &EnvId,
    noun: &str,
    verb: &str,
    target: Value,
    idempotency_key: String,
    fingerprint: &RequestFingerprint,
    auth: &AuthContext,
    previous_generation: Option<u64>,
    new_generation: u64,
) -> Result<PreparedMutation, ApiError> {
    let body = serde_json::to_value(error).map_err(envelope_encode_error)?;
    let kind = body["kind"].as_str().unwrap_or("internal").to_string();
    let audit = AuditEvent {
        schema: SchemaVersion::AUDIT_EVENT_V1.into(),
        event_id: ulid::Ulid::new().to_string(),
        ts: Utc::now(),
        actor: auth.actor.clone(),
        env_id: env_id.as_str().to_string(),
        noun: noun.to_string(),
        verb: verb.to_string(),
        target,
        previous_generation,
        new_generation: Some(new_generation),
        idempotency_key: Some(idempotency_key.clone()),
        authorization: auth.decision.clone(),
        result: AuditResult::Error {
            kind,
            message: error.to_string(),
        },
    };
    let audit_event_id = audit.event_id.clone();
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok(PreparedMutation {
        status,
        body: body.clone(),
        journal: MutationJournal {
            env_id: env_id.clone(),
            idempotency_key,
            operation: format!("{noun}.{verb}"),
            request_fingerprint: fingerprint.0.clone(),
            response_status: status.as_u16(),
            response_body: body,
            audit_event: serde_json::to_value(&audit).map_err(envelope_encode_error)?,
            audit_event_id,
        },
    })
}

fn envelope_encode_error(err: serde_json::Error) -> ApiError {
    tracing::error!(error = %err, "mutation envelope failed to serialize");
    ApiError(RemoteStoreError::Internal {
        message: "mutation envelope failed to serialize".to_string(),
    })
}

/// The replay gate (A8 §2), run before any state is loaded. A key already
/// consumed by a committed mutation either replays that mutation's stored
/// response verbatim — only the `idempotency` marker flips to `replayed`;
/// everything else, original audit record included, is untouched — or, on
/// a fingerprint mismatch, rejects the reuse with the typed 409. Failed
/// requests are never ledgered, so their keys retry freely.
async fn replay_gate<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    idem_key: &str,
    fingerprint: &RequestFingerprint,
) -> Result<Option<Response>, ApiError> {
    let record = state
        .storage
        .lookup_idempotency(env_id, idem_key)
        .await
        .map_err(load_storage_error)?;
    let Some(record) = record else {
        return Ok(None);
    };
    if record.request_fingerprint != fingerprint.0 {
        return Err(ApiError(RemoteStoreError::IdempotencyConflict {
            reason: format!(
                "idempotency key `{idem_key}` was already used by a different \
                 `{}` request on env `{env_id}`; pass a fresh key",
                record.operation
            ),
        }));
    }
    let mut body = record.response_body;
    // Success envelopes flip their marker; committed-on-error bodies have
    // no `idempotency` field and replay byte-identical.
    if body.get("idempotency").is_some() {
        body["idempotency"] = serde_json::to_value(IdempotencyOutcome::Replayed)
            .expect("IdempotencyOutcome serializes");
    }
    let status =
        StatusCode::from_u16(record.response_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok(Some((status, Json(body)).into_response()))
}

/// Converge a post-gate failure onto the replay contract: when the
/// mutation failed but the ledger MEANWHILE holds a fingerprint-matching
/// row for this `(env, key)`, a concurrent duplicate of the SAME request
/// won the race — the operation committed, so replay the winner's
/// response instead of surfacing a conflict the caller cannot act on.
/// Anything else (miss, fingerprint mismatch, lookup failure) surfaces
/// the original error: the recheck must never mask it.
async fn error_or_replay<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    idem_key: &str,
    fingerprint: &RequestFingerprint,
    err: ApiError,
) -> Result<Response, ApiError> {
    match replay_gate(state, env_id, idem_key, fingerprint).await {
        Ok(Some(replay)) => Ok(replay),
        Ok(None) | Err(_) => Err(err),
    }
}

/// The CAS coordinates `env` WILL have after a commit under a fully pinned
/// precondition: the etag derives from content exactly as the storage
/// layer derives it (`serialize → sha256`), and the generation is the
/// pinned one plus one. This determinism is what lets the journaled
/// response body be built BEFORE the commit and land inside the same
/// transaction.
fn next_revision(env: &Environment, loaded: &EnvRevision) -> Result<EnvRevision, ApiError> {
    Ok(EnvRevision {
        generation: loaded.generation + 1,
        etag: content_etag(env)?,
    })
}

/// [`next_revision`]'s create-shaped sibling: a fresh row is generation 1.
fn created_revision(env: &Environment) -> Result<EnvRevision, ApiError> {
    Ok(EnvRevision {
        generation: 1,
        etag: content_etag(env)?,
    })
}

fn content_etag(env: &Environment) -> Result<StateEtag, ApiError> {
    let data = serde_json::to_value(env).map_err(envelope_encode_error)?;
    let integrity = StateIntegrity::sha256_of(&data).map_err(|err| {
        tracing::error!(error = %err, "environment content hashing failed");
        ApiError(RemoteStoreError::Internal {
            message: "environment content hashing failed".to_string(),
        })
    })?;
    Ok(StateEtag::from_integrity(&integrity))
}

/// Require a non-empty `Idempotency-Key` on every mutation (A8 §2). The
/// key is echoed into the audit record (the client's binding check) and
/// consumed by [`replay_gate`] + the ledger on every committed outcome.
fn require_idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty());
    match key {
        Some(k) if k.len() > 255 => Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: "Idempotency-Key exceeds 255 bytes (A8 §2 recommends a ULID)".to_string(),
        })),
        Some(k) => Ok(k),
        None => Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: "missing or empty Idempotency-Key header \
                     (A8 §2: every mutating request must carry one)"
                .to_string(),
        })),
    }
}

/// Extract the request's bearer token, if any (`Authorization: Bearer …`).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Authorize one MUTATION (A8 #3): authenticate the bearer token and check
/// the role against `noun.verb`. Runs BEFORE the replay gate — an
/// unauthorized caller can replay nothing.
///
/// A denial appends a durable audit row ("the rejected attempt is still
/// audited") with the Deny decision and whatever idempotency key the
/// request carried — but NO ledger row: the denial never consumes the key,
/// so the caller may retry it once authorized. The 403 stands even if the
/// audit append itself fails (denying is the fail-safe direction; the
/// append failure is logged, not converted into a different status).
async fn authorize_mutation<S: EnvironmentStorage>(
    state: &AppState<S>,
    headers: &HeaderMap,
    env_id: &EnvId,
    noun: &str,
    verb: &str,
) -> Result<AuthContext, ApiError> {
    let denial = match state
        .rbac
        .authorize_mutation(bearer_token(headers), env_id, noun, verb)
    {
        Ok(auth) => return Ok(auth),
        Err(denial) => denial,
    };
    let RbacDenial {
        actor,
        policy,
        reason,
        authenticated,
    } = denial;
    // Lenient key read: the denial is audited with whatever the request
    // carried, even a key require_idempotency_key would reject.
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|k| !k.trim().is_empty());
    let audit = AuditEvent {
        schema: SchemaVersion::AUDIT_EVENT_V1.into(),
        event_id: ulid::Ulid::new().to_string(),
        ts: Utc::now(),
        actor,
        env_id: env_id.as_str().to_string(),
        noun: noun.to_string(),
        verb: verb.to_string(),
        target: json!({"environment_id": env_id}),
        previous_generation: None,
        new_generation: None,
        idempotency_key,
        authorization: AuditDecision::Deny {
            policy: policy.clone(),
            reason: reason.clone(),
        },
        result: AuditResult::Error {
            kind: "unauthorized".to_string(),
            message: format!("unauthorized: {reason} (policy `{policy}`)"),
        },
    };
    // Durable audit persistence is gated on `authenticated`: anonymous
    // denials (missing/unrecognized token) are logged but not persisted —
    // an unauthenticated caller could flood the audit table.
    if authenticated {
        match serde_json::to_value(&audit) {
            Ok(event) => {
                if let Err(err) = state
                    .storage
                    .record_audit(env_id, &audit.event_id, &event)
                    .await
                {
                    tracing::error!(error = %err, env_id = %env_id, "denial audit append failed");
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "denial audit event failed to serialize");
            }
        }
    } else {
        tracing::warn!(
            env_id = %env_id,
            noun = noun,
            verb = verb,
            "unauthenticated denial (not persisted)"
        );
    }
    Err(ApiError(RemoteStoreError::Unauthorized { policy, reason }))
}

/// Authorize one READ: any authenticated actor whose scope includes
/// `env_id`. `env_id` is `None` for collection reads where filtering
/// happens post-auth via [`crate::rbac::RbacEngine::read_scope`].
fn authorize_read<S: EnvironmentStorage>(
    state: &AppState<S>,
    headers: &HeaderMap,
    env_id: Option<&EnvId>,
) -> Result<(), ApiError> {
    state
        .rbac
        .authorize_read(bearer_token(headers), env_id)
        .map_err(|RbacDenial { policy, reason, .. }| {
            ApiError(RemoteStoreError::Unauthorized { policy, reason })
        })
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
/// otherwise pin the etag the handler just loaded — a torn-write guard
/// only, not true client CAS.
///
/// BOTH forms additionally pin the loaded generation (PR-4.3): the
/// post-commit revision is then deterministically `loaded + 1`, which the
/// pre-built journal body depends on — and the client-etag form no longer
/// races past a content-identical, generation-bumped concurrent write.
fn resolve_precondition(client_etag: Option<StateEtag>, loaded: &EnvRevision) -> Precondition {
    Precondition {
        if_match: Some(client_etag.unwrap_or_else(|| loaded.etag.clone())),
        expected_generation: Some(loaded.generation),
    }
}

// ---------------------------------------------------------------------------
// Handlers — environment lifecycle
// ---------------------------------------------------------------------------

/// `POST /environments` — create-if-absent (A8 route 1).
pub(crate) async fn create_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<CreateEnvironmentPayload>,
) -> Result<Response, ApiError> {
    let env_id = payload.env_id.clone();
    let auth = authorize_mutation(&state, &headers, &env_id, "env", "create").await?;
    let idem_key = require_idempotency_key(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let env = engine::fresh_environment(
            &payload.env_id,
            payload.name,
            payload.host_config,
            RevocationConfig::default(),
            RetentionPolicy::default(),
            HealthStatus::default(),
        );
        let prepared = prepare_mutation(
            &env,
            &env_id,
            "env",
            "create",
            json!({"environment_id": env_id}),
            idem_key,
            &fingerprint,
            &auth,
            None,
            created_revision(&env)?,
        )?;
        // Existence is enforced by the storage layer's atomic create
        // (`AlreadyExists` → 409) — no load-then-check race.
        state
            .storage
            .create_env_journaled(&env, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `PATCH /environments/{env_id}` — tri-state field patch (A8 route 2).
pub(crate) async fn update_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(patch, fingerprint): ApiJson<UpdateEnvironmentPayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "env", "update").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        engine::apply_environment_update(&mut env, patch);
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        let prepared = prepare_mutation(
            &env,
            &env_id,
            "env",
            "update",
            json!({"environment_id": env_id}),
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next_revision(&env, &loaded.revision)?,
        )?;
        state
            .storage
            .update_env_journaled(&env, &precondition, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `POST /environments/{env_id}/reconcile` — server-mediated reconcile
/// authorization (PR-A). The store authorizes + audits + CAS-pins the
/// reconcile and hands back the authorized env snapshot; the operator
/// still executes the k8s apply. No desired-state write — generation
/// and etag echo the loaded revision unchanged.
///
/// `If-Match` is MANDATORY (defense-in-depth against TOCTOU): the operator
/// must pin the reviewed state, and the server enforces it. Absent
/// `If-Match` returns 428; a stale etag returns 412.
pub(crate) async fn reconcile_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "env", "reconcile").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = match parse_if_match(&headers)? {
        Some(etag) => etag,
        None => {
            return Err(ApiError(RemoteStoreError::PreconditionRequired {
                detail: "reconcile requires If-Match to pin the reviewed state".to_string(),
            }));
        }
    };
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        // Manual CAS check: the handler never calls update_env_journaled
        // (where resolve_precondition normally fires), so compare here.
        if client_etag != loaded.revision.etag {
            return Err(ApiError(RemoteStoreError::PreconditionFailed(
                ConcurrencyConflict {
                    expected_etag: Some(client_etag.0),
                    actual_etag: loaded.revision.etag.0.clone(),
                    expected_generation: None,
                    actual_generation: loaded.revision.generation,
                },
            )));
        }
        let target = json!({
            "environment_id": env_id,
            "generation": loaded.revision.generation,
            "etag": loaded.revision.etag.0,
        });
        let prepared = prepare_mutation(
            &loaded.value,
            &env_id,
            "env",
            "reconcile",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(loaded.revision.generation),
            loaded.revision.clone(),
        )?;
        // No desired-state write — record_journal only (same pattern as
        // set_traffic_split's no-mutation branch and seed_trust_root's
        // no-op path).
        state.storage.record_journal(&prepared.journal).await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `POST /environments/{env_id}/migrate-bindings` — merge pack/extension
/// bindings, optionally seeding a missing target (A8 route 3).
pub(crate) async fn migrate_bindings<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<MigrateMergePayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "env", "migrate-bindings").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let existing = match state.storage.load_env(&env_id).await {
            Ok(loaded) => Some(loaded),
            Err(StorageError::NotFound(_)) => None,
            Err(err) => return Err(load_storage_error(err)),
        };
        let prior_revision = existing.as_ref().map(|l| l.revision.clone());
        let mut env =
            engine::seed_or_existing(existing.map(|l| l.value), &env_id, payload.seed_if_missing)?;
        let report = engine::merge_bindings(&mut env, payload.packs, payload.extensions);
        let target = json!({
            "environment_id": env_id,
            "merged_slots": report.merged_slots,
            "merged_extensions": report.merged_extensions,
        });
        let revision = match &prior_revision {
            Some(prior) => next_revision(&env, prior)?,
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
                created_revision(&env)?
            }
        };
        let prepared = prepare_mutation(
            &report,
            &env_id,
            "env",
            "migrate-bindings",
            target,
            idem_key,
            &fingerprint,
            &auth,
            prior_revision.as_ref().map(|r| r.generation),
            revision,
        )?;
        match &prior_revision {
            Some(prior) => {
                let precondition = resolve_precondition(client_etag, prior);
                state
                    .storage
                    .update_env_journaled(&env, &precondition, Some(&prepared.journal))
                    .await?;
            }
            None => {
                state
                    .storage
                    .create_env_journaled(&env, Some(&prepared.journal))
                    .await?;
            }
        }
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
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
    ApiJson(payload, fingerprint): ApiJson<StageRevisionPayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "revisions", "stage").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        let staged = engine::stage_revision(&mut env, payload, Utc::now())?;
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        let target = json!({
            "environment_id": env_id,
            "revision_id": staged.revision_id.to_string(),
            "deployment_id": staged.deployment_id.to_string(),
            "lifecycle_to": "staged",
        });
        let prepared = prepare_mutation(
            &staged,
            &env_id,
            "revisions",
            "stage",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next_revision(&env, &loaded.revision)?,
        )?;
        state
            .storage
            .update_env_journaled(&env, &precondition, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `POST /environments/{env_id}/revisions/{revision_id}/warm` — drive
/// `Staged → Warming → Ready`, applying the client-evaluated health-gate
/// outcome from the body (A8 route 5). The body's `revision_id` must match
/// the URL's.
pub(crate) async fn warm_revision<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, revision_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<WarmRevisionPayload>,
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
    revision_transition(&state, &env_id, &headers, &fingerprint, "warm", |env| {
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
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let revision_id = parse_revision_id(&revision_id)?;
    revision_transition(&state, &env_id, &headers, &fingerprint, "drain", |env| {
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
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let revision_id = parse_revision_id(&revision_id)?;
    revision_transition(&state, &env_id, &headers, &fingerprint, "archive", |env| {
        engine::archive_revision(env, revision_id)
    })
    .await
}

/// Shared warm/drain/archive body: load → pure engine transform → persist
/// per the engine's rule → A8 envelope around [`RevisionTransitionOutcome`].
///
/// Persist rule: `Ok` persists and responds 2xx; an `env_mutated` error (the
/// warm gate's flip to `Failed`) persists FIRST and then surfaces the typed
/// 422 — committed-on-error, mirroring `LocalFsStore`. Both committed
/// outcomes journal (the gate failure's 422 body is its ledgered response —
/// a same-key retry replays it instead of re-walking the chain); a persist
/// failure on the gate path takes precedence (the client must not be told
/// the gate failure is durable when it isn't). Every other error discards
/// the in-memory env and consumes no key.
async fn revision_transition<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &str,
    headers: &HeaderMap,
    fingerprint: &RequestFingerprint,
    verb: &'static str,
    apply: impl FnOnce(&mut Environment) -> Result<engine::RevisionTransition, RevisionLifecycleError>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(env_id)?;
    let auth = authorize_mutation(state, headers, &env_id, "revisions", verb).await?;
    let idem_key = require_idempotency_key(headers)?;
    let client_etag = parse_if_match(headers)?;
    if let Some(replay) = replay_gate(state, &env_id, &idem_key, fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
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
                let target = json!({
                    "environment_id": env_id,
                    "revision_id": transition.revision.revision_id.to_string(),
                    "lifecycle_to": transition.revision.lifecycle,
                });
                let next = next_revision(&env, &loaded.revision)?;
                let outcome = RevisionTransitionOutcome {
                    revision: transition.revision,
                    environment: env,
                    starting_lifecycle: transition.starting_lifecycle,
                };
                let prepared = prepare_mutation(
                    &outcome,
                    &env_id,
                    "revisions",
                    verb,
                    target,
                    idem_key,
                    fingerprint,
                    &auth,
                    Some(previous_generation),
                    next,
                )?;
                state
                    .storage
                    .update_env_journaled(
                        &outcome.environment,
                        &precondition,
                        Some(&prepared.journal),
                    )
                    .await?;
                Ok(prepared.into_response())
            }
            Err(err) if err.env_mutated() => {
                // Health-gate failure: the engine flipped the revision to
                // `Failed` in memory — persist before surfacing the typed 422.
                let target = json!({
                    "environment_id": env_id,
                    "revision_id": match &err {
                        RevisionLifecycleError::HealthGateFailed { revision_id, .. } =>
                            Some(revision_id.to_string()),
                        _ => None,
                    },
                    "lifecycle_to": "failed",
                });
                let next_generation = next_revision(&env, &loaded.revision)?.generation;
                let api_err = ApiError::from(err);
                let prepared = prepare_committed_error(
                    &api_err.0,
                    &env_id,
                    "revisions",
                    verb,
                    target,
                    idem_key,
                    fingerprint,
                    &auth,
                    Some(previous_generation),
                    next_generation,
                )?;
                let precondition = resolve_precondition(client_etag, &loaded.revision);
                state
                    .storage
                    .update_env_journaled(&env, &precondition, Some(&prepared.journal))
                    .await?;
                Ok(prepared.into_response())
            }
            Err(err) => Err(err.into()),
        }
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(state, &env_id, &recheck_key, fingerprint, err).await,
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
    ApiJson(payload, fingerprint): ApiJson<SetTrafficSplitPayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "traffic", "set").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
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
        let mutated = transition.mutated();
        // The domain-level replay branch (`mutated == false`) is reached only
        // when the split's stored key predates this server's ledger (state
        // migrated from a LocalFS store) — same-key retries against THIS
        // server are intercepted by the gate above. Echo the loaded CAS
        // coordinates so the client can keep chaining writes.
        let revision = if mutated {
            next_revision(&env, &loaded.revision)?
        } else {
            loaded.revision.clone()
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
        let prepared = prepare_mutation(
            &outcome,
            &env_id,
            "traffic",
            "set",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            revision,
        )?;
        if mutated {
            let precondition = resolve_precondition(client_etag, &loaded.revision);
            state
                .storage
                .update_env_journaled(&outcome.environment, &precondition, Some(&prepared.journal))
                .await?;
        } else {
            state.storage.record_journal(&prepared.journal).await?;
        }
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `POST /environments/{env_id}/traffic/rollback` — restore a deployment's
/// one-step-previous split (A8 route 9). Always a genuine mutation (the
/// generation advances, never rewinds), so unlike `set` there is no replay
/// short-circuit.
pub(crate) async fn rollback_traffic_split<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<RollbackTrafficSplitPayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "traffic", "rollback").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        let transition =
            engine::rollback_traffic_split(&mut env, payload.deployment_id, Utc::now())?;
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        let target = json!({
            "environment_id": env_id,
            "deployment_id": transition.restored.deployment_id.to_string(),
            "split_generation": transition.new_generation,
        });
        let next = next_revision(&env, &loaded.revision)?;
        let outcome = RollbackTrafficSplitOutcome {
            restored: transition.restored,
            previous_generation: transition.previous_generation,
            new_generation: transition.new_generation,
            environment: env,
        };
        let prepared = prepare_mutation(
            &outcome,
            &env_id,
            "traffic",
            "rollback",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next,
        )?;
        state
            .storage
            .update_env_journaled(&outcome.environment, &precondition, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
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
    fingerprint: RequestFingerprint,
    verb: &'static str,
    noun: &'static str,
    apply: F,
) -> Result<Response, ApiError>
where
    S: EnvironmentStorage,
    T: Serialize,
    F: FnOnce(&mut Environment) -> Result<(T, Value), ApiError>,
{
    let env_id = parse_env_id(&raw_env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, noun, verb).await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        let (result, mut target) = apply(&mut env)?;
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        if let Value::Object(map) = &mut target {
            map.insert("environment_id".to_string(), json!(env_id));
        }
        let prepared = prepare_mutation(
            &result,
            &env_id,
            noun,
            verb,
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next_revision(&env, &loaded.revision)?,
        )?;
        state
            .storage
            .update_env_journaled(&env, &precondition, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `POST /environments/{env_id}/packs` — bind a new env-pack slot
/// (A8 route 10).
pub(crate) async fn add_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<PackBindingPayload>,
) -> Result<Response, ApiError> {
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "add",
        "env-packs",
        |env| {
            let added = engine::add_pack_binding(env, payload.binding)?;
            let target = json!({"slot": added.slot, "kind": added.kind});
            Ok((added, target))
        },
    )
    .await
}

/// `PATCH /environments/{env_id}/packs/{slot}` — replace the binding on an
/// existing slot, stashing the prior one for one-step rollback (A8 route 11).
pub(crate) async fn update_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, slot)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<PackBindingPayload>,
) -> Result<Response, ApiError> {
    let slot = parse_capability_slot(&slot)?;
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "update",
        "env-packs",
        |env| {
            let (binding, generation) = engine::update_pack_binding(env, slot, payload.binding)?;
            let target = json!({"slot": binding.slot, "kind": binding.kind});
            Ok((
                BindingGenerationOutcome {
                    binding,
                    generation,
                },
                target,
            ))
        },
    )
    .await
}

/// `DELETE /environments/{env_id}/packs/{slot}` — remove a pack-binding
/// slot (A8 route 12).
pub(crate) async fn remove_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, slot)): Path<(String, String)>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let slot = parse_capability_slot(&slot)?;
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "remove",
        "env-packs",
        |env| {
            let (binding, generation) = engine::remove_pack_binding(env, slot)?;
            let target = json!({"slot": slot});
            Ok((
                BindingGenerationOutcome {
                    binding,
                    generation,
                },
                target,
            ))
        },
    )
    .await
}

/// `POST /environments/{env_id}/packs/{slot}/rollback` — restore a slot's
/// one-step-previous binding (A8 route 13).
pub(crate) async fn rollback_pack_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, slot)): Path<(String, String)>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let slot = parse_capability_slot(&slot)?;
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "rollback",
        "env-packs",
        |env| {
            let (binding, generation) = engine::rollback_pack_binding(env, slot)?;
            let target = json!({"slot": slot});
            Ok((
                BindingGenerationOutcome {
                    binding,
                    generation,
                },
                target,
            ))
        },
    )
    .await
}

/// `POST /environments/{env_id}/extensions` — add a new extension binding
/// (A8 route 14).
pub(crate) async fn add_extension_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<ExtensionBindingPayload>,
) -> Result<Response, ApiError> {
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "add",
        "extensions",
        |env| {
            let added = engine::add_extension_binding(env, payload.binding)?;
            let target = json!({"kind_path": added.kind.path(), "instance_id": added.instance_id});
            Ok((added, target))
        },
    )
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
    ApiJson(payload, fingerprint): ApiJson<ExtensionKeyedPayload>,
) -> Result<Response, ApiError> {
    let Some(binding) = payload.binding else {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: "update requires `binding` in the request body".to_string(),
        }));
    };
    let key = payload.key;
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "update",
        "extensions",
        |env| {
            let target = json!({"kind_path": key.kind_path, "instance_id": key.instance_id});
            let (binding, generation) = engine::update_extension_binding(env, &key, binding)?;
            Ok((
                BindingGenerationOutcome {
                    binding,
                    generation,
                },
                target,
            ))
        },
    )
    .await
}

/// `DELETE /environments/{env_id}/extensions` — remove an extension
/// binding identified by the body's key (A8 route 16).
pub(crate) async fn remove_extension_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<ExtensionKeyedPayload>,
) -> Result<Response, ApiError> {
    let key = payload.key;
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "remove",
        "extensions",
        |env| {
            let target = json!({"kind_path": key.kind_path, "instance_id": key.instance_id});
            let (binding, generation) = engine::remove_extension_binding(env, &key)?;
            Ok((
                BindingGenerationOutcome {
                    binding,
                    generation,
                },
                target,
            ))
        },
    )
    .await
}

/// `POST /environments/{env_id}/extensions/rollback` — restore an
/// extension binding's one-step-previous snapshot (A8 route 17).
pub(crate) async fn rollback_extension_binding<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<ExtensionKeyedPayload>,
) -> Result<Response, ApiError> {
    let key = payload.key;
    binding_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "rollback",
        "extensions",
        |env| {
            let target = json!({"kind_path": key.kind_path, "instance_id": key.instance_id});
            let (binding, generation) = engine::rollback_extension_binding(env, &key)?;
            Ok((
                BindingGenerationOutcome {
                    binding,
                    generation,
                },
                target,
            ))
        },
    )
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
// SERVER's operator key. The artifact row, the env document (with the
// pinned ref), and a re-check of the trust-root revision the signature
// was evaluated against commit in ONE transaction
// (`update_env_with_revenue_policy`) — the server analogue of the LocalFS
// flock, under which the policy-file write and the env.json save are a
// single critical section. A CAS conflict therefore rolls the artifact
// back too, and a trust-root mutation racing the signing window surfaces
// as a retryable 409 instead of committing a stale signature.

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

/// A built-but-not-yet-committed revenue-policy version: the artifact row
/// ready for storage plus the trust-root row revision the signature was
/// evaluated against. Committing is the handler's job, via
/// `update_env_with_revenue_policy` — ONE transaction re-checks the pin,
/// stores the artifact, and CAS-updates the environment, so committed env
/// state, the artifact it references, and the trust root that authorized
/// the signature can never diverge (Codex F1/F2).
struct PendingRevenuePolicy {
    built: revenue_policy::BuiltRevenuePolicyVersion,
    artifact: RevenuePolicyArtifact,
    trust_root_pin: Option<EnvRevision>,
}

/// Build the next revenue-policy version for `deployment`. Trust root
/// comes from the env's row — absent row decodes to an EMPTY trust root,
/// so the shared builder refuses closed-by-default until the env is
/// bootstrapped. Pure build: nothing is persisted here.
async fn build_revenue_policy<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    deployment: &BundleDeployment,
    created_at: chrono::DateTime<Utc>,
) -> Result<PendingRevenuePolicy, ApiError> {
    let loaded_root = state
        .storage
        .load_trust_root(env_id)
        .await
        .map_err(load_storage_error)?;
    let trust_root_pin = loaded_root.as_ref().map(|l| l.revision.clone());
    let trust_root = match loaded_root {
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
    let artifact = RevenuePolicyArtifact {
        bundle_id: deployment.bundle_id.clone(),
        customer_id: deployment.customer_id.clone(),
        version: built.version,
        policy_ref: built.policy_ref.to_string_lossy().replace('\\', "/"),
        doc: built.doc_bytes.clone(),
        envelope: built.envelope_bytes.clone(),
        doc_sha256: built.doc_sha256.clone(),
        key_id: built.key_id.clone(),
    };
    Ok(PendingRevenuePolicy {
        built,
        artifact,
        trust_root_pin,
    })
}

/// `POST /environments/{env_id}/bundles` — deploy a bundle for a customer
/// (A8 route 7). The server mints the [`DeploymentId`] (the wire payload
/// carries none) and writes the v1 revenue-policy artifact.
pub(crate) async fn add_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<engine::AddBundlePayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "bundles", "add").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        let now = Utc::now();
        let idx = engine::add_bundle(&mut env, payload, DeploymentId::new(), now)?;
        let pending = build_revenue_policy(&state, &env_id, &env.bundles[idx], now).await?;
        env.bundles[idx].revenue_policy_ref = pending.built.policy_ref.clone();
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        let deployment = &env.bundles[idx];
        let target = json!({
            "environment_id": env_id,
            "deployment_id": deployment.deployment_id,
            "bundle_id": deployment.bundle_id,
            "customer_id": deployment.customer_id,
            "revenue_policy_version": pending.built.version,
        });
        let prepared = prepare_mutation(
            deployment,
            &env_id,
            "bundles",
            "add",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next_revision(&env, &loaded.revision)?,
        )?;
        state
            .storage
            .update_env_with_revenue_policy_journaled(
                &env,
                &precondition,
                &pending.artifact,
                pending.trust_root_pin.as_ref(),
                Some(&prepared.journal),
            )
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `PATCH /environments/{env_id}/bundles/{deployment_id}` — patch a
/// deployment's scalar fields (A8 route 8). A `revenue_share` patch writes
/// the next chained revenue-policy version. The body's `deployment_id` is
/// cross-checked against the URL segment (the warm-revision precedent).
pub(crate) async fn update_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, deployment_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<engine::UpdateBundlePayload>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "bundles", "update").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let url_deployment_id = parse_deployment_id(&deployment_id)?;
    if payload.deployment_id != url_deployment_id {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: format!(
                "body deployment_id `{}` does not match URL deployment_id `{url_deployment_id}`",
                payload.deployment_id
            ),
        }));
    }
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        let applied = engine::update_bundle(&mut env, payload)?;
        let idx = applied.index;
        let pending = if applied.revenue_share_changed {
            let pending =
                build_revenue_policy(&state, &env_id, &env.bundles[idx], Utc::now()).await?;
            env.bundles[idx].revenue_policy_ref = pending.built.policy_ref.clone();
            Some(pending)
        } else {
            None
        };
        let policy_version = pending.as_ref().map(|p| p.built.version);
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        let deployment = &env.bundles[idx];
        let target = json!({
            "environment_id": env_id,
            "deployment_id": deployment.deployment_id,
            "revenue_policy_version": policy_version,
        });
        let prepared = prepare_mutation(
            deployment,
            &env_id,
            "bundles",
            "update",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next_revision(&env, &loaded.revision)?,
        )?;
        match &pending {
            Some(p) => {
                state
                    .storage
                    .update_env_with_revenue_policy_journaled(
                        &env,
                        &precondition,
                        &p.artifact,
                        p.trust_root_pin.as_ref(),
                        Some(&prepared.journal),
                    )
                    .await?;
            }
            None => {
                state
                    .storage
                    .update_env_journaled(&env, &precondition, Some(&prepared.journal))
                    .await?;
            }
        }
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `DELETE /environments/{env_id}/bundles/{deployment_id}` — remove a
/// quiesced deployment (A8 route 9). Refuses while live state remains;
/// the pruned archived-revision ids ride the outcome AND the audit target
/// so the destructive compaction is explicit.
pub(crate) async fn remove_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, deployment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "bundles", "remove").await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    let deployment_id = parse_deployment_id(&deployment_id)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        let removed = engine::remove_bundle(&mut env, deployment_id)?;
        let precondition = resolve_precondition(client_etag, &loaded.revision);
        let target = json!({
            "environment_id": env_id,
            "deployment_id": deployment_id,
            "pruned_revision_ids": removed.pruned_revision_ids,
        });
        let prepared = prepare_mutation(
            &removed,
            &env_id,
            "bundles",
            "remove",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next_revision(&env, &loaded.revision)?,
        )?;
        state
            .storage
            .update_env_journaled(&env, &precondition, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

// ---------------------------------------------------------------------------
// Handlers — messaging endpoints (PR-4.2h)
// ---------------------------------------------------------------------------
//
// The verb semantics come from `greentic_deploy_spec::engine::messaging` —
// the same transforms `LocalFsStore` drives, per the same-derivation rule.
// Two LocalFS-only steps deliberately have no server analogue:
//
// - The derived `<env_dir>/messaging/` projection refresh — remote
//   consumers read the environment via `GET` (the runtime-config
//   projection precedent).
// - The webhook-secret SINK: a control-plane store has no secrets plane and
//   never mints, rotates, or custodies secret material. Telegram-class `add`
//   therefore requires a caller-supplied `webhook_secret_ref` (the operator
//   provisions the value in its own secrets plane and the engine stamps the
//   ref without touching the sink). The sink itself ALWAYS refuses, so the
//   only paths that reach it — a telegram `add` with NO ref, or any
//   `rotate-webhook-secret` (the server cannot prove a value rotated, so it
//   will not journal a misleading success) — answer 501 `not-yet-implemented`.
//   The refusal fires exactly where the LocalFS sink would write — after
//   replay/duplicate/ref validation — so every other path is identical.
//
// Persist rule: the engine reports `mutated == false` for idempotent
// replays/no-ops — the handler then echoes the loaded CAS coordinates
// instead of writing (the traffic-set precedent).

impl From<MessagingError> for ApiError {
    fn from(err: MessagingError) -> Self {
        Self(match err {
            MessagingError::IdempotencyKeyReuse { .. } => RemoteStoreError::IdempotencyConflict {
                reason: err.to_string(),
            },
            // The client folds 409 `already-exists` onto the same
            // `Conflict` noun the local store raises.
            MessagingError::EndpointAlreadyExists { .. } => RemoteStoreError::AlreadyExists {
                detail: err.to_string(),
            },
            MessagingError::EndpointNotFound { .. } | MessagingError::BundleNotDeployed { .. } => {
                RemoteStoreError::DependentNotFound {
                    detail: err.to_string(),
                }
            }
            MessagingError::WelcomeFlowOwned { .. } => RemoteStoreError::Conflict {
                detail: err.to_string(),
            },
            MessagingError::BundleNotLinked { .. }
            | MessagingError::WelcomePackUnknown { .. }
            | MessagingError::InvalidSecretRef { .. } => RemoteStoreError::InvalidRequest {
                detail: err.to_string(),
            },
            // The server sink always refuses, so this is produced by a fresh
            // telegram add with no caller-supplied ref or by any rotate;
            // LocalFS maps its dev-store sink failures to `Conflict` instead.
            // 501 is the accurate rendering — the control-plane store has no
            // secrets plane.
            MessagingError::SecretProvision(detail) => {
                RemoteStoreError::NotYetImplemented { detail }
            }
        })
    }
}

/// Parse a path segment into a [`MessagingEndpointId`], rejecting
/// non-ULID input with a typed 400.
fn parse_endpoint_id(raw: &str) -> Result<MessagingEndpointId, ApiError> {
    raw.parse::<ulid::Ulid>()
        .map(MessagingEndpointId)
        .map_err(|e| {
            ApiError(RemoteStoreError::InvalidRequest {
                detail: format!("invalid endpoint_id `{raw}`: {e}"),
            })
        })
}

/// The server's webhook-secret `provision` seam. A control-plane operator
/// store has NO secrets plane and never mints, rotates, or custodies secret
/// material, so the sink ALWAYS refuses:
///
/// - **add**: a telegram-class `add` over a remote store must carry a
///   caller-supplied `webhook_secret_ref` (the operator provisions the value
///   in its own secrets plane). The engine then bypasses this sink entirely,
///   so the only `add` that reaches it is one with no ref — which is refused.
/// - **rotate**: the server cannot prove a value rotated (the value lives
///   operator-side), so echoing the ref would journal a misleading success.
///   Remote `rotate-webhook-secret` is therefore unsupported: re-provision
///   the value operator-side and re-add the endpoint, or rotate on the local
///   store. (A future API that takes a NEW ref could make it verifiable.)
///
/// Both surface as 501 with a directive message.
fn server_webhook_secret_sink(_existing: Option<&SecretRef>) -> Result<SecretRef, MessagingError> {
    Err(MessagingError::SecretProvision(
        "the operator store server neither mints nor rotates webhook secrets: a telegram-class \
         `add` must carry a caller-supplied `webhook_secret_ref` (the operator provisions the \
         value in its own secrets plane), and `rotate-webhook-secret` is unsupported on a remote \
         store — re-provision the value operator-side and re-add the endpoint, or use the local \
         store"
            .to_string(),
    ))
}

/// Shared load → pure-engine transform → persist-if-mutated → A8 envelope
/// cycle for the six messaging verbs (the `binding_mutation` analogue,
/// plus the replay short-circuit). `apply` receives the engine-shaped
/// [`IdempotencyKey`] because this group uses the key as domain state
/// (replay detection), and returns the response body, the audit-target
/// fragment (`environment_id` is injected here), and whether the env was
/// actually mutated.
async fn messaging_mutation<S, T, F>(
    state: AppState<S>,
    raw_env_id: String,
    headers: HeaderMap,
    fingerprint: RequestFingerprint,
    verb: &'static str,
    apply: F,
) -> Result<Response, ApiError>
where
    S: EnvironmentStorage,
    T: Serialize,
    F: FnOnce(&mut Environment, &IdempotencyKey) -> Result<(T, Value, bool), ApiError>,
{
    let env_id = parse_env_id(&raw_env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "messaging.endpoint", verb).await?;
    let idem_key = require_idempotency_key(&headers)?;
    let client_etag = parse_if_match(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let engine_key = IdempotencyKey::new(idem_key.clone())
            .expect("require_idempotency_key guarantees non-empty");
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let previous_generation = loaded.revision.generation;
        let mut env = loaded.value;
        let (result, mut target, mutated) = apply(&mut env, &engine_key)?;
        // Domain-level no-op (a fresh key naming already-converged state):
        // nothing changed — echo the loaded CAS coordinates so the client can
        // keep chaining writes, but still ledger the response (the key is
        // consumed; its retry must replay, not re-evaluate against later state).
        let revision = if mutated {
            next_revision(&env, &loaded.revision)?
        } else {
            loaded.revision.clone()
        };
        if let Value::Object(map) = &mut target {
            map.insert("environment_id".to_string(), json!(env_id));
        }
        let prepared = prepare_mutation(
            &result,
            &env_id,
            "messaging.endpoint",
            verb,
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            revision,
        )?;
        if mutated {
            let precondition = resolve_precondition(client_etag, &loaded.revision);
            state
                .storage
                .update_env_journaled(&env, &precondition, Some(&prepared.journal))
                .await?;
        } else {
            state.storage.record_journal(&prepared.journal).await?;
        }
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `POST /environments/{env_id}/messaging` — add a messaging endpoint
/// (A8 messaging route 1). The server mints the [`MessagingEndpointId`]
/// (the bundles-group `DeploymentId` precedent).
pub(crate) async fn add_messaging_endpoint<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<AddMessagingEndpointPayload>,
) -> Result<Response, ApiError> {
    messaging_mutation(state, env_id, headers, fingerprint, "add", |env, key| {
        let applied = engine::add_messaging_endpoint(
            env,
            payload,
            MessagingEndpointId::new(),
            key,
            Utc::now(),
            server_webhook_secret_sink,
        )?;
        let ep = env.messaging_endpoints[applied.index].clone();
        let target = json!({
            "endpoint_id": ep.endpoint_id.to_string(),
            "provider_id": ep.provider_id,
            "provider_type": ep.provider_type,
        });
        Ok((ep, target, applied.mutated))
    })
    .await
}

/// `POST /environments/{env_id}/messaging/{endpoint_id}/link` — link a
/// deployed bundle to an endpoint (A8 messaging route 2).
pub(crate) async fn link_messaging_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, endpoint_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<MessagingBundleLinkPayload>,
) -> Result<Response, ApiError> {
    let endpoint_id = parse_endpoint_id(&endpoint_id)?;
    messaging_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "link-bundle",
        |env, key| {
            let target = json!({
                "endpoint_id": endpoint_id.to_string(),
                "bundle_id": payload.bundle_id,
            });
            let applied = engine::link_messaging_bundle(
                env,
                endpoint_id,
                payload.bundle_id,
                &payload.updated_by,
                key,
                Utc::now(),
            )?;
            let ep = env.messaging_endpoints[applied.index].clone();
            Ok((ep, target, applied.mutated))
        },
    )
    .await
}

/// `POST /environments/{env_id}/messaging/{endpoint_id}/unlink` — unlink a
/// bundle from an endpoint (A8 messaging route 3).
pub(crate) async fn unlink_messaging_bundle<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, endpoint_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<MessagingBundleLinkPayload>,
) -> Result<Response, ApiError> {
    let endpoint_id = parse_endpoint_id(&endpoint_id)?;
    messaging_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "unlink-bundle",
        |env, key| {
            let target = json!({
                "endpoint_id": endpoint_id.to_string(),
                "bundle_id": payload.bundle_id,
            });
            let applied = engine::unlink_messaging_bundle(
                env,
                endpoint_id,
                payload.bundle_id,
                &payload.updated_by,
                key,
                Utc::now(),
            )?;
            let ep = env.messaging_endpoints[applied.index].clone();
            Ok((ep, target, applied.mutated))
        },
    )
    .await
}

/// `POST /environments/{env_id}/messaging/{endpoint_id}/welcome-flow` —
/// set the endpoint's welcome flow (A8 messaging route 4). The body
/// carries `endpoint_id` too (the PR-3b client pinned that shape); the
/// server cross-checks it against the URL segment.
pub(crate) async fn set_messaging_welcome_flow<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, endpoint_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<SetMessagingWelcomeFlowPayload>,
) -> Result<Response, ApiError> {
    let url_endpoint_id = parse_endpoint_id(&endpoint_id)?;
    if payload.endpoint_id != url_endpoint_id {
        return Err(ApiError(RemoteStoreError::InvalidRequest {
            detail: format!(
                "body endpoint_id `{}` does not match URL endpoint_id `{url_endpoint_id}`",
                payload.endpoint_id
            ),
        }));
    }
    messaging_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "set-welcome-flow",
        |env, key| {
            let target = json!({
                "endpoint_id": payload.endpoint_id.to_string(),
                "bundle_id": payload.bundle_id,
                "pack_id": payload.pack_id,
                "flow_id": payload.flow_id,
            });
            let applied = engine::set_messaging_welcome_flow(env, payload, key, Utc::now())?;
            let ep = env.messaging_endpoints[applied.index].clone();
            Ok((ep, target, applied.mutated))
        },
    )
    .await
}

/// `DELETE /environments/{env_id}/messaging/{endpoint_id}` — remove an
/// endpoint (A8 messaging route 5). Idempotent: removing an absent
/// endpoint succeeds without writing.
pub(crate) async fn remove_messaging_endpoint<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, endpoint_id)): Path<(String, String)>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let endpoint_id = parse_endpoint_id(&endpoint_id)?;
    messaging_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "remove",
        |env, _key| {
            let mutated = engine::remove_messaging_endpoint(env, endpoint_id);
            let target = json!({"endpoint_id": endpoint_id.to_string()});
            Ok((endpoint_id, target, mutated))
        },
    )
    .await
}

/// `POST /environments/{env_id}/messaging/{endpoint_id}/rotate-secret` —
/// rotate the endpoint's webhook secret (A8 messaging route 6). Unsupported
/// on a remote store: the value lives operator-side so the server cannot
/// prove a rotation occurred, and journaling a generation bump would be a
/// misleading success. Answers 501. Unknown endpoints still 404 first; a
/// same-key replay still no-ops without re-stamping.
pub(crate) async fn rotate_messaging_webhook_secret<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, endpoint_id)): Path<(String, String)>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<RotateWebhookSecretPayload>,
) -> Result<Response, ApiError> {
    let endpoint_id = parse_endpoint_id(&endpoint_id)?;
    messaging_mutation(
        state,
        env_id,
        headers,
        fingerprint,
        "rotate-webhook-secret",
        |env, key| {
            let applied = engine::rotate_messaging_webhook_secret(
                env,
                endpoint_id,
                &payload.updated_by,
                key,
                Utc::now(),
                server_webhook_secret_sink,
            )?;
            let ep = env.messaging_endpoints[applied.index].clone();
            let target = json!({"endpoint_id": endpoint_id.to_string()});
            Ok((ep, target, applied.mutated))
        },
    )
    .await
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
/// idempotency key + request fingerprint, the parsed env id, the env's
/// CAS coordinates (the `load_env` doubles as the 404 existence gate),
/// and the current trust-root row if one exists. The replay gate runs
/// BEFORE the loads — a replayed verb touches no state.
struct TrustRootRequest {
    idem_key: String,
    fingerprint: RequestFingerprint,
    env_id: EnvId,
    auth: AuthContext,
    env_revision: EnvRevision,
    current: Option<LoadedTrustRoot>,
}

enum TrustRootGate {
    Replay(Response),
    Fresh(TrustRootRequest),
}

async fn load_trust_root_request<S: EnvironmentStorage>(
    state: &AppState<S>,
    raw_env_id: &str,
    headers: &HeaderMap,
    verb: &'static str,
    fingerprint: RequestFingerprint,
) -> Result<TrustRootGate, ApiError> {
    let env_id = parse_env_id(raw_env_id)?;
    let auth = authorize_mutation(state, headers, &env_id, "trust-root", verb).await?;
    let idem_key = require_idempotency_key(headers)?;
    if let Some(replay) = replay_gate(state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(TrustRootGate::Replay(replay));
    }
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
    Ok(TrustRootGate::Fresh(TrustRootRequest {
        idem_key,
        fingerprint,
        env_id,
        auth,
        env_revision: env.revision,
        current,
    }))
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
///
/// `prepare` builds the verb's response from the post-mutate document;
/// its journal rides each upsert attempt, so the ledger + audit rows
/// commit with — and only with — the attempt that persists (a losing
/// attempt's transaction rolls them back along with the document).
async fn persist_trust_root_mutation<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    mut current: Option<LoadedTrustRoot>,
    on_race: FirstWriteRace,
    mutate: impl Fn(&mut TrustRootDocument),
    prepare: impl Fn(&TrustRootDocument) -> Result<PreparedMutation, ApiError>,
) -> Result<Option<PreparedMutation>, ApiError> {
    loop {
        let (mut doc, precondition) = doc_and_precondition(current);
        mutate(&mut doc);
        let prepared = prepare(&doc)?;
        match state
            .storage
            .upsert_trust_root_journaled(
                env_id,
                &doc,
                precondition.as_ref(),
                Some(&prepared.journal),
            )
            .await
        {
            Ok(_revision) => return Ok(Some(prepared)),
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
/// `key_id` collision — and persist under the row's CAS pin, journaling
/// in the same transaction. `prepare` builds the verb-specific envelope
/// from the granted seed. Returns `None` only when a
/// [`FirstWriteRace::NoOp`] seed observes the concurrent first write (the
/// row it could not see at load time).
async fn grant_operator_key<S: EnvironmentStorage>(
    state: &AppState<S>,
    env_id: &EnvId,
    current: Option<LoadedTrustRoot>,
    on_race: FirstWriteRace,
    prepare: impl Fn(TrustRootSeed) -> Result<PreparedMutation, ApiError>,
) -> Result<Option<PreparedMutation>, ApiError> {
    let op_key = load_server_operator_key(state.operator_key_path.clone()).await?;
    let entry = trust_root::validate_trusted_key(TrustedKey {
        key_id: op_key.key_id.clone(),
        public_key_pem: op_key.public_pem.clone(),
    })?;
    persist_trust_root_mutation(
        state,
        env_id,
        current,
        on_race,
        |doc| {
            trust_root::apply_add(&mut doc.keys, entry.clone());
        },
        |doc| {
            prepare(TrustRootSeed {
                key_id: op_key.key_id.clone(),
                public_key_pem: op_key.public_pem.clone(),
                trusted_key_count: doc.keys.len(),
            })
        },
    )
    .await
}

/// `POST /environments/{env_id}/trust-root/bootstrap` — load (or generate)
/// the server operator key and grant it on the env trust root (A8 route
/// 18). Idempotent re-grant, mirroring `LocalFsStore::bootstrap_trust_root`.
pub(crate) async fn bootstrap_trust_root<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let req =
        match load_trust_root_request(&state, &env_id, &headers, "bootstrap", fingerprint).await? {
            TrustRootGate::Replay(replay) => return Ok(replay),
            TrustRootGate::Fresh(req) => req,
        };
    let TrustRootRequest {
        idem_key,
        fingerprint,
        env_id,
        auth,
        env_revision,
        current,
    } = req;
    let recheck_key = idem_key.clone();
    let outcome = async {
        let prepared =
            grant_operator_key(&state, &env_id, current, FirstWriteRace::Retry, |seed| {
                let target = json!({"environment_id": env_id, "key_id": seed.key_id});
                prepare_mutation(
                    &seed,
                    &env_id,
                    "trust-root",
                    "bootstrap",
                    target,
                    idem_key.clone(),
                    &fingerprint,
                    &auth,
                    Some(env_revision.generation),
                    env_revision.clone(),
                )
            })
            .await?
            .expect("Retry mode always grants");
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
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
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let req = match load_trust_root_request(&state, &env_id, &headers, "seed", fingerprint).await? {
        TrustRootGate::Replay(replay) => return Ok(replay),
        TrustRootGate::Fresh(req) => req,
    };
    let TrustRootRequest {
        idem_key,
        fingerprint,
        env_id,
        auth,
        env_revision,
        current,
    } = req;
    let recheck_key = idem_key.clone();
    let outcome = async {
        let prepare_with = |seed: Option<TrustRootSeed>| {
            let mut target = json!({"environment_id": env_id});
            if let (Some(seed), Value::Object(map)) = (&seed, &mut target) {
                map.insert("key_id".to_string(), json!(seed.key_id));
            }
            prepare_mutation(
                &seed,
                &env_id,
                "trust-root",
                "seed",
                target,
                idem_key.clone(),
                &fingerprint,
                &auth,
                Some(env_revision.generation),
                env_revision.clone(),
            )
        };
        let granted = match current {
            Some(_) => None,
            None => {
                grant_operator_key(&state, &env_id, None, FirstWriteRace::NoOp, |seed| {
                    prepare_with(Some(seed))
                })
                .await?
            }
        };
        let prepared = match granted {
            Some(prepared) => prepared,
            None => {
                // No-op (the root already exists, or a concurrent first write
                // raced this seed): the `null` result still consumes the key —
                // record it standalone so a same-key retry replays it.
                let prepared = prepare_with(None)?;
                state.storage.record_journal(&prepared.journal).await?;
                prepared
            }
        };
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
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
    ApiJson(payload, fingerprint): ApiJson<AddTrustedKeyPayload>,
) -> Result<Response, ApiError> {
    let req = match load_trust_root_request(&state, &env_id, &headers, "add", fingerprint).await? {
        TrustRootGate::Replay(replay) => return Ok(replay),
        TrustRootGate::Fresh(req) => req,
    };
    let TrustRootRequest {
        idem_key,
        fingerprint,
        env_id,
        auth,
        env_revision,
        current,
    } = req;
    let recheck_key = idem_key.clone();
    let outcome = async {
        let supplied_key_id = payload.key_id.clone();
        let entry = trust_root::validate_trusted_key(TrustedKey {
            key_id: payload.key_id,
            public_key_pem: payload.public_key_pem,
        })?;
        // The audit target carries the full PEM so a later-removed key can be
        // reconstructed from the audit log alone — same recovery rationale as
        // the local CLI's audit target.
        let target = json!({
            "environment_id": env_id,
            "key_id": supplied_key_id,
            "public_key_pem": entry.public_key_pem,
        });

        let prepared = persist_trust_root_mutation(
            &state,
            &env_id,
            current,
            FirstWriteRace::Retry,
            |doc| {
                trust_root::apply_add(&mut doc.keys, entry.clone());
            },
            |doc| {
                let outcome = TrustRootAddOutcome {
                    added_key_id: supplied_key_id.clone(),
                    trusted_key_count: doc.keys.len(),
                };
                prepare_mutation(
                    &outcome,
                    &env_id,
                    "trust-root",
                    "add",
                    target.clone(),
                    idem_key.clone(),
                    &fingerprint,
                    &auth,
                    Some(env_revision.generation),
                    env_revision.clone(),
                )
            },
        )
        .await?
        .expect("Retry mode always persists");
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `DELETE /environments/{env_id}/trust-root/keys/{key_id}` — remove a
/// trusted key by case-insensitive id (A8 route 21). Silent no-op when the
/// id is absent; the pre-removal PEM is captured for the outcome's
/// recovery material. A no-op never persists the document — it must not
/// materialize a trust-root row where none existed (row absence is the
/// seed gate) — but its response is still ledgered: the removed-PEM
/// recovery material survives a lost response (a same-key retry replays
/// it instead of reporting "nothing removed").
pub(crate) async fn remove_trusted_key<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let req =
        match load_trust_root_request(&state, &env_id, &headers, "remove", fingerprint).await? {
            TrustRootGate::Replay(replay) => return Ok(replay),
            TrustRootGate::Fresh(req) => req,
        };
    let TrustRootRequest {
        idem_key,
        fingerprint,
        env_id,
        auth,
        env_revision,
        current,
    } = req;
    let recheck_key = idem_key.clone();
    let outcome = async {
        let (mut doc, precondition) = doc_and_precondition(current);
        let removed_public_key_pem = doc
            .keys
            .iter()
            .find(|k| k.key_id.eq_ignore_ascii_case(&key_id))
            .map(|k| k.public_key_pem.clone());
        let removed = trust_root::apply_remove(&mut doc.keys, &key_id);
        let target = json!({"environment_id": env_id, "key_id": key_id});
        let removed_outcome = TrustRootRemoveOutcome {
            removed_key_id: key_id,
            removed_public_key_pem,
            trusted_key_count: doc.keys.len(),
        };
        let prepared = prepare_mutation(
            &removed_outcome,
            &env_id,
            "trust-root",
            "remove",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(env_revision.generation),
            env_revision,
        )?;
        if removed {
            state
                .storage
                .upsert_trust_root_journaled(
                    &env_id,
                    &doc,
                    precondition.as_ref(),
                    Some(&prepared.journal),
                )
                .await?;
        } else {
            state.storage.record_journal(&prepared.journal).await?;
        }
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

// ---------------------------------------------------------------------------
// Handlers — reads
// ---------------------------------------------------------------------------

/// `GET /environments` — list persisted env ids. Plain JSON (reads carry no
/// mutation envelope or audit record).
pub(crate) async fn list_environments<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    // Use `read_scope` directly: it authenticates AND returns the scope
    // for filtering — one call instead of authenticate-then-authenticate.
    let scope = state.rbac.read_scope(bearer_token(&headers)).map_err(
        |RbacDenial { policy, reason, .. }| {
            ApiError(RemoteStoreError::Unauthorized { policy, reason })
        },
    )?;
    let envs = state.storage.list_envs().await?;
    let envs: Vec<_> = envs.into_iter().filter(|id| scope.permits(id)).collect();
    Ok(Json(json!({ "environments": envs })))
}

/// `GET /environments/{env_id}` — load one env with its CAS coordinates,
/// so a client can build the `Precondition` for its next write. This is
/// the "GET-env read endpoint" the remote dispatch's blocked verbs
/// (`revisions stage`/`warm`) name as their missing prerequisite.
pub(crate) async fn get_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<GetEnvironmentResponse>, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    authorize_read(&state, &headers, Some(&env_id))?;
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

/// `GET /environments/{env_id}/runtime` — the runtime host-config sidecar, or
/// `null` when none has been written. The deployer's `env show` over
/// `--store-url` reads this so it can distinguish "no runtime" from "runtime
/// not exposed over HTTP" (a missing ENV is still a 404).
pub(crate) async fn get_runtime<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<GetRuntimeResponse>, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    authorize_read(&state, &headers, Some(&env_id))?;
    if !state.storage.exists(&env_id).await? {
        return Err(ApiError(RemoteStoreError::NotFound));
    }
    let runtime = state
        .storage
        .load_runtime(&env_id)
        .await
        .map_err(load_storage_error)?
        .map(|loaded| loaded.value);
    Ok(Json(GetRuntimeResponse { runtime }))
}

/// `GET /environments/{env_id}/runtime` response body.
#[derive(Debug, Serialize)]
pub struct GetRuntimeResponse {
    pub runtime: Option<EnvironmentRuntime>,
}

/// `GET /environments/{env_id}/trust-root` — list the env's trusted keys.
/// An absent row reads as an empty key set (closed-by-default, mirroring
/// the LocalFS `load`), while a missing ENV is still a 404. Plain JSON in
/// the local CLI's `trust-root list` shape; the remote-dispatch `list`
/// verb wires up to this in the read-verbs follow-up.
pub(crate) async fn get_trust_root<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    authorize_read(&state, &headers, Some(&env_id))?;
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

// ---------------------------------------------------------------------------
// Handlers — backups (A8 #5, PR-4.4)
// ---------------------------------------------------------------------------
//
// A backup snapshots the environment ROW (the full canonical JSON the
// integrity digest covers) without touching it; restore is a guarded
// environment write like any other mutation. All three mutating verbs
// (`create` / `delete` / `restore`) wear the standard A8 envelope —
// `result` carries the contract's `BackupManifest` / deletion echo /
// `RestoreOutcome` — so the client's audit validation and the replay
// ledger work unchanged. Envelope CAS coordinates: create/delete echo the
// env's UNCHANGED coordinates (the trust-root sidecar precedent); restore
// carries the NEW coordinates of the restored document.
//
// The backup store is bounded per env (`MAX_BACKUPS_PER_ENV`): at the cap
// `create` answers 409 — recovery points are never silently evicted; the
// operator deletes explicitly.

/// `POST /environments/{env_id}/backups` — snapshot the environment row
/// (A8 #5 "create backup"). Bodyless; the server mints the ULID
/// `backup_id` and computes the manifest from the loaded row.
pub(crate) async fn create_backup<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "backup", "create").await?;
    let idem_key = require_idempotency_key(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        // Capture the composite snapshot (env + runtime + pack_answers) AND the
        // environment revision it was read at, atomically in one transaction.
        // Sourcing the generation from a separate load_env could race a
        // concurrent mutation and stamp the manifest with a generation that
        // does not match the captured content.
        let (snapshot, revision) = state
            .storage
            .load_env_snapshot(&env_id)
            .await
            .map_err(load_storage_error)?;
        let snapshot_json = serde_json::to_value(&snapshot).map_err(envelope_encode_error)?;
        let snapshot_digest = StateIntegrity::sha256_of(&snapshot_json).map_err(|err| {
            tracing::error!(error = %err, "backup snapshot hashing failed");
            ApiError(RemoteStoreError::Internal {
                message: "backup snapshot hashing failed".to_string(),
            })
        })?;
        // The manifest's integrity covers the environment document only
        // (contract-level digest); the snapshot_digest covers the
        // composite including sidecars. Hash the snapshot's env value
        // (the raw `Value` stored at rest) rather than the loaded typed
        // `Environment` — guarantees the restore cross-check matches.
        let integrity = StateIntegrity::sha256_of(&snapshot.environment).map_err(|err| {
            tracing::error!(error = %err, "env integrity hashing failed");
            ApiError(RemoteStoreError::Internal {
                message: "env integrity hashing failed".to_string(),
            })
        })?;
        // Size of the stored TEXT column — informational, documented as
        // the snapshot's serialized size.
        let size_bytes = snapshot_json.to_string().len() as u64;
        let manifest = BackupManifest {
            schema: SchemaVersion::BACKUP_MANIFEST_V1.into(),
            backup_id: ulid::Ulid::new().to_string(),
            env_id: env_id.clone(),
            created_at: Utc::now(),
            generation: revision.generation,
            integrity,
            size_bytes,
        };
        let target = json!({
            "environment_id": env_id,
            "backup_id": manifest.backup_id,
            "generation": manifest.generation,
        });
        let prepared = prepare_mutation(
            &manifest,
            &env_id,
            "backup",
            "create",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(revision.generation),
            revision,
        )?;
        state
            .storage
            .create_backup_journaled(
                &StoredBackup {
                    manifest,
                    state: snapshot_json,
                    snapshot_digest: snapshot_digest.digest,
                },
                Some(&prepared.journal),
            )
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `GET /environments/{env_id}/backups` — list backup manifests, oldest
/// first (A8 #5 "list backups"). Plain JSON like every read.
pub(crate) async fn list_backups<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    authorize_read(&state, &headers, Some(&env_id))?;
    if !state.storage.exists(&env_id).await? {
        return Err(ApiError(RemoteStoreError::NotFound));
    }
    let backups = state.storage.list_backups(&env_id).await?;
    Ok(Json(json!({"environment_id": env_id, "backups": backups})))
}

/// `DELETE /environments/{env_id}/backups/{backup_id}` — drop one backup.
/// Not in the contract's #5 table but required by the bounded store: at
/// the cap, `create` refuses until the operator deletes explicitly. An
/// unknown `backup_id` is a 404 that consumes nothing.
pub(crate) async fn delete_backup<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, backup_id)): Path<(String, String)>,
    headers: HeaderMap,
    Fingerprint(fingerprint): Fingerprint,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "backup", "delete").await?;
    let idem_key = require_idempotency_key(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        let target = json!({"environment_id": env_id, "backup_id": backup_id});
        let prepared = prepare_mutation(
            json!({"backup_id": backup_id, "deleted": true}),
            &env_id,
            "backup",
            "delete",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(loaded.revision.generation),
            loaded.revision.clone(),
        )?;
        let deleted = state
            .storage
            .delete_backup_journaled(&env_id, &backup_id, Some(&prepared.journal))
            .await?;
        if !deleted {
            return Err(ApiError(RemoteStoreError::DependentNotFound {
                detail: format!("backup `{backup_id}` not found in env `{env_id}`"),
            }));
        }
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `GET /environments/{env_id}/backups/{backup_id}/export` — pull a backup
/// OFFSITE as a portable, self-verifying [`BackupArtifact`] (A8 #5, disaster
/// recovery). The artifact carries the manifest, the FULL composite snapshot
/// (env + sidecars + audit), and the snapshot digest — the exact bytes a later
/// import re-verifies and replays, so a backup survives total store loss.
///
/// Though it performs no mutation (no idempotency key, no journal), export is
/// gated at BACKUP-OPERATOR privilege (`authorize_mutation` on
/// `backup`/`export`), NOT generic read: the snapshot is the complete recovery
/// payload — environment document, runtime, pack answers, and audit history —
/// which a read-only actor (entitled only to manifests, via `list_backups`)
/// must not be able to exfiltrate offsite. An unknown `backup_id` is a 404.
pub(crate) async fn export_backup<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path((env_id, backup_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<BackupArtifact>, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    authorize_mutation(&state, &headers, &env_id, "backup", "export").await?;
    let backup = state
        .storage
        .load_backup(&env_id, &backup_id)
        .await
        .map_err(load_storage_error)?
        .ok_or_else(|| {
            ApiError(RemoteStoreError::DependentNotFound {
                detail: format!("backup `{backup_id}` not found in env `{env_id}`"),
            })
        })?;
    Ok(Json(BackupArtifact {
        schema: SchemaVersion::BACKUP_ARTIFACT_V1.into(),
        manifest: backup.manifest,
        snapshot: backup.state,
        snapshot_digest: backup.snapshot_digest,
    }))
}

/// `POST /environments/{env_id}/import` — reconstruct an environment from a
/// portable [`BackupArtifact`] (A8 #5, disaster recovery). Unlike `restore` (a
/// precondition-guarded rollback of an EXISTING env), import is the FRESH-store
/// path: it refuses if the environment already exists (409) and otherwise
/// creates it at generation 1. The artifact carries no precondition — there is
/// no prior generation to pin after total loss. The composite snapshot's
/// integrity is verified (recompute the digest) BEFORE anything is written — a
/// corrupted artifact is never reconstructed (the same #6 guard restore
/// applies) — and the path `env_id` must match the artifact's manifest. The
/// commit is the same journaled write as every mutation, so the import is
/// audited and replay-protected.
pub(crate) async fn import_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<ImportRequest>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "backup", "import").await?;
    let idem_key = require_idempotency_key(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        let artifact = payload.artifact;
        // The artifact names the env it captured; importing it under a
        // different path would mis-key the reconstructed sidecars.
        if artifact.manifest.env_id != env_id {
            return Err(ApiError(RemoteStoreError::InvalidRequest {
                detail: format!(
                    "artifact env_id `{}` does not match path `{env_id}`",
                    artifact.manifest.env_id
                ),
            }));
        }
        // Verify the composite snapshot digest before importing — a corrupted
        // or tampered artifact is never reconstructed.
        let recomputed = StateIntegrity::sha256_of(&artifact.snapshot).map_err(|err| {
            tracing::error!(error = %err, "import snapshot hashing failed");
            ApiError(RemoteStoreError::Internal {
                message: "import snapshot hashing failed".to_string(),
            })
        })?;
        if recomputed.digest != artifact.snapshot_digest {
            return Err(ApiError(RemoteStoreError::IntegrityMismatch {
                expected: artifact.snapshot_digest.clone(),
                actual: recomputed.digest,
            }));
        }
        let snapshot: crate::storage::EnvSnapshot = serde_json::from_value(artifact.snapshot)
            .map_err(|err| {
                tracing::error!(error = %err, backup_id = %artifact.manifest.backup_id,
                        "import snapshot failed to decode");
                ApiError(RemoteStoreError::Internal {
                    message: "import snapshot failed to decode".to_string(),
                })
            })?;
        let imported_env: Environment = serde_json::from_value(snapshot.environment.clone())
            .map_err(|err| {
                tracing::error!(error = %err, backup_id = %artifact.manifest.backup_id,
                        "import environment failed to decode");
                ApiError(RemoteStoreError::Internal {
                    message: "import environment failed to decode".to_string(),
                })
            })?;
        // A fresh create: generation 1, no prior CAS state.
        let next = created_revision(&imported_env)?;
        let outcome = ImportOutcome {
            imported_generation: next.generation,
            integrity: artifact.manifest.integrity.clone(),
        };
        let target = json!({
            "environment_id": env_id,
            "backup_id": artifact.manifest.backup_id,
            "backup_generation": artifact.manifest.generation,
            "imported_generation": next.generation,
        });
        let prepared = prepare_mutation(
            &outcome,
            &env_id,
            "backup",
            "import",
            target,
            idem_key,
            &fingerprint,
            &auth,
            None,
            next,
        )?;
        // Existence is enforced by the storage layer's atomic create
        // (`AlreadyExists` → 409) — no load-then-check race.
        state
            .storage
            .import_env_journaled(&env_id, &snapshot, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}

/// `POST /environments/{env_id}/restore` — restore the environment from a
/// named backup (A8 #5 "restore"). The contract-pinned
/// [`RestoreRequest`] carries the precondition IN THE BODY, and it is
/// mandatory: `validate` rejects an empty pin (mapped to the same 428 a
/// blind guarded write gets), a stale pin is the standard 412. The
/// snapshot's integrity digest is recomputed before applying (contract #6
/// on the backup itself — a corrupted backup can never be restored), and
/// the commit is the same journaled CAS write as every other mutation, so
/// generation stays monotonic while content reverts.
pub(crate) async fn restore_environment<S: EnvironmentStorage>(
    State(state): State<AppState<S>>,
    Path(env_id): Path<String>,
    headers: HeaderMap,
    ApiJson(payload, fingerprint): ApiJson<RestoreRequest>,
) -> Result<Response, ApiError> {
    let env_id = parse_env_id(&env_id)?;
    let auth = authorize_mutation(&state, &headers, &env_id, "backup", "restore").await?;
    let idem_key = require_idempotency_key(&headers)?;
    if let Some(replay) = replay_gate(&state, &env_id, &idem_key, &fingerprint).await? {
        return Ok(replay);
    }
    let recheck_key = idem_key.clone();
    let outcome = async {
        payload.validate().map_err(|err| {
            // The contract's UnconditionalRestore — "the same 412/428
            // semantics as a normal guarded mutation": an empty pin is the
            // 428 a blind guarded write gets.
            ApiError(RemoteStoreError::PreconditionRequired {
                detail: err.to_string(),
            })
        })?;
        let backup = state
            .storage
            .load_backup(&env_id, &payload.backup_id)
            .await
            .map_err(load_storage_error)?
            .ok_or_else(|| {
                ApiError(RemoteStoreError::DependentNotFound {
                    detail: format!("backup `{}` not found in env `{env_id}`", payload.backup_id),
                })
            })?;
        // Verify the composite snapshot's digest before restoring.
        let recomputed = StateIntegrity::sha256_of(&backup.state).map_err(|err| {
            tracing::error!(error = %err, "backup snapshot hashing failed");
            ApiError(RemoteStoreError::Internal {
                message: "backup snapshot hashing failed".to_string(),
            })
        })?;
        if recomputed.digest != backup.snapshot_digest {
            return Err(ApiError(RemoteStoreError::IntegrityMismatch {
                expected: backup.snapshot_digest.clone(),
                actual: recomputed.digest,
            }));
        }
        // Decode the composite snapshot.
        let snapshot: crate::storage::EnvSnapshot =
            serde_json::from_value(backup.state).map_err(|err| {
                tracing::error!(error = %err, backup_id = %payload.backup_id,
                        "backup snapshot failed to decode");
                ApiError(RemoteStoreError::Internal {
                    message: "backup snapshot failed to decode".to_string(),
                })
            })?;
        let restored_env: Environment = serde_json::from_value(snapshot.environment.clone())
            .map_err(|err| {
                tracing::error!(error = %err, backup_id = %payload.backup_id,
                        "backup environment failed to decode");
                ApiError(RemoteStoreError::Internal {
                    message: "backup environment failed to decode".to_string(),
                })
            })?;
        let loaded = state
            .storage
            .load_env(&env_id)
            .await
            .map_err(load_storage_error)?;
        // The body's precondition pins the CALLER-observed state; check it
        // against the loaded revision up front so a stale pin is a clean
        // 412 before anything is built. The commit below re-pins the
        // loaded revision in full (the pre-built journal needs the
        // deterministic next generation).
        payload
            .precondition
            .check(&loaded.revision.etag, loaded.revision.generation)
            .map_err(|err| ApiError(RemoteStoreError::from(err)))?;
        let previous_generation = loaded.revision.generation;
        let next = next_revision(&restored_env, &loaded.revision)?;
        let outcome = RestoreOutcome {
            restored_generation: next.generation,
            integrity: backup.manifest.integrity.clone(),
        };
        let target = json!({
            "environment_id": env_id,
            "backup_id": payload.backup_id,
            "backup_generation": backup.manifest.generation,
            "restored_generation": next.generation,
        });
        let prepared = prepare_mutation(
            &outcome,
            &env_id,
            "backup",
            "restore",
            target,
            idem_key,
            &fingerprint,
            &auth,
            Some(previous_generation),
            next,
        )?;
        let precondition = resolve_precondition(None, &loaded.revision);
        state
            .storage
            .restore_env_journaled(&env_id, &snapshot, &precondition, Some(&prepared.journal))
            .await?;
        Ok(prepared.into_response())
    }
    .await;
    match outcome {
        Ok(response) => Ok(response),
        Err(err) => error_or_replay(&state, &env_id, &recheck_key, &fingerprint, err).await,
    }
}
