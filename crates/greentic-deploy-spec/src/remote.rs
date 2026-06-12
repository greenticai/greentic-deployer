//! Remote `EnvironmentStore` HTTP contract (plan §5, Phase A gate A8).
//!
//! `LocalFsStore` (in `greentic-deployer`) is the only implementation that
//! ships in Phase A. This module is the *contract* every non-local production
//! store must satisfy before AWS/K8s deploys can be called production-ready
//! (plan §388, §389, §391): optimistic-concurrency writes, idempotency replay,
//! an RBAC decision, an append-only audit record returned per mutation,
//! backup/restore, and at-rest corruption detection.
//!
//! These are pure wire shapes — no transport, no client. The companion HTTP
//! surface (headers, methods, status codes) is documented in the
//! `greentic-operator` API docs; the status mapping is encoded here on
//! [`RemoteStoreError::http_status`] so both sides agree.
//!
//! See also: [`StateIntegrity`](crate::integrity::StateIntegrity) (#6),
//! [`AuditEvent`](crate::audit::AuditEvent) / [`AuditDecision`] (#3, #4).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::EnvId;
use crate::audit::{Actor, AuditDecision, AuditEvent};
use crate::integrity::{IntegrityError, StateIntegrity};
use crate::version::SchemaVersion;

/// Strong entity-tag for a persisted resource. The validator is the resource's
/// SHA-256 content hash (same digest as [`StateIntegrity`]), so a stale writer
/// whose `If-Match` no longer equals the server's tag is rejected (#1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StateEtag(pub String);

impl StateEtag {
    /// Derive the ETag from a resource by hashing its canonical JSON.
    pub fn of<T: Serialize>(value: &T) -> Result<Self, IntegrityError> {
        Ok(Self(StateIntegrity::sha256_of(value)?.digest))
    }

    /// Build an ETag from an already-computed integrity hash.
    pub fn from_integrity(integrity: &StateIntegrity) -> Self {
        Self(integrity.digest.clone())
    }

    /// HTTP `ETag` / `If-Match` header form — the opaque-quoted strong validator.
    pub fn header_value(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

/// Optimistic-concurrency precondition for a mutating request (#1). A request
/// may pin the prior ETag (`If-Match`), the prior generation, or both. An empty
/// precondition is an unconditional write (creates only — see the contract doc).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Precondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_match: Option<StateEtag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
}

impl Precondition {
    /// Pin both the ETag and generation of the resource as currently observed.
    pub fn matching(etag: StateEtag, generation: u64) -> Self {
        Self {
            if_match: Some(etag),
            expected_generation: Some(generation),
        }
    }

    /// True if the precondition pins prior state (an `If-Match` and/or an
    /// expected generation). An empty precondition pins nothing.
    pub fn is_conditional(&self) -> bool {
        self.if_match.is_some() || self.expected_generation.is_some()
    }

    /// Check the precondition against the server's current state for a guarded
    /// (update/restore/delete) write.
    ///
    /// An **empty** precondition is rejected with [`PreconditionError::Required`]
    /// rather than silently passing — a conditional write must pin prior state,
    /// otherwise a stale or malformed client clobbers a newer generation. The
    /// create-if-absent path does not call `check`; it is gated by an existence
    /// check on the server (see the contract doc).
    pub fn check(
        &self,
        current_etag: &StateEtag,
        current_generation: u64,
    ) -> Result<(), PreconditionError> {
        if !self.is_conditional() {
            return Err(PreconditionError::Required);
        }
        let etag_ok = self.if_match.as_ref().is_none_or(|e| e == current_etag);
        let gen_ok = self
            .expected_generation
            .is_none_or(|g| g == current_generation);
        if etag_ok && gen_ok {
            Ok(())
        } else {
            Err(PreconditionError::Conflict(ConcurrencyConflict {
                expected_etag: self.if_match.as_ref().map(|e| e.0.clone()),
                actual_etag: current_etag.0.clone(),
                expected_generation: self.expected_generation,
                actual_generation: current_generation,
            }))
        }
    }
}

/// Why a guarded write's [`Precondition`] did not pass.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PreconditionError {
    /// The precondition pinned no prior state (empty `If-Match`/generation) on a
    /// path where pinning is mandatory — `428 Precondition Required`.
    #[error("a conditional write must pin If-Match and/or expected generation")]
    Required,
    /// The pinned state is stale — `412 Precondition Failed`.
    #[error("precondition failed (stale generation/etag)")]
    Conflict(ConcurrencyConflict),
}

/// The mismatch a stale [`Precondition`] reports (the `412` response body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcurrencyConflict {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_etag: Option<String>,
    pub actual_etag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
    pub actual_generation: u64,
}

/// Idempotency key carried by every mutating request (#2). Non-empty; the
/// contract recommends a ULID. Validated on construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(key: impl Into<String>) -> Result<Self, RemoteContractError> {
        let key = key.into();
        if key.trim().is_empty() {
            return Err(RemoteContractError::EmptyIdempotencyKey);
        }
        Ok(Self(key))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = RemoteContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<IdempotencyKey> for String {
    fn from(key: IdempotencyKey) -> Self {
        key.0
    }
}

/// Server-stored memo of a previously applied mutating request, keyed by its
/// [`IdempotencyKey`] (#2).
///
/// Stores the **full original [`MutationResponse`]** — not just its ETag and
/// generation — so a retry whose original HTTP response was lost can be replied
/// to verbatim, including the original [`AuditEvent`], without re-applying
/// state. Persisting only the etag/generation would force a replay to re-run
/// the mutation or fabricate a fresh audit event, breaking audit fidelity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub key: IdempotencyKey,
    /// SHA-256 over the canonical request body, so a same-key retry can be told
    /// apart from a same-key *different* request.
    pub request_fingerprint: String,
    /// The original response, returned verbatim on a matching replay.
    pub response: MutationResponse,
    pub stored_at: DateTime<Utc>,
}

impl IdempotencyRecord {
    /// Hash a request body into the fingerprint stored alongside the key.
    pub fn fingerprint<T: Serialize>(request: &T) -> Result<String, IntegrityError> {
        Ok(StateIntegrity::sha256_of(request)?.digest)
    }

    /// Match an incoming request that reuses this record's key. A matching
    /// fingerprint yields the stored original response to return **verbatim,
    /// without re-applying state**; a different fingerprint is a `409` conflict.
    pub fn match_request(&self, incoming_fingerprint: &str) -> IdempotencyReplay<'_> {
        if self.request_fingerprint == incoming_fingerprint {
            IdempotencyReplay::Replay(&self.response)
        } else {
            IdempotencyReplay::Conflict {
                reason: "idempotency key reused with a different request body".to_string(),
            }
        }
    }
}

/// Result of matching a key-reusing request against a stored [`IdempotencyRecord`].
#[derive(Debug)]
pub enum IdempotencyReplay<'a> {
    /// Same key + same request — return this stored response verbatim; no
    /// state was re-applied.
    Replay(&'a MutationResponse),
    /// Same key + different request body — maps to
    /// [`RemoteStoreError::IdempotencyConflict`] (`409`).
    Conflict { reason: String },
}

/// How the server treated a mutating request with respect to its idempotency
/// key, recorded on the returned [`MutationResponse`] (#2). Conflicts are not a
/// success outcome — they surface as [`RemoteStoreError::IdempotencyConflict`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "idempotency", rename_all = "kebab-case")]
pub enum IdempotencyOutcome {
    /// New key — the mutation was applied.
    Applied,
    /// Known key, same request — this response is a verbatim replay of the
    /// original; the embedded audit event is the original event, unchanged.
    Replayed,
}

/// An authorization (RBAC) decision request (#3). The decision returned is an
/// [`AuditDecision`]; the local Phase A policy is `local-only`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacRequest {
    pub actor: Actor,
    pub env_id: EnvId,
    pub noun: String,
    pub verb: String,
    pub target: Value,
}

/// The body returned by a successful mutating call (#4). Carries the new strong
/// validator + generation for the next CAS, how the idempotency key was
/// treated, and the audit record the server wrote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationResponse {
    pub etag: StateEtag,
    pub generation: u64,
    pub idempotency: IdempotencyOutcome,
    pub audit: AuditEvent,
}

/// Metadata describing one stored backup of an environment's state (#5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub schema: SchemaVersion,
    pub backup_id: String,
    pub env_id: EnvId,
    pub created_at: DateTime<Utc>,
    pub generation: u64,
    pub integrity: StateIntegrity,
    pub size_bytes: u64,
}

/// Request to restore an environment from a named backup (#5).
///
/// `precondition` is mandatory and must pin prior state: a restore is never a
/// create, so an empty (blind) precondition could clobber a newer generation.
/// The field has no serde default — a request omitting it fails to deserialize
/// — and [`RestoreRequest::validate`] additionally rejects a present-but-empty
/// precondition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub backup_id: String,
    pub precondition: Precondition,
}

impl RestoreRequest {
    /// Reject a restore that pins no prior state (an empty precondition).
    pub fn validate(&self) -> Result<(), RemoteContractError> {
        if !self.precondition.is_conditional() {
            return Err(RemoteContractError::UnconditionalRestore);
        }
        Ok(())
    }
}

/// Outcome of a completed restore (#5). The strong ETag is derived from
/// `integrity` (it is the same digest), so it is exposed as [`RestoreOutcome::etag`]
/// rather than stored as a second, divergeable field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreOutcome {
    pub restored_generation: u64,
    pub integrity: StateIntegrity,
}

impl RestoreOutcome {
    /// The strong ETag of the restored state (the integrity digest).
    pub fn etag(&self) -> StateEtag {
        StateEtag::from_integrity(&self.integrity)
    }
}

/// Errors a remote store can return, each mapped to its HTTP status so the
/// client and server agree on the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RemoteStoreError {
    /// `If-Match`/generation precondition failed — `412`.
    #[error("precondition failed (stale generation/etag)")]
    PreconditionFailed(ConcurrencyConflict),
    /// A guarded write pinned no prior state — `428`.
    #[error("precondition required: {detail}")]
    PreconditionRequired { detail: String },
    /// Idempotency key reused with a different request — `409`.
    #[error("idempotency conflict: {reason}")]
    IdempotencyConflict { reason: String },
    /// RBAC denied the mutation — `403`.
    #[error("unauthorized: {reason} (policy `{policy}`)")]
    Unauthorized { policy: String, reason: String },
    /// Resource does not exist — `404`.
    #[error("environment not found")]
    NotFound,
    /// Create-shaped request targeting a resource that already exists — `409`.
    /// Distinct from [`RemoteStoreError::IdempotencyConflict`] (same status):
    /// that one is a key-reuse protocol violation, this one is a domain
    /// conflict the caller resolves with an update verb instead.
    #[error("already exists: {detail}")]
    AlreadyExists { detail: String },
    /// Request body failed validation before any state was touched — `400`.
    /// Covers malformed payloads and key/payload mismatches (e.g. a body
    /// whose `env_id` contradicts the URL).
    #[error("invalid request: {detail}")]
    InvalidRequest { detail: String },
    /// Stored state failed its integrity hash — `422`.
    #[error("integrity mismatch: expected {expected}, computed {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    /// The operation is recognized but not yet implemented — `501`.
    #[error("not yet implemented: {detail}")]
    NotYetImplemented { detail: String },
    /// Store-internal failure — `500`.
    #[error("internal store error: {message}")]
    Internal { message: String },
}

impl RemoteStoreError {
    /// HTTP status code this error maps to.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::PreconditionFailed(_) => 412,
            Self::PreconditionRequired { .. } => 428,
            Self::IdempotencyConflict { .. } => 409,
            Self::Unauthorized { .. } => 403,
            Self::NotFound => 404,
            Self::AlreadyExists { .. } => 409,
            Self::InvalidRequest { .. } => 400,
            Self::IntegrityMismatch { .. } => 422,
            Self::NotYetImplemented { .. } => 501,
            Self::Internal { .. } => 500,
        }
    }
}

impl From<PreconditionError> for RemoteStoreError {
    fn from(err: PreconditionError) -> Self {
        match err {
            PreconditionError::Required => RemoteStoreError::PreconditionRequired {
                detail: PreconditionError::Required.to_string(),
            },
            PreconditionError::Conflict(conflict) => RemoteStoreError::PreconditionFailed(conflict),
        }
    }
}

impl From<AuditDecision> for Result<(), RemoteStoreError> {
    /// A `Deny` decision becomes a `403 Unauthorized`; `Allow` is `Ok`.
    fn from(decision: AuditDecision) -> Self {
        match decision {
            AuditDecision::Allow { .. } => Ok(()),
            AuditDecision::Deny { policy, reason } => {
                Err(RemoteStoreError::Unauthorized { policy, reason })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RemoteContractError {
    #[error("idempotency key must not be empty")]
    EmptyIdempotencyKey,
    #[error("restore requires a precondition that pins prior state")]
    UnconditionalRestore,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditResult;

    fn etag(s: &str) -> StateEtag {
        StateEtag(s.to_string())
    }

    fn sample_response(etag_value: &str, generation: u64) -> MutationResponse {
        MutationResponse {
            etag: etag(etag_value),
            generation,
            idempotency: IdempotencyOutcome::Applied,
            audit: AuditEvent {
                schema: SchemaVersion::AUDIT_EVENT_V1.into(),
                event_id: "01JTKW5B4W4Q5Y1CQW93F7S5VH".to_string(),
                ts: "2026-05-20T00:00:00Z".parse().unwrap(),
                actor: Actor {
                    kind: "local-user".to_string(),
                    user: Some("tester".to_string()),
                    uid: Some(1000),
                },
                env_id: "local".to_string(),
                noun: "traffic".to_string(),
                verb: "set".to_string(),
                target: serde_json::json!({"env": "local"}),
                previous_generation: Some(generation.saturating_sub(1)),
                new_generation: Some(generation),
                idempotency_key: Some("k1".to_string()),
                authorization: AuditDecision::Allow {
                    policy: "local-only".to_string(),
                    reason: "ok".to_string(),
                },
                result: AuditResult::Ok,
            },
        }
    }

    #[test]
    fn etag_derives_from_content_hash() {
        let resource = serde_json::json!({"generation": 1, "name": "local"});
        let tag = StateEtag::of(&resource).unwrap();
        assert_eq!(tag.0, StateIntegrity::sha256_of(&resource).unwrap().digest);
        assert_eq!(tag.header_value(), format!("\"{}\"", tag.0));
    }

    #[test]
    fn precondition_empty_is_rejected_not_blindly_passed() {
        assert!(!Precondition::default().is_conditional());
        let err = Precondition::default().check(&etag("abc"), 7).unwrap_err();
        assert_eq!(err, PreconditionError::Required);
        let mapped: RemoteStoreError = err.into();
        assert_eq!(mapped.http_status(), 428);
    }

    #[test]
    fn precondition_matching_etag_and_generation_passes() {
        let pre = Precondition::matching(etag("abc"), 7);
        assert!(pre.is_conditional());
        assert!(pre.check(&etag("abc"), 7).is_ok());
    }

    #[test]
    fn precondition_generation_only_is_conditional() {
        let pre = Precondition {
            if_match: None,
            expected_generation: Some(7),
        };
        assert!(pre.is_conditional());
        assert!(pre.check(&etag("anything"), 7).is_ok());
    }

    #[test]
    fn precondition_stale_generation_conflicts() {
        let pre = Precondition::matching(etag("abc"), 6);
        let PreconditionError::Conflict(conflict) = pre.check(&etag("abc"), 7).unwrap_err() else {
            panic!("expected a conflict");
        };
        assert_eq!(conflict.expected_generation, Some(6));
        assert_eq!(conflict.actual_generation, 7);
    }

    #[test]
    fn precondition_stale_etag_conflicts() {
        let pre = Precondition::matching(etag("old"), 7);
        let PreconditionError::Conflict(conflict) = pre.check(&etag("new"), 7).unwrap_err() else {
            panic!("expected a conflict");
        };
        assert_eq!(conflict.expected_etag.as_deref(), Some("old"));
        assert_eq!(conflict.actual_etag, "new");
    }

    #[test]
    fn restore_request_requires_conditional_precondition() {
        let blind = RestoreRequest {
            backup_id: "b1".to_string(),
            precondition: Precondition::default(),
        };
        assert_eq!(
            blind.validate().unwrap_err(),
            RemoteContractError::UnconditionalRestore
        );

        let guarded = RestoreRequest {
            backup_id: "b1".to_string(),
            precondition: Precondition::matching(etag("abc"), 3),
        };
        assert!(guarded.validate().is_ok());
    }

    #[test]
    fn restore_request_precondition_is_not_serde_defaulted() {
        // Omitting the precondition is a hard deserialize error, not a silent
        // empty (blind) precondition.
        let err = serde_json::from_str::<RestoreRequest>(r#"{"backup_id":"b1"}"#);
        assert!(
            err.is_err(),
            "missing precondition must fail to deserialize"
        );
    }

    #[test]
    fn idempotency_key_rejects_empty() {
        assert!(IdempotencyKey::new("  ").is_err());
        assert_eq!(IdempotencyKey::new("k1").unwrap().as_str(), "k1");
    }

    #[test]
    fn idempotency_key_deserializes_through_validation() {
        assert!(serde_json::from_str::<IdempotencyKey>("\"\"").is_err());
        let key: IdempotencyKey = serde_json::from_str("\"01JABC\"").unwrap();
        assert_eq!(key.as_str(), "01JABC");
    }

    #[test]
    fn idempotency_same_body_replays_different_body_conflicts() {
        let body = serde_json::json!({"split": [{"rev": "a", "bps": 10000}]});
        let record = IdempotencyRecord {
            key: IdempotencyKey::new("k1").unwrap(),
            request_fingerprint: IdempotencyRecord::fingerprint(&body).unwrap(),
            response: sample_response("abc", 3),
            stored_at: Utc::now(),
        };

        let same = IdempotencyRecord::fingerprint(&body).unwrap();
        assert!(matches!(
            record.match_request(&same),
            IdempotencyReplay::Replay(_)
        ));

        let other = serde_json::json!({"split": [{"rev": "b", "bps": 10000}]});
        let other_fp = IdempotencyRecord::fingerprint(&other).unwrap();
        assert!(matches!(
            record.match_request(&other_fp),
            IdempotencyReplay::Conflict { .. }
        ));
    }

    #[test]
    fn idempotency_replay_returns_original_response_and_audit_verbatim() {
        let body = serde_json::json!({"split": [{"rev": "a", "bps": 10000}]});
        let original = sample_response("abc", 3);
        let record = IdempotencyRecord {
            key: IdempotencyKey::new("k1").unwrap(),
            request_fingerprint: IdempotencyRecord::fingerprint(&body).unwrap(),
            response: original.clone(),
            stored_at: Utc::now(),
        };

        let same = IdempotencyRecord::fingerprint(&body).unwrap();
        let IdempotencyReplay::Replay(replayed) = record.match_request(&same) else {
            panic!("expected a replay");
        };
        assert_eq!(replayed.etag, original.etag);
        assert_eq!(replayed.generation, original.generation);
        assert_eq!(replayed.audit.event_id, original.audit.event_id);
        assert_eq!(replayed.audit.verb, "set");
        // The full record survives a JSON round-trip, so the stored response is
        // durably replayable across process restarts.
        let json = serde_json::to_string(&record).unwrap();
        let back: IdempotencyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.response.audit.event_id, original.audit.event_id);
    }

    #[test]
    fn deny_decision_maps_to_unauthorized() {
        let denied = AuditDecision::Deny {
            policy: "local-only".to_string(),
            reason: "non-local".to_string(),
        };
        let result: Result<(), RemoteStoreError> = denied.into();
        let err = result.unwrap_err();
        assert_eq!(err.http_status(), 403);
        assert!(matches!(err, RemoteStoreError::Unauthorized { .. }));

        let allowed = AuditDecision::Allow {
            policy: "local-only".to_string(),
            reason: "ok".to_string(),
        };
        let result: Result<(), RemoteStoreError> = allowed.into();
        assert!(result.is_ok());
    }

    #[test]
    fn error_status_mapping_is_stable() {
        assert_eq!(
            RemoteStoreError::PreconditionFailed(ConcurrencyConflict {
                expected_etag: None,
                actual_etag: "x".to_string(),
                expected_generation: None,
                actual_generation: 1,
            })
            .http_status(),
            412
        );
        assert_eq!(
            RemoteStoreError::PreconditionRequired {
                detail: "x".to_string()
            }
            .http_status(),
            428
        );
        assert_eq!(
            RemoteStoreError::IdempotencyConflict {
                reason: "x".to_string()
            }
            .http_status(),
            409
        );
        assert_eq!(RemoteStoreError::NotFound.http_status(), 404);
        assert_eq!(
            RemoteStoreError::AlreadyExists {
                detail: "x".to_string()
            }
            .http_status(),
            409
        );
        assert_eq!(
            RemoteStoreError::InvalidRequest {
                detail: "x".to_string()
            }
            .http_status(),
            400
        );
        assert_eq!(
            RemoteStoreError::IntegrityMismatch {
                expected: "a".to_string(),
                actual: "b".to_string()
            }
            .http_status(),
            422
        );
        assert_eq!(
            RemoteStoreError::NotYetImplemented {
                detail: "x".to_string()
            }
            .http_status(),
            501
        );
        assert_eq!(
            RemoteStoreError::Internal {
                message: "x".to_string()
            }
            .http_status(),
            500
        );
    }

    #[test]
    fn remote_store_error_round_trips_tagged() {
        let err = RemoteStoreError::Unauthorized {
            policy: "local-only".to_string(),
            reason: "nope".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "unauthorized");
        let back: RemoteStoreError = serde_json::from_value(json).unwrap();
        assert_eq!(back, err);
    }
}
