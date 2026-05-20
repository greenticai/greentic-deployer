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

    /// Check the precondition against the server's current state. Returns the
    /// [`ConcurrencyConflict`] a `412 Precondition Failed` carries when stale.
    pub fn check(
        &self,
        current_etag: &StateEtag,
        current_generation: u64,
    ) -> Result<(), ConcurrencyConflict> {
        let etag_ok = self.if_match.as_ref().is_none_or(|e| e == current_etag);
        let gen_ok = self
            .expected_generation
            .is_none_or(|g| g == current_generation);
        if etag_ok && gen_ok {
            Ok(())
        } else {
            Err(ConcurrencyConflict {
                expected_etag: self.if_match.as_ref().map(|e| e.0.clone()),
                actual_etag: current_etag.0.clone(),
                expected_generation: self.expected_generation,
                actual_generation: current_generation,
            })
        }
    }
}

/// The mismatch a failed [`Precondition`] reports (the `412` response body).
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
/// [`IdempotencyKey`]. Lets a retry be classified without re-applying (#2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub key: IdempotencyKey,
    /// SHA-256 over the canonical request body, so a same-key retry can be told
    /// apart from a same-key *different* request.
    pub request_fingerprint: String,
    pub response_etag: StateEtag,
    pub response_generation: u64,
    pub stored_at: DateTime<Utc>,
}

impl IdempotencyRecord {
    /// Hash a request body into the fingerprint stored alongside the key.
    pub fn fingerprint<T: Serialize>(request: &T) -> Result<String, IntegrityError> {
        Ok(StateIntegrity::sha256_of(request)?.digest)
    }

    /// Classify an incoming request that reuses this record's key: a matching
    /// fingerprint is a [`IdempotencyOutcome::Replayed`]; a different one is a
    /// [`IdempotencyOutcome::Conflict`] (same key, different body — `409`).
    pub fn classify(&self, incoming_fingerprint: &str) -> IdempotencyOutcome {
        if self.request_fingerprint == incoming_fingerprint {
            IdempotencyOutcome::Replayed
        } else {
            IdempotencyOutcome::Conflict {
                reason: "idempotency key reused with a different request body".to_string(),
            }
        }
    }
}

/// How the server treated a mutating request with respect to its idempotency
/// key (#2). Mirrors the local `traffic::set` replay semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "idempotency", rename_all = "kebab-case")]
pub enum IdempotencyOutcome {
    /// New key — the mutation was applied.
    Applied,
    /// Known key, same request — the stored response is returned, no re-apply.
    Replayed,
    /// Known key, different request — rejected.
    Conflict { reason: String },
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
    pub schema: String,
    pub backup_id: String,
    pub env_id: EnvId,
    pub created_at: DateTime<Utc>,
    pub generation: u64,
    pub integrity: StateIntegrity,
    pub size_bytes: u64,
}

/// Request to restore an environment from a named backup (#5). The precondition
/// guards against clobbering a newer generation than the operator expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub backup_id: String,
    #[serde(default)]
    pub precondition: Precondition,
}

/// Outcome of a completed restore (#5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreOutcome {
    pub restored_generation: u64,
    pub etag: StateEtag,
    pub integrity: StateIntegrity,
}

/// Errors a remote store can return, each mapped to its HTTP status so the
/// client and server agree on the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RemoteStoreError {
    /// `If-Match`/generation precondition failed — `412`.
    #[error("precondition failed (stale generation/etag)")]
    PreconditionFailed(ConcurrencyConflict),
    /// Idempotency key reused with a different request — `409`.
    #[error("idempotency conflict: {reason}")]
    IdempotencyConflict { reason: String },
    /// RBAC denied the mutation — `403`.
    #[error("unauthorized: {reason} (policy `{policy}`)")]
    Unauthorized { policy: String, reason: String },
    /// Resource does not exist — `404`.
    #[error("environment not found")]
    NotFound,
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
            Self::IdempotencyConflict { .. } => 409,
            Self::Unauthorized { .. } => 403,
            Self::NotFound => 404,
            Self::IntegrityMismatch { .. } => 422,
            Self::NotYetImplemented { .. } => 501,
            Self::Internal { .. } => 500,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn etag(s: &str) -> StateEtag {
        StateEtag(s.to_string())
    }

    #[test]
    fn etag_derives_from_content_hash() {
        let resource = serde_json::json!({"generation": 1, "name": "local"});
        let tag = StateEtag::of(&resource).unwrap();
        assert_eq!(tag.0, StateIntegrity::sha256_of(&resource).unwrap().digest);
        assert_eq!(tag.header_value(), format!("\"{}\"", tag.0));
    }

    #[test]
    fn precondition_empty_always_matches() {
        assert!(Precondition::default().check(&etag("abc"), 7).is_ok());
    }

    #[test]
    fn precondition_matching_etag_and_generation_passes() {
        let pre = Precondition::matching(etag("abc"), 7);
        assert!(pre.check(&etag("abc"), 7).is_ok());
    }

    #[test]
    fn precondition_stale_generation_conflicts() {
        let pre = Precondition::matching(etag("abc"), 6);
        let conflict = pre.check(&etag("abc"), 7).unwrap_err();
        assert_eq!(conflict.expected_generation, Some(6));
        assert_eq!(conflict.actual_generation, 7);
    }

    #[test]
    fn precondition_stale_etag_conflicts() {
        let pre = Precondition::matching(etag("old"), 7);
        let conflict = pre.check(&etag("new"), 7).unwrap_err();
        assert_eq!(conflict.expected_etag.as_deref(), Some("old"));
        assert_eq!(conflict.actual_etag, "new");
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
            response_etag: etag("abc"),
            response_generation: 3,
            stored_at: Utc::now(),
        };

        let same = IdempotencyRecord::fingerprint(&body).unwrap();
        assert_eq!(record.classify(&same), IdempotencyOutcome::Replayed);

        let other = serde_json::json!({"split": [{"rev": "b", "bps": 10000}]});
        let other_fp = IdempotencyRecord::fingerprint(&other).unwrap();
        assert!(matches!(
            record.classify(&other_fp),
            IdempotencyOutcome::Conflict { .. }
        ));
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
            RemoteStoreError::IdempotencyConflict {
                reason: "x".to_string()
            }
            .http_status(),
            409
        );
        assert_eq!(RemoteStoreError::NotFound.http_status(), 404);
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
