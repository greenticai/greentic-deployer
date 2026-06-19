//! Audit-event and authorization-decision wire shapes.
//!
//! A7 emits these locally (`greentic-deployer` owns the FS append writer
//! `AuditLog` and the local authorization gate `authorize_local_only`); A8
//! reuses the same shapes as the remote-store contract surface — a mutating
//! HTTP call returns the [`AuditEvent`] it recorded, and the RBAC decision is
//! an [`AuditDecision`]. Only the serializable shapes live here so the wire
//! contract has a single owner (the deployer keeps the behavior).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::version::SchemaVersion;

/// Phase A authorization policy identifier (`AuditDecision.policy`).
pub const POLICY_LOCAL_ONLY: &str = "local-only";

/// One append-only audit record. Covers every field plan §389 requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema: SchemaVersion,
    pub event_id: String,
    pub ts: DateTime<Utc>,
    pub actor: Actor,
    pub env_id: String,
    pub noun: String,
    pub verb: String,
    pub target: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub authorization: AuditDecision,
    pub result: AuditResult,
}

/// Who performed the mutation. `kind` is a string (one value `local-user`
/// today; A8's remote path adds service/operator kinds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

/// Authorization (RBAC) decision. Phase A uses the `local-only` policy; A8's
/// remote store returns the same shape from its RBAC engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum AuditDecision {
    Allow { policy: String, reason: String },
    Deny { policy: String, reason: String },
}

/// Outcome of the mutation as recorded in the audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum AuditResult {
    Ok,
    Error { kind: String, message: String },
    NotYetImplemented { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditEvent {
        AuditEvent {
            schema: SchemaVersion::AUDIT_EVENT_V1.into(),
            event_id: "01JTKW5B4W4Q5Y1CQW93F7S5VH".to_string(),
            ts: "2026-05-20T00:00:00Z".parse().unwrap(),
            actor: Actor {
                kind: "local-user".to_string(),
                user: Some("tester".to_string()),
                uid: Some(1000),
            },
            env_id: "local".to_string(),
            noun: "env".to_string(),
            verb: "create".to_string(),
            target: serde_json::json!({"environment_id": "local"}),
            previous_generation: None,
            new_generation: Some(0),
            idempotency_key: None,
            authorization: AuditDecision::Allow {
                policy: POLICY_LOCAL_ONLY.to_string(),
                reason: "env `local` is the local env".to_string(),
            },
            result: AuditResult::Ok,
        }
    }

    #[test]
    fn audit_event_round_trips() {
        let event = sample();
        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.env_id, "local");
        assert_eq!(back.verb, "create");
        assert_eq!(back.new_generation, Some(0));
    }

    #[test]
    fn decision_uses_tagged_kebab_case() {
        let json = serde_json::to_value(AuditDecision::Deny {
            policy: POLICY_LOCAL_ONLY.to_string(),
            reason: "nope".to_string(),
        })
        .unwrap();
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["policy"], POLICY_LOCAL_ONLY);
    }

    #[test]
    fn result_tag_round_trips_each_variant() {
        for result in [
            AuditResult::Ok,
            AuditResult::Error {
                kind: "unauthorized".to_string(),
                message: "denied".to_string(),
            },
            AuditResult::NotYetImplemented {
                detail: "A9".to_string(),
            },
        ] {
            let json = serde_json::to_string(&result).unwrap();
            let back: AuditResult = serde_json::from_str(&json).unwrap();
            assert_eq!(
                std::mem::discriminant(&result),
                std::mem::discriminant(&back)
            );
        }
    }

    #[test]
    fn optional_generations_omitted_when_none() {
        let mut event = sample();
        event.new_generation = None;
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.get("new_generation").is_none());
        assert!(json.get("previous_generation").is_none());
        assert!(json.get("idempotency_key").is_none());
    }
}
