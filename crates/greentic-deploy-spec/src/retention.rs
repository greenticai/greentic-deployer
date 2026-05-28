//! Auxiliary policy/health value types for [`Environment`](crate::Environment).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Revocation policy for an Environment (`§5.1`). Detailed semantics
/// (revocation registry, broadcast cadence) are owned by `greentic-cap`; this
/// struct is intentionally a thin record carrying the binding-time settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationConfig {
    /// Whether revocation enforcement is required for this env.
    #[serde(default)]
    pub required: bool,
    /// Optional revocation list pointer (URI or env-relative path string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_ref: Option<String>,
}

/// Retention policy for revisions/audit (`§5.1`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// How many ready/archived revisions to keep per deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_revisions: Option<u32>,
    /// How many days to retain audit events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_retention_days: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    #[default]
    Unknown,
    Green,
    Yellow,
    Red,
}

/// Coarse health snapshot for the Environment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    #[serde(default)]
    pub state: HealthState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<DateTime<Utc>>,
}
