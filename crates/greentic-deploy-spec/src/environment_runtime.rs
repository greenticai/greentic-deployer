//! `greentic.environment-runtime.v1` (`§5.1a`).
//!
//! Sibling file `runtime.json`. Written by the deployer env-pack after each
//! apply; consumed by the runtime for `runtime://` lookups.

use crate::capability_slot::PackDescriptor;
use crate::version::SchemaVersion;
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A discovered runtime value — usually a string, occasionally a nested map
/// (e.g. `generated_secret_arns: { bot_token: ... }`). Stored as `serde_json::Value`
/// to preserve nesting without forcing a typed schema on every deployer.
pub type RuntimeDiscoveryValue = Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentRuntime {
    pub schema: SchemaVersion,
    pub environment_id: EnvId,
    #[serde(default)]
    pub discovered: BTreeMap<String, RuntimeDiscoveryValue>,
    pub generated_at: DateTime<Utc>,
    pub generated_by: PackDescriptor,
    /// Bumped each apply.
    pub generation: u64,
}

impl EnvironmentRuntime {
    pub fn schema_str() -> &'static str {
        SchemaVersion::ENVIRONMENT_RUNTIME_V1
    }
}
