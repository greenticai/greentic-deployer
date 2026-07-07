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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample() -> EnvironmentRuntime {
        let mut discovered = BTreeMap::new();
        discovered.insert(
            "alb_dns".into(),
            serde_json::Value::String("a.example.com".into()),
        );
        EnvironmentRuntime {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
            environment_id: greentic_types::EnvId::from_str("local").unwrap(),
            discovered,
            generated_at: Utc::now(),
            generated_by: PackDescriptor::try_new("greentic.deployer.local-process@1.0.0").unwrap(),
            generation: 1,
        }
    }

    #[test]
    fn schema_str_matches_constant() {
        assert_eq!(
            EnvironmentRuntime::schema_str(),
            SchemaVersion::ENVIRONMENT_RUNTIME_V1
        );
    }

    #[test]
    fn json_round_trip() {
        let original = sample();
        let json = serde_json::to_string(&original).unwrap();
        let back: EnvironmentRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn discovered_defaults_to_empty() {
        let json = serde_json::json!({
            "schema": SchemaVersion::ENVIRONMENT_RUNTIME_V1,
            "environment_id": "local",
            "generated_at": "2026-01-01T00:00:00Z",
            "generated_by": "greentic.deployer.local-process@1.0.0",
            "generation": 1
        });
        let rt: EnvironmentRuntime = serde_json::from_value(json).unwrap();
        assert!(rt.discovered.is_empty());
    }
}
