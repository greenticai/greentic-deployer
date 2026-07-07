//! `greentic.pack-config.v1` (`§5.6`).
//!
//! Three address spaces in one schema:
//! - `non_secret` — inline literal values (wizard answers, non-sensitive).
//! - `secret_refs` — [`SecretRef`] URIs resolved through `Environment.packs[secrets]`.
//! - `runtime_refs` — [`RuntimeRef`] URIs resolved through
//!   [`EnvironmentRuntime::discovered`](crate::EnvironmentRuntime).
//!
//! Runtime resolves `secret_refs` and `runtime_refs` lazily; values never embed
//! in the bundle.

use crate::ids::{PackId, RevisionId};
use crate::refs::{RuntimeRef, SecretRef};
use crate::version::SchemaVersion;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PackConfig {
    pub schema: SchemaVersion,
    pub pack_id: PackId,
    pub revision_id: RevisionId,
    #[serde(default)]
    pub non_secret: BTreeMap<String, Value>,
    #[serde(default)]
    pub secret_refs: BTreeMap<String, SecretRef>,
    #[serde(default)]
    pub runtime_refs: BTreeMap<String, RuntimeRef>,
}

impl PackConfig {
    pub fn schema_str() -> &'static str {
        SchemaVersion::PACK_CONFIG_V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PackConfig {
        let mut non_secret = BTreeMap::new();
        non_secret.insert("locale".into(), serde_json::json!("en-GB"));
        PackConfig {
            schema: SchemaVersion::new(SchemaVersion::PACK_CONFIG_V1),
            pack_id: PackId::new("customer.support.flows"),
            revision_id: RevisionId::new(),
            non_secret,
            secret_refs: BTreeMap::new(),
            runtime_refs: BTreeMap::new(),
        }
    }

    #[test]
    fn schema_str_matches_constant() {
        assert_eq!(PackConfig::schema_str(), SchemaVersion::PACK_CONFIG_V1);
    }

    #[test]
    fn json_round_trip() {
        let original = sample();
        let json = serde_json::to_string(&original).unwrap();
        let back: PackConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn maps_default_to_empty() {
        let json = serde_json::json!({
            "schema": SchemaVersion::PACK_CONFIG_V1,
            "pack_id": "test.pack",
            "revision_id": RevisionId::new().to_string(),
        });
        let pc: PackConfig = serde_json::from_value(json).unwrap();
        assert!(pc.non_secret.is_empty());
        assert!(pc.secret_refs.is_empty());
        assert!(pc.runtime_refs.is_empty());
    }
}
