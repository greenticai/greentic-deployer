//! `greentic.runtime-config.v1` (`§5.7`).
//!
//! Materialized by the operator from `Environment` + active `Revision`s +
//! `TrafficSplit`s. Each runtime-config carries one
//! [`RevisionRuntimeBlock`](RevisionRuntimeBlock) per ready revision across all
//! deployments in the env.

use crate::ids::{BundleId, DeploymentId, RevisionId};
use crate::version::SchemaVersion;
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionRuntimeBlock {
    pub deployment_id: DeploymentId,
    pub revision_id: RevisionId,
    pub bundle_id: BundleId,
    /// Env-relative paths to pinned per-pack lockfiles.
    #[serde(default)]
    pub pack_list_refs: Vec<PathBuf>,
    /// Env-relative paths to `pack-config.v1` documents per pack.
    #[serde(default)]
    pub pack_config_refs: Vec<PathBuf>,
    pub weight_bps: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub schema: SchemaVersion,
    pub env_id: EnvId,
    pub revisions: Vec<RevisionRuntimeBlock>,
}

impl RuntimeConfig {
    pub fn schema_str() -> &'static str {
        SchemaVersion::RUNTIME_CONFIG_V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuntimeConfig {
        RuntimeConfig {
            schema: SchemaVersion::new(SchemaVersion::RUNTIME_CONFIG_V1),
            env_id: greentic_types::EnvId::try_from("local").unwrap(),
            revisions: vec![RevisionRuntimeBlock {
                deployment_id: DeploymentId::new(),
                revision_id: RevisionId::new(),
                bundle_id: "customer.support".into(),
                pack_list_refs: vec![PathBuf::from("revisions/01/PackList.lock")],
                pack_config_refs: vec![PathBuf::from("revisions/01/config.json")],
                weight_bps: 10_000,
            }],
        }
    }

    #[test]
    fn schema_str_matches_constant() {
        assert_eq!(
            RuntimeConfig::schema_str(),
            SchemaVersion::RUNTIME_CONFIG_V1
        );
    }

    #[test]
    fn json_round_trip() {
        let original = sample();
        let json = serde_json::to_string(&original).unwrap();
        let back: RuntimeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn empty_revisions_defaults() {
        let json = serde_json::json!({
            "schema": SchemaVersion::RUNTIME_CONFIG_V1,
            "env_id": "local",
            "revisions": []
        });
        let rc: RuntimeConfig = serde_json::from_value(json).unwrap();
        assert!(rc.revisions.is_empty());
    }
}
