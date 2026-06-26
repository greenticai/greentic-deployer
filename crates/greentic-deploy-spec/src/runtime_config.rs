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
