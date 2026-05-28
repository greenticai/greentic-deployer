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
