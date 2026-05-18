//! `greentic.traffic-split.v1` (`§5.3`).
//!
//! One TrafficSplit per `deployment_id`. Entries sum to exactly 10,000 bps.

use crate::error::SpecError;
use crate::ids::{BundleId, DeploymentId, RevisionId};
use crate::version::SchemaVersion;
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const BASIS_POINTS_TOTAL: u32 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSplitEntry {
    pub revision_id: RevisionId,
    pub weight_bps: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSplit {
    pub schema: SchemaVersion,
    pub env_id: EnvId,
    pub deployment_id: DeploymentId,
    pub bundle_id: BundleId,
    pub generation: u64,
    pub entries: Vec<TrafficSplitEntry>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub idempotency_key: String,
    pub authorization_ref: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_split_ref: Option<PathBuf>,
}

impl TrafficSplit {
    pub fn schema_str() -> &'static str {
        SchemaVersion::TRAFFIC_SPLIT_V1
    }

    /// `§5.3`: sum of `weight_bps` MUST equal 10,000.
    pub fn validate(&self) -> Result<(), SpecError> {
        let sum: u32 = self.entries.iter().map(|e| e.weight_bps).sum();
        if sum != BASIS_POINTS_TOTAL {
            return Err(SpecError::BasisPointsSum { sum });
        }
        Ok(())
    }
}
