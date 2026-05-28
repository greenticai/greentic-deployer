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

    /// `§5.3`: schema discriminator equals `greentic.traffic-split.v1` and
    /// the sum of `weight_bps` MUST equal 10,000.
    ///
    /// Sum widens into `u64` and rejects any per-entry value above 10,000 so a
    /// crafted document like `[u32::MAX, 10001]` cannot wrap to exactly 10,000
    /// in release builds.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema.as_str() != SchemaVersion::TRAFFIC_SPLIT_V1 {
            return Err(SpecError::SchemaMismatch {
                expected: SchemaVersion::TRAFFIC_SPLIT_V1,
                actual: self.schema.as_str().to_string(),
            });
        }
        let mut sum: u64 = 0;
        for entry in &self.entries {
            if entry.weight_bps > BASIS_POINTS_TOTAL {
                return Err(SpecError::BasisPointsEntryTooLarge {
                    value: entry.weight_bps,
                });
            }
            sum += u64::from(entry.weight_bps);
        }
        if sum != u64::from(BASIS_POINTS_TOTAL) {
            return Err(SpecError::BasisPointsSum { sum });
        }
        Ok(())
    }
}
