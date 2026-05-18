//! `greentic.bundle-deployment.v1` (`§5.4`).
//!
//! The usage-level anchor (P6). One per `(env_id, bundle_id, customer_id)`.

use crate::error::SpecError;
use crate::ids::{BundleId, CustomerId, DeploymentId, PartyId, RevisionId};
use crate::version::SchemaVersion;
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const BASIS_POINTS_TOTAL: u32 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleDeploymentStatus {
    Active,
    Paused,
    Archived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantSelector {
    pub tenant: String,
    pub team: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBinding {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    pub tenant_selector: TenantSelector,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenueShareEntry {
    pub party_id: PartyId,
    pub basis_points: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageMeter {
    pub meter_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleDeployment {
    pub schema: SchemaVersion,
    pub deployment_id: DeploymentId,
    pub env_id: EnvId,
    pub bundle_id: BundleId,
    pub customer_id: CustomerId,
    pub status: BundleDeploymentStatus,
    /// Subset of `Environment.revisions` for this deployment.
    #[serde(default)]
    pub current_revisions: Vec<RevisionId>,
    pub route_binding: RouteBinding,
    pub revenue_share: Vec<RevenueShareEntry>,
    /// Path to the signed, versioned policy document.
    pub revenue_policy_ref: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageMeter>,
    pub created_at: DateTime<Utc>,
    pub authorization_ref: PathBuf,
}

impl BundleDeployment {
    pub fn schema_str() -> &'static str {
        SchemaVersion::BUNDLE_DEPLOYMENT_V1
    }

    /// `§5.4`: schema discriminator equals `greentic.bundle-deployment.v1`
    /// and the sum of revenue-share basis points MUST equal 10,000.
    ///
    /// Sum widens into `u64` and rejects any per-entry value above 10,000 so a
    /// crafted document like `[u32::MAX, 10001]` cannot wrap to exactly 10,000
    /// in release builds.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema.as_str() != SchemaVersion::BUNDLE_DEPLOYMENT_V1 {
            return Err(SpecError::SchemaMismatch {
                expected: SchemaVersion::BUNDLE_DEPLOYMENT_V1,
                actual: self.schema.as_str().to_string(),
            });
        }
        let mut sum: u64 = 0;
        for entry in &self.revenue_share {
            if entry.basis_points > BASIS_POINTS_TOTAL {
                return Err(SpecError::BasisPointsEntryTooLarge {
                    value: entry.basis_points,
                });
            }
            sum += u64::from(entry.basis_points);
        }
        if sum != u64::from(BASIS_POINTS_TOTAL) {
            return Err(SpecError::BasisPointsSum { sum });
        }
        Ok(())
    }
}
