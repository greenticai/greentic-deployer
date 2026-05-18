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

    /// `§5.4`: sum of revenue-share basis points MUST equal 10,000.
    pub fn validate(&self) -> Result<(), SpecError> {
        let sum: u32 = self.revenue_share.iter().map(|e| e.basis_points).sum();
        if sum != BASIS_POINTS_TOTAL {
            return Err(SpecError::BasisPointsSum { sum });
        }
        Ok(())
    }
}
