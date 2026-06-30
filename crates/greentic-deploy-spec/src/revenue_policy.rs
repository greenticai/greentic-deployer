//! `greentic.revenue-policy.v1` — versioned, integrity-anchored revenue-share
//! policy document for a [`BundleDeployment`](crate::BundleDeployment) (P6, `§5.4`).
//!
//! Each mutation of a deployment's `revenue_share` writes a **new version** of
//! this document; `BundleDeployment.revenue_policy_ref` points at the latest
//! version's detached sidecar (see the deployer's
//! `environment::bundle_deployment` writer). Versions chain backward via
//! [`previous_version_ref`](RevenuePolicyDocument::previous_version_ref) so the
//! full policy history is auditable.
//!
//! ## Signing posture (B10 vs C2)
//!
//! Phase B (B10) anchors each version with a SHA-256 canonical-JSON integrity
//! hash carried in the detached sidecar (tamper-evident). Real DSSE+Ed25519
//! authenticity signing is C2's scope (`plans/next-gen-deployment.md`); the
//! sidecar envelope is shaped so C2 can attach the cryptographic signature
//! without changing this document format.

use crate::bundle_deployment::{RevenueShareEntry, validate_revenue_share_total};
use crate::error::SpecError;
use crate::ids::{BundleId, CustomerId, DeploymentId};
use crate::version::SchemaVersion;
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenuePolicyDocument {
    pub schema: SchemaVersion,
    /// Monotonic, 1-based version within `(env_id, bundle_id, customer_id)`.
    pub version: u64,
    pub deployment_id: DeploymentId,
    pub env_id: EnvId,
    pub bundle_id: BundleId,
    pub customer_id: CustomerId,
    pub revenue_share: Vec<RevenueShareEntry>,
    pub created_at: DateTime<Utc>,
    /// Env-relative path to the prior version's sidecar (`None` for `v1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version_ref: Option<PathBuf>,
}

impl RevenuePolicyDocument {
    pub fn schema_str() -> &'static str {
        SchemaVersion::REVENUE_POLICY_V1
    }

    /// Schema discriminator equals `greentic.revenue-policy.v1`, the version is
    /// `>= 1`, and the revenue-share basis points obey the `§5.4` total
    /// invariant (per-entry `<= 10,000`, sum `== 10,000`).
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema.as_str() != SchemaVersion::REVENUE_POLICY_V1 {
            return Err(SpecError::SchemaMismatch {
                expected: SchemaVersion::REVENUE_POLICY_V1,
                actual: self.schema.as_str().to_string(),
            });
        }
        if self.version == 0 {
            return Err(SpecError::RevenuePolicyVersionZero);
        }
        validate_revenue_share_total(&self.revenue_share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::PartyId;

    fn doc(version: u64, shares: Vec<(&str, u32)>) -> RevenuePolicyDocument {
        RevenuePolicyDocument {
            schema: SchemaVersion::new(SchemaVersion::REVENUE_POLICY_V1),
            version,
            deployment_id: DeploymentId::new(),
            env_id: EnvId::try_from("local").unwrap(),
            bundle_id: BundleId::new("fast2flow"),
            customer_id: CustomerId::new("local-dev"),
            revenue_share: shares
                .into_iter()
                .map(|(p, bps)| RevenueShareEntry {
                    party_id: PartyId::new(p),
                    basis_points: bps,
                })
                .collect(),
            created_at: Utc::now(),
            previous_version_ref: None,
        }
    }

    #[test]
    fn valid_document_passes() {
        assert!(doc(1, vec![("greentic", 10_000)]).validate().is_ok());
        assert!(
            doc(2, vec![("agency-a", 3_000), ("greentic", 7_000)])
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn wrong_schema_rejected() {
        let mut d = doc(1, vec![("greentic", 10_000)]);
        d.schema = SchemaVersion::new("greentic.revenue-policy.v2");
        assert!(matches!(
            d.validate(),
            Err(SpecError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn version_zero_rejected() {
        assert!(matches!(
            doc(0, vec![("greentic", 10_000)]).validate(),
            Err(SpecError::RevenuePolicyVersionZero)
        ));
    }

    #[test]
    fn basis_points_sum_enforced() {
        assert!(matches!(
            doc(1, vec![("greentic", 9_999)]).validate(),
            Err(SpecError::BasisPointsSum { sum: 9_999 })
        ));
    }

    #[test]
    fn per_entry_overflow_rejected() {
        // [u32::MAX, 10001] would wrap to 10,000 in a u32 sum.
        assert!(matches!(
            doc(1, vec![("a", u32::MAX), ("b", 10_001)]).validate(),
            Err(SpecError::BasisPointsEntryTooLarge { .. })
        ));
    }
}
