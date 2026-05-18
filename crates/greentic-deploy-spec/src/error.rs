//! Cross-cutting error type for spec-level validators.

use crate::capability_slot::CapabilitySlot;
use crate::revision::RevisionLifecycle;
use thiserror::Error;

use crate::ids::{BundleId, DeploymentId, RevisionId};
use greentic_types::EnvId;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("basis-points entries must sum to 10000, got {sum}")]
    BasisPointsSum { sum: u64 },

    #[error("basis-points entry exceeds 10000: {value}")]
    BasisPointsEntryTooLarge { value: u32 },

    #[error("duplicate capability slot `{0}` in Environment.packs")]
    DuplicateCapabilitySlot(CapabilitySlot),

    #[error("revision lifecycle transition {from:?} → {to:?} is not permitted")]
    InvalidLifecycleTransition {
        from: RevisionLifecycle,
        to: RevisionLifecycle,
    },

    #[error("schema discriminator mismatch: expected `{expected}`, got `{actual}`")]
    SchemaMismatch {
        expected: &'static str,
        actual: String,
    },

    #[error("env_id mismatch in {context}: expected `{expected}`, got `{actual}`")]
    EnvIdMismatch {
        context: &'static str,
        expected: EnvId,
        actual: EnvId,
    },

    #[error("traffic split references unknown deployment `{0}`")]
    UnknownDeployment(DeploymentId),

    #[error("reference to unknown revision `{0}`")]
    UnknownRevision(RevisionId),

    #[error(
        "split entry revision `{revision}` belongs to deployment `{actual_deployment}`, not split's `{expected_deployment}`"
    )]
    SplitRevisionWrongDeployment {
        revision: RevisionId,
        expected_deployment: DeploymentId,
        actual_deployment: DeploymentId,
    },

    #[error(
        "split entry revision `{revision}` belongs to bundle `{actual_bundle}`, not split's `{expected_bundle}`"
    )]
    SplitRevisionWrongBundle {
        revision: RevisionId,
        expected_bundle: BundleId,
        actual_bundle: BundleId,
    },

    #[error(
        "bundle `{deployment}` current_revision `{revision}` belongs to deployment `{actual_deployment}`"
    )]
    BundleRevisionWrongDeployment {
        deployment: DeploymentId,
        revision: RevisionId,
        actual_deployment: DeploymentId,
    },

    #[error(
        "bundle deployment `{deployment}` current_revision `{revision}` belongs to bundle `{actual_bundle}`, not deployment's `{expected_bundle}`"
    )]
    BundleRevisionWrongBundle {
        deployment: DeploymentId,
        revision: RevisionId,
        expected_bundle: BundleId,
        actual_bundle: BundleId,
    },

    #[error(
        "traffic split for deployment `{deployment}` carries bundle `{split_bundle}`, but the BundleDeployment record holds bundle `{deployment_bundle}`"
    )]
    SplitDeploymentBundleMismatch {
        deployment: DeploymentId,
        split_bundle: BundleId,
        deployment_bundle: BundleId,
    },
}
