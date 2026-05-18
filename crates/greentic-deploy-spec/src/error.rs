//! Cross-cutting error type for spec-level validators.

use crate::capability_slot::CapabilitySlot;
use crate::revision::RevisionLifecycle;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("basis-points entries must sum to 10000, got {sum}")]
    BasisPointsSum { sum: u32 },

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
}
