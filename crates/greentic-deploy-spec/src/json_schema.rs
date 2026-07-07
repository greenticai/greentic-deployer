//! JSON-schema generation for every top-level spec type (gated by the
//! `schemars` feature).
//!
//! Wiring `#[derive(schemars::JsonSchema)]` across the full type tree is a
//! mechanical pass — semver/ulid/PackDescriptor fields need `#[schemars(with =
//! "String")]`, chrono needs the schemars `chrono` feature. Deferred to a
//! follow-up PR so A1 can land the types without dragging the schemars-derive
//! review surface into the same review. The feature flag and entry points are
//! reserved here.

use schemars::schema::RootSchema;
use std::collections::BTreeMap;

/// Returns every top-level schema keyed by its
/// [`SchemaVersion`](crate::version::SchemaVersion) discriminator.
///
/// Currently a stub — see module-level doc. Subsequent PR wires real derives.
pub fn dump_all_schemas() -> BTreeMap<&'static str, RootSchema> {
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_all_schemas_returns_empty_pending_wiring() {
        let schemas = dump_all_schemas();
        assert!(
            schemas.is_empty(),
            "stub should return empty until schemars derives are wired"
        );
    }
}
