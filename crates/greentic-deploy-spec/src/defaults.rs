//! Default capability-slot bindings for the bootstrap `local` Environment (A4).
//!
//! Pack-descriptor strings are exposed as `&'static str` constants so callers
//! that need only the names (CLI output, telemetry tags) can avoid parsing.
//! [`local_pack_bindings`] returns the five [`EnvPackBinding`]s ready to drop
//! into [`Environment::packs`](crate::Environment::packs); parsing failures
//! propagate as [`PackDescriptorParseError`] but are unreachable for the
//! compile-time constants below.

use crate::capability_slot::{CapabilitySlot, PackDescriptor, PackDescriptorParseError};
use crate::environment::EnvPackBinding;
use crate::ids::PackId;

/// `EnvId` string used by the bootstrap environment.
pub const LOCAL_ENV_ID: &str = "local";

/// Pack descriptor for the deployer slot on the `local` env.
pub const LOCAL_DEPLOYER_PACK: &str = "greentic.deployer.local-process@0.1.0";
/// Pack descriptor for the secrets slot on the `local` env.
pub const LOCAL_SECRETS_PACK: &str = "greentic.secrets.dev-store@0.1.0";
/// Pack descriptor for the telemetry slot on the `local` env.
pub const LOCAL_TELEMETRY_PACK: &str = "greentic.telemetry.stdout@0.1.0";
/// Pack descriptor for the sessions slot on the `local` env.
pub const LOCAL_SESSIONS_PACK: &str = "greentic.sessions.in-memory@0.1.0";
/// Pack descriptor for the state slot on the `local` env.
pub const LOCAL_STATE_PACK: &str = "greentic.state.in-memory@0.1.0";

/// `(slot, descriptor)` pairs for the five default bindings.
pub const LOCAL_DEFAULT_BINDINGS: &[(CapabilitySlot, &str)] = &[
    (CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK),
    (CapabilitySlot::Secrets, LOCAL_SECRETS_PACK),
    (CapabilitySlot::Telemetry, LOCAL_TELEMETRY_PACK),
    (CapabilitySlot::Sessions, LOCAL_SESSIONS_PACK),
    (CapabilitySlot::State, LOCAL_STATE_PACK),
];

/// Builds the default [`EnvPackBinding`] set for the `local` environment.
///
/// Each binding starts at `generation = 0` with `pack_ref` mirroring the
/// descriptor string; the env-pack registry (A9) is responsible for resolving
/// the descriptor to a concrete handler at runtime.
pub fn local_pack_bindings() -> Result<Vec<EnvPackBinding>, PackDescriptorParseError> {
    LOCAL_DEFAULT_BINDINGS
        .iter()
        .map(|(slot, descriptor)| {
            let kind = PackDescriptor::try_new(*descriptor)?;
            Ok(EnvPackBinding {
                slot: *slot,
                kind,
                pack_ref: PackId::new(*descriptor),
                answers_ref: None,
                generation: 0,
                previous_binding_ref: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_pack_bindings_returns_five_bindings_one_per_slot() {
        let bindings = local_pack_bindings().expect("default descriptors parse");
        assert_eq!(bindings.len(), 5);
        let slots: Vec<CapabilitySlot> = bindings.iter().map(|b| b.slot).collect();
        assert_eq!(
            slots,
            vec![
                CapabilitySlot::Deployer,
                CapabilitySlot::Secrets,
                CapabilitySlot::Telemetry,
                CapabilitySlot::Sessions,
                CapabilitySlot::State,
            ]
        );
    }

    #[test]
    fn local_pack_bindings_descriptors_match_constants() {
        let bindings = local_pack_bindings().expect("default descriptors parse");
        let kinds: Vec<&str> = bindings.iter().map(|b| b.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                LOCAL_DEPLOYER_PACK,
                LOCAL_SECRETS_PACK,
                LOCAL_TELEMETRY_PACK,
                LOCAL_SESSIONS_PACK,
                LOCAL_STATE_PACK,
            ]
        );
    }

    #[test]
    fn local_pack_bindings_start_at_generation_zero_with_no_rollback() {
        let bindings = local_pack_bindings().expect("default descriptors parse");
        for binding in &bindings {
            assert_eq!(binding.generation, 0);
            assert!(binding.answers_ref.is_none());
            assert!(binding.previous_binding_ref.is_none());
            assert_eq!(binding.pack_ref.as_str(), binding.kind.as_str());
        }
    }

    #[test]
    fn local_default_bindings_table_covers_every_non_revocation_slot() {
        let table_slots: std::collections::BTreeSet<CapabilitySlot> =
            LOCAL_DEFAULT_BINDINGS.iter().map(|(s, _)| *s).collect();
        let expected: std::collections::BTreeSet<CapabilitySlot> = [
            CapabilitySlot::Deployer,
            CapabilitySlot::Secrets,
            CapabilitySlot::Telemetry,
            CapabilitySlot::Sessions,
            CapabilitySlot::State,
        ]
        .into_iter()
        .collect();
        assert_eq!(table_slots, expected);
        assert!(!table_slots.contains(&CapabilitySlot::Revocation));
    }
}
