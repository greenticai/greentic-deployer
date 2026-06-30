//! Bootstrap types for [`super::mutations_local::LocalFsStore::ensure_local_environment`].
//!
//! These types are split out from `cli/bootstrap.rs` so the typed verb on
//! `LocalFsStore` can return them without pulling in CLI concerns.

use greentic_deploy_spec::{CapabilitySlot, Environment};

use crate::defaults::local_pack_bindings;

use super::store::StoreError;

/// Whether the bootstrap verb created the env, found it intact, or
/// repaired missing default bindings on an existing env.
///
/// `Healed` carries the slots that were missing and got the default binding
/// inserted. Slots already bound to a non-default descriptor are NOT
/// overwritten — bootstrap only fills *missing* slots, never replaces user
/// intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEnvOutcome {
    Created,
    AlreadyExists,
    Healed { added_slots: Vec<CapabilitySlot> },
}

/// Payload for [`super::mutations_local::LocalFsStore::ensure_local_environment`].
///
/// `public_base_url`: when `Some`, persisted on the env's `host_config` ONLY
/// during creation. For `AlreadyExists` and `Healed` outcomes the existing URL
/// is preserved — passing `Some` when the env already exists is rejected with
/// [`StoreError::Conflict`].
#[derive(Debug, Clone, Default)]
pub struct EnsureLocalEnvironmentPayload {
    pub public_base_url: Option<String>,
}

/// Walks the five default capability slots and appends a default
/// [`greentic_deploy_spec::EnvPackBinding`] for any slot not already bound on
/// `env`. Slots already bound — regardless of descriptor — are left untouched
/// so user-customized bindings (e.g. an externally-provisioned secrets backend)
/// survive.
///
/// Returns the slots that were appended, in the canonical default order.
/// Empty return means the env already satisfied the A4 invariant.
pub(crate) fn fill_missing_default_bindings(
    env: &mut Environment,
) -> Result<Vec<CapabilitySlot>, StoreError> {
    let defaults = local_pack_bindings()
        .map_err(|e| StoreError::InvalidArgument(format!("default pack binding parse: {e}")))?;
    let mut added = Vec::new();
    for binding in defaults {
        if env.packs.iter().any(|b| b.slot == binding.slot) {
            continue;
        }
        added.push(binding.slot);
        env.packs.push(binding);
    }
    Ok(added)
}
