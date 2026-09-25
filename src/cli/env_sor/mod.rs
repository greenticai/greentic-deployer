//! The CLI side of SoR units (SoRLa storage phase 3, contract C2/C3):
//! validating the manifest block, recording it at apply time, and assembling
//! what `op env reconcile` needs from the env's store.

// Consumed by the reconcile wiring (`op env reconcile`, phase 3C Task 7);
// drop both allows once that lands.
#[allow(dead_code)]
mod inputs;
mod validate;

#[allow(unused_imports)]
pub(crate) use inputs::{
    refuse_dev_secrets_path_override, require_dev_store_backend, resolve_sor_inputs,
};
pub(crate) use validate::validate_sor_units;

use greentic_deploy_spec::EnvId;

use crate::cli::OpError;
use crate::environment::LocalFsStore;
use crate::environment::sor_units::SorUnit;

/// Record the declared SoR units (`<env_dir>/sor-units.json`) under the env
/// flock. Called by the `set-sor-units` apply step.
pub(crate) fn set_sor_units(
    store: &LocalFsStore,
    env_id: &EnvId,
    units: &[SorUnit],
) -> Result<(), OpError> {
    store
        .transact(env_id, |locked| locked.save_sor_units(units))
        .map_err(OpError::from)
}

/// Store URIs of every declared unit's inputs. Stripped from the dev-store
/// seed that ships into routers and workers: those are the SoR's own
/// credentials (its database URL above all), and no flow or worker reads
/// them — the worker needs only the route document.
pub(crate) fn sor_input_uris(env_id: &EnvId, units: &[SorUnit]) -> Vec<String> {
    units
        .iter()
        .flat_map(SorUnit::input_refs)
        .map(|rel| crate::cli::secrets::dev_store_key(env_id, rel))
        .collect()
}
