//! The CLI side of SoR units (SoRLa storage phase 3, contract C2/C3):
//! validating the manifest block, recording it at apply time, and assembling
//! what `op env reconcile` needs from the env's store.

mod validate;

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
