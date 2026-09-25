//! The CLI side of SoR units (SoRLa storage phase 3, contract C2/C3):
//! validating the manifest block, recording it at apply time, and assembling
//! what `op env reconcile` needs from the env's store.

mod validate;

pub(crate) use validate::validate_sor_units;
