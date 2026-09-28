//! [`LocalFsStore`] wrappers for the explicit removal verbs (unified
//! release Phase 5, PD1). Pure semantics live in
//! `greentic_deploy_spec::engine::removal`; these own the flock,
//! persistence, and the `runtime-config.json` refresh — the same shape as
//! `set_traffic_split` in `mutations_local`.
//!
//! These are inherent methods, not `EnvironmentMutations` trait methods:
//! the A8 wire contract has no route for them yet, so a remote store answers
//! the new verbs with "not supported" at the CLI dispatch layer instead of
//! half-implementing them over HTTP.

use greentic_deploy_spec::engine::{self, BeginRetireOutcome, ClearTrafficOutcome, RemovalError};
use greentic_deploy_spec::{DeploymentId, EnvId, Environment};

use super::store::{LocalFsStore, Locked, StoreError};

/// Map a pure removal refusal onto the local store's error surface.
pub(crate) fn map_removal_err(err: RemovalError) -> StoreError {
    match err {
        RemovalError::DeploymentNotFound { .. } => StoreError::DependentNotFound(err.to_string()),
        RemovalError::NotRetiring { .. }
        | RemovalError::LinkedFromEndpoint { .. }
        | RemovalError::MissingCapability { .. } => StoreError::Conflict(err.to_string()),
    }
}

impl LocalFsStore {
    /// Remove a retiring deployment's traffic split. Idempotent: no split is
    /// a success with `cleared: None`, which still reconciles the derived
    /// runtime config (a retry repairs a refresh that failed after save).
    pub fn clear_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
    ) -> Result<ClearTrafficOutcome, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let outcome =
                engine::clear_traffic_split(&mut env, deployment_id).map_err(map_removal_err)?;
            persist_if(locked, &env, outcome.mutated())?;
            Ok(outcome)
        })
    }

    /// Step one of `op bundles retire`: refuse if an endpoint would be
    /// stranded, mark the deployment retiring and clear its split.
    pub fn begin_retire(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
    ) -> Result<BeginRetireOutcome, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let outcome = engine::begin_retire(&mut env, deployment_id).map_err(map_removal_err)?;
            persist_if(locked, &env, outcome.mutated())?;
            Ok(outcome)
        })
    }
}

/// Save when `mutated`, then refresh the runtime config. A refresh failure
/// after a save is `CommittedAfterSave` so the CLI audit still fires.
fn persist_if(locked: &Locked<'_>, env: &Environment, mutated: bool) -> Result<(), StoreError> {
    if mutated {
        locked.save(env)?;
        locked
            .refresh_runtime_config(env)
            .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))
    } else {
        locked.refresh_runtime_config(env)
    }
}
