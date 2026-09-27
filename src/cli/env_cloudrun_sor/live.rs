//! The live half: regional Google clients behind `SorTargets`.

use std::sync::Arc;

use async_trait::async_trait;
use greentic_deploy_spec::{EnvId, Environment};
use serde_json::{Value, json};

use crate::cli::OpError;
use crate::cli::env_sor::cloudrun::{self, CloudRunSorRun, SorTargetPair, SorTargets};
use crate::env_packs::gcp_cloudrun::bound_session::GcpCredentialMaterial;
use crate::env_packs::gcp_cloudrun::credentials::run_gcp_async;
use crate::env_packs::gcp_cloudrun::deploy_target::CloudRunTarget;
use crate::env_packs::gcp_cloudrun::sor::real::RealSorTarget;
use crate::env_packs::gcp_cloudrun::sor::spec::SorReadyTiming;
use crate::env_packs::gcp_cloudrun::sor::target::SorServiceTarget;
use crate::environment::LocalFsStore;
use crate::environment::sor_units::CloudRunSorPlacement;

/// Builds clients for each place with the env's bound deployer credential,
/// else ambient ADC — the identity every other Cloud Run verb deploys as.
struct RealSorTargets {
    credentials: Option<GcpCredentialMaterial>,
}

#[async_trait]
impl SorTargets for RealSorTargets {
    async fn at(&self, project: &str, region: &str) -> Result<SorTargetPair, OpError> {
        let real = RealSorTarget::resolve(project, region, self.credentials.clone())
            .await
            .map_err(|e| {
                OpError::Conflict(format!(
                    "cannot initialize the GCP Cloud Run client for `{project}`/`{region}`: {e}"
                ))
            })?;
        let secrets: Arc<dyn CloudRunTarget> = Arc::new(real.run_target());
        let services: Arc<dyn SorServiceTarget> = Arc::new(real);
        Ok((secrets, services))
    }
}

fn nothing_to_do(store: &LocalFsStore, env_id: &EnvId) -> Result<bool, OpError> {
    Ok(store.load_sor_units(env_id)?.is_empty() && store.load_sor_ledger(env_id)?.is_empty())
}

pub(crate) fn sor_up(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
) -> Result<Option<CloudRunSorRun>, OpError> {
    // No SoR units, now or ever: no client, no extra answers parse.
    if nothing_to_do(store, env_id)? {
        return Ok(None);
    }
    let (_identity, params, credentials) =
        crate::cli::env::cloudrun_target_inputs(store, env, env_id, answers)?;
    let backend = crate::cli::env::resolve_secrets_backend(store, env)?;
    let targets = RealSorTargets { credentials };
    run_gcp_async(cloudrun::up(
        store,
        env,
        &params,
        &backend,
        &targets,
        SorReadyTiming::from_env(),
    ))
}

pub(crate) fn sor_finish(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
    run: &CloudRunSorRun,
) -> Result<Vec<String>, OpError> {
    let (_identity, _params, credentials) =
        crate::cli::env::cloudrun_target_inputs(store, env, env_id, answers)?;
    let targets = RealSorTargets { credentials };
    run_gcp_async(cloudrun::finish(store, env_id, run, &targets))
}

/// `op env destroy`: delete every Cloud Run SoR service and secret the ledger
/// records (ownership-checked). Runs under the destroy flock; reads the ledger
/// without taking it.
pub(crate) fn teardown_sor_units(
    store: &LocalFsStore,
    env_id: &EnvId,
    credentials: Option<GcpCredentialMaterial>,
) -> Result<Value, String> {
    let places: Vec<CloudRunSorPlacement> = store
        .load_sor_ledger(env_id)
        .map_err(|e| format!("reading the SoR ledger: {e}"))?
        .into_iter()
        .filter_map(|a| a.cloud_run)
        .collect();
    if places.is_empty() {
        return Ok(json!({}));
    }
    let targets = RealSorTargets { credentials };
    let out = run_gcp_async(cloudrun::retire_all(
        env_id.as_str(),
        &places,
        &[],
        &targets,
    ))
    .map_err(|e| e.to_string())?;
    Ok(json!({
        "deleted_services": out.deleted_services,
        "deleted_secrets": out.deleted_secrets,
        "notes": out.notes,
    }))
}
