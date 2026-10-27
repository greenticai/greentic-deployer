//! `op env up` for an Azure Container Apps environment.

use greentic_deploy_spec::EnvId;

use super::OpError;
use super::env_azure::AZURE_ACA_DEPLOYER_PATH;
#[cfg(not(all(feature = "creds-azure", feature = "deploy-azure-aca")))]
use super::env_azure::NO_DEPLOY_FEATURE;
use crate::env_packs::EnvPackRegistry;
use crate::environment::LocalFsStore;

pub(crate) fn names_azure_aca_deployer(d: &greentic_deploy_spec::PackDescriptor) -> bool {
    d.path() == AZURE_ACA_DEPLOYER_PATH
}

fn bound_to_azure(env: &greentic_deploy_spec::Environment) -> bool {
    env.pack_for_slot(greentic_deploy_spec::CapabilitySlot::Deployer)
        .is_some_and(|b| names_azure_aca_deployer(&b.kind))
}

/// Warm every revision that carries traffic, push each recorded split, and return
/// `{environment_id, kind, warmed[], applied_splits, endpoints[], endpoint_url?}`.
/// `None` unless the env is bound to `greentic.deployer.azure-aca`.
#[cfg(all(feature = "creds-azure", feature = "deploy-azure-aca"))]
pub fn azure_env_up(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &EnvId,
) -> Result<Option<serde_json::Value>, OpError> {
    use std::collections::BTreeMap;

    use greentic_deploy_spec::CapabilitySlot;
    use serde_json::json;

    use super::env::{
        RevisionVerb, cloudrun_revisions_to_warm, load_render_answers, preflight_split_granularity,
        resolve_live_deployer_kind,
    };
    use super::env_azure::{apply_revision_azure, apply_traffic_azure};
    use crate::environment::EnvironmentStore as _;

    let env = store.load(env_id)?;
    if !bound_to_azure(&env) {
        return Ok(None);
    }
    let descriptor = resolve_live_deployer_kind(&env, None)?;
    let _handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;
    let (answers, _wire) = load_render_answers(store, &env, &descriptor)?;

    // Whole-percent weights only: refuse a finer split BEFORE warming anything.
    preflight_split_granularity(
        &env,
        crate::env_packs::azure_aca::deployer::WEIGHT_GRANULARITY_BPS,
        "Container Apps",
        "1%",
        None,
    )?;

    let mut warmed: Vec<String> = Vec::new();
    let mut endpoints: BTreeMap<String, String> = BTreeMap::new();
    for revision in cloudrun_revisions_to_warm(&env) {
        let (_identity, app, url) = apply_revision_azure(
            store,
            &env,
            env_id,
            revision.revision_id,
            RevisionVerb::Warm,
            answers.as_ref(),
        )?;
        if let Some(url) = url {
            endpoints.insert(revision.deployment_id.to_string(), url);
        }
        warmed.push(app);
    }
    for split in &env.traffic_splits {
        apply_traffic_azure(store, &env, env_id, split.deployment_id, answers.as_ref())?;
    }
    let mut result = json!({
        "environment_id": env.environment_id.as_str(),
        "kind": descriptor.as_str(),
        "warmed": warmed,
        "applied_splits": env.traffic_splits.len(),
        "endpoints": endpoints
            .iter()
            .map(|(d, u)| json!({"deployment_id": d, "url": u}))
            .collect::<Vec<_>>(),
    });
    if endpoints.len() == 1
        && let Some(url) = endpoints.values().next()
    {
        result["endpoint_url"] = json!(url);
    }
    Ok(Some(result))
}

/// A build without the live client refuses an Azure env by name instead of
/// letting it fall into the k8s phases.
#[cfg(not(all(feature = "creds-azure", feature = "deploy-azure-aca")))]
pub fn azure_env_up(
    store: &LocalFsStore,
    _registry: &EnvPackRegistry,
    env_id: &EnvId,
) -> Result<Option<serde_json::Value>, OpError> {
    use crate::environment::EnvironmentStore as _;

    let env = store.load(env_id)?;
    if bound_to_azure(&env) {
        return Err(OpError::Conflict(NO_DEPLOY_FEATURE.to_string()));
    }
    Ok(None)
}

#[cfg(test)]
#[path = "env_azure_up_tests.rs"]
mod tests;
