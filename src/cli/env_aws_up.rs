//! `op env up` for an AWS ECS environment.

use greentic_deploy_spec::EnvId;

use super::OpError;
use crate::env_packs::EnvPackRegistry;
use crate::environment::LocalFsStore;

/// Descriptor path of the AWS ECS deployer, known in every build (the handler's
/// own constant exists only with `creds-aws`).
pub(crate) const AWS_ECS_DEPLOYER_PATH: &str = "greentic.deployer.aws-ecs";

pub(crate) const NO_DEPLOY_FEATURE: &str = "this build was compiled without the `deploy-aws-ecs` \
     feature; `op env up` needs it to deploy an AWS ECS environment";

pub(crate) fn names_aws_ecs_deployer(descriptor: &greentic_deploy_spec::PackDescriptor) -> bool {
    descriptor.path() == AWS_ECS_DEPLOYER_PATH
}

/// The env's bound deployer is AWS ECS. Read from the binding alone, so it
/// answers in every build (and for an env with no deployer at all: `false`).
fn bound_to_aws_ecs(env: &greentic_deploy_spec::Environment) -> bool {
    env.pack_for_slot(greentic_deploy_spec::CapabilitySlot::Deployer)
        .is_some_and(|b| names_aws_ecs_deployer(&b.kind))
}

/// One-command AWS ECS bring-up for `op env up` — the ECS analogue of
/// [`cloudrun_env_up`](super::env::cloudrun_env_up).
///
/// Returns `None` unless the env's bound deployer is `greentic.deployer.aws-ecs`,
/// so `op env up` falls through to its k8s phases for every other kind.
/// Otherwise it warms every revision that carries traffic
/// ([`cloudrun_revisions_to_warm`](super::env::cloudrun_revisions_to_warm) —
/// the rule is deployer-agnostic), pushes each recorded split to the listener,
/// and returns `{environment_id, kind, warmed[], applied_splits,
/// endpoints[{deployment_id, url}], endpoint_url?}` — `endpoint_url` only when
/// exactly one deployment discovered an endpoint. Warm-then-route, so a split
/// never names a task set that does not exist yet.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
pub fn aws_env_up(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &EnvId,
) -> Result<Option<serde_json::Value>, OpError> {
    use crate::environment::EnvironmentStore as _;
    use greentic_deploy_spec::CapabilitySlot;
    use serde_json::json;
    use std::collections::BTreeMap;

    use super::env::{
        RevisionVerb, apply_revision_aws_ecs, apply_traffic_non_k8s, cloudrun_revisions_to_warm,
        load_render_answers, preflight_split_granularity, resolve_live_deployer_kind,
    };

    let env = store.load(env_id)?;
    if !bound_to_aws_ecs(&env) {
        return Ok(None);
    }
    let descriptor = resolve_live_deployer_kind(&env, None)?;

    // Parity with `apply-revision` / `apply-traffic`: confirm the kind is
    // registered before driving it.
    let _handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;

    let (answers, _answers_ref_wire) = load_render_answers(store, &env, &descriptor)?;

    // ALB forward weights are `weight_bps / 10` (0..=999), so a split finer than
    // 10 bps cannot be expressed. Refuse it before warming anything.
    preflight_split_granularity(
        &env,
        crate::env_packs::aws::real_target::ELB_WEIGHT_GRANULARITY_BPS,
        "ALB",
        "0.1%",
        None,
    )?;

    // 1. Warm every revision that carries traffic. A deployment's revisions sit
    //    behind one listener route, so endpoints are keyed by deployment.
    let mut warmed: Vec<String> = Vec::new();
    let mut endpoints: BTreeMap<String, String> = BTreeMap::new();
    for revision in cloudrun_revisions_to_warm(&env) {
        let (_identity, service_name, url) = apply_revision_aws_ecs(
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
        warmed.push(service_name);
    }

    // 2. Push each recorded split to the listener (a no-op live without one).
    for split in &env.traffic_splits {
        apply_traffic_non_k8s(
            store,
            &env,
            env_id,
            split.deployment_id,
            answers.as_ref(),
            &descriptor,
        )?;
    }

    let mut result = json!({
        "environment_id": env.environment_id.as_str(),
        "kind": descriptor.as_str(),
        "warmed": warmed,
        "applied_splits": env.traffic_splits.len(),
        "endpoints": endpoints
            .iter()
            .map(|(deployment_id, url)| json!({"deployment_id": deployment_id, "url": url}))
            .collect::<Vec<_>>(),
    });
    if endpoints.len() == 1
        && let Some(url) = endpoints.values().next()
    {
        result["endpoint_url"] = json!(url);
    }
    Ok(Some(result))
}

/// A build without the live AWS client cannot bring an ECS env up: refuse by
/// name rather than letting it fall through to the k8s phases. Any other
/// deployer still falls through.
#[cfg(not(all(feature = "creds-aws", feature = "deploy-aws-ecs")))]
pub fn aws_env_up(
    store: &LocalFsStore,
    _registry: &EnvPackRegistry,
    env_id: &EnvId,
) -> Result<Option<serde_json::Value>, OpError> {
    use crate::environment::EnvironmentStore as _;

    let env = store.load(env_id)?;
    if bound_to_aws_ecs(&env) {
        return Err(OpError::Conflict(NO_DEPLOY_FEATURE.to_string()));
    }
    Ok(None)
}

#[cfg(test)]
#[path = "env_aws_up_tests.rs"]
mod tests;
