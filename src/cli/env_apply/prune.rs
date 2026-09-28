//! `op env apply --prune --confirm-prune` (unified release Phase 5, PD1).
//!
//! Default apply stays upsert-only: without `--prune` none of this runs and
//! the report carries no `prune` key. With it, apply retires the WHOLE
//! deployments this manifest owns (see [`super::ownership`]) and no longer
//! declares, through the same sequence as `op bundles retire` (clear →
//! drain → tear down, then archive → remove; one audit event each).
//!
//! Revisions inside a deployment the manifest still declares are never
//! touched: an unrouted `Ready` revision is also a warmed canary waiting for
//! `op traffic set`.
//!
//! Everything that can refuse does so before any mutation, the upsert half
//! included: `--prune` without `--confirm-prune`, a bound deployer without
//! the `remove` capability, and a messaging endpoint that the WHOLE retire
//! set would strand. Prune itself runs only after the upsert half executed
//! and verified.

use std::collections::BTreeSet;

use greentic_deploy_spec::engine::{PrunePlan, check_retire_set_links, prune_plan};
use greentic_deploy_spec::{DeploymentId, Environment, IdempotencyKey};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::super::OpError;
use super::super::bundles_retire::{RetireHooks, retire_deployment};
use super::ApplyContext;
use super::ownership::{self, Owner};

/// Refuse `--prune` without its confirmation flag. Checked first, before the
/// manifest is even read.
pub(super) fn require_confirmation(prune: bool, confirm_prune: bool) -> Result<(), OpError> {
    if prune && !confirm_prune {
        return Err(OpError::InvalidArgument(
            "`--prune` removes deployments this environment's manifest owns but no longer \
             declares; pass `--confirm-prune` as well to proceed"
                .to_string(),
        ));
    }
    Ok(())
}

/// The deployments the current manifest resolves to in `env`.
pub(super) fn declared_ids(env: &Environment, ctx: &ApplyContext) -> BTreeSet<DeploymentId> {
    ctx.bundles
        .iter()
        .filter_map(|rb| {
            env.bundles
                .iter()
                .find(|b| {
                    b.bundle_id.as_str() == rb.spec.bundle_id && b.customer_id == rb.customer_id
                })
                .map(|b| b.deployment_id)
        })
        .collect()
}

fn plan_for(
    store: &LocalFsStore,
    env: &Environment,
    ctx: &ApplyContext,
    owner: &Owner,
) -> Result<PrunePlan, OpError> {
    let owned = ownership::load(store, &ctx.env_id)?.prunable_by(owner, env);
    Ok(prune_plan(env, &owned, &declared_ids(env, ctx)))
}

/// Plan against the env as it stands and run every refusal up front.
pub(super) fn preview(
    store: &LocalFsStore,
    ctx: &ApplyContext,
    owner: &Owner,
    hooks: &dyn RetireHooks,
) -> Result<PrunePlan, OpError> {
    let Some(env) = &ctx.env else {
        return Ok(PrunePlan::default());
    };
    let plan = plan_for(store, env, ctx, owner)?;
    if plan.is_empty() {
        return Ok(plan);
    }
    hooks.preflight(env)?;
    let set: BTreeSet<DeploymentId> = plan.retire.iter().copied().collect();
    check_retire_set_links(env, &set)
        .map_err(|e| OpError::Conflict(format!("prune refused before applying anything: {e}")))?;
    Ok(plan)
}

pub(super) fn plan_json(plan: &PrunePlan, owner: &Owner) -> Value {
    json!({
        "planned": true,
        "owner": owner.key,
        "retire": plan.retire.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
    })
}

/// Run the prune against the post-apply env. Re-plans from the store so the
/// report names exactly what was removed.
pub(super) fn execute(
    store: &LocalFsStore,
    ctx: &ApplyContext,
    owner: &Owner,
    hooks: &dyn RetireHooks,
) -> Result<Value, OpError> {
    let env = store.load(&ctx.env_id)?;
    let plan = plan_for(store, &env, ctx, owner)?;
    let set: BTreeSet<DeploymentId> = plan.retire.iter().copied().collect();
    if !set.is_empty() {
        hooks.preflight(&env)?;
        check_retire_set_links(&env, &set).map_err(|e| OpError::Conflict(e.to_string()))?;
    }
    let mut retired = Vec::new();
    for d in &plan.retire {
        let key = IdempotencyKey::new(format!("env-apply-prune:deployment:{d}"))
            .map_err(|e| OpError::InvalidArgument(format!("idempotency_key: {e}")))?;
        retired.push(retire_deployment(store, hooks, &ctx.env_id, *d, key)?.result);
    }
    let after = store.load(&ctx.env_id)?;
    ownership::record(
        store,
        &ctx.env_id,
        &after,
        owner,
        &declared_ids(&after, ctx),
    )?;
    Ok(json!({
        "planned": false,
        "owner": owner.key,
        "retired": retired,
    }))
}

#[cfg(test)]
#[path = "prune_tests.rs"]
mod tests;
