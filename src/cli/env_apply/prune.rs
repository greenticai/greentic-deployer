//! `op env apply --prune --confirm-prune` (unified release Phase 5, PD1).
//!
//! Default apply stays upsert-only: without `--prune` none of this runs and
//! the report carries no `prune` key. With it, apply removes what its
//! manifest OWNS (the [`super::ownership`] ledger) and no longer declares:
//!
//! - an owned deployment absent from the manifest is retired whole, through
//!   the same sequence as `op bundles retire` (one audit event each);
//! - an owned, still-declared deployment's settled revisions that its split
//!   no longer routes to are archived and torn down.
//!
//! A deployment the ledger does not list is never touched. `--prune` without
//! `--confirm-prune` is refused before anything runs. Prune happens only
//! after the upsert half executed AND verified, and a stranded messaging
//! endpoint refuses the whole prune before any upsert runs.

use std::collections::BTreeSet;

use greentic_deploy_spec::engine::{PrunePlan, check_retire_links, prune_plan};
use greentic_deploy_spec::{DeploymentId, Environment, IdempotencyKey};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::super::OpError;
use super::super::bundles_retire::{HookResult, RetireHooks, retire_deployment};
use super::{ApplyContext, ownership};

/// Refuse `--prune` without its confirmation flag. Checked first, before the
/// manifest is even read.
pub(super) fn require_confirmation(prune: bool, confirm_prune: bool) -> Result<(), OpError> {
    if prune && !confirm_prune {
        return Err(OpError::InvalidArgument(
            "`--prune` removes deployments and revisions this environment's manifest owns but no \
             longer declares; pass `--confirm-prune` as well to proceed"
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

/// Plan against the env as it stands, refusing up front if any retire would
/// strand a messaging endpoint.
pub(super) fn preview(store: &LocalFsStore, ctx: &ApplyContext) -> Result<PrunePlan, OpError> {
    let Some(env) = &ctx.env else {
        return Ok(PrunePlan::default());
    };
    let owned = ownership::load(store, &ctx.env_id)?.ids();
    let plan = prune_plan(env, &owned, &declared_ids(env, ctx));
    let refusals: Vec<String> = plan
        .retire
        .iter()
        .filter_map(|d| check_retire_links(env, *d).err())
        .map(|e| e.to_string())
        .collect();
    if !refusals.is_empty() {
        return Err(OpError::Conflict(format!(
            "prune refused before applying anything: {}",
            refusals.join("; ")
        )));
    }
    Ok(plan)
}

pub(super) fn plan_json(plan: &PrunePlan) -> Value {
    json!({
        "planned": true,
        "retire": plan.retire.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        "archive_revisions": plan
            .archive_revisions
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>(),
    })
}

/// Run the prune against the post-apply env. Re-plans from the store (the
/// upsert half may have staged new revisions), so the report names exactly
/// what was removed.
pub(super) fn execute(
    store: &LocalFsStore,
    ctx: &ApplyContext,
    hooks: &dyn RetireHooks,
) -> Result<Value, OpError> {
    let env = store.load(&ctx.env_id)?;
    let owned = ownership::load(store, &ctx.env_id)?.ids();
    let plan = prune_plan(&env, &owned, &declared_ids(&env, ctx));
    let mut archived = Vec::new();
    for r in &plan.archive_revisions {
        let key = prune_key(&format!("revision:{r}"))?;
        store
            .archive_revision(&ctx.env_id, *r, key)
            .map_err(super::super::map_store_err_preserving_noun)?;
        let teardown = match hooks.teardown(&ctx.env_id, *r)? {
            HookResult::Done => json!({"result": "done"}),
            HookResult::Unavailable(why) => json!({"result": "unavailable", "detail": why}),
        };
        archived.push(json!({"revision_id": r.to_string(), "teardown": teardown}));
    }
    let mut retired = Vec::new();
    for d in &plan.retire {
        let key = prune_key(&format!("deployment:{d}"))?;
        retired.push(retire_deployment(store, hooks, &ctx.env_id, *d, key)?.result);
    }
    let after = store.load(&ctx.env_id)?;
    ownership::record(store, &ctx.env_id, &after, &declared_ids(&after, ctx))?;
    Ok(json!({
        "planned": false,
        "retired": retired,
        "archived_revisions": archived,
    }))
}

fn prune_key(target: &str) -> Result<IdempotencyKey, OpError> {
    IdempotencyKey::new(format!("env-apply-prune:{target}"))
        .map_err(|e| OpError::InvalidArgument(format!("idempotency_key: {e}")))
}

#[cfg(test)]
#[path = "prune_tests.rs"]
mod tests;
