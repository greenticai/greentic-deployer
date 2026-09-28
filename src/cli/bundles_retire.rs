//! `op bundles retire <env> <bundle>` (unified release Phase 5, PD1).
//!
//! Retire is a sequence, not a delete (P5-R2). Each step reads the store
//! first, so every step is idempotent and a retire interrupted anywhere is
//! finished by running it again:
//!
//! 1. **clear** — refuse if a messaging endpoint would be stranded, mark the
//!    deployment retiring (status `archived`) and remove its split.
//! 2. **drain** — stamp `Ready` revisions `Draining`, then run the drain hook
//!    for every draining revision (the bound deployer's enforced
//!    `drain_revision`: wait the drain window, then confirm it serves nothing;
//!    an env without a live deployer reports the hook `unavailable`). An
//!    undrained revision stops the retire unless `--force-drain`, which records
//!    it and lets the teardown skip the drain gate.
//! 3. **teardown, then archive** — per revision, tear it down provider-side
//!    (`archive_revision`) FIRST and archive it in the store only once that
//!    succeeded. A failed teardown leaves the revision live in the store, so
//!    the next attempt retries it. Teardown also re-runs for revisions already
//!    archived (it is idempotent provider-side).
//! 4. **remove** — drop the deployment (and its archived revisions).
//!
//! Before step 1 the retire refuses (`MissingCapability`, capability
//! `remove`) when a deployer IS bound but cannot tear revisions down —
//! removing the record could orphan a running workload. `--store-only` skips
//! both provider hooks and that refusal, for an env whose provider is gone
//! for good; whatever it left running is `op env sweep`'s to find.
//!
//! Data is not destroyed: retire removes serving resources, never tenant
//! state (destroying data is its own workflow).

use greentic_deploy_spec::engine::retire_steps;
use greentic_deploy_spec::{DeploymentId, EnvId, Environment, IdempotencyKey, RevisionId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::env::{ProviderStep, RevisionVerb, provider_revision_step};
use super::{
    AuditCtx, AuditGens, CommitMarker, OpError, OpFlags, OpOutcome, audit_and_record,
    map_store_err_preserving_noun, resolve_idempotency_key,
};

const NOUN: &str = "bundles";
const VERB: &str = "retire";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRetirePayload {
    pub environment_id: String,
    /// A deployment ULID, or a bundle id (unique within the env, else
    /// disambiguate with `customer_id`).
    pub bundle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    /// Skip the provider drain / teardown hooks.
    #[serde(default)]
    pub store_only: bool,
    /// Tear down revisions the deployer cannot confirm drained (P5-R2).
    #[serde(default)]
    pub force_drain: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Result of one provider hook call, reported per revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HookResult {
    Done,
    Unavailable(String),
}

/// Provider side of a retire. Tests inject fakes; the CLI uses
/// [`ProviderHooks`] or [`StoreOnlyHooks`].
pub(crate) trait RetireHooks {
    /// Refuse before anything is mutated when these hooks could not tear the
    /// env's revisions down.
    fn preflight(&self, _env: &Environment) -> Result<(), OpError> {
        Ok(())
    }
    fn drain(&self, env_id: &EnvId, revision_id: RevisionId) -> Result<HookResult, OpError>;
    /// Drain every revision; results in input order. Default: one after
    /// another. [`ProviderHooks`] drains concurrently (bounded), so a retire
    /// of N revisions waits about one drain window, not N.
    fn drain_all(
        &self,
        env_id: &EnvId,
        revisions: &[RevisionId],
    ) -> Vec<Result<HookResult, OpError>> {
        revisions.iter().map(|r| self.drain(env_id, *r)).collect()
    }
    fn teardown(&self, env_id: &EnvId, revision_id: RevisionId) -> Result<HookResult, OpError>;
}

/// Drives the env's bound deployer (`op env apply-revision`'s resolution).
pub(crate) struct ProviderHooks<'a> {
    pub store: &'a LocalFsStore,
    pub registry: &'a crate::env_packs::EnvPackRegistry,
    /// `--force-drain`: an undrained revision is reported, not fatal, and its
    /// teardown skips the drain gate.
    pub force_drain: bool,
}

impl ProviderHooks<'_> {
    fn run(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        verb: RevisionVerb,
    ) -> Result<HookResult, OpError> {
        let step = provider_revision_step(
            self.store,
            self.registry,
            env_id,
            revision_id,
            verb,
            self.force_drain,
        );
        match step {
            Ok(ProviderStep::Done { .. }) => Ok(HookResult::Done),
            Ok(ProviderStep::Unavailable(why)) => Ok(HookResult::Unavailable(why)),
            Err(OpError::NotDrained { reason, .. }) if self.force_drain => Ok(
                HookResult::Unavailable(format!("not drained, forced past: {reason}")),
            ),
            Err(e) => Err(e),
        }
    }
}

impl RetireHooks for ProviderHooks<'_> {
    fn preflight(&self, env: &Environment) -> Result<(), OpError> {
        super::env::deployer_supports_remove(env).map(|_| ())
    }
    fn drain(&self, env_id: &EnvId, revision_id: RevisionId) -> Result<HookResult, OpError> {
        self.run(env_id, revision_id, RevisionVerb::Drain)
    }
    fn drain_all(
        &self,
        env_id: &EnvId,
        revisions: &[RevisionId],
    ) -> Vec<Result<HookResult, OpError>> {
        drain_concurrently(revisions, |r| self.drain(env_id, r))
    }
    fn teardown(&self, env_id: &EnvId, revision_id: RevisionId) -> Result<HookResult, OpError> {
        self.run(env_id, revision_id, RevisionVerb::Archive)
    }
}

/// `--store-only`: no provider call at all.
pub(crate) struct StoreOnlyHooks;

impl RetireHooks for StoreOnlyHooks {
    fn drain(&self, _: &EnvId, _: RevisionId) -> Result<HookResult, OpError> {
        Ok(HookResult::Unavailable("--store-only".to_string()))
    }
    fn teardown(&self, _: &EnvId, _: RevisionId) -> Result<HookResult, OpError> {
        Ok(HookResult::Unavailable("--store-only".to_string()))
    }
}

/// Build the payload from clap args; `None` when neither positional was
/// given (the payload then comes from `--answers`).
pub fn payload_from_retire_args(
    args: super::dispatch::BundleRetireArgs,
) -> Result<Option<BundleRetirePayload>, OpError> {
    let super::dispatch::BundleRetireArgs {
        env_id,
        bundle,
        customer,
        store_only,
        force_drain,
        idempotency_key,
    } = args;
    if env_id.is_none() && bundle.is_none() {
        return Ok(None);
    }
    let environment_id = env_id.ok_or_else(|| {
        OpError::InvalidArgument("bundles retire: missing positional `<env_id>`".to_string())
    })?;
    let bundle = bundle.ok_or_else(|| {
        OpError::InvalidArgument("bundles retire: missing positional `<bundle>`".to_string())
    })?;
    Ok(Some(BundleRetirePayload {
        environment_id,
        bundle,
        customer_id: customer,
        store_only,
        force_drain,
        idempotency_key,
    }))
}

pub fn retire(
    store: &LocalFsStore,
    registry: &crate::env_packs::EnvPackRegistry,
    flags: &OpFlags,
    payload: Option<BundleRetirePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, VERB, retire_schema()));
    }
    let payload = match payload {
        Some(p) => p,
        None => match &flags.answers {
            Some(path) => super::load_answers::<BundleRetirePayload>(path)?,
            None => {
                return Err(OpError::InvalidArgument(
                    "no payload provided: pass `<env_id> <bundle>` or --answers <path>".to_string(),
                ));
            }
        },
    };
    if payload.store_only {
        retire_with_hooks(store, &StoreOnlyHooks, payload)
    } else {
        let hooks = ProviderHooks {
            store,
            registry,
            force_drain: payload.force_drain,
        };
        retire_with_hooks(store, &hooks, payload)
    }
}

pub(crate) fn retire_with_hooks(
    store: &LocalFsStore,
    hooks: &dyn RetireHooks,
    payload: BundleRetirePayload,
) -> Result<OpOutcome, OpError> {
    let env_id = EnvId::try_from(payload.environment_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let Some(deployment_id) =
        resolve_deployment(&env, &payload.bundle, payload.customer_id.as_deref())?
    else {
        // Idempotent: already retired (or never deployed). Said explicitly so
        // a typo does not read as a successful retire.
        return Ok(OpOutcome::new(
            NOUN,
            VERB,
            json!({
                "environment_id": env_id.as_str(),
                "bundle": payload.bundle,
                "state": "absent",
            }),
        ));
    };
    let key = resolve_idempotency_key(payload.idempotency_key)?;
    retire_deployment(store, hooks, &env_id, deployment_id, key)
}

/// Retire one deployment by id under a single audit event. Shared with
/// `op env apply --prune`.
pub(crate) fn retire_deployment(
    store: &LocalFsStore,
    hooks: &dyn RetireHooks,
    env_id: &EnvId,
    deployment_id: DeploymentId,
    key: IdempotencyKey,
) -> Result<OpOutcome, OpError> {
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: VERB,
        target: json!({"deployment_id": deployment_id.to_string()}),
        idempotency_key: Some(key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let result = run_sequence(store, hooks, env_id, deployment_id, key, committed)?;
        Ok((OpOutcome::new(NOUN, VERB, result), AuditGens::NONE))
    })
}

fn run_sequence(
    store: &LocalFsStore,
    hooks: &dyn RetireHooks,
    env_id: &EnvId,
    deployment_id: DeploymentId,
    key: IdempotencyKey,
    committed: &CommitMarker,
) -> Result<Value, OpError> {
    let map = map_store_err_preserving_noun;
    hooks.preflight(&store.load(env_id)?)?;
    let begun = store.begin_retire(env_id, deployment_id).map_err(map)?;
    if begun.mutated() {
        committed.mark_committed();
    }
    let steps = retire_steps(&store.load(env_id)?, deployment_id)
        .map_err(|e| OpError::NotFound(e.to_string()))?;
    for r in &steps.drain_stamp {
        store.drain_revision(env_id, *r, key.clone()).map_err(map)?;
        committed.mark_committed();
    }
    let drained = hooks.drain_all(env_id, &steps.drain_hook);
    let mut drained = drained.into_iter();
    let drain_hooks = run_hook(&steps.drain_hook, |_| {
        drained
            .next()
            .unwrap_or_else(|| Err(OpError::Conflict("drain produced no result".to_string())))
    })?;
    // Provider first, store second: a revision is archived only once its
    // workload is gone, so a failed teardown leaves it live in the store.
    let teardown = run_hook(&steps.teardown, |r| {
        let result = hooks.teardown(env_id, r).map_err(|e| {
            OpError::Conflict(format!(
                "teardown of revision `{r}` failed; it stays un-archived and the next \
                 retire retries it: {e}"
            ))
        })?;
        if steps.archive.contains(&r) {
            store
                .archive_revision(env_id, r, key.clone())
                .map_err(map)?;
            committed.mark_committed();
        }
        Ok(result)
    })?;
    let removed = store
        .remove_bundle(env_id, deployment_id, key)
        .map_err(map)?;
    Ok(json!({
        "environment_id": env_id.as_str(),
        "deployment_id": deployment_id.to_string(),
        "bundle_id": removed.deployment.bundle_id.as_str(),
        "customer_id": removed.deployment.customer_id.as_str(),
        "state": "retired",
        "marked_retiring": begun.marked_retiring,
        "split_cleared": begun.cleared.is_some(),
        "drained": ids(&steps.drain_stamp),
        "drain_hook": drain_hooks,
        "archived": ids(&steps.archive),
        "teardown": teardown,
        "pruned_revision_ids": ids(&removed.pruned_revision_ids),
    }))
}

/// How many revisions a retire drains at once.
pub(crate) const DRAIN_CONCURRENCY: usize = 4;

/// Run `drain` over `revisions` on at most [`DRAIN_CONCURRENCY`] threads at a
/// time; results in input order. Each drain waits its own window, so a batch
/// costs about one window rather than one per revision.
pub(crate) fn drain_concurrently<F>(
    revisions: &[RevisionId],
    drain: F,
) -> Vec<Result<HookResult, OpError>>
where
    F: Fn(RevisionId) -> Result<HookResult, OpError> + Sync,
{
    let mut out = Vec::with_capacity(revisions.len());
    for batch in revisions.chunks(DRAIN_CONCURRENCY) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|r| {
                    let drain = &drain;
                    let r = *r;
                    scope.spawn(move || drain(r))
                })
                .collect();
            for handle in handles {
                out.push(handle.join().unwrap_or_else(|_| {
                    Err(OpError::Conflict("a drain thread panicked".to_string()))
                }));
            }
        });
    }
    out
}

fn run_hook(
    revisions: &[RevisionId],
    mut call: impl FnMut(RevisionId) -> Result<HookResult, OpError>,
) -> Result<Vec<Value>, OpError> {
    revisions
        .iter()
        .map(|r| {
            let row = match call(*r)? {
                HookResult::Done => json!({"revision_id": r.to_string(), "result": "done"}),
                HookResult::Unavailable(why) => json!({
                    "revision_id": r.to_string(),
                    "result": "unavailable",
                    "detail": why,
                }),
            };
            Ok(row)
        })
        .collect()
}

fn ids(revisions: &[RevisionId]) -> Vec<String> {
    revisions.iter().map(|r| r.to_string()).collect()
}

/// `bundle` is a deployment ULID or a bundle id. `Ok(None)` = nothing to
/// retire; more than one match without `customer` is a refusal.
fn resolve_deployment(
    env: &Environment,
    bundle: &str,
    customer: Option<&str>,
) -> Result<Option<DeploymentId>, OpError> {
    use std::str::FromStr;
    if let Ok(ulid) = ulid::Ulid::from_str(bundle) {
        let id = DeploymentId(ulid);
        if env.bundles.iter().any(|b| b.deployment_id == id) {
            return Ok(Some(id));
        }
    }
    let matches: Vec<_> = env
        .bundles
        .iter()
        .filter(|b| b.bundle_id.as_str() == bundle)
        .filter(|b| customer.is_none_or(|c| b.customer_id.as_str() == c))
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one.deployment_id)),
        many => Err(OpError::InvalidArgument(format!(
            "bundle `{bundle}` is deployed for {} customers ({}); pass --customer or the \
             deployment id",
            many.len(),
            many.iter()
                .map(|b| b.customer_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn retire_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "BundleRetirePayload",
        "type": "object",
        "required": ["environment_id", "bundle"],
        "properties": {
            "environment_id": {"type": "string"},
            "bundle": {"type": "string", "description": "Deployment ULID or bundle id"},
            "customer_id": {"type": "string"},
            "store_only": {"type": "boolean", "default": false},
            "force_drain": {"type": "boolean", "default": false},
            "idempotency_key": {"type": "string"}
        },
        "additionalProperties": false
    })
}

#[cfg(test)]
#[path = "bundles_retire_tests.rs"]
mod tests;
