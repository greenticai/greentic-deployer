//! `gtc op revisions {stage,warm,drain,archive,list}` (`A3`).
//!
//! Manages `Environment.revisions: Vec<Revision>` and the per-deployment
//! `current_revisions` list on each `BundleDeployment`. Lifecycle transitions
//! are validated against the spec's pure
//! [`is_valid_transition`]
//! predicate so the operator can't put a Revision into an impossible state.
//!
//! Heavy lifting deferred:
//!
//! - Bundle-archive staging (resolving `.gtbundle` → `pack_list` via the
//!   distributor-client's `stage_bundle` call, digest-verifying the
//!   artifact, and writing the pack-list lockfile atomically before the
//!   revision becomes `Staged`) is **Phase D** work — tracked at
//!   <https://github.com/greenticai/greentic-deployer/issues/209>. Today
//!   `stage` trusts caller-supplied `bundle_digest` / `pack_list` /
//!   `*_ref` fields verbatim. A5 delivered the lifecycle storage guard
//!   (`environment::lifecycle::apply_revision_transition`) and the
//!   distributor-client's `set_bundle_state` atomic-write + transition
//!   matrix, but did NOT integrate `stage_bundle` here.
//! - Runner warm/drain hooks (route-table build, in-flight session
//!   accounting) are owned by `greentic-start`; A3 only updates the
//!   lifecycle bit and stamps `warmed_at`. The full warm/drain dance lands
//!   when the dispatcher lands.

use std::path::PathBuf;

use chrono::Utc;
use greentic_deploy_spec::{
    BundleId, DeploymentId, EnvId, PackId, PackListEntry, Revision, RevisionId, RevisionLifecycle,
    SemVer, is_valid_transition,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore, StageRevisionPayload};
use crate::rollout_telemetry::emit_lifecycle_event;
use greentic_deploy_spec::Environment;
use greentic_telemetry::RolloutEvent;

use super::{
    AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record, map_store_err_preserving_noun,
    mint_idempotency_key,
};

const NOUN: &str = "revisions";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionStagePayload {
    pub environment_id: String,
    pub deployment_id: String,
    /// Local `.gtbundle` to resolve. When set, the bundle is extracted under
    /// the revision dir and its embedded `.gtpack`s are pinned into
    /// `pack-list.lock` — `bundle_digest` / `pack_list` / `pack_list_lock_ref`
    /// are then derived from the artifact and any caller-supplied values for
    /// those fields are ignored. When unset, the legacy path records the
    /// caller-supplied pointers verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<PathBuf>,
    #[serde(default = "default_bundle_digest")]
    pub bundle_digest: String,
    #[serde(default)]
    pub pack_list: Vec<PackListEntryPayload>,
    /// Env-relative pack-list lockfile. Empty (the default) means "no lock
    /// written": the runtime-config materializer only surfaces a non-empty
    /// ref, so an unstaged/legacy revision never points greentic-start at a
    /// file that does not exist. The `--bundle` path overwrites this with the
    /// real `revisions/<rev>/pack-list.lock` it writes.
    #[serde(default)]
    pub pack_list_lock_ref: PathBuf,
    #[serde(default = "default_config_digest")]
    pub config_digest: String,
    #[serde(default = "default_signature_sidecar_ref")]
    pub signature_sidecar_ref: PathBuf,
    #[serde(default = "default_drain_seconds")]
    pub drain_seconds: u32,
}

pub(super) fn default_bundle_digest() -> String {
    "sha256:00".to_string()
}
pub(super) fn default_config_digest() -> String {
    "sha256:00".to_string()
}
pub(super) fn default_signature_sidecar_ref() -> PathBuf {
    PathBuf::from("rev.sig")
}
pub(super) fn default_drain_seconds() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackListEntryPayload {
    pub pack_id: String,
    pub version: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionTransitionPayload {
    pub environment_id: String,
    pub revision_id: String,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI surface
    /// for back-compat; when absent, [`typed_transition`] mints one per
    /// CLI invocation. Operators wanting safe lost-response retries
    /// (HTTP backend, PR-3b) supply a stable key in their payload so the
    /// server can replay the original outcome instead of applying a
    /// second mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionSummary {
    pub revision_id: String,
    pub deployment_id: String,
    pub bundle_id: String,
    pub sequence: u64,
    pub lifecycle: RevisionLifecycle,
}

impl From<&Revision> for RevisionSummary {
    fn from(r: &Revision) -> Self {
        Self {
            revision_id: r.revision_id.to_string(),
            deployment_id: r.deployment_id.to_string(),
            bundle_id: r.bundle_id.as_str().to_string(),
            sequence: r.sequence,
            lifecycle: r.lifecycle,
        }
    }
}

/// `op revisions stage`. Creates a Revision at `inactive → staged`. Bumps
/// the sequence to one past the deployment's current max.
pub fn stage(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionStagePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "stage", stage_schema()));
    }
    let payload = resolve_payload::<RevisionStagePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    // Pre-parse the pack list outside the lock so a payload error doesn't
    // hold the flock. Only the legacy (no-`bundle_path`) path consumes it; on
    // the bundle path the lock is derived from the artifact, so skip parsing
    // entirely — a stale/invalid `pack_list` in an answers payload must not
    // spuriously fail a `--bundle` stage that ignores it.
    let pack_list = if payload.bundle_path.is_some() {
        Vec::new()
    } else {
        payload
            .pack_list
            .into_iter()
            .map(|e| {
                Ok::<_, OpError>(PackListEntry {
                    pack_id: PackId::new(e.pack_id),
                    version: e
                        .version
                        .parse::<SemVer>()
                        .map_err(|err| OpError::InvalidArgument(format!("pack version: {err}")))?,
                    digest: e.digest,
                    source_uri: e.source_uri,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if !is_valid_transition(RevisionLifecycle::Inactive, RevisionLifecycle::Staged) {
        return Err(OpError::Conflict(
            "spec rejects inactive → staged".to_string(),
        ));
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "stage",
        target: json!({
            "deployment_id": deployment_id.to_string(),
            "lifecycle_to": "staged",
        }),
        idempotency_key: None,
    };
    let RevisionStagePayload {
        bundle_path,
        bundle_digest: payload_bundle_digest,
        pack_list_lock_ref: payload_pack_list_lock_ref,
        config_digest,
        signature_sidecar_ref,
        drain_seconds,
        ..
    } = payload;
    audit_and_record(store, ctx, |_committed| {
        // Look up the deployment INSIDE the authz gate. Touching the
        // filesystem (bundle extraction, pack-config materialization)
        // before `audit_and_record` enters its closure would let a
        // denied caller write under `<env>/revisions/...` before being
        // rejected — Codex review on PR-3a.5 flagged that authz bypass.
        let env = store.load(&env_id).map_err(map_store_err_preserving_noun)?;
        let bundle_id = env
            .bundles
            .iter()
            .find(|b| b.deployment_id == deployment_id)
            .map(|b| b.bundle_id.clone())
            .ok_or_else(|| {
                OpError::NotFound(format!(
                    "deployment `{deployment_id}` not found in env `{env_id}`"
                ))
            })?;

        // Mint the revision id now: the `--bundle` path names the
        // per-revision extract dir after this ULID, and the pack-list
        // lock + per-pack pack-config docs are written under that dir
        // before the typed verb sees them.
        let revision_id = crate::environment::mint_revision_id();
        let env_dir = store.env_dir(&env_id)?;
        // Closure that drops the rev_dir on any post-staging failure
        // (materialize_pack_configs OR stage_revision). Both call sites
        // need the same path-join + best-effort remove, so build it once.
        let drop_rev_dir = || {
            let rev_dir = env_dir.join("revisions").join(revision_id.to_string());
            let _ = std::fs::remove_dir_all(&rev_dir);
        };

        // Resolve a local `.gtbundle` (extract + pin packs) when one
        // was supplied, deriving the artifact pointers; otherwise
        // record the caller-supplied pointers verbatim (legacy
        // Phase-A behavior).
        let has_bundle = bundle_path.is_some();
        let (bundle_digest, revision_pack_list, pack_list_lock_ref, pack_config_refs) =
            match bundle_path {
                Some(bundle_path) => {
                    let staged = super::bundle_stage::stage_local_bundle(
                        &env_dir,
                        revision_id,
                        &bundle_path,
                    )?;
                    // Walk `staged.lock.packs` once: build both
                    // `lock_derived_pack_list` (feeds `Revision.pack_list`
                    // so `Environment::validate`'s config-overrides
                    // cross-ref has data) and the pinned-pack-id set for
                    // `materialize_pack_configs` in one pass.
                    let mut lock_derived_pack_list: Vec<PackListEntry> =
                        Vec::with_capacity(staged.lock.packs.len());
                    let mut pinned_pack_ids: std::collections::HashSet<String> =
                        std::collections::HashSet::with_capacity(staged.lock.packs.len());
                    for lp in &staged.lock.packs {
                        let pack_id = lp.pack_id.clone();
                        pinned_pack_ids.insert(pack_id.as_str().to_string());
                        lock_derived_pack_list.push(PackListEntry::from_lock_primitives(
                            pack_id,
                            lp.digest.clone(),
                        ));
                    }
                    let rev_dir = env_dir.join("revisions").join(revision_id.to_string());
                    // If pack-config materialization fails AFTER
                    // `stage_local_bundle` succeeded, drop the rev_dir
                    // so a re-stage starts clean.
                    let pack_config_refs = super::pack_config_stage::materialize_pack_configs(
                        &env_dir,
                        &rev_dir,
                        revision_id,
                        &env_id,
                        &bundle_id,
                        &pinned_pack_ids,
                    )
                    .inspect_err(|_| drop_rev_dir())?;
                    (
                        staged.bundle_digest,
                        lock_derived_pack_list,
                        staged.pack_list_lock_ref,
                        pack_config_refs,
                    )
                }
                None => (
                    payload_bundle_digest,
                    pack_list,
                    payload_pack_list_lock_ref,
                    Vec::new(),
                ),
            };

        let store_payload = StageRevisionPayload {
            revision_id,
            deployment_id,
            bundle_digest,
            pack_list: revision_pack_list,
            pack_list_lock_ref,
            pack_config_refs,
            config_digest,
            signature_sidecar_ref,
            drain_seconds,
            idempotency_key: mint_idempotency_key(),
        };
        // Post-staging cleanup: if the typed verb fails after the
        // `--bundle` path already wrote files under `rev_dir`, drop
        // the rev_dir so a re-stage starts clean. Closes a window
        // that existed pre-PR too: the old closure could return Err
        // from `locked.save(&env)` with the rev_dir already populated.
        let revision = store
            .stage_revision(&env_id, store_payload)
            .inspect_err(|_| {
                if has_bundle {
                    drop_rev_dir();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        let outcome = OpOutcome::new(
            NOUN,
            "stage",
            serde_json::to_value(RevisionSummary::from(&revision))
                .expect("RevisionSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op revisions warm`. `staged → warming → ready`. The two-step move is
/// collapsed here for A3 because no async warm hooks exist yet; Phase D wires
/// the runner warm API.
///
/// Default warm path runs a **Noop** health gate so existing CLI callers stay
/// behavior-compatible. Producers in higher-tier crates (e.g.
/// `greentic-start`) wire a real B9 warm/ready gate via
/// [`warm_with_health_gate`].
pub fn warm(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
) -> Result<OpOutcome, OpError> {
    warm_with_health_gate(store, flags, payload, |_env, _revision| Ok(()))
}

/// Gate-aware variant of [`warm`] (B9 of `plans/next-gen-deployment.md`).
///
/// Drives the same `staged → warming → ready` chain but runs `health_gate`
/// against the post-chain `(env, revision)` view before `warmed_at` is
/// stamped and the env is saved. On gate rejection, the revision is
/// persisted in `Failed` and a `Conflict` (warm/ready health gate) is
/// surfaced — see
/// [`crate::environment::apply_revision_transition_with_health_gate`].
///
/// Higher-tier consumers construct the gate from concrete validators
/// (route-table validate, runtime-config load, signature verify, provider
/// probes); this function only forwards the closure into the lifecycle
/// helper, keeping `greentic-deployer` free of any health-check producers.
pub fn warm_with_health_gate<G>(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
    health_gate: G,
) -> Result<OpOutcome, OpError>
where
    G: FnOnce(
        &greentic_deploy_spec::Environment,
        &Revision,
    ) -> Result<(), crate::environment::HealthGateFailure>,
{
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "warm", transition_schema()));
    }
    transition_with_health_gate(
        store,
        flags,
        payload,
        "warm",
        &[
            (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
            (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
        ],
        |r| {
            r.warmed_at = Some(Utc::now());
        },
        false,
        health_gate,
    )
}

/// `op revisions drain`. `ready → draining`. The full in-flight drain dance
/// (sessions, WebSocket cleanup, etc.) lives in the runtime; this command
/// records the intent and stamps the lifecycle.
pub fn drain(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "drain", transition_schema()));
    }
    typed_transition(
        store,
        flags,
        payload,
        "drain",
        RevisionLifecycle::Draining,
        |env_id, revision_id, key| store.drain_revision(env_id, revision_id, key),
    )
}

/// `op revisions archive`. Transitions the lifecycle to `archived` and
/// removes the revision from `BundleDeployment.current_revisions`. Refuses
/// archival of any revision still referenced by a live `TrafficSplit` —
/// callers must rebalance traffic through `gtc op traffic set` first.
///
/// Accepts the full retirement walk: `Staged | Warming | Ready | Failed`
/// archive in one hop; a revision already drained (Draining → Inactive
/// via the runtime) completes through `Inactive → Archived` in the same
/// CLI call.
pub fn archive(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "archive", transition_schema()));
    }
    typed_transition(
        store,
        flags,
        payload,
        "archive",
        RevisionLifecycle::Archived,
        |env_id, revision_id, key| store.archive_revision(env_id, revision_id, key),
    )
}

/// `op revisions list <env>` (filterable by `--deployment <id>` later).
pub fn list(store: &LocalFsStore, flags: &OpFlags, env_id: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "list",
            json!({"input_schema": "env_id positional"}),
        ));
    }
    let env_id = parse_env_id(env_id)?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let revisions: Vec<RevisionSummary> = env.revisions.iter().map(RevisionSummary::from).collect();
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({"environment_id": env_id.as_str(), "revisions": revisions}),
    ))
}

// --- internals -----------------------------------------------------------

/// CLI-side adapter over a typed
/// [`EnvironmentMutations`](crate::environment::EnvironmentMutations) revision
/// verb. PR-3a.6 replaces the closure-based
/// `apply_revision_transition` driver for the no-gate path (drain + archive)
/// — the typed verb method owns the `transact` flock and the
/// `refresh_runtime_config` refresh; the CLI handles authz, audit, payload
/// resolution, error noun preservation, and lifecycle-event emission.
///
/// The warm/ready gate path stays on the closure-based
/// [`transition_with_health_gate`] until PR-3a.6b: pre-evaluating the gate
/// against a synthesized post-chain view is a behavior shift worth its own PR.
fn typed_transition<F>(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
    op: &'static str,
    lifecycle_to: RevisionLifecycle,
    call_verb: F,
) -> Result<OpOutcome, OpError>
where
    F: FnOnce(
        &greentic_deploy_spec::EnvId,
        greentic_deploy_spec::RevisionId,
        greentic_deploy_spec::IdempotencyKey,
    ) -> Result<
        crate::environment::RevisionTransitionOutcome,
        crate::environment::StoreError,
    >,
{
    let payload = resolve_payload::<RevisionTransitionPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let revision_id = parse_revision_id(&payload.revision_id)?;
    // Resolve the idempotency key once — same value lands in the audit
    // event and in the typed verb call so an HTTP backend (PR-3b) can
    // replay the original outcome on a lost-response retry. Falling back
    // to a fresh ULID keeps existing CLI usage working unchanged.
    let idempotency_key = match payload.idempotency_key {
        Some(raw) => greentic_deploy_spec::IdempotencyKey::new(raw)
            .map_err(|e| OpError::InvalidArgument(format!("idempotency_key: {e}")))?,
        None => mint_idempotency_key(),
    };
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: op,
        // Both drain (always `Draining`) and archive (always `Archived`
        // — the `Draining → Inactive → Archived` chain walks end-to-end
        // in one call so a successful archive start always lands on
        // `Archived`) are deterministic, so record the verb-target state.
        target: json!({
            "revision_id": revision_id.to_string(),
            "lifecycle_to": lifecycle_to,
        }),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        // Committed-on-error: when the typed verb's lifecycle helper
        // saved the env mutation but a post-save step (load /
        // refresh_runtime_config) failed, mark committed BEFORE the
        // error escapes so the audit boundary fails-closed on an
        // audit-append failure (matches the closure-based
        // `transition_with_health_gate` Ok-arm post-save contract —
        // see `warm_ok_with_refresh_failure_and_audit_failure_returns_audit_error`).
        let outcome = call_verb(&env_id, revision_id, idempotency_key)
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        // Typed-verb Ok = saved + runtime-config refreshed before return,
        // so mark committed before any best-effort emit unwinds.
        committed.mark_committed();
        emit_for_op(
            op,
            false,
            Some(outcome.starting_lifecycle),
            &outcome.environment,
            &outcome.revision,
        );
        let summary = RevisionSummary::from(&outcome.revision);
        let op_outcome = OpOutcome::new(
            NOUN,
            op,
            serde_json::to_value(summary).expect("RevisionSummary is json-safe"),
        );
        Ok((op_outcome, super::AuditGens::NONE))
    })
}

/// Gate-aware variant of [`typed_transition`] for the B9 warm/ready gate.
/// Routes `on_final` and the `health_gate` closure through
/// [`crate::environment::apply_revision_transition_with_health_gate`] inside
/// the same `store.transact` lock so the gate sees the same snapshot the
/// chain advance saw and the env is saved once (Failed on rejection, post-
/// transition otherwise).
///
/// **TODO(PR-3a.6b):** delete this in favor of [`typed_transition`] once warm
/// migrates to the typed `LocalFsStore::warm_revision` verb. Today the
/// closure shape stays so the in-lock B9 gate consumer in `greentic-start`
/// keeps its current contract; PR-3a.6b adds env-generation precondition
/// support to `WarmRevisionPayload` so the pre-evaluated outcome can be
/// safely shipped across the HTTP wire.
// One extra arg over the 7-arg sibling typed_transition to thread the gate
// closure; bundling into a struct would touch every existing warm caller for
// no readability win.
#[allow(clippy::too_many_arguments)]
fn transition_with_health_gate<F, G>(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
    op: &'static str,
    accepted_chain: &[(RevisionLifecycle, RevisionLifecycle)],
    on_final: F,
    prune_from_splits: bool,
    health_gate: G,
) -> Result<OpOutcome, OpError>
where
    F: FnOnce(&mut Revision),
    G: FnOnce(
        &greentic_deploy_spec::Environment,
        &Revision,
    ) -> Result<(), crate::environment::HealthGateFailure>,
{
    let payload = resolve_payload::<RevisionTransitionPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let revision_id = parse_revision_id(&payload.revision_id)?;
    // The chain's final `to` state is the lifecycle this verb lands on. Serde
    // emits the canonical lowercase wire form, matching how lifecycle appears
    // everywhere else.
    let lifecycle_to = accepted_chain.last().map(|(_, to)| *to);
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: op,
        target: json!({
            "revision_id": revision_id.to_string(),
            "lifecycle_to": lifecycle_to,
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |committed| {
        let (revision, env, starting_lifecycle) = store.transact(
            &env_id,
            |locked| -> Result<(Revision, Environment, Option<RevisionLifecycle>), OpError> {
                // C5.3: capture the revision's lifecycle BEFORE the helper
                // walks the chain. The `archive` matrix can traverse
                // `Draining → Inactive → Archived` end-to-end in one call,
                // so the final lifecycle alone can't tell us whether we
                // crossed the `Draining → Inactive` eviction hop. Reading
                // the env here is the same disk read the helper does
                // internally, so the extra cost is one in-memory lookup.
                //
                // A load failure leaves `starting_lifecycle = None`, which
                // makes the eviction emit skip silently — emit a
                // `tracing::warn!` so the gap is observable rather than
                // invisible. The lifecycle helper below will likely fail
                // too, but if it transiently recovers (rare), at least the
                // missing telemetry has a breadcrumb.
                let starting_lifecycle = match locked.load() {
                    Ok(e) => e
                        .revisions
                        .iter()
                        .find(|r| r.revision_id == revision_id)
                        .map(|r| r.lifecycle),
                    Err(err) => {
                        tracing::warn!(
                            op = op,
                            env_id = %env_id,
                            revision_id = %revision_id,
                            error = %err,
                            "C5.3: failed to capture starting lifecycle; an `archive` \
                             eviction emit may be skipped"
                        );
                        None
                    }
                };
                let revision = match crate::environment::apply_revision_transition_with_health_gate(
                    locked,
                    revision_id,
                    accepted_chain,
                    on_final,
                    prune_from_splits,
                    health_gate,
                ) {
                    Ok(r) => {
                        // The lifecycle helper called `locked.save(&env)` before
                        // returning Ok — env is durable on disk. From this point
                        // forward, every error path inside the transact (load,
                        // refresh_runtime_config, …) is *committed-on-error*:
                        // mark the audit boundary so a follow-up audit-append
                        // failure fails-closed instead of silently demoting to
                        // `tracing::warn!`.
                        committed.mark_committed();
                        r
                    }
                    Err(e @ crate::environment::LifecycleError::HealthGateFailed { .. }) => {
                        // Gate-fail path: the lifecycle helper flipped the
                        // revision to `Failed` and saved before returning this
                        // error. The Failed state is durable, so mark the
                        // audit boundary BEFORE the best-effort telemetry
                        // emit — matches the Ok-arm convention
                        // (commit-then-emit) and keeps the audit failure
                        // path robust to any unwind from the emit. Telemetry
                        // is best-effort: a load failure here must NOT mask
                        // the original `HealthGateFailed` error, hence
                        // `.ok()`.
                        committed.mark_committed();
                        if let Ok(env_for_emit) = locked.load()
                            && let Some(rev_for_emit) = env_for_emit
                                .revisions
                                .iter()
                                .find(|r| r.revision_id == revision_id)
                        {
                            // `starting_lifecycle` is not used by the
                            // `gate_failed = true` arm of `emit_for_op`, so
                            // passing `None` is fine here.
                            emit_for_op(op, true, None, &env_for_emit, rev_for_emit);
                        }
                        return Err(OpError::from(e));
                    }
                    Err(other) => return Err(OpError::from(other)),
                };
                // Lifecycle transitions don't change traffic splits today, so this
                // is a no-op refresh (guarded by change-detection); it keeps the
                // runtime-config contract uniform across every mutating verb.
                let env = locked.load()?;
                locked.refresh_runtime_config(&env)?;
                Ok((revision, env, starting_lifecycle))
            },
        )?;
        // C5.3: emit the lifecycle event for this verb. Centralized in
        // `emit_for_op` so the verb→event mapping lives in one place. Best-
        // effort observability — `emit_rollout_event` is panic-safe with no
        // subscriber installed, so no fallible path here can affect outcome.
        emit_for_op(op, false, starting_lifecycle, &env, &revision);

        let summary = RevisionSummary::from(&revision);
        let outcome = OpOutcome::new(
            NOUN,
            op,
            serde_json::to_value(summary).expect("RevisionSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// Verb → [`RolloutEvent`] dispatcher (C5.3).
///
/// Centralizes which event(s) each lifecycle verb emits on a successful or
/// health-gate-failed transition, so the verb mapping lives in one place
/// rather than scattered across [`warm`] / [`drain`] / [`archive`] /
/// [`decommission`] / [`activate`].
///
/// - `warm` Ok → `HealthGatePassed` + `RevisionWarmed` (the warm verb both
///   passes the gate and lands the revision in `Ready`).
/// - `warm` health-gate fail → `HealthGateFailed`.
/// - `drain` Ok → `RevisionDraining`.
/// - `archive` Ok with `starting_lifecycle == Some(Draining)` →
///   `RevisionEvicted` (the post-drain eviction hop). The final lifecycle
///   alone can't discriminate this: the `archive` chain walks
///   `Draining → Inactive → Archived` end-to-end in one call, so the
///   revision lands on `Archived` regardless of where it started. We key on
///   the starting lifecycle so a `Ready → Archived` archive (lifecycle
///   retirement, NOT a rollout eviction) correctly emits nothing.
/// - Other verbs and chains: no emit (no live rollout-event match).
fn emit_for_op(
    op: &'static str,
    gate_failed: bool,
    starting_lifecycle: Option<RevisionLifecycle>,
    env: &Environment,
    revision: &Revision,
) {
    match (op, gate_failed) {
        ("warm", false) => {
            emit_lifecycle_event(RolloutEvent::HealthGatePassed, env, revision);
            emit_lifecycle_event(RolloutEvent::RevisionWarmed, env, revision);
        }
        ("warm", true) => {
            emit_lifecycle_event(RolloutEvent::HealthGateFailed, env, revision);
        }
        ("drain", false) => {
            emit_lifecycle_event(RolloutEvent::RevisionDraining, env, revision);
        }
        ("archive", false) if starting_lifecycle == Some(RevisionLifecycle::Draining) => {
            emit_lifecycle_event(RolloutEvent::RevisionEvicted, env, revision);
        }
        _ => {}
    }
}

/// Build a [`RevisionStagePayload`] from direct CLI args, or `None` when no
/// positional args were supplied (deferring to `--answers` / `--schema`).
/// Mirrors `traffic::payload_from_set_args`: all clap fields are optional so
/// the answers/schema paths keep working unchanged.
pub fn payload_from_stage_args(
    args: super::dispatch::RevisionStageArgs,
) -> Result<Option<RevisionStagePayload>, OpError> {
    let super::dispatch::RevisionStageArgs {
        env_id,
        deployment,
        bundle,
    } = args;
    // Nothing positional → answers/schema path.
    if env_id.is_none() && deployment.is_none() && bundle.is_none() {
        return Ok(None);
    }
    let environment_id = env_id.ok_or_else(|| {
        OpError::InvalidArgument("revisions stage: missing positional `<env_id>`".to_string())
    })?;
    let deployment_id = deployment.ok_or_else(|| {
        OpError::InvalidArgument("revisions stage: missing `--deployment <ULID>`".to_string())
    })?;
    // Require `--bundle` on the direct path: without it we'd stage a revision
    // with a placeholder digest and a `pack_list_lock_ref` pointing at a lock
    // file that was never written — warmable by the no-op gate, admissible by
    // traffic, and broken at boot. The legacy verbatim path stays reachable
    // only via an explicit `--answers <file>`.
    let bundle_path = bundle.ok_or_else(|| {
        OpError::InvalidArgument(
            "revisions stage: missing `--bundle <PATH>`. The direct CLI path stages a local \
             .gtbundle; use `--answers <file>` for the legacy verbatim path."
                .to_string(),
        )
    })?;
    Ok(Some(RevisionStagePayload {
        environment_id,
        deployment_id,
        bundle_path: Some(bundle_path),
        bundle_digest: default_bundle_digest(),
        pack_list: Vec::new(),
        pack_list_lock_ref: PathBuf::new(),
        config_digest: default_config_digest(),
        signature_sidecar_ref: default_signature_sidecar_ref(),
        drain_seconds: default_drain_seconds(),
    }))
}

fn resolve_payload<T: serde::de::DeserializeOwned>(
    flags: &OpFlags,
    payload: Option<T>,
) -> Result<T, OpError> {
    if let Some(p) = payload {
        return Ok(p);
    }
    if let Some(path) = &flags.answers {
        return super::load_answers::<T>(path);
    }
    Err(OpError::InvalidArgument(
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn parse_deployment_id(raw: &str) -> Result<DeploymentId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("deployment_id: {e}")))?;
    Ok(DeploymentId(ulid))
}

fn parse_revision_id(raw: &str) -> Result<RevisionId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("revision_id: {e}")))?;
    Ok(RevisionId(ulid))
}

#[allow(dead_code)]
fn discard_bundle(_id: &BundleId) {
    // bundle_id is never used after derivation; this helper keeps the type
    // around for future planning hooks (e.g. ensuring stage rejects a
    // revision whose payload bundle_id contradicts the deployment's).
}

fn stage_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "RevisionStagePayload",
        "type": "object",
        "required": ["environment_id", "deployment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "deployment_id": {"type": "string", "description": "ULID"},
            "bundle_path": {"type": "string", "description": "Local .gtbundle to extract + pin; derives bundle_digest/pack_list/pack_list_lock_ref"},
            "bundle_digest": {"type": "string"},
            "pack_list": {"type": "array"},
            "pack_list_lock_ref": {"type": "string"},
            "config_digest": {"type": "string"},
            "signature_sidecar_ref": {"type": "string"},
            "drain_seconds": {"type": "integer", "minimum": 0}
        }
    })
}

fn transition_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "RevisionTransitionPayload",
        "type": "object",
        "required": ["environment_id", "revision_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "revision_id": {"type": "string", "description": "ULID"},
            "idempotency_key": {
                "type": "string",
                "description": "Optional A8 §2 caller-supplied key for safe retry replay; minted per-invocation when omitted."
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_bundle_deployment, make_env};
    use tempfile::tempdir;

    /// PR-3a.7 schema-drift regression (carries the same fix as
    /// `cli::bundles::tests::remove_schema_lists_idempotency_key`):
    /// `RevisionTransitionPayload` accepts an `idempotency_key` field, so
    /// `--schema` output MUST list it under `properties` — otherwise
    /// schema-driven callers reject the exact field needed for A8 §2
    /// retry replay.
    #[test]
    fn transition_schema_lists_idempotency_key() {
        let schema = transition_schema();
        let props = schema
            .get("properties")
            .and_then(|p| p.as_object())
            .expect("properties block");
        assert!(
            props.contains_key("idempotency_key"),
            "transition_schema must list `idempotency_key` so --schema-driven \
             callers can supply the A8 retry key (schema: {schema:#})"
        );
    }

    fn seed_env_with_deployment(store: &LocalFsStore) -> DeploymentId {
        let mut env = make_env("local");
        let deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        env.bundles.push(deployment);
        store.save(&env).unwrap();
        did
    }

    fn stage_payload(deployment_id: &DeploymentId) -> RevisionStagePayload {
        RevisionStagePayload {
            environment_id: "local".to_string(),
            deployment_id: deployment_id.to_string(),
            bundle_path: None,
            bundle_digest: "sha256:00".to_string(),
            pack_list: vec![PackListEntryPayload {
                pack_id: "greentic.test.pack".to_string(),
                version: "1.0.0".to_string(),
                digest: "sha256:00".to_string(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::new(),
            config_digest: default_config_digest(),
            signature_sidecar_ref: default_signature_sidecar_ref(),
            drain_seconds: default_drain_seconds(),
        }
    }

    #[test]
    fn stage_creates_revision_in_staged() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let outcome = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        assert_eq!(
            outcome.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("staged")
        );
        assert_eq!(
            outcome.result.get("sequence").and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    /// `stage --bundle <local .gtbundle>` extracts the bundle, pins every
    /// embedded `.gtpack` into a `pack-list.lock` under the revision dir, and
    /// records the env-relative lock ref + a real bundle digest on the
    /// revision. The lock's per-pack digest must equal the sha256 of the
    /// extracted `.gtpack` on disk — the exact invariant greentic-start's
    /// `load_revision` re-checks at boot.
    /// Regression for PR-3a.5 Codex finding: bundle staging must NOT touch
    /// the filesystem before `audit_and_record`'s authz gate. A `stage
    /// --bundle` against a non-local env must return `Unauthorized` AND
    /// leave the env's `revisions/` dir untouched.
    #[test]
    fn stage_with_bundle_on_non_local_env_rejects_before_writing_files() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // Seed a non-local env so `authorize_local_only` denies.
        let mut env = make_env("prod");
        let deployment = make_bundle_deployment("prod", "fast2flow");
        let did = deployment.deployment_id;
        env.bundles.push(deployment);
        store.save(&env).unwrap();

        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/perf-smoke-bundle.gtbundle");
        let mut payload = stage_payload(&did);
        payload.environment_id = "prod".to_string();
        payload.bundle_path = Some(fixture);

        let err = stage(&store, &OpFlags::default(), Some(payload)).unwrap_err();
        assert!(
            matches!(err, OpError::Unauthorized { .. }),
            "non-local env stage must be denied, got: {err:?}"
        );
        // No revisions dir should have been created — bundle staging
        // must run INSIDE the audit_and_record closure, not before.
        let rev_root = dir.path().join("prod").join("revisions");
        assert!(
            !rev_root.exists()
                || std::fs::read_dir(&rev_root)
                    .map(|d| d.count() == 0)
                    .unwrap_or(true),
            "denied stage must not write under `{}`",
            rev_root.display()
        );
    }

    #[test]
    fn stage_with_local_bundle_pins_packs_into_lockfile() {
        use greentic_deploy_spec::PackListLock;
        use sha2::{Digest, Sha256};

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);

        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/perf-smoke-bundle.gtbundle");
        let mut payload = stage_payload(&did);
        payload.bundle_path = Some(fixture);
        // Caller-supplied pack pointers must be ignored on the bundle path.
        payload.pack_list = vec![PackListEntryPayload {
            pack_id: "should.be.ignored".to_string(),
            version: "9.9.9".to_string(),
            digest: "sha256:ff".to_string(),
            source_uri: None,
        }];

        let outcome = stage(&store, &OpFlags::default(), Some(payload)).unwrap();
        assert_eq!(
            outcome.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("staged")
        );
        let rid = outcome
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // The stored revision points at the derived lock + a real bundle digest.
        let env_id = EnvId::try_from("local").unwrap();
        let env = store.load(&env_id).unwrap();
        let revision = env
            .revisions
            .iter()
            .find(|r| r.revision_id.to_string() == rid)
            .expect("revision persisted");
        assert!(
            revision.bundle_digest.starts_with("sha256:") && revision.bundle_digest != "sha256:00",
            "bundle_digest should be the real archive hash, got {}",
            revision.bundle_digest
        );
        // Inline pack_list is populated from the lock's pack ids so
        // Environment::validate's config_overrides cross-ref works
        // (Codex finding 1 fix). The lock file stays the on-disk source
        // of truth; the inline list carries pack_id membership only.
        assert!(
            !revision.pack_list.is_empty(),
            "pack_list should be populated from the lock"
        );

        let env_dir = store.env_dir(&env_id).unwrap();
        let lock_path = env_dir.join(&revision.pack_list_lock_ref);
        assert!(lock_path.is_file(), "pack-list.lock must be a regular file");

        let lock: PackListLock =
            serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
        assert_eq!(lock.revision_id, revision.revision_id);
        assert!(!lock.packs.is_empty(), "fixture bundle has a .gtpack");

        for pack in &lock.packs {
            // Ref is env-relative and resolves under the env dir to a real file.
            assert!(pack.path.is_relative(), "lock path must be env-relative");
            let pack_path = env_dir.join(&pack.path);
            assert!(
                pack_path.is_file(),
                "extracted .gtpack must exist: {}",
                pack_path.display()
            );
            // The pinned digest equals the on-disk file's sha256.
            let bytes = std::fs::read(&pack_path).unwrap();
            let expected = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            assert_eq!(pack.digest, expected, "lock digest must match the file");
        }
    }

    /// The direct CLI path must reject a stage with env+deployment but no
    /// `--bundle` — otherwise it would create a placeholder revision pointing
    /// at a never-written lock file (Codex finding 1).
    #[test]
    fn stage_args_without_bundle_is_rejected() {
        let did = DeploymentId::new();
        let args = crate::cli::dispatch::RevisionStageArgs {
            env_id: Some("local".to_string()),
            deployment: Some(did.to_string()),
            bundle: None,
        };
        let err = payload_from_stage_args(args).unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, OpError::InvalidArgument(_)) && msg.contains("--bundle"),
            "expected a missing --bundle error, got: {msg}"
        );
    }

    /// No positional args at all → defer to `--answers` (returns `None`), so
    /// the legacy path stays reachable.
    #[test]
    fn stage_args_empty_defers_to_answers() {
        let args = crate::cli::dispatch::RevisionStageArgs {
            env_id: None,
            deployment: None,
            bundle: None,
        };
        assert!(payload_from_stage_args(args).unwrap().is_none());
    }

    /// The recorded `bundle_digest` is bound to the immutable staged copy under
    /// the revision dir, not to the (mutable) input path: mutating the original
    /// after staging must not change what was pinned (Codex finding 2).
    #[test]
    fn stage_bundle_digest_is_bound_to_staged_copy_not_input() {
        use sha2::{Digest, Sha256};

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);

        // Stage from a temp copy of the fixture so we can mutate "the input"
        // afterward without touching the committed fixture.
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/perf-smoke-bundle.gtbundle");
        let input = dir.path().join("input.gtbundle");
        std::fs::copy(&fixture, &input).unwrap();

        let mut payload = stage_payload(&did);
        payload.bundle_path = Some(input.clone());
        let outcome = stage(&store, &OpFlags::default(), Some(payload)).unwrap();
        let rid = outcome
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let env_id = EnvId::try_from("local").unwrap();
        let env = store.load(&env_id).unwrap();
        let revision = env
            .revisions
            .iter()
            .find(|r| r.revision_id.to_string() == rid)
            .unwrap();

        // The staged copy exists and its sha256 equals the recorded digest.
        let env_dir = store.env_dir(&env_id).unwrap();
        let staged = env_dir.join("revisions").join(&rid).join("bundle.gtbundle");
        assert!(staged.is_file(), "staged bundle copy must persist");
        let staged_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(std::fs::read(&staged).unwrap()))
        );
        assert_eq!(revision.bundle_digest, staged_digest);

        // Corrupt the original input; the staged copy + recorded digest are
        // unaffected (the digest is over bytes we control, not the input path).
        std::fs::write(&input, b"tampered-after-stage").unwrap();
        let staged_digest_after = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(std::fs::read(&staged).unwrap()))
        );
        assert_eq!(
            revision.bundle_digest, staged_digest_after,
            "input mutation must not change the staged artifact's digest"
        );
    }

    #[test]
    fn warm_advances_to_ready() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let warmed = warm(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
                idempotency_key: None,
            }),
        )
        .unwrap();
        assert_eq!(
            warmed.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("ready")
        );
    }

    #[test]
    fn drain_after_warm_succeeds() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        warm(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.clone(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let drained = drain(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
                idempotency_key: None,
            }),
        )
        .unwrap();
        assert_eq!(
            drained.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("draining")
        );
    }

    #[test]
    fn drain_from_staged_errors() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let err = drain(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn archive_prunes_current_revisions_when_no_live_traffic() {
        // After the A5 follow-up landed the active-traffic guard, archive
        // no longer silently prunes live splits. This test exercises the
        // happy path: revision is in `current_revisions` but NOT in any
        // traffic split. Archive succeeds and strips the tracking
        // reference; no traffic state is touched.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let mut deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            RevisionLifecycle::Ready,
        );
        let rid = revision.revision_id;
        deployment.current_revisions.push(rid);
        env.bundles.push(deployment);
        env.revisions.push(revision);
        store.save(&env).unwrap();

        let outcome = archive(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("archived")
        );

        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert!(
            env.bundles[0].current_revisions.is_empty(),
            "current_revisions should be pruned"
        );
    }

    #[test]
    fn archive_refuses_when_revision_is_in_live_traffic_split() {
        // Operator workflow guarantee: archiving a revision that still
        // routes live traffic surfaces a Conflict pointing at the splits
        // to rebalance. The CLI maps `LifecycleError::ActiveTrafficReference`
        // through `From<LifecycleError> for OpError`.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let mut deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            RevisionLifecycle::Ready,
        );
        let rid = revision.revision_id;
        deployment.current_revisions.push(rid);
        let split = crate::cli::tests_common::make_traffic_split(
            "local",
            "fast2flow",
            &did,
            &rid,
            "test-key",
        );
        env.bundles.push(deployment);
        env.revisions.push(revision);
        env.traffic_splits.push(split);
        store.save(&env).unwrap();

        let err = archive(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(
                    msg.contains("live traffic split")
                        && msg.contains("rebalance via `gtc op traffic set`"),
                    "expected actionable conflict message, got: {msg}"
                );
            }
            other => panic!("expected Conflict, got `{other:?}`"),
        }

        // Nothing persisted: lifecycle still Ready, split intact.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
        assert_eq!(env.traffic_splits.len(), 1);
        assert!(env.bundles[0].current_revisions.contains(&rid));
    }

    #[test]
    fn archive_completes_a_drained_revision_through_inactive() {
        // Operator action: `drain` moved Ready → Draining; runtime
        // separately moved Draining → Inactive (simulated here via the
        // store). Archive walks Inactive → Archived in a single CLI call.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            RevisionLifecycle::Inactive,
        );
        let rid = revision.revision_id;
        env.bundles.push(deployment);
        env.revisions.push(revision);
        store.save(&env).unwrap();

        let outcome = archive(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("archived")
        );
    }

    #[test]
    fn list_reflects_stage_calls() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let revs = listed
            .result
            .get("revisions")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(revs.len(), 2);
        // Sequences 1 and 2.
        let seqs: Vec<u64> = revs
            .iter()
            .filter_map(|r| r.get("sequence").and_then(|v| v.as_u64()))
            .collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    // --- B9 warm-with-health-gate tests -----------------------------------

    /// `warm_with_health_gate` with a passing closure behaves exactly like
    /// the gate-less `warm`: revision lands `Ready`, runtime-config refresh
    /// runs, and the outcome envelope is the same shape.
    #[test]
    fn warm_with_passing_gate_lands_ready() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let warmed = warm_with_health_gate(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
                idempotency_key: None,
            }),
            |_env, _revision| Ok(()),
        )
        .unwrap();
        assert_eq!(
            warmed.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("ready")
        );
    }

    /// `warm_with_health_gate` with a failing closure surfaces a Conflict
    /// (from `OpError::From<LifecycleError>`) and persists the revision in
    /// `Failed`. The on-disk env reflects the failed warm so a follow-up
    /// `archive` / retry sees the real state.
    #[test]
    fn warm_with_failing_gate_persists_failed_and_returns_conflict() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid_str = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let err = warm_with_health_gate(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid_str.clone(),
                idempotency_key: None,
            }),
            |_env, _revision| {
                Err(crate::environment::HealthGateFailure {
                    failed_checks: vec![crate::environment::HealthCheckId::RuntimeConfig],
                    message: "runtime-config.json missing".to_string(),
                })
            },
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(msg.contains("warm/ready health gate"), "msg: {msg}");
        assert!(msg.contains("RuntimeConfig"), "msg: {msg}");

        // On-disk: revision is now Failed.
        let env_id = EnvId::try_from("local").unwrap();
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions.len(), 1);
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Failed);
    }

    /// Codex finding 2 regression: when the health gate flips a revision to
    /// `Failed` (state committed) AND the audit-append subsequently fails,
    /// the audit boundary must fail-closed and surface `OpError::Audit` —
    /// NOT downgrade to `tracing::warn!` (the old default for `Err`
    /// returns). We trigger an audit-append failure by placing a regular
    /// file at `<env_dir>/audit`, so `AuditLog::append`'s `create_dir_all`
    /// errors with NotADirectory.
    #[test]
    fn warm_failing_gate_with_audit_failure_returns_audit_error() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid_str = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Block audit appends: delete the existing events.jsonl (created by
        // the stage call above) and put a directory at that path instead, so
        // OpenOptions::open errors with IsADirectory.
        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();
        let events_path = env_dir.join("audit").join("events.jsonl");
        let _ = std::fs::remove_file(&events_path);
        std::fs::create_dir(&events_path).unwrap();

        let err = warm_with_health_gate(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid_str.clone(),
                idempotency_key: None,
            }),
            |_env, _revision| {
                Err(crate::environment::HealthGateFailure {
                    failed_checks: vec![crate::environment::HealthCheckId::RuntimeConfig],
                    message: "runtime-config.json missing".to_string(),
                })
            },
        )
        .unwrap_err();

        // Fail-closed: audit failure on a committed gate-fail must surface
        // as OpError::Audit, NOT the closure's original Conflict.
        match &err {
            OpError::Audit(_) => {}
            other => panic!("expected OpError::Audit (fail-closed); got `{other:?}`"),
        }

        // On-disk lifecycle is still Failed (the gate persisted before the
        // audit attempt).
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Failed);
    }

    /// Negative half of the Finding 2 regression: when a closure returns a
    /// NON-committed error (e.g. a NotFound from a typo'd revision_id) AND
    /// the audit append fails, the existing demote-to-warn behavior is
    /// preserved — the original error reaches the caller, not the audit
    /// error.
    #[test]
    fn warm_uncommitted_error_with_audit_failure_returns_original_error() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let _did = seed_env_with_deployment(&store);

        // Block the audit dir.
        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();
        std::fs::write(env_dir.join("audit"), b"audit-blocker").unwrap();

        // Reference a revision that doesn't exist → NotFound, nothing committed.
        let phantom_rid = ulid::Ulid::new().to_string();
        let err = warm(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: phantom_rid,
                idempotency_key: None,
            }),
        )
        .unwrap_err();

        // Original error preserved (audit failure demoted to warn).
        match &err {
            OpError::NotFound(_) => {}
            other => panic!("expected OpError::NotFound (audit demoted); got `{other:?}`"),
        }
    }

    /// Code-review regression: the `Ok` arm of `apply_revision_transition_
    /// with_health_gate` ALSO commits state (the lifecycle helper called
    /// `locked.save` before returning Ok), so subsequent failures inside
    /// the transact (load / refresh_runtime_config) are committed-on-error
    /// and must trigger fail-closed audit semantics.
    ///
    /// Scenario: passing gate advances Staged → Ready, lifecycle helper
    /// saves env.json (revision durably Ready), then
    /// `locked.refresh_runtime_config` fails because the `runtime-config
    /// .json` path is occupied by a directory; transact returns Err. If
    /// the audit append ALSO fails (events.jsonl blocked), the caller
    /// MUST see `OpError::Audit`, not the inner StoreError demoted to a
    /// warn.
    #[test]
    fn warm_ok_with_refresh_failure_and_audit_failure_returns_audit_error() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid_str = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();

        // Block `refresh_runtime_config` by occupying the runtime-config
        // path with a directory; both save_/delete_ paths fail with IO
        // errors when the target is a directory.
        std::fs::create_dir(env_dir.join("runtime-config.json")).unwrap();

        // Block audit append on the same env (same directory-as-file trick
        // used by the gate-fail audit test).
        let events_path = env_dir.join("audit").join("events.jsonl");
        let _ = std::fs::remove_file(&events_path);
        std::fs::create_dir(&events_path).unwrap();

        let err = warm_with_health_gate(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid_str,
                idempotency_key: None,
            }),
            |_env, _revision| Ok(()),
        )
        .unwrap_err();

        // Fail-closed: the lifecycle helper saved (revision is now Ready
        // on disk) and refresh failed; audit failure on a committed-on-
        // error path must surface as OpError::Audit, NOT the original
        // OpError::Store from the refresh failure.
        match &err {
            OpError::Audit(_) => {}
            other => panic!("expected OpError::Audit (fail-closed); got `{other:?}`"),
        }

        // The lifecycle save committed before the refresh failed: revision
        // is Ready on disk.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
    }

    /// PR-3a.6 Codex regression: the typed drain verb's lifecycle helper
    /// `locked.save`s before `run_revision_transition`'s post-save
    /// reload / runtime-config refresh runs. If refresh fails AND the
    /// audit append fails, the typed-verb-shaped caller (`typed_transition`)
    /// must still fail-closed — same contract as
    /// `warm_ok_with_refresh_failure_and_audit_failure_returns_audit_error`,
    /// just via the `StoreError::CommittedAfterSave` wrapper instead of
    /// the closure-based path's direct mark_committed.
    #[test]
    fn drain_ok_with_refresh_failure_and_audit_failure_returns_audit_error() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid_str = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Drain accepts only `Ready` as a start — flip the staged revision
        // directly instead of running the full warm dance (which isn't the
        // verb under test here).
        let env_id = EnvId::try_from("local").unwrap();
        let mut env = store.load(&env_id).unwrap();
        env.revisions[0].lifecycle = RevisionLifecycle::Ready;
        store.save(&env).unwrap();

        let env_dir = store.env_dir(&env_id).unwrap();

        // Block `refresh_runtime_config` AND `audit append` — same
        // directory-as-file trick used by the warm regression.
        let _ = std::fs::remove_file(env_dir.join("runtime-config.json"));
        std::fs::create_dir(env_dir.join("runtime-config.json")).unwrap();
        let events_path = env_dir.join("audit").join("events.jsonl");
        let _ = std::fs::remove_file(&events_path);
        std::fs::create_dir(&events_path).unwrap();

        let err = drain(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid_str,
                idempotency_key: None,
            }),
        )
        .unwrap_err();

        match &err {
            OpError::Audit(_) => {}
            other => panic!("expected OpError::Audit (fail-closed); got `{other:?}`"),
        }

        // The lifecycle save committed before refresh failed.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Draining);
    }

    // -------------------------------------------------------------------
    // C5.3 — end-to-end rollout-event capture
    //
    // Codex's review found that emitting in scaffolded greentic-start paths
    // produced silent live operator flows. These tests drive the LIVE CLI
    // verbs (`warm`, `drain`, `archive`) and capture the resulting
    // `rollout.*` events through a global `tracing_subscriber` layer
    // (`crate::rollout_telemetry::test_capture`), so the verb→event mapping
    // is regression-tested through the same code path operator HTTP routes
    // use today.
    //
    // The shared capture infra uses one process-global subscriber + a
    // per-thread `Vec` because `tracing::subscriber::with_default` has
    // callsite-interest-cache races under parallel test execution — see
    // the module doc on `test_capture` for the full rationale.
    // -------------------------------------------------------------------

    use crate::rollout_telemetry::test_capture::capture_events;
    use std::collections::BTreeSet;

    /// Convert a flat captured event list into a `BTreeSet` for assert-by-
    /// membership, matching the prior `RolloutCapture::observed()` shape.
    fn observed(events: &[String]) -> BTreeSet<String> {
        events.iter().cloned().collect()
    }

    /// Live `warm` CLI invocation must emit `rollout.health_gate.passed`
    /// and `rollout.revision.warmed` — Codex's "end-to-end warm test that
    /// asserts pass rollout events are observed" recommendation.
    #[test]
    fn warm_emits_health_gate_passed_and_revision_warmed() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let (result, events) = capture_events(|| {
            warm(
                &store,
                &OpFlags::default(),
                Some(RevisionTransitionPayload {
                    environment_id: "local".to_string(),
                    revision_id: rid,
                    idempotency_key: None,
                }),
            )
        });
        result.unwrap();
        let observed = observed(&events);
        assert!(
            observed.contains("rollout.health_gate.passed"),
            "observed events: {observed:?}"
        );
        assert!(
            observed.contains("rollout.revision.warmed"),
            "observed events: {observed:?}"
        );
        // No failure event on a happy-path warm.
        assert!(!observed.contains("rollout.health_gate.failed"));
    }

    /// Live `warm_with_health_gate` with a failing gate closure must emit
    /// `rollout.health_gate.failed` — Codex's "fail rollout events are
    /// observed" recommendation.
    #[test]
    fn warm_with_failing_gate_emits_health_gate_failed() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let (result, events) = capture_events(|| {
            warm_with_health_gate(
                &store,
                &OpFlags::default(),
                Some(RevisionTransitionPayload {
                    environment_id: "local".to_string(),
                    revision_id: rid,
                    idempotency_key: None,
                }),
                |_env, _revision| {
                    Err(crate::environment::HealthGateFailure {
                        failed_checks: vec![crate::environment::HealthCheckId::RuntimeConfig],
                        message: "synthetic gate failure".to_string(),
                    })
                },
            )
        });
        result.unwrap_err();
        let observed = observed(&events);
        assert!(
            observed.contains("rollout.health_gate.failed"),
            "observed events: {observed:?}"
        );
        // No passing event when the gate failed.
        assert!(!observed.contains("rollout.health_gate.passed"));
        assert!(!observed.contains("rollout.revision.warmed"));
    }

    /// Live `drain` CLI invocation must emit `rollout.revision.draining`.
    /// Drives the Ready → Draining transition through the same path the
    /// operator HTTP route uses.
    #[test]
    fn drain_emits_revision_draining() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        // Walk Staged → Warming → Ready so the drain matrix has a valid `from`.
        warm(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.clone(),
                idempotency_key: None,
            }),
        )
        .unwrap();

        let (result, events) = capture_events(|| {
            drain(
                &store,
                &OpFlags::default(),
                Some(RevisionTransitionPayload {
                    environment_id: "local".to_string(),
                    revision_id: rid,
                    idempotency_key: None,
                }),
            )
        });
        result.unwrap();
        let observed = observed(&events);
        assert!(
            observed.contains("rollout.revision.draining"),
            "observed events: {observed:?}"
        );
    }

    /// Live `archive` taking the Draining → Inactive chain must emit
    /// `rollout.revision.evicted`. Other archive chains (e.g. Ready →
    /// Archived) must NOT emit `evicted` — that's lifecycle retirement,
    /// not a rollout eviction.
    #[test]
    fn archive_emits_revision_evicted_on_draining_to_inactive() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        // Walk Staged → Warming → Ready → Draining so archive lands on the
        // Draining → Inactive chain (the post-drain eviction hop).
        warm(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.clone(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        drain(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.clone(),
                idempotency_key: None,
            }),
        )
        .unwrap();

        let (result, events) = capture_events(|| {
            archive(
                &store,
                &OpFlags::default(),
                Some(RevisionTransitionPayload {
                    environment_id: "local".to_string(),
                    revision_id: rid,
                    idempotency_key: None,
                }),
            )
        });
        result.unwrap();
        let observed = observed(&events);
        assert!(
            observed.contains("rollout.revision.evicted"),
            "observed events: {observed:?}"
        );
    }
}
