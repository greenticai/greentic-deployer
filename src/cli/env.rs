//! `gtc op env {create,update,list,show,doctor,destroy}` (`A3` of `plans/next-gen-deployment.md`).
//!
//! Commands operate directly on the [`EnvironmentStore`] from A2. Each
//! mutating call validates the payload before touching disk.

use chrono::Utc;
use greentic_deploy_spec::{
    CapabilitySlot, EnvId, Environment, EnvironmentHostConfig, RevisionId, validate_public_base_url,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{
    EnvironmentReads, EnvironmentStore, FieldUpdate, LocalFsStore, UpdateEnvironmentPayload,
};

use super::{
    AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record, map_store_err_preserving_noun,
};

const NOUN: &str = "env";

/// Payload accepted by `op env create` (and `op env update`).
///
/// Slot bindings (`packs`) and bundle/revision/traffic-split state are NOT
/// accepted here — those go through their own commands so the env CRUD
/// surface stays narrow. An env created this way starts with `packs = []`
/// and no bundles; subsequent `op env-packs add` and `op bundles add` calls
/// populate it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvCreatePayload {
    pub environment_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_org_id: Option<String>,
    /// Bind address for the runtime's local HTTP listener (parsed as
    /// `SocketAddr`). When omitted, the env is created with
    /// `host_config.listen_addr = None`, and the runtime falls back to
    /// `DEFAULT_LISTEN_ADDR` via `resolved_listen_addr()`. Set explicitly
    /// to lock the env to a non-default bind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,
    /// Persistent public base URL the runtime exposes (e.g. via a static
    /// tunnel or external load balancer). Validated on save: origin only —
    /// `https://host[:port]`, no path, query, or fragment. `None` leaves
    /// the env's URL unset, so the runtime falls back to a tunnel-discovered
    /// or `PUBLIC_BASE_URL` env-var value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
}

/// Returned by `op env create` / `op env update`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSummary {
    pub environment_id: String,
    pub name: String,
    pub region: Option<String>,
    pub tenant_org_id: Option<String>,
    /// Explicit bind address for the runtime's local HTTP listener.
    /// `None` means the env relies on `DEFAULT_LISTEN_ADDR`; surface the
    /// effective resolution via `op config show` (full host_config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<std::net::SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    pub pack_count: usize,
    pub bundle_count: usize,
    pub revision_count: usize,
}

impl From<&Environment> for EnvSummary {
    fn from(env: &Environment) -> Self {
        Self {
            environment_id: env.environment_id.as_str().to_string(),
            name: env.name.clone(),
            region: env.host_config.region.clone(),
            tenant_org_id: env.host_config.tenant_org_id.clone(),
            listen_addr: env.host_config.listen_addr,
            public_base_url: env.host_config.public_base_url.clone(),
            pack_count: env.packs.len(),
            bundle_count: env.bundles.len(),
            revision_count: env.revisions.len(),
        }
    }
}

/// `op env create`. Idempotent: if the env already exists, fails with
/// `OpError::Conflict` — callers wanting upsert semantics should use `update`.
pub fn create(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EnvCreatePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return schema_outcome("create");
    }
    let payload = resolve_payload::<EnvCreatePayload>(flags, payload)?;
    let env_id = EnvId::try_from(payload.environment_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))?;
    // Parse the bind address up front so a malformed value is rejected before
    // we touch the env store or the audit log. Same pattern as `op config set`.
    let parsed_listen_addr = payload
        .listen_addr
        .as_deref()
        .map(|raw| {
            raw.parse::<std::net::SocketAddr>().map_err(|e| {
                OpError::InvalidArgument(format!(
                    "listen_addr {raw:?} is not a valid socket address: {e}"
                ))
            })
        })
        .transpose()?;
    let parsed_public_base_url = parse_optional_public_base_url(&payload.public_base_url)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "create",
        target: json!({"environment_id": env_id.as_str()}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store
            .create_environment(
                &env_id,
                payload.name,
                EnvironmentHostConfig {
                    env_id: env_id.clone(),
                    region: payload.region,
                    tenant_org_id: payload.tenant_org_id,
                    listen_addr: parsed_listen_addr,
                    public_base_url: parsed_public_base_url,
                    gui_enabled: None,
                },
            )
            .map_err(map_store_err_preserving_noun)?;
        let outcome = OpOutcome::new(
            NOUN,
            "create",
            serde_json::to_value(EnvSummary::from(&env)).expect("EnvSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op env update`. Replaces `name`, `region`, and `tenant_org_id` on an
/// existing env. The `packs`/`bundles`/`revisions`/`traffic_splits` arrays
/// stay untouched — manage those via their own subcommands.
pub fn update(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EnvCreatePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return schema_outcome("update");
    }
    let payload = resolve_payload::<EnvCreatePayload>(flags, payload)?;
    let env_id = EnvId::try_from(payload.environment_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))?;
    let parsed_public_base_url = parse_optional_public_base_url(&payload.public_base_url)?;
    let mut fields = Vec::new();
    if payload.name != payload.environment_id {
        fields.push("name");
    }
    if payload.region.is_some() {
        fields.push("region");
    }
    if payload.tenant_org_id.is_some() {
        fields.push("tenant_org_id");
    }
    if parsed_public_base_url.is_some() {
        fields.push("public_base_url");
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "update",
        target: json!({"environment_id": env_id.as_str(), "fields": fields}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store
            .update_environment(
                &env_id,
                UpdateEnvironmentPayload {
                    name: Some(payload.name),
                    region: FieldUpdate::from_option(payload.region),
                    tenant_org_id: FieldUpdate::from_option(payload.tenant_org_id),
                    listen_addr: FieldUpdate::Keep,
                    public_base_url: FieldUpdate::from_option(parsed_public_base_url),
                    gui_enabled: FieldUpdate::Keep,
                },
            )
            .map_err(map_store_err_preserving_noun)?;
        let outcome = OpOutcome::new(
            NOUN,
            "update",
            serde_json::to_value(EnvSummary::from(&env)).expect("EnvSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op env list`.
pub fn list(store: &dyn EnvironmentReads, flags: &OpFlags) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        // `list` has no input; produce a null-input schema as a placeholder.
        return Ok(OpOutcome::new(
            NOUN,
            "list",
            json!({ "input_schema": "no input" }),
        ));
    }
    let mut summaries = Vec::new();
    for env_id in store.list_env_ids()? {
        let env = store.load_env(&env_id)?;
        summaries.push(EnvSummary::from(&env));
    }
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({ "environments": summaries }),
    ))
}

/// `op env show <env_id>`.
pub fn show(
    store: &dyn EnvironmentReads,
    flags: &OpFlags,
    env_id: &str,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "show",
            json!({ "input_schema": "env_id positional" }),
        ));
    }
    let env_id =
        EnvId::try_from(env_id).map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.env_exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load_env(&env_id)?;
    let runtime = store.read_runtime(&env_id)?;
    Ok(OpOutcome::new(
        NOUN,
        "show",
        json!({
            "environment": env,
            "runtime": runtime,
        }),
    ))
}

/// `op env doctor <env_id>`. Re-validates the env against `Environment::validate`
/// and checks for missing capability slots. Returns a structured report
/// instead of failing on the first issue.
pub fn doctor(store: &LocalFsStore, flags: &OpFlags, env_id: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "doctor",
            json!({ "input_schema": "env_id positional" }),
        ));
    }
    let env_id =
        EnvId::try_from(env_id).map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let runtime = store.load_runtime(&env_id)?;
    let validate_result = env.validate();
    let bound_slots: Vec<String> = env.packs.iter().map(|b| b.slot.to_string()).collect();
    // Only the core, 1-per-slot families (those bound in `packs`) have a
    // meaningful "missing" state. The N-per-env slots (`Messaging`,
    // `Extension`) live in their own open collections — absence is not a
    // misconfiguration — so they never appear here.
    let missing_slots: Vec<String> = greentic_deploy_spec::CapabilitySlot::ALL
        .iter()
        .copied()
        .filter(|s| s.binds_in_packs())
        .filter(|s| env.pack_for_slot(*s).is_none())
        .map(|s| s.to_string())
        .collect();
    // Resolve each binding's `kind` against the env-pack registry (A9): a
    // binding whose descriptor no native handler backs, or whose handler
    // serves a different slot, is a latent misconfiguration the operator
    // should see before deploy.
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();
    let mut unknown_kinds: Vec<String> = Vec::new();
    let mut slot_mismatches: Vec<Value> = Vec::new();
    let mut version_skew: Vec<Value> = Vec::new();
    for binding in &env.packs {
        match registry.resolve_for_slot(binding.slot, &binding.kind) {
            Ok(_) => {}
            Err(crate::env_packs::RegistryError::Unknown(kind)) => unknown_kinds.push(kind),
            Err(crate::env_packs::RegistryError::SlotMismatch {
                kind,
                expected,
                actual,
            }) => slot_mismatches.push(json!({
                "kind": kind,
                "bound_slot": expected.to_string(),
                "handler_slot": actual.to_string(),
            })),
            Err(crate::env_packs::RegistryError::VersionUnsupported {
                kind,
                requested,
                supported,
            }) => version_skew.push(json!({
                "kind": kind,
                "requested": requested,
                "supported": supported,
            })),
            // `resolve_for_slot` only produces the three variants above;
            // `DuplicateRegistration` and `DeployerMissingCredentials`
            // come solely from `register`.
            Err(
                err @ (crate::env_packs::RegistryError::DuplicateRegistration(_)
                | crate::env_packs::RegistryError::DeployerMissingCredentials { .. }),
            ) => {
                unreachable!("resolve_for_slot never returns {err:?}")
            }
        }
    }
    // Extension bindings (`Path 3`) resolve against the same registry, but as
    // an open N-per-env namespace they never contribute to `missing_slots`.
    // `resolve_for_slot(Extension, ..)` degrades the slot check to "is this a
    // registered extension"; a handler that serves a different slot (a core
    // pack mis-bound as an extension) surfaces as a slot mismatch. With no
    // extension handlers registered, every binding shows as an unknown kind —
    // the honest answer until Phase D plug-ins register real handlers.
    let mut extension_report = ExtensionDoctor::default();
    for ext in &env.extensions {
        match registry.resolve_for_slot(greentic_deploy_spec::CapabilitySlot::Extension, &ext.kind)
        {
            Ok(_) => {}
            Err(crate::env_packs::RegistryError::Unknown(kind)) => {
                extension_report.unknown_kinds.push(kind)
            }
            Err(crate::env_packs::RegistryError::SlotMismatch { kind, actual, .. }) => {
                extension_report.slot_mismatches.push(json!({
                    "kind": kind,
                    "handler_slot": actual.to_string(),
                }))
            }
            Err(crate::env_packs::RegistryError::VersionUnsupported {
                kind,
                requested,
                supported,
            }) => extension_report.version_skew.push(json!({
                "kind": kind,
                "requested": requested,
                "supported": supported,
            })),
            Err(
                err @ (crate::env_packs::RegistryError::DuplicateRegistration(_)
                | crate::env_packs::RegistryError::DeployerMissingCredentials { .. }),
            ) => {
                unreachable!("resolve_for_slot never returns {err:?}")
            }
        }
    }
    // Revisions that live traffic routes to but whose pinned pack list is not
    // on disk. These are why an env staged before greentic 1.1.0 refuses to
    // boot AT ALL — `greentic-start` quarantines the deployment and keeps
    // serving the rest, but the deployment itself is dead until repaired.
    let env_dir = store.env_dir(&env_id)?;
    let stale_revisions: Vec<Value> = crate::pack_ref::scan_stale_revisions(&env, &env_dir)
        .into_iter()
        .map(|s| {
            json!({
                "deployment_id": s.deployment_id.to_string(),
                "revision_id": s.revision_id.to_string(),
                "bundle_id": s.bundle_id.as_str(),
                "recorded_pack_list_lock_ref": s.recorded_ref.display().to_string(),
                "expected_path": s.expected_path.display().to_string(),
                "detail": "pinned pack list is missing; revision was staged before greentic 1.1.0 \
                           and can never serve",
                "fix": format!("gtc op env repair {env_id} --apply"),
            })
        })
        .collect();

    Ok(OpOutcome::new(
        NOUN,
        "doctor",
        json!({
            "environment_id": env.environment_id.as_str(),
            "validate": match &validate_result {
                Ok(()) => json!({"status": "ok"}),
                Err(e) => json!({"status": "error", "message": e.to_string()}),
            },
            "bound_slots": bound_slots,
            "missing_slots": missing_slots,
            "unknown_kinds": unknown_kinds,
            "slot_mismatches": slot_mismatches,
            "version_skew": version_skew,
            "extensions": {
                "count": env.extensions.len(),
                "unknown_kinds": extension_report.unknown_kinds,
                "slot_mismatches": extension_report.slot_mismatches,
                "version_skew": extension_report.version_skew,
            },
            "stale_revisions": stale_revisions,
            "has_runtime": runtime.is_some(),
            "checked_at": Utc::now(),
        }),
    ))
}

/// `op env repair <env_id> [--check | --apply]`.
///
/// Repairs an environment whose traffic splits route to revisions staged before
/// greentic 1.1.0. Those revisions recorded a `pack_list_lock_ref` that no file
/// ever backed (see [`crate::pack_ref`]); they cannot serve, and until 1.1.18
/// a single one of them made the whole env refuse to boot.
///
/// Repair evicts each stale revision from its traffic split and archives it. If
/// a split is left with healthy revisions, their weights are rebalanced back to
/// 10,000 bps; if it is left empty, the split is dropped entirely (the
/// deployment survives with no live routing, so re-deploying its bundle brings
/// it back). Nothing else is touched — bundles, secrets and messaging endpoints
/// are left alone.
///
/// `--check` reports without mutating; the default (neither flag) is also a
/// dry run, so an operator cannot destroy state by fat-fingering the verb.
pub fn repair(
    store: &LocalFsStore,
    flags: &OpFlags,
    env_id: &str,
    apply: bool,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "repair",
            json!({ "input_schema": "env_id positional; --check | --apply" }),
        ));
    }
    let env_id =
        EnvId::try_from(env_id).map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env_dir = store.env_dir(&env_id)?;

    if !apply {
        let env = store.load(&env_id)?;
        let stale = crate::pack_ref::scan_stale_revisions(&env, &env_dir);
        return Ok(OpOutcome::new(
            NOUN,
            "repair",
            json!({
                "environment_id": env_id.as_str(),
                "mode": "check",
                "stale_revisions": stale.iter().map(describe_stale).collect::<Vec<_>>(),
                "repaired": 0,
                "detail": if stale.is_empty() {
                    "no stale revisions; nothing to repair".to_string()
                } else {
                    format!("{} stale revision(s); re-run with --apply to repair", stale.len())
                },
            }),
        ));
    }

    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "repair",
        target: json!({ "environment_id": env_id.to_string() }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let result = store.transact(&env_id, |locked| -> Result<Value, OpError> {
            let mut env = locked.load().map_err(map_store_err_preserving_noun)?;
            let stale = crate::pack_ref::scan_stale_revisions(&env, &env_dir);
            if stale.is_empty() {
                return Ok(json!({
                    "environment_id": env_id.as_str(),
                    "mode": "apply",
                    "stale_revisions": [],
                    "repaired": 0,
                    "detail": "no stale revisions; nothing to repair",
                }));
            }
            let report: Vec<Value> = stale.iter().map(describe_stale).collect();
            let stale_ids: Vec<RevisionId> = stale.iter().map(|s| s.revision_id).collect();

            evict_revisions_from_traffic(&mut env, &stale_ids);

            // Archive the evicted revisions and drop them from their
            // deployment's `current_revisions`. The lifecycle guard refuses to
            // archive a revision that still owns live traffic — which is why
            // the eviction above has to come first.
            for revision in &mut env.revisions {
                if stale_ids.contains(&revision.revision_id) {
                    revision.lifecycle = greentic_deploy_spec::RevisionLifecycle::Archived;
                }
            }
            for deployment in &mut env.bundles {
                deployment
                    .current_revisions
                    .retain(|r| !stale_ids.contains(r));
            }

            locked.save(&env).map_err(map_store_err_preserving_noun)?;
            locked
                .refresh_runtime_config(&env)
                .map_err(map_store_err_preserving_noun)?;

            Ok(json!({
                "environment_id": env_id.as_str(),
                "mode": "apply",
                "stale_revisions": report,
                "repaired": stale_ids.len(),
                "detail": format!(
                    "archived {} stale revision(s) and rewrote the affected traffic split(s); \
                     re-deploy the bundle(s) to bring those deployments back",
                    stale_ids.len()
                ),
            }))
        })?;
        // Repair rewrites the env document wholesale rather than going through
        // a generation-stamped store mutation, so there is no previous/new
        // generation pair to report.
        Ok((
            OpOutcome::new(NOUN, "repair", result),
            super::AuditGens {
                previous: None,
                new: None,
            },
        ))
    })
}

fn describe_stale(s: &crate::pack_ref::StaleRevision) -> Value {
    json!({
        "deployment_id": s.deployment_id.to_string(),
        "revision_id": s.revision_id.to_string(),
        "bundle_id": s.bundle_id.as_str(),
        "recorded_pack_list_lock_ref": s.recorded_ref.display().to_string(),
        "expected_path": s.expected_path.display().to_string(),
    })
}

/// Remove `stale` revisions from every traffic split, rebalancing survivors back
/// to exactly 10,000 bps and dropping any split left with no entries.
///
/// The 10,000-bps sum is a hard invariant: `greentic-start` rejects a
/// deployment whose weights do not total exactly that. So a split that keeps
/// some healthy revisions must be renormalized, not merely shortened —
/// otherwise repair would trade a stale-ref failure for a weight-sum failure.
/// Remainder from integer division goes to the largest survivor, so the total is
/// exact for any entry count.
fn evict_revisions_from_traffic(env: &mut Environment, stale: &[RevisionId]) {
    const TOTAL_BPS: u32 = 10_000;
    for split in &mut env.traffic_splits {
        if !split.entries.iter().any(|e| stale.contains(&e.revision_id)) {
            continue;
        }
        split.entries.retain(|e| !stale.contains(&e.revision_id));
        split.generation = split.generation.saturating_add(1);

        let surviving_total: u32 = split.entries.iter().map(|e| e.weight_bps).sum();
        if split.entries.is_empty() || surviving_total == 0 {
            // Nothing healthy left (or every survivor had zero weight): the
            // deployment has no live routing. Clearing the entries drops the
            // split from the runtime-config projection entirely.
            split.entries.clear();
            continue;
        }
        // Renormalize proportionally, then hand the rounding remainder to the
        // heaviest entry so the sum is exactly TOTAL_BPS.
        let mut running = 0u32;
        let mut heaviest = 0usize;
        for i in 0..split.entries.len() {
            let scaled = (u64::from(split.entries[i].weight_bps) * u64::from(TOTAL_BPS)
                / u64::from(surviving_total)) as u32;
            split.entries[i].weight_bps = scaled;
            running += scaled;
            if split.entries[i].weight_bps > split.entries[heaviest].weight_bps {
                heaviest = i;
            }
        }
        split.entries[heaviest].weight_bps += TOTAL_BPS - running;
    }
    // A split with no entries is not a valid TrafficSplit (weights must sum to
    // 10,000), so drop it rather than persist an invalid document.
    env.traffic_splits.retain(|s| !s.entries.is_empty());
}

/// Aggregated registry-resolution issues for `Environment.extensions`, reported
/// under the `extensions` key in `doctor` output. Mirrors the per-`packs`
/// buckets but omits `missing_slots` (the extension namespace is open).
#[derive(Default)]
struct ExtensionDoctor {
    unknown_kinds: Vec<String>,
    slot_mismatches: Vec<Value>,
    version_skew: Vec<Value>,
}

/// `op env tool-check <env_id>`. Runs each binding's
/// [`crate::env_packs::EnvPackHandler::preflight`] and aggregates the
/// per-binding [`crate::tool_check::ToolCheck`] results into a structured
/// outcome.
///
/// Bindings whose `kind` is not registered (or whose version is rejected by
/// the env-pack registry) surface as `unresolved_bindings` so the operator
/// sees both shape errors and tool-preflight errors in one report. The
/// built-in `local` handlers return empty checks (in-process, no external
/// tools); handlers that shell out populate this from the named-tool catalog.
pub fn tool_check(
    store: &LocalFsStore,
    flags: &OpFlags,
    env_id: &str,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "tool-check",
            json!({ "input_schema": "env_id positional" }),
        ));
    }
    let env_id =
        EnvId::try_from(env_id).map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();
    let mut bindings: Vec<Value> = Vec::with_capacity(env.packs.len());
    let mut unresolved_bindings: Vec<Value> = Vec::new();
    let mut total_checks = 0usize;
    let mut failed_checks = 0usize;
    for binding in &env.packs {
        match registry.resolve_for_slot(binding.slot, &binding.kind) {
            Ok(handler) => {
                let checks = handler.preflight();
                total_checks += checks.len();
                failed_checks += checks.iter().filter(|c| !c.outcome.is_ok()).count();
                bindings.push(json!({
                    "slot": binding.slot.to_string(),
                    "kind": binding.kind.as_str(),
                    "checks": checks,
                }));
            }
            Err(e) => unresolved_bindings.push(json!({
                "slot": binding.slot.to_string(),
                "kind": binding.kind.as_str(),
                "error": e.to_string(),
            })),
        }
    }
    // Extension preflight: an extension handler's `preflight()` runs exactly as
    // a core handler's. Reported under their own keys so the operator sees core
    // and extension tool checks distinctly; both feed the totals.
    let mut extension_bindings: Vec<Value> = Vec::with_capacity(env.extensions.len());
    let mut extension_unresolved: Vec<Value> = Vec::new();
    for ext in &env.extensions {
        match registry.resolve_for_slot(greentic_deploy_spec::CapabilitySlot::Extension, &ext.kind)
        {
            Ok(handler) => {
                let checks = handler.preflight();
                total_checks += checks.len();
                failed_checks += checks.iter().filter(|c| !c.outcome.is_ok()).count();
                extension_bindings.push(json!({
                    "kind": ext.kind.as_str(),
                    "instance_id": ext.instance_id,
                    "checks": checks,
                }));
            }
            Err(e) => extension_unresolved.push(json!({
                "kind": ext.kind.as_str(),
                "instance_id": ext.instance_id,
                "error": e.to_string(),
            })),
        }
    }
    Ok(OpOutcome::new(
        NOUN,
        "tool-check",
        json!({
            "environment_id": env.environment_id.as_str(),
            "bindings": bindings,
            "unresolved_bindings": unresolved_bindings,
            "extension_bindings": extension_bindings,
            "extension_unresolved_bindings": extension_unresolved,
            "total_checks": total_checks,
            "failed_checks": failed_checks,
            "checked_at": Utc::now(),
        }),
    ))
}

/// `op env render <env_id> [--kind <descriptor>] [--output <dir>]` (plan §6
/// step 10). Renders the env's declarative desired state through the
/// deployer env-pack's
/// [`ManifestRenderer`](crate::env_packs::ManifestRenderer) without
/// applying anything — the artifact for direct-apply preview, GitOps
/// repository handoff, or rendered-manifest handoff.
///
/// When the env's Deployer-slot binding records wizard answers
/// (`answers_ref`), the renderer consumes them so operator overrides
/// (custom namespace, digest-pinned image, replica count) propagate into
/// the rendered manifests. When no answers are recorded, sandbox defaults
/// apply.
///
/// With `--output <dir>` each object is written as
/// `<NN>-<kind>-<name>.yaml` in apply order. The output directory is
/// render-managed for files matching the `<NN>-*.yaml` pattern (one or
/// more leading digits followed by `-`): stale managed files from
/// previous renders are removed so `kubectl apply -f <dir>` can never
/// resurrect an archived revision. Other files (e.g. `kustomization.yaml`)
/// are left untouched and reported in the outcome.
/// Without `--output` the manifests are embedded in the JSON outcome.
pub fn render(
    store: &LocalFsStore,
    registry: &crate::env_packs::EnvPackRegistry,
    flags: &OpFlags,
    args: super::dispatch::EnvRenderArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "render",
            json!({
                "input_schema": "env_id positional; --kind <path[@version]> optional \
                 (defaults to the env's deployer binding); --output <dir> optional"
            }),
        ));
    }
    let env_id = EnvId::try_from(args.env_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let descriptor = resolve_render_kind(&env, args.kind.as_deref())?;
    let handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;
    let renderer = handler.as_manifest_renderer().ok_or_else(|| {
        OpError::Conflict(format!(
            "env-pack kind `{}` does not support manifest rendering",
            descriptor.path()
        ))
    })?;

    // Load answers from the binding IFF the env's Deployer-slot binding
    // exists, its kind path matches the resolved descriptor, and
    // `answers_ref` is `Some`.
    let (answers, answers_ref_wire) = load_render_answers(store, &env, &descriptor)?;
    // The K8s renderer's worker secrets identity (dev-store Secret vs. Vault SA
    // + `VAULT_*` env) depends on the env's `Secrets`-slot binding, which the
    // registry handler doesn't carry — resolve it and render through a handler
    // that does. Other deployers ignore the secrets slot, so they keep the
    // registry handler.
    use crate::env_packs::render::ManifestRenderer as _;
    let objects = if descriptor.path() == crate::env_packs::k8s::K8sDeployerHandler::DESCRIPTOR_PATH
    {
        let secrets_backend = resolve_secrets_backend(store, &env)?;
        crate::env_packs::k8s::K8sDeployerHandler::default()
            .with_secrets_backend(secrets_backend)
            .render_environment(&env, answers.as_ref())
            .map_err(|e| OpError::Conflict(e.to_string()))?
    } else {
        renderer
            .render_environment(&env, answers.as_ref())
            .map_err(|e| OpError::Conflict(e.to_string()))?
    };

    let mut result = json!({
        "environment_id": env.environment_id.as_str(),
        "kind": descriptor.as_str(),
        "object_count": objects.len(),
        "answers_ref": answers_ref_wire,
    });
    match args.output {
        Some(dir) => {
            let write_result = write_rendered_objects(&dir, &objects)?;
            result["output_dir"] = json!(dir);
            result["files"] = json!(write_result.files);
            result["removed_stale_files"] = json!(write_result.removed_stale_files);
            result["unmanaged_files"] = json!(write_result.unmanaged_files);
        }
        None => result["manifests"] = Value::Array(objects),
    }
    Ok(OpOutcome::new(NOUN, "render", result))
}

/// `op env reconcile <env_id> [--kind <descriptor>]` — apply the env's
/// declarative desired state to its live cluster and prune the workers of
/// revisions no longer present. The apply-side counterpart of `render` (use
/// `render` for a no-side-effect preview, or a GitOps repository handoff).
///
/// K8s deployer env-pack only today: applying rendered manifests to a cluster
/// is K8s-specific, so other deployer kinds surface a `Conflict` (the AWS-ECS
/// reconcile path is a later Phase D slice). The same `answers_ref` /
/// `--kind` resolution as `render` applies.
///
/// The deployer connects through the binding's `kubeconfig_context` answer
/// and authenticates with the ambient kubeconfig / in-cluster identity today;
/// resolving the env's rotated ServiceAccount token (`credentials_ref` →
/// bearer) rides the Phase D secrets sink.
pub fn reconcile(
    store: &LocalFsStore,
    registry: &crate::env_packs::EnvPackRegistry,
    flags: &OpFlags,
    args: super::dispatch::EnvReconcileArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "reconcile",
            json!({
                "input_schema": "env_id positional; --kind <path[@version]> optional \
                 (defaults to the env's deployer binding)"
            }),
        ));
    }
    let env_id = EnvId::try_from(args.env_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let descriptor = resolve_live_deployer_kind(&env, args.kind.as_deref())?;

    // Reconcile applies rendered manifests to a live cluster — K8s-specific.
    let k8s_path = crate::env_packs::k8s::K8sDeployerHandler::DESCRIPTOR_PATH;
    if descriptor.path() != k8s_path {
        return Err(OpError::Conflict(format!(
            "env reconcile is only supported for the `{k8s_path}` deployer env-pack \
             today; `{}` cannot be reconciled to a live cluster (the AWS-ECS reconcile \
             path is a later Phase D slice)",
            descriptor.path()
        )));
    }
    // Parity with render: confirm the kind is actually registered.
    let _handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;

    let (answers, answers_ref_wire) = load_render_answers(store, &env, &descriptor)?;
    // Resolve the env's bound deployer credential to a ServiceAccount bearer
    // token; `None` → connect with the ambient kubeconfig / in-cluster
    // identity (the pre-closure behaviour). Fail-closed if a ref is bound but
    // unresolvable. Beyond env-var / dev-store, this also reads the durable
    // in-cluster identity Secret (ambient) so a fresh operator machine
    // resolves a `--bind` credential it never wrote locally.
    let bound_token =
        crate::env_packs::k8s::resolve_bound_identity(store, &env, &env_id, answers.as_ref())?;
    let identity = if bound_token.is_some() {
        "bound"
    } else {
        "ambient"
    };
    // Capture the env's local dev-store so reconcile delivers the operator's
    // secrets to the worker (the K8s "no runtime secrets" gap). `None` when the
    // env has no dev-store file yet — the worker's staging init is then a no-op.
    let dev_secrets = read_dev_secrets_b64(store, &env_id)?;
    // Resolve the env's `Secrets`-slot binding into the backend the worker
    // resolves `secret://` refs against — dev-store (values shipped in via the
    // Secret above) or Vault (pod identity + `VAULT_*` env, no values shipped).
    let secrets_backend = resolve_secrets_backend(store, &env)?;
    let report = reconcile_k8s_cluster(
        &env,
        answers.as_ref(),
        bound_token,
        dev_secrets,
        secrets_backend,
        false,
    )?;

    Ok(OpOutcome::new(
        NOUN,
        "reconcile",
        json!({
            "environment_id": env.environment_id.as_str(),
            "kind": descriptor.as_str(),
            "answers_ref": answers_ref_wire,
            // Identity the cluster was mutated as: "bound" = the env's
            // credentials_ref resolved to a ServiceAccount bearer; "ambient" =
            // the CLI's kubeconfig / in-cluster identity (no bound credential).
            // Surfaced so a live mutation is never silent about which identity
            // it ran as.
            "identity": identity,
            "applied_count": report.applied.len(),
            "pruned_count": report.pruned.len(),
            "applied": report.applied,
            "pruned": report.pruned,
        }),
    ))
}

/// Connect to the cluster (binding's `kubeconfig_context`, with `bound_token`
/// overriding the ambient identity when the env has a resolved credential) and
/// converge desired state. Requires the `k8s-client` feature.
#[cfg(feature = "k8s-client")]
pub(crate) fn reconcile_k8s_cluster(
    env: &Environment,
    answers: Option<&Value>,
    bound_token: Option<String>,
    dev_secrets: Option<String>,
    secrets_backend: crate::env_packs::k8s::manifests::SecretsBackend,
    wait_for_rollout: bool,
) -> Result<crate::env_packs::k8s::ReconcileReport, OpError> {
    use crate::env_packs::k8s::async_bridge::run_k8s_async;
    use crate::env_packs::k8s::kube_client::connect;
    use crate::env_packs::k8s::manifests::kubeconfig_context_from_answers;
    use crate::env_packs::k8s::{K8sDeployerHandler, KubeCluster};
    use std::sync::Arc;

    let kubeconfig_context = kubeconfig_context_from_answers(answers);
    // A bound (namespace-scoped) identity must not apply the cluster-scoped
    // Namespace — `bootstrap --bind` already created it, and the bound Role
    // grants no cluster-scoped verbs. The ambient kubeconfig / in-cluster
    // identity (`None`) keeps managing the Namespace, so reconcile still
    // bootstraps a fresh env unchanged.
    let manage_namespace = bound_token.is_none();
    run_k8s_async(async move {
        // `bound_token`: the env's credentials_ref resolved to a ServiceAccount
        // bearer (overrides the context's auth); `None` → the ambient
        // kubeconfig / in-cluster identity.
        let client = connect(kubeconfig_context.as_deref(), bound_token.as_deref())
            .await
            .map_err(|e| OpError::Conflict(format!("cannot reach the cluster: {e}")))?;
        let handler = K8sDeployerHandler::with_cluster_and_dev_secrets(
            Arc::new(KubeCluster::new(client)),
            dev_secrets,
        )
        .with_secrets_backend(secrets_backend);
        handler
            .reconcile_and_wait(env, answers, manage_namespace, wait_for_rollout)
            .await
            .map_err(|e| OpError::Conflict(e.to_string()))
    })
}

/// `k8s-client`-less builds cannot talk to a cluster.
#[cfg(not(feature = "k8s-client"))]
pub(crate) fn reconcile_k8s_cluster(
    _env: &Environment,
    _answers: Option<&Value>,
    _bound_token: Option<String>,
    _dev_secrets: Option<String>,
    _secrets_backend: crate::env_packs::k8s::manifests::SecretsBackend,
    _wait_for_rollout: bool,
) -> Result<crate::env_packs::k8s::ReconcileReport, OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `k8s-client` feature; \
         `op env reconcile` needs it to connect to a cluster"
            .to_string(),
    ))
}

/// Read the env's local dev-store and base64-encode it for the reconcile-time
/// dev-store Secret. `Ok(None)` when no dev-store file exists yet (the worker's
/// staging init is then a guarded no-op). A read error other than not-found is
/// surfaced — a present-but-unreadable store should fail the reconcile rather
/// than silently ship an empty Secret.
pub(crate) fn read_dev_secrets_b64(
    store: &LocalFsStore,
    env_id: &EnvId,
) -> Result<Option<String>, OpError> {
    use base64::Engine as _;
    Ok(read_dev_secrets_bytes(store, env_id)?
        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)))
}

use crate::credentials::store_paths::BOUND_CREDENTIAL_STORE_PATHS;

/// Store URIs in the env dev-store that are control-plane material and must
/// NEVER be staged into a runtime seed — the bound deployer credential. A
/// dev-store-backed env persists that credential in the same `.dev.secrets.env`
/// the seed is built from (`put_credential_material` writes it at exactly this
/// URI), so a workload holding the shared dev master key could otherwise decrypt
/// the credential that deployed it.
///
/// The denylist is the union of two sources, and needs both:
///
/// * **`credentials_ref`** — covers a credential bound at a custom URI.
/// * **`BOUND_CREDENTIAL_STORE_PATHS`, unconditionally** — covers the *orphan* a
///   crashed bootstrap leaves behind, which `credentials_ref` by definition does
///   not name. This is the seed-time half of the invariant in
///   [`credentials::store_paths`](crate::credentials::store_paths); see that
///   module doc for why the window exists and why the list is unconditional.
///   No record of what was written is needed: the minting handlers derive their
///   ref from those very constants, so the landing URI is deterministic per env.
///
/// Fail-open on a non-store-alignable `credentials_ref` is safe, not a leak: the
/// credential can only be present in the dev-store if its ref *is*
/// store-alignable (that is what lets `put_credential_material` write it), so an
/// un-alignable ref provably points somewhere else (e.g. Vault) and there is
/// nothing in this file to strip.
fn staging_excluded_uris(env: &Environment) -> Vec<String> {
    use greentic_deploy_spec::SecretRef;

    let mut uris: Vec<String> = BOUND_CREDENTIAL_STORE_PATHS
        .iter()
        .filter_map(|path| {
            SecretRef::try_new(format!("secret://{}/{path}", env.environment_id.as_str())).ok()
        })
        .filter_map(|bound| super::secrets::secret_ref_to_store_uri(&bound).ok())
        .collect();
    if let Some(cred) = env
        .credentials_ref
        .as_ref()
        .and_then(|cred| super::secrets::secret_ref_to_store_uri(cred).ok())
        && !uris.contains(&cred)
    {
        uris.push(cred);
    }
    uris
}

/// Read the env's local dev-store as raw bytes (the encrypted `.dev.secrets.env`
/// file) for staging into a runtime seed. `Ok(None)` when no dev-store file
/// exists yet; a present-but-unreadable store is surfaced rather than silently
/// shipping nothing. The Cloud Run deploy stages these bytes verbatim as a
/// Secret Manager version, so it needs the raw file, not the k8s path's
/// base64-in-a-K8s-Secret.
///
/// Any control-plane material (`staging_excluded_uris`) is hard-excluded from
/// the returned bytes via a filtered copy, so the staged seed cannot resolve the
/// bound deployer credential even with the shared dev master key. The operator's
/// on-disk store is never modified.
///
/// **Concurrency.** The exclusion is derived from a fresh env load and the
/// dev-store is snapshotted inside a single `store.transact` critical section,
/// under the same per-env flock the credential writer holds. A bootstrap /
/// rotation persists the dev-store credential and then `credentials_ref` under
/// that flock (see `credentials::bootstrap`), so serializing here guarantees the
/// exclusion is consistent with the bytes read: if the snapshot contains the
/// credential, the reloaded env already names it and it is stripped. Reloading
/// the authoritative env — rather than trusting the caller's possibly-stale
/// snapshot — is what closes the stale-state window, so this takes `env_id`, not
/// an `&Environment`. MUST NOT be called from within an open `transact` for the
/// same env (the flock is not re-entrant); all current callers pass an unlocked
/// env.
pub(crate) fn read_dev_secrets_bytes(
    store: &LocalFsStore,
    env_id: &EnvId,
) -> Result<Option<Vec<u8>>, OpError> {
    let env_dir = store
        .env_dir(env_id)
        .map_err(|e| OpError::Conflict(format!("resolving env dir: {e}")))?;
    let src = super::secrets::resolve_dev_store_path(&env_dir, None);

    store.transact(env_id, |locked| -> Result<Option<Vec<u8>>, OpError> {
        let env = locked
            .load()
            .map_err(|e| OpError::Conflict(format!("reloading env for staging: {e}")))?;
        let exclude = staging_excluded_uris(&env);

        // A dev-store file may not exist yet — guarded no-op (a missing file
        // stages nothing; the worker's staging init is then a no-op).
        if !src.exists() {
            return Ok(None);
        }

        // Always stage through a filtered copy — even with nothing to exclude —
        // so the read takes the DevStore advisory lock and never observes a
        // torn write, and so the deployer credential (H3) is hard-excluded: the
        // workload still receives every runtime secret, but no residual
        // ciphertext for the credential survives in the staged bytes. The
        // operator's on-disk store is never modified.
        let staged_dir = tempfile::tempdir()
            .map_err(|e| OpError::Conflict(format!("staging dev-store copy: {e}")))?;
        let staged = staged_dir.path().join(".dev.secrets.env");
        let exclude_refs: Vec<&str> = exclude.iter().map(String::as_str).collect();
        greentic_secrets_lib::DevStore::copy_excluding(&src, &staged, &exclude_refs).map_err(
            |e| {
                OpError::Conflict(format!(
                    "staging dev-store (excluding control-plane material): {e}"
                ))
            },
        )?;
        std::fs::read(&staged).map(Some).map_err(|e| {
            OpError::Conflict(format!(
                "reading staged dev-store at {}: {e}",
                staged.display()
            ))
        })
    })
}

/// `op env apply-revision <env_id> <revision_id> [--kind <descriptor>]` — bring
/// a SINGLE revision's worker resources into agreement with its recorded
/// lifecycle. A revision with cluster presence (Warming / Ready / Draining)
/// has its worker Deployment + Service applied; an absent one (Staged / Failed
/// / Archived / Inactive) has them torn down. The surgical counterpart of
/// `reconcile`, which converges the WHOLE env — `apply-revision` assumes the
/// env-level set (namespace, router) already exists (establish it with
/// `reconcile`), so it only touches the one revision's worker pair.
///
/// K8s deployer env-pack only today (same gate as `reconcile`). Connects
/// through the binding's `kubeconfig_context` answer with the ambient
/// kubeconfig / in-cluster identity; resolving the env's bound ServiceAccount
/// token rides the Phase D secrets sink.
///
/// # Known gaps (Phase D later slices)
///
/// - **Answer / namespace drift.** Both branches render the worker objects from
///   the binding's *current* answers, so the teardown targets the namespace the
///   answers name *now*. If a revision was warmed in namespace A and the binding
///   namespace later changes to B, the archive branch deletes B's worker (a
///   no-op) and reports success, leaving A's worker running — the same drift
///   `reconcile`'s prune already has. A drift-safe teardown needs the
///   per-revision applied-param snapshot or the label-based GC seam
///   (`K8sCluster::list`) tracked with `reconcile`'s prune-scope gap; until then
///   the binding namespace must stay stable while a revision is live (the
///   wizard already states the namespace must match the bootstrap rules pack).
pub fn apply_revision(
    store: &LocalFsStore,
    registry: &crate::env_packs::EnvPackRegistry,
    flags: &OpFlags,
    args: super::dispatch::EnvApplyRevisionArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "apply-revision",
            json!({
                "input_schema": "env_id + revision_id positional; --kind <path[@version]> optional \
                 (defaults to the env's deployer binding)"
            }),
        ));
    }
    let env_id = EnvId::try_from(args.env_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;

    let descriptor = resolve_live_deployer_kind(&env, args.kind.as_deref())?;

    // Confirm the kind is actually registered (parity with reconcile).
    let _handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;

    // Applicability gate, BEFORE the per-revision lookup so an unsupported
    // deployer kind rejects regardless of the revision arg: K8s (applies
    // manifests to a cluster) and AWS-ECS (drives task sets) have live apply
    // paths; any other registered deployer (e.g. local-process) does not.
    let k8s_path = crate::env_packs::k8s::K8sDeployerHandler::DESCRIPTOR_PATH;
    let is_k8s = descriptor.path() == k8s_path;
    if !is_k8s && !is_aws_ecs_kind(&descriptor) && !is_cloudrun_kind(&descriptor) {
        return Err(unsupported_apply_kind(&descriptor));
    }

    let revision_id = {
        use std::str::FromStr;
        let ulid = ulid::Ulid::from_str(&args.revision_id)
            .map_err(|e| OpError::InvalidArgument(format!("revision_id: {e}")))?;
        RevisionId(ulid)
    };
    let revision = env
        .revisions
        .iter()
        .find(|r| r.revision_id == revision_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "revision `{revision_id}` not found in env `{env_id}`"
            ))
        })?;

    let (answers, answers_ref_wire) = load_render_answers(store, &env, &descriptor)?;

    // Present → apply the worker resources (warm); absent → tear them down
    // (archive). Same B7 two-state presence model the renderer and reconcile
    // use; the lifecycle→presence predicate is backend-agnostic.
    let present = crate::env_packs::k8s::manifests::has_cluster_presence(revision.lifecycle);
    let action = if present { "warmed" } else { "archived" };
    let lifecycle = revision.lifecycle;

    // Backend dispatch: connect as the bound identity (fail-closed when a ref is
    // bound but unresolvable, never a silent ambient fall-back) and drive the
    // single revision's verb. Returns the identity used + the live resource name
    // (K8s worker Deployment / ECS service / Cloud Run service) for the outcome.
    // The applicability gate above guarantees the `else` arm is AWS-ECS or Cloud
    // Run; `apply_revision_non_k8s` dispatches between them.
    let (identity, worker_name, endpoint_url): (&'static str, String, Option<String>) = if is_k8s {
        let worker_name = crate::env_packs::k8s::manifests::worker_name(revision);
        let bound_token =
            crate::env_packs::k8s::resolve_bound_identity(store, &env, &env_id, answers.as_ref())?;
        let identity = if bound_token.is_some() {
            "bound"
        } else {
            "ambient"
        };
        // Resolve the env's Secrets backend so a Vault env's single-revision
        // warm renders the worker with its Vault identity + `VAULT_*` env, not a
        // default DevStore worker (parity with `reconcile` / `op env render`).
        let secrets_backend = resolve_secrets_backend(store, &env)?;
        apply_revision_k8s_cluster(
            &env,
            revision_id,
            present,
            answers.as_ref(),
            bound_token,
            secrets_backend,
        )?;
        (identity, worker_name, None)
    } else {
        apply_revision_non_k8s(
            store,
            &env,
            &env_id,
            revision_id,
            present,
            answers.as_ref(),
            &descriptor,
        )?
    };

    let mut result = json!({
        "environment_id": env.environment_id.as_str(),
        "kind": descriptor.as_str(),
        "revision_id": revision_id.to_string(),
        "lifecycle": lifecycle,
        // Which Deployer verb the recorded lifecycle drove.
        "action": action,
        "worker_name": worker_name,
        "answers_ref": answers_ref_wire,
        // Identity the cluster was mutated as — see `reconcile`.
        "identity": identity,
    });
    // Cloud Run discovers a live `*.run.app` URL for the Service and returns it
    // here (the "one command → live URL" milestone). The K8s / AWS-ECS paths
    // have no deployer-discovered endpoint (operator-supplied ingress / ALB), so
    // surface the field only when present — their outcomes stay byte-identical.
    if let Some(url) = endpoint_url {
        result["endpoint_url"] = json!(url);
    }
    Ok(OpOutcome::new(NOUN, "apply-revision", result))
}

/// Connect to the cluster and dispatch the single revision's Deployer verb:
/// `warm_revision` when present, `archive_revision` when absent. Requires the
/// `k8s-client` feature.
#[cfg(feature = "k8s-client")]
fn apply_revision_k8s_cluster(
    env: &Environment,
    revision_id: RevisionId,
    present: bool,
    answers: Option<&Value>,
    bound_token: Option<String>,
    secrets_backend: crate::env_packs::k8s::manifests::SecretsBackend,
) -> Result<(), OpError> {
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::k8s::async_bridge::run_k8s_async;
    use crate::env_packs::k8s::kube_client::connect;
    use crate::env_packs::k8s::manifests::kubeconfig_context_from_answers;
    use crate::env_packs::k8s::{K8sDeployerHandler, KubeCluster};
    use std::sync::Arc;

    let kubeconfig_context = kubeconfig_context_from_answers(answers);
    run_k8s_async(async move {
        // `bound_token`: resolved ServiceAccount bearer (overrides the
        // context's auth); `None` → ambient identity (same as reconcile).
        let client = connect(kubeconfig_context.as_deref(), bound_token.as_deref())
            .await
            .map_err(|e| OpError::Conflict(format!("cannot reach the cluster: {e}")))?;
        let handler = K8sDeployerHandler::with_cluster(Arc::new(KubeCluster::new(client)))
            .with_secrets_backend(secrets_backend);
        let result = if present {
            handler
                .warm_revision(env, revision_id, answers)
                .await
                .map(|_| ())
        } else {
            handler
                .archive_revision(env, revision_id, answers)
                .await
                .map(|_| ())
        };
        result.map_err(|e| OpError::Conflict(e.to_string()))
    })
}

/// `k8s-client`-less builds cannot talk to a cluster.
#[cfg(not(feature = "k8s-client"))]
fn apply_revision_k8s_cluster(
    _env: &Environment,
    _revision_id: RevisionId,
    _present: bool,
    _answers: Option<&Value>,
    _bound_token: Option<String>,
    _secrets_backend: crate::env_packs::k8s::manifests::SecretsBackend,
) -> Result<(), OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `k8s-client` feature; \
         `op env apply-revision` needs it to connect to a cluster"
            .to_string(),
    ))
}

/// True when the descriptor is the AWS-ECS deployer kind. `false` on builds
/// without the AWS env-pack compiled in (`creds-aws` off) — the kind cannot be
/// served, so the applicability gate rejects it.
#[cfg(feature = "creds-aws")]
fn is_aws_ecs_kind(descriptor: &greentic_deploy_spec::PackDescriptor) -> bool {
    descriptor.path() == crate::env_packs::aws::AwsEcsDeployerHandler::DESCRIPTOR_PATH
}

#[cfg(not(feature = "creds-aws"))]
fn is_aws_ecs_kind(_descriptor: &greentic_deploy_spec::PackDescriptor) -> bool {
    false
}

/// True when the descriptor is the GCP Cloud Run deployer kind. `false` on
/// builds without the GCP env-pack compiled in (`creds-gcp` off) — the kind
/// cannot be served, so the applicability gate rejects it. Mirrors
/// [`is_aws_ecs_kind`].
#[cfg(feature = "creds-gcp")]
pub(crate) fn is_cloudrun_kind(descriptor: &greentic_deploy_spec::PackDescriptor) -> bool {
    descriptor.path() == crate::env_packs::gcp_cloudrun::GcpCloudRunDeployerHandler::DESCRIPTOR_PATH
}

#[cfg(not(feature = "creds-gcp"))]
pub(crate) fn is_cloudrun_kind(_descriptor: &greentic_deploy_spec::PackDescriptor) -> bool {
    false
}

/// Conflict for a deployer kind with no live single-revision apply path
/// (anything other than K8s / AWS-ECS / Cloud Run — e.g. the local-process
/// deployer, which runs in-process and has nothing to apply to a remote target).
fn unsupported_apply_kind(descriptor: &greentic_deploy_spec::PackDescriptor) -> OpError {
    OpError::Conflict(format!(
        "env apply-revision is only supported for the `{}` (K8s), \
         `greentic.deployer.aws-ecs` (AWS-ECS), and `greentic.deployer.gcp-cloudrun` \
         (Cloud Run) deployer env-packs today; `{}` has no live single-revision apply path",
        crate::env_packs::k8s::K8sDeployerHandler::DESCRIPTOR_PATH,
        descriptor.path()
    ))
}

/// Dispatch `apply-revision` for a non-K8s deployer. Today the AWS-ECS and GCP
/// Cloud Run env-packs have live deploy paths; every other registered kind is
/// rejected. Returns `(identity, worker_name, endpoint_url)` — the analogue of
/// the K8s `(bound|ambient, worker Deployment name)`, plus the live endpoint URL
/// when the backend discovers one (Cloud Run's `*.run.app`; `None` for AWS-ECS).
#[cfg(any(feature = "creds-aws", feature = "creds-gcp"))]
#[allow(clippy::too_many_arguments)]
fn apply_revision_non_k8s(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    revision_id: RevisionId,
    present: bool,
    answers: Option<&Value>,
    descriptor: &greentic_deploy_spec::PackDescriptor,
) -> Result<(&'static str, String, Option<String>), OpError> {
    #[cfg(feature = "creds-aws")]
    {
        if is_aws_ecs_kind(descriptor) {
            return apply_revision_aws_ecs(store, env, env_id, revision_id, present, answers);
        }
    }
    #[cfg(feature = "creds-gcp")]
    {
        if is_cloudrun_kind(descriptor) {
            return apply_revision_cloudrun(store, env, env_id, revision_id, present, answers);
        }
    }
    Err(unsupported_apply_kind(descriptor))
}

#[cfg(not(any(feature = "creds-aws", feature = "creds-gcp")))]
#[allow(clippy::too_many_arguments)]
fn apply_revision_non_k8s(
    _store: &LocalFsStore,
    _env: &Environment,
    _env_id: &EnvId,
    _revision_id: RevisionId,
    _present: bool,
    _answers: Option<&Value>,
    descriptor: &greentic_deploy_spec::PackDescriptor,
) -> Result<(&'static str, String, Option<String>), OpError> {
    Err(unsupported_apply_kind(descriptor))
}

/// Fail-closed identity guard: a binding that pins a deployer role to assume
/// (`assume_role_arn`) MUST have a bound session, else the live call would
/// silently run as the ambient AWS identity — a tenant/account-isolation
/// footgun (the role was configured but never assumed, i.e. `op env bootstrap
/// --bind` was not run). `true` ⇒ refuse. (`aws_profile` honoring at deploy
/// time is a separate, still-deferred SDK client-builder slice — the binding
/// parser validates it but the verbs do not consume it yet.)
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn pinned_role_without_session(assume_role_arn: Option<&str>, session_present: bool) -> bool {
    assume_role_arn.is_some() && !session_present
}

/// Resolve the bound deployer session, parse the AWS-ECS construction inputs,
/// and enforce the fail-closed preconditions. Returns
/// `(identity_label, session, launch, region, target_group_pool)` — everything
/// `RealEcsTarget::resolve` needs plus the outcome's identity label. Shared by
/// `apply-revision` and `apply-traffic` so both honor the same guards.
///
/// Fails closed (before any AWS call) when the binding pins `assume_role_arn`
/// but no session is bound (`pinned_role_without_session`), and when the Fargate
/// launch config is absent.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[allow(clippy::type_complexity)]
fn aws_ecs_target_inputs(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
) -> Result<
    (
        &'static str,
        Option<crate::env_packs::aws::credentials::AssumedSession>,
        crate::env_packs::aws::real_target::FargateLaunchConfig,
        String,
        Vec<String>,
    ),
    OpError,
> {
    use crate::env_packs::aws::deployer::AwsEcsParams;

    // Bound STS session when the env declares one, else the ambient chain
    // (fail-closed if a ref is bound but unreadable). AWS analogue of the K8s
    // bound-ServiceAccount bearer.
    let session = crate::env_packs::aws::bound_session::resolve_bound_session(store, env, env_id)?;
    let identity = if session.is_some() {
        "bound"
    } else {
        "ambient"
    };
    let params = AwsEcsParams::from_answers(env, answers)
        .map_err(|e| OpError::Conflict(format!("invalid aws-ecs binding answers: {e}")))?;
    if pinned_role_without_session(params.assume_role_arn.as_deref(), session.is_some()) {
        return Err(OpError::Conflict(
            "the aws-ecs binding pins `assume_role_arn` (a deployer role to assume) but no bound \
             deployer session was found — refusing to run as the ambient AWS identity. Mint the \
             scoped session first with `op env bootstrap --bind` (or `op credentials rotate`)."
                .to_string(),
        ));
    }
    let launch = params.launch.ok_or_else(|| {
        OpError::Conflict(
            "the aws-ecs deployer binding has no Fargate launch config (needs execution_role_arn \
             + subnets + security_groups); re-run the binding wizard before applying"
                .to_string(),
        )
    })?;
    Ok((
        identity,
        session,
        launch,
        params.region,
        params.target_group_pool,
    ))
}

/// Resolve the region-pinned AWS clients (with the bound session injected) and
/// wrap them in a handler. Shared by the AWS verb dispatchers so the
/// resolve + `with_target` boilerplate (and its error message) lives once.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
async fn resolve_ecs_handler(
    region: &str,
    launch: crate::env_packs::aws::real_target::FargateLaunchConfig,
    pool: Vec<String>,
    session: Option<crate::env_packs::aws::credentials::AssumedSession>,
) -> Result<crate::env_packs::aws::AwsEcsDeployerHandler, OpError> {
    use crate::env_packs::aws::AwsEcsDeployerHandler;
    use crate::env_packs::aws::real_target::RealEcsTarget;
    use std::sync::Arc;

    let target = RealEcsTarget::resolve(region, launch, pool, session)
        .await
        .map_err(|e| {
            OpError::Conflict(format!(
                "cannot initialize the AWS ECS deployer client: {e}"
            ))
        })?;
    Ok(AwsEcsDeployerHandler::with_target(Arc::new(target)))
}

/// Connect to AWS and drive the single revision's ECS verb: `warm_revision`
/// when present, `archive_revision` when absent (mirrors
/// `apply_revision_k8s_cluster`). Returns `(identity, ECS service name, None)` —
/// AWS-ECS has no deployer-discovered endpoint (the ALB DNS is operator infra),
/// so the endpoint slot is always `None`. Requires the `deploy-aws-ecs` feature.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn apply_revision_aws_ecs(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    revision_id: RevisionId,
    present: bool,
    answers: Option<&Value>,
) -> Result<(&'static str, String, Option<String>), OpError> {
    use crate::env_packs::aws::credentials::run_aws_async;
    use crate::env_packs::aws::real_target::service_name;
    use crate::env_packs::deployer::Deployer;

    let revision = env
        .revisions
        .iter()
        .find(|r| r.revision_id == revision_id)
        .expect("revision presence checked by the caller");
    let worker_name = service_name(&revision.deployment_id);
    let (identity, session, launch, region, pool) =
        aws_ecs_target_inputs(store, env, env_id, answers)?;

    run_aws_async(async move {
        let handler = resolve_ecs_handler(&region, launch, pool, session).await?;
        if present {
            handler
                .warm_revision(env, revision_id, answers)
                .await
                .map_err(|e| OpError::Conflict(e.to_string()))?;
        } else {
            handler
                .archive_revision(env, revision_id, answers)
                .await
                .map_err(|e| OpError::Conflict(e.to_string()))?;
        }
        Ok::<(), OpError>(())
    })?;
    Ok((identity, worker_name, None))
}

#[cfg(all(feature = "creds-aws", not(feature = "deploy-aws-ecs")))]
fn apply_revision_aws_ecs(
    _store: &LocalFsStore,
    _env: &Environment,
    _env_id: &EnvId,
    _revision_id: RevisionId,
    _present: bool,
    _answers: Option<&Value>,
) -> Result<(&'static str, String, Option<String>), OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `deploy-aws-ecs` feature; \
         `op env apply-revision` for an aws-ecs env needs it to talk to AWS"
            .to_string(),
    ))
}

/// Resolve the bound deployer credential (or the ambient ADC chain) and parse
/// the Cloud Run construction inputs from the binding answers. Returns
/// `(identity_label, params, credentials)` — the GCP analogue of
/// [`aws_ecs_target_inputs`], shared by `apply-revision` and `apply-traffic` so
/// both honor the same credential resolution.
///
/// Fails closed (before any GCP call) when a `credentials_ref` is bound but
/// unreadable (via `resolve_bound_credentials`); a `None` credential means "no
/// ref bound", so the target falls back to the ambient ADC chain — the same
/// bound-or-ambient model the AWS path uses.
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
fn cloudrun_target_inputs(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
) -> Result<
    (
        &'static str,
        crate::env_packs::gcp_cloudrun::deployer::GcpCloudRunParams,
        Option<crate::env_packs::gcp_cloudrun::bound_session::GcpCredentialMaterial>,
    ),
    OpError,
> {
    use crate::env_packs::gcp_cloudrun::bound_session::resolve_bound_credentials;
    use crate::env_packs::gcp_cloudrun::deployer::GcpCloudRunParams;

    let credentials = resolve_bound_credentials(store, env, env_id)?;
    let identity = if credentials.is_some() {
        "bound"
    } else {
        "ambient"
    };
    let params = GcpCloudRunParams::from_answers(env, answers)
        .map_err(|e| OpError::Conflict(format!("invalid gcp-cloudrun binding answers: {e}")))?;
    Ok((identity, params, credentials))
}

/// Build the region-pinned Cloud Run + Secret Manager clients (with the bound
/// credential injected, else ambient ADC) and wrap them in a handler — the GCP
/// analogue of [`resolve_ecs_handler`]. The Service's `*.run.app` URL rides back
/// on the warm outcome (read from the upsert response), so the caller needs no
/// separate handle on the target.
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
async fn resolve_cloudrun_handler(
    project: &str,
    region: &str,
    credentials: Option<crate::env_packs::gcp_cloudrun::bound_session::GcpCredentialMaterial>,
    dev_secrets: Option<Vec<u8>>,
) -> Result<crate::env_packs::gcp_cloudrun::GcpCloudRunDeployerHandler, OpError> {
    use crate::env_packs::gcp_cloudrun::GcpCloudRunDeployerHandler;
    use crate::env_packs::gcp_cloudrun::real_target::RealCloudRunTarget;
    use std::sync::Arc;

    let target = RealCloudRunTarget::resolve(project, region, credentials)
        .await
        .map_err(|e| {
            OpError::Conflict(format!(
                "cannot initialize the GCP Cloud Run deployer client: {e}"
            ))
        })?;
    Ok(GcpCloudRunDeployerHandler::with_target_and_dev_secrets(
        Arc::new(target),
        dev_secrets,
    ))
}

/// Store-injected teardown of a Cloud Run env's owned Services, run under the
/// destroy flock before the local state is purged (plan item 5b). Deletes the
/// Service for each of the env's deployments — idempotent, an already-gone
/// Service is not an error — so a retried `destroy` after a partial failure
/// converges. Version-pinned Secret Manager teardown lands with secret *staging*
/// in a later slice (the deploy path stages no secrets yet).
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
struct CloudRunProviderTeardown;

#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
impl crate::environment::ProviderTeardown for CloudRunProviderTeardown {
    fn teardown(
        &self,
        ctx: crate::environment::ProviderTeardownCtx<'_>,
    ) -> Result<Value, crate::environment::StoreError> {
        use crate::env_packs::gcp_cloudrun::credentials::run_gcp_async;
        use crate::env_packs::gcp_cloudrun::deploy_target::{CloudRunTarget, ServiceRef};
        use crate::env_packs::gcp_cloudrun::deployer::{environment_secret_name, service_name};
        use crate::env_packs::gcp_cloudrun::real_target::RealCloudRunTarget;
        use crate::environment::StoreError;

        // Resolve project/region + bound credentials from the same answers the
        // deploy path uses (fails closed on an unreadable bound credential). Any
        // error becomes `ProviderTeardown`, leaving the env intact for retry.
        let (_identity, params, credentials) =
            cloudrun_target_inputs(ctx.store, ctx.env, ctx.env_id, ctx.answers)
                .map_err(|e| StoreError::ProviderTeardown(e.to_string()))?;
        let deployment_ids = ctx.deployment_ids.to_vec();
        let project = params.project.clone();
        let region = params.region.clone();
        // The env-level seed secrets warm staged (plan D6) are per-env, not
        // per-deployment — delete them once, after the Services.
        let secret_name = environment_secret_name(&params.secret_prefix);

        let (deleted_services, deleted_secrets) = run_gcp_async(async move {
            let target = RealCloudRunTarget::resolve(&params.project, &params.region, credentials)
                .await
                .map_err(|e| {
                    StoreError::ProviderTeardown(format!(
                        "cannot initialize the GCP Cloud Run deployer client: {e}"
                    ))
                })?;
            let mut deleted = Vec::with_capacity(deployment_ids.len());
            for deployment_id in deployment_ids {
                let service = ServiceRef {
                    deployment_id,
                    project: params.project.clone(),
                    region: params.region.clone(),
                };
                target.delete_service(&service).await.map_err(|e| {
                    StoreError::ProviderTeardown(format!(
                        "deleting Cloud Run service for deployment `{deployment_id}`: {e}"
                    ))
                })?;
                deleted.push(service_name(deployment_id));
            }
            target.delete_secret(&secret_name).await.map_err(|e| {
                StoreError::ProviderTeardown(format!(
                    "deleting Secret Manager secret `{secret_name}`: {e}"
                ))
            })?;
            Ok::<(Vec<String>, Vec<String>), StoreError>((deleted, vec![secret_name]))
        })?;

        Ok(json!({
            "provider": "gcp-cloudrun",
            "project": project,
            "region": region,
            "deleted_services": deleted_services,
            "deleted_secrets": deleted_secrets,
        }))
    }
}

/// Whether `warm_revision` should stage the local dev-store as Cloud Run seed
/// material: the env has a `Secrets`-slot pack AND resolves `secret://` against
/// the dev-store backend, never Vault. Mirrors the k8s render gate
/// (`SecretsBackend::DevStore` + `env_uses_dev_secrets`). Staging a Vault-backed
/// env's dev-store would ship operator-local material — including any bound
/// deployer credentials persisted there — into the runtime seed.
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
fn cloudrun_stages_dev_secrets(env: &Environment) -> bool {
    env.packs.iter().any(|p| p.slot == CapabilitySlot::Secrets) && secrets_backend_is_dev_store(env)
}

/// Connect to GCP and drive the single revision's Cloud Run verb: `warm_revision`
/// when present, `archive_revision` when absent (mirrors `apply_revision_aws_ecs`).
/// Returns `(identity, Cloud Run service name, endpoint_url)` — the Service's
/// live `*.run.app` URL is discovered after a successful warm (`None` on
/// archive). Requires the `deploy-gcp-cloudrun` feature.
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
fn apply_revision_cloudrun(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    revision_id: RevisionId,
    present: bool,
    answers: Option<&Value>,
) -> Result<(&'static str, String, Option<String>), OpError> {
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::gcp_cloudrun::credentials::run_gcp_async;
    use crate::env_packs::gcp_cloudrun::deployer::service_name;

    let revision = env
        .revisions
        .iter()
        .find(|r| r.revision_id == revision_id)
        .expect("revision presence checked by the caller");
    let worker_name = service_name(revision.deployment_id);
    let (identity, params, credentials) = cloudrun_target_inputs(store, env, env_id, answers)?;

    // Read the env's encrypted dev-store (this process owns the filesystem) so
    // `warm_revision` can stage it under the seed secret — but only when the env
    // resolves `secret://` against the dev-store backend, never Vault, and only
    // on the warm path (`present`). Keeps operator-local Vault material and any
    // bound deployer credentials in the dev-store out of the runtime seed.
    let dev_secrets = if present && cloudrun_stages_dev_secrets(env) {
        read_dev_secrets_bytes(store, env_id)?
    } else {
        None
    };

    let endpoint_url = run_gcp_async(async move {
        let handler =
            resolve_cloudrun_handler(&params.project, &params.region, credentials, dev_secrets)
                .await?;
        if present {
            // The Service's live `*.run.app` URL rides back on the warm outcome
            // (read from the upsert response — no extra round-trip): the "one
            // command → live URL" milestone.
            let outcome = handler
                .warm_revision(env, revision_id, answers)
                .await
                .map_err(|e| OpError::Conflict(e.to_string()))?;
            Ok::<Option<String>, OpError>(outcome.endpoint_url)
        } else {
            handler
                .archive_revision(env, revision_id, answers)
                .await
                .map_err(|e| OpError::Conflict(e.to_string()))?;
            Ok::<Option<String>, OpError>(None)
        }
    })?;
    Ok((identity, worker_name, endpoint_url))
}

/// `deploy-gcp-cloudrun`-less builds recognize the cloudrun kind (the dispatch
/// arm is `creds-gcp`-gated) but cannot talk to Cloud Run — the analogue of the
/// AWS `#[cfg(not(deploy-aws-ecs))]` "compiled without the cloud feature" stub.
#[cfg(all(feature = "creds-gcp", not(feature = "deploy-gcp-cloudrun")))]
fn apply_revision_cloudrun(
    _store: &LocalFsStore,
    _env: &Environment,
    _env_id: &EnvId,
    _revision_id: RevisionId,
    _present: bool,
    _answers: Option<&Value>,
) -> Result<(&'static str, String, Option<String>), OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `deploy-gcp-cloudrun` feature; \
         `op env apply-revision` for a cloudrun env needs it to talk to Cloud Run"
            .to_string(),
    ))
}

/// `op env apply-traffic <env_id> <deployment_id> [--kind <descriptor>]`.
///
/// Pushes the env's recorded traffic split for one deployment to the live ALB
/// listener (AWS-ECS only). The split is recorded spec-only by `op traffic set`;
/// this verb makes it observable in the live runtime — the AWS analogue of
/// `apply-revision` for the routing side. K8s needs no such verb: its
/// in-process router reads the split from runtime-config, so the runtime applies
/// it without a deployer round-trip.
pub fn apply_traffic(
    store: &LocalFsStore,
    registry: &crate::env_packs::EnvPackRegistry,
    flags: &OpFlags,
    args: super::dispatch::EnvApplyTrafficArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "apply-traffic",
            json!({
                "input_schema": "env_id + deployment_id positional; --kind <path[@version]> \
                 optional (defaults to the env's deployer binding)"
            }),
        ));
    }
    let env_id = EnvId::try_from(args.env_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let descriptor = resolve_live_deployer_kind(&env, args.kind.as_deref())?;

    // AWS-ECS and GCP Cloud Run have a live router (ALB listener / Cloud Run
    // traffic weights) the split must be pushed to. K8s and the local deployer
    // serve splits from their in-process router (runtime config), so there is no
    // listener to write — `op traffic set` suffices. Gate on the typed-const
    // helpers (not literals) so the paths can't drift from the descriptor consts.
    if !is_aws_ecs_kind(&descriptor) && !is_cloudrun_kind(&descriptor) {
        return Err(OpError::Conflict(format!(
            "env apply-traffic is only supported for the `greentic.deployer.aws-ecs` (AWS-ECS) \
             and `greentic.deployer.gcp-cloudrun` (Cloud Run) deployer env-packs; `{}` serves \
             traffic splits from its runtime router — record the split with `op traffic set` and \
             the runtime applies it",
            descriptor.path()
        )));
    }
    // Parity with apply-revision: confirm the kind is registered.
    let _handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;

    let deployment_id = {
        use std::str::FromStr;
        let ulid = ulid::Ulid::from_str(&args.deployment_id)
            .map_err(|e| OpError::InvalidArgument(format!("deployment_id: {e}")))?;
        greentic_deploy_spec::DeploymentId(ulid)
    };
    let (answers, _answers_ref_wire) = load_render_answers(store, &env, &descriptor)?;

    // NOTE: when the binding records an ALB routing condition
    // (`alb_routing_host` / `alb_routing_path`), `apply_traffic_split` writes a
    // per-deployment listener rule so deployments coexist behind one listener;
    // with no routing condition it REPLACES the listener's default action
    // (whole-listener ownership), assuming the `alb_listener_arn` is dedicated to
    // this deployment — see the `op env apply-traffic` help WARNING.
    // Dispatch to the resolved kind's live router (AWS-ECS ALB listener or Cloud
    // Run traffic weights); the gate above admitted only those two kinds.
    let (identity, outcome) = apply_traffic_non_k8s(
        store,
        &env,
        &env_id,
        deployment_id,
        answers.as_ref(),
        &descriptor,
    )?;

    Ok(OpOutcome::new(
        NOUN,
        "apply-traffic",
        json!({
            "environment_id": env.environment_id.as_str(),
            "kind": descriptor.as_str(),
            "deployment_id": deployment_id.to_string(),
            // Identity the ALB was mutated as (see apply-revision).
            "identity": identity,
            // The split this call enforced (mirrors the env's recorded entries).
            "applied_entries": outcome
                .applied_entries
                .iter()
                .map(|e| {
                    json!({
                        "revision_id": e.revision_id.to_string(),
                        "weight_bps": e.weight_bps,
                    })
                })
                .collect::<Vec<_>>(),
        }),
    ))
}

/// One-command Cloud Run bring-up for `op env up`.
///
/// After the deployer-agnostic `env_apply::apply`, `op env up` calls this to
/// finish a Cloud Run environment. Returns `Some(outcome)` — carrying the
/// discovered `*.run.app` URL — when the env's live deployer is Cloud Run, or
/// `None` for any other kind so `op env up` falls through to its k8s
/// convergence phases. Keeping the deployer-kind decision here keeps `env_up.rs`
/// free of Cloud-Run-specific knowledge.
///
/// Cloud Run is imperative (no declarative cluster reconcile), so bring-up warms
/// every present revision via the same `apply-revision` verb, then pushes each
/// recorded traffic split via `apply-traffic`. Ordering is warm-then-route so a
/// split never references a revision whose Cloud Run revision does not yet exist.
/// Archived revisions are left in place (they carry no traffic and cost nothing
/// at scale-to-zero); archival convergence stays with the granular
/// `op env apply-revision <id>` verb.
///
/// Known limitations (tracked hardening, not this slice): the underlying warm is
/// not yet content-idempotent, so a second `op env up` (or a retried one) can
/// fail re-pinning an immutable Cloud Run revision (H2); and the env is read into
/// one snapshot for the whole bring-up, so a concurrent `op traffic set` during a
/// long multi-revision warm is not observed (same converge-from-snapshot model as
/// the k8s reconcile). Both are acceptable for a bring-up and neither affects the
/// primary fresh single-revision flow.
pub(crate) fn cloudrun_env_up(
    store: &LocalFsStore,
    registry: &crate::env_packs::EnvPackRegistry,
    env_id: &EnvId,
) -> Result<Option<serde_json::Value>, OpError> {
    let env = store.load(env_id)?;
    let descriptor = resolve_live_deployer_kind(&env, None)?;
    if !is_cloudrun_kind(&descriptor) {
        return Ok(None);
    }

    // Parity with `apply-revision` / `apply-traffic`: confirm the kind is
    // registered before driving it.
    let _handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;

    let (answers, _answers_ref_wire) = load_render_answers(store, &env, &descriptor)?;

    // Preflight (side-effect-free, before any warm): Cloud Run's integer
    // `percent` cannot represent basis-point weights that are not whole multiples
    // of 100 bps (plan D1 — the same invariant `split_to_traffic_targets` enforces
    // at apply time). Reject a non-representable split up front so it fails BEFORE
    // warming creates live revisions we would then be unable to route to.
    for split in &env.traffic_splits {
        for entry in &split.entries {
            if entry.weight_bps % 100 != 0 {
                return Err(OpError::Conflict(format!(
                    "traffic split for deployment `{}` weights revision `{}` at {} bps; \
                     Cloud Run weights must be whole multiples of 100 bps (1%)",
                    split.deployment_id, entry.revision_id, entry.weight_bps,
                )));
            }
        }
    }

    // 1. Warm every present revision (bring-up only — see the archival note in
    //    the doc comment). Each Cloud Run warm returns its Service's `*.run.app`
    //    URL; a deployment's revisions share one Service, so endpoints are keyed
    //    by deployment rather than collapsed to a single last-wins URL.
    let mut warmed: Vec<String> = Vec::new();
    let mut endpoints: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for revision in &env.revisions {
        if !crate::env_packs::k8s::manifests::has_cluster_presence(revision.lifecycle) {
            continue;
        }
        let (_identity, service_name, url) = apply_revision_non_k8s(
            store,
            &env,
            env_id,
            revision.revision_id,
            true,
            answers.as_ref(),
            &descriptor,
        )?;
        if let Some(url) = url {
            endpoints.insert(revision.deployment_id.to_string(), url);
        }
        warmed.push(service_name);
    }

    // 2. Push each recorded traffic split to the live Cloud Run router. A fresh
    //    single-revision env may record none — the warm already routes 100% to
    //    its sole revision — so this is a no-op there and load-bearing only for
    //    multi-revision splits.
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
        // One `*.run.app` URL per deployment — an env may front several Services.
        "endpoints": endpoints
            .iter()
            .map(|(deployment_id, url)| json!({"deployment_id": deployment_id, "url": url}))
            .collect::<Vec<_>>(),
    });
    // Convenience single-URL field for the common one-deployment env; omitted for
    // zero or multiple live Services (callers read `endpoints` for the general case).
    if endpoints.len() == 1
        && let Some(url) = endpoints.values().next()
    {
        result["endpoint_url"] = json!(url);
    }
    Ok(Some(result))
}

/// Dispatch `apply-traffic` for a non-K8s deployer between the AWS-ECS and GCP
/// Cloud Run live routers — the routing-side parallel of [`apply_revision_non_k8s`].
/// The applicability gate in [`apply_traffic`] admits only these two kinds.
///
/// `apply_traffic_aws_ecs` is a total function (its `#[cfg(not(deploy-aws-ecs))]`
/// body is the "compiled without the cloud feature" stub), so AWS-ECS is the
/// fallthrough and only the `creds-gcp`-gated Cloud Run arm needs special-casing
/// — no build-matrix split is required here.
fn apply_traffic_non_k8s(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    deployment_id: greentic_deploy_spec::DeploymentId,
    answers: Option<&Value>,
    descriptor: &greentic_deploy_spec::PackDescriptor,
) -> Result<
    (
        &'static str,
        crate::env_packs::deployer::TrafficSplitOutcome,
    ),
    OpError,
> {
    #[cfg(feature = "creds-gcp")]
    {
        if is_cloudrun_kind(descriptor) {
            return apply_traffic_cloudrun(store, env, env_id, deployment_id, answers);
        }
    }
    // `descriptor` selects the kind only when the cloudrun arm is compiled in.
    #[cfg(not(feature = "creds-gcp"))]
    let _ = descriptor;
    apply_traffic_aws_ecs(store, env, env_id, deployment_id, answers)
}

/// Connect to AWS and push one deployment's recorded traffic split to its ALB
/// listener via `apply_traffic_split` (a no-op live when no `alb_listener_arn`
/// is configured — the recorded split's invariants are still enforced). Returns
/// the identity used + the enforced split. Requires the `deploy-aws-ecs`
/// feature.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn apply_traffic_aws_ecs(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    deployment_id: greentic_deploy_spec::DeploymentId,
    answers: Option<&Value>,
) -> Result<
    (
        &'static str,
        crate::env_packs::deployer::TrafficSplitOutcome,
    ),
    OpError,
> {
    use crate::env_packs::aws::credentials::run_aws_async;
    use crate::env_packs::deployer::Deployer;

    let (identity, session, launch, region, pool) =
        aws_ecs_target_inputs(store, env, env_id, answers)?;

    let outcome = run_aws_async(async move {
        let handler = resolve_ecs_handler(&region, launch, pool, session).await?;
        handler
            .apply_traffic_split(env, deployment_id, answers)
            .await
            .map_err(|e| OpError::Conflict(e.to_string()))
    })?;
    Ok((identity, outcome))
}

#[cfg(not(all(feature = "creds-aws", feature = "deploy-aws-ecs")))]
fn apply_traffic_aws_ecs(
    _store: &LocalFsStore,
    _env: &Environment,
    _env_id: &EnvId,
    _deployment_id: greentic_deploy_spec::DeploymentId,
    _answers: Option<&Value>,
) -> Result<
    (
        &'static str,
        crate::env_packs::deployer::TrafficSplitOutcome,
    ),
    OpError,
> {
    Err(OpError::Conflict(
        "this build was compiled without the `deploy-aws-ecs` feature; \
         `op env apply-traffic` needs it to talk to AWS"
            .to_string(),
    ))
}

/// Push one deployment's recorded traffic split to its live Cloud Run Service
/// (native `traffic[]` weights) via `apply_traffic_split`. A no-op live when the
/// Service does not yet exist (the recorded split's invariants are still
/// enforced first). Returns the identity used + the enforced split. Requires the
/// `deploy-gcp-cloudrun` feature.
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
fn apply_traffic_cloudrun(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    deployment_id: greentic_deploy_spec::DeploymentId,
    answers: Option<&Value>,
) -> Result<
    (
        &'static str,
        crate::env_packs::deployer::TrafficSplitOutcome,
    ),
    OpError,
> {
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::gcp_cloudrun::credentials::run_gcp_async;

    let (identity, params, credentials) = cloudrun_target_inputs(store, env, env_id, answers)?;
    let outcome = run_gcp_async(async move {
        // Traffic reweight never warms a revision, so it stages no seed secret.
        let handler =
            resolve_cloudrun_handler(&params.project, &params.region, credentials, None).await?;
        handler
            .apply_traffic_split(env, deployment_id, answers)
            .await
            .map_err(|e| OpError::Conflict(e.to_string()))
    })?;
    Ok((identity, outcome))
}

/// `deploy-gcp-cloudrun`-less builds recognize the cloudrun kind but cannot talk
/// to Cloud Run — the analogue of the AWS `#[cfg(not(deploy-aws-ecs))]` stub.
#[cfg(all(feature = "creds-gcp", not(feature = "deploy-gcp-cloudrun")))]
fn apply_traffic_cloudrun(
    _store: &LocalFsStore,
    _env: &Environment,
    _env_id: &EnvId,
    _deployment_id: greentic_deploy_spec::DeploymentId,
    _answers: Option<&Value>,
) -> Result<
    (
        &'static str,
        crate::env_packs::deployer::TrafficSplitOutcome,
    ),
    OpError,
> {
    Err(OpError::Conflict(
        "this build was compiled without the `deploy-gcp-cloudrun` feature; \
         `op env apply-traffic` for a cloudrun env needs it to talk to Cloud Run"
            .to_string(),
    ))
}

/// Load the deployer binding's recorded wizard answers for the render path.
///
/// Returns `(Some(json), env-relative path string)` when the binding exists
/// with `answers_ref`, the binding's kind path matches the descriptor, and
/// the file is readable. `(None, null)` when no answers are recorded.
/// Errors (fail-closed) when `answers_ref` is set but the file is missing,
/// unreadable, or contains invalid JSON — never silently falls back to
/// defaults.
///
/// `pub(crate)` so the credentials CLI path can read the same binding
/// answers when connecting a live validator client for `op credentials
/// requirements` (it needs `kubeconfig_context`).
pub(crate) fn load_render_answers(
    store: &LocalFsStore,
    env: &greentic_deploy_spec::Environment,
    descriptor: &greentic_deploy_spec::PackDescriptor,
) -> Result<(Option<Value>, Value), OpError> {
    let binding = env.pack_for_slot(CapabilitySlot::Deployer);
    let answers_ref = match binding {
        Some(b) if b.kind.path() == descriptor.path() => b.answers_ref.as_ref(),
        _ => None,
    };
    let Some(rel_path) = answers_ref else {
        return Ok((None, Value::Null));
    };
    let answers = read_binding_answers(store, env, rel_path)?;
    let wire = json!(rel_path.to_string_lossy());
    Ok((Some(answers), wire))
}

/// Read + parse a binding's `answers_ref` JSON file, enforcing that it lives
/// under the env dir (fail-closed on path escape or a missing file). Shared by
/// [`load_render_answers`] (Deployer slot) and [`load_secrets_answers`]
/// (Secrets slot).
fn read_binding_answers(
    store: &LocalFsStore,
    env: &greentic_deploy_spec::Environment,
    rel_path: &std::path::Path,
) -> Result<Value, OpError> {
    let env_dir = store.env_dir(&env.environment_id)?;
    // Containment check: the answers file must live under the env dir.
    // `normalize_under_root` canonicalizes, so it ALSO fails when the file
    // simply does not exist — discriminate the two so a missing file gets
    // an actionable message instead of a path-escape one. Both fail closed.
    let abs_path = match crate::path_safety::normalize_under_root(&env_dir, rel_path) {
        Ok(canon) => canon,
        Err(e) => {
            let missing =
                !rel_path.is_absolute() && env_dir.join(rel_path).symlink_metadata().is_err();
            return Err(if missing {
                OpError::Conflict(format!(
                    "binding records answers_ref `{}` but the file does not exist \
                     — re-run the binding wizard or fix the binding",
                    rel_path.display()
                ))
            } else {
                OpError::Conflict(format!(
                    "answers_ref `{}` escapes env directory: {e}",
                    rel_path.display()
                ))
            });
        }
    };
    let raw = std::fs::read_to_string(&abs_path).map_err(|e| OpError::Io {
        path: abs_path.clone(),
        source: e,
    })?;
    serde_json::from_str(&raw).map_err(|e| {
        OpError::Conflict(format!(
            "answers_ref `{}` contains invalid JSON: {e}",
            rel_path.display()
        ))
    })
}

/// Resolve the env's `Secrets`-slot binding answers (the non-secret connection
/// config for a real backend), if the binding records an `answers_ref`. Mirrors
/// [`load_render_answers`] but for the `Secrets` slot.
fn load_secrets_answers(
    store: &LocalFsStore,
    env: &greentic_deploy_spec::Environment,
) -> Result<Option<Value>, OpError> {
    let Some(binding) = env.pack_for_slot(CapabilitySlot::Secrets) else {
        return Ok(None);
    };
    let Some(rel_path) = binding.answers_ref.as_ref() else {
        return Ok(None);
    };
    Ok(Some(read_binding_answers(store, env, rel_path)?))
}

/// Resolve the env's `Secrets`-slot binding into the runtime secrets backend the
/// K8s manifests render. No binding or the dev-store kind → `DevStore`; the
/// Vault kind → a Vault backend whose non-secret connection config comes from
/// the binding's answers (`addr` + `role` required; mounts / prefix / transit /
/// namespace default to the provider's). An unknown secrets kind fails closed.
pub(crate) fn resolve_secrets_backend(
    store: &LocalFsStore,
    env: &greentic_deploy_spec::Environment,
) -> Result<crate::env_packs::k8s::manifests::SecretsBackend, OpError> {
    use crate::env_packs::k8s::manifests::SecretsBackend;
    let Some(binding) = env.pack_for_slot(CapabilitySlot::Secrets) else {
        return Ok(SecretsBackend::DevStore);
    };
    let path = binding.kind.path();
    if path == crate::defaults::DEV_STORE_SECRETS_PATH {
        return Ok(SecretsBackend::DevStore);
    }
    if path != crate::defaults::VAULT_SECRETS_PATH {
        return Err(OpError::Conflict(format!(
            "unknown secrets backend kind `{path}`; expected `{}` or `{}`",
            crate::defaults::DEV_STORE_SECRETS_PATH,
            crate::defaults::VAULT_SECRETS_PATH
        )));
    }
    secrets_backend_from_vault_answers(load_secrets_answers(store, env)?.as_ref())
}

/// Whether the env's `Secrets`-slot backend custodies secret values in the
/// local dev-store. No binding or the dev-store kind → `true` (the control
/// plane mints + writes webhook-secret values locally); any other kind (e.g.
/// Vault) → `false` (the operator seeds the value out-of-band and the control
/// plane only stamps the ref). Unlike [`resolve_secrets_backend`] this inspects
/// only the binding *kind*, never the connection answers, so it cannot fail —
/// endpoint provisioning must not be coupled to Vault-answer validity.
pub(crate) fn secrets_backend_is_dev_store(env: &greentic_deploy_spec::Environment) -> bool {
    match env.pack_for_slot(CapabilitySlot::Secrets) {
        None => true,
        Some(binding) => binding.kind.path() == crate::defaults::DEV_STORE_SECRETS_PATH,
    }
}

/// Pure mapping of a Vault `Secrets`-binding's answers to a [`VaultBackend`]:
/// `addr` + `role` are required; the rest default to the provider's. Factored
/// out of [`resolve_secrets_backend`] so the field mapping + fail-closed
/// validation is unit-tested without a store.
pub(crate) fn secrets_backend_from_vault_answers(
    answers: Option<&Value>,
) -> Result<crate::env_packs::k8s::manifests::SecretsBackend, OpError> {
    use crate::env_packs::k8s::manifests::{
        SecretsBackend, VAULT_DEFAULT_AUTH_MOUNT, VAULT_DEFAULT_KV_MOUNT, VAULT_DEFAULT_KV_PREFIX,
        VAULT_DEFAULT_TRANSIT_KEY, VAULT_DEFAULT_TRANSIT_MOUNT, VaultBackend,
    };
    let empty = serde_json::Map::new();
    let obj = match answers {
        Some(v) => v.as_object().ok_or_else(|| {
            OpError::Conflict("vault secrets binding answers must be a JSON object".to_string())
        })?,
        None => &empty,
    };
    let required = |key: &str| -> Result<String, OpError> {
        obj.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                OpError::Conflict(format!(
                    "vault secrets backend requires a non-empty `{key}` answer"
                ))
            })
    };
    let optional = |key: &str, default: &str| -> String {
        obj.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| default.to_string())
    };
    Ok(SecretsBackend::Vault(VaultBackend {
        addr: required("addr")?,
        k8s_role: required("role")?,
        kv_mount: optional("kv_mount", VAULT_DEFAULT_KV_MOUNT),
        kv_prefix: optional("kv_prefix", VAULT_DEFAULT_KV_PREFIX),
        auth_mount: optional("auth_mount", VAULT_DEFAULT_AUTH_MOUNT),
        transit_mount: optional("transit_mount", VAULT_DEFAULT_TRANSIT_MOUNT),
        transit_key: optional("transit_key", VAULT_DEFAULT_TRANSIT_KEY),
        namespace: obj
            .get("namespace")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    }))
}

/// Resolve the `--kind` argument for `op env render` to a full
/// [`PackDescriptor`].
///
/// - Absent → the env's Deployer-slot binding (the common case).
/// - Full `<path>@<version>` → parsed as-is, so an operator can preview a
///   kind before binding it.
/// - Bare path → must match the env's deployer binding, whose pinned
///   version is reused. A bare path with no matching binding is rejected
///   rather than guessing a version.
fn resolve_render_kind(
    env: &Environment,
    kind: Option<&str>,
) -> Result<greentic_deploy_spec::PackDescriptor, OpError> {
    let binding = env.pack_for_slot(CapabilitySlot::Deployer);
    match kind {
        None => binding.map(|b| b.kind.clone()).ok_or_else(|| {
            OpError::Conflict(
                "env has no deployer binding; pass --kind <path>@<version>".to_string(),
            )
        }),
        Some(k) if k.contains('@') => greentic_deploy_spec::PackDescriptor::try_new(k)
            .map_err(|e| OpError::InvalidArgument(format!("--kind: {e}"))),
        Some(path) => match binding {
            Some(b) if b.kind.path() == path => Ok(b.kind.clone()),
            _ => Err(OpError::InvalidArgument(format!(
                "--kind `{path}` carries no version and does not match the env's \
                 deployer binding; pass a full `<path>@<version>`"
            ))),
        },
    }
}

/// Resolve the deployer descriptor for a LIVE (cluster-mutating) verb
/// (`reconcile`, `apply-revision`).
///
/// Unlike [`resolve_render_kind`] — which backs the read-only `render` preview
/// and deliberately lets a full `--kind` describe an *unbound* deployer — a
/// live verb must mutate ONLY the env's declared deployer. The resolved
/// descriptor's **path** must equal the env's Deployer-slot binding path, so a
/// full `--kind` may override the binding's *version* (same deployer) but can
/// neither switch deployers (e.g. force `greentic.deployer.k8s` onto a
/// local-process env) nor apply to an env with no deployer binding at all.
/// Without this, `--kind <full k8s descriptor>` would drive K8s apply/teardown
/// against a cluster for an env that was never K8s-bound.
pub(crate) fn resolve_live_deployer_kind(
    env: &Environment,
    kind: Option<&str>,
) -> Result<greentic_deploy_spec::PackDescriptor, OpError> {
    let descriptor = resolve_render_kind(env, kind)?;
    let bound = env.pack_for_slot(CapabilitySlot::Deployer).ok_or_else(|| {
        OpError::Conflict(
            "env has no deployer binding; a live apply must target a bound deployer".to_string(),
        )
    })?;
    if descriptor.path() != bound.kind.path() {
        return Err(OpError::Conflict(format!(
            "env is bound to deployer `{}`; a live apply cannot use `{}` — it is not the env's \
             bound deployer (a full `--kind` may override the version, not switch deployers)",
            bound.kind.path(),
            descriptor.path()
        )));
    }
    Ok(descriptor)
}

/// Result of [`write_rendered_objects`].
struct WriteResult {
    /// Files written by this render.
    files: Vec<String>,
    /// Render-managed `.yaml` files from a previous render that were removed
    /// from disk because they are no longer in the desired state.
    removed_stale_files: Vec<String>,
    /// Non-managed `.yaml` or other files present in the directory that were
    /// left untouched (e.g. a user's `kustomization.yaml`).
    unmanaged_files: Vec<String>,
}

/// Write each rendered object as a YAML file under `dir` (created if
/// missing). The output directory is render-managed for files matching
/// the `<NN>-*.yaml` pattern: stale managed files from previous renders
/// are deleted so `kubectl apply -f <dir>` can never resurrect an archived
/// revision. Other files are left alone and reported.
///
/// All objects are pre-serialized before any filesystem write so a
/// serialization failure leaves the directory untouched.
fn write_rendered_objects(
    dir: &std::path::Path,
    objects: &[Value],
) -> Result<WriteResult, OpError> {
    let io_err = |source: std::io::Error| OpError::Io {
        path: dir.to_path_buf(),
        source,
    };

    // 1. Pre-serialize ALL objects before touching the filesystem.
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        let file_name = rendered_object_file_name(index, object);
        let yaml = serde_yaml_bw::to_string(object).map_err(|e| OpError::Io {
            path: dir.join(&file_name),
            source: std::io::Error::other(format!("manifest YAML serialization: {e}")),
        })?;
        pairs.push((file_name, yaml));
    }

    // 2. Write files.
    std::fs::create_dir_all(dir).map_err(io_err)?;
    let mut files = Vec::with_capacity(pairs.len());
    for (file_name, yaml) in &pairs {
        let path = dir.join(file_name);
        std::fs::write(&path, yaml).map_err(|source| OpError::Io { path, source })?;
        files.push(file_name.clone());
    }

    // 3. Scan and clean up stale render-managed files.
    let mut removed_stale_files = Vec::new();
    let mut unmanaged_files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io_err)? {
        let name = entry.map_err(io_err)?.file_name();
        let name = name.to_string_lossy().into_owned();
        if files.contains(&name) {
            continue;
        }
        if name.ends_with(".yaml") && is_render_managed_name(&name) {
            let path = dir.join(&name);
            std::fs::remove_file(&path).map_err(|source| OpError::Io { path, source })?;
            removed_stale_files.push(name);
        } else if name.ends_with(".yaml") {
            unmanaged_files.push(name);
        }
        // Non-yaml files are silently ignored.
    }
    removed_stale_files.sort();
    unmanaged_files.sort();

    Ok(WriteResult {
        files,
        removed_stale_files,
        unmanaged_files,
    })
}

/// Whether a file name matches the render-managed pattern: a non-empty
/// leading run of ASCII digits followed by `-` and ending in `.yaml`.
/// Our naming convention is `<NN>-<kind>-<name>.yaml` where NN can exceed
/// 99, so we accept 1+ digits. Implemented without a regex dependency.
fn is_render_managed_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    // Must end in .yaml (already checked by caller, but be defensive).
    if !name.ends_with(".yaml") {
        return false;
    }
    // Find the first non-digit byte.
    let digit_end = bytes.iter().position(|b| !b.is_ascii_digit()).unwrap_or(0);
    // Must have at least one digit followed by `-`.
    digit_end > 0 && bytes.get(digit_end) == Some(&b'-')
}

/// `<NN>-<kind>-<name>.yaml`, lowercased and restricted to `[a-z0-9.-]`
/// so a renderer-supplied name can never traverse out of the output dir.
fn rendered_object_file_name(index: usize, object: &Value) -> String {
    let sanitize = |s: &str| -> String {
        s.to_ascii_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    };
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("object");
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("unnamed");
    format!("{index:02}-{}-{}.yaml", sanitize(kind), sanitize(name))
}

/// `op env init`. Idempotent bootstrap of the `local` env with its five
/// default env-pack bindings; on first init only also seeds the operator
/// key into the env trust root so signature-gated verbs (revenue-policy,
/// bundle/revision DSSE) work out of the box (N1.4). The gate sits on
/// `<env_dir>/trust-root.json`'s presence, so a routine `init` cannot
/// re-grant a key revoked via `trust-root remove`.
///
/// Outcome JSON:
/// - `outcome` discriminator: `"created"` | `"healed"` | `"untouched"`.
/// - `trust_root`: seeded `{operator_key_id, public_pem, trusted_key_count}`
///   on first init, `null` thereafter.
pub fn init(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: EnvInitPayload,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "init",
            json!({ "input_schema": "optional --public-url" }),
        ));
    }
    let env_id = EnvId::try_from(crate::defaults::LOCAL_ENV_ID).map_err(|e| {
        OpError::InvalidArgument(format!(
            "default env id `{}`: {}",
            crate::defaults::LOCAL_ENV_ID,
            e
        ))
    })?;
    // Validate the URL up-front so a malformed value is rejected before any
    // disk state is touched. The "URL given AND env exists → reject" gate
    // fires INSIDE `ensure_local_environment`'s per-env flock so it's both
    // race-free and stat-free here.
    let validated_public_base_url = parse_optional_public_base_url(&payload.public_base_url)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "init",
        target: json!({
            "environment_id": env_id.as_str(),
            "public_base_url_applied": validated_public_base_url.is_some(),
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |committed| {
        let (env, outcome) =
            super::bootstrap::ensure_local_environment(store, validated_public_base_url.clone())?;
        // Env is now persisted. Mark committed so a subsequent trust-root
        // seed failure + audit-append failure still fail-closes (otherwise
        // the audit-append failure would demote to `tracing::warn!` and
        // hide the missing audit record for the env we just wrote).
        committed.mark_committed();
        // N1.4: seed operator key on first init only — see
        // `LocalFsStore::seed_trust_root_if_absent` (Phase D PR-3a.2).
        let trust_root_seed = store
            .seed_trust_root_if_absent(&env.environment_id)
            .map_err(super::map_store_err_preserving_noun)?;
        let trust_root = super::trust_root::trust_root_seed_to_wire_opt(
            &env.environment_id,
            trust_root_seed.as_ref(),
        );
        let bound_slots: Vec<String> = env.packs.iter().map(|b| b.slot.to_string()).collect();
        let mut payload = json!({
            "environment_id": env.environment_id.as_str(),
            "bound_slots": bound_slots,
            "pack_count": env.packs.len(),
            "public_base_url": env.host_config.public_base_url,
            "trust_root": trust_root,
        });
        let payload_obj = payload
            .as_object_mut()
            .expect("payload constructed as object");
        match outcome {
            super::bootstrap::LocalEnvOutcome::Created => {
                payload_obj.insert("outcome".into(), json!("created"));
            }
            super::bootstrap::LocalEnvOutcome::AlreadyExists => {
                payload_obj.insert("outcome".into(), json!("untouched"));
            }
            super::bootstrap::LocalEnvOutcome::Healed { added_slots } => {
                payload_obj.insert("outcome".into(), json!("healed"));
                payload_obj.insert(
                    "added_slots".into(),
                    json!(
                        added_slots
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                    ),
                );
            }
        }
        let outcome = OpOutcome::new(NOUN, "init", payload);
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op env destroy <env_id> --confirm`. Irreversibly removes the env's
/// on-disk state via [`LocalFsStore::destroy_environment`] (mechanics,
/// failure contract, and concurrency notes documented there).
///
/// Force-free safety net: the caller must pass `confirm = true`. The
/// `--confirm` flag is the operator-binary's responsibility; this library
/// just enforces the gate.
///
/// CLI-layer specifics: the audit event appends AFTER the mutation
/// closure, so it lands in a recreated `<env_id>/audit/events.jsonl`
/// holding only the destroy event (fail-closed via `mark_committed`); a
/// later `init` continues the same trail. Destroying `local` is allowed —
/// `gtc setup`/`gtc start` re-create it on next launch. Dev-store secrets
/// redirected outside the env dir via `GREENTIC_DEV_SECRETS_PATH` are not
/// touched.
pub fn destroy(
    store: &LocalFsStore,
    flags: &OpFlags,
    env_id: &str,
    confirm: bool,
    force_local: bool,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "destroy",
            json!({ "input_schema": "env_id positional + confirm flag + optional --force-local" }),
        ));
    }
    if !confirm {
        return Err(OpError::InvalidArgument(
            "destroy requires --confirm".to_string(),
        ));
    }
    let env_id =
        EnvId::try_from(env_id).map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "destroy",
        target: json!({"environment_id": env_id.as_str(), "confirm": confirm}),
        idempotency_key: None,
    };
    // Provider-resource teardown callback. The store recognizes a
    // resource-owning deployer (e.g. Cloud Run) by descriptor string even in a
    // feature-reduced binary and refuses-not-purges when it cannot tear the
    // resources down; the teardown implementation is only wired when the provider
    // feature is compiled in. `--force-local` skips teardown and purges local
    // state only.
    #[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
    let cloudrun_teardown = CloudRunProviderTeardown;
    #[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
    let teardown: Option<&dyn crate::environment::ProviderTeardown> = Some(&cloudrun_teardown);
    #[cfg(not(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun")))]
    let teardown: Option<&dyn crate::environment::ProviderTeardown> = None;

    audit_and_record(store, ctx, |committed| {
        // No pre-check: destroy_environment_with_teardown handles NotFound
        // internally, reaps stale tombstones when the env is already gone, and
        // classifies + tears down provider resources under the same destroy flock.
        let result = store
            .destroy_environment_with_teardown(&env_id, teardown, force_local)
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(super::map_store_err_preserving_noun)?;
        let mut payload = json!({
            "environment_id": env_id.as_str(),
            "outcome": "destroyed",
            "removed_path": result.removed_path.display().to_string(),
        });
        let payload_obj = payload
            .as_object_mut()
            .expect("payload constructed as object");
        if result.reaped_tombstones > 0 {
            payload_obj.insert("reaped_tombstones".into(), json!(result.reaped_tombstones));
        }
        if let Some(teardown_report) = result.provider_teardown {
            payload_obj.insert("provider_teardown".into(), teardown_report);
        }
        let outcome = OpOutcome::new(NOUN, "destroy", payload);
        Ok((outcome, super::AuditGens::NONE))
    })
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

fn schema_outcome(op: &'static str) -> Result<OpOutcome, OpError> {
    Ok(OpOutcome::new(NOUN, op, env_create_payload_schema()))
}

/// Hand-written JSON Schema stub for [`EnvCreatePayload`]. Replaces the full
/// schemars derive until A1's deferred `schemars` wiring lands; the operator
/// surface still gets a useful machine-readable description of the payload.
pub fn env_create_payload_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "EnvCreatePayload",
        "type": "object",
        "required": ["environment_id", "name"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string", "description": "EnvId — kebab-friendly env identifier."},
            "name": {"type": "string"},
            "region": {"type": ["string", "null"]},
            "tenant_org_id": {"type": ["string", "null"]},
            "listen_addr": {"type": ["string", "null"]},
            "public_base_url": {"type": ["string", "null"], "description": "origin-only URL (https://host[:port])"}
        }
    })
}

/// Payload accepted by `op env init`. Init is otherwise a fixed-shape
/// bootstrap of the canonical `local` env; the only optional input is the
/// public URL persisted on the env's `host_config`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvInitPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
}

impl super::dispatch::EnvInitArgs {
    /// Build the typed payload for [`init`]. Init takes no `--answers` /
    /// `--schema` JSON fallback — the only input is `--public-url`. The
    /// returned payload is the source of truth (an absent flag is `None`).
    pub fn into_payload(self, _flags: &OpFlags) -> Result<EnvInitPayload, OpError> {
        Ok(EnvInitPayload {
            public_base_url: self.public_url,
        })
    }
}

/// Validate an optional `public_base_url` against the spec validator and wrap
/// the spec error in `OpError::InvalidArgument` with the canonical
/// `"public_base_url: …"` field prefix. Centralizes the format string so the
/// 5 entry points (`env create`, `env update`, `env init`, `env set-public-url`,
/// `config set`) report identical operator-facing errors.
pub(crate) fn parse_public_base_url(raw: &str) -> Result<String, OpError> {
    validate_public_base_url(raw)
        .map_err(|e| OpError::InvalidArgument(format!("public_base_url: {e}")))
}

/// Validate an `Option<String>` carrying a `public_base_url` payload field.
/// Returns `Ok(None)` when the field was absent, the canonical form when
/// present and valid, and `Err(OpError::InvalidArgument)` when present and
/// invalid. The 5 entry points all share this lift to keep the
/// `.as_deref().map(parse).transpose()` boilerplate in one place.
pub(crate) fn parse_optional_public_base_url(
    raw: &Option<String>,
) -> Result<Option<String>, OpError> {
    raw.as_deref().map(parse_public_base_url).transpose()
}

// ---- Inline-args guards (env-local mirror of messaging.rs's pattern) ------
//
// Both `EnvCreateArgs::into_payload` and `EnvUpdateArgs::into_payload` need to
// (a) reject `--answers` mixed with inline flags and (b) report the partial-
// inline set that's missing required fields. The shape is identical to the
// `messaging.rs` helpers but those are file-private; promoting them to
// `cli::mod.rs` for cross-noun reuse is a follow-up cleanup.

fn reject_inline_plus_answers(
    has_inline: bool,
    flags: &OpFlags,
    verb: &'static str,
) -> Result<(), OpError> {
    if has_inline && flags.answers.is_some() {
        return Err(OpError::InvalidArgument(format!(
            "env {verb}: inline flags and --answers are mutually exclusive; use one or the other"
        )));
    }
    Ok(())
}

fn partial_inline_error(verb: &'static str, missing: &[&str]) -> OpError {
    OpError::InvalidArgument(format!(
        "env {verb}: inline-flag form requires --environment-id and --name; missing: {}",
        missing.join(", ")
    ))
}

/// Helper used by both `EnvCreateArgs` and `EnvUpdateArgs`: enforce the
/// inline-vs-answers contract and collect required-flag presence. Returns
/// `Ok(None)` when no inline flags were supplied (caller falls through to
/// `--answers`), or `Ok(Some((env_id, name)))` when the required pair is
/// present.
fn require_inline_env_id_and_name(
    has_inline: bool,
    env_id: Option<String>,
    name: Option<String>,
    verb: &'static str,
    flags: &OpFlags,
) -> Result<Option<(String, String)>, OpError> {
    reject_inline_plus_answers(has_inline, flags, verb)?;
    if !has_inline {
        return Ok(None);
    }
    let mut missing: Vec<&'static str> = Vec::new();
    if env_id.is_none() {
        missing.push("--environment-id");
    }
    if name.is_none() {
        missing.push("--name");
    }
    if !missing.is_empty() {
        return Err(partial_inline_error(verb, &missing));
    }
    Ok(Some((
        env_id.expect("checked above"),
        name.expect("checked above"),
    )))
}

impl super::dispatch::EnvCreateArgs {
    fn has_inline_input(&self) -> bool {
        self.environment_id.is_some()
            || self.name.is_some()
            || self.region.is_some()
            || self.tenant_org_id.is_some()
            || self.listen_addr.is_some()
            || self.public_url.is_some()
    }

    /// Build an [`EnvCreatePayload`] from CLI flags. Returns:
    /// - `Ok(None)` when no inline flag is set — caller falls through to
    ///   `--answers`.
    /// - `Err(OpError::InvalidArgument)` when SOME inline flags are set but
    ///   required ones (`environment_id`, `name`) are missing, OR when
    ///   inline flags AND `--answers` are both supplied (mutual exclusion).
    /// - `Ok(Some(payload))` on the fully-specified inline path.
    ///
    /// `verb` is the public verb name (`"create"` / `"update"`) folded into
    /// the error message.
    pub fn into_payload(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<EnvCreatePayload>, OpError> {
        let has_inline = self.has_inline_input();
        let Some((environment_id, name)) = require_inline_env_id_and_name(
            has_inline,
            self.environment_id,
            self.name,
            verb,
            flags,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(EnvCreatePayload {
            environment_id,
            name,
            region: self.region,
            tenant_org_id: self.tenant_org_id,
            listen_addr: self.listen_addr,
            public_base_url: self.public_url,
        }))
    }
}

impl super::dispatch::EnvUpdateArgs {
    fn has_inline_input(&self) -> bool {
        self.environment_id.is_some()
            || self.name.is_some()
            || self.region.is_some()
            || self.tenant_org_id.is_some()
    }

    /// Build an [`EnvCreatePayload`] from CLI flags for the `update` verb.
    /// Returns:
    /// - `Ok(None)` when no inline flag is set — caller falls through to
    ///   `--answers`.
    /// - `Err(OpError::InvalidArgument)` when SOME inline flags are set but
    ///   required ones (`environment_id`, `name`) are missing, OR when
    ///   inline flags AND `--answers` are both supplied (mutual exclusion).
    /// - `Ok(Some(payload))` on the fully-specified inline path.
    ///
    /// The produced payload always sets `listen_addr: None` and
    /// `public_base_url: None` — those fields are not exposed on the update
    /// verb. URL changes go through `op env set-public-url`; listen-addr
    /// changes through `op config set --listen-addr`.
    pub fn into_payload(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<EnvCreatePayload>, OpError> {
        let has_inline = self.has_inline_input();
        let Some((environment_id, name)) = require_inline_env_id_and_name(
            has_inline,
            self.environment_id,
            self.name,
            verb,
            flags,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(EnvCreatePayload {
            environment_id,
            name,
            region: self.region,
            tenant_org_id: self.tenant_org_id,
            listen_addr: None,
            public_base_url: None,
        }))
    }
}

/// `op env set-public-url <env_id> <URL>`. Dedicated verb that ONLY mutates
/// `host_config.public_base_url`; safer to expose than `op config set`
/// (which can update name/region/tenant-org/listen-addr in the same call)
/// when callers just want to point the env at a different origin.
pub fn set_public_url(
    store: &LocalFsStore,
    flags: &OpFlags,
    env_id: &str,
    url: &str,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "set-public-url",
            json!({ "input_schema": "<env_id> <url> positional" }),
        ));
    }
    let env_id =
        EnvId::try_from(env_id).map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    let validated = parse_public_base_url(url)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "set-public-url",
        target: json!({"environment_id": env_id.as_str()}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store
            .update_environment(
                &env_id,
                UpdateEnvironmentPayload {
                    public_base_url: FieldUpdate::Set(validated),
                    ..Default::default()
                },
            )
            .map_err(map_store_err_preserving_noun)?;
        let outcome = OpOutcome::new(
            NOUN,
            "set-public-url",
            json!({
                "environment_id": env_id.as_str(),
                "host_config": env.host_config,
            }),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::LocalFsStore;
    use tempfile::tempdir;

    #[test]
    fn create_then_show_roundtrip() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let flags = OpFlags::default();
        let outcome = create(
            &store,
            &flags,
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap();
        assert_eq!(outcome.op, "create");
        assert_eq!(outcome.noun, "env");
        let show_outcome = show(&store, &flags, "local").unwrap();
        assert_eq!(show_outcome.op, "show");
        let env_val = show_outcome
            .result
            .get("environment")
            .expect("environment field");
        assert_eq!(env_val.get("name").and_then(|v| v.as_str()), Some("local"));
    }

    #[test]
    fn create_rejects_duplicate() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();
        let err = create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "again".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn update_rewrites_name_and_region() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();
        let outcome = update(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "renamed".to_string(),
                region: Some("eu-west-1".to_string()),
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("name").and_then(|v| v.as_str()),
            Some("renamed")
        );
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.name, "renamed");
        assert_eq!(env.host_config.region.as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn create_persists_explicit_listen_addr_and_surfaces_it_in_summary() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let outcome = create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: Some("0.0.0.0:9090".to_string()),
                public_base_url: None,
            }),
        )
        .unwrap();
        // Surface check: the create response (EnvSummary) must include the
        // bind address, otherwise operators can't see what they just set.
        let listen = outcome
            .result
            .get("listen_addr")
            .and_then(|v| v.as_str())
            .expect("EnvSummary must expose listen_addr");
        assert_eq!(listen, "0.0.0.0:9090");
        // Storage check: the persisted env carries the typed SocketAddr.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9090);
        assert_eq!(env.host_config.listen_addr, Some(expected));
    }

    #[test]
    fn create_rejects_malformed_listen_addr_before_touching_store() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: Some("not-a-socket-addr".to_string()),
                public_base_url: None,
            }),
        )
        .expect_err("malformed listen_addr must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("listen_addr") && msg.contains("not-a-socket-addr"),
            "error must name the offending field + value, got: {msg}"
        );
        // Store must be untouched — `op env list` sees zero envs.
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn create_preserves_corrupt_environment_json_instead_of_overwriting() {
        // Regression for the `is_ok()`-existence-check footgun in
        // `LocalFsStore::create_environment`. A corrupt `environment.json`
        // must NOT be treated as "env doesn't exist" — otherwise create
        // would silently overwrite a recoverable file with an empty env.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_dir = dir.path().join("local");
        std::fs::create_dir_all(&env_dir).unwrap();
        let corrupt_path = env_dir.join("environment.json");
        let corrupt_bytes = b"{ this is not valid json";
        std::fs::write(&corrupt_path, corrupt_bytes).unwrap();
        let err = create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .expect_err("create over a corrupt environment.json must fail");
        // Anything but Conflict — the env "appears to exist but is unreadable",
        // which is a Store error, not a duplicate.
        assert!(
            !matches!(err, OpError::Conflict(_)),
            "expected store/json error, got Conflict (overwrote the file?): {err:?}"
        );
        // Crucially: the corrupt file is byte-for-byte preserved.
        let on_disk = std::fs::read(&corrupt_path).unwrap();
        assert_eq!(
            on_disk, corrupt_bytes,
            "create must not have rewritten environment.json"
        );
    }

    #[test]
    fn create_with_no_listen_addr_persists_none_so_runtime_falls_back_to_default() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        // `None` on disk → `resolved_listen_addr()` returns `DEFAULT_LISTEN_ADDR`.
        // This is the documented divergence from `op env init` (the local
        // bootstrap), which writes `Some(DEFAULT_LISTEN_ADDR)` explicitly.
        assert_eq!(env.host_config.listen_addr, None);
        assert_eq!(
            env.host_config.resolved_listen_addr(),
            greentic_deploy_spec::DEFAULT_LISTEN_ADDR,
        );
    }

    #[test]
    fn update_preserves_existing_fields_when_payload_omits_them() {
        // PR-3a.3: `op env update` now skips `None` fields instead of wiping
        // them. Matches the trait-shell rule from PR-3a.1 ("None values are
        // skipped") and aligns env update with `op config set` semantics so
        // one HTTP endpoint covers both verbs. Pins the behavior so future
        // refactors can't regress to wholesale-overwrite.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.host_config.region = Some("eu-west-1".to_string());
        env.host_config.tenant_org_id = Some("acme".to_string());
        env.host_config.public_base_url = Some("https://existing.example.com".to_string());
        store.save(&env).unwrap();
        update(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "renamed".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.name, "renamed");
        assert_eq!(
            env.host_config.region.as_deref(),
            Some("eu-west-1"),
            "region must NOT be wiped when payload omits it"
        );
        assert_eq!(
            env.host_config.tenant_org_id.as_deref(),
            Some("acme"),
            "tenant_org_id must NOT be wiped when payload omits it"
        );
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://existing.example.com"),
            "public_base_url must NOT be wiped when payload omits it"
        );
    }

    #[test]
    fn update_environment_clear_resets_optional_fields_to_none() {
        // PR-3a.3 follow-up: `FieldUpdate::Clear` writes `None` into
        // optional host_config fields so callers can un-set a region,
        // tenant_org_id, listen_addr, or public_base_url.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.host_config.region = Some("eu-west-1".to_string());
        env.host_config.tenant_org_id = Some("acme".to_string());
        env.host_config.listen_addr = Some("0.0.0.0:9090".parse().unwrap());
        env.host_config.public_base_url = Some("https://example.com".to_string());
        store.save(&env).unwrap();

        let env_id = EnvId::try_from("local").unwrap();
        let env = store
            .update_environment(
                &env_id,
                UpdateEnvironmentPayload {
                    name: None,
                    region: FieldUpdate::Clear,
                    tenant_org_id: FieldUpdate::Clear,
                    listen_addr: FieldUpdate::Clear,
                    public_base_url: FieldUpdate::Clear,
                    gui_enabled: FieldUpdate::Keep,
                },
            )
            .unwrap();

        assert_eq!(env.host_config.region, None, "region must be cleared");
        assert_eq!(
            env.host_config.tenant_org_id, None,
            "tenant_org_id must be cleared"
        );
        assert_eq!(
            env.host_config.listen_addr, None,
            "listen_addr must be cleared"
        );
        assert_eq!(
            env.host_config.public_base_url, None,
            "public_base_url must be cleared"
        );
        // Name stays unchanged (Clear is not available for required fields).
        assert_eq!(env.name, "local");
    }

    #[test]
    fn update_environment_keep_preserves_set_does_not_collide_with_clear() {
        // Tri-state regression: a mix of Keep, Set, and Clear on different
        // fields in the same payload must each apply independently.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.host_config.region = Some("us-east-1".to_string());
        env.host_config.tenant_org_id = Some("old-org".to_string());
        env.host_config.listen_addr = Some("127.0.0.1:8080".parse().unwrap());
        env.host_config.public_base_url = Some("https://old.example.com".to_string());
        store.save(&env).unwrap();

        let env_id = EnvId::try_from("local").unwrap();
        let env = store
            .update_environment(
                &env_id,
                UpdateEnvironmentPayload {
                    name: Some("renamed".to_string()),
                    region: FieldUpdate::Keep, // preserve
                    tenant_org_id: FieldUpdate::Set("new-org".to_string()), // overwrite
                    listen_addr: FieldUpdate::Clear, // clear
                    public_base_url: FieldUpdate::Set("https://new.example.com".to_string()),
                    gui_enabled: FieldUpdate::Keep,
                },
            )
            .unwrap();

        assert_eq!(env.name, "renamed");
        assert_eq!(
            env.host_config.region.as_deref(),
            Some("us-east-1"),
            "Keep must preserve existing value"
        );
        assert_eq!(
            env.host_config.tenant_org_id.as_deref(),
            Some("new-org"),
            "Set must overwrite"
        );
        assert_eq!(
            env.host_config.listen_addr, None,
            "Clear must reset to None"
        );
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://new.example.com"),
            "Set must overwrite"
        );
    }

    #[test]
    fn update_environment_clear_on_already_none_is_idempotent() {
        // Clear on a field that is already None is a no-op — must not panic
        // or error.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        // make_env creates host_config with all optional fields as None.
        assert!(env.host_config.region.is_none());
        store.save(&env).unwrap();

        let env_id = EnvId::try_from("local").unwrap();
        let env = store
            .update_environment(
                &env_id,
                UpdateEnvironmentPayload {
                    name: None,
                    region: FieldUpdate::Clear,
                    tenant_org_id: FieldUpdate::Clear,
                    listen_addr: FieldUpdate::Clear,
                    public_base_url: FieldUpdate::Clear,
                    gui_enabled: FieldUpdate::Keep,
                },
            )
            .unwrap();

        assert_eq!(env.host_config.region, None);
        assert_eq!(env.host_config.tenant_org_id, None);
        assert_eq!(env.host_config.listen_addr, None);
        assert_eq!(env.host_config.public_base_url, None);
    }

    #[test]
    fn update_environment_default_payload_is_all_keep_noop() {
        // `UpdateEnvironmentPayload::default()` must be a no-op patch —
        // backward compat with code that relied on `..Default::default()`.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.host_config.region = Some("eu-west-1".to_string());
        env.host_config.tenant_org_id = Some("acme".to_string());
        env.host_config.listen_addr = Some("0.0.0.0:9090".parse().unwrap());
        env.host_config.public_base_url = Some("https://example.com".to_string());
        store.save(&env).unwrap();

        let env_id = EnvId::try_from("local").unwrap();
        let env = store
            .update_environment(&env_id, UpdateEnvironmentPayload::default())
            .unwrap();

        assert_eq!(env.host_config.region.as_deref(), Some("eu-west-1"));
        assert_eq!(env.host_config.tenant_org_id.as_deref(), Some("acme"));
        assert_eq!(
            env.host_config.listen_addr,
            Some("0.0.0.0:9090".parse().unwrap())
        );
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn update_rejects_missing_env() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // env_id stays "local" so the A7 authorize gate allows the call
        // through; the NotFound branch is what we want to assert.
        let err = update(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "x".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn list_returns_sorted_envs() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("alpha")).unwrap();
        store.save(&make_env("beta")).unwrap();
        store.save(&make_env("gamma")).unwrap();
        let outcome = list(&store, &OpFlags::default()).unwrap();
        let envs = outcome
            .result
            .get("environments")
            .and_then(|v| v.as_array())
            .expect("environments array");
        let names: Vec<&str> = envs
            .iter()
            .filter_map(|e| e.get("environment_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn init_creates_local_env_when_missing() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let outcome = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        assert_eq!(outcome.op, "init");
        assert_eq!(outcome.noun, "env");
        assert_eq!(
            outcome.result.get("outcome").and_then(|v| v.as_str()),
            Some("created")
        );
        assert_eq!(
            outcome.result.get("pack_count").and_then(|v| v.as_u64()),
            Some(5)
        );
        // No `added_slots` key on "created" — that's a "healed" thing.
        assert!(outcome.result.get("added_slots").is_none());
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.packs.len(), 5);
    }

    #[test]
    fn init_heals_partially_bound_env() {
        use crate::defaults::LOCAL_DEPLOYER_PACK;
        use greentic_deploy_spec::{CapabilitySlot, EnvPackBinding, PackDescriptor, PackId};

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // Seed an env with only the deployer slot bound — mimics the
        // `op env create local` → empty-packs → user adds one binding flow.
        let mut env = make_env("local");
        env.packs = vec![EnvPackBinding {
            slot: CapabilitySlot::Deployer,
            kind: PackDescriptor::try_new(LOCAL_DEPLOYER_PACK).unwrap(),
            pack_ref: PackId::new(LOCAL_DEPLOYER_PACK),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        }];
        store.save(&env).unwrap();

        let outcome = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        assert_eq!(
            outcome.result.get("outcome").and_then(|v| v.as_str()),
            Some("healed")
        );
        let added: Vec<String> = outcome
            .result
            .get("added_slots")
            .and_then(|v| v.as_array())
            .expect("added_slots present on healed")
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert_eq!(
            added,
            vec!["secrets", "telemetry", "sessions", "state"],
            "only the 4 missing slots are reported as added"
        );
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.packs.len(), 5);
    }

    #[test]
    fn init_is_idempotent_and_reports_untouched_on_second_call() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        let outcome = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        assert_eq!(
            outcome.result.get("outcome").and_then(|v| v.as_str()),
            Some("untouched")
        );
        assert!(outcome.result.get("added_slots").is_none());
    }

    #[test]
    fn init_seeds_operator_key_into_env_trust_root_on_first_run() {
        // N1.4: env init folds the former `trust-root bootstrap` step so
        // first-run installs end up with a signature-ready env in one
        // command. The trust-root summary rides on the init outcome under
        // a nested `trust_root` key (non-null on FIRST init only).
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let outcome = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        let trust_root = outcome
            .result
            .get("trust_root")
            .expect("init outcome carries `trust_root`");
        assert!(
            trust_root.is_object(),
            "first init must seed and surface the summary, got {trust_root:?}"
        );
        assert_eq!(
            trust_root.get("environment_id").and_then(|v| v.as_str()),
            Some("local")
        );
        let key_id = trust_root
            .get("operator_key_id")
            .and_then(|v| v.as_str())
            .expect("operator_key_id present");
        assert!(!key_id.is_empty(), "operator_key_id must not be empty");
        assert!(
            trust_root
                .get("operator_public_key_pem")
                .and_then(|v| v.as_str())
                .is_some_and(|pem| pem.starts_with("-----BEGIN PUBLIC KEY-----"))
        );
        assert_eq!(
            trust_root.get("trusted_key_count").and_then(|v| v.as_u64()),
            Some(1),
            "first init seeds exactly one operator key"
        );

        // The trust-root file on disk must contain the same key as the
        // dedicated `trust-root list` verb would report.
        let listed = super::super::trust_root::list(&store, &OpFlags::default(), "local").unwrap();
        let keys = listed.result["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["key_id"].as_str(), Some(key_id));
    }

    #[test]
    fn second_init_does_not_re_touch_trust_root() {
        // The seed gate sits on `<env_dir>/trust-root.json`'s presence. A
        // second init must report `trust_root: null` and leave the
        // already-seeded key alone — no duplicate entry, no replace.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let first = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        let first_key_id = first.result["trust_root"]["operator_key_id"]
            .as_str()
            .expect("first init seeded a key")
            .to_string();
        let second = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        // `is_some_and(is_null)` distinguishes "key present, null value"
        // from "key absent" — bare `.is_null()` on indexed Value returns
        // true for both, masking a future serde change that drops the key.
        let tr = second
            .result
            .as_object()
            .expect("outcome is a JSON object")
            .get("trust_root");
        assert!(
            tr.is_some_and(|v| v.is_null()),
            "second init must report `trust_root: null` (got {tr:?})"
        );
        let listed = super::super::trust_root::list(&store, &OpFlags::default(), "local").unwrap();
        let keys = listed.result["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1, "second init must not duplicate the key");
        assert_eq!(keys[0]["key_id"].as_str(), Some(first_key_id.as_str()));
    }

    #[test]
    fn init_does_not_re_seed_after_operator_key_was_removed() {
        // SECURITY REGRESSION (Codex N1.4 adversarial review): `init` is a
        // routine maintenance verb. `trust-root remove` is the documented
        // revocation boundary for revenue-policy / bundle DSSE signing.
        // Once the operator has explicitly revoked the operator key, a
        // later `init` MUST NOT silently re-grant trust — explicit
        // re-grant goes through `gtc op trust-root bootstrap`.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());

        // First init seeds the operator key.
        let first = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        let key_id = first.result["trust_root"]["operator_key_id"]
            .as_str()
            .expect("first init seeded a key")
            .to_string();

        // Operator explicitly revokes the operator key.
        super::super::trust_root::remove(
            &store,
            &OpFlags::default(),
            Some(super::super::trust_root::TrustRootRemovePayload {
                environment_id: "local".into(),
                key_id: key_id.clone(),
            }),
        )
        .unwrap();
        let listed = super::super::trust_root::list(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(
            listed.result["keys"].as_array().unwrap().len(),
            0,
            "precondition: remove must clear the trust root"
        );

        // Second init MUST NOT re-seed. Use the key-present-and-null check
        // so a future serde regression that drops the field is also caught.
        let second = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        let tr = second
            .result
            .as_object()
            .expect("outcome is a JSON object")
            .get("trust_root");
        assert!(
            tr.is_some_and(|v| v.is_null()),
            "init must not re-grant trust on a revoked key (got {tr:?})"
        );
        let listed = super::super::trust_root::list(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(
            listed.result["keys"].as_array().unwrap().len(),
            0,
            "revoked key must STAY absent across subsequent init runs"
        );
    }

    #[test]
    fn doctor_reports_missing_slots() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let outcome = doctor(&store, &OpFlags::default(), "local").unwrap();
        let missing = outcome
            .result
            .get("missing_slots")
            .and_then(|v| v.as_array())
            .expect("missing_slots array");
        // No packs bound → every CORE slot missing. The N-per-env slots
        // (Messaging, Extension) live in their own collections and never
        // appear in missing_slots.
        let core_slots = greentic_deploy_spec::CapabilitySlot::ALL
            .iter()
            .filter(|s| s.binds_in_packs())
            .count();
        assert_eq!(missing.len(), core_slots);
        assert!(
            missing
                .iter()
                .all(|s| s.as_str() != Some("messaging") && s.as_str() != Some("extension")),
            "N-per-env slots must not appear in missing_slots"
        );
    }

    #[test]
    fn doctor_reports_extensions_separately() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        // No extension handler is registered in `with_builtins`, so an
        // extension binding surfaces under the `extensions` block as an
        // unknown kind — never in `missing_slots`.
        env.extensions.push(greentic_deploy_spec::ExtensionBinding {
            kind: greentic_deploy_spec::PackDescriptor::try_new("acme.oauth.auth0@1.0.0").unwrap(),
            pack_ref: greentic_deploy_spec::PackId::new("pack-ext"),
            instance_id: Some("primary".to_string()),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        });
        store.save(&env).unwrap();
        let outcome = doctor(&store, &OpFlags::default(), "local").unwrap();
        let ext = outcome
            .result
            .get("extensions")
            .expect("extensions report block");
        assert_eq!(ext.get("count").and_then(|v| v.as_u64()), Some(1));
        let unknown = ext
            .get("unknown_kinds")
            .and_then(|v| v.as_array())
            .expect("extension unknown_kinds array");
        assert_eq!(unknown.len(), 1);
        assert!(unknown[0].as_str().unwrap().contains("acme.oauth.auth0"));
        // The extension's path is NOT in missing_slots / unknown_kinds (the
        // core-`packs` buckets).
        let core_unknown = outcome
            .result
            .get("unknown_kinds")
            .and_then(|v| v.as_array())
            .expect("core unknown_kinds array");
        assert!(core_unknown.is_empty());
    }

    #[test]
    fn doctor_flags_unknown_kind_and_slot_mismatch() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        // Unknown descriptor: no native handler backs `acme-vault`.
        env.packs.push(make_binding(
            greentic_deploy_spec::CapabilitySlot::Secrets,
            "greentic.secrets.acme-vault@1.0.0",
        ));
        // Slot mismatch: the State slot bound to a deployer handler's descriptor.
        env.packs.push(make_binding(
            greentic_deploy_spec::CapabilitySlot::State,
            "greentic.deployer.local-process@0.1.0",
        ));
        store.save(&env).unwrap();
        let outcome = doctor(&store, &OpFlags::default(), "local").unwrap();
        let unknown = outcome
            .result
            .get("unknown_kinds")
            .and_then(|v| v.as_array())
            .expect("unknown_kinds array");
        assert_eq!(unknown.len(), 1);
        assert!(unknown[0].as_str().unwrap().contains("acme-vault"));
        let mismatches = outcome
            .result
            .get("slot_mismatches")
            .and_then(|v| v.as_array())
            .expect("slot_mismatches array");
        assert_eq!(mismatches.len(), 1);
        assert_eq!(
            mismatches[0].get("handler_slot").and_then(|v| v.as_str()),
            Some("deployer")
        );
        assert_eq!(
            mismatches[0].get("bound_slot").and_then(|v| v.as_str()),
            Some("state")
        );
    }

    #[test]
    fn doctor_accepts_built_in_bindings() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            greentic_deploy_spec::CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@0.1.0",
        ));
        store.save(&env).unwrap();
        let outcome = doctor(&store, &OpFlags::default(), "local").unwrap();
        for field in ["unknown_kinds", "slot_mismatches", "version_skew"] {
            assert!(
                outcome
                    .result
                    .get(field)
                    .and_then(|v| v.as_array())
                    .unwrap()
                    .is_empty(),
                "{field} should be empty for a built-in binding at its supported version"
            );
        }
    }

    #[test]
    fn doctor_flags_unsupported_version() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        // Known path + correct slot, but a version the built-in doesn't implement.
        env.packs.push(make_binding(
            greentic_deploy_spec::CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@9.9.9",
        ));
        store.save(&env).unwrap();
        let outcome = doctor(&store, &OpFlags::default(), "local").unwrap();
        let skew = outcome
            .result
            .get("version_skew")
            .and_then(|v| v.as_array())
            .expect("version_skew array");
        assert_eq!(skew.len(), 1);
        assert_eq!(
            skew[0].get("requested").and_then(|v| v.as_str()),
            Some("9.9.9")
        );
        assert_eq!(
            skew[0].get("supported").and_then(|v| v.as_str()),
            Some("^0.1.0")
        );
        // A version-skewed binding is not also reported as unknown.
        assert!(
            outcome
                .result
                .get("unknown_kinds")
                .and_then(|v| v.as_array())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn tool_check_returns_empty_per_binding_for_local_builtins() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        for (slot, descriptor) in crate::defaults::LOCAL_DEFAULT_BINDINGS {
            env.packs.push(make_binding(*slot, descriptor));
        }
        store.save(&env).unwrap();
        let outcome = tool_check(&store, &OpFlags::default(), "local").unwrap();
        let bindings = outcome
            .result
            .get("bindings")
            .and_then(|v| v.as_array())
            .expect("bindings array");
        assert_eq!(
            bindings.len(),
            crate::defaults::LOCAL_DEFAULT_BINDINGS.len()
        );
        for entry in bindings {
            let checks = entry
                .get("checks")
                .and_then(|v| v.as_array())
                .expect("checks array on binding");
            assert!(
                checks.is_empty(),
                "Phase A built-in handler should report no external tool checks"
            );
        }
        assert_eq!(
            outcome.result.get("total_checks").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            outcome.result.get("failed_checks").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert!(
            outcome
                .result
                .get("unresolved_bindings")
                .and_then(|v| v.as_array())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn tool_check_surfaces_unresolved_bindings_alongside_resolved() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        // One resolvable built-in + one bogus kind so the verb has to
        // distinguish the two paths.
        env.packs.push(make_binding(
            greentic_deploy_spec::CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@0.1.0",
        ));
        env.packs.push(make_binding(
            greentic_deploy_spec::CapabilitySlot::Deployer,
            "greentic.deployer.does-not-exist@0.1.0",
        ));
        store.save(&env).unwrap();
        let outcome = tool_check(&store, &OpFlags::default(), "local").unwrap();
        let bindings = outcome
            .result
            .get("bindings")
            .and_then(|v| v.as_array())
            .expect("bindings array");
        assert_eq!(bindings.len(), 1, "only the resolvable binding is reported");
        let unresolved = outcome
            .result
            .get("unresolved_bindings")
            .and_then(|v| v.as_array())
            .expect("unresolved_bindings array");
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            unresolved[0].get("kind").and_then(|v| v.as_str()),
            Some("greentic.deployer.does-not-exist@0.1.0")
        );
        assert!(
            unresolved[0]
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false)
        );
    }

    #[test]
    fn tool_check_schema_only_returns_input_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let flags = OpFlags {
            schema_only: true,
            ..Default::default()
        };
        let outcome = tool_check(&store, &flags, "local").unwrap();
        assert_eq!(outcome.op, "tool-check");
        assert!(outcome.result.get("input_schema").is_some());
    }

    #[test]
    fn tool_check_missing_env_errors_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = tool_check(&store, &OpFlags::default(), "local").unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn destroy_without_confirm_errors() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = destroy(&store, &OpFlags::default(), "local", false, false).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn destroy_with_confirm_removes_env_state() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("doomed")).unwrap();
        // Seed sidecars beyond environment.json so the test proves the whole
        // tree goes, not just the file `exists()` checks.
        let env_dir = dir.path().join("doomed");
        std::fs::write(env_dir.join("trust-root.json"), b"{}").unwrap();
        let nested = env_dir.join("env-packs").join("messaging");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("answers.json"), b"{}").unwrap();

        let outcome = destroy(&store, &OpFlags::default(), "doomed", true, false).unwrap();
        assert_eq!(outcome.noun, "env");
        assert_eq!(outcome.op, "destroy");
        assert_eq!(outcome.result["environment_id"], "doomed");
        assert_eq!(outcome.result["outcome"], "destroyed");
        assert_eq!(
            outcome.result["removed_path"],
            env_dir.display().to_string()
        );

        // Live state is gone; only the post-verb audit residue may remain.
        assert!(!env_dir.join("environment.json").exists());
        assert!(!env_dir.join("trust-root.json").exists());
        assert!(!env_dir.join("env-packs").exists());
        assert!(!store.exists(&EnvId::try_from("doomed").unwrap()).unwrap());
        assert!(store.list().unwrap().is_empty());
        // A clean purge emits no reaped_tombstones key.
        assert!(
            outcome.result.get("reaped_tombstones").is_none(),
            "clean destroy must not include reaped_tombstones"
        );
        // A clean purge leaves no tombstone sibling behind.
        let tombstones: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".destroyed~"))
            .collect();
        assert!(tombstones.is_empty(), "got {tombstones:?}");
    }

    #[test]
    fn destroy_missing_env_errors_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = destroy(&store, &OpFlags::default(), "ghost", true, false).unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn destroy_leaves_sibling_envs_untouched() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("doomed")).unwrap();
        store.save(&make_env("survivor")).unwrap();
        destroy(&store, &OpFlags::default(), "doomed", true, false).unwrap();
        let survivor = EnvId::try_from("survivor").unwrap();
        assert!(store.exists(&survivor).unwrap());
        store.load(&survivor).expect("survivor still loads");
        assert_eq!(store.list().unwrap(), vec![survivor]);
    }

    /// `is_cloudrun_kind` recognizes only the Cloud Run descriptor path.
    #[cfg(feature = "creds-gcp")]
    #[test]
    fn is_cloudrun_kind_recognizes_only_cloudrun() {
        use greentic_deploy_spec::PackDescriptor;
        let cr = PackDescriptor::try_new("greentic.deployer.gcp-cloudrun@1.0.0").unwrap();
        let k8s = PackDescriptor::try_new("greentic.deployer.k8s@1.0.0").unwrap();
        assert!(is_cloudrun_kind(&cr));
        assert!(!is_cloudrun_kind(&k8s));
    }

    #[test]
    fn destroy_schema_flag_short_circuits_without_touching_store() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("doomed")).unwrap();
        let flags = OpFlags {
            schema_only: true,
            answers: None,
        };
        // No --confirm needed for a schema dump.
        let outcome = destroy(&store, &flags, "doomed", false, false).unwrap();
        assert_eq!(outcome.op, "destroy");
        assert!(store.exists(&EnvId::try_from("doomed").unwrap()).unwrap());
    }

    #[test]
    fn destroy_records_audit_event_in_recreated_residue_log() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // Create via the CLI verb so a `create` audit event exists first —
        // proving destroy takes prior history with the env.
        create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "doomed".to_string(),
                name: "doomed".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap();
        destroy(&store, &OpFlags::default(), "doomed", true, false).unwrap();
        // The audit event appends AFTER the mutation closure, so it lands in
        // a recreated `<env_id>/audit/` residue dir; only the destroy event
        // survives (the create event went with the env).
        let log = dir.path().join("doomed").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<_> = raw.lines().collect();
        assert_eq!(lines.len(), 1, "only the destroy event survives: {raw}");
        let event: crate::environment::AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(event.env_id, "doomed");
        assert_eq!(event.noun, "env");
        assert_eq!(event.verb, "destroy");
        assert!(matches!(event.result, crate::environment::AuditResult::Ok));
    }

    #[test]
    fn destroy_then_init_yields_fresh_env_and_reseeded_trust_root() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let first = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        assert!(first.result["trust_root"].is_object());
        let env_dir = dir.path().join("local");
        assert!(env_dir.join("trust-root.json").exists());

        destroy(&store, &OpFlags::default(), "local", true, false).unwrap();
        assert!(!env_dir.join("trust-root.json").exists());

        let second = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        assert_eq!(second.result["outcome"], "created");
        // The seed gate is trust-root.json presence; destroy removed it, so
        // re-init runs the seed path again. The operator key is unchanged,
        // so this asserts the PATH was taken, not that key material differs.
        assert!(second.result["trust_root"].is_object());
        // Audit continuity: the residue log bridges destroy → init.
        let raw = std::fs::read_to_string(env_dir.join("audit").join("events.jsonl")).unwrap();
        let verbs: Vec<String> = raw
            .lines()
            .map(|l| {
                serde_json::from_str::<crate::environment::AuditEvent>(l)
                    .unwrap()
                    .verb
            })
            .collect();
        assert_eq!(verbs, vec!["destroy".to_string(), "init".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn destroy_cleanup_failure_is_committed_and_audited() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("doomed")).unwrap();
        let env_dir = dir.path().join("doomed");
        // A write-protected dir with a child makes remove_dir_all fail after
        // the (committing) rename already happened.
        let blocked = env_dir.join("blocked");
        std::fs::create_dir_all(&blocked).unwrap();
        std::fs::write(blocked.join("child"), b"x").unwrap();
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o555)).unwrap();

        let err = destroy(&store, &OpFlags::default(), "doomed", true, false).unwrap_err();

        // The tombstone survives the failed purge; restore permissions so
        // TempDir::drop can clean up.
        let tombstone = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| e.file_name().to_string_lossy().contains(".destroyed~"))
            .expect("tombstone must remain after failed purge");
        std::fs::set_permissions(
            tombstone.path().join("blocked"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        // CommittedAfterSave was unwrapped by the noun-preserving mapper to
        // the inner Io (surfacing as `store`)...
        assert!(matches!(err, OpError::Store(_)), "got {err:?}");
        // ...the rename committed (the canonical path no longer holds the env)...
        assert!(!env_dir.join("environment.json").exists());
        assert!(!store.exists(&EnvId::try_from("doomed").unwrap()).unwrap());
        // ...and mark_committed fired, so the fail-closed audit boundary
        // still appended the (error-result) destroy event.
        let raw = std::fs::read_to_string(env_dir.join("audit").join("events.jsonl")).unwrap();
        let event: crate::environment::AuditEvent = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(event.verb, "destroy");
        assert!(matches!(
            event.result,
            crate::environment::AuditResult::Error { .. }
        ));

        // Re-running destroy reaps the stale tombstone (permissions already
        // restored above).
        let outcome = destroy(&store, &OpFlags::default(), "doomed", true, false).unwrap();
        assert_eq!(outcome.result["outcome"], "destroyed");
        assert_eq!(outcome.result["reaped_tombstones"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn destroy_refuses_symlinked_env_root() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // The real env tree lives under a different root; the store path is
        // a symlink to it.
        let target = tempdir().unwrap();
        let real_store = LocalFsStore::new(target.path());
        real_store.save(&make_env("linked")).unwrap();
        std::os::unix::fs::symlink(target.path().join("linked"), dir.path().join("linked"))
            .unwrap();

        let err = destroy(&store, &OpFlags::default(), "linked", true, false).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        // The link target is untouched.
        assert!(
            target
                .path()
                .join("linked")
                .join("environment.json")
                .exists()
        );
    }

    #[test]
    fn create_non_local_env_succeeds_and_audits_under_local_owner() {
        // Named (non-`local`) envs are first-class on the local FS store
        // (fs-ownership is the authz boundary). `op env create prod` succeeds,
        // persists the env, and audits the mutation under the `local-owner`
        // policy. (Shared-store RBAC lives on the remote path, not here.)
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "prod".to_string(),
                name: "prod".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .expect("named env create must succeed on the local store");
        // environment.json was persisted.
        let env_json = dir.path().join("prod").join("environment.json");
        assert!(env_json.exists(), "create must persist environment.json");
        // The mutation was audited as an allowed `local-owner` decision.
        let log = dir.path().join("prod").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).expect("audit log must exist after create");
        let event: crate::environment::AuditEvent = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(event.env_id, "prod");
        assert_eq!(event.noun, "env");
        assert_eq!(event.verb, "create");
        match event.authorization {
            crate::environment::AuditDecision::Allow { policy, .. } => {
                assert_eq!(policy, crate::environment::POLICY_LOCAL_OWNER);
            }
            other => panic!("expected Allow, got {other:?}"),
        }
        assert!(matches!(event.result, crate::environment::AuditResult::Ok));
    }

    #[test]
    fn create_local_env_writes_ok_audit_event() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap();
        let log = dir.path().join("local").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).unwrap();
        let event: crate::environment::AuditEvent = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(event.noun, "env");
        assert_eq!(event.verb, "create");
        matches!(
            event.authorization,
            crate::environment::AuditDecision::Allow { .. }
        );
        matches!(event.result, crate::environment::AuditResult::Ok);
    }

    // ---- Change C: env public_url + auto-setWebhook ------------------------

    use super::super::dispatch::{EnvCreateArgs, EnvInitArgs, EnvUpdateArgs};

    fn args_with_url(url: &str) -> EnvCreateArgs {
        EnvCreateArgs {
            environment_id: Some("local".into()),
            name: Some("local".into()),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_url: Some(url.into()),
        }
    }

    #[test]
    fn env_create_args_into_payload_returns_none_when_no_inline_flags() {
        // `--answers` path: no inline flag → caller delegates to --answers.
        let args = EnvCreateArgs {
            environment_id: None,
            name: None,
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_url: None,
        };
        assert!(
            args.into_payload("create", &OpFlags::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn env_create_args_into_payload_with_public_url_round_trips() {
        let p = args_with_url("https://chat.example.com")
            .into_payload("create", &OpFlags::default())
            .unwrap()
            .expect("inline path");
        assert_eq!(p.environment_id, "local");
        assert_eq!(
            p.public_base_url.as_deref(),
            Some("https://chat.example.com")
        );
    }

    #[test]
    fn env_create_args_partial_inline_is_rejected_not_silent_fall_through() {
        // Codex-finding regression guard (same shape as the messaging.endpoint
        // verbs): SOME inline flags + missing required ones MUST error out
        // explicitly — never silently drop back to `--answers` which could
        // mutate the wrong env.
        let args = EnvCreateArgs {
            environment_id: None, // missing required
            name: Some("local".into()),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_url: Some("https://chat.example.com".into()),
        };
        let err = args
            .into_payload("create", &OpFlags::default())
            .expect_err("should reject");
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn env_create_args_inline_plus_answers_rejected() {
        // Mutual exclusion: inline flags + --answers together is ambiguous and
        // rejected at the converter (Change B precedent).
        let flags = OpFlags {
            answers: Some(std::path::PathBuf::from("/tmp/x.json")),
            ..Default::default()
        };
        let err = args_with_url("https://chat.example.com")
            .into_payload("create", &flags)
            .expect_err("should reject");
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn env_create_with_public_url_persists_and_validates() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: Some("https://chat.example.com".to_string()),
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://chat.example.com")
        );
    }

    #[test]
    fn env_create_rejects_invalid_public_url_before_touching_disk() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = create(
            &store,
            &OpFlags::default(),
            Some(EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "local".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: Some("https://chat.example.com/path?x=1".to_string()),
            }),
        )
        .expect_err("invalid URL must fail");
        assert!(matches!(err, OpError::InvalidArgument(_)));
        // No env was written.
        assert!(!store.exists(&EnvId::try_from("local").unwrap()).unwrap());
    }

    #[test]
    fn env_init_with_public_url_sets_field_on_creation() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let args = EnvInitArgs {
            public_url: Some("https://demo.greentic.ai".into()),
        };
        let payload = args.into_payload(&OpFlags::default()).unwrap();
        init(&store, &OpFlags::default(), payload).unwrap();
        let env = store
            .load(&EnvId::try_from(crate::defaults::LOCAL_ENV_ID).unwrap())
            .unwrap();
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://demo.greentic.ai")
        );
    }

    #[test]
    fn env_init_rejects_public_url_when_env_already_exists() {
        // init with --public-url on an existing env must error out. The URL is
        // only applied on creation; overwriting requires `op env set-public-url`.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        init(
            &store,
            &OpFlags::default(),
            EnvInitPayload {
                public_base_url: Some("https://first.example.com".into()),
            },
        )
        .unwrap();
        let err = init(
            &store,
            &OpFlags::default(),
            EnvInitPayload {
                public_base_url: Some("https://second.example.com".into()),
            },
        )
        .expect_err("second init with --public-url must error");
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        // First env's URL unchanged.
        let env = store
            .load(&EnvId::try_from(crate::defaults::LOCAL_ENV_ID).unwrap())
            .unwrap();
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://first.example.com"),
            "existing URL must be preserved"
        );
    }

    #[test]
    fn env_init_without_public_url_stays_idempotent_on_existing_env() {
        // init WITHOUT --public-url on an existing env must remain the silent
        // no-op/heal bootstrap it always was.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        init(
            &store,
            &OpFlags::default(),
            EnvInitPayload {
                public_base_url: Some("https://first.example.com".into()),
            },
        )
        .unwrap();
        let outcome = init(&store, &OpFlags::default(), EnvInitPayload::default()).unwrap();
        assert_eq!(
            outcome.result.get("outcome").and_then(|v| v.as_str()),
            Some("untouched")
        );
    }

    #[test]
    fn env_init_includes_persisted_public_url_in_outcome() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let outcome = init(
            &store,
            &OpFlags::default(),
            EnvInitPayload {
                public_base_url: Some("https://demo.greentic.ai".into()),
            },
        )
        .unwrap();
        assert_eq!(
            outcome
                .result
                .get("public_base_url")
                .and_then(|v| v.as_str()),
            Some("https://demo.greentic.ai"),
            "outcome must surface the persisted public_base_url"
        );
    }

    #[test]
    fn env_init_rejects_invalid_public_url_up_front() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = init(
            &store,
            &OpFlags::default(),
            EnvInitPayload {
                public_base_url: Some("ftp://nope.example.com".into()),
            },
        )
        .expect_err("non-http scheme must fail");
        assert!(matches!(err, OpError::InvalidArgument(_)));
        // No env was written.
        assert!(
            !store
                .exists(&EnvId::try_from(crate::defaults::LOCAL_ENV_ID).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn set_public_url_updates_existing_env() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        set_public_url(
            &store,
            &OpFlags::default(),
            "local",
            "https://chat.example.com",
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://chat.example.com")
        );
    }

    #[test]
    fn set_public_url_strips_trailing_slash() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        set_public_url(
            &store,
            &OpFlags::default(),
            "local",
            "https://chat.example.com/",
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        // Trailing slash normalized away — runtime precedence matching is
        // origin-equality so the canonical form must drop the `/`.
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://chat.example.com")
        );
    }

    #[test]
    fn set_public_url_rejects_invalid_origin() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = set_public_url(
            &store,
            &OpFlags::default(),
            "local",
            "https://chat.example.com/path",
        )
        .expect_err("path-bearing URL must fail");
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn set_public_url_unknown_env_errors_and_no_state_written() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = set_public_url(
            &store,
            &OpFlags::default(),
            "missing",
            "https://chat.example.com",
        )
        .expect_err("missing env must fail");
        // Exact `OpError` variant depends on `audit_and_record` plumbing —
        // tighten to NotFound once the audit wrapper stops eagerly wrapping
        // store errors. For now assert no env file was written by the verb.
        let _ = err;
        assert!(!store.exists(&EnvId::try_from("missing").unwrap()).unwrap());
    }

    // ---- Fix 1: EnvUpdateArgs does not expose --public-url or --listen-addr ----

    #[test]
    fn env_update_args_does_not_expose_public_url_inline() {
        // Even when reached via --answers JSON (the legacy contract), the
        // produced payload carries public_base_url: None.
        let args = EnvUpdateArgs {
            environment_id: Some("local".into()),
            name: Some("local".into()),
            region: Some("eu-west-1".into()),
            tenant_org_id: None,
        };
        let payload = args
            .into_payload("update", &OpFlags::default())
            .unwrap()
            .expect("inline path");
        assert_eq!(payload.public_base_url, None);
        assert_eq!(payload.listen_addr, None);
        assert_eq!(payload.region.as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn env_update_args_rejects_partial_inline() {
        // SOME inline flags + missing required → error, never silent --answers fallthrough.
        let args = EnvUpdateArgs {
            environment_id: None, // missing required
            name: Some("local".into()),
            region: None,
            tenant_org_id: None,
        };
        let err = args
            .into_payload("update", &OpFlags::default())
            .expect_err("should reject");
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    // -- render -------------------------------------------------------------

    use crate::cli::dispatch::EnvRenderArgs;
    use std::path::PathBuf;

    /// `K8sParams::for_env` env-level set: Namespace, env-store ConfigMap,
    /// runtime-config ConfigMap, router Deployment + Service + PDB, 6
    /// NetworkPolicies (the worker- and router-egress policies are always
    /// rendered; their egress rule toggles allow-all/deny by pullability — see
    /// the manifests-crate render tests). Every env renders exactly these.
    const K8S_ENV_LEVEL_OBJECT_COUNT: usize = 12;

    fn render_args(env_id: &str, kind: Option<&str>, output: Option<PathBuf>) -> EnvRenderArgs {
        EnvRenderArgs {
            env_id: env_id.to_string(),
            kind: kind.map(str::to_string),
            output,
        }
    }

    fn builtins() -> crate::env_packs::EnvPackRegistry {
        crate::env_packs::EnvPackRegistry::with_builtins()
    }

    fn store_with_k8s_env(dir: &std::path::Path) -> LocalFsStore {
        use crate::cli::tests_common::make_binding;
        let store = LocalFsStore::new(dir);
        let mut env = make_env("zain");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.k8s@1.0.0",
        ));
        store.save(&env).unwrap();
        store
    }

    #[test]
    fn render_embeds_manifests_without_output() {
        let dir = tempdir().unwrap();
        let store = store_with_k8s_env(dir.path());
        let reg = builtins();
        let outcome = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, None),
        )
        .unwrap();
        assert_eq!(outcome.op, "render");
        assert_eq!(
            outcome.result.get("kind").and_then(Value::as_str),
            Some("greentic.deployer.k8s@1.0.0"),
            "kind defaults to the env's deployer binding"
        );
        let manifests = outcome
            .result
            .get("manifests")
            .and_then(Value::as_array)
            .expect("manifests embedded when --output is absent");
        assert_eq!(manifests.len(), K8S_ENV_LEVEL_OBJECT_COUNT);
        assert_eq!(
            outcome.result.get("object_count").and_then(Value::as_u64),
            Some(K8S_ENV_LEVEL_OBJECT_COUNT as u64)
        );
        assert_eq!(
            manifests[0].get("kind").and_then(Value::as_str),
            Some("Namespace"),
            "apply order starts with the Namespace"
        );
    }

    #[test]
    fn render_writes_apply_ordered_yaml_files() {
        let dir = tempdir().unwrap();
        let store = store_with_k8s_env(dir.path());
        let reg = builtins();
        let out = dir.path().join("rendered");
        let outcome = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, Some(out.clone())),
        )
        .unwrap();
        assert!(outcome.result.get("manifests").is_none());
        let files: Vec<String> = outcome
            .result
            .get("files")
            .and_then(Value::as_array)
            .expect("files list")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(files.len(), K8S_ENV_LEVEL_OBJECT_COUNT);
        assert_eq!(files[0], "00-namespace-gtc-zain.yaml");
        assert_eq!(
            outcome
                .result
                .get("removed_stale_files")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        for name in &files {
            let raw = std::fs::read_to_string(out.join(name)).expect("rendered file exists");
            let _: Value = serde_yaml_bw::from_str(&raw).expect("file parses back as YAML");
        }
    }

    #[test]
    fn render_removes_stale_managed_files_and_reports_unmanaged() {
        let dir = tempdir().unwrap();
        let store = store_with_k8s_env(dir.path());
        let reg = builtins();
        let out = dir.path().join("rendered");
        std::fs::create_dir_all(&out).unwrap();
        // A render-managed pattern file (digits + dash prefix) from a
        // previous render — must be deleted.
        std::fs::write(
            out.join("99-deployment-gtc-worker-old.yaml"),
            "kind: Deployment\n",
        )
        .unwrap();
        // A user-owned file — must survive.
        std::fs::write(
            out.join("kustomization.yaml"),
            "apiVersion: kustomize.config.k8s.io/v1beta1\n",
        )
        .unwrap();
        // Non-YAML — silently ignored.
        std::fs::write(out.join("notes.txt"), "not a manifest\n").unwrap();
        let outcome = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, Some(out.clone())),
        )
        .unwrap();
        // Managed stale file was removed from disk.
        assert!(
            !out.join("99-deployment-gtc-worker-old.yaml").exists(),
            "stale managed file must be deleted from disk"
        );
        assert_eq!(
            outcome.result.get("removed_stale_files"),
            Some(&json!(["99-deployment-gtc-worker-old.yaml"])),
        );
        // Unmanaged file survives on disk.
        assert!(out.join("kustomization.yaml").exists());
        assert_eq!(
            outcome.result.get("unmanaged_files"),
            Some(&json!(["kustomization.yaml"])),
        );
        // Re-render into the same dir is idempotent: no stale files.
        let outcome2 = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, Some(out)),
        )
        .unwrap();
        assert_eq!(
            outcome2
                .result
                .get("removed_stale_files")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0),
            "idempotent re-render must report empty removed_stale_files"
        );
    }

    #[test]
    fn render_bare_path_kind_must_match_the_binding() {
        let dir = tempdir().unwrap();
        let store = store_with_k8s_env(dir.path());
        let reg = builtins();
        // Bare path matching the binding reuses its pinned version.
        let outcome = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", Some("greentic.deployer.k8s"), None),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("kind").and_then(Value::as_str),
            Some("greentic.deployer.k8s@1.0.0")
        );
        // A bare path that matches nothing is rejected — no version guessing.
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", Some("greentic.deployer.other"), None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn render_without_deployer_binding_requires_kind() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        store.save(&make_env("bare")).unwrap();
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("bare", None, None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "{err}");
        // An explicit full descriptor renders an unbound kind (preview).
        let outcome = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("bare", Some("greentic.deployer.k8s@1.0.0"), None),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("object_count").and_then(Value::as_u64),
            Some(K8S_ENV_LEVEL_OBJECT_COUNT as u64)
        );
    }

    #[test]
    fn render_rejects_kind_without_a_renderer() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            crate::defaults::LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).unwrap();
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("local", None, None),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(msg.contains("does not support manifest rendering"), "{msg}")
            }
            other => panic!("expected Conflict, got {other}"),
        }
    }

    #[test]
    fn render_missing_env_is_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("ghost", None, None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "{err}");
    }

    #[test]
    fn render_schema_only_returns_input_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let flags = OpFlags {
            schema_only: true,
            ..OpFlags::default()
        };
        let outcome = render(&store, &reg, &flags, render_args("zain", None, None)).unwrap();
        assert!(outcome.result.get("input_schema").is_some());
    }

    // -- reconcile ----------------------------------------------------------

    use crate::cli::dispatch::EnvReconcileArgs;

    fn reconcile_args(env_id: &str, kind: Option<&str>) -> EnvReconcileArgs {
        EnvReconcileArgs {
            env_id: env_id.to_string(),
            kind: kind.map(str::to_string),
        }
    }

    /// A non-K8s deployer kind cannot be reconciled to a cluster — the verb
    /// rejects before any connect attempt (here the env's default binding is
    /// local-process).
    #[test]
    fn reconcile_rejects_non_k8s_deployer_kind() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            crate::defaults::LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).unwrap();
        let err = reconcile(
            &store,
            &reg,
            &OpFlags::default(),
            reconcile_args("local", None),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("only supported for"), "{msg}"),
            other => panic!("expected Conflict, got {other}"),
        }
    }

    #[test]
    fn reconcile_missing_env_is_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let err = reconcile(
            &store,
            &reg,
            &OpFlags::default(),
            reconcile_args("ghost", None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "{err}");
    }

    #[test]
    fn reconcile_schema_only_returns_input_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let flags = OpFlags {
            schema_only: true,
            ..OpFlags::default()
        };
        let outcome = reconcile(&store, &reg, &flags, reconcile_args("zain", None)).unwrap();
        assert_eq!(outcome.op, "reconcile");
        assert!(outcome.result.get("input_schema").is_some());
    }

    // -- apply-revision -----------------------------------------------------

    use crate::cli::dispatch::EnvApplyRevisionArgs;

    fn apply_revision_args(
        env_id: &str,
        revision_id: &str,
        kind: Option<&str>,
    ) -> EnvApplyRevisionArgs {
        EnvApplyRevisionArgs {
            env_id: env_id.to_string(),
            revision_id: revision_id.to_string(),
            kind: kind.map(str::to_string),
        }
    }

    /// A deployer kind with no live apply path (here: local-process) is
    /// rejected at the applicability gate, before the per-revision lookup (so a
    /// bogus revision id is irrelevant here). K8s and AWS-ECS are admitted.
    #[test]
    fn apply_revision_rejects_unsupported_deployer_kind() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            crate::defaults::LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).unwrap();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args("local", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(
                msg.contains("only supported for") && msg.contains("gcp-cloudrun"),
                "{msg}"
            ),
            other => panic!("expected Conflict, got {other}"),
        }
    }

    /// The Cloud Run kind is admitted past the applicability gate (unlike an
    /// unsupported deployer): a cloudrun env with a revision id that is not
    /// staged surfaces `NotFound(revision)` — the post-gate lookup — not the
    /// `unsupported` conflict. Proves the gate recognizes cloudrun.
    #[cfg(feature = "creds-gcp")]
    #[test]
    fn apply_revision_admits_cloudrun_past_gate() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.gcp-cloudrun@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args("local", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::NotFound(msg) => assert!(msg.contains("revision"), "{msg}"),
            other => {
                panic!("expected NotFound(revision) — the gate should admit cloudrun, got {other}")
            }
        }
    }

    /// The GCP Cloud Run deployer kind IS admitted past the applicability gate
    /// (this live-wiring slice): with a bogus revision id the verb falls through
    /// to the per-revision lookup and returns `NotFound`, where PR-2 rejected the
    /// whole kind with a stub `Conflict`. Proves the gate no longer hard-rejects
    /// cloudrun — no GCP call is reached (the revision lookup fails first), so the
    /// test is deterministic without credentials (mirrors
    /// `apply_revision_admits_aws_ecs_kind`).
    #[cfg(feature = "creds-gcp")]
    #[test]
    fn apply_revision_admits_cloudrun_kind() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.gcp-cloudrun@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args("local", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::NotFound(msg) => assert!(msg.contains("revision"), "{msg}"),
            other => panic!("expected NotFound(revision), got {other}"),
        }
    }

    /// The AWS-ECS deployer kind IS admitted past the applicability gate (the
    /// PR-3c-2b live-wiring change): with a bogus revision id the verb now falls
    /// through to the per-revision lookup and returns `NotFound`, where it
    /// previously rejected the whole kind with a `Conflict`. Proves the gate no
    /// longer hard-rejects AWS — no AWS call is reached (revision lookup fails
    /// first), so the test is deterministic without credentials.
    #[test]
    fn apply_revision_admits_aws_ecs_kind() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args("local", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::NotFound(msg) => assert!(msg.contains("revision"), "{msg}"),
            other => panic!("expected NotFound(revision), got {other}"),
        }
    }

    // -- apply-traffic ------------------------------------------------------

    use crate::cli::dispatch::EnvApplyTrafficArgs;

    fn apply_traffic_args(
        env_id: &str,
        deployment_id: &str,
        kind: Option<&str>,
    ) -> EnvApplyTrafficArgs {
        EnvApplyTrafficArgs {
            env_id: env_id.to_string(),
            deployment_id: deployment_id.to_string(),
            kind: kind.map(str::to_string),
        }
    }

    #[test]
    fn apply_traffic_schema_only_returns_input_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let flags = OpFlags {
            schema_only: true,
            ..OpFlags::default()
        };
        let outcome = apply_traffic(
            &store,
            &reg,
            &flags,
            apply_traffic_args("zain", "00000000000000000000000000", None),
        )
        .unwrap();
        assert_eq!(outcome.op, "apply-traffic");
        assert!(outcome.result.get("input_schema").is_some());
    }

    /// A non-AWS deployer (here: local-process) is rejected — K8s and the local
    /// deployer serve splits from their runtime router, so there is no listener
    /// for `apply-traffic` to push to.
    #[test]
    fn apply_traffic_rejects_non_aws_deployer_kind() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            crate::defaults::LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).unwrap();
        let err = apply_traffic(
            &store,
            &reg,
            &OpFlags::default(),
            apply_traffic_args("local", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(
                msg.contains("only supported for") && msg.contains("gcp-cloudrun"),
                "{msg}"
            ),
            other => panic!("expected Conflict, got {other}"),
        }
    }

    /// A cloudrun env IS admitted past the apply-traffic gate (Cloud Run has a
    /// native traffic-weight router, like the ALB listener) and reaches the live
    /// dispatch (this live-wiring slice). With no recorded split for the target
    /// deployment the pure `enforce_split_invariants` precondition fires first —
    /// before any Cloud Run API call — so the test is deterministic without
    /// credentials (mirrors `apply_traffic_admits_aws_ecs_but_requires_launch_config`,
    /// where the AWS launch-config check fires first).
    #[cfg(feature = "creds-gcp")]
    #[test]
    fn apply_traffic_admits_cloudrun_but_requires_recorded_split() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.gcp-cloudrun@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = apply_traffic(
            &store,
            &reg,
            &OpFlags::default(),
            apply_traffic_args("local", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("TrafficSplit"), "{msg}"),
            other => panic!("expected Conflict(no recorded split), got {other}"),
        }
    }

    /// `cloudrun_env_up` is `op env up`'s deployer-dispatch gate: it returns
    /// `None` for any non-Cloud-Run deployer so `op env up` falls through to its
    /// k8s convergence phases. A k8s-deployer env is the negative case (no GCP
    /// call, deterministic without credentials).
    #[test]
    fn cloudrun_env_up_is_none_for_non_cloudrun_deployer() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.k8s@1.0.0",
        ));
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        let out = cloudrun_env_up(&store, &reg, &env_id).unwrap();
        assert!(
            out.is_none(),
            "non-cloudrun deployer must fall through: {out:?}"
        );
    }

    /// A Cloud Run env IS dispatched into the bring-up arm. With zero present
    /// revisions the warm loop and the (empty) traffic loop do nothing — no Cloud
    /// Run API call — so the arm returns `Some` deterministically without
    /// credentials, proving `op env up` routes cloudrun envs here (mirrors
    /// `apply_traffic_admits_cloudrun_but_requires_recorded_split`).
    #[cfg(feature = "creds-gcp")]
    #[test]
    fn cloudrun_env_up_dispatches_to_cloudrun_arm_for_empty_env() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.gcp-cloudrun@1.0.0",
        ));
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        let out = cloudrun_env_up(&store, &reg, &env_id)
            .unwrap()
            .expect("cloudrun deployer must dispatch into the bring-up arm");
        assert!(
            out.get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .contains("gcp-cloudrun"),
            "dispatched under the cloudrun kind: {out:?}"
        );
        assert_eq!(
            out.get("warmed").and_then(|v| v.as_array()).map(Vec::len),
            Some(0),
            "no present revisions to warm"
        );
        assert_eq!(out.get("applied_splits").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            out.get("endpoints")
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(0),
            "no revision warmed → no endpoints"
        );
        assert!(
            out.get("endpoint_url").is_none(),
            "no revision warmed → no single-deployment URL: {out:?}"
        );
    }

    /// The bring-up preflights traffic representability BEFORE warming: a
    /// store-valid split whose weights are not whole multiples of 100 bps (plan
    /// D1) is rejected up front, so `op env up` never creates live Cloud Run
    /// revisions it cannot then route to. Deterministic — the preflight fires
    /// before any GCP call (Codex adversarial-review finding).
    #[cfg(feature = "creds-gcp")]
    #[test]
    fn cloudrun_env_up_rejects_non_representable_split_before_warming() {
        use crate::cli::tests_common::{
            make_binding, make_bundle_deployment, make_revision, make_traffic_split,
        };
        use greentic_deploy_spec::{RevisionLifecycle, TrafficSplitEntry};
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.gcp-cloudrun@1.0.0",
        ));
        let deployment = make_bundle_deployment("local", "demo-bundle");
        let r1 = make_revision(
            "local",
            "demo-bundle",
            &deployment.deployment_id,
            1,
            RevisionLifecycle::Ready,
        );
        let r2 = make_revision(
            "local",
            "demo-bundle",
            &deployment.deployment_id,
            2,
            RevisionLifecycle::Ready,
        );
        // 3333 / 6667 bps sums to 10000 (spec-valid) but 3333 % 100 != 0, so Cloud
        // Run's integer percent cannot represent it — the adapter must reject it.
        let mut split = make_traffic_split(
            "local",
            "demo-bundle",
            &deployment.deployment_id,
            &r1.revision_id,
            "01J000000000000000000000AA",
        );
        split.entries = vec![
            TrafficSplitEntry {
                revision_id: r1.revision_id,
                weight_bps: 3333,
            },
            TrafficSplitEntry {
                revision_id: r2.revision_id,
                weight_bps: 6667,
            },
        ];
        env.bundles.push(deployment);
        env.revisions.push(r1);
        env.revisions.push(r2);
        env.traffic_splits.push(split);
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        let err = cloudrun_env_up(&store, &reg, &env_id).unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("100 bps"), "{msg}"),
            other => panic!("expected Conflict(non-representable split), got {other}"),
        }
    }

    /// An AWS-ECS env IS admitted past the gate, but a binding without a Fargate
    /// launch config is rejected before any AWS call (deterministic, no creds).
    /// Proves the AWS path is reached AND the launch precondition fires first.
    #[cfg(feature = "deploy-aws-ecs")]
    #[test]
    fn apply_traffic_admits_aws_ecs_but_requires_launch_config() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = apply_traffic(
            &store,
            &reg,
            &OpFlags::default(),
            apply_traffic_args("local", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("Fargate launch config"), "{msg}"),
            other => panic!("expected Conflict(launch config), got {other}"),
        }
    }

    /// Identity guard: a binding that pins `assume_role_arn` must have a bound
    /// session, else the live AWS call would silently run as the ambient
    /// identity (a tenant/account-isolation footgun). Only that exact case
    /// refuses; an unpinned env legitimately falls back to ambient.
    #[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
    #[test]
    fn pinned_role_without_session_refuses_only_role_without_session() {
        // role pinned + no session → refuse (the footgun)
        assert!(pinned_role_without_session(
            Some("arn:aws:iam::1:role/dep"),
            false
        ));
        // role pinned + session present → ok (the session IS the assumed role)
        assert!(!pinned_role_without_session(
            Some("arn:aws:iam::1:role/dep"),
            true
        ));
        // no role pinned → ambient fallback is intentional, never refuse
        assert!(!pinned_role_without_session(None, false));
        assert!(!pinned_role_without_session(None, true));
    }

    #[test]
    fn apply_revision_missing_env_is_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args("ghost", "00000000000000000000000000", None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "{err}");
    }

    /// A K8s env with a revision id that isn't staged → NotFound, surfaced
    /// AFTER the applicability gate (the env IS K8s) but before any connect.
    #[test]
    fn apply_revision_missing_revision_is_not_found() {
        let dir = tempdir().unwrap();
        let store = store_with_k8s_env(dir.path());
        let reg = builtins();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args("zain", "00000000000000000000000000", None),
        )
        .unwrap_err();
        match err {
            OpError::NotFound(msg) => assert!(msg.contains("revision"), "{msg}"),
            other => panic!("expected NotFound(revision), got {other}"),
        }
    }

    /// An unparseable revision id is rejected as InvalidArgument (after the
    /// applicability gate passes).
    #[test]
    fn apply_revision_bad_revision_id_is_invalid_argument() {
        let dir = tempdir().unwrap();
        let store = store_with_k8s_env(dir.path());
        let reg = builtins();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args("zain", "not-a-ulid", None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn apply_revision_schema_only_returns_input_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let flags = OpFlags {
            schema_only: true,
            ..OpFlags::default()
        };
        let outcome = apply_revision(
            &store,
            &reg,
            &flags,
            apply_revision_args("zain", "00000000000000000000000000", None),
        )
        .unwrap();
        assert_eq!(outcome.op, "apply-revision");
        assert!(outcome.result.get("input_schema").is_some());
    }

    /// A live verb must not be forced onto a deployer the env isn't bound to: a
    /// full `--kind` K8s override against a local-process-bound env is rejected
    /// at the binding-match guard, before any cluster connect (the Codex F1
    /// fix). The same guard backs `reconcile`.
    #[test]
    fn apply_revision_rejects_unbound_deployer_kind_override() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            crate::defaults::LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).unwrap();
        let err = apply_revision(
            &store,
            &reg,
            &OpFlags::default(),
            apply_revision_args(
                "local",
                "00000000000000000000000000",
                Some("greentic.deployer.k8s@1.0.0"),
            ),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(
                msg.contains("bound to deployer") && msg.contains("not the env's"),
                "{msg}"
            ),
            other => panic!("expected Conflict (unbound deployer), got {other}"),
        }
    }

    #[test]
    fn reconcile_rejects_unbound_deployer_kind_override() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            crate::defaults::LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).unwrap();
        let err = reconcile(
            &store,
            &reg,
            &OpFlags::default(),
            reconcile_args("local", Some("greentic.deployer.k8s@1.0.0")),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("bound to deployer"), "{msg}"),
            other => panic!("expected Conflict (unbound deployer), got {other}"),
        }
    }

    // ---- Fix 1: answers_ref consumption ------------------------------------

    #[test]
    fn render_with_answers_overrides_namespace() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("zain");
        // Build a binding WITH answers_ref.
        let mut binding = make_binding(CapabilitySlot::Deployer, "greentic.deployer.k8s@1.0.0");
        binding.answers_ref = Some(PathBuf::from("env-packs/deployer/answers.json"));
        env.packs.push(binding);
        store.save(&env).unwrap();
        // Write the answers file under the env dir.
        let env_dir = store.env_dir(&EnvId::try_from("zain").unwrap()).unwrap();
        let answers_dir = env_dir.join("env-packs/deployer");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(
            answers_dir.join("answers.json"),
            r#"{"namespace": "custom-ns"}"#,
        )
        .unwrap();
        let outcome = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, None),
        )
        .unwrap();
        // The namespace override must reach the rendered manifests.
        let manifests = outcome
            .result
            .get("manifests")
            .and_then(Value::as_array)
            .expect("manifests");
        assert_eq!(
            manifests[0]["metadata"]["name"].as_str(),
            Some("custom-ns"),
            "Namespace object uses the answer override"
        );
        // answers_ref appears in the outcome.
        assert_eq!(
            outcome.result.get("answers_ref").and_then(Value::as_str),
            Some("env-packs/deployer/answers.json"),
        );
    }

    #[test]
    fn render_answers_ref_missing_file_is_conflict() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("zain");
        let mut binding = make_binding(CapabilitySlot::Deployer, "greentic.deployer.k8s@1.0.0");
        binding.answers_ref = Some(PathBuf::from("env-packs/deployer/answers.json"));
        env.packs.push(binding);
        store.save(&env).unwrap();
        // Do NOT write the answers file.
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, None),
        )
        .unwrap_err();
        // The MESSAGE matters: a missing file must say so, not surface the
        // containment-check's "escapes env directory" canonicalize failure.
        match err {
            OpError::Conflict(msg) => {
                assert!(msg.contains("does not exist"), "got: {msg}")
            }
            other => panic!("expected Conflict, got {other}"),
        }
    }

    #[test]
    fn render_answers_ref_escaping_env_dir_is_conflict() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("zain");
        let mut binding = make_binding(CapabilitySlot::Deployer, "greentic.deployer.k8s@1.0.0");
        // `..`-relative ref pointing at an EXISTING file outside the env dir:
        // must be rejected as an escape, never read.
        binding.answers_ref = Some(PathBuf::from("../outside-answers.json"));
        env.packs.push(binding);
        store.save(&env).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("zain").unwrap()).unwrap();
        std::fs::write(
            env_dir.parent().unwrap().join("outside-answers.json"),
            r#"{"namespace": "evil-ns"}"#,
        )
        .unwrap();
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, None),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("escapes"), "got: {msg}"),
            other => panic!("expected Conflict, got {other}"),
        }
    }

    #[test]
    fn render_answers_ref_invalid_json_is_conflict() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("zain");
        let mut binding = make_binding(CapabilitySlot::Deployer, "greentic.deployer.k8s@1.0.0");
        binding.answers_ref = Some(PathBuf::from("env-packs/deployer/answers.json"));
        env.packs.push(binding);
        store.save(&env).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("zain").unwrap()).unwrap();
        let answers_dir = env_dir.join("env-packs/deployer");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(answers_dir.join("answers.json"), "not json{").unwrap();
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn render_answers_ref_invalid_replicas_is_conflict() {
        use crate::cli::tests_common::make_binding;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let reg = builtins();
        let mut env = make_env("zain");
        let mut binding = make_binding(CapabilitySlot::Deployer, "greentic.deployer.k8s@1.0.0");
        binding.answers_ref = Some(PathBuf::from("env-packs/deployer/answers.json"));
        env.packs.push(binding);
        store.save(&env).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("zain").unwrap()).unwrap();
        let answers_dir = env_dir.join("env-packs/deployer");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(
            answers_dir.join("answers.json"),
            r#"{"router_replicas": "1"}"#,
        )
        .unwrap();
        let err = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("zain", None, None),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    // ---- Fix 3: plug-in registry threading ---------------------------------

    #[test]
    fn render_uses_caller_provided_registry() {
        use crate::cli::tests_common::make_binding;
        use crate::env_packs::render::{ManifestRenderer, RenderError};
        use crate::env_packs::slot::EnvPackHandler;

        /// A test-only deployer handler with a custom renderer.
        #[derive(Debug)]
        struct FakeDeployerHandler;

        impl EnvPackHandler for FakeDeployerHandler {
            fn slot(&self) -> CapabilitySlot {
                CapabilitySlot::Deployer
            }
            fn descriptor_path(&self) -> &str {
                "test.deployer.fake"
            }
            fn supported_versions(&self) -> semver::VersionReq {
                "^1.0.0".parse().unwrap()
            }
            fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
                // Reuse local-process credentials to satisfy the register gate.
                static CREDS: std::sync::LazyLock<
                    crate::env_packs::local_process::LocalProcessCredentials,
                > = std::sync::LazyLock::new(
                    crate::env_packs::local_process::LocalProcessCredentials::default,
                );
                Some(&*CREDS)
            }
            fn as_manifest_renderer(&self) -> Option<&dyn ManifestRenderer> {
                Some(self)
            }
        }

        impl ManifestRenderer for FakeDeployerHandler {
            fn render_environment(
                &self,
                _env: &greentic_deploy_spec::Environment,
                _answers: Option<&serde_json::Value>,
            ) -> Result<Vec<Value>, RenderError> {
                Ok(vec![json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": "fake-rendered"},
                })])
            }
        }

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("plug");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "test.deployer.fake@1.0.0",
        ));
        store.save(&env).unwrap();

        let mut reg = crate::env_packs::EnvPackRegistry::with_builtins();
        reg.register(Box::new(FakeDeployerHandler)).unwrap();

        let outcome = render(
            &store,
            &reg,
            &OpFlags::default(),
            render_args("plug", None, None),
        )
        .unwrap();
        let manifests = outcome
            .result
            .get("manifests")
            .and_then(Value::as_array)
            .expect("manifests");
        assert_eq!(manifests.len(), 1);
        assert_eq!(
            manifests[0]["metadata"]["name"].as_str(),
            Some("fake-rendered"),
            "the custom renderer's objects must come back"
        );
    }

    // ---- secrets backend resolution (Phase E.3) ----------------------------

    use crate::cli::tests_common::make_binding;
    use crate::env_packs::k8s::manifests::{SecretsBackend, VaultBackend};

    #[test]
    fn resolve_secrets_backend_defaults_to_dev_store() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // No Secrets binding → dev-store (back-compat with sandbox envs).
        let env = make_env("local");
        assert!(matches!(
            resolve_secrets_backend(&store, &env).unwrap(),
            SecretsBackend::DevStore
        ));
        // An explicit dev-store binding → dev-store.
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::LOCAL_SECRETS_PACK,
        ));
        assert!(matches!(
            resolve_secrets_backend(&store, &env).unwrap(),
            SecretsBackend::DevStore
        ));
    }

    #[test]
    fn secrets_backend_is_dev_store_classifies_by_kind() {
        // No Secrets binding → custodial dev-store.
        assert!(secrets_backend_is_dev_store(&make_env("local")));

        // Explicit dev-store binding → custodial.
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::LOCAL_SECRETS_PACK,
        ));
        assert!(secrets_backend_is_dev_store(&env));

        // Vault binding → NOT custodial: the operator seeds the value out-of-band
        // and the control plane only stamps the ref. Note this never parses the
        // Vault answers, so it does not fail closed like `resolve_secrets_backend`.
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::VAULT_SECRETS_PACK,
        ));
        assert!(!secrets_backend_is_dev_store(&env));
    }

    #[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
    #[test]
    fn cloudrun_stages_dev_secrets_only_for_the_dev_store_backend() {
        // No Secrets pack → nothing resolves `secret://`, so no seed material.
        assert!(!cloudrun_stages_dev_secrets(&make_env("local")));

        // Dev-store Secrets binding → stage the local dev-store.
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::LOCAL_SECRETS_PACK,
        ));
        assert!(cloudrun_stages_dev_secrets(&env));

        // Vault Secrets binding → NEVER upload the local dev-store: the values
        // (and any bound deployer credentials in it) stay operator-local.
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::VAULT_SECRETS_PACK,
        ));
        assert!(!cloudrun_stages_dev_secrets(&env));
    }

    #[test]
    fn resolve_secrets_backend_rejects_unknown_kind() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.bogus@1.0.0",
        ));
        let OpError::Conflict(msg) = resolve_secrets_backend(&store, &env).unwrap_err() else {
            panic!("expected Conflict");
        };
        assert!(msg.contains("unknown secrets backend kind"), "got: {msg}");
    }

    #[test]
    fn resolve_secrets_backend_vault_without_answers_fails_closed() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        // Vault binding with no `answers_ref` → the required addr is missing.
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::VAULT_SECRETS_PACK,
        ));
        let OpError::Conflict(msg) = resolve_secrets_backend(&store, &env).unwrap_err() else {
            panic!("expected Conflict");
        };
        assert!(msg.contains("requires a non-empty `addr`"), "got: {msg}");
    }

    #[test]
    fn vault_answers_map_to_backend_with_provider_defaults() {
        // addr is trimmed; the rest fall back to the provider defaults.
        let answers = json!({"addr": " http://vault.vault.svc:8200 ", "role": "worker"});
        let SecretsBackend::Vault(b) = secrets_backend_from_vault_answers(Some(&answers)).unwrap()
        else {
            panic!("expected Vault");
        };
        assert_eq!(
            b,
            VaultBackend {
                addr: "http://vault.vault.svc:8200".to_string(),
                k8s_role: "worker".to_string(),
                kv_mount: "secret".to_string(),
                kv_prefix: "greentic".to_string(),
                auth_mount: "kubernetes".to_string(),
                transit_mount: "transit".to_string(),
                transit_key: "greentic".to_string(),
                namespace: None,
            }
        );
    }

    #[test]
    fn vault_answers_override_defaults_and_namespace() {
        let answers = json!({
            "addr": "https://vault.example:8200",
            "role": "worker",
            "kv_mount": "kv",
            "kv_prefix": "tenant-a",
            "auth_mount": "k8s-eu",
            "transit_mount": "tr",
            "transit_key": "rk",
            "namespace": "admin/team",
        });
        let SecretsBackend::Vault(b) = secrets_backend_from_vault_answers(Some(&answers)).unwrap()
        else {
            panic!("expected Vault");
        };
        assert_eq!(b.kv_mount, "kv");
        assert_eq!(b.kv_prefix, "tenant-a");
        assert_eq!(b.auth_mount, "k8s-eu");
        assert_eq!(b.transit_mount, "tr");
        assert_eq!(b.transit_key, "rk");
        assert_eq!(b.namespace.as_deref(), Some("admin/team"));
    }

    #[test]
    fn vault_answers_missing_role_fails_closed() {
        let answers = json!({"addr": "http://vault:8200"});
        let OpError::Conflict(msg) =
            secrets_backend_from_vault_answers(Some(&answers)).unwrap_err()
        else {
            panic!("expected Conflict");
        };
        assert!(msg.contains("`role`"), "got: {msg}");
    }

    #[test]
    fn vault_answers_non_object_rejected() {
        let answers = json!("not an object");
        let OpError::Conflict(msg) =
            secrets_backend_from_vault_answers(Some(&answers)).unwrap_err()
        else {
            panic!("expected Conflict");
        };
        assert!(msg.contains("must be a JSON object"), "got: {msg}");
    }

    /// Repair of environments staged before greentic 1.1.0, whose revisions
    /// recorded a `pack_list_lock_ref` that no file ever backed.
    mod repair_stale_revisions {
        use super::*;
        use crate::cli::tests_common::{make_bundle_deployment, make_revision, make_traffic_split};
        use greentic_deploy_spec::{RevisionLifecycle, TrafficSplitEntry};
        use std::path::{Path, PathBuf};

        /// An env with `bundle_id`'s deployment carrying ONE revision at 100%.
        /// `pack_list_lock_ref` is left at the fixture default (`pack-list.lock`
        /// — the pre-1.1.0 placeholder), so the revision is stale unless
        /// `pin_lock` writes a real lockfile and repoints the ref at it.
        fn seed_env(dir: &Path, bundle_id: &str, pin_lock: bool) -> (LocalFsStore, RevisionId) {
            let store = LocalFsStore::new(dir);
            let mut env = make_env("local");
            let deployment = make_bundle_deployment("local", bundle_id);
            let mut revision = make_revision(
                "local",
                bundle_id,
                &deployment.deployment_id,
                1,
                RevisionLifecycle::Ready,
            );
            if pin_lock {
                let rel = PathBuf::from("revisions")
                    .join(revision.revision_id.to_string())
                    .join("pack-list.lock");
                let abs = dir.join("local").join(&rel);
                std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
                std::fs::write(&abs, "{}").unwrap();
                revision.pack_list_lock_ref = rel;
            }
            let split = make_traffic_split(
                "local",
                bundle_id,
                &deployment.deployment_id,
                &revision.revision_id,
                "01J000000000000000000000AA",
            );
            let revision_id = revision.revision_id;
            env.bundles.push(deployment);
            env.revisions.push(revision);
            env.traffic_splits.push(split);
            store.save(&env).unwrap();
            (store, revision_id)
        }

        #[test]
        fn doctor_reports_the_stale_revision() {
            let dir = tempdir().unwrap();
            let (store, revision_id) = seed_env(dir.path(), "stale-may-bundle", false);
            let outcome = doctor(&store, &OpFlags::default(), "local").unwrap();
            let stale = outcome.result["stale_revisions"].as_array().unwrap();
            assert_eq!(stale.len(), 1, "{:#}", outcome.result);
            assert_eq!(stale[0]["revision_id"], revision_id.to_string());
            assert_eq!(stale[0]["recorded_pack_list_lock_ref"], "pack-list.lock");
        }

        /// A revision whose lockfile really is on disk must never be reported.
        /// Without this, "repair" could happily archive every healthy revision.
        #[test]
        fn doctor_is_silent_on_a_healthy_revision() {
            let dir = tempdir().unwrap();
            let (store, _) = seed_env(dir.path(), "healthy-bundle", true);
            let outcome = doctor(&store, &OpFlags::default(), "local").unwrap();
            assert!(
                outcome.result["stale_revisions"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "a revision with a real lockfile is not stale: {:#}",
                outcome.result
            );
        }

        /// The default (no `--apply`) must be a dry run: it reports, and leaves
        /// the env byte-for-byte alone.
        #[test]
        fn check_reports_without_mutating() {
            let dir = tempdir().unwrap();
            let (store, revision_id) = seed_env(dir.path(), "stale-may-bundle", false);
            let outcome = repair(&store, &OpFlags::default(), "local", false).unwrap();
            assert_eq!(outcome.result["mode"], "check");
            assert_eq!(outcome.result["repaired"], 0);
            assert_eq!(
                outcome.result["stale_revisions"].as_array().unwrap().len(),
                1
            );

            let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
            assert_eq!(
                env.traffic_splits.len(),
                1,
                "check must not touch the traffic split"
            );
            let revision = env
                .revisions
                .iter()
                .find(|r| r.revision_id == revision_id)
                .unwrap();
            assert_eq!(
                revision.lifecycle,
                RevisionLifecycle::Ready,
                "check must not archive anything"
            );
        }

        #[test]
        fn apply_evicts_the_split_and_archives_the_revision() {
            let dir = tempdir().unwrap();
            let (store, revision_id) = seed_env(dir.path(), "stale-may-bundle", false);
            let outcome = repair(&store, &OpFlags::default(), "local", true).unwrap();
            assert_eq!(outcome.result["mode"], "apply");
            assert_eq!(outcome.result["repaired"], 1, "{:#}", outcome.result);

            let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
            assert!(
                env.traffic_splits.is_empty(),
                "the split had only the stale revision, so it must be dropped entirely"
            );
            let revision = env
                .revisions
                .iter()
                .find(|r| r.revision_id == revision_id)
                .unwrap();
            assert_eq!(revision.lifecycle, RevisionLifecycle::Archived);
            assert!(
                env.bundles[0].current_revisions.is_empty(),
                "the archived revision must leave the deployment's current_revisions"
            );
            // The deployment itself survives: re-deploying its bundle must be
            // able to bring it back.
            assert_eq!(env.bundles.len(), 1);
        }

        #[test]
        fn apply_is_idempotent() {
            let dir = tempdir().unwrap();
            let (store, _) = seed_env(dir.path(), "stale-may-bundle", false);
            repair(&store, &OpFlags::default(), "local", true).unwrap();
            let second = repair(&store, &OpFlags::default(), "local", true).unwrap();
            assert_eq!(second.result["repaired"], 0);
            assert_eq!(
                second.result["detail"],
                "no stale revisions; nothing to repair"
            );
        }

        /// A split holding BOTH a stale and a healthy revision must not simply
        /// lose the stale entry: `greentic-start` rejects any deployment whose
        /// weights do not sum to exactly 10,000 bps, so dropping 3,000 bps
        /// would trade a stale-ref failure for a weight-sum failure. The
        /// survivor has to be renormalized back to 10,000.
        #[test]
        fn apply_rebalances_a_split_that_keeps_a_healthy_revision() {
            let dir = tempdir().unwrap();
            let store = LocalFsStore::new(dir.path());
            let mut env = make_env("local");
            let deployment = make_bundle_deployment("local", "mixed-bundle");

            let stale = make_revision(
                "local",
                "mixed-bundle",
                &deployment.deployment_id,
                1,
                RevisionLifecycle::Ready,
            );
            let mut healthy = make_revision(
                "local",
                "mixed-bundle",
                &deployment.deployment_id,
                2,
                RevisionLifecycle::Ready,
            );
            let rel = PathBuf::from("revisions")
                .join(healthy.revision_id.to_string())
                .join("pack-list.lock");
            let abs = dir.path().join("local").join(&rel);
            std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
            std::fs::write(&abs, "{}").unwrap();
            healthy.pack_list_lock_ref = rel;

            let mut split = make_traffic_split(
                "local",
                "mixed-bundle",
                &deployment.deployment_id,
                &stale.revision_id,
                "01J000000000000000000000AA",
            );
            // 30% stale / 70% healthy — a canary that straddled the upgrade.
            split.entries = vec![
                TrafficSplitEntry {
                    revision_id: stale.revision_id,
                    weight_bps: 3_000,
                },
                TrafficSplitEntry {
                    revision_id: healthy.revision_id,
                    weight_bps: 7_000,
                },
            ];
            let healthy_id = healthy.revision_id;
            env.bundles.push(deployment);
            env.revisions.push(stale);
            env.revisions.push(healthy);
            env.traffic_splits.push(split);
            store.save(&env).unwrap();

            let outcome = repair(&store, &OpFlags::default(), "local", true).unwrap();
            assert_eq!(outcome.result["repaired"], 1);

            let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
            let split = &env.traffic_splits[0];
            assert_eq!(split.entries.len(), 1, "the stale entry must be evicted");
            assert_eq!(split.entries[0].revision_id, healthy_id);
            assert_eq!(
                split.entries[0].weight_bps, 10_000,
                "the surviving revision must be renormalized to a full 10,000 bps, \
                 not left at its original 7,000"
            );
        }
    }

    /// The store URI a minting env-pack's bootstrap lands its bound credential at.
    fn known_credential_store_uri(env_id: &str, path: &str) -> String {
        use greentic_deploy_spec::SecretRef;

        let bound = SecretRef::try_new(format!("secret://{env_id}/{path}")).unwrap();
        crate::cli::secrets::secret_ref_to_store_uri(&bound).unwrap()
    }

    /// The H1-orphan window: `bootstrap` writes the credential material (W1) and
    /// crashes before persisting `credentials_ref` (W2). The env names nothing,
    /// so a `credentials_ref`-keyed denylist alone yields an empty exclusion and
    /// the next seed would ship the credential. The well-known paths must be
    /// excluded regardless.
    #[test]
    fn staging_excluded_uris_excludes_known_deployer_paths_without_a_credentials_ref() {
        let env = make_env("cred");
        assert!(
            env.credentials_ref.is_none(),
            "sanity: this pins the crashed-bootstrap shape"
        );

        let excluded = staging_excluded_uris(&env);
        assert!(
            !BOUND_CREDENTIAL_STORE_PATHS.is_empty(),
            "sanity: at least the always-compiled k8s path is present"
        );
        for path in BOUND_CREDENTIAL_STORE_PATHS {
            assert!(
                excluded.contains(&known_credential_store_uri("cred", path)),
                "an env with NO credentials_ref must still exclude `{path}` — a crashed \
                 bootstrap can have orphaned material there that nothing names"
            );
        }
    }

    /// The exclusion is a union, not a replacement: a credential bound at a
    /// custom URI must survive alongside the unconditional well-known paths.
    #[test]
    fn staging_excluded_uris_unions_the_bound_credential_with_the_known_paths() {
        use greentic_deploy_spec::SecretRef;

        let mut env = make_env("cred");
        let cred_ref = SecretRef::try_new("secret://cred/default/_/gcp-deployer/sa_key").unwrap();
        env.credentials_ref = Some(cred_ref.clone());

        let excluded = staging_excluded_uris(&env);
        assert!(
            excluded.contains(&crate::cli::secrets::secret_ref_to_store_uri(&cred_ref).unwrap()),
            "the custom bound credential must still be excluded"
        );
        for path in BOUND_CREDENTIAL_STORE_PATHS {
            assert!(
                excluded.contains(&known_credential_store_uri("cred", path)),
                "the well-known `{path}` must be excluded alongside the bound ref"
            );
        }
    }

    /// A credential bound at exactly a well-known path must not be listed twice.
    #[test]
    fn staging_excluded_uris_does_not_duplicate_a_credential_bound_at_a_known_path() {
        use greentic_deploy_spec::SecretRef;

        let path = BOUND_CREDENTIAL_STORE_PATHS[0];
        let mut env = make_env("cred");
        env.credentials_ref = Some(SecretRef::try_new(format!("secret://cred/{path}")).unwrap());

        let excluded = staging_excluded_uris(&env);
        let uri = known_credential_store_uri("cred", path);
        assert_eq!(
            excluded.iter().filter(|u| **u == uri).count(),
            1,
            "the same store URI must appear once, not once per source"
        );
    }

    /// End-to-end proof of the orphan fix: material sits in the dev-store at a
    /// well-known deployer path while `credentials_ref` is `None` (bootstrap
    /// crashed between W1 and W2). The staged seed must not resolve it.
    #[test]
    fn read_dev_secrets_bytes_strips_an_orphaned_credential_the_env_never_named() {
        use greentic_deploy_spec::SecretRef;
        use greentic_secrets_lib::{DevStore, SecretsStore};

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("cred");
        assert!(env.credentials_ref.is_none());
        store.save(&env).unwrap();
        let env_id = env.environment_id.clone();
        let env_dir = store.env_dir(&env_id).unwrap();

        // W1 landed; W2 never did — the env names no credential.
        let orphan_path = BOUND_CREDENTIAL_STORE_PATHS[0];
        let orphan_ref = SecretRef::try_new(format!("secret://cred/{orphan_path}")).unwrap();
        crate::cli::secrets::put_credential_material(&env_dir, &orphan_ref, "ORPHANED-TOKEN")
            .unwrap();
        let dev_path = crate::cli::secrets::resolve_dev_store_path(&env_dir, None);
        let runtime_uri = "secrets://cred/acme/_/kv/runtime-token";
        crate::cli::secrets::dev_store_put(&dev_path, runtime_uri, "runtime-value").unwrap();

        let orphan_uri = crate::cli::secrets::secret_ref_to_store_uri(&orphan_ref).unwrap();
        assert_eq!(
            crate::cli::tests_common::dev_store_read(&dev_path, &orphan_uri),
            b"ORPHANED-TOKEN",
            "sanity: the source store holds the orphan before staging"
        );

        let staged = read_dev_secrets_bytes(&store, &env_id)
            .unwrap()
            .expect("a dev-store-backed env stages some bytes");

        let staged_dir = tempdir().unwrap();
        let staged_path = staged_dir.path().join(".dev.secrets.env");
        std::fs::write(&staged_path, &staged).unwrap();
        let read_uri = |uri: &str| -> Result<Vec<u8>, ()> {
            let dev = DevStore::with_path(staged_path.clone()).unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async { dev.get(uri).await.map_err(|_| ()) })
        };
        assert_eq!(
            read_uri(runtime_uri).unwrap(),
            b"runtime-value",
            "runtime material must still reach the workload"
        );
        assert!(
            read_uri(&orphan_uri).is_err(),
            "the staged seed must not resolve a credential orphaned by a crashed bootstrap"
        );
    }

    #[test]
    fn read_dev_secrets_bytes_strips_the_deployer_credential_from_the_seed() {
        use greentic_deploy_spec::SecretRef;
        use greentic_secrets_lib::{DevStore, SecretsStore};

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("cred");
        let cred_ref = SecretRef::try_new("secret://cred/default/_/gcp-deployer/sa_key").unwrap();
        env.credentials_ref = Some(cred_ref.clone());
        store.save(&env).unwrap();
        let env_id = env.environment_id.clone();
        let env_dir = store.env_dir(&env_id).unwrap();

        // Write the deployer credential (at the URI the exclusion computes) plus a
        // runtime secret into the env dev-store, exactly as the real flows do.
        // `put_credential_material` succeeding also proves the ref is
        // store-alignable (it computes the same store URI internally).
        crate::cli::secrets::put_credential_material(&env_dir, &cred_ref, "DEPLOYER-SA-KEY")
            .unwrap();
        let dev_path = crate::cli::secrets::resolve_dev_store_path(&env_dir, None);
        let runtime_uri = "secrets://cred/acme/_/kv/runtime-token";
        crate::cli::secrets::dev_store_put(&dev_path, runtime_uri, "runtime-value").unwrap();

        let cred_store_uri = crate::cli::secrets::secret_ref_to_store_uri(&cred_ref).unwrap();
        assert_eq!(
            crate::cli::tests_common::dev_store_read(&dev_path, &cred_store_uri),
            b"DEPLOYER-SA-KEY",
            "sanity: the source store holds the credential before staging"
        );

        let staged = read_dev_secrets_bytes(&store, &env_id)
            .unwrap()
            .expect("a dev-store-backed env stages some bytes");

        // Load the staged bytes as the workload would: the runtime secret
        // resolves, but the deployer credential is gone.
        let staged_dir = tempdir().unwrap();
        let staged_path = staged_dir.path().join(".dev.secrets.env");
        std::fs::write(&staged_path, &staged).unwrap();
        let read_uri = |uri: &str| -> Result<Vec<u8>, ()> {
            let dev = DevStore::with_path(staged_path.clone()).unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async { dev.get(uri).await.map_err(|_| ()) })
        };
        assert_eq!(read_uri(runtime_uri).unwrap(), b"runtime-value");
        assert!(
            read_uri(&cred_store_uri).is_err(),
            "the staged seed must not resolve the deployer credential"
        );

        // The operator's real store is untouched — the credential still resolves.
        assert_eq!(
            crate::cli::tests_common::dev_store_read(&dev_path, &cred_store_uri),
            b"DEPLOYER-SA-KEY",
            "the operator's real dev-store must not be modified by staging"
        );
    }

    // Regression for the stale-environment-state race: staging must derive the
    // exclusion from a *fresh* env load, not the state a caller loaded earlier.
    // Deterministic stand-in for "reconcile loads an uncredentialed env, a
    // concurrent bootstrap binds the credential, staging still excludes it":
    // persist the env uncredentialed, then land the credential + `credentials_ref`
    // (bootstrap's dev-store-then-ref order), then stage. If the helper trusted a
    // stale snapshot it would ship the credential; reloading strips it.
    #[test]
    fn read_dev_secrets_bytes_reloads_env_so_a_late_bound_credential_is_still_stripped() {
        use greentic_deploy_spec::SecretRef;
        use greentic_secrets_lib::{DevStore, SecretsStore};

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());

        // The env is persisted with NO bound credential — the world a reconcile
        // would have loaded before the bind landed.
        let env = make_env("cred");
        assert!(env.credentials_ref.is_none());
        store.save(&env).unwrap();
        let env_id = env.environment_id.clone();
        let env_dir = store.env_dir(&env_id).unwrap();

        // The bind lands afterwards: credential material into the dev-store,
        // then `credentials_ref` persisted (bootstrap's on-flock order).
        let cred_ref = SecretRef::try_new("secret://cred/default/_/gcp-deployer/sa_key").unwrap();
        crate::cli::secrets::put_credential_material(&env_dir, &cred_ref, "LATE-SA-KEY").unwrap();
        let mut bound = store.load(&env_id).unwrap();
        bound.credentials_ref = Some(cred_ref.clone());
        store.save(&bound).unwrap();

        let staged = read_dev_secrets_bytes(&store, &env_id)
            .unwrap()
            .expect("a dev-store-backed env stages some bytes");

        let staged_dir = tempdir().unwrap();
        let staged_path = staged_dir.path().join(".dev.secrets.env");
        std::fs::write(&staged_path, &staged).unwrap();
        let cred_store_uri = crate::cli::secrets::secret_ref_to_store_uri(&cred_ref).unwrap();
        let dev = DevStore::with_path(staged_path).unwrap();
        let resolved = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { dev.get(&cred_store_uri).await });
        assert!(
            resolved.is_err(),
            "staging must reload the env and strip a credential bound after the caller's load"
        );
    }
}
