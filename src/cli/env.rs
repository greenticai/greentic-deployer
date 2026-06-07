//! `gtc op env {create,update,list,show,doctor,destroy}` (`A3` of `plans/next-gen-deployment.md`).
//!
//! Commands operate directly on the [`EnvironmentStore`] from A2. Each
//! mutating call validates the payload before touching disk.

use chrono::Utc;
use greentic_deploy_spec::{
    EnvId, Environment, EnvironmentHostConfig, SchemaVersion, validate_public_base_url,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

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
        let env = store.transact(&env_id, |locked| -> Result<Environment, OpError> {
            if locked.load().is_ok() {
                return Err(OpError::Conflict(format!(
                    "environment `{}` already exists",
                    locked.env_id()
                )));
            }
            let env = Environment {
                schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
                environment_id: locked.env_id().clone(),
                name: payload.name.clone(),
                host_config: EnvironmentHostConfig {
                    env_id: locked.env_id().clone(),
                    region: payload.region.clone(),
                    tenant_org_id: payload.tenant_org_id.clone(),
                    listen_addr: parsed_listen_addr,
                    public_base_url: parsed_public_base_url.clone(),
                },
                packs: Vec::new(),
                credentials_ref: None,
                bundles: Vec::new(),
                revisions: Vec::new(),
                traffic_splits: Vec::new(),
                messaging_endpoints: Vec::new(),
                extensions: Vec::new(),
                revocation: Default::default(),
                retention: Default::default(),
                health: Default::default(),
            };
            locked.save(&env)?;
            Ok(env)
        })?;
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
        let env = store.transact(&env_id, |locked| -> Result<Environment, OpError> {
            let mut env = match locked.load() {
                Ok(env) => env,
                Err(crate::environment::StoreError::NotFound(id)) => {
                    return Err(OpError::NotFound(format!("environment `{id}`")));
                }
                Err(e) => return Err(e.into()),
            };
            env.name = payload.name.clone();
            env.host_config.region = payload.region.clone();
            env.host_config.tenant_org_id = payload.tenant_org_id.clone();
            if let Some(url) = &parsed_public_base_url {
                env.host_config.public_base_url = Some(url.clone());
            }
            locked.save(&env)?;
            Ok(env)
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "update",
            serde_json::to_value(EnvSummary::from(&env)).expect("EnvSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op env list`.
pub fn list(store: &LocalFsStore, flags: &OpFlags) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        // `list` has no input; produce a null-input schema as a placeholder.
        return Ok(OpOutcome::new(
            NOUN,
            "list",
            json!({ "input_schema": "no input" }),
        ));
    }
    let mut summaries = Vec::new();
    for env_id in store.list()? {
        let env = store.load(&env_id)?;
        summaries.push(EnvSummary::from(&env));
    }
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({ "environments": summaries }),
    ))
}

/// `op env show <env_id>`.
pub fn show(store: &LocalFsStore, flags: &OpFlags, env_id: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "show",
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
            // `DuplicateRegistration` comes solely from `register`.
            Err(err @ crate::env_packs::RegistryError::DuplicateRegistration(_)) => {
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
            Err(err @ crate::env_packs::RegistryError::DuplicateRegistration(_)) => {
                unreachable!("resolve_for_slot never returns {err:?}")
            }
        }
    }
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
            "has_runtime": runtime.is_some(),
            "checked_at": Utc::now(),
        }),
    ))
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
        // [`super::trust_root::seed_operator_key_if_trust_root_absent`].
        let trust_root =
            super::trust_root::seed_operator_key_if_trust_root_absent(store, &env.environment_id)?;
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

/// `op env destroy <env_id> --confirm`. Removes the env's on-disk state.
///
/// Force-free safety net: the caller must pass `confirm = true`. The
/// `--confirm` flag is the operator-binary's responsibility; this library
/// just enforces the gate.
pub fn destroy(
    store: &LocalFsStore,
    flags: &OpFlags,
    env_id: &str,
    confirm: bool,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "destroy",
            json!({ "input_schema": "env_id positional + confirm flag" }),
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
    audit_and_record(store, ctx, |_committed| {
        if !store.exists(&env_id)? {
            return Err(OpError::NotFound(format!("environment `{env_id}`")));
        }
        // The A2 trait does not yet expose a remove API. Destructive removal
        // ships with the bundle-deployment retention path (B-phase); A7 wires
        // the audit + authorize surface so the destroy intent is logged today.
        Err(OpError::NotYetImplemented(
            "`op env destroy` requires the retention path (B-phase); use the LocalFsStore root path returned by `op env show` for manual cleanup",
        ))
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
pub(super) fn parse_public_base_url(raw: &str) -> Result<String, OpError> {
    validate_public_base_url(raw)
        .map_err(|e| OpError::InvalidArgument(format!("public_base_url: {e}")))
}

/// Validate an `Option<String>` carrying a `public_base_url` payload field.
/// Returns `Ok(None)` when the field was absent, the canonical form when
/// present and valid, and `Err(OpError::InvalidArgument)` when present and
/// invalid. The 5 entry points all share this lift to keep the
/// `.as_deref().map(parse).transpose()` boilerplate in one place.
pub(super) fn parse_optional_public_base_url(
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
        let host_config = store.transact(&env_id, |locked| -> Result<_, OpError> {
            let mut env = match locked.load() {
                Ok(env) => env,
                Err(crate::environment::StoreError::NotFound(id)) => {
                    return Err(OpError::NotFound(format!("environment `{id}`")));
                }
                Err(e) => return Err(e.into()),
            };
            env.host_config.public_base_url = Some(validated.clone());
            locked.save(&env)?;
            Ok(env.host_config.clone())
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "set-public-url",
            json!({
                "environment_id": env_id.as_str(),
                "host_config": host_config,
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
        let err = destroy(&store, &OpFlags::default(), "local", false).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn destroy_with_confirm_returns_not_yet_implemented() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = destroy(&store, &OpFlags::default(), "local", true).unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");
    }

    #[test]
    fn create_non_local_env_refuses_and_audits_deny() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = create(
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
        .unwrap_err();
        assert!(
            matches!(err, OpError::Unauthorized { .. }),
            "got {err:?}; deny-path must surface as Unauthorized"
        );
        // No environment.json was created.
        let env_json = dir.path().join("prod").join("environment.json");
        assert!(
            !env_json.exists(),
            "deny must not leave behind environment.json"
        );
        // Audit event was written under the denied env's audit dir.
        let log = dir.path().join("prod").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).expect("audit log must exist on deny");
        let event: crate::environment::AuditEvent = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(event.env_id, "prod");
        assert_eq!(event.noun, "env");
        assert_eq!(event.verb, "create");
        matches!(
            event.authorization,
            crate::environment::AuditDecision::Deny { .. }
        );
        match event.result {
            crate::environment::AuditResult::Error { kind, .. } => {
                assert_eq!(kind, "unauthorized");
            }
            other => panic!("expected Error result, got {other:?}"),
        }
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
}
