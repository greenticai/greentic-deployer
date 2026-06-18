//! `gtc op deploy` — the one-shot bundle deployment orchestrator.
//!
//! The default, "just works" path: add the bundle deployment (when new),
//! stage a revision from the local `.gtbundle`, warm it, and route 100 % of
//! traffic to it. It reuses the four single-purpose verbs — `bundles add`,
//! `revisions stage`, `revisions warm`, `traffic set` — so all of the
//! audit / signing / revenue-policy logic stays single-sourced; this module
//! only threads the minted ids between them and fills in sensible defaults.
//!
//! A real local `.gtbundle` is required on every path — `deploy` refuses to
//! publish an artifact-less revision (placeholder digests + an empty pack-list
//! lock would be admissible by traffic yet broken at boot).
//!
//! Re-deploying a bundle that is already deployed in the env stages a NEW
//! revision and shifts 100 % traffic onto it (blue-green): because
//! `traffic set` replaces the whole split, the previously-live revision
//! leaves the routing table and drains at runtime. The superseded revision
//! is retained (not archived) so `gtc op traffic rollback` still works.
//!
//! Each invocation is its own rollout: without a caller-supplied
//! `--idempotency-key`, the cut-over key is derived from the freshly-minted
//! revision, so a re-run stages another revision rather than deduplicating.
//! Supply a stable `--idempotency-key` to make retries idempotent — a repeat
//! with a key that already routed returns the existing outcome without minting
//! a new revision or disturbing the rollback target.
//!
//! The deployer records desired state only; it carries no health-check
//! producers (B9), so `warm` runs a no-op gate and the result reports
//! `routed`, not a runtime liveness claim. greentic-start's watcher reloads
//! and begins serving once the split is written.
//!
//! Prerequisites are required, never auto-created: the env must already exist
//! (`gtc op env init`) and its trust root must carry the operator key
//! (`gtc op trust-root bootstrap`). The deploy path never seeds signing keys
//! — that would grant signing rights as a side effect of a deploy (C2).
//!
//! The four verbs remain the advanced / fine-tune surface, untouched.

use std::collections::BTreeMap;
use std::path::PathBuf;

use greentic_deploy_spec::{EnvId, RouteBinding};

/// Per-pack config overrides: `<pack_id> -> <key> -> <json value>`.
type ConfigOverridesMap = BTreeMap<String, BTreeMap<String, Value>>;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::bundles::{
    BundleAddPayload, BundleSummary, BundleUpdatePayload, RevenueShareEntryPayload,
    RouteBindingPayload,
};
use super::revisions::{RevisionStagePayload, RevisionSummary, RevisionTransitionPayload};
use super::traffic::{TrafficSetEntryPayload, TrafficSetPayload};
use super::{OpError, OpFlags, OpOutcome};

const NOUN: &str = "deploy";
const VERB: &str = "run";

/// 100 % of traffic, in basis points.
pub(crate) const FULL_TRAFFIC_BPS: u32 = 10_000;

/// Input to [`deploy`]. Everything but `bundle_id` and `bundle_path` has a
/// sensible default; the CLI requires `--bundle` and derives `bundle_id` from
/// its filename stem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDeployPayload {
    #[serde(default = "default_environment_id")]
    pub environment_id: String,
    pub bundle_id: String,
    /// Billing principal (P6). Defaults to `local-dev` on the `local` env;
    /// required for every other env. Forwarded verbatim to `bundles add`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    /// Local `.gtbundle` to stage. Required (on every path): `deploy` refuses
    /// to publish an artifact-less revision. Optional in the struct only so an
    /// `--answers` payload that omits it fails with a clear error rather than a
    /// deserialization error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<PathBuf>,
    /// Registry reference the bundle was resolved from, recorded on the staged
    /// revision so a remote worker can pull it at boot. `None` (default) keeps
    /// the revision local-serve only. `op deploy` still stages from the local
    /// `--bundle` file; this only records where the worker can re-fetch it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_source_uri: Option<String>,
    /// Idempotency key for the traffic cut-over. Defaults to a value derived
    /// from the freshly-minted revision id, so each deploy is a distinct
    /// (non-replay) cut-over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// D.4: per-pack provider config overrides applied at egress time
    /// (`<pack_id> -> <key> -> <json value>`). Forwarded into the new
    /// `BundleAddPayload.config_overrides` on a fresh deploy, or applied via
    /// `bundles update` to the existing deployment on a re-deploy (blue-green
    /// version bump).
    ///
    /// Three-valued semantics (Codex finding 3):
    /// - `None` (default, no CLI input) = leave existing overrides untouched
    /// - `Some(empty)` = explicit clear (e.g. `--config-overrides-from` with `{}`)
    /// - `Some(non-empty)` = replace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
    /// Route binding (hosts, path prefixes, tenant selector). Set at deploy
    /// time so a fresh add doesn't need a follow-up `bundles update`.
    ///
    /// `None` (the default) means: on fresh add, use the default empty
    /// binding; on re-deploy, leave the existing binding untouched.
    /// `Some(...)` replaces the whole binding (same all-or-nothing shape as
    /// `bundles update --route-binding`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_binding: Option<RouteBindingPayload>,
    /// Revenue-share split applied on a FRESH deploy (forwarded to
    /// `bundles add`). `None` = the `greentic@10000` default. Ignored on a
    /// re-deploy (a blue-green version bump leaves the existing split
    /// untouched — change it via `bundles update`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revenue_share: Option<Vec<RevenueShareEntryPayload>>,
}

fn default_environment_id() -> String {
    crate::defaults::LOCAL_ENV_ID.to_string()
}

/// Combined summary of an orchestrated deploy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploySummary {
    pub environment_id: String,
    pub bundle_id: String,
    pub deployment_id: String,
    pub revision_id: String,
    /// `true` when the bundle was already deployed and this call reused the
    /// existing deployment (a blue-green version bump).
    pub reused_deployment: bool,
    /// Revisions that were live before this deploy and have now left the
    /// routing table (they drain at runtime; retained for rollback).
    pub superseded_revisions: Vec<String>,
    pub traffic: String,
    pub status: String,
}

impl DeploySummary {
    /// A routed deploy: the 100 %-traffic split is written. `status` is
    /// `routed` (desired state), not a runtime liveness claim — see module docs.
    fn routed(
        env_id: &EnvId,
        bundle_id: String,
        deployment_id: String,
        revision_id: String,
        reused_deployment: bool,
        superseded_revisions: Vec<String>,
    ) -> Self {
        Self {
            environment_id: env_id.as_str().to_string(),
            bundle_id,
            deployment_id,
            revision_id,
            reused_deployment,
            superseded_revisions,
            traffic: format!("100% ({FULL_TRAFFIC_BPS} bps)"),
            status: "routed".to_string(),
        }
    }

    fn into_outcome(self) -> OpOutcome {
        OpOutcome::new(
            NOUN,
            VERB,
            serde_json::to_value(self).expect("DeploySummary is json-safe"),
        )
    }
}

/// Orchestrate add → stage → warm → traffic-set with defaults.
pub fn deploy(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<BundleDeployPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, VERB, deploy_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let bundle_id = payload.bundle_id.trim().to_string();
    if bundle_id.is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_id must not be empty".to_string(),
        ));
    }
    // Payload-level routing validation. Catches the `--answers` JSON path
    // (the CLI flag path also pre-validates via `payload_from_deploy_args`).
    if let Some(rb) = payload.route_binding.as_ref() {
        rb.validate()?;
    }

    // `op deploy` always stages from a real `.gtbundle`: an artifact-less
    // stage would record placeholder digests and an empty pack-list lock —
    // warmable by the no-op gate, admissible by traffic, and broken at boot.
    // Reject it here, before any mutation, so a bad call never creates a
    // deployment it then can't fill. (The legacy verbatim stage path stays
    // reachable only through the explicit `revisions stage --answers` verb.)
    let bundle_path = payload.bundle_path.clone().ok_or_else(|| {
        OpError::InvalidArgument(
            "deploy requires a local `.gtbundle`: pass `--bundle <PATH>`".to_string(),
        )
    })?;
    if !bundle_path.is_file() {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{}` is not a file",
            bundle_path.display()
        )));
    }

    // Preflight: the env must already exist. We never auto-create it, because
    // `env init` is the only path that legitimately seeds the trust root (C2),
    // and a deploy must not grant signing rights as a side effect.
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!(
            "environment `{env_id}` not found — run `gtc op env init` \
             (then `gtc op trust-root bootstrap {env_id}`) before deploying"
        )));
    }

    // Resolve the billing principal the same way `bundles add` does so the
    // reuse scan keys on the real (env_id, bundle_id, customer_id) anchor.
    let customer_id = super::bundles::resolve_customer_id(&env_id, payload.customer_id.clone())?;

    // Operation-level idempotency: if the caller supplied a key and the bundle
    // already has a traffic split under that key, this deploy already ran —
    // return the existing outcome without minting a duplicate revision or
    // moving the rollback target. (`traffic set` alone keys only the cut-over,
    // so a keyed retry would otherwise stage a fresh revision and then conflict
    // at the split, orphaning a Ready revision.)
    let env = store.load(&env_id)?;
    let existing = env
        .bundles
        .iter()
        .find(|b| b.bundle_id.as_str() == bundle_id && b.customer_id == customer_id);

    if let Some(key) = payload.idempotency_key.as_deref()
        && let Some(b) = existing
        && let Some(split) = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id == b.deployment_id && s.idempotency_key == key)
    {
        let revision_id = split
            .entries
            .first()
            .map(|e| e.revision_id.to_string())
            .unwrap_or_default();
        return Ok(DeploySummary::routed(
            &env_id,
            bundle_id,
            b.deployment_id.to_string(),
            revision_id,
            true,
            Vec::new(),
        )
        .into_outcome());
    }

    // On re-deploy with a route_binding in the payload, reject any binding
    // that differs from the deployment's existing one BEFORE staging a
    // revision. Routing is bundle-level metadata that `traffic rollback`
    // does NOT restore (see `traffic::rollback`), so allowing a mutation
    // here would leave the prior revision mis-routed after a rollback.
    //
    // Equal → no-op (preserves the demo flow where the user re-runs the
    // same deploy command). Different → reject with Conflict pointing to
    // `gtc op bundles update` as the right verb for routing mutations on
    // an existing deployment. None → fall through (no change requested).
    if let (Some(b), Some(rb_payload)) = (existing, payload.route_binding.as_ref()) {
        let requested: RouteBinding = super::bundles::into_route_binding(rb_payload.clone());
        if requested != b.route_binding {
            return Err(OpError::Conflict(format!(
                "deploy: route_binding differs from the deployed binding for \
                 `{bundle_id}` — routing is bundle-level metadata and is not \
                 restored by `traffic rollback`. Run `gtc op bundles update \
                 --answers ...` to change routing on an existing deployment, \
                 then re-deploy"
            )));
        }
    }

    let (deployment_id, reused, superseded_revisions) = match existing {
        Some(b) => {
            let dep = b.deployment_id;
            let superseded: Vec<String> = env
                .traffic_splits
                .iter()
                .find(|s| s.deployment_id == dep)
                .map(|s| {
                    s.entries
                        .iter()
                        .map(|e| e.revision_id.to_string())
                        .collect()
                })
                .unwrap_or_default();
            (dep.to_string(), true, superseded)
        }
        None => {
            let add_payload = BundleAddPayload {
                environment_id: payload.environment_id.clone(),
                bundle_id: bundle_id.clone(),
                customer_id: payload.customer_id.clone(),
                route_binding: payload.route_binding.clone().unwrap_or_default(),
                revenue_share: payload
                    .revenue_share
                    .clone()
                    .unwrap_or_else(super::bundles::default_revenue_share),
                authorization_ref: super::bundles::default_authorization_ref(),
                // Fresh deploy: BundleAddPayload takes a plain BTreeMap
                // (no prior state to clear). Unwrap the Option; None → empty.
                config_overrides: payload.config_overrides.clone().unwrap_or_default(),
                idempotency_key: None,
            };
            let outcome = super::bundles::add(store, flags, Some(add_payload))?;
            let summary: BundleSummary = parse_summary(outcome, "bundle")?;
            (summary.deployment_id, false, Vec::new())
        }
    };
    // Drop the borrow on `env` before the mutating steps below.
    drop(env);

    // Stage a fresh revision from the bundle. With `bundle_path` set, stage
    // derives the real bundle_digest / pack_list / lock ref from the artifact;
    // config_digest / signature_sidecar_ref / drain_seconds are still recorded
    // verbatim, so use the same canonical defaults the `stage --answers` path
    // applies rather than re-spelling the literals here.
    let stage_payload = RevisionStagePayload {
        environment_id: payload.environment_id.clone(),
        deployment_id: deployment_id.clone(),
        bundle_path: Some(bundle_path),
        bundle_digest: super::revisions::default_bundle_digest(),
        bundle_source_uri: payload.bundle_source_uri.clone(),
        pack_list: Vec::new(),
        pack_list_lock_ref: PathBuf::new(),
        config_digest: super::revisions::default_config_digest(),
        signature_sidecar_ref: super::revisions::default_signature_sidecar_ref(),
        drain_seconds: super::revisions::default_drain_seconds(),
    };
    let stage_outcome = super::revisions::stage(store, flags, Some(stage_payload))?;
    let staged: RevisionSummary = parse_summary(stage_outcome, "revision")?;
    let revision_id = staged.revision_id;

    // Warm it to Ready.
    super::revisions::warm(
        store,
        flags,
        Some(RevisionTransitionPayload {
            environment_id: payload.environment_id.clone(),
            revision_id: revision_id.clone(),
            idempotency_key: None,
        }),
    )?;

    // On re-deploy of an existing bundle, replace the deployment's
    // config_overrides AFTER stage+warm succeed but BEFORE the traffic
    // cut-over. This ordering ensures that if stage or warm fails (corrupt
    // bundle, unpack error, health gate rejection), the override map is
    // NOT replaced — the old deployment keeps its prior overrides intact
    // (Codex finding 2: override replacement outside the rollout
    // transaction).
    //
    // Note: bundle-level overrides mean rollback (`traffic rollback`)
    // restores the traffic split only, not the prior override map. This is
    // an accepted limitation of the bundle-level altitude; revision-scoped
    // overrides are an explicit non-goal (architectural decision).
    if reused && let Some(ref overrides) = payload.config_overrides {
        super::bundles::update(
            store,
            flags,
            Some(BundleUpdatePayload {
                environment_id: payload.environment_id.clone(),
                deployment_id: deployment_id.clone(),
                status: None,
                route_binding: None,
                revenue_share: None,
                config_overrides: Some(overrides.clone()),
                idempotency_key: None,
            }),
        )?;
    }

    // Route 100 % of traffic to the new revision. `traffic set` is a full
    // replacement, so any previously-live revision drops out of the split
    // (blue-green). Without a caller-supplied key, each deploy is its own
    // rollout: the revision-derived key guarantees a distinct cut-over. Supply
    // `--idempotency-key` to make retries idempotent (handled above).
    let idempotency_key = payload
        .idempotency_key
        .clone()
        .unwrap_or_else(|| format!("deploy:{deployment_id}:{revision_id}"));
    super::traffic::set(
        store,
        flags,
        Some(TrafficSetPayload {
            environment_id: payload.environment_id.clone(),
            deployment_id: deployment_id.clone(),
            entries: vec![TrafficSetEntryPayload {
                revision_id: revision_id.clone(),
                weight_bps: Some(FULL_TRAFFIC_BPS),
                weight_percent: None,
            }],
            updated_by: super::traffic::default_updated_by(),
            idempotency_key,
            authorization_ref: super::traffic::default_authorization_ref(),
        }),
    )?;

    // `status` is "routed" (desired-state split written), not a runtime
    // liveness claim — the deployer has no health-check producers (B9); see
    // `DeploySummary::routed` and the module docs.
    Ok(DeploySummary::routed(
        &env_id,
        bundle_id,
        deployment_id,
        revision_id,
        reused,
        superseded_revisions,
    )
    .into_outcome())
}

/// Build a [`BundleDeployPayload`] from direct CLI args, or `None` when no
/// args were supplied (deferring to `--answers` / `--schema`). Mirrors
/// `revisions::payload_from_stage_args`: all clap fields are optional so the
/// answers / schema paths keep working unchanged.
pub fn payload_from_deploy_args(
    args: super::dispatch::BundleDeployArgs,
) -> Result<Option<BundleDeployPayload>, OpError> {
    let super::dispatch::BundleDeployArgs {
        bundle,
        env,
        bundle_id,
        customer_id,
        idempotency_key,
        config_override,
        config_override_json,
        config_overrides_from,
        path_prefix,
        host,
        tenant,
        team,
    } = args;
    if bundle.is_none()
        && env.is_none()
        && bundle_id.is_none()
        && customer_id.is_none()
        && idempotency_key.is_none()
        && config_override.is_empty()
        && config_override_json.is_empty()
        && config_overrides_from.is_none()
        && path_prefix.is_empty()
        && host.is_empty()
        && tenant.is_none()
        && team.is_none()
    {
        return Ok(None);
    }
    if team.is_some() && tenant.is_none() {
        return Err(OpError::InvalidArgument(
            "deploy: --team requires --tenant".to_string(),
        ));
    }
    let bundle_path = bundle.ok_or_else(|| {
        OpError::InvalidArgument(
            "deploy: missing `--bundle <PATH>` (the local .gtbundle to deploy)".to_string(),
        )
    })?;
    let bundle_id = match bundle_id {
        Some(id) => id,
        None => bundle_path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OpError::InvalidArgument(format!(
                    "deploy: cannot derive bundle_id from `{}` — pass `--bundle-id <ID>`",
                    bundle_path.display()
                ))
            })?,
    };
    let config_overrides = parse_config_overrides_cli(
        &config_override,
        &config_override_json,
        config_overrides_from,
    )?;
    let route_binding = route_binding_from_cli(host, path_prefix, tenant, team)?;
    Ok(Some(BundleDeployPayload {
        environment_id: env.unwrap_or_else(default_environment_id),
        bundle_id,
        customer_id,
        bundle_path: Some(bundle_path),
        bundle_source_uri: None,
        idempotency_key,
        config_overrides,
        route_binding,
        // `op deploy` CLI has no revenue-share flag; defaults stay in
        // `bundles add`. The env-manifest apply path sets this directly.
        revenue_share: None,
    }))
}

/// Build a `Some(RouteBindingPayload)` when ANY routing flag was supplied,
/// `None` otherwise (caller leaves existing binding alone on re-deploy).
///
/// `team` defaults to `default` when `--tenant` is supplied without `--team`
/// (matches the bundles-update payload shape the demo emits by hand). The
/// reverse — `--team` without `--tenant` — is rejected in the caller before
/// we get here. Calls `RouteBindingPayload::validate()` so the same
/// unreachable-binding check covers both flag-built and `--answers` JSON
/// payloads.
fn route_binding_from_cli(
    hosts: Vec<String>,
    path_prefixes: Vec<String>,
    tenant: Option<String>,
    team: Option<String>,
) -> Result<Option<RouteBindingPayload>, OpError> {
    if hosts.is_empty() && path_prefixes.is_empty() && tenant.is_none() {
        return Ok(None);
    }
    let tenant_selector = tenant.map(|t| super::bundles::TenantSelectorPayload {
        tenant: t,
        team: team.unwrap_or_else(|| "default".to_string()),
    });
    let payload = RouteBindingPayload {
        hosts,
        path_prefixes,
        tenant_selector,
    };
    payload.validate()?;
    Ok(Some(payload))
}

/// Parse `--config-override` / `--config-override-json` / `--config-overrides-from`
/// CLI args into the `Option<BTreeMap<pack_id, BTreeMap<key, json>>>` shape
/// that `BundleDeployPayload.config_overrides` expects.
///
/// Returns `None` when no override input was supplied at all (leave existing
/// alone). Returns `Some(empty)` when the caller explicitly passed `{}`
/// (clear existing overrides — Codex finding 3).
///
/// **String flag** (repeating): `--config-override <pack_id>:<key>=<value>`.
/// The value is ALWAYS stored as `Value::String` — no JSON coercion
/// (Codex finding 4). Use `--config-override-json` for typed values.
///
/// **JSON flag** (repeating): `--config-override-json <pack_id>:<key>=<json>`.
/// The value is parsed as JSON; a parse error is an `InvalidArgument`.
///
/// **File form**: `--config-overrides-from <FILE>` — the file is read as a
/// JSON object matching the on-the-wire `config_overrides` shape. Repeating
/// flag entries are merged ON TOP of the file (per-pack, per-key): the flag
/// wins on conflict, so a `--config-overrides-from base.json` plus a
/// `--config-override messaging-telegram:api_base_url=https://staging` lets
/// staging override the file's default.
fn parse_config_overrides_cli(
    string_specs: &[String],
    json_specs: &[String],
    from_file: Option<PathBuf>,
) -> Result<Option<ConfigOverridesMap>, OpError> {
    // No input at all → None (leave existing untouched).
    if string_specs.is_empty() && json_specs.is_empty() && from_file.is_none() {
        return Ok(None);
    }
    let mut overrides: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    if let Some(path) = from_file {
        let bytes = std::fs::read(&path).map_err(|e| {
            OpError::InvalidArgument(format!(
                "deploy: cannot read --config-overrides-from `{}`: {e}",
                path.display()
            ))
        })?;
        let parsed: BTreeMap<String, BTreeMap<String, Value>> = serde_json::from_slice(&bytes)
            .map_err(|e| {
                OpError::InvalidArgument(format!(
                    "deploy: --config-overrides-from `{}` is not a valid \
                     `{{<pack_id>: {{<key>: <value>}}}}` JSON object: {e}",
                    path.display()
                ))
            })?;
        overrides = parsed;
    }
    for spec in string_specs {
        let (pack_id, key, value_raw) = split_override_spec(spec, "--config-override")?;
        overrides
            .entry(pack_id)
            .or_default()
            .insert(key, Value::String(value_raw.to_string()));
    }
    for spec in json_specs {
        let (pack_id, key, value) = parse_one_config_override_json(spec)?;
        overrides.entry(pack_id).or_default().insert(key, value);
    }
    Ok(Some(overrides))
}

/// Parse one `<pack_id>:<key>=<json>` spec where the value is parsed as
/// typed JSON. A parse error is `InvalidArgument`.
fn parse_one_config_override_json(spec: &str) -> Result<(String, String, Value), OpError> {
    let (pack_id, key, value_raw) = split_override_spec(spec, "--config-override-json")?;
    let value = serde_json::from_str::<Value>(value_raw).map_err(|e| {
        OpError::InvalidArgument(format!(
            "deploy: --config-override-json `{spec}` has invalid JSON value: {e}"
        ))
    })?;
    Ok((pack_id, key, value))
}

/// Shared `<pack_id>:<key>=<value>` splitting logic for both flag variants.
fn split_override_spec<'a>(
    spec: &'a str,
    flag_name: &str,
) -> Result<(String, String, &'a str), OpError> {
    let (pack_id, rest) = spec.split_once(':').ok_or_else(|| {
        OpError::InvalidArgument(format!(
            "deploy: {flag_name} `{spec}` is malformed — expected `<pack_id>:<key>=<value>`"
        ))
    })?;
    let (key, value_raw) = rest.split_once('=').ok_or_else(|| {
        OpError::InvalidArgument(format!(
            "deploy: {flag_name} `{spec}` is malformed — expected `<pack_id>:<key>=<value>`"
        ))
    })?;
    if pack_id.is_empty() || key.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "deploy: {flag_name} `{spec}` has an empty pack_id or key"
        )));
    }
    Ok((pack_id.to_string(), key.to_string(), value_raw))
}

/// Deserialize an [`OpOutcome`]'s `result` into a step summary, mapping any
/// failure to an internal-error `OpError` (the sub-verbs are typed, so this
/// should never fire in practice).
fn parse_summary<T: serde::de::DeserializeOwned>(
    outcome: OpOutcome,
    what: &str,
) -> Result<T, OpError> {
    serde_json::from_value(outcome.result).map_err(|e| {
        OpError::InvalidArgument(format!("internal: failed to parse {what} summary: {e}"))
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
        "no payload provided: pass --bundle <path>, --answers <path>, or supply the payload directly"
            .to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn deploy_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "BundleDeployPayload",
        "type": "object",
        "required": ["bundle_id", "bundle_path"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string", "default": "local"},
            "bundle_id": {"type": "string"},
            "customer_id": {"type": "string"},
            "bundle_path": {"type": "string", "description": "local .gtbundle path (required)"},
            "bundle_source_uri": {"type": "string", "description": "oci:// / repo:// / store:// ref the bundle was resolved from; makes the staged revision pullable by a remote worker. Omit for local-serve-only"},
            "idempotency_key": {"type": "string", "description": "supply to make retries idempotent"},
            "config_overrides": {
                "type": "object",
                "description": "D.4: per-pack provider config overrides keyed by pack_id (object of {key: json-value})",
                "additionalProperties": {"type": "object"}
            },
            "route_binding": {
                "type": "object",
                "description": "Set hosts / path_prefixes / tenant_selector at deploy time. Omit to keep the existing binding (or default empty on fresh add).",
                "properties": {
                    "hosts": {"type": "array", "items": {"type": "string"}},
                    "path_prefixes": {"type": "array", "items": {"type": "string"}},
                    "tenant_selector": {
                        "type": "object",
                        "properties": {
                            "tenant": {"type": "string"},
                            "team": {"type": "string"}
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{bootstrap_env_trust_root, make_env};
    use tempfile::tempdir;

    /// Schema-drift regression: `deploy_schema()` declares
    /// `additionalProperties: false`, so a `--schema`-driven `--answers` caller
    /// that supplies `bundle_source_uri` (the remote-pull coordinate) would be
    /// rejected unless the schema advertises the field.
    #[test]
    fn deploy_schema_lists_bundle_source_uri() {
        let schema = deploy_schema();
        assert!(
            schema.pointer("/properties/bundle_source_uri").is_some(),
            "deploy_schema must list `bundle_source_uri` so --schema-driven \
             callers can record the bundle's registry source (schema: {schema:#})"
        );
    }

    fn seeded_store() -> (tempfile::TempDir, LocalFsStore) {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        bootstrap_env_trust_root(&env_dir);
        (dir, store)
    }

    /// The real `.gtbundle` test fixture — extracted (pure-Rust squashfs) and
    /// pinned into a pack-list lock by the stage step, so the orchestration is
    /// exercised against an artifact-backed revision, not a placeholder.
    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/perf-smoke-bundle.gtbundle")
    }

    fn payload(bundle_id: &str) -> BundleDeployPayload {
        BundleDeployPayload {
            environment_id: "local".to_string(),
            bundle_id: bundle_id.to_string(),
            customer_id: None,
            bundle_path: Some(fixture()),
            bundle_source_uri: None,
            idempotency_key: None,
            config_overrides: None,
            route_binding: None,
            revenue_share: None,
        }
    }

    fn deploy_summary(outcome: OpOutcome) -> DeploySummary {
        serde_json::from_value(outcome.result).expect("DeploySummary")
    }

    /// Build a single-pack override map matching the perf-smoke fixture.
    fn perf_smoke_override(url: &str) -> BTreeMap<String, BTreeMap<String, Value>> {
        BTreeMap::from([(
            "perf-smoke-pack".to_string(),
            BTreeMap::from([("api_base_url".to_string(), Value::String(url.to_string()))]),
        )])
    }

    #[test]
    fn fresh_deploy_creates_and_routes() {
        let (_dir, store) = seeded_store();
        let outcome = deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap();
        let s = deploy_summary(outcome);
        assert!(!s.reused_deployment);
        assert!(!s.deployment_id.is_empty());
        assert!(!s.revision_id.is_empty());
        assert!(s.superseded_revisions.is_empty());
        assert_eq!(s.status, "routed");

        // One deployment, one live split at 100 % on the new revision, and the
        // revision is artifact-backed (real digest derived from the .gtbundle).
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.bundles.len(), 1);
        assert_eq!(env.traffic_splits.len(), 1);
        let split = &env.traffic_splits[0];
        assert_eq!(split.entries.len(), 1);
        assert_eq!(split.entries[0].weight_bps, FULL_TRAFFIC_BPS);
        assert_eq!(split.entries[0].revision_id.to_string(), s.revision_id);
        let rev = env
            .revisions
            .iter()
            .find(|r| r.revision_id.to_string() == s.revision_id)
            .expect("revision persisted");
        assert!(
            rev.bundle_digest.starts_with("sha256:") && rev.bundle_digest != "sha256:00",
            "deploy must stage a real artifact digest, got {}",
            rev.bundle_digest
        );
    }

    #[test]
    fn deploy_without_bundle_path_rejected() {
        // The artifact is required on every path, including `--answers` payloads
        // that omit it: deploy must never publish a placeholder-digest revision.
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.bundle_path = None;
        let err = deploy(&store, &OpFlags::default(), Some(p)).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => assert!(msg.contains("--bundle"), "got {msg}"),
            other => panic!("expected InvalidArgument requiring --bundle, got {other:?}"),
        }
        // No partial state: nothing was added before the rejection.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert!(env.bundles.is_empty());
    }

    #[test]
    fn redeploy_with_same_idempotency_key_is_noop() {
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.idempotency_key = Some("rollout-1".to_string());
        let first = deploy_summary(deploy(&store, &OpFlags::default(), Some(p.clone())).unwrap());
        let second = deploy_summary(deploy(&store, &OpFlags::default(), Some(p)).unwrap());

        // The keyed retry returns the existing rollout, mints no new revision,
        // and leaves the rollback target untouched.
        assert_eq!(second.revision_id, first.revision_id);
        assert_eq!(second.deployment_id, first.deployment_id);
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(
            env.revisions.len(),
            1,
            "no duplicate revision on keyed retry"
        );
        let split = &env.traffic_splits[0];
        assert!(
            split.previous_split_ref.is_none(),
            "rollback target must not be disturbed by an idempotent retry"
        );
    }

    #[test]
    fn redeploy_reuses_deployment_and_blue_green_shifts_traffic() {
        let (_dir, store) = seeded_store();
        let first = deploy_summary(
            deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap(),
        );
        let second = deploy_summary(
            deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap(),
        );

        assert!(second.reused_deployment);
        assert_eq!(second.deployment_id, first.deployment_id);
        assert_ne!(second.revision_id, first.revision_id);
        // The first revision was live before; it is now superseded.
        assert_eq!(second.superseded_revisions, vec![first.revision_id.clone()]);

        // Still a single deployment; the live split now points 100 % at rev2.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.bundles.len(), 1);
        let split = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id.to_string() == second.deployment_id)
            .expect("split for deployment");
        assert_eq!(split.entries.len(), 1);
        assert_eq!(split.entries[0].revision_id.to_string(), second.revision_id);
        // The superseded revision is retained (not archived) for rollback.
        assert!(
            env.revisions
                .iter()
                .any(|r| r.revision_id.to_string() == first.revision_id)
        );
    }

    #[test]
    fn missing_env_errors_with_init_hint() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // No env saved.
        let err = deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap_err();
        match err {
            OpError::NotFound(msg) => assert!(msg.contains("env init"), "got {msg}"),
            other => panic!("expected NotFound with init hint, got {other:?}"),
        }
    }

    #[test]
    fn empty_bundle_id_rejected() {
        let (_dir, store) = seeded_store();
        let err = deploy(&store, &OpFlags::default(), Some(payload("  "))).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn derives_bundle_id_from_filename_stem() {
        let args = super::super::dispatch::BundleDeployArgs {
            bundle: Some(PathBuf::from("/tmp/quickstart.gtbundle")),
            env: None,
            bundle_id: None,
            customer_id: None,
            idempotency_key: None,
            config_override: Vec::new(),
            config_override_json: Vec::new(),
            config_overrides_from: None,
            path_prefix: Vec::new(),
            host: Vec::new(),
            tenant: None,
            team: None,
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        assert_eq!(p.bundle_id, "quickstart");
        assert_eq!(p.environment_id, "local");
    }

    #[test]
    fn no_args_defers_to_answers() {
        let args = super::super::dispatch::BundleDeployArgs {
            bundle: None,
            env: None,
            bundle_id: None,
            customer_id: None,
            idempotency_key: None,
            config_override: Vec::new(),
            config_override_json: Vec::new(),
            config_overrides_from: None,
            path_prefix: Vec::new(),
            host: Vec::new(),
            tenant: None,
            team: None,
        };
        assert!(payload_from_deploy_args(args).unwrap().is_none());
    }

    #[test]
    fn missing_bundle_with_other_args_errors() {
        let args = super::super::dispatch::BundleDeployArgs {
            bundle: None,
            env: Some("local".to_string()),
            bundle_id: None,
            customer_id: None,
            idempotency_key: None,
            config_override: Vec::new(),
            config_override_json: Vec::new(),
            config_overrides_from: None,
            path_prefix: Vec::new(),
            host: Vec::new(),
            tenant: None,
            team: None,
        };
        let err = payload_from_deploy_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    // ---- D.4 train-2 ----------------------------------------------------

    fn empty_args() -> super::super::dispatch::BundleDeployArgs {
        super::super::dispatch::BundleDeployArgs {
            bundle: Some(PathBuf::from("/tmp/quickstart.gtbundle")),
            env: None,
            bundle_id: None,
            customer_id: None,
            idempotency_key: None,
            config_override: Vec::new(),
            config_override_json: Vec::new(),
            config_overrides_from: None,
            path_prefix: Vec::new(),
            host: Vec::new(),
            tenant: None,
            team: None,
        }
    }

    /// `--config-override` always stores values as strings (Codex finding 4).
    #[test]
    fn config_override_flag_always_stores_string() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec![
                "messaging-telegram:api_base_url=https://staging.example.com".to_string(),
                "messaging-telegram:retry_max=5".to_string(),
                "messaging-slack:enabled=true".to_string(),
            ],
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let overrides = p.config_overrides.as_ref().unwrap();
        assert_eq!(
            overrides["messaging-telegram"]["api_base_url"],
            Value::String("https://staging.example.com".to_string())
        );
        // Not Number(5) — string flag never coerces.
        assert_eq!(
            overrides["messaging-telegram"]["retry_max"],
            Value::String("5".to_string())
        );
        // Not Bool(true) — string flag never coerces.
        assert_eq!(
            overrides["messaging-slack"]["enabled"],
            Value::String("true".to_string())
        );
    }

    /// `--config-override-json` parses typed JSON values.
    #[test]
    fn config_override_json_flag_parses_typed_values() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override_json: vec![
                "messaging-telegram:retry_max=5".to_string(),
                r#"messaging-slack:enabled=true"#.to_string(),
                r#"messaging-telegram:tags=["a","b"]"#.to_string(),
            ],
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let overrides = p.config_overrides.as_ref().unwrap();
        assert_eq!(
            overrides["messaging-telegram"]["retry_max"],
            Value::Number(serde_json::Number::from(5))
        );
        assert_eq!(overrides["messaging-slack"]["enabled"], Value::Bool(true));
        assert_eq!(
            overrides["messaging-telegram"]["tags"],
            serde_json::json!(["a", "b"])
        );
    }

    /// `--config-override-json` with invalid JSON is an error.
    #[test]
    fn config_override_json_rejects_invalid_json() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override_json: vec!["pack:k=not-valid-json".to_string()],
            ..empty_args()
        };
        let err = payload_from_deploy_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(msg.contains("config-override-json"), "got {msg}");
    }

    /// Both flag forms merge into the same map (later flags win per-(pack,key)).
    #[test]
    fn config_override_and_json_flags_merge() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec![
                "messaging-telegram:api_base_url=https://staging.example.com".to_string(),
            ],
            config_override_json: vec!["messaging-telegram:retry_max=3".to_string()],
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let overrides = p.config_overrides.as_ref().unwrap();
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides["messaging-telegram"].len(), 2);
    }

    #[test]
    fn config_override_repeating_flags_merge_per_pack() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec![
                "messaging-telegram:api_base_url=https://staging.example.com".to_string(),
                "messaging-telegram:retry_max=3".to_string(),
                "messaging-slack:webhook_url=https://hooks.slack/abc".to_string(),
            ],
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let overrides = p.config_overrides.as_ref().unwrap();
        assert_eq!(overrides.len(), 2);
        assert_eq!(overrides["messaging-telegram"].len(), 2);
        assert_eq!(overrides["messaging-slack"].len(), 1);
    }

    #[test]
    fn config_override_rejects_missing_colon() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec!["api_base_url=https://example.com".to_string()],
            ..empty_args()
        };
        let err = payload_from_deploy_args(args).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => {
                assert!(msg.contains("config-override"), "got {msg}")
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn config_override_rejects_missing_equals() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec!["pack:no-value".to_string()],
            ..empty_args()
        };
        let err = payload_from_deploy_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn config_override_rejects_empty_pack_or_key() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec![":key=value".to_string()],
            ..empty_args()
        };
        assert!(matches!(
            payload_from_deploy_args(args).unwrap_err(),
            OpError::InvalidArgument(_)
        ));
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec!["pack:=value".to_string()],
            ..empty_args()
        };
        assert!(matches!(
            payload_from_deploy_args(args).unwrap_err(),
            OpError::InvalidArgument(_)
        ));
    }

    #[test]
    fn config_overrides_from_file_loads_bulk_and_flags_override_per_key() {
        // File supplies a baseline; a `--config-override` flag wins per (pack, key).
        let dir = tempdir().unwrap();
        let file = dir.path().join("overrides.json");
        std::fs::write(
            &file,
            r#"{
                "messaging-telegram": {
                    "api_base_url": "https://prod.example.com",
                    "retry_max": 10
                }
            }"#,
        )
        .unwrap();
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: vec![
                "messaging-telegram:api_base_url=https://staging.example.com".to_string(),
            ],
            config_overrides_from: Some(file),
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let overrides = p.config_overrides.as_ref().unwrap();
        // Flag wins the api_base_url key
        assert_eq!(
            overrides["messaging-telegram"]["api_base_url"],
            Value::String("https://staging.example.com".to_string())
        );
        // File's retry_max survives (flag didn't override it)
        assert_eq!(
            overrides["messaging-telegram"]["retry_max"],
            Value::Number(serde_json::Number::from(10))
        );
    }

    #[test]
    fn config_overrides_from_missing_file_errors() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_overrides_from: Some(PathBuf::from("/nonexistent/path/overrides.json")),
            ..empty_args()
        };
        assert!(matches!(
            payload_from_deploy_args(args).unwrap_err(),
            OpError::InvalidArgument(_)
        ));
    }

    /// No override input at all → `config_overrides: None` (Codex finding 3).
    #[test]
    fn no_override_input_yields_none() {
        let args = super::super::dispatch::BundleDeployArgs {
            config_override: Vec::new(),
            config_override_json: Vec::new(),
            config_overrides_from: None,
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        assert!(p.config_overrides.is_none());
    }

    /// Explicit empty `{}` file → `config_overrides: Some(empty)` (Codex finding 3).
    #[test]
    fn empty_overrides_file_yields_some_empty() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("empty.json");
        std::fs::write(&file, "{}").unwrap();
        let args = super::super::dispatch::BundleDeployArgs {
            config_overrides_from: Some(file),
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let overrides = p.config_overrides.as_ref().unwrap();
        assert!(overrides.is_empty(), "explicit {{}} → Some(empty)");
    }

    #[test]
    fn deploy_persists_config_overrides_via_add_path() {
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.config_overrides = Some(perf_smoke_override("https://staging.example.com"));
        let outcome = deploy(&store, &OpFlags::default(), Some(p)).unwrap();
        let s = deploy_summary(outcome);
        assert!(!s.reused_deployment, "fresh deploy");
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let bundle = env
            .bundles
            .iter()
            .find(|b| b.deployment_id.to_string() == s.deployment_id)
            .unwrap();
        assert_eq!(
            bundle.config_overrides["perf-smoke-pack"]["api_base_url"],
            Value::String("https://staging.example.com".to_string())
        );
    }

    #[test]
    fn redeploy_with_new_overrides_replaces_them_on_existing_bundle() {
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.config_overrides = Some(perf_smoke_override("https://v1.example.com"));
        deploy(&store, &OpFlags::default(), Some(p)).unwrap();
        let mut p2 = payload("quickstart");
        p2.config_overrides = Some(perf_smoke_override("https://v2.example.com"));
        let s = deploy_summary(deploy(&store, &OpFlags::default(), Some(p2)).unwrap());
        assert!(s.reused_deployment, "blue-green re-deploy");
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let bundle = env
            .bundles
            .iter()
            .find(|b| b.deployment_id.to_string() == s.deployment_id)
            .unwrap();
        assert_eq!(
            bundle.config_overrides["perf-smoke-pack"]["api_base_url"],
            Value::String("https://v2.example.com".to_string())
        );
    }

    /// `None` overrides on re-deploy leaves existing alone (Codex finding 3).
    #[test]
    fn redeploy_with_none_overrides_leaves_existing_alone() {
        let (_dir, store) = seeded_store();
        let initial = perf_smoke_override("https://v1.example.com");
        let mut p = payload("quickstart");
        p.config_overrides = Some(initial.clone());
        deploy(&store, &OpFlags::default(), Some(p)).unwrap();
        // Re-deploy with None (no override input) — existing must survive.
        let s = deploy_summary(
            deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap(),
        );
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let bundle = env
            .bundles
            .iter()
            .find(|b| b.deployment_id.to_string() == s.deployment_id)
            .unwrap();
        assert_eq!(bundle.config_overrides, initial);
    }

    /// `Some(empty)` overrides on re-deploy clears existing (Codex finding 3).
    #[test]
    fn redeploy_with_explicit_empty_overrides_clears_existing() {
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.config_overrides = Some(perf_smoke_override("https://v1.example.com"));
        deploy(&store, &OpFlags::default(), Some(p)).unwrap();
        // Re-deploy with Some(empty) — explicit clear.
        let mut p2 = payload("quickstart");
        p2.config_overrides = Some(BTreeMap::new());
        let s = deploy_summary(deploy(&store, &OpFlags::default(), Some(p2)).unwrap());
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let bundle = env
            .bundles
            .iter()
            .find(|b| b.deployment_id.to_string() == s.deployment_id)
            .unwrap();
        assert!(
            bundle.config_overrides.is_empty(),
            "explicit clear must empty the map"
        );
    }

    // ---- routing flags (Change A) ---------------------------------------

    #[test]
    fn route_flags_build_payload() {
        let args = super::super::dispatch::BundleDeployArgs {
            path_prefix: vec!["/legal".to_string()],
            host: vec!["api.example.com".to_string()],
            tenant: Some("legal".to_string()),
            team: Some("legal-team".to_string()),
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let rb = p.route_binding.as_ref().expect("route_binding set");
        assert_eq!(rb.path_prefixes, vec!["/legal"]);
        assert_eq!(rb.hosts, vec!["api.example.com"]);
        let ts = rb.tenant_selector.as_ref().expect("tenant_selector");
        assert_eq!(ts.tenant, "legal");
        assert_eq!(ts.team, "legal-team");
    }

    #[test]
    fn tenant_without_team_defaults_to_default() {
        let args = super::super::dispatch::BundleDeployArgs {
            tenant: Some("legal".to_string()),
            path_prefix: vec!["/legal".to_string()],
            ..empty_args()
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        let ts = p
            .route_binding
            .as_ref()
            .and_then(|rb| rb.tenant_selector.as_ref())
            .expect("tenant_selector");
        assert_eq!(ts.tenant, "legal");
        assert_eq!(ts.team, "default");
    }

    #[test]
    fn team_without_tenant_rejected() {
        let args = super::super::dispatch::BundleDeployArgs {
            team: Some("billing".to_string()),
            ..empty_args()
        };
        let err = payload_from_deploy_args(args).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => assert!(msg.contains("--team requires --tenant")),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn no_routing_flags_yields_none() {
        let args = empty_args();
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        assert!(
            p.route_binding.is_none(),
            "no routing flags → route_binding is None (leave existing alone)"
        );
    }

    #[test]
    fn fresh_deploy_with_route_binding_persists_it() {
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.route_binding = Some(RouteBindingPayload {
            hosts: Vec::new(),
            path_prefixes: vec!["/legal".to_string()],
            tenant_selector: Some(super::super::bundles::TenantSelectorPayload {
                tenant: "legal".to_string(),
                team: "default".to_string(),
            }),
        });
        let s = deploy_summary(deploy(&store, &OpFlags::default(), Some(p)).unwrap());
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let bundle = env
            .bundles
            .iter()
            .find(|b| b.deployment_id.to_string() == s.deployment_id)
            .unwrap();
        assert_eq!(
            bundle.route_binding.path_prefixes,
            vec!["/legal".to_string()]
        );
        // RouteBinding.tenant_selector is not Option in the persisted form;
        // `into_route_binding` populates a literal "default"/"default" when
        // the payload's Option is None. Here we supplied a real selector.
        assert_eq!(bundle.route_binding.tenant_selector.tenant, "legal");
        assert_eq!(bundle.route_binding.tenant_selector.team, "default");
    }

    /// A re-deploy with a DIFFERENT route_binding is rejected (rollback-safety:
    /// `traffic rollback` only restores the TrafficSplit, not the binding).
    #[test]
    fn redeploy_with_differing_route_binding_rejected() {
        let (_dir, store) = seeded_store();
        let mut p1 = payload("quickstart");
        p1.route_binding = Some(RouteBindingPayload {
            hosts: Vec::new(),
            path_prefixes: vec!["/v1".to_string()],
            tenant_selector: None,
        });
        deploy(&store, &OpFlags::default(), Some(p1)).unwrap();
        let mut p2 = payload("quickstart");
        p2.route_binding = Some(RouteBindingPayload {
            hosts: Vec::new(),
            path_prefixes: vec!["/v2".to_string()],
            tenant_selector: Some(super::super::bundles::TenantSelectorPayload {
                tenant: "legal".to_string(),
                team: "default".to_string(),
            }),
        });
        let err = deploy(&store, &OpFlags::default(), Some(p2)).unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(
                    msg.contains("route_binding differs"),
                    "expected 'route_binding differs', got {msg}"
                );
                assert!(
                    msg.contains("bundles update"),
                    "expected guidance to use 'bundles update', got {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    /// A re-deploy with the SAME route_binding is a no-op (skip bundles::update).
    #[test]
    fn redeploy_with_matching_route_binding_is_noop() {
        let (_dir, store) = seeded_store();
        let rb = RouteBindingPayload {
            hosts: Vec::new(),
            path_prefixes: vec!["/legal".to_string()],
            tenant_selector: Some(super::super::bundles::TenantSelectorPayload {
                tenant: "legal".to_string(),
                team: "default".to_string(),
            }),
        };
        let mut p1 = payload("quickstart");
        p1.route_binding = Some(rb.clone());
        deploy(&store, &OpFlags::default(), Some(p1)).unwrap();
        // Re-deploy with the exact same route_binding.
        let mut p2 = payload("quickstart");
        p2.route_binding = Some(rb);
        let s = deploy_summary(deploy(&store, &OpFlags::default(), Some(p2)).unwrap());
        assert!(s.reused_deployment, "blue-green re-deploy");
        // Binding is unchanged.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let bundle = env
            .bundles
            .iter()
            .find(|b| b.deployment_id.to_string() == s.deployment_id)
            .unwrap();
        assert_eq!(
            bundle.route_binding.path_prefixes,
            vec!["/legal".to_string()]
        );
        assert_eq!(bundle.route_binding.tenant_selector.tenant, "legal");
        assert_eq!(bundle.route_binding.tenant_selector.team, "default");
    }

    /// `--tenant` without `--host` or `--path-prefix` is rejected (the binding
    /// would have no matchers and be unreachable).
    #[test]
    fn tenant_without_host_or_path_rejected() {
        let args = super::super::dispatch::BundleDeployArgs {
            tenant: Some("legal".to_string()),
            ..empty_args()
        };
        let err = payload_from_deploy_args(args).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("host") && msg.contains("path_prefix"),
                    "expected validate() message mentioning host and path_prefix, got {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    /// `--answers` JSON with the same unreachable shape must be rejected too,
    /// because validate() runs on the payload at `deploy()` entry — not just
    /// at the CLI flag layer (altitude fix).
    #[test]
    fn answers_payload_with_unreachable_route_binding_rejected() {
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.route_binding = Some(RouteBindingPayload {
            hosts: Vec::new(),
            path_prefixes: Vec::new(),
            tenant_selector: Some(super::super::bundles::TenantSelectorPayload {
                tenant: "legal".to_string(),
                team: "default".to_string(),
            }),
        });
        let err = deploy(&store, &OpFlags::default(), Some(p)).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => assert!(
                msg.contains("host") && msg.contains("path_prefix"),
                "got {msg}"
            ),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        // No partial state: validate() ran before any add/stage.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert!(env.bundles.is_empty(), "no deployment created");
    }

    #[test]
    fn redeploy_without_route_binding_leaves_existing_alone() {
        let (_dir, store) = seeded_store();
        let mut p1 = payload("quickstart");
        p1.route_binding = Some(RouteBindingPayload {
            hosts: Vec::new(),
            path_prefixes: vec!["/legal".to_string()],
            tenant_selector: None,
        });
        deploy(&store, &OpFlags::default(), Some(p1)).unwrap();
        // Re-deploy with route_binding = None — existing must survive.
        let s = deploy_summary(
            deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap(),
        );
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let bundle = env
            .bundles
            .iter()
            .find(|b| b.deployment_id.to_string() == s.deployment_id)
            .unwrap();
        assert_eq!(
            bundle.route_binding.path_prefixes,
            vec!["/legal".to_string()],
            "route_binding=None must NOT clear the existing binding"
        );
    }
}
