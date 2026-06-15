//! `greentic.env-manifest.v1` — the declarative desired-state document
//! consumed by `gtc op env apply` (PR-1 of `plans/env-manifest-apply.md`).
//!
//! The manifest declares the desired *wiring* of one environment: env
//! identity, trust root, secrets, bundle deployments with route
//! bindings, and messaging endpoints with their bundle links. It is a
//! durable document keyed by resource natural keys, designed to live in
//! version control and be re-applied — NOT a recorded wizard-answers file
//! and NOT a batch of per-verb payloads (see the design doc §4 for why
//! those shapes were rejected).
//!
//! This module owns the serde types plus the manifest-*shape* validation
//! (everything checkable without touching the store or the filesystem).
//! Environment-dependent validation, artifact digesting, diffing, and
//! execution live in [`super::env_apply`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use greentic_deploy_spec::CapabilitySlot;
use qa_spec::spec::ListSpec;
use qa_spec::spec::question::QuestionPolicy;
use qa_spec::{AnswerSet, Expr, FormSpec, QuestionSpec, QuestionType};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use greentic_deploy_spec::BundleDeploymentStatus;

use super::OpError;
use super::bundles::{RevenueShareEntryPayload, RouteBindingPayload, TenantSelectorPayload};

/// Exact `schema` discriminator the manifest must carry.
pub const ENV_MANIFEST_SCHEMA_V1: &str = "greentic.env-manifest.v1";

/// Top-level manifest document. `deny_unknown_fields` everywhere so a typo
/// fails loudly at parse time instead of silently no-opping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvManifest {
    /// Must equal [`ENV_MANIFEST_SCHEMA_V1`].
    pub schema: String,
    pub environment: ManifestEnvironment,
    /// `"bootstrap"` seeds the env trust root with the local operator key
    /// (idempotent). Absent = skip the step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_root: Option<TrustRootDirective>,
    /// Dev-store secret entries — always-put (`op secrets get` is
    /// not-yet-implemented, so values cannot be diffed until A9).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<ManifestSecret>,
    /// Env-pack bindings (capability slots that `binds_in_packs`). Each slot
    /// must be a core capability (not Messaging/Extension). Applied after
    /// trust-root, before secrets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<ManifestPack>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<ManifestBundle>,
    /// Extension bindings (N-per-env, open namespace). Applied after bundles,
    /// before messaging endpoints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ManifestExtension>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messaging_endpoints: Vec<ManifestEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEnvironment {
    /// Environment id. Apply bootstraps `local` (via `env init`, seeding the
    /// default env-pack bindings). Any other id must ALREADY exist — apply
    /// reconciles a non-local env but cannot create one (non-local creation
    /// is reserved for the remote operator store, A7).
    pub id: String,
    /// When set, persisted via the `env set-public-url` path. Absent/`null`
    /// means "leave whatever is there" (upsert — apply never clears it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    /// Human-readable display name. Absent = leave untouched; set = reconciled
    /// via `op config set` on the existing env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Cloud region tag. Absent = leave untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Tenant organization id. Absent = leave untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_org_id: Option<String>,
    /// Bind address for the runtime's local HTTP listener (parsed as
    /// `SocketAddr` during shape validation). Absent = leave untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,
}

/// v1 accepts only the string `"bootstrap"`. A future
/// `{ "additional_keys": [...] }` shape extends this enum without a schema
/// bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustRootDirective {
    Bootstrap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSecret {
    /// Dev-store path `<tenant>/<team>/<pack>/<name>` — exactly the
    /// `SecretsPutPayload.path` shape.
    pub path: String,
    /// Name of the environment variable holding the value — apply reads
    /// `$from_env` at apply time. Absent ⇒ the value is supplied
    /// interactively (a masked paste prompt) and read back from the env's
    /// secrets store on re-apply. Secret VALUES never appear in the manifest
    /// either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_env: Option<String>,
}

/// One env-pack binding: a core capability slot bound to a pack descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPack {
    /// The capability slot (must satisfy `binds_in_packs()`).
    pub slot: CapabilitySlot,
    /// Pack descriptor string, e.g. `greentic.secrets.dev-store@1.0.0`.
    pub kind: String,
    /// Pack reference (registry id or local path).
    pub pack_ref: String,
    /// Optional answers file relative to the manifest directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_ref: Option<PathBuf>,
}

/// One extension binding in the open-namespace `extensions[]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestExtension {
    /// Pack descriptor string, e.g. `acme.oauth.auth0@1.0.0`.
    pub kind: String,
    /// Pack reference (registry id or local path).
    pub pack_ref: String,
    /// Instance selector for N instances of the same extension type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// Optional answers file relative to the manifest directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_ref: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBundle {
    /// Natural key — unique within the manifest.
    pub bundle_id: String,
    /// Single-revision form (100 % traffic): local `.gtbundle`. Relative
    /// paths resolve against the manifest file's directory (not the CWD),
    /// so manifests are relocatable. Mutually exclusive with `revisions`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<PathBuf>,
    /// Multi-revision / traffic-split form: each entry names a revision
    /// with its own bundle artifact and optional weight. Mutually
    /// exclusive with `bundle_path`. The wizard (`answers_to_manifest`)
    /// always produces the single-revision form; multi-revision is
    /// JSON-first (hand-authored or generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revisions: Option<Vec<ManifestRevision>>,
    /// Billing principal (P6/B10): required for non-`local` environments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    /// Revenue-share split (G2). Absent = leave untouched (`greentic@10000`
    /// on a fresh deploy). When set, the entries' `basis_points` must sum to
    /// exactly 10 000; applied at create time and reconciled via
    /// `bundles update` for an existing deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revenue_share: Option<Vec<RevenueShareEntryPayload>>,
    /// Deployment status (G3): `active` | `paused` | `archived`. Absent =
    /// leave untouched. Reconciled via `bundles update` against an existing
    /// deployment; a freshly-created deployment is always `active` and a
    /// declared non-`active` status converges on the next apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<BundleDeploymentStatus>,
    /// Forwarded verbatim with `op deploy`'s three-valued semantics:
    /// absent = leave untouched, `{}` = explicit clear, non-empty = replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
    /// Absent = same as `op deploy`: empty binding on fresh add, untouched
    /// on re-deploy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_binding: Option<RouteBindingPayload>,
}

/// One revision in a multi-revision bundle entry. Each carries its own
/// bundle artifact path and optional traffic weight / drain / abort knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRevision {
    /// Manifest-local handle — unique within the bundle's `revisions[]`.
    pub name: String,
    /// Local `.gtbundle`. Same path-resolution rules as
    /// [`ManifestBundle::bundle_path`].
    pub bundle_path: PathBuf,
    /// Traffic weight as a percentage (0..=100). Mutually exclusive with
    /// `weight_bps` on the same revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_percent: Option<u32>,
    /// Traffic weight in basis points (0..=10 000). Mutually exclusive
    /// with `weight_percent` on the same revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_bps: Option<u32>,
    /// Per-revision drain window override (seconds). Forwarded to
    /// `RevisionStagePayload.drain_seconds`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_seconds: Option<u32>,
    /// Abort-metric names for canary evaluation. Reserved for the
    /// canary-evaluation engine (not consumed by apply today).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub abort_metrics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEndpoint {
    /// Manifest-local handle AND the endpoint's `display_name` AND (on
    /// create) its `provider_id` instance identity. Upsert natural key:
    /// apply matches an existing endpoint by `(provider_type, name)`.
    pub name: String,
    /// Provider class, e.g. `messaging.telegram.bot`.
    pub provider_type: String,
    /// `bundle_id`s this endpoint admits. Each must be declared in this
    /// manifest's `bundles[]` or already exist in the environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_flow: Option<ManifestWelcomeFlow>,
    /// Forwarded to `EndpointAddPayload.secret_refs` on create. Drift on an
    /// existing endpoint is reported as a warning (no update verb exists).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestWelcomeFlow {
    pub bundle_id: String,
    pub pack_id: String,
    pub flow_id: String,
}

impl EnvManifest {
    /// Manifest-shape validation: everything checkable without the store or
    /// the filesystem. Runs before any artifact digesting or env read so a
    /// malformed manifest fails fast with no side effects.
    pub fn validate_shape(&self) -> Result<(), OpError> {
        if self.schema != ENV_MANIFEST_SCHEMA_V1 {
            return Err(OpError::InvalidArgument(format!(
                "manifest schema `{}` is not the expected `{ENV_MANIFEST_SCHEMA_V1}`",
                self.schema
            )));
        }
        if self.environment.id.trim().is_empty() {
            return Err(OpError::InvalidArgument(
                "environment.id must not be empty".to_string(),
            ));
        }
        // listen_addr: parse-validate as SocketAddr at shape time.
        if let Some(raw) = &self.environment.listen_addr {
            raw.parse::<std::net::SocketAddr>().map_err(|e| {
                OpError::InvalidArgument(format!(
                    "environment.listen_addr `{raw}` is not a valid socket address: {e}"
                ))
            })?;
        }

        // Env-pack bindings: each slot must bind in packs, unique slots,
        // kind must parse as PackDescriptor, pack_ref non-empty.
        let mut pack_slots = BTreeSet::new();
        for p in &self.packs {
            if !p.slot.binds_in_packs() {
                return Err(OpError::InvalidArgument(format!(
                    "packs[]: slot `{}` does not bind in packs — use \
                     messaging_endpoints[] or extensions[] instead",
                    p.slot
                )));
            }
            if !pack_slots.insert(p.slot) {
                return Err(OpError::InvalidArgument(format!(
                    "duplicate slot `{}` in manifest packs[]",
                    p.slot
                )));
            }
            greentic_deploy_spec::PackDescriptor::try_new(&p.kind).map_err(|e| {
                OpError::InvalidArgument(format!("packs[] slot `{}`: kind: {e}", p.slot))
            })?;
            if p.pack_ref.trim().is_empty() {
                return Err(OpError::InvalidArgument(format!(
                    "packs[] slot `{}`: pack_ref must not be empty",
                    p.slot
                )));
            }
        }

        // Extension bindings: unique (kind.path(), instance_id), kind parses,
        // instance_id chars [a-z0-9-] non-empty when present, pack_ref non-empty.
        let mut ext_keys = BTreeSet::new();
        for ext in &self.extensions {
            let descriptor =
                greentic_deploy_spec::PackDescriptor::try_new(&ext.kind).map_err(|e| {
                    OpError::InvalidArgument(format!("extensions[]: kind `{}`: {e}", ext.kind))
                })?;
            if ext.pack_ref.trim().is_empty() {
                return Err(OpError::InvalidArgument(format!(
                    "extensions[] kind `{}`: pack_ref must not be empty",
                    ext.kind
                )));
            }
            if let Some(inst) = &ext.instance_id
                && (inst.is_empty()
                    || !inst
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
            {
                return Err(OpError::InvalidArgument(format!(
                    "extensions[] kind `{}`: instance_id `{inst}` must be non-empty \
                     and contain only [a-z0-9-]",
                    ext.kind
                )));
            }
            let key = (
                descriptor.path().to_string(),
                ext.instance_id.as_deref().unwrap_or("").to_string(),
            );
            if !ext_keys.insert(key) {
                return Err(OpError::InvalidArgument(format!(
                    "duplicate extension (path `{}`, instance_id {:?}) in manifest extensions[]",
                    descriptor.path(),
                    ext.instance_id
                )));
            }
        }

        // Secrets: path shape + canonicality via the same checks
        // `secrets.rs::put` applies (shared helper — the two surfaces cannot
        // drift), so a bad path fails the whole apply here instead of
        // mid-run. `from_env` *resolution* (var set + non-empty) needs
        // process context and lives in `env_apply`'s validation.
        let mut secret_paths = BTreeSet::new();
        for s in &self.secrets {
            let rel_path = s.path.trim_start_matches('/');
            super::secrets::validate_dev_store_secret_path(rel_path)?;
            if !secret_paths.insert(rel_path) {
                return Err(OpError::InvalidArgument(format!(
                    "duplicate secret path `{rel_path}` in manifest secrets[] \
                     (order-dependent last-write-wins is never what you want)"
                )));
            }
            if let Some(from_env) = &s.from_env
                && from_env.trim().is_empty()
            {
                return Err(OpError::InvalidArgument(format!(
                    "secret `{rel_path}`: from_env, when present, must name an environment \
                     variable — omit it entirely for a pasted (interactively-supplied) secret"
                )));
            }
        }

        let mut bundle_ids = BTreeSet::new();
        for b in &self.bundles {
            if b.bundle_id.trim().is_empty() {
                return Err(OpError::InvalidArgument(
                    "bundles[].bundle_id must not be empty".to_string(),
                ));
            }
            if !bundle_ids.insert(b.bundle_id.as_str()) {
                return Err(OpError::InvalidArgument(format!(
                    "duplicate bundle_id `{}` in manifest bundles[]",
                    b.bundle_id
                )));
            }
            // XOR: exactly one of `bundle_path` / `revisions` must be set.
            match (&b.bundle_path, &b.revisions) {
                (Some(_), None) | (None, Some(_)) => {}
                (Some(_), Some(_)) => {
                    return Err(OpError::InvalidArgument(format!(
                        "bundle `{}`: `bundle_path` and `revisions` are mutually exclusive \
                         — use `bundle_path` for single-revision (100 %) or `revisions` \
                         for a traffic split",
                        b.bundle_id
                    )));
                }
                (None, None) => {
                    return Err(OpError::InvalidArgument(format!(
                        "bundle `{}`: either `bundle_path` or `revisions` must be set",
                        b.bundle_id
                    )));
                }
            }

            // Per-revision validation (multi-revision form only).
            if let Some(revisions) = &b.revisions {
                if revisions.is_empty() {
                    return Err(OpError::InvalidArgument(format!(
                        "bundle `{}`: `revisions` must not be empty",
                        b.bundle_id
                    )));
                }
                let mut rev_names = BTreeSet::new();
                for rev in revisions {
                    if rev.name.trim().is_empty() {
                        return Err(OpError::InvalidArgument(format!(
                            "bundle `{}`: revision name must not be empty",
                            b.bundle_id
                        )));
                    }
                    if !rev_names.insert(rev.name.as_str()) {
                        return Err(OpError::InvalidArgument(format!(
                            "bundle `{}`: duplicate revision name `{}`",
                            b.bundle_id, rev.name
                        )));
                    }
                    // Per-revision: weight_percent and weight_bps are mutually exclusive.
                    if rev.weight_percent.is_some() && rev.weight_bps.is_some() {
                        return Err(OpError::InvalidArgument(format!(
                            "bundle `{}`, revision `{}`: `weight_percent` and `weight_bps` \
                             are mutually exclusive",
                            b.bundle_id, rev.name
                        )));
                    }
                }
                // Weight consistency: all-set must sum to FULL_TRAFFIC_BPS;
                // all-unset = equal split (computed at resolve time); mixed = error.
                validate_revision_weights(&b.bundle_id, revisions)?;
            }

            // Revenue-share (G2): when declared, the split must be non-empty
            // and sum to exactly FULL_TRAFFIC_BPS — mirrors the spec's
            // `validate_revenue_share` so a bad split fails at manifest-shape
            // time with a clear message instead of at store-save time.
            if let Some(shares) = &b.revenue_share {
                if shares.is_empty() {
                    return Err(OpError::InvalidArgument(format!(
                        "bundle `{}`: `revenue_share` must not be empty",
                        b.bundle_id
                    )));
                }
                let mut parties = BTreeSet::new();
                let mut sum: u64 = 0;
                for entry in shares {
                    if entry.party_id.trim().is_empty() {
                        return Err(OpError::InvalidArgument(format!(
                            "bundle `{}`: revenue_share party_id must not be empty",
                            b.bundle_id
                        )));
                    }
                    if !parties.insert(entry.party_id.as_str()) {
                        return Err(OpError::InvalidArgument(format!(
                            "bundle `{}`: duplicate revenue_share party_id `{}`",
                            b.bundle_id, entry.party_id
                        )));
                    }
                    sum += u64::from(entry.basis_points);
                }
                if sum != u64::from(FULL_TRAFFIC_BPS) {
                    return Err(OpError::InvalidArgument(format!(
                        "bundle `{}`: revenue_share basis_points sum to {sum}, must be exactly \
                         {FULL_TRAFFIC_BPS}",
                        b.bundle_id
                    )));
                }
            }

            if let Some(rb) = &b.route_binding {
                rb.validate()?;
                for prefix in &rb.path_prefixes {
                    if !prefix.starts_with('/') {
                        return Err(OpError::InvalidArgument(format!(
                            "bundle `{}` route_binding.path_prefixes entry `{prefix}` \
                             must start with `/`",
                            b.bundle_id
                        )));
                    }
                }
            }
        }

        let mut endpoint_names = BTreeSet::new();
        for ep in &self.messaging_endpoints {
            if ep.name.trim().is_empty() {
                return Err(OpError::InvalidArgument(
                    "messaging_endpoints[].name must not be empty".to_string(),
                ));
            }
            if ep.provider_type.trim().is_empty() {
                return Err(OpError::InvalidArgument(format!(
                    "endpoint `{}`: provider_type must not be empty",
                    ep.name
                )));
            }
            if !endpoint_names.insert(ep.name.as_str()) {
                return Err(OpError::InvalidArgument(format!(
                    "duplicate endpoint name `{}` in manifest messaging_endpoints[]",
                    ep.name
                )));
            }
            let mut link_set = BTreeSet::new();
            for link in &ep.links {
                if !link_set.insert(link.as_str()) {
                    return Err(OpError::InvalidArgument(format!(
                        "endpoint `{}`: duplicate link `{link}` in links[]",
                        ep.name
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Full traffic in basis points (10 000 bps = 100 %).
pub(crate) const FULL_TRAFFIC_BPS: u32 = 10_000;

/// Validate the weight consistency of a multi-revision bundle entry.
///
/// Three cases:
/// - **All unset**: equal split — computed at resolve time, nothing to
///   validate here.
/// - **All set** (via `weight_percent` or `weight_bps`): must sum to
///   exactly [`FULL_TRAFFIC_BPS`] (10 000 bps).
/// - **Mixed** (some set, some unset): error — no implicit remainder.
fn validate_revision_weights(
    bundle_id: &str,
    revisions: &[ManifestRevision],
) -> Result<(), OpError> {
    let has_weight: Vec<bool> = revisions
        .iter()
        .map(|r| r.weight_percent.is_some() || r.weight_bps.is_some())
        .collect();
    let all_set = has_weight.iter().all(|&w| w);
    let none_set = has_weight.iter().all(|&w| !w);
    if !all_set && !none_set {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{bundle_id}`: either ALL revisions must declare a weight or NONE \
             (equal split) — mixing set and unset weights is not allowed"
        )));
    }
    if all_set {
        let sum: u32 = revisions
            .iter()
            .map(|r| effective_bps_single(r).expect("all_set guarantees a weight"))
            .sum();
        if sum != FULL_TRAFFIC_BPS {
            return Err(OpError::InvalidArgument(format!(
                "bundle `{bundle_id}`: revision weights sum to {sum} bps, must be exactly \
                 {FULL_TRAFFIC_BPS} (100 %)"
            )));
        }
    }
    Ok(())
}

/// Resolve one revision's declared weight to basis points. `None` when the
/// revision has no weight (equal-split case).
fn effective_bps_single(rev: &ManifestRevision) -> Option<u32> {
    if let Some(pct) = rev.weight_percent {
        // 1 % = 100 bps.
        Some(pct * 100)
    } else {
        rev.weight_bps
    }
}

/// Compute the effective weight in basis points for every revision in a
/// multi-revision entry. Callers have already passed `validate_shape`, so
/// weights are either all-set or all-unset.
///
/// - **All set**: each revision's declared value (percent * 100 or bps).
/// - **All unset**: equal split — `floor(10000 / n)` per revision,
///   remainder added to the first.
pub(crate) fn compute_effective_weights_bps(revisions: &[ManifestRevision]) -> Vec<u32> {
    let n = revisions.len() as u32;
    assert!(n > 0, "validated: revisions is non-empty");
    if revisions[0].weight_percent.is_none() && revisions[0].weight_bps.is_none() {
        // Equal split.
        let base = FULL_TRAFFIC_BPS / n;
        let remainder = FULL_TRAFFIC_BPS - base * n;
        (0..n)
            .map(|i| if i == 0 { base + remainder } else { base })
            .collect()
    } else {
        revisions
            .iter()
            .map(|r| effective_bps_single(r).expect("validated: all-set"))
            .collect()
    }
}

/// Skeleton manifest for `op env apply --emit-answers-template`: one worked
/// example entry per section, ready to edit. Secret entries name an
/// environment VARIABLE (`from_env`) — values never appear in a manifest.
///
/// A verbatim literal (not a serialized [`EnvManifest`]) so the emitted
/// file keeps the authoring order (`schema` first) instead of serde_json's
/// alphabetical keys. Guarded by a round-trip test: the template must
/// deserialize through [`EnvManifest`] (`deny_unknown_fields`) and pass
/// [`EnvManifest::validate_shape`], so template and types cannot drift.
pub const MANIFEST_TEMPLATE_JSON: &str = r#"{
  "schema": "greentic.env-manifest.v1",
  "environment": {
    "id": "local",
    "public_base_url": null
  },
  "trust_root": "bootstrap",
  "secrets": [
    {
      "path": "default/_/messaging-telegram/telegram_bot_token",
      "from_env": "TELEGRAM_BOT_TOKEN"
    }
  ],
  "bundles": [
    {
      "bundle_id": "example-bundle",
      "bundle_path": "example-bundle.gtbundle",
      "route_binding": {
        "path_prefixes": ["/example"],
        "tenant_selector": { "tenant": "default", "team": "default" }
      }
    }
  ],
  "messaging_endpoints": [
    {
      "name": "example-endpoint",
      "provider_type": "messaging.telegram.bot",
      "links": ["example-bundle"],
      "welcome_flow": {
        "bundle_id": "example-bundle",
        "pack_id": "example-pack",
        "flow_id": "main"
      }
    }
  ]
}
"#;

/// Hand-written JSON Schema for the manifest (`op env apply --schema`),
/// following the existing convention (A1 schemars wiring is still deferred).
pub fn manifest_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "EnvManifest",
        "description": "greentic.env-manifest.v1 — declarative environment wiring for `gtc op env apply`",
        "type": "object",
        "required": ["schema", "environment"],
        "additionalProperties": false,
        "properties": {
            "schema": {"const": ENV_MANIFEST_SCHEMA_V1},
            "environment": {
                "type": "object",
                "required": ["id"],
                "additionalProperties": false,
                "properties": {
                    "id": {"type": "string", "description": "Environment id; `local` bootstraps via env init; any other id must already exist (apply reconciles, the operator store creates)"},
                    "public_base_url": {"type": ["string", "null"], "description": "origin-only URL; absent = leave untouched"},
                    "name": {"type": ["string", "null"], "description": "display name; absent = leave untouched (or default to id on create)"},
                    "region": {"type": ["string", "null"], "description": "cloud region tag; absent = leave untouched"},
                    "tenant_org_id": {"type": ["string", "null"], "description": "tenant organization id; absent = leave untouched"},
                    "listen_addr": {"type": ["string", "null"], "description": "bind address (SocketAddr); absent = leave untouched"}
                }
            },
            "trust_root": {"enum": ["bootstrap", null], "description": "`bootstrap` seeds the operator key (idempotent)"},
            "secrets": {
                "type": "array",
                "description": "dev-store secret entries; always-put (values cannot be diffed until A9)",
                "items": {
                    "type": "object",
                    "required": ["path"],
                    "additionalProperties": false,
                    "properties": {
                        "path": {"type": "string", "description": "<tenant>/<team>/<pack>/<name>"},
                        "from_env": {"type": "string", "description": "env var holding the value; omit for a pasted (interactively-supplied) secret. Values never appear in the manifest either way"}
                    }
                }
            },
            "packs": {
                "type": "array",
                "description": "env-pack bindings (core capability slots); applied after trust-root, before secrets",
                "items": {
                    "type": "object",
                    "required": ["slot", "kind", "pack_ref"],
                    "additionalProperties": false,
                    "properties": {
                        "slot": {"type": "string", "description": "capability slot (must satisfy binds_in_packs)"},
                        "kind": {"type": "string", "description": "PackDescriptor — `<namespace>.<id>@<semver>`"},
                        "pack_ref": {"type": "string", "description": "pack reference (registry id or local path)"},
                        "answers_ref": {"type": ["string", "null"], "description": "optional answers file relative to the manifest"}
                    }
                }
            },
            "bundles": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["bundle_id"],
                    "additionalProperties": false,
                    "properties": {
                        "bundle_id": {"type": "string"},
                        "bundle_path": {"type": ["string", "null"], "description": "single-revision form: local .gtbundle; relative to the manifest file; mutually exclusive with `revisions`"},
                        "revisions": {
                            "type": "array",
                            "description": "multi-revision / traffic-split form; mutually exclusive with `bundle_path`",
                            "items": {
                                "type": "object",
                                "required": ["name", "bundle_path"],
                                "additionalProperties": false,
                                "properties": {
                                    "name": {"type": "string", "description": "manifest-local handle, unique within the bundle"},
                                    "bundle_path": {"type": "string", "description": "local .gtbundle; relative to the manifest file"},
                                    "weight_percent": {"type": ["integer", "null"], "description": "0..100; mutually exclusive with weight_bps"},
                                    "weight_bps": {"type": ["integer", "null"], "description": "0..10000; mutually exclusive with weight_percent"},
                                    "drain_seconds": {"type": ["integer", "null"], "description": "per-revision drain window override"},
                                    "abort_metrics": {"type": "array", "items": {"type": "string"}, "description": "reserved for canary evaluation"}
                                }
                            }
                        },
                        "customer_id": {"type": ["string", "null"], "description": "required for non-local envs (B10)"},
                        "revenue_share": {
                            "type": ["array", "null"],
                            "description": "G2: billing split; basis_points must sum to 10000; absent=untouched (greentic@10000)",
                            "items": {
                                "type": "object",
                                "required": ["party_id", "basis_points"],
                                "additionalProperties": false,
                                "properties": {
                                    "party_id": {"type": "string"},
                                    "basis_points": {"type": "integer", "description": "0..10000; all entries sum to 10000"}
                                }
                            }
                        },
                        "status": {"type": ["string", "null"], "enum": ["active", "paused", "archived", null], "description": "G3: deployment status; absent=untouched; reconciled against an existing deployment"},
                        "config_overrides": {"type": ["object", "null"], "description": "<pack_id> -> <key> -> <json>; absent=untouched, {}=clear, map=replace"},
                        "route_binding": {
                            "type": ["object", "null"],
                            "properties": {
                                "hosts": {"type": "array", "items": {"type": "string"}},
                                "path_prefixes": {"type": "array", "items": {"type": "string"}},
                                "tenant_selector": {
                                    "type": ["object", "null"],
                                    "required": ["tenant", "team"],
                                    "properties": {"tenant": {"type": "string"}, "team": {"type": "string"}}
                                }
                            }
                        }
                    }
                }
            },
            "extensions": {
                "type": "array",
                "description": "extension bindings (N-per-env open namespace); applied after bundles, before endpoints",
                "items": {
                    "type": "object",
                    "required": ["kind", "pack_ref"],
                    "additionalProperties": false,
                    "properties": {
                        "kind": {"type": "string", "description": "PackDescriptor — `<namespace>.<id>@<semver>`"},
                        "pack_ref": {"type": "string", "description": "pack reference (registry id or local path)"},
                        "instance_id": {"type": ["string", "null"], "description": "instance selector for N instances of the same type; [a-z0-9-]"},
                        "answers_ref": {"type": ["string", "null"], "description": "optional answers file relative to the manifest"}
                    }
                }
            },
            "messaging_endpoints": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "provider_type"],
                    "additionalProperties": false,
                    "properties": {
                        "name": {"type": "string", "description": "natural key: matches existing endpoints by (provider_type, display_name)"},
                        "provider_type": {"type": "string"},
                        "links": {"type": "array", "items": {"type": "string"}},
                        "welcome_flow": {
                            "type": ["object", "null"],
                            "required": ["bundle_id", "pack_id", "flow_id"],
                            "additionalProperties": false,
                            "properties": {
                                "bundle_id": {"type": "string"},
                                "pack_id": {"type": "string"},
                                "flow_id": {"type": "string"}
                            }
                        },
                        "secret_refs": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        }
    })
}

/// Form id of the env-manifest authoring form ([`manifest_form_spec`]).
pub const ENV_MANIFEST_FORM_ID: &str = "greentic.env-manifest";

/// Version paired with [`ENV_MANIFEST_FORM_ID`]. Answer sets carry it and
/// [`answers_to_manifest`] rejects a mismatch — bump it whenever the
/// question set changes shape, so stale answer files fail loudly instead of
/// converting wrong.
pub const ENV_MANIFEST_FORM_VERSION: &str = "1";

/// The one `qa_spec::FormSpec` for authoring a manifest. The greentic-setup
/// terminal wizard, the future web UI, and Adaptive-Card front-ends all
/// render these same questions; [`answers_to_manifest`] converts the
/// resulting [`AnswerSet`] into a typed [`EnvManifest`] — the manifest stays
/// the durable artifact, answers are an input mechanism.
///
/// Conventions (each pinned by a test):
/// - Repeating manifest sections (`secrets[]`, `bundles[]`,
///   `messaging_endpoints[]`) are `List` questions; an answer is an array of
///   objects keyed by the row field ids.
/// - Secret-adjacent questions ask for the env-var NAME (`from_env`), never
///   a value — no question carries `secret: true`. Unset variables are the
///   apply engine's concern (missing-inputs contract + TTY fill-in).
/// - `required` is the manifest's validation truth, and doubles as the
///   normal-mode marker under greentic-setup's `advanced || required`
///   wizard filter: fields the manifest allows to be absent
///   (`public_base_url`, `customer_id`, `config_overrides`, route binding,
///   welcome flow, …) are `required: false` and surface in advanced mode.
///   The three `List` sections are `required: false` — an empty section is
///   a valid manifest, so absence must pass [`qa_spec::validate()`], and the
///   qa prompt loop walks `List` questions regardless of `required` (its
///   normal-mode filter exempts tables). `trust_root_bootstrap` stays
///   `required` (a `false` answer is valid; the prompt fills the default).
/// - Nested string arrays (`links`, `route_path_prefixes`, …) are
///   comma-separated `String` questions — qa-spec `List` rows cannot nest
///   lists. [`answers_to_manifest`] owns the split.
pub fn manifest_form_spec() -> FormSpec {
    let mut environment_id = question(
        "environment_id",
        QuestionType::String,
        "Environment id",
        "Environment to apply to. `local` bootstraps with default env-pack \
         bindings; any other id must already exist (apply reconciles it; \
         non-local env creation is reserved for the operator store).",
        true,
    );
    environment_id.default_value = Some("local".to_string());

    let public_base_url = question(
        "public_base_url",
        QuestionType::String,
        "Public base URL",
        "Origin-only URL persisted on the environment (e.g. \
         https://bots.example.com). Leave empty to keep the current value.",
        false,
    );

    let mut trust_root_bootstrap = question(
        "trust_root_bootstrap",
        QuestionType::Boolean,
        "Bootstrap the trust root?",
        "Seed the environment trust root with the local operator key \
         (idempotent; required once before bundles can be staged).",
        true,
    );
    trust_root_bootstrap.default_value = Some("true".to_string());

    let mut secrets = question(
        "secrets",
        QuestionType::List,
        "Secrets",
        "Dev-store secret entries. Each secret's value comes either from a \
         named environment variable or from a value you paste in — values \
         never go into a manifest.",
        false,
    );
    // Not `required`: a sensible default of `env` keeps older answer rows
    // (which only carried `from_env`) valid, and drives the prompt default.
    let mut secret_source = question(
        "source",
        QuestionType::Enum,
        "Secret source",
        "`env` reads the value from a named environment variable at apply \
         time; `paste` lets you enter the value interactively — it is stored \
         in the env's secrets store, never in the manifest.",
        false,
    );
    secret_source.choices = Some(vec!["env".to_string(), "paste".to_string()]);
    secret_source.default_value = Some("env".to_string());

    let mut secret_from_env = question(
        "from_env",
        QuestionType::String,
        "Environment variable name",
        "Name of the variable holding the secret value (e.g. \
         TELEGRAM_BOT_TOKEN) — the name, never the value. Required when the \
         source is `env`.",
        false,
    );
    secret_from_env.visible_if = Some(Expr::Eq {
        left: Box::new(Expr::Var {
            path: "source".to_string(),
        }),
        right: Box::new(Expr::Literal {
            value: Value::String("env".to_string()),
        }),
    });

    secrets.list = Some(ListSpec {
        min_items: None,
        max_items: None,
        fields: vec![
            question(
                "path",
                QuestionType::String,
                "Secret path",
                "`<tenant>/<team>/<pack>/<name>`, e.g. \
                 default/_/messaging-telegram/telegram_bot_token",
                true,
            ),
            secret_source,
            secret_from_env,
        ],
        item_label: Some("secret".to_string()),
    });

    let mut bundles = question(
        "bundles",
        QuestionType::List,
        "Bundles",
        "Bundle deployments for this environment.",
        false,
    );
    bundles.list = Some(ListSpec {
        min_items: None,
        max_items: None,
        fields: vec![
            question(
                "bundle_id",
                QuestionType::String,
                "Bundle id",
                "Natural key — unique within the manifest.",
                true,
            ),
            question(
                "bundle_path",
                QuestionType::String,
                "Bundle path",
                "Local `.gtbundle`. Relative paths resolve against the \
                 manifest file's directory.",
                true,
            ),
            question(
                "customer_id",
                QuestionType::String,
                "Customer id",
                "Billing principal — required by apply for non-`local` \
                 environments.",
                false,
            ),
            question(
                "config_overrides",
                QuestionType::String,
                "Config overrides (JSON)",
                "JSON object `{\"<pack_id>\": {\"<key>\": <value>}}`. Empty \
                 = leave untouched; `{}` = explicit clear.",
                false,
            ),
            question(
                "route_hosts",
                QuestionType::String,
                "Route hosts",
                "Comma-separated host names for the route binding.",
                false,
            ),
            {
                // Defaults to `/<bundle_id>` (the everyday single-prefix
                // route); the operator overrides for multi-prefix or custom
                // routes. `computed_overridable` ⇒ shown as the prompt
                // default, not force-applied.
                let mut q = question(
                    "route_path_prefixes",
                    QuestionType::String,
                    "Route path prefixes",
                    "Comma-separated HTTP path prefixes, each starting with `/` \
                     (e.g. /legal).",
                    false,
                );
                q.computed = Some(Expr::Concat {
                    parts: vec![
                        Expr::Literal {
                            value: Value::String("/".to_string()),
                        },
                        Expr::Var {
                            path: "bundle_id".to_string(),
                        },
                    ],
                });
                q.computed_overridable = true;
                q
            },
            {
                // Defaults to the bundle id so each bundle gets its own
                // tenant scope out of the box.
                let mut q = question(
                    "route_tenant",
                    QuestionType::String,
                    "Route tenant",
                    "Tenant for the route binding's tenant selector — set \
                     together with `route_team`.",
                    false,
                );
                q.computed = Some(Expr::Var {
                    path: "bundle_id".to_string(),
                });
                q.computed_overridable = true;
                q
            },
            {
                // Defaults to the `default` team (the common single-team
                // case); paired with `route_tenant` to form the selector.
                let mut q = question(
                    "route_team",
                    QuestionType::String,
                    "Route team",
                    "Team for the route binding's tenant selector — set \
                     together with `route_tenant`.",
                    false,
                );
                q.default_value = Some("default".to_string());
                q
            },
        ],
        item_label: Some("bundle".to_string()),
    });

    let mut messaging_endpoints = question(
        "messaging_endpoints",
        QuestionType::List,
        "Messaging endpoints",
        "Messaging endpoints and their bundle links.",
        false,
    );
    messaging_endpoints.list = Some(ListSpec {
        min_items: None,
        max_items: None,
        fields: vec![
            question(
                "name",
                QuestionType::String,
                "Endpoint name",
                "Manifest-local handle and display name. Upsert key \
                 together with the provider type.",
                true,
            ),
            question(
                "provider_type",
                QuestionType::String,
                "Provider type",
                "Provider class, e.g. messaging.telegram.bot.",
                true,
            ),
            {
                // Defaults to the endpoint name, which by convention matches
                // the bundle id it fronts (e.g. endpoint `legal` admits
                // bundle `legal`). Override to admit several bundles.
                let mut q = question(
                    "links",
                    QuestionType::String,
                    "Linked bundle ids",
                    "Comma-separated `bundle_id`s this endpoint admits.",
                    false,
                );
                q.computed = Some(Expr::Var {
                    path: "name".to_string(),
                });
                q.computed_overridable = true;
                q
            },
            question(
                "welcome_bundle_id",
                QuestionType::String,
                "Welcome flow: bundle id",
                "Set the three welcome_* fields together (or none).",
                false,
            ),
            question(
                "welcome_pack_id",
                QuestionType::String,
                "Welcome flow: pack id",
                "Set the three welcome_* fields together (or none).",
                false,
            ),
            question(
                "welcome_flow_id",
                QuestionType::String,
                "Welcome flow: flow id",
                "Set the three welcome_* fields together (or none).",
                false,
            ),
            question(
                "secret_refs",
                QuestionType::String,
                "Secret refs",
                "Comma-separated secret refs forwarded on endpoint create.",
                false,
            ),
        ],
        item_label: Some("Messaging endpoint".to_string()),
    });

    FormSpec {
        id: ENV_MANIFEST_FORM_ID.to_string(),
        title: "Environment setup".to_string(),
        version: ENV_MANIFEST_FORM_VERSION.to_string(),
        description: Some(format!(
            "Authors a `{ENV_MANIFEST_SCHEMA_V1}` manifest — the durable, \
             re-appliable desired-state document for one environment."
        )),
        presentation: None,
        progress_policy: None,
        secrets_policy: None,
        store: Vec::new(),
        validations: Vec::new(),
        includes: Vec::new(),
        // Secrets come LAST: the terminal wizard derives the required
        // secret paths from the bundles/endpoints just authored and asks
        // only for the env-var name, so the section is most useful after
        // those are known. Other front-ends render the same order.
        questions: vec![
            environment_id,
            public_base_url,
            trust_root_bootstrap,
            bundles,
            messaging_endpoints,
            secrets,
        ],
    }
}

/// [`QuestionSpec`] constructor. Spells out every field (no
/// `..Default::default()`) on purpose: a field added to qa-spec's
/// `QuestionSpec` becomes a compile error here, forcing a deliberate
/// default instead of silently inheriting one.
fn question(
    id: &str,
    kind: QuestionType,
    title: &str,
    description: &str,
    required: bool,
) -> QuestionSpec {
    QuestionSpec {
        id: id.to_string(),
        kind,
        title: title.to_string(),
        title_i18n: None,
        description: Some(description.to_string()),
        description_i18n: None,
        required,
        choices: None,
        default_value: None,
        secret: false,
        visible_if: None,
        constraint: None,
        list: None,
        computed: None,
        policy: QuestionPolicy::default(),
        computed_overridable: false,
    }
}

/// Convert a [`manifest_form_spec`] answer set into a typed [`EnvManifest`].
///
/// Pure conversion: errors only on values that cannot map onto the manifest
/// types (wrong JSON type, half-set field pairs, unparseable
/// `config_overrides`). Callers run `qa_spec::validate` on the answers
/// first for required/constraint enforcement, and the apply engine runs
/// [`EnvManifest::validate_shape`] on the result — this function does not
/// duplicate either. Lenient on absence (missing sections → empty) so a
/// minimal hand-written answers file converts.
///
/// Convention reminder for new fields: every `Vec<String>` manifest field
/// (`links`, `route_hosts`, `route_path_prefixes`, `secret_refs`) is a
/// comma-separated `String` question and MUST come through
/// [`split_csv`] — a plain `req_row_string` would smuggle the commas into
/// a single entry.
pub fn answers_to_manifest(answers: &AnswerSet) -> Result<EnvManifest, OpError> {
    if answers.form_id != ENV_MANIFEST_FORM_ID {
        return Err(OpError::InvalidArgument(format!(
            "answers form_id `{}` is not `{ENV_MANIFEST_FORM_ID}`",
            answers.form_id
        )));
    }
    if answers.spec_version != ENV_MANIFEST_FORM_VERSION {
        return Err(OpError::InvalidArgument(format!(
            "answers spec_version `{}` is not `{ENV_MANIFEST_FORM_VERSION}` \
             — re-run the wizard against the current form",
            answers.spec_version
        )));
    }
    let map = answers
        .answers
        .as_object()
        .ok_or_else(|| OpError::InvalidArgument("answers must be a JSON object".to_string()))?;

    let environment_id = opt_string(map, "environment_id")?.ok_or_else(|| {
        OpError::InvalidArgument("answers: environment_id must be a non-empty string".to_string())
    })?;
    let public_base_url = opt_string(map, "public_base_url")?;
    let trust_root = match map.get("trust_root_bootstrap") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(TrustRootDirective::Bootstrap),
        Some(other) => {
            return Err(OpError::InvalidArgument(format!(
                "answers: trust_root_bootstrap must be a boolean, got {other}"
            )));
        }
    };

    let mut secrets = Vec::new();
    for (idx, row) in rows(map, "secrets")?.iter().enumerate() {
        let row = row_object("secrets", idx, row)?;
        let path = req_row_string("secrets", idx, row, "path")?;
        // `source` selects where the value comes from. Defaulting to `env`
        // keeps older answer rows (which only carried `from_env`) working.
        let source =
            opt_row_string("secrets", idx, row, "source")?.unwrap_or_else(|| "env".to_string());
        let from_env = match source.as_str() {
            "env" => Some(req_row_string("secrets", idx, row, "from_env")?),
            "paste" => None,
            other => {
                return Err(OpError::InvalidArgument(format!(
                    "answers: secrets[{idx}]: source must be `env` or `paste`, got `{other}`"
                )));
            }
        };
        secrets.push(ManifestSecret { path, from_env });
    }

    let mut bundles = Vec::new();
    for (idx, row) in rows(map, "bundles")?.iter().enumerate() {
        let row = row_object("bundles", idx, row)?;
        let bundle_id = req_row_string("bundles", idx, row, "bundle_id")?;
        let config_overrides = match opt_row_string("bundles", idx, row, "config_overrides")? {
            None => None,
            Some(raw) => Some(
                serde_json::from_str::<BTreeMap<String, BTreeMap<String, Value>>>(&raw).map_err(
                    |err| {
                        OpError::InvalidArgument(format!(
                            "answers: bundles[{idx}] (`{bundle_id}`): config_overrides is \
                             not a `<pack_id> -> <key> -> <value>` JSON object: {err}"
                        ))
                    },
                )?,
            ),
        };
        let hosts = split_csv(opt_row_string("bundles", idx, row, "route_hosts")?);
        let path_prefixes = split_csv(opt_row_string("bundles", idx, row, "route_path_prefixes")?);
        let tenant_selector = match (
            opt_row_string("bundles", idx, row, "route_tenant")?,
            opt_row_string("bundles", idx, row, "route_team")?,
        ) {
            (Some(tenant), Some(team)) => Some(TenantSelectorPayload { tenant, team }),
            (None, None) => None,
            _ => {
                return Err(OpError::InvalidArgument(format!(
                    "answers: bundles[{idx}] (`{bundle_id}`): set route_tenant and \
                     route_team together (or neither)"
                )));
            }
        };
        let route_binding =
            if hosts.is_empty() && path_prefixes.is_empty() && tenant_selector.is_none() {
                None
            } else {
                Some(RouteBindingPayload {
                    hosts,
                    path_prefixes,
                    tenant_selector,
                })
            };
        bundles.push(ManifestBundle {
            bundle_id,
            bundle_path: Some(PathBuf::from(req_row_string(
                "bundles",
                idx,
                row,
                "bundle_path",
            )?)),
            revisions: None,
            customer_id: opt_row_string("bundles", idx, row, "customer_id")?,
            revenue_share: None,
            status: None,
            config_overrides,
            route_binding,
        });
    }

    let mut messaging_endpoints = Vec::new();
    for (idx, row) in rows(map, "messaging_endpoints")?.iter().enumerate() {
        let row = row_object("messaging_endpoints", idx, row)?;
        let name = req_row_string("messaging_endpoints", idx, row, "name")?;
        let welcome_flow = match (
            opt_row_string("messaging_endpoints", idx, row, "welcome_bundle_id")?,
            opt_row_string("messaging_endpoints", idx, row, "welcome_pack_id")?,
            opt_row_string("messaging_endpoints", idx, row, "welcome_flow_id")?,
        ) {
            (Some(bundle_id), Some(pack_id), Some(flow_id)) => Some(ManifestWelcomeFlow {
                bundle_id,
                pack_id,
                flow_id,
            }),
            (None, None, None) => None,
            _ => {
                return Err(OpError::InvalidArgument(format!(
                    "answers: messaging_endpoints[{idx}] (`{name}`): set \
                     welcome_bundle_id, welcome_pack_id and welcome_flow_id \
                     together (or none)"
                )));
            }
        };
        messaging_endpoints.push(ManifestEndpoint {
            name,
            provider_type: req_row_string("messaging_endpoints", idx, row, "provider_type")?,
            links: split_csv(opt_row_string("messaging_endpoints", idx, row, "links")?),
            welcome_flow,
            secret_refs: split_csv(opt_row_string(
                "messaging_endpoints",
                idx,
                row,
                "secret_refs",
            )?),
        });
    }

    Ok(EnvManifest {
        schema: ENV_MANIFEST_SCHEMA_V1.to_string(),
        environment: ManifestEnvironment {
            id: environment_id,
            public_base_url,
            name: None,
            region: None,
            tenant_org_id: None,
            listen_addr: None,
        },
        trust_root,
        secrets,
        packs: Vec::new(),
        bundles,
        extensions: Vec::new(),
        messaging_endpoints,
    })
}

/// A `List` answer: absent/null → empty, anything but an array → error.
fn rows<'a>(map: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a [Value], OpError> {
    const EMPTY: &[Value] = &[];
    match map.get(key) {
        None | Some(Value::Null) => Ok(EMPTY),
        Some(Value::Array(items)) => Ok(items.as_slice()),
        Some(other) => Err(OpError::InvalidArgument(format!(
            "answers: {key} must be an array, got {other}"
        ))),
    }
}

fn row_object<'a>(
    section: &str,
    idx: usize,
    row: &'a Value,
) -> Result<&'a serde_json::Map<String, Value>, OpError> {
    row.as_object().ok_or_else(|| {
        OpError::InvalidArgument(format!(
            "answers: {section}[{idx}] must be an object, got {row}"
        ))
    })
}

/// Optional string answer: absent/null/blank → `None`; non-string → error.
fn opt_string(map: &serde_json::Map<String, Value>, key: &str) -> Result<Option<String>, OpError> {
    opt_string_at(map, key, key)
}

/// [`opt_string`] with a caller-supplied error label (`section[idx].key`
/// for row fields), so every type error keeps the offending value.
fn opt_string_at(
    map: &serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<Option<String>, OpError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Some(other) => Err(OpError::InvalidArgument(format!(
            "answers: {label} must be a string, got {other}"
        ))),
    }
}

fn opt_row_string(
    section: &str,
    idx: usize,
    row: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, OpError> {
    opt_string_at(row, key, &format!("{section}[{idx}].{key}"))
}

fn req_row_string(
    section: &str,
    idx: usize,
    row: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, OpError> {
    opt_row_string(section, idx, row, key)?.ok_or_else(|| {
        OpError::InvalidArgument(format!(
            "answers: {section}[{idx}].{key} must be a non-empty string"
        ))
    })
}

/// Split a comma-separated answer into trimmed, non-empty entries.
fn split_csv(value: Option<String>) -> Vec<String> {
    value
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(schema: &str) -> EnvManifest {
        serde_json::from_value(serde_json::json!({
            "schema": schema,
            "environment": {"id": "local"}
        }))
        .expect("minimal manifest parses")
    }

    #[test]
    fn schema_mismatch_rejected() {
        let err = minimal("greentic.env-manifest.v2")
            .validate_shape()
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn unknown_top_level_field_rejected_at_parse() {
        let err = serde_json::from_value::<EnvManifest>(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundlez": []
        }))
        .unwrap_err();
        assert!(err.to_string().contains("bundlez"), "{err}");
    }

    #[test]
    fn valid_secrets_pass_shape_validation() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [
                {"path": "legal/_/messaging-telegram/telegram_bot_token", "from_env": "A"},
                {"path": "accounting/_/messaging-telegram/telegram_bot_token", "from_env": "B"}
            ]
        }))
        .unwrap();
        manifest.validate_shape().expect("valid");
    }

    #[test]
    fn non_canonical_secret_path_rejected_at_shape() {
        // Same checks as `op secrets put` (shared helper): wrong depth,
        // non-canonical team, non-canonical name.
        for path in [
            "credentials/aws",
            "legal/default/messaging-telegram/telegram_bot_token",
            "legal/_/messaging-telegram/BOT-TOKEN",
        ] {
            let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
                "schema": ENV_MANIFEST_SCHEMA_V1,
                "environment": {"id": "local"},
                "secrets": [{"path": path, "from_env": "X"}]
            }))
            .unwrap();
            let err = manifest.validate_shape().unwrap_err();
            assert!(
                matches!(err, OpError::InvalidArgument(_)),
                "path `{path}` got {err}"
            );
        }
    }

    #[test]
    fn duplicate_secret_path_rejected() {
        // The dup check runs on the trimmed path, so a leading `/` cannot
        // smuggle in a duplicate.
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [
                {"path": "legal/_/p/tok", "from_env": "A"},
                {"path": "/legal/_/p/tok", "from_env": "B"}
            ]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate secret path"), "{err}");
    }

    #[test]
    fn empty_from_env_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [{"path": "legal/_/p/tok", "from_env": "  "}]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("from_env"), "{err}");
    }

    #[test]
    fn paste_secret_omits_from_env_and_validates() {
        // A paste-sourced secret carries no `from_env`; validate_shape accepts
        // it and serialization omits the field (no plaintext, no empty key).
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [{"path": "legal/_/p/tok"}]
        }))
        .unwrap();
        manifest
            .validate_shape()
            .expect("paste secret is shape-valid");
        assert_eq!(manifest.secrets[0].from_env, None);
        let json = serde_json::to_value(&manifest).unwrap();
        assert!(
            json["secrets"][0].get("from_env").is_none(),
            "absent from_env is omitted, not serialized as null"
        );
    }

    #[test]
    fn answers_to_manifest_maps_secret_source() {
        // `source: env` keeps `from_env`.
        let env_set = answers(serde_json::json!({
            "environment_id": "local",
            "secrets": [{"path": "legal/_/p/tok", "source": "env", "from_env": "LEGAL_TOK"}]
        }));
        assert_eq!(
            answers_to_manifest(&env_set).unwrap().secrets[0]
                .from_env
                .as_deref(),
            Some("LEGAL_TOK")
        );

        // `source: paste` drops `from_env`.
        let paste_set = answers(serde_json::json!({
            "environment_id": "local",
            "secrets": [{"path": "legal/_/p/tok", "source": "paste"}]
        }));
        assert_eq!(
            answers_to_manifest(&paste_set).unwrap().secrets[0].from_env,
            None
        );

        // No `source` defaults to `env` (back-compat with older answer rows).
        let legacy_set = answers(serde_json::json!({
            "environment_id": "local",
            "secrets": [{"path": "legal/_/p/tok", "from_env": "LEGACY"}]
        }));
        assert_eq!(
            answers_to_manifest(&legacy_set).unwrap().secrets[0]
                .from_env
                .as_deref(),
            Some("LEGACY")
        );

        // An unknown source is a clear error, not a silent default.
        let bad_set = answers(serde_json::json!({
            "environment_id": "local",
            "secrets": [{"path": "legal/_/p/tok", "source": "vault"}]
        }));
        let err = answers_to_manifest(&bad_set).unwrap_err();
        assert!(err.to_string().contains("source must be"), "{err}");
    }

    #[test]
    fn form_spec_secrets_models_env_or_paste() {
        let spec = manifest_form_spec();
        let secrets = spec
            .questions
            .iter()
            .find(|q| q.id == "secrets")
            .expect("secrets question");
        let list = secrets.list.as_ref().expect("secrets is a list");

        let source = list
            .fields
            .iter()
            .find(|f| f.id == "source")
            .expect("source column");
        assert_eq!(source.kind, QuestionType::Enum);
        assert_eq!(
            source.choices.as_deref(),
            Some(&["env".to_string(), "paste".to_string()][..])
        );
        assert_eq!(source.default_value.as_deref(), Some("env"));
        assert!(!source.required, "source defaults to env, never required");

        let from_env = list
            .fields
            .iter()
            .find(|f| f.id == "from_env")
            .expect("from_env column");
        assert!(
            !from_env.required,
            "from_env is needed only for env-sourced secrets"
        );
        assert_eq!(
            from_env.visible_if,
            Some(Expr::Eq {
                left: Box::new(Expr::Var {
                    path: "source".to_string()
                }),
                right: Box::new(Expr::Literal {
                    value: Value::String("env".to_string())
                }),
            }),
            "from_env is shown only when source == env"
        );
    }

    #[test]
    fn duplicate_bundle_id_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [
                {"bundle_id": "a", "bundle_path": "a.gtbundle"},
                {"bundle_id": "a", "bundle_path": "b.gtbundle"}
            ]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate bundle_id"), "{err}");
    }

    #[test]
    fn duplicate_endpoint_name_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [
                {"name": "n", "provider_type": "messaging.telegram.bot"},
                {"name": "n", "provider_type": "messaging.telegram.bot"}
            ]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate endpoint name"), "{err}");
    }

    #[test]
    fn tenant_selector_without_matcher_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "a",
                "bundle_path": "a.gtbundle",
                "route_binding": {"tenant_selector": {"tenant": "t", "team": "d"}}
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("tenant_selector"), "{err}");
    }

    #[test]
    fn path_prefix_must_start_with_slash() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "a",
                "bundle_path": "a.gtbundle",
                "route_binding": {"path_prefixes": ["legal"]}
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("must start with `/`"), "{err}");
    }

    #[test]
    fn duplicate_link_in_endpoint_rejected() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [{
                "name": "n",
                "provider_type": "messaging.telegram.bot",
                "links": ["bundle-a", "bundle-a"]
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate link"), "{err}");
        assert!(err.to_string().contains("bundle-a"), "{err}");
    }

    #[test]
    fn trust_root_bootstrap_parses() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "trust_root": "bootstrap"
        }))
        .unwrap();
        assert_eq!(manifest.trust_root, Some(TrustRootDirective::Bootstrap));
        manifest.validate_shape().expect("valid");
    }

    #[test]
    fn template_round_trips_through_manifest_and_shape_validation() {
        // The `--emit-answers-template` skeleton and the serde types must
        // never drift: the template parses under `deny_unknown_fields` AND
        // passes shape validation (canonical secret path, route binding
        // rules, ...) as-is.
        let manifest: EnvManifest =
            serde_json::from_str(MANIFEST_TEMPLATE_JSON).expect("template parses as EnvManifest");
        manifest
            .validate_shape()
            .expect("template passes validate_shape");
        assert_eq!(manifest.schema, ENV_MANIFEST_SCHEMA_V1);
        // Every section carries a worked example.
        assert_eq!(manifest.trust_root, Some(TrustRootDirective::Bootstrap));
        assert!(!manifest.secrets.is_empty());
        assert!(!manifest.bundles.is_empty());
        assert!(!manifest.messaging_endpoints.is_empty());
    }

    #[test]
    fn two_dept_worked_example_parses() {
        // The full §3 worked example from the design doc.
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local", "public_base_url": null},
            "trust_root": "bootstrap",
            "secrets": [
                {
                    "path": "legal/_/messaging-telegram/telegram_bot_token",
                    "from_env": "TELEGRAM_LEGAL_BOT_TOKEN"
                },
                {
                    "path": "accounting/_/messaging-telegram/telegram_bot_token",
                    "from_env": "TELEGRAM_ACCOUNTING_BOT_TOKEN"
                }
            ],
            "bundles": [
                {
                    "bundle_id": "realbot-legal",
                    "bundle_path": "bundle-workspace-legal/realbot-legal.gtbundle",
                    "route_binding": {
                        "hosts": [],
                        "path_prefixes": ["/legal"],
                        "tenant_selector": {"tenant": "legal", "team": "default"}
                    }
                },
                {
                    "bundle_id": "realbot-accounting",
                    "bundle_path": "bundle-workspace-accounting/realbot-accounting.gtbundle",
                    "route_binding": {
                        "hosts": [],
                        "path_prefixes": ["/accounting"],
                        "tenant_selector": {"tenant": "accounting", "team": "default"}
                    }
                }
            ],
            "messaging_endpoints": [
                {
                    "name": "realbot-legal",
                    "provider_type": "messaging.telegram.bot",
                    "links": ["realbot-legal"]
                },
                {
                    "name": "realbot-accounting",
                    "provider_type": "messaging.telegram.bot",
                    "links": ["realbot-accounting"]
                }
            ]
        }))
        .unwrap();
        manifest.validate_shape().expect("worked example is valid");
        assert_eq!(manifest.secrets.len(), 2);
        assert_eq!(manifest.bundles.len(), 2);
        assert_eq!(manifest.messaging_endpoints.len(), 2);
    }

    /// Composite id (`list.field`) for every question, the same notation the
    /// coverage table uses.
    fn question_ids(spec: &FormSpec) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for q in &spec.questions {
            match &q.list {
                Some(list) => {
                    for field in &list.fields {
                        assert!(
                            ids.insert(format!("{}.{}", q.id, field.id)),
                            "duplicate question id {}.{}",
                            q.id,
                            field.id
                        );
                    }
                }
                None => {
                    assert!(ids.insert(q.id.clone()), "duplicate question id {}", q.id);
                }
            }
        }
        ids
    }

    fn answers(value: Value) -> AnswerSet {
        AnswerSet {
            form_id: ENV_MANIFEST_FORM_ID.to_string(),
            spec_version: ENV_MANIFEST_FORM_VERSION.to_string(),
            answers: value,
            meta: None,
        }
    }

    #[test]
    fn form_spec_never_asks_for_secret_values() {
        // The design rule: secret questions ask for env-var NAMES, so no
        // question is secret-flagged and every List question carries its row
        // definition.
        let spec = manifest_form_spec();
        for q in &spec.questions {
            assert!(!q.secret, "`{}` must not be a secret question", q.id);
            match q.kind {
                QuestionType::List => {
                    let list = q.list.as_ref().unwrap_or_else(|| {
                        panic!("List question `{}` is missing its row definition", q.id)
                    });
                    assert!(!list.fields.is_empty(), "`{}` has no row fields", q.id);
                    for field in &list.fields {
                        assert!(!field.secret, "`{}.{}` must not be secret", q.id, field.id);
                    }
                }
                _ => assert!(q.list.is_none(), "`{}` is not a List but has rows", q.id),
            }
        }
    }

    #[test]
    fn required_marks_the_normal_mode_surface() {
        // `required` is validation truth AND the normal-mode marker under
        // greentic-setup's `advanced || required` wizard filter. Everything
        // the manifest allows to be absent must stay non-required.
        let spec = manifest_form_spec();
        let mut required = BTreeSet::new();
        for q in &spec.questions {
            if q.required {
                required.insert(q.id.clone());
            }
            for field in q.list.iter().flat_map(|l| &l.fields) {
                if field.required {
                    required.insert(format!("{}.{}", q.id, field.id));
                }
            }
        }
        let expected: BTreeSet<String> = [
            "environment_id",
            "trust_root_bootstrap",
            // `secrets.from_env` is no longer required (a paste secret omits
            // it); `secrets.source` defaults to `env`, so it is not required
            // either.
            "secrets.path",
            "bundles.bundle_id",
            "bundles.bundle_path",
            "messaging_endpoints.name",
            "messaging_endpoints.provider_type",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(required, expected);
    }

    #[test]
    fn derived_row_defaults_evaluate_from_sibling_columns() {
        // The everyday-wiring defaults: a single-bundle `legal` setup should
        // pre-fill route prefix `/legal`, tenant `legal`, team `default`, and
        // endpoint link `legal` — each derived from a sibling column in the
        // same row via `computed` (+ `computed_overridable`, so the wizard
        // surfaces them as overridable prompt defaults) or a static default.
        let spec = manifest_form_spec();

        fn list_fields<'a>(spec: &'a FormSpec, id: &str) -> &'a [QuestionSpec] {
            spec.questions
                .iter()
                .find(|q| q.id == id)
                .and_then(|q| q.list.as_ref())
                .map(|l| l.fields.as_slice())
                .unwrap_or_else(|| panic!("list `{id}` missing"))
        }
        fn field<'a>(fields: &'a [QuestionSpec], id: &str) -> &'a QuestionSpec {
            fields
                .iter()
                .find(|f| f.id == id)
                .unwrap_or_else(|| panic!("field `{id}` missing"))
        }
        // Row context as the wizard builds it: keys are sibling field ids.
        let bundle_row = serde_json::json!({ "bundle_id": "legal" });
        let endpoint_row = serde_json::json!({ "name": "legal" });

        let bundles = list_fields(&spec, "bundles");
        let prefixes = field(bundles, "route_path_prefixes");
        assert!(prefixes.computed_overridable);
        assert_eq!(
            prefixes
                .computed
                .as_ref()
                .and_then(|e| e.evaluate_value(&bundle_row)),
            Some(serde_json::json!("/legal"))
        );
        let tenant = field(bundles, "route_tenant");
        assert!(tenant.computed_overridable);
        assert_eq!(
            tenant
                .computed
                .as_ref()
                .and_then(|e| e.evaluate_value(&bundle_row)),
            Some(serde_json::json!("legal"))
        );
        assert_eq!(
            field(bundles, "route_team").default_value.as_deref(),
            Some("default")
        );

        let endpoints = list_fields(&spec, "messaging_endpoints");
        let links = field(endpoints, "links");
        assert!(links.computed_overridable);
        assert_eq!(
            links
                .computed
                .as_ref()
                .and_then(|e| e.evaluate_value(&endpoint_row)),
            Some(serde_json::json!("legal"))
        );

        // Custom row-add labels for the terminal wizard prompt.
        let label = |id: &str| {
            spec.questions
                .iter()
                .find(|q| q.id == id)
                .and_then(|q| q.list.as_ref())
                .and_then(|l| l.item_label.clone())
        };
        assert_eq!(label("bundles").as_deref(), Some("bundle"));
        assert_eq!(
            label("messaging_endpoints").as_deref(),
            Some("Messaging endpoint")
        );
    }

    #[test]
    fn form_questions_and_manifest_fields_cover_each_other() {
        // Bidirectional drift guard: every manifest field (leaf of
        // `manifest_schema()`) maps to a question, and every question maps
        // to a manifest field. Adding a field to the manifest or a question
        // to the form fails this test until the mapping (and the
        // counterpart) exists. `""` marks fields `answers_to_manifest`
        // produces as constants.
        const FIELD_TO_QUESTION: &[(&str, &str)] = &[
            ("schema", ""),
            ("environment.id", "environment_id"),
            ("environment.public_base_url", "public_base_url"),
            ("environment.name", ""),
            ("environment.region", ""),
            ("environment.tenant_org_id", ""),
            ("environment.listen_addr", ""),
            ("trust_root", "trust_root_bootstrap"),
            ("secrets[].path", "secrets.path"),
            ("secrets[].from_env", "secrets.from_env"),
            ("packs[].slot", ""),
            ("packs[].kind", ""),
            ("packs[].pack_ref", ""),
            ("packs[].answers_ref", ""),
            ("bundles[].bundle_id", "bundles.bundle_id"),
            ("bundles[].bundle_path", "bundles.bundle_path"),
            // Multi-revision fields are JSON-first (no form question).
            ("bundles[].revisions[].name", ""),
            ("bundles[].revisions[].bundle_path", ""),
            ("bundles[].revisions[].weight_percent", ""),
            ("bundles[].revisions[].weight_bps", ""),
            ("bundles[].revisions[].drain_seconds", ""),
            ("bundles[].revisions[].abort_metrics", ""),
            ("bundles[].customer_id", "bundles.customer_id"),
            // revenue_share / status are JSON-first (no form question).
            ("bundles[].revenue_share[].party_id", ""),
            ("bundles[].revenue_share[].basis_points", ""),
            ("bundles[].status", ""),
            ("bundles[].config_overrides", "bundles.config_overrides"),
            ("bundles[].route_binding.hosts", "bundles.route_hosts"),
            (
                "bundles[].route_binding.path_prefixes",
                "bundles.route_path_prefixes",
            ),
            (
                "bundles[].route_binding.tenant_selector.tenant",
                "bundles.route_tenant",
            ),
            (
                "bundles[].route_binding.tenant_selector.team",
                "bundles.route_team",
            ),
            ("extensions[].kind", ""),
            ("extensions[].pack_ref", ""),
            ("extensions[].instance_id", ""),
            ("extensions[].answers_ref", ""),
            ("messaging_endpoints[].name", "messaging_endpoints.name"),
            (
                "messaging_endpoints[].provider_type",
                "messaging_endpoints.provider_type",
            ),
            ("messaging_endpoints[].links", "messaging_endpoints.links"),
            (
                "messaging_endpoints[].welcome_flow.bundle_id",
                "messaging_endpoints.welcome_bundle_id",
            ),
            (
                "messaging_endpoints[].welcome_flow.pack_id",
                "messaging_endpoints.welcome_pack_id",
            ),
            (
                "messaging_endpoints[].welcome_flow.flow_id",
                "messaging_endpoints.welcome_flow_id",
            ),
            (
                "messaging_endpoints[].secret_refs",
                "messaging_endpoints.secret_refs",
            ),
        ];

        fn collect_leaves(node: &Value, prefix: &str, out: &mut BTreeSet<String>) {
            if let Some(items) = node.get("items") {
                if items.get("properties").is_some() {
                    collect_leaves(items, &format!("{prefix}[]"), out);
                } else {
                    out.insert(prefix.to_string());
                }
                return;
            }
            if let Some(props) = node.get("properties").and_then(Value::as_object) {
                for (key, sub) in props {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    collect_leaves(sub, &path, out);
                }
                return;
            }
            out.insert(prefix.to_string());
        }

        let mut schema_leaves = BTreeSet::new();
        collect_leaves(&manifest_schema(), "", &mut schema_leaves);
        let mapped_fields: BTreeSet<String> = FIELD_TO_QUESTION
            .iter()
            .map(|(field, _)| field.to_string())
            .collect();
        assert_eq!(
            schema_leaves, mapped_fields,
            "manifest fields and the coverage table drifted — map every \
             schema leaf to a question (or `\"\"` for constants)"
        );

        // `secrets.source` is a UI-only discriminator: it selects whether a
        // secret carries `from_env` (env-sourced) or omits it (paste-sourced).
        // It drives `secrets[].from_env`'s presence rather than mapping to a
        // manifest field of its own.
        const FORM_ONLY_QUESTIONS: &[&str] = &["secrets.source"];
        let mut mapped_questions: BTreeSet<String> = FIELD_TO_QUESTION
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(_, q)| q.to_string())
            .collect();
        mapped_questions.extend(FORM_ONLY_QUESTIONS.iter().map(|q| q.to_string()));
        assert_eq!(
            question_ids(&manifest_form_spec()),
            mapped_questions,
            "form questions and the coverage table drifted — every question \
             must map to a manifest field (or be a declared form-only discriminator)"
        );
    }

    #[test]
    fn answers_round_trip_to_valid_manifest() {
        let spec = manifest_form_spec();
        let set = answers(serde_json::json!({
            "environment_id": "local",
            "public_base_url": "https://bots.example.com",
            "trust_root_bootstrap": true,
            "secrets": [
                {
                    "path": "legal/_/messaging-telegram/telegram_bot_token",
                    "from_env": "TELEGRAM_LEGAL_BOT_TOKEN"
                }
            ],
            "bundles": [
                {
                    "bundle_id": "realbot-legal",
                    "bundle_path": "bundle-workspace-legal/realbot-legal.gtbundle",
                    "customer_id": "acme",
                    "config_overrides": "{\"realbot\": {\"mode\": \"prod\"}}",
                    "route_path_prefixes": "/legal, /legal-archive",
                    "route_tenant": "legal",
                    "route_team": "default"
                }
            ],
            "messaging_endpoints": [
                {
                    "name": "realbot-legal",
                    "provider_type": "messaging.telegram.bot",
                    "links": "realbot-legal, realbot-audit",
                    "welcome_bundle_id": "realbot-legal",
                    "welcome_pack_id": "realbot",
                    "welcome_flow_id": "main"
                }
            ]
        }));

        let report = qa_spec::validate(&spec, &set.answers);
        assert!(report.valid, "answers must pass the form spec: {report:?}");

        let manifest = answers_to_manifest(&set).expect("converts");
        manifest.validate_shape().expect("round-trip passes shape");

        assert_eq!(manifest.environment.id, "local");
        assert_eq!(
            manifest.environment.public_base_url.as_deref(),
            Some("https://bots.example.com")
        );
        assert_eq!(manifest.trust_root, Some(TrustRootDirective::Bootstrap));
        assert_eq!(manifest.secrets.len(), 1);
        assert_eq!(
            manifest.secrets[0].from_env.as_deref(),
            Some("TELEGRAM_LEGAL_BOT_TOKEN"),
            "from_env carries the variable NAME"
        );
        let bundle = &manifest.bundles[0];
        assert_eq!(bundle.customer_id.as_deref(), Some("acme"));
        assert_eq!(
            bundle.config_overrides.as_ref().unwrap()["realbot"]["mode"],
            serde_json::json!("prod")
        );
        let rb = bundle.route_binding.as_ref().expect("route binding built");
        assert_eq!(rb.path_prefixes, ["/legal", "/legal-archive"]);
        assert!(rb.hosts.is_empty());
        let selector = rb.tenant_selector.as_ref().expect("selector built");
        assert_eq!(
            (selector.tenant.as_str(), selector.team.as_str()),
            ("legal", "default")
        );
        let ep = &manifest.messaging_endpoints[0];
        assert_eq!(ep.links, ["realbot-legal", "realbot-audit"]);
        assert_eq!(
            ep.welcome_flow,
            Some(ManifestWelcomeFlow {
                bundle_id: "realbot-legal".to_string(),
                pack_id: "realbot".to_string(),
                flow_id: "main".to_string(),
            })
        );
        assert!(ep.secret_refs.is_empty());
    }

    #[test]
    fn minimal_answers_convert_leniently() {
        // Conversion is lenient on absence (qa_spec::validate owns
        // required-ness): a bare environment_id yields a valid empty
        // manifest with no trust-root directive.
        let manifest = answers_to_manifest(&answers(serde_json::json!({
            "environment_id": "demo",
            "trust_root_bootstrap": false
        })))
        .expect("converts");
        manifest.validate_shape().expect("valid shape");
        assert_eq!(manifest.environment.id, "demo");
        assert_eq!(manifest.environment.public_base_url, None);
        assert_eq!(manifest.trust_root, None);
        assert!(manifest.secrets.is_empty());
        assert!(manifest.bundles.is_empty());
        assert!(manifest.messaging_endpoints.is_empty());
    }

    #[test]
    fn minimal_answers_pass_form_validation() {
        // An empty section is a valid manifest, so the `List` sections must
        // be `required: false`: minimal answers (no lists at all) pass
        // qa_spec::validate — the wizard's declined tables don't trip a
        // bogus required nag, and headless validation stays honest.
        let result = qa_spec::validate(
            &manifest_form_spec(),
            &serde_json::json!({
                "environment_id": "local",
                "trust_root_bootstrap": true
            }),
        );
        assert!(
            result.valid,
            "errors: {:?}, missing: {:?}, unknown: {:?}",
            result.errors, result.missing_required, result.unknown_fields
        );
    }

    #[test]
    fn answers_conversion_errors_name_the_gap() {
        for (label, value, needle) in [
            (
                "missing environment_id",
                serde_json::json!({}),
                "environment_id",
            ),
            (
                "tenant without team",
                serde_json::json!({
                    "environment_id": "local",
                    "bundles": [{
                        "bundle_id": "b", "bundle_path": "b.gtbundle",
                        "route_tenant": "legal"
                    }]
                }),
                "route_team",
            ),
            (
                "partial welcome flow",
                serde_json::json!({
                    "environment_id": "local",
                    "messaging_endpoints": [{
                        "name": "n", "provider_type": "messaging.telegram.bot",
                        "welcome_bundle_id": "b"
                    }]
                }),
                "welcome_pack_id",
            ),
            (
                "config_overrides not an object",
                serde_json::json!({
                    "environment_id": "local",
                    "bundles": [{
                        "bundle_id": "b", "bundle_path": "b.gtbundle",
                        "config_overrides": "[1, 2]"
                    }]
                }),
                "config_overrides",
            ),
            (
                "row field of the wrong type",
                serde_json::json!({
                    "environment_id": "local",
                    "secrets": [{"path": "a/_/p/tok", "from_env": 7}]
                }),
                "secrets[0].from_env",
            ),
        ] {
            let err = answers_to_manifest(&answers(value)).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "{label}: expected `{needle}` in `{err}`"
            );
        }
    }

    #[test]
    fn answers_form_identity_is_checked() {
        let mut set = answers(serde_json::json!({"environment_id": "local"}));
        set.form_id = "something.else".to_string();
        let err = answers_to_manifest(&set).unwrap_err();
        assert!(err.to_string().contains(ENV_MANIFEST_FORM_ID), "{err}");

        let mut set = answers(serde_json::json!({"environment_id": "local"}));
        set.spec_version = "0".to_string();
        let err = answers_to_manifest(&set).unwrap_err();
        assert!(err.to_string().contains("spec_version"), "{err}");
    }

    #[test]
    fn form_spec_enforces_required_row_fields() {
        // Guards the row field ids against typos: a secrets row without the
        // required `path` must fail qa-spec validation (not slide through as
        // an unknown field). `from_env` is optional now (paste secrets omit
        // it), so `path` is the row's required field to probe.
        let spec = manifest_form_spec();
        let report = qa_spec::validate(
            &spec,
            &serde_json::json!({
                "environment_id": "local",
                "trust_root_bootstrap": false,
                "secrets": [{"source": "env", "from_env": "X"}],
                "bundles": [],
                "messaging_endpoints": []
            }),
        );
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| format!("{e:?}").contains("path")),
            "missing row field must be reported: {report:?}"
        );
    }

    // --- multi-revision tests ---

    #[test]
    fn multi_revision_deserialize_and_validate() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "canary-test",
                "revisions": [
                    {"name": "stable", "bundle_path": "stable.gtbundle", "weight_bps": 9000},
                    {"name": "canary", "bundle_path": "canary.gtbundle", "weight_bps": 1000}
                ]
            }]
        }))
        .unwrap();
        manifest.validate_shape().expect("valid multi-revision");
        let revs = manifest.bundles[0].revisions.as_ref().unwrap();
        assert_eq!(revs.len(), 2);
        assert_eq!(revs[0].name, "stable");
        assert_eq!(revs[1].weight_bps, Some(1000));
    }

    #[test]
    fn multi_revision_equal_split_no_weights() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "ab-test",
                "revisions": [
                    {"name": "a", "bundle_path": "a.gtbundle"},
                    {"name": "b", "bundle_path": "b.gtbundle"},
                    {"name": "c", "bundle_path": "c.gtbundle"}
                ]
            }]
        }))
        .unwrap();
        manifest.validate_shape().expect("valid equal-split");
        let revs = manifest.bundles[0].revisions.as_ref().unwrap();
        let weights = compute_effective_weights_bps(revs);
        // 10000 / 3 = 3333 each, remainder 1 to first.
        assert_eq!(weights, vec![3334, 3333, 3333]);
        assert_eq!(weights.iter().sum::<u32>(), FULL_TRAFFIC_BPS);
    }

    #[test]
    fn multi_revision_weight_percent_converts_to_bps() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "pct-test",
                "revisions": [
                    {"name": "a", "bundle_path": "a.gtbundle", "weight_percent": 70},
                    {"name": "b", "bundle_path": "b.gtbundle", "weight_percent": 30}
                ]
            }]
        }))
        .unwrap();
        manifest.validate_shape().expect("valid percent weights");
        let revs = manifest.bundles[0].revisions.as_ref().unwrap();
        let weights = compute_effective_weights_bps(revs);
        assert_eq!(weights, vec![7000, 3000]);
    }

    #[test]
    fn multi_revision_weight_sum_not_10000_fails() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "bad-sum",
                "revisions": [
                    {"name": "a", "bundle_path": "a.gtbundle", "weight_bps": 5000},
                    {"name": "b", "bundle_path": "b.gtbundle", "weight_bps": 3000}
                ]
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("8000 bps"), "{err}");
        assert!(err.to_string().contains("10000"), "{err}");
    }

    #[test]
    fn both_bundle_path_and_revisions_fails() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "both",
                "bundle_path": "both.gtbundle",
                "revisions": [
                    {"name": "a", "bundle_path": "a.gtbundle"}
                ]
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn neither_bundle_path_nor_revisions_fails() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "neither"
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("must be set"), "{err}");
    }

    #[test]
    fn duplicate_revision_name_fails() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "dups",
                "revisions": [
                    {"name": "same", "bundle_path": "a.gtbundle", "weight_bps": 5000},
                    {"name": "same", "bundle_path": "b.gtbundle", "weight_bps": 5000}
                ]
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate revision name"), "{err}");
    }

    #[test]
    fn mixed_set_unset_weights_fails() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "mixed",
                "revisions": [
                    {"name": "a", "bundle_path": "a.gtbundle", "weight_bps": 5000},
                    {"name": "b", "bundle_path": "b.gtbundle"}
                ]
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("mixing set and unset"), "{err}");
    }

    #[test]
    fn weight_percent_and_bps_on_same_revision_fails() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "clash",
                "revisions": [
                    {"name": "a", "bundle_path": "a.gtbundle",
                     "weight_percent": 50, "weight_bps": 5000},
                    {"name": "b", "bundle_path": "b.gtbundle",
                     "weight_percent": 50, "weight_bps": 5000}
                ]
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn empty_revisions_array_fails() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "empty-revs",
                "revisions": []
            }]
        }))
        .unwrap();
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn answers_to_manifest_stays_single_revision() {
        // The wizard always produces the single-revision form.
        let set = answers(serde_json::json!({
            "environment_id": "local",
            "trust_root_bootstrap": false,
            "bundles": [{
                "bundle_id": "b",
                "bundle_path": "b.gtbundle"
            }]
        }));
        let manifest = answers_to_manifest(&set).expect("converts");
        manifest.validate_shape().expect("valid shape");
        assert!(manifest.bundles[0].bundle_path.is_some());
        assert!(manifest.bundles[0].revisions.is_none());
    }

    #[test]
    fn single_revision_equal_split_is_full_traffic() {
        let manifest: EnvManifest = serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "solo",
                "revisions": [
                    {"name": "only", "bundle_path": "only.gtbundle"}
                ]
            }]
        }))
        .unwrap();
        manifest.validate_shape().expect("valid");
        let revs = manifest.bundles[0].revisions.as_ref().unwrap();
        let weights = compute_effective_weights_bps(revs);
        assert_eq!(weights, vec![FULL_TRAFFIC_BPS]);
    }

    // --- G2/G3: revenue_share + status shape ---

    fn bundle_with(extra: serde_json::Value) -> EnvManifest {
        let mut bundle = serde_json::json!({
            "bundle_id": "b",
            "bundle_path": "b.gtbundle"
        });
        bundle
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [bundle]
        }))
        .expect("deserialize")
    }

    #[test]
    fn revenue_share_valid_sum_passes() {
        let manifest = bundle_with(serde_json::json!({
            "revenue_share": [
                {"party_id": "greentic", "basis_points": 8000},
                {"party_id": "partner", "basis_points": 2000}
            ]
        }));
        manifest.validate_shape().expect("valid 10000 sum");
        assert_eq!(manifest.bundles[0].revenue_share.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn revenue_share_wrong_sum_fails() {
        let manifest = bundle_with(serde_json::json!({
            "revenue_share": [
                {"party_id": "greentic", "basis_points": 8000},
                {"party_id": "partner", "basis_points": 1000}
            ]
        }));
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("9000"), "{err}");
        assert!(err.to_string().contains("10000"), "{err}");
    }

    #[test]
    fn revenue_share_empty_fails() {
        let manifest = bundle_with(serde_json::json!({ "revenue_share": [] }));
        let err = manifest.validate_shape().unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn revenue_share_duplicate_party_fails() {
        let manifest = bundle_with(serde_json::json!({
            "revenue_share": [
                {"party_id": "greentic", "basis_points": 5000},
                {"party_id": "greentic", "basis_points": 5000}
            ]
        }));
        let err = manifest.validate_shape().unwrap_err();
        assert!(
            err.to_string().contains("duplicate revenue_share party_id"),
            "{err}"
        );
    }

    #[test]
    fn status_deserializes_lowercase() {
        for (text, want) in [
            ("active", BundleDeploymentStatus::Active),
            ("paused", BundleDeploymentStatus::Paused),
            ("archived", BundleDeploymentStatus::Archived),
        ] {
            let manifest = bundle_with(serde_json::json!({ "status": text }));
            manifest.validate_shape().expect("valid status");
            assert_eq!(manifest.bundles[0].status, Some(want), "status `{text}`");
        }
    }

    #[test]
    fn unknown_status_rejected_at_parse() {
        let err = serde_json::from_value::<EnvManifest>(serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "b", "bundle_path": "b.gtbundle", "status": "running"}]
        }))
        .unwrap_err();
        assert!(
            err.to_string().contains("status") || err.to_string().contains("variant"),
            "{err}"
        );
    }
}
