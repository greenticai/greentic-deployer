//! Pure environment-verb semantics shared by every `EnvironmentMutations`
//! backend (Phase D PR-4.2a).
//!
//! `LocalFsStore` (in `greentic-deployer`) and the operator-store-server's
//! HTTP handlers must apply byte-identical transforms for the same verb —
//! two hand-maintained copies of "what `op env update` means" WILL drift.
//! This module is the single source of those semantics: pure
//! `Environment → Environment` transforms with no I/O, no clock, and no
//! key material. Each backend supplies storage (flock'd JSON file vs.
//! SQLite CAS row) around the same call.
//!
//! The payload structs here double as the A8 wire DTOs: they derive
//! `Serialize`/`Deserialize` in exactly the JSON shape the PR-3b
//! `HttpEnvironmentStore` client established (see the wire-format tests at
//! the bottom — they pin the encoding). Verb groups migrate here one slice
//! at a time alongside their server routes; this file starts with the
//! environment-lifecycle group (`create` / `update` / `migrate-bindings`).
//!
//! FS-coupled verb steps (revenue-policy sidecar signing, operator-key
//! loading, trust-root files, ID minting) are deliberately NOT here — they
//! stay behind injected seams in each backend.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::environment::{EnvPackBinding, Environment, EnvironmentHostConfig, ExtensionBinding};
use crate::retention::{HealthStatus, RetentionPolicy, RevocationConfig};
use crate::version::SchemaVersion;
use greentic_types::EnvId;

/// Revision-lifecycle verb group (PR-4.2b). Re-exported flat so call sites
/// use `engine::stage_revision` etc. like the env-lifecycle group above.
pub mod revisions;
pub use revisions::*;

/// Failures produced by pure verb transforms. Each backend maps these onto
/// its own error surface: `LocalFsStore` → `StoreError`,
/// the operator-store-server → [`crate::remote::RemoteStoreError`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EngineError {
    /// The target environment does not exist and the verb's payload did not
    /// authorize creating it.
    #[error("environment `{0}` not found")]
    NotFound(EnvId),
}

// ---------------------------------------------------------------------------
// FieldUpdate — tri-state patch field (moved from greentic-deployer
// `environment::mutations` in PR-4.2a; semantics unchanged)
// ---------------------------------------------------------------------------

/// Tri-state field for [`UpdateEnvironmentPayload`]: callers can keep the
/// existing value, set a new one, or clear an optional field back to `None`.
///
/// `Keep` maps to the prior `None` behavior (no change). `Set(v)` maps to
/// the prior `Some(v)`. `Clear` writes `None` into the persisted field,
/// which a plain `Option<T>` patch shape could not express.
///
/// # Wire format
///
/// Serde mirrors the A8 wire encoding established by the PR-3b client:
/// `Set(v)` is `{"value": v}`, `Clear` is `{"clear": true}`, and `Keep` is
/// the **absent field** (every payload field carries
/// `#[serde(default, skip_serializing_if = "FieldUpdate::is_keep")]`).
/// A present-but-`{"clear": false}` value deserializes to `Keep` — the
/// caller said "don't clear" and named no new value.
///
/// Deserialization is **strict**: a body carrying both `value` and `clear`
/// keys is rejected (contradictory patch intent), and unknown keys are
/// rejected via `deny_unknown_fields`. `{"value": null}` is treated as
/// absent for `T` that deserializes from null.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FieldUpdate<T> {
    /// Leave the existing value unchanged (the prior `None` behavior).
    #[default]
    Keep,
    /// Write a new value.
    Set(T),
    /// Clear an optional field back to `None`. Only valid for fields that
    /// are `Option<T>` on the persisted struct.
    Clear,
}

impl<T> FieldUpdate<T> {
    /// Convert from `Option<T>` (backward-compat): `None` → `Keep`,
    /// `Some(v)` → `Set(v)`. Existing callers that pass bare `None` keep
    /// the prior semantics with no code change beyond wrapping.
    pub fn from_option(opt: Option<T>) -> Self {
        match opt {
            Some(v) => Self::Set(v),
            None => Self::Keep,
        }
    }

    /// Convert from `Option<Option<T>>` (JSON tri-state): outer `None` →
    /// `Keep`, `Some(None)` → `Clear`, `Some(Some(v))` → `Set(v)`.
    pub fn from_double_option(opt: Option<Option<T>>) -> Self {
        match opt {
            None => Self::Keep,
            Some(None) => Self::Clear,
            Some(Some(v)) => Self::Set(v),
        }
    }

    /// Whether this update is a no-op.
    pub fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }

    /// Apply this update to an `Option<T>` target field: `Keep` is a no-op,
    /// `Set(v)` writes `Some(v)`, `Clear` writes `None`.
    pub fn apply_to(self, target: &mut Option<T>) {
        match self {
            Self::Keep => {}
            Self::Set(v) => *target = Some(v),
            Self::Clear => *target = None,
        }
    }
}

/// Private serde representation for `Serialize` only: `{"value": v}` for
/// `Set`, `{"clear": true}` for `Clear`. Deserialization uses a strict
/// `deny_unknown_fields` helper below.
#[derive(Serialize)]
#[serde(untagged)]
enum FieldUpdateRepr<T> {
    Set { value: T },
    Clear { clear: bool },
}

/// Strict deserialization helper — `deny_unknown_fields` rejects payloads
/// carrying both `value` and `clear` (or any unknown key).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldUpdateDeHelper<T> {
    value: Option<T>,
    clear: Option<bool>,
}

impl<T: Serialize> Serialize for FieldUpdate<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            // Reachable only when a container forgets `skip_serializing_if`;
            // `null` round-trips back to `Keep` below.
            Self::Keep => serializer.serialize_none(),
            Self::Set(v) => FieldUpdateRepr::Set { value: v }.serialize(serializer),
            Self::Clear => FieldUpdateRepr::<&T>::Clear { clear: true }.serialize(serializer),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for FieldUpdate<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Outer `Option` maps JSON `null` (or absent field via `#[serde(default)]`)
        // to `Keep`. The inner helper is `deny_unknown_fields`, so
        // `{"value":…,"clear":…}` or any unknown key raises a typed error.
        //
        // NOTE: `{"value": null}` is indistinguishable from a missing `value`
        // key for `T` that deserializes from null — treated as absent. Do not
        // over-engineer: document this edge case and move on.
        match Option::<FieldUpdateDeHelper<T>>::deserialize(deserializer)? {
            None => Ok(Self::Keep),
            Some(h) => match (h.value, h.clear) {
                (Some(_), Some(_)) => Err(serde::de::Error::custom(
                    "field update cannot carry both `value` and `clear`",
                )),
                (Some(v), None) => Ok(Self::Set(v)),
                (None, Some(true)) => Ok(Self::Clear),
                (None, Some(false)) => Ok(Self::Keep),
                (None, None) => Err(serde::de::Error::custom(
                    "field update object must carry `value` or `clear`",
                )),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Verb payloads (wire DTOs)
// ---------------------------------------------------------------------------

/// Inputs to `EnvironmentMutations::create_environment`, and the A8
/// `POST /environments` request body. `env_id` rides in the body (not the
/// URL) because the resource does not exist yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEnvironmentPayload {
    pub env_id: EnvId,
    pub name: String,
    pub host_config: EnvironmentHostConfig,
}

/// Optional-field patch for `EnvironmentMutations::update_environment`, and
/// the A8 `PATCH /environments/{env_id}` request body. Replaces the earlier
/// `set_public_url` and `set_config` verbs — both were strict subsets of
/// this patch shape, so collapsing them removes two HTTP endpoints and two
/// impl bodies that would drift over time.
///
/// Required fields (`name`) stay `Option<T>` — `None` = keep, `Some(v)` =
/// set. Optional fields (`region`, `tenant_org_id`, `listen_addr`,
/// `public_base_url`) use [`FieldUpdate<T>`] so callers can distinguish
/// Keep / Set / Clear.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateEnvironmentPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "FieldUpdate::is_keep")]
    pub region: FieldUpdate<String>,
    #[serde(default, skip_serializing_if = "FieldUpdate::is_keep")]
    pub tenant_org_id: FieldUpdate<String>,
    #[serde(default, skip_serializing_if = "FieldUpdate::is_keep")]
    pub listen_addr: FieldUpdate<std::net::SocketAddr>,
    #[serde(default, skip_serializing_if = "FieldUpdate::is_keep")]
    pub public_base_url: FieldUpdate<String>,
}

/// Optional seed payload for `EnvironmentMutations::migrate_merge_bindings`.
/// Supplied when the caller wants the impl to atomically create the target
/// env (using these fields) if it doesn't exist yet, then merge the bindings
/// into it. Mirrors the seed-from-source behavior of `op env migrate-dev`
/// where the source's host config + policy state ride along onto the freshly
/// created target.
///
/// `name` is intentionally omitted: the impl derives it from the target
/// env id. `schema` is set to the current `ENVIRONMENT_V1` constant by the
/// impl, not threaded through the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateSeedPayload {
    pub host_config: EnvironmentHostConfig,
    pub revocation: RevocationConfig,
    pub retention: RetentionPolicy,
    pub health: HealthStatus,
}

/// Inputs to `EnvironmentMutations::migrate_merge_bindings`, and the A8
/// `POST /environments/{env_id}/migrate-bindings` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateMergePayload {
    pub packs: Vec<EnvPackBinding>,
    pub extensions: Vec<ExtensionBinding>,
    /// When `Some`, the impl atomically creates the target env (using
    /// these fields) if it doesn't exist yet, then merges the bindings
    /// into it. When `None`, the impl returns not-found if the target
    /// doesn't exist — the caller is asserting target presence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_if_missing: Option<MigrateSeedPayload>,
}

/// Result of [`merge_bindings`], and the A8 migrate-bindings response body
/// (`merged_slots` / `merged_extensions` keys pinned by the PR-3b client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeReport {
    pub merged_slots: Vec<String>,
    pub merged_extensions: Vec<String>,
}

// ---------------------------------------------------------------------------
// ExtensionKey (moved from greentic-deployer `environment::mutations` in
// PR-4.2a; semantics unchanged)
// ---------------------------------------------------------------------------

/// `(kind_path, instance_id)` composite key identifying one extension binding
/// in `Environment::extensions`. `kind_path` is the canonical
/// `ExtensionKind::path()` form (e.g. `"capability/memory/long-term"`).
///
/// `instance_id` is `Option<String>`: a `None` binding (the unnamed default)
/// and a `Some("default")` binding on the same `kind_path` are **distinct**
/// and may coexist — two `None` bindings on the same path collide.
/// This mirrors [`ExtensionBinding::instance_id`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionKey {
    pub kind_path: String,
    pub instance_id: Option<String>,
}

impl ExtensionKey {
    pub fn new(kind_path: impl Into<String>, instance_id: Option<String>) -> Self {
        Self {
            kind_path: kind_path.into(),
            instance_id,
        }
    }

    /// Derive the key from an existing [`ExtensionBinding`], mirroring the
    /// `(descriptor-path, instance_id)` convention in the deployer CLI.
    pub fn from_binding(b: &ExtensionBinding) -> Self {
        Self {
            kind_path: b.kind.path().to_string(),
            instance_id: b.instance_id.clone(),
        }
    }

    /// Whether `b` carries this `(kind_path, instance_id)` key. Borrowed
    /// comparison — no allocation per element, so it's cheap inside a scan.
    pub fn matches(&self, b: &ExtensionBinding) -> bool {
        b.kind.path() == self.kind_path && b.instance_id.as_deref() == self.instance_id.as_deref()
    }
}

/// Wire-stable rendering used by audit-event targets and CLI outcome JSON.
/// `<kind_path>/<instance_id>` when an instance is present, otherwise just
/// `<kind_path>`. Mirrors the deployer CLI's Display so existing
/// operator-facing strings stay byte-identical.
impl std::fmt::Display for ExtensionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.instance_id {
            Some(inst) => write!(f, "{}/{}", self.kind_path, inst),
            None => f.write_str(&self.kind_path),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure transforms — environment-lifecycle verb group
// ---------------------------------------------------------------------------

/// Build an empty [`Environment`] at the current `ENVIRONMENT_V1` schema
/// with the supplied `host_config` + policy state. All collection fields
/// start empty and `credentials_ref` is `None` — populated downstream by
/// the binding verbs. Shared by `create_environment` (which passes
/// `Default::default()` for revocation/retention/health) and
/// `migrate_merge_bindings`' seed branch (which threads the source's
/// existing policy state through).
///
/// The caller's [`EnvironmentHostConfig::env_id`] is overwritten with
/// `env_id` so the persisted row's host-config envelope cannot disagree
/// with the key it lands under.
///
/// Centralizing this prevents seed sites from drifting when a new
/// `Environment` field lands — every site must zero/default it, and
/// missing one site is the silent-zero-value footgun.
pub fn fresh_environment(
    env_id: &EnvId,
    name: String,
    host_config: EnvironmentHostConfig,
    revocation: RevocationConfig,
    retention: RetentionPolicy,
    health: HealthStatus,
) -> Environment {
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id.clone(),
        name,
        host_config: EnvironmentHostConfig {
            env_id: env_id.clone(),
            ..host_config
        },
        packs: Vec::new(),
        credentials_ref: None,
        bundles: Vec::new(),
        revisions: Vec::new(),
        traffic_splits: Vec::new(),
        messaging_endpoints: Vec::new(),
        extensions: Vec::new(),
        revocation,
        retention,
        health,
    }
}

/// Apply an [`UpdateEnvironmentPayload`] patch to an existing env in place:
/// `Keep` fields are skipped, `Set` writes the new value, `Clear` resets an
/// optional field to `None`. Infallible — field-level validation (URL shape,
/// etc.) happens at the CLI/handler boundary before the payload is built.
pub fn apply_environment_update(env: &mut Environment, patch: UpdateEnvironmentPayload) {
    if let Some(name) = patch.name {
        env.name = name;
    }
    patch.region.apply_to(&mut env.host_config.region);
    patch
        .tenant_org_id
        .apply_to(&mut env.host_config.tenant_org_id);
    patch.listen_addr.apply_to(&mut env.host_config.listen_addr);
    patch
        .public_base_url
        .apply_to(&mut env.host_config.public_base_url);
}

/// Resolve the migrate-bindings target: an existing env passes through; a
/// missing env is seeded from `seed` (name derived from `env_id`) or — when
/// the caller asserted presence by passing `seed: None` — rejected with
/// [`EngineError::NotFound`].
pub fn seed_or_existing(
    existing: Option<Environment>,
    env_id: &EnvId,
    seed: Option<MigrateSeedPayload>,
) -> Result<Environment, EngineError> {
    match existing {
        Some(env) => Ok(env),
        None => match seed {
            Some(seed) => Ok(fresh_environment(
                env_id,
                env_id.as_str().to_string(),
                seed.host_config,
                seed.revocation,
                seed.retention,
                seed.health,
            )),
            None => Err(EngineError::NotFound(env_id.clone())),
        },
    }
}

/// Merge pack bindings and extension bindings into `env`, skipping slots
/// already in `env.packs` and extension keys already in `env.extensions`
/// (uniqueness on `(kind_path, instance_id)`). Returns the merged names.
///
/// `messaging_endpoints` are NOT merged by this verb: they reference
/// `linked_bundles` that don't migrate, so a blind copy would break
/// referential integrity.
pub fn merge_bindings(
    env: &mut Environment,
    packs: Vec<EnvPackBinding>,
    extensions: Vec<ExtensionBinding>,
) -> MergeReport {
    let mut merged_slots = Vec::new();
    for binding in packs {
        if env.packs.iter().any(|b| b.slot == binding.slot) {
            continue;
        }
        merged_slots.push(binding.slot.to_string());
        env.packs.push(binding);
    }
    let mut merged_extensions = Vec::new();
    for ext in extensions {
        let key = ExtensionKey::from_binding(&ext);
        if env.extensions.iter().any(|e| key.matches(e)) {
            continue;
        }
        merged_extensions.push(key.to_string());
        env.extensions.push(ext);
    }
    MergeReport {
        merged_slots,
        merged_extensions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn host_config() -> EnvironmentHostConfig {
        EnvironmentHostConfig {
            env_id: env_id(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }
    }

    fn minimal_env() -> Environment {
        fresh_environment(
            &env_id(),
            "local".to_string(),
            host_config(),
            RevocationConfig::default(),
            RetentionPolicy::default(),
            HealthStatus::default(),
        )
    }

    // --- FieldUpdate semantics (moved from greentic-deployer) ---

    #[test]
    fn field_update_default_is_keep() {
        assert!(FieldUpdate::<String>::default().is_keep());
    }

    #[test]
    fn field_update_from_option_maps_none_to_keep_and_some_to_set() {
        assert_eq!(FieldUpdate::from_option(None::<u32>), FieldUpdate::Keep);
        assert_eq!(FieldUpdate::from_option(Some(7)), FieldUpdate::Set(7));
    }

    #[test]
    fn field_update_from_double_option_maps_tristate() {
        assert_eq!(
            FieldUpdate::from_double_option(None::<Option<u32>>),
            FieldUpdate::Keep
        );
        assert_eq!(
            FieldUpdate::from_double_option(Some(None::<u32>)),
            FieldUpdate::Clear
        );
        assert_eq!(
            FieldUpdate::from_double_option(Some(Some(7))),
            FieldUpdate::Set(7)
        );
    }

    #[test]
    fn field_update_apply_to_covers_all_arms() {
        let mut target = Some("old".to_string());
        FieldUpdate::Keep.apply_to(&mut target);
        assert_eq!(target.as_deref(), Some("old"));
        FieldUpdate::Set("new".to_string()).apply_to(&mut target);
        assert_eq!(target.as_deref(), Some("new"));
        FieldUpdate::<String>::Clear.apply_to(&mut target);
        assert_eq!(target, None);
        // Clear on already-None is a no-op.
        FieldUpdate::<String>::Clear.apply_to(&mut target);
        assert_eq!(target, None);
    }

    #[test]
    fn update_environment_payload_defaults_to_all_keep() {
        let payload = UpdateEnvironmentPayload::default();
        assert!(payload.name.is_none());
        assert!(payload.region.is_keep());
        assert!(payload.tenant_org_id.is_keep());
        assert!(payload.listen_addr.is_keep());
        assert!(payload.public_base_url.is_keep());
    }

    #[test]
    fn extension_key_identity_distinguishes_none_from_named_instance() {
        let key = ExtensionKey::new("capability/memory/long-term", Some("default".to_string()));
        assert_eq!(key.to_string(), "capability/memory/long-term/default");

        // Hashable + Eq for `(kind_path, instance_id)` lookup keys. `None`
        // (the unnamed default) and `Some("default")` on the SAME path are
        // distinct identities that coexist.
        let unnamed = ExtensionKey::new("capability/memory/long-term", None);
        assert_eq!(unnamed.to_string(), "capability/memory/long-term");
        assert_ne!(unnamed, key, "None and Some(_) must differ");

        let mut set = std::collections::HashSet::new();
        set.insert(key.clone());
        assert!(set.contains(&key));
        assert!(
            !set.contains(&unnamed),
            "None key must not hash-collide with Some(_) key"
        );
        set.insert(unnamed);
        assert_eq!(set.len(), 2);
    }

    // --- Wire-format pinning (must match the PR-3b client encoding) ---

    #[test]
    fn update_payload_wire_format_is_pinned() {
        // Set → {"value": v}; Clear → {"clear": true}; Keep → absent.
        let payload = UpdateEnvironmentPayload {
            name: Some("renamed".to_string()),
            region: FieldUpdate::Set("eu-west-1".to_string()),
            tenant_org_id: FieldUpdate::Clear,
            listen_addr: FieldUpdate::Keep,
            public_base_url: FieldUpdate::Keep,
        };
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            json!({
                "name": "renamed",
                "region": {"value": "eu-west-1"},
                "tenant_org_id": {"clear": true},
            })
        );
    }

    #[test]
    fn update_payload_deserializes_tristate() {
        let payload: UpdateEnvironmentPayload = serde_json::from_value(json!({
            "region": {"value": "eu-west-1"},
            "tenant_org_id": {"clear": true},
        }))
        .unwrap();
        assert_eq!(payload.name, None);
        assert_eq!(payload.region, FieldUpdate::Set("eu-west-1".to_string()));
        assert_eq!(payload.tenant_org_id, FieldUpdate::Clear);
        assert!(payload.listen_addr.is_keep());
        assert!(payload.public_base_url.is_keep());
    }

    #[test]
    fn field_update_clear_false_and_null_deserialize_to_keep() {
        let payload: UpdateEnvironmentPayload = serde_json::from_value(json!({
            "region": {"clear": false},
            "tenant_org_id": null,
        }))
        .unwrap();
        assert!(payload.region.is_keep());
        assert!(payload.tenant_org_id.is_keep());
    }

    #[test]
    fn field_update_rejects_contradictory_value_and_clear() {
        let err = serde_json::from_value::<UpdateEnvironmentPayload>(json!({
            "region": {"value": "x", "clear": true},
        }))
        .unwrap_err();
        assert!(
            err.to_string().contains("cannot carry both"),
            "expected contradictory-field rejection: {err}"
        );
    }

    #[test]
    fn field_update_rejects_unknown_keys() {
        let err = serde_json::from_value::<UpdateEnvironmentPayload>(json!({
            "region": {"unknown_key": 1},
        }))
        .unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-key rejection: {err}"
        );
    }

    #[test]
    fn create_payload_round_trips() {
        let payload = CreateEnvironmentPayload {
            env_id: env_id(),
            name: "local".to_string(),
            host_config: host_config(),
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(value["env_id"], "local");
        assert_eq!(value["name"], "local");
        let back: CreateEnvironmentPayload = serde_json::from_value(value).unwrap();
        assert_eq!(back.env_id, payload.env_id);
        assert_eq!(back.name, payload.name);
    }

    #[test]
    fn migrate_payload_omits_absent_seed() {
        let payload = MigrateMergePayload {
            packs: Vec::new(),
            extensions: Vec::new(),
            seed_if_missing: None,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("seed_if_missing").is_none());
        let back: MigrateMergePayload =
            serde_json::from_value(json!({"packs": [], "extensions": []})).unwrap();
        assert!(back.seed_if_missing.is_none());
    }

    // --- Transform semantics ---

    #[test]
    fn fresh_environment_pins_host_config_env_id() {
        let other = EnvId::try_from("other").unwrap();
        let mut hc = host_config();
        hc.env_id = other;
        let env = fresh_environment(
            &env_id(),
            "local".to_string(),
            hc,
            RevocationConfig::default(),
            RetentionPolicy::default(),
            HealthStatus::default(),
        );
        assert_eq!(env.host_config.env_id, env_id());
        assert_eq!(env.environment_id, env_id());
        assert!(env.packs.is_empty() && env.bundles.is_empty());
    }

    #[test]
    fn apply_environment_update_patches_and_clears() {
        let mut env = minimal_env();
        env.host_config.region = Some("us-east-1".to_string());
        apply_environment_update(
            &mut env,
            UpdateEnvironmentPayload {
                name: Some("renamed".to_string()),
                region: FieldUpdate::Clear,
                tenant_org_id: FieldUpdate::Set("org-1".to_string()),
                listen_addr: FieldUpdate::Keep,
                public_base_url: FieldUpdate::Keep,
            },
        );
        assert_eq!(env.name, "renamed");
        assert_eq!(env.host_config.region, None);
        assert_eq!(env.host_config.tenant_org_id.as_deref(), Some("org-1"));
    }

    #[test]
    fn seed_or_existing_passes_through_seeds_and_rejects() {
        let existing = minimal_env();
        let out = seed_or_existing(Some(existing.clone()), &env_id(), None).unwrap();
        assert_eq!(out.name, existing.name);

        let seeded = seed_or_existing(
            None,
            &env_id(),
            Some(MigrateSeedPayload {
                host_config: host_config(),
                revocation: RevocationConfig::default(),
                retention: RetentionPolicy::default(),
                health: HealthStatus::default(),
            }),
        )
        .unwrap();
        assert_eq!(seeded.name, "local");

        let err = seed_or_existing(None, &env_id(), None).unwrap_err();
        assert_eq!(err, EngineError::NotFound(env_id()));
    }

    #[test]
    fn merge_bindings_dedups_slots_and_extension_keys() {
        use crate::capability_slot::{CapabilitySlot, PackDescriptor};
        use crate::ids::PackId;

        let pack = |slot: CapabilitySlot| EnvPackBinding {
            slot,
            kind: PackDescriptor::try_new("greentic.secrets@1.0.0").unwrap(),
            pack_ref: PackId::new("greentic.secrets"),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        };
        let ext = |instance: Option<&str>| ExtensionBinding {
            kind: PackDescriptor::try_new("greentic.memory@0.1.0").unwrap(),
            pack_ref: PackId::new("greentic.memory"),
            instance_id: instance.map(str::to_string),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        };

        let mut env = minimal_env();
        env.packs.push(pack(CapabilitySlot::Secrets));
        env.extensions.push(ext(None));

        let report = merge_bindings(
            &mut env,
            vec![pack(CapabilitySlot::Secrets), pack(CapabilitySlot::State)],
            vec![ext(None), ext(Some("alt"))],
        );

        // Existing slot + existing (path, None) key skipped; new ones merged.
        assert_eq!(report.merged_slots, vec!["state".to_string()]);
        assert_eq!(
            report.merged_extensions,
            vec!["greentic.memory/alt".to_string()]
        );
        assert_eq!(env.packs.len(), 2);
        assert_eq!(env.extensions.len(), 2);
    }
}
