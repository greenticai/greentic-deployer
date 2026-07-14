//! `greentic.update-channel.v1`.
//!
//! Sibling file `update-channel.json`. Operator-owned *policy* for the pull-based
//! update channel's Phase 4 notification behavior — whether the runtime acts on a
//! discovered update, and how often it polls. Distinct from the enrolled mTLS
//! identity (secrets under `<tenant>/_/tls/`) and the update trust root
//! (`trust-root.json`): this file carries nothing secret.
//!
//! Absent file → the channel is **disabled** (deny-by-default): the runtime
//! neither polls nor honors a webhook until an operator opts in via
//! `op updates config-set`, or declares an `updates` block in the env-manifest
//! it hands to `op env apply`.
//!
//! Two fields describe the action on a verified plan: the legacy
//! [`OnNotifyAction`] (`on_notify`) and the superseding [`UpdateAction`]
//! (`on_update`, which adds `apply`). Read them through
//! [`UpdateChannelConfig::resolved_action`]; write them through
//! [`UpdateChannelConfig::set_action`], never individually.

use crate::version::SchemaVersion;
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};

/// Legacy on-notify policy. Superseded by [`UpdateAction`] via
/// [`UpdateChannelConfig::on_update`]; retained (not removed, not extended) so a
/// binary older than the `on_update` schema still reads a *safe* value out of a
/// channel configured for `apply` — see [`UpdateChannelConfig::on_update`].
///
/// Extending this enum with an `Apply` variant was the obvious move and is the
/// wrong one: `apply` would fail to deserialize on every older binary, taking the
/// whole channel config down with it, and the added variant is a semver-major
/// break that forces `greentic-runner` (whose public API carries
/// `greentic_deploy_spec::ids::*`) onto a new deploy-spec line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnNotifyAction {
    /// Record "plan N available" (status/audit/log) but download nothing.
    RecordOnly,
    /// Download + verify + stage the plan (as `op updates get`) so it is ready
    /// to apply. Applying stays an explicit operator step. The default.
    #[default]
    Stage,
}

impl OnNotifyAction {
    /// Canonical wire string (matches the serde `snake_case` renaming).
    pub fn as_str(&self) -> &'static str {
        match self {
            OnNotifyAction::RecordOnly => "record_only",
            OnNotifyAction::Stage => "stage",
        }
    }

    /// Parse an operator-supplied string, accepting both `snake_case` and the
    /// hyphenated CLI spelling.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "record_only" | "record-only" => Some(OnNotifyAction::RecordOnly),
            "stage" => Some(OnNotifyAction::Stage),
            _ => None,
        }
    }
}

/// What the runtime does with an update plan it has discovered and verified —
/// the full policy, superseding [`OnNotifyAction`].
///
/// Still deny-by-default: [`UpdateChannelConfig::enabled`] gates the machinery,
/// and an unset action resolves to [`Stage`](UpdateAction::Stage), never
/// [`Apply`](UpdateAction::Apply). `Apply` is an explicit operator opt-in.
///
/// `#[non_exhaustive]` from birth: a fourth action must not be another
/// semver-major break.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpdateAction {
    /// Record "plan N available" (status/audit/log) but download nothing.
    RecordOnly,
    /// Download + verify + stage the plan so it is ready to apply. Applying
    /// stays an explicit operator step (`op updates apply`). The default.
    #[default]
    Stage,
    /// Stage, then converge the environment onto the plan's signed target —
    /// snapshot, apply, verify, roll back on failure. The runtime updates
    /// itself with no operator step. Opt-in only.
    ///
    /// **Requires a runtime that reads `on_update`.** The executor lives in
    /// `greentic-start`; releases that predate this field resolve their policy
    /// from the legacy [`on_notify`](UpdateChannelConfig::on_notify) mirror,
    /// which [`legacy_on_notify`](Self::legacy_on_notify) sets to
    /// [`OnNotifyAction::Stage`]. Against such a runtime `Apply` therefore
    /// *stages* — safe, and visibly short of what was asked for. Check
    /// `op updates config-show` against the runtime version actually deployed.
    Apply,
}

impl UpdateAction {
    /// Canonical wire string (matches the serde `snake_case` renaming).
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateAction::RecordOnly => "record_only",
            UpdateAction::Stage => "stage",
            UpdateAction::Apply => "apply",
        }
    }

    /// Parse an operator-supplied string, accepting both `snake_case` and the
    /// hyphenated CLI spelling.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "record_only" | "record-only" => Some(UpdateAction::RecordOnly),
            "stage" => Some(UpdateAction::Stage),
            "apply" => Some(UpdateAction::Apply),
            _ => None,
        }
    }

    /// The value to persist in the legacy [`UpdateChannelConfig::on_notify`]
    /// field alongside this action, so a binary that predates `on_update` reads
    /// a safe policy. `Apply` degrades to `Stage`: an old runtime stages the
    /// plan and waits for an operator instead of ignoring the channel or
    /// failing to parse it.
    pub fn legacy_on_notify(self) -> OnNotifyAction {
        match self {
            UpdateAction::RecordOnly => OnNotifyAction::RecordOnly,
            UpdateAction::Stage | UpdateAction::Apply => OnNotifyAction::Stage,
        }
    }
}

impl From<OnNotifyAction> for UpdateAction {
    fn from(legacy: OnNotifyAction) -> Self {
        match legacy {
            OnNotifyAction::RecordOnly => UpdateAction::RecordOnly,
            OnNotifyAction::Stage => UpdateAction::Stage,
        }
    }
}

/// Default poll interval when [`UpdateChannelConfig::poll_interval_secs`] is
/// unset and polling is enabled — 1 hour. The primary discovery path is the
/// signed webhook; polling is the fallback, so a slow default is fine.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 3600;

/// Floor for a configured poll interval, so a misconfiguration can't hammer the
/// control plane. The setter rejects values below this; the resolver also clamps
/// as defense in depth.
pub const MIN_POLL_INTERVAL_SECS: u64 = 60;

/// `greentic.update-channel.v1` — operator policy for the update channel's
/// notification behavior. Persisted as `<env_dir>/update-channel.json`. Every
/// behavior field is `Option`: absent = the deny-by-default resolution below.
///
/// `Eq` is deliberately not derived: [`unknown`](Self::unknown) holds arbitrary
/// JSON (`serde_json::Value` is `PartialEq` but not `Eq`). Nothing in the
/// ecosystem uses this type as a map key or in a set, so `PartialEq` is enough.
///
/// `#[non_exhaustive]` from birth: all behavior fields are optional and additive,
/// and the `#[serde(flatten)] unknown` catch-all already preserves
/// forward-compatibility on the wire. `#[non_exhaustive]` now preserves it in the
/// Rust API — future optional fields can land in a patch release without breaking
/// downstream struct-literal construction, keeping deploy-spec on the 0.2.x line
/// that `greentic-runner-host` requires.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UpdateChannelConfig {
    pub schema: SchemaVersion,
    pub environment_id: EnvId,
    /// Master switch. `None`/absent file → disabled. The runtime neither polls
    /// nor honors webhooks unless this is `Some(true)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Legacy on-notify action. Superseded by [`on_update`](Self::on_update),
    /// which wins when both are set. Still written by `op updates config-set` so
    /// a rolled-back binary reads a safe value; see
    /// [`UpdateAction::legacy_on_notify`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_notify: Option<OnNotifyAction>,
    /// What to do with a verified plan. `None` → fall back to
    /// [`on_notify`](Self::on_notify), then to [`UpdateAction::Stage`]. Resolve
    /// through [`resolved_action`](Self::resolved_action), never by reading this
    /// field directly.
    ///
    /// A binary that predates this field parses the config fine — the key lands
    /// in [`unknown`](Self::unknown) and is re-emitted verbatim on save — and
    /// reads `on_notify` instead, so an `apply` channel degrades to staging
    /// rather than breaking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_update: Option<UpdateAction>,
    /// Fallback poll interval in seconds. `None` → [`DEFAULT_POLL_INTERVAL_SECS`],
    /// clamped up to [`MIN_POLL_INTERVAL_SECS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_secs: Option<u64>,
    /// Base URL the poll loop GETs the latest signed plan from (`{url}` for the
    /// plan, `{url}.sig` for the DSSE envelope). Absent → the poll loop has no
    /// source and does nothing even if `enabled` is `true`. This is operator
    /// policy, carries nothing secret, and is validated as an acceptable control
    /// URL on set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_endpoint: Option<String>,
    /// Whether the runtime subscribes to a pushed update stream (SSE) instead of
    /// relying solely on the fallback poll. `None` → resolved to `true`: push
    /// carries the same data, in the same outbound direction, as the poll this
    /// channel already authorizes, so it is not a new authority. A server without
    /// the stream endpoint 404s and the runtime silently degrades to poll-only —
    /// i.e. exactly today's behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_enabled: Option<bool>,
    /// SSE stream endpoint the runtime connects to for pushed updates. When unset,
    /// derived from `plan_endpoint` by replacing a trailing `/plan` with
    /// `/updates/stream`; `None` when there is no plan endpoint or it does not end
    /// in `/plan` (we will not guess). Validated as an acceptable control URL on
    /// set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_endpoint: Option<String>,
    /// Forward-compatibility catch-all. Any keys in the on-disk
    /// `update-channel.json` that this binary's schema does not recognize are
    /// captured here and re-emitted verbatim on save. `config-set` is a
    /// read-modify-write, so without this a binary older than the one that wrote
    /// the file would silently drop the newer fields it doesn't know — under a
    /// rollback that would reset an enabled channel's policy (e.g. lose its
    /// `plan_endpoint`). Establishes forward-compat from this schema revision on;
    /// it cannot retroactively protect fields against binaries that predate it.
    /// Empty in the common case, so it serializes to nothing and the on-disk file
    /// is unchanged for configs with no unknown keys.
    #[serde(flatten)]
    pub unknown: serde_json::Map<String, serde_json::Value>,
}

impl UpdateChannelConfig {
    pub fn schema_str() -> &'static str {
        SchemaVersion::UPDATE_CHANNEL_V1
    }

    /// A fresh, fully-unset config for `environment_id` — the state an absent
    /// file resolves to, and the seed that `op updates config-set` merges onto.
    pub fn disabled(environment_id: EnvId) -> Self {
        Self {
            schema: SchemaVersion::new(SchemaVersion::UPDATE_CHANNEL_V1),
            environment_id,
            enabled: None,
            on_notify: None,
            on_update: None,
            poll_interval_secs: None,
            plan_endpoint: None,
            push_enabled: None,
            stream_endpoint: None,
            unknown: serde_json::Map::new(),
        }
    }

    /// Whether the notification machinery is active. Absent/unset → `false`
    /// (deny-by-default).
    pub fn resolved_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    /// Resolved on-notify action ([`OnNotifyAction::Stage`] when unset).
    ///
    /// Legacy view: it cannot express [`UpdateAction::Apply`]. Callers deciding
    /// what to *do* with a plan must use [`resolved_action`](Self::resolved_action).
    pub fn resolved_on_notify(&self) -> OnNotifyAction {
        self.on_notify.unwrap_or_default()
    }

    /// Resolved update action: [`on_update`](Self::on_update) when set, else the
    /// legacy [`on_notify`](Self::on_notify) mapped forward, else
    /// [`UpdateAction::Stage`]. Never resolves to [`UpdateAction::Apply`] by
    /// default — that takes an explicit `on_update: "apply"`.
    pub fn resolved_action(&self) -> UpdateAction {
        match self.on_update {
            Some(action) => action,
            None => self.resolved_on_notify().into(),
        }
    }

    /// Set the update action, keeping the legacy [`on_notify`](Self::on_notify)
    /// field in sync so a rolled-back binary reads a safe policy. The single
    /// mutation point for the action pair — writing either field alone lets the
    /// two disagree.
    pub fn set_action(&mut self, action: UpdateAction) {
        self.on_update = Some(action);
        self.on_notify = Some(action.legacy_on_notify());
    }

    /// Resolved poll interval, floored at [`MIN_POLL_INTERVAL_SECS`].
    pub fn resolved_poll_interval_secs(&self) -> u64 {
        self.poll_interval_secs
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECS)
            .max(MIN_POLL_INTERVAL_SECS)
    }

    /// Resolved plan endpoint (`None` when unset — the poll loop has no source).
    pub fn resolved_plan_endpoint(&self) -> Option<&str> {
        self.plan_endpoint.as_deref()
    }

    /// `None` => `true`. Push carries the same data, in the same outbound
    /// direction, as the poll this channel already authorizes, so it is not a
    /// new authority. A server without the stream endpoint 404s and the runtime
    /// silently degrades to poll-only — i.e. exactly today's behavior.
    pub fn resolved_push_enabled(&self) -> bool {
        self.push_enabled.unwrap_or(true)
    }

    /// Explicit value when set; otherwise DERIVED from `plan_endpoint` by
    /// replacing a trailing `/plan` with `/updates/stream`. Returns `None` when
    /// there is no plan endpoint, or when it does not end in `/plan` (we will
    /// not guess).
    pub fn resolved_stream_endpoint(&self) -> Option<String> {
        if let Some(ref ep) = self.stream_endpoint {
            return Some(ep.clone());
        }
        let plan_ep = self.plan_endpoint.as_deref()?;
        plan_ep
            .strip_suffix("/plan")
            .map(|base| format!("{base}/updates/stream"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(id: &str) -> EnvId {
        EnvId::try_from(id).unwrap()
    }

    #[test]
    fn disabled_resolves_deny_by_default() {
        let cfg = UpdateChannelConfig::disabled(env("local"));
        assert!(!cfg.resolved_enabled());
        assert_eq!(cfg.resolved_on_notify(), OnNotifyAction::Stage);
        assert_eq!(
            cfg.resolved_poll_interval_secs(),
            DEFAULT_POLL_INTERVAL_SECS
        );
    }

    #[test]
    fn poll_interval_floored_at_minimum() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.poll_interval_secs = Some(1);
        assert_eq!(cfg.resolved_poll_interval_secs(), MIN_POLL_INTERVAL_SECS);
    }

    #[test]
    fn on_notify_round_trips_and_parses() {
        assert_eq!(OnNotifyAction::parse("stage"), Some(OnNotifyAction::Stage));
        assert_eq!(
            OnNotifyAction::parse("record-only"),
            Some(OnNotifyAction::RecordOnly)
        );
        assert_eq!(
            OnNotifyAction::parse("record_only"),
            Some(OnNotifyAction::RecordOnly)
        );
        assert_eq!(OnNotifyAction::parse("apply"), None);
        // serde uses the same snake_case wire form as `as_str`.
        let json = serde_json::to_string(&OnNotifyAction::RecordOnly).unwrap();
        assert_eq!(json, "\"record_only\"");
    }

    #[test]
    fn json_round_trip_omits_unset_fields() {
        let cfg = UpdateChannelConfig::disabled(env("local"));
        let json = serde_json::to_value(&cfg).unwrap();
        // Unset behavior fields are skipped, keeping the on-disk file minimal.
        assert!(json.get("enabled").is_none());
        assert!(json.get("on_notify").is_none());
        assert!(json.get("poll_interval_secs").is_none());
        assert!(json.get("plan_endpoint").is_none());
        let back: UpdateChannelConfig = serde_json::from_value(json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn plan_endpoint_round_trips() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.plan_endpoint = Some("https://updates.example.com/plans/latest".into());
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            json.get("plan_endpoint").and_then(|v| v.as_str()),
            Some("https://updates.example.com/plans/latest")
        );
        let back: UpdateChannelConfig = serde_json::from_value(json).unwrap();
        assert_eq!(back.plan_endpoint, cfg.plan_endpoint);
        assert_eq!(
            back.resolved_plan_endpoint(),
            Some("https://updates.example.com/plans/latest")
        );
    }

    #[test]
    fn unknown_fields_survive_read_modify_write() {
        // A file written by a NEWER binary carries a field this schema revision
        // does not know (`future_field`). It must survive a load → mutate a known
        // field → save cycle (what `op updates config-set` does) so a rolled-back
        // binary never silently drops the newer policy.
        let on_disk = serde_json::json!({
            "schema": UpdateChannelConfig::schema_str(),
            "environment_id": "local",
            "enabled": true,
            "future_field": { "nested": [1, 2, 3] },
        });

        let mut cfg: UpdateChannelConfig = serde_json::from_value(on_disk).unwrap();
        // Known fields parse; the unknown key lands in the catch-all (never in a
        // typed field).
        assert_eq!(cfg.enabled, Some(true));
        assert_eq!(
            cfg.unknown.get("future_field"),
            Some(&serde_json::json!({ "nested": [1, 2, 3] }))
        );
        assert!(!cfg.unknown.contains_key("enabled"));

        // Mutate a known field the way `config-set` would, then re-serialize.
        cfg.on_notify = Some(OnNotifyAction::RecordOnly);
        let rewritten = serde_json::to_value(&cfg).unwrap();

        // The unknown field is re-emitted verbatim at the top level (flattened),
        // alongside the mutated known field.
        assert_eq!(
            rewritten.get("future_field"),
            Some(&serde_json::json!({ "nested": [1, 2, 3] }))
        );
        assert_eq!(
            rewritten.get("on_notify").and_then(|v| v.as_str()),
            Some("record_only")
        );
        assert_eq!(
            rewritten.get("enabled").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn no_unknown_fields_serializes_clean() {
        // The common case: a config with no unknown keys serializes to exactly the
        // known fields — the catch-all adds nothing to the on-disk file.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        let json = serde_json::to_value(&cfg).unwrap();
        let obj = json.as_object().unwrap();
        // schema, environment_id, enabled — and nothing else.
        assert_eq!(obj.len(), 3, "unexpected keys: {obj:?}");
    }

    #[test]
    fn resolved_action_defaults_to_stage_never_apply() {
        // Deny-by-default extends to the action: nothing an operator omits can
        // resolve to `Apply`.
        let cfg = UpdateChannelConfig::disabled(env("local"));
        assert_eq!(cfg.resolved_action(), UpdateAction::Stage);
    }

    #[test]
    fn resolved_action_maps_legacy_on_notify_when_on_update_unset() {
        // A channel written by a pre-`on_update` binary keeps its meaning.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.on_notify = Some(OnNotifyAction::RecordOnly);
        assert_eq!(cfg.resolved_action(), UpdateAction::RecordOnly);

        cfg.on_notify = Some(OnNotifyAction::Stage);
        assert_eq!(cfg.resolved_action(), UpdateAction::Stage);
    }

    #[test]
    fn on_update_wins_over_legacy_on_notify() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.on_notify = Some(OnNotifyAction::Stage);
        cfg.on_update = Some(UpdateAction::Apply);
        assert_eq!(cfg.resolved_action(), UpdateAction::Apply);
    }

    #[test]
    fn set_action_keeps_legacy_field_safe_under_rollback() {
        // The property the whole two-field shape exists for: a binary that
        // predates `on_update` must read `on_notify` and STAGE, never ignore the
        // channel and never fail to parse it.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.set_action(UpdateAction::Apply);
        assert_eq!(cfg.resolved_action(), UpdateAction::Apply);
        assert_eq!(
            cfg.on_notify,
            Some(OnNotifyAction::Stage),
            "an `apply` channel must degrade to `stage` for an older binary"
        );

        cfg.set_action(UpdateAction::RecordOnly);
        assert_eq!(cfg.on_notify, Some(OnNotifyAction::RecordOnly));
    }

    #[test]
    fn old_binary_round_trips_on_update_through_the_catch_all() {
        // Simulate the rollback: serialize with `on_update: apply`, then parse
        // with a schema that does not know the field (the legacy struct shape is
        // modelled by dropping it into `unknown` — exactly what an older
        // `UpdateChannelConfig` does). It must survive a read-modify-write.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.set_action(UpdateAction::Apply);
        let on_disk = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            on_disk.get("on_update").and_then(|v| v.as_str()),
            Some("apply")
        );
        assert_eq!(
            on_disk.get("on_notify").and_then(|v| v.as_str()),
            Some("stage"),
            "the legacy field is what an old binary reads"
        );

        // An old binary's view: `on_update` is just an unknown key.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyConfig {
            schema: SchemaVersion,
            environment_id: EnvId,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            enabled: Option<bool>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            on_notify: Option<OnNotifyAction>,
            #[serde(flatten)]
            unknown: serde_json::Map<String, serde_json::Value>,
        }
        let mut legacy: LegacyConfig = serde_json::from_value(on_disk).unwrap();
        assert_eq!(legacy.on_notify, Some(OnNotifyAction::Stage));
        assert_eq!(
            legacy.unknown.get("on_update"),
            Some(&serde_json::json!("apply"))
        );

        // The old binary rewrites the file (a `config-set`), then a new binary
        // reads it back: `on_update` survived, so `apply` is not silently lost.
        legacy.enabled = Some(false);
        let rewritten = serde_json::to_value(&legacy).unwrap();
        let back: UpdateChannelConfig = serde_json::from_value(rewritten).unwrap();
        assert_eq!(back.resolved_action(), UpdateAction::Apply);
        assert_eq!(back.enabled, Some(false));
    }

    #[test]
    fn resolved_push_enabled_defaults_to_true() {
        let cfg = UpdateChannelConfig::disabled(env("local"));
        assert!(cfg.resolved_push_enabled(), "unset defaults to true");
        assert_eq!(cfg.push_enabled, None);
    }

    #[test]
    fn resolved_push_enabled_respects_explicit_false() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.push_enabled = Some(false);
        assert!(!cfg.resolved_push_enabled());
    }

    #[test]
    fn resolved_stream_endpoint_explicit() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.stream_endpoint = Some("https://custom.example.com/stream".into());
        assert_eq!(
            cfg.resolved_stream_endpoint().as_deref(),
            Some("https://custom.example.com/stream")
        );
    }

    #[test]
    fn resolved_stream_endpoint_derived_from_plan_endpoint() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.plan_endpoint = Some("https://updates.example.com/v1/environments/local/plan".into());
        assert_eq!(
            cfg.resolved_stream_endpoint().as_deref(),
            Some("https://updates.example.com/v1/environments/local/updates/stream")
        );
    }

    #[test]
    fn resolved_stream_endpoint_underivable() {
        // plan_endpoint does not end in `/plan` — derivation returns None.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.plan_endpoint = Some("https://updates.example.com/v1/latest".into());
        assert_eq!(cfg.resolved_stream_endpoint(), None);
    }

    #[test]
    fn resolved_stream_endpoint_none_when_no_plan_endpoint() {
        let cfg = UpdateChannelConfig::disabled(env("local"));
        assert_eq!(cfg.resolved_stream_endpoint(), None);
    }

    #[test]
    fn push_fields_round_trip_through_serde() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.push_enabled = Some(false);
        cfg.stream_endpoint = Some("https://example.com/updates/stream".into());
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            json.get("push_enabled").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            json.get("stream_endpoint").and_then(|v| v.as_str()),
            Some("https://example.com/updates/stream")
        );
        let back: UpdateChannelConfig = serde_json::from_value(json).unwrap();
        assert_eq!(back.push_enabled, Some(false));
        assert_eq!(
            back.stream_endpoint.as_deref(),
            Some("https://example.com/updates/stream")
        );
    }

    #[test]
    fn push_fields_omitted_when_none() {
        let cfg = UpdateChannelConfig::disabled(env("local"));
        let json = serde_json::to_value(&cfg).unwrap();
        assert!(json.get("push_enabled").is_none());
        assert!(json.get("stream_endpoint").is_none());
    }

    #[test]
    fn unknown_catch_all_still_works_with_push_fields() {
        // A config carrying both push fields AND an unknown field:
        // the unknown key must not collide with the new typed fields.
        let on_disk = serde_json::json!({
            "schema": UpdateChannelConfig::schema_str(),
            "environment_id": "local",
            "push_enabled": true,
            "stream_endpoint": "https://example.com/stream",
            "future_field_2": "hello",
        });
        let cfg: UpdateChannelConfig = serde_json::from_value(on_disk).unwrap();
        assert_eq!(cfg.push_enabled, Some(true));
        assert_eq!(
            cfg.stream_endpoint.as_deref(),
            Some("https://example.com/stream")
        );
        assert_eq!(
            cfg.unknown.get("future_field_2"),
            Some(&serde_json::json!("hello"))
        );
        assert!(!cfg.unknown.contains_key("push_enabled"));
        assert!(!cfg.unknown.contains_key("stream_endpoint"));
    }

    #[test]
    fn new_binary_config_parses_on_old_binary_schema() {
        // A config written by the NEW binary (with push fields) must still
        // parse when an older binary reads it — the new keys land in `unknown`
        // and survive a read-modify-write cycle.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.push_enabled = Some(true);
        cfg.stream_endpoint = Some("https://example.com/stream".into());
        let on_disk = serde_json::to_value(&cfg).unwrap();

        // Simulate an old binary that does NOT know push_enabled / stream_endpoint.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct OldConfig {
            schema: SchemaVersion,
            environment_id: EnvId,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            enabled: Option<bool>,
            #[serde(flatten)]
            unknown: serde_json::Map<String, serde_json::Value>,
        }
        let old: OldConfig = serde_json::from_value(on_disk.clone()).unwrap();
        assert_eq!(old.enabled, Some(true));
        // push_enabled and stream_endpoint survive as unknown keys.
        assert_eq!(
            old.unknown.get("push_enabled"),
            Some(&serde_json::json!(true))
        );
        assert!(old.unknown.contains_key("stream_endpoint"));

        // The old binary re-serializes → the new binary reads back: fields survive.
        let rewritten = serde_json::to_value(&old).unwrap();
        let back: UpdateChannelConfig = serde_json::from_value(rewritten).unwrap();
        assert_eq!(back.push_enabled, Some(true));
        assert_eq!(
            back.stream_endpoint.as_deref(),
            Some("https://example.com/stream")
        );
    }

    #[test]
    fn update_action_round_trips_and_parses() {
        assert_eq!(UpdateAction::parse("apply"), Some(UpdateAction::Apply));
        assert_eq!(UpdateAction::parse("stage"), Some(UpdateAction::Stage));
        assert_eq!(
            UpdateAction::parse("record-only"),
            Some(UpdateAction::RecordOnly)
        );
        assert_eq!(
            UpdateAction::parse("record_only"),
            Some(UpdateAction::RecordOnly)
        );
        assert_eq!(UpdateAction::parse("converge"), None);
        assert_eq!(
            serde_json::to_string(&UpdateAction::Apply).unwrap(),
            "\"apply\""
        );
        for action in [
            UpdateAction::RecordOnly,
            UpdateAction::Stage,
            UpdateAction::Apply,
        ] {
            assert_eq!(UpdateAction::parse(action.as_str()), Some(action));
        }
    }
}
