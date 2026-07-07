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
//! `op updates config-set`.

use crate::version::SchemaVersion;
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};

/// What the runtime does when it verifies a signed notification that a newer
/// update plan is available. Deny-by-default and additive: full self-update
/// (verify → get → apply) is deliberately NOT a variant — it is a future opt-in
/// that would add its own gated variant.
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateChannelConfig {
    pub schema: SchemaVersion,
    pub environment_id: EnvId,
    /// Master switch. `None`/absent file → disabled. The runtime neither polls
    /// nor honors webhooks unless this is `Some(true)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// What to do on a verified notification. `None` → [`OnNotifyAction::Stage`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_notify: Option<OnNotifyAction>,
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
            poll_interval_secs: None,
            plan_endpoint: None,
            unknown: serde_json::Map::new(),
        }
    }

    /// Whether the notification machinery is active. Absent/unset → `false`
    /// (deny-by-default).
    pub fn resolved_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    /// Resolved on-notify action ([`OnNotifyAction::Stage`] when unset).
    pub fn resolved_on_notify(&self) -> OnNotifyAction {
        self.on_notify.unwrap_or_default()
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
}
