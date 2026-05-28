//! `gtc op config {show,set}` (`A3`).
//!
//! `show` is the inspection surface — host_config, per-slot answers (each
//! redacted), and runtime values are folded into one structured envelope.
//! `set` mutates `host_config` only; setup answers go through
//! `op env-packs add/update` and runtime is intentionally read-only per
//! `plans/next-gen-deployment.md` §P1b.

use chrono::Utc;
use greentic_deploy_spec::{CapabilitySlot, EnvId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "config";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigShowFilter {
    pub environment_id: String,
    /// When set, return only this slot's answers under `pack_answers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<CapabilitySlot>,
}

/// `op config show`. Returns host_config, per-slot answer-presence map,
/// and runtime discovery values. Secrets are NEVER inlined — slots that
/// hold secret-shaped answers are reported as presence-only.
pub fn show(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<ConfigShowFilter>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "show", show_schema()));
    }
    let payload = resolve_payload::<ConfigShowFilter>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;
    let runtime = store.load_runtime(&env_id)?;
    let mut pack_answers = serde_json::Map::new();
    let slots: Vec<CapabilitySlot> = match payload.slot {
        Some(s) => vec![s],
        None => env.packs.iter().map(|b| b.slot).collect(),
    };
    for slot in slots {
        let value = store.load_pack_answers(&env_id, slot)?;
        pack_answers.insert(
            slot.to_string(),
            match value {
                Some(v) => json!({
                    "present": true,
                    "keys": collect_top_keys(&v),
                }),
                None => json!({"present": false}),
            },
        );
    }
    Ok(OpOutcome::new(
        NOUN,
        "show",
        json!({
            "environment_id": env_id.as_str(),
            "host_config": env.host_config,
            "credentials_ref": env.credentials_ref,
            "packs": env.packs,
            "pack_answers": pack_answers,
            "runtime": runtime,
            "snapshot_at": Utc::now(),
        }),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSetPayload {
    pub environment_id: String,
    pub name: Option<String>,
    pub region: Option<String>,
    pub tenant_org_id: Option<String>,
    /// Bind address for the runtime's local HTTP listener. Accepted as a
    /// free-form `SocketAddr` string (e.g. `127.0.0.1:8080`, `0.0.0.0:9090`,
    /// `[::1]:8443`). Parsed and validated at apply time so a malformed value
    /// is rejected before the env is touched. `None` leaves the existing
    /// value unchanged — matches `region`/`tenant_org_id` semantics; there's
    /// no clear-to-`None` flow today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,
}

/// `op config set`. Mutates `host_config` fields (region, tenant_org_id,
/// listen_addr) and the env's display `name`. To change anything inside an
/// env-pack's answers, use `op env-packs update`.
pub fn set(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<ConfigSetPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "set", set_schema()));
    }
    let payload = resolve_payload::<ConfigSetPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    // Parse the bind address up front so a malformed value is rejected before
    // we touch the env store, the audit log, or even the transaction lock.
    // `{raw:?}` debug-formats the input — escaping newlines/quotes — so a
    // hostile payload can't break the structured audit log it lands in.
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
    let mut fields = Vec::new();
    if payload.name.is_some() {
        fields.push("name");
    }
    if payload.region.is_some() {
        fields.push("region");
    }
    if payload.tenant_org_id.is_some() {
        fields.push("tenant_org_id");
    }
    if parsed_listen_addr.is_some() {
        fields.push("listen_addr");
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "set",
        target: json!({"fields": fields}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let (host_config, name) = store.transact(&env_id, |locked| -> Result<_, OpError> {
            let mut env = locked.load()?;
            if let Some(name) = payload.name.clone() {
                env.name = name;
            }
            if let Some(region) = payload.region.clone() {
                env.host_config.region = Some(region);
            }
            if let Some(org) = payload.tenant_org_id.clone() {
                env.host_config.tenant_org_id = Some(org);
            }
            if let Some(addr) = parsed_listen_addr {
                env.host_config.listen_addr = Some(addr);
            }
            locked.save(&env)?;
            Ok((env.host_config.clone(), env.name.clone()))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "set",
            json!({
                "environment_id": env_id.as_str(),
                "host_config": host_config,
                "name": name,
            }),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

// --- internals -----------------------------------------------------------

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

fn collect_top_keys(v: &Value) -> Vec<String> {
    v.as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn show_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ConfigShowFilter",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "slot": {"type": ["string", "null"], "enum": [null, "deployer", "secrets", "telemetry", "sessions", "state", "revocation"]}
        }
    })
}

fn set_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ConfigSetPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "name": {"type": ["string", "null"]},
            "region": {"type": ["string", "null"]},
            "tenant_org_id": {"type": ["string", "null"]},
            "listen_addr": {
                "type": ["string", "null"],
                "description": "Bind address for the runtime's local HTTP listener (e.g. 127.0.0.1:8080, 0.0.0.0:9090, [::1]:8443). Parsed as SocketAddr; malformed values are rejected."
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use tempfile::tempdir;

    #[test]
    fn show_returns_host_config_and_runtime() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let outcome = show(
            &store,
            &OpFlags::default(),
            Some(ConfigShowFilter {
                environment_id: "local".to_string(),
                slot: None,
            }),
        )
        .unwrap();
        assert_eq!(outcome.op, "show");
        let host = outcome.result.get("host_config").unwrap();
        assert_eq!(host.get("env_id").and_then(|v| v.as_str()), Some("local"));
    }

    #[test]
    fn show_filters_by_slot() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        // Save answers for one slot only.
        store
            .save_pack_answers(
                &EnvId::try_from("local").unwrap(),
                CapabilitySlot::Secrets,
                &json!({"backend": "dev-store", "url": "memory://"}),
            )
            .unwrap();
        let outcome = show(
            &store,
            &OpFlags::default(),
            Some(ConfigShowFilter {
                environment_id: "local".to_string(),
                slot: Some(CapabilitySlot::Secrets),
            }),
        )
        .unwrap();
        let pa = outcome.result.get("pack_answers").unwrap();
        let secrets = pa.get("secrets").unwrap();
        assert_eq!(secrets.get("present").and_then(|v| v.as_bool()), Some(true));
        let keys = secrets.get("keys").and_then(|v| v.as_array()).unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn set_updates_region_and_tenant_org_id() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        set(
            &store,
            &OpFlags::default(),
            Some(ConfigSetPayload {
                environment_id: "local".to_string(),
                name: Some("renamed".to_string()),
                region: Some("eu-west-1".to_string()),
                tenant_org_id: Some("acme".to_string()),
                listen_addr: None,
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.name, "renamed");
        assert_eq!(env.host_config.region.as_deref(), Some("eu-west-1"));
        assert_eq!(env.host_config.tenant_org_id.as_deref(), Some("acme"));
        // listen_addr is left untouched when payload field is None.
        assert_eq!(env.host_config.listen_addr, None);
    }

    #[test]
    fn set_updates_listen_addr_to_loopback_default() {
        use greentic_deploy_spec::DEFAULT_LISTEN_ADDR;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let outcome = set(
            &store,
            &OpFlags::default(),
            Some(ConfigSetPayload {
                environment_id: "local".to_string(),
                name: None,
                region: None,
                tenant_org_id: None,
                listen_addr: Some("127.0.0.1:8080".to_string()),
            }),
        )
        .unwrap();
        assert_eq!(outcome.op, "set");
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.host_config.listen_addr, Some(DEFAULT_LISTEN_ADDR));
    }

    #[test]
    fn set_updates_listen_addr_to_explicit_non_loopback() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        set(
            &store,
            &OpFlags::default(),
            Some(ConfigSetPayload {
                environment_id: "local".to_string(),
                name: None,
                region: None,
                tenant_org_id: None,
                listen_addr: Some("0.0.0.0:9090".to_string()),
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9090);
        assert_eq!(env.host_config.listen_addr, Some(expected));
    }

    #[test]
    fn set_rejects_malformed_listen_addr_before_touching_env() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = set(
            &store,
            &OpFlags::default(),
            Some(ConfigSetPayload {
                environment_id: "local".to_string(),
                name: None,
                region: None,
                tenant_org_id: None,
                listen_addr: Some("not-a-socket-addr".to_string()),
            }),
        )
        .expect_err("malformed listen_addr must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("listen_addr") && msg.contains("not-a-socket-addr"),
            "error must name the offending field + value, got: {msg}"
        );
        // Env state must remain untouched.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.host_config.listen_addr, None);
    }

    #[test]
    fn set_error_debug_formats_hostile_input_to_neutralize_log_injection() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        // A payload that tries to inject a fake structured-log line.
        let hostile = "1.2.3.4\nlevel=ERROR msg=injected";
        let err = set(
            &store,
            &OpFlags::default(),
            Some(ConfigSetPayload {
                environment_id: "local".to_string(),
                name: None,
                region: None,
                tenant_org_id: None,
                listen_addr: Some(hostile.to_string()),
            }),
        )
        .expect_err("hostile listen_addr must still be rejected");
        let msg = err.to_string();
        // Debug-format escapes the newline as `\n`, so the literal newline
        // doesn't survive into the error message — log shippers see one line.
        assert!(
            !msg.contains('\n'),
            "error message must not contain a raw newline, got: {msg:?}"
        );
        assert!(
            msg.contains("\\n"),
            "debug-format should have escaped the newline; got: {msg:?}"
        );
    }

    #[test]
    fn set_schema_advertises_every_payload_field_so_strict_properties_does_not_reject() {
        // `additionalProperties: false` means the schema gate rejects any key
        // the schema does not list. If a contributor adds a field to
        // `ConfigSetPayload` and forgets to extend `set_schema()`, callers
        // can never set it. This test pins the full expected key set so the
        // failure mode is "test break" not "silent CLI gap".
        let schema = set_schema();
        let props = schema
            .get("properties")
            .and_then(|p| p.as_object())
            .expect("schema has properties");
        let actual: std::collections::BTreeSet<&str> = props.keys().map(String::as_str).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "environment_id",
            "name",
            "region",
            "tenant_org_id",
            "listen_addr",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            actual, expected,
            "set_schema properties must match ConfigSetPayload fields exactly"
        );
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&json!(false)),
            "set_schema must keep additionalProperties: false; otherwise the \
             completeness check above is moot",
        );
    }
}
