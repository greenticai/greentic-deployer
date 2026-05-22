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
}

/// `op config set`. Mutates `host_config` fields (region, tenant_org_id) and
/// the env's display `name`. To change anything inside an env-pack's
/// answers, use `op env-packs update`.
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
            "tenant_org_id": {"type": ["string", "null"]}
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
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.name, "renamed");
        assert_eq!(env.host_config.region.as_deref(), Some("eu-west-1"));
        assert_eq!(env.host_config.tenant_org_id.as_deref(), Some("acme"));
    }
}
