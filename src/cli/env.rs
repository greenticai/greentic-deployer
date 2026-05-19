//! `gtc op env {create,update,list,show,doctor,destroy}` (`A3` of `plans/next-gen-deployment.md`).
//!
//! Commands operate directly on the [`EnvironmentStore`] from A2. Each
//! mutating call validates the payload before touching disk.

use chrono::Utc;
use greentic_deploy_spec::{EnvId, Environment, EnvironmentHostConfig, SchemaVersion};
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
}

/// Returned by `op env create` / `op env update`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSummary {
    pub environment_id: String,
    pub name: String,
    pub region: Option<String>,
    pub tenant_org_id: Option<String>,
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "create",
        target: json!({"environment_id": env_id.as_str()}),
        previous_generation: None,
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
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
                },
                packs: Vec::new(),
                credentials_ref: None,
                bundles: Vec::new(),
                revisions: Vec::new(),
                traffic_splits: Vec::new(),
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "update",
        target: json!({"environment_id": env_id.as_str(), "fields": fields}),
        previous_generation: None,
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
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
    let missing_slots: Vec<String> = greentic_deploy_spec::CapabilitySlot::ALL
        .iter()
        .copied()
        .filter(|s| env.pack_for_slot(*s).is_none())
        .map(|s| s.to_string())
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
            "has_runtime": runtime.is_some(),
            "checked_at": Utc::now(),
        }),
    ))
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
        previous_generation: None,
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
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
            "tenant_org_id": {"type": ["string", "null"]}
        }
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
        // No packs bound → every slot missing.
        assert_eq!(
            missing.len(),
            greentic_deploy_spec::CapabilitySlot::ALL.len()
        );
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
}
