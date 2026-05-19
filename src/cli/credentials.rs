//! `gtc op credentials {requirements,bootstrap,rotate}` (`A3`).
//!
//! Per `plans/next-gen-deployment.md` §P5, credentials are first-class with
//! two modes:
//!
//! - **requirements**: validate user-supplied minimum credentials against
//!   the deployer env-pack's declared requirements.
//! - **bootstrap**: run the deployer env-pack's bootstrap pack against
//!   ephemeral admin credentials; produce low-privilege output + a
//!   reviewable rules pack.
//! - **rotate**: re-validate; rotate session tokens where the deployer
//!   supports it.
//!
//! All three depend on the deployer env-pack registry (A9) and the actual
//! deployer's `credentials.yaml` contract. A3 ships the command *surface*
//! only — every call returns a structured envelope describing what was
//! requested + a `NotYetImplemented` for the action itself, pointing at
//! the gating PR.
//!
//! What A3 *does* enforce:
//!
//! - The env must exist.
//! - The env must have a `Deployer` slot bound (otherwise there's no
//!   credentials.yaml to consult).
//! - For `requirements`/`rotate`, the env must already have a
//!   `credentials_ref` (the user supplied creds somewhere). For
//!   `bootstrap`, `credentials_ref` MUST be absent (bootstrap creates it).

use greentic_deploy_spec::{CapabilitySlot, EnvId, SecretRef};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "credentials";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsRequirementsPayload {
    pub environment_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsBootstrapPayload {
    pub environment_id: String,
    /// Local profile name (e.g. AWS named profile) used for the one-time
    /// admin run. Never written to the env's storage.
    pub admin_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsRotatePayload {
    pub environment_id: String,
}

/// `op credentials requirements`. Returns a structured report describing
/// what *would* be checked and yields `NotYetImplemented` for the actual
/// validation. A5/Phase D wires the deployer env-pack `credentials.yaml`.
pub fn requirements(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<CredentialsRequirementsPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "requirements", req_schema()));
    }
    let payload = resolve_payload::<CredentialsRequirementsPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;
    let deployer = env.pack_for_slot(CapabilitySlot::Deployer).ok_or_else(|| {
        OpError::Conflict(format!(
            "env `{env_id}` has no deployer env-pack bound; bind one with `op env-packs add` first"
        ))
    })?;
    let creds_ref: &SecretRef = env.credentials_ref.as_ref().ok_or_else(|| {
        OpError::Conflict(format!(
            "env `{env_id}` has no credentials_ref; run `op credentials bootstrap` first"
        ))
    })?;
    let _ = describe_intent("requirements", &env_id, deployer, Some(creds_ref));
    Err(OpError::NotYetImplemented(
        "credential validation depends on deployer env-pack `credentials.yaml`; lands in A5+Phase D",
    ))
}

pub fn bootstrap(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<CredentialsBootstrapPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "bootstrap", bootstrap_schema()));
    }
    let payload = resolve_payload::<CredentialsBootstrapPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "bootstrap",
        target: json!({"admin_profile": payload.admin_profile}),
        previous_generation: None,
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
        let env = store.load(&env_id)?;
        let deployer = env.pack_for_slot(CapabilitySlot::Deployer).ok_or_else(|| {
            OpError::Conflict(format!(
                "env `{env_id}` has no deployer env-pack bound; bind one with `op env-packs add` first"
            ))
        })?;
        if env.credentials_ref.is_some() {
            return Err(OpError::Conflict(format!(
                "env `{env_id}` already has credentials_ref; use `rotate` instead of `bootstrap`"
            )));
        }
        let _ = describe_intent("bootstrap", &env_id, deployer, None);
        Err(OpError::NotYetImplemented(
            "bootstrap runs the deployer env-pack's bootstrap module against ephemeral admin credentials; lands in A5+Phase D",
        ))
    })
}

pub fn rotate(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<CredentialsRotatePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "rotate", rotate_schema()));
    }
    let payload = resolve_payload::<CredentialsRotatePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rotate",
        target: json!({}),
        previous_generation: None,
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
        let env = store.load(&env_id)?;
        let deployer = env.pack_for_slot(CapabilitySlot::Deployer).ok_or_else(|| {
            OpError::Conflict(format!("env `{env_id}` has no deployer env-pack bound"))
        })?;
        let creds_ref: &SecretRef = env.credentials_ref.as_ref().ok_or_else(|| {
            OpError::Conflict(format!("env `{env_id}` has no credentials_ref to rotate"))
        })?;
        let _ = describe_intent("rotate", &env_id, deployer, Some(creds_ref));
        Err(OpError::NotYetImplemented(
            "credential rotation depends on deployer-specific session/token rotation hooks; lands in A5+Phase D",
        ))
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

fn describe_intent(
    op: &'static str,
    env_id: &EnvId,
    deployer: &greentic_deploy_spec::EnvPackBinding,
    creds_ref: Option<&SecretRef>,
) -> Value {
    json!({
        "op": op,
        "environment_id": env_id.as_str(),
        "deployer_kind": deployer.kind.to_string(),
        "deployer_pack_ref": deployer.pack_ref.as_str(),
        "credentials_ref": creds_ref.map(|c| c.as_str()),
    })
}

fn req_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CredentialsRequirementsPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {"environment_id": {"type": "string"}}
    })
}

fn bootstrap_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CredentialsBootstrapPayload",
        "type": "object",
        "required": ["environment_id", "admin_profile"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "admin_profile": {"type": "string"}
        }
    })
}

fn rotate_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CredentialsRotatePayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {"environment_id": {"type": "string"}}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_binding, make_env};
    use tempfile::tempdir;

    #[test]
    fn requirements_rejects_env_without_deployer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = requirements(
            &store,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn bootstrap_rejects_when_creds_already_set() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        env.credentials_ref = Some(SecretRef::try_new("secret://local/credentials/aws").unwrap());
        store.save(&env).unwrap();
        let err = bootstrap(
            &store,
            &OpFlags::default(),
            Some(CredentialsBootstrapPayload {
                environment_id: "local".to_string(),
                admin_profile: "admin".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn bootstrap_with_deployer_no_creds_yields_not_yet_implemented() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = bootstrap(
            &store,
            &OpFlags::default(),
            Some(CredentialsBootstrapPayload {
                environment_id: "local".to_string(),
                admin_profile: "admin".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");
    }

    #[test]
    fn rotate_rejects_env_without_credentials_ref() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = rotate(
            &store,
            &OpFlags::default(),
            Some(CredentialsRotatePayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn requirements_with_complete_setup_yields_not_yet_implemented() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        env.credentials_ref = Some(SecretRef::try_new("secret://local/credentials/aws").unwrap());
        store.save(&env).unwrap();
        let err = requirements(
            &store,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");
    }

    #[test]
    fn bootstrap_stub_records_not_yet_implemented_audit_result() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = bootstrap(
            &store,
            &OpFlags::default(),
            Some(CredentialsBootstrapPayload {
                environment_id: "local".to_string(),
                admin_profile: "admin".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)));
        let log = dir.path().join("local").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).unwrap();
        let event: crate::environment::AuditEvent = serde_json::from_str(raw.trim_end()).unwrap();
        // Stub verbs MUST record `NotYetImplemented` (distinct from `Error`) so
        // post-A7 readers can filter stub attempts from real errors.
        match event.result {
            crate::environment::AuditResult::NotYetImplemented { detail } => {
                assert!(detail.contains("bootstrap"), "detail: {detail}");
            }
            other => panic!("expected NotYetImplemented, got {other:?}"),
        }
    }
}
