//! `gtc op secrets {list,put,get,rotate}` (`A3`).
//!
//! Operates on the env's bound `Secrets` env-pack. The actual backend
//! dispatch (AWS Secrets Manager, Azure Key Vault, dev-store, Vault, etc.)
//! lives in `greentic-secrets-lib`; the env-pack registry (A9) is what binds
//! a `PackDescriptor` to a concrete backend at runtime. A3 ships the
//! command surface, enforces the env-must-have-secrets-pack precondition,
//! and reports the resolved kind in every envelope.
//!
//! Get/put/rotate against the live backend return `NotYetImplemented` and
//! point at the gating PR (A9 — env-pack registry + handler dispatch).
//! `list` returns the *namespace* keys the env owns (always `secret://<env>/...`)
//! — no actual material is fetched.

use chrono::Utc;
use greentic_deploy_spec::{CapabilitySlot, EnvId, EnvPackBinding, SecretRef};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "secrets";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsListPayload {
    pub environment_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsPutPayload {
    pub environment_id: String,
    /// Path relative to the env's secret namespace. The full SecretRef is
    /// rendered as `secret://<env>/<path>`.
    pub path: String,
    /// The value is intentionally typed as a plain JSON string so payload
    /// transport stays uniform; the live backend handler (A9) is what reads
    /// this and converts to the backend-native shape.
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsGetPayload {
    pub environment_id: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsRotatePayload {
    pub environment_id: String,
    pub path: String,
}

/// `op secrets list`. Returns the env's secret-ref namespace plus the kind
/// of the bound secrets env-pack. Phase A does not yet enumerate live
/// backend-side keys (no handler dispatch); the operator gets the namespace
/// plus backend identity, which is what wizards need to know to write into
/// the right place.
pub fn list(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<SecretsListPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "list", list_schema()));
    }
    let payload = resolve_payload::<SecretsListPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;
    let secrets = require_secrets_pack(&env, &env_id)?;
    // Walk every SecretRef known in the env so the operator can audit what
    // the env *expects* to be present. This is purely structural — the
    // backend itself may have more or fewer keys.
    let mut known_refs: Vec<String> = env
        .credentials_ref
        .as_ref()
        .map(|c| c.as_str().to_string())
        .into_iter()
        .collect();
    if let Some(bs) = env
        .bundles
        .iter()
        .map(|b| b.authorization_ref.to_string_lossy().into_owned())
        .next()
    {
        // authorization_ref is a path, not a secret://, but include it for
        // visibility into where bundle auth resolves.
        known_refs.push(format!("auth://{bs}"));
    }
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({
            "environment_id": env_id.as_str(),
            "secrets_kind": secrets.kind.to_string(),
            "namespace": format!("secret://{}/", env_id.as_str()),
            "known_refs": known_refs,
            "snapshot_at": Utc::now(),
            "note": "Phase A: namespace + known-refs only; live backend enumeration lands in A9.",
        }),
    ))
}

pub fn put(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<SecretsPutPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "put", put_schema()));
    }
    let payload = resolve_payload::<SecretsPutPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "put",
        target: json!({"path": payload.path}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store.load(&env_id)?;
        let secrets = require_secrets_pack(&env, &env_id)?;
        // Build the resolved SecretRef so we can validate the env-scoping.
        let secret_uri = format!(
            "secret://{}/{}",
            env_id.as_str(),
            payload.path.trim_start_matches('/')
        );
        SecretRef::try_new(secret_uri.clone())
            .map_err(|e| OpError::InvalidArgument(format!("secret path: {e}")))?;
        // Make sure the value is non-empty — writing empty strings to a real
        // backend is almost always a bug.
        if payload.value.is_empty() {
            return Err(OpError::InvalidArgument(
                "value must not be empty".to_string(),
            ));
        }
        let _kind = secrets.kind.to_string();
        Err(OpError::NotYetImplemented(
            "secrets backend dispatch lands in A9 (env-pack registry); A3 wires the surface only",
        ))
    })
}

pub fn get(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<SecretsGetPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "get", get_schema()));
    }
    let payload = resolve_payload::<SecretsGetPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;
    let _secrets = require_secrets_pack(&env, &env_id)?;
    SecretRef::try_new(format!(
        "secret://{}/{}",
        env_id.as_str(),
        payload.path.trim_start_matches('/')
    ))
    .map_err(|e| OpError::InvalidArgument(format!("secret path: {e}")))?;
    Err(OpError::NotYetImplemented(
        "secrets backend dispatch lands in A9 (env-pack registry); A3 wires the surface only",
    ))
}

pub fn rotate(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<SecretsRotatePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "rotate", rotate_schema()));
    }
    let payload = resolve_payload::<SecretsRotatePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rotate",
        target: json!({"path": payload.path}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store.load(&env_id)?;
        let _secrets = require_secrets_pack(&env, &env_id)?;
        SecretRef::try_new(format!(
            "secret://{}/{}",
            env_id.as_str(),
            payload.path.trim_start_matches('/')
        ))
        .map_err(|e| OpError::InvalidArgument(format!("secret path: {e}")))?;
        Err(OpError::NotYetImplemented(
            "secret rotation depends on backend-specific rotate hooks; lands in A9",
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

fn require_secrets_pack<'a>(
    env: &'a greentic_deploy_spec::Environment,
    env_id: &EnvId,
) -> Result<&'a EnvPackBinding, OpError> {
    env.pack_for_slot(CapabilitySlot::Secrets).ok_or_else(|| {
        OpError::Conflict(format!(
            "env `{env_id}` has no secrets env-pack bound; bind one with `op env-packs add` first"
        ))
    })
}

fn list_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SecretsListPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {"environment_id": {"type": "string"}}
    })
}

fn put_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SecretsPutPayload",
        "type": "object",
        "required": ["environment_id", "path", "value"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "path": {"type": "string", "description": "Relative path under secret://<env>/"},
            "value": {"type": "string"}
        }
    })
}

fn get_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SecretsGetPayload",
        "type": "object",
        "required": ["environment_id", "path"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "path": {"type": "string"}
        }
    })
}

fn rotate_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SecretsRotatePayload",
        "type": "object",
        "required": ["environment_id", "path"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "path": {"type": "string"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_binding, make_env};
    use tempfile::tempdir;

    fn env_with_secrets() -> greentic_deploy_spec::Environment {
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        env
    }

    #[test]
    fn list_reports_namespace_and_kind() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let outcome = list(
            &store,
            &OpFlags::default(),
            Some(SecretsListPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("secrets_kind").and_then(|v| v.as_str()),
            Some("greentic.secrets.dev-store@1.0.0")
        );
        assert_eq!(
            outcome.result.get("namespace").and_then(|v| v.as_str()),
            Some("secret://local/")
        );
    }

    #[test]
    fn list_rejects_env_without_secrets_pack() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = list(
            &store,
            &OpFlags::default(),
            Some(SecretsListPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn put_validates_path_then_returns_not_yet_implemented() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let err = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: "credentials/aws".to_string(),
                value: "secret-material".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");
    }

    #[test]
    fn put_rejects_empty_value() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let err = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: "x".to_string(),
                value: "".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn get_yields_not_yet_implemented_after_path_validation() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let err = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: "credentials/aws".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");
    }
}
