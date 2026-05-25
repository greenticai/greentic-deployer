//! `gtc op env trust-root {list,add,remove}` (C2 of `plans/next-gen-deployment.md`).
//!
//! Wraps [`crate::environment::trust_root`] in the operator-CLI shape so
//! external callers can manage the per-env trust root without writing JSON
//! by hand. All mutations run under the env flock via
//! [`LocalFsStore::transact`].

use std::path::PathBuf;

use greentic_deploy_spec::EnvId;
use greentic_distributor_client::signing::TrustedKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{LocalFsStore, trust_root as store_trust_root};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "trust-root";

/// Payload for `op env trust-root add`. Either inline `public_key_pem` OR a
/// `public_key_file` path; one is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRootAddPayload {
    pub environment_id: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_file: Option<PathBuf>,
}

/// Payload for `op env trust-root remove`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRootRemovePayload {
    pub environment_id: String,
    pub key_id: String,
}

/// Payload for `op env trust-root bootstrap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRootBootstrapPayload {
    pub environment_id: String,
}

/// `op env trust-root bootstrap` — load (or generate) the operator key and
/// add its `(key_id, public_pem)` to the env trust root. This is the
/// **only** seeded code path: the revenue-policy writer NEVER mutates the
/// trust root, so revocation via [`remove`] is a durable boundary. Run
/// once per env; subsequent runs with the same operator key are a no-op.
pub fn bootstrap(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrustRootBootstrapPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "bootstrap", bootstrap_schema()));
    }
    let payload = resolve_payload::<TrustRootBootstrapPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let op_key = crate::operator_key::load_or_generate()
        .map_err(crate::environment::BundleDeploymentError::from)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "bootstrap",
        target: json!({
            "key_id": op_key.key_id,
            "public_key_pem": op_key.public_pem,
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env_dir = store.env_dir(&env_id)?;
        let summary = store.transact(&env_id, |_locked| -> Result<Value, OpError> {
            let trust = store_trust_root::add_trusted_key(
                &env_dir,
                TrustedKey {
                    key_id: op_key.key_id.clone(),
                    public_key_pem: op_key.public_pem.clone(),
                },
            )?;
            Ok(json!({
                "environment_id": env_id.as_str(),
                "operator_key_id": op_key.key_id,
                "trusted_key_count": trust.keys.len(),
            }))
        })?;
        Ok((
            OpOutcome::new(NOUN, "bootstrap", summary),
            super::AuditGens::NONE,
        ))
    })
}

/// `op env trust-root list <env_id>` — return all trusted keys for the env.
pub fn list(store: &LocalFsStore, flags: &OpFlags, env_id: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "list", list_schema()));
    }
    let env_id = parse_env_id(env_id)?;
    let env_dir = store.env_dir(&env_id)?;
    let trust = store_trust_root::load(&env_dir)?;
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({
            "environment_id": env_id.as_str(),
            "keys": trust
                .keys
                .iter()
                .map(|k| json!({"key_id": k.key_id, "public_key_pem": k.public_key_pem}))
                .collect::<Vec<_>>(),
        }),
    ))
}

/// `op env trust-root add` — validate the (key_id, public_pem) pair and
/// persist it (idempotent on case-insensitive key_id).
pub fn add(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrustRootAddPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "add", add_schema()));
    }
    let payload = resolve_payload::<TrustRootAddPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let public_key_pem = resolve_pem(&payload)?;
    // Codex #3: audit `target` carries the full PEM, so a removed key can be
    // reconstructed from the audit log alone if the on-disk backup is also
    // lost. `key_id` alone is not sufficient for recovery.
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({
            "key_id": payload.key_id,
            "public_key_pem": public_key_pem,
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env_dir = store.env_dir(&env_id)?;
        let summary = store.transact(&env_id, |_locked| -> Result<Value, OpError> {
            let trust = store_trust_root::add_trusted_key(
                &env_dir,
                TrustedKey {
                    key_id: payload.key_id.clone(),
                    public_key_pem: public_key_pem.clone(),
                },
            )?;
            Ok(json!({
                "environment_id": env_id.as_str(),
                "added_key_id": payload.key_id,
                "trusted_key_count": trust.keys.len(),
            }))
        })?;
        Ok((OpOutcome::new(NOUN, "add", summary), super::AuditGens::NONE))
    })
}

/// `op env trust-root remove` — silently no-ops if the key isn't present.
pub fn remove(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrustRootRemovePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "remove", remove_schema()));
    }
    let payload = resolve_payload::<TrustRootRemovePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    // Codex #3: look up the PEM *before* removal so the audit `target`
    // captures what is about to be discarded — `key_id` alone is not enough
    // to reconstruct a removed key.
    let env_dir = store.env_dir(&env_id)?;
    let pre_removal = store_trust_root::load(&env_dir)?;
    let removed_pem = pre_removal
        .keys
        .iter()
        .find(|k| k.key_id.eq_ignore_ascii_case(&payload.key_id))
        .map(|k| k.public_key_pem.clone());
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({
            "key_id": payload.key_id,
            "public_key_pem": removed_pem,
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env_dir = store.env_dir(&env_id)?;
        let summary = store.transact(&env_id, |_locked| -> Result<Value, OpError> {
            let trust = store_trust_root::remove_trusted_key(&env_dir, &payload.key_id)?;
            Ok(json!({
                "environment_id": env_id.as_str(),
                "removed_key_id": payload.key_id,
                "trusted_key_count": trust.keys.len(),
            }))
        })?;
        Ok((
            OpOutcome::new(NOUN, "remove", summary),
            super::AuditGens::NONE,
        ))
    })
}

fn resolve_pem(payload: &TrustRootAddPayload) -> Result<String, OpError> {
    match (&payload.public_key_pem, &payload.public_key_file) {
        (Some(pem), None) => Ok(pem.clone()),
        (None, Some(path)) => std::fs::read_to_string(path).map_err(|source| OpError::Io {
            path: path.clone(),
            source,
        }),
        (Some(_), Some(_)) => Err(OpError::InvalidArgument(
            "trust-root add: pass exactly one of `public_key_pem` or `public_key_file`".to_string(),
        )),
        (None, None) => Err(OpError::InvalidArgument(
            "trust-root add: one of `public_key_pem` or `public_key_file` is required".to_string(),
        )),
    }
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
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

fn bootstrap_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrustRootBootstrapPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"}
        }
    })
}

fn list_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrustRootList",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"}
        }
    })
}

fn add_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrustRootAddPayload",
        "type": "object",
        "required": ["environment_id", "key_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "key_id": {"type": "string", "description": "Canonical key id (hex SHA-256[..16] of the raw public key)."},
            "public_key_pem": {"type": ["string", "null"], "description": "Inline SPKI PEM."},
            "public_key_file": {"type": ["string", "null"], "description": "Path to a SPKI PEM file."}
        }
    })
}

fn remove_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrustRootRemovePayload",
        "type": "object",
        "required": ["environment_id", "key_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "key_id": {"type": "string"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::EnvironmentStore;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use greentic_distributor_client::signing::key_id_for_public_key_pem;
    use tempfile::tempdir;

    fn keypair(seed: u8) -> (String, String) {
        let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        let pem = vk.to_public_key_pem(LineEnding::LF).unwrap();
        let id = key_id_for_public_key_pem(&pem).unwrap();
        (pem, id)
    }

    #[test]
    fn list_on_fresh_env_returns_empty_keys() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let out = list(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(out.result["keys"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn add_then_list_includes_the_key() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let (pem, id) = keypair(31);
        add(
            &store,
            &OpFlags::default(),
            Some(TrustRootAddPayload {
                environment_id: "local".into(),
                key_id: id.clone(),
                public_key_pem: Some(pem.clone()),
                public_key_file: None,
            }),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let keys = listed.result["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["key_id"].as_str().unwrap(), id);
    }

    #[test]
    fn add_loads_pem_from_file_when_inline_omitted() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let (pem, id) = keypair(32);
        let pem_path = dir.path().join("key.pub");
        std::fs::write(&pem_path, &pem).unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(TrustRootAddPayload {
                environment_id: "local".into(),
                key_id: id.clone(),
                public_key_pem: None,
                public_key_file: Some(pem_path),
            }),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(listed.result["keys"][0]["key_id"].as_str().unwrap(), id);
    }

    #[test]
    fn add_rejects_both_pem_sources_set() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let (pem, id) = keypair(33);
        let err = add(
            &store,
            &OpFlags::default(),
            Some(TrustRootAddPayload {
                environment_id: "local".into(),
                key_id: id,
                public_key_pem: Some(pem),
                public_key_file: Some(PathBuf::from("/dev/null")),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn add_rejects_neither_pem_source_set() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let (_pem, id) = keypair(34);
        let err = add(
            &store,
            &OpFlags::default(),
            Some(TrustRootAddPayload {
                environment_id: "local".into(),
                key_id: id,
                public_key_pem: None,
                public_key_file: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn add_rejects_mismatched_key_id() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let (pem, _id) = keypair(35);
        let (_pem_b, id_b) = keypair(36);
        let err = add(
            &store,
            &OpFlags::default(),
            Some(TrustRootAddPayload {
                environment_id: "local".into(),
                key_id: id_b,
                public_key_pem: Some(pem),
                public_key_file: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::TrustRoot(_)));
    }

    #[test]
    fn remove_drops_only_matching_key() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let (pem_a, id_a) = keypair(37);
        let (pem_b, id_b) = keypair(38);
        for (pem, id) in [(pem_a, id_a.clone()), (pem_b, id_b.clone())] {
            add(
                &store,
                &OpFlags::default(),
                Some(TrustRootAddPayload {
                    environment_id: "local".into(),
                    key_id: id,
                    public_key_pem: Some(pem),
                    public_key_file: None,
                }),
            )
            .unwrap();
        }
        remove(
            &store,
            &OpFlags::default(),
            Some(TrustRootRemovePayload {
                environment_id: "local".into(),
                key_id: id_a,
            }),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let keys = listed.result["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["key_id"].as_str().unwrap(), id_b);
    }

    #[test]
    fn bootstrap_seeds_operator_key_into_env_trust_root() {
        // Codex #1: explicit bootstrap is the only authorized path to seed
        // the operator key into the env trust root.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let outcome = bootstrap(
            &store,
            &OpFlags::default(),
            Some(TrustRootBootstrapPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        assert_eq!(outcome.op, "bootstrap");
        assert!(outcome.result["operator_key_id"].is_string());
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(listed.result["keys"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        bootstrap(
            &store,
            &OpFlags::default(),
            Some(TrustRootBootstrapPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        bootstrap(
            &store,
            &OpFlags::default(),
            Some(TrustRootBootstrapPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(
            listed.result["keys"].as_array().unwrap().len(),
            1,
            "second bootstrap must not duplicate the operator key"
        );
    }

    #[test]
    fn schema_only_returns_payload_schema_without_touching_disk() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = add(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "add");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["key_id"].is_object());
    }
}
