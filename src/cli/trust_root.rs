//! `gtc op env trust-root {list,add,remove}` (C2 of `plans/next-gen-deployment.md`).
//!
//! Wraps the typed trust-root verbs on [`LocalFsStore`] (Phase D PR-3a.2)
//! in the operator-CLI shape so external callers can manage the per-env
//! trust root without writing JSON by hand.

use std::path::PathBuf;

use greentic_deploy_spec::EnvId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{
    LocalFsStore, TrustRootAddOutcome, TrustRootRemoveOutcome, TrustRootSeed,
    trust_root as store_trust_root,
};

use super::{
    AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record, map_store_err_preserving_noun,
    mint_idempotency_key,
};

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
    // Build ctx with a placeholder target; we only know which key we
    // bootstrapped AFTER `audit_and_record` runs the local-only authz gate.
    // If the gate denies, we never auto-generate `~/.greentic/operator/key.pem`
    // as a side effect of a verb that wasn't authorized to touch the env.
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "bootstrap",
        target: json!({"environment_id": env_id.as_str()}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        // Authz passed: now safe to load-or-generate the operator key.
        let seed = store
            .bootstrap_trust_root(&env_id)
            .map_err(map_store_err_preserving_noun)?;
        Ok((
            OpOutcome::new(NOUN, "bootstrap", trust_root_seed_to_wire(&env_id, &seed)),
            super::AuditGens::NONE,
        ))
    })
}

/// Wire shape the CLI emits for a [`TrustRootSeed`] — preserves the
/// pre-PR-3a.2 envelope (`environment_id`/`operator_key_id`/`operator_public_key_pem`/`trusted_key_count`).
/// Used by `bootstrap` here and `op env init` (via [`trust_root_seed_to_wire_opt`]).
pub(super) fn trust_root_seed_to_wire(env_id: &EnvId, seed: &TrustRootSeed) -> Value {
    json!({
        "environment_id": env_id.as_str(),
        "operator_key_id": seed.key_id,
        "operator_public_key_pem": seed.public_key_pem,
        "trusted_key_count": seed.trusted_key_count,
    })
}

/// `Option` variant: returns JSON `null` when the trust root was already
/// present (op no-op), preserving the pre-PR-3a.2 `Option<TrustRootSeedResult>`
/// serialization the `env init` payload depended on.
pub(super) fn trust_root_seed_to_wire_opt(env_id: &EnvId, seed: Option<&TrustRootSeed>) -> Value {
    match seed {
        Some(s) => trust_root_seed_to_wire(env_id, s),
        None => Value::Null,
    }
}

fn trust_root_add_outcome_to_wire(env_id: &EnvId, out: &TrustRootAddOutcome) -> Value {
    json!({
        "environment_id": env_id.as_str(),
        "added_key_id": out.added_key_id,
        "trusted_key_count": out.trusted_key_count,
    })
}

fn trust_root_remove_outcome_to_wire(env_id: &EnvId, out: &TrustRootRemoveOutcome) -> Value {
    json!({
        "environment_id": env_id.as_str(),
        "removed_key_id": out.removed_key_id,
        "removed_public_key_pem": out.removed_public_key_pem,
        "trusted_key_count": out.trusted_key_count,
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
    // PR-3a.2 follow-up (Codex review of PR #260): every trust-root mutation
    // gets an idempotency key so the HTTP backend can replay the original
    // response (Phase D §A8 #2). The CLI auto-generates a ULID per call
    // today; future direct-args support can plumb a caller-supplied value
    // through the payload (matches the `cli/traffic.rs` precedent).
    let idem = mint_idempotency_key();
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({
            "key_id": payload.key_id,
            "public_key_pem": public_key_pem,
        }),
        idempotency_key: Some(idem.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let outcome = store
            .add_trusted_key(&env_id, payload.key_id, public_key_pem, idem)
            .map_err(map_store_err_preserving_noun)?;
        Ok((
            OpOutcome::new(
                NOUN,
                "add",
                trust_root_add_outcome_to_wire(&env_id, &outcome),
            ),
            super::AuditGens::NONE,
        ))
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
    let idem = mint_idempotency_key();
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        // Audit ctx target carries only the key_id. The full removed PEM
        // would be ideal for recovery, but capturing it BEFORE the env
        // flock races with a concurrent `add` — the audit would log a stale
        // PEM. The trust-root backup file (Codex #3) is the authoritative
        // recovery artifact; the outcome value below carries the PEM that
        // was actually removed under the flock.
        target: json!({"key_id": payload.key_id}),
        idempotency_key: Some(idem.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let outcome = store
            .remove_trusted_key(&env_id, payload.key_id, idem)
            .map_err(map_store_err_preserving_noun)?;
        Ok((
            OpOutcome::new(
                NOUN,
                "remove",
                trust_root_remove_outcome_to_wire(&env_id, &outcome),
            ),
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
