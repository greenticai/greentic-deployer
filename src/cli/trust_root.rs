//! `gtc op env trust-root {list,add,remove}` (C2 of `plans/next-gen-deployment.md`).
//!
//! Wraps the typed trust-root verbs on [`LocalFsStore`] (Phase D PR-3a.2)
//! in the operator-CLI shape so external callers can manage the per-env
//! trust root without writing JSON by hand.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use greentic_deploy_spec::EnvId;
use greentic_distributor_client::signing::TrustedKey;
use greentic_trust::{
    DidWeb, HttpResolver, RootResolver, TrustDocument, greentic_key_id, spki_pem,
};
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

/// The resolver is built fresh per invocation and used exactly once, so the
/// cache never serves a hit — these exist only because `HttpResolver::new`
/// requires them. Kept small rather than tuned.
const DID_CACHE_TTL: Duration = Duration::from_secs(60);
const DID_CACHE_CAPACITY: u64 = 1;

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

/// Payload for `op env trust-root add-did`. The DID is the whole input: the
/// key ids and PEMs are derived from the document it resolves to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRootAddDidPayload {
    pub environment_id: String,
    pub did: String,
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
pub(crate) fn trust_root_seed_to_wire(env_id: &EnvId, seed: &TrustRootSeed) -> Value {
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

pub(crate) fn trust_root_add_outcome_to_wire(env_id: &EnvId, out: &TrustRootAddOutcome) -> Value {
    json!({
        "environment_id": env_id.as_str(),
        "added_key_id": out.added_key_id,
        "trusted_key_count": out.trusted_key_count,
    })
}

pub(crate) fn trust_root_remove_outcome_to_wire(
    env_id: &EnvId,
    out: &TrustRootRemoveOutcome,
) -> Value {
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
    Ok(list_outcome(&env_id, &trust.keys))
}

/// Render the `trust-root list` outcome from a key set. Shared by the local
/// FS path above and the remote `--store-url` dispatch, which fetches the
/// keys from `GET /environments/{env_id}/trust-root` instead of disk.
pub(crate) fn list_outcome(env_id: &EnvId, keys: &[TrustedKey]) -> OpOutcome {
    OpOutcome::new(
        NOUN,
        "list",
        json!({
            "environment_id": env_id.as_str(),
            "keys": keys
                .iter()
                .map(|k| json!({"key_id": k.key_id, "public_key_pem": k.public_key_pem}))
                .collect::<Vec<_>>(),
        }),
    )
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

/// Resolve `did` and derive the `(key_id, public_key_pem)` pair for every key
/// the document authorizes, in document order.
///
/// Split out from [`add_did`] so tests can drive resolution on its own — the
/// canonical key-id derivation and the malformed-DID rejection are asserted
/// here, with no store in the picture.
///
/// An empty assertion set is impossible to reach here: `TrustDocument::parse`
/// already rejects it with `NoAssertionKeys`. That is load-bearing — a document
/// resolving to zero keys must be an error, never a success that reports
/// "added 0" and leaves the operator believing they are anchored.
pub(crate) fn resolve_did_keys(
    did: &str,
    resolver: &dyn RootResolver,
) -> Result<Vec<(String, String)>, OpError> {
    let did = DidWeb::parse(did)
        .map_err(|e| OpError::InvalidArgument(format!("trust-root add-did: {e}")))?;
    let document = block_on_resolve(resolver, &did)?;
    document
        .assertion_keys()
        .iter()
        .map(|key| {
            let pem = spki_pem(key).map_err(|e| {
                OpError::Fetch(format!(
                    "did:web `{}`: encoding a resolved key: {e}",
                    did.as_str()
                ))
            })?;
            Ok((greentic_key_id(key), pem))
        })
        .collect()
}

/// Drive the async resolve on a dedicated thread with its own runtime.
///
/// `main.rs` already drives every `op` verb under `block_on`, so building a
/// second runtime inline would panic with "Cannot start a runtime from within a
/// runtime". Same reason and same shape as `bundle_fetch::fetch_oci_to_cache`.
fn block_on_resolve(
    resolver: &dyn RootResolver,
    did: &DidWeb,
) -> Result<Arc<TrustDocument>, OpError> {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| -> Result<Arc<TrustDocument>, OpError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| {
                    OpError::Fetch(format!("build did:web resolve runtime: {source}"))
                })?;
            rt.block_on(resolver.resolve(did))
                .map_err(|source| OpError::Fetch(format!("resolve `{}`: {source}", did.as_str())))
        });
        match handle.join() {
            Ok(result) => result,
            Err(_) => Err(OpError::Fetch(
                "did:web resolve thread panicked".to_string(),
            )),
        }
    })
}

/// `op env trust-root add-did` — resolve a `did:web` document and trust every
/// key it authorizes.
///
/// **Add-only, and deliberately so.** This verb never removes a key, because
/// the document arrives over the network: a reconciling verb would hand whoever
/// controls — or can spoof — that document the power to strip the local
/// operator bootstrap key. Best case the operator is locked out of their own
/// env; worst case the attacker's key is the only one left standing. Revocation
/// stays a deliberate local [`remove`].
///
/// The keys land in `trust-root.json` indistinguishable from hand-added ones.
/// That is a decision, not an oversight: `TrustedKey` has all-public fields and
/// 17 crates depend on `greentic-distributor-client`, so adding a `source` field
/// is a fleet-wide breaking change — and the write path in
/// `greentic-operator-trust` reconstructs the value anyway, so it would be
/// dropped. The audit record below carries the DID, which is the provenance.
///
/// Idempotent: `add_trusted_key` is a no-op for a key id already present, so a
/// re-run against an unchanged document leaves `trusted_key_count` unmoved.
pub fn add_did(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrustRootAddDidPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "add-did", add_did_schema()));
    }
    let payload = resolve_payload::<TrustRootAddDidPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let resolver = HttpResolver::new(DID_CACHE_TTL, DID_CACHE_CAPACITY)
        .map_err(|e| OpError::Fetch(format!("build did:web resolver: {e}")))?;
    // Resolve BEFORE `audit_and_record`, unlike `bootstrap`: a GET has no local
    // side effect to withhold from an unauthorized caller, and holding the env
    // flock across a network round trip would block every concurrent verb for
    // the resolver's full timeout.
    let keys = resolve_did_keys(&payload.did, &resolver)?;
    add_resolved_did_keys(store, &env_id, &payload.did, &keys)
}

/// Persist an already-resolved key set under one audit record. Split from
/// [`add_did`] so tests can drive it with a fake [`RootResolver`], and so the
/// partial-failure tests can feed it a synthetic key set the resolver would
/// never produce.
pub(crate) fn add_resolved_did_keys(
    store: &LocalFsStore,
    env_id: &EnvId,
    did: &str,
    keys: &[(String, String)],
) -> Result<OpOutcome, OpError> {
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add-did",
        // Carries the DID *and* the full PEMs. The DID because it is the only
        // provenance that exists (see the type-level note above); the PEMs for
        // the same reason `add` records them — a key removed later can be
        // reconstructed from the audit log alone.
        target: json!({
            "did": did,
            "keys": keys
                .iter()
                .map(|(key_id, pem)| json!({"key_id": key_id, "public_key_pem": pem}))
                .collect::<Vec<_>>(),
        }),
        // One record per operator action, matching `bootstrap`. The per-key
        // idempotency keys below are separate: reusing one across N adds would
        // make the HTTP backend replay the first key's response for all of them.
        idempotency_key: Some(mint_idempotency_key().as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let mut trusted_key_count = 0;
        // Each key is its own store transaction, so a failure partway through
        // leaves the earlier ones trusted. Two things follow, and neither is
        // optional:
        //
        //  - `mark_committed` after the FIRST success. Without it
        //    `audit_and_record` classifies the whole verb as non-committing and
        //    demotes an audit-append failure to a `warn!` — silently changing
        //    which keys an env trusts with no durable record. Every other verb
        //    in this file writes once, so this is the first closure here that
        //    can persist state and still return `Err`.
        //  - Name the keys that DID land in the error. The audit event records
        //    the full resolved set as its target, so without this the operator
        //    reads "add-did failed" over a list of N keys while some subset of
        //    them is now trusted.
        let mut persisted: Vec<&str> = Vec::new();
        for (key_id, pem) in keys {
            let outcome = store
                .add_trusted_key(env_id, key_id.clone(), pem.clone(), mint_idempotency_key())
                .map_err(|source| {
                    let err = map_store_err_preserving_noun(source);
                    if persisted.is_empty() {
                        return err;
                    }
                    OpError::Conflict(format!(
                        "trust-root add-did `{did}` partially applied: {err}. \
                         Already trusted and NOT rolled back: {}. \
                         Re-running is safe — adding a key already present is a no-op.",
                        persisted.join(", ")
                    ))
                })?;
            committed.mark_committed();
            persisted.push(key_id);
            trusted_key_count = outcome.trusted_key_count;
        }
        Ok((
            OpOutcome::new(
                NOUN,
                "add-did",
                json!({
                    "environment_id": env_id.as_str(),
                    "did": did,
                    "key_ids": keys.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>(),
                    "trusted_key_count": trusted_key_count,
                }),
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

pub(crate) fn resolve_pem(payload: &TrustRootAddPayload) -> Result<String, OpError> {
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

fn add_did_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrustRootAddDidPayload",
        "type": "object",
        "required": ["environment_id", "did"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "did": {
                "type": "string",
                "description": "did:web identifier, e.g. `did:web:trust.greentic.cloud`. Every key its document authorizes is added; none are removed."
            }
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
    use greentic_operator_trust::test_support::keypair;
    use tempfile::tempdir;

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

    // -- add-did ----------------------------------------------------------
    //
    // Driven through a fake `RootResolver` rather than a mock HTTP server:
    // `RootResolver` is a public trait, so this exercises the real document
    // parse and key derivation without a listener, a dev-dep, or the
    // `testing`-gated `allow_http` escape hatch.

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use greentic_trust::TrustError;

    fn root_key(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    /// A resolver that serves one prepared document, or a fetch failure.
    struct FakeResolver(Result<Vec<VerifyingKey>, ()>);

    #[async_trait::async_trait]
    impl RootResolver for FakeResolver {
        async fn resolve(&self, did: &DidWeb) -> Result<Arc<TrustDocument>, TrustError> {
            // `HttpStatus` rather than `Fetch`: constructing a `Fetch` means
            // fabricating a `reqwest::Error`, and two reqwest majors coexist in
            // this dependency graph. Any resolve error maps to the same
            // `OpError::Fetch`, so the variant is immaterial to what is asserted.
            let roots = self
                .0
                .as_ref()
                .map_err(|()| TrustError::HttpStatus { code: 503 })?;
            let doc = greentic_trust::ceremony::build_document(did, roots, &[])?;
            let bytes = serde_json::to_vec(&doc).expect("ceremony document serializes");
            Ok(Arc::new(TrustDocument::parse(did, &bytes)?))
        }
    }

    const TEST_DID: &str = "did:web:trust.greentic.cloud";

    fn seeded_env(dir: &tempfile::TempDir) -> LocalFsStore {
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        store
    }

    fn trusted_key_ids(store: &LocalFsStore) -> Vec<String> {
        let listed = list(store, &OpFlags::default(), "local").unwrap();
        listed.result["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["key_id"].as_str().unwrap().to_string())
            .collect()
    }

    /// Resolve + persist, bypassing only the `HttpResolver` construction that
    /// `add_did` would do. Everything downstream is the production path.
    fn add_did_via(
        store: &LocalFsStore,
        resolver: &dyn RootResolver,
    ) -> Result<OpOutcome, OpError> {
        let env_id = parse_env_id("local")?;
        let keys = resolve_did_keys(TEST_DID, resolver)?;
        add_resolved_did_keys(store, &env_id, TEST_DID, &keys)
    }

    #[test]
    fn add_did_trusts_every_key_the_document_authorizes() {
        let dir = tempdir().unwrap();
        let store = seeded_env(&dir);
        let resolver = FakeResolver(Ok(vec![root_key(7), root_key(8)]));

        let out = add_did_via(&store, &resolver).unwrap();

        assert_eq!(out.noun, NOUN);
        assert_eq!(out.op, "add-did");
        assert_eq!(out.result["did"].as_str().unwrap(), TEST_DID);
        assert_eq!(out.result["trusted_key_count"].as_u64().unwrap(), 2);
        assert_eq!(
            out.result["key_ids"].as_array().unwrap().len(),
            2,
            "a two-key document must trust both keys, not just the first"
        );
        assert_eq!(trusted_key_ids(&store).len(), 2);
    }

    #[test]
    fn add_did_reports_the_canonical_key_id_for_each_resolved_key() {
        let resolver = FakeResolver(Ok(vec![root_key(7)]));
        let keys = resolve_did_keys(TEST_DID, &resolver).unwrap();

        assert_eq!(keys.len(), 1);
        let (key_id, pem) = &keys[0];
        assert_eq!(
            *key_id,
            greentic_key_id(&root_key(7)),
            "the id written to trust-root.json must be the canonical derivation — \
             the verifier matches keyid by exact string equality, so a divergence \
             never fails loudly, it just stops every signature matching"
        );
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn add_did_is_idempotent() {
        let dir = tempdir().unwrap();
        let store = seeded_env(&dir);
        let resolver = FakeResolver(Ok(vec![root_key(7), root_key(8)]));

        add_did_via(&store, &resolver).unwrap();
        let second = add_did_via(&store, &resolver).unwrap();

        assert_eq!(
            second.result["trusted_key_count"].as_u64().unwrap(),
            2,
            "re-running against an unchanged document must not duplicate keys"
        );
        assert_eq!(trusted_key_ids(&store).len(), 2);
    }

    /// The load-bearing security property: the document arrives over the
    /// network, so it must never be able to take a key away. A reconciling
    /// implementation would strip the operator's own bootstrap key here.
    #[test]
    fn add_did_never_removes_a_key_the_document_does_not_authorize() {
        let dir = tempdir().unwrap();
        let store = seeded_env(&dir);
        // The operator's own key, added by hand and NOT in the DID document.
        let (pem, hand_added) = keypair(41);
        add(
            &store,
            &OpFlags::default(),
            Some(TrustRootAddPayload {
                environment_id: "local".into(),
                key_id: hand_added.clone(),
                public_key_pem: Some(pem),
                public_key_file: None,
            }),
        )
        .unwrap();

        add_did_via(&store, &FakeResolver(Ok(vec![root_key(7)]))).unwrap();

        let ids = trusted_key_ids(&store);
        assert!(
            ids.contains(&hand_added),
            "add-did stripped a hand-added key: a hijacked did:web document \
             must never be able to revoke the local operator key"
        );
        assert_eq!(ids.len(), 2, "the did key is added alongside, not instead");
    }

    #[test]
    fn add_did_rejects_a_malformed_did() {
        let resolver = FakeResolver(Ok(vec![root_key(7)]));
        let err = resolve_did_keys("https://trust.greentic.cloud", &resolver).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(_)),
            "a non-did input is an argument error, not a fetch failure: {err}"
        );
    }

    #[test]
    fn add_did_adds_nothing_when_resolution_fails() {
        let dir = tempdir().unwrap();
        let store = seeded_env(&dir);

        let err = add_did_via(&store, &FakeResolver(Err(()))).unwrap_err();

        assert!(matches!(err, OpError::Fetch(_)), "got {err}");
        assert!(
            trusted_key_ids(&store).is_empty(),
            "a failed resolve must leave the trust root untouched"
        );
    }

    /// A document authorizing no keys must be an error, never a success that
    /// reports "added 0" and leaves the operator believing they are anchored.
    /// Enforced upstream by `TrustDocument::parse`; asserted here so a future
    /// change that starts hand-rolling the parse cannot silently lose it.
    #[test]
    fn add_did_refuses_a_document_with_no_assertion_keys() {
        struct EmptyDoc;
        #[async_trait::async_trait]
        impl RootResolver for EmptyDoc {
            async fn resolve(&self, did: &DidWeb) -> Result<Arc<TrustDocument>, TrustError> {
                let bytes = serde_json::to_vec(&json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": did.as_str(),
                    "verificationMethod": [],
                    "assertionMethod": [],
                }))
                .unwrap();
                Ok(Arc::new(TrustDocument::parse(did, &bytes)?))
            }
        }

        let dir = tempdir().unwrap();
        let store = seeded_env(&dir);
        let err = add_did_via(&store, &EmptyDoc).unwrap_err();

        assert!(matches!(err, OpError::Fetch(_)), "got {err}");
        assert!(trusted_key_ids(&store).is_empty());
    }

    /// Each key is its own store transaction, so a mid-import failure really
    /// does leave the earlier keys trusted. The error has to say which ones, or
    /// the operator reads "add-did failed" over the audit event's full N-key
    /// target while some subset is live.
    #[test]
    fn add_did_partial_failure_names_the_keys_it_already_trusted() {
        let dir = tempdir().unwrap();
        let store = seeded_env(&dir);
        let (good_pem, good_id) = keypair(51);
        let keys = vec![
            (good_id.clone(), good_pem),
            (
                "ffffffffffffffffffffffffffffffff".to_string(),
                "not a pem".to_string(),
            ),
        ];

        let err = add_resolved_did_keys(&store, &parse_env_id("local").unwrap(), TEST_DID, &keys)
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains(&good_id),
            "a partially applied import must name the keys that landed; got: {msg}"
        );
        assert!(
            trusted_key_ids(&store).contains(&good_id),
            "the first key really is trusted — that is why the error must say so"
        );
    }

    /// `audit_and_record` demotes an audit-append failure to a `warn!` for a
    /// non-committing op. A partial import IS committing, so it must instead
    /// fail closed with `OpError::Audit`: silently changing which keys an env
    /// trusts, with no durable record, is the worst outcome available here.
    /// Every other verb in this file writes once and cannot reach this state.
    #[test]
    fn add_did_partial_failure_fails_closed_when_the_audit_write_also_fails() {
        let dir = tempdir().unwrap();
        let store = seeded_env(&dir);
        // Block the audit log: `append` does `create_dir_all(<env>/audit)`,
        // which fails when that path is an ordinary file.
        let env_dir = store.env_dir(&parse_env_id("local").unwrap()).unwrap();
        std::fs::write(env_dir.join("audit"), b"not a directory").unwrap();

        let (good_pem, good_id) = keypair(52);
        let keys = vec![
            (good_id, good_pem),
            (
                "ffffffffffffffffffffffffffffffff".to_string(),
                "not a pem".to_string(),
            ),
        ];

        let err = add_resolved_did_keys(&store, &parse_env_id("local").unwrap(), TEST_DID, &keys)
            .unwrap_err();

        assert!(
            matches!(err, OpError::Audit(_)),
            "a committed mutation with no durable audit record must surface as \
             OpError::Audit, not the underlying store error: {err}"
        );
    }

    #[test]
    fn add_did_schema_only_returns_payload_schema_without_touching_disk() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = add_did(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "add-did");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["did"].is_object());
        assert!(
            out.result["properties"]["key_id"].is_null(),
            "add-did derives key ids; accepting one would let a caller pin a key \
             the document does not authorize"
        );
    }
}
