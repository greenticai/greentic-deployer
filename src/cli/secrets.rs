//! `gtc op secrets {list,put,get,rotate,delete}` (`A3`).
//!
//! Operates on the env's bound `Secrets` env-pack. The actual backend
//! dispatch (AWS Secrets Manager, Azure Key Vault, dev-store, Vault, etc.)
//! lives in `greentic-secrets-lib`; the env-pack registry (A9) is what binds
//! a `PackDescriptor` to a concrete backend at runtime. A3 ships the
//! command surface, enforces the env-must-have-secrets-pack precondition,
//! and reports the resolved kind in every envelope.
//!
//! `put` is live for the `greentic.secrets.dev-store` kind (the default
//! binding `op env init` creates): it writes the value into the env's local
//! dev store at the same path the runtime reader (greentic-start
//! `SecretsClient::open(<env_dir>)`) resolves, so a put is immediately
//! visible to served revisions. All other kinds — and get/rotate against any
//! live backend — return `NotYetImplemented` and point at the gating PR
//! (A9 — env-pack registry + handler dispatch).
//! `list` returns the *namespace* keys the env owns (always `secret://<env>/...`)
//! — no actual material is fetched. With a `prefix` it also enumerates the
//! dev store's stored KEY NAMES under that prefix (never values).
//!
//! `delete` removes one key (`path`) or every key under a `prefix` from the dev
//! store — dropped from the store file entirely, not tombstoned, because the
//! env-packs ship that whole file into every workload (see
//! `dev_store_keys`). Deleting a missing key is a success with
//! `deleted: false`.

use std::path::{Path, PathBuf};

use chrono::Utc;
use greentic_deploy_spec::{CapabilitySlot, EnvId, EnvPackBinding, Environment, SecretRef};
use greentic_secrets_lib::{DevStore, SecretFormat, SecretsStore, canonical_secret_store_key};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvFlock, EnvironmentStore, LocalFsStore};

use super::{
    AuditCtx, AuditGens, OpError, OpFlags, OpOutcome, audit_and_record, resolve_idempotency_key,
};

#[cfg(test)]
mod delete_tests;
mod dev_store_keys;

use dev_store_keys::DevStorePrefix;

const NOUN: &str = "secrets";

/// `PackDescriptor::path()` of the local dev-store secrets backend — the
/// default binding `op env init` creates and the only kind `put` dispatches
/// to in Phase A. Shared with `env apply` (PR-2), which pre-checks the bound
/// backend at validation time so a non-dev-store env fails before any
/// mutation instead of mid-run.
pub(super) const DEV_STORE_KIND_PATH: &str = "greentic.secrets.dev-store";

/// Same override the runtime reader honors (`greentic-start
/// `dev_store_path::override_path`): when set, both writer and reader use
/// this path instead of the env-dir defaults below. `pub(crate)` so the P0b
/// snapshot can note when the dev-store is redirected off the env tree.
pub(crate) const DEV_SECRETS_PATH_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";

/// Dev-store candidates relative to the env dir. MUST mirror greentic-start's
/// `dev_store_path.rs` (`STORE_RELATIVE` / `STORE_STATE_RELATIVE`) — the
/// runtime's `SecretsClient::open(<env_dir>)` resolves the same chain, so a
/// put here is what a served revision reads back. `pub(crate)` so the P0b
/// snapshot (`environment::snapshot`) captures the same paths this writes.
pub(crate) const DEV_STORE_RELATIVE: &str = ".greentic/dev/.dev.secrets.env";
pub(crate) const DEV_STORE_STATE_RELATIVE: &str = ".greentic/state/dev/.dev.secrets.env";

/// Pack segments whose keys are owned by greentic-designer-admin rather
/// than by an environment: stored VERBATIM, under the `default` env segment.
/// `mcp` keys an MCP server by its hyphenated UUID; `a2a` keys an external
/// A2A agent the same way (`agent_id` is a hyphenated UUID too). Both are
/// written and read byte-for-byte because the admin mints the id and the
/// runtime looks it up unmodified — canonicalising either would rewrite the
/// hyphens to underscores and resolve nothing, silently, since a missing
/// credential of either kind is reported as an ordinary node/tool error.
///
/// Mirrors greentic-start's reader carve-out (`src/secrets_client.rs`,
/// `canonicalize_dev_store_secret_uri`) exactly. The two must agree: a writer
/// that normalizes a key the reader does not — or files it under a different
/// env segment — stores a credential nothing ever looks up, and the failure
/// surfaces only as an ordinary MCP/A2A node error.
const MCP_CATEGORY: &str = "mcp";

/// See [`MCP_CATEGORY`] — the same verbatim-storage rule applies to `a2a`.
const A2A_CATEGORY: &str = "a2a";

/// Env segment every `mcp`/`a2a` key is written under, matching
/// `greentic_aw_runtime::mcp_secrets::MCP_ENV_SEGMENT`.
const MCP_ENV_SEGMENT: &str = "default";

/// Whether `rel_path` (`<tenant>/<team>/<pack>/<name>`) names a category
/// whose secret name is stored verbatim (`mcp` or `a2a`). Keyed on the PACK
/// position, never a substring: a tenant or a secret merely called `mcp` or
/// `a2a` is an ordinary key.
fn is_verbatim_category_rel_path(rel_path: &str) -> bool {
    matches!(
        rel_path.split('/').nth(2),
        Some(MCP_CATEGORY | A2A_CATEGORY)
    )
}

/// The `llm` category: an agent's LLM API key, keyed by the agent's
/// `llm.credential_ref`.
///
/// greentic-runner reads it at `secrets://default/<tenant>/_/llm/<ref>`
/// (`resolve_in_process_llm_key`) — the `default` env segment is hardcoded
/// there, exactly as it is for `mcp`. Unlike `mcp`/`a2a` the NAME is not
/// verbatim: greentic-start's reader carve-out covers only those two, so it
/// canonicalizes an `llm` name before lookup, and the ordinary canonical-name
/// validation below is what makes the write land on that same key. Only the
/// env segment differs from an ordinary key, and it is the whole defect: keyed
/// by the environment id, every staged LLM key sat one segment away from the
/// read and the agent ran with no key at all.
const LLM_CATEGORY: &str = "llm";

/// Whether `rel_path` names the `llm` category (pack position only, like
/// [`is_verbatim_category_rel_path`]).
fn is_llm_category_rel_path(rel_path: &str) -> bool {
    rel_path.split('/').nth(2) == Some(LLM_CATEGORY)
}

/// The dev store's native key for `rel_path` in `env_id`.
///
/// THE one derivation, shared by [`put_env_secret`], [`get_env_secret`] and
/// [`dev_store_has`] so a write, the read that checks it and the presence
/// probe `env apply` gates on cannot land on different keys.
pub(super) fn dev_store_key(env_id: &EnvId, rel_path: &str) -> String {
    if is_verbatim_category_rel_path(rel_path) || is_llm_category_rel_path(rel_path) {
        format!("secrets://{MCP_ENV_SEGMENT}/{rel_path}")
    } else {
        format!("secrets://{}/{rel_path}", env_id.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsListPayload {
    pub environment_id: String,
    /// Optional `<tenant>/<team>/<pack>/[<name-prefix>]`. When set, the
    /// outcome also carries `prefix` and `stored_keys` — the dev store's live
    /// key NAMES under it (dev-store backend only). Absent keeps the output
    /// byte-for-byte what it was before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
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
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsGetPayload {
    pub environment_id: String,
    pub path: String,
    /// When true, the decrypted value is included in the outcome envelope.
    /// Default false — only presence + metadata is returned, so a `get` does
    /// not leak the value into CI logs / audit trails.
    #[serde(default)]
    pub reveal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsRotatePayload {
    pub environment_id: String,
    pub path: String,
}

/// `op secrets delete` payload. Exactly one of `path` / `prefix`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsDeletePayload {
    pub environment_id: String,
    /// One key, `<tenant>/<team>/<pack>/<name>` — validated exactly like `put`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Every live key under `<tenant>/<team>/<pack>/[<name-prefix>]`, removed
    /// in one atomic rewrite of the store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Caller-supplied A8 §2 idempotency key; minted per invocation when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
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
    let mut result = json!({
        "environment_id": env_id.as_str(),
        "secrets_kind": secrets.kind.to_string(),
        "namespace": format!("secret://{}/", env_id.as_str()),
        "known_refs": known_refs,
        "snapshot_at": Utc::now(),
        "note": "Phase A: namespace + known-refs only; live backend enumeration lands in A9.",
    });
    if let Some(raw_prefix) = payload.prefix.as_deref() {
        let prefix = DevStorePrefix::parse(raw_prefix)?;
        require_dev_store_kind(secrets, "list --prefix")?;
        let dev_path = env_dev_store_path(store, &env_id)?;
        let keys = dev_store_keys::list_keys(&dev_path, &env_id, &prefix)?;
        result["prefix"] = Value::String(prefix.render());
        result["store_path"] = Value::String(dev_path.display().to_string());
        result["stored_keys"] = serde_json::to_value(keys)
            .map_err(|e| OpError::InvalidArgument(format!("serializing stored keys: {e}")))?;
    }
    Ok(OpOutcome::new(NOUN, "list", result))
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
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key.clone())?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "put",
        target: json!({"path": payload.path}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store.load(&env_id)?;
        let secrets = require_secrets_pack(&env, &env_id)?;
        let rel_path = payload.path.trim_start_matches('/');
        // Build the resolved SecretRef so we can validate the env-scoping.
        let secret_uri = format!("secret://{}/{rel_path}", env_id.as_str());
        SecretRef::try_new(secret_uri.clone())
            .map_err(|e| OpError::InvalidArgument(format!("secret path: {e}")))?;
        // Make sure the value is non-empty — writing empty strings to a real
        // backend is almost always a bug.
        if payload.value.is_empty() {
            return Err(OpError::InvalidArgument(
                "value must not be empty".to_string(),
            ));
        }
        let kind_path = secrets.kind.path();
        let (store_uri, extra) =
            put_env_secret(store, &env, &env_id, kind_path, rel_path, &payload.value)?;
        // Preserve the pre-extraction field order (backend-specific field before
        // `written`): base identity fields, then the backend `extra`, then the
        // `written` flag.
        let mut result = json!({
            "environment_id": env_id.as_str(),
            "secret_ref": secret_uri,
            "store_uri": store_uri,
            "secrets_kind": secrets.kind.to_string(),
        });
        if let (Value::Object(result_map), Value::Object(extra_map)) = (&mut result, extra) {
            result_map.extend(extra_map);
        }
        result["written"] = Value::Bool(true);
        Ok((OpOutcome::new(NOUN, "put", result), AuditGens::NONE))
    })
}

/// `op secrets get`. Reads a secret back for the dev-store and Vault backends
/// (symmetric to [`put`]); other kinds return `NotYetImplemented` (A9). Reads
/// are not audited (matching [`list`]). By default only presence + metadata is
/// returned; `reveal: true` includes the decrypted value.
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
    let secrets = require_secrets_pack(&env, &env_id)?;
    let rel_path = payload.path.trim_start_matches('/');
    let secret_uri = format!("secret://{}/{rel_path}", env_id.as_str());
    SecretRef::try_new(secret_uri.clone())
        .map_err(|e| OpError::InvalidArgument(format!("secret path: {e}")))?;

    let kind = secrets.kind.to_string();
    let kind_path = secrets.kind.path();
    let (value, store_uri, extra) = get_env_secret(store, &env, &env_id, kind_path, rel_path)?;
    Ok(OpOutcome::new(
        NOUN,
        "get",
        get_result_json(
            env_id.as_str(),
            &secret_uri,
            &store_uri,
            &kind,
            extra,
            value,
            payload.reveal,
        ),
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
            "secret rotation depends on backend-specific rotate hooks; lands in A9".to_string(),
        ))
    })
}

/// `op secrets delete`. Removes one key (`path`) or every live key under a
/// `prefix` from the env's dev store. Idempotent: a key that is not there is a
/// success with `deleted: false`. Audited like [`put`]. Only the dev-store
/// backend is supported; other kinds return `NotYetImplemented`.
pub fn delete(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<SecretsDeletePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "delete", delete_schema()));
    }
    let payload = resolve_payload::<SecretsDeletePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key.clone())?;
    let target = match (&payload.path, &payload.prefix) {
        (Some(path), None) => json!({"path": path}),
        (None, Some(prefix)) => json!({"prefix": prefix}),
        _ => {
            return Err(OpError::InvalidArgument(
                "exactly one of `path` or `prefix` is required".to_string(),
            ));
        }
    };
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "delete",
        target,
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store.load(&env_id)?;
        let secrets = require_secrets_pack(&env, &env_id)?;
        let result = match (&payload.path, &payload.prefix) {
            (Some(path), None) => delete_one(store, &env_id, secrets, path)?,
            (None, Some(prefix)) => delete_under_prefix(store, &env_id, secrets, prefix)?,
            _ => {
                return Err(OpError::InvalidArgument(
                    "exactly one of `path` or `prefix` is required".to_string(),
                ));
            }
        };
        Ok((OpOutcome::new(NOUN, "delete", result), AuditGens::NONE))
    })
}

fn delete_one(
    store: &LocalFsStore,
    env_id: &EnvId,
    secrets: &EnvPackBinding,
    path: &str,
) -> Result<Value, OpError> {
    let rel_path = path.trim_start_matches('/');
    let secret_uri = format!("secret://{}/{rel_path}", env_id.as_str());
    SecretRef::try_new(secret_uri.clone())
        .map_err(|e| OpError::InvalidArgument(format!("secret path: {e}")))?;
    require_dev_store_kind(secrets, "delete")?;
    // Same validation as `put`/`get` — including the reservation of the
    // deployer's own bound credential paths — and the same key derivation.
    validate_dev_store_secret_path(rel_path)?;
    let store_uri = dev_store_key(env_id, rel_path);
    let dev_path = env_dev_store_path(store, env_id)?;
    let deleted = dev_store_keys::delete_key(&dev_path, &store_uri)?;
    Ok(json!({
        "environment_id": env_id.as_str(),
        "secret_ref": secret_uri,
        "store_uri": store_uri,
        "secrets_kind": secrets.kind.to_string(),
        "store_path": dev_path.display().to_string(),
        "deleted": deleted,
    }))
}

fn delete_under_prefix(
    store: &LocalFsStore,
    env_id: &EnvId,
    secrets: &EnvPackBinding,
    raw_prefix: &str,
) -> Result<Value, OpError> {
    let prefix = DevStorePrefix::parse(raw_prefix)?;
    require_dev_store_kind(secrets, "delete --prefix")?;
    let dev_path = env_dev_store_path(store, env_id)?;
    let removed = dev_store_keys::delete_prefix(&dev_path, env_id, &prefix)?;
    let count = removed.len();
    Ok(json!({
        "environment_id": env_id.as_str(),
        "prefix": prefix.render(),
        "secrets_kind": secrets.kind.to_string(),
        "store_path": dev_path.display().to_string(),
        "deleted": count > 0,
        "deleted_count": count,
        "deleted_keys": serde_json::to_value(removed).map_err(|e| {
            OpError::InvalidArgument(format!("serializing deleted keys: {e}"))
        })?,
    }))
}

/// Key enumeration and hard delete exist for the dev store only.
fn require_dev_store_kind(secrets: &EnvPackBinding, verb: &str) -> Result<(), OpError> {
    if secrets.kind.path() == DEV_STORE_KIND_PATH {
        Ok(())
    } else {
        Err(OpError::NotYetImplemented(format!(
            "`op secrets {verb}` supports the dev-store backend only; backend \
             dispatch for `{}` lands in A9 (env-pack registry)",
            secrets.kind
        )))
    }
}

/// The env's dev store file, resolved exactly as `put`/`get` resolve it.
fn env_dev_store_path(store: &LocalFsStore, env_id: &EnvId) -> Result<PathBuf, OpError> {
    Ok(resolve_dev_store_path(
        &store.env_dir(env_id)?,
        std::env::var_os(DEV_SECRETS_PATH_ENV).map(PathBuf::from),
    ))
}

// --- internals -----------------------------------------------------------

/// Persist `value` at `rel_path` (`<tenant>/<team>/<pack>/<name>`) into the
/// env's configured secrets backend, dispatching on `kind_path` (dev-store or
/// Vault). Returns `(store_uri, backend_extra)` where `backend_extra` is the
/// backend-identifying JSON fragment for the op outcome (`store_path` for the
/// dev store, `vault_addr` for Vault). Shared by `op secrets put` and
/// `op updates enroll` so the two write surfaces cannot drift.
pub(super) fn put_env_secret(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    kind_path: &str,
    rel_path: &str,
    value: &str,
) -> Result<(String, Value), OpError> {
    if kind_path == DEV_STORE_KIND_PATH {
        validate_dev_store_secret_path(rel_path)?;
        let store_uri = dev_store_key(env_id, rel_path);
        let dev_path = resolve_dev_store_path(
            &store.env_dir(env_id)?,
            std::env::var_os(DEV_SECRETS_PATH_ENV).map(PathBuf::from),
        );
        dev_store_put(&dev_path, &store_uri, value)?;
        Ok((
            store_uri,
            json!({"store_path": dev_path.display().to_string()}),
        ))
    } else if kind_path == crate::defaults::VAULT_SECRETS_PATH {
        // Same ref shape as the dev store; the difference is the backend.
        validate_dev_store_secret_path(rel_path)?;
        let store_uri = dev_store_key(env_id, rel_path);
        let vault_addr = vault_seed_put(store, env, &store_uri, value)?;
        Ok((store_uri, json!({"vault_addr": vault_addr})))
    } else {
        Err(OpError::NotYetImplemented(
            "secrets backend dispatch beyond the dev-store and Vault lands in A9 \
             (env-pack registry)"
                .to_string(),
        ))
    }
}

/// Read the value at `rel_path` back from the env's configured secrets backend,
/// dispatching on `kind_path`. Returns `(value, store_uri, backend_extra)`;
/// `value` is `None` when the key is absent. Counterpart to [`put_env_secret`];
/// shared by `op secrets get` and `op updates status`.
pub(super) fn get_env_secret(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    kind_path: &str,
    rel_path: &str,
) -> Result<(Option<String>, String, Value), OpError> {
    if kind_path == DEV_STORE_KIND_PATH {
        validate_dev_store_secret_path(rel_path)?;
        let store_uri = dev_store_key(env_id, rel_path);
        let dev_path = resolve_dev_store_path(
            &store.env_dir(env_id)?,
            std::env::var_os(DEV_SECRETS_PATH_ENV).map(PathBuf::from),
        );
        // A missing store file means nothing was ever written for this env —
        // absence, not an error (mirrors `dev_store_has`'s existence guard).
        let value = if dev_path.exists() {
            dev_store_get_value(&dev_path, &store_uri)?
        } else {
            None
        };
        Ok((
            value,
            store_uri,
            json!({"store_path": dev_path.display().to_string()}),
        ))
    } else if kind_path == crate::defaults::VAULT_SECRETS_PATH {
        validate_dev_store_secret_path(rel_path)?;
        let store_uri = dev_store_key(env_id, rel_path);
        let (value, vault_addr) = vault_seed_get(store, env, &store_uri)?;
        Ok((value, store_uri, json!({"vault_addr": vault_addr})))
    } else {
        Err(OpError::NotYetImplemented(
            "secrets backend dispatch beyond the dev-store and Vault lands in A9 \
             (env-pack registry)"
                .to_string(),
        ))
    }
}

/// Build the `get` outcome body: identity fields + a `present` flag, plus the
/// decrypted value only when `reveal` is set (so a non-revealing `get` never
/// puts material into logs/audit). `extra` carries the backend-specific field
/// (`store_path` for dev-store, `vault_addr` for Vault).
fn get_result_json(
    env_id: &str,
    secret_ref: &str,
    store_uri: &str,
    secrets_kind: &str,
    extra: Value,
    value: Option<String>,
    reveal: bool,
) -> Value {
    let mut body = json!({
        "environment_id": env_id,
        "secret_ref": secret_ref,
        "store_uri": store_uri,
        "secrets_kind": secrets_kind,
        "present": value.is_some(),
    });
    if let Value::Object(extra_map) = extra
        && let Value::Object(map) = &mut body
    {
        map.extend(extra_map);
    }
    if reveal && let Some(v) = value {
        body["value"] = Value::String(v);
    }
    body
}

/// Seed a Vault-backed secret through the embedded [`SecretsCore`]: the value is
/// envelope-encrypted via `transit/encrypt` and written to the KV record the
/// worker reads back (a raw `vault kv put` would not produce that envelope, so
/// the runtime could not decrypt it).
///
/// The Vault *connection* is assembled from two sources. The env's Vault binding
/// supplies the non-secret mounts/prefix/transit, so the seeded path matches
/// exactly what the worker reads. The operator's ambient environment supplies the
/// admin credential (`VAULT_TOKEN`, which must hold `transit/encrypt` + KV write)
/// and a reachable `VAULT_ADDR` — seeding runs from the operator host, not the
/// pod, so it authenticates with a token rather than the pod's Kubernetes-role
/// identity. The provider exposes only an env-driven `build_backend()` and this
/// crate is `#![forbid(unsafe_code)]`, so the deployer cannot inject the binding's
/// mounts into the process env; it instead fails closed when the ambient env would
/// not resolve to the binding's values. Returns the Vault address used.
fn vault_seed_put(
    store: &LocalFsStore,
    env: &Environment,
    store_uri: &str,
    value: &str,
) -> Result<String, OpError> {
    use crate::env_packs::k8s::manifests::SecretsBackend;

    // A Vault-backed env is single-tenant at the runtime (greentic-start scopes
    // one SecretsCore to the env owner and fails closed otherwise), so seeding
    // requires an owner and writes under it.
    let tenant = env
        .host_config
        .tenant_org_id
        .clone()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            OpError::InvalidArgument(
                "a Vault-backed env must be tenant-owned before seeding; set the owner with \
                 `op env update <env> --tenant-org <tenant>`"
                    .to_string(),
            )
        })?;

    // Non-secret connection config (mounts/prefix/transit) from the env binding.
    let SecretsBackend::Vault(vault) = super::env::resolve_secrets_backend(store, env)? else {
        return Err(OpError::Conflict(
            "env secrets binding is not Vault-backed".to_string(),
        ));
    };

    // Admin credential + reachable address come from the operator's environment.
    // The address is intentionally NOT matched against the binding's `addr`: the
    // binding holds the in-cluster service DNS the worker pod dials, which the
    // operator host generally cannot reach — it seeds via a port-forward or
    // ingress. The seeded address is returned in the outcome for visibility, and
    // a wrong target surfaces loudly as a missing-secret read at runtime.
    if std::env::var("VAULT_TOKEN")
        .map(|t| t.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(OpError::InvalidArgument(
            "seeding a Vault-backed secret needs an admin `VAULT_TOKEN` (with `transit/encrypt` \
             and KV write) exported in the environment"
                .to_string(),
        ));
    }
    let addr = match std::env::var("VAULT_ADDR") {
        Ok(a) if !a.trim().is_empty() => a,
        _ => {
            return Err(OpError::InvalidArgument(
                "seeding a Vault-backed secret needs `VAULT_ADDR` exported (a Vault address \
                 reachable from here, e.g. a port-forward to the in-cluster Vault)"
                    .to_string(),
            ));
        }
    };

    // The seed must land where the worker reads: `build_backend()` takes the
    // mounts/prefix/transit/namespace from ambient env (or provider defaults), and
    // this crate cannot set them, so fail closed when the operator's ambient env
    // would not resolve to the binding's path-determining values.
    vault_seed_path_consistency(&vault, |var| {
        std::env::var(var).ok().and_then(|v| {
            let trimmed = v.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
    })?;

    // Construct the embedded core over the env-driven Vault backend and write the
    // value verbatim (the broker envelope-encrypts). The config is read from the
    // ambient env (the same fields `build_backend` used) and the write is driven
    // through the shared seed core so this verb and `env up`'s explicit-config
    // seed path cannot drift.
    let config = greentic_secrets_lib::vault::VaultBackendConfig::from_env().map_err(|e| {
        OpError::Conflict(format!("vault backend config from environment failed: {e}"))
    })?;
    vault_put_with_config(config, tenant.as_str(), store_uri, value)?;

    Ok(addr)
}

/// Read a Vault-backed secret back through the embedded [`SecretsCore`] — the
/// counterpart to [`vault_seed_put`]. Assembles the same connection (binding
/// mounts + ambient `VAULT_TOKEN`/`VAULT_ADDR`, with the same path-consistency
/// guard) and `get_text`s the store URI; the broker `transit/decrypt`s the
/// envelope. Returns `(Some(plaintext), addr)` when present, `(None, addr)`
/// when the key is absent. The admin `VAULT_TOKEN` must hold `transit/decrypt`
/// + KV read.
fn vault_seed_get(
    store: &LocalFsStore,
    env: &Environment,
    store_uri: &str,
) -> Result<(Option<String>, String), OpError> {
    use crate::env_packs::k8s::manifests::SecretsBackend;

    let tenant = env
        .host_config
        .tenant_org_id
        .clone()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            OpError::InvalidArgument(
                "a Vault-backed env must be tenant-owned before reading; set the owner with \
                 `op env update <env> --tenant-org <tenant>`"
                    .to_string(),
            )
        })?;

    let SecretsBackend::Vault(vault) = super::env::resolve_secrets_backend(store, env)? else {
        return Err(OpError::Conflict(
            "env secrets binding is not Vault-backed".to_string(),
        ));
    };

    if std::env::var("VAULT_TOKEN")
        .map(|t| t.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(OpError::InvalidArgument(
            "reading a Vault-backed secret needs an admin `VAULT_TOKEN` (with `transit/decrypt` \
             and KV read) exported in the environment"
                .to_string(),
        ));
    }
    let addr = match std::env::var("VAULT_ADDR") {
        Ok(a) if !a.trim().is_empty() => a,
        _ => {
            return Err(OpError::InvalidArgument(
                "reading a Vault-backed secret needs `VAULT_ADDR` exported (a Vault address \
                 reachable from here, e.g. a port-forward to the in-cluster Vault)"
                    .to_string(),
            ));
        }
    };

    vault_seed_path_consistency(&vault, |var| {
        std::env::var(var).ok().and_then(|v| {
            let trimmed = v.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
    })?;

    let config = greentic_secrets_lib::vault::VaultBackendConfig::from_env().map_err(|e| {
        OpError::Conflict(format!("vault backend config from environment failed: {e}"))
    })?;
    let value = vault_get_with_config(config, tenant.as_str(), store_uri)?;

    Ok((value, addr))
}

/// Default Vault HTTP timeout for the explicit-config seed path (matches the
/// provider's `VaultBackendConfig::from_env` default).
#[cfg(feature = "k8s-client")]
const VAULT_SEED_TIMEOUT_SECS: u64 = 15;

/// Build an explicit [`VaultBackendConfig`] from the env's Vault binding (the
/// path-determining mounts/prefix/transit/namespace the worker reads) plus an
/// explicitly-reachable `addr` and `auth`. This is the seam that lets `env up`
/// seed over a `kubectl port-forward` with a root token WITHOUT mutating process
/// env (the deployer is `#![forbid(unsafe_code)]`): the binding supplies the
/// path fields, so the seeded record lands exactly where the worker looks —
/// path consistency holds by construction, not by the ambient-env
/// [`vault_seed_path_consistency`] guard the CLI verbs need.
#[cfg(feature = "k8s-client")]
pub(crate) fn vault_backend_config_from_binding(
    vault: &crate::env_packs::k8s::manifests::VaultBackend,
    addr: String,
    auth: greentic_secrets_lib::vault::VaultAuth,
) -> greentic_secrets_lib::vault::VaultBackendConfig {
    greentic_secrets_lib::vault::VaultBackendConfig {
        addr,
        auth,
        namespace: vault.namespace.clone(),
        kv_mount: vault.kv_mount.clone(),
        kv_prefix: vault.kv_prefix.clone(),
        transit_mount: vault.transit_mount.clone(),
        transit_key: vault.transit_key.clone(),
        timeout: std::time::Duration::from_secs(VAULT_SEED_TIMEOUT_SECS),
        ca_bundle: None,
    }
}

/// Write `value` at `store_uri` through an embedded [`SecretsCore`] over the
/// given explicit Vault backend `config`, scoped to `tenant`. The broker
/// envelope-encrypts via `transit/encrypt` before the KV write, so the worker
/// can decrypt on read. Driven through the secrets runtime so the async backend
/// runs from a synchronous caller — which MUST NOT already be inside a tokio
/// runtime (the `env up` seed phase runs outside `run_k8s_async`). Shared by the
/// ambient-env `op secrets put` verb and the `env up` seed phase.
pub(crate) fn vault_put_with_config(
    config: greentic_secrets_lib::vault::VaultBackendConfig,
    tenant: &str,
    store_uri: &str,
    value: &str,
) -> Result<(), OpError> {
    use greentic_secrets_lib::core::{CoreBuilder, rt};
    rt::sync_await(async {
        let components = greentic_secrets_lib::vault::build_backend_with(config)
            .await
            .map_err(|e| OpError::Conflict(format!("vault backend init failed: {e}")))?;
        let core = CoreBuilder::default()
            .tenant(tenant)
            .backend(components.backend, components.key_provider)
            .build()
            .await
            .map_err(|e| OpError::Conflict(format!("vault secrets core build failed: {e}")))?;
        core.put_text(store_uri, value)
            .await
            .map_err(|e| OpError::Conflict(format!("vault put failed: {e}")))?;
        Ok::<(), OpError>(())
    })
}

/// Read `store_uri` back through an embedded [`SecretsCore`] over the given
/// explicit Vault backend `config` — the counterpart to
/// [`vault_put_with_config`]. `Some(plaintext)` when present, `None` when
/// absent. Same runtime constraint as the put.
pub(crate) fn vault_get_with_config(
    config: greentic_secrets_lib::vault::VaultBackendConfig,
    tenant: &str,
    store_uri: &str,
) -> Result<Option<String>, OpError> {
    use greentic_secrets_lib::core::{CoreBuilder, Error as CoreError, SecretsError, rt};
    rt::sync_await(async {
        let components = greentic_secrets_lib::vault::build_backend_with(config)
            .await
            .map_err(|e| OpError::Conflict(format!("vault backend init failed: {e}")))?;
        let core = CoreBuilder::default()
            .tenant(tenant)
            .backend(components.backend, components.key_provider)
            .build()
            .await
            .map_err(|e| OpError::Conflict(format!("vault secrets core build failed: {e}")))?;
        match core.get_text(store_uri).await {
            Ok(text) => Ok(Some(text)),
            Err(SecretsError::Core(CoreError::NotFound { .. })) => Ok(None),
            Err(e) => Err(OpError::Conflict(format!("vault get failed: {e}"))),
        }
    })
}

/// Fail closed when the operator's ambient Vault environment would not resolve
/// to the binding's path-determining values, so a seed cannot silently land
/// somewhere the worker will never read. `ambient(var)` returns the trimmed,
/// non-empty value of a `VAULT_*` variable, else `None`.
///
/// Each tuple is `(env var, the binding's value, the provider default applied
/// when the var is unset)`. The KV mount/prefix and transit mount/key choose the
/// record location and envelope; the Enterprise **namespace** prefixes *every*
/// path, so an absent binding namespace (default `""`) requires the ambient var
/// to be absent too — a stray `VAULT_NAMESPACE` would otherwise seed a different
/// namespace than the (namespace-less) worker reads. The k8s auth mount is
/// deliberately excluded: it governs login, not where the record lands, and is
/// unused here because seeding authenticates with a static `VAULT_TOKEN`.
fn vault_seed_path_consistency(
    vault: &crate::env_packs::k8s::manifests::VaultBackend,
    ambient: impl Fn(&str) -> Option<String>,
) -> Result<(), OpError> {
    use crate::env_packs::k8s::manifests::{
        VAULT_DEFAULT_KV_MOUNT, VAULT_DEFAULT_KV_PREFIX, VAULT_DEFAULT_TRANSIT_KEY,
        VAULT_DEFAULT_TRANSIT_MOUNT,
    };
    let checks = [
        (
            "VAULT_KV_MOUNT",
            vault.kv_mount.as_str(),
            VAULT_DEFAULT_KV_MOUNT,
        ),
        (
            "VAULT_KV_PREFIX",
            vault.kv_prefix.as_str(),
            VAULT_DEFAULT_KV_PREFIX,
        ),
        (
            "VAULT_TRANSIT_MOUNT",
            vault.transit_mount.as_str(),
            VAULT_DEFAULT_TRANSIT_MOUNT,
        ),
        (
            "VAULT_TRANSIT_KEY",
            vault.transit_key.as_str(),
            VAULT_DEFAULT_TRANSIT_KEY,
        ),
        (
            "VAULT_NAMESPACE",
            vault.namespace.as_deref().unwrap_or(""),
            "",
        ),
    ];
    for (var, binding_value, default) in checks {
        let ambient_value = ambient(var);
        let effective = ambient_value.as_deref().unwrap_or(default);
        if effective != binding_value {
            return Err(OpError::InvalidArgument(format!(
                "the env's Vault binding requires {var}=`{binding_value}` but the seed would use \
                 `{effective}`; export {var}=`{binding_value}` so the seeded record matches what \
                 the worker reads"
            )));
        }
    }
    Ok(())
}

/// Where the env's dev store lives, mirroring the runtime reader's chain
/// (greentic-start `dev_store_path`): explicit override env var, else the
/// first *existing* default candidate under the env dir, else the primary
/// default (created on first write).
pub(super) fn resolve_dev_store_path(env_dir: &Path, override_path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = override_path {
        return path;
    }
    let primary = env_dir.join(DEV_STORE_RELATIVE);
    if primary.exists() {
        return primary;
    }
    let fallback = env_dir.join(DEV_STORE_STATE_RELATIVE);
    if fallback.exists() {
        return fallback;
    }
    primary
}

/// Validate that `rel_path` (leading `/` already trimmed) is a writable
/// dev-store secret path: exactly `<tenant>/<team>/<pack>/<name>` with
/// store-canonical team and name segments.
///
/// The dev store's native key shape is the runtime's `secrets://` (plural)
/// URI: `secrets://<env>/<tenant>/<team>/<pack>/<name>`; the backend handler
/// converts the logical `secret://` ref 1:1. `DevStore::put` itself rejects
/// any other depth, so enforce the shape upfront with a teachable error
/// instead of surfacing the backend's "uri is missing category" — exactly
/// four non-empty segments.
///
/// Shared between `put` (pre-write) and `env apply`'s pre-mutation manifest
/// validation (PR-2) so the two surfaces cannot drift.
pub(super) fn validate_dev_store_secret_path(rel_path: &str) -> Result<(), OpError> {
    let shape_err = || {
        OpError::InvalidArgument(format!(
            "dev-store secret path must be `<tenant>/<team>/<pack>/<name>` \
             (e.g. `default/_/messaging-telegram/telegram_bot_token`); \
             got `{rel_path}`"
        ))
    };
    let segs: Vec<&str> = rel_path.split('/').collect();
    let [_tenant, team, _pack, name] = segs[..] else {
        return Err(shape_err());
    };
    if segs.iter().any(|s| s.is_empty()) {
        return Err(shape_err());
    }
    // The runtime reader canonicalizes the team segment before lookup
    // (greentic-start `secrets_manager::canonical_team` maps `default`/
    // empty — trimmed, case-insensitive — to `_`), so a literal
    // `default` team would be written under a key no lookup ever uses.
    // Same policy as the name segment: reject instead of silently
    // transforming.
    if !is_canonical_team(team) {
        return Err(OpError::InvalidArgument(format!(
            "team segment `{team}` is not store-canonical: the runtime \
             reads the default team as `_` — pass `_` (or a real team \
             name without surrounding whitespace)"
        )));
    }
    // Outside the `mcp`/`a2a` categories the runtime reader canonicalizes the
    // name segment before lookup (greentic-start
    // `secret_name::canonical_secret_name`), so a non-canonical name would be
    // written but never found. Reject instead of silently transforming —
    // producer and consumer must share one derivation, and we share it by
    // only accepting already-canonical input.
    //
    // The `mcp` and `a2a` categories are exempt, mirroring greentic-start's
    // reader (`src/secrets_client.rs`, `canonicalize_dev_store_secret_uri`):
    // admin keys an MCP server, and an external A2A agent, by a hyphenated
    // UUID, and the runtime reads each verbatim (`greentic_aw_runtime::
    // mcp_secrets`, and the A2A equivalent). Normalizing here would rewrite
    // the lookup to `…/mcp/ff308b9c_951a_…` (or `…/a2a/…`) and resolve
    // nothing — silently, because a missing MCP/A2A credential is reported
    // as an ordinary node/tool error.
    //
    // The TEAM segment above is deliberately NOT exempt: the runtime
    // canonicalizes the team either way, so a literal `default` is still a key
    // nothing reads.
    if !is_verbatim_category_rel_path(rel_path) && !is_canonical_secret_name(name) {
        return Err(OpError::InvalidArgument(format!(
            "secret name `{name}` is not store-canonical: use lowercase \
             a-z, 0-9 and single `_` separators (no leading/trailing `_`)"
        )));
    }
    reject_reserved_credential_rel_path(rel_path)?;
    Ok(())
}

/// Refuse to write RUNTIME material onto the deployer's reserved credential
/// namespace (see [`credentials::store_paths`](crate::credentials::store_paths)
/// for what is reserved and why).
///
/// Two distinct harms, hence a hard reject rather than a warning:
///
/// * **Silent loss.** Those paths are stripped from every runtime seed, so a
///   runtime secret written here would be stored and audited as present, then
///   never reach the workload.
/// * **Credential clobber.** A caller-supplied ref pointed at one of them would
///   overwrite the env's live bound deployer credential with unrelated material,
///   breaking every subsequent deployer verb.
pub(super) fn reject_reserved_credential_rel_path(rel_path: &str) -> Result<(), OpError> {
    if crate::credentials::store_paths::is_reserved_rel_path(rel_path) {
        return Err(OpError::InvalidArgument(format!(
            "`{rel_path}` is reserved for the deployer's own bound credential and \
             cannot hold runtime material: writing it would overwrite the env's \
             deployer credential, and it is stripped from every staged runtime seed \
             so a workload could never read it back — choose another path"
        )));
    }
    Ok(())
}

/// A segment is writable iff the runtime reader's canonicalization maps it to
/// itself — anything else is written under a key no lookup will ever use. Both
/// checks call the shared `greentic-secrets` definitions (`normalize_team` /
/// `canonical_secret_name`) — the same functions the runtime reader and the
/// deployer's resolver use — so the predicate can't drift from the
/// transformation it guards.
fn is_canonical_team(team: &str) -> bool {
    // `normalize_team` returns `None` for the team-less cases (`default`,
    // empty, whitespace, AND the `_` placeholder itself). The canonical
    // string form of a team-less segment is `TEAM_PLACEHOLDER` (`_`), so a
    // segment is store-canonical iff it equals its normalization rendered
    // back through that placeholder — this accepts `_` (and real team names)
    // while still rejecting `default`/empty.
    greentic_secrets_lib::normalize_team(Some(team))
        .as_deref()
        .unwrap_or(greentic_secrets_lib::TEAM_PLACEHOLDER)
        == team
}

fn is_canonical_secret_name(name: &str) -> bool {
    greentic_secrets_lib::canonical_secret_name(name) == name
}

/// Write one value into the dev store from this sync context.
///
/// `DevStore::put` is async; same constraint as
/// `runtime_secrets::block_on_async_resolution` — the caller may sit on a
/// current-thread runtime (where `block_in_place` panics) or no runtime at
/// all, so hop to a dedicated OS thread that owns its own current-thread
/// runtime.
///
/// The backend is load-snapshot-at-open / persist-full-snapshot-on-write
/// (its internal flock covers each step, NOT the open→put window), so two
/// concurrent writers silently lose the slower one's update. Serialize the
/// whole cycle with a blocking sidecar flock (`<store>.lock`) held from
/// before `DevStore::with_path` (the snapshot load) until after `put` (the
/// persist). The sidecar — not the store file itself — because the
/// backend's own flock on the store file would deadlock against ours.
/// This serializes `op secrets put` writers; other tools writing the same
/// store (`greentic-secrets apply`, the runtime's QA persist) don't take
/// this lock — closing that belongs in the backend (A9 follow-up).
///
/// Failures map to `OpError::Io` keyed on the store path — the dev store is
/// a local file, and adding a dedicated `OpError` variant would break
/// Map a deploy-spec [`SecretRef`] (`secret://`) to its runtime dev-store URI
/// (`secrets://`), delegating to the one authoritative converter in
/// `greentic-secrets` ([`SecretRef::to_store_uri`]) instead of a local
/// `replacen`. It additionally re-canonicalizes the team segment (`default` →
/// `_`), and errors when the ref is not a store-aligned 5-segment URI (a scheme
/// flip alone has no canonical store location for other shapes).
pub(super) fn secret_ref_to_store_uri(secret_ref: &SecretRef) -> Result<String, OpError> {
    secret_ref
        .to_store_uri()
        .map(|uri| uri.to_string())
        .map_err(|e| {
            OpError::InvalidArgument(format!(
                "secret ref `{}` is not a store-aligned URI: {e}",
                secret_ref.as_str()
            ))
        })
}

/// downstream exhaustive matches (greentic-operator's HTTP status mapping).
/// Error messages carry the backend's text only — never secret material.
///
/// Writes RUNTIME material, so it refuses the deployer's reserved credential
/// namespace. The check lives here — at the shared writer — rather than at each
/// caller, so a new write surface is protected by default instead of having to
/// remember; the webhook writer needing its own check was a bug found in review,
/// not a design. The credential sink uses
/// [`dev_store_put_credential`] to opt out.
pub(super) fn dev_store_put(path: &Path, uri: &str, value: &str) -> Result<(), OpError> {
    if let Some(rel) = crate::credentials::store_paths::split_store_uri(uri).map(|(_env, rel)| rel)
    {
        reject_reserved_credential_rel_path(&rel)?;
    }
    dev_store_put_credential(path, uri, value)
}

/// [`dev_store_put`] without the reserved-namespace check — the ONLY legitimate
/// writer of the deployer's own bound credential, driven by
/// [`put_credential_material`] from the credentials bootstrap/rotate sink.
/// Runtime material must never use this.
pub(super) fn dev_store_put_credential(path: &Path, uri: &str, value: &str) -> Result<(), OpError> {
    let io_err = |message: String| OpError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(message),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| OpError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let _write_lock = EnvFlock::acquire(&dev_store_lock_path(path))
        .map_err(|source| OpError::Store(source.into()))?;
    let store = DevStore::with_path(path.to_path_buf())
        .map_err(|e| io_err(format!("open dev store: {e}")))?;
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| io_err(format!("build runtime: {e}")))?
                    .block_on(store.put(uri, SecretFormat::Text, value.as_bytes()))
                    .map_err(|e| io_err(format!("dev store write: {e}")))
            })
            .join()
            .expect("dev-store write thread panicked")
    })
}

/// Persist a bound credential's material into the env dev store at the
/// location [`resolve_credentials_token`] reads it back from — the
/// secret-backend write the credentials-bootstrap runner drives through its
/// secret sink. Mirrors `op secrets put`'s dev-store write exactly so a
/// bound token resolves identically on later live verbs (reconcile /
/// apply-revision / requirements).
pub(super) fn put_credential_material(
    env_dir: &Path,
    secret_ref: &SecretRef,
    value: &str,
) -> Result<(), OpError> {
    let store_uri = secret_ref_to_store_uri(secret_ref)?;
    let dev_path = resolve_dev_store_path(
        env_dir,
        std::env::var_os(DEV_SECRETS_PATH_ENV).map(PathBuf::from),
    );
    dev_store_put_credential(&dev_path, &store_uri, value)
}

/// Whether the env's dev store already holds a non-empty value at `rel_path`
/// (`<tenant>/<team>/<pack>/<name>`). `env apply` uses this so a paste-sourced
/// secret (`from_env` absent) that is already stored is treated as satisfied —
/// no re-prompt, no missing input — making the store the source of truth for
/// pasted values across re-applies. A missing store file (fresh env) reads as
/// `false`.
pub(super) fn dev_store_has(
    env_dir: &Path,
    env_id: &EnvId,
    rel_path: &str,
) -> Result<bool, OpError> {
    let dev_path = resolve_dev_store_path(
        env_dir,
        std::env::var_os(DEV_SECRETS_PATH_ENV).map(PathBuf::from),
    );
    if !dev_path.exists() {
        return Ok(false);
    }
    // Same derivation as the write (`put_env_secret`), or `env apply` probes a
    // key nothing was stored at and re-prompts for a secret already held.
    let uri = dev_store_key(env_id, rel_path.trim_start_matches('/'));
    dev_store_contains(&dev_path, &uri)
}

/// Read one key from a dev store, reporting only presence. Delegates to
/// [`dev_store_get_value`] — a `get` error (missing key / unreadable) maps to
/// `false` (absence), so apply re-collects the value rather than aborting.
fn dev_store_contains(path: &Path, uri: &str) -> Result<bool, OpError> {
    Ok(dev_store_get_value(path, uri)?.is_some())
}

/// Read one key's value from a dev store, returning `None` when the key is
/// absent / empty / not valid UTF-8 (a missing secret is absence, not a hard
/// error — the only hard failure is being unable to open the store file). Same
/// dedicated-thread runtime hop as [`dev_store_put`] (the caller may sit on a
/// current-thread runtime where `block_in_place` panics).
fn dev_store_get_value(path: &Path, uri: &str) -> Result<Option<String>, OpError> {
    let io_err = |message: String| OpError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(message),
    };
    let store = DevStore::with_path(path.to_path_buf())
        .map_err(|e| io_err(format!("open dev store: {e}")))?;
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| io_err(format!("build runtime: {e}")))?;
                Ok(rt.block_on(async {
                    match store.get(uri).await {
                        Ok(bytes) if !bytes.is_empty() => String::from_utf8(bytes).ok(),
                        _ => None,
                    }
                }))
            })
            .join()
            .expect("dev-store read thread panicked")
    })
}

/// Resolve an environment's bound `credentials_ref` to the deployer's bearer
/// token for live cluster verbs (`op env reconcile` / `apply-revision` /
/// `credentials requirements`).
///
/// Mirrors `runtime_secrets::resolve_runtime_secrets` precedence so an operator
/// supplies the deployer's ServiceAccount token exactly the way every other
/// secret is supplied — environment variable first (keyed by the canonical
/// store key), then the env's dev store (the same file [`put`] writes):
///
/// - `Ok(None)` — no `credentials_ref` is bound. The caller connects with the
///   ambient kubeconfig / in-cluster identity (the pre-closure behaviour).
/// - `Ok(Some(token))` — the ref resolves to a non-empty value; the caller
///   binds it onto the kube config (overriding the ambient identity).
/// - `Err(Conflict)` — a ref IS bound but no material is found. Fail closed:
///   silently falling back to the ambient (often broader-privileged) identity
///   when an env explicitly declares a bound credential would be a
///   privilege-escalation surprise.
pub(crate) fn resolve_credentials_token(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
) -> Result<Option<String>, OpError> {
    let Some(secret_ref) = env.credentials_ref.as_ref() else {
        return Ok(None);
    };
    let store_uri = secret_ref_to_store_uri(secret_ref)?;
    let mut checked: Vec<String> = Vec::new();

    if let Some(env_key) = canonical_secret_store_key(&store_uri) {
        checked.push(format!("env {env_key}"));
        if let Ok(value) = std::env::var(&env_key)
            && !value.is_empty()
        {
            return Ok(Some(value));
        }
    }

    let dev_path = resolve_dev_store_path(
        &store.env_dir(env_id)?,
        std::env::var_os(DEV_SECRETS_PATH_ENV).map(PathBuf::from),
    );
    checked.push(dev_path.display().to_string());
    if dev_path.exists()
        && let Some(value) = dev_store_get_value(&dev_path, &store_uri)?
    {
        return Ok(Some(value));
    }

    Err(OpError::Conflict(format!(
        "environment `{}` declares credentials_ref `{}` but no secret material was \
         found (looked in: {}); supply it via `op secrets put` or the corresponding \
         environment variable before running live cluster verbs",
        env_id.as_str(),
        secret_ref.as_str(),
        checked.join(", "),
    )))
}

/// Sidecar lock path for a dev store file: the full path with `.lock`
/// appended (`.dev.secrets.env` → `.dev.secrets.env.lock`). Appending to the
/// whole path (not just the file name) keeps the directory component intact
/// without the extract-fallback-reassemble dance.
fn dev_store_lock_path(store_path: &Path) -> PathBuf {
    let mut lock = store_path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
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

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

/// The env-must-have-secrets-pack precondition every secrets verb enforces.
/// Shared with `env apply`'s validation (PR-2).
pub(super) fn require_secrets_pack<'a>(
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
        "properties": {
            "environment_id": {"type": "string"},
            "prefix": {"type": ["string", "null"], "description": "Optional <tenant>/<team>/<pack>/[<name-prefix>]. When set, the outcome also lists `stored_keys` — the dev store's live key names under it (never values). Dev-store backend only."}
        }
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
            "path": {"type": "string", "description": "Relative path under secret://<env>/. For the dev-store backend: <tenant>/<team>/<pack>/<name> (e.g. default/_/messaging-telegram/telegram_bot_token). Use `_` for the default team — a literal `default` team is rejected (the runtime reads the default team as `_`)."},
            "value": {"type": "string"},
            "idempotency_key": {"type": ["string", "null"], "description": "Caller-supplied idempotency key; minted per invocation when absent."}
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
            "path": {"type": "string"},
            "reveal": {"type": "boolean", "default": false, "description": "Include the decrypted value in the outcome. Default false — presence + metadata only."}
        }
    })
}

fn delete_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SecretsDeletePayload",
        "type": "object",
        "required": ["environment_id"],
        "oneOf": [{"required": ["path"]}, {"required": ["prefix"]}],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "path": {"type": "string", "description": "One key, <tenant>/<team>/<pack>/<name> — validated exactly like `put`. Deleting a missing key succeeds with `deleted: false`."},
            "prefix": {"type": "string", "description": "Every live key under <tenant>/<team>/<pack>/[<name-prefix>], removed in one atomic rewrite. Refused when it covers the deployer's own bound credential."},
            "idempotency_key": {"type": ["string", "null"], "description": "Caller-supplied idempotency key; minted per invocation when absent."}
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
        env_with_secrets_kind("greentic.secrets.dev-store@1.0.0")
    }

    /// A store-aligned credentials ref (`secret://<env>/<tenant>/<team>/<pack>/<name>`)
    /// and its `secrets://` store URI — the deployer's bound ServiceAccount token.
    const CREDS_REF: &str = "secret://local/default/_/k8s-deployer/sa_token";
    const CREDS_STORE_URI: &str = "secrets://local/default/_/k8s-deployer/sa_token";

    fn env_with_credentials_ref(ref_str: &str) -> greentic_deploy_spec::Environment {
        let mut env = make_env("local");
        env.credentials_ref = Some(SecretRef::try_new(ref_str).expect("well-formed ref"));
        env
    }

    #[test]
    fn resolve_credentials_token_none_when_no_ref() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        assert_eq!(
            resolve_credentials_token(&store, &env, &env_id).unwrap(),
            None
        );
    }

    #[test]
    fn resolve_credentials_token_reads_from_env_dev_store() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = env_with_credentials_ref(CREDS_REF);
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // Seed the token where `op secrets put` would write it, then resolve it.
        let dev_path = resolve_dev_store_path(&store.env_dir(&env_id).unwrap(), None);
        dev_store_put(&dev_path, CREDS_STORE_URI, "sa-bearer-xyz").unwrap();
        assert_eq!(
            resolve_credentials_token(&store, &env, &env_id).unwrap(),
            Some("sa-bearer-xyz".to_string())
        );
    }

    #[test]
    fn resolve_credentials_token_fails_closed_when_ref_present_but_unresolved() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = env_with_credentials_ref(CREDS_REF);
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // No material seeded anywhere → fail closed rather than silently
        // falling back to ambient identity.
        let err = resolve_credentials_token(&store, &env, &env_id).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn resolve_credentials_token_accepts_the_bootstrap_advertised_ref_shape() {
        // The K8s bootstrap README tells operators to bind
        // `secret://<env>/<DEPLOYER_TOKEN_STORE_PATH>`. That exact shape must be
        // store-aligned so the resolver can read it — regression for a ref that
        // `SecretRef::to_store_uri` would reject (e.g. the old `…/k8s/deployer-token`).
        use crate::env_packs::k8s::bootstrap::DEPLOYER_TOKEN_STORE_PATH;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let ref_str = format!("secret://local/{DEPLOYER_TOKEN_STORE_PATH}");
        let secret_ref = SecretRef::try_new(&ref_str).expect("documented ref must be well-formed");
        let env = env_with_credentials_ref(&ref_str);
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // Seed at the store URI the documented ref maps to (this conversion is
        // exactly what the resolver does — and what the old shape failed).
        let store_uri =
            secret_ref_to_store_uri(&secret_ref).expect("documented ref is store-aligned");
        let dev_path = resolve_dev_store_path(&store.env_dir(&env_id).unwrap(), None);
        // The credential sink's writer: this path is the deployer's own reserved
        // namespace, which the runtime writer (`dev_store_put`) refuses.
        dev_store_put_credential(&dev_path, &store_uri, "sa-bearer-doc").unwrap();
        assert_eq!(
            resolve_credentials_token(&store, &env, &env_id).unwrap(),
            Some("sa-bearer-doc".to_string())
        );
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
                prefix: None,
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
                prefix: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    fn env_with_secrets_kind(kind: &str) -> greentic_deploy_spec::Environment {
        let mut env = make_env("local");
        env.packs.push(make_binding(CapabilitySlot::Secrets, kind));
        env
    }

    fn read_back(store_path: &str, uri: &str) -> Vec<u8> {
        crate::cli::tests_common::dev_store_read(Path::new(store_path), uri)
    }

    #[test]
    fn put_vault_requires_tenant_owned_env() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // A Vault-bound env with no tenant owner: seeding must fail closed
        // before any Vault I/O, because the runtime scopes a Vault SecretsCore
        // to the env owner (greentic-start #305).
        store
            .save(&env_with_secrets_kind("greentic.secrets.vault@0.1.0"))
            .unwrap();
        let err = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: "tenant-default/_/messaging-telegram/telegram_bot_token".to_string(),
                value: "tok-dummy-123".to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        match err {
            OpError::InvalidArgument(m) => assert!(m.contains("tenant-owned"), "msg: {m}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    fn vault_backend_fixture(
        namespace: Option<&str>,
    ) -> crate::env_packs::k8s::manifests::VaultBackend {
        use crate::env_packs::k8s::manifests::{
            VAULT_DEFAULT_AUTH_MOUNT, VAULT_DEFAULT_KV_MOUNT, VAULT_DEFAULT_KV_PREFIX,
            VAULT_DEFAULT_TRANSIT_KEY, VAULT_DEFAULT_TRANSIT_MOUNT, VaultBackend,
        };
        VaultBackend {
            addr: "http://vault.example:8200".to_string(),
            k8s_role: "gtc-worker".to_string(),
            kv_mount: VAULT_DEFAULT_KV_MOUNT.to_string(),
            kv_prefix: VAULT_DEFAULT_KV_PREFIX.to_string(),
            auth_mount: VAULT_DEFAULT_AUTH_MOUNT.to_string(),
            transit_mount: VAULT_DEFAULT_TRANSIT_MOUNT.to_string(),
            transit_key: VAULT_DEFAULT_TRANSIT_KEY.to_string(),
            namespace: namespace.map(str::to_string),
        }
    }

    #[test]
    fn vault_seed_path_consistency_accepts_defaults_with_no_ambient() {
        // All-default binding + nothing exported ⇒ effective values == defaults.
        let vault = vault_backend_fixture(None);
        assert!(vault_seed_path_consistency(&vault, |_| None).is_ok());
    }

    #[test]
    fn vault_seed_path_consistency_rejects_kv_prefix_mismatch() {
        let mut vault = vault_backend_fixture(None);
        vault.kv_prefix = "tenant-a".to_string();
        // Ambient unset ⇒ effective prefix = default `greentic` != `tenant-a`.
        let err = vault_seed_path_consistency(&vault, |_| None).unwrap_err();
        match err {
            OpError::InvalidArgument(m) => assert!(m.contains("VAULT_KV_PREFIX"), "msg: {m}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn vault_seed_path_consistency_requires_ambient_namespace_when_binding_sets_one() {
        let vault = vault_backend_fixture(Some("team-a"));
        // Binding namespace `team-a`, ambient unset ⇒ effective `` != `team-a`.
        let err = vault_seed_path_consistency(&vault, |_| None).unwrap_err();
        match err {
            OpError::InvalidArgument(m) => assert!(m.contains("VAULT_NAMESPACE"), "msg: {m}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn vault_seed_path_consistency_rejects_stray_namespace_when_binding_has_none() {
        let vault = vault_backend_fixture(None);
        // Binding has no namespace, but the operator's env sets one ⇒ the seed
        // would land in `team-b` while the (namespace-less) worker reads root.
        let err = vault_seed_path_consistency(&vault, |var| {
            (var == "VAULT_NAMESPACE").then(|| "team-b".to_string())
        })
        .unwrap_err();
        match err {
            OpError::InvalidArgument(m) => assert!(m.contains("VAULT_NAMESPACE"), "msg: {m}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn vault_seed_path_consistency_accepts_matching_namespace() {
        let vault = vault_backend_fixture(Some("team-a"));
        let result = vault_seed_path_consistency(&vault, |var| {
            (var == "VAULT_NAMESPACE").then(|| "team-a".to_string())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn put_non_dev_store_backend_returns_not_yet_implemented() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store
            .save(&env_with_secrets_kind("greentic.secrets.aws-sm@1.0.0"))
            .unwrap();
        let err = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: "credentials/aws".to_string(),
                value: "secret-material".to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");
    }

    #[test]
    fn put_writes_through_to_env_dev_store() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let outcome = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: "default/_/messaging-telegram/telegram_bot_token".to_string(),
                value: "tok-dummy-123".to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let result = &outcome.result;
        assert_eq!(
            result.get("store_uri").and_then(|v| v.as_str()),
            Some("secrets://local/default/_/messaging-telegram/telegram_bot_token")
        );
        assert_eq!(result.get("written").and_then(|v| v.as_bool()), Some(true));
        // The outcome must never echo the value.
        let envelope = serde_json::to_string(&outcome).unwrap();
        assert!(!envelope.contains("tok-dummy-123"));
        let store_path = result
            .get("store_path")
            .and_then(|v| v.as_str())
            .expect("store_path in outcome");
        let bytes = read_back(
            store_path,
            "secrets://local/default/_/messaging-telegram/telegram_bot_token",
        );
        assert_eq!(bytes, b"tok-dummy-123".to_vec());
    }

    #[test]
    fn put_rejects_default_team_segment() {
        // The runtime reads the default team as `_`; a literal `default`
        // segment would be written but never looked up.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        for team in ["default", "Default", "DEFAULT"] {
            let err = put(
                &store,
                &OpFlags::default(),
                Some(SecretsPutPayload {
                    environment_id: "local".to_string(),
                    path: format!("acme/{team}/messaging-telegram/telegram_bot_token"),
                    value: "tok-dummy".to_string(),
                    idempotency_key: None,
                }),
            )
            .unwrap_err();
            assert!(
                matches!(&err, OpError::InvalidArgument(msg) if msg.contains('_')),
                "team `{team}` got {err:?}"
            );
        }
    }

    #[test]
    fn canonical_team_accepts_placeholder_and_real_teams() {
        // The `_` placeholder IS the canonical team-less segment. Routing the
        // validator through the lib's `normalize_team` (which returns `None`
        // for `_`) must not make the documented `default/_/...` path
        // unwritable — regression for the secrets-lib consolidation.
        assert!(
            is_canonical_team("_"),
            "`_` is the canonical team-less segment"
        );
        assert!(is_canonical_team("legal"), "a real team name is canonical");
        assert!(!is_canonical_team("default"));
        assert!(!is_canonical_team("Default"));
        assert!(!is_canonical_team(""));
        assert!(!is_canonical_team(" _ "));
    }

    #[test]
    fn concurrent_puts_do_not_lose_writes() {
        // The dev backend is load-snapshot / persist-full-snapshot; without
        // the sidecar flock spanning open→put, concurrent writers lose
        // updates silently (each persists a snapshot missing the other's
        // key). With the lock, every key must survive.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let names: Vec<String> = (0..8).map(|i| format!("concurrent_key_{i}")).collect();
        let store = &store;
        std::thread::scope(|scope| {
            for name in &names {
                scope.spawn(move || {
                    let outcome = put(
                        store,
                        &OpFlags::default(),
                        Some(SecretsPutPayload {
                            environment_id: "local".to_string(),
                            path: format!("default/_/demo-pack/{name}"),
                            value: format!("value-{name}"),
                            idempotency_key: None,
                        }),
                    )
                    .unwrap();
                    assert_eq!(
                        outcome.result.get("written").and_then(|v| v.as_bool()),
                        Some(true)
                    );
                });
            }
        });
        let store_path = dir
            .path()
            .join("local")
            .join(DEV_STORE_RELATIVE)
            .display()
            .to_string();
        for name in &names {
            let bytes = read_back(
                &store_path,
                &format!("secrets://local/default/_/demo-pack/{name}"),
            );
            assert_eq!(bytes, format!("value-{name}").into_bytes());
        }
    }

    #[test]
    fn dev_store_lock_path_is_sidecar() {
        assert_eq!(
            dev_store_lock_path(Path::new("/x/.greentic/dev/.dev.secrets.env")),
            Path::new("/x/.greentic/dev/.dev.secrets.env.lock")
        );
        assert_eq!(
            dev_store_lock_path(Path::new("state/dev-store.dat")),
            Path::new("state/dev-store.dat.lock")
        );
    }

    #[test]
    fn put_rejects_non_canonical_name_segment() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let err = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: "default/_/messaging-telegram/TELEGRAM-BOT-TOKEN".to_string(),
                value: "tok-dummy".to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    /// The deployer's credential namespace is reserved: the runtime-seed
    /// denylist strips those paths unconditionally, so runtime material written
    /// there would be stored and audited as present, then silently vanish from
    /// the workload. Reject at the write surface so the collision cannot exist.
    #[test]
    fn put_rejects_the_reserved_deployer_credential_paths() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        for path in crate::credentials::store_paths::BOUND_CREDENTIAL_STORE_PATHS {
            let err = put(
                &store,
                &OpFlags::default(),
                Some(SecretsPutPayload {
                    environment_id: "local".to_string(),
                    path: (*path).to_string(),
                    value: "v".to_string(),
                    idempotency_key: None,
                }),
            )
            .unwrap_err();
            assert!(
                matches!(&err, OpError::InvalidArgument(msg) if msg.contains("reserved")),
                "runtime material must not be writable at the reserved deployer \
                 credential path `{path}`; got {err:?}"
            );
        }
    }

    /// The reservation lives in the validator shared by `op secrets put`, `op
    /// updates enroll` and `env apply`'s manifest validation, so no write
    /// surface can drift from it. The credentials bootstrap's own sink writes
    /// through `dev_store_put` and is deliberately unaffected.
    #[test]
    fn the_shared_validator_reserves_deployer_credential_paths() {
        for path in crate::credentials::store_paths::BOUND_CREDENTIAL_STORE_PATHS {
            let err = validate_dev_store_secret_path(path).unwrap_err();
            assert!(
                matches!(&err, OpError::InvalidArgument(msg) if msg.contains("reserved")),
                "`{path}` must be reserved in the shared validator; got {err:?}"
            );
        }
        // A neighbouring path in the same category is still writable — the
        // reservation is exact, not a prefix ban.
        validate_dev_store_secret_path("default/_/k8s-deployer/some_runtime_value")
            .expect("only the exact reserved paths are refused");
    }

    /// A store URI's last segment may carry an `@version`, and the dev-store's
    /// exclusion filter matches by versionless identity — so a version-qualified
    /// ref names the SAME key. Comparing raw strings would let
    /// `…/deployer_token@1` through: accepted, written over the live credential's
    /// key, then stripped from the seed anyway.
    #[test]
    fn the_reservation_matches_version_qualified_refs() {
        for path in crate::credentials::store_paths::BOUND_CREDENTIAL_STORE_PATHS {
            for qualified in [format!("{path}@1"), format!("{path}@v2")] {
                assert!(
                    crate::credentials::store_paths::is_reserved_rel_path(&qualified),
                    "`{qualified}` names the same key as the reserved `{path}` and \
                     must be refused"
                );
                let err = reject_reserved_credential_rel_path(&qualified).unwrap_err();
                assert!(matches!(&err, OpError::InvalidArgument(msg) if msg.contains("reserved")));
            }
        }
        // Version stripping must not over-match: a different name is writable.
        assert!(!crate::credentials::store_paths::is_reserved_rel_path(
            "default/_/k8s-deployer/other@1"
        ));
    }

    #[test]
    fn put_rejects_wrong_depth_path() {
        // `DevStore::put` only accepts the 5-segment `secrets://` shape; the
        // verb rejects other depths upfront with a teachable message.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        for path in ["credentials/aws", "default/_/pack/extra/name", "a//b/c"] {
            let err = put(
                &store,
                &OpFlags::default(),
                Some(SecretsPutPayload {
                    environment_id: "local".to_string(),
                    path: path.to_string(),
                    value: "v".to_string(),
                    idempotency_key: None,
                }),
            )
            .unwrap_err();
            assert!(
                matches!(&err, OpError::InvalidArgument(msg) if msg.contains("<tenant>/<team>/<pack>/<name>")),
                "path `{path}` got {err:?}"
            );
        }
    }

    #[test]
    fn resolve_dev_store_path_override_wins() {
        let dir = tempdir().unwrap();
        let override_path = dir.path().join("custom.dat");
        assert_eq!(
            resolve_dev_store_path(dir.path(), Some(override_path.clone())),
            override_path
        );
    }

    #[test]
    fn resolve_dev_store_path_prefers_existing_candidate() {
        let dir = tempdir().unwrap();
        let fallback = dir.path().join(DEV_STORE_STATE_RELATIVE);
        std::fs::create_dir_all(fallback.parent().unwrap()).unwrap();
        std::fs::write(&fallback, b"").unwrap();
        assert_eq!(resolve_dev_store_path(dir.path(), None), fallback);
        // Once the primary exists it wins over the state fallback.
        let primary = dir.path().join(DEV_STORE_RELATIVE);
        std::fs::create_dir_all(primary.parent().unwrap()).unwrap();
        std::fs::write(&primary, b"").unwrap();
        assert_eq!(resolve_dev_store_path(dir.path(), None), primary);
    }

    #[test]
    fn resolve_dev_store_path_defaults_to_primary() {
        let dir = tempdir().unwrap();
        assert_eq!(
            resolve_dev_store_path(dir.path(), None),
            dir.path().join(DEV_STORE_RELATIVE)
        );
    }

    #[test]
    fn canonical_name_fixed_points() {
        assert!(is_canonical_secret_name("telegram_bot_token"));
        assert!(is_canonical_secret_name("a1"));
        assert!(!is_canonical_secret_name(""));
        assert!(!is_canonical_secret_name("TELEGRAM_BOT_TOKEN"));
        assert!(!is_canonical_secret_name("bot-token"));
        assert!(!is_canonical_secret_name("_leading"));
        assert!(!is_canonical_secret_name("trailing_"));
        assert!(!is_canonical_secret_name("double__underscore"));
    }

    #[test]
    fn an_mcp_key_is_written_under_the_default_env_segment() {
        // greentic-start reads `secrets://default/<tenant>/<team>/mcp/<id>`
        // (`src/secrets_client.rs`, the MCP carve-out), and
        // `greentic_aw_runtime::mcp_secrets::MCP_ENV_SEGMENT` pins `default`
        // because that is what greentic-designer-admin writes. Keying an MCP
        // secret by the environment id instead stores it where no lookup ever
        // goes — silently, because an unresolved MCP credential surfaces only
        // as an ordinary node error.
        let env_id = EnvId::try_from("local").unwrap();
        assert_eq!(
            dev_store_key(&env_id, "acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3"),
            "secrets://default/acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3"
        );
    }

    #[test]
    fn an_llm_key_is_written_under_the_default_env_segment() {
        // greentic-runner reads an agent's LLM key at
        // `secrets://default/<tenant>/_/llm/<credential_ref>`, and greentic-start
        // canonicalizes that name before lookup (its carve-out is mcp/a2a
        // only), so the canonical name under `default` is the key it hits.
        let env_id = EnvId::try_from("local").unwrap();
        assert_eq!(
            dev_store_key(&env_id, "default/_/llm/ff308b9c_951a_40b8"),
            "secrets://default/default/_/llm/ff308b9c_951a_40b8"
        );
    }

    #[test]
    fn an_llm_name_must_still_be_canonical() {
        // Not a verbatim category: a hyphenated name would be stored where
        // the canonicalizing reader never looks, so it is refused.
        assert!(validate_dev_store_secret_path("default/_/llm/ff308b9c-951a").is_err());
        assert!(validate_dev_store_secret_path("default/_/llm/ff308b9c_951a").is_ok());
    }

    #[test]
    fn every_other_category_keeps_the_environment_id() {
        let env_id = EnvId::try_from("local").unwrap();
        assert_eq!(
            dev_store_key(&env_id, "acme/_/messaging-telegram/bot_token"),
            "secrets://local/acme/_/messaging-telegram/bot_token"
        );
    }

    #[test]
    fn the_category_is_the_third_segment_not_a_substring() {
        // `mcp` anywhere but the pack position is an ordinary key. A tenant
        // literally named `mcp` must not move every one of its secrets.
        let env_id = EnvId::try_from("local").unwrap();
        assert_eq!(
            dev_store_key(&env_id, "mcp/_/messaging-telegram/bot_token"),
            "secrets://local/mcp/_/messaging-telegram/bot_token"
        );
    }

    #[test]
    fn an_mcp_name_keeps_its_hyphenated_uuid() {
        // greentic-designer-admin keys an MCP server by its hyphenated UUID
        // and greentic-runner reads it verbatim. Canonicalizing turns the
        // lookup into `…/mcp/ff308b9c_951a_…`, which resolves nothing.
        validate_dev_store_secret_path("acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3")
            .expect("an mcp name must reach the store byte-for-byte");
    }

    #[test]
    fn a_non_mcp_name_is_still_rejected() {
        let err = validate_dev_store_secret_path("acme/_/messaging-telegram/BOT-TOKEN")
            .expect_err("non-mcp keys must still be normalized");
        assert!(format!("{err}").contains("store-canonical"), "{err}");
    }

    #[test]
    fn an_mcp_path_still_rejects_a_literal_default_team() {
        // The carve-out covers the NAME and the env segment, never the team:
        // the runtime reads the default team as `_`, so a literal `default`
        // would be written under a key no lookup uses.
        let err =
            validate_dev_store_secret_path("acme/default/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3")
                .expect_err("the team segment keeps its rule");
        assert!(format!("{err}").contains("team segment"), "{err}");
    }

    #[test]
    fn an_mcp_path_still_needs_four_segments() {
        validate_dev_store_secret_path("acme/_/mcp")
            .expect_err("shape is checked before the category");
    }

    #[test]
    fn a_put_and_a_get_agree_on_an_mcp_key() {
        // The write and the read must derive the same key. They were two
        // independent `format!` calls; a carve-out applied to one of them
        // would store a credential that `op secrets get` then reports as
        // absent.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let path = "acme/sales/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3";
        let put_outcome = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: path.to_string(),
                value: "t0k".to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let get_outcome = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: path.to_string(),
                reveal: true,
            }),
        )
        .unwrap();

        let put_uri = put_outcome.result.get("store_uri").and_then(|v| v.as_str());
        assert_eq!(put_uri, Some(format!("secrets://default/{path}").as_str()));
        assert_eq!(
            put_uri,
            get_outcome.result.get("store_uri").and_then(|v| v.as_str())
        );
        assert_eq!(
            get_outcome.result.get("value").and_then(|v| v.as_str()),
            Some("t0k")
        );
    }

    #[test]
    fn an_a2a_key_is_written_under_the_default_env_segment() {
        // greentic-start reads `secrets://default/<tenant>/<team>/a2a/<id>`
        // (the same carve-out as MCP), and greentic-designer-admin writes it
        // verbatim. Keying an a2a secret by the environment id instead stores
        // it where no lookup ever goes.
        let env_id = EnvId::try_from("local").unwrap();
        assert_eq!(
            dev_store_key(&env_id, "acme/_/a2a/ff308b9c-951a-40b8-acea-f62cdd19c8f3"),
            "secrets://default/acme/_/a2a/ff308b9c-951a-40b8-acea-f62cdd19c8f3"
        );
    }

    #[test]
    fn the_a2a_category_is_the_third_segment_not_a_substring() {
        // `a2a` anywhere but the pack position is an ordinary key. A tenant
        // literally named `a2a` must not move every one of its secrets.
        let env_id = EnvId::try_from("local").unwrap();
        assert_eq!(
            dev_store_key(&env_id, "a2a/_/messaging-telegram/bot_token"),
            "secrets://local/a2a/_/messaging-telegram/bot_token"
        );
    }

    #[test]
    fn an_a2a_name_keeps_its_hyphenated_uuid() {
        // greentic-designer-admin keys an A2A agent by its hyphenated UUID
        // and greentic-runner reads it verbatim. Canonicalizing turns the
        // lookup into `…/a2a/ff308b9c_951a_…`, which resolves nothing.
        validate_dev_store_secret_path("acme/_/a2a/ff308b9c-951a-40b8-acea-f62cdd19c8f3")
            .expect("an a2a name must reach the store byte-for-byte");
    }

    #[test]
    fn an_a2a_path_still_rejects_a_literal_default_team() {
        // The carve-out covers the NAME and the env segment, never the team:
        // the runtime reads the default team as `_`, so a literal `default`
        // would be written under a key no lookup uses.
        let err =
            validate_dev_store_secret_path("acme/default/a2a/ff308b9c-951a-40b8-acea-f62cdd19c8f3")
                .expect_err("the team segment keeps its rule");
        assert!(format!("{err}").contains("team segment"), "{err}");
    }

    #[test]
    fn an_a2a_path_still_needs_four_segments() {
        validate_dev_store_secret_path("acme/_/a2a")
            .expect_err("shape is checked before the category");
    }

    #[test]
    fn a_put_and_a_get_agree_on_an_a2a_key() {
        // The write and the read must derive the same key. They were two
        // independent `format!` calls; a carve-out applied to one of them
        // would store a credential that `op secrets get` then reports as
        // absent.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let path = "acme/sales/a2a/ff308b9c-951a-40b8-acea-f62cdd19c8f3";
        let put_outcome = put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: path.to_string(),
                value: "t0k".to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let get_outcome = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: path.to_string(),
                reveal: true,
            }),
        )
        .unwrap();

        let put_uri = put_outcome.result.get("store_uri").and_then(|v| v.as_str());
        assert_eq!(put_uri, Some(format!("secrets://default/{path}").as_str()));
        assert_eq!(
            put_uri,
            get_outcome.result.get("store_uri").and_then(|v| v.as_str())
        );
        assert_eq!(
            get_outcome.result.get("value").and_then(|v| v.as_str()),
            Some("t0k")
        );
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
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn get_reads_back_put_value_from_dev_store() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let path = "default/_/messaging-telegram/telegram_bot_token";
        put(
            &store,
            &OpFlags::default(),
            Some(SecretsPutPayload {
                environment_id: "local".to_string(),
                path: path.to_string(),
                value: "tok-roundtrip-456".to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();

        // reveal=false → present, but the value never appears in the envelope.
        let outcome = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: path.to_string(),
                reveal: false,
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("present").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(outcome.result.get("value").is_none());
        let envelope = serde_json::to_string(&outcome).unwrap();
        assert!(!envelope.contains("tok-roundtrip-456"));

        // reveal=true → the decrypted value is included.
        let outcome = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: path.to_string(),
                reveal: true,
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("value").and_then(|v| v.as_str()),
            Some("tok-roundtrip-456")
        );
    }

    #[test]
    fn get_absent_key_returns_present_false() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&env_with_secrets()).unwrap();
        let outcome = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: "default/_/messaging-telegram/never_written".to_string(),
                reveal: true,
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("present").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert!(outcome.result.get("value").is_none());
    }

    #[test]
    fn get_vault_requires_tenant_owned_env() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // Mirror put: a Vault env with no tenant owner must fail closed before
        // any Vault I/O (the runtime scopes a Vault SecretsCore to the owner).
        store
            .save(&env_with_secrets_kind("greentic.secrets.vault@0.1.0"))
            .unwrap();
        let err = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: "tenant-default/_/messaging-telegram/telegram_bot_token".to_string(),
                reveal: false,
            }),
        )
        .unwrap_err();
        match err {
            OpError::InvalidArgument(m) => assert!(m.contains("tenant-owned"), "msg: {m}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn get_non_dev_store_backend_returns_not_yet_implemented() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store
            .save(&env_with_secrets_kind("greentic.secrets.aws-sm@1.0.0"))
            .unwrap();
        let err = get(
            &store,
            &OpFlags::default(),
            Some(SecretsGetPayload {
                environment_id: "local".to_string(),
                path: "default/_/pack/key_name".to_string(),
                reveal: false,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");
    }
}
