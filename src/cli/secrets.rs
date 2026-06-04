//! `gtc op secrets {list,put,get,rotate}` (`A3`).
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
//! — no actual material is fetched.

use std::path::{Path, PathBuf};

use chrono::Utc;
use greentic_deploy_spec::{CapabilitySlot, EnvId, EnvPackBinding, SecretRef};
use greentic_secrets_lib::{DevStore, SecretFormat, SecretsStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, AuditGens, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "secrets";

/// `PackDescriptor::path()` of the local dev-store secrets backend — the
/// default binding `op env init` creates and the only kind `put` dispatches
/// to in Phase A.
const DEV_STORE_KIND_PATH: &str = "greentic.secrets.dev-store";

/// Same override the runtime reader honors (`greentic-start
/// `dev_store_path::override_path`): when set, both writer and reader use
/// this path instead of the env-dir defaults below.
const DEV_SECRETS_PATH_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";

/// Dev-store candidates relative to the env dir. MUST mirror greentic-start's
/// `dev_store_path.rs` (`STORE_RELATIVE` / `STORE_STATE_RELATIVE`) — the
/// runtime's `SecretsClient::open(<env_dir>)` resolves the same chain, so a
/// put here is what a served revision reads back.
const DEV_STORE_RELATIVE: &str = ".greentic/dev/.dev.secrets.env";
const DEV_STORE_STATE_RELATIVE: &str = ".greentic/state/dev/.dev.secrets.env";

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
        if secrets.kind.path() != DEV_STORE_KIND_PATH {
            return Err(OpError::NotYetImplemented(
                "secrets backend dispatch beyond the dev-store lands in A9 (env-pack registry)",
            ));
        }
        // The dev store's native key shape is the runtime's `secrets://`
        // (plural) URI: `secrets://<env>/<tenant>/<team>/<pack>/<name>`.
        // The backend handler converts the logical `secret://` ref 1:1.
        // `DevStore::put` itself rejects any other depth, so enforce the
        // shape upfront with a teachable error instead of surfacing the
        // backend's "uri is missing category".
        let segments: Vec<&str> = rel_path.split('/').collect();
        if segments.len() != 4 || segments.iter().any(|s| s.is_empty()) {
            return Err(OpError::InvalidArgument(format!(
                "dev-store secret path must be `<tenant>/<team>/<pack>/<name>` \
                 (e.g. `default/_/messaging-telegram/telegram_bot_token`); \
                 got `{rel_path}`"
            )));
        }
        // The runtime reader canonicalizes the name segment before lookup
        // (greentic-start `secret_name::canonical_secret_name`), so a
        // non-canonical name would be written but never found. Reject
        // instead of silently transforming — producer and consumer must
        // share one derivation, and we share it by only accepting
        // already-canonical input.
        let name = segments[3];
        if !is_canonical_secret_name(name) {
            return Err(OpError::InvalidArgument(format!(
                "secret name `{name}` is not store-canonical: use lowercase \
                 a-z, 0-9 and single `_` separators (no leading/trailing `_`)"
            )));
        }
        let store_uri = format!("secrets://{}/{rel_path}", env_id.as_str());
        let dev_path = resolve_dev_store_path(
            &store.env_dir(&env_id)?,
            std::env::var_os(DEV_SECRETS_PATH_ENV).map(PathBuf::from),
        );
        dev_store_put(&dev_path, &store_uri, &payload.value)?;
        Ok((
            OpOutcome::new(
                NOUN,
                "put",
                json!({
                    "environment_id": env_id.as_str(),
                    "secret_ref": secret_uri,
                    "store_uri": store_uri,
                    "secrets_kind": secrets.kind.to_string(),
                    "store_path": dev_path.display().to_string(),
                    "written": true,
                }),
            ),
            AuditGens::NONE,
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

/// Where the env's dev store lives, mirroring the runtime reader's chain
/// (greentic-start `dev_store_path`): explicit override env var, else the
/// first *existing* default candidate under the env dir, else the primary
/// default (created on first write).
fn resolve_dev_store_path(env_dir: &Path, override_path: Option<PathBuf>) -> PathBuf {
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

/// Fixed-point check against greentic-start's `canonical_secret_name`: a
/// name passes iff canonicalizing it would be a no-op, which is exactly when
/// a put key matches what the runtime reader looks up.
fn is_canonical_secret_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('_')
        && !name.ends_with('_')
        && !name.contains("__")
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Write one value into the dev store from this sync context.
///
/// `DevStore::put` is async; same constraint as
/// `runtime_secrets::block_on_async_resolution` — the caller may sit on a
/// current-thread runtime (where `block_in_place` panics) or no runtime at
/// all, so hop to a dedicated OS thread that owns its own current-thread
/// runtime.
///
/// Failures map to `OpError::Io` keyed on the store path — the dev store is
/// a local file, and adding a dedicated `OpError` variant would break
/// downstream exhaustive matches (greentic-operator's HTTP status mapping).
/// Error messages carry the backend's text only — never secret material.
fn dev_store_put(path: &Path, uri: &str, value: &str) -> Result<(), OpError> {
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
            "path": {"type": "string", "description": "Relative path under secret://<env>/. For the dev-store backend: <tenant>/<team>/<pack>/<name> (e.g. default/_/messaging-telegram/telegram_bot_token)."},
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
        env_with_secrets_kind("greentic.secrets.dev-store@1.0.0")
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

    fn env_with_secrets_kind(kind: &str) -> greentic_deploy_spec::Environment {
        let mut env = make_env("local");
        env.packs.push(make_binding(CapabilitySlot::Secrets, kind));
        env
    }

    fn read_back(store_path: &str, uri: &str) -> Vec<u8> {
        let dev = DevStore::with_path(PathBuf::from(store_path)).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { dev.get(uri).await.unwrap() })
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
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
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
