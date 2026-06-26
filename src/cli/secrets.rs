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
use greentic_deploy_spec::{CapabilitySlot, EnvId, EnvPackBinding, Environment, SecretRef};
use greentic_secrets_lib::{DevStore, SecretFormat, SecretsStore, canonical_secret_store_key};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvFlock, EnvironmentStore, LocalFsStore};

use super::{
    AuditCtx, AuditGens, OpError, OpFlags, OpOutcome, audit_and_record, resolve_idempotency_key,
};

const NOUN: &str = "secrets";

/// `PackDescriptor::path()` of the local dev-store secrets backend — the
/// default binding `op env init` creates and the only kind `put` dispatches
/// to in Phase A. Shared with `env apply` (PR-2), which pre-checks the bound
/// backend at validation time so a non-dev-store env fails before any
/// mutation instead of mid-run.
pub(super) const DEV_STORE_KIND_PATH: &str = "greentic.secrets.dev-store";

/// Same override the runtime reader honors (`greentic-start
/// `dev_store_path::override_path`): when set, both writer and reader use
/// this path instead of the env-dir defaults below.
pub(super) const DEV_SECRETS_PATH_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";

/// Dev-store candidates relative to the env dir. MUST mirror greentic-start's
/// `dev_store_path.rs` (`STORE_RELATIVE` / `STORE_STATE_RELATIVE`) — the
/// runtime's `SecretsClient::open(<env_dir>)` resolves the same chain, so a
/// put here is what a served revision reads back.
pub(super) const DEV_STORE_RELATIVE: &str = ".greentic/dev/.dev.secrets.env";
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
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
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
        if kind_path == DEV_STORE_KIND_PATH {
            validate_dev_store_secret_path(rel_path)?;
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
        } else if kind_path == crate::defaults::VAULT_SECRETS_PATH {
            // Same ref shape as the dev store; the difference is the backend.
            validate_dev_store_secret_path(rel_path)?;
            let store_uri = format!("secrets://{}/{rel_path}", env_id.as_str());
            let vault_addr = vault_seed_put(store, &env, &store_uri, &payload.value)?;
            Ok((
                OpOutcome::new(
                    NOUN,
                    "put",
                    json!({
                        "environment_id": env_id.as_str(),
                        "secret_ref": secret_uri,
                        "store_uri": store_uri,
                        "secrets_kind": secrets.kind.to_string(),
                        "vault_addr": vault_addr,
                        "written": true,
                    }),
                ),
                AuditGens::NONE,
            ))
        } else {
            Err(OpError::NotYetImplemented(
                "secrets backend dispatch beyond the dev-store and Vault lands in A9 \
                 (env-pack registry)"
                    .to_string(),
            ))
        }
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
        "secrets backend dispatch lands in A9 (env-pack registry); A3 wires the surface only"
            .to_string(),
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

// --- internals -----------------------------------------------------------

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
    use greentic_secrets_lib::core::{CoreBuilder, rt};

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
    // value verbatim (the broker envelope-encrypts). Driven through the secrets
    // runtime so the async backend runs from this synchronous verb.
    rt::sync_await(async {
        let components = greentic_secrets_lib::vault::build_backend()
            .await
            .map_err(|e| OpError::Conflict(format!("vault backend init failed: {e}")))?;
        let core = CoreBuilder::default()
            .tenant(tenant.as_str())
            .backend(components.backend, components.key_provider)
            .build()
            .await
            .map_err(|e| OpError::Conflict(format!("vault secrets core build failed: {e}")))?;
        core.put_text(store_uri, value)
            .await
            .map_err(|e| OpError::Conflict(format!("vault put failed: {e}")))?;
        Ok::<(), OpError>(())
    })?;

    Ok(addr)
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
    // The runtime reader canonicalizes the name segment before lookup
    // (greentic-start `secret_name::canonical_secret_name`), so a
    // non-canonical name would be written but never found. Reject
    // instead of silently transforming — producer and consumer must
    // share one derivation, and we share it by only accepting
    // already-canonical input.
    if !is_canonical_secret_name(name) {
        return Err(OpError::InvalidArgument(format!(
            "secret name `{name}` is not store-canonical: use lowercase \
             a-z, 0-9 and single `_` separators (no leading/trailing `_`)"
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
pub(super) fn dev_store_put(path: &Path, uri: &str, value: &str) -> Result<(), OpError> {
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
    dev_store_put(&dev_path, &store_uri, value)
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
    let uri = format!(
        "secrets://{}/{}",
        env_id.as_str(),
        rel_path.trim_start_matches('/')
    );
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
        dev_store_put(&dev_path, &store_uri, "sa-bearer-doc").unwrap();
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
