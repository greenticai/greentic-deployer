//! Key enumeration and hard deletion for the env dev store — the internals of
//! `op secrets list --prefix` and `op secrets delete`.
//!
//! **Why deletion is a rewrite, not the backend's `delete`.** The dev backend's
//! `SecretsBackend::delete` only appends a tombstone: the key and the previous
//! value's ciphertext stay in the store file. The env-packs ship that WHOLE file
//! into every workload of the environment, and one store is shared by several
//! deployments — so a tombstoned credential would still travel, encrypted, into
//! containers that must not hold it. Deletion therefore goes through
//! [`DevStore::copy_excluding`] (the same primitive `env up` uses to strip the
//! deployer credential from a staged seed), which drops the key before anything
//! is written, and the sanitized copy is renamed over the store atomically.
//!
//! **Why enumeration uses `DevBackend` directly.** `DevStore` exposes put/get
//! and no listing. `DevBackend::list` returns metadata only — it never decrypts
//! a value — which is exactly the contract `list` needs: names, never material.

use std::path::{Path, PathBuf};

use greentic_deploy_spec::EnvId;
use greentic_secrets_lib::DevStore;
use greentic_secrets_lib::spec::{SecretUri, SecretsBackend};
use secrets_provider_dev::DevBackend;
use serde::Serialize;

use super::{OpError, dev_store_key, dev_store_lock_path, is_canonical_team};
use crate::environment::EnvFlock;

/// A parsed `<tenant>/<team>/<pack>/[<name-prefix>]` enumeration prefix.
///
/// The dev backend lists by exact scope (env + tenant + team), so the first
/// three segments are mandatory; only the NAME may be a partial prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::cli) struct DevStorePrefix {
    tenant: String,
    team: String,
    category: String,
    name_prefix: String,
}

impl DevStorePrefix {
    /// Parse and validate `raw` (a leading `/` is ignored). Accepts
    /// `t/team/pack`, `t/team/pack/` and `t/team/pack/<name-prefix>`.
    pub(in crate::cli) fn parse(raw: &str) -> Result<Self, OpError> {
        let rel = raw.trim_start_matches('/');
        let shape_err = || {
            OpError::InvalidArgument(format!(
                "secret prefix must be `<tenant>/<team>/<pack>/[<name-prefix>]` \
                 (e.g. `acme/_/mcp/` or `acme/_/a2a/agent.unit-`); got `{raw}`"
            ))
        };
        let segs: Vec<&str> = rel.split('/').collect();
        let (tenant, team, category, name_prefix) = match segs[..] {
            [tenant, team, category] => (tenant, team, category, ""),
            [tenant, team, category, name_prefix] => (tenant, team, category, name_prefix),
            _ => return Err(shape_err()),
        };
        if tenant.is_empty() || team.is_empty() || category.is_empty() {
            return Err(shape_err());
        }
        // Same rule as a full path: the runtime reads the default team as `_`,
        // so a literal `default` would enumerate a scope nothing writes to.
        if !is_canonical_team(team) {
            return Err(OpError::InvalidArgument(format!(
                "team segment `{team}` is not store-canonical: the runtime reads \
                 the default team as `_` — pass `_` (or a real team name)"
            )));
        }
        Ok(Self {
            tenant: tenant.to_string(),
            team: team.to_string(),
            category: category.to_string(),
            name_prefix: name_prefix.to_string(),
        })
    }

    /// The canonical rendering, always with the trailing `/` after the pack
    /// segment: `<tenant>/<team>/<pack>/<name-prefix>`.
    pub(in crate::cli) fn render(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.tenant, self.team, self.category, self.name_prefix
        )
    }

    fn matches(&self, uri: &SecretUri) -> bool {
        uri.category() == self.category && uri.name().starts_with(&self.name_prefix)
    }
}

/// One stored key, by name only. `path` is directly usable as the `path` of
/// `op secrets get` / `op secrets delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::cli) struct StoredKey {
    pub path: String,
    pub store_uri: String,
}

/// Every LIVE key under `prefix` in the dev store at `dev_path`, sorted by
/// store URI. A missing store file lists nothing. Reads metadata only.
pub(in crate::cli) fn list_keys(
    dev_path: &Path,
    env_id: &EnvId,
    prefix: &DevStorePrefix,
) -> Result<Vec<StoredKey>, OpError> {
    if !dev_path.exists() {
        return Ok(Vec::new());
    }
    list_keys_in_existing_store(dev_path, env_id, prefix)
}

/// Remove the key at `store_uri` from the dev store. Returns whether a LIVE
/// value was removed; a missing store, a missing key and a key that only
/// carried a tombstone all return `false` (the tombstone residue is still
/// purged from the file).
pub(in crate::cli) fn delete_key(dev_path: &Path, store_uri: &str) -> Result<bool, OpError> {
    if !dev_path.exists() {
        return Ok(false);
    }
    let _write_lock = EnvFlock::acquire(&dev_store_lock_path(dev_path))
        .map_err(|source| OpError::Store(source.into()))?;
    let uri = parse_uri(dev_path, store_uri)?;
    let (on_disk, live) = {
        let backend = open_backend(dev_path)?;
        let versions = backend
            .versions(&uri)
            .map_err(|e| io_err(dev_path, format!("read dev store: {e}")))?;
        let live = backend
            .exists(&uri)
            .map_err(|e| io_err(dev_path, format!("read dev store: {e}")))?;
        (!versions.is_empty(), live)
    };
    if on_disk {
        rewrite_excluding(dev_path, &[store_uri])?;
    }
    Ok(live)
}

/// Remove every live key under `prefix` in ONE atomic rewrite, returning what
/// was removed. Refuses outright — deleting nothing — when the prefix covers
/// the deployer's own bound credential, which runtime tooling must never touch.
pub(in crate::cli) fn delete_prefix(
    dev_path: &Path,
    env_id: &EnvId,
    prefix: &DevStorePrefix,
) -> Result<Vec<StoredKey>, OpError> {
    if !dev_path.exists() {
        return Ok(Vec::new());
    }
    let _write_lock = EnvFlock::acquire(&dev_store_lock_path(dev_path))
        .map_err(|source| OpError::Store(source.into()))?;
    let keys = list_keys_in_existing_store(dev_path, env_id, prefix)?;
    if let Some(reserved) = keys
        .iter()
        .find(|k| crate::credentials::store_paths::is_reserved_rel_path(&k.path))
    {
        return Err(OpError::InvalidArgument(format!(
            "prefix `{}` covers `{}`, which is reserved for the deployer's own bound \
             credential and cannot be deleted through `op secrets delete`",
            prefix.render(),
            reserved.path
        )));
    }
    if keys.is_empty() {
        return Ok(keys);
    }
    let uris: Vec<&str> = keys.iter().map(|k| k.store_uri.as_str()).collect();
    rewrite_excluding(dev_path, &uris)?;
    Ok(keys)
}

// --- internals -----------------------------------------------------------

fn list_keys_in_existing_store(
    dev_path: &Path,
    env_id: &EnvId,
    prefix: &DevStorePrefix,
) -> Result<Vec<StoredKey>, OpError> {
    // The env segment is decided by the ONE shared derivation (`mcp`/`a2a` live
    // under `default`, everything else under the env id), so a listing looks in
    // exactly the scope a put writes to. The probe name is never looked up.
    let probe_rel = format!(
        "{}/{}/{}/probe",
        prefix.tenant, prefix.team, prefix.category
    );
    let probe = parse_uri(dev_path, &dev_store_key(env_id, &probe_rel))?;
    let backend = open_backend(dev_path)?;
    let name_prefix = (!prefix.name_prefix.is_empty()).then_some(prefix.name_prefix.as_str());
    let items = backend
        .list(probe.scope(), Some(&prefix.category), name_prefix)
        .map_err(|e| io_err(dev_path, format!("list dev store: {e}")))?;
    let mut keys = Vec::with_capacity(items.len());
    for item in items {
        // The backend matches the category by prefix; the contract is exact.
        if !prefix.matches(&item.uri) {
            continue;
        }
        let versionless = item
            .uri
            .clone()
            .with_version(None)
            .map_err(|e| io_err(dev_path, format!("list dev store: {e}")))?;
        let store_uri = versionless.to_string();
        let Some((_env, path)) = crate::credentials::store_paths::split_store_uri(&store_uri)
        else {
            continue;
        };
        keys.push(StoredKey { path, store_uri });
    }
    keys.sort_by(|a, b| a.store_uri.cmp(&b.store_uri));
    keys.dedup();
    Ok(keys)
}

fn open_backend(dev_path: &Path) -> Result<DevBackend, OpError> {
    DevBackend::with_persistence(dev_path.to_path_buf())
        .map_err(|e| io_err(dev_path, format!("open dev store: {e}")))
}

fn parse_uri(dev_path: &Path, store_uri: &str) -> Result<SecretUri, OpError> {
    SecretUri::parse(store_uri)
        .map_err(|e| io_err(dev_path, format!("dev store key `{store_uri}`: {e}")))
}

/// Write a copy of the store without `exclude` next to it, then rename it over
/// the store. The rename is atomic on one filesystem, so a reader sees the old
/// file or the new one, never a half-written one; the caller holds the sidecar
/// write lock, so no `op secrets` writer races the swap.
fn rewrite_excluding(dev_path: &Path, exclude: &[&str]) -> Result<(), OpError> {
    let staged = staged_sibling(dev_path);
    DevStore::copy_excluding(dev_path, &staged, exclude)
        .map_err(|e| io_err(dev_path, format!("rewrite dev store: {e}")))?;
    if let Err(source) = std::fs::rename(&staged, dev_path) {
        let _ = std::fs::remove_file(&staged);
        return Err(OpError::Io {
            path: dev_path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// A fresh, dot-prefixed path in the store's own directory (same filesystem,
/// so the publishing rename is atomic).
fn staged_sibling(dev_path: &Path) -> PathBuf {
    let file_name = dev_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dev-secrets".to_string());
    let staged = format!(".{file_name}.delete-{}", ulid::Ulid::new());
    match dev_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(staged),
        _ => PathBuf::from(staged),
    }
}

fn io_err(path: &Path, message: String) -> OpError {
    OpError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(message),
    }
}
