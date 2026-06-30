//! Whole-environment snapshot/restore (P0b of the Greentic updater).
//!
//! A snapshot captures the **full per-env file set** — `environment.json`,
//! `runtime.json`, `runtime-config.json`, per-slot `env-packs/<slot>/answers.json`,
//! `messaging/**`, and `trust-root.json` — into `<env_dir>/snapshots/<id>/`.
//! Restore replays the captured bytes **exactly**, then re-derives the
//! projected files (`runtime-config.json`, `messaging/`) so the running
//! system picks up the restored state.
//!
//! Both operations run under the env's flock via [`LocalFsStore::transact`].
//!
//! **Meaningful-absence:** if a file was absent at snapshot time (e.g.
//! `trust-root.json` or `runtime-config.json`), restore deletes it from the
//! live env if it exists — a snapshot records *exactly* what was there.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use greentic_deploy_spec::{CapabilitySlot, EnvId, SecretRef};
use serde::{Deserialize, Serialize};

use super::atomic_write::{atomic_write_bytes, atomic_write_json};
use super::store::{LocalFsStore, StoreError};
use super::trust_root::TRUST_ROOT_FILE;

// ---------------------------------------------------------------------------
// SnapshotId
// ---------------------------------------------------------------------------

/// Collision-resistant, chronologically-sortable identifier for a snapshot.
/// Backed by a ULID so two concurrent snapshots in the same env never collide
/// and listing by name produces chronological order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(String);

impl Default for SnapshotId {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotId {
    /// Generate a new, unique snapshot identifier.
    pub fn new() -> Self {
        Self(ulid::Ulid::new().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Snapshot manifest — tracks which files were present/absent
// ---------------------------------------------------------------------------

/// On-disk manifest persisted as `manifest.json` inside a snapshot directory.
/// Each key is a **relative** path (from the env dir); the value records
/// whether the file was present (and captured) or absent at snapshot time.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SnapshotManifest {
    /// Schema discriminator for forward-compat.
    schema: String,
    /// The environment id this snapshot was taken from.
    env_id: EnvId,
    /// `relative_path -> present`. `true` = file captured in the snapshot
    /// dir; `false` = file was absent and restore must ensure it stays absent.
    files: BTreeMap<String, bool>,
}

const SNAPSHOT_MANIFEST_SCHEMA: &str = "greentic.snapshot-manifest.v1";
const SNAPSHOTS_DIR: &str = "snapshots";
const MANIFEST_FILE: &str = "manifest.json";

// ---------------------------------------------------------------------------
// snapshot_environment
// ---------------------------------------------------------------------------

/// Capture the full per-env file set under the env's flock.
///
/// Returns the [`SnapshotId`] of the created snapshot. The snapshot is
/// persisted under `<env_dir>/snapshots/<id>/` and includes a `manifest.json`
/// recording presence/absence for every tracked file.
pub fn snapshot_environment(
    store: &LocalFsStore,
    env_id: &EnvId,
) -> Result<SnapshotId, StoreError> {
    store.transact(env_id, |_locked| snapshot_locked(store, env_id))
}

fn snapshot_locked(store: &LocalFsStore, env_id: &EnvId) -> Result<SnapshotId, StoreError> {
    let env_dir = store.env_dir(env_id)?;
    if !env_dir.exists() {
        return Err(StoreError::NotFound(env_id.clone()));
    }

    let snap_id = SnapshotId::new();
    let snap_dir = env_dir.join(SNAPSHOTS_DIR).join(snap_id.as_str());

    let mut manifest_files: BTreeMap<String, bool> = BTreeMap::new();

    // --- Tracked top-level files ---
    let top_level = &[
        "environment.json",
        "runtime.json",
        "runtime-config.json",
        TRUST_ROOT_FILE,
    ];
    for rel in top_level {
        capture_file(&env_dir, rel, &snap_dir, &mut manifest_files)?;
    }

    // --- Per-slot pack answers ---
    for slot in CapabilitySlot::ALL {
        let rel = format!("env-packs/{}/answers.json", slot.as_str());
        capture_file(&env_dir, &rel, &snap_dir, &mut manifest_files)?;
    }

    // --- Messaging projections ---
    let messaging_dir = env_dir.join("messaging");
    if messaging_dir.is_dir() {
        for entry in fs::read_dir(&messaging_dir).map_err(|source| StoreError::Io {
            path: messaging_dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| StoreError::Io {
                path: messaging_dir.clone(),
                source,
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !name.ends_with(".json") {
                continue;
            }
            let rel = format!("messaging/{name}");
            capture_file(&env_dir, &rel, &snap_dir, &mut manifest_files)?;
        }
    }
    // Record messaging dir absence so restore knows to clean up stale files.
    if !messaging_dir.is_dir() {
        // No messaging files existed — nothing to record (absence is the
        // default; restore deletes anything not in the manifest).
    }

    // Persist the manifest itself.
    let manifest = SnapshotManifest {
        schema: SNAPSHOT_MANIFEST_SCHEMA.to_string(),
        env_id: env_id.clone(),
        files: manifest_files,
    };
    atomic_write_json(&snap_dir.join(MANIFEST_FILE), &manifest)?;

    Ok(snap_id)
}

/// Copy a single file into the snapshot dir, recording its presence/absence
/// in the manifest map.
fn capture_file(
    env_dir: &Path,
    rel_path: &str,
    snap_dir: &Path,
    manifest: &mut BTreeMap<String, bool>,
) -> Result<(), StoreError> {
    let src = env_dir.join(rel_path);
    if src.is_file() {
        let dst = snap_dir.join(rel_path);
        let dst_parent = dst.parent().expect("snapshot file always has a parent");
        fs::create_dir_all(dst_parent).map_err(|source| StoreError::Io {
            path: dst_parent.to_path_buf(),
            source,
        })?;
        fs::copy(&src, &dst).map_err(|source| StoreError::Io {
            path: src.clone(),
            source,
        })?;
        manifest.insert(rel_path.to_string(), true);
    } else {
        manifest.insert(rel_path.to_string(), false);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// restore_environment
// ---------------------------------------------------------------------------

/// Restore a previously snapshotted environment, byte-exact.
///
/// Runs under the env's flock. After restoring the raw files:
/// 1. Backs up each live file being overwritten (via the store's `backups/`
///    convention).
/// 2. Restores each captured file byte-exact via [`atomic_write_bytes`].
/// 3. Deletes any live file that was absent in the snapshot (meaningful-absence).
/// 4. Loads the restored `Environment`, rewrites every [`SecretRef`]'s
///    env-segment to the target `env_id` (so `validate()` does not reject
///    with `CrossEnvRef`), then re-derives `runtime-config.json` and the
///    messaging projection.
pub fn restore_environment(
    store: &LocalFsStore,
    env_id: &EnvId,
    snapshot: &SnapshotId,
) -> Result<(), StoreError> {
    store.transact(env_id, |locked| {
        let env_dir = store.env_dir(env_id)?;
        let snap_dir = env_dir.join(SNAPSHOTS_DIR).join(snapshot.as_str());
        let manifest_path = snap_dir.join(MANIFEST_FILE);

        if !manifest_path.is_file() {
            return Err(StoreError::NotFound(env_id.clone()));
        }
        let manifest_bytes = fs::read(&manifest_path).map_err(|source| StoreError::Io {
            path: manifest_path.clone(),
            source,
        })?;
        let manifest: SnapshotManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|source| StoreError::Json {
                path: manifest_path,
                source,
            })?;

        let backups_dir = env_dir.join("backups");

        // --- Restore each tracked file ---
        for (rel_path, present) in &manifest.files {
            let live_path = env_dir.join(rel_path);
            if *present {
                // File was present at snapshot time → restore byte-exact.
                let snap_file = snap_dir.join(rel_path);
                let bytes = fs::read(&snap_file).map_err(|source| StoreError::Io {
                    path: snap_file,
                    source,
                })?;
                // Back up the current live file (if any) before overwriting.
                super::atomic_write::copy_to_backup(&live_path, &backups_dir)?;
                atomic_write_bytes(&live_path, &bytes)?;
            } else {
                // File was absent at snapshot time → ensure it's gone now.
                if live_path.is_file() {
                    super::atomic_write::copy_to_backup(&live_path, &backups_dir)?;
                    fs::remove_file(&live_path).map_err(|source| StoreError::Io {
                        path: live_path,
                        source,
                    })?;
                }
            }
        }

        // --- Clean up stray messaging files not in the snapshot ---
        //
        // If the snapshot had messaging files, any live messaging file whose
        // relative path is NOT in the manifest is a stray that appeared after
        // the snapshot was taken — remove it.
        let messaging_dir = env_dir.join("messaging");
        if messaging_dir.is_dir() {
            for entry in fs::read_dir(&messaging_dir).map_err(|source| StoreError::Io {
                path: messaging_dir.clone(),
                source,
            })? {
                let entry = entry.map_err(|source| StoreError::Io {
                    path: messaging_dir.clone(),
                    source,
                })?;
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let rel = format!("messaging/{name}");
                if !manifest.files.contains_key(&rel) {
                    super::atomic_write::copy_to_backup(&path, &backups_dir)?;
                    fs::remove_file(&path).map_err(|source| StoreError::Io {
                        path: path.clone(),
                        source,
                    })?;
                }
            }
        }

        // --- Rewrite SecretRef env segments + re-derive projections ---
        //
        // Load the restored environment.json, rewrite any SecretRef whose
        // env_segment differs from the target env_id, then save and re-derive.
        let mut env = locked.load()?;
        let target_env_str = env_id.as_str();

        let mut rewritten = false;

        // credentials_ref
        if let Some(ref cred) = env.credentials_ref
            && cred.env_segment() != target_env_str
        {
            env.credentials_ref = Some(rewrite_secret_ref_env(cred, target_env_str)?);
            rewritten = true;
        }

        // messaging_endpoints[].secret_refs + webhook_secret_ref
        for ep in &mut env.messaging_endpoints {
            for sr in &mut ep.secret_refs {
                if sr.env_segment() != target_env_str {
                    *sr = rewrite_secret_ref_env(sr, target_env_str)?;
                    rewritten = true;
                }
            }
            if let Some(ref wsr) = ep.webhook_secret_ref
                && wsr.env_segment() != target_env_str
            {
                ep.webhook_secret_ref = Some(rewrite_secret_ref_env(wsr, target_env_str)?);
                rewritten = true;
            }
        }

        if rewritten {
            // Re-save with corrected refs so the on-disk file passes validate().
            locked.save(&env)?;
        }

        // Re-derive projected files from the (possibly rewritten) env.
        locked.refresh_runtime_config(&env)?;
        locked.refresh_messaging_projection(&env)?;

        Ok(())
    })
}

/// Replace the env-segment in a `SecretRef` URI with `new_env`.
///
/// `secret://<old_env>/rest/of/path` → `secret://<new_env>/rest/of/path`
fn rewrite_secret_ref_env(sr: &SecretRef, new_env: &str) -> Result<SecretRef, StoreError> {
    let raw = sr.as_str();
    let scheme = "secret://";
    let after_scheme = &raw[scheme.len()..];
    let rest = match after_scheme.find('/') {
        Some(idx) => &after_scheme[idx..],
        None => "",
    };
    let new_raw = format!("{scheme}{new_env}{rest}");
    SecretRef::try_new(new_raw).map_err(|e| {
        StoreError::InvalidArgument(format!("failed to rewrite SecretRef env segment: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chrono::Utc;
    use greentic_deploy_spec::{
        EnvId, Environment, EnvironmentHostConfig, HealthStatus, MessagingEndpoint,
        MessagingEndpointId, RetentionPolicy, RevocationConfig, SchemaVersion,
    };
    use tempfile::TempDir;

    use crate::environment::store::EnvironmentStore;

    /// Build a minimal valid `Environment` for testing.
    fn test_env(env_id: &EnvId) -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id.clone(),
            name: "test-env".into(),
            host_config: EnvironmentHostConfig {
                env_id: env_id.clone(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
            packs: vec![],
            credentials_ref: None,
            bundles: vec![],
            revisions: vec![],
            traffic_splits: vec![],
            messaging_endpoints: vec![],
            extensions: vec![],
            revocation: RevocationConfig::default(),
            retention: RetentionPolicy::default(),
            health: HealthStatus::default(),
        }
    }

    fn test_messaging_endpoint(env_id: &EnvId) -> MessagingEndpoint {
        MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: env_id.clone(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: "tg-test".into(),
            provider_type: "telegram".into(),
            display_name: "Test Bot".into(),
            secret_refs: vec![
                SecretRef::try_new(format!("secret://{}/default/_/messaging/token", env_id))
                    .unwrap(),
            ],
            webhook_secret_ref: Some(
                SecretRef::try_new(format!(
                    "secret://{}/default/_/messaging/webhook_secret",
                    env_id
                ))
                .unwrap(),
            ),
            linked_bundles: vec![],
            welcome_flow: None,
            generation: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            updated_by: "operator://test".into(),
        }
    }

    /// Seed an on-disk env with the full file set and return the store + env_id.
    fn seed_env(tmp: &TempDir) -> (LocalFsStore, EnvId, Environment) {
        let store = LocalFsStore::new(tmp.path());
        let env_id = EnvId::from_str("snapshot-test").unwrap();
        let env_dir = tmp.path().join(env_id.as_str());
        fs::create_dir_all(&env_dir).unwrap();
        // .lock file (empty)
        fs::write(env_dir.join(".lock"), b"").unwrap();

        let env = test_env(&env_id);
        store.save(&env).unwrap();

        (store, env_id, env)
    }

    #[test]
    fn snapshot_and_restore_byte_exact() {
        let tmp = TempDir::new().unwrap();
        let (store, env_id, mut env) = seed_env(&tmp);
        let env_dir = tmp.path().join(env_id.as_str());

        // Write additional files: runtime.json stub, answers for deployer slot,
        // trust-root, and a messaging endpoint.
        let runtime_content = br#"{"schema":"greentic.environment-runtime.v1","environment_id":"snapshot-test","discovered":{}}"#;
        fs::write(env_dir.join("runtime.json"), runtime_content).unwrap();

        let answers_dir = env_dir.join("env-packs").join("deployer");
        fs::create_dir_all(&answers_dir).unwrap();
        let answers_content = br#"{"cloud":"aws","region":"us-east-1"}"#;
        fs::write(answers_dir.join("answers.json"), answers_content).unwrap();

        let trust_root_content = br#"{"schema":"greentic.trust-root.v1","keys":[]}"#;
        fs::write(env_dir.join(TRUST_ROOT_FILE), trust_root_content).unwrap();

        // Add a messaging endpoint and project it.
        env.messaging_endpoints
            .push(test_messaging_endpoint(&env_id));
        store.save(&env).unwrap();
        store
            .transact(&env_id, |locked| locked.refresh_messaging_projection(&env))
            .unwrap();

        // Snapshot
        let snap_id = snapshot_environment(&store, &env_id).unwrap();

        // Mutate/corrupt: overwrite environment.json, delete trust-root, add
        // a stray messaging file, overwrite answers.
        let corrupted = b"CORRUPTED";
        fs::write(env_dir.join("environment.json"), corrupted).unwrap();
        fs::remove_file(env_dir.join(TRUST_ROOT_FILE)).unwrap();
        fs::write(env_dir.join("messaging").join("stray.json"), b"stray").unwrap();
        fs::write(answers_dir.join("answers.json"), b"{}").unwrap();

        // Restore
        restore_environment(&store, &env_id, &snap_id).unwrap();

        // Verify byte-exact restoration.
        let restored_env_bytes = fs::read(env_dir.join("environment.json")).unwrap();
        assert_ne!(
            restored_env_bytes, corrupted,
            "should not be corrupted anymore"
        );
        // The environment.json was re-saved (SecretRef re-derive path), so we
        // verify via deserialization + validate.
        let restored_env: Environment = serde_json::from_slice(&restored_env_bytes).unwrap();
        restored_env.validate().unwrap();
        assert_eq!(restored_env.environment_id, env_id);

        // runtime.json byte-exact
        assert_eq!(
            fs::read(env_dir.join("runtime.json")).unwrap(),
            runtime_content
        );

        // trust-root.json restored
        assert_eq!(
            fs::read(env_dir.join(TRUST_ROOT_FILE)).unwrap(),
            trust_root_content
        );

        // answers.json byte-exact
        assert_eq!(
            fs::read(answers_dir.join("answers.json")).unwrap(),
            answers_content
        );

        // Stray messaging file gone
        assert!(
            !env_dir.join("messaging").join("stray.json").exists(),
            "stray messaging file should be removed"
        );
    }

    #[test]
    fn meaningful_absence_trust_root() {
        let tmp = TempDir::new().unwrap();
        let (store, env_id, _env) = seed_env(&tmp);
        let env_dir = tmp.path().join(env_id.as_str());

        // No trust-root.json exists.
        assert!(!env_dir.join(TRUST_ROOT_FILE).exists());

        // Snapshot (captures absence).
        let snap_id = snapshot_environment(&store, &env_id).unwrap();

        // Create a trust-root after the snapshot.
        fs::write(
            env_dir.join(TRUST_ROOT_FILE),
            br#"{"schema":"greentic.trust-root.v1","keys":[]}"#,
        )
        .unwrap();
        assert!(env_dir.join(TRUST_ROOT_FILE).exists());

        // Restore — trust-root should be gone again.
        restore_environment(&store, &env_id, &snap_id).unwrap();
        assert!(
            !env_dir.join(TRUST_ROOT_FILE).exists(),
            "trust-root.json should be absent after restoring a snapshot that lacked it"
        );
    }

    #[test]
    fn meaningful_absence_runtime_config() {
        let tmp = TempDir::new().unwrap();
        let (store, env_id, _env) = seed_env(&tmp);
        let env_dir = tmp.path().join(env_id.as_str());

        // No runtime-config.json — env has no traffic splits.
        assert!(!env_dir.join("runtime-config.json").exists());

        let snap_id = snapshot_environment(&store, &env_id).unwrap();

        // Simulate one appearing post-snapshot.
        fs::write(env_dir.join("runtime-config.json"), b"{}").unwrap();

        restore_environment(&store, &env_id, &snap_id).unwrap();
        assert!(
            !env_dir.join("runtime-config.json").exists(),
            "runtime-config.json should be absent after restoring a snapshot without one"
        );
    }

    #[test]
    fn secret_ref_rewrite_passes_validate() {
        let tmp = TempDir::new().unwrap();
        let (store, env_id, mut env) = seed_env(&tmp);

        // Add a credentials_ref and messaging endpoint with SecretRefs.
        env.credentials_ref =
            Some(SecretRef::try_new(format!("secret://{}/credentials/main", env_id)).unwrap());
        env.messaging_endpoints
            .push(test_messaging_endpoint(&env_id));
        store.save(&env).unwrap();
        store
            .transact(&env_id, |locked| locked.refresh_messaging_projection(&env))
            .unwrap();

        let snap_id = snapshot_environment(&store, &env_id).unwrap();

        // Restore should succeed and validate() must pass (the SecretRef
        // env_segment matches the target env).
        restore_environment(&store, &env_id, &snap_id).unwrap();

        let restored: Environment = store.load(&env_id).unwrap();
        restored.validate().unwrap();

        // Verify all SecretRefs point to the correct env.
        if let Some(cred) = &restored.credentials_ref {
            assert_eq!(cred.env_segment(), env_id.as_str());
        }
        for ep in &restored.messaging_endpoints {
            for sr in &ep.secret_refs {
                assert_eq!(sr.env_segment(), env_id.as_str());
            }
            if let Some(wsr) = &ep.webhook_secret_ref {
                assert_eq!(wsr.env_segment(), env_id.as_str());
            }
        }
    }

    #[test]
    fn snapshot_id_is_unique() {
        let a = SnapshotId::new();
        let b = SnapshotId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn rewrite_secret_ref_env_works() {
        let sr = SecretRef::try_new("secret://old-env/tenant/team/cat/name").unwrap();
        let rewritten = rewrite_secret_ref_env(&sr, "new-env").unwrap();
        assert_eq!(rewritten.as_str(), "secret://new-env/tenant/team/cat/name");
        assert_eq!(rewritten.env_segment(), "new-env");
    }

    #[test]
    fn rewrite_secret_ref_env_no_trailing_path() {
        let sr = SecretRef::try_new("secret://old-env").unwrap();
        let rewritten = rewrite_secret_ref_env(&sr, "new-env").unwrap();
        assert_eq!(rewritten.as_str(), "secret://new-env");
        assert_eq!(rewritten.env_segment(), "new-env");
    }
}
