//! [`EnvironmentStore`] trait + [`LocalFsStore`] filesystem implementation
//! per `plans/next-gen-deployment.md` A2.
//!
//! On-disk layout (single env):
//!
//! ```text
//! <root>/<env_id>/
//!   .lock                              ← per-env exclusive flock target
//!   environment.json                   ← Environment compose-view (§5.1)
//!   runtime.json                       ← EnvironmentRuntime (§5.1a, optional)
//!   env-packs/<slot>/answers.json      ← per-slot opaque answers
//!   backups/
//!     environment.json.<ts>.bak
//!     runtime.json.<ts>.bak
//!     env-packs/<slot>/answers.json.<ts>.bak
//! ```
//!
//! Every mutation:
//! 1. acquires the env's flock,
//! 2. copies the current file (if any) into `backups/` with a UTC timestamp,
//! 3. validates the in-memory value (where applicable),
//! 4. atomically rewrites the target via [`atomic_write_json`].
//!
//! Generations/ETags/compare-and-swap are NOT implemented here — those are
//! the remote-store contract (A8). Local FS coordinates via flock only.

use std::path::{Path, PathBuf};

use greentic_deploy_spec::{
    CapabilitySlot, EnvId, Environment, EnvironmentRuntime, SchemaVersion, SpecError,
};
use serde_json::Value;
use thiserror::Error;

use super::atomic_write::{AtomicWriteError, atomic_write_json, copy_to_backup};
use super::file_lock::{EnvFlock, LockError};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("environment `{0}` not found")]
    NotFound(EnvId),
    #[error("environment_id mismatch: file is `{file}`, value is `{value}`")]
    EnvIdMismatch { file: EnvId, value: EnvId },
    #[error(
        "environment id `{0}` is not safe as a path segment (rejects \"\", \".\", \"..\", and ids containing path separators)"
    )]
    UnsafeEnvId(EnvId),
    #[error("spec validation failed: {0}")]
    Spec(#[from] SpecError),
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(transparent)]
    AtomicWrite(#[from] AtomicWriteError),
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("json error on {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Reject env ids that, while valid per the upstream `EnvId` validator
/// (which allows `.` and `..` as full strings), would escape the store
/// root when used as a path segment. The upstream validator already
/// rejects `/`, `\`, `:`, and whitespace; this is the narrow gap to close.
fn safe_env_segment(env_id: &EnvId) -> Result<&str, StoreError> {
    let s = env_id.as_str();
    if s.is_empty() || s == "." || s == ".." {
        return Err(StoreError::UnsafeEnvId(env_id.clone()));
    }
    // Defense-in-depth: even though the upstream validator should already
    // strip these, refuse anything that looks like a multi-segment path.
    if s.contains('/') || s.contains('\\') || s.contains(':') || s.contains('\0') {
        return Err(StoreError::UnsafeEnvId(env_id.clone()));
    }
    Ok(s)
}

/// Local-FS persistence contract.
///
/// All methods are synchronous. Wrap in `tokio::task::spawn_blocking` at call
/// sites that need async.
pub trait EnvironmentStore: Send + Sync {
    fn list(&self) -> Result<Vec<EnvId>, StoreError>;
    fn exists(&self, env_id: &EnvId) -> Result<bool, StoreError>;

    fn load(&self, env_id: &EnvId) -> Result<Environment, StoreError>;
    fn save(&self, env: &Environment) -> Result<(), StoreError>;

    fn load_runtime(&self, env_id: &EnvId) -> Result<Option<EnvironmentRuntime>, StoreError>;
    fn save_runtime(&self, runtime: &EnvironmentRuntime) -> Result<(), StoreError>;

    fn load_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> Result<Option<Value>, StoreError>;
    fn save_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        answers: &Value,
    ) -> Result<(), StoreError>;
    fn delete_pack_answers(&self, env_id: &EnvId, slot: CapabilitySlot) -> Result<(), StoreError>;

    /// Acquire the per-env exclusive lock for a multi-step transaction. The
    /// individual `save_*` methods acquire this internally; callers only need
    /// it for atomic compound mutations.
    fn lock(&self, env_id: &EnvId) -> Result<EnvFlock, StoreError>;
}

#[derive(Debug, Clone)]
pub struct LocalFsStore {
    root: PathBuf,
}

impl LocalFsStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `~/.greentic/environments` per the Phase A acceptance criteria.
    pub fn default_root() -> Option<PathBuf> {
        dirs_home().map(|h| h.join(".greentic").join("environments"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn env_dir(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.root.join(safe_env_segment(env_id)?))
    }

    fn lock_path(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.env_dir(env_id)?.join(".lock"))
    }

    fn environment_path(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.env_dir(env_id)?.join("environment.json"))
    }

    fn runtime_path(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.env_dir(env_id)?.join("runtime.json"))
    }

    fn pack_answers_path(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> Result<PathBuf, StoreError> {
        Ok(self
            .env_dir(env_id)?
            .join("env-packs")
            .join(slot.as_str())
            .join("answers.json"))
    }

    fn backups_dir(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.env_dir(env_id)?.join("backups"))
    }

    fn pack_backups_dir(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> Result<PathBuf, StoreError> {
        Ok(self
            .backups_dir(env_id)?
            .join("env-packs")
            .join(slot.as_str()))
    }

    fn read_json<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T, StoreError> {
        let bytes = std::fs::read(path).map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(|source| StoreError::Json {
            path: path.to_path_buf(),
            source,
        })
    }
}

impl EnvironmentStore for LocalFsStore {
    fn list(&self) -> Result<Vec<EnvId>, StoreError> {
        if !self.root.exists() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.root).map_err(|source| StoreError::Io {
            path: self.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| StoreError::Io {
                path: self.root.clone(),
                source,
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(id) = EnvId::try_from(name) else {
                continue;
            };
            // Skip ids that escape the root segment (e.g. `.` or `..`).
            if safe_env_segment(&id).is_err() {
                continue;
            }
            let env_path = path.join("environment.json");
            if !env_path.exists() {
                continue;
            }
            // Silently skip envs whose on-disk file is unreadable, fails to
            // deserialize, or carries a mismatched `environment_id`. Without
            // this check a corrupted document could surface in `list()` under
            // a name that does not match its own contents.
            let Ok(env) = self.read_json::<Environment>(&env_path) else {
                continue;
            };
            if env.environment_id != id {
                continue;
            }
            out.push(id);
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }

    fn exists(&self, env_id: &EnvId) -> Result<bool, StoreError> {
        Ok(self.environment_path(env_id)?.exists())
    }

    fn load(&self, env_id: &EnvId) -> Result<Environment, StoreError> {
        let path = self.environment_path(env_id)?;
        if !path.exists() {
            return Err(StoreError::NotFound(env_id.clone()));
        }
        let env: Environment = self.read_json(&path)?;
        if env.environment_id != *env_id {
            return Err(StoreError::EnvIdMismatch {
                file: env_id.clone(),
                value: env.environment_id,
            });
        }
        env.validate()?;
        Ok(env)
    }

    fn save(&self, env: &Environment) -> Result<(), StoreError> {
        // Validate first so a bad value never touches disk and never claims
        // the lock from another writer.
        env.validate()?;
        // Discriminator double-check (validate() already does this, but the
        // explicit error surface here is clearer).
        if env.schema.as_str() != SchemaVersion::ENVIRONMENT_V1 {
            return Err(StoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_V1,
                actual: env.schema.as_str().to_string(),
            }));
        }
        let env_id = &env.environment_id;
        let _guard = EnvFlock::acquire(&self.lock_path(env_id)?)?;
        let target = self.environment_path(env_id)?;
        copy_to_backup(&target, &self.backups_dir(env_id)?)?;
        atomic_write_json(&target, env)?;
        Ok(())
    }

    fn load_runtime(&self, env_id: &EnvId) -> Result<Option<EnvironmentRuntime>, StoreError> {
        let path = self.runtime_path(env_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let runtime: EnvironmentRuntime = self.read_json(&path)?;
        if runtime.environment_id != *env_id {
            return Err(StoreError::EnvIdMismatch {
                file: env_id.clone(),
                value: runtime.environment_id,
            });
        }
        if runtime.schema.as_str() != SchemaVersion::ENVIRONMENT_RUNTIME_V1 {
            return Err(StoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_RUNTIME_V1,
                actual: runtime.schema.as_str().to_string(),
            }));
        }
        Ok(Some(runtime))
    }

    fn save_runtime(&self, runtime: &EnvironmentRuntime) -> Result<(), StoreError> {
        if runtime.schema.as_str() != SchemaVersion::ENVIRONMENT_RUNTIME_V1 {
            return Err(StoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_RUNTIME_V1,
                actual: runtime.schema.as_str().to_string(),
            }));
        }
        let env_id = &runtime.environment_id;
        let _guard = EnvFlock::acquire(&self.lock_path(env_id)?)?;
        let target = self.runtime_path(env_id)?;
        copy_to_backup(&target, &self.backups_dir(env_id)?)?;
        atomic_write_json(&target, runtime)?;
        Ok(())
    }

    fn load_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> Result<Option<Value>, StoreError> {
        let path = self.pack_answers_path(env_id, slot)?;
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(self.read_json(&path)?))
    }

    fn save_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        answers: &Value,
    ) -> Result<(), StoreError> {
        let _guard = EnvFlock::acquire(&self.lock_path(env_id)?)?;
        let target = self.pack_answers_path(env_id, slot)?;
        copy_to_backup(&target, &self.pack_backups_dir(env_id, slot)?)?;
        atomic_write_json(&target, answers)?;
        Ok(())
    }

    fn delete_pack_answers(&self, env_id: &EnvId, slot: CapabilitySlot) -> Result<(), StoreError> {
        let _guard = EnvFlock::acquire(&self.lock_path(env_id)?)?;
        let target = self.pack_answers_path(env_id, slot)?;
        if target.exists() {
            // Snapshot before removal so the previous answers can be recovered.
            copy_to_backup(&target, &self.pack_backups_dir(env_id, slot)?)?;
            std::fs::remove_file(&target).map_err(|source| StoreError::Io {
                path: target,
                source,
            })?;
        }
        Ok(())
    }

    fn lock(&self, env_id: &EnvId) -> Result<EnvFlock, StoreError> {
        Ok(EnvFlock::acquire(&self.lock_path(env_id)?)?)
    }
}

#[cfg(unix)]
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(windows)]
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(PathBuf::from)
}

#[cfg(not(any(unix, windows)))]
fn dirs_home() -> Option<PathBuf> {
    None
}
