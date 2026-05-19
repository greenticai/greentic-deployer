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
        let env_id = &env.environment_id;
        let _guard = EnvFlock::acquire(&self.lock_path(env_id)?)?;
        self.save_locked(env)
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
        let env_id = &runtime.environment_id;
        let _guard = EnvFlock::acquire(&self.lock_path(env_id)?)?;
        self.save_runtime_locked(runtime)
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
        self.save_pack_answers_locked(env_id, slot, answers)
    }

    fn delete_pack_answers(&self, env_id: &EnvId, slot: CapabilitySlot) -> Result<(), StoreError> {
        let _guard = EnvFlock::acquire(&self.lock_path(env_id)?)?;
        self.delete_pack_answers_locked(env_id, slot)
    }
}

// --- Locked-but-no-relock inner helpers ----------------------------------
//
// Each `save_*` and `delete_*` on `LocalFsStore` extracts to a `_locked`
// inner that assumes the caller already holds the env flock. The trait
// methods take the lock themselves; [`LocalFsStore::transact`] takes it
// once and dispatches through [`Locked`].

impl LocalFsStore {
    fn save_locked(&self, env: &Environment) -> Result<(), StoreError> {
        // Discriminator double-check (validate() also covers this, but the
        // explicit error surface here is clearer).
        if env.schema.as_str() != SchemaVersion::ENVIRONMENT_V1 {
            return Err(StoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_V1,
                actual: env.schema.as_str().to_string(),
            }));
        }
        env.validate()?;
        let env_id = &env.environment_id;
        let target = self.environment_path(env_id)?;
        copy_to_backup(&target, &self.backups_dir(env_id)?)?;
        atomic_write_json(&target, env)?;
        Ok(())
    }

    fn save_runtime_locked(&self, runtime: &EnvironmentRuntime) -> Result<(), StoreError> {
        if runtime.schema.as_str() != SchemaVersion::ENVIRONMENT_RUNTIME_V1 {
            return Err(StoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_RUNTIME_V1,
                actual: runtime.schema.as_str().to_string(),
            }));
        }
        let env_id = &runtime.environment_id;
        let target = self.runtime_path(env_id)?;
        copy_to_backup(&target, &self.backups_dir(env_id)?)?;
        atomic_write_json(&target, runtime)?;
        Ok(())
    }

    fn save_pack_answers_locked(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        answers: &Value,
    ) -> Result<(), StoreError> {
        let target = self.pack_answers_path(env_id, slot)?;
        copy_to_backup(&target, &self.pack_backups_dir(env_id, slot)?)?;
        atomic_write_json(&target, answers)?;
        Ok(())
    }

    fn delete_pack_answers_locked(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> Result<(), StoreError> {
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

    /// Resolve the per-env lock path. Public so external callers that need
    /// raw `EnvFlock` semantics can grab the path without poking at private
    /// internals — but they must understand that each mutating call already
    /// re-acquires this lock blocking, so externally-held guards combined
    /// with `save_*` on the same instance will deadlock. Prefer
    /// [`LocalFsStore::transact`] for compound mutations.
    pub fn env_lock_path(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        self.lock_path(env_id)
    }

    /// Run `f` while holding the env's exclusive lock. The closure receives
    /// a [`Locked`] view whose mutator methods skip lock acquisition, so a
    /// natural `load → mutate → save` flow inside the closure does not
    /// re-enter (and deadlock on) the per-FD flock.
    ///
    /// Reads (`load`, `load_runtime`, `load_pack_answers`, `exists`,
    /// `list`) do not take the lock and are also available on the
    /// `Locked` handle for convenience.
    ///
    /// Generic over the closure's error type via `E: From<StoreError>` so
    /// callers that mix storage errors with their own domain errors (e.g.
    /// the `cli::*` operator surface using `OpError`) can run validation +
    /// load + mutate + save in a single critical section without an
    /// outer-layer error-mapping dance. Existing callers passing
    /// `Result<_, StoreError>` continue to work because
    /// `From<StoreError> for StoreError` is automatic.
    pub fn transact<F, R, E>(&self, env_id: &EnvId, f: F) -> Result<R, E>
    where
        F: FnOnce(&Locked<'_>) -> Result<R, E>,
        E: From<StoreError>,
    {
        let lock_path = self.lock_path(env_id).map_err(E::from)?;
        let _guard = EnvFlock::acquire(&lock_path).map_err(|e| E::from(StoreError::Lock(e)))?;
        let locked = Locked {
            store: self,
            env_id: env_id.clone(),
        };
        f(&locked)
    }
}

/// Lock-holding handle returned by [`LocalFsStore::transact`]. All mutator
/// methods on this type skip lock acquisition; the lock is held by the
/// enclosing `transact` scope and released on its return.
///
/// Mutators on this handle reject writes whose embedded `environment_id`
/// (or runtime `environment_id`) does not match the env the transaction is
/// scoped to — the lock guards exactly one env's state, so accidentally
/// writing a different env's payload inside the closure would bypass that
/// env's flock entirely.
#[derive(Debug)]
pub struct Locked<'a> {
    store: &'a LocalFsStore,
    env_id: EnvId,
}

impl<'a> Locked<'a> {
    pub fn env_id(&self) -> &EnvId {
        &self.env_id
    }

    pub fn load(&self) -> Result<Environment, StoreError> {
        self.store.load(&self.env_id)
    }

    pub fn save(&self, env: &Environment) -> Result<(), StoreError> {
        if env.environment_id != self.env_id {
            return Err(StoreError::EnvIdMismatch {
                file: self.env_id.clone(),
                value: env.environment_id.clone(),
            });
        }
        self.store.save_locked(env)
    }

    pub fn load_runtime(&self) -> Result<Option<EnvironmentRuntime>, StoreError> {
        self.store.load_runtime(&self.env_id)
    }

    pub fn save_runtime(&self, runtime: &EnvironmentRuntime) -> Result<(), StoreError> {
        if runtime.environment_id != self.env_id {
            return Err(StoreError::EnvIdMismatch {
                file: self.env_id.clone(),
                value: runtime.environment_id.clone(),
            });
        }
        self.store.save_runtime_locked(runtime)
    }

    pub fn load_pack_answers(&self, slot: CapabilitySlot) -> Result<Option<Value>, StoreError> {
        self.store.load_pack_answers(&self.env_id, slot)
    }

    pub fn save_pack_answers(
        &self,
        slot: CapabilitySlot,
        answers: &Value,
    ) -> Result<(), StoreError> {
        self.store
            .save_pack_answers_locked(&self.env_id, slot, answers)
    }

    pub fn delete_pack_answers(&self, slot: CapabilitySlot) -> Result<(), StoreError> {
        self.store.delete_pack_answers_locked(&self.env_id, slot)
    }
}

#[cfg(unix)]
pub(crate) fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(windows)]
pub(crate) fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(PathBuf::from)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn dirs_home() -> Option<PathBuf> {
    None
}
