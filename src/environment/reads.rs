//! Read-only environment views shared by the local and remote stores.
//!
//! The `op` read verbs (`env list`/`show`, the `*-list` verbs, `traffic
//! show`, `messaging endpoint show`) all project from a single loaded
//! [`Environment`] — plus, for `env show`, the runtime sidecar.
//! [`EnvironmentReads`] is the minimal read surface that BOTH
//! [`LocalFsStore`](super::LocalFsStore) (filesystem) and
//! [`HttpEnvironmentStore`](super::HttpEnvironmentStore) (the A8 `GET`
//! endpoints) implement, so a single verb function serves both backends —
//! the local CLI passes the FS store, the `--store-url` dispatch passes the
//! HTTP store, and neither projection is duplicated.
//!
//! The methods carry distinct names (`load_env`, not `load`) on purpose:
//! `LocalFsStore` implements both this trait and
//! [`EnvironmentStore`](super::EnvironmentStore), and reusing `load`/`list`/
//! `exists` here would make those calls ambiguous on a concrete
//! `LocalFsStore`.
//!
//! Trust-root reads are deliberately NOT on this trait: they come from a
//! separate document (its own error type) and a separate `GET .../trust-root`
//! endpoint, so they are wired through an inherent
//! [`HttpEnvironmentStore::load_trust_root_keys`] method instead.

use greentic_deploy_spec::{EnvId, Environment, EnvironmentRuntime};

use super::store::{EnvironmentStore, LocalFsStore, StoreError};

/// The read surface the `op` read verbs need, implemented by both the
/// filesystem and HTTP backends.
pub trait EnvironmentReads: Send + Sync {
    /// All environment ids known to the store, sorted.
    fn list_env_ids(&self) -> Result<Vec<EnvId>, StoreError>;
    /// Whether `env_id` exists.
    fn env_exists(&self, env_id: &EnvId) -> Result<bool, StoreError>;
    /// Load the environment document.
    fn load_env(&self, env_id: &EnvId) -> Result<Environment, StoreError>;
    /// Load the runtime host-config sidecar, if present. The HTTP backend has
    /// no runtime `GET` endpoint, so it returns `Ok(None)` — remote `env
    /// show` therefore reports `runtime: null`.
    fn read_runtime(&self, env_id: &EnvId) -> Result<Option<EnvironmentRuntime>, StoreError>;
}

impl EnvironmentReads for LocalFsStore {
    fn list_env_ids(&self) -> Result<Vec<EnvId>, StoreError> {
        EnvironmentStore::list(self)
    }

    fn env_exists(&self, env_id: &EnvId) -> Result<bool, StoreError> {
        EnvironmentStore::exists(self, env_id)
    }

    fn load_env(&self, env_id: &EnvId) -> Result<Environment, StoreError> {
        EnvironmentStore::load(self, env_id)
    }

    fn read_runtime(&self, env_id: &EnvId) -> Result<Option<EnvironmentRuntime>, StoreError> {
        EnvironmentStore::load_runtime(self, env_id)
    }
}
