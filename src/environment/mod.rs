//! Environment persistence (A2 of `plans/next-gen-deployment.md`).
//!
//! Public surface:
//!
//! - [`EnvironmentStore`] — local-FS persistence trait
//! - [`LocalFsStore`] — concrete impl rooted at `~/.greentic/environments/`
//! - [`StoreError`] — typed errors
//! - [`EnvFlock`] — RAII per-env exclusive lock (re-exported for transactional callers)
//! - [`atomic_write_json`], [`atomic_write_bytes`], [`copy_to_backup`] — primitives
//! - [`mint_revision_id`], [`mint_deployment_id`] — ULID generators

pub mod atomic_write;
pub mod file_lock;
pub mod store;

pub use atomic_write::{AtomicWriteError, atomic_write_bytes, atomic_write_json, copy_to_backup};
pub use file_lock::{EnvFlock, LockError};
pub use store::{EnvironmentStore, LocalFsStore, StoreError};

use greentic_deploy_spec::{DeploymentId, RevisionId};

/// Mint a fresh [`RevisionId`] (ULID). Wrapper kept here so call sites do not
/// need a direct dependency on the spec crate.
pub fn mint_revision_id() -> RevisionId {
    RevisionId::new()
}

/// Mint a fresh [`DeploymentId`] (ULID). Wrapper kept here so call sites do
/// not need a direct dependency on the spec crate.
pub fn mint_deployment_id() -> DeploymentId {
    DeploymentId::new()
}
