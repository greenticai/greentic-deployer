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
//!   runtime-config.json                ← materialized runtime-config.v1 (§5.7, optional)
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
    CapabilitySlot, EnvId, Environment, EnvironmentRuntime, MessagingEndpoint, MessagingEndpointId,
    RuntimeConfig, SchemaVersion, SpecError, UpdateChannelConfig,
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
    /// Surfaces from trust-root verbs on [`crate::environment::mutations`] —
    /// the typed-verb shape returns `StoreError` so the HTTP backend can map
    /// transport errors into the same enum. CLI callers preserve the
    /// trust-root noun by downcasting this variant back to `OpError::TrustRoot`.
    #[error("trust root: {0}")]
    TrustRoot(#[from] super::trust_root::TrustRootError),
    /// Surfaces from `bootstrap_trust_root` / `seed_trust_root_if_absent` when
    /// loading or generating `~/.greentic/operator/key.pem` fails. Distinct
    /// from `TrustRoot` so CLI callers can surface the right error noun.
    #[error("operator key: {0}")]
    OperatorKey(#[from] crate::operator_key::OperatorKeyError),
    /// Mutator-precondition violation surfaced by [`super::mutations`] verbs
    /// (e.g. [`super::LocalFsStore::create_environment`] when the env already
    /// exists). CLI callers preserve the `conflict` noun by downcasting in
    /// [`crate::cli::map_store_err_preserving_noun`].
    #[error("conflict: {0}")]
    Conflict(String),
    /// Caller-supplied argument is structurally valid but semantically wrong
    /// (e.g. a `pack_id` that does not appear in any current revision, or a
    /// welcome-flow bundle that is not linked). CLI callers preserve the
    /// `invalid-argument` noun via
    /// [`crate::cli::map_store_err_preserving_noun`].
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Sub-entity (e.g. a `BundleDeployment`, `EnvPackBinding`,
    /// `MessagingEndpoint`) is missing under an existing env. Distinct from
    /// [`StoreError::NotFound`] which is reserved for missing envs. The CLI
    /// mapper preserves the `not-found` noun by downcasting; the string
    /// carries the verbatim caller-facing message ("deployment `<id>` not
    /// found in env `<env>`", etc.) so backend impls don't have to reconstruct it.
    #[error("not found: {0}")]
    DependentNotFound(String),
    /// Revision-lifecycle failure surfaced by the typed
    /// `warm_revision` / `drain_revision` / `archive_revision` verbs
    /// (PR-3a.6). The inner [`super::LifecycleError`] preserves the
    /// structured detail (`HealthGateFailed::failed_checks`,
    /// `Conflict::expected_starts`, `ActiveTrafficReference::splits`)
    /// the CLI renders to the operator. No `#[from]` impl: the cycle
    /// between `LifecycleError::Store(StoreError)` and this variant is
    /// broken in [`super::mutations_local`] by unwrapping
    /// `LifecycleError::Store` back into the inner `StoreError` at the
    /// boundary. CLI callers re-extract via
    /// [`crate::cli::map_store_err_preserving_noun`].
    #[error(transparent)]
    Lifecycle(Box<super::LifecycleError>),
    /// Revenue-policy sidecar write failure (PR-3a.7b). Surfaces the
    /// inner [`super::BundleDeploymentError`] so CLI callers can
    /// downcast to `OpError::RevenuePolicy` via
    /// [`crate::cli::map_store_err_preserving_noun`].
    #[error("revenue policy: {0}")]
    RevenuePolicy(#[from] super::BundleDeploymentError),
    /// RBAC denial surfaced by a remote store backend (`403` on the A8
    /// wire, [`greentic_deploy_spec::RemoteStoreError::Unauthorized`]).
    /// Local-FS verbs never construct it — local RBAC runs in the CLI's
    /// audit boundary before the verb fires. CLI callers preserve the
    /// `unauthorized` noun via [`crate::cli::map_store_err_preserving_noun`]
    /// (PR-4.0; previously flattened into [`StoreError::Conflict`]).
    #[error("unauthorized: {reason} (policy `{policy}`)")]
    Unauthorized { policy: String, reason: String },
    /// Verb recognized but not implemented by the backend (`501` on the A8
    /// wire, [`greentic_deploy_spec::RemoteStoreError::NotYetImplemented`]).
    /// CLI callers preserve the `not-yet-implemented` noun via
    /// [`crate::cli::map_store_err_preserving_noun`] (PR-4.0).
    #[error("not yet implemented: {0}")]
    NotYetImplemented(String),
    /// A typed-verb body persisted state to disk via the lifecycle
    /// helper's internal `locked.save(...)` and *then* failed on a
    /// post-save step (env reload, materialized-runtime-config refresh,
    /// etc.). The wrapped `StoreError` is the original failure; CLI
    /// callers MUST treat the verb as `committed` (so the audit
    /// boundary fails-closed on an audit-append failure rather than
    /// demoting it to `tracing::warn!`) AND forward the inner error.
    /// The closure-based revision-transition path already had this
    /// invariant — surfacing it across the typed-verb boundary keeps
    /// the committed-on-error contract intact (`warm` test
    /// `warm_ok_with_refresh_failure_and_audit_failure_returns_audit_error`).
    /// HTTP backends (PR-3b) wrap any "we wrote, then the response
    /// pipeline failed" error in this variant for the same reason.
    #[error(transparent)]
    CommittedAfterSave(Box<StoreError>),
}

impl StoreError {
    /// `true` iff `self` is the [`StoreError::CommittedAfterSave`] wrapper.
    /// Typed-verb callers (`cli::revisions::typed_transition`) query this
    /// BEFORE mapping the error to an `OpError` so they can call
    /// [`crate::cli::CommitMarker::mark_committed`] on the boundary — the
    /// wrapper itself is unwrapped one layer at a time by
    /// [`crate::cli::map_store_err_preserving_noun`].
    pub fn is_committed_after_save(&self) -> bool {
        matches!(self, StoreError::CommittedAfterSave(_))
    }
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

    pub(crate) fn env_dir(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
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

    /// The materialized `greentic.runtime-config.v1` document that
    /// `greentic-start` loads at boot. Distinct from `runtime.json` (the
    /// `EnvironmentRuntime` host-config view).
    fn runtime_config_path(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.env_dir(env_id)?.join("runtime-config.json"))
    }

    /// `<env_dir>/update-channel.json` — the operator's update-channel policy
    /// ([`UpdateChannelConfig`], `§Phase 4`). Optional; an absent file resolves
    /// to disabled.
    fn update_channel_path(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.env_dir(env_id)?.join("update-channel.json"))
    }

    /// Load the operator's update-channel policy. Absent file → `Ok(None)`
    /// (callers resolve that to deny-by-default). Validates the env-id binding
    /// and schema discriminator, mirroring [`load_runtime`](EnvironmentStore::load_runtime).
    /// Inherent (not a trait method): the update channel is a local-runtime
    /// concern, so remote store backends need not carry it.
    pub fn load_update_channel(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<UpdateChannelConfig>, StoreError> {
        let path = self.update_channel_path(env_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let cfg: UpdateChannelConfig = self.read_json(&path)?;
        if cfg.environment_id != *env_id {
            return Err(StoreError::EnvIdMismatch {
                file: env_id.clone(),
                value: cfg.environment_id,
            });
        }
        if cfg.schema.as_str() != SchemaVersion::UPDATE_CHANNEL_V1 {
            return Err(StoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::UPDATE_CHANNEL_V1,
                actual: cfg.schema.as_str().to_string(),
            }));
        }
        Ok(Some(cfg))
    }

    /// Write the update-channel policy WITHOUT acquiring the env flock — the
    /// caller must already hold it (via [`LocalFsStore::transact`] / [`Locked`]).
    /// Backs up any prior file first, then writes atomically. There is
    /// deliberately no unlocked public `save_update_channel`: the sidecar is
    /// only ever written inside a locked transaction, so the read-modify-write
    /// in `op updates config-set` is free of lost updates (mirrors
    /// `save_runtime_locked`).
    fn save_update_channel_locked(&self, cfg: &UpdateChannelConfig) -> Result<(), StoreError> {
        let target = self.update_channel_path(&cfg.environment_id)?;
        copy_to_backup(&target, &self.backups_dir(&cfg.environment_id)?)?;
        atomic_write_json(&target, cfg)?;
        Ok(())
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

    /// `<env_dir>/messaging/` — directory holding per-endpoint projections.
    fn messaging_dir(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.env_dir(env_id)?.join("messaging"))
    }

    /// `<env_dir>/messaging/index.json` — projection enumerating every
    /// endpoint in source-of-truth order.
    fn messaging_index_path(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.messaging_dir(env_id)?.join("index.json"))
    }

    /// `<env_dir>/messaging/<endpoint_id>.json` — per-endpoint projection.
    fn messaging_endpoint_path(
        &self,
        env_id: &EnvId,
        endpoint_id: &MessagingEndpointId,
    ) -> Result<PathBuf, StoreError> {
        Ok(self
            .messaging_dir(env_id)?
            .join(format!("{endpoint_id}.json")))
    }

    /// Subdirectory under `backups/` for messaging projection snapshots.
    fn messaging_backups_dir(&self, env_id: &EnvId) -> Result<PathBuf, StoreError> {
        Ok(self.backups_dir(env_id)?.join("messaging"))
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

    /// Write the materialized runtime-config, skipping the backup+write when
    /// the on-disk file already matches. Re-materialization runs after every
    /// traffic mutation, but the projection only changes when `traffic_splits`
    /// does — the change-detection guard keeps no-op refreshes from churning
    /// backups.
    fn save_runtime_config_locked(&self, cfg: &RuntimeConfig) -> Result<(), StoreError> {
        let env_id = &cfg.env_id;
        let target = self.runtime_config_path(env_id)?;
        if let Ok(existing) = self.read_json::<RuntimeConfig>(&target)
            && &existing == cfg
        {
            return Ok(());
        }
        copy_to_backup(&target, &self.backups_dir(env_id)?)?;
        atomic_write_json(&target, cfg)?;
        Ok(())
    }

    /// Remove the runtime-config when no split routes any revision. B0 rejects
    /// a config with an empty `revisions` list, so absence — not an empty file
    /// — is the correct "nothing live" signal.
    fn delete_runtime_config_locked(&self, env_id: &EnvId) -> Result<(), StoreError> {
        let target = self.runtime_config_path(env_id)?;
        if target.exists() {
            copy_to_backup(&target, &self.backups_dir(env_id)?)?;
            std::fs::remove_file(&target).map_err(|source| StoreError::Io {
                path: target,
                source,
            })?;
        }
        Ok(())
    }

    /// Reconcile `<env_dir>/messaging/` against the just-saved env's
    /// `messaging_endpoints`. Writes one `<endpoint_id>.json` per endpoint
    /// (skipping no-op rewrites) plus an `index.json` enumerator, and removes
    /// per-endpoint files whose endpoint is no longer in the env.
    ///
    /// When the env has zero endpoints, the directory is left empty (after
    /// removing stale files) and `index.json` is deleted — absence is the
    /// "no endpoints" signal, mirroring the `runtime-config.json` precedent.
    fn refresh_messaging_locked(&self, env: &Environment) -> Result<(), StoreError> {
        let env_id = &env.environment_id;
        let dir = self.messaging_dir(env_id)?;
        // Snapshot existing endpoint files so we can prune anything not in
        // the new endpoint set. Pre-existing non-endpoint files (`index.json`,
        // unrelated dotfiles) are skipped.
        let mut existing_files: Vec<(MessagingEndpointId, PathBuf)> = Vec::new();
        if dir.exists() {
            for entry in std::fs::read_dir(&dir).map_err(|source| StoreError::Io {
                path: dir.clone(),
                source,
            })? {
                let entry = entry.map_err(|source| StoreError::Io {
                    path: dir.clone(),
                    source,
                })?;
                let path = entry.path();
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if stem == "index" {
                    continue;
                }
                let Ok(ulid) = stem.parse::<ulid::Ulid>() else {
                    continue;
                };
                existing_files.push((MessagingEndpointId(ulid), path));
            }
        }
        // Write each endpoint; track ids written so we can prune the rest.
        let mut written_ids: std::collections::HashSet<MessagingEndpointId> =
            std::collections::HashSet::with_capacity(env.messaging_endpoints.len());
        for endpoint in &env.messaging_endpoints {
            written_ids.insert(endpoint.endpoint_id);
            let target = self.messaging_endpoint_path(env_id, &endpoint.endpoint_id)?;
            if let Ok(existing) = self.read_json::<MessagingEndpoint>(&target)
                && existing == *endpoint
            {
                continue;
            }
            copy_to_backup(&target, &self.messaging_backups_dir(env_id)?)?;
            atomic_write_json(&target, endpoint)?;
        }
        for (id, path) in existing_files {
            if !written_ids.contains(&id) {
                copy_to_backup(&path, &self.messaging_backups_dir(env_id)?)?;
                std::fs::remove_file(&path).map_err(|source| StoreError::Io {
                    path: path.clone(),
                    source,
                })?;
            }
        }
        // Index file: rewrite when non-empty, delete when empty.
        let index_path = self.messaging_index_path(env_id)?;
        let index = super::messaging::materialize_messaging_index(env);
        if index.is_empty() {
            if index_path.exists() {
                copy_to_backup(&index_path, &self.messaging_backups_dir(env_id)?)?;
                std::fs::remove_file(&index_path).map_err(|source| StoreError::Io {
                    path: index_path,
                    source,
                })?;
            }
        } else {
            if let Ok(existing) =
                self.read_json::<Vec<super::messaging::MessagingEndpointIndexEntry>>(&index_path)
                && existing == index
            {
                return Ok(());
            }
            copy_to_backup(&index_path, &self.messaging_backups_dir(env_id)?)?;
            atomic_write_json(&index_path, &index)?;
        }
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

    pub fn load_update_channel(&self) -> Result<Option<UpdateChannelConfig>, StoreError> {
        self.store.load_update_channel(&self.env_id)
    }

    pub fn save_update_channel(&self, cfg: &UpdateChannelConfig) -> Result<(), StoreError> {
        if cfg.environment_id != self.env_id {
            return Err(StoreError::EnvIdMismatch {
                file: self.env_id.clone(),
                value: cfg.environment_id.clone(),
            });
        }
        self.store.save_update_channel_locked(cfg)
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

    /// Re-materialize `runtime-config.json` from `env`'s current traffic
    /// splits. Call with the just-saved env after any mutation that can change
    /// the `TrafficSplit` set, inside the same `transact` scope, so the file
    /// `greentic-start` boots from stays in lock-step with `environment.json`.
    /// Writes the projection, or deletes the file when no split routes a
    /// revision — `greentic-start` rejects a config with an empty `revisions`
    /// list, so absence is the correct "nothing live" signal.
    pub fn refresh_runtime_config(&self, env: &Environment) -> Result<(), StoreError> {
        let cfg = super::runtime_config::materialize_runtime_config(env);
        if cfg.revisions.is_empty() {
            self.store.delete_runtime_config_locked(&self.env_id)
        } else {
            self.store.save_runtime_config_locked(&cfg)
        }
    }

    /// Reconcile `<env_dir>/messaging/` against the just-saved env. Call
    /// after any mutation that can change `Environment.messaging_endpoints`
    /// (M1.2 add/update/remove verbs). Writes one file per endpoint plus an
    /// `index.json` enumerator; per-endpoint files for ids no longer in the
    /// env are pruned (with backup) and `index.json` is removed when the env
    /// has zero endpoints.
    pub fn refresh_messaging_projection(&self, env: &Environment) -> Result<(), StoreError> {
        if env.environment_id != self.env_id {
            return Err(StoreError::EnvIdMismatch {
                file: self.env_id.clone(),
                value: env.environment_id.clone(),
            });
        }
        self.store.refresh_messaging_locked(env)
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
