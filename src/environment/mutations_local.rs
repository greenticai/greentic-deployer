//! [`EnvironmentMutations`]-trait-shaped inherent methods on [`LocalFsStore`].
//!
//! Phase D PR-3a.2..3a.16 lands one verb group per PR here, each replacing
//! the matching `store.transact(env_id, |locked| …)` closure in `src/cli/*`
//! with a typed verb that can also be implemented by `HttpEnvironmentStore`
//! (PR-3b) over the A8 wire contract.
//!
//! The methods land as **inherent** (not the trait impl) so each PR can land
//! independently — Rust requires all trait methods to exist before a single
//! `impl EnvironmentMutations for LocalFsStore` block compiles. Once every
//! verb group has migrated (PR-3a.16), a trailing PR wires the trait impl as
//! thin forwarders.

use std::path::Path;

use chrono::Utc;
use greentic_distributor_client::signing::TrustedKey;

use greentic_deploy_spec::engine::{self, EngineError};
use greentic_deploy_spec::{
    BundleDeployment, BundleId, CapabilitySlot, DeploymentId, EnvId, EnvPackBinding, Environment,
    EnvironmentHostConfig, ExtensionBinding, HealthStatus, IdempotencyKey, MessagingEndpoint,
    MessagingEndpointId, RetentionPolicy, Revision, RevisionId, RevocationConfig, SchemaVersion,
    SecretRef,
};

use super::bootstrap::{
    EnsureLocalEnvironmentPayload, LocalEnvOutcome, fill_missing_default_bindings,
};
use super::lifecycle::LifecycleError;
use super::mutations::{
    AddBundlePayload, AddMessagingEndpointPayload, ApplyTrafficSplitOutcome, EnvironmentMutations,
    ExtensionKey, MigrateMergePayload, RemoveBundleOutcome, RevisionTransitionOutcome,
    RollbackTrafficSplitOutcome, SetMessagingWelcomeFlowPayload, SetTrafficSplitPayload,
    StageRevisionPayload, TrustRootAddOutcome, TrustRootRemoveOutcome, TrustRootSeed,
    UpdateBundlePayload, UpdateEnvironmentPayload, WarmRevisionPayload,
};
use super::store::{EnvironmentStore, LocalFsStore, StoreError};
use super::trust_root::{self as store_trust_root, trust_root_path};

/// Map a [`LifecycleError`] into `StoreError`, peeling `LifecycleError::Store`
/// so the original [`StoreError`] reaches callers unboxed.
fn fold_lifecycle_err(err: LifecycleError) -> StoreError {
    match err {
        LifecycleError::Store(inner) => inner,
        other => StoreError::Lifecycle(Box::new(other)),
    }
}

/// Map a pure-engine failure onto the local store's error surface. The
/// operator-store-server maps the same [`EngineError`]s onto
/// `RemoteStoreError` — both sides share the transform, each owns its
/// error vocabulary.
fn map_engine_err(err: EngineError) -> StoreError {
    match err {
        EngineError::NotFound(id) => StoreError::NotFound(id),
    }
}

/// Map a pure traffic-split failure onto the local store's error surface
/// (the operator-store-server maps the same errors onto
/// `RemoteStoreError`). Variant → noun choices preserve the pre-engine
/// behavior verbatim: referential misses are `DependentNotFound`, state /
/// protocol conflicts are `Conflict`, and spec-validation failures keep
/// their typed [`StoreError::Spec`] so the CLI's traffic mapper can peel
/// them back into `OpError::Spec`.
fn map_traffic_err(err: engine::TrafficSplitError) -> StoreError {
    use engine::TrafficSplitError as E;
    match err {
        E::DeploymentNotFound { .. }
        | E::RevisionNotFound { .. }
        | E::NoSplit { .. }
        | E::SnapshotMissing { .. } => StoreError::DependentNotFound(err.to_string()),
        E::WrongDeployment { .. }
        | E::IdempotencyKeyReused { .. }
        | E::AdmissionRevisionMissing { .. }
        | E::NotReady { .. }
        | E::SnapshotEncode { .. }
        | E::NoPreviousSnapshot { .. }
        | E::SnapshotDecode { .. } => StoreError::Conflict(err.to_string()),
        E::Invalid(spec) => StoreError::Spec(spec),
    }
}

/// Map a pure binding failure onto the local store's error surface,
/// preserving the kinds the pre-engine closures raised (PR-4.2d): a
/// missing slot / extension / stash payload is a dependent lookup miss;
/// everything else is an operator-resolvable conflict. `NotPackSlot` is
/// unreachable through the CLI (rejected upstream with its own message) —
/// it exists for the store-server's wire surface.
fn map_binding_err(err: engine::BindingError) -> StoreError {
    use engine::BindingError as E;
    match err {
        E::SlotNotBound { .. }
        | E::ExtensionNotBound { .. }
        | E::SlotSnapshotMissing { .. }
        | E::ExtensionSnapshotMissing { .. } => StoreError::DependentNotFound(err.to_string()),
        E::SlotAlreadyBound { .. }
        | E::SlotMismatch { .. }
        | E::NotPackSlot { .. }
        | E::SlotNoPrevious { .. }
        | E::SlotGenerationOverflow { .. }
        | E::ExtensionAlreadyBound { .. }
        | E::ExtensionKeyMismatch { .. }
        | E::ExtensionNoPrevious { .. }
        | E::ExtensionGenerationOverflow { .. }
        | E::SnapshotEncode { .. }
        | E::SnapshotDecode { .. } => StoreError::Conflict(err.to_string()),
    }
}

/// Map the engine's typed bundle errors onto the store surface. Messages
/// are verbatim (the engine moved them in PR-4.2g), so operator-facing CLI
/// errors are unchanged.
fn map_bundle_err(err: engine::BundleError) -> StoreError {
    use engine::BundleError as E;
    match err {
        E::DeploymentNotFound { .. } => StoreError::DependentNotFound(err.to_string()),
        E::AlreadyDeployed { .. } | E::StillLive { .. } => StoreError::Conflict(err.to_string()),
    }
}

/// Map the engine's typed messaging errors onto the store surface. Messages
/// are verbatim (the engine moved them in PR-4.2h), so operator-facing CLI
/// errors are unchanged. `SecretProvision` carries the dev-store sink's
/// message and keeps the `Conflict` noun this store raised before the move.
fn map_messaging_err(err: engine::MessagingError) -> StoreError {
    use engine::MessagingError as E;
    match err {
        E::EndpointNotFound { .. } | E::BundleNotDeployed { .. } => {
            StoreError::DependentNotFound(err.to_string())
        }
        E::IdempotencyKeyReuse { .. }
        | E::EndpointAlreadyExists { .. }
        | E::WelcomeFlowOwned { .. } => StoreError::Conflict(err.to_string()),
        E::BundleNotLinked { .. } | E::WelcomePackUnknown { .. } | E::InvalidSecretRef { .. } => {
            StoreError::InvalidArgument(err.to_string())
        }
        E::SecretProvision(message) => StoreError::Conflict(message),
    }
}

/// Derive the webhook-secret provisioning context from the env: the env's owning
/// tenant (`tenant_org_id`, trimmed; `None` when absent or blank) and whether the
/// secrets backend custodies values in the local dev-store (so the sink mints +
/// writes the value) versus an external backend like Vault (where the operator
/// seeds the value out-of-band and the sink only stamps the ref). Computed from
/// `env` before the `&mut env` engine call so the `provision` closure captures
/// owned values, not a borrow of `env`. The owner→tenant-segment mapping (and the
/// fail-closed rule for non-custodial backends with no owner) lives in
/// [`crate::cli::messaging::provision_webhook_secret`].
fn webhook_provision_ctx(env: &Environment) -> (Option<String>, bool) {
    let owner = env
        .host_config
        .tenant_org_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    (owner, crate::cli::env::secrets_backend_is_dev_store(env))
}

impl LocalFsStore {
    // -------------------------------------------------------------
    // Environment lifecycle  (PR-3a.3)
    //   `op env create | update | set-public-url`
    //   `op config set`
    // -------------------------------------------------------------

    /// Create a fresh environment with empty bundles/revisions/packs.
    /// Rejects (via [`StoreError::Conflict`]) if the env already exists —
    /// callers wanting upsert semantics should call
    /// [`Self::update_environment`].
    ///
    /// The caller's [`EnvironmentHostConfig::env_id`] is overwritten with
    /// `env_id` so the on-disk row's host-config envelope cannot disagree
    /// with the directory it lands in.
    pub fn create_environment(
        &self,
        env_id: &EnvId,
        name: String,
        host_config: EnvironmentHostConfig,
    ) -> Result<Environment, StoreError> {
        self.transact(env_id, |locked| {
            // Existence check must reject non-NotFound errors instead of
            // treating "load failed" as "env doesn't exist". A corrupt
            // `environment.json`, an env-id mismatch, or any I/O error
            // would otherwise fall through to fresh `Environment`
            // construction and overwrite the existing (recoverable) file
            // — silent data loss while reporting create success.
            match locked.load() {
                Ok(_) => {
                    return Err(StoreError::Conflict(format!(
                        "environment `{}` already exists",
                        locked.env_id()
                    )));
                }
                Err(StoreError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
            let env = engine::fresh_environment(
                locked.env_id(),
                name,
                host_config,
                RevocationConfig::default(),
                RetentionPolicy::default(),
                HealthStatus::default(),
            );
            locked.save(&env)?;
            Ok(env)
        })
    }

    /// Patch the named scalar fields on an existing env. [`FieldUpdate::Keep`]
    /// fields are skipped, [`FieldUpdate::Set`] writes the new value, and
    /// [`FieldUpdate::Clear`] resets an optional field to `None`. Returns the
    /// fully-updated [`Environment`]. Collapses what was previously split
    /// across the `op env update`, `op env set-public-url`, and `op config
    /// set` verbs — see [`UpdateEnvironmentPayload`] for the rationale.
    ///
    /// `StoreError::NotFound` passes through unchanged; the CLI mapper
    /// downcasts it to `OpError::NotFound` via
    /// [`crate::cli::map_store_err_preserving_noun`].
    pub fn update_environment(
        &self,
        env_id: &EnvId,
        patch: UpdateEnvironmentPayload,
    ) -> Result<Environment, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            engine::apply_environment_update(&mut env, patch);
            locked.save(&env)?;
            Ok(env)
        })
    }

    // -------------------------------------------------------------
    // Migration  (PR-3a.4)
    //   `op env migrate-dev --apply`
    // -------------------------------------------------------------

    /// Merge pack bindings and extension bindings into `target_env_id`,
    /// optionally seeding a fresh target env from a source when the target
    /// doesn't exist yet. All work runs under the target's flock so the
    /// existence check + optional seed + merge + save are atomic.
    ///
    /// Skips slots already in the target's `packs` and extension keys
    /// already in the target's `extensions` (uniqueness on
    /// `(kind.path(), instance_id)`). Returns `(merged_slot_names,
    /// merged_extension_key_strings)`.
    ///
    /// Returns `StoreError::NotFound` if target is missing AND
    /// `payload.seed_if_missing` is `None` (the caller asserted target
    /// presence).
    pub fn migrate_merge_bindings(
        &self,
        target_env_id: &EnvId,
        payload: MigrateMergePayload,
    ) -> Result<(Vec<String>, Vec<String>), StoreError> {
        let MigrateMergePayload {
            packs,
            extensions,
            seed_if_missing,
        } = payload;
        self.transact(target_env_id, |locked| {
            let existing = match locked.load() {
                Ok(env) => Some(env),
                Err(StoreError::NotFound(_)) => None,
                Err(e) => return Err(e),
            };
            let mut target_env =
                engine::seed_or_existing(existing, locked.env_id(), seed_if_missing)
                    .map_err(map_engine_err)?;
            // Extension bindings (`Path 3`) are light, referentially
            // independent state — like `packs`, they migrate.
            // (`messaging_endpoints` are NOT migrated: they reference
            // `linked_bundles` that don't migrate, so a blind copy would
            // break referential integrity.)
            let report = engine::merge_bindings(&mut target_env, packs, extensions);
            locked.save(&target_env)?;
            Ok((report.merged_slots, report.merged_extensions))
        })
    }

    // -------------------------------------------------------------
    // Revision lifecycle — stage  (PR-3a.5)
    //   `op revisions stage`
    //   warm/drain/archive land in PR-3a.6
    // -------------------------------------------------------------

    /// Stage a fresh revision under `payload.deployment_id`. The caller
    /// supplies the pre-resolved artifact pointers (`bundle_digest`,
    /// `pack_list`, `pack_list_lock_ref`, `pack_config_refs`) and a
    /// pre-minted [`RevisionId`] — bundle staging (extract + lock-pin +
    /// pack-config materialization) runs OUTSIDE the env flock because
    /// the `rev_dir` is named after the ULID and the extraction cost
    /// shouldn't hold the lock.
    ///
    /// Inside the flock: load → re-validate deployment exists →
    /// compute `next_sequence = max(existing[deployment]) + 1` → build
    /// `Revision` (Staged) → push → save.
    ///
    /// Returns [`StoreError::DependentNotFound`] when the deployment is
    /// missing under the env at lock-acquisition time (closes the
    /// TOCTOU window over any pre-call lookup the caller may have done
    /// for input validation).
    ///
    /// `payload.idempotency_key` is accepted for trait conformance and
    /// ignored locally; the HTTP backend caches it for A8 §2 replay.
    pub fn stage_revision(
        &self,
        env_id: &EnvId,
        payload: StageRevisionPayload,
        _idempotency_key: IdempotencyKey,
    ) -> Result<Revision, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let revision = engine::stage_revision(&mut env, payload, Utc::now())
                .map_err(|err| fold_lifecycle_err(err.into()))?;
            locked.save(&env)?;
            Ok(revision)
        })
    }

    /// Drive a revision through the `Staged → Warming → Ready` chain and
    /// apply the client-evaluated warm/ready health-gate outcome. The
    /// chain advance, the `warmed_at` stamp, the gate-result application
    /// (Ready on `Ok(())`; Failed on `Err(failure)`, persisted), and the
    /// `runtime-config.json` refresh all happen inside one
    /// [`super::store::LocalFsStore::transact`] flock so the on-disk env
    /// is durable when the call returns.
    ///
    /// The lifecycle precondition (`payload.expected_lifecycle`, PR-3a.6b),
    /// the chain constants, and the gate semantics live in
    /// [`engine::warm_revision`] — shared verbatim with the
    /// operator-store-server.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn warm_revision(
        &self,
        env_id: &EnvId,
        payload: WarmRevisionPayload,
        _idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        self.run_revision_transition(env_id, |env| {
            engine::warm_revision(env, payload, Utc::now())
        })
    }

    /// Transition a `Ready` revision to `Draining`. Pure lifecycle stamp —
    /// the in-flight drain dance (sessions, WebSocket cleanup) is owned by
    /// `greentic-start`.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn drain_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        _idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        self.run_revision_transition(env_id, |env| engine::drain_revision(env, revision_id))
    }

    /// Archive a revision, walking any of `Staged | Warming | Ready | Failed`
    /// to `Archived` in one hop and the post-drain `Draining → Inactive →
    /// Archived` walk end-to-end. Refuses if the revision still routes live
    /// traffic — callers rebalance via `gtc op traffic set` first.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn archive_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        _idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        self.run_revision_transition(env_id, |env| engine::archive_revision(env, revision_id))
    }

    /// Shared transact body for warm/drain/archive: load the env, drive the
    /// pure engine transform, persist per the engine's rule (`Ok` and
    /// `env_mutated` errors — the gate-failed flip to `Failed` — save;
    /// every other error discards), refresh the materialized runtime
    /// config, return the typed outcome.
    ///
    /// The engine reports `starting_lifecycle` (the archive
    /// eviction-vs-retirement discriminator in
    /// `cli::revisions::emit_for_op`) — `archive`'s chain can traverse
    /// `Draining → Inactive → Archived` end-to-end in one call, so the
    /// final lifecycle alone can't tell whether the eviction hop fired.
    fn run_revision_transition<F>(
        &self,
        env_id: &EnvId,
        apply: F,
    ) -> Result<RevisionTransitionOutcome, StoreError>
    where
        F: FnOnce(
            &mut Environment,
        ) -> Result<engine::RevisionTransition, engine::RevisionLifecycleError>,
    {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let transition = match apply(&mut env) {
                Ok(transition) => {
                    locked.save(&env)?;
                    transition
                }
                Err(err) if err.env_mutated() => {
                    // Gate failure: the revision was flipped to `Failed` in
                    // memory; persist before surfacing (committed-on-error,
                    // the CLI's mark_committed contract relies on it).
                    locked.save(&env)?;
                    return Err(fold_lifecycle_err(err.into()));
                }
                Err(err) => return Err(fold_lifecycle_err(err.into())),
            };
            // From here on the env mutation is durable on disk. Any
            // subsequent failure (materialized runtime-config refresh) is
            // committed-on-error and MUST be surfaced as
            // `StoreError::CommittedAfterSave` so the CLI audit boundary
            // fails-closed on an audit-append failure.
            //
            // Lifecycle transitions don't change traffic splits today, so
            // the refresh is a no-op-guarded by change-detection; it
            // keeps the runtime-config contract uniform across every
            // mutating verb.
            locked
                .refresh_runtime_config(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(RevisionTransitionOutcome {
                revision: transition.revision,
                environment: env,
                starting_lifecycle: transition.starting_lifecycle,
            })
        })
    }

    // -------------------------------------------------------------
    // Bundle deployment CRUD  (PR-3a.7 + PR-3a.7b)
    //   `op bundles add | update | remove`
    // -------------------------------------------------------------

    /// Add a [`BundleDeployment`] to the env. Rejects with
    /// [`StoreError::Conflict`] when `(bundle_id, customer_id)` is already
    /// deployed (verb semantics live in [`engine::add_bundle`]). Writes the
    /// v1 revenue-policy sidecar via
    /// [`super::write_revenue_policy_version`] and pins the resulting ref
    /// on the deployment.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn add_bundle(
        &self,
        env_id: &EnvId,
        payload: AddBundlePayload,
        _idempotency_key: IdempotencyKey,
    ) -> Result<BundleDeployment, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let idx = engine::add_bundle(
                &mut env,
                payload,
                crate::environment::mint_deployment_id(),
                Utc::now(),
            )
            .map_err(map_bundle_err)?;
            let operator_key = crate::operator_key::load_existing_only()?;
            let version = crate::environment::write_revenue_policy_version(
                &env_dir,
                &env.bundles[idx],
                &env.bundles[idx].revenue_share,
                env.bundles[idx].created_at,
                &operator_key,
            )?;
            env.bundles[idx].revenue_policy_ref = version.policy_ref;
            locked.save(&env)?;
            Ok(env.bundles[idx].clone())
        })
    }

    /// Patch a [`BundleDeployment`]'s scalar fields. `None` fields are
    /// skipped (verb semantics live in [`engine::update_bundle`]). When
    /// `revenue_share` is `Some`, writes a new signed/versioned
    /// revenue-policy sidecar (chain-linked to the prior version) and pins
    /// the new ref on the deployment.
    ///
    /// Returns [`StoreError::DependentNotFound`] when `deployment_id` is
    /// absent under the env at lock-acquisition time.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn update_bundle(
        &self,
        env_id: &EnvId,
        payload: UpdateBundlePayload,
        _idempotency_key: IdempotencyKey,
    ) -> Result<BundleDeployment, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let applied = engine::update_bundle(&mut env, payload).map_err(map_bundle_err)?;
            if applied.revenue_share_changed {
                let idx = applied.index;
                let created_at = Utc::now();
                let operator_key = crate::operator_key::load_existing_only()?;
                let version = crate::environment::write_revenue_policy_version(
                    &env_dir,
                    &env.bundles[idx],
                    &env.bundles[idx].revenue_share,
                    created_at,
                    &operator_key,
                )?;
                env.bundles[idx].revenue_policy_ref = version.policy_ref;
            }
            locked.save(&env)?;
            Ok(env.bundles[applied.index].clone())
        })
    }

    /// Remove a [`BundleDeployment`] from the env. Refuses with
    /// [`StoreError::Conflict`] if the deployment still carries live state
    /// (any [`greentic_deploy_spec::TrafficSplit`] pointing at it, or any
    /// non-`Archived` revision under it) — callers run `op traffic clear`
    /// and archive revisions first. Drops archived revisions for the same
    /// `deployment_id` so the env stays compact. Verb semantics live in
    /// [`engine::remove_bundle`]; this wrapper owns the flock + persistence.
    ///
    /// Returns [`StoreError::DependentNotFound`] when the deployment is
    /// absent under the env at lock-acquisition time (matches the
    /// `DependentNotFound` precedent set by `stage_revision`).
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn remove_bundle(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        _idempotency_key: IdempotencyKey,
    ) -> Result<RemoveBundleOutcome, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let outcome = engine::remove_bundle(&mut env, deployment_id).map_err(map_bundle_err)?;
            locked.save(&env)?;
            Ok(outcome)
        })
    }

    // -------------------------------------------------------------
    // Env-pack binding CRUD  (PR-3a.8)
    //   `op env-packs add | update | remove | rollback`
    // -------------------------------------------------------------

    /// Bind a new env-pack slot. Rejects with [`StoreError::Conflict`]
    /// when the slot is already bound (callers should `update` instead).
    /// Verb semantics live in [`engine::add_pack_binding`]; this wrapper
    /// owns the flock + persistence.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn add_pack_binding(
        &self,
        env_id: &EnvId,
        binding: EnvPackBinding,
        _idempotency_key: IdempotencyKey,
    ) -> Result<EnvPackBinding, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let added = engine::add_pack_binding(&mut env, binding).map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok(added)
        })
    }

    /// Replace the binding on an existing slot. The engine snapshots the
    /// prior binding inline (one-step-rollback stash) — see
    /// [`engine::update_pack_binding`].
    ///
    /// Returns `(new_binding, new_generation)`.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn update_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        binding: EnvPackBinding,
        _idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let (updated, new_generation) =
                engine::update_pack_binding(&mut env, slot, binding).map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok((updated, new_generation))
        })
    }

    /// Remove a pack-binding slot. Returns `(removed_binding,
    /// removed_generation)`.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn remove_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        _idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let (removed, generation) =
                engine::remove_pack_binding(&mut env, slot).map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok((removed, generation))
        })
    }

    /// Rollback a pack-binding slot to its one-step-previous snapshot.
    /// Returns `(restored_binding, new_generation)`. Fails with
    /// [`StoreError::DependentNotFound`] when the slot doesn't exist
    /// and [`StoreError::Conflict`] when there is no previous snapshot
    /// to restore.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn rollback_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        _idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let (restored, new_generation) =
                engine::rollback_pack_binding(&mut env, slot).map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok((restored, new_generation))
        })
    }

    // -------------------------------------------------------------
    // Trust root  (PR-3a.2)
    //   `op env trust-root bootstrap | add | remove`
    //   `op env init` calls `seed_trust_root_if_absent` for first-init only.
    // -------------------------------------------------------------

    /// Unconditional re-grant: load (or generate) the operator key and add
    /// it to the env trust root. Idempotent on case-insensitive key_id
    /// collision — the existing entry's PEM is overwritten with whatever
    /// the operator-key file holds today.
    ///
    /// **Lock placement.** `operator_key::load_or_generate` runs OUTSIDE the
    /// env flock so a slow OS RNG seed does not hold the lock; the trust-root
    /// mutation runs INSIDE the flock so concurrent `add`/`remove` cannot
    /// race the read-modify-write. Caller is responsible for any authz gate
    /// before invoking this method — `~/.greentic/operator/key.pem` is
    /// generated on first call to `load_or_generate`, so an authz failure
    /// after this method runs would not roll back that side effect.
    pub fn bootstrap_trust_root(&self, env_id: &EnvId) -> Result<TrustRootSeed, StoreError> {
        let op_key = crate::operator_key::load_or_generate()?;
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |_locked| seed_op_key(&env_dir, op_key))
    }

    /// First-init-only variant: returns `None` when `<env_dir>/trust-root.json`
    /// already exists (operator has touched the trust root via
    /// bootstrap/add/remove). The existence check and `load_or_generate` both
    /// sit under the env flock so a concurrent `trust-root remove` cannot race
    /// the gate, and `~/.greentic/operator/key.pem` is not auto-generated when
    /// the gate would skip.
    pub fn seed_trust_root_if_absent(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<TrustRootSeed>, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        let tr_path = trust_root_path(&env_dir);
        self.transact(env_id, |_locked| {
            if tr_path.exists() {
                return Ok(None);
            }
            let op_key = crate::operator_key::load_or_generate()?;
            seed_op_key(&env_dir, op_key).map(Some)
        })
    }

    /// Add a trusted (key_id, public_key_pem) entry to the env trust root.
    /// Validates `key_id` matches the canonical derivation from `pem` and
    /// rejects empty/whitespace key ids. Idempotent on case-insensitive
    /// `key_id` collision.
    ///
    /// `_idempotency_key` is accepted for trait-conformance with
    /// [`super::mutations::EnvironmentMutations::add_trusted_key`] and
    /// ignored locally — the HTTP backend caches it for A8 §2 replay.
    pub fn add_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        public_key_pem: String,
        _idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootAddOutcome, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |_locked| {
            let trust = store_trust_root::add_trusted_key(
                &env_dir,
                TrustedKey {
                    key_id: key_id.clone(),
                    public_key_pem,
                },
            )?;
            Ok(TrustRootAddOutcome {
                added_key_id: key_id,
                trusted_key_count: trust.keys.len(),
            })
        })
    }

    /// Remove a trusted key by case-insensitive `key_id`. Silent no-op when
    /// the id is absent. Captures the pre-state PEM under the flock for
    /// race-safe recovery reporting.
    ///
    /// `_idempotency_key` is accepted for trait-conformance with
    /// [`super::mutations::EnvironmentMutations::remove_trusted_key`] and
    /// ignored locally. The HTTP backend MUST cache and replay the original
    /// outcome so retries don't surface `removed_public_key_pem: None` (the
    /// failure mode that motivated requiring the key).
    pub fn remove_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        _idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootRemoveOutcome, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |_locked| {
            let pre = store_trust_root::load(&env_dir)?;
            let removed_public_key_pem = pre
                .keys
                .iter()
                .find(|k| k.key_id.eq_ignore_ascii_case(&key_id))
                .map(|k| k.public_key_pem.clone());
            let trust = store_trust_root::remove_trusted_key(&env_dir, &key_id)?;
            Ok(TrustRootRemoveOutcome {
                removed_key_id: key_id,
                removed_public_key_pem,
                trusted_key_count: trust.keys.len(),
            })
        })
    }

    // -------------------------------------------------------------
    // Extension binding CRUD  (PR-3a.9)
    //   `op extensions add | update | remove | rollback`
    // -------------------------------------------------------------

    /// Add a new extension binding to the env. Rejects with
    /// [`StoreError::Conflict`] if a binding with the same
    /// `(kind.path(), instance_id)` key already exists — callers wanting
    /// to replace use [`Self::update_extension_binding`]. Verb semantics
    /// live in [`engine::add_extension_binding`].
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn add_extension_binding(
        &self,
        env_id: &EnvId,
        binding: ExtensionBinding,
        _idempotency_key: IdempotencyKey,
    ) -> Result<ExtensionBinding, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let added =
                engine::add_extension_binding(&mut env, binding).map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok(added)
        })
    }

    /// Replace an existing extension binding identified by `key`. The
    /// engine bumps `generation` and stashes the prior binding inline so
    /// [`Self::rollback_extension_binding`] can restore it — see
    /// [`engine::update_extension_binding`].
    ///
    /// Returns `(new_binding, new_generation)`.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn update_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        binding: ExtensionBinding,
        _idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let (updated, new_generation) =
                engine::update_extension_binding(&mut env, &key, binding)
                    .map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok((updated, new_generation))
        })
    }

    /// Remove an extension binding identified by `key`. Returns the removed
    /// binding and its generation at the time of removal.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn remove_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        _idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let (removed, generation) =
                engine::remove_extension_binding(&mut env, &key).map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok((removed, generation))
        })
    }

    /// Rollback an extension binding to its previous version. Requires the
    /// binding to have a stashed `previous_binding_ref`. Bumps generation
    /// and clears the stash so a second rollback fails (single-step only).
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn rollback_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        _idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let (restored, new_generation) =
                engine::rollback_extension_binding(&mut env, &key).map_err(map_binding_err)?;
            locked.save(&env)?;
            Ok((restored, new_generation))
        })
    }

    // -------------------------------------------------------------
    // Traffic split  (PR-3a.11)
    //   `op traffic set | rollback`
    // -------------------------------------------------------------

    /// Replace the entire traffic-split entry list for one deployment.
    /// Pure semantics (10,000 bps sum invariant, §5.3 admission, the
    /// idempotency contract, the one-step rollback stash) live in
    /// [`engine::set_traffic_split`]; this wrapper owns persistence and the
    /// derived `runtime-config.json`.
    ///
    /// Post-save, the materialized `runtime-config.json` is refreshed. A
    /// failure there wraps as [`StoreError::CommittedAfterSave`] so the CLI
    /// audit fires for the already-persisted mutation. The idempotent no-op
    /// replay skips the save but still reconciles runtime-config (repairs a
    /// prior publish failure) — a refresh failure there is NOT
    /// committed-after-save, because nothing new was committed.
    ///
    /// `TrafficSplitApplied` telemetry is emitted by the CLI layer from the
    /// outcome's env snapshot (identical local and remote), not here.
    pub fn set_traffic_split(
        &self,
        env_id: &EnvId,
        payload: SetTrafficSplitPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<ApplyTrafficSplitOutcome, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let transition =
                engine::set_traffic_split(&mut env, payload, &idempotency_key, Utc::now())
                    .map_err(map_traffic_err)?;
            if transition.mutated() {
                locked.save(&env)?;
                // From here on the env mutation is durable on disk. Any
                // subsequent failure (runtime-config refresh) wraps as
                // `CommittedAfterSave` so the CLI audit fires for the
                // already-persisted mutation.
                locked
                    .refresh_runtime_config(&env)
                    .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            } else {
                // No-op replay. Reconcile the derived runtime-config before
                // returning so a retry repairs a publish that failed after
                // environment.json was already durable.
                locked.refresh_runtime_config(&env)?;
            }
            Ok(ApplyTrafficSplitOutcome {
                split: transition.split,
                previous_generation: transition.previous_generation,
                new_generation: transition.new_generation,
                environment: env,
            })
        })
    }

    /// Rollback the traffic split for a deployment to its one-step-previous
    /// snapshot. Pure semantics live in [`engine::rollback_traffic_split`];
    /// this wrapper owns persistence and the `runtime-config.json` refresh
    /// (wrapped as [`StoreError::CommittedAfterSave`] post-save).
    ///
    /// Returns [`StoreError::DependentNotFound`] when no split exists for
    /// the deployment, and [`StoreError::Conflict`] when there is no
    /// previous snapshot to restore.
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn rollback_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        _idempotency_key: IdempotencyKey,
    ) -> Result<RollbackTrafficSplitOutcome, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let transition = engine::rollback_traffic_split(&mut env, deployment_id, Utc::now())
                .map_err(map_traffic_err)?;
            locked.save(&env)?;
            // From here on the env mutation is durable on disk.
            locked
                .refresh_runtime_config(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(RollbackTrafficSplitOutcome {
                restored: transition.restored,
                previous_generation: transition.previous_generation,
                new_generation: transition.new_generation,
                environment: env,
            })
        })
    }

    // -------------------------------------------------------------
    // Messaging endpoint CRUD  (PR-3a.10, engine rewire PR-4.2h)
    //   `op messaging endpoint add | link-bundle | unlink-bundle
    //                  | set-welcome-flow | remove | rotate-webhook-secret`
    //
    // The verb semantics live in `greentic_deploy_spec::engine::messaging`
    // (shared with the operator-store-server). This impl supplies the env
    // flock, the dev-store webhook-secret sink, and the derived
    // `<env_dir>/messaging/` projection refresh — the projection runs on
    // EVERY outcome (including engine no-op replays) because it also
    // repairs a stale projection from a prior failed call.
    // -------------------------------------------------------------

    /// Add a messaging endpoint. Rejects with [`StoreError::Conflict`] when
    /// the `(provider_type, provider_id)` pair is already present or when the
    /// idempotency key was already used for a different endpoint identity.
    /// Idempotent on same-key same-identity replay (repairs a stale
    /// projection from a prior failed call).
    ///
    /// Telegram-class providers auto-generate a webhook secret at creation
    /// time via [`crate::cli::messaging::provision_webhook_secret`].
    pub fn add_messaging_endpoint(
        &self,
        env_id: &EnvId,
        payload: AddMessagingEndpointPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let eid = MessagingEndpointId::new();
            let (owner, custodial) = webhook_provision_ctx(&env);
            let applied = engine::add_messaging_endpoint(
                &mut env,
                payload,
                eid,
                &idempotency_key,
                Utc::now(),
                |existing| {
                    self.provision_webhook_secret_sink(
                        env_id,
                        &eid,
                        owner.as_deref(),
                        custodial,
                        existing,
                    )
                },
            )
            .map_err(map_messaging_err)?;
            self.finish_messaging_mutation(locked, &env, applied)
        })
    }

    /// Link a bundle to an existing messaging endpoint. Idempotent when the
    /// bundle is already linked (repairs a stale projection). Rejects with
    /// [`StoreError::DependentNotFound`] when the endpoint or bundle is
    /// missing.
    pub fn link_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let applied = engine::link_messaging_bundle(
                &mut env,
                endpoint_id,
                bundle_id,
                &updated_by,
                &idempotency_key,
                Utc::now(),
            )
            .map_err(map_messaging_err)?;
            self.finish_messaging_mutation(locked, &env, applied)
        })
    }

    /// Unlink a bundle from an existing messaging endpoint. Idempotent when
    /// the bundle is not linked (repairs a stale projection). Rejects with
    /// [`StoreError::Conflict`] if the bundle owns the endpoint's
    /// `welcome_flow`.
    pub fn unlink_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let applied = engine::unlink_messaging_bundle(
                &mut env,
                endpoint_id,
                bundle_id,
                &updated_by,
                &idempotency_key,
                Utc::now(),
            )
            .map_err(map_messaging_err)?;
            self.finish_messaging_mutation(locked, &env, applied)
        })
    }

    /// Set the welcome flow on a messaging endpoint. Rejects with
    /// [`StoreError::InvalidArgument`] when the bundle is not linked, or when
    /// `pack_id` does not appear in any current revision's pack_list.
    /// Idempotent when the same welcome flow ref is already set (repairs a
    /// stale projection).
    pub fn set_messaging_welcome_flow(
        &self,
        env_id: &EnvId,
        payload: SetMessagingWelcomeFlowPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let applied =
                engine::set_messaging_welcome_flow(&mut env, payload, &idempotency_key, Utc::now())
                    .map_err(map_messaging_err)?;
            self.finish_messaging_mutation(locked, &env, applied)
        })
    }

    /// Remove a messaging endpoint by id. Idempotent when the endpoint is
    /// already absent (repairs a stale projection). Returns the id of the
    /// removed endpoint.
    pub fn remove_messaging_endpoint(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
    ) -> Result<MessagingEndpointId, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            if engine::remove_messaging_endpoint(&mut env, endpoint_id) {
                locked.save(&env)?;
            }
            // Refresh runs even on the absent-endpoint no-op: it repairs a
            // stale projection from a prior failed call.
            locked
                .refresh_messaging_projection(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(endpoint_id)
        })
    }

    /// Rotate the webhook secret for a messaging endpoint. Generates a new
    /// CSPRNG secret value, writes it to the dev-store under the existing
    /// (or freshly-built) secret ref URI, and bumps generation.
    /// Idempotent on same-idem-key replay (returns the existing endpoint
    /// without re-generating).
    pub fn rotate_messaging_webhook_secret(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let (owner, custodial) = webhook_provision_ctx(&env);
            // The control plane can only rotate a value it custodies (the local
            // dev-store). For an external backend (e.g. Vault) the value lives in
            // the backend and is rotated out-of-band, so fail closed rather than
            // bump generation and report success without changing anything.
            if !custodial {
                return Err(StoreError::Conflict(format!(
                    "cannot rotate a webhook secret on a non-dev-store secrets backend from the \
                     control plane (env `{}`); rotate the value in the secrets backend and \
                     re-seed it (e.g. via `op secrets put`)",
                    env_id.as_str()
                )));
            }
            let applied = engine::rotate_messaging_webhook_secret(
                &mut env,
                endpoint_id,
                &updated_by,
                &idempotency_key,
                Utc::now(),
                // The local store mints its own value; it never threads a
                // caller-supplied ref (the CLI rejects one).
                None,
                |existing| {
                    self.provision_webhook_secret_sink(
                        env_id,
                        &endpoint_id,
                        owner.as_deref(),
                        custodial,
                        existing,
                    )
                },
            )
            .map_err(map_messaging_err)?;
            self.finish_messaging_mutation(locked, &env, applied)
        })
    }

    /// The LocalFS webhook-secret sink for the engine's `provision` seam: build
    /// the ref under the env `owner` (or `default` for an ownerless custodial
    /// env) and, when `custodial`, mint a CSPRNG value and write it into the
    /// env-pack dev-store via [`crate::cli::messaging::provision_webhook_secret`].
    /// A non-custodial backend with no `owner` fails closed there. Failures map to
    /// [`engine::MessagingError::SecretProvision`], which
    /// [`map_messaging_err`] folds back onto the `Conflict` noun this store
    /// raised before the engine rewire.
    fn provision_webhook_secret_sink(
        &self,
        env_id: &EnvId,
        endpoint_id: &MessagingEndpointId,
        owner: Option<&str>,
        custodial: bool,
        existing_ref: Option<&SecretRef>,
    ) -> Result<SecretRef, engine::MessagingError> {
        crate::cli::messaging::provision_webhook_secret(
            self,
            env_id,
            endpoint_id,
            owner,
            custodial,
            existing_ref,
        )
        .map_err(|e| engine::MessagingError::SecretProvision(e.to_string()))
    }

    /// Shared tail of every endpoint-returning messaging verb: persist when
    /// the engine actually mutated, refresh the derived projection on EVERY
    /// outcome (no-op replays repair a stale projection from a prior failed
    /// call), and clone the affected endpoint out.
    fn finish_messaging_mutation(
        &self,
        locked: &super::store::Locked<'_>,
        env: &Environment,
        applied: engine::MessagingApplied,
    ) -> Result<MessagingEndpoint, StoreError> {
        if applied.mutated {
            locked.save(env)?;
        }
        let ep = env.messaging_endpoints[applied.index].clone();
        locked
            .refresh_messaging_projection(env)
            .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
        Ok(ep)
    }

    // -------------------------------------------------------------
    // Bootstrap  (PR-3a.12)
    //   `op env init` — idempotent first-run bootstrap
    // -------------------------------------------------------------

    /// Get-or-create-with-heal: idempotent first-run bootstrap of the `local`
    /// [`Environment`] with default env-pack bindings. Returns the env + an
    /// outcome variant indicating whether it was Created, Healed (default
    /// bindings added), or AlreadyExists (no change needed).
    ///
    /// The entire read-modify-write runs inside [`LocalFsStore::transact`], so
    /// concurrent first-run invocations on the same host serialize on the
    /// per-env flock and produce a single env.
    ///
    /// `refresh_local_runtime_stub` is NOT called here — the CLI layer runs
    /// it after the verb returns, outside the flock. The tiny race window
    /// (another writer could modify the env between verb-return and
    /// stub-refresh) is acceptable because the runtime stub is a derived
    /// projection that self-heals on every bootstrap call.
    ///
    /// This verb is **not** part of the [`super::mutations::EnvironmentMutations`]
    /// trait — bootstrap is `LocalFsStore`-specific. Remote stores don't run
    /// first-run local bootstrap.
    pub fn ensure_local_environment(
        &self,
        env_id: &EnvId,
        payload: EnsureLocalEnvironmentPayload,
    ) -> Result<(Environment, LocalEnvOutcome), StoreError> {
        self.transact(env_id, |locked| {
            match locked.load() {
                Ok(mut existing) => {
                    // The URL is only applied on creation; overwriting an
                    // existing env's URL goes through `op env set-public-url`.
                    if payload.public_base_url.is_some() {
                        return Err(StoreError::InvalidArgument(format!(
                            "env `{}` already exists; use `op env set-public-url <env_id> <URL>` \
                             to overwrite the persisted public URL",
                            locked.env_id()
                        )));
                    }
                    let added = fill_missing_default_bindings(&mut existing)?;
                    if added.is_empty() {
                        return Ok((existing, LocalEnvOutcome::AlreadyExists));
                    }
                    locked.save(&existing)?;
                    Ok((existing, LocalEnvOutcome::Healed { added_slots: added }))
                }
                Err(StoreError::NotFound(_)) => {
                    let packs = crate::defaults::local_pack_bindings().map_err(|e| {
                        StoreError::InvalidArgument(format!("default pack binding parse: {e}"))
                    })?;
                    let env = Environment {
                        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
                        environment_id: locked.env_id().clone(),
                        name: env_id.as_str().to_string(),
                        host_config: EnvironmentHostConfig {
                            env_id: locked.env_id().clone(),
                            region: None,
                            tenant_org_id: None,
                            listen_addr: Some(greentic_deploy_spec::DEFAULT_LISTEN_ADDR),
                            public_base_url: payload.public_base_url.clone(),
                            gui_enabled: None,
                        },
                        packs,
                        credentials_ref: None,
                        bundles: Vec::new(),
                        revisions: Vec::new(),
                        traffic_splits: Vec::new(),
                        messaging_endpoints: Vec::new(),
                        extensions: Vec::new(),
                        revocation: Default::default(),
                        retention: Default::default(),
                        health: Default::default(),
                    };
                    locked.save(&env)?;
                    Ok((env, LocalEnvOutcome::Created))
                }
                Err(e) => Err(e),
            }
        })
    }
}

// Endpoint lookup and welcome-flow pack_id validation moved to
// `greentic_deploy_spec::engine::messaging` (PR-4.2h) so the
// operator-store-server validates identically.

// `fresh_environment` moved to `greentic_deploy_spec::engine` (PR-4.2a) so
// the operator-store-server seeds envs identically.

/// Persist `op_key` as a trusted entry on `env_dir`'s trust root and shape
/// the typed [`TrustRootSeed`] outcome. Shared body of `bootstrap_trust_root`
/// and `seed_trust_root_if_absent` — invariant is that the env flock is held
/// at the call site (both callers wrap in `self.transact`).
fn seed_op_key(
    env_dir: &Path,
    op_key: crate::operator_key::OperatorKey,
) -> Result<TrustRootSeed, StoreError> {
    let trust = store_trust_root::add_trusted_key(
        env_dir,
        TrustedKey {
            key_id: op_key.key_id.clone(),
            public_key_pem: op_key.public_pem.clone(),
        },
    )?;
    Ok(TrustRootSeed {
        key_id: op_key.key_id,
        public_key_pem: op_key.public_pem,
        trusted_key_count: trust.keys.len(),
    })
}

// ---------------------------------------------------------------------------
// Trait impl — thin forwarders to the inherent methods above.
//
// PR-3a.16: every inherent method landed independently (PR-3a.2..3a.15);
// now that all 30 exist, this block wires the `EnvironmentMutations` trait
// so callers can use `dyn EnvironmentMutations` / generic `T: EnvironmentMutations`.
// ---------------------------------------------------------------------------

impl EnvironmentMutations for LocalFsStore {
    /// See [`LocalFsStore::create_environment`].
    fn create_environment(
        &self,
        env_id: &EnvId,
        name: String,
        host_config: EnvironmentHostConfig,
    ) -> Result<Environment, StoreError> {
        self.create_environment(env_id, name, host_config)
    }

    /// See [`LocalFsStore::update_environment`].
    fn update_environment(
        &self,
        env_id: &EnvId,
        patch: UpdateEnvironmentPayload,
    ) -> Result<Environment, StoreError> {
        self.update_environment(env_id, patch)
    }

    /// Reads the persisted env via [`EnvironmentStore::load`] — the trait's
    /// one read verb, surfaced here so `&dyn EnvironmentMutations` callers
    /// (the remote dispatch) can evaluate client-side preconditions.
    fn load_environment(&self, env_id: &EnvId) -> Result<Environment, StoreError> {
        EnvironmentStore::load(self, env_id)
    }

    /// A seeded env has the trust-root file present — the seed/add paths always
    /// write ≥1 key, mirroring the `tr_path.exists()` check in
    /// [`LocalFsStore::seed_trust_root_if_absent`].
    fn trust_root_is_seeded(&self, env_id: &EnvId) -> Result<bool, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        Ok(trust_root_path(&env_dir).exists())
    }

    /// See [`LocalFsStore::migrate_merge_bindings`].
    fn migrate_merge_bindings(
        &self,
        target_env_id: &EnvId,
        payload: MigrateMergePayload,
    ) -> Result<(Vec<String>, Vec<String>), StoreError> {
        self.migrate_merge_bindings(target_env_id, payload)
    }

    /// See [`LocalFsStore::stage_revision`].
    fn stage_revision(
        &self,
        env_id: &EnvId,
        payload: StageRevisionPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<Revision, StoreError> {
        self.stage_revision(env_id, payload, idempotency_key)
    }

    /// See [`LocalFsStore::warm_revision`].
    fn warm_revision(
        &self,
        env_id: &EnvId,
        payload: WarmRevisionPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        self.warm_revision(env_id, payload, idempotency_key)
    }

    /// See [`LocalFsStore::drain_revision`].
    fn drain_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        self.drain_revision(env_id, revision_id, idempotency_key)
    }

    /// See [`LocalFsStore::archive_revision`].
    fn archive_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        self.archive_revision(env_id, revision_id, idempotency_key)
    }

    /// See [`LocalFsStore::add_bundle`].
    fn add_bundle(
        &self,
        env_id: &EnvId,
        payload: AddBundlePayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<BundleDeployment, StoreError> {
        self.add_bundle(env_id, payload, idempotency_key)
    }

    /// See [`LocalFsStore::update_bundle`].
    fn update_bundle(
        &self,
        env_id: &EnvId,
        payload: UpdateBundlePayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<BundleDeployment, StoreError> {
        self.update_bundle(env_id, payload, idempotency_key)
    }

    /// See [`LocalFsStore::remove_bundle`].
    fn remove_bundle(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RemoveBundleOutcome, StoreError> {
        self.remove_bundle(env_id, deployment_id, idempotency_key)
    }

    /// See [`LocalFsStore::add_pack_binding`].
    fn add_pack_binding(
        &self,
        env_id: &EnvId,
        binding: EnvPackBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<EnvPackBinding, StoreError> {
        self.add_pack_binding(env_id, binding, idempotency_key)
    }

    /// See [`LocalFsStore::update_pack_binding`].
    fn update_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        binding: EnvPackBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        self.update_pack_binding(env_id, slot, binding, idempotency_key)
    }

    /// See [`LocalFsStore::remove_pack_binding`].
    fn remove_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        self.remove_pack_binding(env_id, slot, idempotency_key)
    }

    /// See [`LocalFsStore::rollback_pack_binding`].
    fn rollback_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        self.rollback_pack_binding(env_id, slot, idempotency_key)
    }

    /// See [`LocalFsStore::add_extension_binding`].
    fn add_extension_binding(
        &self,
        env_id: &EnvId,
        binding: ExtensionBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<ExtensionBinding, StoreError> {
        self.add_extension_binding(env_id, binding, idempotency_key)
    }

    /// See [`LocalFsStore::update_extension_binding`].
    fn update_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        binding: ExtensionBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        self.update_extension_binding(env_id, key, binding, idempotency_key)
    }

    /// See [`LocalFsStore::remove_extension_binding`].
    fn remove_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        self.remove_extension_binding(env_id, key, idempotency_key)
    }

    /// See [`LocalFsStore::rollback_extension_binding`].
    fn rollback_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        self.rollback_extension_binding(env_id, key, idempotency_key)
    }

    /// See [`LocalFsStore::set_traffic_split`].
    fn set_traffic_split(
        &self,
        env_id: &EnvId,
        payload: SetTrafficSplitPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<ApplyTrafficSplitOutcome, StoreError> {
        self.set_traffic_split(env_id, payload, idempotency_key)
    }

    /// See [`LocalFsStore::rollback_traffic_split`].
    fn rollback_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RollbackTrafficSplitOutcome, StoreError> {
        self.rollback_traffic_split(env_id, deployment_id, idempotency_key)
    }

    /// See [`LocalFsStore::add_messaging_endpoint`].
    fn add_messaging_endpoint(
        &self,
        env_id: &EnvId,
        payload: AddMessagingEndpointPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.add_messaging_endpoint(env_id, payload, idempotency_key)
    }

    /// See [`LocalFsStore::link_messaging_bundle`].
    fn link_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.link_messaging_bundle(env_id, endpoint_id, bundle_id, updated_by, idempotency_key)
    }

    /// See [`LocalFsStore::unlink_messaging_bundle`].
    fn unlink_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.unlink_messaging_bundle(env_id, endpoint_id, bundle_id, updated_by, idempotency_key)
    }

    /// See [`LocalFsStore::set_messaging_welcome_flow`].
    fn set_messaging_welcome_flow(
        &self,
        env_id: &EnvId,
        payload: SetMessagingWelcomeFlowPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.set_messaging_welcome_flow(env_id, payload, idempotency_key)
    }

    /// See [`LocalFsStore::remove_messaging_endpoint`].
    fn remove_messaging_endpoint(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
    ) -> Result<MessagingEndpointId, StoreError> {
        self.remove_messaging_endpoint(env_id, endpoint_id)
    }

    /// See [`LocalFsStore::rotate_messaging_webhook_secret`].
    fn rotate_messaging_webhook_secret(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        self.rotate_messaging_webhook_secret(env_id, endpoint_id, updated_by, idempotency_key)
    }

    /// See [`LocalFsStore::bootstrap_trust_root`].
    fn bootstrap_trust_root(&self, env_id: &EnvId) -> Result<TrustRootSeed, StoreError> {
        self.bootstrap_trust_root(env_id)
    }

    /// See [`LocalFsStore::seed_trust_root_if_absent`].
    fn seed_trust_root_if_absent(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<TrustRootSeed>, StoreError> {
        self.seed_trust_root_if_absent(env_id)
    }

    /// See [`LocalFsStore::add_trusted_key`].
    fn add_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        public_key_pem: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootAddOutcome, StoreError> {
        self.add_trusted_key(env_id, key_id, public_key_pem, idempotency_key)
    }

    /// See [`LocalFsStore::remove_trusted_key`].
    fn remove_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootRemoveOutcome, StoreError> {
        self.remove_trusted_key(env_id, key_id, idempotency_key)
    }
}

#[cfg(test)]
mod warm_revision_tests {
    //! Direct tests for the typed `warm_revision` verb (PR-3a.6). `drain` and
    //! `archive` are covered through the CLI integration tests in
    //! `cli::revisions`; `warm` is not CLI-wired yet (the closure-shaped
    //! `warm_with_health_gate` path still owns the gate consumer) so its
    //! typed-verb behavior is locked in here.
    use super::*;
    use crate::environment::lifecycle::{HealthCheckId, HealthGateFailure, LifecycleError};
    use crate::environment::store::EnvironmentStore;
    use chrono::{TimeZone, Utc};
    use greentic_deploy_spec::{
        BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
        Environment, EnvironmentHostConfig, PartyId, RevenueShareEntry, Revision, RevisionId,
        RevisionLifecycle, RouteBinding, SchemaVersion, TenantSelector,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::tempdir;

    const ENV_ID: &str = "local";

    fn env_id() -> EnvId {
        EnvId::try_from(ENV_ID).unwrap()
    }

    fn seed_one_staged() -> (LocalFsStore, EnvId, RevisionId) {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().to_path_buf());
        let did = DeploymentId::new();
        let rid = RevisionId::new();
        let env = Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: ENV_ID.to_string(),
            host_config: EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
            packs: Vec::new(),
            credentials_ref: None,
            bundles: vec![BundleDeployment {
                schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
                deployment_id: did,
                env_id: env_id(),
                bundle_id: BundleId::new("fast2flow"),
                customer_id: CustomerId::new("local-dev"),
                status: BundleDeploymentStatus::Active,
                current_revisions: vec![rid],
                route_binding: RouteBinding {
                    hosts: vec!["fast2flow.local".to_string()],
                    path_prefixes: Vec::new(),
                    tenant_selector: TenantSelector {
                        tenant: "default".to_string(),
                        team: "default".to_string(),
                    },
                },
                revenue_share: vec![RevenueShareEntry {
                    party_id: PartyId::new("greentic"),
                    basis_points: 10_000,
                }],
                revenue_policy_ref: PathBuf::from("revenue.json"),
                usage: None,
                created_at: Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap(),
                authorization_ref: PathBuf::from("auth.json"),
                config_overrides: BTreeMap::new(),
            }],
            revisions: vec![Revision {
                schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
                revision_id: rid,
                env_id: env_id(),
                bundle_id: BundleId::new("fast2flow"),
                deployment_id: did,
                sequence: 1,
                created_at: Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap(),
                bundle_digest: "sha256:00".to_string(),
                bundle_source_uri: None,
                pack_list: Vec::new(),
                pack_list_lock_ref: PathBuf::new(),
                pack_config_refs: Vec::new(),
                config_digest: "sha256:00".to_string(),
                signature_sidecar_ref: PathBuf::from("rev.sig"),
                lifecycle: RevisionLifecycle::Staged,
                staged_at: Some(Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap()),
                warmed_at: None,
                drain_seconds: 30,
                abort_metrics: Vec::new(),
            }],
            traffic_splits: Vec::new(),
            messaging_endpoints: Vec::new(),
            extensions: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        };
        store.save(&env).unwrap();
        // `keep()` consumes the tempdir's `Drop` guard so the dir survives the
        // test scope without leaking via `mem::forget`.
        let _ = dir.keep();
        (store, env_id(), rid)
    }

    fn idem() -> IdempotencyKey {
        IdempotencyKey::new(ulid::Ulid::new().to_string()).unwrap()
    }

    #[test]
    fn warm_revision_with_passing_gate_lands_ready_and_stamps_warmed_at() {
        let (store, env_id, rid) = seed_one_staged();
        let outcome = store
            .warm_revision(
                &env_id,
                WarmRevisionPayload {
                    revision_id: rid,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem(),
            )
            .unwrap();
        assert_eq!(outcome.revision.lifecycle, RevisionLifecycle::Ready);
        assert!(outcome.revision.warmed_at.is_some());
        assert_eq!(outcome.starting_lifecycle, RevisionLifecycle::Staged);
        // Persisted.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
    }

    #[test]
    fn warm_revision_with_failing_gate_persists_failed_and_surfaces_health_gate_error() {
        let (store, env_id, rid) = seed_one_staged();
        let err = store
            .warm_revision(
                &env_id,
                WarmRevisionPayload {
                    revision_id: rid,
                    health_gate: Err(HealthGateFailure {
                        failed_checks: vec![HealthCheckId::RouteTable],
                        message: "missing routes".to_string(),
                    }),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem(),
            )
            .unwrap_err();
        match err {
            StoreError::Lifecycle(inner) => match *inner {
                LifecycleError::HealthGateFailed {
                    revision_id,
                    failed_checks,
                    ..
                } => {
                    assert_eq!(revision_id, rid);
                    assert_eq!(failed_checks, vec![HealthCheckId::RouteTable]);
                }
                other => panic!("expected HealthGateFailed, got {other:?}"),
            },
            other => panic!("expected StoreError::Lifecycle, got {other:?}"),
        }
        // Failed state is durable per the B9 contract.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Failed);
    }

    #[test]
    fn drain_revision_advances_ready_to_draining() {
        let (store, env_id, rid) = seed_one_staged();
        // First warm the revision to Ready (drain only accepts Ready as a start).
        store
            .warm_revision(
                &env_id,
                WarmRevisionPayload {
                    revision_id: rid,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem(),
            )
            .unwrap();
        let outcome = store.drain_revision(&env_id, rid, idem()).unwrap();
        assert_eq!(outcome.revision.lifecycle, RevisionLifecycle::Draining);
        assert_eq!(outcome.starting_lifecycle, RevisionLifecycle::Ready);
    }

    #[test]
    fn archive_revision_walks_draining_through_inactive_to_archived() {
        let (store, env_id, rid) = seed_one_staged();
        store
            .warm_revision(
                &env_id,
                WarmRevisionPayload {
                    revision_id: rid,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem(),
            )
            .unwrap();
        store.drain_revision(&env_id, rid, idem()).unwrap();
        let outcome = store.archive_revision(&env_id, rid, idem()).unwrap();
        assert_eq!(outcome.revision.lifecycle, RevisionLifecycle::Archived);
        // Starting lifecycle must surface `Draining` so the CLI eviction-emit
        // discriminator can branch correctly (archive's chain walks
        // Draining→Inactive→Archived in one hop, so the final lifecycle alone
        // can't tell us we crossed the eviction boundary).
        assert_eq!(outcome.starting_lifecycle, RevisionLifecycle::Draining);
    }

    /// PR-3a.6b regression: a concurrent mutation that changes the revision's
    /// lifecycle AFTER gate evaluation but BEFORE the typed verb acquires the
    /// flock must be rejected. Simulated here by supplying an
    /// `expected_lifecycle` that doesn't match the revision's on-disk state.
    #[test]
    fn warm_with_concurrent_lifecycle_change_rejects() {
        let (store, env_id, rid) = seed_one_staged();
        // The revision is `Staged` on disk, but the caller claims it observed
        // `Ready` (simulating a concurrent drain that landed between gate-eval
        // and verb dispatch). The precondition must reject.
        let err = store
            .warm_revision(
                &env_id,
                WarmRevisionPayload {
                    revision_id: rid,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Ready,
                },
                idem(),
            )
            .unwrap_err();
        match err {
            StoreError::Lifecycle(inner) => match *inner {
                LifecycleError::Conflict {
                    revision_id: conflict_rid,
                    actual,
                    expected_starts,
                } => {
                    assert_eq!(conflict_rid, rid);
                    assert_eq!(actual, RevisionLifecycle::Staged);
                    assert_eq!(expected_starts, vec![RevisionLifecycle::Ready]);
                }
                other => panic!("expected LifecycleError::Conflict, got {other:?}"),
            },
            other => panic!("expected StoreError::Lifecycle, got {other:?}"),
        }
        // Env untouched — revision stays Staged.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Staged);
    }

    /// Complement of `warm_with_concurrent_lifecycle_change_rejects`:
    /// an idempotent retry against an already-Ready revision must
    /// succeed regardless of the `expected_lifecycle` value, because
    /// the chain walk is a no-op and the gate is never fired.
    #[test]
    fn warm_idempotent_retry_skips_precondition() {
        let (store, env_id, rid) = seed_one_staged();
        // Warm once (Staged → Ready).
        store
            .warm_revision(
                &env_id,
                WarmRevisionPayload {
                    revision_id: rid,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem(),
            )
            .unwrap();
        // Retry with a stale `expected_lifecycle` (Staged, not Ready).
        // Must succeed because the revision is already at the chain's
        // final state.
        let outcome = store
            .warm_revision(
                &env_id,
                WarmRevisionPayload {
                    revision_id: rid,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem(),
            )
            .unwrap();
        assert_eq!(outcome.revision.lifecycle, RevisionLifecycle::Ready);
    }
}

#[cfg(test)]
mod bootstrap_typed_verb_tests {
    //! Direct tests for the typed `ensure_local_environment` verb (PR-3a.12).
    //! The CLI-layer tests in `cli::bootstrap` exercise the full wrapper
    //! including `refresh_local_runtime_stub`; these lock in the store-level
    //! typed-verb behavior: Created, AlreadyExists, Healed, and
    //! public_base_url overwrite rejection.
    use super::*;
    use crate::defaults::{
        LOCAL_DEPLOYER_PACK, LOCAL_ENV_ID, LOCAL_SECRETS_PACK, LOCAL_SESSIONS_PACK,
        LOCAL_STATE_PACK, LOCAL_TELEMETRY_PACK,
    };
    use crate::environment::bootstrap::{EnsureLocalEnvironmentPayload, LocalEnvOutcome};
    use crate::environment::store::EnvironmentStore;
    use greentic_deploy_spec::{CapabilitySlot, EnvId, EnvPackBinding, PackDescriptor, PackId};
    use tempfile::TempDir;

    fn store() -> (TempDir, LocalFsStore) {
        let tmp = TempDir::new().expect("tempdir");
        let s = LocalFsStore::new(tmp.path().to_path_buf());
        (tmp, s)
    }

    fn env_id() -> EnvId {
        EnvId::try_from(LOCAL_ENV_ID).unwrap()
    }

    fn payload(public_base_url: Option<&str>) -> EnsureLocalEnvironmentPayload {
        EnsureLocalEnvironmentPayload {
            public_base_url: public_base_url.map(ToString::to_string),
        }
    }

    #[test]
    fn creates_env_when_missing() {
        let (_tmp, store) = store();
        let (env, outcome) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("create");
        assert_eq!(outcome, LocalEnvOutcome::Created);
        assert_eq!(env.environment_id.as_str(), LOCAL_ENV_ID);
        assert_eq!(env.name, LOCAL_ENV_ID);
        assert_eq!(env.packs.len(), 5);
        env.validate().expect("spec-valid");
    }

    #[test]
    fn creates_env_with_public_base_url() {
        let (_tmp, store) = store();
        let (env, outcome) = store
            .ensure_local_environment(&env_id(), payload(Some("https://example.com")))
            .expect("create with url");
        assert_eq!(outcome, LocalEnvOutcome::Created);
        assert_eq!(
            env.host_config.public_base_url.as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn returns_already_exists_on_second_call() {
        let (_tmp, store) = store();
        let (first, _) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("first");
        let (second, outcome) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("second");
        assert_eq!(outcome, LocalEnvOutcome::AlreadyExists);
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_public_base_url_when_env_exists() {
        let (_tmp, store) = store();
        store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("first");
        let err = store
            .ensure_local_environment(&env_id(), payload(Some("https://example.com")))
            .unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidArgument(ref msg) if msg.contains("already exists")),
            "expected InvalidArgument, got {err:?}"
        );
    }

    /// Seed an empty `local` env (all 5 slots missing) — mimics `op env create local`.
    fn seed_empty_local_env(store: &LocalFsStore) -> greentic_deploy_spec::Environment {
        let eid = env_id();
        let env = greentic_deploy_spec::Environment {
            schema: greentic_deploy_spec::SchemaVersion::new(
                greentic_deploy_spec::SchemaVersion::ENVIRONMENT_V1,
            ),
            environment_id: eid.clone(),
            name: LOCAL_ENV_ID.to_string(),
            host_config: greentic_deploy_spec::EnvironmentHostConfig {
                env_id: eid,
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            messaging_endpoints: Vec::new(),
            extensions: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        };
        store.save(&env).expect("seed");
        env
    }

    fn custom_binding(slot: CapabilitySlot, descriptor: &str) -> EnvPackBinding {
        EnvPackBinding {
            slot,
            kind: PackDescriptor::try_new(descriptor).expect("valid"),
            pack_ref: PackId::new(descriptor),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        }
    }

    #[test]
    fn webhook_provision_ctx_trims_and_blanks_owner() {
        let (_tmp, store) = store();
        let mut env = seed_empty_local_env(&store);
        // No Secrets binding → custodial dev-store; no owner → None.
        let (owner, custodial) = webhook_provision_ctx(&env);
        assert_eq!(owner, None);
        assert!(custodial);
        // A padded owner is trimmed.
        env.host_config.tenant_org_id = Some("  tenant-default  ".to_string());
        assert_eq!(
            webhook_provision_ctx(&env).0.as_deref(),
            Some("tenant-default")
        );
        // A blank owner collapses to None.
        env.host_config.tenant_org_id = Some("   ".to_string());
        assert_eq!(webhook_provision_ctx(&env).0, None);
    }

    #[test]
    fn rotate_messaging_webhook_secret_rejects_non_dev_store_backend() {
        let (_tmp, store) = store();
        let mut env = seed_empty_local_env(&store);
        // A tenant-owned env bound to the Vault secrets backend (non-custodial).
        env.host_config.tenant_org_id = Some("tenant-default".to_string());
        env.packs.push(custom_binding(
            CapabilitySlot::Secrets,
            crate::defaults::VAULT_SECRETS_PACK,
        ));
        store.save(&env).unwrap();

        // Add stamps the owner-tenant ref without writing a dev-store value.
        let added = store
            .add_messaging_endpoint(
                &env_id(),
                AddMessagingEndpointPayload {
                    provider_id: "tg".to_string(),
                    provider_type: "telegram".to_string(),
                    display_name: "t".to_string(),
                    secret_refs: Vec::new(),
                    webhook_secret_ref: None,
                    updated_by: "tester".to_string(),
                },
                IdempotencyKey::new(ulid::Ulid::new().to_string()).unwrap(),
            )
            .unwrap();
        assert!(
            added
                .webhook_secret_ref
                .as_ref()
                .expect("telegram endpoint stamps a ref")
                .as_str()
                .starts_with("secret://local/tenant-default/_/"),
            "add must stamp the owner-tenant ref"
        );

        // Rotate must fail closed — the control plane cannot rotate a Vault value.
        let err = store
            .rotate_messaging_webhook_secret(
                &env_id(),
                added.endpoint_id,
                "tester".to_string(),
                IdempotencyKey::new(ulid::Ulid::new().to_string()).unwrap(),
            )
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Conflict(ref m) if m.contains("non-dev-store")),
            "expected Conflict, got {err:?}"
        );
    }

    #[test]
    fn heals_env_with_no_packs() {
        let (_tmp, store) = store();
        seed_empty_local_env(&store);
        let (env, outcome) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Deployer,
                        CapabilitySlot::Secrets,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                    ]
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        assert_eq!(env.packs.len(), 5);
        env.validate().expect("spec-valid after heal");
        // Re-run: now fully bound, should be AlreadyExists.
        let (_, outcome2) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("second");
        assert_eq!(outcome2, LocalEnvOutcome::AlreadyExists);
    }

    #[test]
    fn heals_env_with_partial_packs() {
        let (_tmp, store) = store();
        let mut env = seed_empty_local_env(&store);
        env.packs.push(custom_binding(
            CapabilitySlot::Deployer,
            LOCAL_DEPLOYER_PACK,
        ));
        store.save(&env).expect("partial save");

        let (env, outcome) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Secrets,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                    ]
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        assert_eq!(env.packs.len(), 5);
    }

    #[test]
    fn heal_preserves_user_bound_non_default_descriptor() {
        let (_tmp, store) = store();
        let mut env = seed_empty_local_env(&store);
        let custom_secrets = "greentic.secrets.aws-secrets-manager@1.0.0";
        env.packs
            .push(custom_binding(CapabilitySlot::Secrets, custom_secrets));
        store.save(&env).expect("custom-secrets save");

        let (env, outcome) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("heal");
        match outcome {
            LocalEnvOutcome::Healed { added_slots } => {
                assert_eq!(
                    added_slots,
                    vec![
                        CapabilitySlot::Deployer,
                        CapabilitySlot::Telemetry,
                        CapabilitySlot::Sessions,
                        CapabilitySlot::State,
                    ]
                );
            }
            other => panic!("expected Healed, got {other:?}"),
        }
        let secrets_desc = env
            .packs
            .iter()
            .find(|b| b.slot == CapabilitySlot::Secrets)
            .map(|b| b.kind.as_str())
            .expect("secrets slot");
        assert_eq!(secrets_desc, custom_secrets);
    }

    #[test]
    fn default_bindings_cover_expected_descriptors() {
        let (_tmp, store) = store();
        let (env, _) = store
            .ensure_local_environment(&env_id(), payload(None))
            .expect("create");
        let by_slot: std::collections::BTreeMap<CapabilitySlot, &str> = env
            .packs
            .iter()
            .map(|b| (b.slot, b.kind.as_str()))
            .collect();
        assert_eq!(by_slot[&CapabilitySlot::Deployer], LOCAL_DEPLOYER_PACK);
        assert_eq!(by_slot[&CapabilitySlot::Secrets], LOCAL_SECRETS_PACK);
        assert_eq!(by_slot[&CapabilitySlot::Telemetry], LOCAL_TELEMETRY_PACK);
        assert_eq!(by_slot[&CapabilitySlot::Sessions], LOCAL_SESSIONS_PACK);
        assert_eq!(by_slot[&CapabilitySlot::State], LOCAL_STATE_PACK);
    }
}
