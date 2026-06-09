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

use greentic_deploy_spec::{
    BundleId, CapabilitySlot, DeploymentId, EnvId, EnvPackBinding, Environment,
    EnvironmentHostConfig, ExtensionBinding, HealthStatus, IdempotencyKey, MessagingEndpoint,
    MessagingEndpointId, RetentionPolicy, Revision, RevisionId, RevisionLifecycle,
    RevocationConfig, SchemaVersion, SecretRef, WelcomeFlowRef,
};

use super::lifecycle::{
    LifecycleError, apply_revision_transition, apply_revision_transition_with_health_gate,
};
use super::mutations::{
    AddMessagingEndpointPayload, ExtensionKey, MigrateMergePayload, RemoveBundleOutcome,
    RevisionTransitionOutcome, SetMessagingWelcomeFlowPayload, StageRevisionPayload,
    TrustRootAddOutcome, TrustRootRemoveOutcome, TrustRootSeed, UpdateEnvironmentPayload,
    WarmRevisionPayload,
};
use super::store::{LocalFsStore, StoreError};
use super::trust_root::{self as store_trust_root, trust_root_path};

/// Map a [`LifecycleError`] into `StoreError`, peeling `LifecycleError::Store`
/// so the original [`StoreError`] reaches callers unboxed.
fn fold_lifecycle_err(err: LifecycleError) -> StoreError {
    match err {
        LifecycleError::Store(inner) => inner,
        other => StoreError::Lifecycle(Box::new(other)),
    }
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
            let env = fresh_environment(
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

    /// Patch the named scalar fields on an existing env. `None` fields are
    /// skipped (no clear-to-`None` flow today). Returns the fully-updated
    /// [`Environment`]. Collapses what was previously split across the
    /// `op env update`, `op env set-public-url`, and `op config set` verbs
    /// — see [`UpdateEnvironmentPayload`] for the rationale.
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
            if let Some(name) = patch.name {
                env.name = name;
            }
            if let Some(region) = patch.region {
                env.host_config.region = Some(region);
            }
            if let Some(org) = patch.tenant_org_id {
                env.host_config.tenant_org_id = Some(org);
            }
            if let Some(addr) = patch.listen_addr {
                env.host_config.listen_addr = Some(addr);
            }
            if let Some(url) = patch.public_base_url {
                env.host_config.public_base_url = Some(url);
            }
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
            let mut target_env = match locked.load() {
                Ok(env) => env,
                Err(StoreError::NotFound(id)) => match seed_if_missing {
                    Some(seed) => fresh_environment(
                        locked.env_id(),
                        locked.env_id().as_str().to_string(),
                        seed.host_config,
                        seed.revocation,
                        seed.retention,
                        seed.health,
                    ),
                    None => return Err(StoreError::NotFound(id)),
                },
                Err(e) => return Err(e),
            };
            let mut added_slots = Vec::new();
            for binding in packs {
                if target_env.packs.iter().any(|b| b.slot == binding.slot) {
                    continue;
                }
                added_slots.push(binding.slot.to_string());
                target_env.packs.push(binding);
            }
            // Extension bindings (`Path 3`) are light, referentially
            // independent state — like `packs`, they migrate. Merge by
            // `(kind.path(), instance_id)`, preserving any binding the
            // target already carries. (`messaging_endpoints` are NOT
            // migrated here: they reference `linked_bundles` that don't
            // migrate, so a blind copy would break referential integrity.)
            let mut added_extensions = Vec::new();
            for ext in extensions {
                let key = ExtensionKey::from_binding(&ext);
                if target_env.extensions.iter().any(|e| key.matches(e)) {
                    continue;
                }
                added_extensions.push(key.to_string());
                target_env.extensions.push(ext);
            }
            locked.save(&target_env)?;
            Ok((added_slots, added_extensions))
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
    ) -> Result<Revision, StoreError> {
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            // Resolve `bundle_id` from the deployment row. Cloning only the
            // ID — not the whole `BundleDeployment` — drops the
            // route_binding/revenue_share/config_overrides clone churn.
            let bundle_id = env
                .bundles
                .iter()
                .find(|b| b.deployment_id == payload.deployment_id)
                .map(|b| b.bundle_id.clone())
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "deployment `{}` not found in env `{}`",
                        payload.deployment_id, env_id
                    ))
                })?;
            let next_sequence = env
                .revisions
                .iter()
                .filter(|r| r.deployment_id == payload.deployment_id)
                .map(|r| r.sequence)
                .max()
                .unwrap_or(0)
                + 1;
            let now = Utc::now();
            let revision = Revision {
                schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
                revision_id: payload.revision_id,
                env_id: env_id.clone(),
                bundle_id,
                deployment_id: payload.deployment_id,
                sequence: next_sequence,
                created_at: now,
                bundle_digest: payload.bundle_digest,
                pack_list: payload.pack_list,
                pack_list_lock_ref: payload.pack_list_lock_ref,
                pack_config_refs: payload.pack_config_refs,
                config_digest: payload.config_digest,
                signature_sidecar_ref: payload.signature_sidecar_ref,
                lifecycle: RevisionLifecycle::Staged,
                staged_at: Some(now),
                warmed_at: None,
                drain_seconds: payload.drain_seconds,
                abort_metrics: Vec::new(),
            };
            env.revisions.push(revision.clone());
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
    /// `payload.health_gate` is `Result<(), HealthGateFailure>`, not a
    /// closure — closures don't cross the A8 HTTP wire (PR-3b). The
    /// deployer CLI evaluates the gate locally against the post-chain
    /// `(env, revision)` view and ships the outcome here.
    ///
    /// `payload.idempotency_key` is accepted for trait conformance and
    /// ignored locally; the HTTP backend caches it for A8 §2 replay.
    ///
    /// **Lifecycle precondition (PR-3a.6b).** The gate is evaluated
    /// OUTSIDE the env flock (by definition — closures don't cross the
    /// wire). `payload.expected_lifecycle` records the revision's
    /// lifecycle at gate-evaluation time; the impl re-checks under the
    /// flock that the revision still carries that lifecycle before
    /// applying the gate result. On mismatch, the verb rejects with
    /// `LifecycleError::Conflict` so a stale gate outcome (evaluated
    /// against env state that has since changed) is never applied.
    ///
    /// The precondition is skipped on the idempotent-retry path (revision
    /// already at the chain's final state, chain walk is a no-op) because
    /// the gate fires only when the chain actually advanced.
    pub fn warm_revision(
        &self,
        env_id: &EnvId,
        payload: WarmRevisionPayload,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let WarmRevisionPayload {
            revision_id,
            health_gate,
            idempotency_key: _,
            expected_lifecycle,
        } = payload;
        self.run_revision_transition(env_id, revision_id, |locked| {
            // Lifecycle precondition (PR-3a.6b): verify under the flock that
            // the revision still carries the lifecycle the caller observed at
            // gate-evaluation time. Skipped on the idempotent-retry path
            // (revision already at the chain's final `Ready` state) because
            // the gate fires only when the chain actually advanced — a retry
            // that doesn't advance the chain never applies the gate result,
            // so the precondition is moot.
            let env_snapshot = locked.load()?;
            let current_lifecycle = env_snapshot
                .revisions
                .iter()
                .find(|r| r.revision_id == revision_id)
                .map(|r| r.lifecycle);
            let chain_final = RevisionLifecycle::Ready;
            if let Some(actual) = current_lifecycle {
                let is_idempotent_retry = actual == chain_final;
                if !is_idempotent_retry && actual != expected_lifecycle {
                    return Err(LifecycleError::Conflict {
                        revision_id,
                        actual,
                        expected_starts: vec![expected_lifecycle],
                    });
                }
            }
            // Precondition passed (or skipped for idempotent retry).
            // Drop env_snapshot; the lifecycle helper does its own load.
            drop(env_snapshot);
            apply_revision_transition_with_health_gate(
                locked,
                revision_id,
                &[
                    (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                    (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                ],
                |r| {
                    r.warmed_at = Some(Utc::now());
                },
                false,
                // FnOnce closure consumes the pre-evaluated outcome — the
                // lifecycle helper only fires the gate when the chain
                // actually advanced, so an idempotent retry against an
                // already-`Ready` revision skips the gate.
                |_env, _rev| health_gate,
            )
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
        self.run_revision_transition(env_id, revision_id, |locked| {
            apply_revision_transition(
                locked,
                revision_id,
                &[(RevisionLifecycle::Ready, RevisionLifecycle::Draining)],
                |_| {},
                false,
            )
        })
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
        self.run_revision_transition(env_id, revision_id, |locked| {
            apply_revision_transition(
                locked,
                revision_id,
                &[
                    (RevisionLifecycle::Staged, RevisionLifecycle::Archived),
                    (RevisionLifecycle::Warming, RevisionLifecycle::Archived),
                    (RevisionLifecycle::Ready, RevisionLifecycle::Archived),
                    (RevisionLifecycle::Failed, RevisionLifecycle::Archived),
                    (RevisionLifecycle::Draining, RevisionLifecycle::Inactive),
                    (RevisionLifecycle::Inactive, RevisionLifecycle::Archived),
                ],
                |_| {},
                true,
            )
        })
    }

    /// Shared transact body for warm/drain/archive: capture the starting
    /// lifecycle (for the archive eviction-vs-retirement discriminator in
    /// `cli::revisions::emit_for_op`), drive the lifecycle helper, refresh
    /// the materialized runtime config, return the typed outcome.
    ///
    /// `archive`'s chain can traverse `Draining → Inactive → Archived`
    /// end-to-end in one call, so the final lifecycle alone can't tell us
    /// whether the eviction hop fired — capture the starting state here so
    /// the CLI emit can branch on it.
    fn run_revision_transition<F>(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        apply: F,
    ) -> Result<RevisionTransitionOutcome, StoreError>
    where
        F: FnOnce(&super::store::Locked<'_>) -> Result<Revision, LifecycleError>,
    {
        self.transact(env_id, |locked| {
            // C5.3: capture the revision's pre-chain lifecycle before the
            // helper walks the chain. A load failure leaves the value at
            // `Inactive` — the CLI eviction emit (the only consumer) will
            // skip silently, which matches the prior fail-safe behavior.
            let starting_lifecycle = locked
                .load()
                .ok()
                .and_then(|e| {
                    e.revisions
                        .iter()
                        .find(|r| r.revision_id == revision_id)
                        .map(|r| r.lifecycle)
                })
                .unwrap_or(RevisionLifecycle::Inactive);
            let revision = apply(locked).map_err(fold_lifecycle_err)?;
            // From here on the lifecycle helper has already called
            // `locked.save(...)` — the env mutation is durable on disk.
            // Any subsequent failure (env reload, materialized
            // runtime-config refresh) is committed-on-error and MUST be
            // surfaced as `StoreError::CommittedAfterSave` so the CLI
            // audit boundary fails-closed on an audit-append failure
            // (matches the closure-based path's `mark_committed` +
            // post-save fall-through contract).
            //
            // Lifecycle transitions don't change traffic splits today, so
            // the refresh is a no-op-guarded by change-detection; it
            // keeps the runtime-config contract uniform across every
            // mutating verb.
            let environment = locked
                .load()
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            locked
                .refresh_runtime_config(&environment)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(RevisionTransitionOutcome {
                revision,
                environment,
                starting_lifecycle,
            })
        })
    }

    // -------------------------------------------------------------
    // Bundle deployment CRUD  (PR-3a.7)
    //   `op bundles remove`
    //   `op bundles add | update` move in PR-3a.7b (revenue-policy
    //   sidecar + operator-key signing across the HTTP wire is a
    //   distinct design pass).
    // -------------------------------------------------------------

    /// Remove a [`BundleDeployment`] from the env. Refuses with
    /// [`StoreError::Conflict`] if the deployment still carries live state
    /// (any [`greentic_deploy_spec::TrafficSplit`] pointing at it, or any
    /// non-`Archived` revision under it) — callers run `op traffic clear`
    /// and archive revisions first. Drops archived revisions for the same
    /// `deployment_id` so the env stays compact.
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
            let idx = env
                .bundles
                .iter()
                .position(|b| b.deployment_id == deployment_id)
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "deployment `{deployment_id}` not found in env `{env_id}`"
                    ))
                })?;
            // Live-state guard + prune set computed in one pass over
            // `env.revisions`. `current_revisions` is plan-level future
            // signal that A3's stage/warm path does not yet maintain, so
            // it can't be the gate; the live-state proof is: any traffic
            // split pointing at this deployment, or any non-`Archived`
            // revision for it.
            let active_splits = env
                .traffic_splits
                .iter()
                .filter(|s| s.deployment_id == deployment_id)
                .count();
            let mut active_revisions = 0usize;
            let mut pruned_revision_ids: Vec<RevisionId> = Vec::new();
            for r in env.revisions.iter() {
                if r.deployment_id != deployment_id {
                    continue;
                }
                if matches!(r.lifecycle, RevisionLifecycle::Archived) {
                    pruned_revision_ids.push(r.revision_id);
                } else {
                    active_revisions += 1;
                }
            }
            if active_splits > 0 || active_revisions > 0 {
                return Err(StoreError::Conflict(format!(
                    "deployment `{deployment_id}` is still live: {active_splits} traffic split(s), \
                     {active_revisions} non-archived revision(s). Archive revisions and clear the \
                     split first."
                )));
            }
            let deployment = env.bundles.remove(idx);
            env.revisions.retain(|r| r.deployment_id != deployment_id);
            locked.save(&env)?;
            Ok(RemoveBundleOutcome {
                deployment,
                pruned_revision_ids,
            })
        })
    }

    // -------------------------------------------------------------
    // Env-pack binding CRUD  (PR-3a.8)
    //   `op env-packs add | update | remove | rollback`
    // -------------------------------------------------------------

    /// Bind a new env-pack slot. Rejects with [`StoreError::Conflict`]
    /// when the slot is already bound (callers should `update` instead).
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
            if env.pack_for_slot(binding.slot).is_some() {
                return Err(StoreError::Conflict(format!(
                    "slot `{}` already bound on env `{}`; use update",
                    binding.slot, env_id
                )));
            }
            env.packs.push(binding.clone());
            locked.save(&env)?;
            Ok(env.packs.last().expect("just pushed").clone())
        })
    }

    /// Replace the binding on an existing slot. Snapshots the prior binding
    /// inline via [`crate::cli::env_packs::stash_previous`] so one-step
    /// `rollback` works without a sidecar history file.
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
            let idx = env
                .packs
                .iter()
                .position(|b| b.slot == slot)
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "slot `{}` not bound on env `{}`",
                        slot, env_id
                    ))
                })?;
            if binding.slot != slot {
                return Err(StoreError::Conflict(format!(
                    "binding slot `{}` does not match target slot `{}`",
                    binding.slot, slot
                )));
            }
            let prev_generation = env.packs[idx].generation;
            let prev_snapshot = serde_json::to_value(&env.packs[idx])
                .map_err(|e| StoreError::Conflict(format!("snapshot prior binding: {e}")))?;
            let new_generation = prev_generation + 1;
            let mut new_binding = EnvPackBinding {
                generation: new_generation,
                ..binding
            };
            new_binding.previous_binding_ref =
                Some(crate::cli::env_packs::stash_previous(prev_snapshot));
            env.packs[idx] = new_binding;
            locked.save(&env)?;
            Ok((env.packs[idx].clone(), new_generation))
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
            let idx = env
                .packs
                .iter()
                .position(|b| b.slot == slot)
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "slot `{}` not bound on env `{}`",
                        slot, env_id
                    ))
                })?;
            let removed = env.packs.remove(idx);
            let generation = removed.generation;
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
            let idx = env
                .packs
                .iter()
                .position(|b| b.slot == slot)
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "slot `{}` not bound on env `{}`",
                        slot, env_id
                    ))
                })?;
            let prev_generation = env.packs[idx].generation;
            let prev_ref = env.packs[idx].previous_binding_ref.clone().ok_or_else(|| {
                StoreError::Conflict(format!(
                    "slot `{}` on env `{}` has no previous binding to roll back to",
                    slot, env_id
                ))
            })?;
            let prev_value = crate::cli::env_packs::load_previous(&prev_ref).ok_or_else(|| {
                StoreError::DependentNotFound(format!(
                    "previous binding payload `{}` missing for slot `{}`",
                    prev_ref.display(),
                    slot
                ))
            })?;
            let mut restored: EnvPackBinding = serde_json::from_value(prev_value)
                .map_err(|e| StoreError::Conflict(format!("deserialise previous binding: {e}")))?;
            restored.generation = prev_generation + 1;
            restored.previous_binding_ref = None;
            let new_generation = restored.generation;
            env.packs[idx] = restored;
            locked.save(&env)?;
            Ok((env.packs[idx].clone(), new_generation))
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
    /// to replace use [`Self::update_extension_binding`].
    ///
    /// `_idempotency_key` is accepted for trait conformance and ignored
    /// locally; the HTTP backend caches it for A8 §2 replay.
    pub fn add_extension_binding(
        &self,
        env_id: &EnvId,
        binding: ExtensionBinding,
        _idempotency_key: IdempotencyKey,
    ) -> Result<ExtensionBinding, StoreError> {
        let key = ExtensionKey::from_binding(&binding);
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            if env.extensions.iter().any(|b| key.matches(b)) {
                return Err(StoreError::Conflict(format!(
                    "extension `{}` is already bound on env `{}`; use update",
                    key, env_id
                )));
            }
            env.extensions.push(binding.clone());
            locked.save(&env)?;
            Ok(env.extensions.last().expect("just pushed").clone())
        })
    }

    /// Replace an existing extension binding identified by `key`. Bumps
    /// `generation` to `previous + 1` and stashes the prior binding inline
    /// so [`Self::rollback_extension_binding`] can restore it.
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
            let idx = env
                .extensions
                .iter()
                .position(|b| key.matches(b))
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "extension `{}` not bound on env `{}`",
                        key, env_id
                    ))
                })?;
            let prev_generation = env.extensions[idx].generation;
            let new_generation = prev_generation.checked_add(1).ok_or_else(|| {
                StoreError::Conflict(format!(
                    "extension `{}` on env `{}`: generation overflow ({})",
                    key, env_id, prev_generation
                ))
            })?;
            let prev_snapshot = serde_json::to_value(&env.extensions[idx])
                .map_err(|e| StoreError::Conflict(format!("snapshot prior binding: {e}")))?;
            let mut new_binding = binding;
            new_binding.generation = new_generation;
            new_binding.previous_binding_ref =
                Some(crate::cli::env_packs::stash_previous(prev_snapshot));
            env.extensions[idx] = new_binding;
            locked.save(&env)?;
            Ok((env.extensions[idx].clone(), new_generation))
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
            let idx = env
                .extensions
                .iter()
                .position(|b| key.matches(b))
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "extension `{}` not bound on env `{}`",
                        key, env_id
                    ))
                })?;
            let removed = env.extensions.remove(idx);
            let generation = removed.generation;
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
            let idx = env
                .extensions
                .iter()
                .position(|b| key.matches(b))
                .ok_or_else(|| {
                    StoreError::DependentNotFound(format!(
                        "extension `{}` not bound on env `{}`",
                        key, env_id
                    ))
                })?;
            let prev_generation = env.extensions[idx].generation;
            let new_generation = prev_generation.checked_add(1).ok_or_else(|| {
                StoreError::Conflict(format!(
                    "extension `{}` on env `{}`: generation overflow ({})",
                    key, env_id, prev_generation
                ))
            })?;
            let prev_ref = env.extensions[idx]
                .previous_binding_ref
                .clone()
                .ok_or_else(|| {
                    StoreError::Conflict(format!(
                        "extension `{}` on env `{}` has no previous binding to roll back to",
                        key, env_id
                    ))
                })?;
            let prev_value = crate::cli::env_packs::load_previous(&prev_ref).ok_or_else(|| {
                StoreError::DependentNotFound(format!(
                    "previous binding payload `{}` missing for extension `{}`",
                    prev_ref.display(),
                    key
                ))
            })?;
            let mut restored: ExtensionBinding = serde_json::from_value(prev_value)
                .map_err(|e| StoreError::Conflict(format!("deserialise previous binding: {e}")))?;
            restored.generation = new_generation;
            restored.previous_binding_ref = None;
            env.extensions[idx] = restored;
            locked.save(&env)?;
            Ok((env.extensions[idx].clone(), new_generation))
        })
    }

    // -------------------------------------------------------------
    // Messaging endpoint CRUD  (PR-3a.10)
    //   `op messaging endpoint add | link-bundle | unlink-bundle
    //                  | set-welcome-flow | remove | rotate-webhook-secret`
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
    ) -> Result<MessagingEndpoint, StoreError> {
        use crate::cli::messaging::{
            carries_idem_key, format_idem_writer, idem_suffix, is_telegram_class,
            provision_webhook_secret,
        };
        let idem_suffix_str = idem_suffix(payload.idempotency_key.as_str());
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            // Idempotent replay: re-running with the same key returns the
            // previously-created endpoint iff the payload's instance
            // identity matches what was stored.
            if let Some(prev) = env
                .messaging_endpoints
                .iter()
                .find(|e| carries_idem_key(e, &idem_suffix_str))
            {
                if prev.provider_type == payload.provider_type
                    && prev.provider_id == payload.provider_id
                {
                    let ep = prev.clone();
                    locked
                        .refresh_messaging_projection(&env)
                        .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
                    return Ok(ep);
                }
                return Err(StoreError::Conflict(format!(
                    "idempotency key `{}` already used to add `{}`/`{}` in env `{env_id}`; pass a fresh key",
                    payload.idempotency_key.as_str(),
                    prev.provider_type,
                    prev.provider_id
                )));
            }
            if env
                .messaging_endpoints
                .iter()
                .any(|e| {
                    e.provider_type == payload.provider_type
                        && e.provider_id == payload.provider_id
                })
            {
                return Err(StoreError::Conflict(format!(
                    "messaging endpoint with provider_type=`{}` provider_id=`{}` already exists in env `{env_id}`",
                    payload.provider_type, payload.provider_id
                )));
            }
            // Validate secret_refs BEFORE provisioning the webhook secret so
            // a malformed ref does not leave an orphan secret in the dev-store.
            let secret_refs: Vec<SecretRef> = payload
                .secret_refs
                .iter()
                .map(|r| {
                    SecretRef::try_new(r)
                        .map_err(|e| StoreError::InvalidArgument(format!("secret_ref `{r}`: {e}")))
                })
                .collect::<Result<_, _>>()?;
            let now = Utc::now();
            let eid = MessagingEndpointId::new();
            let webhook_secret_ref = if is_telegram_class(&payload.provider_type) {
                Some(
                    provision_webhook_secret(self, env_id, &eid, None)
                        .map_err(|e| StoreError::Conflict(e.to_string()))?,
                )
            } else {
                None
            };
            let endpoint = MessagingEndpoint {
                schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
                env_id: env_id.clone(),
                endpoint_id: eid,
                provider_id: payload.provider_id.clone(),
                provider_type: payload.provider_type.clone(),
                display_name: payload.display_name.clone(),
                secret_refs,
                webhook_secret_ref,
                linked_bundles: Vec::new(),
                welcome_flow: None,
                generation: 0,
                created_at: now,
                updated_at: now,
                updated_by: format_idem_writer(
                    &payload.updated_by,
                    payload.idempotency_key.as_str(),
                ),
            };
            env.messaging_endpoints.push(endpoint);
            locked.save(&env)?;
            let ep = env
                .messaging_endpoints
                .last()
                .expect("just pushed endpoint")
                .clone();
            locked
                .refresh_messaging_projection(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(ep)
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
        use crate::cli::messaging::stamp_mutation;
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let idx = find_messaging_endpoint_idx(&env, endpoint_id, env_id)?;
            if !env.bundles.iter().any(|b| b.bundle_id == bundle_id) {
                return Err(StoreError::DependentNotFound(format!(
                    "bundle `{bundle_id}` is not deployed in env `{env_id}`"
                )));
            }
            if env.messaging_endpoints[idx]
                .linked_bundles
                .contains(&bundle_id)
            {
                let ep = env.messaging_endpoints[idx].clone();
                locked
                    .refresh_messaging_projection(&env)
                    .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
                return Ok(ep);
            }
            env.messaging_endpoints[idx].linked_bundles.push(bundle_id);
            stamp_mutation(
                &mut env.messaging_endpoints[idx],
                &updated_by,
                idempotency_key.as_str(),
            );
            locked.save(&env)?;
            let ep = env.messaging_endpoints[idx].clone();
            locked
                .refresh_messaging_projection(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(ep)
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
        use crate::cli::messaging::stamp_mutation;
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let idx = find_messaging_endpoint_idx(&env, endpoint_id, env_id)?;
            let bundle_idx = env.messaging_endpoints[idx]
                .linked_bundles
                .iter()
                .position(|b| b == &bundle_id);
            let Some(bidx) = bundle_idx else {
                // Idempotent: unlinking a bundle that isn't linked is a no-op.
                let ep = env.messaging_endpoints[idx].clone();
                locked
                    .refresh_messaging_projection(&env)
                    .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
                return Ok(ep);
            };
            if let Some(welcome) = &env.messaging_endpoints[idx].welcome_flow
                && welcome.bundle_id == bundle_id
            {
                return Err(StoreError::Conflict(format!(
                    "cannot unlink bundle `{bundle_id}` from endpoint `{endpoint_id}` while it owns the welcome_flow; clear the welcome_flow first via `set-welcome-flow` to a different linked bundle, or `remove` the endpoint"
                )));
            }
            env.messaging_endpoints[idx].linked_bundles.remove(bidx);
            stamp_mutation(
                &mut env.messaging_endpoints[idx],
                &updated_by,
                idempotency_key.as_str(),
            );
            locked.save(&env)?;
            let ep = env.messaging_endpoints[idx].clone();
            locked
                .refresh_messaging_projection(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(ep)
        })
    }

    /// Set the welcome flow on a messaging endpoint. Rejects with
    /// [`StoreError::Conflict`] when the bundle is not linked, or when
    /// `pack_id` does not appear in any current revision's pack_list.
    /// Idempotent when the same welcome flow ref is already set (repairs a
    /// stale projection).
    pub fn set_messaging_welcome_flow(
        &self,
        env_id: &EnvId,
        payload: SetMessagingWelcomeFlowPayload,
    ) -> Result<MessagingEndpoint, StoreError> {
        use crate::cli::messaging::stamp_mutation;
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let idx =
                find_messaging_endpoint_idx(&env, payload.endpoint_id, env_id)?;
            if !env.messaging_endpoints[idx]
                .linked_bundles
                .contains(&payload.bundle_id)
            {
                return Err(StoreError::InvalidArgument(format!(
                    "welcome_flow bundle `{}` is not linked to endpoint `{}`; link it first via `link-bundle`",
                    payload.bundle_id, payload.endpoint_id
                )));
            }
            validate_welcome_pack_id_store(&env, &payload.bundle_id, payload.pack_id.as_str())?;
            let new_welcome = WelcomeFlowRef {
                bundle_id: payload.bundle_id.clone(),
                pack_id: payload.pack_id.clone(),
                flow_id: payload.flow_id.clone(),
            };
            if env.messaging_endpoints[idx].welcome_flow.as_ref() == Some(&new_welcome) {
                let ep = env.messaging_endpoints[idx].clone();
                locked
                    .refresh_messaging_projection(&env)
                    .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
                return Ok(ep);
            }
            env.messaging_endpoints[idx].welcome_flow = Some(new_welcome);
            stamp_mutation(
                &mut env.messaging_endpoints[idx],
                &payload.updated_by,
                payload.idempotency_key.as_str(),
            );
            locked.save(&env)?;
            let ep = env.messaging_endpoints[idx].clone();
            locked
                .refresh_messaging_projection(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(ep)
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
            let idx = env
                .messaging_endpoints
                .iter()
                .position(|e| e.endpoint_id == endpoint_id);
            let Some(idx) = idx else {
                // Idempotent: removing an absent endpoint succeeds. Repair
                // any stale projection from a prior failed call.
                locked
                    .refresh_messaging_projection(&env)
                    .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
                return Ok(endpoint_id);
            };
            env.messaging_endpoints.remove(idx);
            locked.save(&env)?;
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
        use crate::cli::messaging::{
            carries_idem_key, idem_suffix, provision_webhook_secret, stamp_mutation,
        };
        let idem_suffix_str = idem_suffix(idempotency_key.as_str());
        self.transact(env_id, |locked| {
            let mut env = locked.load()?;
            let idx = find_messaging_endpoint_idx(&env, endpoint_id, env_id)?;
            // Idempotent replay: if the endpoint already carries this idem key,
            // the rotation already landed — return the existing endpoint.
            if carries_idem_key(&env.messaging_endpoints[idx], &idem_suffix_str) {
                let ep = env.messaging_endpoints[idx].clone();
                locked
                    .refresh_messaging_projection(&env)
                    .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
                return Ok(ep);
            }
            let secret_ref = provision_webhook_secret(
                self,
                env_id,
                &endpoint_id,
                env.messaging_endpoints[idx].webhook_secret_ref.as_ref(),
            )
            .map_err(|e| StoreError::Conflict(e.to_string()))?;
            env.messaging_endpoints[idx].webhook_secret_ref = Some(secret_ref);
            stamp_mutation(
                &mut env.messaging_endpoints[idx],
                &updated_by,
                idempotency_key.as_str(),
            );
            locked.save(&env)?;
            let ep = env.messaging_endpoints[idx].clone();
            locked
                .refresh_messaging_projection(&env)
                .map_err(|e| StoreError::CommittedAfterSave(Box::new(e)))?;
            Ok(ep)
        })
    }
}

/// Locate a messaging endpoint by id inside an environment, returning
/// [`StoreError::DependentNotFound`] when absent.
fn find_messaging_endpoint_idx(
    env: &Environment,
    endpoint_id: MessagingEndpointId,
    env_id: &EnvId,
) -> Result<usize, StoreError> {
    env.messaging_endpoints
        .iter()
        .position(|e| e.endpoint_id == endpoint_id)
        .ok_or_else(|| {
            StoreError::DependentNotFound(format!(
                "messaging endpoint `{endpoint_id}` not found in env `{env_id}`"
            ))
        })
}

/// Store-level welcome-flow pack_id validation mirroring
/// [`crate::cli::messaging::validate_welcome_pack_id`] but returning
/// [`StoreError::Conflict`] instead of `OpError`.
fn validate_welcome_pack_id_store(
    env: &Environment,
    bundle_id: &BundleId,
    pack_id: &str,
) -> Result<(), StoreError> {
    let bundles: Vec<_> = env
        .bundles
        .iter()
        .filter(|b| b.bundle_id == *bundle_id)
        .collect();
    if bundles.is_empty() {
        return Ok(());
    }
    let mut saw_any_pack = false;
    let mut known_packs: Vec<String> = Vec::new();
    for bundle in bundles {
        for rev_id in &bundle.current_revisions {
            let Some(rev) = env.revisions.iter().find(|r| r.revision_id == *rev_id) else {
                continue;
            };
            for entry in &rev.pack_list {
                saw_any_pack = true;
                if entry.pack_id.as_str() == pack_id {
                    return Ok(());
                }
                known_packs.push(entry.pack_id.as_str().to_string());
            }
        }
    }
    if !saw_any_pack {
        return Ok(());
    }
    known_packs.sort();
    known_packs.dedup();
    Err(StoreError::InvalidArgument(format!(
        "welcome_flow.pack_id `{pack_id}` does not appear in any current revision of bundle `{bundle_id}` (known: [{}])",
        known_packs.join(", ")
    )))
}

/// Build an empty [`Environment`] at the current `ENVIRONMENT_V1` schema
/// with the supplied `host_config` + policy state. All collection fields
/// start empty and `credentials_ref` is `None` — populated downstream by
/// the binding verbs. Shared by `create_environment` (which passes
/// `Default::default()` for revocation/retention/health) and
/// `migrate_merge_bindings`' seed branch (which threads the source's
/// existing policy state through).
///
/// Centralizing this prevents the two seed sites from drifting when a new
/// `Environment` field lands — both currently must zero/default it, and
/// missing one site is the silent-zero-value footgun.
fn fresh_environment(
    env_id: &EnvId,
    name: String,
    host_config: EnvironmentHostConfig,
    revocation: RevocationConfig,
    retention: RetentionPolicy,
    health: HealthStatus,
) -> Environment {
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id.clone(),
        name,
        host_config: EnvironmentHostConfig {
            env_id: env_id.clone(),
            ..host_config
        },
        packs: Vec::new(),
        credentials_ref: None,
        bundles: Vec::new(),
        revisions: Vec::new(),
        traffic_splits: Vec::new(),
        messaging_endpoints: Vec::new(),
        extensions: Vec::new(),
        revocation,
        retention,
        health,
    }
}

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
                    idempotency_key: idem(),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
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
                    idempotency_key: idem(),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
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
                    idempotency_key: idem(),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
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
                    idempotency_key: idem(),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
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
                    idempotency_key: idem(),
                    expected_lifecycle: RevisionLifecycle::Ready,
                },
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
                    idempotency_key: idem(),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
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
                    idempotency_key: idem(),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
            )
            .unwrap();
        assert_eq!(outcome.revision.lifecycle, RevisionLifecycle::Ready);
    }
}
