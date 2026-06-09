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
    DeploymentId, EnvId, Environment, EnvironmentHostConfig, HealthStatus, IdempotencyKey,
    RetentionPolicy, Revision, RevisionId, RevisionLifecycle, RevocationConfig, SchemaVersion,
};

use super::lifecycle::{
    LifecycleError, apply_revision_transition, apply_revision_transition_with_health_gate,
};
use super::mutations::{
    ExtensionKey, MigrateMergePayload, RemoveBundleOutcome, RevisionTransitionOutcome,
    StageRevisionPayload, TrustRootAddOutcome, TrustRootRemoveOutcome, TrustRootSeed,
    UpdateEnvironmentPayload, WarmRevisionPayload,
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
    /// **Stale-snapshot caution.** The gate is evaluated OUTSIDE the env
    /// flock (by definition — closures don't cross the wire). A
    /// concurrent mutation that lands BETWEEN gate evaluation and this
    /// verb's flock acquisition can produce a Ready/Failed outcome that
    /// doesn't match the env state the gate actually observed. The
    /// current consumer (closure-based CLI `warm_with_health_gate`) is
    /// not affected — it stays in-lock. Future typed consumers (PR-3b
    /// HTTP backend, Phase D `greentic-start` warm gate) MUST add an
    /// env-generation / lifecycle-hash precondition to
    /// [`super::mutations::WarmRevisionPayload`] and revalidate under
    /// the lock before applying the gate result. Tracked for PR-3a.6b /
    /// PR-3b before any caller wires the typed verb live.
    pub fn warm_revision(
        &self,
        env_id: &EnvId,
        payload: WarmRevisionPayload,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let WarmRevisionPayload {
            revision_id,
            health_gate,
            idempotency_key: _,
        } = payload;
        self.run_revision_transition(env_id, revision_id, |locked| {
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
            // Live-state guard. `current_revisions` is plan-level future
            // signal that A3's stage/warm path does not yet maintain, so
            // it can't be the gate. The actual live-state proof is: any
            // traffic split pointing at this deployment, or any
            // non-archived revision for it.
            let active_splits = env
                .traffic_splits
                .iter()
                .filter(|s| s.deployment_id == deployment_id)
                .count();
            let active_revisions = env
                .revisions
                .iter()
                .filter(|r| {
                    r.deployment_id == deployment_id
                        && !matches!(r.lifecycle, RevisionLifecycle::Archived)
                })
                .count();
            if active_splits > 0 || active_revisions > 0 {
                return Err(StoreError::Conflict(format!(
                    "deployment `{deployment_id}` is still live: {active_splits} traffic split(s), \
                     {active_revisions} non-archived revision(s). Archive revisions and clear the \
                     split first."
                )));
            }
            let deployment = env.bundles.remove(idx);
            // Capture the archived revisions BEFORE retaining the rest so
            // the prune set is explicit on the outcome (HTTP backends can
            // apply a separate authz check; audit logs the IDs).
            let pruned_revision_ids: Vec<RevisionId> = env
                .revisions
                .iter()
                .filter(|r| r.deployment_id == deployment_id)
                .map(|r| r.revision_id)
                .collect();
            env.revisions.retain(|r| r.deployment_id != deployment_id);
            locked.save(&env)?;
            Ok(RemoveBundleOutcome {
                deployment,
                pruned_revision_ids,
            })
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
}
