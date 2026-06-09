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
    EnvId, Environment, EnvironmentHostConfig, HealthStatus, IdempotencyKey, RetentionPolicy,
    Revision, RevisionLifecycle, RevocationConfig, SchemaVersion,
};

use super::mutations::{
    ExtensionKey, MigrateMergePayload, StageRevisionPayload, TrustRootAddOutcome,
    TrustRootRemoveOutcome, TrustRootSeed, UpdateEnvironmentPayload,
};
use super::store::{LocalFsStore, StoreError};
use super::trust_root::{self as store_trust_root, trust_root_path};

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
