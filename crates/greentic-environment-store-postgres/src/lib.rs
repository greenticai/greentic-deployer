//! Postgres-backed `EnvironmentStore` prototype.
//!
//! Phase D §13.5 prereq #2 — see `plans/next-gen-deployment.md` and
//! `greentic-operator/docs/remote-environment-store-contract.md` (the A8
//! contract this impl realizes). This crate is the production-grade
//! backing for `Environment` + `EnvironmentRuntime` + per-slot pack
//! answers, complementing `LocalFsStore` in the deployer crate's
//! `environment::store` module.
//!
//! Scope of PR-1 (prototype):
//!
//! - Three rows of state: `environments`, `environment_runtimes`,
//!   `pack_answers` — covering A8 contract clauses #1 (optimistic CAS via
//!   `generation` + `etag`) and #6 (at-rest integrity hash).
//! - **Async-native** API. The sync [`EnvironmentStore`] trait in the
//!   deployer crate is **deliberately not** implemented here — see the
//!   crate-level note below.
//! - Tests are `testcontainers`-driven; see `tests/integration.rs`.
//!
//! Out of scope, intentional follow-ups:
//!
//! - Audit log (`audit_events` table — contract #4)
//! - Idempotency replay (`idempotency_records` table — contract #2)
//! - Backup / restore (`backups` table — contract #5)
//! - RBAC / RLS (contract #3)
//! - Adapter that lets a deployer-side caller swap `LocalFsStore` for
//!   this impl. The current sync trait expects sync methods. Bridging is
//!   PR-2's job.
//!
//! # Why the trait is not implemented here
//!
//! `greentic_deployer::environment::EnvironmentStore` is sync (with a
//! `// Wrap in tokio::task::spawn_blocking at call sites that need
//! async.` doc-comment). sqlx is async-native; bridging via
//! `Runtime::block_on` from a blocking thread is workable, but the
//! conversation around PR-1 settled on shipping the prototype clean
//! and converting the trait + every caller in a focused follow-up. The
//! public surface here is therefore async and concrete — `PostgresEnvironmentStore`
//! is the type the future async trait will hang off.

use std::time::Duration;

use greentic_deploy_spec::{
    CapabilitySlot, ConcurrencyConflict, EnvId, Environment, EnvironmentRuntime, IntegrityError,
    Precondition, PreconditionError, SchemaVersion, SpecError, StateEtag, StateIntegrity,
};
use serde_json::Value;
use sqlx::{
    PgPool, Row,
    postgres::{PgPoolOptions, PgRow},
};
use thiserror::Error;

/// Migrator bundled with this crate; call [`PostgresEnvironmentStore::migrate`]
/// to apply against a connected database.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Server-observed revision of a stored resource. Returned from every
/// successful mutation so the caller can build a [`Precondition`] for the
/// next write without an extra round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvRevision {
    pub generation: u64,
    pub etag: StateEtag,
}

/// A loaded resource paired with its server-observed revision.
///
/// `Eq` is intentionally not derived: the runtime + answers payload types
/// contain non-`Eq` fields (`serde_json::Value`, `BTreeMap` values), and
/// one consistent shape across all `T` beats a per-resource struct.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded<T> {
    pub value: T,
    pub revision: EnvRevision,
}

/// `load_env` return type.
pub type LoadedEnv = Loaded<Environment>;
/// `load_runtime` return type.
pub type LoadedRuntime = Loaded<EnvironmentRuntime>;
/// `load_pack_answers` return type.
pub type LoadedAnswers = Loaded<Value>;

/// Errors surfaced by the Postgres store.
///
/// Variants map cleanly onto the [`greentic_deploy_spec::RemoteStoreError`]
/// HTTP status table for a future HTTP fronting layer:
///
/// | Variant | HTTP equivalent |
/// |---|---|
/// | `NotFound` | `404` |
/// | `AlreadyExists` | `409` |
/// | `PreconditionRequired` | `428` |
/// | `PreconditionFailed` | `412` |
/// | `IntegrityMismatch` | `422` |
/// | `Spec` / `EnvIdMismatch` | `400` |
/// | `Sqlx` / `Migrate` / `Json` / `Integrity` | `500` |
#[derive(Debug, Error)]
pub enum PgStoreError {
    #[error("environment `{0}` not found")]
    NotFound(EnvId),
    #[error("environment `{env_id}` already exists at generation {generation}")]
    AlreadyExists { env_id: EnvId, generation: u64 },
    #[error("a conditional write must pin If-Match and/or expected generation")]
    PreconditionRequired,
    #[error("precondition failed for `{env_id}`")]
    PreconditionFailed {
        env_id: EnvId,
        conflict: ConcurrencyConflict,
    },
    #[error(
        "integrity mismatch on `{env_id}`: stored digest `{stored}` != recomputed `{recomputed}`"
    )]
    IntegrityMismatch {
        env_id: EnvId,
        stored: String,
        recomputed: String,
    },
    #[error("environment_id mismatch: row keyed by `{keyed}`, payload says `{payload}`")]
    EnvIdMismatch { keyed: EnvId, payload: EnvId },
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

impl PgStoreError {
    fn from_precondition(env_id: EnvId, err: PreconditionError) -> Self {
        match err {
            PreconditionError::Required => Self::PreconditionRequired,
            PreconditionError::Conflict(conflict) => Self::PreconditionFailed { env_id, conflict },
        }
    }
}

/// Postgres-backed environment store. Cheap to clone — wraps `sqlx::PgPool`.
#[derive(Debug, Clone)]
pub struct PostgresEnvironmentStore {
    pool: PgPool,
}

impl PostgresEnvironmentStore {
    /// Connect a pool against `database_url`. Defaults: max 5 connections,
    /// 10-second acquire timeout. Callers that need different sizing can
    /// build their own pool and use [`PostgresEnvironmentStore::from_pool`].
    pub async fn connect(database_url: &str) -> Result<Self, PgStoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Wrap an externally-managed pool (e.g. a per-service pool with
    /// caller-specified sizing or TLS config).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply the bundled migrations. Idempotent — sqlx tracks applied
    /// migrations in `_sqlx_migrations`.
    pub async fn migrate(&self) -> Result<(), PgStoreError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    // --- environments ---------------------------------------------------

    /// List every persisted environment id, alphabetically.
    pub async fn list_envs(&self) -> Result<Vec<EnvId>, PgStoreError> {
        let rows = sqlx::query("SELECT env_id FROM environments ORDER BY env_id ASC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let s: String = r.try_get("env_id").ok()?;
                EnvId::try_from(s.as_str()).ok()
            })
            .collect())
    }

    /// Return whether `env_id` exists.
    pub async fn exists(&self, env_id: &EnvId) -> Result<bool, PgStoreError> {
        let row = sqlx::query("SELECT 1 AS one FROM environments WHERE env_id = $1")
            .bind(env_id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Load `env_id`'s environment along with its revision. Verifies the
    /// stored integrity digest against the canonical JSON of the decoded
    /// payload before returning — corruption surfaces as
    /// [`PgStoreError::IntegrityMismatch`] (contract #6).
    pub async fn load_env(&self, env_id: &EnvId) -> Result<LoadedEnv, PgStoreError> {
        let row = sqlx::query(
            "SELECT generation, etag, data, integrity_digest \
             FROM environments WHERE env_id = $1",
        )
        .bind(env_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(PgStoreError::NotFound(env_id.clone()));
        };
        let (revision, data, stored_digest) = decode_revision_with_data(&row)?;
        let env: Environment = serde_json::from_value(data)?;
        if env.environment_id != *env_id {
            return Err(PgStoreError::EnvIdMismatch {
                keyed: env_id.clone(),
                payload: env.environment_id,
            });
        }
        env.validate()?;
        let recomputed = StateIntegrity::sha256_of(&env)?;
        if recomputed.digest != stored_digest {
            return Err(PgStoreError::IntegrityMismatch {
                env_id: env_id.clone(),
                stored: stored_digest,
                recomputed: recomputed.digest,
            });
        }
        Ok(Loaded {
            value: env,
            revision,
        })
    }

    /// Create `env` if-absent. Fails [`PgStoreError::AlreadyExists`] if the
    /// row already exists; never silently overwrites (contract create-if-absent
    /// rule).
    pub async fn create_env(&self, env: &Environment) -> Result<EnvRevision, PgStoreError> {
        validate_environment(env)?;
        let (etag, integrity, data) = serialize_for_write(env)?;

        // ON CONFLICT DO NOTHING returns zero rows on collision. We then
        // look up the existing generation to give the caller a useful error.
        let inserted = sqlx::query(
            "INSERT INTO environments (env_id, generation, etag, data, integrity_digest) \
             VALUES ($1, 1, $2, $3, $4) \
             ON CONFLICT (env_id) DO NOTHING \
             RETURNING generation, etag",
        )
        .bind(env.environment_id.as_str())
        .bind(&etag.0)
        .bind(&data)
        .bind(&integrity.digest)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = inserted {
            return decode_revision(&row);
        }
        let existing = sqlx::query("SELECT generation FROM environments WHERE env_id = $1")
            .bind(env.environment_id.as_str())
            .fetch_one(&self.pool)
            .await?;
        let generation: i64 = existing.try_get("generation")?;
        Err(PgStoreError::AlreadyExists {
            env_id: env.environment_id.clone(),
            generation: generation as u64,
        })
    }

    /// Update `env` under `precondition`. Rejects an empty precondition
    /// with [`PgStoreError::PreconditionRequired`] (contract #1, blind
    /// writes never apply).
    pub async fn update_env(
        &self,
        env: &Environment,
        precondition: &Precondition,
    ) -> Result<EnvRevision, PgStoreError> {
        validate_environment(env)?;
        if !precondition.is_conditional() {
            return Err(PgStoreError::PreconditionRequired);
        }
        let (etag, integrity, data) = serialize_for_write(env)?;

        let mut tx = self.pool.begin().await?;
        let current =
            sqlx::query("SELECT generation, etag FROM environments WHERE env_id = $1 FOR UPDATE")
                .bind(env.environment_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;
        let Some(current) = current else {
            return Err(PgStoreError::NotFound(env.environment_id.clone()));
        };
        let current_rev = decode_revision(&current)?;
        precondition
            .check(&current_rev.etag, current_rev.generation)
            .map_err(|e| PgStoreError::from_precondition(env.environment_id.clone(), e))?;

        let new_gen = current_rev.generation + 1;
        sqlx::query(
            "UPDATE environments \
             SET data = $1, generation = $2, etag = $3, integrity_digest = $4, updated_at = NOW() \
             WHERE env_id = $5",
        )
        .bind(&data)
        .bind(new_gen as i64)
        .bind(&etag.0)
        .bind(&integrity.digest)
        .bind(env.environment_id.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(EnvRevision {
            generation: new_gen,
            etag,
        })
    }

    // --- runtime --------------------------------------------------------

    pub async fn load_runtime(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<LoadedRuntime>, PgStoreError> {
        let row = sqlx::query(
            "SELECT generation, etag, data, integrity_digest \
             FROM environment_runtimes WHERE env_id = $1",
        )
        .bind(env_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let (revision, data, stored_digest) = decode_revision_with_data(&row)?;
        let runtime: EnvironmentRuntime = serde_json::from_value(data)?;
        if runtime.environment_id != *env_id {
            return Err(PgStoreError::EnvIdMismatch {
                keyed: env_id.clone(),
                payload: runtime.environment_id,
            });
        }
        if runtime.schema.as_str() != SchemaVersion::ENVIRONMENT_RUNTIME_V1 {
            return Err(PgStoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_RUNTIME_V1,
                actual: runtime.schema.as_str().to_string(),
            }));
        }
        let recomputed = StateIntegrity::sha256_of(&runtime)?;
        if recomputed.digest != stored_digest {
            return Err(PgStoreError::IntegrityMismatch {
                env_id: env_id.clone(),
                stored: stored_digest,
                recomputed: recomputed.digest,
            });
        }
        Ok(Some(Loaded {
            value: runtime,
            revision,
        }))
    }

    /// Upsert the runtime. On first write (no existing row) `precondition`
    /// is ignored — that is the create-if-absent path. On subsequent
    /// writes `precondition` must be conditional.
    pub async fn upsert_runtime(
        &self,
        runtime: &EnvironmentRuntime,
        precondition: Option<&Precondition>,
    ) -> Result<EnvRevision, PgStoreError> {
        if runtime.schema.as_str() != SchemaVersion::ENVIRONMENT_RUNTIME_V1 {
            return Err(PgStoreError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_RUNTIME_V1,
                actual: runtime.schema.as_str().to_string(),
            }));
        }
        let (etag, integrity, data) = serialize_for_write(runtime)?;

        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT generation, etag FROM environment_runtimes \
             WHERE env_id = $1 FOR UPDATE",
        )
        .bind(runtime.environment_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;

        let new_gen = match current {
            None => {
                // Row absent: only allow the create-if-absent path
                // (no precondition). A conditional precondition here
                // means the caller expected an existing row — another
                // actor deleted it in the meantime. Resurrecting with
                // stale data would break CAS.
                if precondition.is_some_and(|pc| pc.is_conditional()) {
                    return Err(PgStoreError::NotFound(runtime.environment_id.clone()));
                }
                sqlx::query(
                    "INSERT INTO environment_runtimes \
                     (env_id, generation, etag, data, integrity_digest) \
                     VALUES ($1, 1, $2, $3, $4)",
                )
                .bind(runtime.environment_id.as_str())
                .bind(&etag.0)
                .bind(&data)
                .bind(&integrity.digest)
                .execute(&mut *tx)
                .await?;
                1
            }
            Some(current) => {
                let Some(pc) = precondition else {
                    return Err(PgStoreError::PreconditionRequired);
                };
                let current_rev = decode_revision(&current)?;
                pc.check(&current_rev.etag, current_rev.generation)
                    .map_err(|e| {
                        PgStoreError::from_precondition(runtime.environment_id.clone(), e)
                    })?;
                let new_gen = current_rev.generation + 1;
                sqlx::query(
                    "UPDATE environment_runtimes \
                     SET data = $1, generation = $2, etag = $3, \
                         integrity_digest = $4, updated_at = NOW() \
                     WHERE env_id = $5",
                )
                .bind(&data)
                .bind(new_gen as i64)
                .bind(&etag.0)
                .bind(&integrity.digest)
                .bind(runtime.environment_id.as_str())
                .execute(&mut *tx)
                .await?;
                new_gen
            }
        };
        tx.commit().await?;
        Ok(EnvRevision {
            generation: new_gen,
            etag,
        })
    }

    // --- pack answers ---------------------------------------------------

    pub async fn load_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> Result<Option<LoadedAnswers>, PgStoreError> {
        let row = sqlx::query(
            "SELECT generation, etag, data, integrity_digest \
             FROM pack_answers WHERE env_id = $1 AND slot = $2",
        )
        .bind(env_id.as_str())
        .bind(slot.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        // `data` is `Value` on both sides of the row boundary — no
        // additional `from_value` round-trip is needed.
        let (revision, answers, stored_digest) = decode_revision_with_data(&row)?;
        let recomputed = StateIntegrity::sha256_of(&answers)?;
        if recomputed.digest != stored_digest {
            return Err(PgStoreError::IntegrityMismatch {
                env_id: env_id.clone(),
                stored: stored_digest,
                recomputed: recomputed.digest,
            });
        }
        Ok(Some(Loaded {
            value: answers,
            revision,
        }))
    }

    /// Upsert pack answers under `(env_id, slot)`. Same semantics as
    /// [`Self::upsert_runtime`] — first write is unconditional, later
    /// writes require a conditional precondition.
    pub async fn upsert_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        answers: &Value,
        precondition: Option<&Precondition>,
    ) -> Result<EnvRevision, PgStoreError> {
        let (etag, integrity, data) = serialize_for_write(answers)?;

        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT generation, etag FROM pack_answers \
             WHERE env_id = $1 AND slot = $2 FOR UPDATE",
        )
        .bind(env_id.as_str())
        .bind(slot.as_str())
        .fetch_optional(&mut *tx)
        .await?;

        let new_gen = match current {
            None => {
                // Row absent: only allow the create-if-absent path
                // (no precondition). A conditional precondition means
                // the caller expected an existing row — another actor
                // deleted it. Resurrecting would break CAS.
                if precondition.is_some_and(|pc| pc.is_conditional()) {
                    return Err(PgStoreError::NotFound(env_id.clone()));
                }
                sqlx::query(
                    "INSERT INTO pack_answers \
                     (env_id, slot, generation, etag, data, integrity_digest) \
                     VALUES ($1, $2, 1, $3, $4, $5)",
                )
                .bind(env_id.as_str())
                .bind(slot.as_str())
                .bind(&etag.0)
                .bind(&data)
                .bind(&integrity.digest)
                .execute(&mut *tx)
                .await?;
                1
            }
            Some(current) => {
                let Some(pc) = precondition else {
                    return Err(PgStoreError::PreconditionRequired);
                };
                let current_rev = decode_revision(&current)?;
                pc.check(&current_rev.etag, current_rev.generation)
                    .map_err(|e| PgStoreError::from_precondition(env_id.clone(), e))?;
                let new_gen = current_rev.generation + 1;
                sqlx::query(
                    "UPDATE pack_answers \
                     SET data = $1, generation = $2, etag = $3, \
                         integrity_digest = $4, updated_at = NOW() \
                     WHERE env_id = $5 AND slot = $6",
                )
                .bind(&data)
                .bind(new_gen as i64)
                .bind(&etag.0)
                .bind(&integrity.digest)
                .bind(env_id.as_str())
                .bind(slot.as_str())
                .execute(&mut *tx)
                .await?;
                new_gen
            }
        };
        tx.commit().await?;
        Ok(EnvRevision {
            generation: new_gen,
            etag,
        })
    }

    /// Delete pack answers under `(env_id, slot)` with a guarded
    /// precondition. Missing rows are a no-op (delete is idempotent).
    pub async fn delete_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        precondition: &Precondition,
    ) -> Result<(), PgStoreError> {
        if !precondition.is_conditional() {
            return Err(PgStoreError::PreconditionRequired);
        }
        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT generation, etag FROM pack_answers \
             WHERE env_id = $1 AND slot = $2 FOR UPDATE",
        )
        .bind(env_id.as_str())
        .bind(slot.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current) = current else {
            // Idempotent delete: nothing to remove.
            return Ok(());
        };
        let current_rev = decode_revision(&current)?;
        precondition
            .check(&current_rev.etag, current_rev.generation)
            .map_err(|e| PgStoreError::from_precondition(env_id.clone(), e))?;
        sqlx::query(
            "DELETE FROM pack_answers \
             WHERE env_id = $1 AND slot = $2",
        )
        .bind(env_id.as_str())
        .bind(slot.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

// --- helpers ------------------------------------------------------------

fn validate_environment(env: &Environment) -> Result<(), PgStoreError> {
    if env.schema.as_str() != SchemaVersion::ENVIRONMENT_V1 {
        return Err(PgStoreError::Spec(SpecError::SchemaMismatch {
            expected: SchemaVersion::ENVIRONMENT_V1,
            actual: env.schema.as_str().to_string(),
        }));
    }
    env.validate()?;
    Ok(())
}

/// Compute `(etag, integrity, data_value)` once for a payload that's about
/// to be written. Keeps the call sites from re-deriving the same things.
fn serialize_for_write<T: serde::Serialize>(
    value: &T,
) -> Result<(StateEtag, StateIntegrity, Value), PgStoreError> {
    let integrity = StateIntegrity::sha256_of(value)?;
    let etag = StateEtag::from_integrity(&integrity);
    let data = serde_json::to_value(value)?;
    Ok((etag, integrity, data))
}

fn decode_revision(row: &PgRow) -> Result<EnvRevision, PgStoreError> {
    let generation: i64 = row.try_get("generation")?;
    let etag: String = row.try_get("etag")?;
    Ok(EnvRevision {
        generation: generation as u64,
        etag: StateEtag(etag),
    })
}

fn decode_revision_with_data(row: &PgRow) -> Result<(EnvRevision, Value, String), PgStoreError> {
    let revision = decode_revision(row)?;
    let data: Value = row.try_get("data")?;
    let integrity_digest: String = row.try_get("integrity_digest")?;
    Ok((revision, data, integrity_digest))
}
