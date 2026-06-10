//! SQLite-backed [`EnvironmentStorage`] — the v1 production backend.
//!
//! Port of the parked Postgres prototype
//! (`crates/greentic-environment-store-postgres`) onto an embedded SQLite
//! file. The store is control-plane-only state: tiny, human-paced
//! mutations — a single file on disk (backed up by file copy or
//! Litestream) is the right operational weight. The pool is capped at
//! **one connection**, so every transaction is fully serialized
//! in-process and the CAS read-check-write windows are trivially
//! race-free (SQLite has no `FOR UPDATE`; it doesn't need one here).

use std::path::Path;
use std::time::Duration;

use greentic_deploy_spec::{
    CapabilitySlot, EnvId, Environment, EnvironmentRuntime, Precondition, SchemaVersion, SpecError,
    StateEtag, StateIntegrity,
};
use serde_json::Value;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow},
};

use crate::storage::{
    EnvRevision, EnvironmentStorage, Loaded, LoadedAnswers, LoadedEnv, LoadedRuntime, StorageError,
};

impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        Self::backend(err)
    }
}

impl From<sqlx::migrate::MigrateError> for StorageError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::backend(err)
    }
}

/// Migrator bundled with this crate; applied by [`SqliteEnvironmentStore::open`].
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// SQLite-backed environment store. Cheap to clone — wraps `sqlx::SqlitePool`.
#[derive(Debug, Clone)]
pub struct SqliteEnvironmentStore {
    pool: SqlitePool,
}

impl SqliteEnvironmentStore {
    /// Open (creating if missing) the SQLite database at `path` and apply
    /// the bundled migrations. Migration is idempotent — sqlx tracks
    /// applied files in `_sqlx_migrations`.
    pub async fn open(path: &Path) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);
        // One connection by design: the server is the single writer, and a
        // single connection serializes every transaction (see module doc).
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

impl EnvironmentStorage for SqliteEnvironmentStore {
    async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    // --- environments ---------------------------------------------------

    async fn list_envs(&self) -> Result<Vec<EnvId>, StorageError> {
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

    async fn exists(&self, env_id: &EnvId) -> Result<bool, StorageError> {
        let row = sqlx::query("SELECT 1 AS one FROM environments WHERE env_id = $1")
            .bind(env_id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn load_env(&self, env_id: &EnvId) -> Result<LoadedEnv, StorageError> {
        let row = sqlx::query(
            "SELECT generation, etag, data, integrity_digest \
             FROM environments WHERE env_id = $1",
        )
        .bind(env_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(StorageError::NotFound(env_id.clone()));
        };
        let (revision, data, stored_digest) = decode_revision_with_data(&row)?;
        let env: Environment = serde_json::from_value(data)?;
        if env.environment_id != *env_id {
            return Err(StorageError::EnvIdMismatch {
                keyed: env_id.clone(),
                payload: env.environment_id,
            });
        }
        env.validate()?;
        let recomputed = StateIntegrity::sha256_of(&env)?;
        if recomputed.digest != stored_digest {
            return Err(StorageError::IntegrityMismatch {
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

    async fn create_env(&self, env: &Environment) -> Result<EnvRevision, StorageError> {
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
        Err(StorageError::AlreadyExists {
            env_id: env.environment_id.clone(),
            generation: generation as u64,
        })
    }

    async fn update_env(
        &self,
        env: &Environment,
        precondition: &Precondition,
    ) -> Result<EnvRevision, StorageError> {
        validate_environment(env)?;
        if !precondition.is_conditional() {
            return Err(StorageError::PreconditionRequired);
        }
        let (etag, integrity, data) = serialize_for_write(env)?;

        let mut tx = self.pool.begin().await?;
        let current = sqlx::query("SELECT generation, etag FROM environments WHERE env_id = $1")
            .bind(env.environment_id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
        let Some(current) = current else {
            return Err(StorageError::NotFound(env.environment_id.clone()));
        };
        let current_rev = decode_revision(&current)?;
        precondition
            .check(&current_rev.etag, current_rev.generation)
            .map_err(|e| StorageError::from_precondition(env.environment_id.clone(), e))?;

        let new_gen = current_rev.generation + 1;
        sqlx::query(
            "UPDATE environments \
             SET data = $1, generation = $2, etag = $3, integrity_digest = $4, \
                 updated_at = datetime('now') \
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

    async fn load_runtime(&self, env_id: &EnvId) -> Result<Option<LoadedRuntime>, StorageError> {
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
            return Err(StorageError::EnvIdMismatch {
                keyed: env_id.clone(),
                payload: runtime.environment_id,
            });
        }
        if runtime.schema.as_str() != SchemaVersion::ENVIRONMENT_RUNTIME_V1 {
            return Err(StorageError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_RUNTIME_V1,
                actual: runtime.schema.as_str().to_string(),
            }));
        }
        let recomputed = StateIntegrity::sha256_of(&runtime)?;
        if recomputed.digest != stored_digest {
            return Err(StorageError::IntegrityMismatch {
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

    async fn upsert_runtime(
        &self,
        runtime: &EnvironmentRuntime,
        precondition: Option<&Precondition>,
    ) -> Result<EnvRevision, StorageError> {
        if runtime.schema.as_str() != SchemaVersion::ENVIRONMENT_RUNTIME_V1 {
            return Err(StorageError::Spec(SpecError::SchemaMismatch {
                expected: SchemaVersion::ENVIRONMENT_RUNTIME_V1,
                actual: runtime.schema.as_str().to_string(),
            }));
        }
        let (etag, integrity, data) = serialize_for_write(runtime)?;

        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT generation, etag FROM environment_runtimes \
             WHERE env_id = $1",
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
                    return Err(StorageError::NotFound(runtime.environment_id.clone()));
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
                    return Err(StorageError::PreconditionRequired);
                };
                let current_rev = decode_revision(&current)?;
                pc.check(&current_rev.etag, current_rev.generation)
                    .map_err(|e| {
                        StorageError::from_precondition(runtime.environment_id.clone(), e)
                    })?;
                let new_gen = current_rev.generation + 1;
                sqlx::query(
                    "UPDATE environment_runtimes \
                     SET data = $1, generation = $2, etag = $3, \
                         integrity_digest = $4, updated_at = datetime('now') \
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

    async fn load_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> Result<Option<LoadedAnswers>, StorageError> {
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
            return Err(StorageError::IntegrityMismatch {
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

    async fn upsert_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        answers: &Value,
        precondition: Option<&Precondition>,
    ) -> Result<EnvRevision, StorageError> {
        let (etag, integrity, data) = serialize_for_write(answers)?;

        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT generation, etag FROM pack_answers \
             WHERE env_id = $1 AND slot = $2",
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
                    return Err(StorageError::NotFound(env_id.clone()));
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
                    return Err(StorageError::PreconditionRequired);
                };
                let current_rev = decode_revision(&current)?;
                pc.check(&current_rev.etag, current_rev.generation)
                    .map_err(|e| StorageError::from_precondition(env_id.clone(), e))?;
                let new_gen = current_rev.generation + 1;
                sqlx::query(
                    "UPDATE pack_answers \
                     SET data = $1, generation = $2, etag = $3, \
                         integrity_digest = $4, updated_at = datetime('now') \
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

    async fn delete_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        precondition: &Precondition,
    ) -> Result<(), StorageError> {
        if !precondition.is_conditional() {
            return Err(StorageError::PreconditionRequired);
        }
        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT generation, etag FROM pack_answers \
             WHERE env_id = $1 AND slot = $2",
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
            .map_err(|e| StorageError::from_precondition(env_id.clone(), e))?;
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

fn validate_environment(env: &Environment) -> Result<(), StorageError> {
    if env.schema.as_str() != SchemaVersion::ENVIRONMENT_V1 {
        return Err(StorageError::Spec(SpecError::SchemaMismatch {
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
) -> Result<(StateEtag, StateIntegrity, Value), StorageError> {
    let integrity = StateIntegrity::sha256_of(value)?;
    let etag = StateEtag::from_integrity(&integrity);
    let data = serde_json::to_value(value)?;
    Ok((etag, integrity, data))
}

fn decode_revision(row: &SqliteRow) -> Result<EnvRevision, StorageError> {
    let generation: i64 = row.try_get("generation")?;
    let etag: String = row.try_get("etag")?;
    Ok(EnvRevision {
        generation: generation as u64,
        etag: StateEtag(etag),
    })
}

fn decode_revision_with_data(
    row: &SqliteRow,
) -> Result<(EnvRevision, Value, String), StorageError> {
    let revision = decode_revision(row)?;
    let data: Value = row.try_get("data")?;
    let integrity_digest: String = row.try_get("integrity_digest")?;
    Ok((revision, data, integrity_digest))
}
