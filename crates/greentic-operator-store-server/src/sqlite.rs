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
//!
//! The single-writer assumption is **enforced** via an exclusive sidecar
//! flock (`<db>.lock`), acquired non-blocking during [`SqliteEnvironmentStore::open`].
//! A second process opening the same file is rejected before a connection
//! is established.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fs4::fs_std::FileExt;
use greentic_deploy_spec::{
    BackupManifest, BundleId, CapabilitySlot, CustomerId, EnvId, Environment, EnvironmentRuntime,
    INTEGRITY_ALGORITHM_SHA256, Precondition, SchemaVersion, SpecError, StateEtag, StateIntegrity,
};
use serde_json::Value;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow},
};

use greentic_operator_trust::trust_root::{TRUST_ROOT_SCHEMA_V1, TrustRootDocument};

use crate::storage::{
    EnvRevision, EnvSnapshot, EnvironmentStorage, Loaded, LoadedAnswers, LoadedEnv, LoadedRuntime,
    LoadedTrustRoot, MutationJournal, RevenuePolicyArtifact, StorageError, StoredBackup,
    StoredIdempotencyRecord,
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
///
/// The `_owner_lock` field holds an exclusive advisory flock on a sidecar
/// `.lock` file next to the database. It survives clones (via `Arc`) and
/// is released when the last clone is dropped.
#[derive(Debug, Clone)]
pub struct SqliteEnvironmentStore {
    pool: SqlitePool,
    _owner_lock: Arc<File>,
}

impl SqliteEnvironmentStore {
    /// Open the SQLite database at `path` (creating file and parent
    /// directories if missing) and apply the bundled migrations.
    ///
    /// An exclusive advisory flock on `<path>.lock` is acquired first
    /// (non-blocking). If another process already holds the lock, this
    /// returns [`StorageError::Backend`] immediately.
    pub async fn open(path: &Path) -> Result<Self, StorageError> {
        // --- sidecar flock (single-writer enforcement) ---
        // The lock sidecar shares the database's parent directory, so this
        // create_dir_all also guarantees the parent `create_if_missing`
        // needs below.
        let lock_path_string = format!("{}.lock", path.display());
        let lock_path = Path::new(&lock_path_string);
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                io_backend(format!("create lock-file parent {}", parent.display()), e)
            })?;
        }
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|e| io_backend(format!("open lock file {}", lock_path.display()), e))?;
        match lock_file.try_lock_exclusive() {
            Ok(true) => {} // acquired
            Ok(false) => {
                return Err(StorageError::backend(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    format!(
                        "database {} is already locked by another operator-store-server process",
                        path.display()
                    ),
                )));
            }
            Err(e) => {
                return Err(io_backend(format!("flock {}", lock_path.display()), e));
            }
        }

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
        Ok(Self {
            pool,
            _owner_lock: Arc::new(lock_file),
        })
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
        verify_integrity(env_id, &data, stored_digest)?;
        let env: Environment = serde_json::from_value(data)?;
        if env.environment_id != *env_id {
            return Err(StorageError::EnvIdMismatch {
                keyed: env_id.clone(),
                payload: env.environment_id,
            });
        }
        env.validate()?;
        Ok(Loaded {
            value: env,
            revision,
        })
    }

    async fn create_env_journaled(
        &self,
        env: &Environment,
        journal: Option<&MutationJournal>,
    ) -> Result<EnvRevision, StorageError> {
        validate_environment(env)?;
        let (etag, integrity, data) = serialize_for_write(env)?;

        // ON CONFLICT DO NOTHING returns zero rows on collision. We then
        // look up the existing generation to give the caller a useful error.
        // The collision path never reaches the journal insert, so a lost
        // create consumes no idempotency key.
        let mut tx = self.pool.begin().await?;
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
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = inserted {
            journal_in_tx(&mut tx, journal).await?;
            tx.commit().await?;
            return decode_revision(&row);
        }
        let existing = sqlx::query("SELECT generation FROM environments WHERE env_id = $1")
            .bind(env.environment_id.as_str())
            .fetch_one(&mut *tx)
            .await?;
        let generation: i64 = existing.try_get("generation")?;
        Err(StorageError::AlreadyExists {
            env_id: env.environment_id.clone(),
            generation: generation as u64,
        })
    }

    async fn update_env_journaled(
        &self,
        env: &Environment,
        precondition: &Precondition,
        journal: Option<&MutationJournal>,
    ) -> Result<EnvRevision, StorageError> {
        let mut tx = self.pool.begin().await?;
        let revision = update_env_in_tx(&mut tx, env, precondition).await?;
        journal_in_tx(&mut tx, journal).await?;
        tx.commit().await?;
        Ok(revision)
    }

    async fn lookup_idempotency(
        &self,
        env_id: &EnvId,
        key: &str,
    ) -> Result<Option<StoredIdempotencyRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT operation, request_fingerprint, response_status, response_body \
             FROM idempotency_ledger WHERE env_id = $1 AND idempotency_key = $2",
        )
        .bind(env_id.as_str())
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let status: i64 = row.try_get("response_status")?;
        Ok(Some(StoredIdempotencyRecord {
            operation: row.try_get("operation")?,
            request_fingerprint: row.try_get("request_fingerprint")?,
            response_status: status as u16,
            response_body: row.try_get("response_body")?,
        }))
    }

    async fn record_journal(&self, journal: &MutationJournal) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        journal_in_tx(&mut tx, Some(journal)).await?;
        tx.commit().await?;
        Ok(())
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
        verify_integrity(env_id, &data, stored_digest)?;
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
        // `deleted = 0`: tombstoned rows are logically absent.
        let row = sqlx::query(
            "SELECT generation, etag, data, integrity_digest \
             FROM pack_answers WHERE env_id = $1 AND slot = $2 AND deleted = 0",
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
        verify_integrity(env_id, &answers, stored_digest)?;
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
            "SELECT generation, etag, deleted FROM pack_answers \
             WHERE env_id = $1 AND slot = $2",
        )
        .bind(env_id.as_str())
        .bind(slot.as_str())
        .fetch_optional(&mut *tx)
        .await?;

        let new_gen = match current {
            None => {
                // No row at all: only allow the create-if-absent path
                // (no precondition). A conditional precondition means
                // the caller expected an existing row.
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
                let deleted: i32 = current.try_get("deleted")?;
                let current_rev = decode_revision(&current)?;

                if deleted != 0 {
                    // Tombstoned row: a conditional precondition expects
                    // a LIVE row — fail with NotFound so stale
                    // preconditions from a previous incarnation can't
                    // ABA-match the new one. Unconditional writes
                    // resurrect, continuing the generation sequence.
                    if precondition.is_some_and(|pc| pc.is_conditional()) {
                        return Err(StorageError::NotFound(env_id.clone()));
                    }
                } else {
                    // Live row: require a conditional precondition.
                    let Some(pc) = precondition else {
                        return Err(StorageError::PreconditionRequired);
                    };
                    pc.check(&current_rev.etag, current_rev.generation)
                        .map_err(|e| StorageError::from_precondition(env_id.clone(), e))?;
                }
                // One write for both cases: `deleted = 0` is a no-op on a
                // live row and resurrects a tombstone.
                let new_gen = current_rev.generation + 1;
                sqlx::query(
                    "UPDATE pack_answers \
                     SET data = $1, generation = $2, etag = $3, \
                         integrity_digest = $4, deleted = 0, \
                         updated_at = datetime('now') \
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

    // --- trust root -------------------------------------------------------

    async fn load_trust_root(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<LoadedTrustRoot>, StorageError> {
        let row = sqlx::query(
            "SELECT generation, etag, data, integrity_digest \
             FROM trust_roots WHERE env_id = $1",
        )
        .bind(env_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let (revision, data, stored_digest) = decode_revision_with_data(&row)?;
        verify_integrity(env_id, &data, stored_digest)?;
        let doc: TrustRootDocument = serde_json::from_value(data)?;
        if doc.schema != TRUST_ROOT_SCHEMA_V1 {
            return Err(StorageError::Spec(SpecError::SchemaMismatch {
                expected: TRUST_ROOT_SCHEMA_V1,
                actual: doc.schema,
            }));
        }
        Ok(Some(Loaded {
            value: doc,
            revision,
        }))
    }

    async fn upsert_trust_root_journaled(
        &self,
        env_id: &EnvId,
        doc: &TrustRootDocument,
        precondition: Option<&Precondition>,
        journal: Option<&MutationJournal>,
    ) -> Result<EnvRevision, StorageError> {
        if doc.schema != TRUST_ROOT_SCHEMA_V1 {
            return Err(StorageError::Spec(SpecError::SchemaMismatch {
                expected: TRUST_ROOT_SCHEMA_V1,
                actual: doc.schema.clone(),
            }));
        }
        let (etag, integrity, data) = serialize_for_write(doc)?;

        let mut tx = self.pool.begin().await?;
        let current = sqlx::query("SELECT generation, etag FROM trust_roots WHERE env_id = $1")
            .bind(env_id.as_str())
            .fetch_optional(&mut *tx)
            .await?;

        let new_gen = match current {
            None => {
                // Row absent: only the create-if-absent path (no
                // precondition) applies — see `upsert_runtime`.
                if precondition.is_some_and(|pc| pc.is_conditional()) {
                    return Err(StorageError::NotFound(env_id.clone()));
                }
                sqlx::query(
                    "INSERT INTO trust_roots \
                     (env_id, generation, etag, data, integrity_digest) \
                     VALUES ($1, 1, $2, $3, $4)",
                )
                .bind(env_id.as_str())
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
                    "UPDATE trust_roots \
                     SET data = $1, generation = $2, etag = $3, \
                         integrity_digest = $4, updated_at = datetime('now') \
                     WHERE env_id = $5",
                )
                .bind(&data)
                .bind(new_gen as i64)
                .bind(&etag.0)
                .bind(&integrity.digest)
                .bind(env_id.as_str())
                .execute(&mut *tx)
                .await?;
                new_gen
            }
        };
        journal_in_tx(&mut tx, journal).await?;
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
            "SELECT generation, etag, deleted FROM pack_answers \
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
        let deleted: i32 = current.try_get("deleted")?;
        if deleted != 0 {
            // Already tombstoned — idempotent no-op (no generation bump).
            return Ok(());
        }
        let current_rev = decode_revision(&current)?;
        precondition
            .check(&current_rev.etag, current_rev.generation)
            .map_err(|e| StorageError::from_precondition(env_id.clone(), e))?;
        let new_gen = current_rev.generation + 1;
        sqlx::query(
            "UPDATE pack_answers \
             SET deleted = 1, generation = $1, updated_at = datetime('now') \
             WHERE env_id = $2 AND slot = $3",
        )
        .bind(new_gen as i64)
        .bind(env_id.as_str())
        .bind(slot.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn update_env_with_revenue_policy_journaled(
        &self,
        env: &Environment,
        precondition: &Precondition,
        artifact: &RevenuePolicyArtifact,
        trust_root_pin: Option<&EnvRevision>,
        journal: Option<&MutationJournal>,
    ) -> Result<EnvRevision, StorageError> {
        let env_id = &env.environment_id;
        let mut tx = self.pool.begin().await?;

        // 1. The trust root the caller signed against must not have moved
        //    (a concurrent revocation between load and commit invalidates
        //    the signature it would otherwise race past).
        let current_root =
            sqlx::query("SELECT generation, etag FROM trust_roots WHERE env_id = $1")
                .bind(env_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;
        let unchanged = match (&current_root, trust_root_pin) {
            (None, None) => true,
            (Some(row), Some(pin)) => decode_revision(row)? == *pin,
            _ => false,
        };
        if !unchanged {
            return Err(StorageError::TrustRootChanged {
                env_id: env_id.clone(),
            });
        }

        // 2. The artifact, INSERT OR REPLACE on its version key (a
        //    same-key replay rebuilding the same version overwrites
        //    rather than duplicates).
        sqlx::query(
            "INSERT OR REPLACE INTO revenue_policies \
             (env_id, bundle_id, customer_id, version, policy_ref, doc, \
              envelope, doc_sha256, key_id, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, datetime('now'))",
        )
        .bind(env_id.as_str())
        .bind(artifact.bundle_id.as_str())
        .bind(artifact.customer_id.as_str())
        .bind(artifact.version as i64)
        .bind(&artifact.policy_ref)
        .bind(&artifact.doc)
        .bind(&artifact.envelope)
        .bind(&artifact.doc_sha256)
        .bind(&artifact.key_id)
        .execute(&mut *tx)
        .await?;

        // 3. The environment under its CAS pin. A conflict here rolls the
        //    artifact back too — committed env state and the artifact it
        //    references commit or fail as one.
        let revision = update_env_in_tx(&mut tx, env, precondition).await?;
        journal_in_tx(&mut tx, journal).await?;
        tx.commit().await?;
        Ok(revision)
    }

    async fn load_revenue_policy(
        &self,
        env_id: &EnvId,
        bundle_id: &BundleId,
        customer_id: &CustomerId,
        version: u64,
    ) -> Result<Option<RevenuePolicyArtifact>, StorageError> {
        let row = sqlx::query(
            "SELECT policy_ref, doc, envelope, doc_sha256, key_id \
             FROM revenue_policies \
             WHERE env_id = $1 AND bundle_id = $2 AND customer_id = $3 \
               AND version = $4",
        )
        .bind(env_id.as_str())
        .bind(bundle_id.as_str())
        .bind(customer_id.as_str())
        .bind(version as i64)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(RevenuePolicyArtifact {
            bundle_id: bundle_id.clone(),
            customer_id: customer_id.clone(),
            version,
            policy_ref: row.try_get("policy_ref")?,
            doc: row.try_get("doc")?,
            envelope: row.try_get("envelope")?,
            doc_sha256: row.try_get("doc_sha256")?,
            key_id: row.try_get("key_id")?,
        }))
    }

    // --- backups (A8 #5, PR-4.4) -----------------------------------------

    async fn create_backup_journaled(
        &self,
        backup: &StoredBackup,
        journal: Option<&MutationJournal>,
    ) -> Result<(), StorageError> {
        let manifest = &backup.manifest;
        let mut tx = self.pool.begin().await?;
        // Cap check inside the same transaction (single-writer pool, so
        // count-then-insert cannot race another create).
        let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM backups WHERE env_id = $1")
            .bind(manifest.env_id.as_str())
            .fetch_one(&mut *tx)
            .await?
            .try_get("n")?;
        if count >= crate::storage::MAX_BACKUPS_PER_ENV {
            return Err(StorageError::BackupLimitReached {
                env_id: manifest.env_id.clone(),
                limit: crate::storage::MAX_BACKUPS_PER_ENV,
            });
        }
        sqlx::query(
            "INSERT INTO backups \
             (env_id, backup_id, created_at, generation, integrity, size_bytes, state, \
              snapshot_digest) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(manifest.env_id.as_str())
        .bind(&manifest.backup_id)
        .bind(manifest.created_at.to_rfc3339())
        .bind(manifest.generation as i64)
        .bind(&manifest.integrity.digest)
        .bind(manifest.size_bytes as i64)
        .bind(&backup.state)
        .bind(&backup.snapshot_digest)
        .execute(&mut *tx)
        .await?;
        journal_in_tx(&mut tx, journal).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn list_backups(&self, env_id: &EnvId) -> Result<Vec<BackupManifest>, StorageError> {
        let rows = sqlx::query(
            "SELECT backup_id, created_at, generation, integrity, size_bytes \
             FROM backups WHERE env_id = $1 ORDER BY backup_id",
        )
        .bind(env_id.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| decode_backup_manifest(env_id, row))
            .collect()
    }

    async fn load_backup(
        &self,
        env_id: &EnvId,
        backup_id: &str,
    ) -> Result<Option<StoredBackup>, StorageError> {
        let row = sqlx::query(
            "SELECT backup_id, created_at, generation, integrity, size_bytes, state, \
                    snapshot_digest \
             FROM backups WHERE env_id = $1 AND backup_id = $2",
        )
        .bind(env_id.as_str())
        .bind(backup_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(StoredBackup {
            manifest: decode_backup_manifest(env_id, &row)?,
            state: row.try_get("state")?,
            snapshot_digest: row.try_get("snapshot_digest")?,
        }))
    }

    async fn delete_backup_journaled(
        &self,
        env_id: &EnvId,
        backup_id: &str,
        journal: Option<&MutationJournal>,
    ) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin().await?;
        let deleted = sqlx::query("DELETE FROM backups WHERE env_id = $1 AND backup_id = $2")
            .bind(env_id.as_str())
            .bind(backup_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if deleted == 0 {
            // Nothing happened — write nothing (the journal must never
            // record a mutation that did not apply).
            return Ok(false);
        }
        journal_in_tx(&mut tx, journal).await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn load_env_snapshot(&self, env_id: &EnvId) -> Result<EnvSnapshot, StorageError> {
        // One transaction so the capture cannot be torn by an interleaved
        // mutation (the single-connection pool serializes statements but
        // NOT multi-statement sequences outside a tx).
        let mut tx = self.pool.begin().await?;

        // Environment row (required — callers already verified existence).
        let env_row = sqlx::query("SELECT data FROM environments WHERE env_id = $1")
            .bind(env_id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
        let Some(env_row) = env_row else {
            return Err(StorageError::NotFound(env_id.clone()));
        };
        let environment: Value = env_row.try_get("data")?;

        // Runtime sidecar (optional).
        let runtime_row = sqlx::query("SELECT data FROM environment_runtimes WHERE env_id = $1")
            .bind(env_id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
        let runtime: Option<Value> = match runtime_row {
            Some(row) => Some(row.try_get("data")?),
            None => None,
        };

        // Pack-answers sidecars (optional, only live rows).
        let answer_rows =
            sqlx::query("SELECT slot, data FROM pack_answers WHERE env_id = $1 AND deleted = 0")
                .bind(env_id.as_str())
                .fetch_all(&mut *tx)
                .await?;
        let mut pack_answers = std::collections::BTreeMap::new();
        for row in &answer_rows {
            let slot: String = row.try_get("slot")?;
            let data: Value = row.try_get("data")?;
            pack_answers.insert(slot, data);
        }

        tx.commit().await?;
        Ok(EnvSnapshot {
            environment,
            runtime,
            pack_answers,
        })
    }

    async fn restore_env_journaled(
        &self,
        env_id: &EnvId,
        snapshot: &EnvSnapshot,
        precondition: &Precondition,
        journal: Option<&MutationJournal>,
    ) -> Result<EnvRevision, StorageError> {
        // Decode + validate the environment from the snapshot before writing.
        let env: Environment = serde_json::from_value(snapshot.environment.clone())?;
        validate_environment(&env)?;

        let mut tx = self.pool.begin().await?;

        // 1. CAS-guarded environment update.
        let revision = update_env_in_tx(&mut tx, &env, precondition).await?;

        // 2. Runtime sidecar: upsert if present in snapshot, delete if absent.
        //    Generation must continue the existing sequence (never reset to 1
        //    when a row exists — mirrors `upsert_runtime`'s invariant).
        match &snapshot.runtime {
            Some(runtime_data) => {
                let (etag, integrity, data) = serialize_for_write_value(runtime_data)?;
                let existing =
                    sqlx::query("SELECT 1 AS one FROM environment_runtimes WHERE env_id = $1")
                        .bind(env_id.as_str())
                        .fetch_optional(&mut *tx)
                        .await?;
                if existing.is_some() {
                    sqlx::query(
                        "UPDATE environment_runtimes \
                         SET data = $1, generation = generation + 1, etag = $2, \
                             integrity_digest = $3, updated_at = datetime('now') \
                         WHERE env_id = $4",
                    )
                    .bind(&data)
                    .bind(&etag.0)
                    .bind(&integrity.digest)
                    .bind(env_id.as_str())
                    .execute(&mut *tx)
                    .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO environment_runtimes \
                         (env_id, generation, etag, data, integrity_digest) \
                         VALUES ($1, 1, $2, $3, $4)",
                    )
                    .bind(env_id.as_str())
                    .bind(&etag.0)
                    .bind(&data)
                    .bind(&integrity.digest)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            None => {
                // Hard delete is the only expressible "absent" for runtimes
                // (the table has no tombstone column and no other delete path).
                sqlx::query("DELETE FROM environment_runtimes WHERE env_id = $1")
                    .bind(env_id.as_str())
                    .execute(&mut *tx)
                    .await?;
            }
        }

        // 3. Pack-answers sidecars: tombstone-preserving restore.
        //    The `pack_answers` table uses a `deleted` tombstone column so
        //    generation sequences survive delete/recreate cycles (ABA
        //    protection). A restore must continue those sequences, never
        //    reset to 1 when a row already exists.
        let existing_rows =
            sqlx::query("SELECT slot, generation, deleted FROM pack_answers WHERE env_id = $1")
                .bind(env_id.as_str())
                .fetch_all(&mut *tx)
                .await?;
        let mut existing_map: std::collections::HashMap<String, (u64, bool)> =
            std::collections::HashMap::new();
        for row in &existing_rows {
            let slot: String = row.try_get("slot")?;
            let generation: i64 = row.try_get("generation")?;
            let deleted: i32 = row.try_get("deleted")?;
            existing_map.insert(slot, (generation as u64, deleted != 0));
        }

        // (a) Snapshot slots: upsert (continuing generation) or insert.
        for (slot, answers_data) in &snapshot.pack_answers {
            let (etag, integrity, data) = serialize_for_write_value(answers_data)?;
            if let Some(&(old_gen, _)) = existing_map.get(slot.as_str()) {
                // Row exists (live or tombstoned): update, continuing the
                // generation sequence. `deleted = 0` resurrects a tombstone.
                sqlx::query(
                    "UPDATE pack_answers \
                     SET data = $1, generation = $2, etag = $3, \
                         integrity_digest = $4, deleted = 0, \
                         updated_at = datetime('now') \
                     WHERE env_id = $5 AND slot = $6",
                )
                .bind(&data)
                .bind((old_gen + 1) as i64)
                .bind(&etag.0)
                .bind(&integrity.digest)
                .bind(env_id.as_str())
                .bind(slot.as_str())
                .execute(&mut *tx)
                .await?;
            } else {
                // No row at all: first incarnation, generation 1.
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
            }
        }

        // (b) Live rows NOT in the snapshot: soft-delete (tombstone),
        //     mirroring `delete_pack_answers`. Already-tombstoned rows
        //     not in the snapshot stay untouched.
        for (slot, &(old_gen, is_deleted)) in &existing_map {
            if !is_deleted && !snapshot.pack_answers.contains_key(slot.as_str()) {
                sqlx::query(
                    "UPDATE pack_answers \
                     SET deleted = 1, generation = $1, \
                         updated_at = datetime('now') \
                     WHERE env_id = $2 AND slot = $3",
                )
                .bind((old_gen + 1) as i64)
                .bind(env_id.as_str())
                .bind(slot.as_str())
                .execute(&mut *tx)
                .await?;
            }
        }

        journal_in_tx(&mut tx, journal).await?;
        tx.commit().await?;
        Ok(revision)
    }

    async fn record_audit(
        &self,
        env_id: &EnvId,
        event_id: &str,
        event: &Value,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO audit_log (env_id, event_id, event) VALUES ($1, $2, $3)")
            .bind(env_id.as_str())
            .bind(event_id)
            .bind(event)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// --- helpers ------------------------------------------------------------

/// Write a [`MutationJournal`]'s ledger + audit rows inside the caller's
/// transaction (PR-4.3). `None` is a no-op so the journal-free trait
/// defaults share the same code paths.
///
/// The ledger insert is a plain INSERT against the `(env_id,
/// idempotency_key)` primary key: a violation means a concurrent request
/// committed the same key between this request's replay-gate lookup and
/// its commit — surfaced as [`StorageError::IdempotencyKeyCommitted`], the
/// caller's whole transaction (mutation included) rolls back, and the
/// retry replays the winner's stored response.
async fn journal_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    journal: Option<&MutationJournal>,
) -> Result<(), StorageError> {
    let Some(journal) = journal else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO idempotency_ledger \
         (env_id, idempotency_key, operation, request_fingerprint, \
          response_status, response_body) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(journal.env_id.as_str())
    .bind(&journal.idempotency_key)
    .bind(&journal.operation)
    .bind(&journal.request_fingerprint)
    .bind(journal.response_status as i64)
    .bind(&journal.response_body)
    .execute(&mut **tx)
    .await
    .map_err(|err| match &err {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            StorageError::IdempotencyKeyCommitted {
                env_id: journal.env_id.clone(),
                key: journal.idempotency_key.clone(),
            }
        }
        _ => StorageError::from(err),
    })?;
    sqlx::query(
        "DELETE FROM idempotency_ledger WHERE env_id = $1 AND rowid NOT IN ( \
         SELECT rowid FROM idempotency_ledger WHERE env_id = $1 \
         ORDER BY rowid DESC LIMIT $2)",
    )
    .bind(journal.env_id.as_str())
    .bind(crate::storage::MAX_LEDGER_ROWS_PER_ENV)
    .execute(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO audit_log (env_id, event_id, event) VALUES ($1, $2, $3)")
        .bind(journal.env_id.as_str())
        .bind(&journal.audit_event_id)
        .bind(&journal.audit_event)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Rebuild a [`BackupManifest`] from its row. The schema and integrity
/// algorithm are constants of this backend (every backup is created by
/// [`EnvironmentStorage::create_backup_journaled`] with
/// `StateIntegrity::sha256_of`), so only the digest is stored.
fn decode_backup_manifest(env_id: &EnvId, row: &SqliteRow) -> Result<BackupManifest, StorageError> {
    let created_at: String = row.try_get("created_at")?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map_err(StorageError::backend)?
        .with_timezone(&chrono::Utc);
    let generation: i64 = row.try_get("generation")?;
    let size_bytes: i64 = row.try_get("size_bytes")?;
    Ok(BackupManifest {
        schema: SchemaVersion::BACKUP_MANIFEST_V1.into(),
        backup_id: row.try_get("backup_id")?,
        env_id: env_id.clone(),
        created_at,
        generation: generation as u64,
        integrity: StateIntegrity {
            algorithm: INTEGRITY_ALGORITHM_SHA256.to_string(),
            digest: row.try_get("integrity")?,
        },
        size_bytes: size_bytes as u64,
    })
}

/// CAS-checked environment UPDATE inside an existing transaction — the
/// shared body of `update_env` and `update_env_with_revenue_policy`. The
/// caller owns commit/rollback.
async fn update_env_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    env: &Environment,
    precondition: &Precondition,
) -> Result<EnvRevision, StorageError> {
    validate_environment(env)?;
    if !precondition.is_conditional() {
        return Err(StorageError::PreconditionRequired);
    }
    let (etag, integrity, data) = serialize_for_write(env)?;

    let current = sqlx::query("SELECT generation, etag FROM environments WHERE env_id = $1")
        .bind(env.environment_id.as_str())
        .fetch_optional(&mut **tx)
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
    .execute(&mut **tx)
    .await?;

    Ok(EnvRevision {
        generation: new_gen,
        etag,
    })
}

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
/// to be written. Serializes to `Value` first, then hashes the raw `Value`
/// so that the write-side digest matches the load-side raw-first check.
fn serialize_for_write<T: serde::Serialize>(
    value: &T,
) -> Result<(StateEtag, StateIntegrity, Value), StorageError> {
    let data = serde_json::to_value(value)?;
    let integrity = StateIntegrity::sha256_of(&data)?;
    let etag = StateEtag::from_integrity(&integrity);
    Ok((etag, integrity, data))
}

/// [`serialize_for_write`] for an already-serialized `Value` — used by the
/// restore path where the snapshot carries raw JSON, not typed structs.
fn serialize_for_write_value(
    data: &Value,
) -> Result<(StateEtag, StateIntegrity, Value), StorageError> {
    let integrity = StateIntegrity::sha256_of(data)?;
    let etag = StateEtag::from_integrity(&integrity);
    Ok((etag, integrity, data.clone()))
}

/// Wrap an `io::Error` with call-site context as a [`StorageError::Backend`].
fn io_backend(context: String, err: std::io::Error) -> StorageError {
    StorageError::backend(std::io::Error::new(err.kind(), format!("{context}: {err}")))
}

/// Verify the stored digest against the RAW `Value` BEFORE typed
/// deserialization — serde silently drops unknown fields, so a post-typed
/// check would miss injected top-level keys.
fn verify_integrity(
    env_id: &EnvId,
    data: &Value,
    stored_digest: String,
) -> Result<(), StorageError> {
    let recomputed = StateIntegrity::sha256_of(data)?;
    if recomputed.digest != stored_digest {
        return Err(StorageError::IntegrityMismatch {
            env_id: env_id.clone(),
            stored: stored_digest,
            recomputed: recomputed.digest,
        });
    }
    Ok(())
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
