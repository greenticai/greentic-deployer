//! Backend-agnostic storage contract for the operator store server.
//!
//! The trait mirrors the concrete surface of the parked Postgres
//! prototype (`crates/greentic-environment-store-postgres`) so that
//! backend can implement it later without reshaping. v1 ships SQLite
//! only ([`crate::sqlite::SqliteEnvironmentStore`]).

use std::future::Future;

use greentic_deploy_spec::{
    BackupManifest, BundleId, CapabilitySlot, ConcurrencyConflict, CustomerId, EnvId, Environment,
    EnvironmentRuntime, IntegrityError, Precondition, PreconditionError, SpecError, StateEtag,
};
use greentic_operator_trust::trust_root::TrustRootDocument;
use serde_json::Value;
use thiserror::Error;

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
/// `load_trust_root` return type.
pub type LoadedTrustRoot = Loaded<TrustRootDocument>;

/// Errors surfaced by a storage backend.
///
/// The HTTP statuses the operator store server will emit for each variant
/// (these are A8 contract statuses, not `RemoteStoreError` variants):
///
/// | Variant | HTTP status |
/// |---|---|
/// | `NotFound` | `404` |
/// | `AlreadyExists` | `409` |
/// | `PreconditionRequired` | `428` |
/// | `PreconditionFailed` | `412` |
/// | `IntegrityMismatch` | `422` |
/// | `TrustRootChanged` | `409` |
/// | `IdempotencyKeyCommitted` | `409` (`idempotency-conflict`) |
/// | `Spec` / `EnvIdMismatch` | `400` |
/// | `Json` / `Integrity` / `Backend` | `500` |
///
/// The mapping is implemented by `crate::api::map_storage_error`, emitting
/// the [`greentic_deploy_spec::RemoteStoreError`] kinds `already-exists`
/// (409) and `invalid-request` (400) added in PR-4.2a.
#[derive(Debug, Error)]
pub enum StorageError {
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
    /// The trust-root row moved (or appeared) between the handler's load
    /// and a signing commit pinned to it — a concurrent trust-root
    /// mutation (e.g. a revocation) raced the signature. Retryable: the
    /// caller reloads the trust root and re-evaluates. Maps to `409
    /// conflict` on the wire.
    #[error("trust root for `{env_id}` changed concurrently; reload and retry the mutation")]
    TrustRootChanged { env_id: EnvId },
    /// A concurrent request committed the same `(env_id, idempotency_key)`
    /// ledger row between this request's replay-gate lookup and its commit
    /// (the ledger insert hit the primary key). The whole transaction —
    /// mutation included — rolls back; the retry replays the winner's
    /// stored response. Maps to `409 idempotency-conflict` on the wire.
    #[error(
        "idempotency key `{key}` was committed concurrently by another request \
         on env `{env_id}`; retry to replay its response"
    )]
    IdempotencyKeyCommitted { env_id: EnvId, key: String },
    /// The per-environment backup cap is reached. Unlike the idempotency
    /// ledger, backups are never silently evicted — the operator must
    /// delete old ones explicitly. Maps to `409 conflict` on the wire.
    #[error(
        "environment `{env_id}` already holds {limit} backups; \
         delete old backups before creating new ones"
    )]
    BackupLimitReached { env_id: EnvId, limit: i64 },
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Driver-level failure (connection, SQL, migration). Kept opaque so
    /// the trait stays backend-neutral.
    #[error("storage backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl StorageError {
    pub(crate) fn from_precondition(env_id: EnvId, err: PreconditionError) -> Self {
        match err {
            PreconditionError::Required => Self::PreconditionRequired,
            PreconditionError::Conflict(conflict) => Self::PreconditionFailed { env_id, conflict },
        }
    }

    pub(crate) fn backend(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Backend(Box::new(err))
    }
}

/// Per-environment replay-window size: the ledger keeps the most recent
/// N committed mutations' responses (clock-free — measured in mutations,
/// not seconds; matches the ecosystem's bounded-map posture). Older rows
/// are evicted inside the same transaction that inserts a new one; a
/// retry of an evicted key simply re-executes, the same acceptance the
/// replay contract already grants pre-ledger requests. The audit log is
/// append-only WITHOUT bound by default — it must never forget a committed
/// mutation; archival is the PR-4.4 backup story. An operator may opt in to
/// a per-environment audit-row cap
/// ([`crate::sqlite::SqliteEnvironmentStore::with_audit_max_rows_per_env`]),
/// in which case the prune is recorded in the `audit_retention` watermark
/// rather than dropped silently like the ledger.
pub const MAX_LEDGER_ROWS_PER_ENV: i64 = 4096;

/// Per-environment backup cap (A8 #5). Backups are operator-initiated
/// recovery points, so the cap REFUSES new creates
/// ([`StorageError::BackupLimitReached`], 409 on the wire) rather than
/// evicting old ones — silently dropping a recovery point is worse than
/// asking the operator to delete explicitly.
pub const MAX_BACKUPS_PER_ENV: i64 = 256;

/// One captured `audit_log` row (PR-4.4 archival). The original `id` is
/// preserved so a later restore can re-instate the row at its place in the
/// append sequence and keep the [`AuditRetention`] watermark consistent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    /// `audit_log.id` — the append-order key. Preserved across backup/restore.
    pub id: i64,
    /// `audit_log.event_id` — the unique ULID of the audit record.
    pub event_id: String,
    /// `audit_log.recorded_at` — wall-clock the row was appended.
    pub recorded_at: String,
    /// The full `AuditEvent` JSON.
    pub event: Value,
}

/// The captured `audit_retention` watermark (PR-4.4 archival): how far back
/// retention has trimmed this env's audit history. Present only when the env
/// has a watermark row (retention has pruned at least once).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditRetention {
    /// Highest `audit_log.id` retention has removed (everything `<=` is gone).
    pub pruned_through_id: i64,
    /// Cumulative count of audit rows removed.
    pub pruned_total: i64,
    /// The cap in force at the last prune.
    pub policy_max_rows: i64,
    /// Wall-clock of the last prune.
    pub last_pruned_at: String,
}

/// Composite environment snapshot: the environment document plus any sidecar
/// state (runtime, pack answers) AND the durable audit history (`audit_log`
/// rows + the `audit_retention` watermark) captured at backup time.
///
/// `load_env_snapshot` populates every field;
/// [`EnvironmentStorage::restore_env_journaled`] reverts the content
/// (environment + sidecars) AND re-instates the captured audit history —
/// merging the archived rows back by `event_id` without ever deleting a live
/// row, so a backup is a complete, recoverable archival point.
///
/// The `audit_log` / `audit_retention` fields are serde-defaulted and skipped
/// when empty, so backups taken before audit capture existed deserialize to an
/// empty log and no watermark (and the serialized form of an audit-free env is
/// byte-identical to the pre-capture shape — no digest churn).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EnvSnapshot {
    /// The environment row (the `Environment` document).
    pub environment: Value,
    /// The runtime sidecar, if present at backup time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<Value>,
    /// Pack-answers sidecars keyed by slot, if any were present.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub pack_answers: std::collections::BTreeMap<String, Value>,
    /// The full `audit_log` for the env at backup time, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_log: Vec<AuditEntry>,
    /// The `audit_retention` watermark at backup time, if retention has
    /// trimmed this env's history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_retention: Option<AuditRetention>,
}

/// One stored backup: the contract's [`BackupManifest`] metadata plus the
/// full composite snapshot of the environment it captured.
#[derive(Debug, Clone)]
pub struct StoredBackup {
    pub manifest: BackupManifest,
    /// The composite snapshot's canonical JSON. Restore verifies
    /// `manifest.integrity` against this value before applying.
    pub state: Value,
    /// SHA-256 of `state` — stored alongside the snapshot so the load path
    /// can verify without re-hashing.
    pub snapshot_digest: String,
}

/// Everything the server must persist about ONE committed mutation, beyond
/// the mutated resource itself (PR-4.3): the idempotency-ledger row (the
/// durable form of `greentic_deploy_spec::remote::IdempotencyRecord` — it
/// additionally stores the response's `result` payload, which the contract
/// type's `MutationResponse` omits) and the audit-log append.
///
/// Built by the handler BEFORE the commit — the post-commit revision is
/// deterministic under a fully pinned precondition (`generation + 1`, etag
/// from content) — and handed to the journaled storage verbs so both rows
/// land in the SAME transaction as the mutation. No-op mutations (idempotent
/// domain replays that persist nothing) journal via
/// [`EnvironmentStorage::record_journal`] instead.
#[derive(Debug, Clone, PartialEq)]
pub struct MutationJournal {
    pub env_id: EnvId,
    pub idempotency_key: String,
    /// Canonical `{noun}.{verb}` of the A8 route (forensics + conflict
    /// diagnostics; the replay match itself is fingerprint-driven).
    pub operation: String,
    /// SHA-256 over the canonical request (method + path + body) — see
    /// `api::RequestFingerprint`.
    pub request_fingerprint: String,
    /// HTTP status of the recorded response (`200`, or `422` for the warm
    /// health gate's committed-on-error path).
    pub response_status: u16,
    /// The FULL response body, replayed verbatim on a same-key same-request
    /// retry (modulo the `idempotency` marker flip to `replayed`).
    pub response_body: Value,
    /// The audit record as JSON — also embedded in `response_body` for
    /// success responses; standalone for committed-on-error responses.
    pub audit_event: Value,
    /// The audit record's ULID (the `audit_log.event_id` column).
    pub audit_event_id: String,
}

/// A ledger row loaded for the replay gate: enough to tell a verbatim
/// retry (fingerprint match → replay `response_body`) from a same-key
/// different-request protocol violation (mismatch → `409`).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredIdempotencyRecord {
    pub operation: String,
    pub request_fingerprint: String,
    pub response_status: u16,
    pub response_body: Value,
}

/// Storage backend contract for the operator store server.
///
/// Methods are declared as `-> impl Future + Send` rather than `async fn`
/// so generic consumers (axum handlers must produce `Send` futures) can
/// await them without an unnameable-`Send`-bound escape hatch.
/// Implementations still write plain `async fn` bodies — the compiler
/// checks the resulting future against the declared `Send` bound.
///
/// The four committing verbs each exist in two forms: the `*_journaled`
/// required method (mutation + [`MutationJournal`] rows in ONE transaction —
/// what the A8 handlers call) and a provided journal-free default delegating
/// with `None` (storage-level tests and non-A8 callers).
pub trait EnvironmentStorage: Send + Sync {
    /// Cheap connectivity probe for readiness checks.
    fn ping(&self) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// List every persisted environment id, alphabetically.
    fn list_envs(&self) -> impl Future<Output = Result<Vec<EnvId>, StorageError>> + Send;

    /// Return whether `env_id` exists.
    fn exists(&self, env_id: &EnvId) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Load `env_id`'s environment along with its revision. Verifies the
    /// stored integrity digest against the canonical JSON of the decoded
    /// payload before returning (A8 contract #6).
    ///
    /// `Spec` / `EnvIdMismatch` / `Json` from THIS method indicate stored-row
    /// corruption, not a bad request — HTTP handlers must map load failures
    /// via `api::load_storage_error` (500), never the blanket
    /// request-error mapping (400). A trait-level load/write error split is
    /// a PR-4.2b+ candidate once all verb groups are in.
    fn load_env(
        &self,
        env_id: &EnvId,
    ) -> impl Future<Output = Result<LoadedEnv, StorageError>> + Send;

    /// Create `env` if-absent. Fails [`StorageError::AlreadyExists`] if the
    /// row already exists; never silently overwrites. With `Some(journal)`
    /// the ledger + audit rows commit in the same transaction (and are
    /// rolled back when the create loses to an existing row).
    fn create_env_journaled(
        &self,
        env: &Environment,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Journal-free [`Self::create_env_journaled`].
    fn create_env(
        &self,
        env: &Environment,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send {
        self.create_env_journaled(env, None)
    }

    /// Update `env` under `precondition`. Rejects an empty precondition
    /// with [`StorageError::PreconditionRequired`] (A8 contract #1, blind
    /// writes never apply). With `Some(journal)` the ledger + audit rows
    /// commit in the same transaction — a CAS conflict rolls them back too.
    fn update_env_journaled(
        &self,
        env: &Environment,
        precondition: &Precondition,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Journal-free [`Self::update_env_journaled`].
    fn update_env(
        &self,
        env: &Environment,
        precondition: &Precondition,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send {
        self.update_env_journaled(env, precondition, None)
    }

    /// Load the ledger row for `(env_id, key)`, if a committed mutation
    /// already consumed the key (the replay gate's lookup).
    fn lookup_idempotency(
        &self,
        env_id: &EnvId,
        key: &str,
    ) -> impl Future<Output = Result<Option<StoredIdempotencyRecord>, StorageError>> + Send;

    /// Persist a [`MutationJournal`] on its own (one small transaction) —
    /// the path for idempotent no-op mutations, whose responses must still
    /// be replayable although no resource row was written.
    fn record_journal(
        &self,
        journal: &MutationJournal,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    fn load_runtime(
        &self,
        env_id: &EnvId,
    ) -> impl Future<Output = Result<Option<LoadedRuntime>, StorageError>> + Send;

    /// Upsert the runtime. On first write (no existing row) `precondition`
    /// must be absent — that is the create-if-absent path. On subsequent
    /// writes `precondition` must be conditional.
    fn upsert_runtime(
        &self,
        runtime: &EnvironmentRuntime,
        precondition: Option<&Precondition>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    fn load_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
    ) -> impl Future<Output = Result<Option<LoadedAnswers>, StorageError>> + Send;

    /// Upsert pack answers under `(env_id, slot)`. Same semantics as
    /// [`Self::upsert_runtime`] — first write is unconditional, later
    /// writes require a conditional precondition.
    fn upsert_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        answers: &Value,
        precondition: Option<&Precondition>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Delete pack answers under `(env_id, slot)` with a guarded
    /// precondition. Missing rows are a no-op (delete is idempotent).
    fn delete_pack_answers(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        precondition: &Precondition,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Load `env_id`'s trust-root document (PR-4.2f). `None` mirrors the
    /// LocalFS backend's missing `trust-root.json` — it is how the
    /// seed-if-absent verb detects "never bootstrapped", so an empty
    /// document and an absent row are distinct states.
    fn load_trust_root(
        &self,
        env_id: &EnvId,
    ) -> impl Future<Output = Result<Option<LoadedTrustRoot>, StorageError>> + Send;

    /// Upsert the trust-root document. Same precondition semantics as
    /// [`Self::upsert_runtime`] — first write (no existing row) must be
    /// unconditional, later writes require a conditional precondition.
    /// With `Some(journal)` the ledger + audit rows commit in the same
    /// transaction.
    fn upsert_trust_root_journaled(
        &self,
        env_id: &EnvId,
        doc: &TrustRootDocument,
        precondition: Option<&Precondition>,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Journal-free [`Self::upsert_trust_root_journaled`].
    fn upsert_trust_root(
        &self,
        env_id: &EnvId,
        doc: &TrustRootDocument,
        precondition: Option<&Precondition>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send {
        self.upsert_trust_root_journaled(env_id, doc, precondition, None)
    }

    /// Persist `env` (under `precondition`) AND `artifact` in ONE
    /// transaction (PR-4.2g) — the server analogue of the LocalFS flock,
    /// under which the policy-file write and the `env.json` save are a
    /// single critical section. A CAS failure on the environment row
    /// rolls the artifact back too, so committed environment state and
    /// the artifact it references can never diverge (concurrent
    /// same-version builds serialize on the env CAS; the loser writes
    /// nothing).
    ///
    /// `trust_root_pin` is the trust-root row revision the caller
    /// observed when it selected the signing trust root (`None` = the
    /// row was absent). The transaction re-checks the row against the
    /// pin and rejects with [`StorageError::TrustRootChanged`] when it
    /// moved — a concurrent revocation between load and commit must
    /// invalidate the signature it would otherwise have raced past.
    ///
    /// The artifact lands via INSERT OR REPLACE on its
    /// `(env_id, bundle_id, customer_id, version)` key: version numbers
    /// derive from the COMMITTED `revenue_policy_ref`, so a same-version
    /// rebuild racing past the replay gate overwrites rather than
    /// duplicates. With `Some(journal)` the ledger + audit rows join the
    /// same transaction.
    fn update_env_with_revenue_policy_journaled(
        &self,
        env: &Environment,
        precondition: &Precondition,
        artifact: &RevenuePolicyArtifact,
        trust_root_pin: Option<&EnvRevision>,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Journal-free [`Self::update_env_with_revenue_policy_journaled`].
    fn update_env_with_revenue_policy(
        &self,
        env: &Environment,
        precondition: &Precondition,
        artifact: &RevenuePolicyArtifact,
        trust_root_pin: Option<&EnvRevision>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send {
        self.update_env_with_revenue_policy_journaled(
            env,
            precondition,
            artifact,
            trust_root_pin,
            None,
        )
    }

    /// Load a stored revenue-policy artifact version, if present.
    fn load_revenue_policy(
        &self,
        env_id: &EnvId,
        bundle_id: &BundleId,
        customer_id: &CustomerId,
        version: u64,
    ) -> impl Future<Output = Result<Option<RevenuePolicyArtifact>, StorageError>> + Send;

    /// Persist one backup (A8 #5) — manifest metadata + the full state
    /// snapshot — together with its [`MutationJournal`] rows in ONE
    /// transaction. Enforces [`MAX_BACKUPS_PER_ENV`] inside the same
    /// transaction: at the cap the insert is refused with
    /// [`StorageError::BackupLimitReached`] and nothing (journal included)
    /// is written.
    fn create_backup_journaled(
        &self,
        backup: &StoredBackup,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// List `env_id`'s backup manifests, oldest first (`backup_id` is a
    /// ULID, so lexicographic order is creation order).
    fn list_backups(
        &self,
        env_id: &EnvId,
    ) -> impl Future<Output = Result<Vec<BackupManifest>, StorageError>> + Send;

    /// Load one backup (manifest + snapshot), if present.
    fn load_backup(
        &self,
        env_id: &EnvId,
        backup_id: &str,
    ) -> impl Future<Output = Result<Option<StoredBackup>, StorageError>> + Send;

    /// Delete one backup together with its journal rows in ONE
    /// transaction. Returns `false` (and writes NOTHING, journal included)
    /// when the backup does not exist — the handler maps that to a 404 and
    /// the request's key stays unconsumed.
    fn delete_backup_journaled(
        &self,
        env_id: &EnvId,
        backup_id: &str,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Load the composite environment snapshot for a backup: the environment
    /// document, the runtime sidecar (if any), and all pack-answers sidecars.
    /// Used by `create_backup` to build the [`EnvSnapshot`] atomically.
    ///
    /// Returns the captured snapshot together with the environment
    /// [`EnvRevision`] read in the SAME transaction. `create_backup` must use
    /// this revision for the manifest's `generation` and the envelope CAS — a
    /// separate `load_env` read could observe a different generation than the
    /// snapshot content, producing a backup whose metadata lies about what it
    /// captured.
    fn load_env_snapshot(
        &self,
        env_id: &EnvId,
    ) -> impl Future<Output = Result<(EnvSnapshot, EnvRevision), StorageError>> + Send;

    /// Restore a composite [`EnvSnapshot`] atomically: replace the
    /// environment row, upsert/delete the runtime sidecar, upsert/delete
    /// every pack-answers sidecar, AND re-instate the captured audit history
    /// — all inside ONE transaction together with the [`MutationJournal`]
    /// rows. The `precondition` guards the environment row (the CAS target);
    /// the sidecars are replaced unconditionally (their preconditions were not
    /// captured at backup time, and restoring partial state is worse than
    /// restoring all of it).
    ///
    /// Audit is a forward-only ledger, so its "restore" is a MERGE, not a
    /// replacement: captured rows are re-inserted by `event_id` (preserving
    /// their original `id`/`recorded_at`) and live rows are never deleted —
    /// rolling content back must not erase forensic history. The retention
    /// watermark only advances. A normal rollback into a live store is
    /// therefore a no-op for audit; the merge matters when restoring into a
    /// store that has lost (pruned) or never had those rows.
    fn restore_env_journaled(
        &self,
        env_id: &EnvId,
        snapshot: &EnvSnapshot,
        precondition: &Precondition,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Import a composite [`EnvSnapshot`] into a store that does NOT yet have
    /// the environment — disaster recovery from a portable backup. Unlike
    /// [`Self::restore_env_journaled`] (a precondition-guarded rollback of an
    /// EXISTING environment), import CREATES the environment row, failing
    /// [`StorageError::AlreadyExists`] (409) if it is already present so it can
    /// never clobber live state, and reconstructs every sidecar plus the
    /// captured audit history from scratch — all inside ONE transaction with
    /// the [`MutationJournal`] rows.
    ///
    /// The environment is created fresh at generation 1; the reproduced
    /// deployment state (revisions + traffic splits — the active routing) lives
    /// in the restored environment document, not in the row's CAS counter.
    ///
    /// Scope: import reconstructs exactly what an [`EnvSnapshot`] captures — the
    /// environment document, runtime/pack-answers sidecars, and audit history.
    /// Operator-level material kept OUTSIDE the snapshot (trust-root documents,
    /// signed revenue-policy artifacts) is NOT reproduced — the same boundary
    /// `restore` has — and must be re-established separately during recovery.
    /// Audit rows are re-appended with FRESH ids (the captured global ids are
    /// not preserved), since the id is store-wide and shared with other envs'
    /// imports; `event_id`/`recorded_at`/order carry the forensic identity.
    fn import_env_journaled(
        &self,
        env_id: &EnvId,
        snapshot: &EnvSnapshot,
        journal: Option<&MutationJournal>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Append ONE audit row with no idempotency-ledger row — the durable
    /// record of a DENIED mutation (A8 #3: "the rejected attempt is still
    /// audited"). Denials never consume the request's idempotency key, so
    /// they must not ride [`Self::record_journal`].
    fn record_audit(
        &self,
        env_id: &EnvId,
        event_id: &str,
        event: &Value,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// A stored revenue-policy version: the exact bytes the shared builder
/// (`greentic_operator_trust::revenue_policy`) produced, plus the identity
/// they are keyed under. The server-side analogue of the LocalFS
/// `billing-policies/<bundle>/<customer>/vN.json{,.sig}` file pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevenuePolicyArtifact {
    pub bundle_id: BundleId,
    pub customer_id: CustomerId,
    /// 1-based version within `(bundle_id, customer_id)`.
    pub version: u64,
    /// Canonical storage-relative sidecar ref — exactly the value pinned on
    /// `BundleDeployment.revenue_policy_ref`.
    pub policy_ref: String,
    /// Exact bytes of `vN.json`.
    pub doc: Vec<u8>,
    /// Exact bytes of the DSSE envelope sidecar.
    pub envelope: Vec<u8>,
    /// Lowercase-hex SHA-256 of `doc` (the digest the DSSE subject pins).
    pub doc_sha256: String,
    /// `keyid` recorded in the DSSE envelope.
    pub key_id: String,
}
