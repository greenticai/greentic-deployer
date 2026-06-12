//! Backend-agnostic storage contract for the operator store server.
//!
//! The trait mirrors the concrete surface of the parked Postgres
//! prototype (`crates/greentic-environment-store-postgres`) so that
//! backend can implement it later without reshaping. v1 ships SQLite
//! only ([`crate::sqlite::SqliteEnvironmentStore`]).

use std::future::Future;

use greentic_deploy_spec::{
    CapabilitySlot, ConcurrencyConflict, EnvId, Environment, EnvironmentRuntime, IntegrityError,
    Precondition, PreconditionError, SpecError, StateEtag,
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

/// Storage backend contract for the operator store server.
///
/// Methods are declared as `-> impl Future + Send` rather than `async fn`
/// so generic consumers (axum handlers must produce `Send` futures) can
/// await them without an unnameable-`Send`-bound escape hatch.
/// Implementations still write plain `async fn` bodies — the compiler
/// checks the resulting future against the declared `Send` bound.
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
    /// row already exists; never silently overwrites.
    fn create_env(
        &self,
        env: &Environment,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

    /// Update `env` under `precondition`. Rejects an empty precondition
    /// with [`StorageError::PreconditionRequired`] (A8 contract #1, blind
    /// writes never apply).
    fn update_env(
        &self,
        env: &Environment,
        precondition: &Precondition,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;

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
    fn upsert_trust_root(
        &self,
        env_id: &EnvId,
        doc: &TrustRootDocument,
        precondition: Option<&Precondition>,
    ) -> impl Future<Output = Result<EnvRevision, StorageError>> + Send;
}
