//! Environment persistence (A2 of `plans/next-gen-deployment.md`).
//!
//! Public surface:
//!
//! - [`EnvironmentStore`] — local-FS persistence trait
//! - [`LocalFsStore`] — concrete impl rooted at `~/.greentic/environments/`
//! - [`StoreError`] — typed errors
//! - [`EnvFlock`] — RAII per-env exclusive lock (re-exported for transactional callers)
//! - [`atomic_write_json`], [`atomic_write_bytes`], [`copy_to_backup`] — primitives
//! - [`mint_revision_id`], [`mint_deployment_id`] — ULID generators

pub mod atomic_write;
pub mod audit;
pub mod bootstrap;
pub mod bundle_deployment;
pub mod file_lock;
pub mod lifecycle;
pub mod messaging;
pub mod mutations;
pub mod mutations_local;
pub mod runtime_config;
pub mod store;
pub mod trust_root;

pub use atomic_write::{AtomicWriteError, atomic_write_bytes, atomic_write_json, copy_to_backup};
pub use audit::{
    AUDIT_EVENT_SCHEMA_V1, Actor, AuditDecision, AuditError, AuditEvent, AuditLog, AuditResult,
    POLICY_LOCAL_ONLY, authorize_local_only, current_local_actor,
};
pub use bootstrap::{EnsureLocalEnvironmentPayload, LocalEnvOutcome};
pub use bundle_deployment::{
    BundleDeploymentError, REVENUE_POLICY_PREDICATE_TYPE_V1, RevenuePolicyPredicate,
    RevenuePolicyVersion, write_revenue_policy_version,
};
pub use file_lock::{EnvFlock, LockError};
pub use lifecycle::{
    HealthCheckId, HealthGateFailure, LifecycleError, apply_revision_transition,
    apply_revision_transition_with_health_gate,
};
pub use messaging::{MessagingEndpointIndexEntry, materialize_messaging_index};
pub use mutations::{
    AddBundlePayload, AddMessagingEndpointPayload, ApplyTrafficSplitOutcome, EnvironmentMutations,
    ExtensionKey, FieldUpdate, MigrateMergePayload, MigrateSeedPayload, RemoveBundleOutcome,
    RevisionTransitionOutcome, RollbackTrafficSplitOutcome, SetMessagingWelcomeFlowPayload,
    StageRevisionPayload, TrustRootAddOutcome, TrustRootRemoveOutcome, TrustRootSeed,
    UpdateBundlePayload, UpdateEnvironmentPayload, WarmRevisionPayload,
};
pub use runtime_config::materialize_runtime_config;
pub use store::{EnvironmentStore, LocalFsStore, Locked, StoreError};
pub use trust_root::{
    TRUST_ROOT_FILE, TRUST_ROOT_SCHEMA_V1, TrustRootDocument, TrustRootError, add_trusted_key,
    load as load_trust_root, remove_trusted_key, trust_root_path,
};

use greentic_deploy_spec::{DeploymentId, RevisionId};

/// Mint a fresh [`RevisionId`] (ULID). Wrapper kept here so call sites do not
/// need a direct dependency on the spec crate.
pub fn mint_revision_id() -> RevisionId {
    RevisionId::new()
}

/// Mint a fresh [`DeploymentId`] (ULID). Wrapper kept here so call sites do
/// not need a direct dependency on the spec crate.
pub fn mint_deployment_id() -> DeploymentId {
    DeploymentId::new()
}
