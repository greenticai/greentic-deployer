//! Greentic deployment object-model schemas.
//!
//! See `plans/next-gen-deployment.md` §5 for the design rationale. This crate is
//! the single owner of the [`Environment`], [`Revision`], [`TrafficSplit`],
//! [`BundleDeployment`], [`Credentials`], [`PackConfig`], and [`RuntimeConfig`]
//! types. Other crates depend on it; nothing in this crate depends on
//! operational or runtime code.

#![warn(missing_debug_implementations)]
#![forbid(unsafe_code)]

pub mod adapters;
pub mod audit;
pub mod bundle_deployment;
pub mod capability_slot;
pub mod credentials;
pub mod engine;
pub mod environment;
pub mod environment_runtime;
pub mod error;
pub mod ids;
pub mod integrity;
pub mod messaging_endpoint;
pub mod pack_config;
pub mod pack_list_lock;
pub mod refs;
pub mod remote;
pub mod retention;
pub mod revenue_policy;
pub mod revision;
pub mod runtime_config;
pub mod traffic_split;
pub mod version;

#[cfg(feature = "schemars")]
pub mod json_schema;

pub use audit::{Actor, AuditDecision, AuditEvent, AuditResult, POLICY_LOCAL_ONLY};
pub use bundle_deployment::{
    BundleDeployment, BundleDeploymentStatus, RevenueShareEntry, RouteBinding, TenantSelector,
    UsageMeter,
};
pub use capability_slot::{CapabilitySlot, PackDescriptor, PackDescriptorParseError};
pub use credentials::{
    Credentials, CredentialsBootstrap, CredentialsExpiry, CredentialsMode, CredentialsValidation,
    CredentialsValidationResult,
};
pub use engine::{
    ActiveSplitRef, ApplyTrafficSplitOutcome, BindingError, BindingGenerationOutcome,
    CreateEnvironmentPayload, EngineError, ExtensionBindingPayload, ExtensionKey,
    ExtensionKeyedPayload, FieldUpdate, HealthCheckId, HealthGateFailure, MergeReport,
    MigrateMergePayload, MigrateSeedPayload, PackBindingPayload, RevisionLifecycleError,
    RevisionTransition, RevisionTransitionOutcome, RollbackTrafficSplitOutcome,
    RollbackTrafficSplitPayload, SetTrafficSplitPayload, StageRevisionPayload,
    TrafficRollbackTransition, TrafficSplitError, TrafficSplitTransition, UpdateEnvironmentPayload,
    WarmRevisionPayload,
};
pub use environment::{
    DEFAULT_LISTEN_ADDR, EnvPackBinding, Environment, EnvironmentHostConfig, ExtensionBinding,
    validate_public_base_url,
};
pub use environment_runtime::{EnvironmentRuntime, RuntimeDiscoveryValue};
pub use error::SpecError;
pub use ids::{
    BundleId, CustomerId, DeploymentId, MessagingEndpointId, PackId, PartyId, RevisionId,
};
pub use integrity::{INTEGRITY_ALGORITHM_SHA256, IntegrityError, StateIntegrity, canonical_json};
pub use messaging_endpoint::{MessagingEndpoint, WelcomeFlowRef};
pub use pack_config::PackConfig;
pub use pack_list_lock::{LockedPack, PackListLock};
pub use refs::{
    ExtensionRef, ExtensionRefParseError, RuntimeRef, RuntimeRefParseError, SecretRef,
    SecretRefParseError,
};
pub use remote::{
    BackupManifest, ConcurrencyConflict, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord,
    IdempotencyReplay, MutationResponse, Precondition, PreconditionError, RbacRequest,
    RemoteContractError, RemoteStoreError, RestoreOutcome, RestoreRequest, StateEtag,
};
pub use retention::{HealthState, HealthStatus, RetentionPolicy, RevocationConfig};
pub use revenue_policy::RevenuePolicyDocument;
pub use revision::{PackListEntry, Revision, RevisionLifecycle, is_valid_transition};
pub use runtime_config::{RevisionRuntimeBlock, RuntimeConfig};
pub use traffic_split::{TrafficSplit, TrafficSplitEntry};
pub use version::{SchemaVersion, SemVer};

pub use greentic_types::EnvId;
