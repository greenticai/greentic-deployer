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
pub mod bundle_deployment;
pub mod capability_slot;
pub mod credentials;
pub mod defaults;
pub mod environment;
pub mod environment_runtime;
pub mod error;
pub mod ids;
pub mod pack_config;
pub mod refs;
pub mod retention;
pub mod revision;
pub mod runtime_config;
pub mod traffic_split;
pub mod version;

#[cfg(feature = "schemars")]
pub mod json_schema;

pub use bundle_deployment::{
    BundleDeployment, BundleDeploymentStatus, RevenueShareEntry, RouteBinding, TenantSelector,
    UsageMeter,
};
pub use capability_slot::{CapabilitySlot, PackDescriptor, PackDescriptorParseError};
pub use credentials::{
    Credentials, CredentialsBootstrap, CredentialsExpiry, CredentialsMode, CredentialsValidation,
    CredentialsValidationResult,
};
pub use environment::{EnvPackBinding, Environment, EnvironmentHostConfig};
pub use environment_runtime::{EnvironmentRuntime, RuntimeDiscoveryValue};
pub use error::SpecError;
pub use ids::{BundleId, CustomerId, DeploymentId, PackId, PartyId, RevisionId};
pub use pack_config::PackConfig;
pub use refs::{RuntimeRef, RuntimeRefParseError, SecretRef, SecretRefParseError};
pub use retention::{HealthState, HealthStatus, RetentionPolicy, RevocationConfig};
pub use revision::{PackListEntry, Revision, RevisionLifecycle, is_valid_transition};
pub use runtime_config::{RevisionRuntimeBlock, RuntimeConfig};
pub use traffic_split::{TrafficSplit, TrafficSplitEntry};
pub use version::{SchemaVersion, SemVer};

pub use greentic_types::EnvId;
