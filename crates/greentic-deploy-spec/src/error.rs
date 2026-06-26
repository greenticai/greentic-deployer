//! Cross-cutting error type for spec-level validators.

use crate::capability_slot::CapabilitySlot;
use crate::revision::RevisionLifecycle;
use thiserror::Error;

use crate::ids::{BundleId, DeploymentId, MessagingEndpointId, RevisionId};
use greentic_types::EnvId;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("basis-points entries must sum to 10000, got {sum}")]
    BasisPointsSum { sum: u64 },

    #[error("basis-points entry exceeds 10000: {value}")]
    BasisPointsEntryTooLarge { value: u32 },

    #[error("revenue-policy version must be >= 1 (1-based monotonic)")]
    RevenuePolicyVersionZero,

    #[error("duplicate capability slot `{0}` in Environment.packs")]
    DuplicateCapabilitySlot(CapabilitySlot),

    #[error("revision lifecycle transition {from:?} → {to:?} is not permitted")]
    InvalidLifecycleTransition {
        from: RevisionLifecycle,
        to: RevisionLifecycle,
    },

    #[error("schema discriminator mismatch: expected `{expected}`, got `{actual}`")]
    SchemaMismatch {
        expected: &'static str,
        actual: String,
    },

    #[error("env_id mismatch in {context}: expected `{expected}`, got `{actual}`")]
    EnvIdMismatch {
        context: &'static str,
        expected: EnvId,
        actual: EnvId,
    },

    #[error("traffic split references unknown deployment `{0}`")]
    UnknownDeployment(DeploymentId),

    #[error("reference to unknown revision `{0}`")]
    UnknownRevision(RevisionId),

    #[error(
        "split entry revision `{revision}` belongs to deployment `{actual_deployment}`, not split's `{expected_deployment}`"
    )]
    SplitRevisionWrongDeployment {
        revision: RevisionId,
        expected_deployment: DeploymentId,
        actual_deployment: DeploymentId,
    },

    #[error(
        "split entry revision `{revision}` belongs to bundle `{actual_bundle}`, not split's `{expected_bundle}`"
    )]
    SplitRevisionWrongBundle {
        revision: RevisionId,
        expected_bundle: BundleId,
        actual_bundle: BundleId,
    },

    #[error(
        "bundle `{deployment}` current_revision `{revision}` belongs to deployment `{actual_deployment}`"
    )]
    BundleRevisionWrongDeployment {
        deployment: DeploymentId,
        revision: RevisionId,
        actual_deployment: DeploymentId,
    },

    #[error(
        "bundle deployment `{deployment}` current_revision `{revision}` belongs to bundle `{actual_bundle}`, not deployment's `{expected_bundle}`"
    )]
    BundleRevisionWrongBundle {
        deployment: DeploymentId,
        revision: RevisionId,
        expected_bundle: BundleId,
        actual_bundle: BundleId,
    },

    #[error(
        "traffic split for deployment `{deployment}` carries bundle `{split_bundle}`, but the BundleDeployment record holds bundle `{deployment_bundle}`"
    )]
    SplitDeploymentBundleMismatch {
        deployment: DeploymentId,
        split_bundle: BundleId,
        deployment_bundle: BundleId,
    },

    #[error("{context} ref `{uri}` is scoped to env `{actual_env}`, expected `{expected_env}`")]
    CrossEnvRef {
        context: &'static str,
        uri: String,
        expected_env: EnvId,
        actual_env: String,
    },

    #[error("duplicate messaging endpoint id `{0}` in Environment.messaging_endpoints")]
    DuplicateMessagingEndpoint(MessagingEndpointId),

    #[error(
        "duplicate provider instance `{provider_type}` / `{provider_id}` in Environment.messaging_endpoints"
    )]
    DuplicateProviderInstance {
        provider_type: String,
        provider_id: String,
    },

    #[error(
        "messaging endpoint `{endpoint}` links bundle `{bundle}` which is not deployed in this env"
    )]
    MessagingEndpointBundleNotLinked {
        endpoint: MessagingEndpointId,
        bundle: BundleId,
    },

    #[error(
        "messaging endpoint `{endpoint}` welcome_flow references bundle `{bundle}` which is not in linked_bundles"
    )]
    WelcomeFlowBundleNotLinked {
        endpoint: MessagingEndpointId,
        bundle: BundleId,
    },

    #[error("messaging endpoint provider_id is empty")]
    EmptyMessagingProviderId,

    #[error("messaging endpoint provider_type is empty")]
    EmptyMessagingProviderType,

    #[error("messaging endpoint welcome_flow.flow_id is empty")]
    EmptyWelcomeFlowId,

    #[error(
        "duplicate extension binding for path `{path}` / instance `{instance_id:?}` in Environment.extensions"
    )]
    DuplicateExtension {
        path: String,
        instance_id: Option<String>,
    },

    #[error("extension binding `{path}` has an invalid instance id: {reason}")]
    InvalidExtensionInstanceId { path: String, reason: String },

    #[error("bundle config_overrides carries {count} packs, exceeds cap of {max}")]
    ConfigOverridesTooManyPacks { count: usize, max: usize },

    #[error(
        "bundle config_overrides for pack `{pack_id}` carries {count} keys, exceeds cap of {max}"
    )]
    ConfigOverridesTooManyKeysForPack {
        pack_id: String,
        count: usize,
        max: usize,
    },

    #[error("bundle config_overrides serialized size is {bytes} bytes, exceeds cap of {max}")]
    ConfigOverridesTooLarge { bytes: usize, max: usize },

    #[error("bundle config_overrides has an empty pack id key")]
    ConfigOverrideEmptyPackId,

    #[error("bundle config_overrides for pack `{pack_id}` has an empty config key")]
    ConfigOverrideEmptyKey { pack_id: String },

    #[error(
        "bundle deployment `{deployment}` config_overrides references pack `{pack_id}` which is not in any current revision's pack_list"
    )]
    ConfigOverridePackNotInRevisions {
        deployment: DeploymentId,
        pack_id: String,
    },

    #[error("public_base_url `{value}` is invalid: {reason}")]
    InvalidPublicBaseUrl { value: String, reason: &'static str },
}
