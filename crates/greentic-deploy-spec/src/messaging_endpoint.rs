//! `greentic.messaging-endpoint.v1` (`Phase M1`).
//!
//! A `MessagingEndpoint` is a per-environment instance of a messaging provider —
//! e.g. a Teams bot identity (`teams-legal`) distinct from another instance of
//! the same provider class (`teams-accounting`). Each endpoint binds a curated
//! set of bundles whose flows it can route to plus an optional default
//! welcome-flow that runs on first contact.
//!
//! Endpoints are N-per-env (no [`CapabilitySlot`](crate::CapabilitySlot)
//! 1-per-slot constraint). The capability-slot enum carries a `Messaging`
//! variant for reservation but bindings live in
//! [`Environment::messaging_endpoints`](crate::Environment), never in
//! `Environment::packs`.
//!
//! ## `linked_bundles` is the admit-gate, not the deployment-selector
//!
//! [`MessagingEndpoint::linked_bundles`] is an **ACL** keyed on
//! [`BundleId`](crate::BundleId), intentionally distinct from deployment
//! selection. The runtime is expected to resolve the concrete
//! [`BundleDeployment`](crate::BundleDeployment) via existing routing
//! (host/path/`tenant_selector` on `BundleDeployment.route_binding`, plus
//! revision routing from `traffic_splits`), then use the endpoint to
//! enforce: *"the deployment we just resolved must carry a `bundle_id` in
//! THIS endpoint's `linked_bundles`."*
//!
//! That keeps the data model clean even when an env hosts multiple
//! deployments of the same bundle for different customers (the
//! `(env_id, bundle_id, customer_id)` keying on
//! [`BundleDeployment`](crate::BundleDeployment) supports this) —
//! customer/billing attribution belongs to the deployment, never to the
//! endpoint. Authoring an endpoint by `bundle_id` alone is therefore
//! correct: it scopes which bundles' FLOWS can be reached, not which
//! customer is charged. See `M1.4` ingress propagation for the runtime
//! composition and `project-messaging-endpoints-and-scoped-routing` in
//! the workspace memo for the architecture.

use crate::error::SpecError;
use crate::ids::{BundleId, MessagingEndpointId, PackId};
use crate::refs::SecretRef;
use crate::version::SchemaVersion;
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};

/// Pointer at a flow inside one of the endpoint's `linked_bundles`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeFlowRef {
    pub bundle_id: BundleId,
    pub pack_id: PackId,
    pub flow_id: String,
}

/// Per-environment messaging provider instance (`Phase M1`).
///
/// `provider_id` is the INSTANCE identity (unique within an env per
/// `provider_type`); `provider_type` is the class (`teams` / `slack` / ...).
/// The two are distinct — see M1.1 for the runtime cutover that separated them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagingEndpoint {
    pub schema: SchemaVersion,
    pub env_id: EnvId,
    pub endpoint_id: MessagingEndpointId,
    /// Instance identity, e.g. `"teams-legal-bot"`.
    pub provider_id: String,
    /// Provider class, e.g. `"teams"`.
    pub provider_type: String,
    /// Human-readable label for operator surfaces.
    pub display_name: String,
    /// Refs into the env's secrets env-pack (bot token, signing secret, ...).
    #[serde(default)]
    pub secret_refs: Vec<SecretRef>,
    /// Bundles whose flows this endpoint can route to.
    #[serde(default)]
    pub linked_bundles: Vec<BundleId>,
    /// Default flow dispatched on first contact (see M1.5). When unset, the
    /// runner falls through to the regular Fast2Flow router on the first turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_flow: Option<WelcomeFlowRef>,
    /// Bumped on every mutation.
    #[serde(default)]
    pub generation: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
}

impl MessagingEndpoint {
    pub fn schema_str() -> &'static str {
        SchemaVersion::MESSAGING_ENDPOINT_V1
    }

    /// Per-document invariants. Cross-document invariants
    /// (`(provider_type, provider_id)` uniqueness, `linked_bundles` membership,
    /// `welcome_flow.bundle_id ∈ linked_bundles`) live on
    /// [`Environment::validate`](crate::Environment::validate) where the
    /// surrounding state is in scope.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema.as_str() != SchemaVersion::MESSAGING_ENDPOINT_V1 {
            return Err(SpecError::SchemaMismatch {
                expected: SchemaVersion::MESSAGING_ENDPOINT_V1,
                actual: self.schema.as_str().to_string(),
            });
        }
        if self.provider_id.trim().is_empty() {
            return Err(SpecError::EmptyMessagingProviderId);
        }
        if self.provider_type.trim().is_empty() {
            return Err(SpecError::EmptyMessagingProviderType);
        }
        for secret in &self.secret_refs {
            let actual = secret.env_segment();
            if actual != self.env_id.as_str() {
                return Err(SpecError::CrossEnvRef {
                    context: "messaging_endpoint.secret_refs",
                    uri: secret.as_str().to_string(),
                    expected_env: self.env_id.clone(),
                    actual_env: actual.to_string(),
                });
            }
        }
        if let Some(welcome) = &self.welcome_flow
            && welcome.flow_id.trim().is_empty()
        {
            return Err(SpecError::EmptyWelcomeFlowId);
        }
        Ok(())
    }
}
