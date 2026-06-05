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

/// Minimum length for [`MessagingEndpoint::webhook_secret`] when set.
/// 32 chars of URL-safe base64 ≈ 192 bits of entropy — comfortably above the
/// brute-force horizon for an HTTPS-bound shared-secret token.
pub const MIN_WEBHOOK_SECRET_LEN: usize = 32;

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
    /// Per-endpoint auth secret presented by the upstream provider on every
    /// inbound webhook. Today only Telegram (`x-telegram-bot-api-secret-token`
    /// header on `setWebhook`). Decoupled from [`provider_id`] so the routing
    /// discriminator and the auth secret can't collapse to one operator-named
    /// value — see `project_telegram_secret_token_auth_deferred`. Auto-generated
    /// at endpoint creation (32 URL-safe random chars); `None` preserves the
    /// pre-decoupling fallback where `provider_id` doubles as the secret-token.
    ///
    /// Validation enforces ≥`MIN_WEBHOOK_SECRET_LEN` chars when set — guards
    /// against operators hand-supplying a short string that wouldn't survive
    /// brute force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
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
        if let Some(secret) = &self.webhook_secret
            && secret.len() < MIN_WEBHOOK_SECRET_LEN
        {
            return Err(SpecError::MessagingWebhookSecretTooShort {
                min: MIN_WEBHOOK_SECRET_LEN,
                got: secret.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn fixture(webhook_secret: Option<String>) -> MessagingEndpoint {
        MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: EnvId::from_str("prod").unwrap(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: "tg-legal".into(),
            provider_type: "telegram".into(),
            display_name: "Legal Bot".into(),
            secret_refs: vec![],
            webhook_secret,
            linked_bundles: vec![],
            welcome_flow: None,
            generation: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            updated_by: "operator://test".into(),
        }
    }

    #[test]
    fn validate_accepts_none_webhook_secret() {
        // None preserves the pre-decoupling fallback where provider_id is the
        // secret-token. Existing envs must round-trip unchanged.
        assert!(fixture(None).validate().is_ok());
    }

    #[test]
    fn validate_accepts_secret_at_min_len() {
        let secret = "a".repeat(MIN_WEBHOOK_SECRET_LEN);
        assert!(fixture(Some(secret)).validate().is_ok());
    }

    #[test]
    fn validate_rejects_short_webhook_secret() {
        let secret = "a".repeat(MIN_WEBHOOK_SECRET_LEN - 1);
        let err = fixture(Some(secret)).validate().unwrap_err();
        assert!(matches!(
            err,
            SpecError::MessagingWebhookSecretTooShort { min, got }
                if min == MIN_WEBHOOK_SECRET_LEN && got == MIN_WEBHOOK_SECRET_LEN - 1
        ));
    }

    #[test]
    fn serde_skips_webhook_secret_when_none() {
        // Persisted env.json must NOT carry `webhook_secret: null` for endpoints
        // created before the decoupling — the field is genuinely absent so old
        // and new clients can both read it. `skip_serializing_if = Option::is_none`
        // achieves this; the test pins the contract.
        let json = serde_json::to_string(&fixture(None)).unwrap();
        assert!(
            !json.contains("webhook_secret"),
            "None webhook_secret should be omitted from serialized JSON: {json}",
        );
    }

    #[test]
    fn serde_round_trip_with_some_webhook_secret() {
        let secret = "x".repeat(MIN_WEBHOOK_SECRET_LEN);
        let original = fixture(Some(secret.clone()));
        let json = serde_json::to_string(&original).unwrap();
        let parsed: MessagingEndpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.webhook_secret.as_deref(), Some(secret.as_str()));
    }

    #[test]
    fn serde_default_when_field_absent() {
        // A pre-decoupling env.json (no `webhook_secret` key) must deserialize
        // as `webhook_secret: None`, not error.
        let json = serde_json::to_string(&fixture(None)).unwrap();
        let parsed: MessagingEndpoint = serde_json::from_str(&json).unwrap();
        assert!(parsed.webhook_secret.is_none());
    }
}
