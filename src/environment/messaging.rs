//! Messaging-endpoint projection producer (`Phase M1.2`).
//!
//! `environment.json` is the source of truth; per-endpoint files under
//! `<env_dir>/messaging/` are derived projections rebuilt on every mutation.
//! Mirrors the [`runtime_config`](super::runtime_config) pattern: a single
//! pure projector + a [`Locked::refresh_messaging_projection`] helper that
//! reconciles disk against the just-saved env inside the same transaction.
//!
//! Per-endpoint file: `<env_dir>/messaging/<endpoint_id>.json`. Each endpoint
//! is written verbatim so external tooling can read one endpoint without
//! parsing the full `environment.json`. An index file
//! `<env_dir>/messaging/index.json` carries a stable list of `(endpoint_id,
//! provider_type, provider_id, display_name)` tuples for quick enumeration.
//!
//! `refresh_messaging_projection` removes per-endpoint files for ids no
//! longer in the env so the directory tracks the source-of-truth set exactly.

use greentic_deploy_spec::{Environment, MessagingEndpoint, MessagingEndpointId};
use serde::{Deserialize, Serialize};

/// One row of the on-disk `messaging/index.json` projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagingEndpointIndexEntry {
    pub endpoint_id: MessagingEndpointId,
    pub provider_type: String,
    pub provider_id: String,
    pub display_name: String,
}

impl MessagingEndpointIndexEntry {
    pub fn from(endpoint: &MessagingEndpoint) -> Self {
        Self {
            endpoint_id: endpoint.endpoint_id,
            provider_type: endpoint.provider_type.clone(),
            provider_id: endpoint.provider_id.clone(),
            display_name: endpoint.display_name.clone(),
        }
    }
}

/// Materialize the `messaging/index.json` projection. Pure and total: one
/// row per endpoint in `Environment.messaging_endpoints` order. An env with
/// no endpoints yields an empty list (callers delete the file instead of
/// writing an empty array, mirroring the runtime-config "absence is the
/// nothing-live signal" precedent).
pub fn materialize_messaging_index(env: &Environment) -> Vec<MessagingEndpointIndexEntry> {
    env.messaging_endpoints
        .iter()
        .map(MessagingEndpointIndexEntry::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use greentic_deploy_spec::{
        EnvId, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId, SchemaVersion,
    };

    fn endpoint(provider_type: &str, provider_id: &str) -> MessagingEndpoint {
        MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: EnvId::try_from("local").unwrap(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: provider_id.into(),
            provider_type: provider_type.into(),
            display_name: format!("{provider_type}: {provider_id}"),
            secret_refs: vec![],
            webhook_secret_ref: None,
            linked_bundles: vec![],
            welcome_flow: None,
            generation: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            updated_by: "operator://test".into(),
        }
    }

    fn env(endpoints: Vec<MessagingEndpoint>) -> Environment {
        let env_id = EnvId::try_from("local").unwrap();
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id.clone(),
            name: "local".into(),
            host_config: EnvironmentHostConfig {
                env_id,
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
                default_bundle: None,
            },
            packs: vec![],
            credentials_ref: None,
            bundles: vec![],
            revisions: vec![],
            traffic_splits: vec![],
            messaging_endpoints: endpoints,
            extensions: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    #[test]
    fn empty_env_yields_empty_index() {
        assert!(materialize_messaging_index(&env(vec![])).is_empty());
    }

    #[test]
    fn index_preserves_endpoint_order() {
        let legal = endpoint("teams", "legal-bot");
        let accounting = endpoint("teams", "accounting-bot");
        let index = materialize_messaging_index(&env(vec![legal.clone(), accounting.clone()]));
        assert_eq!(index.len(), 2);
        assert_eq!(index[0].endpoint_id, legal.endpoint_id);
        assert_eq!(index[1].endpoint_id, accounting.endpoint_id);
    }

    #[test]
    fn index_carries_human_label() {
        let ep = endpoint("teams", "legal-bot");
        let index = materialize_messaging_index(&env(vec![ep.clone()]));
        assert_eq!(index[0].display_name, ep.display_name);
        assert_eq!(index[0].provider_type, "teams");
        assert_eq!(index[0].provider_id, "legal-bot");
    }
}
