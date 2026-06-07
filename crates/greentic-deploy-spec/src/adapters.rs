//! Adapters from legacy types to the new spec.
//!
//! `greentic-config-types::EnvironmentConfig` currently carries the host-level
//! Environment shape. Phase A `EnvironmentHostConfig` is its successor; the
//! `From` impl below lets callers thread legacy values through unchanged. The
//! `deployment`/`connection` fields don't have a place in the new host-config —
//! they belong to `EnvPackBinding[Sessions]` and `EnvPackBinding[Deployer]`
//! respectively — and are dropped at the adapter boundary. Phase A wizards
//! reconstruct them from the env-pack registry.

use crate::environment::EnvironmentHostConfig;
use greentic_config_types::EnvironmentConfig;

impl From<EnvironmentConfig> for EnvironmentHostConfig {
    fn from(value: EnvironmentConfig) -> Self {
        Self {
            env_id: value.env_id,
            region: value.region,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }
    }
}

impl From<&EnvironmentConfig> for EnvironmentHostConfig {
    fn from(value: &EnvironmentConfig) -> Self {
        Self {
            env_id: value.env_id.clone(),
            region: value.region.clone(),
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }
    }
}
