use greentic_config_types::EnvironmentConfig;
use greentic_deploy_spec::{EnvId, EnvironmentHostConfig};
use std::str::FromStr;

#[test]
fn legacy_environment_config_maps_to_host_config() {
    let legacy = EnvironmentConfig {
        env_id: EnvId::from_str("local").unwrap(),
        deployment: None,
        connection: None,
        region: Some("eu-west-1".into()),
    };
    let host: EnvironmentHostConfig = legacy.into();
    assert_eq!(host.env_id.to_string(), "local");
    assert_eq!(host.region.as_deref(), Some("eu-west-1"));
    assert_eq!(host.tenant_org_id, None);
}

#[test]
fn adapter_borrows_legacy_config() {
    let legacy = EnvironmentConfig {
        env_id: EnvId::from_str("prod").unwrap(),
        deployment: None,
        connection: None,
        region: None,
    };
    let host: EnvironmentHostConfig = (&legacy).into();
    assert_eq!(host.env_id.to_string(), "prod");
    assert_eq!(host.region, None);
}
