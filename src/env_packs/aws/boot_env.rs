//! The worker container's boot environment on ECS Fargate.
//!
//! The AWS twin of GCP's `runtime_boot_env`: the same variable set in the same
//! order, so a runtime sees one contract on every lane. The telemetry header
//! credential is NOT part of this list; it is a Secrets Manager reference
//! injected through the container's `secrets` (see `SecretEnvRef`).

use greentic_deploy_spec::{Environment, Revision};

use super::deployer::AwsEcsParams;
use super::registry_credential::OCI_USERNAME_ENV;

/// Mount point of the seed volume (`GREENTIC_SEED_DIR`).
pub(crate) const SEED_MOUNT_DIR: &str = "/seed";
/// Writable store root for greentic-start's boot copy of the seed.
pub(crate) const RUNTIME_HOME: &str = "/tmp";

/// Boot env for the worker container, in GCP's order: identity and seed
/// activation first, optional tenant/team, then sorted telemetry env.
pub(crate) fn ecs_boot_env(
    env: &Environment,
    revision: &Revision,
    params: &AwsEcsParams,
) -> Vec<(String, String)> {
    let env_id = env.environment_id.as_str();
    let mut vars = vec![
        ("GREENTIC_ENV".to_string(), env_id.to_string()),
        ("GREENTIC_ENV_ID".to_string(), env_id.to_string()),
        ("GREENTIC_SEED_DIR".to_string(), SEED_MOUNT_DIR.to_string()),
        ("HOME".to_string(), RUNTIME_HOME.to_string()),
        (
            "GREENTIC_GATEWAY_LISTEN_ADDR".to_string(),
            "0.0.0.0".to_string(),
        ),
        (
            "GREENTIC_REVISION_ID".to_string(),
            revision.revision_id.0.to_string(),
        ),
        (
            "GREENTIC_DEPLOYMENT_ID".to_string(),
            revision.deployment_id.0.to_string(),
        ),
        (
            "GREENTIC_BUNDLE_ID".to_string(),
            revision.bundle_id.as_str().to_string(),
        ),
        (
            "GREENTIC_BUNDLE_DIGEST".to_string(),
            revision.bundle_digest.clone(),
        ),
    ];
    if let Some(tenant) = &params.runtime_tenant {
        vars.push(("GREENTIC_TENANT".to_string(), tenant.clone()));
    }
    if let Some(team) = &params.runtime_team {
        vars.push(("GREENTIC_TEAM".to_string(), team.clone()));
    }
    vars.extend(params.telemetry.env_for_role("worker"));
    // The registry username is not secret; the password is injected through the
    // container's `secrets` and is never part of this list.
    if let Some(registry) = &params.registry {
        vars.push((
            OCI_USERNAME_ENV.to_string(),
            registry.username().to_string(),
        ));
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::telemetry::{self, HEADER_ENV_NAMES};
    use serde_json::json;

    #[test]
    fn boot_env_matches_the_gcp_variable_set_and_order() {
        let env = build_fixture_env();
        let revision = &env.revisions[0];
        let mut params = AwsEcsParams::for_env(&env);
        params.runtime_tenant = Some("acme".to_string());
        params.runtime_team = Some("ops".to_string());
        params.telemetry = telemetry::parse(
            Some(&json!({
                "OTEL_SERVICE_NAME": "svc",
                "GREENTIC_TELEMETRY_ENABLED": "true"
            })),
            None,
        )
        .unwrap();
        let vars = ecs_boot_env(&env, revision, &params);
        let names: Vec<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "GREENTIC_ENV",
                "GREENTIC_ENV_ID",
                "GREENTIC_SEED_DIR",
                "HOME",
                "GREENTIC_GATEWAY_LISTEN_ADDR",
                "GREENTIC_REVISION_ID",
                "GREENTIC_DEPLOYMENT_ID",
                "GREENTIC_BUNDLE_ID",
                "GREENTIC_BUNDLE_DIGEST",
                "GREENTIC_TENANT",
                "GREENTIC_TEAM",
                "GREENTIC_TELEMETRY_ENABLED",
                "OTEL_RESOURCE_ATTRIBUTES",
                "OTEL_SERVICE_NAME",
            ]
        );
        let get = |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("GREENTIC_SEED_DIR"), Some("/seed"));
        assert_eq!(get("HOME"), Some("/tmp"));
        assert_eq!(get("GREENTIC_ENV"), Some(env.environment_id.as_str()));
        assert_eq!(get("GREENTIC_GATEWAY_LISTEN_ADDR"), Some("0.0.0.0"));
        assert_eq!(
            get("GREENTIC_REVISION_ID"),
            Some(revision.revision_id.0.to_string().as_str())
        );
        assert_eq!(
            get("GREENTIC_BUNDLE_DIGEST"),
            Some(revision.bundle_digest.as_str())
        );
        assert_eq!(get("GREENTIC_TENANT"), Some("acme"));

        // Without tenant/team/telemetry the optional vars are omitted.
        let bare = ecs_boot_env(&env, revision, &AwsEcsParams::for_env(&env));
        assert_eq!(bare.len(), 9);
    }

    #[test]
    fn boot_env_never_contains_telemetry_headers() {
        let env = build_fixture_env();
        let mut params = AwsEcsParams::for_env(&env);
        params.telemetry = telemetry::parse(
            Some(&json!({ "OTEL_SERVICE_NAME": "svc" })),
            Some(&json!("Authorization=Bearer topsecret")),
        )
        .unwrap();
        let vars = ecs_boot_env(&env, &env.revisions[0], &params);
        for (name, value) in &vars {
            assert!(!HEADER_ENV_NAMES.contains(&name.as_str()), "{name}");
            assert!(!value.contains("topsecret"), "{name} leaks the header");
        }
    }

    #[test]
    fn boot_env_carries_the_registry_username_last_and_never_the_password() {
        let env = build_fixture_env();
        let mut params = AwsEcsParams::for_env(&env);
        params.runtime_tenant = Some("acme".to_string());
        params.registry = super::super::registry_credential::parse(
            Some(&json!("robot")),
            Some(&json!("topsecret")),
        )
        .unwrap();
        let vars = ecs_boot_env(&env, &env.revisions[0], &params);
        assert_eq!(
            vars.last(),
            Some(&("OCI_USERNAME".to_string(), "robot".to_string()))
        );
        for (name, value) in &vars {
            assert_ne!(name, "OCI_PASSWORD");
            assert!(!value.contains("topsecret"), "{name} leaks the password");
        }
    }
}
