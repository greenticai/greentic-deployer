//! The worker container's boot environment on Container Apps.
//!
//! Same variable set and order as the Cloud Run and ECS lanes, so the runtime
//! sees one contract everywhere. Telemetry headers and the registry password are
//! NOT here: they are `secretRef` env entries (see `arm_body::EnvEntry`).

use greentic_deploy_spec::{Environment, Revision};

use super::params::AcaParams;
use super::registry_credential::OCI_USERNAME_ENV;
use super::seed::SEED_MOUNT_DIR;

pub(crate) const RUNTIME_HOME: &str = "/tmp";

pub(crate) fn aca_boot_env(
    env: &Environment,
    revision: &Revision,
    params: &AcaParams,
) -> Vec<(String, String)> {
    let env_id = env.environment_id.as_str();
    let mut vars = vec![
        ("GREENTIC_ENV".to_string(), env_id.to_string()),
        ("GREENTIC_ENV_ID".to_string(), env_id.to_string()),
        ("GREENTIC_SEED_DIR".to_string(), SEED_MOUNT_DIR.to_string()),
        ("HOME".to_string(), RUNTIME_HOME.to_string()),
        ("GREENTIC_GATEWAY_LISTEN_ADDR".to_string(), "0.0.0.0".to_string()),
        ("GREENTIC_REVISION_ID".to_string(), revision.revision_id.0.to_string()),
        ("GREENTIC_DEPLOYMENT_ID".to_string(), revision.deployment_id.0.to_string()),
        ("GREENTIC_BUNDLE_ID".to_string(), revision.bundle_id.as_str().to_string()),
        ("GREENTIC_BUNDLE_DIGEST".to_string(), revision.bundle_digest.clone()),
    ];
    if let Some(t) = &params.runtime_tenant {
        vars.push(("GREENTIC_TENANT".to_string(), t.clone()));
    }
    if let Some(t) = &params.runtime_team {
        vars.push(("GREENTIC_TEAM".to_string(), t.clone()));
    }
    vars.extend(params.telemetry.env_for_role("worker"));
    if let Some(r) = &params.registry {
        vars.push((OCI_USERNAME_ENV.to_string(), r.username().to_string()));
    }
    vars
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    fn params(extra: serde_json::Value) -> AcaParams {
        let mut a = json!({
            "subscription_id": "11111111-2222-3333-4444-555555555555",
            "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "resource_group": "rg", "environment_name": "ce",
        });
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            a[k] = v;
        }
        AcaParams::from_answers(Some(&a)).unwrap()
    }

    #[test]
    fn matches_the_aws_and_gcp_variable_set_and_order() {
        let env = build_fixture_env();
        let p = params(json!({
            "runtime_tenant": "acme", "runtime_team": "ops",
            "telemetry_env": {"OTEL_SERVICE_NAME": "svc"}
        }));
        let names: Vec<String> =
            aca_boot_env(&env, &env.revisions[0], &p).into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            names[..11],
            [
                "GREENTIC_ENV", "GREENTIC_ENV_ID", "GREENTIC_SEED_DIR", "HOME",
                "GREENTIC_GATEWAY_LISTEN_ADDR", "GREENTIC_REVISION_ID", "GREENTIC_DEPLOYMENT_ID",
                "GREENTIC_BUNDLE_ID", "GREENTIC_BUNDLE_DIGEST", "GREENTIC_TENANT", "GREENTIC_TEAM",
            ]
        );
        assert!(names.contains(&"OTEL_SERVICE_NAME".to_string()));
    }

    #[test]
    fn never_carries_telemetry_headers_or_the_registry_password() {
        let env = build_fixture_env();
        let p = params(json!({
            "telemetry_headers": "Authorization=Bearer topsecret",
            "oci_username": "tok", "oci_password": "hunter2"
        }));
        let vars = aca_boot_env(&env, &env.revisions[0], &p);
        let joined = format!("{vars:?}");
        assert!(!joined.contains("topsecret") && !joined.contains("hunter2"));
        assert!(vars.iter().any(|(k, v)| k == "OCI_USERNAME" && v == "tok"));
        assert!(!vars.iter().any(|(k, _)| k == "OCI_PASSWORD" || k == "OTLP_HEADERS"));
    }
}
