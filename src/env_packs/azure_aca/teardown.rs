//! Provider teardown of an Azure Container Apps environment: what `op env
//! destroy` removes before local state is purged.
//!
//! Everything the lane creates (revisions, secrets, volumes) lives inside the
//! Container App, so deleting the app removes it all. An app whose owner tag is
//! not this environment's is skipped, never deleted. The managed environment,
//! registry and workspace are the operator's and are never touched.

use greentic_deploy_spec::DeploymentId;
use serde_json::{Value, json};

use super::deploy_target::{AcaDeployTarget, AcaTargetError, AppRef, AppState};
use super::naming::app_name;
use crate::env_packs::owner_stamp::env_owner_stamp;

pub(crate) const PROVIDER: &str = "greentic.deployer.azure-aca";

/// Idempotent: a second run finds nothing and reports empty `deleted_apps`.
pub(crate) async fn teardown_environment(
    target: &dyn AcaDeployTarget,
    env_id: &str,
    deployment_ids: &[DeploymentId],
) -> Result<Value, AcaTargetError> {
    let ours = env_owner_stamp(env_id);
    let mut deleted = Vec::new();
    let mut skipped = Vec::new();
    for deployment_id in deployment_ids {
        let name = app_name(deployment_id);
        let app = AppRef {
            name: name.as_str().to_string(),
        };
        match target.inspect_app(&app).await? {
            AppState::Absent => {}
            AppState::Present { owner, .. } if owner.as_deref() != Some(ours.as_str()) => {
                skipped.push(json!({
                    "app": app.name,
                    "reason": match owner {
                        Some(_) => "owned by another environment",
                        None => "carries no greentic:owner tag",
                    },
                }));
            }
            AppState::Present { .. } => {
                if target.delete_app(&app).await? {
                    deleted.push(app.name);
                }
            }
        }
    }
    Ok(json!({"provider": PROVIDER, "deleted_apps": deleted, "skipped_apps": skipped}))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::env_packs::azure_aca::AzureAcaDeployerHandler;
    use crate::env_packs::azure_aca::fake::InMemoryAca;
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    fn answers() -> serde_json::Value {
        json!({
            "subscription_id": "11111111-2222-3333-4444-555555555555",
            "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "resource_group": "rg", "environment_name": "ce",
        })
    }

    #[tokio::test]
    async fn destroy_deletes_the_app_and_is_idempotent() {
        let t = Arc::new(InMemoryAca::new());
        let h = AzureAcaDeployerHandler::with_target_and_dev_secrets(t.clone(), None);
        let env = build_fixture_env();
        let rev = &env.revisions[0];
        h.warm_revision(&env, rev.revision_id, Some(&answers()))
            .await
            .unwrap();
        let ids: Vec<_> = env.bundles.iter().map(|b| b.deployment_id).collect();
        let first = teardown_environment(t.as_ref(), env.environment_id.as_str(), &ids)
            .await
            .unwrap();
        assert_eq!(first["deleted_apps"].as_array().unwrap().len(), 1);
        assert!(t.app_names().is_empty());
        let second = teardown_environment(t.as_ref(), env.environment_id.as_str(), &ids)
            .await
            .unwrap();
        assert!(second["deleted_apps"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn destroy_skips_a_foreign_owner() {
        let t = InMemoryAca::new();
        let env = build_fixture_env();
        let dep = env.bundles[0].deployment_id;
        t.seed_app(app_name(&dep).as_str(), Some("someone-else"));
        let r = teardown_environment(&t, env.environment_id.as_str(), &[dep])
            .await
            .unwrap();
        assert!(r["deleted_apps"].as_array().unwrap().is_empty());
        assert_eq!(
            r["skipped_apps"][0]["reason"],
            "owned by another environment"
        );
        assert_eq!(t.app_names().len(), 1);
    }
}
