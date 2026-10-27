//! Provider teardown of an AWS-ECS environment: the resources `op env destroy`
//! must remove before the local state is purged.
//!
//! The logic is generic over [`EcsDeployTarget`] so it runs against
//! [`InMemoryEcs`](super::deploy_target::InMemoryEcs) in tests; the CLI wrapper
//! (`EcsProviderTeardown`) only resolves the real target and calls in.
//!
//! What is removed, per deployment: its own host/path listener rule, its ECS
//! service (task sets first), its log group. Per environment: the three seed
//! secrets, each only when this environment's owner stamp is on it. The
//! cluster, the load balancer, the listener and the target groups are the
//! operator's and are never touched.

use greentic_deploy_spec::DeploymentId;
use serde_json::{Value, json};

use super::deploy_target::{
    EcsDeployTarget, EcsTargetError, ListenerRef, ServiceRef, log_group_name, service_name,
};
use super::deployer::AwsEcsParams;
use super::seed_stage::{
    dev_store_secret_name, environment_secret_name, oci_password_secret_name,
    telemetry_headers_secret_name,
};
use crate::env_packs::owner_stamp::env_owner_stamp;

/// The `provider` value of the teardown report.
pub(crate) const PROVIDER: &str = "greentic.deployer.aws-ecs";

/// Tear down everything the environment owns on AWS. Idempotent: a second run
/// finds nothing and reports empty lists.
pub(crate) async fn teardown_environment(
    target: &dyn EcsDeployTarget,
    params: &AwsEcsParams,
    env_id: &str,
    deployment_ids: &[DeploymentId],
) -> Result<Value, EcsTargetError> {
    let mut deleted_services = Vec::new();
    let mut deleted_log_groups = Vec::new();
    for &deployment_id in deployment_ids {
        // The rule goes before the service so the listener never forwards to a
        // service that is already gone.
        if let Some(listener_arn) = &params.listener_arn {
            target
                .delete_listener_rule(&ListenerRef {
                    deployment_id,
                    listener_arn: listener_arn.clone(),
                    cluster: params.cluster.clone(),
                    routing: params.routing.clone(),
                })
                .await?;
        }
        // Only a resource that existed and was removed is reported: an
        // idempotent no-op on an absent one deleted nothing.
        if target
            .delete_service(&ServiceRef {
                deployment_id,
                cluster: params.cluster.clone(),
                region: params.region.clone(),
            })
            .await?
        {
            deleted_services.push(service_name(&deployment_id));
        }
        let log_group = log_group_name(&params.secret_prefix, &deployment_id);
        if target.delete_log_group(&log_group).await? {
            deleted_log_groups.push(log_group);
        }
    }

    let ours = env_owner_stamp(env_id);
    let mut deleted_secrets = Vec::new();
    let mut skipped_secrets = Vec::new();
    for name in [
        environment_secret_name(&params.secret_prefix),
        dev_store_secret_name(&params.secret_prefix),
        telemetry_headers_secret_name(&params.secret_prefix),
        oci_password_secret_name(&params.secret_prefix),
    ] {
        match target.get_secret_owner(&name).await? {
            None => {}
            Some(owner) if owner == ours => {
                target.delete_secret(&name).await?;
                deleted_secrets.push(name);
            }
            // Another environment's, or unstamped: an unstamped ECS secret was
            // not made by this deployer, so it is foreign (there is no legacy
            // unstamped secret to adopt, unlike Cloud Run).
            Some(owner) => skipped_secrets.push(json!({
                "secret": name,
                "owned_by": owner,
                "reason": if owner.is_empty() {
                    "carries no owner stamp, so this deployer did not create it; left intact"
                } else {
                    "belongs to another environment; left intact"
                },
            })),
        }
    }

    Ok(json!({
        "provider": PROVIDER,
        "region": params.region,
        "deleted_services": deleted_services,
        "deleted_secrets": deleted_secrets,
        "skipped_secrets": skipped_secrets,
        "deleted_log_groups": deleted_log_groups,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use greentic_deploy_spec::{DeploymentId, Environment};
    use ulid::Ulid;

    use super::*;
    use crate::env_packs::aws::AwsEcsDeployerHandler;
    use crate::env_packs::aws::deploy_target::{
        InMemoryEcs, ListenerRouting, TargetGroupWeight, UnconfiguredEcsTarget,
    };
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    const LISTENER: &str = "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/x/y/z";

    fn ids(env: &Environment) -> Vec<DeploymentId> {
        env.bundles.iter().map(|b| b.deployment_id).collect()
    }

    fn params(env: &Environment) -> AwsEcsParams {
        AwsEcsParams::for_env(env)
    }

    /// A warmed deployment: service, task set, the seed secrets, a log group.
    async fn warmed() -> (Environment, Arc<InMemoryEcs>) {
        let target = Arc::new(InMemoryEcs::default());
        let handler = AwsEcsDeployerHandler::with_target(target.clone());
        let env = build_fixture_env();
        handler
            .warm_revision(&env, env.revisions[0].revision_id, None)
            .await
            .expect("warm");
        assert!(!target.services().is_empty());
        assert!(!target.task_sets().is_empty());
        assert!(!target.secrets().is_empty());
        assert!(!target.log_groups().is_empty());
        (env, target)
    }

    #[tokio::test]
    async fn destroy_deletes_task_sets_service_secrets_and_log_group() {
        let (env, target) = warmed().await;
        let secrets_before = target.secrets().len();
        let services_before = target.services().len();
        let groups_before = target.log_groups().len();
        let report = teardown_environment(
            target.as_ref(),
            &params(&env),
            env.environment_id.as_str(),
            &ids(&env),
        )
        .await
        .expect("teardown");

        assert!(target.task_sets().is_empty(), "task sets must go");
        assert!(target.services().is_empty(), "service must go");
        assert!(target.secrets().is_empty(), "owned secrets must go");
        assert!(target.log_groups().is_empty(), "log group must go");
        assert_eq!(report["provider"], "greentic.deployer.aws-ecs");
        assert_eq!(report["region"], params(&env).region);
        assert_eq!(
            report["deleted_services"].as_array().map(Vec::len),
            Some(services_before)
        );
        assert_eq!(
            report["deleted_secrets"].as_array().map(Vec::len),
            Some(secrets_before)
        );
        assert_eq!(
            report["deleted_log_groups"].as_array().map(Vec::len),
            Some(groups_before)
        );
        assert_eq!(report["skipped_secrets"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn destroy_deletes_the_registry_password_secret() {
        let target = Arc::new(InMemoryEcs::default());
        let handler = AwsEcsDeployerHandler::with_target(target.clone());
        let env = build_fixture_env();
        handler
            .warm_revision(
                &env,
                env.revisions[0].revision_id,
                Some(&json!({ "oci_username": "robot", "oci_password": "pw" })),
            )
            .await
            .expect("warm");
        let name = oci_password_secret_name(&params(&env).secret_prefix);
        assert!(target.secrets().contains_key(&name));
        let report = teardown_environment(
            target.as_ref(),
            &params(&env),
            env.environment_id.as_str(),
            &ids(&env),
        )
        .await
        .expect("teardown");
        assert!(target.secrets().is_empty(), "the password secret must go");
        assert!(
            report["deleted_secrets"]
                .as_array()
                .is_some_and(|v| v.iter().any(|s| s == &json!(name)))
        );
    }

    #[tokio::test]
    async fn destroy_twice_is_ok() {
        let (env, target) = warmed().await;
        let p = params(&env);
        let id = env.environment_id.as_str();
        teardown_environment(target.as_ref(), &p, id, &ids(&env))
            .await
            .expect("first");
        let report = teardown_environment(target.as_ref(), &p, id, &ids(&env))
            .await
            .expect("second teardown is idempotent");
        for key in [
            "deleted_services",
            "deleted_log_groups",
            "deleted_secrets",
            "skipped_secrets",
        ] {
            assert_eq!(
                report[key],
                serde_json::json!([]),
                "a second run deletes nothing, so `{key}` is empty"
            );
        }
        assert!(target.services().is_empty());
    }

    #[tokio::test]
    async fn destroy_reports_only_what_it_deleted() {
        let (env, target) = warmed().await;
        let all = ids(&env);
        assert!(all.len() >= 2);
        let gone = all[0];
        // One deployment's service and log group are already gone.
        let p = params(&env);
        target
            .delete_service(&ServiceRef {
                deployment_id: gone,
                cluster: p.cluster.clone(),
                region: p.region.clone(),
            })
            .await
            .unwrap();
        target
            .delete_log_group(&log_group_name(&p.secret_prefix, &gone))
            .await
            .unwrap();
        let report = teardown_environment(target.as_ref(), &p, env.environment_id.as_str(), &all)
            .await
            .unwrap();
        let services = report["deleted_services"].as_array().unwrap();
        assert!(!services.iter().any(|s| *s == service_name(&gone)));
        let groups = report["deleted_log_groups"].as_array().unwrap();
        assert!(
            !groups
                .iter()
                .any(|g| *g == log_group_name(&p.secret_prefix, &gone))
        );
    }

    #[tokio::test]
    async fn destroy_skips_a_secret_owned_by_another_env() {
        let (env, target) = warmed().await;
        let p = params(&env);
        let foreign = environment_secret_name(&p.secret_prefix);
        target.seed_secret(&foreign, "someone-else-0123");
        let report =
            teardown_environment(target.as_ref(), &p, env.environment_id.as_str(), &ids(&env))
                .await
                .expect("teardown");
        assert_eq!(
            target.secrets().get(&foreign).map(String::as_str),
            Some("someone-else-0123"),
            "another environment's secret must survive"
        );
        let skipped = report["skipped_secrets"].as_array().expect("array");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["secret"], foreign);
        assert_eq!(skipped[0]["owned_by"], "someone-else-0123");
        assert!(
            !report["deleted_secrets"]
                .as_array()
                .expect("array")
                .iter()
                .any(|s| *s == foreign)
        );
    }

    #[tokio::test]
    async fn destroy_skips_an_unstamped_secret() {
        let (env, target) = warmed().await;
        let p = params(&env);
        let unstamped = dev_store_secret_name(&p.secret_prefix);
        target.seed_secret(&unstamped, "");
        let report =
            teardown_environment(target.as_ref(), &p, env.environment_id.as_str(), &ids(&env))
                .await
                .expect("teardown");
        assert!(
            target.secrets().contains_key(&unstamped),
            "an unstamped secret is foreign and must survive"
        );
        let skipped = report["skipped_secrets"].as_array().expect("array");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["secret"], unstamped);
    }

    #[tokio::test]
    async fn destroy_never_touches_the_listener_or_other_deployments_rules() {
        let target = Arc::new(InMemoryEcs::default());
        let env = build_fixture_env();
        let mut p = params(&env);
        p.listener_arn = Some(LISTENER.to_string());
        let mine = DeploymentId(Ulid::from(0xA1_u128));
        let other = DeploymentId(Ulid::from(0xB2_u128));
        let routing = |host: &str| {
            Some(ListenerRouting {
                host: Some(host.to_string()),
                path: None,
            })
        };
        for (dep, host) in [(mine, "mine.example.com"), (other, "other.example.com")] {
            target
                .apply_listener_weights(
                    &ListenerRef {
                        deployment_id: dep,
                        listener_arn: LISTENER.to_string(),
                        cluster: p.cluster.clone(),
                        routing: routing(host),
                    },
                    &[TargetGroupWeight {
                        revision_id: env.revisions[0].revision_id,
                        weight_bps: 10_000,
                    }],
                )
                .await
                .expect("seed rule");
            target.seed_service(dep, 1);
        }
        p.routing = routing("mine.example.com");

        teardown_environment(target.as_ref(), &p, env.environment_id.as_str(), &[mine])
            .await
            .expect("teardown");

        assert_eq!(target.rule_deletions(), vec![mine]);
        assert!(target.routing_for(mine).is_none(), "own rule removed");
        assert!(target.routing_for(other).is_some(), "sibling rule kept");
        assert!(target.weights_for(other).is_some(), "sibling weights kept");
        assert!(!target.services().contains(&mine));
        assert!(target.services().contains(&other), "sibling service kept");
    }

    #[tokio::test]
    async fn a_listener_without_routing_owns_no_rule() {
        let target = InMemoryEcs::default();
        let dep = DeploymentId(Ulid::from(0xC3_u128));
        let listener = ListenerRef {
            deployment_id: dep,
            listener_arn: LISTENER.to_string(),
            cluster: "c".into(),
            routing: None,
        };
        target
            .apply_listener_weights(&listener, &[])
            .await
            .expect("default-action write");
        target.delete_listener_rule(&listener).await.expect("no-op");
        assert!(target.rule_deletions().is_empty());
        assert!(
            target.weights_for(dep).is_some(),
            "listener default untouched"
        );
    }

    #[tokio::test]
    async fn unconfigured_target_refuses_service_and_rule_deletion() {
        let target = UnconfiguredEcsTarget;
        let dep = DeploymentId(Ulid::from(0xD4_u128));
        assert!(matches!(
            target
                .delete_service(&ServiceRef {
                    deployment_id: dep,
                    cluster: "c".into(),
                    region: "r".into(),
                })
                .await,
            Err(EcsTargetError::Unconfigured)
        ));
        assert!(matches!(
            target
                .delete_listener_rule(&ListenerRef {
                    deployment_id: dep,
                    listener_arn: LISTENER.to_string(),
                    cluster: "c".into(),
                    routing: None,
                })
                .await,
            Err(EcsTargetError::Unconfigured)
        ));
        let env = build_fixture_env();
        assert!(
            teardown_environment(
                &target,
                &params(&env),
                env.environment_id.as_str(),
                &ids(&env)
            )
            .await
            .is_err(),
            "an unconfigured target must fail the teardown, not report success"
        );
    }
}
