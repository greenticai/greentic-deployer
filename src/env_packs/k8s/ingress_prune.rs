//! Removal of the deployer-owned Ingress once the `ingress_*` answers are
//! cleared ([`manifests::ingress`](super::manifests::ingress)).
//!
//! Env-level objects are otherwise never pruned; the Ingress is the
//! exception because it publishes the environment on a public hostname, and
//! clearing the answer must stop that. Only an Ingress carrying every
//! [`owner_labels`](super::manifests::ingress::owner_labels) is removed — an
//! operator-created `gtc-router` Ingress is left alone. An identity that may
//! not read Ingresses (a bound env bootstrapped before the Ingress verbs
//! existed) cannot prove ownership, so nothing is removed and the reconcile
//! proceeds exactly as before.

use greentic_deploy_spec::Environment;
use serde_json::json;

use super::cluster::{K8sCluster, K8sClusterError, ObjectRef};
use super::manifests::{K8sParams, ROUTER_NAME, ingress};

/// When `params` configures no Ingress, delete the deployer-owned one if it
/// exists. `Some` names the removed object for the reconcile's `pruned`
/// list; `None` when there was nothing of ours to remove, the answers still
/// configure an Ingress, or the check itself failed (logged, never fatal).
pub(super) async fn remove_unanswered(
    cluster: &dyn K8sCluster,
    env: &Environment,
    params: &K8sParams,
) -> Result<Option<ObjectRef>, K8sClusterError> {
    if params.ingress.is_some() {
        return Ok(None);
    }
    let object = ObjectRef::from_manifest(&json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": ROUTER_NAME, "namespace": params.namespace},
    }))?;
    let owner = ingress::owner_labels(env);
    let labels: Vec<(&str, &str)> = owner.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // This runs on EVERY reconcile of an env without `ingress_*` answers,
    // after everything else converged, so it must never fail one: any error
    // is a warning, and the Ingress is re-checked on the next reconcile.
    match cluster.delete_if_labeled(&object, &labels).await {
        Ok(removed) => Ok(removed.then_some(object)),
        Err(e) => {
            tracing::warn!(
                object = %object,
                error = %e,
                "could not check for a deployer-managed Ingress to remove; the reconcile \
                 continues and the next one re-checks"
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::cluster::InMemoryCluster;

    fn params(answers: serde_json::Value) -> K8sParams {
        K8sParams::from_answers(&build_fixture_env(), Some(&answers)).expect("valid answers")
    }

    fn ingress_ref(namespace: &str) -> ObjectRef {
        ObjectRef::from_manifest(&json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"name": ROUTER_NAME, "namespace": namespace},
        }))
        .expect("valid ref")
    }

    async fn cluster_with_rendered_ingress() -> (InMemoryCluster, K8sParams) {
        let env = build_fixture_env();
        let with = params(json!({"ingress_host": "a.example.com"}));
        let cluster = InMemoryCluster::default();
        let manifest = ingress::render(&env, &with).expect("rendered");
        cluster.apply(&manifest).await.expect("apply");
        (cluster, with)
    }

    #[tokio::test]
    async fn cleared_answers_remove_the_deployer_owned_ingress() {
        let env = build_fixture_env();
        let (cluster, with) = cluster_with_rendered_ingress().await;
        let cleared = params(json!({}));
        let removed = remove_unanswered(&cluster, &env, &cleared)
            .await
            .expect("ok");
        assert_eq!(removed, Some(ingress_ref(&with.namespace)));
        assert!(cluster.objects().is_empty());
    }

    #[tokio::test]
    async fn answered_ingress_is_never_removed() {
        let env = build_fixture_env();
        let (cluster, with) = cluster_with_rendered_ingress().await;
        let removed = remove_unanswered(&cluster, &env, &with).await.expect("ok");
        assert_eq!(removed, None);
        assert_eq!(cluster.objects().len(), 1);
    }

    #[tokio::test]
    async fn an_operator_created_ingress_of_the_same_name_is_left_alone() {
        let env = build_fixture_env();
        let cleared = params(json!({}));
        for labels in [
            json!({}),
            // Our env label alone is not ownership: managed-by + component too.
            json!({"greentic.ai/env": env.environment_id.as_str()}),
            json!({
                "app.kubernetes.io/managed-by": "greentic",
                "app.kubernetes.io/component": "router-ingress",
                "greentic.ai/env": "another-env",
            }),
        ] {
            let cluster = InMemoryCluster::default();
            cluster
                .apply(&json!({
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "metadata": {"name": ROUTER_NAME, "namespace": cleared.namespace, "labels": labels},
                }))
                .await
                .expect("apply");
            let removed = remove_unanswered(&cluster, &env, &cleared)
                .await
                .expect("ok");
            assert_eq!(removed, None, "labels {labels}");
            assert_eq!(cluster.objects().len(), 1);
        }
    }

    /// End to end through `reconcile`: clearing the answers reports the
    /// removed Ingress in `pruned`.
    #[tokio::test]
    async fn reconcile_prunes_the_ingress_once_the_answers_are_cleared() {
        use crate::env_packs::k8s::K8sDeployerHandler;
        use std::sync::Arc;

        let env = build_fixture_env();
        let cluster = Arc::new(InMemoryCluster::default());
        let handler = K8sDeployerHandler::with_cluster(cluster.clone());
        let with = json!({"ingress_host": "a.example.com"});
        let first = handler
            .reconcile(&env, Some(&with), true)
            .await
            .expect("reconcile");
        let namespace = params(with).namespace;
        assert!(first.applied.contains(&ingress_ref(&namespace)));
        assert!(!first.pruned.contains(&ingress_ref(&namespace)));

        let second = handler
            .reconcile(&env, None, true)
            .await
            .expect("reconcile");
        assert!(second.pruned.contains(&ingress_ref(&namespace)));
        assert!(!cluster.objects().contains_key(&ingress_ref(&namespace)));

        let third = handler
            .reconcile(&env, None, true)
            .await
            .expect("reconcile");
        assert!(
            !third.pruned.contains(&ingress_ref(&namespace)),
            "reported once"
        );
    }

    /// M1: a pre-existing Ingress this deployer did not create is refused,
    /// never adopted (and so never later deletable), and left unchanged.
    #[tokio::test]
    async fn reconcile_refuses_to_adopt_an_operator_ingress() {
        use crate::env_packs::k8s::K8sDeployerHandler;
        use std::sync::Arc;

        let env = build_fixture_env();
        let with = json!({"ingress_host": "a.example.com"});
        let namespace = params(with.clone()).namespace;
        let cluster = Arc::new(InMemoryCluster::default());
        let operator = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"name": ROUTER_NAME, "namespace": namespace},
            "spec": {"rules": [{"host": "ops.example.com"}]},
        });
        cluster.apply(&operator).await.expect("seed");
        let handler = K8sDeployerHandler::with_cluster(cluster.clone());
        let err = handler
            .reconcile(&env, Some(&with), true)
            .await
            .expect_err("must refuse");
        assert!(err.to_string().contains(ROUTER_NAME), "{err}");
        assert_eq!(
            cluster.objects().get(&ingress_ref(&namespace)),
            Some(&operator)
        );
    }

    /// M2: a failed check never fails a reconcile that asked for no Ingress.
    #[tokio::test]
    async fn a_failed_check_is_a_warning_not_an_error() {
        #[derive(Debug)]
        struct FailingRead;
        #[async_trait::async_trait]
        impl K8sCluster for FailingRead {
            async fn apply(&self, _: &serde_json::Value) -> Result<(), K8sClusterError> {
                Ok(())
            }
            async fn delete(&self, _: &ObjectRef) -> Result<(), K8sClusterError> {
                Ok(())
            }
            async fn get_rollout_status(
                &self,
                _: &ObjectRef,
            ) -> Result<crate::env_packs::k8s::cluster::RolloutStatus, K8sClusterError>
            {
                Err(K8sClusterError::Api("unused".into()))
            }
            async fn get_service_status(
                &self,
                _: &ObjectRef,
            ) -> Result<crate::env_packs::k8s::cluster::ServiceStatus, K8sClusterError>
            {
                Err(K8sClusterError::Api("unused".into()))
            }
            async fn delete_if_labeled(
                &self,
                _: &ObjectRef,
                _: &[(&str, &str)],
            ) -> Result<bool, K8sClusterError> {
                Err(K8sClusterError::Api(
                    "apiserver unavailable (status 503)".into(),
                ))
            }
        }
        let env = build_fixture_env();
        let removed = remove_unanswered(&FailingRead, &env, &params(json!({})))
            .await
            .expect("never an error");
        assert_eq!(removed, None);
    }

    #[tokio::test]
    async fn nothing_to_remove_is_not_reported() {
        let env = build_fixture_env();
        let cluster = InMemoryCluster::default();
        let removed = remove_unanswered(&cluster, &env, &params(json!({})))
            .await
            .expect("ok");
        assert_eq!(removed, None);
    }
}
