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
/// list; `None` when there was nothing of ours to remove (or the answers
/// still configure an Ingress).
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
    Ok(cluster
        .delete_if_labeled(&object, &labels)
        .await?
        .then_some(object))
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
        let cluster = InMemoryCluster::default();
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
