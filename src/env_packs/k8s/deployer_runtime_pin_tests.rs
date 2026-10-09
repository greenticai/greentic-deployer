//! Per-revision runtime pin on the k8s deployer (unified update L2b): warm
//! applies the revision's own worker image and keeps the answer's repository.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::k8s::cluster::InMemoryCluster;
use crate::env_packs::k8s::manifests::worker_name;

const PIN: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ANSWER_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn deployed_worker_image(cluster: &InMemoryCluster, name: &str) -> String {
    cluster
        .objects()
        .iter()
        .find(|(o, _)| o.kind == "Deployment" && o.name == name)
        .and_then(|(_, m)| m.pointer("/spec/template/spec/containers/0/image"))
        .and_then(|v| v.as_str())
        .expect("worker image")
        .to_string()
}

#[test]
fn k8s_declares_runtime_pin() {
    let handler = K8sDeployerHandler::default();
    assert!(handler.capabilities().runtime_pin);
    assert!(
        handler
            .capability_notes()
            .iter()
            .any(|n| n.starts_with("runtime_pin:") && n.contains("router"))
    );
}

#[tokio::test]
async fn warm_applies_the_revisions_own_pin_and_keeps_the_answer_repository() {
    let cluster = Arc::new(InMemoryCluster::default());
    let handler = K8sDeployerHandler::with_cluster(cluster.clone());
    let mut env = build_fixture_env();
    env.revisions[0].runtime_image_digest = Some(PIN.into());
    let answers = json!({"runtime_image": "registry.internal:5000/greentic/start:1.2"});
    handler
        .warm_revision(&env, env.revisions[0].revision_id, Some(&answers))
        .await
        .expect("warms");
    assert_eq!(
        deployed_worker_image(&cluster, &worker_name(&env.revisions[0])),
        format!("registry.internal:5000/greentic/start@{PIN}")
    );
}

#[tokio::test]
async fn an_unpinned_revision_runs_the_answer() {
    let cluster = Arc::new(InMemoryCluster::default());
    let handler = K8sDeployerHandler::with_cluster(cluster.clone());
    let env = build_fixture_env();
    let image = format!("ghcr.io/acme/rt@{ANSWER_DIGEST}");
    let answers = json!({ "runtime_image": image });
    handler
        .warm_revision(&env, env.revisions[0].revision_id, Some(&answers))
        .await
        .expect("warms");
    assert_eq!(
        deployed_worker_image(&cluster, &worker_name(&env.revisions[0])),
        image
    );
}
