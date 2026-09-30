//! Per-revision runtime pin (unified update L2): a revision is warmed on the
//! runtime image its own manifest pinned, not the binding's answer.

use serde_json::json;

use std::sync::Arc;

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;

const RUNTIME_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RUNTIME_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn a_revision_pin_overrides_the_answer_but_keeps_the_repository() {
    let env = build_fixture_env();
    let mut p = GcpCloudRunParams::for_env(&env);
    p.project = "p".into();
    p.region = "europe-west1".into();
    p.runtime_image_digest = Some(RUNTIME_A.into());
    assert_eq!(
        p.image_ref_for(Some(RUNTIME_B)),
        format!("ghcr.io/greenticai/greentic-start-distroless@{RUNTIME_B}")
    );
    p.ar_repo = Some("mirror".into());
    assert_eq!(
        p.image_ref_for(Some(RUNTIME_B)),
        format!(
            "europe-west1-docker.pkg.dev/p/mirror/greenticai/greentic-start-distroless@{RUNTIME_B}"
        )
    );
    assert_eq!(p.image_ref_for(None), p.image_ref());
}

#[tokio::test]
async fn warm_uses_the_revisions_own_runtime() {
    let target = Arc::new(InMemoryCloudRun::default());
    let handler = GcpCloudRunDeployerHandler::with_target(target.clone());
    let mut env = build_fixture_env();
    env.revisions[0].runtime_image_digest = Some(RUNTIME_B.into());
    let (rev, dep) = (env.revisions[0].revision_id, env.revisions[0].deployment_id);
    handler
        .warm_revision(&env, rev, Some(&json!({"runtime_image_digest": RUNTIME_A})))
        .await
        .expect("warms");
    let image = target.revision_image_for(dep, rev).expect("created");
    assert!(image.ends_with(RUNTIME_B), "{image}");
}

#[tokio::test]
async fn an_unpinned_revision_runs_the_binding_answer() {
    let target = Arc::new(InMemoryCloudRun::default());
    let handler = GcpCloudRunDeployerHandler::with_target(target.clone());
    let env = build_fixture_env();
    let (rev, dep) = (env.revisions[0].revision_id, env.revisions[0].deployment_id);
    handler
        .warm_revision(&env, rev, Some(&json!({"runtime_image_digest": RUNTIME_A})))
        .await
        .expect("warms");
    let image = target.revision_image_for(dep, rev).expect("created");
    assert!(image.ends_with(RUNTIME_A), "{image}");
}
