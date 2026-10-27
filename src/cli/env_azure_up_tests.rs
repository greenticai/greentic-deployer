//! `op env up` for an Azure Container Apps environment, driven against the
//! in-memory fake through the CLI's test-only target seam.

use std::path::PathBuf;

use greentic_deploy_spec::{CapabilitySlot, EnvId, Environment, RevisionLifecycle};
use serde_json::json;
use tempfile::tempdir;

use super::*;
use crate::cli::tests_common::{
    make_binding, make_bundle_deployment, make_env, make_revision, make_traffic_split,
};
use crate::environment::{EnvironmentStore as _, LocalFsStore};

fn registry() -> crate::env_packs::EnvPackRegistry {
    crate::env_packs::EnvPackRegistry::with_builtins()
}

#[test]
fn azure_env_up_returns_none_for_other_deployers() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.k8s@1.0.0",
    ));
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    assert!(
        azure_env_up(&store, &registry(), &env_id)
            .unwrap()
            .is_none()
    );
}

#[cfg(not(all(feature = "creds-azure", feature = "deploy-azure-aca")))]
#[test]
fn azure_env_up_without_the_deploy_feature_refuses_by_name() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.azure-aca@1.0.0",
    ));
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    match azure_env_up(&store, &registry(), &env_id) {
        Err(OpError::Conflict(m)) => assert!(m.contains("deploy-azure-aca"), "{m}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[cfg(all(feature = "creds-azure", feature = "deploy-azure-aca"))]
fn bind_azure(env: &mut Environment) {
    let mut binding = make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.azure-aca@1.0.0",
    );
    binding.answers_ref = Some(PathBuf::from("azure-answers.json"));
    env.packs.push(binding);
}

#[cfg(all(feature = "creds-azure", feature = "deploy-azure-aca"))]
fn write_answers(store: &LocalFsStore, env_id: &EnvId, subscription: &str) {
    let env_dir = store.env_dir(env_id).unwrap();
    std::fs::create_dir_all(&env_dir).unwrap();
    let answers = json!({
        "subscription_id": subscription,
        "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "resource_group": "rg",
        "environment_name": "ce",
    });
    std::fs::write(
        env_dir.join("azure-answers.json"),
        serde_json::to_vec(&answers).unwrap(),
    )
    .unwrap();
}

/// Two deployments: one routed by a split, one unsplit whose newest revision is
/// warmed; a superseded unrouted revision is not re-warmed.
#[cfg(all(feature = "creds-azure", feature = "deploy-azure-aca"))]
#[test]
fn env_up_warms_every_routed_revision_and_returns_endpoints() {
    use std::sync::Arc;

    use crate::env_packs::azure_aca::fake::InMemoryAca;
    let sub = "11111111-0000-0000-0000-00000000aaa1";
    let fake = Arc::new(InMemoryAca::new());
    let _seam = crate::cli::env_azure::install_target(sub, fake.clone());

    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_azure(&mut env);
    let d1 = make_bundle_deployment("local", "bundle-a");
    let d2 = make_bundle_deployment("local", "bundle-b");
    let r1 = make_revision(
        "local",
        "bundle-a",
        &d1.deployment_id,
        1,
        RevisionLifecycle::Ready,
    );
    let r2_old = make_revision(
        "local",
        "bundle-b",
        &d2.deployment_id,
        1,
        RevisionLifecycle::Ready,
    );
    let r2_new = make_revision(
        "local",
        "bundle-b",
        &d2.deployment_id,
        2,
        RevisionLifecycle::Ready,
    );
    let split = make_traffic_split(
        "local",
        "bundle-a",
        &d1.deployment_id,
        &r1.revision_id,
        "01J000000000000000000000AA",
    );
    env.bundles.extend([d1.clone(), d2.clone()]);
    env.revisions.extend([r1, r2_old, r2_new]);
    env.traffic_splits.push(split);
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    write_answers(&store, &env_id, sub);

    let out = azure_env_up(&store, &registry(), &env_id)
        .unwrap()
        .expect("azure arm answers");
    assert!(
        out["kind"]
            .as_str()
            .unwrap()
            .starts_with("greentic.deployer.azure-aca"),
        "{out}"
    );
    assert_eq!(out["warmed"].as_array().map(Vec::len), Some(2), "{out}");
    assert_eq!(fake.app_names().len(), 2);
    let endpoints = out["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert!(
        endpoints
            .iter()
            .all(|e| e["url"].as_str().unwrap().starts_with("https://"))
    );
    assert!(out.get("endpoint_url").is_none());
    assert_eq!(out["applied_splits"], 1);
}

#[test]
fn the_azure_kind_is_recognized_in_every_build() {
    let d =
        greentic_deploy_spec::PackDescriptor::try_new("greentic.deployer.azure-aca@1.0.0").unwrap();
    assert!(names_azure_aca_deployer(&d));
    let _ = (json!({}), PathBuf::new());
}
