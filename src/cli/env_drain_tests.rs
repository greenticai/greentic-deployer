//! Tests for [`super`] (`op env drain-revision` / `sweep` / `capabilities`).
use tempfile::tempdir;

use super::*;
use crate::cli::tests_common::{make_binding, make_env};

fn store_with(kind: &str) -> (tempfile::TempDir, LocalFsStore) {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("zain");
    env.packs.push(make_binding(CapabilitySlot::Deployer, kind));
    store.save(&env).unwrap();
    (dir, store)
}

#[test]
fn capabilities_reports_the_k8s_flags() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    let caps = &out.result["capabilities"];
    assert_eq!(caps["drain"], true);
    assert_eq!(caps["remove"], true);
    assert_eq!(caps["multi_instance_safe"], false);
    assert!(
        out.result["missing"]
            .as_array()
            .unwrap()
            .contains(&json!("ingress_managed"))
    );
}

#[cfg(feature = "creds-gcp")]
#[test]
fn capabilities_is_honest_about_cloud_run_multi_instance() {
    let (_d, store) = store_with("greentic.deployer.gcp-cloudrun@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["multi_instance_safe"], false);
    assert_eq!(out.result["capabilities"]["drain"], true);
    let notes = out.result["notes"].to_string();
    assert!(notes.contains("/tmp"), "{notes}");
}

#[cfg(feature = "creds-aws")]
#[test]
fn capabilities_reports_the_aws_ecs_flags() {
    let (_d, store) = store_with("greentic.deployer.aws-ecs@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    let caps = &out.result["capabilities"];
    assert_eq!(caps["drain"], false);
    assert_eq!(caps["traffic_split"], true);
    assert_eq!(caps["ingress_managed"], false);
    assert_eq!(caps["private_registry_auth"], true);
    assert_eq!(caps["multi_instance_safe"], false);
    assert_eq!(caps["remove"], true);
    assert_eq!(caps["runtime_pin"], false);
}

#[cfg(feature = "creds-aws")]
#[test]
fn aws_ecs_capability_notes_state_the_single_task_and_operator_provided_ingress() {
    let (_d, store) = store_with("greentic.deployer.aws-ecs@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    let notes = out.result["notes"].to_string();
    assert!(notes.contains("scale-to-zero"), "{notes}");
    assert!(notes.contains("operator-provided"), "{notes}");
}

/// k8s builds without `creds-gcp`, so its half of the runtime_pin claim is
/// asserted ungated (unified update L2b: it declares it, like Cloud Run).
#[test]
fn k8s_declares_runtime_pin() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["runtime_pin"], true);
}

#[cfg(feature = "creds-gcp")]
#[test]
fn cloud_run_declares_runtime_pin() {
    let (_d, store) = store_with("greentic.deployer.gcp-cloudrun@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["runtime_pin"], true);
}

#[test]
fn drain_is_refused_by_capability_name_on_an_adapter_without_drain() {
    let (_d, store) = store_with(crate::defaults::LOCAL_DEPLOYER_PACK);
    let err = drain_revision(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        EnvDrainRevisionArgs {
            env_id: "zain".into(),
            revision_id: "00000000000000000000000000".into(),
            kind: None,
        },
    )
    .unwrap_err();
    assert_eq!(err.kind(), "capability-missing");
    assert!(err.to_string().contains("`drain`"), "{err}");
}

#[test]
fn sweep_is_refused_by_capability_name_on_an_adapter_without_remove() {
    let (_d, store) = store_with(crate::defaults::LOCAL_DEPLOYER_PACK);
    let err = sweep(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        EnvSweepArgs {
            env_id: "zain".into(),
            apply: false,
            kind: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("`remove`"), "{err}");
}

#[test]
fn drain_names_an_unknown_revision() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let err = drain_revision(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        EnvDrainRevisionArgs {
            env_id: "zain".into(),
            revision_id: "00000000000000000000000000".into(),
            kind: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, OpError::NotFound(_)), "{err}");
}

#[test]
fn not_drained_maps_to_a_typed_cli_error_naming_the_revision() {
    let r = RevisionId::new();
    let err = drain_error(DeployerError::NotDrained {
        revision_id: r,
        reason: "1 pod".into(),
    });
    assert_eq!(err.kind(), "not-drained");
    let msg = err.to_string();
    assert!(
        msg.contains(&r.to_string()) && msg.contains("--force-drain"),
        "{msg}"
    );
}

#[tokio::test]
async fn archive_gate_refuses_then_force_overrides() {
    use crate::env_packs::deployer::DrainPolicy;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::K8sDeployerHandler;
    use crate::env_packs::k8s::cluster::InMemoryCluster;
    let h = K8sDeployerHandler::with_cluster(std::sync::Arc::new(InMemoryCluster::default()))
        .with_drain_policy(DrainPolicy::immediate());
    let env = build_fixture_env();
    let r = env.revisions[0].revision_id;
    h.warm_revision(&env, r, None).await.unwrap();
    let err = archive_drain_gate(&h, &env, r, None, false)
        .await
        .unwrap_err();
    assert!(matches!(err, OpError::NotDrained { .. }), "{err}");
    archive_drain_gate(&h, &env, r, None, true).await.unwrap();
}

#[test]
fn sweep_preflight_refusal_is_a_typed_permission_error() {
    use crate::env_packs::k8s::sweep::SweepPreflightError;
    let err = preflight_error(SweepPreflightError::MissingPermission {
        env_id: "zain".into(),
        namespace: "gtc-zain".into(),
        permissions: vec!["k8s.rbac.allow:apps/deployments:list".into()],
    });
    assert_eq!(err.kind(), "permission-missing");
    let msg = err.to_string();
    assert!(msg.contains("apps/deployments:list"), "{msg}");
    assert!(msg.contains("gtc op credentials bootstrap zain"), "{msg}");
    let err = preflight_error(SweepPreflightError::ReviewFailed("x".into()));
    assert_eq!(err.kind(), "conflict");
}

/// Issue #661: a client gates sending `replicas` / `max_instances` > 1 on this
/// flag, so an older deployer (which omits it) is never sent unknown keys.
#[test]
fn k8s_reports_scale_out_answers() {
    let (_d, store) = store_with("greentic.deployer.k8s@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["scale_out_answers"], true);
    assert!(
        !out.result["missing"]
            .as_array()
            .unwrap()
            .contains(&json!("scale_out_answers"))
    );
}

#[cfg(feature = "creds-gcp")]
#[test]
fn cloud_run_reports_scale_out_answers() {
    let (_d, store) = store_with("greentic.deployer.gcp-cloudrun@1.0.0");
    let out = capabilities(
        &store,
        &EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        "zain",
        None,
    )
    .unwrap();
    assert_eq!(out.result["capabilities"]["scale_out_answers"], true);
    // Reporting the answers is not a claim that scaling out is safe by itself.
    assert_eq!(out.result["capabilities"]["multi_instance_safe"], false);
}
