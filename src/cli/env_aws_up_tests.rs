//! `op env up` for an AWS ECS environment, driven against the in-memory ECS
//! fake through the CLI's test-only target seam.

use std::path::PathBuf;
use std::sync::Arc;

use greentic_deploy_spec::{
    CapabilitySlot, EnvId, Environment, RevisionLifecycle, TrafficSplitEntry,
};
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
fn aws_env_up_returns_none_for_other_deployers() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.k8s@1.0.0",
    ));
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    let out = aws_env_up(&store, &registry(), &env_id).unwrap();
    assert!(out.is_none(), "a k8s env must fall through: {out:?}");
}

#[cfg(not(all(feature = "creds-aws", feature = "deploy-aws-ecs")))]
#[test]
fn aws_env_up_without_a_deploy_feature_refuses_clearly() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.aws-ecs@1.0.0",
    ));
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    match aws_env_up(&store, &registry(), &env_id) {
        Err(OpError::Conflict(msg)) => {
            assert!(msg.contains("deploy-aws-ecs"), "{msg}");
            assert!(msg.contains("op env up"), "{msg}");
        }
        other => panic!("expected a deploy-aws-ecs refusal, got {other:?}"),
    }
}

/// Bind the AWS deployer to an answers file [`write_aws_answers`] writes.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn bind_aws(env: &mut Environment) {
    let mut binding = make_binding(CapabilitySlot::Deployer, "greentic.deployer.aws-ecs@1.0.0");
    binding.answers_ref = Some(PathBuf::from("aws-answers.json"));
    env.packs.push(binding);
}

#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn write_aws_answers(store: &LocalFsStore, env_id: &EnvId, region: &str) {
    let env_dir = store.env_dir(env_id).unwrap();
    std::fs::create_dir_all(&env_dir).unwrap();
    let answers = json!({
        "region": region,
        "alb_listener_arn": "arn:aws:elasticloadbalancing:eu-west-1:111122223333:listener/app/x/y/z",
        "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
        "subnets": "subnet-1",
        "security_groups": "sg-1",
        "target_group_arns": "tg-a,tg-b",
    });
    std::fs::write(
        env_dir.join("aws-answers.json"),
        serde_json::to_vec(&answers).unwrap(),
    )
    .unwrap();
}

/// Two deployments: one whose split routes a revision, one with no split whose
/// newest revision is the one to warm. Both warm, each yields an endpoint, and
/// with two endpoints there is no single `endpoint_url`.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn aws_env_up_warms_every_routed_revision_and_returns_endpoints() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-warms-every-routed";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());

    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_aws(&mut env);
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
    let (r1_id, r2_old_id, r2_new_id) = (r1.revision_id, r2_old.revision_id, r2_new.revision_id);
    env.bundles.push(d1.clone());
    env.bundles.push(d2.clone());
    env.revisions.extend([r1, r2_old, r2_new]);
    env.traffic_splits.push(split);
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    write_aws_answers(&store, &env_id, region);

    let out = aws_env_up(&store, &registry(), &env_id)
        .unwrap()
        .expect("an aws env is brought up by the aws arm");

    assert!(
        out["kind"]
            .as_str()
            .unwrap()
            .starts_with("greentic.deployer.aws-ecs"),
        "{out}"
    );
    assert_eq!(out["environment_id"], "local");
    assert_eq!(out["warmed"].as_array().map(Vec::len), Some(2), "{out}");
    assert!(fake.task_set_spec_of(d1.deployment_id, r1_id).is_some());
    assert!(fake.task_set_spec_of(d2.deployment_id, r2_new_id).is_some());
    assert!(
        fake.task_set_spec_of(d2.deployment_id, r2_old_id).is_none(),
        "a superseded revision that carries no traffic is not re-warmed"
    );
    let endpoints = out["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2, "{out}");
    let ids: Vec<&str> = endpoints
        .iter()
        .map(|e| e["deployment_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&d1.deployment_id.to_string().as_str()));
    assert!(ids.contains(&d2.deployment_id.to_string().as_str()));
    assert!(
        endpoints
            .iter()
            .all(|e| e["url"].as_str().unwrap().starts_with("https://")),
        "{out}"
    );
    assert!(out.get("endpoint_url").is_none(), "two endpoints: {out}");
    assert_eq!(out["applied_splits"], 1);
}

/// A 50/50 split is warmed revision by revision and then pushed to the
/// listener; one deployment means one `endpoint_url`.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn aws_env_up_applies_the_traffic_splits() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-applies-splits";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());

    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_aws(&mut env);
    let d = make_bundle_deployment("local", "bundle-a");
    let r1 = make_revision(
        "local",
        "bundle-a",
        &d.deployment_id,
        1,
        RevisionLifecycle::Ready,
    );
    let r2 = make_revision(
        "local",
        "bundle-a",
        &d.deployment_id,
        2,
        RevisionLifecycle::Ready,
    );
    let mut split = make_traffic_split(
        "local",
        "bundle-a",
        &d.deployment_id,
        &r1.revision_id,
        "01J000000000000000000000AB",
    );
    split.entries = vec![
        TrafficSplitEntry {
            revision_id: r1.revision_id,
            weight_bps: 5_000,
        },
        TrafficSplitEntry {
            revision_id: r2.revision_id,
            weight_bps: 5_000,
        },
    ];
    env.bundles.push(d.clone());
    env.revisions.extend([r1, r2]);
    env.traffic_splits.push(split);
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    write_aws_answers(&store, &env_id, region);

    let out = aws_env_up(&store, &registry(), &env_id).unwrap().unwrap();

    assert_eq!(out["warmed"].as_array().map(Vec::len), Some(2), "{out}");
    assert_eq!(out["applied_splits"], 1);
    let weights = fake
        .weights_for(d.deployment_id)
        .expect("the split was pushed to the listener");
    assert_eq!(weights.len(), 2);
    assert!(weights.iter().all(|w| w.weight_bps == 5_000), "{weights:?}");
    assert!(
        out["endpoint_url"].as_str().is_some(),
        "one deployment → one convenience URL: {out}"
    );
}

/// ALB weights are bps / 10, so a split finer than 10 bps cannot be expressed
/// and is refused BEFORE any revision is warmed.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn aws_env_up_rejects_a_split_the_alb_cannot_express_before_warming() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-rejects-fine-split";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());

    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_aws(&mut env);
    let d = make_bundle_deployment("local", "bundle-a");
    let r1 = make_revision(
        "local",
        "bundle-a",
        &d.deployment_id,
        1,
        RevisionLifecycle::Ready,
    );
    let r2 = make_revision(
        "local",
        "bundle-a",
        &d.deployment_id,
        2,
        RevisionLifecycle::Ready,
    );
    let mut split = make_traffic_split(
        "local",
        "bundle-a",
        &d.deployment_id,
        &r1.revision_id,
        "01J000000000000000000000AC",
    );
    split.entries = vec![
        TrafficSplitEntry {
            revision_id: r1.revision_id,
            weight_bps: 3_333,
        },
        TrafficSplitEntry {
            revision_id: r2.revision_id,
            weight_bps: 6_667,
        },
    ];
    env.bundles.push(d);
    env.revisions.extend([r1, r2]);
    env.traffic_splits.push(split);
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    write_aws_answers(&store, &env_id, region);

    match aws_env_up(&store, &registry(), &env_id) {
        Err(OpError::Conflict(msg)) => assert!(msg.contains("10 bps"), "{msg}"),
        other => panic!("expected a split refusal, got {other:?}"),
    }
    assert_eq!(fake.create_task_set_calls(), 0, "nothing warmed");
}

/// The dev store is staged as seed material only when the env resolves
/// `secret://` against the dev store — never for an env without a Secrets
/// pack, and never for a Vault-backed one.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn apply_revision_stages_the_dev_store_only_when_the_env_stages_dev_secrets() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;

    fn warm_with_secrets_pack(region: &str, secrets_pack: Option<&str>) -> Arc<InMemoryEcs> {
        let fake = Arc::new(InMemoryEcs::default());
        let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        bind_aws(&mut env);
        if let Some(pack) = secrets_pack {
            env.packs.push(make_binding(CapabilitySlot::Secrets, pack));
        }
        let d = make_bundle_deployment("local", "bundle-a");
        let r = make_revision(
            "local",
            "bundle-a",
            &d.deployment_id,
            1,
            RevisionLifecycle::Ready,
        );
        let revision_id = r.revision_id;
        env.bundles.push(d);
        env.revisions.push(r);
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        write_aws_answers(&store, &env_id, region);
        let env_dir = store.env_dir(&env_id).unwrap();
        let dev_path = crate::cli::env::staged_dev_store_path(&env_dir);
        crate::cli::secrets::dev_store_put(&dev_path, "secrets://local/acme/_/kv/token", "v")
            .unwrap();

        let answers: serde_json::Value =
            serde_json::from_slice(&std::fs::read(env_dir.join("aws-answers.json")).unwrap())
                .unwrap();
        crate::cli::env::apply_revision_aws_ecs(
            &store,
            &env,
            &env_id,
            revision_id,
            crate::cli::env::RevisionVerb::Warm,
            Some(&answers),
        )
        .unwrap();
        fake
    }

    let dev_store_secret = "gtc-local-dev-store";
    let staged = warm_with_secrets_pack(
        "fake-region-dev-store-staged",
        Some(crate::defaults::LOCAL_SECRETS_PACK),
    );
    assert!(
        staged.secrets().contains_key(dev_store_secret),
        "a dev-store env stages its dev store: {:?}",
        staged.secrets()
    );

    let none = warm_with_secrets_pack("fake-region-dev-store-none", None);
    assert!(
        !none.secrets().contains_key(dev_store_secret),
        "no Secrets pack → nothing staged: {:?}",
        none.secrets()
    );

    let vault = warm_with_secrets_pack(
        "fake-region-dev-store-vault",
        Some(crate::defaults::VAULT_SECRETS_PACK),
    );
    assert!(
        !vault.secrets().contains_key(dev_store_secret),
        "a Vault env never ships the operator's dev store: {:?}",
        vault.secrets()
    );
}

/// The build-independent path must stay the handler's own registry key.
#[cfg(feature = "creds-aws")]
#[test]
fn the_aws_descriptor_path_is_the_handlers() {
    assert_eq!(
        AWS_ECS_DEPLOYER_PATH,
        crate::env_packs::aws::AwsEcsDeployerHandler::DESCRIPTOR_PATH
    );
}

/// A revision id the env does not carry is a typed refusal, not a panic.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn apply_revision_aws_ecs_refuses_an_unknown_revision_instead_of_panicking() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_aws(&mut env);
    let d = make_bundle_deployment("local", "bundle-a");
    let stranger = make_revision(
        "local",
        "bundle-a",
        &d.deployment_id,
        1,
        RevisionLifecycle::Ready,
    );
    // `stranger` is deliberately NOT pushed onto the env.
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    match crate::cli::env::apply_revision_aws_ecs(
        &store,
        &env,
        &env_id,
        stranger.revision_id,
        crate::cli::env::RevisionVerb::Warm,
        None,
    ) {
        Err(OpError::NotFound(msg)) => assert!(msg.contains("revision"), "{msg}"),
        other => panic!("expected a NotFound refusal, got {other:?}"),
    }
}

/// `op env apply-traffic` on its own applies the same granularity preflight
/// `op env up` does: 3333/6667 would otherwise be silently truncated.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn apply_traffic_refuses_a_split_finer_than_the_alb_granularity() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-apply-traffic-fine-split";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());

    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_aws(&mut env);
    let d = make_bundle_deployment("local", "bundle-a");
    let r1 = make_revision(
        "local",
        "bundle-a",
        &d.deployment_id,
        1,
        RevisionLifecycle::Ready,
    );
    let r2 = make_revision(
        "local",
        "bundle-a",
        &d.deployment_id,
        2,
        RevisionLifecycle::Ready,
    );
    let mut split = make_traffic_split(
        "local",
        "bundle-a",
        &d.deployment_id,
        &r1.revision_id,
        "01J000000000000000000000AC",
    );
    split.entries = vec![
        TrafficSplitEntry {
            revision_id: r1.revision_id,
            weight_bps: 3_333,
        },
        TrafficSplitEntry {
            revision_id: r2.revision_id,
            weight_bps: 6_667,
        },
    ];
    let deployment_id = d.deployment_id;
    env.bundles.push(d);
    env.revisions.extend([r1, r2]);
    env.traffic_splits.push(split);
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    write_aws_answers(&store, &env_id, region);

    match crate::cli::env::apply_traffic_aws_ecs(&store, &env, &env_id, deployment_id, None) {
        Err(OpError::Conflict(msg)) => assert!(msg.contains("10 bps"), "{msg}"),
        other => panic!("expected a split refusal, got {other:?}"),
    }
}

/// Two deployments in one env: `target` carries a healthy 50/50 split and
/// `other` a hand-edited 3333/6667 one. Returns (store, env, env_id, target id).
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn env_with_a_fine_split_on_another_deployment(
    region: &str,
    fine_on_target: bool,
) -> (
    tempfile::TempDir,
    Environment,
    EnvId,
    greentic_deploy_spec::DeploymentId,
) {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_aws(&mut env);
    let mut ids = Vec::new();
    for (name, fine, ulid) in [
        ("bundle-a", fine_on_target, "01J000000000000000000000AC"),
        ("bundle-b", !fine_on_target, "01J000000000000000000000AD"),
    ] {
        let d = make_bundle_deployment("local", name);
        let r1 = make_revision("local", name, &d.deployment_id, 1, RevisionLifecycle::Ready);
        let r2 = make_revision("local", name, &d.deployment_id, 2, RevisionLifecycle::Ready);
        let mut split = make_traffic_split("local", name, &d.deployment_id, &r1.revision_id, ulid);
        let (w1, w2) = if fine { (3_333, 6_667) } else { (5_000, 5_000) };
        split.entries = vec![
            TrafficSplitEntry {
                revision_id: r1.revision_id,
                weight_bps: w1,
            },
            TrafficSplitEntry {
                revision_id: r2.revision_id,
                weight_bps: w2,
            },
        ];
        ids.push(d.deployment_id);
        env.bundles.push(d);
        env.revisions.extend([r1, r2]);
        env.traffic_splits.push(split);
    }
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    write_aws_answers(&store, &env_id, region);
    (dir, env, env_id, ids[0])
}

/// Another deployment's stale fine-grained split is not this call's business.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn apply_traffic_ignores_another_deployments_fine_grained_split() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-apply-traffic-other-split";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());
    let (dir, env, env_id, target) = env_with_a_fine_split_on_another_deployment(region, false);
    let store = LocalFsStore::new(dir.path());
    // Whatever the live apply answers, it must not be the granularity refusal.
    if let Err(OpError::Conflict(msg)) =
        crate::cli::env::apply_traffic_aws_ecs(&store, &env, &env_id, target, None)
    {
        assert!(!msg.contains("whole multiples"), "{msg}");
    }
}

/// The target deployment's own fine split is still refused.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn apply_traffic_still_refuses_the_target_deployments_own_fine_split() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-apply-traffic-own-split";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());
    let (dir, env, env_id, target) = env_with_a_fine_split_on_another_deployment(region, true);
    let store = LocalFsStore::new(dir.path());
    match crate::cli::env::apply_traffic_aws_ecs(&store, &env, &env_id, target, None) {
        Err(OpError::Conflict(msg)) => assert!(msg.contains("10 bps"), "{msg}"),
        other => panic!("expected a split refusal, got {other:?}"),
    }
}

/// Rewrite the answers file without the listener.
#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn drop_listener_answer(store: &LocalFsStore, env_id: &EnvId) {
    let path = store.env_dir(env_id).unwrap().join("aws-answers.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("alb_listener_arn");
    std::fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
}

#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
fn env_with_split(
    region: &str,
    weights: &[u32],
) -> (
    tempfile::TempDir,
    LocalFsStore,
    Environment,
    EnvId,
    greentic_deploy_spec::DeploymentId,
) {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    bind_aws(&mut env);
    let d = make_bundle_deployment("local", "bundle-a");
    let mut revisions = Vec::new();
    for n in 1..=weights.len() {
        revisions.push(make_revision(
            "local",
            "bundle-a",
            &d.deployment_id,
            n as u64,
            RevisionLifecycle::Ready,
        ));
    }
    let mut split = make_traffic_split(
        "local",
        "bundle-a",
        &d.deployment_id,
        &revisions[0].revision_id,
        "01J000000000000000000000AC",
    );
    split.entries = revisions
        .iter()
        .zip(weights)
        .map(|(r, w)| TrafficSplitEntry {
            revision_id: r.revision_id,
            weight_bps: *w,
        })
        .collect();
    let dep = d.deployment_id;
    env.bundles.push(d);
    env.revisions.extend(revisions);
    env.traffic_splits.push(split);
    store.save(&env).unwrap();
    let env_id = EnvId::try_from("local").unwrap();
    write_aws_answers(&store, &env_id, region);
    drop_listener_answer(&store, &env_id);
    (dir, store, env, env_id, dep)
}

#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn aws_env_up_refuses_a_multi_revision_split_without_a_listener_before_warming() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-up-no-listener-multi";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());
    let (_dir, store, _env, env_id, _dep) = env_with_split(region, &[5_000, 5_000]);

    match aws_env_up(&store, &registry(), &env_id) {
        Err(OpError::Conflict(msg)) => assert!(msg.contains("alb_listener_arn"), "{msg}"),
        other => panic!("expected a listener refusal, got {other:?}"),
    }
    assert_eq!(fake.create_task_set_calls(), 0, "nothing warmed");
}

#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn aws_env_up_with_a_single_revision_split_needs_no_listener() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-up-no-listener-single";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());
    let (_dir, store, _env, env_id, _dep) = env_with_split(region, &[10_000]);

    let out = aws_env_up(&store, &registry(), &env_id).unwrap().unwrap();
    assert_eq!(out["applied_splits"], 1, "{out}");
    assert!(fake.create_task_set_calls() >= 1);
}

#[cfg(all(feature = "creds-aws", feature = "deploy-aws-ecs"))]
#[test]
fn apply_traffic_without_a_listener_refuses_a_fifty_fifty_split() {
    use crate::env_packs::aws::deploy_target::InMemoryEcs;
    let region = "fake-region-apply-traffic-no-listener";
    let fake = Arc::new(InMemoryEcs::default());
    let _seam = crate::cli::env::ecs_target_seam::install(region, fake.clone());
    let (_dir, store, env, env_id, dep) = env_with_split(region, &[5_000, 5_000]);
    let answers: serde_json::Value = serde_json::from_slice(
        &std::fs::read(store.env_dir(&env_id).unwrap().join("aws-answers.json")).unwrap(),
    )
    .unwrap();

    match crate::cli::env::apply_traffic_aws_ecs(&store, &env, &env_id, dep, Some(&answers)) {
        Err(OpError::Conflict(msg)) => assert!(msg.contains("alb_listener_arn"), "{msg}"),
        other => panic!("expected a listener refusal, got {other:?}"),
    }
}
