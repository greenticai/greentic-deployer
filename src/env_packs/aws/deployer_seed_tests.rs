//! `warm_revision`'s seed staging and revision-intent convergence.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::cli::secrets::DEV_STORE_RELATIVE;
use crate::env_packs::aws::boot_env::ecs_boot_env;
use crate::env_packs::aws::deploy_target::{InMemoryEcs, log_group_name};
use crate::env_packs::aws::seed_stage::{
    SEED_MAX_BYTES, dev_store_secret_name, environment_secret_name, telemetry_headers_secret_name,
};
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::telemetry::HEADER_ENV_NAMES;
use greentic_deploy_spec::{PackId, PackListEntry};

/// The conformance fixture with the warmed revision's pack list grown until the
/// compact document is at least `min_bytes`. The warmed revision is always kept
/// by the prune, so the size survives it.
fn env_of_at_least(min_bytes: usize) -> Environment {
    let mut env = build_fixture_env();
    let mut n = 0u64;
    while serde_json::to_vec(&env).unwrap().len() < min_bytes {
        for _ in 0..50 {
            env.revisions[0]
                .pack_list
                .push(PackListEntry::from_lock_primitives(
                    PackId::new(format!("greentic.fixture.seed-pad-{n}")),
                    format!("sha256:{n:064x}"),
                ));
            n += 1;
        }
    }
    env
}

fn handler_with_fake() -> (AwsEcsDeployerHandler, Arc<InMemoryEcs>) {
    let target = Arc::new(InMemoryEcs::default());
    (AwsEcsDeployerHandler::with_target(target.clone()), target)
}

fn prefix(env: &Environment) -> String {
    format!("gtc-{}", env.environment_id.as_str())
}

fn spec_of(target: &InMemoryEcs, env: &Environment) -> TaskSetSpec {
    let rev = &env.revisions[0];
    target
        .task_set_spec_of(rev.deployment_id, rev.revision_id)
        .expect("warm created the task set")
}

#[tokio::test]
async fn warm_without_dev_secrets_stages_only_environment_json() {
    let (handler, target) = handler_with_fake();
    let env = build_fixture_env();
    handler
        .warm_revision(&env, env.revisions[0].revision_id, None)
        .await
        .unwrap();

    let spec = spec_of(&target, &env);
    let seed = spec.seed.expect("a seed is staged");
    let names: Vec<&str> = seed.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["environment.json"]);
    let env_secret = environment_secret_name(&prefix(&env));
    assert_eq!(
        target.secrets().keys().cloned().collect::<Vec<_>>(),
        vec![env_secret.clone()],
        "only the environment secret exists"
    );
    let versions = target.secret_versions_of(&env_secret);
    assert_eq!(versions.len(), 1);
    assert!(
        seed.files[0]
            .secret_value_from
            .ends_with(&format!(":::{}", versions[0])),
        "the file pins the staged version"
    );
    assert!(spec.secret_env.is_empty(), "no header, no secret env");
}

#[tokio::test]
async fn warm_with_dev_secrets_stages_both() {
    let target = Arc::new(InMemoryEcs::default());
    let dev = b"GREENTIC_DEV_KEY=c2VjcmV0\n".to_vec();
    let handler =
        AwsEcsDeployerHandler::with_target_and_dev_secrets(target.clone(), Some(dev.clone()));
    let env = build_fixture_env();
    handler
        .warm_revision(&env, env.revisions[0].revision_id, None)
        .await
        .unwrap();

    let seed = spec_of(&target, &env).seed.expect("a seed is staged");
    let names: Vec<&str> = seed.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["environment.json", DEV_STORE_RELATIVE]);
    let dev_secret = dev_store_secret_name(&prefix(&env));
    assert_eq!(target.secret_versions_of(&dev_secret).len(), 1);
    use sha2::{Digest, Sha256};
    assert_eq!(seed.files[1].sha256_hex, hex::encode(Sha256::digest(&dev)));
}

#[tokio::test]
async fn rewarm_same_inputs_is_a_noop() {
    let target = Arc::new(InMemoryEcs::default());
    let handler =
        AwsEcsDeployerHandler::with_target_and_dev_secrets(target.clone(), Some(b"K=v\n".to_vec()));
    let env = build_fixture_env();
    let rev = env.revisions[0].revision_id;
    handler.warm_revision(&env, rev, None).await.unwrap();
    let secrets = target.secrets();
    let versions: Vec<_> = secrets
        .keys()
        .map(|n| target.secret_versions_of(n))
        .collect();

    handler.warm_revision(&env, rev, None).await.unwrap();

    assert_eq!(target.create_task_set_calls(), 1, "no second create");
    assert_eq!(target.task_sets().len(), 1);
    assert_eq!(target.secrets(), secrets);
    let after: Vec<_> = secrets
        .keys()
        .map(|n| target.secret_versions_of(n))
        .collect();
    assert_eq!(after, versions, "no new secret versions");
}

#[tokio::test]
async fn rewarm_with_changed_inputs_conflicts() {
    let (handler, target) = handler_with_fake();
    let env = build_fixture_env();
    let rev = env.revisions[0].revision_id;
    handler.warm_revision(&env, rev, None).await.unwrap();

    let err = handler
        .warm_revision(&env, rev, Some(&json!({ "min_instances": "2" })))
        .await
        .unwrap_err();
    match err {
        DeployerError::Provider(msg) => {
            assert!(msg.contains(&rev.to_string()), "names the revision: {msg}");
            assert!(msg.contains("immutable"), "{msg}");
        }
        other => panic!("expected Provider, got {other:?}"),
    }
    assert_eq!(target.create_task_set_calls(), 1);
}

/// A changed launch field (here the task role) is baked into the immutable
/// task definition, so a re-warm of the live revision must refuse rather than
/// report success while the old role keeps serving.
#[tokio::test]
async fn rewarm_with_a_changed_task_role_conflicts() {
    let (handler, target) = handler_with_fake();
    let env = build_fixture_env();
    let rev = env.revisions[0].revision_id;
    let launch = |task_role: &str| {
        json!({
            "execution_role_arn": "arn:aws:iam::111122223333:role/exec",
            "task_role_arn": task_role,
            "subnets": "subnet-aaaa",
            "security_groups": "sg-1111",
        })
    };
    handler
        .warm_revision(&env, rev, Some(&launch("arn:aws:iam::111122223333:role/a")))
        .await
        .unwrap();
    // The same launch answers converge.
    handler
        .warm_revision(&env, rev, Some(&launch("arn:aws:iam::111122223333:role/a")))
        .await
        .unwrap();

    let err = handler
        .warm_revision(&env, rev, Some(&launch("arn:aws:iam::111122223333:role/b")))
        .await
        .unwrap_err();
    match err {
        DeployerError::Provider(msg) => assert!(msg.contains("immutable"), "{msg}"),
        other => panic!("expected Provider, got {other:?}"),
    }
    assert_eq!(target.create_task_set_calls(), 1, "no second task set");
}

/// Retention is a property of the log group, which every warm converges; it
/// is not baked into the task definition, so a re-warm with a new retention
/// converges and applies it.
#[tokio::test]
async fn a_changed_log_retention_still_converges() {
    let (handler, target) = handler_with_fake();
    let env = build_fixture_env();
    let rev = &env.revisions[0];
    handler
        .warm_revision(
            &env,
            rev.revision_id,
            Some(&json!({ "log_retention_days": "30" })),
        )
        .await
        .unwrap();
    handler
        .warm_revision(
            &env,
            rev.revision_id,
            Some(&json!({ "log_retention_days": "14" })),
        )
        .await
        .expect("a changed retention converges");

    assert_eq!(target.create_task_set_calls(), 1, "no second task set");
    let params = AwsEcsParams::for_env(&env);
    let group = log_group_name(&params.secret_prefix, &rev.deployment_id);
    assert_eq!(target.log_groups().get(&group), Some(&14));
}

#[tokio::test]
async fn oversized_seed_is_refused_not_truncated() {
    let (handler, target) = handler_with_fake();
    let env = env_of_at_least(SEED_MAX_BYTES + 1);
    let err = handler
        .warm_revision(&env, env.revisions[0].revision_id, None)
        .await
        .unwrap_err();
    match err {
        DeployerError::Provider(msg) => {
            assert!(msg.contains("environment.json"), "{msg}");
            assert!(msg.contains(&SEED_MAX_BYTES.to_string()), "{msg}");
        }
        other => panic!("expected Provider, got {other:?}"),
    }
    assert!(target.secrets().is_empty(), "no secret created");
    assert!(target.task_sets().is_empty(), "no task set created");
}

#[tokio::test]
async fn telemetry_headers_only_reach_secret_env() {
    let (handler, target) = handler_with_fake();
    let env = build_fixture_env();
    let answers = json!({
        "telemetry_env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example" },
        "telemetry_headers": "authorization=Bearer s3cret",
    });
    handler
        .warm_revision(&env, env.revisions[0].revision_id, Some(&answers))
        .await
        .unwrap();

    let spec = spec_of(&target, &env);
    assert!(
        spec.env
            .iter()
            .all(|(k, v)| !v.contains("s3cret") && !HEADER_ENV_NAMES.contains(&k.as_str())),
        "the header never reaches plain env: {:?}",
        spec.env
    );
    let names: Vec<&str> = spec.secret_env.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, HEADER_ENV_NAMES.to_vec());
    let headers_secret = telemetry_headers_secret_name(&prefix(&env));
    assert_eq!(target.secret_versions_of(&headers_secret).len(), 1);
    assert!(
        spec.secret_env
            .iter()
            .all(|s| s.value_from_arn.contains(&headers_secret))
    );
}

#[tokio::test]
async fn a_foreign_or_unstamped_secret_owner_is_a_conflict() {
    for owner in ["another-env-stamp", ""] {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let name = environment_secret_name(&prefix(&env));
        target.ensure_secret(&name, owner).await.unwrap();

        let err = handler
            .warm_revision(&env, env.revisions[0].revision_id, None)
            .await
            .unwrap_err();
        match err {
            DeployerError::Provider(msg) => assert!(msg.contains(&name), "{msg}"),
            other => panic!("expected Provider, got {other:?}"),
        }
        assert!(
            target.secret_versions_of(&name).is_empty(),
            "owner `{owner}`: nothing written into a secret we do not own"
        );
        assert!(target.task_sets().is_empty());
    }
}

#[tokio::test]
async fn warm_sets_log_group_and_boot_env() {
    let (handler, target) = handler_with_fake();
    let env = build_fixture_env();
    let rev = &env.revisions[0];
    handler
        .warm_revision(&env, rev.revision_id, None)
        .await
        .unwrap();

    let params = AwsEcsParams::for_env(&env);
    let spec = spec_of(&target, &env);
    let group = log_group_name(&params.secret_prefix, &rev.deployment_id);
    assert_eq!(spec.log_group.as_deref(), Some(group.as_str()));
    assert_eq!(target.log_groups().get(&group), Some(&30));
    assert_eq!(spec.env, ecs_boot_env(&env, rev, &params));
    assert_eq!(spec.image, params.runtime_image());
    assert_eq!(spec.revision_intent.len(), 32, "the intent is stamped");
}
