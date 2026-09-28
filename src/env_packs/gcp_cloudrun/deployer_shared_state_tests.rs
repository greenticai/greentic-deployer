//! Warm-path tests for Redis-backed sessions, VPC egress and the
//! multi-instance gate (`shared_state`), against the in-memory fake.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;
use crate::env_packs::gcp_cloudrun::shared_state::{
    GeneratedSecretSeed, SESSION_BACKEND_ENV, STATE_BACKEND_ENV, VpcEgress,
};

const URL: &str = "redis://:s3cret-auth@10.0.0.3:6379";

fn handler() -> (GcpCloudRunDeployerHandler, Arc<InMemoryCloudRun>) {
    let target = Arc::new(InMemoryCloudRun::default());
    (
        GcpCloudRunDeployerHandler::with_target(target.clone()),
        target,
    )
}

fn intent_for(env: &Environment, params: &GcpCloudRunParams) -> String {
    let revision = &env.revisions[0];
    revision_intent_with_vpc(
        revision_intent(
            &params.image_ref(),
            &params.runtime_service_account(env.environment_id.as_str()),
            &params.scaling(),
            SESSION_AFFINITY,
            &environment_secret_name(&params.secret_prefix),
            &runtime_boot_env(env, revision, params),
            &secret_env_names(params),
        ),
        params.shared_state.vpc.as_ref(),
    )
}

/// Golden: an environment answering neither Redis nor VPC renders the boot env
/// it rendered before these answers existed — spelled out LITERALLY here, not
/// derived from `runtime_boot_env` — and the revision intent pinned below.
/// `revision_intent` itself is untouched by this change, so the hex is the
/// fixture's pre-change intent; a new boot var or secret-env name moves it.
#[test]
fn no_shared_state_answers_keep_the_intent_byte_identical() {
    let env = build_fixture_env();
    let revision = &env.revisions[0];
    let env_id = env.environment_id.as_str();
    let params = GcpCloudRunParams::from_answers(&env, Some(&json!({}))).expect("parse");
    assert!(secret_env_names(&params).is_empty());

    let legacy_boot: Vec<(String, String)> = [
        ("GREENTIC_ENV", env_id.to_string()),
        ("GREENTIC_ENV_ID", env_id.to_string()),
        ("GREENTIC_SEED_DIR", "/seed".to_string()),
        ("HOME", "/tmp".to_string()),
        ("GREENTIC_GATEWAY_LISTEN_ADDR", "0.0.0.0".to_string()),
        ("GREENTIC_REVISION_ID", revision.revision_id.0.to_string()),
        (
            "GREENTIC_DEPLOYMENT_ID",
            revision.deployment_id.0.to_string(),
        ),
        (
            "GREENTIC_BUNDLE_ID",
            revision.bundle_id.as_str().to_string(),
        ),
        ("GREENTIC_BUNDLE_DIGEST", revision.bundle_digest.clone()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    assert_eq!(runtime_boot_env(&env, revision, &params), legacy_boot);

    assert_eq!(intent_for(&env, &params), GOLDEN_FIXTURE_INTENT);
    assert_eq!(
        revision_intent_with_vpc(GOLDEN_FIXTURE_INTENT.to_string(), None),
        GOLDEN_FIXTURE_INTENT
    );
}

/// The conformance fixture's first revision, default answers.
const GOLDEN_FIXTURE_INTENT: &str = "PLACEHOLDER";

#[tokio::test]
async fn a_plain_warm_renders_no_vpc_no_redis_env() {
    let (handler, target) = handler();
    let env = build_fixture_env();
    let (dep, rev) = (env.bundles[0].deployment_id, env.revisions[0].revision_id);
    handler.warm_revision(&env, rev, None).await.expect("warm");
    assert_eq!(target.revision_vpc_access_for(dep, rev), Some(None));
    assert!(
        target
            .service_secret_env_for(dep)
            .expect("service")
            .is_empty()
    );
}

#[tokio::test]
async fn redis_is_selected_and_its_url_staged_as_one_secret_version() {
    let (handler, target) = handler();
    let env = build_fixture_env();
    let (dep, rev) = (env.bundles[0].deployment_id, env.revisions[0].revision_id);
    let answers = json!({"redis_url": URL, "vpc_connector": "gtc-conn"});
    handler
        .warm_revision(&env, rev, Some(&answers))
        .await
        .expect("warm");

    let plain = target.service_env_for(dep).expect("service");
    assert!(plain.contains(&(SESSION_BACKEND_ENV.into(), "redis".into())));
    assert!(plain.contains(&(STATE_BACKEND_ENV.into(), "redis".into())));
    assert!(
        !plain.iter().any(|(_, v)| v.contains("s3cret-auth")),
        "the URL never rides as a literal"
    );

    let secret_env = target.service_secret_env_for(dep).expect("service");
    let names: Vec<&str> = secret_env.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, REDIS_URL_ENV_NAMES.to_vec());
    let secret_name = environment_secret_name(&GcpCloudRunParams::for_env(&env).secret_prefix);
    assert!(secret_env.iter().all(|s| s.secret_name == secret_name));
    let versions: std::collections::BTreeSet<&str> =
        secret_env.iter().map(|s| s.version.as_str()).collect();
    assert_eq!(versions.len(), 1, "both names read ONE pinned version");
    assert_eq!(
        target.secrets()[&secret_name].payload,
        URL.as_bytes(),
        "the last staged version is the URL"
    );

    assert_eq!(
        target.revision_vpc_access_for(dep, rev),
        Some(Some(VpcAccess {
            target: VpcTarget::Connector(format!(
                "projects/{}/locations/{}/connectors/gtc-conn",
                GcpCloudRunParams::for_env(&env).project,
                GcpCloudRunParams::for_env(&env).region
            )),
            egress: VpcEgress::PrivateRangesOnly,
        }))
    );
}

#[test]
fn vpc_and_redis_answers_move_the_intent() {
    let env = build_fixture_env();
    let base = intent_for(&env, &GcpCloudRunParams::for_env(&env));
    let direct = GcpCloudRunParams::from_answers(
        &env,
        Some(&json!({"vpc_network": "n", "vpc_subnet": "s"})),
    )
    .expect("parse");
    let connector =
        GcpCloudRunParams::from_answers(&env, Some(&json!({"vpc_connector": "c"}))).expect("parse");
    let all_traffic = GcpCloudRunParams::from_answers(
        &env,
        Some(&json!({"vpc_connector": "c", "vpc_egress": "all-traffic"})),
    )
    .expect("parse");
    let redis = GcpCloudRunParams::from_answers(
        &env,
        Some(&json!({"redis_url": URL, "vpc_connector": "c"})),
    )
    .expect("parse");
    let intents = [
        base,
        intent_for(&env, &direct),
        intent_for(&env, &connector),
        intent_for(&env, &all_traffic),
        intent_for(&env, &redis),
    ];
    let unique: std::collections::BTreeSet<&String> = intents.iter().collect();
    assert_eq!(unique.len(), intents.len(), "{intents:?}");

    // The URL value never moves the intent — only its presence does.
    let other_url = GcpCloudRunParams::from_answers(
        &env,
        Some(&json!({"redis_url": "redis://:other@10.0.0.4:6379", "vpc_connector": "c"})),
    )
    .expect("parse");
    assert_eq!(intent_for(&env, &redis), intent_for(&env, &other_url));
}

#[tokio::test]
async fn multi_instance_is_refused_before_any_provider_call() {
    let (handler, target) = handler();
    let env = build_fixture_env();
    let rev = env.revisions[0].revision_id;
    let err = handler
        .warm_revision(&env, rev, Some(&json!({"max_instances": "3"})))
        .await
        .expect_err("refused");
    assert!(err.to_string().contains("`redis_url`"), "{err}");
    assert!(target.services().is_empty() && target.secrets().is_empty());

    // Redis + VPC but an unverified seed: still refused, still nothing staged.
    let err = handler
        .warm_revision(
            &env,
            rev,
            Some(&json!({"max_instances": "3", "redis_url": URL, "vpc_connector": "c"})),
        )
        .await
        .expect_err("refused");
    assert!(err.to_string().contains("generated secret"), "{err}");
    assert!(!err.to_string().contains("s3cret-auth"));
    assert!(target.services().is_empty() && target.secrets().is_empty());
}

#[tokio::test]
async fn multi_instance_warms_with_the_store_and_a_complete_seed() {
    let target = Arc::new(InMemoryCloudRun::default());
    let handler = GcpCloudRunDeployerHandler::with_target(target.clone())
        .with_generated_secret_seed(GeneratedSecretSeed::Complete);
    let env = build_fixture_env();
    let rev = env.revisions[0].revision_id;
    handler
        .warm_revision(
            &env,
            rev,
            Some(&json!({"max_instances": "3", "redis_url": URL, "vpc_connector": "c"})),
        )
        .await
        .expect("warm");
    assert_eq!(target.services().len(), 1);
}
