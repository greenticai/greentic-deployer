//! Warm-path tests for Redis-backed sessions, VPC egress and the
//! multi-instance gate (`shared_state`), against the in-memory fake.

use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;
use crate::env_packs::gcp_cloudrun::redis_secret::redis_url_secret_name;
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
const GOLDEN_FIXTURE_INTENT: &str = "b9af277c076a1fb76883b40bf8ccf931";

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
    // Its OWN env-owned secret, never the seed secret (so a superseded
    // password can be destroyed without touching live seed versions).
    let prefix = GcpCloudRunParams::for_env(&env).secret_prefix;
    let redis_secret = redis_url_secret_name(&prefix);
    assert!(secret_env.iter().all(|s| s.secret_name == redis_secret));
    let versions: std::collections::BTreeSet<&str> =
        secret_env.iter().map(|s| s.version.as_str()).collect();
    assert_eq!(versions.len(), 1, "both names read ONE pinned version");
    assert_eq!(target.secrets()[&redis_secret].payload, URL.as_bytes());
    assert_eq!(
        target.secrets()[&redis_secret].owner,
        Some(env_owner_stamp(env.environment_id.as_str()))
    );
    let runtime_sa =
        GcpCloudRunParams::for_env(&env).runtime_service_account(env.environment_id.as_str());
    assert_eq!(
        target.secret_accessors_for(&redis_secret),
        Some(vec![runtime_sa])
    );
    let seed = environment_secret_name(&prefix);
    assert_ne!(
        target.secrets()[&seed].payload,
        URL.as_bytes(),
        "the seed secret never carries the URL"
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

/// Warm `revisions[i]` of the fixture with `url` (single instance).
async fn warm_with(
    handler: &GcpCloudRunDeployerHandler,
    env: &Environment,
    i: usize,
    url: &str,
) -> Result<WarmOutcome, DeployerError> {
    let answers = json!({"redis_url": url, "vpc_connector": "c"});
    handler
        .warm_revision(env, env.revisions[i].revision_id, Some(&answers))
        .await
}

/// `(enabled, destroyed)` per version of the env's Redis URL secret.
fn redis_states(target: &InMemoryCloudRun, env: &Environment) -> Vec<(bool, bool)> {
    let name = redis_url_secret_name(&GcpCloudRunParams::for_env(env).secret_prefix);
    target
        .secret_versions_of(&name)
        .iter()
        .map(|v| (v.enabled, v.destroyed))
        .collect()
}

const URL_B: &str = "redis://:rotated-once@10.0.0.3:6379";
const URL_C: &str = "redis://:rotated-twice@10.0.0.3:6379";

#[tokio::test]
async fn an_unchanged_url_reuses_its_version_and_prunes_nothing() {
    let (handler, target) = handler();
    let env = build_fixture_env();
    warm_with(&handler, &env, 0, URL).await.expect("warm 0");
    warm_with(&handler, &env, 1, URL).await.expect("warm 1");
    warm_with(&handler, &env, 2, URL).await.expect("warm 2");
    assert_eq!(redis_states(&target, &env), vec![(true, false)]);
    let pinned: std::collections::BTreeSet<String> = env
        .bundles
        .iter()
        .take(2)
        .flat_map(|b| target.service_secret_env_for(b.deployment_id).expect("svc"))
        .map(|s| s.version)
        .collect();
    assert_eq!(pinned.len(), 1, "every deployment shares the one version");
}

#[tokio::test]
async fn a_changed_url_keeps_the_previous_version_and_destroys_older_ones() {
    let (handler, target) = handler();
    let env = build_fixture_env();
    let seed = environment_secret_name(&GcpCloudRunParams::for_env(&env).secret_prefix);
    warm_with(&handler, &env, 0, URL).await.expect("warm A");
    warm_with(&handler, &env, 1, URL_B).await.expect("warm B");
    // B is new: A is the immediately previous version and must survive.
    assert_eq!(
        redis_states(&target, &env),
        vec![(true, false), (true, false)]
    );
    let seed_versions = target.secret_versions_of(&seed);

    warm_with(&handler, &env, 2, URL_C).await.expect("warm C");
    // C is new: B stays (previous), A (older) is disabled + destroyed.
    assert_eq!(
        redis_states(&target, &env),
        vec![(false, true), (true, false), (true, false)]
    );
    // The seed secret is never pruned.
    assert!(
        target
            .secret_versions_of(&seed)
            .iter()
            .all(|v| v.enabled && !v.destroyed)
    );
    assert!(target.secret_versions_of(&seed).len() > seed_versions.len());

    // Reverting to B reuses B: nothing minted, nothing destroyed.
    let mut env2 = env.clone();
    env2.revisions[0].revision_id = greentic_deploy_spec::RevisionId::new();
    warm_with(&handler, &env2, 0, URL_B)
        .await
        .expect("revert to B");
    assert_eq!(
        redis_states(&target, &env),
        vec![(false, true), (true, false), (true, false)]
    );
}

#[tokio::test]
async fn a_failed_prune_leaves_the_versions_and_the_deploy_succeeds() {
    let (handler, target) = handler();
    let env = build_fixture_env();
    target.deny_version_destroy();
    warm_with(&handler, &env, 0, URL).await.expect("warm A");
    warm_with(&handler, &env, 1, URL_B).await.expect("warm B");
    warm_with(&handler, &env, 2, URL_C)
        .await
        .expect("deploy still succeeds");
    assert_eq!(redis_states(&target, &env), vec![(true, false); 3]);
}

#[tokio::test]
async fn without_versions_list_reuse_falls_back_to_latest_and_nothing_is_pruned() {
    let (handler, target) = handler();
    let env = build_fixture_env();
    target.deny_version_list();
    warm_with(&handler, &env, 0, URL).await.expect("warm A");
    warm_with(&handler, &env, 1, URL)
        .await
        .expect("same URL reuses latest");
    assert_eq!(redis_states(&target, &env), vec![(true, false)]);
    warm_with(&handler, &env, 2, URL_B).await.expect("warm B");
    assert_eq!(
        redis_states(&target, &env),
        vec![(true, false), (true, false)]
    );
}

#[tokio::test]
async fn a_redis_secret_this_env_did_not_stamp_is_never_written() {
    for owner in [Some("someone-else"), None] {
        let (handler, target) = handler();
        let env = build_fixture_env();
        let name = redis_url_secret_name(&GcpCloudRunParams::for_env(&env).secret_prefix);
        target.seed_secret(&name, owner);
        let err = warm_with(&handler, &env, 0, URL)
            .await
            .expect_err("refused");
        assert!(err.to_string().contains(&name), "{err}");
        assert!(!err.to_string().contains("s3cret-auth"), "{err}");
        assert_eq!(target.secrets()[&name].versions, 1, "nothing added");
        assert!(target.secret_accessors_for(&name).is_none(), "no grant");
    }
}
