//! `seed_mode`: the answer, and what `warm_revision` stages under each value.

use serde_json::{Value, json};

use std::sync::Arc;

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;
use crate::env_packs::gcp_cloudrun::seed_pointer::{POINTER_KEY, SEED_INLINE_THRESHOLD};
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

fn handler_with_fake() -> (GcpCloudRunDeployerHandler, Arc<InMemoryCloudRun>) {
    let target = Arc::new(InMemoryCloudRun::default());
    (
        GcpCloudRunDeployerHandler::with_target(target.clone()),
        target,
    )
}

fn staged_payload(target: &InMemoryCloudRun, env: &Environment) -> Vec<u8> {
    let params = params_from_answers(env, None).unwrap();
    target
        .secrets()
        .get(&environment_secret_name(&params.secret_prefix))
        .expect("seed secret staged")
        .payload
        .clone()
}

#[test]
fn seed_mode_defaults_to_inline_and_parses_both_values() {
    let env = build_fixture_env();
    assert_eq!(GcpCloudRunParams::for_env(&env).seed_mode, SeedMode::Inline);
    for (value, mode) in [
        (json!("inline"), SeedMode::Inline),
        (json!("auto"), SeedMode::Auto),
        (json!(""), SeedMode::Inline),
    ] {
        let p =
            GcpCloudRunParams::from_answers(&env, Some(&json!({ "seed_mode": value }))).unwrap();
        assert_eq!(p.seed_mode, mode);
    }
    for bad in [json!("pointer"), json!(1), json!(null)] {
        assert!(GcpCloudRunParams::from_answers(&env, Some(&json!({ "seed_mode": bad }))).is_err());
    }
    // The answer is not a deployment-intent input: nothing rolls when it changes.
    let a = GcpCloudRunParams::from_answers(&env, Some(&json!({ "seed_mode": "auto" }))).unwrap();
    assert_eq!(a.scaling(), GcpCloudRunParams::for_env(&env).scaling());
}

#[tokio::test]
async fn auto_stages_a_small_seed_inline_byte_for_byte() {
    let (handler, target) = handler_with_fake();
    let env = build_fixture_env();
    let rev = env.revisions[0].revision_id;
    handler
        .warm_revision(&env, rev, Some(&json!({ "seed_mode": "auto" })))
        .await
        .unwrap();
    assert_eq!(
        staged_payload(&target, &env),
        serde_json::to_vec(&env).unwrap()
    );
    assert!(target.seed_artifacts().is_empty());
}

#[tokio::test]
async fn auto_stages_a_pointer_for_a_large_seed_and_inline_stays_inline() {
    let mut env = env_of_at_least(SEED_INLINE_THRESHOLD + 5_000);
    env.revisions[0].bundle_source_uri =
        Some("oci://europe-docker.pkg.dev/proj/repo/unit-0:abc".to_string());
    let rev = env.revisions[0].revision_id;
    let full = serde_json::to_vec(&env).unwrap();

    // Default (inline): the document itself, whatever its size.
    let (handler, target) = handler_with_fake();
    handler.warm_revision(&env, rev, None).await.unwrap();
    assert_eq!(staged_payload(&target, &env), full);
    assert!(target.seed_artifacts().is_empty());

    // auto: a pointer whose sha256 is the document's.
    let (handler, target) = handler_with_fake();
    handler
        .warm_revision(&env, rev, Some(&json!({ "seed_mode": "auto" })))
        .await
        .unwrap();
    let payload = staged_payload(&target, &env);
    let pointer: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(pointer[POINTER_KEY], 1);
    assert_eq!(pointer["size"], full.len());
    assert_eq!(
        pointer["sha256"],
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&full))
    );
    let pushed = target.seed_artifacts();
    assert_eq!(pushed.len(), 1);
    let (_reference, (digest, bytes)) = pushed.iter().next().unwrap();
    assert_eq!(bytes, &full);
    assert!(
        pointer["uri"]
            .as_str()
            .unwrap()
            .ends_with(&format!("@{digest}"))
    );
}
