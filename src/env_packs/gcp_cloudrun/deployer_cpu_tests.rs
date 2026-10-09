//! `cpu_always_allocated`: parsing, and that the answer leaves every existing
//! deployment's revision intent untouched unless it is set.

use serde_json::json;

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;

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

/// The conformance fixture's first revision under default answers — the same
/// value `deployer_shared_state_tests` pins, computed before this answer
/// existed. An absent or `false` answer must keep it.
const GOLDEN_FIXTURE_INTENT: &str = "b9af277c076a1fb76883b40bf8ccf931";

#[test]
fn defaults_to_false_and_keeps_scaling_unchanged() {
    let env = build_fixture_env();
    let params = GcpCloudRunParams::from_answers(&env, Some(&json!({}))).expect("parse");
    assert!(!params.cpu_always_allocated);
    assert!(!params.scaling().cpu_always_allocated);
    assert!(!GcpCloudRunParams::for_env(&env).cpu_always_allocated);
}

#[test]
fn accepts_json_bools_and_flat_strings() {
    let env = build_fixture_env();
    for (value, expected) in [
        (json!(true), true),
        (json!(false), false),
        (json!("true"), true),
        (json!("false"), false),
        (json!(" true "), true),
    ] {
        let params =
            GcpCloudRunParams::from_answers(&env, Some(&json!({ "cpu_always_allocated": value })))
                .expect("parse");
        assert_eq!(params.cpu_always_allocated, expected, "{value}");
        assert_eq!(params.scaling().cpu_always_allocated, expected);
    }
}

#[test]
fn rejects_garbage_with_a_named_key() {
    let env = build_fixture_env();
    for value in [json!("yes"), json!("1"), json!(""), json!(1), json!(null)] {
        let err =
            GcpCloudRunParams::from_answers(&env, Some(&json!({ "cpu_always_allocated": value })))
                .expect_err("garbage must be refused");
        match err {
            GcpCloudRunParamsError::Invalid { key, detail } => {
                assert_eq!(key, "cpu_always_allocated");
                assert!(!detail.is_empty());
            }
            other => panic!("unexpected error for {value}: {other:?}"),
        }
    }
}

#[test]
fn absent_or_false_keeps_the_intent_byte_identical() {
    let env = build_fixture_env();
    let absent = GcpCloudRunParams::from_answers(&env, Some(&json!({}))).expect("parse");
    let off = GcpCloudRunParams::from_answers(&env, Some(&json!({"cpu_always_allocated": false})))
        .expect("parse");
    let off_str =
        GcpCloudRunParams::from_answers(&env, Some(&json!({"cpu_always_allocated": "false"})))
            .expect("parse");
    assert_eq!(intent_for(&env, &absent), GOLDEN_FIXTURE_INTENT);
    assert_eq!(intent_for(&env, &off), GOLDEN_FIXTURE_INTENT);
    assert_eq!(intent_for(&env, &off_str), GOLDEN_FIXTURE_INTENT);
}

#[test]
fn true_moves_the_intent_so_it_rolls_a_new_revision() {
    let env = build_fixture_env();
    let on = GcpCloudRunParams::from_answers(&env, Some(&json!({"cpu_always_allocated": true})))
        .expect("parse");
    let on_intent = intent_for(&env, &on);
    assert_ne!(on_intent, GOLDEN_FIXTURE_INTENT);
    // Stable: the same answer always yields the same intent.
    assert_eq!(on_intent, intent_for(&env, &on));
}
