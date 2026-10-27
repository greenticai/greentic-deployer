//! Wizard answers for scaling, the runtime pin, telemetry and tenant scope.

use serde_json::json;

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn parse(answers: serde_json::Value) -> Result<AwsEcsParams, AwsEcsParamsError> {
    AwsEcsParams::from_answers(&build_fixture_env(), Some(&answers))
}

#[test]
fn defaults_are_one_instance_develop_tag_and_env_prefix() {
    let env = build_fixture_env();
    let p = AwsEcsParams::for_env(&env);
    assert_eq!((p.min_instances, p.max_instances), (1, 1));
    assert_eq!(p.runtime_image_tag, "develop");
    assert_eq!(p.runtime_image_digest, None);
    assert_eq!(
        p.secret_prefix,
        format!("gtc-{}", env.environment_id.as_str())
    );
    assert!(p.runtime_tenant.is_none() && p.runtime_team.is_none());
    assert!(p.telemetry.is_empty());
}

#[test]
fn from_answers_accepts_scaling_runtime_and_telemetry_keys() {
    let p = parse(json!({
        "min_instances": "1",
        "max_instances": 1,
        "runtime_image_tag": "v2",
        "runtime_image_digest": DIGEST,
        "secret_prefix": "acme",
        "runtime_tenant": "t1",
        "runtime_team": " ",
        "telemetry_env": { "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example" },
        "telemetry_headers": "authorization=Bearer s3cret"
    }))
    .unwrap();
    assert_eq!((p.min_instances, p.max_instances), (1, 1));
    assert_eq!(p.runtime_image_tag, "v2");
    assert_eq!(p.runtime_image_digest.as_deref(), Some(DIGEST));
    assert_eq!(p.secret_prefix, "acme");
    assert_eq!(p.runtime_tenant.as_deref(), Some("t1"));
    assert_eq!(p.runtime_team, None);
    assert!(!p.telemetry.is_empty());
    assert!(p.telemetry.headers().is_some());
}

#[test]
fn max_instances_above_one_is_refused() {
    let err = parse(json!({ "max_instances": "2" })).unwrap_err();
    assert!(matches!(err, AwsEcsParamsError::Invalid { ref key, .. } if key == "max_instances"));
}

#[test]
fn min_instances_zero_is_refused() {
    let err = parse(json!({ "min_instances": "0" })).unwrap_err();
    assert!(matches!(err, AwsEcsParamsError::Invalid { ref key, .. } if key == "min_instances"));
}

#[test]
fn gcp_only_keys_are_still_unknown() {
    for key in ["access_mode", "vpc_egress"] {
        let err = parse(json!({ key: "x" })).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::UnknownKey(ref k) if k == key));
    }
}

#[test]
fn a_bad_telemetry_answer_is_a_params_error() {
    let err = parse(json!({ "telemetry_env": "not-an-object" })).unwrap_err();
    assert!(matches!(err, AwsEcsParamsError::Telemetry(_)));
}

#[test]
fn runtime_image_digest_must_be_sha256() {
    let err = parse(json!({ "runtime_image_digest": "sha256:abc" })).unwrap_err();
    assert!(
        matches!(err, AwsEcsParamsError::Invalid { ref key, .. } if key == "runtime_image_digest")
    );
}

#[test]
fn runtime_image_is_digest_pinned_or_tag_based() {
    let mut p = AwsEcsParams::for_env(&build_fixture_env());
    assert_eq!(
        p.runtime_image(),
        "ghcr.io/greenticai/greentic-start-distroless:develop"
    );
    p.runtime_image_digest = Some(DIGEST.to_string());
    assert_eq!(
        p.runtime_image(),
        format!("ghcr.io/greenticai/greentic-start-distroless@{DIGEST}")
    );
}

#[test]
fn blank_secret_prefix_defaults() {
    let env = build_fixture_env();
    for blank in ["", "   "] {
        let p = parse(json!({ "secret_prefix": blank })).unwrap();
        assert_eq!(
            p.secret_prefix,
            format!("gtc-{}", env.environment_id.as_str()),
            "blank `{blank}` falls back to the env default"
        );
    }
}

#[test]
fn log_retention_days_defaults_to_30_and_must_be_a_cloudwatch_value() {
    assert_eq!(
        AwsEcsParams::for_env(&build_fixture_env()).log_retention_days,
        30
    );
    assert_eq!(
        parse(json!({ "log_retention_days": "14" }))
            .unwrap()
            .log_retention_days,
        14
    );
    for bad in ["2", "0", "10000"] {
        let err = parse(json!({ "log_retention_days": bad })).unwrap_err();
        assert!(
            matches!(&err, AwsEcsParamsError::Invalid { key, .. } if key == "log_retention_days"),
            "`{bad}`: {err}"
        );
    }
}
