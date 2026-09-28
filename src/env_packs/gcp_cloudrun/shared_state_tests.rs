use serde_json::{Value, json};

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::gcp_cloudrun::deployer::{GcpCloudRunParams, GcpCloudRunParamsError};

const URL: &str = "redis://:s3cret-auth@10.0.0.3:6379";

fn params(answers: Value) -> Result<GcpCloudRunParams, GcpCloudRunParamsError> {
    GcpCloudRunParams::from_answers(&build_fixture_env(), Some(&answers))
}

fn shared_err(answers: Value) -> SharedStateAnswerError {
    match params(answers) {
        Err(GcpCloudRunParamsError::SharedState(e)) => e,
        other => panic!("expected a shared-state answer error, got {other:?}"),
    }
}

#[test]
fn no_answers_leave_the_shared_state_empty() {
    let p = params(json!({})).expect("parse");
    assert_eq!(p.shared_state, SharedState::default());
    assert!(p.shared_state.boot_env().is_empty());
    assert!(p.shared_state.secret_env_names().is_empty());
    assert!(!multi_instance_safe(&p));
}

#[test]
fn blank_answers_read_as_absent() {
    let p =
        params(json!({"redis_url": " ", "vpc_connector": "", "vpc_egress": ""})).expect("parse");
    assert_eq!(p.shared_state, SharedState::default());
}

#[test]
fn a_connector_and_redis_select_the_redis_backends() {
    let p = params(json!({"redis_url": URL, "vpc_connector": "gtc-conn"})).expect("parse");
    assert_eq!(
        p.shared_state.vpc,
        Some(VpcAccess {
            target: VpcTarget::Connector(format!(
                "projects/{}/locations/{}/connectors/gtc-conn",
                p.project, p.region
            )),
            egress: VpcEgress::PrivateRangesOnly,
        })
    );
    assert_eq!(
        p.shared_state.boot_env(),
        vec![
            (SESSION_BACKEND_ENV.to_string(), "redis".to_string()),
            (STATE_BACKEND_ENV.to_string(), "redis".to_string()),
        ]
    );
    assert_eq!(p.shared_state.secret_env_names(), &REDIS_URL_ENV_NAMES);
    assert!(multi_instance_safe(&p));
}

#[test]
fn direct_vpc_egress_takes_network_and_subnet() {
    let p = params(json!({
        "vpc_network": "default",
        "vpc_subnet": "gtc-sub",
        "vpc_egress": "all-traffic",
    }))
    .expect("parse");
    assert_eq!(
        p.shared_state.vpc,
        Some(VpcAccess {
            target: VpcTarget::Direct {
                network: "default".to_string(),
                subnetwork: "gtc-sub".to_string(),
            },
            egress: VpcEgress::AllTraffic,
        })
    );
    // VPC alone is not multi-instance safe: no shared store.
    assert!(!multi_instance_safe(&p));
}

#[test]
fn rediss_is_refused_naming_the_follow_up() {
    let err = shared_err(json!({"redis_url": "rediss://:a@10.0.0.3:6378", "vpc_connector": "c"}));
    assert_eq!(err, SharedStateAnswerError::RedisTlsUnsupported);
    assert!(err.to_string().contains("follow-up F"), "{err}");
}

#[test]
fn an_invalid_redis_url_never_echoes_its_auth_string() {
    for bad in [
        "http://:s3cret-auth@h:1",
        "not a url s3cret-auth",
        "redis://:s3cret-auth@",
    ] {
        let err = shared_err(json!({"redis_url": bad, "vpc_connector": "c"}));
        assert!(
            matches!(err, SharedStateAnswerError::RedisUrlInvalid(_)),
            "{bad}: {err:?}"
        );
        assert!(!err.to_string().contains("s3cret-auth"), "{err}");
    }
}

#[test]
fn redis_without_a_vpc_route_is_refused() {
    assert_eq!(
        shared_err(json!({"redis_url": URL})),
        SharedStateAnswerError::RedisWithoutVpc
    );
}

#[test]
fn vpc_answer_combinations_are_validated() {
    assert_eq!(
        shared_err(json!({"vpc_connector": "c", "vpc_network": "n", "vpc_subnet": "s"})),
        SharedStateAnswerError::VpcConnectorAndDirect
    );
    assert_eq!(
        shared_err(json!({"vpc_network": "n"})),
        SharedStateAnswerError::VpcDirectIncomplete(VPC_SUBNET_KEY)
    );
    assert_eq!(
        shared_err(json!({"vpc_subnet": "s"})),
        SharedStateAnswerError::VpcDirectIncomplete(VPC_NETWORK_KEY)
    );
    assert_eq!(
        shared_err(json!({"vpc_egress": "all-traffic"})),
        SharedStateAnswerError::VpcEgressWithoutVpc
    );
    assert_eq!(
        shared_err(json!({"vpc_connector": "c", "vpc_egress": "everything"})),
        SharedStateAnswerError::VpcEgressInvalid("everything".to_string())
    );
    assert_eq!(
        shared_err(json!({"vpc_connector": 7})),
        SharedStateAnswerError::NotAString(VPC_CONNECTOR_KEY.to_string())
    );
}

#[test]
fn debug_redacts_the_redis_url() {
    let p = params(json!({"redis_url": URL, "vpc_connector": "c"})).expect("parse");
    let dbg = format!("{p:?}");
    assert!(!dbg.contains("s3cret-auth"), "{dbg}");
    assert!(dbg.contains("RedisUrl(<redacted>)"), "{dbg}");
}

#[test]
fn a_single_instance_always_passes_the_gate() {
    let p = params(json!({})).expect("parse");
    assert_eq!(gate(&p, &GeneratedSecretSeed::Unverified), Ok(()));
}

#[test]
fn multi_instance_without_redis_and_vpc_is_refused_naming_both() {
    let p = params(json!({"max_instances": "3"})).expect("parse");
    let err = gate(&p, &GeneratedSecretSeed::Complete).expect_err("refused");
    let msg = err.to_string();
    assert!(matches!(
        err,
        MultiInstanceRefusal::SharedStoreMissing { .. }
    ));
    assert!(
        msg.contains("`redis_url`") && msg.contains("`vpc_connector`"),
        "{msg}"
    );
}

#[test]
fn multi_instance_with_the_store_still_needs_the_generated_secrets() {
    let p = params(json!({"max_instances": "2", "redis_url": URL, "vpc_connector": "c"}))
        .expect("parse");
    assert_eq!(gate(&p, &GeneratedSecretSeed::Complete), Ok(()));
    assert!(matches!(
        gate(&p, &GeneratedSecretSeed::Unverified),
        Err(MultiInstanceRefusal::GeneratedSecretsUnverified { .. })
    ));
    assert!(matches!(
        gate(
            &p,
            &GeneratedSecretSeed::Unestablished("no lock".to_string())
        ),
        Err(MultiInstanceRefusal::GeneratedSecretsUnverified { .. })
    ));
    let err = gate(
        &p,
        &GeneratedSecretSeed::Missing(vec!["secrets://e/t/_/p/jwt_signing_key".to_string()]),
    )
    .expect_err("refused");
    assert!(err.to_string().contains("jwt_signing_key"), "{err}");
}

#[test]
fn the_gate_never_prints_the_redis_url() {
    let p = params(json!({"max_instances": "2", "redis_url": URL, "vpc_connector": "c"}))
        .expect("parse");
    let err = gate(&p, &GeneratedSecretSeed::Unverified).expect_err("refused");
    assert!(!err.to_string().contains("s3cret-auth"));
}

#[test]
fn a_bare_connector_expands_and_hashes_like_its_full_path() {
    let bare = params(json!({"vpc_connector": "gtc-conn"})).expect("parse");
    let full = params(json!({"vpc_connector": format!(
        "projects/{}/locations/{}/connectors/gtc-conn",
        bare.project, bare.region
    )}))
    .expect("parse");
    assert_eq!(bare.shared_state, full.shared_state);
    // A full path in another (Shared-VPC host) project is kept verbatim.
    let host =
        params(json!({"vpc_connector": "projects/host/locations/r/connectors/c"})).expect("parse");
    assert_eq!(
        host.shared_state.vpc.map(|v| v.target),
        Some(VpcTarget::Connector(
            "projects/host/locations/r/connectors/c".to_string()
        ))
    );
    for bad in [
        "a/b",
        "projects/p/locations/r/connectors/",
        "x/p/locations/r/connectors/c",
    ] {
        assert_eq!(
            shared_err(json!({"vpc_connector": bad})),
            SharedStateAnswerError::VpcConnectorInvalid(bad.to_string()),
        );
    }
}

/// The gate judges the EFFECTIVE ceiling: `max_instances = 0` is Cloud Run's
/// default (up to 100), and `min_instances > 1` keeps several warm.
#[test]
fn zero_max_and_min_above_one_are_multi_instance() {
    for answers in [
        json!({"max_instances": "0"}),
        json!({"max_instances": 0}),
        json!({"min_instances": "3"}),
        json!({"max_instances": "1", "min_instances": "2"}),
    ] {
        let p = params(answers.clone()).expect("parse");
        assert!(runs_multiple_instances(&p), "{answers}");
        let err = gate(&p, &GeneratedSecretSeed::Complete).expect_err("refused");
        assert!(
            matches!(err, MultiInstanceRefusal::SharedStoreMissing { .. }),
            "{answers}"
        );
    }
    let zero = gate(
        &params(json!({"max_instances": "0"})).expect("parse"),
        &GeneratedSecretSeed::Complete,
    )
    .expect_err("refused")
    .to_string();
    assert!(zero.contains("default ceiling"), "{zero}");
}

/// Absent answers keep today's default of exactly one instance, so the gate is
/// a no-op; `min_instances = 1` with `max_instances = 1` is still single.
#[test]
fn the_default_and_one_warm_instance_stay_single() {
    for answers in [
        json!({}),
        json!({"max_instances": "1"}),
        json!({"max_instances": "1", "min_instances": "1"}),
    ] {
        let p = params(answers.clone()).expect("parse");
        assert!(!runs_multiple_instances(&p), "{answers}");
        assert_eq!(
            gate(&p, &GeneratedSecretSeed::Unverified),
            Ok(()),
            "{answers}"
        );
    }
    assert_eq!(
        GcpCloudRunParams::for_env(&build_fixture_env()).max_instances,
        1
    );
}
