use std::time::Duration;

use ulid::Ulid;

use super::*;
use crate::env_packs::azure_aca::arm_body::OWNER_TAG;
use crate::env_packs::azure_aca::arm_http::fake::FakeHttp;
use crate::env_packs::azure_aca::arm_types::*;
use crate::env_packs::azure_aca::naming::{app_name, revision_suffix};
use crate::env_packs::azure_aca::rbac::{REAL_ACA_TARGET_RBAC_ACTIONS, REQUIRED_ACTIONS};
use greentic_deploy_spec::{DeploymentId, RevisionId};

fn target(http: Arc<FakeHttp>) -> RealAcaTarget {
    let scope = AzureScope {
        subscription: "sub".into(),
        resource_group: "rg".into(),
        environment: "env".into(),
    };
    RealAcaTarget::new(http, scope).with_policy(Policy {
        attempts: 3,
        default_delay: Duration::ZERO,
        poll_attempts: 3,
        poll_interval: Duration::ZERO,
    })
}

fn spec() -> AppSpec {
    AppSpec {
        name: app_name(&DeploymentId(Ulid::from(1_u128))),
        location: "southeastasia".into(),
        environment_id: "env-id".into(),
        tags: vec![(OWNER_TAG.into(), "me".into())],
        target_port: 8080,
        secrets: vec![AppSecret::new("seed-a", "TOPSECRETVALUE")],
        traffic: vec![],
        revision: RevisionSpec {
            suffix: revision_suffix(&RevisionId(Ulid::from(2_u128))),
            image: "img".into(),
            cpu: 0.5,
            memory: "1Gi".into(),
            env: vec![],
            init: None,
            min_replicas: 0,
            max_replicas: 1,
        },
    }
}

#[tokio::test]
async fn put_app_sends_the_body_to_the_app_url_and_polls_the_operation() {
    let http = Arc::new(FakeHttp::with(vec![
        ArmResponse::new(201, "{}").with_header("Azure-AsyncOperation", "https://op/1"),
        ArmResponse::new(200, r#"{"status":"Succeeded"}"#),
    ]));
    let rev = target(http.clone()).put_revision(&spec()).await.unwrap();
    let seen = http.seen();
    assert_eq!(seen[0].method, Method::Put);
    assert!(
        seen[0].url.contains("/containerApps/gtc-")
            && seen[0].url.contains("api-version=2024-03-01")
    );
    let body: Value = serde_json::from_slice(seen[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(
        body["properties"]["configuration"]["activeRevisionsMode"],
        "Multiple"
    );
    assert_eq!(seen[1].url, "https://op/1");
    assert!(rev.name.contains("--r"));
}

#[tokio::test]
async fn a_persistent_throttle_surfaces_as_an_api_error() {
    let http = Arc::new(FakeHttp::with(vec![
        ArmResponse::new(
            429,
            r#"{"error":{"code":"TooManyRequests","message":"slow"}}"#
        );
        3
    ]));
    let e = target(http).put_revision(&spec()).await.unwrap_err();
    assert!(
        e.to_string().contains("429") && e.to_string().contains("TooManyRequests"),
        "{e}"
    );
}

#[tokio::test]
async fn delete_of_404_is_ok_false_and_a_delete_polls_to_ok_true() {
    let app = AppRef {
        name: "gtc-x".into(),
    };
    let http = Arc::new(FakeHttp::with(vec![ArmResponse::new(404, "{}")]));
    assert!(!target(http).delete_app(&app).await.unwrap());
    let http = Arc::new(FakeHttp::with(vec![ArmResponse::new(200, "{}")]));
    assert!(target(http).delete_app(&app).await.unwrap());
}

#[tokio::test]
async fn list_secrets_reads_values_but_never_prints_them() {
    let http = Arc::new(FakeHttp::with(vec![ArmResponse::new(
        200,
        r#"{"value":[{"name":"a","value":"TOPSECRETVALUE"}]}"#,
    )]));
    let secrets = target(http.clone())
        .list_secrets(&AppRef { name: "x".into() })
        .await
        .unwrap();
    assert_eq!(secrets[0].name, "a");
    assert!(!format!("{secrets:?}").contains("TOPSECRETVALUE"));
    assert!(!format!("{:?}", http.seen()).contains("TOPSECRETVALUE"));
    assert_eq!(http.seen()[0].method, Method::Post);
}

#[tokio::test]
async fn the_put_request_debug_hides_the_secret_body() {
    let http = Arc::new(FakeHttp::with(vec![ArmResponse::new(200, "{}")]));
    target(http.clone()).put_revision(&spec()).await.unwrap();
    assert!(!format!("{:?}", http.seen()).contains("TOPSECRETVALUE"));
}

#[tokio::test]
async fn inspect_status_and_deactivate_map_404_and_json() {
    let app = AppRef {
        name: "gtc-x".into(),
    };
    let rev = RevisionRef {
        app: app.clone(),
        name: "gtc-x--r1".into(),
    };
    let http = Arc::new(FakeHttp::with(vec![
        ArmResponse::new(404, "{}"),
        ArmResponse::new(
            200,
            r#"{"properties":{"provisioningState":"Provisioned","runningState":"Running","replicas":1}}"#,
        ),
        ArmResponse::new(404, "{}"),
        ArmResponse::new(404, "{}"),
    ]));
    let t = target(http);
    assert_eq!(t.inspect_app(&app).await.unwrap(), AppState::Absent);
    assert_eq!(
        t.revision_status(&rev).await.unwrap(),
        RevisionStatus::Running { replicas: 1 }
    );
    assert_eq!(
        t.revision_status(&rev).await.unwrap(),
        RevisionStatus::Absent
    );
    t.deactivate_revision(&rev).await.unwrap();
}

#[tokio::test]
async fn set_traffic_refuses_weights_not_summing_to_100_before_any_call() {
    let http = Arc::new(FakeHttp::default());
    let e = target(http.clone())
        .set_traffic(
            &AppRef { name: "x".into() },
            &[TrafficEntry {
                revision_name: "r".into(),
                weight: 60,
            }],
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("sum"), "{e}");
    assert!(http.seen().is_empty());
}

#[test]
fn real_target_rbac_actions_are_in_the_validator_set() {
    for a in REAL_ACA_TARGET_RBAC_ACTIONS {
        assert!(REQUIRED_ACTIONS.contains(a), "{a}");
    }
}
