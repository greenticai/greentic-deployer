use serde_json::{Value, json};

use super::*;

const SUB: &str = "11111111-2222-3333-4444-555555555555";

fn base() -> Value {
    json!({
        "subscription_id": SUB,
        "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "resource_group": "gtc-rg",
        "environment_name": "gtc-env",
    })
}

fn with(key: &str, v: Value) -> Value {
    let mut b = base();
    b[key] = v;
    b
}

#[test]
fn accepts_the_documented_keys() {
    let mut a = base();
    for (k, v) in [
        ("location", json!("westeurope")),
        ("acr_login_server", json!("MyAcr.azurecr.io")),
        ("log_analytics_workspace_id", json!("ws-guid")),
        ("min_instances", json!("1")),
        ("max_instances", json!(1)),
        ("cpu", json!("0.5")),
        ("memory", json!("1Gi")),
        ("runtime_image_tag", json!("v1")),
        ("runtime_tenant", json!("acme")),
        ("runtime_team", json!("ops")),
        ("oci_username", json!("tok")),
        ("oci_password", json!("pw")),
    ] {
        a[k] = v;
    }
    let p = AcaParams::from_answers(Some(&a)).unwrap();
    assert_eq!(p.location, "westeurope");
    assert_eq!(p.acr_login_server.as_deref(), Some("myacr.azurecr.io"));
    assert_eq!(p.min_instances, 1);
    assert!(p.registry.is_some());
    assert!(
        p.managed_environment_id()
            .ends_with("/managedEnvironments/gtc-env")
    );
}

#[test]
fn defaults_are_scale_to_zero_single_instance_southeastasia() {
    let p = AcaParams::from_answers(Some(&base())).unwrap();
    assert_eq!((p.min_instances, p.max_instances), (0, 1));
    assert_eq!(p.location, "southeastasia");
    assert_eq!(
        p.runtime_image_for(None),
        format!("{RUNTIME_IMAGE_REPO}:develop")
    );
}

#[test]
fn max_and_min_instances_are_bounded() {
    assert!(AcaParams::from_answers(Some(&with("max_instances", json!(2)))).is_err());
    assert!(AcaParams::from_answers(Some(&with("min_instances", json!(2)))).is_err());
}

#[test]
fn unknown_and_cross_cloud_keys_are_unknown_key() {
    for k in [
        "access_mode",
        "secret_prefix",
        "cluster",
        "alb_listener_arn",
        "region",
        "project",
    ] {
        let e = AcaParams::from_answers(Some(&with(k, json!("x")))).unwrap_err();
        assert!(
            matches!(e, AcaParamsError::UnknownKey(ref n) if n == k),
            "{k}: {e}"
        );
    }
}

#[test]
fn scope_answers_are_required_and_validated() {
    assert!(matches!(
        AcaParams::from_answers(None),
        Err(AcaParamsError::Missing(_))
    ));
    for k in [
        "subscription_id",
        "tenant_id",
        "resource_group",
        "environment_name",
    ] {
        let mut a = base();
        a.as_object_mut().unwrap().remove(k);
        assert!(
            matches!(
                AcaParams::from_answers(Some(&a)),
                Err(AcaParamsError::Missing(_))
            ),
            "{k}"
        );
    }
    assert!(AcaParams::from_answers(Some(&with("subscription_id", json!("not-a-guid")))).is_err());
    assert!(AcaParams::from_answers(Some(&with("resource_group", json!("a b")))).is_err());
}

#[test]
fn bad_digest_telemetry_and_lone_registry_half_are_errors() {
    assert!(
        AcaParams::from_answers(Some(&with("runtime_image_digest", json!("sha256:abc")))).is_err()
    );
    let d = format!("sha256:{}", "a".repeat(64));
    let p = AcaParams::from_answers(Some(&with("runtime_image_digest", json!(d)))).unwrap();
    assert!(p.runtime_image_for(None).contains('@'));
    assert!(
        p.runtime_image_for(Some("sha256:pin"))
            .ends_with("@sha256:pin")
    );
    let bad_tel = with("telemetry_env", json!({"NOT_ALLOWED": "x"}));
    assert!(matches!(
        AcaParams::from_answers(Some(&bad_tel)),
        Err(AcaParamsError::Telemetry(_))
    ));
    assert!(AcaParams::from_answers(Some(&with("oci_username", json!("u")))).is_err());
}

#[test]
fn debug_never_prints_secrets() {
    let mut a = with("oci_username", json!("tok"));
    a["oci_password"] = json!("hunter2-secret");
    a["telemetry_headers"] = json!("Authorization=Bearer topsecret");
    let p = AcaParams::from_answers(Some(&a)).unwrap();
    let shown = format!("{p:?}");
    assert!(
        !shown.contains("hunter2-secret") && !shown.contains("topsecret"),
        "{shown}"
    );
}
