use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::super::{K8sParams, ROUTER_NAME, render_environment_manifests};
use super::{INGRESS_TLS_SECRET_NAME, IngressTls, public_base_url_from_answers};
use crate::env_packs::deployer::conformance::build_fixture_env;

fn sha256_hex(v: &[Value]) -> String {
    let bytes = serde_json::to_vec(v).expect("manifests serialize");
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn render(answers: Value) -> Vec<Value> {
    let env = build_fixture_env();
    let params = K8sParams::from_answers(&env, Some(&answers)).expect("valid answers");
    render_environment_manifests(&env, &params)
}

fn ingress_of(objects: &[Value]) -> Option<&Value> {
    objects.iter().find(|o| o["kind"] == "Ingress")
}

fn refusal(answers: Value) -> String {
    let env = build_fixture_env();
    K8sParams::from_answers(&env, Some(&answers)).expect_err("answers must be refused")
}

/// Golden: SHA-256 of the env-level set rendered for the conformance fixture,
/// measured on an unmodified `develop` @ f13cf8d (a scratch test run on that
/// tree before any Ingress code existed), not on this branch. An env
/// that answers none of them must render exactly those bytes.
///
/// Re-measured once, deliberately, when the router Service gained
/// `sessionAffinity: ClientIP` (the router keeps conversation state per
/// replica): that is the ONLY difference between the old and new bytes, and it
/// applies to every environment regardless of its Ingress answers.
#[test]
fn unanswered_ingress_keeps_the_rendered_set_byte_identical() {
    const DEFAULT_GOLDEN: &str = "f8c61a1cf342d759d3d070987fbdc2e3a47b98a58a3bebf4da9f899fe283a239";
    const CUSTOM_GOLDEN: &str = "c5fee323cd83fd7a3c5ed2f51d30f07b31220db78930a87ae9b769fc3dcdf3ea";
    let env = build_fixture_env();
    let defaults = render_environment_manifests(&env, &K8sParams::for_env(&env));
    assert_eq!(sha256_hex(&defaults), DEFAULT_GOLDEN);
    assert_eq!(sha256_hex(&render(json!({}))), DEFAULT_GOLDEN);
    // Blank answers are "left blank in the wizard", not a request.
    let blank = render(json!({
        "ingress_host": "", "ingress_class": null,
        "ingress_tls_secret": "", "ingress_cert_manager_issuer": null,
    }));
    assert_eq!(sha256_hex(&blank), DEFAULT_GOLDEN);
    let custom = render(json!({"service_type": "LoadBalancer", "namespace": "custom-ns"}));
    assert_eq!(sha256_hex(&custom), CUSTOM_GOLDEN);
    assert!(ingress_of(&defaults).is_none());
}

#[test]
fn host_alone_renders_a_plain_http_ingress_to_the_router() {
    let objects = render(json!({"ingress_host": "Chat.Example.com"}));
    let ingress = ingress_of(&objects).expect("an Ingress is rendered");
    assert_eq!(objects.last(), Some(ingress), "appended last");
    assert_eq!(ingress["apiVersion"], "networking.k8s.io/v1");
    assert_eq!(ingress["metadata"]["name"], ROUTER_NAME);
    assert!(ingress["metadata"].get("annotations").is_none());
    assert!(ingress["spec"].get("tls").is_none());
    assert!(ingress["spec"].get("ingressClassName").is_none());
    let rule = &ingress["spec"]["rules"][0];
    assert_eq!(rule["host"], "chat.example.com", "host is lowercased");
    let backend = &rule["http"]["paths"][0]["backend"]["service"];
    assert_eq!(backend["name"], ROUTER_NAME);
    assert_eq!(backend["port"]["number"], 8080);
    assert_eq!(rule["http"]["paths"][0]["pathType"], "Prefix");
}

#[test]
fn a_tls_secret_answer_terminates_tls_with_that_secret() {
    let objects = render(json!({
        "ingress_host": "chat.example.com",
        "ingress_class": "nginx",
        "ingress_tls_secret": "chat-example-tls",
    }));
    let ingress = ingress_of(&objects).expect("an Ingress is rendered");
    assert_eq!(ingress["spec"]["ingressClassName"], "nginx");
    assert_eq!(
        ingress["spec"]["tls"],
        json!([{"hosts": ["chat.example.com"], "secretName": "chat-example-tls"}])
    );
    assert!(ingress["metadata"].get("annotations").is_none());
}

#[test]
fn a_cert_manager_issuer_annotates_and_names_the_reserved_secret() {
    let objects = render(json!({
        "ingress_host": "chat.example.com",
        "ingress_cert_manager_issuer": "letsencrypt-prod",
    }));
    let ingress = ingress_of(&objects).expect("an Ingress is rendered");
    assert_eq!(
        ingress["metadata"]["annotations"]["cert-manager.io/cluster-issuer"],
        "letsencrypt-prod"
    );
    assert_eq!(
        ingress["spec"]["tls"][0]["secretName"],
        INGRESS_TLS_SECRET_NAME
    );
    assert_eq!(ingress["spec"]["tls"][0]["hosts"][0], "chat.example.com");
}

#[test]
fn public_base_url_follows_the_tls_mode() {
    let env = build_fixture_env();
    let url = |answers: Value| public_base_url_from_answers(&env, Some(&answers));
    assert_eq!(url(json!({})), None);
    assert_eq!(public_base_url_from_answers(&env, None), None);
    assert_eq!(
        url(json!({"ingress_host": "a.example.com"})).as_deref(),
        Some("http://a.example.com")
    );
    assert_eq!(
        url(json!({"ingress_host": "a.example.com", "ingress_tls_secret": "t"})).as_deref(),
        Some("https://a.example.com")
    );
    assert_eq!(
        url(json!({"ingress_host": "a.example.com", "ingress_cert_manager_issuer": "le"}))
            .as_deref(),
        Some("https://a.example.com")
    );
}

#[test]
fn tls_mode_is_parsed_into_the_params() {
    let env = build_fixture_env();
    let params = K8sParams::from_answers(
        &env,
        Some(&json!({"ingress_host": "a.example.com", "ingress_tls_secret": "t"})),
    )
    .expect("valid");
    let ingress = params.ingress.expect("ingress parsed");
    assert_eq!(ingress.tls, IngressTls::Secret("t".into()));
    assert_eq!(ingress.class, None);
}

#[test]
fn a_class_or_tls_answer_without_a_host_is_refused() {
    for answers in [
        json!({"ingress_class": "nginx"}),
        json!({"ingress_tls_secret": "t"}),
        json!({"ingress_cert_manager_issuer": "le"}),
    ] {
        let err = refusal(answers.clone());
        assert!(err.contains("ingress_host is required"), "{answers}: {err}");
    }
}

#[test]
fn non_string_answers_are_refused_not_coerced() {
    for (key, value) in [
        ("ingress_class", json!(true)),
        ("ingress_host", json!(42)),
        ("ingress_tls_secret", json!(["t"])),
        ("ingress_cert_manager_issuer", json!({"name": "le"})),
    ] {
        let mut answers = json!({"ingress_host": "a.example.com"});
        answers[key] = value;
        let err = refusal(answers);
        assert!(
            err.contains(key) && err.contains("must be a string"),
            "{key}: {err}"
        );
    }
}

#[test]
fn both_tls_modes_at_once_are_refused() {
    let err = refusal(json!({
        "ingress_host": "a.example.com",
        "ingress_tls_secret": "t",
        "ingress_cert_manager_issuer": "le",
    }));
    assert!(err.contains("mutually exclusive"), "{err}");
}

#[test]
fn an_invalid_host_is_refused() {
    for host in [
        "localhost",
        "*.example.com",
        "10.0.0.1",
        "under_score.example.com",
        "-lead.example.com",
        "a..example.com",
        "https://a.example.com",
        "a.example.com/path",
    ] {
        let err = refusal(json!({"ingress_host": host}));
        assert!(err.contains("ingress_host"), "{host}: {err}");
    }
    let long_label = format!("{}.example.com", "a".repeat(64));
    assert!(refusal(json!({"ingress_host": long_label})).contains("ingress_host"));
}

#[test]
fn invalid_names_are_refused() {
    let host = "a.example.com";
    let err = refusal(json!({"ingress_host": host, "ingress_class": "Nginx_Class"}));
    assert!(err.contains("ingress_class"), "{err}");
    let err = refusal(json!({"ingress_host": host, "ingress_tls_secret": "Bad Secret"}));
    assert!(err.contains("ingress_tls_secret"), "{err}");
    let err = refusal(json!({"ingress_host": host, "ingress_cert_manager_issuer": "LE!"}));
    assert!(err.contains("ingress_cert_manager_issuer"), "{err}");
}

#[test]
fn a_tls_secret_colliding_with_a_pack_object_is_refused() {
    for name in ["gtc-oci-credentials", INGRESS_TLS_SECRET_NAME] {
        let err = refusal(json!({"ingress_host": "a.example.com", "ingress_tls_secret": name}));
        assert!(err.contains("collides"), "{name}: {err}");
    }
    let err = refusal(json!({
        "ingress_host": "a.example.com",
        "ingress_tls_secret": "shared",
        "image_pull_secret": "shared",
        "oci_username": "u",
        "oci_password": "p",
    }));
    assert!(err.contains("image_pull_secret"), "{err}");
}

#[test]
fn the_issuer_secret_name_cannot_be_taken_by_the_image_pull_secret() {
    let err = refusal(json!({
        "image_pull_secret": INGRESS_TLS_SECRET_NAME,
        "oci_username": "u",
        "oci_password": "p",
    }));
    assert!(err.contains("collides"), "{err}");
}
