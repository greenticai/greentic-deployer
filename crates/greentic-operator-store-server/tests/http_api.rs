//! A8 environment-lifecycle route tests (PR-4.2a): create / update /
//! migrate-bindings mutations plus the two reads, exercised over the real
//! SQLite backend through tower `oneshot`.
//!
//! What these pin down:
//! - the mutation envelope shape the PR-4.0 client validates
//!   (`{result, etag, generation, idempotency, audit}`, audit binds env +
//!   idempotency key, allow + ok);
//! - status↔body consistency for the A8 error vocabulary (the client
//!   rejects a mismatch as a contract violation);
//! - tri-state PATCH semantics (set / clear / keep) through the shared
//!   `greentic_deploy_spec::engine` transform.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use greentic_operator_store_server::http::router;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::util::ServiceExt;

mod common;
use common::fresh_store;

const IDEM_KEY: &str = "01JTKW5B4W4Q5Y1CQW93F7S5VH";

/// Dispatch one JSON request and return `(status, parsed body)`.
async fn send(app: Router, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Accept", "application/json")
        .header("Idempotency-Key", IDEM_KEY);
    let body = match body {
        Some(value) => {
            builder = builder.header("Content-Type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("dispatch request");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes).expect("json body");
    (status, value)
}

fn create_body(env_id: &str) -> Value {
    json!({
        "env_id": env_id,
        "name": env_id,
        "host_config": { "env_id": env_id },
    })
}

/// Assert the A8 mutation envelope + audit binding the client enforces.
fn assert_envelope(body: &Value, env_id: &str) {
    assert!(body["etag"].is_string(), "etag missing: {body}");
    assert!(body["generation"].is_u64(), "generation missing: {body}");
    assert_eq!(body["idempotency"]["idempotency"], "applied");
    let audit = &body["audit"];
    assert_eq!(audit["env_id"], env_id);
    assert_eq!(audit["idempotency_key"], IDEM_KEY);
    assert_eq!(audit["authorization"]["decision"], "allow");
    assert_eq!(audit["result"]["outcome"], "ok");
}

async fn app() -> (tempfile::TempDir, Router) {
    let (dir, store) = fresh_store().await;
    (dir, router(Arc::new(store)))
}

#[tokio::test]
async fn create_returns_envelope_and_persists() {
    let (_d, app) = app().await;
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["generation"], 1);
    assert_eq!(body["result"]["environment_id"], "local");
    assert_eq!(body["audit"]["verb"], "create");
    assert!(
        body["audit"]["previous_generation"].is_null(),
        "create has no prior generation"
    );

    // Read it back with CAS coordinates.
    let (status, body) = send(app.clone(), Method::GET, "/environments/local", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["environment"]["environment_id"], "local");
    assert_eq!(body["generation"], 1);
    assert!(body["etag"].is_string());

    let (status, body) = send(app, Method::GET, "/environments", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["environments"], json!(["local"]));
}

#[tokio::test]
async fn create_duplicate_is_409_already_exists_with_consistent_body() {
    let (_d, app) = app().await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        app,
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    // Status and A8 body kind must agree — the client cross-checks them.
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["kind"], "already-exists");
}

#[tokio::test]
async fn update_applies_tristate_patch_and_bumps_generation() {
    let (_d, app) = app().await;
    let mut create = create_body("local");
    create["host_config"]["region"] = json!("us-east-1");
    create["host_config"]["tenant_org_id"] = json!("org-1");
    let (status, _) = send(app.clone(), Method::POST, "/environments", Some(create)).await;
    assert_eq!(status, StatusCode::OK);

    // Set name, clear region, keep tenant_org_id (absent field).
    let (status, body) = send(
        app.clone(),
        Method::PATCH,
        "/environments/local",
        Some(json!({
            "name": "renamed",
            "region": {"clear": true},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["generation"], 2);
    assert_eq!(body["audit"]["previous_generation"], 1);
    assert_eq!(body["result"]["name"], "renamed");
    assert!(body["result"]["host_config"]["region"].is_null());
    assert_eq!(body["result"]["host_config"]["tenant_org_id"], "org-1");

    // The patch persisted, not just echoed.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["name"], "renamed");
    assert_eq!(read["generation"], 2);
}

#[tokio::test]
async fn update_of_missing_env_is_404_not_found() {
    let (_d, app) = app().await;
    let (status, body) = send(
        app,
        Method::PATCH,
        "/environments/ghost",
        Some(json!({"name": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["kind"], "not-found");
}

#[tokio::test]
async fn get_missing_env_is_404_and_malformed_body_is_400() {
    let (_d, app) = app().await;
    let (status, body) = send(app.clone(), Method::GET, "/environments/ghost", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["kind"], "not-found");

    // Malformed JSON body → typed A8 invalid-request, not a plaintext 4xx.
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/environments")
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", IDEM_KEY)
                .body(Body::from("{not json"))
                .expect("build request"),
        )
        .await
        .expect("dispatch request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("json body");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn migrate_bindings_merges_into_existing_env() {
    let (_d, app) = app().await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let binding = json!({
        "slot": "secrets",
        "kind": "greentic.secrets@1.0.0",
        "pack_ref": "greentic.secrets",
    });
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/migrate-bindings",
        Some(json!({"packs": [binding], "extensions": []})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["result"]["merged_slots"], json!(["secrets"]));
    assert_eq!(body["result"]["merged_extensions"], json!([]));
    assert_eq!(body["audit"]["verb"], "migrate-bindings");

    // Same merge again: the slot is already bound, so nothing merges —
    // but the verb still bumps the generation (a save happened).
    let binding = json!({
        "slot": "secrets",
        "kind": "greentic.secrets@1.0.0",
        "pack_ref": "greentic.secrets",
    });
    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/migrate-bindings",
        Some(json!({"packs": [binding], "extensions": []})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["merged_slots"], json!([]));
}

#[tokio::test]
async fn migrate_bindings_seeds_missing_target_and_rejects_without_seed() {
    let (_d, app) = app().await;

    // No seed + missing target → 404 (caller asserted presence).
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/fresh/migrate-bindings",
        Some(json!({"packs": [], "extensions": []})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "not-found");

    // With a seed the target is created atomically, then merged into.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/fresh/migrate-bindings",
        Some(json!({
            "packs": [{
                "slot": "secrets",
                "kind": "greentic.secrets@1.0.0",
                "pack_ref": "greentic.secrets",
            }],
            "extensions": [],
            "seed_if_missing": {
                "host_config": {"env_id": "fresh"},
                "revocation": {},
                "retention": {},
                "health": {},
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "fresh");
    assert_eq!(body["result"]["merged_slots"], json!(["secrets"]));

    let (status, read) = send(app, Method::GET, "/environments/fresh", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["environment"]["name"], "fresh");
    assert_eq!(read["environment"]["packs"][0]["slot"], "secrets");
}
