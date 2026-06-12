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
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::util::ServiceExt;

mod common;
use common::fresh_store;

const IDEM_KEY: &str = "01JTKW5B4W4Q5Y1CQW93F7S5VH";

/// Dispatch one JSON request with the default `Idempotency-Key` and return
/// `(status, parsed body)`. Thin wrapper over [`send_custom`].
async fn send(app: Router, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    send_custom(app, method, path, body, &[("Idempotency-Key", IDEM_KEY)]).await
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

// ---------------------------------------------------------------------------
// send_custom — dispatch with explicit headers (no default Idempotency-Key)
// ---------------------------------------------------------------------------

/// Like `send` but accepts custom headers. Does NOT auto-inject Idempotency-Key.
async fn send_custom(
    app: Router,
    method: Method,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Accept", "application/json");
    for &(name, value) in headers {
        builder = builder.header(name, value);
    }
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

async fn app_with_store() -> (tempfile::TempDir, Router, Arc<SqliteEnvironmentStore>) {
    let (dir, store) = fresh_store().await;
    let store = Arc::new(store);
    let app = router(Arc::clone(&store));
    (dir, app, store)
}

// ---------------------------------------------------------------------------
// FIX 2 — missing Idempotency-Key → 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mutation_without_idempotency_key_is_400() {
    let (_d, app) = app().await;
    let (status, body) = send_custom(
        app,
        Method::POST,
        "/environments",
        Some(create_body("local")),
        &[], // no Idempotency-Key
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("Idempotency-Key"),
        "detail must mention the header: {body}"
    );
}

// ---------------------------------------------------------------------------
// FIX 3 — If-Match enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_with_stale_if_match_is_412() {
    let (_d, app) = app().await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // PATCH with a stale etag → 412
    let (status, body) = send_custom(
        app,
        Method::PATCH,
        "/environments/local",
        Some(json!({"name": "x"})),
        &[("Idempotency-Key", IDEM_KEY), ("If-Match", "\"deadbeef\"")],
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "body: {body}");
    assert_eq!(body["kind"], "precondition-failed");
}

#[tokio::test]
async fn patch_with_current_if_match_succeeds() {
    let (_d, app) = app().await;
    let (status, created) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Read the current etag and use it in If-Match
    let etag = created["etag"].as_str().unwrap();
    let if_match = format!("\"{etag}\"");
    let (status, body) = send_custom(
        app,
        Method::PATCH,
        "/environments/local",
        Some(json!({"name": "renamed"})),
        &[("Idempotency-Key", IDEM_KEY), ("If-Match", &if_match)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["result"]["name"], "renamed");
}

#[tokio::test]
async fn patch_with_weak_etag_is_400() {
    let (_d, app) = app().await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send_custom(
        app,
        Method::PATCH,
        "/environments/local",
        Some(json!({"name": "x"})),
        &[("Idempotency-Key", IDEM_KEY), ("If-Match", "W/\"abc\"")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn migrate_bindings_with_if_match_on_missing_env_is_412() {
    let (_d, app) = app().await;
    let (status, body) = send_custom(
        app,
        Method::POST,
        "/environments/ghost/migrate-bindings",
        Some(json!({
            "packs": [],
            "extensions": [],
            "seed_if_missing": {
                "host_config": {"env_id": "ghost"},
                "revocation": {},
                "retention": {},
                "health": {},
            },
        })),
        &[("Idempotency-Key", IDEM_KEY), ("If-Match", "\"deadbeef\"")],
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "body: {body}");
    assert_eq!(body["kind"], "precondition-failed");
}

// ---------------------------------------------------------------------------
// FIX 4 — corrupt stored row → 500 (not 400)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_corrupt_stored_env_is_500_internal() {
    let (_d, app, store) = app_with_store().await;

    // Insert a corrupt row: env_id key is "corrupt" but the JSON payload says
    // environment_id = "other". Compute integrity over the value so it passes
    // the digest check and hits the EnvIdMismatch validation path.
    let env = greentic_deploy_spec::engine::fresh_environment(
        &greentic_deploy_spec::EnvId::try_from("other").unwrap(),
        "other".to_string(),
        greentic_deploy_spec::EnvironmentHostConfig {
            env_id: greentic_deploy_spec::EnvId::try_from("other").unwrap(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        },
        greentic_deploy_spec::RevocationConfig::default(),
        greentic_deploy_spec::RetentionPolicy::default(),
        greentic_deploy_spec::HealthStatus::default(),
    );
    let data = serde_json::to_value(&env).unwrap();
    let integrity = greentic_deploy_spec::StateIntegrity::sha256_of(&data).unwrap();
    let etag = greentic_deploy_spec::StateEtag::from_integrity(&integrity);

    sqlx::query(
        "INSERT INTO environments (env_id, generation, etag, data, integrity_digest) \
         VALUES ($1, 1, $2, $3, $4)",
    )
    .bind("corrupt")
    .bind(&etag.0)
    .bind(&data)
    .bind(&integrity.digest)
    .execute(store.pool())
    .await
    .expect("insert corrupt row");

    // GET /environments/corrupt must return 500 (not 400)
    let (status, body) = send(app, Method::GET, "/environments/corrupt", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["kind"], "internal");
}

// ---------------------------------------------------------------------------
// FIX 5 — strict FieldUpdate deserialization at the wire level
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_with_contradictory_field_update_is_400() {
    let (_d, app) = app().await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // {"region": {"value": "x", "clear": true}} is contradictory → 400
    let (status, body) = send(
        app,
        Method::PATCH,
        "/environments/local",
        Some(json!({"region": {"value": "x", "clear": true}})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}
