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
use greentic_operator_store_server::http::{router, router_with_operator_key};
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;
use greentic_operator_store_server::storage::EnvironmentStorage;
use greentic_operator_trust::test_support::keypair;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::util::ServiceExt;

mod common;
use common::fresh_store;

const IDEM_KEY: &str = "01JTKW5B4W4Q5Y1CQW93F7S5VH";

/// Dispatch one JSON request with a FRESH `Idempotency-Key` and return
/// `(status, parsed body)`. Thin wrapper over [`send_custom`]. Fresh keys
/// per call mirror real clients (PR-4.3: the replay ledger consumes every
/// committed key, so a shared key would replay/conflict across the
/// sequential mutations these tests drive); tests that deliberately reuse
/// a key use [`send_custom`] with an explicit one.
async fn send(app: Router, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let key = ulid::Ulid::new().to_string();
    send_custom(app, method, path, body, &[("Idempotency-Key", &key)]).await
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
    // `send` mints a fresh key per call — assert presence here; the
    // explicit-key tests (replay, stamps) assert the exact echo.
    assert!(
        audit["idempotency_key"]
            .as_str()
            .is_some_and(|k| !k.is_empty()),
        "audit must echo the idempotency key: {body}"
    );
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

// ---------------------------------------------------------------------------
// Revision lifecycle routes (PR-4.2b)
// ---------------------------------------------------------------------------

use chrono::Utc;
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
    EnvironmentHostConfig, PartyId, Precondition, RevenueShareEntry, RevisionId, RouteBinding,
    SchemaVersion, TenantSelector, TrafficSplit, TrafficSplitEntry,
};
use std::path::PathBuf;

/// Seed an env carrying one bundle deployment directly through the storage
/// backend — revision tests need a deployment but not the bundle group's
/// trust-root/revenue-policy preconditions (`POST /bundles` exists since
/// PR-4.2g; the revision tests stay storage-seeded to keep them
/// independent).
async fn seed_env_with_deployment(store: &SqliteEnvironmentStore, env_id: &str) -> DeploymentId {
    let eid = EnvId::try_from(env_id).expect("env id");
    let mut env = greentic_deploy_spec::engine::fresh_environment(
        &eid,
        env_id.to_string(),
        EnvironmentHostConfig {
            env_id: eid.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        },
        Default::default(),
        Default::default(),
        Default::default(),
    );
    let deployment_id = DeploymentId::new();
    env.bundles.push(BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id,
        env_id: eid,
        bundle_id: BundleId::new("fast2flow"),
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: RouteBinding {
            hosts: Vec::new(),
            path_prefixes: Vec::new(),
            tenant_selector: TenantSelector {
                tenant: "default".to_string(),
                team: "default".to_string(),
            },
        },
        revenue_share: vec![RevenueShareEntry {
            party_id: PartyId::new("greentic"),
            basis_points: 10_000,
        }],
        revenue_policy_ref: PathBuf::from("revenue.json"),
        usage: None,
        created_at: Utc::now(),
        authorization_ref: PathBuf::from("auth.json"),
        config_overrides: Default::default(),
    });
    store.create_env(&env).await.expect("seed env");
    deployment_id
}

/// The pinned A8 stage request body (matches the shared
/// `StageRevisionPayload` wire encoding).
fn stage_body(deployment_id: DeploymentId, revision_id: RevisionId) -> Value {
    json!({
        "revision_id": revision_id.to_string(),
        "deployment_id": deployment_id.to_string(),
        "bundle_digest": "sha256:00",
        "pack_list": [{
            "pack_id": "greentic.test.pack",
            "version": "1.0.0",
            "digest": "sha256:00",
        }],
        "pack_list_lock_ref": "pack-list.lock",
        "pack_config_refs": [],
        "config_digest": "sha256:00",
        "signature_sidecar_ref": "rev.sig",
        "drain_seconds": 30,
    })
}

fn warm_body(revision_id: RevisionId, expected_lifecycle: &str) -> Value {
    json!({
        "revision_id": revision_id.to_string(),
        "health_gate": {"ok": true},
        "expected_lifecycle": expected_lifecycle,
    })
}

/// Stage one revision over HTTP and return its id.
async fn stage_one(app: &Router, deployment_id: DeploymentId) -> RevisionId {
    let revision_id = RevisionId::new();
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/revisions",
        Some(stage_body(deployment_id, revision_id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stage failed: {body}");
    revision_id
}

#[tokio::test]
async fn stage_returns_staged_revision_and_persists() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;

    let revision_id = RevisionId::new();
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/revisions",
        Some(stage_body(deployment_id, revision_id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["result"]["lifecycle"], "staged");
    assert_eq!(body["result"]["sequence"], 1);
    assert_eq!(body["result"]["revision_id"], revision_id.to_string());
    assert_eq!(body["audit"]["verb"], "stage");

    // Persisted, and a second stage gets the next sequence.
    let (_, read) = send(app.clone(), Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["revisions"][0]["lifecycle"], "staged");

    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/revisions",
        Some(stage_body(deployment_id, RevisionId::new())),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["sequence"], 2);
}

#[tokio::test]
async fn stage_same_revision_id_twice_is_409_already_exists() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = RevisionId::new();

    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments/local/revisions",
        Some(stage_body(deployment_id, revision_id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A retry of a lost response replays the same caller-minted ULID —
    // it must conflict, never append a second copy.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/revisions",
        Some(stage_body(deployment_id, revision_id)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "already-exists");

    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(
        read["environment"]["revisions"].as_array().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn stage_unknown_deployment_is_404_dependent_not_found() {
    let (_d, app, store) = app_with_store().await;
    seed_env_with_deployment(&store, "local").await;

    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/revisions",
        Some(stage_body(DeploymentId::new(), RevisionId::new())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

#[tokio::test]
async fn stage_into_missing_env_is_404_not_found() {
    let (_d, app) = app().await;
    let (status, body) = send(
        app,
        Method::POST,
        "/environments/ghost/revisions",
        Some(stage_body(DeploymentId::new(), RevisionId::new())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "not-found");
}

#[tokio::test]
async fn warm_advances_staged_to_ready_and_persists() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = stage_one(&app, deployment_id).await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/warm"),
        Some(warm_body(revision_id, "staged")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "warm");
    assert_eq!(body["result"]["revision"]["lifecycle"], "ready");
    assert!(
        body["result"]["revision"]["warmed_at"].is_string(),
        "warmed_at must be stamped: {body}"
    );
    assert_eq!(body["result"]["starting_lifecycle"], "staged");

    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["revisions"][0]["lifecycle"], "ready");
}

#[tokio::test]
async fn warm_gate_failure_is_422_and_persists_failed() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = stage_one(&app, deployment_id).await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/warm"),
        Some(json!({
            "revision_id": revision_id.to_string(),
            "health_gate": {
                "ok": false,
                "failure": {
                    "failed_checks": ["route-table"],
                    "message": "route table invalid",
                },
            },
            "expected_lifecycle": "staged",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
    assert_eq!(body["kind"], "health-gate-failed");
    assert_eq!(body["revision_id"], revision_id.to_string());
    assert_eq!(body["failed_checks"], json!(["route-table"]));

    // Committed-on-error: the Failed flip is durable.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["revisions"][0]["lifecycle"], "failed");
}

#[tokio::test]
async fn warm_stale_expected_lifecycle_is_409_conflict() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = stage_one(&app, deployment_id).await;

    // Caller claims it observed `warming`, but the revision is `staged`.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/warm"),
        Some(warm_body(revision_id, "warming")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");

    // Nothing was persisted — the revision is still staged.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["revisions"][0]["lifecycle"], "staged");
}

#[tokio::test]
async fn warm_body_revision_id_must_match_url() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = stage_one(&app, deployment_id).await;

    let (status, body) = send(
        app,
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/warm"),
        Some(warm_body(RevisionId::new(), "staged")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn malformed_revision_id_in_url_is_400() {
    let (_d, app, store) = app_with_store().await;
    seed_env_with_deployment(&store, "local").await;

    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/revisions/not-a-ulid/drain",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn drain_requires_ready_then_archive_walks_to_archived() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = stage_one(&app, deployment_id).await;

    // Drain from `staged` → 409 conflict.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/drain"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");

    // Warm to ready, then drain succeeds.
    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/warm"),
        Some(warm_body(revision_id, "staged")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/drain"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["result"]["revision"]["lifecycle"], "draining");
    assert_eq!(body["result"]["starting_lifecycle"], "ready");
    assert_eq!(body["audit"]["verb"], "drain");

    // Archive walks Draining → Inactive → Archived end-to-end.
    let (status, body) = send(
        app,
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/archive"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["result"]["revision"]["lifecycle"], "archived");
    assert_eq!(body["result"]["starting_lifecycle"], "draining");
    assert_eq!(body["audit"]["verb"], "archive");
}

#[tokio::test]
async fn archive_with_live_traffic_reference_is_409() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = stage_one(&app, deployment_id).await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/warm"),
        Some(warm_body(revision_id, "staged")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Route 100% of traffic to the revision, directly through storage — a
    // hand-built split keeps this guard test independent of the traffic
    // route's own §5.3 admission checks.
    let eid = EnvId::try_from("local").expect("env id");
    let loaded = store.load_env(&eid).await.expect("load");
    let mut env = loaded.value;
    env.traffic_splits.push(TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: eid.clone(),
        deployment_id,
        bundle_id: BundleId::new("fast2flow"),
        generation: 0,
        entries: vec![TrafficSplitEntry {
            revision_id,
            weight_bps: 10_000,
        }],
        updated_at: Utc::now(),
        updated_by: "tester".to_string(),
        idempotency_key: "k1".to_string(),
        authorization_ref: PathBuf::from("auth.json"),
        previous_split_ref: None,
    });
    let precondition =
        Precondition::matching(loaded.revision.etag.clone(), loaded.revision.generation);
    store
        .update_env(&env, &precondition)
        .await
        .expect("seed split");

    let (status, body) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/archive"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("traffic split"),
        "detail must explain the live-traffic refusal: {body}"
    );

    // Refusal persisted nothing — the revision stays ready.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["revisions"][0]["lifecycle"], "ready");
}

// ---------------------------------------------------------------------------
// Traffic routes (PR-4.2c)
// ---------------------------------------------------------------------------

/// The pinned A8 set-traffic request body (matches the shared
/// `SetTrafficSplitPayload` wire encoding; `authorization_ref` absent).
fn traffic_body(deployment_id: DeploymentId, entries: &[(RevisionId, u32)]) -> Value {
    json!({
        "deployment_id": deployment_id.to_string(),
        "entries": entries
            .iter()
            .map(|(rid, bps)| json!({"revision_id": rid.to_string(), "weight_bps": bps}))
            .collect::<Vec<_>>(),
        "updated_by": "operator@test",
    })
}

/// Stage one revision and warm it to `Ready` over HTTP.
async fn ready_one(app: &Router, deployment_id: DeploymentId) -> RevisionId {
    let revision_id = stage_one(app, deployment_id).await;
    let (status, body) = send(
        app.clone(),
        Method::POST,
        &format!("/environments/local/revisions/{revision_id}/warm"),
        Some(warm_body(revision_id, "staged")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "warm failed: {body}");
    revision_id
}

#[tokio::test]
async fn traffic_set_persists_split_and_same_key_replay_is_noop() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let rid = ready_one(&app, deployment_id).await;

    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(rid, 10_000)])),
        &[("Idempotency-Key", IDEM_KEY)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "set");
    assert_eq!(body["result"]["split"]["generation"], 0);
    assert_eq!(
        body["result"]["split"]["idempotency_key"], IDEM_KEY,
        "the A8 header key must persist into the split (rollback-target contract)"
    );
    assert_eq!(body["result"]["previous_generation"], Value::Null);
    assert_eq!(body["result"]["new_generation"], 0);
    assert_eq!(body["result"]["environment"]["environment_id"], "local");
    let original = body;

    // Same key + same request → the PR-4.3 transport replay: the ledgered
    // original response verbatim (same audit event, same generations),
    // only the `idempotency` marker flips to `replayed`. Nothing persists.
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(rid, 10_000)])),
        &[("Idempotency-Key", IDEM_KEY)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["idempotency"]["idempotency"], "replayed");
    assert_eq!(body["result"], original["result"]);
    assert_eq!(
        body["audit"]["event_id"], original["audit"]["event_id"],
        "a replay returns the ORIGINAL audit event, not a fresh one"
    );
    assert_eq!(body["generation"], original["generation"]);

    // Durable: exactly one split, env generation unmoved past the commit.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["generation"], original["generation"]);
    let splits = read["environment"]["traffic_splits"]
        .as_array()
        .expect("splits array");
    assert_eq!(splits.len(), 1);
    assert_eq!(splits[0]["generation"], 0);
}

#[tokio::test]
async fn traffic_set_key_reuse_with_different_entries_is_409_idempotency_conflict() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let r1 = ready_one(&app, deployment_id).await;
    let r2 = ready_one(&app, deployment_id).await;

    let (status, _) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(r1, 10_000)])),
        &[("Idempotency-Key", IDEM_KEY)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The 409 now fires at the PR-4.3 replay gate (fingerprint mismatch);
    // the engine's domain-level key check still guards the LocalFS backend.
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(r2, 10_000)])),
        &[("Idempotency-Key", IDEM_KEY)],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "idempotency-conflict");

    // The live split is untouched.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(
        read["environment"]["traffic_splits"][0]["entries"][0]["revision_id"],
        r1.to_string()
    );
}

#[tokio::test]
async fn traffic_new_key_advances_generation_and_rollback_restores_previous() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let r1 = ready_one(&app, deployment_id).await;
    let r2 = ready_one(&app, deployment_id).await;

    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(r1, 10_000)])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A NEW key replaces the split and stashes the prior one.
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(r2, 10_000)])),
        &[("Idempotency-Key", "01JTKW5B4W4Q5Y1CQW93F7S5VJ")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["result"]["previous_generation"], 0);
    assert_eq!(body["result"]["new_generation"], 1);

    // Rollback restores the r1 split under generation 2 (advance, never
    // rewind).
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/traffic/rollback",
        Some(json!({"deployment_id": deployment_id.to_string()})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "rollback");
    assert_eq!(body["result"]["previous_generation"], 1);
    assert_eq!(body["result"]["new_generation"], 2);
    assert_eq!(
        body["result"]["restored"]["entries"][0]["revision_id"],
        r1.to_string()
    );

    // The restored split has no further snapshot — a second rollback is a
    // 409 conflict, not a flip-flop.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/traffic/rollback",
        Some(json!({"deployment_id": deployment_id.to_string()})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");

    // Durable: generation 2 routing r1.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["traffic_splits"][0]["generation"], 2);
    assert_eq!(
        read["environment"]["traffic_splits"][0]["entries"][0]["revision_id"],
        r1.to_string()
    );
}

#[tokio::test]
async fn traffic_set_unknown_deployment_is_404_dependent_not_found() {
    let (_d, app, store) = app_with_store().await;
    seed_env_with_deployment(&store, "local").await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(DeploymentId::new(), &[])),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");

    // Missing env entirely → plain not-found.
    let (status, body) = send(
        app,
        Method::POST,
        "/environments/ghost/traffic",
        Some(traffic_body(DeploymentId::new(), &[])),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "not-found");
}

#[tokio::test]
async fn traffic_set_non_ready_revision_is_409_conflict() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    // Staged, never warmed — §5.3 admission must refuse it.
    let rid = stage_one(&app, deployment_id).await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(rid, 10_000)])),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("only `Ready` revisions"),
        "detail must explain the admission refusal: {body}"
    );

    // Nothing persisted.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert!(
        read["environment"]["traffic_splits"]
            .as_array()
            .expect("splits array")
            .is_empty()
    );
}

#[tokio::test]
async fn traffic_set_bad_weight_sum_is_400_invalid_request() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let rid = ready_one(&app, deployment_id).await;

    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(rid, 9_999)])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn traffic_rollback_without_split_is_404_dependent_not_found() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;

    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/traffic/rollback",
        Some(json!({"deployment_id": deployment_id.to_string()})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

// ---------------------------------------------------------------------------
// Pack / extension binding routes (PR-4.2d)
// ---------------------------------------------------------------------------

/// The pinned A8 pack-binding request body (matches the shared
/// `PackBindingPayload` wire encoding).
fn pack_body(slot: &str, kind: &str) -> Value {
    json!({
        "binding": {
            "slot": slot,
            "kind": format!("{kind}@1.0.0"),
            "pack_ref": kind,
            "generation": 0,
        }
    })
}

/// The pinned A8 keyed-extension request body (`ExtensionKeyedPayload`):
/// `binding: None` is absent, the key's `instance_id` rides explicitly.
fn extension_key_body(kind_path: &str, instance_id: Option<&str>, binding: Option<Value>) -> Value {
    let mut body = json!({
        "key": {"kind_path": kind_path, "instance_id": instance_id},
    });
    if let Some(binding) = binding {
        body["binding"] = binding;
    }
    body
}

fn extension_binding(kind: &str, instance_id: Option<&str>, pack_ref: &str) -> Value {
    json!({
        "kind": format!("{kind}@0.1.0"),
        "pack_ref": pack_ref,
        "instance_id": instance_id,
        "generation": 0,
    })
}

#[tokio::test]
async fn pack_binding_add_update_rollback_walk() {
    let (_d, app) = app().await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Add binds the slot and returns the bare binding.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/packs",
        Some(pack_body("secrets", "greentic.secrets")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["noun"], "env-packs");
    assert_eq!(body["audit"]["verb"], "add");
    assert_eq!(body["audit"]["target"]["environment_id"], "local");
    assert_eq!(body["audit"]["target"]["slot"], "secrets");
    assert_eq!(body["result"]["slot"], "secrets");

    // Duplicate add → 409 already-exists; nothing persisted on top.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/packs",
        Some(pack_body("secrets", "greentic.other")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "already-exists");

    // Update replaces the binding, bumps the generation, stashes the prior.
    let (status, body) = send(
        app.clone(),
        Method::PATCH,
        "/environments/local/packs/secrets",
        Some(pack_body("secrets", "greentic.vault")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "update");
    assert_eq!(body["result"]["generation"], 1);
    assert_eq!(body["result"]["binding"]["kind"], "greentic.vault@1.0.0");
    let stash = body["result"]["binding"]["previous_binding_ref"]
        .as_str()
        .expect("prior binding stashed");
    assert!(stash.starts_with("inline://"), "stash token: {stash}");

    // Rollback restores the original and clears the stash (single-step).
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/packs/secrets/rollback",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "rollback");
    assert_eq!(body["result"]["generation"], 2);
    assert_eq!(body["result"]["binding"]["kind"], "greentic.secrets@1.0.0");
    assert!(body["result"]["binding"]["previous_binding_ref"].is_null());

    // Second rollback → 409 conflict (no previous binding left).
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/packs/secrets/rollback",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");

    // Durable: the restored binding survives a fresh read.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    let packs = read["environment"]["packs"].as_array().expect("packs");
    assert_eq!(packs.len(), 1);
    assert_eq!(packs[0]["kind"], "greentic.secrets@1.0.0");
    assert_eq!(packs[0]["generation"], 2);
}

#[tokio::test]
async fn pack_binding_remove_returns_removed_binding() {
    let (_d, app) = app().await;
    send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    send(
        app.clone(),
        Method::POST,
        "/environments/local/packs",
        Some(pack_body("secrets", "greentic.secrets")),
    )
    .await;

    let (status, body) = send(
        app.clone(),
        Method::DELETE,
        "/environments/local/packs/secrets",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "remove");
    assert_eq!(body["result"]["binding"]["kind"], "greentic.secrets@1.0.0");

    // Second remove → 404 dependent-not-found (slot no longer bound).
    let (status, body) = send(
        app,
        Method::DELETE,
        "/environments/local/packs/secrets",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

#[tokio::test]
async fn pack_binding_rejects_n_per_env_and_unknown_slots() {
    let (_d, app) = app().await;
    send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;

    // N-per-env slot in the body → typed 400 (the engine's wire guard;
    // the deployer CLI rejects these upstream with its own message).
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/packs",
        Some(pack_body("messaging", "greentic.slack")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");

    // Unknown slot path segment → typed 400, not a 500 or a router miss.
    let (status, body) = send(
        app,
        Method::PATCH,
        "/environments/local/packs/nonsense",
        Some(pack_body("secrets", "greentic.secrets")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn extension_binding_add_update_remove_walk() {
    let (_d, app) = app().await;
    send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;

    // Add the unnamed default instance.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/extensions",
        Some(json!({"binding": extension_binding("greentic.memory", None, "greentic.memory")})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["noun"], "extensions");
    assert_eq!(body["audit"]["target"]["kind_path"], "greentic.memory");
    assert!(body["audit"]["target"]["instance_id"].is_null());

    // A named instance on the same path coexists with the default.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/extensions",
        Some(
            json!({"binding": extension_binding("greentic.memory", Some("alt"), "greentic.memory")}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // Re-adding the default key → 409 already-exists.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/extensions",
        Some(json!({"binding": extension_binding("greentic.memory", None, "greentic.memory")})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "already-exists");

    // Keyed update swaps the pack_ref and bumps the generation.
    let (status, body) = send(
        app.clone(),
        Method::PATCH,
        "/environments/local/extensions",
        Some(extension_key_body(
            "greentic.memory",
            None,
            Some(extension_binding(
                "greentic.memory",
                None,
                "greentic.memory-v2",
            )),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "update");
    assert_eq!(body["result"]["generation"], 1);
    assert_eq!(body["result"]["binding"]["pack_ref"], "greentic.memory-v2");

    // Keyed remove targets ONLY the default instance; `alt` survives.
    let (status, body) = send(
        app.clone(),
        Method::DELETE,
        "/environments/local/extensions",
        Some(extension_key_body("greentic.memory", None, None)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "remove");

    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    let extensions = read["environment"]["extensions"]
        .as_array()
        .expect("extensions");
    assert_eq!(extensions.len(), 1);
    assert_eq!(extensions[0]["instance_id"], "alt");
}

#[tokio::test]
async fn extension_update_without_binding_is_400() {
    let (_d, app) = app().await;
    send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;

    let (status, body) = send(
        app,
        Method::PATCH,
        "/environments/local/extensions",
        Some(extension_key_body("greentic.memory", None, None)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn extension_rollback_restores_previous_binding() {
    let (_d, app) = app().await;
    send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    send(
        app.clone(),
        Method::POST,
        "/environments/local/extensions",
        Some(json!({"binding": extension_binding("greentic.memory", None, "greentic.memory")})),
    )
    .await;
    send(
        app.clone(),
        Method::PATCH,
        "/environments/local/extensions",
        Some(extension_key_body(
            "greentic.memory",
            None,
            Some(extension_binding(
                "greentic.memory",
                None,
                "greentic.memory-v2",
            )),
        )),
    )
    .await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/extensions/rollback",
        Some(extension_key_body("greentic.memory", None, None)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "rollback");
    assert_eq!(body["result"]["generation"], 2);
    assert_eq!(body["result"]["binding"]["pack_ref"], "greentic.memory");

    // No stash left → second rollback is a 409 conflict.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/extensions/rollback",
        Some(extension_key_body("greentic.memory", None, None)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");

    // Unknown key → 404 dependent-not-found.
    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/extensions/rollback",
        Some(extension_key_body("greentic.ghost", None, None)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

#[tokio::test]
async fn binding_routes_on_ghost_env_are_404_not_found() {
    let (_d, app) = app().await;
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/ghost/packs",
        Some(pack_body("secrets", "greentic.secrets")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "not-found");

    let (status, body) = send(
        app,
        Method::DELETE,
        "/environments/ghost/extensions",
        Some(extension_key_body("greentic.memory", None, None)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "not-found");
}

#[tokio::test]
async fn extension_update_with_mismatched_key_is_409_conflict() {
    let (_d, app) = app().await;
    send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;

    // Add the default (None) instance.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/extensions",
        Some(json!({"binding": extension_binding("greentic.memory", None, "greentic.memory")})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add failed: {body}");

    // PATCH with key targeting the default instance but a replacement
    // binding whose instance_id differs ("renamed") — must be rejected.
    let (status, body) = send(
        app.clone(),
        Method::PATCH,
        "/environments/local/extensions",
        Some(extension_key_body(
            "greentic.memory",
            None,
            Some(extension_binding(
                "greentic.memory",
                Some("renamed"),
                "greentic.memory",
            )),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");

    // Nothing persisted: the stored extension still has instance_id null
    // and generation 0.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    let extensions = read["environment"]["extensions"]
        .as_array()
        .expect("extensions");
    assert_eq!(extensions.len(), 1);
    assert!(extensions[0]["instance_id"].is_null());
    assert_eq!(extensions[0]["generation"], 0);
}

// ---------------------------------------------------------------------------
// PR-4.2f — trust-root verb group
// ---------------------------------------------------------------------------

/// Like [`app_with_store`], but with the server operator key pinned to a
/// file inside the test's `TempDir` (so bootstrap/seed never touch the
/// real `~/.greentic/operator/key.pem`).
async fn app_with_trust_key() -> (tempfile::TempDir, Router, Arc<SqliteEnvironmentStore>) {
    let (dir, store) = fresh_store().await;
    let store = Arc::new(store);
    let app = router_with_operator_key(Arc::clone(&store), dir.path().join("operator-key.pem"));
    (dir, app, store)
}

async fn create_local_env(app: &Router) {
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create env failed: {body}");
}

#[tokio::test]
async fn trust_root_bootstrap_grants_operator_key_idempotently() {
    let (_d, app, _store) = app_with_trust_key().await;
    create_local_env(&app).await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/bootstrap",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["noun"], "trust-root");
    assert_eq!(body["audit"]["verb"], "bootstrap");
    let key_id = body["result"]["key_id"]
        .as_str()
        .expect("key_id")
        .to_string();
    assert!(
        body["result"]["public_key_pem"]
            .as_str()
            .unwrap_or("")
            .contains("PUBLIC KEY")
    );
    assert_eq!(body["result"]["trusted_key_count"], 1);

    // Re-grant: same server key, same single entry.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/bootstrap",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["result"]["key_id"], key_id.as_str());
    assert_eq!(body["result"]["trusted_key_count"], 1);

    let (status, body) = send(app, Method::GET, "/environments/local/trust-root", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["environment_id"], "local");
    assert_eq!(body["keys"].as_array().expect("keys").len(), 1);
    assert_eq!(body["keys"][0]["key_id"], key_id.as_str());
}

#[tokio::test]
async fn trust_root_seed_mints_once_then_nulls() {
    let (_d, app, store) = app_with_trust_key().await;
    create_local_env(&app).await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/seed",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "seed");
    assert_eq!(body["result"]["trusted_key_count"], 1);

    // Already seeded — the no-op contract is a 200 with a `null` result.
    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/trust-root/seed",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert!(body["result"].is_null(), "body: {body}");

    let loaded = store
        .load_trust_root(&greentic_deploy_spec::EnvId::try_from("local").unwrap())
        .await
        .expect("load")
        .expect("row exists after seed");
    assert_eq!(loaded.value.keys.len(), 1);
}

#[tokio::test]
async fn trust_root_add_validates_and_canonicalizes() {
    let (_d, app, _store) = app_with_trust_key().await;
    create_local_env(&app).await;

    // Uppercase id is accepted (validated against the derivation
    // case-insensitively); the outcome echoes the caller's form while the
    // stored entry is canonical lowercase.
    let (pem, id) = keypair(40);
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/keys",
        Some(json!({"key_id": id.to_uppercase(), "public_key_pem": pem})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "add");
    assert_eq!(body["result"]["added_key_id"], id.to_uppercase());
    assert_eq!(body["result"]["trusted_key_count"], 1);

    let (status, body) = send(
        app.clone(),
        Method::GET,
        "/environments/local/trust-root",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["keys"][0]["key_id"],
        id.as_str(),
        "stored id is canonical"
    );

    // A key_id that does not match the PEM's derivation → typed 400
    // before any state is touched.
    let (pem_a, _) = keypair(41);
    let (_, id_b) = keypair(42);
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/keys",
        Some(json!({"key_id": id_b, "public_key_pem": pem_a})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");

    // Adding the trust root via `add` also flips the seed gate.
    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/trust-root/seed",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body["result"].is_null(),
        "manual add must count as bootstrapped: {body}"
    );
}

#[tokio::test]
async fn trust_root_remove_returns_pem_and_noops_on_absent() {
    let (_d, app, store) = app_with_trust_key().await;
    create_local_env(&app).await;
    let local = greentic_deploy_spec::EnvId::try_from("local").unwrap();

    // No-op remove on an env that was never bootstrapped must NOT
    // materialize a trust-root row (row absence is the seed gate).
    let (status, body) = send(
        app.clone(),
        Method::DELETE,
        "/environments/local/trust-root/keys/deadbeef",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["result"]["removed_public_key_pem"].is_null());
    assert_eq!(body["result"]["trusted_key_count"], 0);
    assert!(
        store.load_trust_root(&local).await.expect("load").is_none(),
        "no-op remove must not create the trust-root row"
    );

    let (pem, id) = keypair(43);
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/keys",
        Some(json!({"key_id": id, "public_key_pem": pem})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Case-insensitive removal returns the removed PEM (recovery material).
    let (status, body) = send(
        app.clone(),
        Method::DELETE,
        &format!("/environments/local/trust-root/keys/{}", id.to_uppercase()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "remove");
    assert_eq!(body["result"]["removed_key_id"], id.to_uppercase());
    assert_eq!(body["result"]["removed_public_key_pem"], pem.as_str());
    assert_eq!(body["result"]["trusted_key_count"], 0);

    // Second remove: silent no-op, PEM gone, row (and its generation) kept.
    let (status, body) = send(
        app,
        Method::DELETE,
        &format!("/environments/local/trust-root/keys/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["result"]["removed_public_key_pem"].is_null());
    let loaded = store
        .load_trust_root(&local)
        .await
        .expect("load")
        .expect("row survives emptying");
    assert!(loaded.value.keys.is_empty());
    assert_eq!(
        loaded.revision.generation, 2,
        "no-op remove must not bump the row generation"
    );
}

#[tokio::test]
async fn trust_root_verbs_on_missing_env_are_404() {
    let (_d, app, _store) = app_with_trust_key().await;
    let (pem, id) = keypair(44);
    let cases: Vec<(Method, &str, Option<Value>)> = vec![
        (Method::GET, "/environments/ghost/trust-root", None),
        (
            Method::POST,
            "/environments/ghost/trust-root/bootstrap",
            None,
        ),
        (Method::POST, "/environments/ghost/trust-root/seed", None),
        (
            Method::POST,
            "/environments/ghost/trust-root/keys",
            Some(json!({"key_id": id, "public_key_pem": pem})),
        ),
        (
            Method::DELETE,
            "/environments/ghost/trust-root/keys/deadbeef",
            None,
        ),
    ];
    for (method, path, payload) in cases {
        let (status, body) = send(app.clone(), method.clone(), path, payload).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {path} body: {body}"
        );
        assert_eq!(body["kind"], "not-found", "{method} {path}");
    }
}

// ---------------------------------------------------------------------------
// Concurrent trust-root first-write convergence (F3 race fix)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trust_root_concurrent_seeds_converge() {
    let (_d, app, _store) = app_with_trust_key().await;
    create_local_env(&app).await;

    // Fire 4 concurrent seeds with distinct idempotency keys.
    let (r1, r2, r3, r4) = tokio::join!(
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/seed",
            None,
            &[("Idempotency-Key", "SEED-RACE-1")],
        ),
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/seed",
            None,
            &[("Idempotency-Key", "SEED-RACE-2")],
        ),
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/seed",
            None,
            &[("Idempotency-Key", "SEED-RACE-3")],
        ),
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/seed",
            None,
            &[("Idempotency-Key", "SEED-RACE-4")],
        ),
    );

    let results = [r1, r2, r3, r4];
    for (i, (status, body)) in results.iter().enumerate() {
        assert_eq!(*status, StatusCode::OK, "seed {i} body: {body}");
    }

    // Exactly one result is non-null (the winner); the rest are null no-ops.
    let non_null_count = results
        .iter()
        .filter(|(_, body)| !body["result"].is_null())
        .count();
    assert_eq!(
        non_null_count, 1,
        "exactly one seed must win; got {non_null_count} non-null results"
    );

    // Final state: exactly 1 key.
    let (status, body) = send(app, Method::GET, "/environments/local/trust-root", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keys"].as_array().expect("keys").len(), 1);
}

#[tokio::test]
async fn trust_root_concurrent_adds_of_distinct_keys_both_land() {
    let (_d, app, _store) = app_with_trust_key().await;
    create_local_env(&app).await;

    let (pem_a, id_a) = keypair(60);
    let (pem_b, id_b) = keypair(61);

    let (r1, r2) = tokio::join!(
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/keys",
            Some(json!({"key_id": id_a, "public_key_pem": pem_a})),
            &[("Idempotency-Key", "ADD-RACE-1")],
        ),
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/keys",
            Some(json!({"key_id": id_b, "public_key_pem": pem_b})),
            &[("Idempotency-Key", "ADD-RACE-2")],
        ),
    );

    assert_eq!(r1.0, StatusCode::OK, "add key A: {}", r1.1);
    assert_eq!(r2.0, StatusCode::OK, "add key B: {}", r2.1);

    // Both distinct keys must be present.
    let (status, body) = send(app, Method::GET, "/environments/local/trust-root", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["keys"].as_array().expect("keys").len(),
        2,
        "both distinct keys must land: {body}"
    );
}

#[tokio::test]
async fn trust_root_concurrent_bootstraps_converge() {
    let (_d, app, _store) = app_with_trust_key().await;
    create_local_env(&app).await;

    let (r1, r2) = tokio::join!(
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/bootstrap",
            None,
            &[("Idempotency-Key", "BOOT-RACE-1")],
        ),
        send_custom(
            app.clone(),
            Method::POST,
            "/environments/local/trust-root/bootstrap",
            None,
            &[("Idempotency-Key", "BOOT-RACE-2")],
        ),
    );

    assert_eq!(r1.0, StatusCode::OK, "bootstrap 1: {}", r1.1);
    assert_eq!(r2.0, StatusCode::OK, "bootstrap 2: {}", r2.1);

    // Both report the same key_id.
    let kid1 = r1.1["result"]["key_id"].as_str().expect("key_id 1");
    let kid2 = r2.1["result"]["key_id"].as_str().expect("key_id 2");
    assert_eq!(kid1, kid2, "both bootstraps must report the same key");

    // Final state: exactly 1 key.
    let (status, body) = send(app, Method::GET, "/environments/local/trust-root", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keys"].as_array().expect("keys").len(), 1);
}

// ---------------------------------------------------------------------------
// PR-4.2g — bundles verb group
// ---------------------------------------------------------------------------

fn add_bundle_body(bundle: &str, customer: &str) -> Value {
    json!({
        "bundle_id": bundle,
        "customer_id": customer,
        "revenue_share": [{"party_id": "greentic", "basis_points": 10_000}],
        "config_overrides": {},
    })
}

/// App + env + bootstrapped trust root — the precondition for any bundle
/// verb that writes a revenue policy (the server refuses closed-by-default
/// otherwise).
async fn bundles_app() -> (tempfile::TempDir, Router, Arc<SqliteEnvironmentStore>) {
    let (dir, app, store) = app_with_trust_key().await;
    create_local_env(&app).await;
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/bootstrap",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap failed: {body}");
    (dir, app, store)
}

async fn add_one_bundle(app: &Router, bundle: &str, customer: &str) -> DeploymentId {
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/bundles",
        Some(add_bundle_body(bundle, customer)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add bundle failed: {body}");
    body["result"]["deployment_id"]
        .as_str()
        .expect("deployment_id")
        .parse::<ulid::Ulid>()
        .map(DeploymentId)
        .expect("ulid deployment_id")
}

#[tokio::test]
async fn bundles_add_persists_deployment_and_signed_policy_artifact() {
    let (_d, app, store) = bundles_app().await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/bundles",
        Some(add_bundle_body("acme", "cust-1")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["noun"], "bundles");
    assert_eq!(body["audit"]["verb"], "add");
    assert_eq!(body["audit"]["target"]["revenue_policy_version"], 1);
    let result = &body["result"];
    assert_eq!(result["bundle_id"], "acme");
    assert_eq!(result["customer_id"], "cust-1");
    assert_eq!(result["status"], "active");
    assert_eq!(
        result["revenue_policy_ref"],
        "billing-policies/acme/cust-1/v1.json.sig"
    );
    let deployment_id = result["deployment_id"].as_str().expect("server-minted id");
    assert!(deployment_id.parse::<ulid::Ulid>().is_ok());
    // Env CAS advanced (create=1 → bundle add=2).
    assert_eq!(body["generation"], 2);

    // The artifact row holds the exact built bytes, self-consistent.
    let artifact = store
        .load_revenue_policy(
            &EnvId::try_from("local").unwrap(),
            &BundleId::new("acme"),
            &CustomerId::new("cust-1"),
            1,
        )
        .await
        .expect("load artifact")
        .expect("v1 artifact stored");
    assert_eq!(
        artifact.policy_ref,
        "billing-policies/acme/cust-1/v1.json.sig"
    );
    assert_eq!(
        artifact.doc_sha256,
        greentic_operator_trust::revenue_policy::sha256_hex(&artifact.doc)
    );
    let doc: Value = serde_json::from_slice(&artifact.doc).expect("doc decodes");
    assert_eq!(doc["schema"], "greentic.revenue-policy.v1");
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["deployment_id"], deployment_id);
    assert!(doc.get("previous_version_ref").is_none(), "v1 has no chain");
    // The sidecar is a DSSE envelope signed by the bootstrapped server key.
    let envelope: Value = serde_json::from_slice(&artifact.envelope).expect("envelope decodes");
    assert_eq!(envelope["payloadType"], "application/vnd.in-toto+json");
    assert_eq!(envelope["signatures"][0]["keyid"], artifact.key_id.as_str());

    // And the stored environment carries the pinned ref.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(
        read["environment"]["bundles"][0]["revenue_policy_ref"],
        "billing-policies/acme/cust-1/v1.json.sig"
    );
}

#[tokio::test]
async fn bundles_add_without_trust_root_is_409_not_trusted_and_persists_nothing() {
    let (_d, app, store) = app_with_trust_key().await;
    create_local_env(&app).await;
    // No bootstrap: the trust-root row is absent → empty trust root →
    // closed-by-default refusal.
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/bundles",
        Some(add_bundle_body("acme", "cust-1")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("is not trusted in env `local`"),
        "detail should guide to bootstrap: {body}"
    );

    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["bundles"], json!([]));
    let artifact = store
        .load_revenue_policy(
            &EnvId::try_from("local").unwrap(),
            &BundleId::new("acme"),
            &CustomerId::new("cust-1"),
            1,
        )
        .await
        .expect("load artifact");
    assert!(artifact.is_none(), "refusal must leave no artifact row");
}

#[tokio::test]
async fn bundles_add_duplicate_pair_is_409_already_exists() {
    let (_d, app, _store) = bundles_app().await;
    add_one_bundle(&app, "acme", "cust-1").await;
    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/bundles",
        Some(add_bundle_body("acme", "cust-1")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "already-exists");

    // Same bundle, different customer: a distinct deployment.
    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/bundles",
        Some(add_bundle_body("acme", "cust-2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn bundles_update_revenue_share_chains_policy_v2() {
    let (_d, app, store) = bundles_app().await;
    let did = add_one_bundle(&app, "acme", "cust-1").await;

    let (status, body) = send(
        app.clone(),
        Method::PATCH,
        &format!("/environments/local/bundles/{did}"),
        Some(json!({
            "deployment_id": did.to_string(),
            "status": "paused",
            "revenue_share": [{"party_id": "partner", "basis_points": 10_000}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "update");
    assert_eq!(body["audit"]["target"]["revenue_policy_version"], 2);
    assert_eq!(body["result"]["status"], "paused");
    assert_eq!(
        body["result"]["revenue_policy_ref"],
        "billing-policies/acme/cust-1/v2.json.sig"
    );
    assert_eq!(
        body["result"]["revenue_share"],
        json!([{"party_id": "partner", "basis_points": 10_000}])
    );

    // v2 chains back to the committed v1 sidecar.
    let artifact = store
        .load_revenue_policy(
            &EnvId::try_from("local").unwrap(),
            &BundleId::new("acme"),
            &CustomerId::new("cust-1"),
            2,
        )
        .await
        .expect("load artifact")
        .expect("v2 artifact stored");
    let doc: Value = serde_json::from_slice(&artifact.doc).expect("doc decodes");
    assert_eq!(
        doc["previous_version_ref"],
        "billing-policies/acme/cust-1/v1.json.sig"
    );
}

#[tokio::test]
async fn bundles_update_without_revenue_share_writes_no_policy() {
    let (_d, app, store) = bundles_app().await;
    let did = add_one_bundle(&app, "acme", "cust-1").await;

    let (status, body) = send(
        app.clone(),
        Method::PATCH,
        &format!("/environments/local/bundles/{did}"),
        Some(json!({
            "deployment_id": did.to_string(),
            "status": "paused",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["audit"]["target"]["revenue_policy_version"].is_null());
    assert_eq!(
        body["result"]["revenue_policy_ref"], "billing-policies/acme/cust-1/v1.json.sig",
        "ref unchanged"
    );
    let artifact = store
        .load_revenue_policy(
            &EnvId::try_from("local").unwrap(),
            &BundleId::new("acme"),
            &CustomerId::new("cust-1"),
            2,
        )
        .await
        .expect("load artifact");
    assert!(artifact.is_none(), "no v2 without a revenue_share patch");
}

#[tokio::test]
async fn bundles_update_unknown_deployment_is_404_dependent_not_found() {
    let (_d, app, _store) = bundles_app().await;
    let ghost = DeploymentId::new();
    let (status, body) = send(
        app,
        Method::PATCH,
        &format!("/environments/local/bundles/{ghost}"),
        Some(json!({"deployment_id": ghost.to_string(), "status": "paused"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

#[tokio::test]
async fn bundles_update_body_url_mismatch_is_400() {
    let (_d, app, _store) = bundles_app().await;
    let did = add_one_bundle(&app, "acme", "cust-1").await;
    let other = DeploymentId::new();
    let (status, body) = send(
        app,
        Method::PATCH,
        &format!("/environments/local/bundles/{did}"),
        Some(json!({"deployment_id": other.to_string(), "status": "paused"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn bundles_remove_quiesced_deployment_prunes_and_persists() {
    let (_d, app, _store) = bundles_app().await;
    let did = add_one_bundle(&app, "acme", "cust-1").await;

    let (status, body) = send(
        app.clone(),
        Method::DELETE,
        &format!("/environments/local/bundles/{did}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["verb"], "remove");
    assert_eq!(
        body["result"]["deployment"]["deployment_id"],
        did.to_string()
    );
    assert_eq!(body["result"]["pruned_revision_ids"], json!([]));

    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["bundles"], json!([]));
}

#[tokio::test]
async fn bundles_remove_with_live_revision_is_409_conflict() {
    let (_d, app, _store) = bundles_app().await;
    let did = add_one_bundle(&app, "acme", "cust-1").await;
    // Stage a revision under the deployment — live state.
    stage_one(&app, did).await;

    let (status, body) = send(
        app.clone(),
        Method::DELETE,
        &format!("/environments/local/bundles/{did}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "conflict");
    assert!(
        body["detail"].as_str().unwrap_or("").contains("still live"),
        "body: {body}"
    );

    // Nothing removed.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["bundles"].as_array().unwrap().len(), 1);
    assert_eq!(
        read["environment"]["revisions"].as_array().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn bundles_remove_unknown_deployment_is_404_dependent_not_found() {
    let (_d, app, _store) = bundles_app().await;
    let ghost = DeploymentId::new();
    let (status, body) = send(
        app,
        Method::DELETE,
        &format!("/environments/local/bundles/{ghost}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

#[tokio::test]
async fn bundles_concurrent_updates_keep_env_and_artifact_consistent() {
    // Codex F1 at the route level: two concurrent revenue-share updates of
    // the same deployment race load → build → commit. Whatever the
    // interleave (full serialization → both 200; overlapping loads → the
    // loser's CAS fails 412 and its artifact rolls back), the COMMITTED
    // environment must reference an artifact whose content matches the
    // committed revenue share.
    let (_d, app, store) = bundles_app().await;
    let did = add_one_bundle(&app, "acme", "cust-1").await;

    let update = |party: &str, key: &str| {
        let body = json!({
            "deployment_id": did.to_string(),
            "revenue_share": [{"party_id": party, "basis_points": 10_000}],
        });
        let key = key.to_string();
        let app = app.clone();
        async move {
            send_custom(
                app,
                Method::PATCH,
                &format!("/environments/local/bundles/{did}"),
                Some(body),
                &[("Idempotency-Key", &key)],
            )
            .await
        }
    };
    let (r1, r2) = tokio::join!(update("party-a", "RACE-A"), update("party-b", "RACE-B"));

    for (status, body) in [&r1, &r2] {
        assert!(
            *status == StatusCode::OK || *status == StatusCode::PRECONDITION_FAILED,
            "unexpected status {status}: {body}"
        );
    }
    assert!(
        r1.0 == StatusCode::OK || r2.0 == StatusCode::OK,
        "at least one update commits: {} / {}",
        r1.1,
        r2.1
    );

    // Committed env state and the artifact behind its ref agree.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    let bundle = &read["environment"]["bundles"][0];
    let committed_party = bundle["revenue_share"][0]["party_id"]
        .as_str()
        .expect("party");
    let ref_str = bundle["revenue_policy_ref"].as_str().expect("ref");
    let version: u64 = ref_str
        .rsplit_once("/v")
        .and_then(|(_, tail)| tail.strip_suffix(".json.sig"))
        .expect("vN ref shape")
        .parse()
        .expect("numeric version");
    let artifact = store
        .load_revenue_policy(
            &EnvId::try_from("local").unwrap(),
            &BundleId::new("acme"),
            &CustomerId::new("cust-1"),
            version,
        )
        .await
        .expect("load artifact")
        .expect("referenced artifact exists");
    let doc: Value = serde_json::from_slice(&artifact.doc).expect("doc decodes");
    assert_eq!(
        doc["revenue_share"][0]["party_id"], committed_party,
        "committed env and its referenced artifact must agree; env: {bundle}, doc: {doc}"
    );
}

// ---------------------------------------------------------------------------
// PR-4.2h — messaging verb group
// ---------------------------------------------------------------------------

fn add_endpoint_body(provider_type: &str, provider_id: &str) -> Value {
    json!({
        "provider_id": provider_id,
        "provider_type": provider_type,
        "display_name": format!("{provider_type} {provider_id}"),
        "secret_refs": [],
        "updated_by": "tester",
    })
}

/// Add an endpoint under an explicit idempotency key (the messaging group
/// uses the key as replay-detection domain state, so tests that add more
/// than one endpoint must vary it) and return the server-minted id.
async fn add_one_endpoint(
    app: &Router,
    provider_type: &str,
    provider_id: &str,
    key: &str,
) -> String {
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/messaging",
        Some(add_endpoint_body(provider_type, provider_id)),
        &[("Idempotency-Key", key)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add endpoint failed: {body}");
    body["result"]["endpoint_id"]
        .as_str()
        .expect("endpoint_id")
        .to_string()
}

#[tokio::test]
async fn messaging_add_persists_endpoint_with_server_minted_id() {
    let (_d, app) = app().await;
    create_local_env(&app).await;

    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/messaging",
        Some(add_endpoint_body("teams", "legal-bot")),
        &[("Idempotency-Key", IDEM_KEY)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_envelope(&body, "local");
    assert_eq!(body["audit"]["noun"], "messaging.endpoint");
    assert_eq!(body["audit"]["verb"], "add");
    assert_eq!(
        body["audit"]["idempotency_key"], IDEM_KEY,
        "the audit must echo the exact key sent"
    );
    assert_eq!(body["audit"]["target"]["provider_type"], "teams");
    let result = &body["result"];
    assert_eq!(result["provider_id"], "legal-bot");
    assert_eq!(result["provider_type"], "teams");
    assert_eq!(result["generation"], 0);
    assert_eq!(
        result["updated_by"],
        format!("tester#idem=add:{IDEM_KEY}"),
        "the idem key must be stamped into updated_by"
    );
    let eid = result["endpoint_id"].as_str().expect("server-minted id");
    assert!(eid.parse::<ulid::Ulid>().is_ok());
    // Env CAS advanced (create=1 → endpoint add=2).
    assert_eq!(body["generation"], 2);

    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(
        read["environment"]["messaging_endpoints"][0]["endpoint_id"],
        eid
    );
}

#[tokio::test]
async fn messaging_add_telegram_class_is_501_and_persists_nothing() {
    let (_d, app) = app().await;
    create_local_env(&app).await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/messaging",
        Some(add_endpoint_body("telegram", "tg-bot")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "body: {body}");
    assert_eq!(body["kind"], "not-yet-implemented");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("secrets sink"),
        "detail must point at the missing sink: {body}"
    );

    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(
        read["environment"]["messaging_endpoints"],
        json!([]),
        "the refused add must not persist"
    );
    assert_eq!(read["generation"], 1, "env CAS must not advance");
}

#[tokio::test]
async fn messaging_add_duplicate_identity_is_409_already_exists() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    add_one_endpoint(&app, "teams", "legal-bot", "k-add-1").await;

    let (status, body) = send_custom(
        app,
        Method::POST,
        "/environments/local/messaging",
        Some(add_endpoint_body("teams", "legal-bot")),
        &[("Idempotency-Key", "k-add-2")],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "already-exists");
}

#[tokio::test]
async fn messaging_add_same_key_replay_returns_existing_without_cas_advance() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-replay").await;

    let (status, body) = send_custom(
        app,
        Method::POST,
        "/environments/local/messaging",
        Some(add_endpoint_body("teams", "legal-bot")),
        &[("Idempotency-Key", "k-replay")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["result"]["endpoint_id"], eid,
        "replay must return the original endpoint"
    );
    assert_eq!(
        body["generation"], 2,
        "no-op replay must echo the loaded CAS coordinates"
    );
}

#[tokio::test]
async fn messaging_add_key_reuse_with_different_identity_is_409_idempotency_conflict() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    add_one_endpoint(&app, "teams", "legal-bot", "k-shared").await;

    let (status, body) = send_custom(
        app,
        Method::POST,
        "/environments/local/messaging",
        Some(add_endpoint_body("slack", "ops-bot")),
        &[("Idempotency-Key", "k-shared")],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "idempotency-conflict");
}

#[tokio::test]
async fn messaging_link_and_unlink_roundtrip() {
    let (_d, app, _store) = bundles_app().await;
    add_one_bundle(&app, "acme", "cust-1").await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-add").await;

    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        &format!("/environments/local/messaging/{eid}/link"),
        Some(json!({"bundle_id": "acme", "updated_by": "op"})),
        &[("Idempotency-Key", "k-link")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "link-bundle");
    assert_eq!(body["result"]["linked_bundles"], json!(["acme"]));
    assert_eq!(body["result"]["generation"], 1);
    assert_eq!(body["result"]["updated_by"], "op#idem=link-bundle:k-link");

    // Re-linking is a no-op: the env CAS must not advance.
    let linked_gen = body["generation"].as_u64().expect("generation");
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        &format!("/environments/local/messaging/{eid}/link"),
        Some(json!({"bundle_id": "acme", "updated_by": "op"})),
        &[("Idempotency-Key", "k-link-2")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["generation"].as_u64().expect("generation"), linked_gen);

    let (status, body) = send_custom(
        app,
        Method::POST,
        &format!("/environments/local/messaging/{eid}/unlink"),
        Some(json!({"bundle_id": "acme", "updated_by": "op"})),
        &[("Idempotency-Key", "k-unlink")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "unlink-bundle");
    assert_eq!(body["result"]["linked_bundles"], json!([]));
}

#[tokio::test]
async fn messaging_link_unknown_bundle_is_404_dependent_not_found() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-add").await;

    let (status, body) = send(
        app,
        Method::POST,
        &format!("/environments/local/messaging/{eid}/link"),
        Some(json!({"bundle_id": "ghost", "updated_by": "op"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

#[tokio::test]
async fn messaging_unknown_endpoint_is_404_dependent_not_found() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    let ghost = ulid::Ulid::new().to_string();

    let (status, body) = send(
        app,
        Method::POST,
        &format!("/environments/local/messaging/{ghost}/link"),
        Some(json!({"bundle_id": "acme", "updated_by": "op"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

#[tokio::test]
async fn messaging_invalid_endpoint_id_segment_is_400() {
    let (_d, app) = app().await;
    create_local_env(&app).await;

    let (status, body) = send(
        app,
        Method::POST,
        "/environments/local/messaging/not-a-ulid/link",
        Some(json!({"bundle_id": "acme", "updated_by": "op"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
}

#[tokio::test]
async fn messaging_welcome_flow_set_and_url_mismatch_rejected() {
    let (_d, app, _store) = bundles_app().await;
    add_one_bundle(&app, "acme", "cust-1").await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-add").await;
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        &format!("/environments/local/messaging/{eid}/link"),
        Some(json!({"bundle_id": "acme", "updated_by": "op"})),
        &[("Idempotency-Key", "k-link")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let welcome = json!({
        "endpoint_id": eid,
        "bundle_id": "acme",
        "pack_id": "welcome-pack",
        "flow_id": "hello",
        "updated_by": "op",
    });
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        &format!("/environments/local/messaging/{eid}/welcome-flow"),
        Some(welcome.clone()),
        &[("Idempotency-Key", "k-welcome")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "set-welcome-flow");
    assert_eq!(body["result"]["welcome_flow"]["pack_id"], "welcome-pack");

    // Body endpoint_id contradicting the URL → typed 400 before any load.
    let other = ulid::Ulid::new().to_string();
    let (status, body) = send_custom(
        app,
        Method::POST,
        &format!("/environments/local/messaging/{other}/welcome-flow"),
        Some(welcome),
        &[("Idempotency-Key", "k-welcome-2")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("does not match URL"),
        "detail must name the mismatch: {body}"
    );
}

#[tokio::test]
async fn messaging_welcome_flow_on_unlinked_bundle_is_400() {
    let (_d, app, _store) = bundles_app().await;
    add_one_bundle(&app, "acme", "cust-1").await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-add").await;

    let (status, body) = send(
        app,
        Method::POST,
        &format!("/environments/local/messaging/{eid}/welcome-flow"),
        Some(json!({
            "endpoint_id": eid,
            "bundle_id": "acme",
            "pack_id": "welcome-pack",
            "flow_id": "hello",
            "updated_by": "op",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["kind"], "invalid-request");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("link it first"),
        "detail must guide to link-bundle: {body}"
    );
}

#[tokio::test]
async fn messaging_remove_is_idempotent_without_second_cas_advance() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-add").await;

    let (status, body) = send(
        app.clone(),
        Method::DELETE,
        &format!("/environments/local/messaging/{eid}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["audit"]["verb"], "remove");
    assert_eq!(body["result"], eid, "result is the removed endpoint id");
    let removed_gen = body["generation"].as_u64().expect("generation");

    // Removing an absent endpoint succeeds without writing.
    let (status, body) = send(
        app,
        Method::DELETE,
        &format!("/environments/local/messaging/{eid}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["generation"].as_u64().expect("generation"),
        removed_gen
    );
}

#[tokio::test]
async fn messaging_rotate_secret_is_501_until_the_secrets_sink_lands() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-add").await;

    // Existing endpoint, fresh key → the refusing sink answers 501.
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        &format!("/environments/local/messaging/{eid}/rotate-secret"),
        Some(json!({"updated_by": "op"})),
        &[("Idempotency-Key", "k-rotate")],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "body: {body}");
    assert_eq!(body["kind"], "not-yet-implemented");

    // Validation order pin: an unknown endpoint still 404s BEFORE the sink.
    let ghost = ulid::Ulid::new().to_string();
    let (status, body) = send_custom(
        app,
        Method::POST,
        &format!("/environments/local/messaging/{ghost}/rotate-secret"),
        Some(json!({"updated_by": "op"})),
        &[("Idempotency-Key", "k-rotate-2")],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["kind"], "dependent-not-found");
}

/// Regression: add a (non-telegram) endpoint with key K, then POST
/// rotate-secret with the SAME key K — the rotate must NOT falsely
/// replay add's success as 200. Since PR-4.3 the transport replay gate
/// rejects the cross-operation reuse with a typed 409 (the add's ledger
/// row carries a different request fingerprint) one layer before the
/// engine's op-scoped stamps, which still guard the LocalFS backend.
#[tokio::test]
async fn messaging_rotate_with_add_key_does_not_falsely_replay() {
    let (_d, app) = app().await;
    create_local_env(&app).await;
    let eid = add_one_endpoint(&app, "teams", "legal-bot", "k-shared").await;

    let (status, body) = send_custom(
        app,
        Method::POST,
        &format!("/environments/local/messaging/{eid}/rotate-secret"),
        Some(json!({"updated_by": "op"})),
        &[("Idempotency-Key", "k-shared")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "rotate with add's key must be rejected, not replay add's 200: {body}"
    );
    assert_eq!(body["kind"], "idempotency-conflict");
    assert!(
        body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("messaging.endpoint.add"),
        "the conflict names the operation that consumed the key: {body}"
    );
}

// ---------------------------------------------------------------------------
// Idempotency replay ledger + durable audit log (PR-4.3)
// ---------------------------------------------------------------------------
//
// The transport-level replay contract every verb group now shares: a key
// consumed by a committed mutation replays that mutation's stored response
// verbatim (marker flipped to `replayed`), any other reuse of the key is a
// typed 409, failed requests consume nothing, and every committed mutation
// leaves a durable `audit_log` row — written in the SAME transaction as
// the mutation itself.

use sqlx::Row;

/// All audit-log event ids recorded for `env`, in append order.
async fn audit_log_event_ids(store: &SqliteEnvironmentStore, env: &str) -> Vec<String> {
    sqlx::query("SELECT event_id FROM audit_log WHERE env_id = $1 ORDER BY id ASC")
        .bind(env)
        .fetch_all(store.pool())
        .await
        .expect("audit query")
        .into_iter()
        .map(|r| r.get::<String, _>("event_id"))
        .collect()
}

#[tokio::test]
async fn replay_returns_verbatim_original_and_appends_no_second_audit_row() {
    let (_d, app, store) = app_with_store().await;
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments",
        Some(create_body("local")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let patch = json!({"name": "renamed"});
    let (status, original) = send_custom(
        app.clone(),
        Method::PATCH,
        "/environments/local",
        Some(patch.clone()),
        &[("Idempotency-Key", "k-patch")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {original}");
    assert_eq!(original["idempotency"]["idempotency"], "applied");

    // The response audit record IS the durable audit-log append.
    let logged = audit_log_event_ids(&store, "local").await;
    assert_eq!(logged.len(), 2, "create + update");
    assert_eq!(logged[1], original["audit"]["event_id"]);

    // Same key + same request → verbatim replay: original audit event,
    // original CAS coordinates, marker flipped — and NOTHING appended.
    let (status, replay) = send_custom(
        app.clone(),
        Method::PATCH,
        "/environments/local",
        Some(patch),
        &[("Idempotency-Key", "k-patch")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {replay}");
    assert_eq!(replay["idempotency"]["idempotency"], "replayed");
    assert_eq!(replay["result"], original["result"]);
    assert_eq!(replay["audit"], original["audit"]);
    assert_eq!(replay["etag"], original["etag"]);
    assert_eq!(replay["generation"], original["generation"]);
    assert_eq!(audit_log_event_ids(&store, "local").await.len(), 2);

    // The env did not move.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["generation"], original["generation"]);
    assert_eq!(read["environment"]["name"], "renamed");
}

#[tokio::test]
async fn same_key_with_different_body_is_409_idempotency_conflict() {
    let (_d, app) = app().await;
    create_local_env(&app).await;

    let (status, _) = send_custom(
        app.clone(),
        Method::PATCH,
        "/environments/local",
        Some(json!({"name": "first"})),
        &[("Idempotency-Key", "k-reuse")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send_custom(
        app.clone(),
        Method::PATCH,
        "/environments/local",
        Some(json!({"name": "second"})),
        &[("Idempotency-Key", "k-reuse")],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "idempotency-conflict");
    assert!(
        body["reason"].as_str().unwrap_or("").contains("env.update"),
        "the conflict names the operation that consumed the key: {body}"
    );

    // The second patch was rejected before touching state.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["name"], "first");
}

#[tokio::test]
async fn bodyless_replay_is_verbatim_and_path_scoped() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let rid = ready_one(&app, deployment_id).await;

    let drain_path = format!("/environments/local/revisions/{rid}/drain");
    let (status, original) = send_custom(
        app.clone(),
        Method::POST,
        &drain_path,
        None,
        &[("Idempotency-Key", "k-drain")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {original}");

    // Same key, same bodyless request → verbatim replay (the ORIGINAL
    // audit event comes back)...
    let (status, replay) = send_custom(
        app.clone(),
        Method::POST,
        &drain_path,
        None,
        &[("Idempotency-Key", "k-drain")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {replay}");
    assert_eq!(replay["idempotency"]["idempotency"], "replayed");
    assert_eq!(replay["audit"]["event_id"], original["audit"]["event_id"]);

    // ...while a FRESH key re-executes (the drain walk is an idempotent
    // no-op here) and mints a fresh audit event — the contrast that pins
    // replay-vs-reexecution apart.
    let (status, body) = send(app.clone(), Method::POST, &drain_path, None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["idempotency"]["idempotency"], "applied");
    assert_ne!(body["audit"]["event_id"], original["audit"]["event_id"]);

    // Same key on a DIFFERENT bodyless route: the path is part of the
    // fingerprint, so this is reuse, not replay.
    let (status, body) = send_custom(
        app,
        Method::POST,
        &format!("/environments/local/revisions/{rid}/archive"),
        None,
        &[("Idempotency-Key", "k-drain")],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["kind"], "idempotency-conflict");
}

#[tokio::test]
async fn warm_gate_failure_consumes_the_key_and_replays_the_422() {
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let revision_id = stage_one(&app, deployment_id).await;

    let gate_fail = json!({
        "revision_id": revision_id.to_string(),
        "health_gate": {
            "ok": false,
            "failure": {
                "failed_checks": ["route-table"],
                "message": "route table invalid",
            },
        },
        "expected_lifecycle": "staged",
    });
    let warm_path = format!("/environments/local/revisions/{revision_id}/warm");
    let (status, body) = send_custom(
        app.clone(),
        Method::POST,
        &warm_path,
        Some(gate_fail.clone()),
        &[("Idempotency-Key", "k-warm-fail")],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
    assert_eq!(body["kind"], "health-gate-failed");

    // Committed-on-error consumed the key: the durable audit log records
    // the non-ok outcome...
    let logged = audit_log_event_ids(&store, "local").await;
    let last = logged.last().expect("audit row");
    let event: Value = sqlx::query("SELECT event FROM audit_log WHERE event_id = $1")
        .bind(last)
        .fetch_one(store.pool())
        .await
        .expect("event row")
        .get::<Value, _>("event");
    assert_eq!(event["verb"], "warm");
    assert_eq!(event["result"]["outcome"], "error");
    assert_eq!(event["result"]["kind"], "health-gate-failed");

    // ...and a same-key retry replays the 422 verbatim instead of
    // re-walking the (now Failed) revision into a different error.
    let (status, replay) = send_custom(
        app.clone(),
        Method::POST,
        &warm_path,
        Some(gate_fail),
        &[("Idempotency-Key", "k-warm-fail")],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {replay}");
    assert_eq!(replay, body, "committed-on-error bodies replay byte-equal");
    assert_eq!(
        audit_log_event_ids(&store, "local").await.len(),
        logged.len()
    );
}

#[tokio::test]
async fn failed_requests_do_not_consume_the_key() {
    let (_d, app) = app().await;

    // 404 — the env does not exist yet; the key must survive.
    let (status, _) = send_custom(
        app.clone(),
        Method::PATCH,
        "/environments/local",
        Some(json!({"name": "ghost"})),
        &[("Idempotency-Key", "k-fail-free")],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The same key then commits a completely different request cleanly.
    let (status, body) = send_custom(
        app,
        Method::POST,
        "/environments",
        Some(create_body("local")),
        &[("Idempotency-Key", "k-fail-free")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["idempotency"]["idempotency"], "applied");
}

#[tokio::test]
async fn delayed_retry_replays_the_original_instead_of_overwriting_newer_state() {
    // The 4.2c F1 hazard, closed: a duplicate of an OLD traffic set
    // arriving after a newer set must not re-apply the old entries.
    let (_d, app, store) = app_with_store().await;
    let deployment_id = seed_env_with_deployment(&store, "local").await;
    let r1 = ready_one(&app, deployment_id).await;
    let r2 = ready_one(&app, deployment_id).await;

    let old_set = traffic_body(deployment_id, &[(r1, 10_000)]);
    let (status, original) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(old_set.clone()),
        &[("Idempotency-Key", "k-old")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(traffic_body(deployment_id, &[(r2, 10_000)])),
        &[("Idempotency-Key", "k-new")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The delayed duplicate of the OLD request: replayed, not re-applied.
    let (status, replay) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/traffic",
        Some(old_set),
        &[("Idempotency-Key", "k-old")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {replay}");
    assert_eq!(replay["idempotency"]["idempotency"], "replayed");
    assert_eq!(replay["result"], original["result"]);

    // The NEWER split stays live.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(
        read["environment"]["traffic_splits"][0]["entries"][0]["revision_id"],
        r2.to_string()
    );
}

#[tokio::test]
async fn bundles_add_retry_replays_without_a_second_policy_version() {
    // The 4.2g F3 hazard, closed: a same-key retry of `bundles add` must
    // not rebuild/duplicate the signed revenue-policy artifact.
    let (_d, app, store) = bundles_app().await;

    let (status, original) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/bundles",
        Some(add_bundle_body("acme", "cust-1")),
        &[("Idempotency-Key", "k-bundle")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {original}");

    let (status, replay) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/bundles",
        Some(add_bundle_body("acme", "cust-1")),
        &[("Idempotency-Key", "k-bundle")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {replay}");
    assert_eq!(replay["idempotency"]["idempotency"], "replayed");
    assert_eq!(
        replay["result"]["deployment_id"], original["result"]["deployment_id"],
        "the replay echoes the ORIGINAL server-minted deployment id"
    );

    // Exactly one deployment, exactly one policy version.
    let (_, read) = send(app, Method::GET, "/environments/local", None).await;
    assert_eq!(read["environment"]["bundles"].as_array().unwrap().len(), 1);
    let bundle_id = BundleId::new("acme");
    let customer_id = CustomerId::new("cust-1");
    let env = EnvId::try_from("local").expect("env id");
    assert!(
        store
            .load_revenue_policy(&env, &bundle_id, &customer_id, 1)
            .await
            .expect("load v1")
            .is_some()
    );
    assert!(
        store
            .load_revenue_policy(&env, &bundle_id, &customer_id, 2)
            .await
            .expect("load v2")
            .is_none(),
        "no second version may exist after a replayed add"
    );
}

#[tokio::test]
async fn trust_root_remove_replay_preserves_the_recovery_pem() {
    // The 4.2f F2 hazard, closed: a lost remove response's PEM recovery
    // material is replayed, not re-derived from the now-keyless root.
    let (dir, store) = fresh_store().await;
    let store = Arc::new(store);
    let app = router_with_operator_key(Arc::clone(&store), dir.path().join("operator-key.pem"));
    create_local_env(&app).await;

    let (status, body) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/bootstrap",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let key_id = body["result"]["key_id"]
        .as_str()
        .expect("key id")
        .to_string();

    let remove_path = format!("/environments/local/trust-root/keys/{key_id}");
    let (status, original) = send_custom(
        app.clone(),
        Method::DELETE,
        &remove_path,
        None,
        &[("Idempotency-Key", "k-remove")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {original}");
    let pem = original["result"]["removed_public_key_pem"]
        .as_str()
        .expect("recovery PEM")
        .to_string();

    // Re-execution would now find nothing to remove (PEM = null); the
    // replay returns the ORIGINAL response, PEM included.
    let (status, replay) = send_custom(
        app,
        Method::DELETE,
        &remove_path,
        None,
        &[("Idempotency-Key", "k-remove")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {replay}");
    assert_eq!(replay["idempotency"]["idempotency"], "replayed");
    assert_eq!(replay["result"]["removed_public_key_pem"], pem.as_str());
}

#[tokio::test]
async fn domain_noop_with_fresh_key_is_journaled_for_replay() {
    // A fresh key naming already-converged state (here: trust-root seed on
    // an existing root) is a 200 no-op that still consumes its key — the
    // retry replays instead of re-evaluating against whatever state holds
    // later.
    let (dir, store) = fresh_store().await;
    let store = Arc::new(store);
    let app = router_with_operator_key(Arc::clone(&store), dir.path().join("operator-key.pem"));
    create_local_env(&app).await;

    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/bootstrap",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, original) = send_custom(
        app.clone(),
        Method::POST,
        "/environments/local/trust-root/seed",
        None,
        &[("Idempotency-Key", "k-seed-noop")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {original}");
    assert!(original["result"].is_null(), "existing root → null seed");

    let (status, replay) = send_custom(
        app,
        Method::POST,
        "/environments/local/trust-root/seed",
        None,
        &[("Idempotency-Key", "k-seed-noop")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {replay}");
    assert_eq!(replay["idempotency"]["idempotency"], "replayed");
    assert_eq!(replay["audit"]["event_id"], original["audit"]["event_id"]);
}
