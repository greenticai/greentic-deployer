//! HTTP scaffold tests: `/healthz` + `/readyz` over the SQLite backend.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use greentic_operator_store_server::http::router;
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;
use http_body_util::BodyExt;
use tower::util::ServiceExt;

async fn fresh_store() -> (tempfile::TempDir, SqliteEnvironmentStore) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let store = SqliteEnvironmentStore::open(&dir.path().join("store.sqlite"))
        .await
        .expect("open sqlite store");
    (dir, store)
}

async fn get_json(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("dispatch request");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let value = serde_json::from_slice(&bytes).expect("json body");
    (status, value)
}

#[tokio::test]
async fn healthz_reports_ok_without_touching_storage() {
    let (_d, store) = fresh_store().await;
    let (status, body) = get_json(router(Arc::new(store)), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "greentic-operator-store-server");
}

#[tokio::test]
async fn readyz_reports_ready_when_storage_answers() {
    let (_d, store) = fresh_store().await;
    let (status, body) = get_json(router(Arc::new(store)), "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
async fn readyz_reports_unready_when_storage_is_gone() {
    let (_d, store) = fresh_store().await;
    store.pool().close().await;
    let (status, body) = get_json(router(Arc::new(store)), "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "unready");
}
