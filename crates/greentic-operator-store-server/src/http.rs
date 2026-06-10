//! Axum surface for the operator store server.
//!
//! PR-4.1 scaffold: liveness (`/healthz`) + readiness (`/readyz`, pings
//! the storage backend). The 28 A8 mutation/read routes (pinned in the
//! deployer's `environment::http_store` module doc) land in PR-4.2+.

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};

use crate::storage::EnvironmentStorage;

/// Shared handler state. Manual `Clone` so `S` itself doesn't need to be
/// `Clone` — the `Arc` is what's cloned per request.
pub struct AppState<S> {
    pub storage: Arc<S>,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
        }
    }
}

/// Build the server router over any [`EnvironmentStorage`] backend.
pub fn router<S>(storage: Arc<S>) -> Router
where
    S: EnvironmentStorage + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<S>))
        .with_state(AppState { storage })
}

/// Liveness: the process is up. Deliberately storage-free.
async fn healthz() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Readiness: the storage backend answers a probe.
async fn readyz<S>(State(state): State<AppState<S>>) -> (StatusCode, Json<Value>)
where
    S: EnvironmentStorage,
{
    match state.storage.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unready", "error": err.to_string() })),
        ),
    }
}
