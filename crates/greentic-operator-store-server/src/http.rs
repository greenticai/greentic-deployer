//! Axum surface for the operator store server.
//!
//! Health endpoints (`/healthz` liveness, `/readyz` storage-probing
//! readiness) plus the A8 verb routes from [`crate::api`]. PR-4.2a serves
//! the environment-lifecycle group; the remaining verb groups from the
//! route table pinned in the deployer's `environment::http_store` module
//! doc land group-by-group in PR-4.2b+.

use std::sync::Arc;

use axum::routing::{get, patch, post};
use axum::{Json, Router, extract::State, http::StatusCode};
use serde_json::{Value, json};

use crate::api;
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
        .route(
            "/environments",
            get(api::list_environments::<S>).post(api::create_environment::<S>),
        )
        .route(
            "/environments/{env_id}",
            get(api::get_environment::<S>).patch(api::update_environment::<S>),
        )
        .route(
            "/environments/{env_id}/migrate-bindings",
            post(api::migrate_bindings::<S>),
        )
        .route(
            "/environments/{env_id}/revisions",
            post(api::stage_revision::<S>),
        )
        .route(
            "/environments/{env_id}/revisions/{revision_id}/warm",
            post(api::warm_revision::<S>),
        )
        .route(
            "/environments/{env_id}/revisions/{revision_id}/drain",
            post(api::drain_revision::<S>),
        )
        .route(
            "/environments/{env_id}/revisions/{revision_id}/archive",
            post(api::archive_revision::<S>),
        )
        .route(
            "/environments/{env_id}/traffic",
            post(api::set_traffic_split::<S>),
        )
        .route(
            "/environments/{env_id}/traffic/rollback",
            post(api::rollback_traffic_split::<S>),
        )
        .route(
            "/environments/{env_id}/packs",
            post(api::add_pack_binding::<S>),
        )
        .route(
            "/environments/{env_id}/packs/{slot}",
            patch(api::update_pack_binding::<S>).delete(api::remove_pack_binding::<S>),
        )
        .route(
            "/environments/{env_id}/packs/{slot}/rollback",
            post(api::rollback_pack_binding::<S>),
        )
        .route(
            "/environments/{env_id}/extensions",
            post(api::add_extension_binding::<S>)
                .patch(api::update_extension_binding::<S>)
                .delete(api::remove_extension_binding::<S>),
        )
        .route(
            "/environments/{env_id}/extensions/rollback",
            post(api::rollback_extension_binding::<S>),
        )
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
