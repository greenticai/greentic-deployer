//! Axum surface for the operator store server.
//!
//! Health endpoints (`/healthz` liveness, `/readyz` storage-probing
//! readiness) plus the A8 verb routes from [`crate::api`]. PR-4.2a serves
//! the environment-lifecycle group; the remaining verb groups from the
//! route table pinned in the deployer's `environment::http_store` module
//! doc land group-by-group in PR-4.2b+.

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{delete, get, patch, post};
use axum::{Json, Router, extract::State, http::StatusCode};
use serde_json::{Value, json};

use crate::api;
use crate::storage::EnvironmentStorage;

/// Shared handler state. Manual `Clone` so `S` itself doesn't need to be
/// `Clone` — the `Arc` is what's cloned per request.
pub struct AppState<S> {
    pub storage: Arc<S>,
    /// Path of the SERVER's operator signing key — the trust-root
    /// bootstrap/seed verbs load (or first-time generate) it here.
    /// `None` falls back to the CLI's standard resolution
    /// (`GTC_OPERATOR_KEY_PATH` env var, else `~/.greentic/operator/key.pem`).
    pub operator_key_path: Option<Arc<PathBuf>>,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            operator_key_path: self.operator_key_path.clone(),
        }
    }
}

/// Build the server router over any [`EnvironmentStorage`] backend, with
/// the default operator-key resolution (see [`AppState::operator_key_path`]).
pub fn router<S>(storage: Arc<S>) -> Router
where
    S: EnvironmentStorage + 'static,
{
    build_router(storage, None)
}

/// [`router`] with an explicit operator-key path — the trust-root
/// bootstrap/seed verbs mint/load the server key there instead of the
/// per-user default. Tests and multi-instance deployments use this.
pub fn router_with_operator_key<S>(storage: Arc<S>, operator_key_path: PathBuf) -> Router
where
    S: EnvironmentStorage + 'static,
{
    build_router(storage, Some(Arc::new(operator_key_path)))
}

fn build_router<S>(storage: Arc<S>, operator_key_path: Option<Arc<PathBuf>>) -> Router
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
        .route("/environments/{env_id}/bundles", post(api::add_bundle::<S>))
        .route(
            "/environments/{env_id}/bundles/{deployment_id}",
            patch(api::update_bundle::<S>).delete(api::remove_bundle::<S>),
        )
        .route(
            "/environments/{env_id}/trust-root",
            get(api::get_trust_root::<S>),
        )
        .route(
            "/environments/{env_id}/trust-root/bootstrap",
            post(api::bootstrap_trust_root::<S>),
        )
        .route(
            "/environments/{env_id}/trust-root/seed",
            post(api::seed_trust_root::<S>),
        )
        .route(
            "/environments/{env_id}/trust-root/keys",
            post(api::add_trusted_key::<S>),
        )
        .route(
            "/environments/{env_id}/trust-root/keys/{key_id}",
            delete(api::remove_trusted_key::<S>),
        )
        .with_state(AppState {
            storage,
            operator_key_path,
        })
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
