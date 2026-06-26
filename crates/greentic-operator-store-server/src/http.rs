//! Axum surface for the operator store server.
//!
//! Health endpoints (`/healthz` liveness, `/readyz` storage-probing
//! readiness) plus the A8 verb routes from [`crate::api`] — the full route
//! table pinned in the deployer's `environment::http_store` module doc,
//! plus the backup/restore group (A8 #5, PR-4.4). Authorization
//! ([`crate::rbac::RbacEngine`]) is part of the shared [`AppState`]:
//! [`RouterOptions::rbac`] selects open-dev (default) or static-token
//! enforcement.

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{delete, get, patch, post};
use axum::{Json, Router, extract::State, http::StatusCode};
use serde_json::{Value, json};

use crate::api;
use crate::rbac::RbacEngine;
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
    /// Authorization engine (A8 #3): open-dev allows everything; static
    /// tokens fail closed.
    pub rbac: Arc<RbacEngine>,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            operator_key_path: self.operator_key_path.clone(),
            rbac: Arc::clone(&self.rbac),
        }
    }
}

/// Optional router configuration beyond the storage backend.
pub struct RouterOptions {
    /// See [`AppState::operator_key_path`].
    pub operator_key_path: Option<PathBuf>,
    /// See [`AppState::rbac`]. Defaults to [`RbacEngine::open_dev`].
    pub rbac: RbacEngine,
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self {
            operator_key_path: None,
            rbac: RbacEngine::open_dev(),
        }
    }
}

/// Build the server router over any [`EnvironmentStorage`] backend with
/// default options (open-dev RBAC, standard operator-key resolution).
pub fn router<S>(storage: Arc<S>) -> Router
where
    S: EnvironmentStorage + 'static,
{
    router_with_options(storage, RouterOptions::default())
}

/// [`router`] with an explicit operator-key path — the trust-root
/// bootstrap/seed verbs mint/load the server key there instead of the
/// per-user default. Tests and multi-instance deployments use this.
pub fn router_with_operator_key<S>(storage: Arc<S>, operator_key_path: PathBuf) -> Router
where
    S: EnvironmentStorage + 'static,
{
    router_with_options(
        storage,
        RouterOptions {
            operator_key_path: Some(operator_key_path),
            ..RouterOptions::default()
        },
    )
}

/// [`router`] with full [`RouterOptions`].
pub fn router_with_options<S>(storage: Arc<S>, options: RouterOptions) -> Router
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
        .route("/environments/{env_id}/runtime", get(api::get_runtime::<S>))
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
            "/environments/{env_id}/messaging",
            post(api::add_messaging_endpoint::<S>),
        )
        .route(
            "/environments/{env_id}/messaging/{endpoint_id}",
            delete(api::remove_messaging_endpoint::<S>),
        )
        .route(
            "/environments/{env_id}/messaging/{endpoint_id}/link",
            post(api::link_messaging_bundle::<S>),
        )
        .route(
            "/environments/{env_id}/messaging/{endpoint_id}/unlink",
            post(api::unlink_messaging_bundle::<S>),
        )
        .route(
            "/environments/{env_id}/messaging/{endpoint_id}/welcome-flow",
            post(api::set_messaging_welcome_flow::<S>),
        )
        .route(
            "/environments/{env_id}/messaging/{endpoint_id}/rotate-secret",
            post(api::rotate_messaging_webhook_secret::<S>),
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
        .route(
            "/environments/{env_id}/backups",
            get(api::list_backups::<S>).post(api::create_backup::<S>),
        )
        .route(
            "/environments/{env_id}/backups/{backup_id}",
            delete(api::delete_backup::<S>),
        )
        .route(
            "/environments/{env_id}/backups/{backup_id}/export",
            get(api::export_backup::<S>),
        )
        .route(
            "/environments/{env_id}/restore",
            post(api::restore_environment::<S>),
        )
        .route(
            "/environments/{env_id}/import",
            post(api::import_environment::<S>),
        )
        .with_state(AppState {
            storage,
            operator_key_path: options.operator_key_path.map(Arc::new),
            rbac: Arc::new(options.rbac),
        })
}

/// Liveness: the process is up. Deliberately storage-free (and
/// deliberately unauthenticated, like `/readyz` — orchestrator probes
/// carry no tokens and the endpoints expose no environment state).
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
