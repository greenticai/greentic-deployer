//! End-to-end proof of the PR-4.2a remote env-lifecycle slice: the REAL
//! `HttpEnvironmentStore` client (blocking reqwest, A8 envelope + audit
//! validation) drives the REAL operator-store-server (axum + SQLite) over
//! a loopback listener — no mocks on either side.
//!
//! This is the wire-compatibility gate for the shared
//! `greentic_deploy_spec::engine` payload types: the client serializes
//! them, the server deserializes the same structs, and both apply the same
//! engine transforms. A drift in either direction fails here before it can
//! ship.

use std::sync::Arc;

use greentic_deploy_spec::{EnvId, EnvironmentHostConfig};
use greentic_deployer::environment::{
    AuthMethod, EnvironmentMutations, HttpEnvironmentStore, StoreError,
};
use greentic_deployer::environment::{FieldUpdate, MigrateMergePayload, UpdateEnvironmentPayload};
use greentic_operator_store_server::http::router;
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;
use url::Url;

fn env_id(raw: &str) -> EnvId {
    EnvId::try_from(raw).expect("valid env id")
}

fn host_config(raw: &str) -> EnvironmentHostConfig {
    EnvironmentHostConfig {
        env_id: env_id(raw),
        region: Some("eu-west-1".to_string()),
        tenant_org_id: None,
        listen_addr: None,
        public_base_url: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_env_lifecycle_end_to_end() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = SqliteEnvironmentStore::open(&dir.path().join("store.sqlite"))
        .await
        .expect("open sqlite store");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, router(Arc::new(store)))
            .await
            .expect("serve");
    });

    // The blocking reqwest client must not run on a tokio worker thread.
    tokio::task::spawn_blocking(move || {
        let base = Url::parse(&format!("http://{addr}/")).expect("base url");
        let store = HttpEnvironmentStore::new(base, AuthMethod::None).expect("client");
        let id = env_id("local");

        // Create — server runs engine::fresh_environment, client validates
        // the A8 envelope (audit binds env + idempotency key).
        let created = store
            .create_environment(&id, "local".to_string(), host_config("local"))
            .expect("create environment");
        assert_eq!(created.environment_id, id);
        assert_eq!(created.host_config.region.as_deref(), Some("eu-west-1"));

        // Duplicate create — server's 409 `already-exists` body maps onto
        // the same `Conflict` noun the local store uses.
        let err = store
            .create_environment(&id, "local".to_string(), host_config("local"))
            .expect_err("duplicate create must conflict");
        assert!(
            matches!(&err, StoreError::Conflict(msg) if msg.contains("already exists")),
            "unexpected error: {err:?}"
        );

        // Update — tri-state patch travels as the shared wire encoding
        // (Set → {"value"}, Clear → {"clear": true}, Keep → absent).
        let updated = store
            .update_environment(
                &id,
                UpdateEnvironmentPayload {
                    name: Some("renamed".to_string()),
                    region: FieldUpdate::Clear,
                    tenant_org_id: FieldUpdate::Set("org-1".to_string()),
                    listen_addr: FieldUpdate::Keep,
                    public_base_url: FieldUpdate::Keep,
                },
            )
            .expect("update environment");
        assert_eq!(updated.name, "renamed");
        assert_eq!(updated.host_config.region, None, "Clear must persist None");
        assert_eq!(updated.host_config.tenant_org_id.as_deref(), Some("org-1"));

        // Migrate-bindings without a seed against a missing env → NotFound.
        let err = store
            .migrate_merge_bindings(
                &env_id("ghost"),
                MigrateMergePayload {
                    packs: Vec::new(),
                    extensions: Vec::new(),
                    seed_if_missing: None,
                },
            )
            .expect_err("missing target without seed must be NotFound");
        assert!(
            matches!(err, StoreError::NotFound(_)),
            "unexpected error: {err:?}"
        );

        // Merge into the existing env (empty merge set — referential
        // fixtures for pack bindings live in the server-side route tests;
        // here the point is the verb's wire round-trip).
        let (slots, extensions) = store
            .migrate_merge_bindings(
                &id,
                MigrateMergePayload {
                    packs: Vec::new(),
                    extensions: Vec::new(),
                    seed_if_missing: None,
                },
            )
            .expect("merge into existing env");
        assert!(slots.is_empty() && extensions.is_empty());
    })
    .await
    .expect("client task");
}
