//! End-to-end proof of the PR-4.2a/4.2b remote slices: the REAL
//! `HttpEnvironmentStore` client (blocking reqwest, A8 envelope + audit
//! validation) drives the REAL operator-store-server (axum + SQLite) over
//! a loopback listener — no mocks on either side.
//!
//! This is the wire-compatibility gate for the shared
//! `greentic_deploy_spec::engine` payload types: the client serializes
//! them, the server deserializes the same structs, and both apply the same
//! engine transforms. A drift in either direction fails here before it can
//! ship.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
    EnvironmentHostConfig, IdempotencyKey, PackListEntry, PartyId, Precondition, RevenueShareEntry,
    RevisionId, RevisionLifecycle, RouteBinding, SchemaVersion, SemVer, TenantSelector,
};
use greentic_deployer::environment::{
    AuthMethod, EnvironmentMutations, HealthCheckId, HealthGateFailure, HttpEnvironmentStore,
    LifecycleError, StoreError,
};
use greentic_deployer::environment::{
    FieldUpdate, MigrateMergePayload, StageRevisionPayload, UpdateEnvironmentPayload,
    WarmRevisionPayload,
};
use greentic_operator_store_server::http::router;
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;
use greentic_operator_store_server::storage::EnvironmentStorage;
use url::Url;

fn env_id(raw: &str) -> EnvId {
    EnvId::try_from(raw).expect("valid env id")
}

fn idem(raw: &str) -> IdempotencyKey {
    IdempotencyKey::new(raw).expect("valid idempotency key")
}

fn stage_payload(deployment_id: DeploymentId) -> StageRevisionPayload {
    StageRevisionPayload {
        revision_id: RevisionId::new(),
        deployment_id,
        bundle_digest: "sha256:00".to_string(),
        pack_list: vec![PackListEntry {
            pack_id: greentic_deploy_spec::PackId::new("greentic.test.pack"),
            version: SemVer::new(1, 0, 0),
            digest: "sha256:00".to_string(),
            source_uri: None,
        }],
        pack_list_lock_ref: PathBuf::from("pack-list.lock"),
        pack_config_refs: Vec::new(),
        config_digest: "sha256:00".to_string(),
        signature_sidecar_ref: PathBuf::from("rev.sig"),
        drain_seconds: 30,
    }
}

/// Seed a bundle deployment into an existing env directly through the
/// server's storage backend — the bundles verb group has no server route
/// yet (PR-4.2c+).
async fn seed_deployment(backend: &SqliteEnvironmentStore, id: &EnvId) -> DeploymentId {
    let loaded = backend.load_env(id).await.expect("load env");
    let mut env = loaded.value;
    let deployment_id = DeploymentId::new();
    env.bundles.push(BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id,
        env_id: id.clone(),
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
    let precondition = Precondition::matching(loaded.revision.etag, loaded.revision.generation);
    backend
        .update_env(&env, &precondition)
        .await
        .expect("seed deployment");
    deployment_id
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
    let backend = Arc::new(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let serve_backend = Arc::clone(&backend);
    tokio::spawn(async move {
        axum::serve(listener, router(serve_backend))
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

    // ----- PR-4.2b: the revision verb group over the same wire. -----

    let id = env_id("local");
    let deployment_id = seed_deployment(&backend, &id).await;

    let client_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let base = Url::parse(&format!("http://{addr}/")).expect("base url");
        let store = HttpEnvironmentStore::new(base, AuthMethod::None).expect("client");
        let id = client_id;

        // Stage — server resolves the deployment, assigns sequence 1.
        let staged = store
            .stage_revision(&id, stage_payload(deployment_id), idem("k-stage-1"))
            .expect("stage revision");
        assert_eq!(staged.lifecycle, RevisionLifecycle::Staged);
        assert_eq!(staged.sequence, 1);

        // Warm with a FAILING gate — the server persists the `Failed` flip
        // and the client reconstructs the SAME typed error the local store
        // raises (`StoreError::Lifecycle(HealthGateFailed)`), so the CLI's
        // committed-on-error handling behaves identically remotely.
        let err = store
            .warm_revision(
                &id,
                WarmRevisionPayload {
                    revision_id: staged.revision_id,
                    health_gate: Err(HealthGateFailure {
                        failed_checks: vec![HealthCheckId::RouteTable],
                        message: "route table invalid".to_string(),
                    }),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem("k-warm-fail"),
            )
            .expect_err("failing gate must surface");
        assert!(
            matches!(
                &err,
                StoreError::Lifecycle(inner) if matches!(
                    inner.as_ref(),
                    LifecycleError::HealthGateFailed { failed_checks, .. }
                        if failed_checks == &vec![HealthCheckId::RouteTable]
                )
            ),
            "unexpected error: {err:?}"
        );

        // Stage a second revision and walk it Staged → Ready → Draining →
        // Archived through the remote verbs.
        let rev = store
            .stage_revision(&id, stage_payload(deployment_id), idem("k-stage-2"))
            .expect("stage second revision");
        assert_eq!(rev.sequence, 2);

        let warmed = store
            .warm_revision(
                &id,
                WarmRevisionPayload {
                    revision_id: rev.revision_id,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem("k-warm-ok"),
            )
            .expect("warm revision");
        assert_eq!(warmed.revision.lifecycle, RevisionLifecycle::Ready);
        assert!(warmed.revision.warmed_at.is_some());
        assert_eq!(warmed.starting_lifecycle, RevisionLifecycle::Staged);

        let drained = store
            .drain_revision(&id, rev.revision_id, idem("k-drain"))
            .expect("drain revision");
        assert_eq!(drained.revision.lifecycle, RevisionLifecycle::Draining);

        let archived = store
            .archive_revision(&id, rev.revision_id, idem("k-archive"))
            .expect("archive revision");
        assert_eq!(archived.revision.lifecycle, RevisionLifecycle::Archived);
        assert_eq!(archived.starting_lifecycle, RevisionLifecycle::Draining);

        // Unknown revision → the server's 404 `dependent-not-found` maps to
        // the same noun the local store uses.
        let err = store
            .drain_revision(&id, RevisionId::new(), idem("k-drain-ghost"))
            .expect_err("unknown revision must be dependent-not-found");
        assert!(
            matches!(err, StoreError::DependentNotFound(_)),
            "unexpected error: {err:?}"
        );

        staged.revision_id
    })
    .await
    .map(|failed_rev| async move {
        // The gate failure's `Failed` flip is durable on the server.
        let loaded = backend.load_env(&id).await.expect("load env");
        let failed = loaded
            .value
            .revisions
            .iter()
            .find(|r| r.revision_id == failed_rev)
            .expect("failed revision persisted");
        assert_eq!(failed.lifecycle, RevisionLifecycle::Failed);
    })
    .expect("revision client task")
    .await;
}
