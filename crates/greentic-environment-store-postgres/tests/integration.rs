//! Integration tests for `PostgresEnvironmentStore`.
//!
//! These tests spin up a Postgres container via `testcontainers` and exercise
//! the full CRUD + CAS surface. They are marked `#[ignore]` so the default
//! `cargo test` run skips them — Docker isn't always available in CI. Run
//! locally with:
//!
//! ```text
//! cargo test -p greentic-environment-store-postgres -- --ignored
//! ```

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use greentic_deploy_spec::{
    CapabilitySlot, ConcurrencyConflict, EnvId, EnvPackBinding, Environment, EnvironmentHostConfig,
    EnvironmentRuntime, PackDescriptor, PackId, Precondition, SchemaVersion, StateEtag,
};
use greentic_environment_store_postgres::{PgStoreError, PostgresEnvironmentStore};
use serde_json::json;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres as PgImage;

async fn fresh_store() -> (
    testcontainers::ContainerAsync<PgImage>,
    PostgresEnvironmentStore,
) {
    let container = PgImage::default()
        .start()
        .await
        .expect("start postgres container");
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("container port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let store = PostgresEnvironmentStore::connect(&url)
        .await
        .expect("connect");
    store.migrate().await.expect("migrate");
    (container, store)
}

fn env_id(s: &str) -> EnvId {
    EnvId::try_from(s).expect("valid env id")
}

fn pack_descriptor(s: &str) -> PackDescriptor {
    s.parse().expect("valid pack descriptor")
}

fn minimal_environment(id: &EnvId) -> Environment {
    Environment {
        schema: SchemaVersion::from(SchemaVersion::ENVIRONMENT_V1),
        environment_id: id.clone(),
        name: id.as_str().to_string(),
        host_config: EnvironmentHostConfig {
            env_id: id.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
            default_bundle: None,
        },
        packs: vec![EnvPackBinding {
            slot: CapabilitySlot::Deployer,
            kind: pack_descriptor("greentic.deployer.local-process@1.0.0"),
            pack_ref: PackId::new("local-process"),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        }],
        credentials_ref: None,
        bundles: vec![],
        revisions: vec![],
        traffic_splits: vec![],
        messaging_endpoints: vec![],
        extensions: vec![],
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}

fn minimal_runtime(id: &EnvId) -> EnvironmentRuntime {
    EnvironmentRuntime {
        schema: SchemaVersion::from(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
        environment_id: id.clone(),
        discovered: BTreeMap::new(),
        generated_at: Utc.with_ymd_and_hms(2026, 6, 9, 0, 0, 0).unwrap(),
        generated_by: pack_descriptor("greentic.deployer.local-process@1.0.0"),
        generation: 1,
    }
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn create_then_load_round_trip() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);

    let rev = store.create_env(&env).await.expect("create");
    assert_eq!(rev.generation, 1);
    assert!(store.exists(&id).await.expect("exists"));

    let loaded = store.load_env(&id).await.expect("load");
    assert_eq!(loaded.value, env);
    assert_eq!(loaded.revision, rev);
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn create_twice_returns_already_exists() {
    let (_c, store) = fresh_store().await;
    let id = env_id("dup");
    let env = minimal_environment(&id);

    store.create_env(&env).await.expect("first create");
    let err = store
        .create_env(&env)
        .await
        .expect_err("second create must fail");
    let PgStoreError::AlreadyExists {
        env_id: e,
        generation,
    } = err
    else {
        panic!("expected AlreadyExists, got: {err:?}");
    };
    assert_eq!(e, id);
    assert_eq!(generation, 1);
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn update_with_matching_precondition_bumps_generation() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    let rev1 = store.create_env(&env).await.expect("create");

    env.name = "renamed".to_string();
    let pc = Precondition::matching(rev1.etag.clone(), rev1.generation);
    let rev2 = store.update_env(&env, &pc).await.expect("update");
    assert_eq!(rev2.generation, 2);
    assert_ne!(rev2.etag, rev1.etag);

    let loaded = store.load_env(&id).await.expect("load");
    assert_eq!(loaded.value.name, "renamed");
    assert_eq!(loaded.revision.generation, 2);
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn update_with_stale_precondition_returns_conflict() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    let rev1 = store.create_env(&env).await.expect("create");

    // First successful update bumps to gen 2.
    env.name = "first-rename".to_string();
    let pc1 = Precondition::matching(rev1.etag.clone(), rev1.generation);
    store.update_env(&env, &pc1).await.expect("update 1");

    // Second attempt with the stale (gen-1) precondition must fail.
    env.name = "second-rename".to_string();
    let stale = Precondition::matching(rev1.etag, rev1.generation);
    let err = store
        .update_env(&env, &stale)
        .await
        .expect_err("stale precondition must reject");
    let PgStoreError::PreconditionFailed { conflict, .. } = err else {
        panic!("expected PreconditionFailed, got: {err:?}");
    };
    let ConcurrencyConflict {
        actual_generation, ..
    } = conflict;
    assert_eq!(actual_generation, 2);
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn update_without_precondition_is_required_error() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    store.create_env(&env).await.expect("create");

    let blank = Precondition::default();
    let err = store
        .update_env(&env, &blank)
        .await
        .expect_err("blind write must reject");
    assert!(matches!(err, PgStoreError::PreconditionRequired));
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn update_missing_env_returns_not_found() {
    let (_c, store) = fresh_store().await;
    let id = env_id("ghost");
    let env = minimal_environment(&id);

    let pc = Precondition::matching(StateEtag("00".repeat(32)), 1);
    let err = store
        .update_env(&env, &pc)
        .await
        .expect_err("update of missing env must fail");
    let PgStoreError::NotFound(missing) = err else {
        panic!("expected NotFound, got: {err:?}");
    };
    assert_eq!(missing, id);
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn runtime_round_trip_with_cas() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    store.create_env(&env).await.expect("create env");

    assert!(store.load_runtime(&id).await.expect("load").is_none());

    let mut runtime = minimal_runtime(&id);
    let rev1 = store
        .upsert_runtime(&runtime, None)
        .await
        .expect("first upsert (no pc)");
    assert_eq!(rev1.generation, 1);

    let loaded = store
        .load_runtime(&id)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(loaded.revision, rev1);

    runtime
        .discovered
        .insert("listen_addr".to_string(), serde_json::json!("127.0.0.1:0"));
    let pc = Precondition::matching(rev1.etag.clone(), rev1.generation);
    let rev2 = store
        .upsert_runtime(&runtime, Some(&pc))
        .await
        .expect("second upsert");
    assert_eq!(rev2.generation, 2);

    let err = store
        .upsert_runtime(&runtime, None)
        .await
        .expect_err("missing pc on existing row must reject");
    assert!(matches!(err, PgStoreError::PreconditionRequired));
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn pack_answers_round_trip_with_cas() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    store.create_env(&env).await.expect("create env");

    assert!(
        store
            .load_pack_answers(&id, CapabilitySlot::Deployer)
            .await
            .expect("load")
            .is_none()
    );

    let answers = json!({"region": "eu-west-1"});
    let rev1 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, None)
        .await
        .expect("first upsert");
    assert_eq!(rev1.generation, 1);

    let answers2 = json!({"region": "eu-west-2"});
    let pc = Precondition::matching(rev1.etag.clone(), rev1.generation);
    let rev2 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers2, Some(&pc))
        .await
        .expect("second upsert");
    assert_eq!(rev2.generation, 2);

    let loaded = store
        .load_pack_answers(&id, CapabilitySlot::Deployer)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(loaded.value, answers2);

    // Stale pc → conflict.
    let stale = Precondition::matching(rev1.etag.clone(), rev1.generation);
    let err = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, Some(&stale))
        .await
        .expect_err("stale must reject");
    assert!(matches!(err, PgStoreError::PreconditionFailed { .. }));

    // Delete with current precondition.
    let pc2 = Precondition::matching(rev2.etag.clone(), rev2.generation);
    store
        .delete_pack_answers(&id, CapabilitySlot::Deployer, &pc2)
        .await
        .expect("delete");
    assert!(
        store
            .load_pack_answers(&id, CapabilitySlot::Deployer)
            .await
            .expect("load after delete")
            .is_none()
    );

    // Delete of missing row is idempotent.
    store
        .delete_pack_answers(&id, CapabilitySlot::Deployer, &pc2)
        .await
        .expect("idempotent delete");
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn list_envs_returns_sorted_ids() {
    let (_c, store) = fresh_store().await;
    for n in ["c", "a", "b"] {
        let id = env_id(n);
        store
            .create_env(&minimal_environment(&id))
            .await
            .expect("create");
    }
    let ids = store.list_envs().await.expect("list");
    let names: Vec<&str> = ids.iter().map(|i| i.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c"]);
}

// --- Finding 1: stale-after-delete CAS bypass ---

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn upsert_pack_answers_after_delete_with_stale_precondition_returns_not_found() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    // Create answers, then delete them.
    let answers = json!({"region": "eu-west-1"});
    let rev1 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, None)
        .await
        .expect("create answers");
    let pc_delete = Precondition::matching(rev1.etag.clone(), rev1.generation);
    store
        .delete_pack_answers(&id, CapabilitySlot::Deployer, &pc_delete)
        .await
        .expect("delete answers");

    // Attempt to upsert with the OLD (pre-delete) precondition.
    // This must NOT silently resurrect the row — it should return NotFound.
    let stale = Precondition::matching(rev1.etag.clone(), rev1.generation);
    let err = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, Some(&stale))
        .await
        .expect_err("conditional upsert on deleted row must fail");
    let PgStoreError::NotFound(missing) = err else {
        panic!("expected NotFound, got: {err:?}");
    };
    assert_eq!(missing, id);

    // Verify no row was resurrected.
    assert!(
        store
            .load_pack_answers(&id, CapabilitySlot::Deployer)
            .await
            .expect("load")
            .is_none()
    );
}

// --- Finding 2: integrity digest tamper detection ---

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn load_runtime_detects_tampered_data() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    let runtime = minimal_runtime(&id);
    store
        .upsert_runtime(&runtime, None)
        .await
        .expect("upsert runtime");

    // Tamper: write a valid-but-different runtime so deserialization
    // succeeds but the integrity digest no longer matches.
    let mut tampered = minimal_runtime(&id);
    tampered.generation = 999;
    let tampered_json = serde_json::to_value(&tampered).unwrap();
    sqlx::query("UPDATE environment_runtimes SET data = $1 WHERE env_id = $2")
        .bind(&tampered_json)
        .bind(id.as_str())
        .execute(store.pool())
        .await
        .expect("tamper");

    let err = store
        .load_runtime(&id)
        .await
        .expect_err("tampered runtime must fail integrity check");
    assert!(
        matches!(err, PgStoreError::IntegrityMismatch { .. }),
        "expected IntegrityMismatch, got: {err:?}"
    );
}

#[tokio::test]
#[ignore = "requires Docker for testcontainers Postgres"]
async fn load_pack_answers_detects_tampered_data() {
    let (_c, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    let answers = json!({"region": "eu-west-1"});
    store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, None)
        .await
        .expect("upsert answers");

    // Tamper with the stored JSON without updating integrity_digest.
    sqlx::query("UPDATE pack_answers SET data = $1 WHERE env_id = $2 AND slot = $3")
        .bind(serde_json::to_value(json!({"tampered": true})).unwrap())
        .bind(id.as_str())
        .bind(CapabilitySlot::Deployer.as_str())
        .execute(store.pool())
        .await
        .expect("tamper");

    let err = store
        .load_pack_answers(&id, CapabilitySlot::Deployer)
        .await
        .expect_err("tampered answers must fail integrity check");
    assert!(
        matches!(err, PgStoreError::IntegrityMismatch { .. }),
        "expected IntegrityMismatch, got: {err:?}"
    );
}
