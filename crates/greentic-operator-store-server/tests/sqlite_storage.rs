//! Integration tests for `SqliteEnvironmentStore`.
//!
//! Ported from the parked Postgres prototype's testcontainers suite
//! (`crates/greentic-environment-store-postgres/tests/integration.rs`).
//! Unlike that suite these need no Docker — each test gets its own
//! SQLite file in a `TempDir` (mirroring the per-test isolation shape of
//! the `LocalFsStore` tests) and runs in the default `cargo test` pass.
//!
//! All storage calls resolve through the [`EnvironmentStorage`] trait, so
//! the suite doubles as a compile-time proof that the SQLite backend
//! satisfies the trait's `Send` bounds.

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use greentic_deploy_spec::{
    BundleId, CapabilitySlot, ConcurrencyConflict, CustomerId, EnvId, EnvPackBinding, Environment,
    EnvironmentHostConfig, EnvironmentRuntime, PackDescriptor, PackId, Precondition, SchemaVersion,
    StateEtag,
};
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;
use greentic_operator_store_server::storage::{
    EnvironmentStorage, MutationJournal, RevenuePolicyArtifact, StorageError,
};
use greentic_operator_trust::test_support::keypair;
use greentic_operator_trust::trust_root::{TrustRootDocument, TrustedKey};
use serde_json::json;
use sqlx::Row;

mod common;
use common::fresh_store;

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
async fn create_then_load_round_trip() {
    let (_d, store) = fresh_store().await;
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
async fn create_twice_returns_already_exists() {
    let (_d, store) = fresh_store().await;
    let id = env_id("dup");
    let env = minimal_environment(&id);

    store.create_env(&env).await.expect("first create");
    let err = store
        .create_env(&env)
        .await
        .expect_err("second create must fail");
    let StorageError::AlreadyExists {
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
async fn update_with_matching_precondition_bumps_generation() {
    let (_d, store) = fresh_store().await;
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
async fn update_with_stale_precondition_returns_conflict() {
    let (_d, store) = fresh_store().await;
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
    let StorageError::PreconditionFailed { conflict, .. } = err else {
        panic!("expected PreconditionFailed, got: {err:?}");
    };
    let ConcurrencyConflict {
        actual_generation, ..
    } = conflict;
    assert_eq!(actual_generation, 2);
}

#[tokio::test]
async fn update_without_precondition_is_required_error() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    store.create_env(&env).await.expect("create");

    let blank = Precondition::default();
    let err = store
        .update_env(&env, &blank)
        .await
        .expect_err("blind write must reject");
    assert!(matches!(err, StorageError::PreconditionRequired));
}

#[tokio::test]
async fn update_missing_env_returns_not_found() {
    let (_d, store) = fresh_store().await;
    let id = env_id("ghost");
    let env = minimal_environment(&id);

    let pc = Precondition::matching(StateEtag("00".repeat(32)), 1);
    let err = store
        .update_env(&env, &pc)
        .await
        .expect_err("update of missing env must fail");
    let StorageError::NotFound(missing) = err else {
        panic!("expected NotFound, got: {err:?}");
    };
    assert_eq!(missing, id);
}

#[tokio::test]
async fn runtime_round_trip_with_cas() {
    let (_d, store) = fresh_store().await;
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
    assert!(matches!(err, StorageError::PreconditionRequired));
}

#[tokio::test]
async fn pack_answers_round_trip_with_cas() {
    let (_d, store) = fresh_store().await;
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
    assert!(matches!(err, StorageError::PreconditionFailed { .. }));

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
async fn list_envs_returns_sorted_ids() {
    let (_d, store) = fresh_store().await;
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

// --- stale-after-delete CAS bypass (Postgres-suite Finding 1) ---

#[tokio::test]
async fn upsert_pack_answers_after_delete_with_stale_precondition_returns_not_found() {
    let (_d, store) = fresh_store().await;
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
    let StorageError::NotFound(missing) = err else {
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

// --- ABA: delete/recreate generation continuity (tombstone) ---

#[tokio::test]
async fn recreate_after_delete_continues_generation_sequence() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    let answers = json!({"region": "eu-west-1"});
    let rev1 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, None)
        .await
        .expect("create answers (gen 1)");
    assert_eq!(rev1.generation, 1);

    // Delete (tombstone internally at gen 2).
    let pc_del = Precondition::matching(rev1.etag.clone(), rev1.generation);
    store
        .delete_pack_answers(&id, CapabilitySlot::Deployer, &pc_del)
        .await
        .expect("delete");

    // Unconditional re-upsert must continue from the tombstone generation.
    let answers2 = json!({"region": "us-east-1"});
    let rev3 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers2, None)
        .await
        .expect("recreate answers");
    assert_eq!(
        rev3.generation, 3,
        "generation must continue past tombstone"
    );

    let loaded = store
        .load_pack_answers(&id, CapabilitySlot::Deployer)
        .await
        .expect("load")
        .expect("present after recreate");
    assert_eq!(loaded.value, answers2);
    assert_eq!(loaded.revision.generation, 3);
}

#[tokio::test]
async fn stale_first_incarnation_precondition_rejected_after_recreate() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    // Create content A at gen 1.
    let content_a = json!({"region": "eu-west-1"});
    let rev1 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &content_a, None)
        .await
        .expect("create answers");
    assert_eq!(rev1.generation, 1);

    // Delete with rev1.
    let pc_del = Precondition::matching(rev1.etag.clone(), rev1.generation);
    store
        .delete_pack_answers(&id, CapabilitySlot::Deployer, &pc_del)
        .await
        .expect("delete");

    // Unconditional re-upsert with the SAME content A.
    let rev3 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &content_a, None)
        .await
        .expect("recreate with same content");
    assert_eq!(rev3.generation, 3);

    // Attempt CAS with stale rev1 precondition — etag matches (same
    // content!) but generation 1 != 3. This was the ABA hole.
    let stale = Precondition::matching(rev1.etag.clone(), rev1.generation);
    let err = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &content_a, Some(&stale))
        .await
        .expect_err("stale first-incarnation precondition must reject");
    assert!(
        matches!(err, StorageError::PreconditionFailed { .. }),
        "expected PreconditionFailed, got: {err:?}"
    );
}

#[tokio::test]
async fn delete_of_deleted_row_is_idempotent_without_generation_bump() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    let answers = json!({"region": "eu-west-1"});
    let rev1 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, None)
        .await
        .expect("create answers");

    let pc = Precondition::matching(rev1.etag.clone(), rev1.generation);
    store
        .delete_pack_answers(&id, CapabilitySlot::Deployer, &pc)
        .await
        .expect("first delete");

    // Second delete of the already-tombstoned row — idempotent, no gen bump.
    store
        .delete_pack_answers(&id, CapabilitySlot::Deployer, &pc)
        .await
        .expect("second delete (idempotent)");

    // Re-upsert must land at gen 3 (tombstone was gen 2; second delete
    // did NOT bump to gen 3).
    let rev3 = store
        .upsert_pack_answers(&id, CapabilitySlot::Deployer, &answers, None)
        .await
        .expect("recreate");
    assert_eq!(
        rev3.generation, 3,
        "second delete must not have bumped generation"
    );
}

// --- integrity digest tamper detection (Postgres-suite Finding 2) ---

#[tokio::test]
async fn load_runtime_detects_tampered_data() {
    let (_d, store) = fresh_store().await;
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
        matches!(err, StorageError::IntegrityMismatch { .. }),
        "expected IntegrityMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn load_pack_answers_detects_tampered_data() {
    let (_d, store) = fresh_store().await;
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
        matches!(err, StorageError::IntegrityMismatch { .. }),
        "expected IntegrityMismatch, got: {err:?}"
    );
}

// --- unknown-field injection (raw-first integrity check) ---

#[tokio::test]
async fn load_env_detects_unknown_field_injection() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    store.create_env(&env).await.expect("create env");

    // Inject an extra top-level key into the stored JSON without touching
    // integrity_digest. serde would silently drop the unknown field on
    // deserialization, so a post-typed hash check would miss this — only
    // the raw-first check catches it.
    let mut data: serde_json::Value =
        sqlx::query("SELECT data FROM environments WHERE env_id = $1")
            .bind(id.as_str())
            .fetch_one(store.pool())
            .await
            .expect("fetch")
            .try_get("data")
            .expect("data column");
    data.as_object_mut()
        .expect("object")
        .insert("__injected".to_string(), json!(true));
    sqlx::query("UPDATE environments SET data = $1 WHERE env_id = $2")
        .bind(&data)
        .bind(id.as_str())
        .execute(store.pool())
        .await
        .expect("inject");

    let err = store
        .load_env(&id)
        .await
        .expect_err("unknown-field injection must fail integrity check");
    assert!(
        matches!(err, StorageError::IntegrityMismatch { .. }),
        "expected IntegrityMismatch, got: {err:?}"
    );
}

// --- single-process ownership (sidecar flock) ---

#[tokio::test]
async fn second_open_of_same_file_is_rejected_while_lock_held() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("store.sqlite");

    let store_a = SqliteEnvironmentStore::open(&db_path)
        .await
        .expect("first open");

    // A second open of the same path must fail while A holds the lock.
    let err = SqliteEnvironmentStore::open(&db_path)
        .await
        .expect_err("second open must fail while lock is held");
    let msg = err.to_string();
    assert!(
        msg.contains("already locked"),
        "expected 'already locked' in error, got: {msg}"
    );

    // Drop store A (releases the flock via Arc<File> drop).
    drop(store_a);

    // Re-open should now succeed.
    let _store_b = SqliteEnvironmentStore::open(&db_path)
        .await
        .expect("re-open after drop must succeed");
}

// --- trust root (PR-4.2f) ---

fn trust_doc(seeds: &[u8]) -> TrustRootDocument {
    TrustRootDocument::v1(
        seeds
            .iter()
            .map(|&seed| {
                let (pem, id) = keypair(seed);
                TrustedKey {
                    key_id: id,
                    public_key_pem: pem,
                }
            })
            .collect(),
    )
}

#[tokio::test]
async fn trust_root_round_trip_with_cas() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    // Row absence is load-bearing (the seed-if-absent gate) — a fresh env
    // reads `None`, not an empty document.
    assert!(store.load_trust_root(&id).await.expect("load").is_none());

    let doc = trust_doc(&[1]);
    let rev1 = store
        .upsert_trust_root(&id, &doc, None)
        .await
        .expect("first upsert (no pc)");
    assert_eq!(rev1.generation, 1);

    let loaded = store
        .load_trust_root(&id)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(loaded.value, doc);
    assert_eq!(loaded.revision, rev1);

    let doc2 = trust_doc(&[1, 2]);
    let pc = Precondition::matching(rev1.etag.clone(), rev1.generation);
    let rev2 = store
        .upsert_trust_root(&id, &doc2, Some(&pc))
        .await
        .expect("second upsert");
    assert_eq!(rev2.generation, 2);

    let err = store
        .upsert_trust_root(&id, &doc2, None)
        .await
        .expect_err("missing pc on existing row must reject");
    assert!(matches!(err, StorageError::PreconditionRequired));
}

#[tokio::test]
async fn trust_root_conditional_upsert_on_absent_row_is_not_found() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    let pc = Precondition::matching(StateEtag("stale".to_string()), 1);
    let err = store
        .upsert_trust_root(&id, &trust_doc(&[3]), Some(&pc))
        .await
        .expect_err("conditional write against an absent row must reject");
    assert!(matches!(err, StorageError::NotFound(_)));
}

#[tokio::test]
async fn trust_root_stale_precondition_conflicts() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    let rev1 = store
        .upsert_trust_root(&id, &trust_doc(&[4]), None)
        .await
        .expect("first upsert");
    let stale = Precondition::matching(StateEtag("stale".to_string()), rev1.generation);
    let err = store
        .upsert_trust_root(&id, &trust_doc(&[4, 5]), Some(&stale))
        .await
        .expect_err("stale etag must conflict");
    let StorageError::PreconditionFailed { conflict, .. } = err else {
        panic!("expected PreconditionFailed, got: {err:?}");
    };
    let ConcurrencyConflict { actual_etag, .. } = conflict;
    assert_eq!(actual_etag, rev1.etag.0);
}

#[tokio::test]
async fn trust_root_rejects_unknown_schema() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    let mut doc = trust_doc(&[6]);
    doc.schema = "greentic.trust-root.v999".to_string();
    let err = store
        .upsert_trust_root(&id, &doc, None)
        .await
        .expect_err("unknown schema must reject before write");
    assert!(matches!(err, StorageError::Spec(_)), "got: {err:?}");
}

#[tokio::test]
async fn load_trust_root_detects_tampered_data() {
    let (_d, store) = fresh_store().await;
    let id = env_id("local");
    store
        .create_env(&minimal_environment(&id))
        .await
        .expect("create env");

    store
        .upsert_trust_root(&id, &trust_doc(&[7]), None)
        .await
        .expect("upsert trust root");

    // Tamper with the stored JSON without updating integrity_digest.
    sqlx::query("UPDATE trust_roots SET data = $1 WHERE env_id = $2")
        .bind(serde_json::to_value(trust_doc(&[8])).unwrap())
        .bind(id.as_str())
        .execute(store.pool())
        .await
        .expect("tamper");

    let err = store
        .load_trust_root(&id)
        .await
        .expect_err("tampered trust root must fail integrity check");
    assert!(
        matches!(err, StorageError::IntegrityMismatch { .. }),
        "expected IntegrityMismatch, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// revenue_policies (PR-4.2g)
// ---------------------------------------------------------------------------
//
// The artifact never lands alone: `update_env_with_revenue_policy` commits
// the artifact row, the environment CAS update, and a re-check of the
// trust-root revision the signature was evaluated against in ONE
// transaction (the server analogue of the LocalFS flock).

fn policy_artifact(version: u64, payload: &str) -> RevenuePolicyArtifact {
    RevenuePolicyArtifact {
        bundle_id: BundleId::new("acme"),
        customer_id: CustomerId::new("cust-1"),
        version,
        policy_ref: format!("billing-policies/acme/cust-1/v{version}.json.sig"),
        doc: payload.as_bytes().to_vec(),
        envelope: format!("envelope-{payload}").into_bytes(),
        doc_sha256: format!("sha-{payload}"),
        key_id: "deadbeef".to_string(),
    }
}

async fn load_policy(
    store: &SqliteEnvironmentStore,
    id: &EnvId,
    version: u64,
) -> Option<RevenuePolicyArtifact> {
    store
        .load_revenue_policy(
            id,
            &BundleId::new("acme"),
            &CustomerId::new("cust-1"),
            version,
        )
        .await
        .expect("load artifact")
}

#[tokio::test]
async fn revenue_policy_commits_with_env_and_round_trips_per_version() {
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    let rev1 = store.create_env(&env).await.expect("create env");

    // No trust-root row → pin is None.
    let rev2 = store
        .update_env_with_revenue_policy(
            &env,
            &Precondition::matching(rev1.etag.clone(), rev1.generation),
            &policy_artifact(1, "v1-doc"),
            None,
        )
        .await
        .expect("commit v1 + env");
    assert_eq!(rev2.generation, 2, "env CAS advanced with the artifact");

    let rev3 = store
        .update_env_with_revenue_policy(
            &env,
            &Precondition::matching(rev2.etag.clone(), rev2.generation),
            &policy_artifact(2, "v2-doc"),
            None,
        )
        .await
        .expect("commit v2 + env");
    assert_eq!(rev3.generation, 3);

    assert_eq!(
        load_policy(&store, &id, 1).await.expect("v1 present"),
        policy_artifact(1, "v1-doc")
    );
    assert_eq!(
        load_policy(&store, &id, 2).await.expect("v2 present").doc,
        b"v2-doc"
    );
    assert!(load_policy(&store, &id, 3).await.is_none());
    let other_customer = store
        .load_revenue_policy(&id, &BundleId::new("acme"), &CustomerId::new("other"), 1)
        .await
        .expect("load other");
    assert!(other_customer.is_none(), "keyed per (bundle, customer)");
}

#[tokio::test]
async fn revenue_policy_rolls_back_when_env_cas_fails() {
    // Codex F1: a CAS conflict on the environment must take the artifact
    // down with it — a committed env can never reference (or be shadowed
    // by) an artifact from a losing concurrent mutation.
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    let rev1 = store.create_env(&env).await.expect("create env");

    // Advance the env so the captured precondition goes stale.
    let rev2 = store
        .update_env(
            &env,
            &Precondition::matching(rev1.etag.clone(), rev1.generation),
        )
        .await
        .expect("advance env");
    assert_eq!(rev2.generation, 2);

    let err = store
        .update_env_with_revenue_policy(
            &env,
            &Precondition::matching(rev1.etag, rev1.generation), // stale
            &policy_artifact(1, "loser"),
            None,
        )
        .await
        .expect_err("stale CAS must fail");
    assert!(
        matches!(err, StorageError::PreconditionFailed { .. }),
        "expected PreconditionFailed, got: {err:?}"
    );
    assert!(
        load_policy(&store, &id, 1).await.is_none(),
        "artifact must roll back with the failed env CAS"
    );
}

#[tokio::test]
async fn revenue_policy_rejects_when_trust_root_moved_since_load() {
    // Codex F2: a trust-root mutation (e.g. revocation) between the
    // handler's load and the signing commit must invalidate the commit —
    // the pinned revision no longer matches.
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    let rev1 = store.create_env(&env).await.expect("create env");

    // The signer loaded the trust root at generation 1...
    let root_rev1 = store
        .upsert_trust_root(&id, &trust_doc(&[7]), None)
        .await
        .expect("seed trust root");
    // ...then a concurrent mutation (revocation) advanced it.
    store
        .upsert_trust_root(
            &id,
            &trust_doc(&[8]),
            Some(&Precondition::matching(
                root_rev1.etag.clone(),
                root_rev1.generation,
            )),
        )
        .await
        .expect("concurrent trust-root mutation");

    let err = store
        .update_env_with_revenue_policy(
            &env,
            &Precondition::matching(rev1.etag.clone(), rev1.generation),
            &policy_artifact(1, "stale-signature"),
            Some(&root_rev1), // pin from BEFORE the concurrent mutation
        )
        .await
        .expect_err("moved trust root must reject the commit");
    assert!(
        matches!(err, StorageError::TrustRootChanged { .. }),
        "expected TrustRootChanged, got: {err:?}"
    );
    assert!(
        load_policy(&store, &id, 1).await.is_none(),
        "nothing persists on a trust-root pin mismatch"
    );
    let env_after = store.load_env(&id).await.expect("load env");
    assert_eq!(env_after.revision.generation, 1, "env untouched");
}

#[tokio::test]
async fn revenue_policy_rejects_when_trust_root_appeared_since_load() {
    // The None-pin arm: the signer observed NO trust-root row (and could
    // only have refused — but the storage contract still rejects if a row
    // appeared, keeping the invariant unconditional).
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    let rev1 = store.create_env(&env).await.expect("create env");
    store
        .upsert_trust_root(&id, &trust_doc(&[7]), None)
        .await
        .expect("row appears after the signer's load");

    let err = store
        .update_env_with_revenue_policy(
            &env,
            &Precondition::matching(rev1.etag, rev1.generation),
            &policy_artifact(1, "doc"),
            None, // signer saw no row
        )
        .await
        .expect_err("appeared trust root must reject the commit");
    assert!(matches!(err, StorageError::TrustRootChanged { .. }));
}

#[tokio::test]
async fn revenue_policy_overwrites_replayed_version_under_matching_pin() {
    // Same-version rebuilds (a same-key retry after a lost response,
    // PR-4.3) overwrite the row rather than duplicate or error.
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    let rev1 = store.create_env(&env).await.expect("create env");

    let rev2 = store
        .update_env_with_revenue_policy(
            &env,
            &Precondition::matching(rev1.etag, rev1.generation),
            &policy_artifact(1, "first"),
            None,
        )
        .await
        .expect("first commit");
    store
        .update_env_with_revenue_policy(
            &env,
            &Precondition::matching(rev2.etag, rev2.generation),
            &policy_artifact(1, "rebuild"),
            None,
        )
        .await
        .expect("same-version rebuild overwrites");

    assert_eq!(
        load_policy(&store, &id, 1).await.expect("present").doc,
        b"rebuild"
    );
}

// ---------------------------------------------------------------------------
// Idempotency ledger + audit log (PR-4.3)
// ---------------------------------------------------------------------------

fn journal(id: &EnvId, key: &str, fingerprint: &str) -> MutationJournal {
    MutationJournal {
        env_id: id.clone(),
        idempotency_key: key.to_string(),
        operation: "env.update".to_string(),
        request_fingerprint: fingerprint.to_string(),
        response_status: 200,
        response_body: json!({"result": {"ok": true}, "idempotency": {"idempotency": "applied"}}),
        audit_event: json!({"event_id": format!("evt-{key}"), "verb": "update"}),
        audit_event_id: format!("evt-{key}"),
    }
}

async fn audit_event_ids(store: &SqliteEnvironmentStore, id: &EnvId) -> Vec<String> {
    sqlx::query("SELECT event_id FROM audit_log WHERE env_id = $1 ORDER BY id ASC")
        .bind(id.as_str())
        .fetch_all(store.pool())
        .await
        .expect("audit query")
        .into_iter()
        .map(|r| r.get::<String, _>("event_id"))
        .collect()
}

#[tokio::test]
async fn update_env_journaled_commits_ledger_and_audit_atomically() {
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    let rev = store.create_env(&env).await.expect("create env");

    env.name = "renamed".to_string();
    let journal = journal(&id, "k-1", "fp-1");
    store
        .update_env_journaled(
            &env,
            &Precondition::matching(rev.etag, rev.generation),
            Some(&journal),
        )
        .await
        .expect("journaled update");

    let record = store
        .lookup_idempotency(&id, "k-1")
        .await
        .expect("lookup")
        .expect("ledger row");
    assert_eq!(record.operation, "env.update");
    assert_eq!(record.request_fingerprint, "fp-1");
    assert_eq!(record.response_status, 200);
    assert_eq!(record.response_body, journal.response_body);
    assert_eq!(audit_event_ids(&store, &id).await, vec!["evt-k-1"]);
}

#[tokio::test]
async fn cas_conflict_rolls_the_journal_back_with_the_mutation() {
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    store.create_env(&env).await.expect("create env");

    env.name = "renamed".to_string();
    let err = store
        .update_env_journaled(
            &env,
            &Precondition::matching(StateEtag("stale".to_string()), 99),
            Some(&journal(&id, "k-lost", "fp")),
        )
        .await
        .expect_err("stale precondition");
    assert!(matches!(err, StorageError::PreconditionFailed { .. }));

    // The failed mutation consumed nothing: no ledger row, no audit row.
    assert!(
        store
            .lookup_idempotency(&id, "k-lost")
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(audit_event_ids(&store, &id).await.is_empty());
}

#[tokio::test]
async fn duplicate_ledger_key_rolls_back_the_whole_transaction() {
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    let rev = store.create_env(&env).await.expect("create env");

    env.name = "first".to_string();
    let rev2 = store
        .update_env_journaled(
            &env,
            &Precondition::matching(rev.etag, rev.generation),
            Some(&journal(&id, "k-dup", "fp-a")),
        )
        .await
        .expect("first commit");

    // Same key again (the concurrent-duplicate shape): the ledger PK
    // violation must abort the transaction — env row INCLUDED.
    env.name = "second".to_string();
    let err = store
        .update_env_journaled(
            &env,
            &Precondition::matching(rev2.etag.clone(), rev2.generation),
            Some(&journal(&id, "k-dup", "fp-b")),
        )
        .await
        .expect_err("duplicate key");
    assert!(matches!(err, StorageError::IdempotencyKeyCommitted { .. }));

    let loaded = store.load_env(&id).await.expect("load");
    assert_eq!(loaded.value.name, "first", "loser's env write rolled back");
    assert_eq!(loaded.revision.generation, rev2.generation);
    assert_eq!(audit_event_ids(&store, &id).await.len(), 1);
}

#[tokio::test]
async fn record_journal_standalone_round_trips() {
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");

    store
        .record_journal(&journal(&id, "k-noop", "fp-n"))
        .await
        .expect("standalone record");
    let record = store
        .lookup_idempotency(&id, "k-noop")
        .await
        .expect("lookup")
        .expect("row");
    assert_eq!(record.request_fingerprint, "fp-n");
    assert_eq!(audit_event_ids(&store, &id).await, vec!["evt-k-noop"]);

    // Unknown keys stay misses.
    assert!(
        store
            .lookup_idempotency(&id, "k-other")
            .await
            .expect("lookup")
            .is_none()
    );
}

#[tokio::test]
async fn create_env_journaled_journals_only_the_winning_create() {
    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);

    store
        .create_env_journaled(&env, Some(&journal(&id, "k-create", "fp-c")))
        .await
        .expect("create");
    assert!(
        store
            .lookup_idempotency(&id, "k-create")
            .await
            .expect("lookup")
            .is_some()
    );

    // The losing duplicate (different key) journals nothing.
    let err = store
        .create_env_journaled(&env, Some(&journal(&id, "k-create-2", "fp-c2")))
        .await
        .expect_err("already exists");
    assert!(matches!(err, StorageError::AlreadyExists { .. }));
    assert!(
        store
            .lookup_idempotency(&id, "k-create-2")
            .await
            .expect("lookup")
            .is_none()
    );
    assert_eq!(audit_event_ids(&store, &id).await.len(), 1);
}

#[tokio::test]
async fn ledger_evicts_beyond_the_per_env_window() {
    use greentic_operator_store_server::storage::MAX_LEDGER_ROWS_PER_ENV;

    let (_dir, store) = fresh_store().await;
    let id = env_id("local");
    let env = minimal_environment(&id);
    store.create_env(&env).await.expect("create env");

    let cap = MAX_LEDGER_ROWS_PER_ENV as usize;
    for i in 0..cap + 1 {
        store
            .record_journal(&journal(&id, &format!("k-{i}"), &format!("fp-{i}")))
            .await
            .expect("record journal");
    }

    // k-0 should be evicted, the last key should survive.
    assert!(
        store
            .lookup_idempotency(&id, "k-0")
            .await
            .expect("lookup")
            .is_none(),
        "k-0 should have been evicted"
    );
    assert!(
        store
            .lookup_idempotency(&id, &format!("k-{cap}"))
            .await
            .expect("lookup")
            .is_some(),
        "last key should survive"
    );

    // Row count for this env equals the cap.
    let count: i64 =
        sqlx::query("SELECT COUNT(*) AS cnt FROM idempotency_ledger WHERE env_id = $1")
            .bind(id.as_str())
            .fetch_one(store.pool())
            .await
            .expect("count")
            .get("cnt");
    assert_eq!(count, MAX_LEDGER_ROWS_PER_ENV);

    // Eviction is per-env: a journal under a second env id survives.
    let id2 = env_id("other");
    let env2 = minimal_environment(&id2);
    store.create_env(&env2).await.expect("create env2");
    store
        .record_journal(&journal(&id2, "k-other", "fp-other"))
        .await
        .expect("record other");
    assert!(
        store
            .lookup_idempotency(&id2, "k-other")
            .await
            .expect("lookup")
            .is_some(),
        "other env's key must survive"
    );
}
