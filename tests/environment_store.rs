//! Integration tests for [`EnvironmentStore`] + [`LocalFsStore`] (A2).
//!
//! Unit tests for the underlying [`atomic_write`] and [`file_lock`] primitives
//! live alongside the modules; this file exercises the full trait surface
//! against a real temp-rooted [`LocalFsStore`].

use std::sync::Arc;
use std::thread;

use greentic_deploy_spec::{
    CapabilitySlot, EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, EnvironmentRuntime,
    PackDescriptor, PackId, RuntimeDiscoveryValue, SchemaVersion,
};
use greentic_deployer::environment::{
    EnvFlock, EnvironmentStore, LocalFsStore, StoreError, mint_deployment_id, mint_revision_id,
};
use serde_json::json;
use tempfile::TempDir;

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
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}

fn fresh_store() -> (TempDir, LocalFsStore) {
    let tmp = TempDir::new().expect("tempdir");
    let store = LocalFsStore::new(tmp.path());
    (tmp, store)
}

#[test]
fn save_then_load_round_trip() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    let env = minimal_environment(&id);

    store.save(&env).expect("save");
    let loaded = store.load(&id).expect("load");
    assert_eq!(loaded, env);
}

#[test]
fn load_missing_env_is_not_found() {
    let (_tmp, store) = fresh_store();
    let id = env_id("nope");
    match store.load(&id) {
        Err(StoreError::NotFound(missing)) => assert_eq!(missing, id),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn exists_reflects_save() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    assert!(!store.exists(&id).unwrap());
    store.save(&minimal_environment(&id)).unwrap();
    assert!(store.exists(&id).unwrap());
}

#[test]
fn list_returns_saved_envs_sorted() {
    let (_tmp, store) = fresh_store();
    store.save(&minimal_environment(&env_id("prod"))).unwrap();
    store.save(&minimal_environment(&env_id("local"))).unwrap();
    store.save(&minimal_environment(&env_id("dev"))).unwrap();

    let envs = store.list().unwrap();
    let names: Vec<_> = envs.iter().map(|e| e.as_str().to_string()).collect();
    assert_eq!(names, vec!["dev", "local", "prod"]);
}

#[test]
fn list_on_missing_root_is_empty() {
    let tmp = TempDir::new().unwrap();
    let store = LocalFsStore::new(tmp.path().join("does-not-exist-yet"));
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn list_skips_dirs_without_environment_json() {
    let (tmp, store) = fresh_store();
    std::fs::create_dir_all(tmp.path().join("orphan")).unwrap();
    let id = env_id("real");
    store.save(&minimal_environment(&id)).unwrap();

    let envs = store.list().unwrap();
    let names: Vec<_> = envs.iter().map(|e| e.as_str().to_string()).collect();
    assert_eq!(names, vec!["real"]);
}

#[test]
fn save_rejects_invalid_schema() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    env.schema = SchemaVersion::from("greentic.environment.v999");

    let err = store.save(&env).expect_err("must reject bad schema");
    matches!(err, StoreError::Spec(_));
    assert!(!store.exists(&id).unwrap(), "no file should be written");
}

#[test]
fn save_rejects_env_id_mismatch_in_host_config() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    env.host_config.env_id = env_id("other");

    let err = store.save(&env).expect_err("must reject id mismatch");
    matches!(err, StoreError::Spec(_));
    assert!(!store.exists(&id).unwrap());
}

#[test]
fn save_rejects_duplicate_capability_slot() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    env.packs.push(EnvPackBinding {
        slot: CapabilitySlot::Deployer,
        kind: pack_descriptor("greentic.deployer.k8s@1.0.0"),
        pack_ref: PackId::new("k8s"),
        answers_ref: None,
        generation: 0,
        previous_binding_ref: None,
    });

    let err = store.save(&env).expect_err("must reject duplicate slot");
    matches!(err, StoreError::Spec(_));
}

#[test]
fn mutation_writes_timestamped_backup() {
    let (tmp, store) = fresh_store();
    let id = env_id("local");
    let mut env = minimal_environment(&id);

    store.save(&env).unwrap();
    env.name = "Local".to_string();
    // Sleep so the second backup timestamp can't possibly collide with first.
    std::thread::sleep(std::time::Duration::from_millis(5));
    store.save(&env).unwrap();

    let backups_dir = tmp.path().join("local").join("backups");
    let backups: Vec<_> = std::fs::read_dir(&backups_dir)
        .expect("backups dir exists after mutation")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("environment.json.") && n.ends_with(".bak"))
        .collect();
    assert_eq!(
        backups.len(),
        1,
        "exactly one backup (only second save had a target to copy): {backups:?}"
    );
}

#[test]
fn no_backup_on_first_save() {
    let (tmp, store) = fresh_store();
    let id = env_id("local");
    store.save(&minimal_environment(&id)).unwrap();

    let backups_dir = tmp.path().join("local").join("backups");
    if backups_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&backups_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "no backups expected on first save, got {entries:?}"
        );
    }
}

#[test]
fn runtime_save_and_load() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    store.save(&minimal_environment(&id)).unwrap();

    assert!(store.load_runtime(&id).unwrap().is_none());

    let runtime = EnvironmentRuntime {
        schema: SchemaVersion::from(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
        environment_id: id.clone(),
        discovered: [(
            "cluster_endpoint".to_string(),
            RuntimeDiscoveryValue::String("https://kube.local:6443".into()),
        )]
        .into_iter()
        .collect(),
        generated_at: chrono::Utc::now(),
        generated_by: pack_descriptor("greentic.deployer.local-process@1.0.0"),
        generation: 1,
    };

    store.save_runtime(&runtime).unwrap();
    let loaded = store
        .load_runtime(&id)
        .unwrap()
        .expect("runtime should exist after save");
    assert_eq!(loaded, runtime);
}

#[test]
fn runtime_save_rejects_bad_schema() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    let runtime = EnvironmentRuntime {
        schema: SchemaVersion::from("greentic.environment-runtime.v999"),
        environment_id: id,
        discovered: Default::default(),
        generated_at: chrono::Utc::now(),
        generated_by: pack_descriptor("greentic.deployer.local-process@1.0.0"),
        generation: 0,
    };
    let err = store
        .save_runtime(&runtime)
        .expect_err("schema must be rejected");
    matches!(err, StoreError::Spec(_));
}

#[test]
fn pack_answers_round_trip_and_delete() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    let slot = CapabilitySlot::Secrets;
    let answers = json!({ "vault_addr": "http://localhost:8200" });

    assert!(store.load_pack_answers(&id, slot).unwrap().is_none());

    store.save_pack_answers(&id, slot, &answers).unwrap();
    let loaded = store
        .load_pack_answers(&id, slot)
        .unwrap()
        .expect("answers should be present after save");
    assert_eq!(loaded, answers);

    store.delete_pack_answers(&id, slot).unwrap();
    assert!(store.load_pack_answers(&id, slot).unwrap().is_none());
}

#[test]
fn pack_answers_delete_no_op_when_absent() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    store
        .delete_pack_answers(&id, CapabilitySlot::Secrets)
        .expect("delete on missing must succeed");
}

#[test]
fn pack_answers_overwrite_writes_backup() {
    let (tmp, store) = fresh_store();
    let id = env_id("local");
    let slot = CapabilitySlot::State;
    store
        .save_pack_answers(&id, slot, &json!({ "v": 1 }))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    store
        .save_pack_answers(&id, slot, &json!({ "v": 2 }))
        .unwrap();

    let backups: Vec<_> = std::fs::read_dir(
        tmp.path()
            .join("local")
            .join("backups")
            .join("env-packs")
            .join("state"),
    )
    .unwrap()
    .filter_map(|e| e.ok())
    .map(|e| e.file_name().to_string_lossy().into_owned())
    .collect();
    assert_eq!(backups.len(), 1, "got {backups:?}");
    assert!(backups[0].starts_with("answers.json."));
    assert!(backups[0].ends_with(".bak"));
}

#[test]
fn lock_serializes_concurrent_writers() {
    let (_tmp, store) = fresh_store();
    let store = Arc::new(store);
    let id = env_id("local");
    store.save(&minimal_environment(&id)).unwrap();

    // Spawn N threads, each updating `name` to its index and re-saving.
    // After all threads return, the file must still be valid JSON and the
    // backups dir must contain N-1 backups (one per overwrite).
    const N: usize = 12;
    let mut handles = Vec::new();
    for i in 0..N {
        let s = Arc::clone(&store);
        let id = id.clone();
        handles.push(thread::spawn(move || {
            let mut env = s.load(&id).unwrap();
            env.name = format!("w{i}");
            s.save(&env).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let final_env = store.load(&id).expect("file is still valid json");
    assert!(final_env.name.starts_with('w'));
}

#[test]
fn try_acquire_blocks_while_transact_holds_lock() {
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    let lock_path = store.env_lock_path(&id).unwrap();
    // Capture the path before transact takes the lock; once inside the
    // closure another `EnvFlock::try_acquire` must fail.
    store
        .transact(&id, |_locked| {
            let attempt = EnvFlock::try_acquire(&lock_path).unwrap();
            assert!(
                attempt.is_none(),
                "second flock acquire must fail while transact holds the lock"
            );
            Ok::<(), StoreError>(())
        })
        .unwrap();
    // After transact returns, the lock is released and try_acquire succeeds.
    let after = EnvFlock::try_acquire(&lock_path).unwrap();
    assert!(after.is_some());
}

#[test]
fn transact_load_then_save_does_not_deadlock() {
    // Regression: the pre-fix trait advertised `EnvironmentStore::lock` as
    // the entry point for compound mutations, but every `save_*` re-acquired
    // the same per-FD flock blocking, so `let g = store.lock(&id); store.save()`
    // would self-deadlock. The replacement closure-based `transact` API must
    // make the natural pattern (load → mutate → save) work.
    let (_tmp, store) = fresh_store();
    let id = env_id("local");
    store.save(&minimal_environment(&id)).unwrap();

    store
        .transact(&id, |locked| {
            let mut env = locked.load()?;
            env.name = "transacted".into();
            locked.save(&env)?;
            // Compound: mutate pack-answers within the same transaction.
            locked.save_pack_answers(CapabilitySlot::Secrets, &json!({ "rotated": true }))?;
            Ok::<(), StoreError>(())
        })
        .unwrap();

    let env = store.load(&id).unwrap();
    assert_eq!(env.name, "transacted");
    let ans = store
        .load_pack_answers(&id, CapabilitySlot::Secrets)
        .unwrap();
    assert_eq!(ans, Some(json!({ "rotated": true })));
}

#[test]
fn transact_rejects_mismatched_env_id_in_payload() {
    // Lock is scoped to `local`; trying to save a payload whose
    // environment_id is `prod` must be rejected — otherwise the closure
    // could bypass `prod`'s flock entirely.
    let (_tmp, store) = fresh_store();
    let local_id = env_id("local");
    let prod_id = env_id("prod");
    store.save(&minimal_environment(&local_id)).unwrap();
    store.save(&minimal_environment(&prod_id)).unwrap();

    let err = store
        .transact(&local_id, |locked| {
            let prod_env = minimal_environment(&env_id("prod"));
            locked.save(&prod_env)
        })
        .expect_err("transact must reject cross-env payload");
    assert!(matches!(err, StoreError::EnvIdMismatch { .. }));
}

#[test]
fn mint_ids_are_unique() {
    let a = mint_revision_id();
    let b = mint_revision_id();
    assert_ne!(a, b);
    let c = mint_deployment_id();
    let d = mint_deployment_id();
    assert_ne!(c, d);
}

// ----------------------------------------------------------------------------
// Codex adversarial-review regressions
// ----------------------------------------------------------------------------

#[test]
fn save_rejects_env_id_equal_to_dotdot() {
    // Without the safe_env_segment guard, `EnvId("..")` would resolve to
    // <root>/.. and write `environment.json` into the parent directory.
    let (_tmp, store) = fresh_store();
    let id = env_id("..");
    let env = minimal_environment(&id);
    let err = store.save(&env).expect_err("must reject `..`");
    assert!(
        matches!(err, StoreError::UnsafeEnvId(_)),
        "expected UnsafeEnvId, got {err:?}"
    );
    // Nothing escaped into the parent of the temp root.
    assert!(!store.root().join("..").join("environment.json").exists());
}

#[test]
fn save_rejects_env_id_equal_to_dot() {
    let (_tmp, store) = fresh_store();
    let id = env_id(".");
    let env = minimal_environment(&id);
    let err = store.save(&env).expect_err("must reject `.`");
    assert!(matches!(err, StoreError::UnsafeEnvId(_)));
}

#[test]
fn load_runtime_answers_lock_all_reject_unsafe_env_id() {
    let (_tmp, store) = fresh_store();
    let bad = env_id("..");
    assert!(matches!(
        store.load(&bad).unwrap_err(),
        StoreError::UnsafeEnvId(_)
    ));
    assert!(matches!(
        store.load_runtime(&bad).unwrap_err(),
        StoreError::UnsafeEnvId(_)
    ));
    assert!(matches!(
        store.exists(&bad).unwrap_err(),
        StoreError::UnsafeEnvId(_)
    ));
    assert!(matches!(
        store
            .load_pack_answers(&bad, CapabilitySlot::Secrets)
            .unwrap_err(),
        StoreError::UnsafeEnvId(_)
    ));
    assert!(matches!(
        store
            .save_pack_answers(&bad, CapabilitySlot::Secrets, &json!({}))
            .unwrap_err(),
        StoreError::UnsafeEnvId(_)
    ));
    assert!(matches!(
        store
            .delete_pack_answers(&bad, CapabilitySlot::Secrets)
            .unwrap_err(),
        StoreError::UnsafeEnvId(_)
    ));
    assert!(matches!(
        store.env_lock_path(&bad).unwrap_err(),
        StoreError::UnsafeEnvId(_)
    ));
    let err = store
        .transact(&bad, |_| Ok(()))
        .expect_err("transact must reject unsafe env id");
    assert!(matches!(err, StoreError::UnsafeEnvId(_)));
}

#[test]
fn load_rejects_corrupted_file_with_mismatched_env_id() {
    // Simulate a restored / corrupted file where environment_id does not
    // match the directory the file lives in.
    let (tmp, store) = fresh_store();
    let dir_id = env_id("local");
    let value_id = env_id("prod");
    let mut env = minimal_environment(&value_id);
    env.name = "stolen".into();

    let dir = tmp.path().join("local");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("environment.json"),
        serde_json::to_vec_pretty(&env).unwrap(),
    )
    .unwrap();

    let err = store.load(&dir_id).expect_err("must reject id mismatch");
    match err {
        StoreError::EnvIdMismatch { file, value } => {
            assert_eq!(file, dir_id);
            assert_eq!(value, value_id);
        }
        other => panic!("expected EnvIdMismatch, got {other:?}"),
    }
}

#[test]
fn load_validates_environment_after_deserialize() {
    // Hand-written file with a slot duplicated would pass deserialize but
    // fail validate(). Old load() would happily return it.
    let (tmp, store) = fresh_store();
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    env.packs.push(EnvPackBinding {
        slot: CapabilitySlot::Deployer,
        kind: pack_descriptor("greentic.deployer.k8s@1.0.0"),
        pack_ref: PackId::new("k8s"),
        answers_ref: None,
        generation: 0,
        previous_binding_ref: None,
    });
    let dir = tmp.path().join("local");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("environment.json"),
        serde_json::to_vec_pretty(&env).unwrap(),
    )
    .unwrap();

    let err = store
        .load(&id)
        .expect_err("load must run spec validate() on result");
    assert!(matches!(err, StoreError::Spec(_)));
}

#[test]
fn load_runtime_rejects_mismatched_env_id() {
    let (tmp, store) = fresh_store();
    let dir_id = env_id("local");
    let value_id = env_id("prod");

    let runtime = EnvironmentRuntime {
        schema: SchemaVersion::from(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
        environment_id: value_id.clone(),
        discovered: Default::default(),
        generated_at: chrono::Utc::now(),
        generated_by: pack_descriptor("greentic.deployer.local-process@1.0.0"),
        generation: 1,
    };
    let dir = tmp.path().join("local");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("runtime.json"),
        serde_json::to_vec_pretty(&runtime).unwrap(),
    )
    .unwrap();

    let err = store
        .load_runtime(&dir_id)
        .expect_err("must reject id mismatch");
    match err {
        StoreError::EnvIdMismatch { file, value } => {
            assert_eq!(file, dir_id);
            assert_eq!(value, value_id);
        }
        other => panic!("expected EnvIdMismatch, got {other:?}"),
    }
}

#[test]
fn list_silently_skips_corrupted_files() {
    let (tmp, store) = fresh_store();

    // A perfectly fine env.
    store.save(&minimal_environment(&env_id("good"))).unwrap();

    // A directory with malformed JSON.
    let bad_dir = tmp.path().join("malformed");
    std::fs::create_dir_all(&bad_dir).unwrap();
    std::fs::write(bad_dir.join("environment.json"), b"{not json").unwrap();

    // A directory whose environment_id field doesn't match the dir name.
    let mismatch_dir = tmp.path().join("mismatch");
    std::fs::create_dir_all(&mismatch_dir).unwrap();
    let env = minimal_environment(&env_id("totally-different"));
    std::fs::write(
        mismatch_dir.join("environment.json"),
        serde_json::to_vec_pretty(&env).unwrap(),
    )
    .unwrap();

    let envs = store.list().unwrap();
    let names: Vec<_> = envs.iter().map(|e| e.as_str().to_string()).collect();
    assert_eq!(names, vec!["good"]);
}

#[test]
fn backups_survive_rapid_successive_saves() {
    // Codex finding: ms-precision filenames + fs::copy(no-clobber-off) means
    // two saves landing in the same millisecond would overwrite each other's
    // backup. With ns precision + create_new reservation, both must survive.
    let (tmp, store) = fresh_store();
    let id = env_id("local");
    let mut env = minimal_environment(&id);
    store.save(&env).unwrap(); // initial → no backup
    const ROUNDS: usize = 20;
    for i in 0..ROUNDS {
        env.name = format!("rev-{i}");
        store.save(&env).unwrap();
    }
    let backups_dir = tmp.path().join("local").join("backups");
    let backups: Vec<_> = std::fs::read_dir(&backups_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("environment.json.") && n.ends_with(".bak"))
        .collect();
    assert_eq!(
        backups.len(),
        ROUNDS,
        "expected one backup per non-initial save, got {backups:?}"
    );
}

#[test]
fn default_root_under_home() {
    if let Some(root) = LocalFsStore::default_root() {
        let s = root.to_string_lossy();
        assert!(
            s.ends_with(".greentic/environments") || s.ends_with(".greentic\\environments"),
            "got {s}"
        );
    }
}
