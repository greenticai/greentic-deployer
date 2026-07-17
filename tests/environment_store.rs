//! Integration tests for [`EnvironmentStore`] + [`LocalFsStore`] (A2).
//!
//! Unit tests for the underlying [`atomic_write`] and [`file_lock`] primitives
//! live alongside the modules; this file exercises the full trait surface
//! against a real temp-rooted [`LocalFsStore`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use chrono::{TimeZone, Utc};
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, DeploymentId,
    EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, EnvironmentRuntime, PackDescriptor,
    PackId, PartyId, RevenueShareEntry, RouteBinding, RuntimeDiscoveryValue, SchemaVersion,
    TenantSelector,
};
use greentic_deployer::environment::{
    EnvFlock, EnvironmentStore, LocalFsStore, PROVIDER_TEARDOWN_DESCRIPTORS, ProviderTeardown,
    ProviderTeardownCtx, StoreError, mint_deployment_id, mint_revision_id,
};
use serde_json::{Value, json};
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
            public_base_url: None,
            gui_enabled: None,
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

#[test]
fn destroy_environment_removes_tree_and_returns_canonical_path() {
    let (tmp, store) = fresh_store();
    let id = env_id("doomed");
    store.save(&minimal_environment(&id)).unwrap();
    // A sidecar the store APIs never wrote proves rename-then-remove needs
    // no enumeration of the env dir's contents.
    std::fs::write(tmp.path().join("doomed").join("trust-root.json"), b"{}").unwrap();

    let outcome = store.destroy_environment(&id).unwrap();
    assert_eq!(outcome.removed_path, tmp.path().join("doomed"));
    assert_eq!(outcome.reaped_tombstones, 0);
    assert!(!outcome.removed_path.exists());
    assert!(!store.exists(&id).unwrap());
    assert!(store.list().unwrap().is_empty());
    // A clean purge leaves no tombstone sibling behind.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(leftovers.is_empty(), "got {leftovers:?}");
}

#[test]
fn destroy_environment_missing_env_is_not_found() {
    let (tmp, store) = fresh_store();
    let err = store.destroy_environment(&env_id("ghost")).unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "got {err:?}");
    // The unlocked fast-path must not leave a flock husk dir behind.
    assert!(!tmp.path().join("ghost").exists());
}

/// Make the (future) tombstone's purge fail: a write-protected dir with a
/// child makes `remove_dir_all` fail after the (committing) rename.
#[cfg(unix)]
fn poison_purge(env_dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let blocked = env_dir.join("blocked");
    std::fs::create_dir_all(&blocked).unwrap();
    std::fs::write(blocked.join("child"), b"x").unwrap();
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o555)).unwrap();
}

/// Find the surviving tombstone under `root` and restore write permissions
/// on its poisoned dir so a reap — or TempDir::drop — can remove it. Call
/// BEFORE any assertion so cleanup happens on every exit path.
#[cfg(unix)]
fn find_tombstone_and_unblock(root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let tombstone = std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().contains(".destroyed~"))
        .expect("tombstone survives the failed purge");
    std::fs::set_permissions(
        tombstone.path().join("blocked"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    tombstone.path()
}

#[cfg(unix)]
#[test]
fn destroy_environment_purge_failure_is_committed_after_save() {
    let (tmp, store) = fresh_store();
    let id = env_id("doomed");
    store.save(&minimal_environment(&id)).unwrap();
    poison_purge(&tmp.path().join("doomed"));

    let err = store.destroy_environment(&id).unwrap_err();
    let _tombstone = find_tombstone_and_unblock(tmp.path());

    assert!(err.is_committed_after_save(), "got {err:?}");
    // The rename committed: the canonical path is gone...
    assert!(!store.exists(&id).unwrap());
    assert!(!tmp.path().join("doomed").exists());
    // ...and the surviving tombstone is invisible to list().
    assert!(store.list().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn destroy_environment_rerun_reaps_stale_tombstone() {
    let (tmp, store) = fresh_store();
    let id = env_id("doomed");
    store.save(&minimal_environment(&id)).unwrap();
    poison_purge(&tmp.path().join("doomed"));

    let err = store.destroy_environment(&id).unwrap_err();
    assert!(err.is_committed_after_save());
    find_tombstone_and_unblock(tmp.path());

    // Re-running destroy reaps the stale tombstone.
    let outcome = store.destroy_environment(&id).unwrap();
    assert_eq!(outcome.removed_path, tmp.path().join("doomed"));
    assert_eq!(outcome.reaped_tombstones, 1);

    // The tombstone is gone from the root.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".destroyed~"))
        .collect();
    assert!(leftovers.is_empty(), "got {leftovers:?}");
}

// --- provider-resource teardown on destroy (plan item 5b) --------------------

/// The Cloud Run deployer descriptor, versioned as it appears on a binding.
/// `PackDescriptor::path()` strips the `@version`, so it matches the version-less
/// entry in [`PROVIDER_TEARDOWN_DESCRIPTORS`].
const CLOUDRUN_DESCRIPTOR: &str = "greentic.deployer.gcp-cloudrun@1.0.0";

/// A minimal-but-valid `BundleDeployment` for the env, mirroring the crate's
/// internal `make_bundle_deployment` fixture (empty `current_revisions` so
/// `Environment::validate` needs no matching revisions).
fn make_cloudrun_bundle(id: &EnvId) -> BundleDeployment {
    BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id: mint_deployment_id(),
        env_id: id.clone(),
        bundle_id: BundleId::new("demo"),
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: RouteBinding {
            hosts: vec!["demo.local".to_string()],
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
        created_at: Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap(),
        authorization_ref: PathBuf::from("auth.json"),
        config_overrides: BTreeMap::new(),
    }
}

/// A saved cloudrun-bound env with `n` deployments + seeded deployer answers.
/// Returns the store, tempdir, env id, and the env's deployment ids in order.
fn saved_cloudrun_env(n: usize) -> (TempDir, LocalFsStore, EnvId, Vec<DeploymentId>) {
    let (tmp, store) = fresh_store();
    let id = env_id("cloudy");
    let mut env = minimal_environment(&id);
    env.packs[0].kind = pack_descriptor(CLOUDRUN_DESCRIPTOR);
    env.packs[0].pack_ref = PackId::new("gcp-cloudrun");
    let bundles: Vec<BundleDeployment> = (0..n).map(|_| make_cloudrun_bundle(&id)).collect();
    let ids: Vec<DeploymentId> = bundles.iter().map(|b| b.deployment_id).collect();
    env.bundles = bundles;
    store.save(&env).unwrap();
    store
        .save_pack_answers(
            &id,
            CapabilitySlot::Deployer,
            &json!({ "project": "demo-proj", "region": "us-central1" }),
        )
        .unwrap();
    (tmp, store, id, ids)
}

/// One captured teardown invocation.
struct RecordedTeardown {
    env_id: String,
    descriptor: String,
    deployment_ids: Vec<DeploymentId>,
    answers: Option<Value>,
}

/// Records each teardown invocation for assertions.
#[derive(Default)]
struct RecordingTeardown {
    calls: Mutex<Vec<RecordedTeardown>>,
}

impl ProviderTeardown for RecordingTeardown {
    fn teardown(&self, ctx: ProviderTeardownCtx<'_>) -> Result<Value, StoreError> {
        self.calls.lock().unwrap().push(RecordedTeardown {
            env_id: ctx.env_id.as_str().to_string(),
            descriptor: ctx.descriptor_path.to_string(),
            deployment_ids: ctx.deployment_ids.to_vec(),
            answers: ctx.answers.cloned(),
        });
        Ok(json!({ "deleted_services": ctx.deployment_ids.len() }))
    }
}

/// Always fails, leaving the env intact for a retry.
struct FailingTeardown;

impl ProviderTeardown for FailingTeardown {
    fn teardown(&self, _ctx: ProviderTeardownCtx<'_>) -> Result<Value, StoreError> {
        Err(StoreError::ProviderTeardown(
            "simulated GCP failure".to_string(),
        ))
    }
}

/// Signals when teardown starts, then blocks until released — proves the destroy
/// flock is held across teardown.
struct BlockingTeardown {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ProviderTeardown for BlockingTeardown {
    fn teardown(&self, _ctx: ProviderTeardownCtx<'_>) -> Result<Value, StoreError> {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        Ok(json!({ "deleted_services": 0 }))
    }
}

#[test]
fn provider_teardown_descriptors_lists_cloudrun() {
    // The store recognizes the Cloud Run deployer by string, feature-independently.
    assert!(PROVIDER_TEARDOWN_DESCRIPTORS.contains(&"greentic.deployer.gcp-cloudrun"));
}

#[test]
fn destroy_cloudrun_env_without_teardown_capability_refuses_not_purges() {
    let (_tmp, store, id, _ids) = saved_cloudrun_env(1);
    // No teardown impl (feature-reduced binary) and no --force-local → refuse.
    let err = store
        .destroy_environment_with_teardown(&id, None, false)
        .unwrap_err();
    assert!(
        matches!(err, StoreError::ProviderTeardownUnavailable { .. }),
        "got {err:?}"
    );
    // The env survives so the resources are not orphaned and destroy is retryable.
    assert!(store.exists(&id).unwrap());
}

#[test]
fn destroy_cloudrun_env_runs_provider_teardown_then_purges() {
    let (_tmp, store, id, ids) = saved_cloudrun_env(2);
    let teardown = RecordingTeardown::default();

    let outcome = store
        .destroy_environment_with_teardown(&id, Some(&teardown), false)
        .unwrap();

    // Teardown was invoked once with the version-less descriptor, both
    // deployment ids (in order), and the seeded answers.
    let calls = teardown.calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "teardown called exactly once");
    let call = &calls[0];
    assert_eq!(call.env_id, "cloudy");
    assert_eq!(call.descriptor, "greentic.deployer.gcp-cloudrun");
    assert_eq!(call.deployment_ids, ids);
    assert_eq!(
        call.answers.as_ref().and_then(|a| a.get("project")),
        Some(&json!("demo-proj"))
    );

    // Local state is purged and the teardown report rides back on the outcome.
    assert!(!store.exists(&id).unwrap());
    assert_eq!(
        outcome.provider_teardown,
        Some(json!({ "deleted_services": 2 }))
    );
}

#[test]
fn destroy_cloudrun_env_force_local_skips_teardown_and_purges() {
    let (_tmp, store, id, _ids) = saved_cloudrun_env(1);
    // --force-local: purge local state only, even with no teardown impl.
    let outcome = store
        .destroy_environment_with_teardown(&id, None, true)
        .unwrap();
    assert!(!store.exists(&id).unwrap());
    let report = outcome
        .provider_teardown
        .expect("force-local records a skip");
    assert_eq!(report.get("status"), Some(&json!("skipped")));
    assert_eq!(report.get("reason"), Some(&json!("force_local")));
}

#[test]
fn destroy_provider_teardown_failure_leaves_env_intact_for_retry() {
    let (_tmp, store, id, _ids) = saved_cloudrun_env(1);
    let err = store
        .destroy_environment_with_teardown(&id, Some(&FailingTeardown), false)
        .unwrap_err();
    assert!(
        matches!(err, StoreError::ProviderTeardown(_)),
        "got {err:?}"
    );
    // No rename happened — the env (and its resource inventory) survives.
    assert!(store.exists(&id).unwrap());
}

#[test]
fn destroy_non_cloudrun_env_ignores_teardown_capability() {
    // A local-process env owns no remote resources: the teardown impl must not
    // be consulted, and the env purges normally.
    let (_tmp, store) = fresh_store();
    let id = env_id("plain");
    store.save(&minimal_environment(&id)).unwrap();
    let teardown = RecordingTeardown::default();

    let outcome = store
        .destroy_environment_with_teardown(&id, Some(&teardown), false)
        .unwrap();

    assert!(teardown.calls.lock().unwrap().is_empty());
    assert!(outcome.provider_teardown.is_none());
    assert!(!store.exists(&id).unwrap());
}

#[test]
fn destroy_holds_env_flock_across_provider_teardown() {
    let (_tmp, store, id, _ids) = saved_cloudrun_env(1);
    let lock_path = store.env_lock_path(&id).unwrap();

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let teardown = Arc::new(BlockingTeardown {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });

    let store = Arc::new(store);
    let worker = {
        let store = Arc::clone(&store);
        let teardown = Arc::clone(&teardown);
        let id = id.clone();
        thread::spawn(move || {
            store.destroy_environment_with_teardown(&id, Some(teardown.as_ref()), false)
        })
    };

    // Wait until teardown is running — the destroy flock is now held.
    entered_rx.recv().unwrap();
    // A concurrent lock acquisition must fail while destroy is mid-teardown,
    // proving classify + teardown + rename are one atomic critical section.
    assert!(
        EnvFlock::try_acquire(&lock_path).unwrap().is_none(),
        "env flock must be held across provider teardown"
    );

    // Release teardown; destroy completes and purges.
    release_tx.send(()).unwrap();
    let outcome = worker.join().unwrap().unwrap();
    assert!(!store.exists(&id).unwrap());
    assert_eq!(
        outcome.provider_teardown,
        Some(json!({ "deleted_services": 0 }))
    );
    // The lock is free again after the destroy returns.
    assert!(EnvFlock::try_acquire(&lock_path).unwrap().is_some());
}
