use std::path::{Path, PathBuf};

use greentic_deploy_spec::{EnvId, RevisionLifecycle};
use serde_json::{Value, json};
use tempfile::tempdir;

use super::super::{ApplyMode, ApplyOptions, apply};
use crate::cli::env_manifest::ENV_MANIFEST_SCHEMA_V1;
use crate::cli::tests_common::{bootstrap_env_trust_root, make_bundle_deployment, make_env};
use crate::cli::{OpError, OpFlags, OpOutcome};
use crate::environment::{EnvironmentStore, LocalFsStore};

fn seeded() -> (tempfile::TempDir, LocalFsStore) {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    store.save(&make_env("local")).expect("save env");
    let env_dir = store.env_dir(&env_id()).expect("env dir");
    bootstrap_env_trust_root(&env_dir);
    (dir, store)
}

fn env_id() -> EnvId {
    EnvId::try_from("local").expect("env id")
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/bundles/perf-smoke-bundle.gtbundle")
}

fn manifest(dir: &Path, bundles: &[&str]) -> PathBuf {
    manifest_at(dir, bundles)
}

/// A manifest file in `dir` — a different `dir` is a different manifest
/// identity, so a different ownership.
fn manifest_at(dir: &Path, bundles: &[&str]) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir");
    let value = json!({
        "schema": ENV_MANIFEST_SCHEMA_V1,
        "environment": {"id": "local"},
        "bundles": bundles
            .iter()
            .map(|b| json!({"bundle_id": b, "bundle_path": fixture()}))
            .collect::<Vec<Value>>(),
    });
    let path = dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("json")).expect("write");
    path
}

fn run(
    store: &LocalFsStore,
    manifest: &Path,
    mode: ApplyMode,
    prune: bool,
    confirm_prune: bool,
) -> Result<OpOutcome, OpError> {
    let flags = OpFlags {
        schema_only: false,
        answers: Some(manifest.to_path_buf()),
    };
    apply(
        store,
        &flags,
        ApplyOptions {
            mode,
            non_interactive: true,
            prune,
            confirm_prune,
            ..ApplyOptions::default()
        },
    )
}

fn bundle_ids(store: &LocalFsStore) -> Vec<String> {
    let mut ids: Vec<String> = store
        .load(&env_id())
        .expect("load")
        .bundles
        .iter()
        .map(|b| b.bundle_id.as_str().to_string())
        .collect();
    ids.sort();
    ids
}

#[test]
fn prune_without_confirmation_is_refused_before_anything_runs() {
    let (dir, store) = seeded();
    let path = manifest(dir.path(), &["alpha"]);
    let err = run(&store, &path, ApplyMode::Apply, true, false).unwrap_err();
    assert_eq!(err.kind(), "invalid-argument", "{err}");
    assert!(err.to_string().contains("--confirm-prune"), "{err}");
    assert!(bundle_ids(&store).is_empty(), "nothing applied");
}

#[test]
fn default_apply_is_upsert_only_and_reports_no_prune_key() {
    let (dir, store) = seeded();
    run(
        &store,
        &manifest(dir.path(), &["alpha", "beta"]),
        ApplyMode::Apply,
        false,
        false,
    )
    .expect("first apply");
    let out = run(
        &store,
        &manifest(dir.path(), &["alpha"]),
        ApplyMode::Apply,
        false,
        false,
    )
    .expect("second apply");
    assert!(out.result.get("prune").is_none(), "{}", out.result);
    assert_eq!(
        bundle_ids(&store),
        vec!["alpha", "beta"],
        "omission is not deletion"
    );
}

#[test]
fn prune_retires_an_owned_bundle_the_manifest_dropped() {
    let (dir, store) = seeded();
    run(
        &store,
        &manifest(dir.path(), &["alpha", "beta"]),
        ApplyMode::Apply,
        false,
        false,
    )
    .expect("first apply");
    let path = manifest(dir.path(), &["alpha"]);

    let preview = run(&store, &path, ApplyMode::DryRun, true, true).expect("dry run");
    assert_eq!(preview.result["prune"]["planned"], true);
    assert_eq!(
        preview.result["prune"]["retire"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        bundle_ids(&store),
        vec!["alpha", "beta"],
        "dry run mutates nothing"
    );
    let check = run(&store, &path, ApplyMode::Check, true, true).unwrap_err();
    assert_eq!(check.kind(), "conflict", "pending prune is drift: {check}");

    let out = run(&store, &path, ApplyMode::Apply, true, true).expect("prune apply");
    let retired = out.result["prune"]["retired"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(retired.len(), 1, "{}", out.result);
    assert_eq!(retired[0]["bundle_id"], "beta");
    assert_eq!(bundle_ids(&store), vec!["alpha"]);

    let again = run(&store, &path, ApplyMode::Apply, true, true).expect("replay");
    assert_eq!(
        again.result["prune"]["retired"].as_array().map(Vec::len),
        Some(0),
        "idempotent: nothing left to prune"
    );
}

#[test]
fn prune_never_touches_a_deployment_the_manifest_never_owned() {
    let (dir, store) = seeded();
    run(
        &store,
        &manifest(dir.path(), &["alpha"]),
        ApplyMode::Apply,
        false,
        false,
    )
    .expect("apply");
    let mut env = store.load(&env_id()).expect("load");
    env.bundles
        .push(make_bundle_deployment("local", "handmade"));
    store.save(&env).expect("save");
    let out = run(
        &store,
        &manifest(dir.path(), &["alpha"]),
        ApplyMode::Apply,
        true,
        true,
    )
    .expect("prune apply");
    assert_eq!(
        out.result["prune"]["retired"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(bundle_ids(&store), vec!["alpha", "handmade"]);
}

#[test]
fn prune_leaves_a_warmed_canary_of_a_declared_bundle_alone() {
    let (dir, store) = seeded();
    let path = manifest(dir.path(), &["alpha"]);
    run(&store, &path, ApplyMode::Apply, false, false).expect("apply");
    let mut env = store.load(&env_id()).expect("load");
    let mut canary = env.revisions[0].clone();
    canary.revision_id = greentic_deploy_spec::RevisionId::new();
    canary.lifecycle = RevisionLifecycle::Ready;
    let canary_id = canary.revision_id;
    env.revisions.push(canary);
    store.save(&env).expect("save");

    let out = run(&store, &path, ApplyMode::Apply, true, true).expect("prune apply");
    assert_eq!(
        out.result["prune"]["retired"].as_array().map(Vec::len),
        Some(0)
    );
    let env = store.load(&env_id()).expect("load");
    let canary = env.revisions.iter().find(|r| r.revision_id == canary_id);
    assert_eq!(canary.map(|r| r.lifecycle), Some(RevisionLifecycle::Ready));
}

#[test]
fn a_manifest_only_prunes_what_it_declared_itself() {
    let (dir, store) = seeded();
    let a = dir.path().join("team-a");
    let b = dir.path().join("team-b");
    run(
        &store,
        &manifest_at(&a, &["alpha"]),
        ApplyMode::Apply,
        false,
        false,
    )
    .expect("a");
    run(
        &store,
        &manifest_at(&b, &["beta"]),
        ApplyMode::Apply,
        false,
        false,
    )
    .expect("b");
    // Manifest A now declares only `gamma`: it may retire `alpha` (its own),
    // never `beta` (manifest B's).
    let out = run(
        &store,
        &manifest_at(&a, &["gamma"]),
        ApplyMode::Apply,
        true,
        true,
    )
    .expect("prune a");
    let retired = out.result["prune"]["retired"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(retired.len(), 1, "{}", out.result);
    assert_eq!(retired[0]["bundle_id"], "alpha");
    assert_eq!(bundle_ids(&store), vec!["beta", "gamma"]);
}

#[test]
fn a_stranded_endpoint_refuses_the_whole_prune_before_the_upsert() {
    let (dir, store) = seeded();
    run(
        &store,
        &manifest(dir.path(), &["alpha", "beta"]),
        ApplyMode::Apply,
        false,
        false,
    )
    .expect("apply");
    let mut env = store.load(&env_id()).expect("load");
    let now = env.bundles[0].created_at;
    env.messaging_endpoints
        .push(greentic_deploy_spec::MessagingEndpoint {
            schema: greentic_deploy_spec::SchemaVersion::new(
                greentic_deploy_spec::SchemaVersion::MESSAGING_ENDPOINT_V1,
            ),
            env_id: env.environment_id.clone(),
            endpoint_id: greentic_deploy_spec::MessagingEndpointId::new(),
            provider_id: "bot".to_string(),
            provider_type: "messaging.telegram.bot".to_string(),
            display_name: "bot".to_string(),
            secret_refs: Vec::new(),
            webhook_secret_ref: None,
            linked_bundles: vec![greentic_deploy_spec::BundleId::new("beta")],
            welcome_flow: None,
            generation: 0,
            created_at: now,
            updated_at: now,
            updated_by: "test".to_string(),
        });
    store.save(&env).expect("save");
    let before = store.load(&env_id()).expect("load");
    let err = run(
        &store,
        &manifest(dir.path(), &["alpha", "delta"]),
        ApplyMode::Apply,
        true,
        true,
    )
    .unwrap_err();
    assert_eq!(err.kind(), "conflict", "{err}");
    assert!(err.to_string().contains("bot"), "{err}");
    assert_eq!(
        store.load(&env_id()).expect("load"),
        before,
        "nothing applied"
    );
}
