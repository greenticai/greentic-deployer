//! CLI-level tests for the ssh-host wiring: binding validation, credential
//! probes, `apply-revision` and `env up`, all against the simulated VM
//! (no network). Each test installs its own VM for its own thread.

use std::path::Path;
use std::sync::Arc;

use greentic_deploy_spec::{CapabilitySlot, EnvId, Environment, RevisionLifecycle};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::*;
use crate::cli::dispatch::EnvApplyRevisionArgs;
use crate::cli::env_up::{EnvUpArgs, up};
use crate::cli::tests_common::{make_binding, make_bundle_deployment, make_env, make_revision};
use crate::cli::{OpFlags, env_packs};
use crate::credentials::CapabilityStatus;
use crate::env_packs::ssh_host::fake::FakeRemote;

const ENV: &str = "vmtest";
const KIND: &str = "greentic.deployer.ssh-host@0.1.0";
const ANSWERS_REL: &str = "env-packs/deployer/answers.json";
/// A path that must never appear in any output or error.
const SECRET_KEY_PATH: &str = "/home/operator/.ssh/id_super_secret";

fn answers() -> Value {
    json!({"host": "vm.example.com", "user": "greentic", "identity_file": SECRET_KEY_PATH})
}

fn vm() -> Arc<FakeRemote> {
    let remote = Arc::new(FakeRemote::default());
    remote.put_executable("/opt/greentic/bin/greentic-start", b"#!binary");
    remote
}

fn write_answers(store: &LocalFsStore, env_id: &str, body: &Value) {
    let dir = store.root().join(env_id).join("env-packs/deployer");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("answers.json"), serde_json::to_vec(body).unwrap()).unwrap();
}

/// An env with one Ready revision and the ssh-host deployer bound (answers
/// recorded when `bound_answers` is `Some`).
fn seeded(dir: &Path, bound_answers: Option<&Value>) -> LocalFsStore {
    let store = LocalFsStore::new(dir);
    let mut env = make_env(ENV);
    let mut binding = make_binding(CapabilitySlot::Deployer, KIND);
    if let Some(body) = bound_answers {
        write_answers(&store, ENV, body);
        binding.answers_ref = Some(ANSWERS_REL.into());
    }
    env.packs.push(binding);
    let deployment = make_bundle_deployment(ENV, "demo");
    env.revisions.push(make_revision(
        ENV,
        "demo",
        &deployment.deployment_id,
        1,
        RevisionLifecycle::Ready,
    ));
    env.bundles.push(deployment);
    store.save(&env).unwrap();
    store
}

fn env_of(store: &LocalFsStore) -> Environment {
    store.load(&EnvId::try_from(ENV).unwrap()).unwrap()
}

fn env_id() -> EnvId {
    EnvId::try_from(ENV).unwrap()
}

fn up_args() -> EnvUpArgs {
    EnvUpArgs {
        yes: true,
        non_interactive: true,
        dry_run: false,
        skip_cluster: true,
        no_port_forward: true,
        port: 8080,
        allow_missing_seeds: false,
        updated_by: None,
    }
}

fn manifest(dir: &TempDir, packs: Value) -> OpFlags {
    let path = dir.path().join("manifest.json");
    let doc = json!({
        "schema": "greentic.env-manifest.v1",
        "environment": {"id": ENV},
        "packs": packs,
    });
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
    OpFlags {
        answers: Some(path),
        ..Default::default()
    }
}

// ---- binding validation -----------------------------------------------------

#[test]
fn a_binding_with_valid_answers_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), Some(&answers()));
    let env = env_of(&store);
    let binding = env.pack_for_slot(CapabilitySlot::Deployer).unwrap();
    validate_binding_answers(&store, &env_id(), binding).unwrap();
}

#[test]
fn a_binding_with_bad_answers_is_refused_without_echoing_the_key_path() {
    let dir = tempfile::tempdir().unwrap();
    let bad = json!({"host": "vm.example.com", "user": "greentic", "port": "nope",
                     "identity_file": SECRET_KEY_PATH});
    let store = seeded(dir.path(), Some(&bad));
    let env = env_of(&store);
    let binding = env.pack_for_slot(CapabilitySlot::Deployer).unwrap();
    let err = validate_binding_answers(&store, &env_id(), binding).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid ssh-host binding answers"), "{msg}");
    assert!(msg.contains("port"), "{msg}");
    assert!(!msg.contains(SECRET_KEY_PATH), "{msg}");
}

#[test]
fn an_unknown_answer_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(
        dir.path(),
        Some(&json!({"host": "h", "user": "u", "strict_host_key_checking": "no"})),
    );
    let env = env_of(&store);
    let binding = env.pack_for_slot(CapabilitySlot::Deployer).unwrap();
    let err = validate_binding_answers(&store, &env_id(), binding).unwrap_err();
    assert!(err.to_string().contains("unknown answer key"), "{err}");
}

#[test]
fn other_deployers_and_answerless_bindings_are_not_validated() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), None);
    let env = env_of(&store);
    let binding = env.pack_for_slot(CapabilitySlot::Deployer).unwrap();
    validate_binding_answers(&store, &env_id(), binding).unwrap();

    let mut other = make_binding(CapabilitySlot::Deployer, "greentic.deployer.k8s@1.0.0");
    other.answers_ref = Some("does/not/exist.json".into());
    validate_binding_answers(&store, &env_id(), &other).unwrap();
}

#[test]
fn env_packs_update_refuses_bad_answers_and_leaves_the_binding_alone() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), None);
    write_answers(&store, ENV, &json!({"host": "vm.example.com"}));
    let payload = |answers_ref: &str| env_packs::EnvPackBindingPayload {
        environment_id: ENV.into(),
        slot: CapabilitySlot::Deployer,
        kind: KIND.into(),
        pack_ref: "greentic.deployer.ssh-host".into(),
        answers_ref: Some(answers_ref.into()),
        idempotency_key: None,
    };
    let err =
        env_packs::update(&store, &OpFlags::default(), Some(payload(ANSWERS_REL))).unwrap_err();
    assert!(err.to_string().contains("`user` is required"), "{err}");
    assert!(
        env_of(&store)
            .pack_for_slot(CapabilitySlot::Deployer)
            .unwrap()
            .answers_ref
            .is_none(),
        "the refused update must not have been recorded"
    );

    write_answers(&store, ENV, &answers());
    env_packs::update(&store, &OpFlags::default(), Some(payload(ANSWERS_REL))).unwrap();
    assert!(
        env_of(&store)
            .pack_for_slot(CapabilitySlot::Deployer)
            .unwrap()
            .answers_ref
            .is_some()
    );
}

// ---- credentials requirements -----------------------------------------------

fn requirements(store: &LocalFsStore) -> Result<crate::cli::OpOutcome, crate::cli::OpError> {
    crate::cli::credentials::requirements(
        store,
        &crate::env_packs::EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        Some(crate::cli::credentials::CredentialsRequirementsPayload {
            environment_id: ENV.into(),
        }),
    )
}

#[test]
fn requirements_probes_the_bound_vm_for_real() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), Some(&answers()));
    let remote = vm();
    let _guard = test_remote::install(remote.clone());

    let outcome = requirements(&store).unwrap();
    assert_eq!(outcome.result["result"], "pass", "{}", outcome.result);
    let checks = outcome.result["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 6, "all six VM probes ran: {checks:?}");
    assert!(!remote.commands().is_empty(), "the probes reached the VM");
    assert!(!outcome.result.to_string().contains(SECRET_KEY_PATH));
}

#[test]
fn requirements_report_a_failing_probe_against_the_vm() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), Some(&answers()));
    let remote = Arc::new(FakeRemote {
        systemd_present: false,
        ..FakeRemote::default()
    });
    let _guard = test_remote::install(remote);

    let outcome = requirements(&store).unwrap();
    assert_eq!(outcome.result["result"], "fail");
    let missing = outcome.result["missing_capabilities"].to_string();
    assert!(missing.contains("ssh-host.systemd"), "{missing}");
}

#[test]
fn requirements_without_answers_still_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), None);
    let remote = vm();
    let _guard = test_remote::install(remote.clone());

    let outcome = requirements(&store).unwrap();
    assert_eq!(outcome.result["result"], "fail");
    assert!(remote.commands().is_empty(), "nothing may reach a network");
    let checks = outcome.result["checks"].to_string();
    assert!(checks.contains("records no answers"), "{checks}");
}

#[test]
fn requirements_refuse_invalid_recorded_answers() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), None);
    // Written behind the validating verbs' back (e.g. hand-edited).
    write_answers(
        &store,
        ENV,
        &json!({"host": "-oProxyCommand=x", "user": "u"}),
    );
    let mut env = env_of(&store);
    env.packs[0].answers_ref = Some(ANSWERS_REL.into());
    store.save(&env).unwrap();
    let err = requirements(&store).unwrap_err();
    assert!(
        err.to_string().contains("invalid ssh-host binding answers"),
        "{err}"
    );
}

#[test]
fn connected_credentials_is_none_for_other_deployers() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env(ENV);
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.k8s@1.0.0",
    ));
    store.save(&env).unwrap();
    assert!(connected_credentials(&store, &env_id()).unwrap().is_none());
}

// ---- apply-revision ---------------------------------------------------------

fn apply_revision_args(env: &Environment) -> EnvApplyRevisionArgs {
    EnvApplyRevisionArgs {
        env_id: ENV.into(),
        revision_id: env.revisions[0].revision_id.to_string(),
        kind: None,
        force_drain: false,
    }
}

#[test]
fn apply_revision_warms_the_vm_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), Some(&answers()));
    let env = env_of(&store);
    let remote = vm();
    let _guard = test_remote::install(remote.clone());
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();

    let out = crate::cli::env::apply_revision(
        &store,
        &registry,
        &OpFlags::default(),
        apply_revision_args(&env),
    )
    .unwrap();
    assert_eq!(out.result["action"], "warmed");
    assert_eq!(out.result["worker_name"], format!("greentic-{ENV}"));
    assert_eq!(out.result["identity"], "ssh-identity-file");
    assert!(remote.is_running(&format!("greentic-{ENV}")));
    assert!(!out.result.to_string().contains(SECRET_KEY_PATH));
    let restarts = remote.restarts();

    crate::cli::env::apply_revision(
        &store,
        &registry,
        &OpFlags::default(),
        apply_revision_args(&env),
    )
    .unwrap();
    assert_eq!(
        remote.restarts(),
        restarts,
        "a converged VM is not restarted"
    );
}

#[test]
fn apply_revision_without_recorded_answers_names_the_fix() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), None);
    let env = env_of(&store);
    let remote = vm();
    let _guard = test_remote::install(remote.clone());
    let err = crate::cli::env::apply_revision(
        &store,
        &crate::env_packs::EnvPackRegistry::with_builtins(),
        &OpFlags::default(),
        apply_revision_args(&env),
    )
    .unwrap_err();
    assert!(err.to_string().contains("records no answers"), "{err}");
    assert!(remote.commands().is_empty());
}

// ---- env up -----------------------------------------------------------------

#[test]
fn env_up_from_a_manifest_binds_the_deployer_and_puts_the_store_on_the_vm() {
    let dir = tempfile::tempdir().unwrap();
    // The env exists with a revision but no deployer bound yet.
    let store = LocalFsStore::new(dir.path().join("store"));
    let mut env = make_env(ENV);
    let deployment = make_bundle_deployment(ENV, "demo");
    env.revisions.push(make_revision(
        ENV,
        "demo",
        &deployment.deployment_id,
        1,
        RevisionLifecycle::Ready,
    ));
    env.bundles.push(deployment);
    store.save(&env).unwrap();

    let remote = vm();
    let _guard = test_remote::install(remote.clone());
    let flags = manifest(
        &dir,
        json!([{
            "slot": "deployer",
            "kind": KIND,
            "pack_ref": "greentic.deployer.ssh-host",
            "answers": answers(),
        }]),
    );
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();

    let (outcome, forward) = up(&store, &registry, &flags, up_args()).unwrap();
    assert!(forward.is_none());
    let result = &outcome.result;
    assert_eq!(result["kind"], KIND);
    assert_eq!(result["service"], format!("greentic-{ENV}"));
    assert_eq!(result["listen_addr"], "127.0.0.1:8080");
    assert_eq!(result["store_slot"], "store-a");
    assert_eq!(result["changed"], true);
    assert_eq!(result["exposed"], false);
    assert!(result.get("endpoint_url").is_none(), "{result}");
    assert_eq!(result["revisions"].as_array().unwrap().len(), 1);
    assert!(!result.to_string().contains(SECRET_KEY_PATH));
    assert!(remote.is_running(&format!("greentic-{ENV}")));
    assert!(remote.is_enabled(&format!("greentic-{ENV}")));
    let restarts = remote.restarts();

    // Idempotent: nothing changed, nothing restarted, the same slot is live.
    let (again, _) = up(&store, &registry, &flags, up_args()).unwrap();
    assert_eq!(again.result["changed"], false, "{}", again.result);
    assert_eq!(again.result["store_slot"], "store-a");
    assert_eq!(remote.restarts(), restarts);
}

#[test]
fn env_up_reports_the_endpoint_only_when_exposed() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = answers();
    a["expose"] = json!(true);
    a["listen_port"] = json!(18647);
    let store = seeded(dir.path(), Some(&a));
    let manifest_dir = tempfile::tempdir().unwrap();
    let _guard = test_remote::install(vm());
    let flags = manifest(&manifest_dir, json!([]));
    let (outcome, _) = up(
        &store,
        &crate::env_packs::EnvPackRegistry::with_builtins(),
        &flags,
        up_args(),
    )
    .unwrap();
    assert_eq!(
        outcome.result["endpoint_url"],
        "http://vm.example.com:18647"
    );
    assert_eq!(outcome.result["listen_addr"], "0.0.0.0:18647");
}

#[test]
fn env_up_dry_run_never_touches_the_vm() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), Some(&answers()));
    let manifest_dir = tempfile::tempdir().unwrap();
    let remote = vm();
    let _guard = test_remote::install(remote.clone());
    let flags = manifest(&manifest_dir, json!([]));
    let mut args = up_args();
    args.dry_run = true;
    up(
        &store,
        &crate::env_packs::EnvPackRegistry::with_builtins(),
        &flags,
        args,
    )
    .unwrap();
    assert!(remote.commands().is_empty());
}

#[test]
fn env_up_refuses_bad_manifest_answers_before_anything_changes() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), None);
    let manifest_dir = tempfile::tempdir().unwrap();
    let remote = vm();
    let _guard = test_remote::install(remote.clone());
    let flags = manifest(
        &manifest_dir,
        json!([{
            "slot": "deployer",
            "kind": KIND,
            "pack_ref": "greentic.deployer.ssh-host",
            "answers": {"host": "vm.example.com", "user": "u", "listen_port": 0,
                        "identity_file": SECRET_KEY_PATH},
        }]),
    );
    let err = up(
        &store,
        &crate::env_packs::EnvPackRegistry::with_builtins(),
        &flags,
        up_args(),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("listen_port"), "{msg}");
    assert!(!msg.contains(SECRET_KEY_PATH), "{msg}");
    assert!(remote.commands().is_empty());
}

#[test]
fn env_up_without_a_revision_says_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    write_answers(&store, ENV, &answers());
    let mut env = make_env(ENV);
    let mut binding = make_binding(CapabilitySlot::Deployer, KIND);
    binding.answers_ref = Some(ANSWERS_REL.into());
    env.packs.push(binding);
    store.save(&env).unwrap();
    let remote = vm();
    let _guard = test_remote::install(remote.clone());
    let err = env_up(
        &store,
        &crate::env_packs::EnvPackRegistry::with_builtins(),
        &env_id(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("op deploy"), "{err}");
    assert!(remote.commands().is_empty());
}

#[test]
fn env_up_is_none_for_other_deployers() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env(ENV);
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.k8s@1.0.0",
    ));
    store.save(&env).unwrap();
    assert!(
        env_up(
            &store,
            &crate::env_packs::EnvPackRegistry::with_builtins(),
            &env_id()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn an_unreachable_vm_surfaces_a_clear_error_without_the_key_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), Some(&answers()));
    let remote = Arc::new(FakeRemote {
        unreachable: true,
        ..FakeRemote::default()
    });
    let _guard = test_remote::install(remote);
    let err = env_up(
        &store,
        &crate::env_packs::EnvPackRegistry::with_builtins(),
        &env_id(),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ssh-host"), "{msg}");
    assert!(!msg.contains(SECRET_KEY_PATH), "{msg}");
}

#[test]
fn the_credential_probe_statuses_are_pass_on_a_healthy_vm() {
    // The probes are the deployer's own (covered in env_packs::ssh_host); this
    // pins that the CLI binding hands them the answers' target, not a default.
    let dir = tempfile::tempdir().unwrap();
    let store = seeded(dir.path(), Some(&answers()));
    let _guard = test_remote::install(vm());
    let creds = connected_credentials(&store, &env_id()).unwrap().unwrap();
    let env = env_of(&store);
    let ctx = crate::credentials::ValidationContext {
        env_id: &env_id(),
        env_root: dir.path(),
        host_config: &env.host_config,
    };
    let report = creds.validate(&ctx);
    assert!(
        report
            .checks
            .iter()
            .all(|c| matches!(c.status, CapabilityStatus::Pass)),
        "{:?}",
        report.checks
    );
}
