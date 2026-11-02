//! Handler-level tests for the ssh-host env-pack: registration, wizard,
//! conformance, and the warm / drain procedures against the simulated VM.

use std::sync::Arc;

use greentic_deploy_spec::{CapabilitySlot, Environment, PackDescriptor};
use serde_json::{Value, json};

use super::fake::FakeRemote;
use super::params::ANSWER_KEYS;
use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::deployer::{Deployer, DeployerError, run_conformance};
use crate::env_packs::registry::EnvPackRegistry;

const SERVICE: &str = "greentic-conformance";
const UNIT: &str = "/etc/systemd/system/greentic-conformance.service";

fn answers(extra: Value) -> Value {
    let mut a = json!({"host": "vm.example.com", "user": "greentic"});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    a
}

fn params(extra: Value) -> SshHostParams {
    SshHostParams::from_answers(&build_fixture_env(), &answers(extra)).unwrap()
}

/// A local store shaped like the spike's, for env `conformance`.
fn local_store() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    super::snapshot::tests::fixture_store(dir.path());
    dir
}

/// A handler wired to a fake VM that already has greentic-start installed and
/// to a local store. Keep the `TempDir` alive for the test's duration.
fn setup() -> (SshHostDeployerHandler, Arc<FakeRemote>, tempfile::TempDir) {
    let remote = Arc::new(FakeRemote::default());
    remote.put_executable("/opt/greentic/bin/greentic-start", b"#!binary");
    let store = local_store();
    let handler = SshHostDeployerHandler::with_remote(remote.clone(), Some(params(json!({}))))
        .with_local_store(store.path().to_path_buf(), None);
    (handler, remote, store)
}

/// Same handler, other dev-store bytes.
fn with_dev(
    handler: SshHostDeployerHandler,
    store: &tempfile::TempDir,
    dev: &[u8],
) -> SshHostDeployerHandler {
    handler.with_local_store(store.path().to_path_buf(), Some(dev.to_vec()))
}

/// A handler over a caller-built remote and params, bound to a fresh store.
fn bound(
    remote: &Arc<FakeRemote>,
    p: SshHostParams,
) -> (SshHostDeployerHandler, tempfile::TempDir) {
    let store = local_store();
    let handler = SshHostDeployerHandler::with_remote(remote.clone(), Some(p))
        .with_local_store(store.path().to_path_buf(), None);
    (handler, store)
}

fn first_revision(env: &Environment) -> greentic_deploy_spec::RevisionId {
    env.revisions[0].revision_id
}

async fn warm(handler: &SshHostDeployerHandler, env: &Environment) -> Result<(), DeployerError> {
    handler
        .warm_revision(env, first_revision(env), None)
        .await
        .map(|_| ())
}

fn provider_message(err: DeployerError) -> String {
    match err {
        DeployerError::Provider(m) => m,
        other => panic!("expected a Provider error, got {other:?}"),
    }
}

// ---- registration, wizard, conformance -------------------------------------

#[test]
fn handler_serves_deployer_slot_with_ssh_host_path() {
    let h = SshHostDeployerHandler::default();
    assert_eq!(h.slot(), CapabilitySlot::Deployer);
    assert_eq!(h.descriptor_path(), "greentic.deployer.ssh-host");
    let req = h.supported_versions();
    assert!(req.matches(&"0.1.0".parse().unwrap()));
    assert!(req.matches(&"0.1.9".parse().unwrap()));
    assert!(!req.matches(&"0.2.0".parse().unwrap()));
    assert!(!req.matches(&"1.0.0".parse().unwrap()));
}

#[test]
fn registry_resolves_the_descriptor_for_the_deployer_slot() {
    let registry = EnvPackRegistry::with_builtins();
    let descriptor = PackDescriptor::try_new("greentic.deployer.ssh-host@0.1.0").unwrap();
    let handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .expect("ssh-host is a registered built-in");
    assert!(handler.deployer_credentials().is_some());
    assert!(handler.as_deployer().is_some());
    assert!(
        registry
            .wizard_qaspec_yaml_for_descriptor(&descriptor)
            .unwrap()
            .is_some()
    );
}

#[test]
fn wizard_id_matches_and_questions_are_exactly_the_accepted_answer_keys() {
    let yaml = SshHostDeployerHandler::default()
        .wizard_qaspec_yaml()
        .unwrap();
    let spec: qa_spec::FormSpec = serde_yaml_bw::from_str(yaml).unwrap();
    assert_eq!(spec.id, "greentic.deployer.ssh-host.wizard");
    let ids: Vec<&str> = spec.questions.iter().map(|q| q.id.as_str()).collect();
    assert_eq!(ids, ANSWER_KEYS, "wizard and params parser must agree");
    // No question may ask for a secret VALUE.
    for forbidden in ["password", "passphrase", "private_key", "token"] {
        assert!(!ids.iter().any(|id| id.contains(forbidden)), "{forbidden}");
    }
}

#[test]
fn handler_exposes_credentials_and_deployer() {
    let h = SshHostDeployerHandler::default();
    assert!(
        !h.deployer_credentials()
            .unwrap()
            .requires_credentials_material()
    );
    assert!((&h as &dyn EnvPackHandler).as_deployer().is_some());
}

#[tokio::test]
async fn ssh_host_passes_conformance_against_the_simulated_vm() {
    let (handler, _remote, _store) = setup();
    run_conformance(&handler)
        .await
        .expect("ssh-host satisfies the Phase D conformance contract");
}

#[tokio::test]
async fn default_handler_refuses_without_answers_and_never_reaches_a_network() {
    // `default()` holds the real transport. With no answers and no fallback the
    // verb must stop before any ssh is spawned.
    let handler = SshHostDeployerHandler::default();
    let env = build_fixture_env();
    let msg = provider_message(warm(&handler, &env).await.unwrap_err());
    assert!(msg.contains("answers are required"), "{msg}");
}

#[test]
fn capabilities_claim_nothing_and_say_why() {
    let h = SshHostDeployerHandler::default();
    assert_eq!(
        h.capabilities(),
        crate::env_packs::deployer::AdapterCapabilities::NONE
    );
    assert!(
        h.capability_notes()
            .iter()
            .any(|n| n.contains("one instance per VM"))
    );
}

// ---- warm: sequence and result ---------------------------------------------

#[tokio::test]
async fn warm_on_a_fresh_vm_runs_the_steps_in_order() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    let outcome = handler
        .warm_revision(&env, first_revision(&env), None)
        .await
        .unwrap();
    assert_eq!(
        outcome.endpoint_url, None,
        "loopback bind is not a network endpoint"
    );

    let cmds = remote.commands();
    let pos = |needle: &str| {
        cmds.iter()
            .position(|c| c.contains(needle))
            .unwrap_or_else(|| panic!("no `{needle}` in {cmds:#?}"))
    };
    assert!(
        pos("mkdir -p /opt/greentic/bin /opt/greentic/home /opt/greentic/logs") < pos("test -x")
    );
    assert!(pos("test -x") < pos("cat /opt/greentic/store/.greentic-store.sha256"));
    assert!(pos("cat /opt/greentic/store/") < pos("readlink /opt/greentic/store"));
    assert!(pos("readlink") < pos("rm -rf /opt/greentic/store-a"));
    assert!(pos("rm -rf") < pos("tar -xf - -C /opt/greentic/store-a"));
    assert!(pos("tar -xf") < pos("ln -sfn /opt/greentic/logs /opt/greentic/store-a/logs"));
    assert!(
        pos("ln -sfn /opt/greentic/logs")
            < pos("ln -sfn /opt/greentic/store-a /opt/greentic/store.next")
    );
    assert!(pos("store.next") < pos("mv -T /opt/greentic/store.next /opt/greentic/store"));
    assert!(pos("mv -T") < pos("cmp -s"));
    assert!(pos("cmp -s") < pos("sudo -n install -m 0644"));
    assert!(pos("sudo -n install") < pos("sudo -n systemctl daemon-reload"));
    assert!(pos("daemon-reload") < pos("sudo -n systemctl enable greentic-conformance"));
    assert!(pos("systemctl enable") < pos("sudo -n systemctl restart"));
    assert!(pos("systemctl restart") < pos("systemctl is-active"));

    assert_eq!(
        remote.symlink_target("/opt/greentic/store").as_deref(),
        Some("/opt/greentic/store-a")
    );
    assert!(
        remote
            .file("/opt/greentic/store-a/conformance/environment.json")
            .is_some()
    );
    assert!(
        remote
            .file("/opt/greentic/store-a/.greentic-store.sha256")
            .is_some()
    );
    assert!(
        remote.uploads().iter().all(|u| !u.ends_with(".tar")),
        "the snapshot is streamed, never uploaded as a file: {:?}",
        remote.uploads()
    );
    assert!(remote.is_enabled(SERVICE) && remote.is_running(SERVICE));
    let unit = remote.file_text(UNIT).unwrap();
    assert!(unit.contains(
        "ExecStart=/opt/greentic/bin/greentic-start start --store-root /opt/greentic/store \
         --env conformance --no-browser --nats off --no-updates"
    ));
    assert!(unit.contains("Environment=HOME=/opt/greentic/home"));
    assert!(unit.contains("User=greentic"));
}

#[tokio::test]
async fn expose_makes_the_endpoint_a_network_address_and_rebinds_runtime_json() {
    let remote = Arc::new(FakeRemote::default());
    remote.put_executable("/opt/greentic/bin/greentic-start", b"x");
    let (handler, _store) = bound(
        &remote,
        params(json!({"expose": true, "listen_port": 9191})),
    );
    let env = build_fixture_env();
    let outcome = handler
        .warm_revision(&env, first_revision(&env), None)
        .await
        .unwrap();
    assert_eq!(
        outcome.endpoint_url.as_deref(),
        Some("http://vm.example.com:9191")
    );
    let runtime = remote
        .file_text("/opt/greentic/store/conformance/runtime.json")
        .unwrap();
    assert!(runtime.contains("0.0.0.0:9191"), "{runtime}");
    let unit = remote.file_text(UNIT).unwrap();
    assert!(unit.contains("GREENTIC_GATEWAY_LISTEN_ADDR=0.0.0.0"));
    assert!(unit.contains("GREENTIC_GATEWAY_PORT=9191"));
}

#[tokio::test]
async fn the_vm_gets_the_portable_set_and_none_of_the_excluded_files() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    let base = "/opt/greentic/store/conformance";
    // Shipped, including the lookalikes a `*.lock` glob would have dropped.
    for kept in [
        "revisions/r1/pack-list.lock",
        "revisions/r1/bundle.lock.json",
        "revisions/r1/bundle-lock.json",
        "revisions/r1/manifest.json",
        "revisions/r1/bundle/.greentic/dev/.dev.secrets.env",
        "runtime.json",
    ] {
        assert!(
            remote.file(&format!("{base}/{kept}")).is_some(),
            "{kept} must be shipped"
        );
    }
    for dropped in [
        ".lock",
        ".greentic/dev/.dev.secrets.env",
        ".greentic/dev/.dev.secrets.env.lock",
        ".greentic/state/dev/.dev.secrets.env",
        "backups/b1.json",
        "audit/a.log",
        "revisions/r1/bundle.gtbundle",
    ] {
        assert!(
            remote.file(&format!("{base}/{dropped}")).is_none(),
            "{dropped} must not be shipped"
        );
    }
    // The runtime's own state at the local store root, and other envs, never travel.
    assert!(
        remote
            .file("/opt/greentic/store/revision-signing.key")
            .is_none()
    );
    assert!(
        remote
            .file("/opt/greentic/store/other-env/environment.json")
            .is_none()
    );
}

#[tokio::test]
async fn warm_without_a_bound_local_store_refuses_before_the_vm() {
    let remote = Arc::new(FakeRemote::default());
    let handler = SshHostDeployerHandler::with_remote(remote.clone(), Some(params(json!({}))));
    let env = build_fixture_env();
    let msg = provider_message(warm(&handler, &env).await.unwrap_err());
    assert!(msg.contains("no local store is bound"), "{msg}");
    assert!(remote.calls().is_empty());
}

#[tokio::test]
async fn warm_honours_answers_over_the_fallback() {
    let (handler, remote, _store) = setup();
    remote.add_dir("/opt/greentic/alt");
    remote.put_executable("/opt/greentic/alt/bin/greentic-start", b"x");
    let env = build_fixture_env();
    let a = answers(
        json!({"install_dir": "/opt/greentic/alt", "listen_port": 9191, "expose": true, "service_name": "gt-alt"}),
    );
    let outcome = handler
        .warm_revision(&env, first_revision(&env), Some(&a))
        .await
        .unwrap();
    assert_eq!(
        outcome.endpoint_url.as_deref(),
        Some("http://vm.example.com:9191")
    );
    assert!(remote.file("/etc/systemd/system/gt-alt.service").is_some());
    assert_eq!(
        remote.symlink_target("/opt/greentic/alt/store").as_deref(),
        Some("/opt/greentic/alt/store-a")
    );
}

#[tokio::test]
async fn warm_rejects_injection_in_answers_before_touching_the_vm() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    for bad in [
        answers(json!({"install_dir": "/opt/x; rm -rf /"})),
        answers(json!({"install_dir": "/opt/$(id)"})),
        answers(json!({"service_name": "a b"})),
        answers(json!({"install_dir": "/opt/../etc"})),
        answers(json!({"host": "-oProxyCommand=id"})),
    ] {
        let err = handler
            .warm_revision(&env, first_revision(&env), Some(&bad))
            .await
            .unwrap_err();
        assert!(provider_message(err).starts_with("ssh-host:"));
    }
    assert!(
        remote.calls().is_empty(),
        "no command may be sent for invalid answers"
    );
}

// ---- warm: idempotency and change detection ---------------------------------

#[tokio::test]
async fn a_second_warm_changes_and_restarts_nothing() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    assert_eq!(remote.restarts(), 1);
    remote.clear_calls();

    warm(&handler, &env).await.unwrap();
    assert_eq!(
        remote.restarts(),
        1,
        "unchanged inputs must not restart the service"
    );
    let cmds = remote.commands().join("\n");
    for forbidden in [
        "tar -xf",
        "mv -T",
        "rm -rf",
        "install -m",
        "daemon-reload",
        "restart",
    ] {
        assert!(
            !cmds.contains(forbidden),
            "`{forbidden}` ran on a converged VM:\n{cmds}"
        );
    }
    assert!(remote.is_running(SERVICE));
}

#[tokio::test]
async fn warm_restarts_a_stopped_but_converged_service_without_a_restart_cycle() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    // Simulate an operator having stopped it.
    let a = answers(json!({}));
    handler
        .drain_revision(&unrouted(&env), first_revision(&env), Some(&a))
        .await
        .unwrap();
    assert!(!remote.is_running(SERVICE));
    warm(&handler, &env).await.unwrap();
    assert!(remote.is_running(SERVICE));
    assert_eq!(
        remote.restarts(),
        1,
        "`enable --now` starts it; no restart needed"
    );
}

#[tokio::test]
async fn a_changedstore_flips_slots_atomically_and_restarts() {
    let (handler, remote, store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    assert_eq!(
        remote.symlink_target("/opt/greentic/store").as_deref(),
        Some("/opt/greentic/store-a")
    );

    let handler = with_dev(handler, &store, b"ciphertext-1");
    warm(&handler, &env).await.unwrap();
    assert_eq!(
        remote.symlink_target("/opt/greentic/store").as_deref(),
        Some("/opt/greentic/store-b")
    );
    assert_eq!(remote.restarts(), 2);
    assert_eq!(
        remote
            .file("/opt/greentic/store/conformance/.greentic/dev/.dev.secrets.env")
            .as_deref(),
        Some(&b"ciphertext-1"[..])
    );
    // The previous generation is intact for a manual rollback.
    assert!(
        remote
            .file("/opt/greentic/store-a/conformance/environment.json")
            .is_some()
    );

    let handler = with_dev(handler, &store, b"ciphertext-2");
    warm(&handler, &env).await.unwrap();
    assert_eq!(
        remote.symlink_target("/opt/greentic/store").as_deref(),
        Some("/opt/greentic/store-a")
    );
    assert_eq!(remote.restarts(), 3);
}

#[tokio::test]
async fn dev_secrets_travel_only_inside_the_private_snapshot() {
    let (handler, remote, store) = setup();
    let handler = with_dev(handler, &store, b"VERY-SECRET-CIPHERTEXT");
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    // Not in any command line, and the uploaded tar is gone from the VM.
    assert!(!remote.commands().join("\n").contains("VERY-SECRET"));
    assert!(remote.uploads().iter().all(|u| !u.ends_with(".tar")));
    // Not in the unit either.
    assert!(!remote.file_text(UNIT).unwrap().contains("VERY-SECRET"));
}

// ---- warm: the binary --------------------------------------------------------

#[tokio::test]
async fn warm_without_a_binary_fails_clearly_and_installs_nothing() {
    let remote = Arc::new(FakeRemote::default());
    let (handler, _store) = bound(&remote, params(json!({})));
    let env = build_fixture_env();
    let msg = provider_message(warm(&handler, &env).await.unwrap_err());
    assert!(msg.contains("start_binary"), "{msg}");
    assert!(msg.contains("/opt/greentic/bin/greentic-start"), "{msg}");
    assert!(msg.contains("vm.example.com"), "{msg}");
    assert!(remote.symlink_target("/opt/greentic/store").is_none());
    assert!(remote.file(UNIT).is_none());
}

#[tokio::test]
async fn start_binary_is_copied_atomically_and_only_when_it_differs() {
    let local = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(local.path(), b"greentic-start v1").unwrap();
    let remote = Arc::new(FakeRemote::default());
    let p = params(json!({"start_binary": local.path().to_str().unwrap()}));
    let (handler, _store) = bound(&remote, p);
    let env = build_fixture_env();

    warm(&handler, &env).await.unwrap();
    let cmds = remote.commands();
    let pos = |needle: &str| cmds.iter().position(|c| c.contains(needle)).unwrap();
    assert!(
        remote
            .uploads()
            .contains(&"/opt/greentic/bin/greentic-start.new".to_string())
    );
    assert!(
        pos("chmod 0755 /opt/greentic/bin/greentic-start.new")
            < pos("mv -f /opt/greentic/bin/greentic-start.new /opt/greentic/bin/greentic-start")
    );
    assert_eq!(
        remote.file("/opt/greentic/bin/greentic-start").as_deref(),
        Some(&b"greentic-start v1"[..])
    );
    assert!(
        remote
            .file("/opt/greentic/bin/greentic-start.new")
            .is_none()
    );

    // Same bytes: not copied, no restart.
    remote.clear_calls();
    warm(&handler, &env).await.unwrap();
    assert!(
        !remote
            .uploads()
            .iter()
            .any(|u| u.contains("greentic-start.new"))
    );
    assert_eq!(remote.restarts(), 1);

    // New bytes: copied, restarted.
    std::fs::write(local.path(), b"greentic-start v2").unwrap();
    warm(&handler, &env).await.unwrap();
    assert_eq!(
        remote.file("/opt/greentic/bin/greentic-start").as_deref(),
        Some(&b"greentic-start v2"[..])
    );
    assert_eq!(remote.restarts(), 2);
}

#[tokio::test]
async fn an_unreadable_start_binary_is_a_clear_error() {
    let remote = Arc::new(FakeRemote::default());
    let p = params(json!({"start_binary": "/nonexistent/greentic-start"}));
    let (handler, _store) = bound(&remote, p);
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(
        msg.contains("start_binary") && msg.contains("/nonexistent/greentic-start"),
        "{msg}"
    );
}

#[tokio::test]
async fn a_start_binary_that_does_not_run_is_never_installed() {
    let local = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(local.path(), b"").unwrap(); // an empty file does not execute
    let remote = Arc::new(FakeRemote::default());
    remote.put_executable("/opt/greentic/bin/greentic-start", b"working v1");
    let p = params(json!({"start_binary": local.path().to_str().unwrap()}));
    let (handler, _store) = bound(&remote, p);
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("checking the new greentic-start"), "{msg}");
    assert!(msg.contains("NOT installed"), "{msg}");
    // The working binary is untouched, the staged file is gone, nothing restarted
    // and no store or unit was touched.
    assert_eq!(
        remote.file("/opt/greentic/bin/greentic-start").as_deref(),
        Some(&b"working v1"[..])
    );
    assert!(
        remote
            .file("/opt/greentic/bin/greentic-start.new")
            .is_none()
    );
    assert_eq!(remote.restarts(), 0);
    assert!(remote.symlink_target("/opt/greentic/store").is_none());
    assert!(remote.file(UNIT).is_none());
}

// ---- warm: the service account ---------------------------------------------

#[tokio::test]
async fn a_service_user_owns_what_the_runtime_writes_and_runs_the_unit() {
    let (handler, remote, _store) = {
        let remote = Arc::new(FakeRemote::default());
        remote.put_executable("/opt/greentic/bin/greentic-start", b"#!binary");
        let (h, s) = bound(&remote, params(json!({"service_user": "nobody"})));
        (h, remote, s)
    };
    warm(&handler, &build_fixture_env()).await.unwrap();
    let cmds = remote.commands();
    let pos = |needle: &str| cmds.iter().position(|c| c.contains(needle)).unwrap();
    // The account is looked up before anything is created or changed.
    assert!(pos("id -u nobody") < pos("mkdir -p"));
    // home/logs are handed over, and the NEW slot is handed over before it is live.
    assert!(
        cmds.iter().any(|c| c.contains(
            "sudo -n chown -R -h nobody /opt/greentic/home /opt/greentic/logs"
        )),
        "{cmds:?}"
    );
    assert!(
        pos("sudo -n chown -R -h nobody /opt/greentic/store-a")
            < pos("mv -T /opt/greentic/store.next /opt/greentic/store")
    );
    assert!(remote.file_text(UNIT).unwrap().contains("\nUser=nobody\n"));

    // An unchanged store is re-owned (the account may have changed), not re-sent.
    remote.clear_calls();
    warm(&handler, &build_fixture_env()).await.unwrap();
    let again = remote.commands();
    assert!(
        again
            .iter()
            .any(|c| c.contains("chown -R -h nobody /opt/greentic/store/."))
    );
    assert!(!again.iter().any(|c| c.contains("tar -xf")));
    assert_eq!(remote.restarts(), 1);
}

#[tokio::test]
async fn an_unknown_service_user_fails_before_anything_is_created() {
    let remote = Arc::new(FakeRemote::default());
    remote.put_executable("/opt/greentic/bin/greentic-start", b"#!binary");
    remote.fail_command(
        "id -u ghost",
        RemoteOutput::failed(1, "id: 'ghost': no such user"),
    );
    let (handler, _store) = bound(&remote, params(json!({"service_user": "ghost"})));
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("checking the service account"), "{msg}");
    assert!(msg.contains("no such user"), "{msg}");
    assert!(remote.symlink_target("/opt/greentic/store").is_none());
    assert!(remote.file(UNIT).is_none());
    assert!(!remote.commands().iter().any(|c| c.contains("mkdir")));
}

#[tokio::test]
async fn a_service_user_equal_to_the_login_user_changes_nothing() {
    let (handler, remote, _store) = {
        let remote = Arc::new(FakeRemote::default());
        remote.put_executable("/opt/greentic/bin/greentic-start", b"#!binary");
        let (h, s) = bound(&remote, params(json!({"service_user": "greentic"})));
        (h, remote, s)
    };
    warm(&handler, &build_fixture_env()).await.unwrap();
    assert!(
        !remote
            .commands()
            .iter()
            .any(|c| c.contains("chown") || c.contains("id -u"))
    );
}

// ---- warm: failures leave no half-done swap ----------------------------------

/// (command needle that fails, phrase the error must contain)
const FAILURE_POINTS: &[(&str, &str)] = &[
    (
        "mkdir -p /opt/greentic/bin",
        "creating the install directories",
    ),
    (
        "rm -rf /opt/greentic/store-a",
        "clearing the inactive store slot",
    ),
    (
        "mkdir -p /opt/greentic/store-a",
        "creating the inactive store slot",
    ),
    ("tar -xf", "extracting the store snapshot"),
    (
        "ln -sfn /opt/greentic/logs",
        "linking the persistent logs directory",
    ),
    (
        "ln -sfn /opt/greentic/store-a",
        "preparing the store switch",
    ),
    ("mv -T", "activating the new store"),
    ("sudo -n install", "installing the systemd unit"),
    ("daemon-reload", "reloading systemd"),
    ("systemctl enable", "enabling the service"),
    ("systemctl restart", "restarting the service"),
    ("systemctl is-active", "checking the service"),
];

#[tokio::test]
async fn a_failure_at_any_step_is_reported_with_its_step_and_never_half_swaps_the_store() {
    for (needle, phrase) in FAILURE_POINTS {
        let (handler, remote, _store) = setup();
        remote.fail_command(needle, RemoteOutput::failed(1, "simulated failure"));
        let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
        assert!(msg.starts_with("ssh-host:"), "{needle}: {msg}");
        assert!(
            msg.contains(phrase),
            "{needle}: expected `{phrase}` in `{msg}`"
        );
        assert!(msg.contains("vm.example.com"), "{needle}: {msg}");
        // Before `mv -T` succeeds, the live store path must not exist: the swap
        // is all-or-nothing.
        let activated = remote.commands().iter().any(|c| c.contains("mv -T")) && *needle != "mv -T";
        if !activated {
            assert!(
                remote.symlink_target("/opt/greentic/store").is_none(),
                "{needle}: live store switched despite the failure"
            );
        }
        assert!(
            remote.uploads().iter().all(|u| !u.ends_with(".tar")),
            "{needle}: no snapshot file may be written to the VM"
        );
    }
}

#[tokio::test]
async fn runtime_state_survives_a_store_change() {
    let (handler, remote, store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    // The runtime writes its signing key into the store root and logs beside it.
    remote.put_file("/opt/greentic/store/revision-signing.key", b"RUNTIME-KEY-1");
    remote.put_file("/opt/greentic/store/logs/run.log", b"line");
    assert_eq!(
        remote.file("/opt/greentic/logs/run.log").as_deref(),
        Some(&b"line"[..])
    );

    for round in 0..3u8 {
        let handler = with_dev(setup_clone(&remote, &store), &store, &[round]);
        warm(&handler, &env).await.unwrap();
        assert_eq!(
            remote
                .file("/opt/greentic/store/revision-signing.key")
                .as_deref(),
            Some(&b"RUNTIME-KEY-1"[..]),
            "round {round}: the signing key must be carried over"
        );
        assert_eq!(
            remote.file("/opt/greentic/store/logs/run.log").as_deref(),
            Some(&b"line"[..]),
            "round {round}: logs live outside the slots"
        );
    }
}

fn setup_clone(remote: &Arc<FakeRemote>, store: &tempfile::TempDir) -> SshHostDeployerHandler {
    SshHostDeployerHandler::with_remote(remote.clone(), Some(params(json!({}))))
        .with_local_store(store.path().to_path_buf(), None)
}

#[tokio::test]
async fn a_failed_unit_upload_after_activation_does_not_restart_or_roll_back_the_store() {
    let (handler, remote, _store) = setup();
    remote.fail_upload(".service.new");
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("uploading the systemd unit"), "{msg}");
    assert_eq!(remote.restarts(), 0);
    assert!(!remote.is_running(SERVICE));
}

#[tokio::test]
async fn a_failed_extraction_after_a_good_deploy_keeps_serving_the_oldstore() {
    let (handler, remote, store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();

    let handler = with_dev(handler, &store, b"new");
    remote.fail_command("tar -xf", RemoteOutput::failed(2, "tar: unexpected EOF"));
    assert!(warm(&handler, &env).await.is_err());
    assert_eq!(
        remote.symlink_target("/opt/greentic/store").as_deref(),
        Some("/opt/greentic/store-a")
    );
}

#[tokio::test]
async fn a_wedged_activation_onto_a_real_directory_fails_without_data_loss() {
    // `mv -T` cannot replace a real directory: the operator must move it away.
    let (handler, remote, _store) = setup();
    remote.add_dir("/opt/greentic/store");
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("activating the new store"), "{msg}");
    assert!(remote.symlink_target("/opt/greentic/store").is_none());
}

#[tokio::test]
async fn missing_sudo_fails_at_the_unit_install_not_after_a_partial_start() {
    let remote = Arc::new(FakeRemote {
        sudo_works: false,
        ..FakeRemote::default()
    });
    remote.put_executable("/opt/greentic/bin/greentic-start", b"x");
    let (handler, _store) = bound(&remote, params(json!({})));
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("installing the systemd unit"), "{msg}");
    assert!(msg.contains("password is required"), "{msg}");
    assert!(!remote.is_running(SERVICE));
}

#[tokio::test]
async fn root_login_without_sudo_runs_systemctl_directly() {
    let remote = Arc::new(FakeRemote {
        is_root: true,
        ..FakeRemote::default()
    });
    remote.put_executable("/opt/greentic/bin/greentic-start", b"x");
    let p = params(json!({"user": "root"}));
    assert!(!p.use_sudo);
    let (handler, _store) = bound(&remote, p);
    warm(&handler, &build_fixture_env()).await.unwrap();
    assert!(remote.commands().iter().all(|c| !c.starts_with("sudo")));
    assert!(!remote.file_text(UNIT).unwrap().contains("User="));
}

#[tokio::test]
async fn an_unreachable_vm_is_a_transport_error_naming_the_host() {
    let remote = Arc::new(FakeRemote {
        unreachable: true,
        ..FakeRemote::default()
    });
    let (handler, _store) = bound(&remote, params(json!({})));
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(
        msg.contains("vm.example.com") && msg.contains("Connection timed out"),
        "{msg}"
    );
}

#[tokio::test]
async fn a_service_that_does_not_stay_active_points_at_the_journal() {
    let (handler, remote, _store) = setup();
    remote.fail_command("is-active", RemoteOutput::failed(3, ""));
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("journalctl -u greentic-conformance"), "{msg}");
}

#[tokio::test]
async fn a_service_that_does_not_stay_active_quotes_the_journal_tail() {
    let (handler, remote, _store) = setup();
    remote.fail_command("is-active", RemoteOutput::failed(3, "activating\n"));
    remote.fail_command(
        "journalctl",
        RemoteOutput::with_stdout(
            "Error: creating runtime-config debouncer\nToo many open files\n",
        ),
    );
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("last log lines:"), "{msg}");
    assert!(msg.contains("Too many open files"), "{msg}");
    // Read as root-or-sudo: a journal readable only by privileged users.
    assert!(
        remote
            .commands()
            .iter()
            .any(|c| c.contains("sudo -n journalctl -u greentic-conformance"))
    );
}

#[tokio::test]
async fn an_unreadable_journal_leaves_the_error_without_a_tail() {
    let (handler, remote, _store) = setup();
    remote.fail_command("is-active", RemoteOutput::failed(3, ""));
    remote.fail_command("journalctl", RemoteOutput::failed(1, "not permitted"));
    let msg = provider_message(warm(&handler, &build_fixture_env()).await.unwrap_err());
    assert!(msg.contains("journalctl -u greentic-conformance"), "{msg}");
    assert!(!msg.contains("last log lines"), "{msg}");
}

#[tokio::test]
async fn the_service_is_judged_only_after_it_has_had_time_to_crash() {
    let (handler, remote, _store) = setup();
    warm(&handler, &build_fixture_env()).await.unwrap();
    let cmds = remote.commands();
    let pos = |needle: &str| cmds.iter().position(|c| c.contains(needle)).unwrap();
    assert!(pos("systemctl restart") < pos("sleep 3"));
    assert!(pos("sleep 3") < pos("systemctl is-active"));
}

#[tokio::test]
async fn the_identity_file_path_never_appears_in_commands_uploads_or_errors() {
    let remote = Arc::new(FakeRemote::default());
    remote.put_executable("/opt/greentic/bin/greentic-start", b"x");
    let p = params(json!({"identity_file": "/home/ops/.ssh/TOPSECRET_KEY"}));
    let (handler, _store) = bound(&remote, p);
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    remote.fail_command("is-active", RemoteOutput::failed(3, ""));
    let err = provider_message(
        handler
            .warm_revision(&env, first_revision(&env), None)
            .await
            .unwrap_err(),
    );
    let everything = format!("{:?}{err}{:?}", remote.calls(), handler);
    assert!(!everything.contains("TOPSECRET_KEY"), "{everything}");
}

// ---- drain / archive / split --------------------------------------------------

fn unrouted(env: &Environment) -> Environment {
    let mut env = env.clone();
    for split in &mut env.traffic_splits {
        for entry in &mut split.entries {
            entry.weight_bps = 0;
        }
    }
    env
}

#[tokio::test]
async fn drain_leaves_the_service_up_while_any_revision_is_still_routed() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    remote.clear_calls();
    let out = handler
        .drain_revision(&env, first_revision(&env), Some(&answers(json!({}))))
        .await
        .unwrap();
    assert_eq!(out, Default::default(), "no drain evidence is claimed");
    assert!(
        remote.calls().is_empty(),
        "a routed env must not touch the VM"
    );
    assert!(remote.is_running(SERVICE));
}

#[tokio::test]
async fn drain_stops_the_service_once_nothing_is_routed_and_is_idempotent() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    warm(&handler, &env).await.unwrap();
    let idle = unrouted(&env);
    let a = answers(json!({}));
    for _ in 0..2 {
        handler
            .drain_revision(&idle, first_revision(&idle), Some(&a))
            .await
            .unwrap();
        assert!(!remote.is_running(SERVICE));
    }
    assert!(
        remote
            .commands()
            .iter()
            .any(|c| c == "sudo -n systemctl stop greentic-conformance")
    );
}

#[tokio::test]
async fn drain_treats_an_uninstalled_unit_as_already_stopped_but_surfaces_other_failures() {
    let (handler, remote, _store) = setup(); // nothing warmed: the unit does not exist (systemd exit 5)
    let idle = unrouted(&build_fixture_env());
    let a = answers(json!({}));
    handler
        .drain_revision(&idle, first_revision(&idle), Some(&a))
        .await
        .unwrap();

    remote.fail_command("systemctl stop", RemoteOutput::failed(1, "Access denied"));
    let msg = provider_message(
        handler
            .drain_revision(&idle, first_revision(&idle), Some(&a))
            .await
            .unwrap_err(),
    );
    assert!(
        msg.contains("stopping the service") && msg.contains("Access denied"),
        "{msg}"
    );
}

#[tokio::test]
async fn archive_and_traffic_split_never_touch_the_vm() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    handler
        .stage_revision(&env, first_revision(&env))
        .await
        .unwrap();
    handler
        .archive_revision(&env, first_revision(&env), None)
        .await
        .unwrap();
    handler
        .apply_traffic_split(&env, env.bundles[0].deployment_id, None)
        .await
        .unwrap();
    assert!(remote.calls().is_empty());
}

#[tokio::test]
async fn every_verb_rejects_an_unknown_revision_before_the_vm() {
    let (handler, remote, _store) = setup();
    let env = build_fixture_env();
    let unknown = greentic_deploy_spec::RevisionId(ulid::Ulid::from(0xFFFF_u128));
    assert!(matches!(
        handler.stage_revision(&env, unknown).await,
        Err(DeployerError::RevisionNotFound { .. })
    ));
    assert!(matches!(
        handler.warm_revision(&env, unknown, None).await,
        Err(DeployerError::RevisionNotFound { .. })
    ));
    assert!(matches!(
        handler.drain_revision(&env, unknown, None).await,
        Err(DeployerError::RevisionNotFound { .. })
    ));
    assert!(matches!(
        handler.archive_revision(&env, unknown, None).await,
        Err(DeployerError::RevisionNotFound { .. })
    ));
    assert!(remote.calls().is_empty());
}
