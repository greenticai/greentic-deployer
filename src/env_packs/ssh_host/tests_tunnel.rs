//! The `tunnel` answer end to end against the simulated VM: parsing, the
//! once-per-`env up` lifetime, the route every operation takes, and the
//! credentials probe. The providers used here start nothing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use greentic_deploy_spec::EnvironmentHostConfig;
use serde_json::{Value, json};

use super::fake::{Call, FakeRemote};
use super::tunnel::{
    TunnelConfig, TunnelContext, TunnelError, TunnelGuard, TunnelProvider, TunnelRegistry, TunnelUp,
};
use super::*;
use crate::credentials::{CapabilityStatus, DeployerCredentials, ValidationContext};
use crate::env_packs::deployer::Deployer;
use crate::env_packs::deployer::conformance::build_fixture_env;

const PROXY: &str = "test-proxy %h %p";

/// Counts how often a tunnel is brought up and torn down.
#[derive(Debug, Default)]
struct Recorder {
    ups: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    fail: bool,
}

impl TunnelProvider for Recorder {
    fn kind(&self) -> &'static str {
        "recorder"
    }

    fn validate(&self, _settings: &BTreeMap<String, String>) -> Result<(), TunnelError> {
        Ok(())
    }

    fn up(&self, _ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError> {
        self.ups.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(TunnelError::up("recorder", "the gateway refused the login"));
        }
        let closed = Arc::clone(&self.closed);
        let mut guard = TunnelGuard::empty();
        guard.on_drop(move || {
            closed.fetch_add(1, Ordering::SeqCst);
        });
        Ok(TunnelUp {
            proxy_command: Some(PROXY.into()),
            guard,
        })
    }
}

fn recorder(fail: bool) -> (Arc<TunnelRegistry>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let provider = Recorder {
        fail,
        ..Recorder::default()
    };
    let (ups, closed) = (Arc::clone(&provider.ups), Arc::clone(&provider.closed));
    (
        Arc::new(TunnelRegistry::with_providers(vec![Box::new(provider)])),
        ups,
        closed,
    )
}

fn answers(extra: Value) -> Value {
    let mut a = json!({"host": "vm.example.com", "user": "greentic"});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    a
}

fn parse(extra: Value) -> Result<SshHostParams, params::SshHostParamsError> {
    SshHostParams::from_answers(&build_fixture_env(), &answers(extra))
}

fn with_recorder_tunnel() -> SshHostParams {
    let mut p = parse(json!({})).unwrap();
    p.tunnel = Some(TunnelConfig {
        kind: "recorder".into(),
        settings: BTreeMap::new(),
    });
    p
}

fn store() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    super::snapshot::tests::fixture_store(dir.path());
    dir
}

fn vm() -> Arc<FakeRemote> {
    let remote = Arc::new(FakeRemote::default());
    remote.put_executable("/opt/greentic/bin/greentic-start", b"#!binary");
    remote
}

// ---- parsing ---------------------------------------------------------------

#[test]
fn no_tunnel_answer_means_no_tunnel() {
    assert_eq!(parse(json!({})).unwrap().tunnel, None);
    assert_eq!(parse(json!({"tunnel": null})).unwrap().tunnel, None);
}

#[test]
fn a_tunnel_answer_is_parsed_strictly() {
    let p = parse(json!({"tunnel": {"kind": "none"}})).unwrap();
    assert_eq!(p.tunnel.unwrap().kind, "none");
    let p = parse(json!({"tunnel": {"kind": "jump", "settings": {
        "jump_host": "bastion.example.com", "jump_known_hosts_file": "/keys/kh", "jump_port": 2200
    }}}))
    .unwrap();
    let t = p.tunnel.unwrap();
    assert_eq!(
        t.settings["jump_port"], "2200",
        "numbers are read as their text"
    );

    for bad in [
        json!("jump"),
        json!({}),
        json!({"kind": ""}),
        json!({"kind": 7}),
        json!({"kind": "none", "extra": 1}),
        json!({"kind": "none", "settings": "x"}),
        json!({"kind": "none", "settings": {"a": ["list"]}}),
        json!({"kind": "teleporter"}),
        json!({"kind": "jump", "settings": {"jump_host": "b.example.com"}}),
    ] {
        assert!(parse(json!({"tunnel": bad.clone()})).is_err(), "{bad}");
    }
}

#[test]
fn a_bad_tunnel_setting_is_refused_where_the_answers_are_written_and_never_echoed() {
    let err = parse(json!({"tunnel": {"kind": "jump", "settings": {
        "jump_host": "b.example.com;reboot", "jump_known_hosts_file": "/keys/kh"
    }}}))
    .unwrap_err()
    .to_string();
    assert!(err.contains("tunnel") && err.contains("jump_host"), "{err}");
    assert!(!err.contains("reboot"), "{err}");
}

#[test]
fn the_debug_output_of_the_params_shows_no_tunnel_setting_values() {
    let p = parse(json!({"tunnel": {"kind": "proxy", "settings": {
        "proxy_type": "socks5", "proxy_host": "p.example.com", "proxy_port": "1080",
        "proxy_user": "svc", "proxy_password_file": "/keys/very-secret-path"
    }}}))
    .unwrap();
    let dbg = format!("{p:?}");
    assert!(
        !dbg.contains("very-secret-path") && !dbg.contains("svc"),
        "{dbg}"
    );
}

// ---- once per `env up`, on every operation -----------------------------------

#[tokio::test]
async fn one_warm_brings_the_tunnel_up_once_and_every_operation_rides_it() {
    let (registry, ups, closed) = recorder(false);
    let remote = vm();
    let dir = store();
    let handler = SshHostDeployerHandler::with_remote(remote.clone(), Some(with_recorder_tunnel()))
        .with_tunnels(registry)
        .with_local_store(dir.path().to_path_buf(), None);
    let env = build_fixture_env();
    let report = handler
        .warm_with_report(&env, &[env.revisions[0].revision_id], None)
        .await
        .unwrap();
    assert!(report.changed);

    assert_eq!(
        ups.load(Ordering::SeqCst),
        1,
        "one tunnel for the whole warm, not one per command"
    );
    assert_eq!(
        closed.load(Ordering::SeqCst),
        1,
        "torn down when the warm ends"
    );
    let targets = remote.targets();
    assert!(targets.len() > 5, "the warm ran many operations");
    assert!(
        targets
            .iter()
            .all(|t| t.proxy_command.as_deref() == Some(PROXY)),
        "commands, tar streams and uploads all take the tunnel"
    );
    assert!(remote.calls().iter().any(|c| matches!(c, Call::Upload(_))));
}

#[tokio::test]
async fn a_tunnel_that_cannot_come_up_stops_the_warm_before_the_vm_is_touched() {
    let (registry, ups, closed) = recorder(true);
    let remote = vm();
    let dir = store();
    let handler = SshHostDeployerHandler::with_remote(remote.clone(), Some(with_recorder_tunnel()))
        .with_tunnels(registry)
        .with_local_store(dir.path().to_path_buf(), None);
    let env = build_fixture_env();
    let err = handler
        .warm_revision(&env, env.revisions[0].revision_id, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("could not be brought up") && err.contains("refused the login"),
        "{err}"
    );
    assert_eq!(ups.load(Ordering::SeqCst), 1, "no retry");
    assert_eq!(closed.load(Ordering::SeqCst), 0);
    assert!(remote.calls().is_empty(), "the VM was never touched");
}

#[tokio::test]
async fn a_kind_this_build_cannot_bring_up_refuses_without_touching_the_vm() {
    let remote = vm();
    let dir = store();
    let handler = SshHostDeployerHandler::with_remote(remote.clone(), None)
        .with_local_store(dir.path().to_path_buf(), None);
    let env = build_fixture_env();
    for kind in ["wireguard", "tailscale", "openvpn", "ikev2", "zerotier"] {
        let a = answers(json!({"tunnel": {"kind": kind}}));
        let err = handler
            .warm_revision(&env, env.revisions[0].revision_id, Some(&a))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not available in this build"), "{kind}: {err}");
    }
    assert!(remote.calls().is_empty());
}

#[tokio::test]
async fn drain_rides_the_tunnel_too() {
    let (registry, ups, closed) = recorder(false);
    let remote = vm();
    let handler = SshHostDeployerHandler::with_remote(remote.clone(), Some(with_recorder_tunnel()))
        .with_tunnels(registry);
    let mut env = build_fixture_env();
    env.traffic_splits.clear();
    handler
        .drain_revision(&env, env.revisions[0].revision_id, None)
        .await
        .unwrap();
    assert_eq!(ups.load(Ordering::SeqCst), 1);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(
        remote
            .targets()
            .iter()
            .all(|t| t.proxy_command.as_deref() == Some(PROXY))
    );
}

#[tokio::test]
async fn without_a_tunnel_the_targets_carry_no_proxy_command() {
    let remote = vm();
    let dir = store();
    let handler =
        SshHostDeployerHandler::with_remote(remote.clone(), Some(parse(json!({})).unwrap()))
            .with_local_store(dir.path().to_path_buf(), None);
    let env = build_fixture_env();
    handler
        .warm_revision(&env, env.revisions[0].revision_id, None)
        .await
        .unwrap();
    assert!(remote.targets().iter().all(|t| t.proxy_command.is_none()));
}

// ---- credentials -----------------------------------------------------------

fn validate(creds: &SshHostCredentials) -> crate::credentials::RequirementsReport {
    let env = build_fixture_env();
    let hc = EnvironmentHostConfig::new(env.environment_id.clone());
    let dir = tempfile::tempdir().unwrap();
    creds.validate(&ValidationContext {
        env_id: &env.environment_id,
        env_root: dir.path(),
        host_config: &hc,
    })
}

#[test]
fn a_configured_tunnel_is_probed_first_and_the_probes_ride_it() {
    let (registry, ups, closed) = recorder(false);
    let remote = vm();
    let creds = SshHostCredentials::with_target(remote.clone(), with_recorder_tunnel())
        .with_tunnels(registry);
    let ids: Vec<String> = creds
        .required_capabilities()
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(ids[0], credentials::TUNNEL_CAP);
    assert_eq!(ids.len(), 7);
    let report = validate(&creds);
    assert!(report.passed(), "{:?}", report.missing());
    assert_eq!(
        ups.load(Ordering::SeqCst),
        1,
        "one tunnel for all the probes"
    );
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(
        remote
            .targets()
            .iter()
            .all(|t| t.proxy_command.as_deref() == Some(PROXY))
    );
}

#[test]
fn a_tunnel_that_fails_the_probe_fails_closed_and_nothing_else_is_probed() {
    let (registry, _, _) = recorder(true);
    let remote = vm();
    let creds = SshHostCredentials::with_target(remote.clone(), with_recorder_tunnel())
        .with_tunnels(registry);
    let report = validate(&creds);
    assert!(!report.passed());
    let first = &report.checks[0];
    assert_eq!(first.capability.id, credentials::TUNNEL_CAP);
    match &first.status {
        CapabilityStatus::Fail { reason } => {
            assert!(reason.contains("refused the login"), "{reason}")
        }
        other => panic!("{other:?}"),
    }
    for check in &report.checks[1..] {
        match &check.status {
            CapabilityStatus::Fail { reason } => {
                assert!(reason.contains("tunnel is not up"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(remote.calls().is_empty());
}

#[test]
fn no_tunnel_or_none_keeps_exactly_the_six_original_capabilities() {
    for extra in [json!({}), json!({"tunnel": {"kind": "none"}})] {
        let creds = SshHostCredentials::with_target(vm(), parse(extra).unwrap());
        let ids: Vec<String> = creds
            .required_capabilities()
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(ids.len(), 6);
        assert!(!ids.contains(&credentials::TUNNEL_CAP.to_string()));
        assert!(validate(&creds).passed());
    }
}
