//! LIVE test of the ssh-host env-pack against a real Linux VM with systemd.
//!
//! `#[ignore]`d: it needs a machine you own and it changes it (inside one
//! install directory and one systemd unit, both removed at the end — also when
//! an assertion fails). Nothing here has a default; every target value comes
//! from the environment, so no host, address or user is ever committed.
//!
//! Required environment variables:
//!
//! | variable | meaning |
//! |---|---|
//! | `GREENTIC_SSH_LIVE_HOST` | VM address |
//! | `GREENTIC_SSH_LIVE_USER` | login user (the deployer uses `sudo -n` unless it is `root`) |
//! | `GREENTIC_SSH_LIVE_KNOWN_HOSTS` | a `known_hosts` file that already trusts the VM |
//! | `GREENTIC_SSH_LIVE_START_BINARY` | a greentic-start binary built for the VM |
//! | `GREENTIC_SSH_LIVE_STORE` | a store ROOT holding `<env_id>/` (read-only; it is copied) |
//! | `GREENTIC_SSH_LIVE_INSTALL_DIR` | install dir on the VM; its name must contain `vmtest` |
//! | `GREENTIC_SSH_LIVE_SERVICE` | systemd unit name; must start with `greentic-vmtest` |
//! | `GREENTIC_SSH_LIVE_LISTEN_PORT` | loopback port for the service (must be free) |
//!
//! Optional: `GREENTIC_SSH_LIVE_PORT` (ssh port), `GREENTIC_SSH_LIVE_IDENTITY`
//! (key path; absent = the ssh agent / default keys), `GREENTIC_SSH_LIVE_UI_PATH`
//! (a path on the service that must answer 200, e.g. a webchat page),
//! `GREENTIC_SSH_LIVE_SERVICE_USER` (run the service as this account),
//! `GREENTIC_SSH_LIVE_KEEP=1` (leave the install dir and unit in place when the
//! test ends — to inspect a failure, or to skip the slow binary upload on the
//! next run; you must then remove them yourself).
//!
//! ```text
//! GREENTIC_SSH_LIVE_HOST=... cargo test --test ssh_host_live -- --ignored --nocapture
//! ```
//!
//! The two names guarded by `vmtest` / `greentic-vmtest` exist so a mistyped
//! variable can never make the cleanup delete a real service or directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use greentic_deploy_spec::{Environment, EnvironmentHostConfig, RevisionId};
use greentic_deployer::credentials::{CapabilityStatus, DeployerCredentials, ValidationContext};
use greentic_deployer::env_packs::deployer::Deployer;
use greentic_deployer::env_packs::ssh_host::{
    Remote, RemoteTarget, SshHostCredentials, SshHostDeployerHandler, SshHostParams, SystemSsh,
};
use serde_json::{Value, json};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is not set; see the header of tests/ssh_host_live.rs (there are no defaults)"
        )
    })
}

fn opt(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

struct Live {
    answers: Value,
    params: SshHostParams,
    target: RemoteTarget,
    remote: Arc<SystemSsh>,
    install_dir: String,
    service: String,
    port: String,
    ui_path: Option<String>,
}

impl Live {
    fn from_env(env: &Environment, start_binary: &Path) -> Self {
        let install_dir = var("GREENTIC_SSH_LIVE_INSTALL_DIR");
        let service = var("GREENTIC_SSH_LIVE_SERVICE");
        assert!(
            install_dir.starts_with('/')
                && install_dir.contains("vmtest")
                && !install_dir.ends_with('/'),
            "install dir must be absolute, contain `vmtest` and have no trailing slash"
        );
        assert!(
            service.starts_with("greentic-vmtest"),
            "service name must start with `greentic-vmtest`"
        );
        let port = var("GREENTIC_SSH_LIVE_LISTEN_PORT");
        let mut answers = json!({
            "host": var("GREENTIC_SSH_LIVE_HOST"),
            "user": var("GREENTIC_SSH_LIVE_USER"),
            "known_hosts_file": var("GREENTIC_SSH_LIVE_KNOWN_HOSTS"),
            "install_dir": install_dir,
            "service_name": service,
            "listen_port": port.parse::<u16>().expect("listen port"),
            "start_binary": start_binary.display().to_string(),
        });
        if let Some(p) = opt("GREENTIC_SSH_LIVE_PORT") {
            answers["port"] = json!(p.parse::<u16>().expect("ssh port"));
        }
        if let Some(i) = opt("GREENTIC_SSH_LIVE_IDENTITY") {
            answers["identity_file"] = json!(i);
        }
        if let Some(u) = opt("GREENTIC_SSH_LIVE_SERVICE_USER") {
            answers["service_user"] = json!(u);
        }
        let params = SshHostParams::from_answers(env, &answers).expect("answers are valid");
        assert!(!params.expose, "the live test never exposes the service");
        Self {
            target: RemoteTarget::from(&params),
            answers,
            params,
            remote: Arc::new(SystemSsh::new()),
            install_dir,
            service,
            port,
            ui_path: opt("GREENTIC_SSH_LIVE_UI_PATH"),
        }
    }

    fn with_binary(&self, binary: &Path) -> Value {
        let mut a = self.answers.clone();
        a["start_binary"] = json!(binary.display().to_string());
        a
    }

    /// Run `sh -c script` on the VM; returns (status, stdout+stderr).
    fn sh(&self, script: &str) -> (i32, String) {
        let argv = vec!["sh".to_string(), "-c".to_string(), script.to_string()];
        let out = self.remote.run(&self.target, &argv).expect("ssh transport");
        (
            out.status,
            format!("{}{}", out.stdout, out.stderr).trim().to_string(),
        )
    }

    fn sh_ok(&self, script: &str) -> String {
        let (status, text) = self.sh(script);
        assert_eq!(status, 0, "`{script}` exited {status}: {text}");
        text
    }

    fn http_code(&self, path: &str) -> String {
        self.sh(&format!(
            "curl -s -o /dev/null -m 5 -w '%{{http_code}}' http://127.0.0.1:{}{path}",
            self.port
        ))
        .1
    }

    /// Wait (bounded) for `path` to answer 200.
    fn wait_http_200(&self, path: &str, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last = String::new();
        while Instant::now() < deadline {
            last = self.http_code(path);
            if last == "200" {
                eprintln!("  {what}: GET {path} -> 200");
                return;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        let journal = self
            .sh(&format!(
                "journalctl -u {} --no-pager -n 25 -o cat 2>&1 | cut -c1-240",
                self.service
            ))
            .1;
        panic!("{what}: GET {path} never answered 200 (last: {last:?}); journal:\n{journal}");
    }

    fn active(&self) -> String {
        self.sh(&format!("systemctl is-active {}", self.service)).1
    }

    /// `ActiveEnterTimestampMonotonic` changes on every (re)start.
    fn start_stamp(&self) -> String {
        self.sh_ok(&format!(
            "systemctl show -p ActiveEnterTimestampMonotonic --value {}",
            self.service
        ))
    }

    /// Listing + sizes + mtimes of everything under the install dir, hashed.
    /// Excludes `store/` contents the runtime itself rewrites while running
    /// (locks, audit) by looking at the `bin/` and unit only plus the slot link.
    fn fingerprint(&self) -> String {
        self.sh_ok(&format!(
            "cd {d} && {{ ls -l --time-style=full-iso bin; readlink store; cat store/.greentic-store.sha256; \
             stat -c '%Y %n' /etc/systemd/system/{s}.service; }} | sha256sum | cut -c1-16",
            d = self.install_dir,
            s = self.service
        ))
    }

    fn cleanup(&self) {
        // Only ever our own unit and our own directory (names checked in `from_env`).
        let s = &self.service;
        let d = &self.install_dir;
        let script = format!(
            "systemctl stop {s} 2>&1; systemctl disable {s} 2>&1; \
             rm -f /etc/systemd/system/{s}.service /etc/systemd/system/{s}.service.new; \
             systemctl daemon-reload 2>&1; systemctl reset-failed {s} 2>&1; rm -rf -- {d}; echo cleanup-done"
        );
        let script = if self.params.use_sudo {
            format!("sudo -n sh -c '{}'", script.replace('\'', "'\\''"))
        } else {
            script
        };
        let (status, text) = self.sh(&script);
        eprintln!(
            "[cleanup] exit {status}: {}",
            text.lines().last().unwrap_or("")
        );
    }
}

/// Removes everything the test created, also when it panics.
struct CleanupGuard<'a>(&'a Live);

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        if opt("GREENTIC_SSH_LIVE_KEEP").as_deref() == Some("1") {
            eprintln!(
                "[cleanup] skipped (GREENTIC_SSH_LIVE_KEEP=1): remove the unit and install dir by hand"
            );
            return;
        }
        self.0.cleanup();
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let dest = to.join(entry.file_name());
        if ty.is_dir() {
            copy_dir(&entry.path(), &dest);
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// The store's own `environment.json`, as the env the deployer is driven with.
fn load_env(store_root: &Path) -> (Environment, String) {
    let mut found = None;
    for entry in std::fs::read_dir(store_root).unwrap() {
        let p = entry.unwrap().path();
        if p.join("environment.json").is_file() {
            assert!(found.is_none(), "the store root holds more than one env");
            found = Some(p);
        }
    }
    let dir = found.expect("no <env_id>/environment.json under the store root");
    let env: Environment =
        serde_json::from_slice(&std::fs::read(dir.join("environment.json")).unwrap())
            .expect("environment.json parses as an Environment");
    let id = env.environment_id.as_str().to_string();
    (env, id)
}

fn step(n: u32, title: &str, will_change: &str) {
    eprintln!("\n=== [{n}] {title}\n    WILL CHANGE ON THE VM: {will_change}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real VM; see the header of tests/ssh_host_live.rs"]
async fn ssh_host_against_a_real_vm() {
    let start_binary = PathBuf::from(var("GREENTIC_SSH_LIVE_START_BINARY"));
    assert!(start_binary.is_file(), "start binary not found");
    let scratch = tempfile::tempdir().unwrap();
    // Work on a COPY of the store: the caller's store is never touched.
    let store_root = scratch.path().join("store");
    copy_dir(Path::new(&var("GREENTIC_SSH_LIVE_STORE")), &store_root);
    let (env, env_id) = load_env(&store_root);
    let revision: RevisionId = env.revisions[0].revision_id;
    let live = Live::from_env(&env, &start_binary);
    let _cleanup = CleanupGuard(&live);
    let handler = SshHostDeployerHandler::new().with_local_store(store_root.clone(), None);
    let answers = live.answers.clone();

    // ---- 1. probe credentials -------------------------------------------------
    step(1, "probe credentials", "nothing (read-only probes)");
    let creds = SshHostCredentials::with_target(live.remote.clone(), live.params.clone());
    let hc = EnvironmentHostConfig::new(env.environment_id.clone());
    let report = creds.validate(&ValidationContext {
        env_id: &env.environment_id,
        env_root: scratch.path(),
        host_config: &hc,
    });
    for c in &report.checks {
        eprintln!("  {:<32} {:?}", c.capability.id, c.status);
        assert!(
            matches!(c.status, CapabilityStatus::Pass),
            "{} did not pass",
            c.capability.id
        );
    }
    assert_eq!(report.checks.len(), 6);

    // ---- 2. full warm ---------------------------------------------------------
    step(
        2,
        "warm_revision (first)",
        &format!(
            "creates {d}/{{bin,home,logs,store-a,store}}, installs unit {u}.service, enables + starts it",
            d = live.install_dir,
            u = live.service
        ),
    );
    let out = handler
        .warm_revision(&env, revision, Some(&answers))
        .await
        .expect("first warm succeeds");
    eprintln!("  warm outcome endpoint_url = {:?}", out.endpoint_url);
    assert!(
        out.endpoint_url.is_none(),
        "loopback bind advertises no endpoint"
    );
    assert_eq!(live.active(), "active");
    live.wait_http_200("/healthz", "healthz");
    if let Some(ui) = &live.ui_path {
        live.wait_http_200(ui, "ui");
    }
    eprintln!(
        "  listeners of the service:\n{}",
        live.sh(&format!(
            "ss -ltnp 2>/dev/null | grep -F 'pid='$(systemctl show -p MainPID --value {}) || true",
            live.service
        ))
        .1
    );
    eprintln!(
        "  layout:\n{}",
        live.sh_ok(&format!(
            "cd {d} && ls -la --time-style=+ . | tail -n +2; readlink store; ls -a store/ | head -20; cat store/.greentic-store.sha256",
            d = live.install_dir
        ))
    );
    // The runtime writes its signing key and logs INSIDE the env dir.
    let key_a = live.sh_ok(&format!(
        "sha256sum {}/store/{env_id}/revision-signing.key | cut -c1-16",
        live.install_dir
    ));
    eprintln!("  runtime signing key after first start: {key_a}");
    eprintln!(
        "  service runs as: {}",
        live.sh(&format!(
            "ps -o user= -p $(systemctl show -p MainPID --value {})",
            live.service
        ))
        .1
    );
    let unit = live.sh_ok(&format!("cat /etc/systemd/system/{}.service", live.service));
    assert!(unit.contains("GREENTIC_GATEWAY_LISTEN_ADDR=127.0.0.1"));
    let bound = live.sh(&format!(
        "ss -ltn | grep -c '127.0.0.1:{}\\b'; ss -ltn | grep -c '0.0.0.0:{}\\b'",
        live.port, live.port
    ));
    eprintln!(
        "  listeners on 127.0.0.1:port / 0.0.0.0:port (counts): {:?}",
        bound.1
    );
    let slot_before = live.sh_ok(&format!("readlink {}/store", live.install_dir));
    let stamp1 = live.start_stamp();

    // ---- 3a. idempotent warm --------------------------------------------------
    step(
        3,
        "warm_revision again, nothing changed",
        "nothing expected (no-op)",
    );
    let fp_before = live.fingerprint();
    handler
        .warm_revision(&env, revision, Some(&answers))
        .await
        .expect("second warm succeeds");
    let stamp2 = live.start_stamp();
    let fp_after = live.fingerprint();
    eprintln!("  start stamp {stamp1} -> {stamp2}; fingerprint {fp_before} -> {fp_after}");
    assert_eq!(stamp1, stamp2, "an unchanged warm restarted the service");
    assert_eq!(
        fp_before, fp_after,
        "an unchanged warm modified the install dir"
    );
    assert_eq!(
        slot_before,
        live.sh_ok(&format!("readlink {}/store", live.install_dir))
    );
    live.wait_http_200("/healthz", "healthz after no-op warm");

    // ---- 3b. warm after a small change ---------------------------------------
    step(
        3,
        "warm_revision after a small store change",
        "fills the other store slot, flips the `store` symlink, restarts the service",
    );
    std::fs::write(
        store_root.join(&env_id).join("vmtest-change.txt"),
        b"changed on purpose\n",
    )
    .unwrap();
    handler
        .warm_revision(&env, revision, Some(&answers))
        .await
        .expect("warm after change succeeds");
    let slot_after = live.sh_ok(&format!("readlink {}/store", live.install_dir));
    let stamp3 = live.start_stamp();
    eprintln!("  active slot {slot_before} -> {slot_after}; start stamp {stamp2} -> {stamp3}");
    assert_ne!(slot_before, slot_after, "the slot did not alternate");
    assert_ne!(
        stamp2, stamp3,
        "a changed store did not restart the service"
    );
    live.wait_http_200("/healthz", "healthz after the swap");
    if let Some(ui) = &live.ui_path {
        live.wait_http_200(ui, "ui after the swap");
    }
    let key_b = live.sh_ok(&format!(
        "sha256sum {}/store/{env_id}/revision-signing.key | cut -c1-16",
        live.install_dir
    ));
    eprintln!("  signing key after the swap: {key_b}");
    assert_eq!(
        key_a, key_b,
        "revision-signing.key was not carried to the new slot"
    );
    assert_eq!(
        live.sh(&format!(
            "test -f {}/store/{env_id}/vmtest-change.txt",
            live.install_dir
        ))
        .0,
        0
    );
    assert_eq!(
        live.sh_ok(&format!(
            "readlink {}/store/{env_id}/logs",
            live.install_dir
        )),
        format!("{}/logs", live.install_dir),
        "logs must link to the persistent directory"
    );
    let logged = live.sh_ok(&format!("ls -la {}/logs", live.install_dir));
    eprintln!("  persistent logs/ after the swap:\n{logged}");
    assert!(
        logged.contains("system.log"),
        "the runtime did not log into logs/"
    );

    // ---- 4. failure: a bad binary ---------------------------------------------
    step(
        4,
        "warm_revision pointed at an empty start_binary",
        "should change NOTHING: the previous binary and store must keep serving",
    );
    let good_hash = live.sh_ok(&format!(
        "sha256sum {}/bin/greentic-start | cut -c1-16",
        live.install_dir
    ));
    let empty = scratch.path().join("empty-binary");
    std::fs::write(&empty, b"").unwrap();
    let failed = handler
        .warm_revision(&env, revision, Some(&live.with_binary(&empty)))
        .await;
    match &failed {
        Ok(_) => eprintln!("  UNEXPECTED: warm with an empty binary reported success"),
        Err(e) => eprintln!("  error: {e}"),
    }
    let after_hash = live.sh_ok(&format!(
        "sha256sum {}/bin/greentic-start | cut -c1-16",
        live.install_dir
    ));
    eprintln!(
        "  binary hash {good_hash} -> {after_hash}; service {}",
        live.active()
    );
    assert!(failed.is_err(), "an empty binary must fail the warm");
    assert_eq!(
        good_hash, after_hash,
        "the working binary was replaced by the bad one"
    );
    assert_eq!(live.active(), "active", "the old service stopped serving");
    live.wait_http_200("/healthz", "healthz after the failed warm");
    let strays = live.sh(&format!("ls {}/bin", live.install_dir)).1;
    eprintln!("  bin/ after the failure: {strays:?}");
    assert_eq!(
        strays.trim(),
        "greentic-start",
        "a staged file was left behind"
    );

    // ---- 5. drain / archive ---------------------------------------------------
    step(
        5,
        "drain_revision while traffic is routed",
        "nothing (service must stay up)",
    );
    handler
        .drain_revision(&env, revision, Some(&answers))
        .await
        .expect("drain with traffic");
    assert_eq!(
        live.active(),
        "active",
        "drain stopped a service that still routes traffic"
    );

    step(5, "archive_revision", "nothing (must not delete data)");
    let fp_pre = live.fingerprint();
    handler
        .archive_revision(&env, revision, Some(&answers))
        .await
        .expect("archive");
    assert_eq!(fp_pre, live.fingerprint(), "archive modified the VM");

    step(
        5,
        "drain_revision with no traffic routed",
        "stops the service (data must stay)",
    );
    let mut quiet = env.clone();
    quiet.traffic_splits.clear();
    handler
        .drain_revision(&quiet, revision, Some(&answers))
        .await
        .expect("drain without traffic");
    let state = live.active();
    eprintln!(
        "  service after drain: {state:?}; healthz: {}",
        live.http_code("/healthz")
    );
    assert_ne!(state, "active");
    assert_ne!(live.http_code("/healthz"), "200");
    assert_eq!(
        live.sh_ok(&format!("systemctl is-enabled {}", live.service)),
        "enabled",
        "drain must not disable the unit"
    );
    assert_eq!(fp_pre, live.fingerprint(), "drain changed files on the VM");

    // The service can be warmed back up from the drained state.
    handler
        .warm_revision(&env, revision, Some(&answers))
        .await
        .expect("warm after drain");
    live.wait_http_200("/healthz", "healthz after re-warm");
    eprintln!("\nALL LIVE CHECKS PASSED (cleanup follows)");
}
