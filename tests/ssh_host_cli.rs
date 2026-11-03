//! The ssh-host deployer, reached through the real `greentic-deployer` binary.
//!
//! No network and no VM: `ssh` is a stub script on `PATH` that logs its
//! arguments and fails like an unreachable host. That is enough to prove the
//! CLI wiring — the binding's answers reach the ssh command line, the verbs
//! refuse bad input before touching anything, and the SSH identity never shows
//! up in any output. The behaviour of the deploy itself (stores, slots, units)
//! is covered against a simulated VM in `src/cli/ssh_host/tests.rs`, and
//! against a real one by `tests/ssh_host_live.rs`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

const KIND: &str = "greentic.deployer.ssh-host@0.1.0";
const IDENTITY: &str = "/home/operator/.ssh/id_super_secret";

struct Fixture {
    root: TempDir,
    ssh_log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let ssh_log = root.path().join("ssh.log");
        let stub = bin.join("ssh");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
                 echo 'ssh: connect to host failed (stub)' >&2\nexit 255\n",
                ssh_log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fixture = Self { root, ssh_log };
        let out = fixture.op(&["env", "init"], None);
        assert!(out.status.success(), "env init: {}", text(&out));
        fixture
    }

    fn store(&self) -> PathBuf {
        self.root.path().join("store")
    }

    fn write_json(&self, name: &str, body: &Value) -> PathBuf {
        let path = self.root.path().join(name);
        std::fs::write(&path, serde_json::to_vec(body).unwrap()).unwrap();
        path
    }

    /// `greentic-deployer op --store-root <store> [--answers F] <args…>` with the
    /// stub `ssh` first on `PATH`.
    fn op(&self, args: &[&str], answers: Option<&Path>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"));
        cmd.arg("op").arg("--store-root").arg(self.store());
        if let Some(path) = answers {
            cmd.arg("--answers").arg(path);
        }
        let path = format!(
            "{}:{}",
            self.root.path().join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.args(args).env("PATH", path).output().unwrap()
    }

    /// Bind the ssh-host deployer on the `local` env with these answers.
    fn bind(&self, answers: &Value) -> Output {
        let env_dir = self.store().join("local/env-packs/deployer");
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(
            env_dir.join("answers.json"),
            serde_json::to_vec(answers).unwrap(),
        )
        .unwrap();
        let payload = self.write_json(
            "bind.json",
            &json!({
                "environment_id": "local",
                "slot": "deployer",
                "kind": KIND,
                "pack_ref": "greentic.deployer.ssh-host",
                "answers_ref": "env-packs/deployer/answers.json",
            }),
        );
        self.op(&["env-packs", "update"], Some(&payload))
    }

    fn ssh_calls(&self) -> String {
        std::fs::read_to_string(&self.ssh_log).unwrap_or_default()
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn answers() -> Value {
    json!({
        "host": "vm.example.com",
        "user": "greentic",
        "port": 2222,
        "identity_file": IDENTITY,
        "known_hosts_file": "/tmp/known_hosts_for_test",
    })
}

#[test]
fn binding_bad_answers_is_refused_and_good_answers_are_recorded() {
    let fx = Fixture::new();
    let bad = fx.bind(
        &json!({"host": "vm.example.com", "user": "u", "identity_file": IDENTITY,
                              "strict_host_key_checking": "no"}),
    );
    assert!(!bad.status.success(), "{}", text(&bad));
    let msg = text(&bad);
    assert!(msg.contains("unknown answer key"), "{msg}");
    assert!(!msg.contains(IDENTITY), "{msg}");

    let good = fx.bind(&answers());
    assert!(good.status.success(), "{}", text(&good));
    assert!(text(&good).contains("ssh-host"), "{}", text(&good));
    assert!(!text(&good).contains(IDENTITY));
    assert!(fx.ssh_calls().is_empty(), "binding must not reach the VM");
}

#[test]
fn credentials_requirements_probes_the_bound_target() {
    let fx = Fixture::new();
    assert!(fx.bind(&answers()).status.success());
    let payload = fx.write_json("req.json", &json!({"environment_id": "local"}));
    let out = fx.op(&["credentials", "requirements"], Some(&payload));
    let all = text(&out);
    // The stub host is unreachable, so the report fails; what matters is that
    // the probes ran against the bound target instead of failing closed with
    // "no SSH target is bound".
    assert!(!all.contains("no SSH target is bound"), "{all}");
    assert!(all.contains("ssh-host.reachable"), "{all}");
    assert!(!all.contains(IDENTITY), "{all}");
    let calls = fx.ssh_calls();
    assert!(calls.contains("greentic@vm.example.com"), "{calls}");
    assert!(calls.contains("2222"), "{calls}");
    assert!(calls.contains("BatchMode=yes"), "{calls}");
    assert!(calls.contains("StrictHostKeyChecking=yes"), "{calls}");
    assert!(calls.contains("/tmp/known_hosts_for_test"), "{calls}");
}

#[test]
fn env_up_without_a_revision_refuses_before_reaching_the_vm() {
    let fx = Fixture::new();
    assert!(fx.bind(&answers()).status.success());
    let manifest = fx.write_json(
        "manifest.json",
        &json!({"schema": "greentic.env-manifest.v1", "environment": {"id": "local"}}),
    );
    let out = fx.op(
        &["env", "up", "--yes", "--non-interactive"],
        Some(&manifest),
    );
    assert!(!out.status.success(), "{}", text(&out));
    let all = text(&out);
    assert!(all.contains("op deploy"), "{all}");
    assert!(!all.contains(IDENTITY), "{all}");
    assert!(fx.ssh_calls().is_empty(), "nothing may reach the VM: {all}");
}

#[test]
fn env_up_refuses_bad_manifest_answers_naming_the_pack() {
    let fx = Fixture::new();
    let manifest = fx.write_json(
        "manifest.json",
        &json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer", "kind": KIND,
                "pack_ref": "greentic.deployer.ssh-host",
                "answers": {"host": "vm.example.com", "user": "u", "expose": "maybe",
                            "identity_file": IDENTITY},
            }],
        }),
    );
    let out = fx.op(
        &["env", "up", "--yes", "--non-interactive"],
        Some(&manifest),
    );
    assert!(!out.status.success(), "{}", text(&out));
    let all = text(&out);
    assert!(all.contains("expose"), "{all}");
    assert!(all.contains("deployer"), "{all}");
    assert!(!all.contains(IDENTITY), "{all}");
    assert!(fx.ssh_calls().is_empty());
}
