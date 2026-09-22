//! End-to-end CLI tests for `op secrets delete` and `op secrets list --prefix`,
//! driven through the shipped binary exactly as greentic-designer calls it:
//! `op --store-root <root> --answers <payload.json> secrets <verb>`.
//!
//! Every run overrides HOME and clears `GREENTIC_DEV_SECRETS_PATH`, so the
//! binary never touches real user state.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

const MCP_A: &str = "acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3.unit-alpha";
const MCP_B: &str = "acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3.unit-beta";
const A2A_A: &str = "acme/_/a2a/0b6f2d8e-1c1d-4f5e-9a7b-3c2d1e0f9a8b.unit-alpha";

struct Harness {
    home: TempDir,
    store: TempDir,
    payloads: TempDir,
}

impl Harness {
    fn new() -> Self {
        let harness = Self {
            home: tempfile::tempdir().expect("home tempdir"),
            store: tempfile::tempdir().expect("store tempdir"),
            payloads: tempfile::tempdir().expect("payload tempdir"),
        };
        harness.run_ok(&["env", "init"], None);
        harness
    }

    fn command(&self, verb_args: &[&str], payload: Option<&Value>) -> std::process::Output {
        let mut args: Vec<String> = vec![
            "op".into(),
            "--store-root".into(),
            path_str(self.store.path()),
        ];
        if let Some(payload) = payload {
            let file = self
                .payloads
                .path()
                .join(format!("{}.json", next_payload_name()));
            std::fs::write(&file, payload.to_string()).expect("write payload");
            args.push("--answers".into());
            args.push(path_str(&file));
        }
        args.extend(verb_args.iter().map(|a| a.to_string()));
        Command::new(deployer_bin())
            .args(&args)
            .env("HOME", self.home.path())
            .env_remove("GREENTIC_DEV_SECRETS_PATH")
            .output()
            .expect("spawn greentic-deployer")
    }

    fn run_ok(&self, verb_args: &[&str], payload: Option<&Value>) -> Value {
        let out = self.command(verb_args, payload);
        assert!(
            out.status.success(),
            "`{verb_args:?}` failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON envelope")
    }

    fn put(&self, path: &str, value: &str) {
        self.run_ok(
            &["secrets", "put"],
            Some(&json!({"environment_id": "local", "path": path, "value": value})),
        );
    }

    fn get(&self, path: &str) -> Value {
        self.run_ok(
            &["secrets", "get"],
            Some(&json!({"environment_id": "local", "path": path, "reveal": true})),
        )
    }

    fn list(&self, prefix: &str) -> Value {
        self.run_ok(
            &["secrets", "list"],
            Some(&json!({"environment_id": "local", "prefix": prefix})),
        )
    }

    fn delete(&self, body: Value) -> Value {
        self.run_ok(&["secrets", "delete"], Some(&body))
    }
}

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

fn path_str(path: &Path) -> String {
    path.to_str().expect("utf-8 tempdir path").to_string()
}

fn next_payload_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("payload-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn paths(keys: &Value) -> Vec<String> {
    keys.as_array()
        .expect("key array")
        .iter()
        .map(|k| k["path"].as_str().expect("path").to_string())
        .collect()
}

#[test]
fn op_secrets_help_lists_delete() {
    let out = Command::new(deployer_bin())
        .args(["op", "secrets", "--help"])
        .output()
        .expect("spawn greentic-deployer");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for verb in ["list", "put", "get", "rotate", "delete"] {
        assert!(stdout.contains(verb), "missing `{verb}`:\n{stdout}");
    }
}

#[test]
fn delete_removes_one_key_and_is_idempotent() {
    let h = Harness::new();
    h.put(MCP_A, "tok-a");
    h.put(MCP_B, "tok-b");

    let deleted = h.delete(json!({"environment_id": "local", "path": MCP_A}));
    assert_eq!(deleted["noun"], "secrets");
    assert_eq!(deleted["op"], "delete");
    assert_eq!(deleted["result"]["deleted"], true);
    assert_eq!(
        deleted["result"]["store_uri"],
        format!("secrets://default/{MCP_A}")
    );

    assert_eq!(h.get(MCP_A)["result"]["present"], false);
    assert_eq!(h.get(MCP_B)["result"]["value"], "tok-b");

    let again = h.delete(json!({"environment_id": "local", "path": MCP_A}));
    assert_eq!(again["result"]["deleted"], false);
}

#[test]
fn list_prefix_enumerates_names_only_and_delete_prefix_purges_them() {
    let h = Harness::new();
    h.put(MCP_A, "value-that-must-not-print-a");
    h.put(MCP_B, "value-that-must-not-print-b");
    h.put(A2A_A, "value-that-must-not-print-c");

    let listed = h.list("acme/_/mcp/");
    assert_eq!(listed["result"]["prefix"], "acme/_/mcp/");
    assert_eq!(
        paths(&listed["result"]["stored_keys"]),
        vec![MCP_A.to_string(), MCP_B.to_string()]
    );
    assert!(
        !listed.to_string().contains("value-that-must-not-print"),
        "list leaked a value: {listed}"
    );

    let purged = h.delete(json!({"environment_id": "local", "prefix": "acme/_/mcp/"}));
    assert_eq!(purged["result"]["deleted"], true);
    assert_eq!(purged["result"]["deleted_count"], 2);
    assert_eq!(
        paths(&purged["result"]["deleted_keys"]),
        vec![MCP_A.to_string(), MCP_B.to_string()]
    );

    assert!(paths(&h.list("acme/_/mcp/")["result"]["stored_keys"]).is_empty());
    assert_eq!(
        paths(&h.list("acme/_/a2a/")["result"]["stored_keys"]),
        vec![A2A_A.to_string()]
    );
    assert_eq!(h.get(MCP_B)["result"]["present"], false);
    assert_eq!(h.get(A2A_A)["result"]["present"], true);
}

#[test]
fn delete_refuses_an_invalid_path_with_a_json_error_envelope() {
    let h = Harness::new();
    let out = h.command(
        &["secrets", "delete"],
        Some(&json!({"environment_id": "local", "path": "acme/default/mcp/x"})),
    );
    assert!(!out.status.success(), "a literal `default` team must fail");
    assert!(out.stdout.is_empty(), "the error envelope goes to stderr");
    let envelope: Value = serde_json::from_slice(&out.stderr).expect("stderr is a JSON envelope");
    assert_eq!(envelope["noun"], "secrets");
    assert_eq!(envelope["op"], "delete");
    assert_eq!(envelope["error"]["kind"], "invalid-argument");
}
