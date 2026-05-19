//! End-to-end CLI smoke tests for `greentic-deployer op …`.
//!
//! Regression for the Codex finding that the library was previously
//! unreachable from the shipped binary. These tests spawn the actual
//! `greentic-deployer` binary and verify both `--help` parsing and at
//! least one full create+list round-trip against a tempdir store.

use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

fn deployer_bin() -> PathBuf {
    // Prefer the cargo-provided binary path for the integration runner.
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

#[test]
fn op_env_help_lists_create_update_destroy() {
    let out = Command::new(deployer_bin())
        .args(["op", "env", "--help"])
        .output()
        .expect("spawn greentic-deployer");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for verb in ["create", "update", "list", "show", "doctor", "destroy"] {
        assert!(
            stdout.contains(verb),
            "missing verb `{verb}` in `op env --help`:\n{stdout}"
        );
    }
}

#[test]
fn op_help_lists_every_noun() {
    let out = Command::new(deployer_bin())
        .args(["op", "--help"])
        .output()
        .expect("spawn greentic-deployer");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for noun in [
        "env",
        "env-packs",
        "bundles",
        "revisions",
        "traffic",
        "config",
        "credentials",
        "secrets",
    ] {
        assert!(
            stdout.contains(noun),
            "missing noun `{noun}` in `op --help`:\n{stdout}"
        );
    }
}

#[test]
fn op_env_create_then_list_roundtrips_against_tempdir_store() {
    let dir = tempdir().expect("tempdir");
    let payload_path = dir.path().join("payload.json");
    std::fs::write(
        &payload_path,
        r#"{"environment_id":"local","name":"local"}"#,
    )
    .expect("write payload");

    // create
    let create = Command::new(deployer_bin())
        .args([
            "op",
            "--store-root",
            dir.path().to_str().unwrap(),
            "--answers",
            payload_path.to_str().unwrap(),
            "env",
            "create",
        ])
        .output()
        .expect("spawn create");
    assert!(
        create.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let create_stdout = String::from_utf8_lossy(&create.stdout);
    let create_json: serde_json::Value =
        serde_json::from_str(create_stdout.trim()).expect("create stdout is json");
    assert_eq!(create_json["noun"], "env");
    assert_eq!(create_json["op"], "create");
    assert_eq!(create_json["result"]["environment_id"], "local");

    // list
    let list = Command::new(deployer_bin())
        .args([
            "op",
            "--store-root",
            dir.path().to_str().unwrap(),
            "env",
            "list",
        ])
        .output()
        .expect("spawn list");
    assert!(
        list.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    let list_json: serde_json::Value =
        serde_json::from_str(list_stdout.trim()).expect("list stdout is json");
    let envs = list_json["result"]["environments"]
        .as_array()
        .expect("environments array");
    assert_eq!(envs.len(), 1, "expected one env after create");
    assert_eq!(envs[0]["environment_id"], "local");
}

#[test]
fn op_env_show_missing_emits_json_error_envelope() {
    let dir = tempdir().expect("tempdir");
    let out = Command::new(deployer_bin())
        .args([
            "op",
            "--store-root",
            dir.path().to_str().unwrap(),
            "env",
            "show",
            "definitely-not-an-env",
        ])
        .output()
        .expect("spawn show");
    assert!(
        !out.status.success(),
        "expected non-zero exit for missing env; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let envelope: serde_json::Value = serde_json::from_str(stderr.trim())
        .unwrap_or_else(|err| panic!("stderr is not JSON (err={err}): {stderr}"));
    assert_eq!(envelope["op"], "show");
    assert_eq!(envelope["noun"], "env");
    assert_eq!(envelope["error"]["kind"], "not-found");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("definitely-not-an-env")),
        "error.message should mention the missing env id: {}",
        envelope["error"]
    );
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty on error path: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn op_help_renders_envelope_contract_in_after_help() {
    let out = Command::new(deployer_bin())
        .args(["op", "--help"])
        .output()
        .expect("spawn greentic-deployer");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "Examples:",
        "--schema",
        "--answers",
        "Errors are written to stderr",
        "\"result\"",
    ] {
        assert!(
            stdout.contains(needle),
            "missing `{needle}` in `op --help` after_help:\n{stdout}"
        );
    }
}

#[test]
fn op_env_schema_dumps_payload_schema() {
    let dir = tempdir().expect("tempdir");
    let out = Command::new(deployer_bin())
        .args([
            "op",
            "--store-root",
            dir.path().to_str().unwrap(),
            "--schema",
            "env",
            "create",
        ])
        .output()
        .expect("spawn --schema");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("schema stdout is json");
    assert_eq!(json["op"], "create");
    let result = &json["result"];
    assert_eq!(result["title"], "EnvCreatePayload");
    assert!(result["properties"]["environment_id"].is_object());
}
