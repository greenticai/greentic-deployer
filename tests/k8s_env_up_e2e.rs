//! Live-cluster E2E for `op env up` (the one-command bootstrap path).
//!
//! Gated on `GREENTIC_K8S_E2E=1` (same gate as `k8s_reconcile_e2e`). Exercises
//! the full `up` sequence against a kind cluster: parse → preflight → cluster →
//! env ensure → apply → reconcile+rollout. Asserts exit 0, both router and
//! worker Deployments reach Ready, and a second run converges (idempotency).
//!
//! Runs against the ambient kubeconfig current-context (kind in CI).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Env that arms the tests. Unset (the default in `cargo test`) -> skip.
const E2E_GATE: &str = "GREENTIC_K8S_E2E";

/// The kind cluster name used by these tests.
const KIND_CLUSTER: &str = "gtc-env-up-e2e";

/// Namespace derived from the env id (`gtc-<env_id>`).
const NAMESPACE: &str = "gtc-local";

const ROUTER_DEPLOY: &str = "gtc-router";

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

/// `true` when the tests are armed. Unset -> the caller returns early.
fn armed() -> bool {
    if std::env::var(E2E_GATE).is_err() {
        eprintln!("skipping env-up E2E: set {E2E_GATE}=1 (needs docker + kind on PATH)");
        return false;
    }
    true
}

/// Run `op ... <args>` with `--answers <file>` against `store`, assert
/// success, and return the parsed JSON envelope.
fn op(store: &Path, answers: &Path, args: &[&str]) -> Value {
    let mut cmd = Command::new(deployer_bin());
    cmd.arg("op")
        .arg("--store-root")
        .arg(store)
        .arg("--answers")
        .arg(answers);
    cmd.args(args);
    let out = cmd.output().expect("spawn greentic-deployer");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "`op {args:?}` failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("`op {args:?}` stdout is not json ({e}):\n{stdout}"))
}

/// Write a manifest file under `dir` and return its path.
fn write_manifest(dir: &Path, manifest: &Value) -> PathBuf {
    let path = dir.join("env-manifest.json");
    std::fs::write(&path, serde_json::to_vec(manifest).unwrap()).expect("write manifest");
    path
}

/// Build the minimal env-manifest for `env up`.
fn minimal_manifest() -> Value {
    serde_json::json!({
        "schema": "greentic.env-manifest.v1",
        "environment": { "id": "local" },
        "cluster": {
            "provider": "kind",
            "name": KIND_CLUSTER,
        },
    })
}

/// Check whether a Deployment is Ready (available replicas == desired replicas).
fn deployment_ready(name: &str) -> bool {
    let out = Command::new("kubectl")
        .args([
            "-n",
            NAMESPACE,
            "get",
            "deployment",
            name,
            "-o",
            "jsonpath={.status.availableReplicas}",
        ])
        .output()
        .expect("spawn kubectl");
    let avail = String::from_utf8_lossy(&out.stdout);
    let avail: i64 = avail.trim().parse().unwrap_or(0);
    avail >= 1
}

/// Clean up the kind cluster used by these tests.
fn cleanup_kind_cluster() {
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", KIND_CLUSTER])
        .status();
}

#[test]
fn env_up_creates_cluster_and_reconciles() {
    if !armed() {
        return;
    }

    // Start clean: tear down any prior cluster from a failed run.
    cleanup_kind_cluster();

    let store = tempfile::tempdir().expect("create temp store");
    let manifest = minimal_manifest();
    let manifest_path = write_manifest(store.path(), &manifest);

    // First run: creates the kind cluster, inits the env, applies, reconciles.
    let outcome = op(
        store.path(),
        &manifest_path,
        &["env", "up", "--yes", "--no-port-forward"],
    );
    assert_eq!(outcome["noun"], "env", "outcome: {outcome}");
    assert_eq!(outcome["op"], "up", "outcome: {outcome}");
    let applied = outcome["result"]["applied_count"]
        .as_i64()
        .expect("applied_count");
    assert!(applied > 0, "at least one object applied: {outcome}");

    // Verify Deployments are Ready.
    assert!(
        deployment_ready(ROUTER_DEPLOY),
        "router Deployment must be ready after env up"
    );

    // Second run: idempotent convergence.
    let outcome2 = op(
        store.path(),
        &manifest_path,
        &["env", "up", "--yes", "--no-port-forward"],
    );
    assert_eq!(outcome2["noun"], "env");
    assert_eq!(outcome2["op"], "up");
    let applied2 = outcome2["result"]["applied_count"]
        .as_i64()
        .expect("applied_count");
    assert!(
        applied2 > 0,
        "idempotent run still applies (declarative upsert)"
    );

    // Teardown.
    cleanup_kind_cluster();
}
