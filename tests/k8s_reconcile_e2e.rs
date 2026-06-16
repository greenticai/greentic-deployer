//! Live-cluster E2E for `op env reconcile` (Phase D PR-5.3).
//!
//! `reconcile` is the first deployer verb that drives a *connected* cluster:
//! it applies the rendered desired state and prunes the workers of revisions
//! that no longer have cluster presence. The unit tests in
//! `env_packs::k8s::deployer` exercise that logic against an in-memory fake
//! and the kube-client tests drive a pre-built `kube::Client` over a
//! `tower-test` mock — neither opens a socket, so the *success path against a
//! real API server* (TLS, server-side apply, real delete) has zero coverage.
//! This test closes that gap end-to-end against a kind cluster.
//!
//! It is gated twice so it never runs in the normal suite:
//!   - the whole module needs `GREENTIC_K8S_E2E=1` (set only by the CI
//!     `k8s-e2e` job, which stands up kind first), otherwise it no-ops; and
//!   - it shells out to `kubectl` and the cargo-built binary, talking to the
//!     ambient kubeconfig current-context (kind in CI).
//!
//! The ceremony mirrors a real deployment: create env → bind the K8s
//! deployer → bootstrap the trust root → add a bundle → stage + warm a
//! revision → reconcile (apply) → archive → reconcile (prune).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// Env that arms the test. Unset (the default in `cargo test`) → skip.
const E2E_GATE: &str = "GREENTIC_K8S_E2E";

/// `local` is the only env id the LocalFsStore CLI accepts without RBAC;
/// its namespace derives to `gtc-local`.
const ENV_ID: &str = "local";
const NAMESPACE: &str = "gtc-local";
const ROUTER_DEPLOY: &str = "gtc-router";

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

/// Run `op … <args>` (optionally with `--answers <file>`) against `store`,
/// assert success, and return the parsed JSON envelope.
fn op(store: &Path, answers: Option<&Path>, args: &[&str]) -> Value {
    let mut cmd = Command::new(deployer_bin());
    cmd.arg("op").arg("--store-root").arg(store);
    if let Some(path) = answers {
        cmd.arg("--answers").arg(path);
    }
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

/// Write a JSON payload file under `store` and return its path.
fn payload(store: &Path, name: &str, body: Value) -> PathBuf {
    let path = store.join(name);
    std::fs::write(&path, serde_json::to_vec(&body).unwrap()).expect("write payload");
    path
}

fn kubectl(args: &[&str]) -> Output {
    Command::new("kubectl")
        .args(args)
        .output()
        .expect("spawn kubectl — is it on PATH? (the CI `k8s-e2e` job installs it)")
}

/// `true` when the named object exists in the cluster.
fn object_exists(kind: &str, name: &str, namespace: Option<&str>) -> bool {
    let mut args = vec!["get", kind, name, "-o", "name"];
    if let Some(ns) = namespace {
        args.push("-n");
        args.push(ns);
    }
    kubectl(&args).status.success()
}

/// `reconcile`'s self-reported `(applied_count, pruned_count)`.
fn reconcile(store: &Path) -> (u64, u64) {
    let env = op(store, None, &["env", "reconcile", ENV_ID]);
    let result = &env["result"];
    assert_eq!(
        result["identity"], "ambient",
        "reconcile runs as ambient identity until the secrets sink lands"
    );
    (
        result["applied_count"].as_u64().expect("applied_count"),
        result["pruned_count"].as_u64().expect("pruned_count"),
    )
}

#[test]
fn reconcile_applies_then_prunes_against_a_live_cluster() {
    if std::env::var(E2E_GATE).is_err() {
        eprintln!(
            "skipping live-cluster E2E: set {E2E_GATE}=1 (needs a kind cluster on the ambient kubeconfig)"
        );
        return;
    }
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    // 1. Create the env and bind the K8s deployer (namespace → gtc-local).
    let create = payload(
        store,
        "create.json",
        serde_json::json!({"environment_id": ENV_ID, "name": ENV_ID}),
    );
    op(store, Some(&create), &["env", "create"]);
    let bind = payload(
        store,
        "bind.json",
        serde_json::json!({
            "environment_id": ENV_ID,
            "slot": "deployer",
            "kind": "greentic.deployer.k8s@1.0.0",
            "pack_ref": "builtin",
        }),
    );
    op(store, Some(&bind), &["env-packs", "add"]);

    // 2. Bootstrap the trust root (the revenue-policy writer in `bundles add`
    //    refuses to sign without the operator key trusted for this env).
    op(store, None, &["trust-root", "bootstrap", ENV_ID]);

    // 3. Add a bundle, then stage + warm a revision so it has cluster
    //    presence. Stage/warm are desired-state-only (no cluster contact) —
    //    `reconcile` is the first verb to touch the API server.
    let add = payload(
        store,
        "add.json",
        serde_json::json!({
            "environment_id": ENV_ID,
            "bundle_id": "e2e-bundle",
            "route_binding": {"path_prefixes": ["/e2e"]},
        }),
    );
    let deployment_id = op(store, Some(&add), &["bundles", "add"])["result"]["deployment_id"]
        .as_str()
        .expect("deployment_id")
        .to_string();

    let stage = payload(
        store,
        "stage.json",
        serde_json::json!({"environment_id": ENV_ID, "deployment_id": deployment_id}),
    );
    let revision_id = op(store, Some(&stage), &["revisions", "stage"])["result"]["revision_id"]
        .as_str()
        .expect("revision_id")
        .to_string();

    let rev = payload(
        store,
        "rev.json",
        serde_json::json!({"environment_id": ENV_ID, "revision_id": revision_id}),
    );
    let warmed = op(store, Some(&rev), &["revisions", "warm"]);
    assert_eq!(
        warmed["result"]["lifecycle"], "ready",
        "revision warmed to Ready"
    );

    // Worker objects are named after the lowercased revision ULID.
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    // 4. Reconcile → applies the env-level set (9) + the warmed revision's
    //    worker pair (2). Verify both the verb's self-report and ground truth.
    let (applied, pruned) = reconcile(store);
    assert_eq!(
        (applied, pruned),
        (11, 0),
        "first reconcile applies env-level + worker pair, prunes nothing"
    );
    assert!(
        object_exists("namespace", NAMESPACE, None),
        "cluster-scoped namespace applied"
    );
    assert!(
        object_exists("deployment", ROUTER_DEPLOY, Some(NAMESPACE)),
        "router deployment applied"
    );
    assert!(
        object_exists("deployment", &worker, Some(NAMESPACE)),
        "worker deployment applied"
    );
    assert!(
        object_exists("service", &worker, Some(NAMESPACE)),
        "worker service applied"
    );

    // 5. Reconcile again → declarative upsert is idempotent: same applied
    //    set, nothing pruned, worker still present.
    let (applied2, pruned2) = reconcile(store);
    assert_eq!((applied2, pruned2), (11, 0), "reconcile is idempotent");
    assert!(
        object_exists("deployment", &worker, Some(NAMESPACE)),
        "worker survives idempotent reconcile"
    );

    // 6. Archive the revision (→ no cluster presence), reconcile → prunes the
    //    worker pair, leaves the env-level set. Env-level objects are NEVER
    //    pruned (that would be env destruction, a separate verb).
    let archived = op(store, Some(&rev), &["revisions", "archive"]);
    assert_eq!(
        archived["result"]["lifecycle"], "archived",
        "revision archived"
    );

    let (applied3, pruned3) = reconcile(store);
    assert_eq!(
        (applied3, pruned3),
        (9, 2),
        "reconcile prunes the now-absent revision's worker pair"
    );
    assert!(
        !object_exists("deployment", &worker, Some(NAMESPACE)),
        "worker deployment pruned"
    );
    assert!(
        !object_exists("service", &worker, Some(NAMESPACE)),
        "worker service pruned"
    );
    assert!(
        object_exists("deployment", ROUTER_DEPLOY, Some(NAMESPACE)),
        "env-level router survives prune"
    );

    // Best-effort cleanup so reruns against a persistent cluster start clean.
    // (CI's kind cluster is torn down with the job, so this is a local nicety.)
    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}
