//! Live-cluster E2E for `op env up` with Vault-backed secrets.
//!
//! Gated on `GREENTIC_VAULT_E2E=1`. Exercises the full Vault path against a
//! kind cluster: parse → preflight → cluster → vault deploy + bootstrap + seed →
//! apply → reconcile+rollout → verify. Asserts exit 0, the Vault outcome block
//! reports the expected deploy mode / namespace / seed count, the Vault
//! Deployment is Ready in its own namespace, the worker runs as ServiceAccount
//! `gtc-worker` (not the default SA), NO `gtc-dev-secrets` Secret exists in the
//! env namespace (Vault replaces the dev-store bridge), and a second run
//! converges (idempotency).
//!
//! Runs against the ambient kubeconfig current-context (kind in CI).
//!
//! NOTE — skeleton until the k8s-vault demo. This fixture is **not yet runnable
//! end to end**: it declares no bundle, so `env up` renders no worker Deployment
//! and phase 6b (`vault_verify_phase`) rejects an empty worker list ("no worker
//! Deployment found to verify"). A passing run needs a warmed bundle (a real
//! revision → worker) — e.g. the `webchat-bot` OCI bundle used by
//! `my_demos/k8s-vault-demo` — plus a tenant-owned env whose `tenant_org_id`
//! covers the served deployment tenant. The full manifest is completed and this
//! test is actually executed as part of the k8s-vault demo step; until then it
//! stands as the intended-assertions skeleton and only compiles + gated-skips.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Env that arms the tests. Unset (the default in `cargo test`) -> skip.
const E2E_GATE: &str = "GREENTIC_VAULT_E2E";

/// The kind cluster name used by these tests.
const KIND_CLUSTER: &str = "gtc-vault-e2e";

/// Namespace derived from the env id (`gtc-<env_id>`).
const NAMESPACE: &str = "gtc-local";

/// Namespace the dev Vault runs in (matches `DEFAULT_VAULT_NAMESPACE`).
const VAULT_NAMESPACE: &str = "greentic";

/// Vault pack descriptor bound to the secrets slot.
const VAULT_SECRETS_PACK: &str = "greentic.secrets.vault@0.1.0";

/// Env var the seed entry reads from.
const SEED_ENV_VAR: &str = "GREENTIC_VAULT_E2E_SEED";

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

/// `true` when the tests are armed. Unset -> the caller returns early.
fn armed() -> bool {
    if std::env::var(E2E_GATE).is_err() {
        eprintln!("skipping vault env-up E2E: set {E2E_GATE}=1 (needs docker + kind on PATH)");
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
    // Export the seed env var so the Vault seed phase can resolve it.
    cmd.env(SEED_ENV_VAR, "dummy-e2e-bot-token");
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

/// Build the env-manifest for a Vault-backed `env up`.
///
/// NOTE: intentionally declares no `bundles[]` yet, so this manifest produces no
/// worker and `vault_verify_phase` fails if armed as-is (see the module header).
/// Add a warmed bundle (e.g. the demo's `webchat-bot`) to make it a passing run
/// at the demo step.
fn vault_manifest() -> Value {
    serde_json::json!({
        "schema": "greentic.env-manifest.v1",
        "environment": { "id": "local", "tenant_org_id": "e2e-org" },
        "cluster": {
            "provider": "kind",
            "name": KIND_CLUSTER,
        },
        "packs": [
            {
                "slot": "secrets",
                "kind": VAULT_SECRETS_PACK,
                "pack_ref": "builtin",
            },
        ],
        "vault_bootstrap": {
            "deploy": "dev-in-cluster",
            "seed": [
                {
                    "path": "tenant-default/_/messaging-telegram/telegram_bot_token",
                    "from_env": SEED_ENV_VAR,
                },
            ],
        },
    })
}

/// Check whether a Deployment is Ready (available replicas >= 1).
fn deployment_ready(namespace: &str, name: &str) -> bool {
    let out = Command::new("kubectl")
        .args([
            "-n",
            namespace,
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

/// Check whether a K8s Secret whose name contains `pattern` exists in `namespace`.
fn secret_exists(namespace: &str, pattern: &str) -> bool {
    let out = Command::new("kubectl")
        .args(["-n", namespace, "get", "secrets", "-o", "name"])
        .output()
        .expect("spawn kubectl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().any(|l| l.contains(pattern))
}

/// Clean up the kind cluster used by these tests.
fn cleanup_kind_cluster() {
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", KIND_CLUSTER])
        .status();
}

#[test]
fn vault_env_up_deploys_vault_and_seeds() {
    if !armed() {
        return;
    }

    // Start clean: tear down any prior cluster from a failed run.
    cleanup_kind_cluster();

    let store = tempfile::tempdir().expect("create temp store");
    let manifest = vault_manifest();
    let manifest_path = write_manifest(store.path(), &manifest);

    // ── First run: creates the kind cluster, deploys Vault, seeds, reconciles.
    let outcome = op(
        store.path(),
        &manifest_path,
        &["env", "up", "--yes", "--no-port-forward"],
    );
    assert_eq!(outcome["op"], "up", "outcome: {outcome}");

    // Vault outcome block assertions.
    let vault = &outcome["result"]["vault"];
    assert_eq!(
        vault["deploy"], "dev-in-cluster",
        "vault deploy mode: {outcome}"
    );
    assert_eq!(
        vault["namespace"], VAULT_NAMESPACE,
        "vault namespace: {outcome}"
    );
    let seeded = vault["seeded"].as_i64().expect("seeded count");
    assert!(seeded >= 1, "at least one secret seeded: {outcome}");

    // Vault Deployment is Ready in its own namespace.
    assert!(
        deployment_ready(VAULT_NAMESPACE, "vault"),
        "Vault Deployment must be ready in namespace `{VAULT_NAMESPACE}`"
    );

    // Worker Deployment uses the gtc-worker ServiceAccount (Vault-shaped).
    let worker_sa = Command::new("kubectl")
        .args([
            "-n",
            NAMESPACE,
            "get",
            "deployment",
            "-l",
            "app.kubernetes.io/component=worker",
            "-o",
            "jsonpath={.items[0].spec.template.spec.serviceAccountName}",
        ])
        .output()
        .expect("spawn kubectl");
    let sa = String::from_utf8_lossy(&worker_sa.stdout);
    assert_eq!(
        sa.trim(),
        "gtc-worker",
        "worker must run as SA `gtc-worker`, got `{}`",
        sa.trim()
    );

    // No dev-store Secret in the env namespace — Vault replaces the bridge.
    assert!(
        !secret_exists(NAMESPACE, "gtc-dev-secrets"),
        "no `gtc-dev-secrets` Secret must exist in `{NAMESPACE}` when using Vault"
    );

    // ── Idempotency: second run converges.
    let outcome2 = op(
        store.path(),
        &manifest_path,
        &["env", "up", "--yes", "--no-port-forward"],
    );
    assert_eq!(outcome2["op"], "up", "idempotent run outcome: {outcome2}");

    // Teardown.
    cleanup_kind_cluster();
}
