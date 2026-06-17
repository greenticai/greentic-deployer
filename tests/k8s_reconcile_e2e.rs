//! Live-cluster E2E for `op env reconcile`, `op env apply-revision`, and
//! `op credentials requirements` (Phase D PR-5.3).
//!
//! These are the first deployer verbs that drive a *connected* cluster:
//! `reconcile` converges the whole env (apply desired state + prune absent
//! revisions' workers); `apply-revision` is the surgical single-revision
//! counterpart (apply OR tear down one revision's worker pair via the Deployer
//! trait verbs). The unit tests in `env_packs::k8s::deployer` exercise that
//! logic against an in-memory fake and the kube-client tests drive a pre-built
//! `kube::Client` over a `tower-test` mock — neither opens a socket, so the
//! *success path against a real API server* (TLS, server-side apply, real
//! delete) has zero coverage. These tests close that gap end-to-end against a
//! kind cluster.
//!
//! They are gated twice so they never run in the normal suite:
//!   - the whole module needs `GREENTIC_K8S_E2E=1` (set only by the CI
//!     `k8s-e2e` job, which stands up kind first), otherwise they no-op; and
//!   - they shell out to `kubectl` and the cargo-built binary, talking to the
//!     ambient kubeconfig current-context (kind in CI).
//!
//! All three use the env id `local` (→ namespace `gtc-local`). The two
//! reconcile/apply-revision tests mutate that namespace on the one kind
//! cluster, so each resets it at the start (best-effort, waits for any prior
//! Terminating to finish) to stay order-independent; the credentials test is a
//! read-only SSAR permission check that touches no namespace state. The CI job
//! runs them with `--test-threads=1`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// Env that arms the tests. Unset (the default in `cargo test`) → skip.
const E2E_GATE: &str = "GREENTIC_K8S_E2E";

/// `local` is the only env id the LocalFsStore CLI accepts without RBAC;
/// its namespace derives to `gtc-local`.
const ENV_ID: &str = "local";
const NAMESPACE: &str = "gtc-local";
const ROUTER_DEPLOY: &str = "gtc-router";

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

/// `true` when the tests are armed. Unset → the caller returns early.
fn armed() -> bool {
    if std::env::var(E2E_GATE).is_err() {
        eprintln!(
            "skipping live-cluster E2E: set {E2E_GATE}=1 (needs a kind cluster on the ambient kubeconfig)"
        );
        return false;
    }
    true
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

/// Delete the test namespace and WAIT for it to be gone, so a test starts from
/// a clean slate regardless of what a prior test left Terminating. Best-effort:
/// a missing namespace is a no-op (`--ignore-not-found`).
fn reset_namespace() {
    let _ = kubectl(&["delete", "namespace", NAMESPACE, "--ignore-not-found"]);
}

/// Create the env and bind the K8s deployer (namespace → `gtc-local`). The
/// minimum setup before any cluster-touching verb — shared by the reconcile /
/// apply-revision ceremony and the credentials probe.
fn bind_k8s_env(store: &Path) {
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
}

/// Stamp a `credentials_ref` on the stored env through the public
/// [`EnvironmentStore`](greentic_deployer::environment::EnvironmentStore) API.
///
/// The K8s deployer reports `requires_credentials_material() == true`, so the
/// requirements runner rejects an env without one — but there is no CLI verb
/// to supply it (it normally arrives via the setup wizard). The ambient-identity
/// probe (`bound_token = None`) ignores the ref's value; it validates the
/// kubeconfig identity, so any well-formed ref unblocks the check.
fn set_credentials_ref(store: &Path) {
    use greentic_deploy_spec::{EnvId, SecretRef};
    use greentic_deployer::environment::{EnvironmentStore, LocalFsStore};

    let api = LocalFsStore::new(store);
    let mut env = api
        .load(&EnvId::try_from(ENV_ID).expect("env id"))
        .expect("load env to stamp credentials_ref");
    env.credentials_ref =
        Some(SecretRef::try_new("secret://local/k8s/ambient").expect("well-formed ref"));
    api.save(&env).expect("save env with credentials_ref");
}

/// Run the full setup ceremony (create env → bind the K8s deployer →
/// bootstrap the trust root → add a bundle → stage + warm a revision) and
/// return the warmed revision id. The revision ends up `Ready` (cluster
/// presence) but nothing has touched the cluster yet — stage/warm are
/// desired-state-only; `reconcile` / `apply-revision` are the first verbs to
/// reach the API server.
fn provision_ready_revision(store: &Path) -> String {
    // 1. Create the env and bind the K8s deployer (namespace → gtc-local).
    bind_k8s_env(store);

    // 2. Bootstrap the trust root (the revenue-policy writer in `bundles add`
    //    refuses to sign without the operator key trusted for this env).
    op(store, None, &["trust-root", "bootstrap", ENV_ID]);

    // 3. Add a bundle, then stage + warm a revision so it has cluster presence.
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
    revision_id
}

/// Archive a revision (desired-state-only — no cluster contact).
fn archive(store: &Path, revision_id: &str) {
    let rev = payload(
        store,
        "archive.json",
        serde_json::json!({"environment_id": ENV_ID, "revision_id": revision_id}),
    );
    let archived = op(store, Some(&rev), &["revisions", "archive"]);
    assert_eq!(
        archived["result"]["lifecycle"], "archived",
        "revision archived"
    );
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

/// `apply-revision`'s self-reported action (`"warmed"` / `"archived"`).
fn apply_revision(store: &Path, revision_id: &str) -> String {
    let env = op(store, None, &["env", "apply-revision", ENV_ID, revision_id]);
    let result = &env["result"];
    assert_eq!(
        result["identity"], "ambient",
        "apply-revision runs as ambient identity until the secrets sink lands"
    );
    result["action"].as_str().expect("action").to_string()
}

#[test]
fn reconcile_applies_then_prunes_against_a_live_cluster() {
    if !armed() {
        return;
    }
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    let revision_id = provision_ready_revision(store);
    // Worker objects are named after the lowercased revision ULID.
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    // Reconcile → applies the env-level set (9) + the warmed revision's worker
    // pair (2). Verify both the verb's self-report and ground truth.
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

    // Reconcile again → declarative upsert is idempotent: same applied set,
    // nothing pruned, worker still present.
    let (applied2, pruned2) = reconcile(store);
    assert_eq!((applied2, pruned2), (11, 0), "reconcile is idempotent");
    assert!(
        object_exists("deployment", &worker, Some(NAMESPACE)),
        "worker survives idempotent reconcile"
    );

    // Archive the revision (→ no cluster presence), reconcile → prunes the
    // worker pair, leaves the env-level set. Env-level objects are NEVER pruned
    // (that would be env destruction, a separate verb).
    archive(store, &revision_id);

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

    // Best-effort cleanup (the next test's reset also waits, so --wait=false).
    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}

/// `op credentials requirements` against a live cluster: the wiring connects a
/// real `KubeValidatorClient` and runs `SelfSubjectReview` (identity) plus one
/// `SelfSubjectAccessReview` per validated operation. kind's default kubeconfig
/// is cluster-admin, so identity resolves and every op is Allowed → overall
/// `pass`. This is the only coverage of the SSAR sweep against a real API
/// server — the unit tests drive a `tower-test` mock and never open a socket.
///
/// SSAR is a read-only permission check: it touches no namespace state, so this
/// test needs no reset/cleanup and is independent of the reconcile tests.
#[test]
fn credentials_requirements_passes_against_a_live_cluster() {
    if !armed() {
        return;
    }
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    bind_k8s_env(store);
    set_credentials_ref(store);

    // `credentials requirements` takes the env via the `--answers` payload
    // (a unit clap verb), unlike reconcile / apply-revision's positional env.
    let req = payload(
        store,
        "creds_req.json",
        serde_json::json!({"environment_id": ENV_ID}),
    );
    let out = op(store, Some(&req), &["credentials", "requirements"]);
    let result = &out["result"];
    assert_eq!(
        result["result"], "pass",
        "kind admin resolves identity and is allowed every validated op: {result}"
    );
    assert_eq!(
        result["missing_capabilities"].as_array().map(Vec::len),
        Some(0),
        "no capability is missing under cluster-admin: {result}"
    );
    let checks = result["checks"].as_array().expect("checks array");
    assert!(
        checks
            .iter()
            .any(|c| c["capability"]["id"] == "k8s.api.reachable" && c["status"] == "pass"),
        "the reachability probe ran and passed: {result}"
    );
    assert!(
        checks.len() > 1,
        "reachable + one SSAR check per validated operation: {result}"
    );
}

#[test]
fn apply_revision_warms_then_archives_a_single_revision_against_a_live_cluster() {
    if !armed() {
        return;
    }
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    let revision_id = provision_ready_revision(store);
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    // Establish the env-level set (namespace + router) so the surgical
    // apply-revision has somewhere to land. apply-revision only touches the
    // one revision's worker pair — it assumes the env already exists.
    let (applied, _) = reconcile(store);
    assert_eq!(applied, 11, "reconcile establishes env-level + worker pair");

    // apply-revision on the Ready (present) revision → warm branch. Idempotent
    // over reconcile's apply: same worker pair, still present.
    let action = apply_revision(store, &revision_id);
    assert_eq!(action, "warmed", "Ready revision drives the warm branch");
    assert!(
        object_exists("deployment", &worker, Some(NAMESPACE)),
        "worker deployment present after warm"
    );
    assert!(
        object_exists("service", &worker, Some(NAMESPACE)),
        "worker service present after warm"
    );

    // Archive the revision's recorded state, then apply-revision on the now
    // absent revision → archive branch tears the worker pair down (a real
    // present → absent deletion, distinct from reconcile's bulk prune).
    archive(store, &revision_id);
    let action2 = apply_revision(store, &revision_id);
    assert_eq!(
        action2, "archived",
        "archived revision drives the archive branch"
    );
    assert!(
        !object_exists("deployment", &worker, Some(NAMESPACE)),
        "worker deployment torn down by apply-revision"
    );
    assert!(
        !object_exists("service", &worker, Some(NAMESPACE)),
        "worker service torn down by apply-revision"
    );
    // Env-level objects are untouched — apply-revision only owns the worker pair.
    assert!(
        object_exists("deployment", ROUTER_DEPLOY, Some(NAMESPACE)),
        "env-level router survives apply-revision archive"
    );

    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}
