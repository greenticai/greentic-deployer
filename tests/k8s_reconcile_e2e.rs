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

/// A runtime image that deliberately never serves `/healthz` under the
/// `start --env` boot: the stable `:latest` predates the bundle-less serve
/// path, so `start --env` fails fast and the worker never becomes ready. The
/// warm-gate-blocks test pins this (via a `runtime_image` answer) so it keeps
/// testing the readiness gate even though [`DEFAULT_RUNTIME_IMAGE`] is now a
/// serving `:develop` image.
const UNREADY_IMAGE: &str = "ghcr.io/greenticai/greentic-start-distroless:latest";

/// Store-aligned credentials ref for the deployer's bound ServiceAccount token
/// (`secret://<env>/<tenant>/<team>/<pack>/<name>`). The resolver derives the
/// env-var store-key from this, so seeding that var supplies the token.
const CREDS_REF: &str = "secret://local/default/_/k8s-deployer/sa_token";
/// Dedicated namespace holding the identity-flip test's ServiceAccounts —
/// separate from the env's `gtc-local` so it never collides with the
/// reconcile/apply-revision tests' namespace churn.
const CREDS_SA_NS: &str = "gtc-creds-e2e";

/// In-cluster plain-HTTP server (busybox `httpd`) that serves the fixture
/// `.gtbundle` for the M2 boot-time pull test. The worker pulls over `http://`,
/// which greentic-start's bundle-ref path fetches with `ureq` — bypassing the
/// OCI client (HTTPS-only, no insecure escape hatch), so kind needs no registry
/// or TLS. Lives in the env's own `gtc-local` namespace for one-shot cleanup.
const BUNDLE_SERVER: &str = "gtc-bundle-server";
/// ConfigMap carrying the fixture bundle's bytes (the 4 KiB fixture is far
/// under the 1 MiB ConfigMap limit), mounted into the httpd pod's docroot.
const BUNDLE_BLOB_CM: &str = "gtc-bundle-blob";
/// The file name the bundle is served (and pulled) under.
const BUNDLE_FILE: &str = "bundle.gtbundle";
/// The port the in-cluster httpd listens on (and the Service exposes).
const BUNDLE_SERVER_PORT: u16 = 8080;

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
/// apply-revision ceremony and the credentials probe. When `runtime_image` is
/// `Some`, it is recorded as the deployer-slot `runtime_image` answer (via
/// `answers_ref`) so the rendered worker/router pods use it instead of the
/// default published image.
fn bind_k8s_env(store: &Path, runtime_image: Option<&str>) {
    let create = payload(
        store,
        "create.json",
        serde_json::json!({"environment_id": ENV_ID, "name": ENV_ID}),
    );
    op(store, Some(&create), &["env", "create"]);
    let mut bind_doc = serde_json::json!({
        "environment_id": ENV_ID,
        "slot": "deployer",
        "kind": "greentic.deployer.k8s@1.0.0",
        "pack_ref": "builtin",
    });
    if let Some(image) = runtime_image {
        // The render/reconcile path reads the deployer-slot answers from the
        // binding's `answers_ref` — a file under the env dir (which `env
        // create` just made).
        let answers_rel = "deployer-answers.json";
        std::fs::write(
            store.join(ENV_ID).join(answers_rel),
            serde_json::to_vec(&serde_json::json!({"runtime_image": image}))
                .expect("answers serialize"),
        )
        .expect("write deployer answers");
        bind_doc["answers_ref"] = serde_json::json!(answers_rel);
    }
    let bind = payload(store, "bind.json", bind_doc);
    op(store, Some(&bind), &["env-packs", "add"]);
}

/// Stamp a store-aligned `credentials_ref` on the stored env through the public
/// [`EnvironmentStore`](greentic_deployer::environment::EnvironmentStore) API.
///
/// The K8s deployer reports `requires_credentials_material() == true`, so the
/// requirements runner rejects an env without one — and there is no CLI verb to
/// set it (it normally arrives via the setup wizard). The live verbs now resolve
/// this ref to a bearer token, so it must be store-aligned and have its material
/// seeded (here: via the env var the resolver reads) before use.
fn set_credentials_ref(store: &Path, ref_str: &str) {
    use greentic_deploy_spec::{EnvId, SecretRef};
    use greentic_deployer::environment::{EnvironmentStore, LocalFsStore};

    let api = LocalFsStore::new(store);
    let mut env = api
        .load(&EnvId::try_from(ENV_ID).expect("env id"))
        .expect("load env to stamp credentials_ref");
    env.credentials_ref = Some(SecretRef::try_new(ref_str).expect("well-formed ref"));
    api.save(&env).expect("save env with credentials_ref");
}

/// The canonical env-var key the bound-credential resolver reads for `CREDS_REF`.
/// The deployer derives the same key from the ref's `secrets://` store URI, so
/// setting this var on the spawned `op` process supplies the SA token
/// cross-process — the same env-var source `resolve_runtime_secrets` honors.
fn creds_token_env_key() -> String {
    use greentic_deploy_spec::SecretRef;
    use greentic_secrets_lib::canonical_secret_store_key;
    let store_uri = SecretRef::try_new(CREDS_REF)
        .expect("ref")
        .to_store_uri()
        .expect("store-aligned uri")
        .to_string();
    canonical_secret_store_key(&store_uri).expect("canonical store key")
}

/// Run kubectl, asserting success, returning trimmed stdout.
fn kubectl_ok(args: &[&str]) -> String {
    let out = kubectl(args);
    assert!(
        out.status.success(),
        "kubectl {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `op credentials requirements` with the bound ServiceAccount token seeded via
/// the env var the resolver reads. Returns the parsed envelope.
fn requirements_with_token(store: &Path, token: &str) -> Value {
    let req = payload(
        store,
        "creds_req.json",
        serde_json::json!({"environment_id": ENV_ID}),
    );
    let mut cmd = Command::new(deployer_bin());
    cmd.arg("op")
        .arg("--store-root")
        .arg(store)
        .arg("--answers")
        .arg(&req);
    cmd.args(["credentials", "requirements"]);
    cmd.env(creds_token_env_key(), token);
    let out = cmd.output().expect("spawn greentic-deployer");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "`op credentials requirements` failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("requirements stdout is not json ({e}):\n{stdout}"))
}

/// Shared provisioning ceremony for the cluster E2Es: create env (optionally
/// pinning `runtime_image`) → bind the K8s deployer (namespace → gtc-local) →
/// bootstrap the trust root → add a bundle → stage + warm a revision to
/// `Ready`. When `bundle_path` is set, stage hashes the real bundle (recording
/// its sha256 as `bundle_digest`); when `source_uri` is set, it rides on the
/// stage payload as the worker's boot-pull source; when `route` is set, 100 %
/// of traffic is pointed at the revision afterward. Nothing touches the cluster
/// yet — stage/warm/traffic are desired-state-only; `reconcile` /
/// `apply-revision` are the first verbs to reach the API server. Returns the
/// warmed revision id.
fn provision_revision(
    store: &Path,
    runtime_image: Option<&str>,
    bundle_path: Option<&Path>,
    source_uri: Option<&str>,
    route: bool,
) -> String {
    // 1. Create the env and bind the K8s deployer (namespace → gtc-local).
    bind_k8s_env(store, runtime_image);

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

    // `bundle_path` makes stage hash the real fixture (→ the same sha256 the
    // worker recomputes on the pulled bytes); `bundle_source_uri` is what the
    // worker reads from `environment.json` to pull.
    let mut stage_doc = serde_json::json!({
        "environment_id": ENV_ID,
        "deployment_id": deployment_id,
    });
    if let Some(path) = bundle_path {
        stage_doc["bundle_path"] = serde_json::json!(path.to_string_lossy());
    }
    if let Some(uri) = source_uri {
        stage_doc["bundle_source_uri"] = serde_json::json!(uri);
    }
    let stage = payload(store, "stage.json", stage_doc);
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

    // Route 100 % of traffic to the revision so the worker's boot pull (which
    // only pulls traffic-routed revisions) fires.
    if route {
        let traffic = payload(
            store,
            "traffic.json",
            serde_json::json!({
                "environment_id": ENV_ID,
                "deployment_id": deployment_id,
                "entries": [{"revision_id": revision_id, "weight_bps": 10000}],
                "idempotency_key": format!("e2e-traffic-{revision_id}"),
            }),
        );
        op(store, Some(&traffic), &["traffic", "set"]);
    }

    revision_id
}

/// The desired-state-only ceremony with no bundle bytes and no routing — the
/// revision reaches `Ready` (cluster presence) but a worker booting it serves
/// probes only (no `bundle_source_uri` to pull). Used by the reconcile /
/// apply-revision / warm-serving tests.
fn provision_ready_revision(store: &Path, runtime_image: Option<&str>) -> String {
    provision_revision(store, runtime_image, None, None, false)
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
        "reconcile runs as ambient identity when no credentials_ref is bound"
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
        "apply-revision runs as ambient identity when no credentials_ref is bound"
    );
    result["action"].as_str().expect("action").to_string()
}

/// Drive `op env apply-revision` expecting the warm readiness gate to FAIL,
/// returning the parsed error JSON.
///
/// This exercises the BLOCK path: the worker never becomes ready, so
/// `warm_revision`'s readiness wait times out. The caller pins a
/// deliberately-unready [`UNREADY_IMAGE`] (the stable `:latest`, which predates
/// the `start --env` boot and fails fast) via a `runtime_image` answer, so the
/// gate blocks on the image regardless of what [`DEFAULT_RUNTIME_IMAGE`] is —
/// now a serving `:develop`. The positive path (a real serving image reaches
/// Ready) is covered by
/// `worker_reaches_ready_and_serves_healthz_with_a_serving_image`. A short
/// `GREENTIC_K8S_WARM_READY_TIMEOUT_SECS` keeps the gate observable without a
/// multi-minute hang (the default is 5 minutes).
fn apply_revision_expect_not_ready(store: &Path, revision_id: &str) -> Value {
    let mut cmd = Command::new(deployer_bin());
    cmd.arg("op").arg("--store-root").arg(store);
    cmd.args(["env", "apply-revision", ENV_ID, revision_id]);
    cmd.env("GREENTIC_K8S_WARM_READY_TIMEOUT_SECS", "20");
    let out = cmd.output().expect("spawn greentic-deployer");
    assert!(
        !out.status.success(),
        "apply-revision warm must fail when the worker never becomes ready:\nstdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    serde_json::from_str(stderr.trim())
        .unwrap_or_else(|e| panic!("apply-revision stderr is not json ({e}):\n{stderr}"))
}

/// The serving runtime image the worker/router pods boot, or `None` (with a
/// skip notice) when `GREENTIC_K8S_SERVING_IMAGE` is unset — the
/// `:develop`-publish-dependent gate the serving tests share on top of
/// [`armed`].
fn serving_image() -> Option<String> {
    match std::env::var("GREENTIC_K8S_SERVING_IMAGE") {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => {
            eprintln!(
                "skipping serving test: set GREENTIC_K8S_SERVING_IMAGE to a serving image \
                 already loaded into the cluster (e.g. greentic-start-distroless:<tag>)"
            );
            None
        }
    }
}

/// Path to the only ready-made valid `.gtbundle` fixture in the repo. Its pack
/// carries no `.wasm` (manifest/lock/sbom only), so it ACTIVATES and serves
/// `/healthz` but a real request would 500 at flow execution — exactly enough
/// to prove the worker pulled, digest-verified, materialized, and activated a
/// real revision without standing up a component runtime.
fn fixture_bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/bundles/perf-smoke-bundle.gtbundle")
}

/// The in-cluster URL the worker pulls its bundle from (plain HTTP, in the env
/// namespace).
fn bundle_source_uri() -> String {
    format!(
        "http://{BUNDLE_SERVER}.{NAMESPACE}.svc.cluster.local:{BUNDLE_SERVER_PORT}/{BUNDLE_FILE}"
    )
}

/// `kubectl apply -f -`, piping `manifest` on stdin; asserts success.
fn kubectl_apply_stdin(manifest: &str) {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kubectl apply -f -");
    child
        .stdin
        .take()
        .expect("kubectl stdin")
        .write_all(manifest.as_bytes())
        .expect("write manifest to kubectl");
    let out = child.wait_with_output().expect("kubectl apply -f -");
    assert!(
        out.status.success(),
        "kubectl apply -f - failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Stand up an in-cluster plain-HTTP server that serves the fixture bundle at
/// `/{BUNDLE_FILE}` and WAIT for it to be ready, so the worker can pull the
/// moment it boots. The bundle bytes ride in a ConfigMap mounted into a
/// `busybox httpd` pod's docroot. Idempotent: clears any prior run first. The
/// env namespace is created here (before `reconcile`) so the server precedes
/// the worker.
fn start_bundle_server() {
    // Clean slate, then (re)create the env namespace the server shares with the
    // worker. `reset_namespace` (a blocking delete) ran first, so the namespace
    // is gone; tolerate "already exists" defensively.
    let _ = kubectl(&["create", "namespace", NAMESPACE]);
    let _ = kubectl(&[
        "delete",
        "configmap",
        BUNDLE_BLOB_CM,
        "-n",
        NAMESPACE,
        "--ignore-not-found",
    ]);

    // Bundle bytes → ConfigMap (kubectl auto-detects binary → binaryData).
    let fixture = fixture_bundle();
    kubectl_ok(&[
        "create",
        "configmap",
        BUNDLE_BLOB_CM,
        "-n",
        NAMESPACE,
        &format!("--from-file={BUNDLE_FILE}={}", fixture.to_string_lossy()),
    ]);

    // busybox httpd Deployment + Service serving the mounted bundle. Readiness
    // is the bundle itself returning 200, so a completed rollout means the
    // worker's pull will succeed.
    let manifest = format!(
        "apiVersion: apps/v1
kind: Deployment
metadata:
  name: {BUNDLE_SERVER}
  namespace: {NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {BUNDLE_SERVER}
  template:
    metadata:
      labels:
        app: {BUNDLE_SERVER}
    spec:
      containers:
        - name: httpd
          image: busybox:1.36
          command: [\"httpd\", \"-f\", \"-v\", \"-p\", \"{BUNDLE_SERVER_PORT}\", \"-h\", \"/www\"]
          ports:
            - containerPort: {BUNDLE_SERVER_PORT}
          readinessProbe:
            httpGet:
              path: /{BUNDLE_FILE}
              port: {BUNDLE_SERVER_PORT}
            initialDelaySeconds: 1
            periodSeconds: 2
          volumeMounts:
            - name: blob
              mountPath: /www
              readOnly: true
      volumes:
        - name: blob
          configMap:
            name: {BUNDLE_BLOB_CM}
---
apiVersion: v1
kind: Service
metadata:
  name: {BUNDLE_SERVER}
  namespace: {NAMESPACE}
spec:
  selector:
    app: {BUNDLE_SERVER}
  ports:
    - port: {BUNDLE_SERVER_PORT}
      targetPort: {BUNDLE_SERVER_PORT}
"
    );
    kubectl_apply_stdin(&manifest);

    let status = kubectl(&[
        "rollout",
        "status",
        &format!("deployment/{BUNDLE_SERVER}"),
        "-n",
        NAMESPACE,
        "--timeout=120s",
    ]);
    assert!(
        status.status.success(),
        "in-cluster bundle server must come up before the worker boots:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
}

/// Provision a revision the worker will PULL at boot: stage the FIXTURE bundle
/// (so the revision records its real sha256 as `bundle_digest`) WITH the
/// `bundle_source_uri` the worker fetches, warm to Ready, and route 100 % of
/// traffic to it (boot-time pull only fires for traffic-routed revisions).
/// Returns the revision id.
fn provision_pullable_revision(store: &Path, image: &str, source_uri: &str) -> String {
    provision_revision(
        store,
        Some(image),
        Some(&fixture_bundle()),
        Some(source_uri),
        true,
    )
}

/// Dump everything needed to root-cause a worker that never reached Ready: pod
/// state, namespace events, and the worker's own logs (current and, if it
/// crash-looped, the previous container) — plus the bundle server's endpoints
/// and access log. The single fact that bisects the failure is whether the
/// worker's pull request reached the server: a GET in the server's log means
/// network + DNS worked and the failure is downstream (materialize / activate /
/// digest); no GET means the worker never connected (DNS or pod-to-pod). The
/// boot pull is fail-closed, so this only runs on a failed rollout — the live
/// cluster is still up at that point, so the queries return real state.
fn worker_failure_diagnostics(worker: &str) -> String {
    let worker_dep = format!("deployment/{worker}");
    let server_dep = format!("deployment/{BUNDLE_SERVER}");
    let probes: [(&str, Vec<&str>); 7] = [
        (
            "pods (wide)",
            vec!["get", "pods", "-n", NAMESPACE, "-o", "wide"],
        ),
        (
            "namespace events",
            vec!["get", "events", "-n", NAMESPACE, "--sort-by=.lastTimestamp"],
        ),
        ("pods describe", vec!["describe", "pods", "-n", NAMESPACE]),
        (
            "worker logs",
            vec![
                "logs",
                &worker_dep,
                "-n",
                NAMESPACE,
                "--all-containers",
                "--tail=150",
            ],
        ),
        (
            "worker logs (previous)",
            vec![
                "logs",
                &worker_dep,
                "-n",
                NAMESPACE,
                "--all-containers",
                "--previous",
                "--tail=150",
            ],
        ),
        (
            "bundle-server endpoints",
            vec![
                "get",
                "endpoints",
                BUNDLE_SERVER,
                "-n",
                NAMESPACE,
                "-o",
                "wide",
            ],
        ),
        (
            "bundle-server logs (did the pull arrive?)",
            vec!["logs", &server_dep, "-n", NAMESPACE, "--tail=60"],
        ),
    ];
    let mut out = String::new();
    for (label, args) in probes {
        let res = kubectl(&args);
        out.push_str(&format!(
            "\n--- {label} ---\n{}{}",
            String::from_utf8_lossy(&res.stdout),
            String::from_utf8_lossy(&res.stderr),
        ));
    }
    out
}

#[test]
fn reconcile_applies_then_prunes_against_a_live_cluster() {
    if !armed() {
        return;
    }
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    let revision_id = provision_ready_revision(store, None);
    // Worker objects are named after the lowercased revision ULID.
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    // Reconcile → applies the env-level set (11: namespace, env-store +
    // runtime-config ConfigMaps, router Deployment/Service/PDB, 5 NetworkPolicies
    // incl. the always-rendered worker-egress policy) + the warmed revision's
    // worker pair (2). Verify both the verb's self-report and ground truth.
    let (applied, pruned) = reconcile(store);
    assert_eq!(
        (applied, pruned),
        (13, 0),
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
    assert_eq!((applied2, pruned2), (13, 0), "reconcile is idempotent");
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
        (11, 2),
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

/// `op credentials requirements` against a live cluster, proving the bound
/// `credentials_ref` actually drives the probe identity — not the ambient
/// kubeconfig admin. The deployer resolves the ref to a ServiceAccount bearer,
/// clears the kubeconfig's client cert (so the token is the sole credential),
/// and runs `SelfSubjectReview` (identity) + one `SelfSubjectAccessReview` per
/// validated operation AS that ServiceAccount:
///
///   - bound to a cluster-admin SA token → every validated op is Allowed → pass;
///   - bound to a no-RBAC SA token → the same ops are Denied → fail.
///
/// Under the ambient kind admin BOTH would pass, so the `fail` in the second
/// case is the live proof the bound token took effect (and that the cert clear
/// in `apply_bound_token` works — without it the kind client cert would shadow
/// the token and both cases would pass). This is also the only coverage of the
/// SSAR sweep against a real API server — the unit tests drive a `tower-test`
/// mock and never open a socket.
///
/// Creates two ServiceAccounts + a ClusterRoleBinding, so it cleans them up; it
/// uses a dedicated namespace and is independent of the reconcile tests.
#[test]
fn credentials_requirements_reflects_the_bound_serviceaccount_identity() {
    if !armed() {
        return;
    }
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    bind_k8s_env(store, None);
    set_credentials_ref(store, CREDS_REF);

    // Stand up the two ServiceAccounts in a dedicated namespace (best-effort
    // clean slate first — a prior run's CRB/namespace may linger).
    let crb = "gtc-creds-e2e-admin";
    let _ = kubectl(&["delete", "clusterrolebinding", crb, "--ignore-not-found"]);
    let _ = kubectl(&["delete", "namespace", CREDS_SA_NS, "--ignore-not-found"]);
    kubectl_ok(&["create", "namespace", CREDS_SA_NS]);
    kubectl_ok(&[
        "create",
        "serviceaccount",
        "deployer-admin",
        "-n",
        CREDS_SA_NS,
    ]);
    kubectl_ok(&[
        "create",
        "serviceaccount",
        "deployer-norbac",
        "-n",
        CREDS_SA_NS,
    ]);
    kubectl_ok(&[
        "create",
        "clusterrolebinding",
        crb,
        "--clusterrole=cluster-admin",
        &format!("--serviceaccount={CREDS_SA_NS}:deployer-admin"),
    ]);

    // 1. Bind the cluster-admin SA token → every validated op Allowed → pass.
    let admin_token = kubectl_ok(&["create", "token", "deployer-admin", "-n", CREDS_SA_NS]);
    let out = requirements_with_token(store, &admin_token);
    let result = &out["result"];
    assert_eq!(
        result["result"], "pass",
        "the cluster-admin-bound SA is allowed every validated op: {result}"
    );
    assert_eq!(
        result["missing_capabilities"].as_array().map(Vec::len),
        Some(0),
        "no capability is missing for the admin-bound SA: {result}"
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

    // 2. Re-bind the no-RBAC SA token → the SAME probe now fails. Ambient admin
    //    would pass, so a `fail` here proves the bound token drives the identity.
    let norbac_token = kubectl_ok(&["create", "token", "deployer-norbac", "-n", CREDS_SA_NS]);
    let out = requirements_with_token(store, &norbac_token);
    let result = &out["result"];
    assert_eq!(
        result["result"], "fail",
        "the no-RBAC SA is denied the validated ops (ambient admin would pass): {result}"
    );
    assert!(
        result["missing_capabilities"]
            .as_array()
            .is_some_and(|m| !m.is_empty()),
        "the denied ops surface as missing capabilities: {result}"
    );

    // Cleanup the cluster-scoped artifacts this test created.
    let _ = kubectl(&["delete", "clusterrolebinding", crb, "--ignore-not-found"]);
    let _ = kubectl(&[
        "delete",
        "namespace",
        CREDS_SA_NS,
        "--ignore-not-found",
        "--wait=false",
    ]);
}

#[test]
fn apply_revision_warm_gate_blocks_unready_worker_then_archives_against_a_live_cluster() {
    if !armed() {
        return;
    }
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    let revision_id = provision_ready_revision(store, Some(UNREADY_IMAGE));
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    // Establish the env-level set (namespace + router) so the surgical
    // apply-revision has somewhere to land. apply-revision only touches the
    // one revision's worker pair — it assumes the env already exists.
    let (applied, _) = reconcile(store);
    assert_eq!(applied, 13, "reconcile establishes env-level + worker pair");

    // apply-revision on the Ready (present) revision → warm branch. warm
    // re-upserts the worker pair, then waits for the rollout. The pinned
    // UNREADY_IMAGE (`:latest`) predates the `start --env` serve boot and exits
    // immediately, so the pod never becomes available and the readiness gate
    // FAILS the warm rather than promoting a non-serving worker — the
    // live-cluster proof that the gate reads real Deployment status
    // (`observedGeneration` + `availableReplicas`) and blocks.
    let err = apply_revision_expect_not_ready(store, &revision_id);
    assert_eq!(
        err["error"]["kind"], "conflict",
        "the gate failure surfaces as a conflict: {err}"
    );
    assert!(
        err["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("did not become ready")),
        "the readiness gate must report the rollout stall: {err}"
    );
    // The worker pair stays present — apply upserts BEFORE the wait, so a gate
    // failure does not roll back the applied objects.
    assert!(
        object_exists("deployment", &worker, Some(NAMESPACE)),
        "worker deployment applied before the readiness gate"
    );
    assert!(
        object_exists("service", &worker, Some(NAMESPACE)),
        "worker service applied before the readiness gate"
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

/// The positive path: given a runtime image that actually serves `/healthz`
/// under the `start --env` boot, the worker Deployment becomes Ready (its
/// readiness probe passes) and `apply-revision` warm SUCCEEDS — the inverse of
/// the warm-gate-blocks test above.
///
/// Gated on `GREENTIC_K8S_SERVING_IMAGE` (a serving image already loaded into
/// the cluster, e.g. `kind load docker-image greentic-start-distroless:<tag>`)
/// ON TOP OF the usual `GREENTIC_K8S_E2E` gate. The deployer's `k8s-e2e` CI job
/// best-effort loads `:develop` and sets this var, so the test runs once that
/// image is published; it self-skips when the var is unset (which the CI step
/// leaves unset while `:develop` is not yet pullable).
#[test]
fn worker_reaches_ready_and_serves_healthz_with_a_serving_image() {
    if !armed() {
        return;
    }
    let Some(image) = serving_image() else {
        return;
    };
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    // Provision with the worker/router image pinned to the serving image.
    let revision_id = provision_ready_revision(store, Some(&image));
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    let (applied, _) = reconcile(store);
    assert_eq!(applied, 13, "reconcile applies env-level + worker pair");

    // The worker's readiness probe hits `/healthz`, so "rollout complete" ==
    // "the bundle-less boot is serving `/healthz` on the pod IP". This is the
    // first live proof a Greentic worker actually serves over HTTP in K8s.
    let status = kubectl(&[
        "rollout",
        "status",
        &format!("deployment/{worker}"),
        "-n",
        NAMESPACE,
        "--timeout=120s",
    ]);
    assert!(
        status.status.success(),
        "worker rollout must complete (serving image reaches Ready):\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );

    // The router (same image) likewise becomes Available.
    let router_status = kubectl(&[
        "rollout",
        "status",
        &format!("deployment/{ROUTER_DEPLOY}"),
        "-n",
        NAMESPACE,
        "--timeout=120s",
    ]);
    assert!(
        router_status.status.success(),
        "router rollout must complete with the serving image"
    );

    // And the warm readiness gate now SUCCEEDS where it blocked the
    // non-serving default — apply-revision promotes the Ready worker.
    let action = apply_revision(store, &revision_id);
    assert_eq!(
        action, "warmed",
        "apply-revision warms the now-serving worker"
    );

    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}

/// M2 end-to-end: a freshly-seeded worker PULLS its bundle at boot and serves
/// the real revision — the first live proof of the distributor-pull path.
///
/// The env-store ConfigMap ships only `environment.json` (M1), so the worker
/// boots `start --env` with an empty runtime-config. Because the routed
/// revision carries a `bundle_source_uri`, the bundle-less boot fetches the
/// `.gtbundle` over HTTP from the in-cluster server, materializes it
/// (digest-gated: the pulled bytes' sha256 must equal the sha256 the deployer
/// pinned when it staged the same fixture), activates it, and serves.
///
/// The proof is layered:
///   - The HTTP server, the worker's `/healthz` probe, and `reconcile`'s
///     readiness are all gated, so a completed worker rollout means the worker
///     pulled, digest-verified, materialized, AND activated — a failed pull or
///     a digest mismatch aborts the boot fail-closed (→ CrashLoop, never Ready).
///   - But probes-only M1 workers also reach Ready, so the boot banner on the
///     worker's stdout is asserted to name a REAL revision
///     (`serving N revision(s) for env …`) rather than the probes-only line
///     (`… serving probes only`) — the direct proof the pulled bundle became a
///     live revision.
///
/// Gated on `GREENTIC_K8S_SERVING_IMAGE` (a `:develop` worker image that
/// supports the boot pull + serve) on top of `GREENTIC_K8S_E2E`; self-skips
/// when unset, exactly like the warm-serving test above. The pull rides the
/// `http://` bundle-ref path (plain HTTP via `ureq`), so kind needs no OCI
/// registry or TLS.
#[test]
fn worker_pulls_http_bundle_and_serves_the_real_revision() {
    if !armed() {
        return;
    }
    let Some(image) = serving_image() else {
        return;
    };
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    // Serve the fixture bundle in-cluster BEFORE the worker boots (its rollout
    // waits, so the pull can't race the server coming up).
    start_bundle_server();

    let revision_id = provision_pullable_revision(store, &image, &bundle_source_uri());
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    // reconcile renders the env-store ConfigMap (carrying `environment.json`
    // with the routed revision + its `bundle_source_uri`) and the worker pair.
    let (applied, _) = reconcile(store);
    assert_eq!(applied, 13, "reconcile applies env-level + worker pair");

    // A completed rollout proves the full boot chain ran: pull → digest gate →
    // materialize → activate → serve. The HTTP server is the only bundle
    // source, so Ready here is impossible without a successful pull.
    let status = kubectl(&[
        "rollout",
        "status",
        &format!("deployment/{worker}"),
        "-n",
        NAMESPACE,
        "--timeout=180s",
    ]);
    if !status.status.success() {
        // Fail-closed boot means a stuck rollout hides the real cause (a failed
        // pull, a digest mismatch, an unreachable server). Dump the live cluster
        // state into the panic so CI surfaces *why* the worker never went Ready.
        let diag = worker_failure_diagnostics(&worker);
        panic!(
            "worker must reach Ready by pulling + serving the http bundle:\n\
             stdout: {}\nstderr: {}\n\n=== diagnostics ==={diag}",
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr),
        );
    }

    // Distinguish a REAL activated revision from a probes-only boot: the worker
    // logs `serving N revision(s) for env …` only when packs activated, vs
    // `… serving probes only` when no bundle attached.
    let logs = kubectl_ok(&["logs", &format!("deployment/{worker}"), "-n", NAMESPACE]);
    assert!(
        logs.contains("revision(s) for env"),
        "the worker must log the real-revision serve banner (not probes-only):\n{logs}"
    );

    // Cleanup (deletes the bundle server + its ConfigMap with the namespace).
    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}
