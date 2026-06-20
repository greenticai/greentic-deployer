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

/// ServiceAccount the `--bind` producer provisions (mirrors
/// `bootstrap::DEPLOYER_SERVICE_ACCOUNT`). Hardcoded so a rename in the producer
/// surfaces as an E2E failure — the live-cluster counterpart of the renderer's
/// offline unit-test name guard.
const DEPLOYER_SA: &str = "greentic-deployer";
/// Namespaced Role + RoleBinding the producer renders (both named `<sa>-min`).
const DEPLOYER_RBAC_NAME: &str = "greentic-deployer-min";
/// Store-aligned ref the `--bind` producer records on the env (env `local` +
/// `bootstrap::DEPLOYER_TOKEN_STORE_PATH`). Distinct from [`CREDS_REF`] (the
/// resolver-side identity-flip test stamps that one by hand); `--bind` owns the
/// `deployer_token` name end to end.
const BIND_REF: &str = "secret://local/default/_/k8s-deployer/deployer_token";

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

/// In-cluster OCI registry (`registry:2`) for the M2 OCI-transport boot-pull
/// test. Unlike the plain-HTTP bundle server, the worker pulls this over the OCI
/// client, which is HTTPS-only UNLESS the registry authority is allow-listed in
/// `GREENTIC_OCI_INSECURE_REGISTRIES` — the escape hatch greentic-start#283
/// added (`ClientProtocol::HttpsExcept`). The registry serves plain HTTP, so the
/// worker reaches it only with that allow-list set (injected post-reconcile,
/// test-only). Lives in the env's own `gtc-local` namespace for one-shot
/// cleanup, exactly like the bundle server.
const OCI_REGISTRY: &str = "gtc-oci-registry";
/// The port `registry:2` listens on (and the Service exposes).
const OCI_REGISTRY_PORT: u16 = 5000;
/// Repository + tag the fixture bundle is pushed and pulled under.
const OCI_BUNDLE_REPO: &str = "bundles/e2e";
const OCI_BUNDLE_TAG: &str = "latest";

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

/// `true` when `subject` is authorized for `auth can-i <args>`. Runs the check
/// via impersonation (`--as <subject>`) as the ambient admin, so the API server
/// evaluates the subject's effective RBAC — no token minted, no bound credential
/// handled. `kubectl auth can-i` exits 0 for "yes" and non-zero for "no", so the
/// exit code is the decision (robust to stdout warnings on cluster-scoped
/// resources). The ambient kind admin is cluster-admin and may impersonate.
fn subject_can(subject: &str, args: &[&str]) -> bool {
    let mut full = vec!["auth", "can-i"];
    full.extend_from_slice(args);
    full.extend_from_slice(&["--as", subject]);
    kubectl(&full).status.success()
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

/// Bind the K8s env and mint the bound deployer ServiceAccount via `--bind`:
/// creates the env namespace + minimal RBAC, mints the SA token, and records the
/// env's credential ref + bearer in the dev store. Returns the bootstrap verb's
/// full JSON envelope (callers read `["result"]`). Shared by the bind producer
/// test and the bound-reconcile test. The K8s bind path authenticates via the
/// ambient kubeconfig CONTEXT, not via admin material, but the bootstrap loader
/// still requires *some* material — a placeholder it never reads on this path.
fn bind_k8s_env_and_bootstrap_bound_sa(store: &Path) -> Value {
    bind_k8s_env(store, None);
    let admin_context = kubectl_ok(&["config", "current-context"]);
    let bootstrap = payload(
        store,
        "bootstrap.json",
        serde_json::json!({
            "environment_id": ENV_ID,
            "admin_profile": admin_context,
            "admin_material_inline": "ambient-kubeconfig",
            "bind": true,
        }),
    );
    op(store, Some(&bootstrap), &["credentials", "bootstrap"])
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

/// Path to the M3 fixture: a `.gtbundle` whose pack carries a real
/// `component-templates@0.6.0` WASM component plus a one-node flow that invokes
/// it (`operation: handle_message`). Unlike [`fixture_bundle`] this proves the
/// worker not only pulls + activates but *executes a real flow* on
/// `/workers/invoke` — the end-to-end check for the greentic-runner#466
/// flow-node component-id resolution fix (a dotted resolved symbol like
/// `ai.greentic.component-templates` must not be split into a bogus
/// `ai.greentic` component).
fn templates_fixture_bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/bundles/templates-bundle.gtbundle")
}

/// The in-cluster URL the worker pulls its bundle from (plain HTTP, in the env
/// namespace).
fn bundle_source_uri() -> String {
    format!(
        "http://{BUNDLE_SERVER}.{NAMESPACE}.svc.cluster.local:{BUNDLE_SERVER_PORT}/{BUNDLE_FILE}"
    )
}

/// The in-cluster authority the worker dials for the OCI pull. This is also the
/// exact string the insecure-registry allow-list must carry:
/// `oci_distribution` matches `ClientProtocol::HttpsExcept` against the pull
/// reference's `host:port`, so the env var and the `oci://` ref must agree.
fn oci_registry_authority() -> String {
    format!("{OCI_REGISTRY}.{NAMESPACE}.svc.cluster.local:{OCI_REGISTRY_PORT}")
}

/// The `oci://` ref the worker pulls its bundle from. Tag-based (no digest):
/// greentic-start's boot-pull enables tags, and the revision's pinned
/// `bundle_digest` is the integrity authority regardless of how the ref resolves.
fn oci_bundle_source_uri() -> String {
    format!(
        "oci://{}/{OCI_BUNDLE_REPO}:{OCI_BUNDLE_TAG}",
        oci_registry_authority()
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

/// Stand up an in-cluster plain-HTTP server that serves the given fixture
/// bundle at `/{BUNDLE_FILE}` and WAIT for it to be ready, so the worker can
/// pull the moment it boots. The bundle bytes ride in a ConfigMap mounted into
/// a `busybox httpd` pod's docroot. Idempotent: clears any prior run first. The
/// env namespace is created here (before `reconcile`) so the server precedes
/// the worker.
///
/// Also applies an ingress-allow NetworkPolicy for the server: the env pack's
/// `gtc-default-deny` (empty podSelector) denies ingress to EVERY pod in the
/// namespace, and modern kindnet (kindest/node v1.31+) ENFORCES NetworkPolicy,
/// so without this allow the worker's pull is dropped and the boot fails closed
/// (~127 s TCP timeout → CrashLoop). In production the bundle source is an
/// external registry, outside the namespace and unaffected by these policies;
/// only this in-cluster test fixture is caught by the env's default-deny, so the
/// allow lives here in the test, not in the production render. The worker's
/// matching egress is already granted by `gtc-allow-worker-egress`.
fn start_bundle_server(fixture: &Path) {
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
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gtc-bundle-server-allow-ingress
  namespace: {NAMESPACE}
spec:
  podSelector:
    matchLabels:
      app: {BUNDLE_SERVER}
  policyTypes:
    - Ingress
  ingress:
    - {{}}
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

/// Stand up an in-cluster `registry:2` (plain HTTP) in the env namespace, wait
/// for it to be ready, and push `fixture` into it as the OCI artifact the worker
/// pulls at boot. The OCI sibling of [`start_bundle_server`].
///
/// Mirrors the bundle server's ingress-allow NetworkPolicy reasoning: the env
/// pack's `gtc-default-deny` denies ingress to EVERY pod in the namespace and
/// modern kindnet ENFORCES NetworkPolicy, so without an allow the worker's pull
/// is dropped and the boot fails closed. In production the registry is external
/// (outside the namespace, unaffected by these policies); only this in-cluster
/// fixture is caught by the env's default-deny, so the allow lives here in the
/// test, not in the production render.
///
/// The fixture is pushed by a host-side `oras push` over a `kubectl
/// port-forward` (kubelet→pod), NOT an in-cluster pusher: a pod pushing to the
/// registry Service would be a *client* and hit the namespace's default-deny
/// EGRESS (only worker pods are egress-allowed), whereas a port-forward reaches
/// the registry pod's already-allowed ingress.
fn start_oci_registry(fixture: &Path) {
    // (Re)create the env namespace the registry shares with the worker;
    // `reset_namespace` ran first, so tolerate "already exists" defensively.
    let _ = kubectl(&["create", "namespace", NAMESPACE]);

    let manifest = format!(
        "apiVersion: apps/v1
kind: Deployment
metadata:
  name: {OCI_REGISTRY}
  namespace: {NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {OCI_REGISTRY}
  template:
    metadata:
      labels:
        app: {OCI_REGISTRY}
    spec:
      containers:
        - name: registry
          image: registry:2
          ports:
            - containerPort: {OCI_REGISTRY_PORT}
          readinessProbe:
            httpGet:
              path: /v2/
              port: {OCI_REGISTRY_PORT}
            initialDelaySeconds: 1
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: {OCI_REGISTRY}
  namespace: {NAMESPACE}
spec:
  selector:
    app: {OCI_REGISTRY}
  ports:
    - port: {OCI_REGISTRY_PORT}
      targetPort: {OCI_REGISTRY_PORT}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gtc-oci-registry-allow-ingress
  namespace: {NAMESPACE}
spec:
  podSelector:
    matchLabels:
      app: {OCI_REGISTRY}
  policyTypes:
    - Ingress
  ingress:
    - {{}}
"
    );
    kubectl_apply_stdin(&manifest);

    let status = kubectl(&[
        "rollout",
        "status",
        &format!("deployment/{OCI_REGISTRY}"),
        "-n",
        NAMESPACE,
        "--timeout=120s",
    ]);
    assert!(
        status.status.success(),
        "in-cluster OCI registry must come up before the fixture push:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );

    oci_push_fixture(fixture);
}

/// Push `fixture` to the in-cluster registry as `{OCI_BUNDLE_REPO}:{OCI_BUNDLE_TAG}`
/// via a host-side `oras push` over a port-forward. The artifact's single
/// `application/octet-stream` layer is the raw `.gtbundle`, so greentic-start's
/// OCI boot-pull writes the layer back byte-identically and the revision's
/// `bundle_digest` gate (the deployer re-hashes the pulled bytes) passes — the
/// same integrity authority the HTTP path relies on. `--plain-http` because the
/// registry terminates HTTP, matching the worker's insecure-registry allow-list.
fn oci_push_fixture(fixture: &Path) {
    let pf = PortForward::open(&format!("deployment/{OCI_REGISTRY}"), OCI_REGISTRY_PORT);
    let target = format!(
        "localhost:{}/{OCI_BUNDLE_REPO}:{OCI_BUNDLE_TAG}",
        pf.local_port
    );
    // `<path>:<mediaType>` is oras's file-ref form (see the gtpack publish
    // workflows); the path has no colon, so the trailing media type parses clean.
    // `--disable-path-validation` because `fixture` is absolute (CARGO_MANIFEST_DIR)
    // and oras otherwise refuses an absolute file ref ("absolute file path detected").
    let file_ref = format!("{}:application/octet-stream", fixture.to_string_lossy());
    let out = Command::new("oras")
        .args([
            "push",
            "--plain-http",
            "--disable-path-validation",
            &target,
            &file_ref,
        ])
        .output()
        .expect(
            "spawn oras — is it on PATH? (the CI `k8s-e2e` job installs oras-project/setup-oras)",
        );
    assert!(
        out.status.success(),
        "oras push of the fixture bundle must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Provision a revision the worker will PULL at boot: stage the given bundle
/// (so the revision records its real sha256 as `bundle_digest`) WITH the
/// `bundle_source_uri` the worker fetches, warm to Ready, and route 100 % of
/// traffic to it (boot-time pull only fires for traffic-routed revisions).
/// Returns the revision id.
fn provision_pullable_revision(
    store: &Path,
    image: &str,
    source_uri: &str,
    bundle: &Path,
) -> String {
    provision_revision(store, Some(image), Some(bundle), Some(source_uri), true)
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
    let probes: [(&str, Vec<&str>); 8] = [
        (
            "pods (wide)",
            vec!["get", "pods", "-n", NAMESPACE, "-o", "wide"],
        ),
        (
            "namespace events",
            vec!["get", "events", "-n", NAMESPACE, "--sort-by=.lastTimestamp"],
        ),
        // NetworkPolicies gate pod-to-pod reachability under an enforcing CNI
        // (kindnet on v1.31+): if the worker's pull is dropped, the missing
        // allow shows up here.
        (
            "network policies",
            vec!["get", "networkpolicies", "-n", NAMESPACE, "-o", "wide"],
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
            // Target the main `worker` container by name: `--all-containers
            // --previous` errors on the init container (which has no previous
            // instance) and aborts before reaching the crash logs we want.
            "worker logs (previous crash)",
            vec![
                "logs",
                &worker_dep,
                "-c",
                "worker",
                "-n",
                NAMESPACE,
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

    // Reconcile → applies the env-level set (12: namespace, env-store +
    // runtime-config ConfigMaps, router Deployment/Service/PDB, 6 NetworkPolicies
    // incl. the always-rendered worker- and router-egress policies) + the warmed
    // revision's worker pair (2). Verify both the verb's self-report and ground
    // truth.
    let (applied, pruned) = reconcile(store);
    assert_eq!(
        (applied, pruned),
        (14, 0),
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
    assert_eq!((applied2, pruned2), (14, 0), "reconcile is idempotent");
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
        (12, 2),
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
    assert_eq!(applied, 14, "reconcile establishes env-level + worker pair");

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
    assert_eq!(applied, 14, "reconcile applies env-level + worker pair");

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

/// Boot a worker that PULLS `fixture` over HTTP and serves it, returning the
/// worker deployment name. Shared by the M2 pull test and the M3 flow-execution
/// test — the only thing that varies is the fixture bundle.
///
/// Serves the fixture in-cluster over plain HTTP, then defers to
/// [`boot_worker_pulling_revision`] (no extra boot env: the `http://` ref rides
/// greentic-start's `ureq` path, which needs no insecure-registry allow-list).
fn boot_worker_serving_bundle(store: &Path, image: &str, fixture: &Path) -> String {
    // Serve the fixture bundle in-cluster BEFORE the worker boots (its rollout
    // waits, so the pull can't race the server coming up).
    start_bundle_server(fixture);
    boot_worker_pulling_revision(store, image, fixture, &bundle_source_uri(), &[])
}

/// Shared boot-and-serve tail for the M2/M3 pull tests: provision a pullable +
/// 100%-routed revision on `source_uri` (whatever the caller stood up), apply
/// the desired state, wait for the worker rollout to reach Ready, and assert the
/// REAL-revision serve banner. Returns the worker deployment name.
///
/// A completed rollout proves the full boot chain ran (pull → digest gate →
/// materialize → activate → serve) — the in-cluster source is the only bundle
/// source, so Ready is impossible without a successful pull. The banner assertion
/// (`serving N revision(s) for env …` rather than the probes-only line) then
/// keeps a probes-only M1 boot from masquerading as success.
///
/// `pull_env` carries boot env the production render deliberately omits — the
/// OCI path's `GREENTIC_OCI_INSECURE_REGISTRIES` allow-list. It is applied AFTER
/// reconcile (so it never enters the rendered manifests) and BEFORE the rollout
/// wait (so the rolled pods boot with it); the first pre-set-env pods fail closed
/// on the OCI pull and are superseded, and `rollout status` tracks the new
/// ReplicaSets.
///
/// It goes to BOTH the worker AND the router: both boot `start --env` and pull
/// the same routed bundle-sourced revision (each has its own egress allow —
/// `gtc-allow-{worker,router}-egress`), so an unpatched router would fail its OCI
/// pull and CrashLoop. When `pull_env` is set the router rollout is therefore a
/// success criterion too — otherwise a broken router (a dead ingress serve path)
/// would hide behind the worker-only banner. The HTTP path passes `&[]`: its
/// router already pulls over `http://`, so it is neither patched nor waited here,
/// exactly as before.
fn boot_worker_pulling_revision(
    store: &Path,
    image: &str,
    fixture: &Path,
    source_uri: &str,
    pull_env: &[(&str, &str)],
) -> String {
    let revision_id = provision_pullable_revision(store, image, source_uri, fixture);
    let worker = format!("gtc-worker-{}", revision_id.to_lowercase());

    // reconcile renders the env-store ConfigMap (carrying `environment.json`
    // with the routed revision + its `bundle_source_uri`) and the worker pair.
    let (applied, _) = reconcile(store);
    assert_eq!(applied, 14, "reconcile applies env-level + worker pair");

    if !pull_env.is_empty() {
        set_deployments_env(&[worker.as_str(), ROUTER_DEPLOY], pull_env);
    }

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
            "worker must reach Ready by pulling + serving the bundle:\n\
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

    // The router pulls the SAME revision over the SAME (insecure) transport, so
    // with `pull_env` set its rollout must complete too — boot is fail-closed, so
    // a Ready router proves its pull succeeded. Skipped for the HTTP path (empty
    // `pull_env`), whose router already pulls over `http://` and is left unwaited
    // as before.
    if !pull_env.is_empty() {
        let router_status = kubectl(&[
            "rollout",
            "status",
            &format!("deployment/{ROUTER_DEPLOY}"),
            "-n",
            NAMESPACE,
            "--timeout=180s",
        ]);
        if !router_status.status.success() {
            let router_logs = kubectl(&[
                "logs",
                &format!("deployment/{ROUTER_DEPLOY}"),
                "-n",
                NAMESPACE,
                "--all-containers",
                "--tail=150",
            ]);
            panic!(
                "router must also reach Ready by pulling the bundle over the same transport:\n\
                 stdout: {}\nstderr: {}\n\n=== router logs ===\n{}{}",
                String::from_utf8_lossy(&router_status.stdout),
                String::from_utf8_lossy(&router_status.stderr),
                String::from_utf8_lossy(&router_logs.stdout),
                String::from_utf8_lossy(&router_logs.stderr),
            );
        }
    }

    worker
}

/// `kubectl set env deployment/<a> deployment/<b> … K=V …` in the env namespace,
/// asserting success. One invocation patches every target (a single API
/// round-trip); patching a deployment rolls a fresh pod that boots with the vars.
fn set_deployments_env(deployments: &[&str], vars: &[(&str, &str)]) {
    let targets: Vec<String> = deployments
        .iter()
        .map(|d| format!("deployment/{d}"))
        .collect();
    let assignments: Vec<String> = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut args: Vec<&str> = vec!["set", "env"];
    args.extend(targets.iter().map(String::as_str));
    args.extend(["-n", NAMESPACE]);
    args.extend(assignments.iter().map(String::as_str));
    kubectl_ok(&args);
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

    boot_worker_serving_bundle(store, &image, &fixture_bundle());

    // Cleanup (deletes the bundle server + its ConfigMap with the namespace).
    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}

/// A live `kubectl port-forward` to `target` (e.g. `deployment/foo`), bound to an
/// OS-chosen local port read off kubectl's `Forwarding from 127.0.0.1:<port>`
/// line (so a lingering forward can't collide on a fixed port). Its stdout is
/// drained on a side thread for the forward's WHOLE lifetime: kubectl writes a
/// `Handling connection for <port>` line per forwarded request, and closing the
/// read end mid-run would EPIPE those writes and tear the tunnel down — fatal
/// when the caller makes several requests over one forward (a curl retry loop, an
/// `oras push`'s blob + manifest uploads). Killed on drop. Shared by
/// [`worker_invoke`] and [`oci_push_fixture`].
struct PortForward {
    child: std::process::Child,
    reader: Option<std::thread::JoinHandle<()>>,
    local_port: u16,
}

impl PortForward {
    /// Open a forward from an OS-chosen local port to `target`'s `remote_port`,
    /// blocking until kubectl announces the local port (panics on a 30 s timeout).
    fn open(target: &str, remote_port: u16) -> PortForward {
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;
        use std::sync::mpsc;

        let mut child = Command::new("kubectl")
            .args([
                "port-forward",
                target,
                &format!(":{remote_port}"),
                "-n",
                NAMESPACE,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn kubectl port-forward");

        let stdout = child.stdout.take().expect("port-forward stdout");
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut tx = Some(tx);
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(rest) = line.split("127.0.0.1:").nth(1) {
                    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                    if let Ok(port) = digits.parse::<u16>()
                        && let Some(tx) = tx.take()
                    {
                        let _ = tx.send(port);
                    }
                }
            }
        });
        match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(local_port) => PortForward {
                child,
                reader: Some(reader),
                local_port,
            },
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                panic!("kubectl port-forward never announced a local port within 30s");
            }
        }
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// POST a `HostWorkerRequest` to the worker's loopback-only `/workers/invoke`
/// via `kubectl port-forward`, returning `(http_status, response_body)`.
///
/// `/workers/invoke` trusts the caller-asserted tenant only from loopback peers
/// (`revision_serve.rs`), so `kubectl port-forward` (which tunnels through the
/// kubelet → the request reaches the pod from `127.0.0.1`) is what satisfies the
/// gate. It also sidesteps the same-node pod-to-pod CNI quirks some kind hosts
/// hit, since the hop is kubelet→pod, not pod→pod. kubectl picks the local port
/// (`:8080`) and we read it off its first `Forwarding from 127.0.0.1:<port>`
/// line, so a lingering forward can't collide on a fixed port; `curl` (on the CI
/// runner alongside kubectl) does the POST. port-forward stderr is inherited so
/// any forwarding error lands in the `--nocapture` CI log, and `curl -S`
/// surfaces transport failures the same way.
fn worker_invoke(worker: &str, payload: &Value) -> (u16, String) {
    let pf = PortForward::open(&format!("deployment/{worker}"), 8080);
    let local_port = pf.local_port;

    // The announce line can precede the pod connection by a beat, so retry the
    // POST until the tunnel carries it (`http_code` 0 == curl couldn't connect).
    let url = format!("http://127.0.0.1:{local_port}/workers/invoke");
    let body = serde_json::to_string(payload).expect("serialize HostWorkerRequest");
    let mut result = (0u16, String::new());
    let mut last_curl_err = String::new();
    for _ in 0..20 {
        let out = Command::new("curl")
            .args([
                "-sS",
                "-m",
                "20",
                "-w",
                "\n%{http_code}",
                "-X",
                "POST",
                &url,
                "-H",
                "content-type: application/json",
                "-d",
                &body,
            ])
            .output()
            .expect("spawn curl");
        last_curl_err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let raw = String::from_utf8_lossy(&out.stdout);
        if let Some((resp_body, code)) = raw.rsplit_once('\n')
            && let Ok(status) = code.trim().parse::<u16>()
        {
            result = (status, resp_body.to_string());
            if status != 0 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    drop(pf);
    // Make a transport failure actionable instead of a bare "body: ".
    if result.0 == 0 && result.1.is_empty() {
        result.1 = format!(
            "(no HTTP response via port-forward 127.0.0.1:{local_port}; last curl stderr: {last_curl_err})"
        );
    }
    result
}

/// M3: the worker not only pulls + activates a real revision but EXECUTES a flow
/// on it. The fixture bundle carries a real `component-templates@0.6.0` WASM
/// component and a one-node flow that invokes it; a POST to the loopback-only
/// `/workers/invoke` must run that flow and echo the templated message — the
/// end-to-end proof of the greentic-runner#466 flow-node component-id resolution
/// fix (before it, the dotted resolved symbol `ai.greentic.component-templates`
/// was split into a bogus `ai.greentic` component and execution failed with
/// "component '…' not found in pack").
///
/// Builds on `worker_pulls_http_bundle_and_serves_the_real_revision`: same
/// pull-over-HTTP boot and the same Ready + real-revision-banner gates, then the
/// extra invoke hop. Gated on `GREENTIC_K8S_SERVING_IMAGE` (a `:develop` worker
/// image new enough to carry the #466 fix) on top of `GREENTIC_K8S_E2E`.
#[test]
fn worker_executes_a_real_flow_over_workers_invoke() {
    if !armed() {
        return;
    }
    let Some(image) = serving_image() else {
        return;
    };
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    let worker = boot_worker_serving_bundle(store, &image, &templates_fixture_bundle());

    // The M3 assertion: run the flow. Its single node invokes
    // `ai.greentic.component-templates` (a dotted resolved symbol) with
    // `operation: handle_message`; #466 keeps that symbol intact instead of
    // splitting it, so execution succeeds and the component echoes its input.
    let (http_status, body) = worker_invoke(
        &worker,
        &serde_json::json!({
            "version": "1.0.0",
            "tenant": {
                "env": ENV_ID,
                "tenant": "default",
                "tenant_id": "default",
                "attempt": 0
            },
            "worker_id": "templates-bundle",
            "payload": {"text": "m3"}
        }),
    );
    if http_status != 200 {
        // Dump live pod/log state so a non-200 (or no-response) is diagnosable
        // from the CI log rather than a bare status + body.
        let diag = worker_failure_diagnostics(&worker);
        panic!(
            "POST /workers/invoke must return 200, got {http_status}; body: {body}\n\n\
             === diagnostics ==={diag}"
        );
    }
    assert!(
        body.contains("component-templates::handle_message =>"),
        "the flow must execute and return the templates component's echo \
         (the greentic-runner#466 fix); body: {body}"
    );
    // Prove the flow GRAPH ran, not just that the component is reachable. The
    // `render` node feeds the component a literal input ("M3 hello from
    // templates"); the runtime echoes that node input back inside the activity
    // payload as a byte sequence, whose prefix `34,77,51,32,104,101,108,108,111`
    // is `"M3 hello`. Its presence means the runner loaded the flow, resolved
    // the dotted `ai.greentic.component-templates` symbol (the #466 fix), and
    // ran the node with its configured input — a canned or direct-component
    // success could clear the prefix check above but not this. (The request
    // `payload` is not echoed: the node input is flow-configured, not
    // request-derived, so the fixture's node input is the value to require.)
    assert!(
        body.contains("34,77,51,32,104,101,108,108,111"),
        "the flow's render-node input (bytes of \"M3 hello...\") must appear in \
         the echoed activity payload, proving graph execution rather than only \
         component reachability; body: {body}"
    );
    assert!(
        !body.contains("not found in pack"),
        "flow execution must not fail with a component-resolution error; body: {body}"
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

/// M2 OCI-transport sibling of
/// [`worker_pulls_http_bundle_and_serves_the_real_revision`]: the worker pulls
/// its bundle from an in-cluster **OCI registry** over greentic-start's OCI
/// client (not the plain-HTTP `ureq` path), proving the `oci://` boot-pull end to
/// end.
///
/// The registry serves plain HTTP, and the OCI client is HTTPS-only by default,
/// so the pull succeeds ONLY because the worker is launched with
/// `GREENTIC_OCI_INSECURE_REGISTRIES` listing the registry authority — the escape
/// hatch greentic-start#283 added (`ClientProtocol::HttpsExcept`). That env is
/// injected post-reconcile (test-only — `set_deployment_env`, never the
/// production render), so production OCI pulls stay HTTPS-only. The `#283` fix
/// also scopes the hatch to the digest-gated boot-pull, which this test's pinned
/// `:develop` serving image must carry.
///
/// Same proof structure as the HTTP test: the registry rollout, the worker's
/// `/healthz` probe, and `reconcile`'s readiness are all gated, so a completed
/// worker rollout means the worker pulled over OCI, digest-verified (the pulled
/// layer's sha256 must equal the sha256 the deployer pinned when it staged the
/// same fixture), materialized, and activated; the real-revision serve banner
/// then rules out a probes-only boot.
///
/// Gated on `GREENTIC_K8S_SERVING_IMAGE` (a `:develop` image carrying the #283
/// hatch) on top of `GREENTIC_K8S_E2E`; self-skips when unset, like the other
/// serving tests. Needs `oras` on PATH (the CI `k8s-e2e` job installs it) to load
/// the fixture into the registry.
#[test]
fn worker_pulls_oci_bundle_and_serves_the_real_revision() {
    if !armed() {
        return;
    }
    let Some(image) = serving_image() else {
        return;
    };
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    // Stand up the registry + push the fixture BEFORE the worker boots (the
    // worker's rollout waits, so the pull can't race the registry coming up).
    let fixture = fixture_bundle();
    start_oci_registry(&fixture);
    let authority = oci_registry_authority();
    boot_worker_pulling_revision(
        store,
        &image,
        &fixture,
        &oci_bundle_source_uri(),
        &[("GREENTIC_OCI_INSECURE_REGISTRIES", &authority)],
    );

    // Cleanup (deletes the registry + its objects with the namespace).
    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}

/// `op credentials bootstrap --bind` against a live cluster: the deployer
/// connects AS THE ADMIN (the ambient kubeconfig context), applies the rendered
/// minimum-privilege RBAC (Namespace + ServiceAccount + Role + RoleBinding),
/// mints the ServiceAccount's token via the TokenRequest subresource, writes it
/// into the env dev store, and records `credentials_ref` + the granted expiry on
/// the env — the PRODUCER side of the bound-credential contract.
///
/// Inverse-complete of
/// [`credentials_requirements_reflects_the_bound_serviceaccount_identity`]: that
/// test hand-rolls a cluster-admin SA to prove the *resolver* honours a bound
/// token; this one drives the *producer* and proves the RBAC it renders is
/// self-consistent — the minted token, bound ONLY to the rendered minimal Role,
/// passes the very `requirements` SSAR sweep that probes `VALIDATED_K8S_OPERATIONS`.
/// No env var is seeded, so the only token source is what `--bind` wrote to the
/// dev store; a `pass` therefore exercises the full produce → persist → resolve →
/// authorize loop against a real API server (TokenRequest + server-side RBAC
/// apply — the mock unit tests drive a `tower-test` mock and never open a socket).
///
/// Scoped deliberately to `requirements` (namespaced ops), NOT `reconcile`: the
/// rendered Role is namespaced, so the bound SA is sufficient for the validated
/// op sweep but cannot yet drive `reconcile` (which re-applies the cluster-scoped
/// Namespace) — the known namespace-apply-trust gap, tracked as a separate slice.
///
/// Touches no pod-to-pod networking (only kubectl→API-server and the deployer's
/// own apply/mint/SSAR calls), so unlike the bundle-pull tests it is not blocked
/// by an unenforced-CNI / same-node-routing environment. Mutates `gtc-local`
/// (bind creates the namespace + RBAC), so it resets the namespace up front and
/// tears it down after, staying order-independent with the reconcile /
/// apply-revision tests that share it.
#[test]
fn bind_provisions_rbac_and_resolves_the_bound_identity() {
    if !armed() {
        return;
    }
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    // Bind the K8s env (namespace → gtc-local) + mint the bound deployer SA via
    // `--bind`. No namespace pre-create is needed (unlike the bundle-server
    // tests): the rendered RBAC pack carries the Namespace object and the admin
    // applies it as part of `--bind`.
    let out = bind_k8s_env_and_bootstrap_bound_sa(store);
    let result = &out["result"];

    // 1. The verb self-reports a bound credential, the store-aligned ref, and a
    //    (cluster-clamped) expiry read back from the granted TokenRequest.
    assert_eq!(
        result["bound"], true,
        "bootstrap --bind reports a bound credential: {result}"
    );
    assert_eq!(
        result["credentials_ref"], BIND_REF,
        "the recorded ref is the store-aligned deployer-token path: {result}"
    );
    assert!(
        result["expires_at"].as_str().is_some_and(|s| !s.is_empty()),
        "the minted token carries the granted (cluster-clamped) expiry: {result}"
    );

    // 2. Ground truth: the rendered RBAC objects exist, scoped to the namespace
    //    the producer targeted. The Namespace is the only cluster-scoped object;
    //    the Role/RoleBinding confine the deployer to it.
    assert!(
        object_exists("namespace", NAMESPACE, None),
        "bind created the env namespace"
    );
    assert!(
        object_exists("serviceaccount", DEPLOYER_SA, Some(NAMESPACE)),
        "bind created the deployer ServiceAccount"
    );
    assert!(
        object_exists("role", DEPLOYER_RBAC_NAME, Some(NAMESPACE)),
        "bind created the minimal Role"
    );
    assert!(
        object_exists("rolebinding", DEPLOYER_RBAC_NAME, Some(NAMESPACE)),
        "bind created the RoleBinding"
    );

    // 3. The env persisted the bound ref — read straight back through the store,
    //    independent of the verb's self-report.
    use greentic_deploy_spec::{EnvId, SecretRef};
    use greentic_deployer::environment::{EnvironmentStore, LocalFsStore};
    let env = LocalFsStore::new(store)
        .load(&EnvId::try_from(ENV_ID).expect("env id"))
        .expect("reload env after bind");
    assert_eq!(
        env.credentials_ref.as_ref().map(SecretRef::as_str),
        Some(BIND_REF),
        "the producer persisted credentials_ref on the env"
    );

    // 4. The minted token resolves from the dev store (NO env var seeded) and
    //    PASSES the validated-ops sweep AS the bound SA. The rendered minimal
    //    Role grants exactly `VALIDATED_K8S_OPERATIONS`, so every SSAR is
    //    Allowed — the live proof the produced RBAC is self-consistent with the
    //    probe (and that the dev-store write/read line up cross-process).
    let req = payload(
        store,
        "creds_req.json",
        serde_json::json!({"environment_id": ENV_ID}),
    );
    let req_out = op(store, Some(&req), &["credentials", "requirements"]);
    let req_result = &req_out["result"];
    assert_eq!(
        req_result["result"], "pass",
        "the bound SA is allowed every validated op via the rendered Role: {req_result}"
    );
    assert_eq!(
        req_result["missing_capabilities"].as_array().map(Vec::len),
        Some(0),
        "no validated capability is missing for the bound SA: {req_result}"
    );

    // 5. Minimum-privilege confinement — the NEGATIVE complement to step 4. The
    //    requirements sweep only proves the needed verbs are PRESENT, so an
    //    over-grant regression (a ClusterRoleBinding, cluster-admin, a wider
    //    Role) would pass it while quietly breaking the security boundary. These
    //    denials make "bound only to the rendered minimal Role" a checked claim
    //    rather than a doc comment. Impersonating the SA evaluates its effective
    //    RBAC, so it also catches an unexpected ClusterRole/CRB behaviorally
    //    (any of those would flip a denial below to allowed).
    let sa_subject = format!("system:serviceaccount:{NAMESPACE}:{DEPLOYER_SA}");
    // Positive control: the in-namespace verb the Role grants is allowed — proves
    // the impersonation path resolves the binding, so the denials below are real
    // denials, not a broken `--as`.
    assert!(
        subject_can(&sa_subject, &["get", "deployments", "-n", NAMESPACE]),
        "the bound SA can get deployments in its own namespace (Role grant)"
    );
    // Cluster-scoped Namespace op is DENIED — a namespaced Role cannot reach
    // cluster scope. This is exactly the reconcile-time gap (reconcile re-applies
    // the cluster-scoped Namespace, which this SA cannot), so a regression that
    // granted it (e.g. a cluster-admin binding) would flip this assertion.
    assert!(
        !subject_can(&sa_subject, &["create", "namespaces"]),
        "the bound SA must NOT create cluster-scoped namespaces (over-grant guard)"
    );
    // Cross-namespace: the RoleBinding confines the grant to gtc-local, so the
    // same verb in another namespace is denied. A cluster-wide binding regression
    // would flip this.
    assert!(
        !subject_can(&sa_subject, &["get", "deployments", "-n", "default"]),
        "the bound SA must NOT get deployments outside its namespace (confinement)"
    );

    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}

/// The companion to [`bind_provisions_rbac_and_resolves_the_bound_identity`]:
/// having minted the bound ServiceAccount, prove it can actually drive
/// `op env reconcile` — the production blocker for `--bind` on Zain. Before this
/// slice the rendered env-level set led with the cluster-scoped `Namespace`,
/// which a namespaced Role cannot apply, so a bound reconcile 403'd on its very
/// first object: the bound SA passed `requirements` yet could not reconcile.
///
/// `reconcile` now drops the Namespace from the applied set for a bound identity
/// (`manage_namespace == bound_token.is_none()`). The `--bind` bootstrap already
/// created the namespace, and the bound Role grants every namespaced verb
/// (`VALIDATED_K8S_OPERATIONS`), so the rest applies cleanly. The proof is that
/// the verb SUCCEEDS as the bound SA — `op` asserts a zero exit, so a 403 would
/// panic this call — and self-reports `identity == "bound"` with no Namespace in
/// the applied set.
///
/// Like the bind test this touches only kubectl→API-server and the deployer's
/// own apply calls (no pod-to-pod networking), so it runs on any kind host,
/// including ones whose CNI breaks same-node pod-to-pod. Shares `gtc-local`, so
/// it resets up front and tears down after.
#[test]
fn bound_identity_drives_reconcile_without_the_cluster_scoped_namespace() {
    if !armed() {
        return;
    }
    reset_namespace();
    let store = tempfile::tempdir().expect("tempdir");
    let store = store.path();

    // Mint the bound ServiceAccount via `--bind` (creates the namespace + minimal
    // RBAC and records the env's credential ref + bearer in the dev store). After
    // this, `op env reconcile` resolves that bearer and connects AS the bound SA
    // instead of the ambient admin.
    let boot = bind_k8s_env_and_bootstrap_bound_sa(store);
    assert_eq!(
        boot["result"]["bound"], true,
        "precondition: --bind minted the bound SA: {}",
        boot["result"]
    );

    // The payoff: reconcile AS the bound SA. `op` asserts a zero exit, so whether
    // this call panics is itself the gate — before the fix the bound Role's
    // missing cluster-scoped Namespace verb 403'd the first apply.
    let out = op(store, None, &["env", "reconcile", ENV_ID]);
    let result = &out["result"];

    // Ran as the bound ServiceAccount, not the ambient admin.
    assert_eq!(
        result["identity"], "bound",
        "reconcile resolved the env's bound credential and ran as the SA: {result}"
    );

    // The cluster-scoped Namespace is absent from the applied set — the one
    // object the bound Role cannot touch was dropped; everything else applied.
    let applied = result["applied"].as_array().expect("applied is an array");
    assert!(
        !applied
            .iter()
            .any(|o| o["kind"].as_str() == Some("Namespace")),
        "a bound reconcile must not apply the cluster-scoped Namespace: {result}"
    );
    // ...but the namespaced env-level objects DID apply: the router Deployment is
    // in the applied set and present on the cluster, proving the bound SA drove a
    // real apply rather than no-oping.
    assert!(
        applied
            .iter()
            .any(|o| o["kind"].as_str() == Some("Deployment")),
        "the bound reconcile applied the namespaced router Deployment: {result}"
    );
    assert!(
        object_exists("deployment", ROUTER_DEPLOY, Some(NAMESPACE)),
        "the router Deployment the bound SA applied is on the cluster"
    );
    // The namespace `--bind` created survives: reconcile never deletes env-level
    // objects, and a bound reconcile never re-applies it either.
    assert!(
        object_exists("namespace", NAMESPACE, None),
        "the bootstrap-created namespace is intact after a bound reconcile"
    );

    let _ = kubectl(&[
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ]);
}
