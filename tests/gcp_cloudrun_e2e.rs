//! Live-project E2E for the GCP Cloud Run deployer env-pack (plan item 7).
//!
//! **Provenance: first executed against a real GCP project on 2026-07-17
//! (`europe-west1`) and PASSED** — deploy → boot from the staged seed → bundle
//! pulled from public GHCR → 50/50 split → 100 % shift → archive → teardown, in
//! ~95 s, leaving nothing behind. Unlike `aws_ecs_e2e` (still never run against
//! a live account), the assertions below are confirmed, not merely plausible.
//! That first run immediately earned its keep: the deploy was flawless and the
//! probe 404'd, because Cloud Run swallows `/healthz` — see [`LIVENESS_PATH`].
//!
//! The Cloud Run deployer's decision logic — params parsing, the integer-percent
//! traffic conversion, secret ownership, the conformance suite — is unit-tested
//! against the in-memory `InMemoryCloudRun` fake, which opens no sockets. The
//! thin `.send()` glue that drives the *real* google-cloud-rust clients
//! (`CreateService` / `UpdateService` with the etag read-modify-write / the LRO
//! readiness poll / `CreateSecret` / `AddSecretVersion` / the `secretAccessor`
//! and invoker IAM RMWs / `DeleteService` / `DeleteSecret`) therefore has zero
//! end-to-end coverage. This test closes that gap by driving a full lifecycle —
//! `env up → serves → warm B → 50/50 split → SHIFT 100 % to B → archive A →
//! destroy` — through the real CLI verbs against a real GCP project.
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! What only THIS test can prove:
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//!   - **The workload actually boots from the staged seed AND does its job.** The
//!     secret-staging chain (environment.json + the dev-store rendered as
//!     version-pinned Secret Manager volumes, `GREENTIC_SEED_DIR` pointing
//!     greentic-start's boot-copy at them) is asserted only against the fake
//!     everywhere else. Proven here in two steps, deliberately: a 200 from the
//!     liveness path says the container came up, but that is a STATIC route which
//!     answers just as happily from a runtime that loaded nothing — so `/status`
//!     (`greentic.status.v1`) is the real assertion, because its
//!     `bundles_active` / `revisions_active` counts are non-zero only once the
//!     seed parsed, the bundle OCI-pulled, and its packs loaded.
//!   - **The integer-percent split (plan D1) is accepted by the real API.**
//!     Cloud Run takes whole percents summing to exactly 100; the bps→percent
//!     conversion is pure-tested, but only a live `UpdateService` proves the
//!     shape it produces is one the API takes.
//!   - **Teardown reclaims what it created (plan D6 + the H1 ownership check).**
//!     `op env destroy` runs the provider teardown inside the store's destroy
//!     flock; the delete glue and the owner-stamp classification have never run
//!     against real Secret Manager.
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Why this is gated and operator-run (NOT in CI):
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Like the AWS-ECS E2E (`aws_ecs_e2e`) and unlike the K8s E2E — which stands up
//! a free `kind` cluster inside the CI `k8s-e2e` job — Cloud Run has no free CI
//! substrate: it is a hosted Google service with no local emulator worth
//! asserting against, and CI holds no GCP credentials. This test is therefore
//! **manual / operator-run**: armed only when [`E2E_GATE`]`=1` is set, and it
//! bills a real project. It is never in the default `cargo test` matrix.
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Operator pre-provisioning (the test does NOT create these):
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//!   - A GCP project with **billing enabled** (`GTC_GCP_E2E_PROJECT`).
//!   - The `run` + `secretmanager` APIs enabled, a **runtime service account**,
//!     and the deployer principal's own permissions. `gtc op credentials
//!     bootstrap` renders a Terraform pack that creates exactly these with the
//!     minimum-privilege verb set the deployer uses (see
//!     `VALIDATED_GCP_PERMISSIONS`) — apply it first. The runtime SA defaults to
//!     `gtc-<env-id>-runtime@<project>.iam.gserviceaccount.com`; override with
//!     `GTC_GCP_E2E_SERVICE_ACCOUNT`.
//!   - Nothing else. The worker image and the bundle are pulled straight from
//!     public GHCR (plan D3's default — no Artifact Registry remote repo, which
//!     is what keeps idle storage cost at zero).
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Identity:
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! The deployer runs as the **ambient** ADC chain (`GOOGLE_APPLICATION_
//! CREDENTIALS`, `gcloud auth application-default login`, or the metadata
//! server) unless the env binds a deployer session. Point the host's ADC at the
//! same project `GTC_GCP_E2E_PROJECT` names.
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Env-var contract (read once the gate is set; a missing REQUIRED var while
//! armed is a hard failure — you opted in, so you must supply the scope):
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//!   REQUIRED:
//!     GTC_GCP_E2E_PROJECT            GCP project id (billing enabled)
//!     GTC_GCP_E2E_REGION             e.g. europe-west1
//!   OPTIONAL:
//!     GTC_GCP_E2E_SERVICE_ACCOUNT    runtime SA email
//!                                    (default: gtc-<env>-runtime@<project>…)
//!     GTC_GCP_E2E_SECRET_PREFIX      Secret Manager name prefix. Default: a
//!                                    per-run unique prefix — do NOT pin it to a
//!                                    constant for two concurrent runs (see
//!                                    `run_secret_prefix`).
//!     GTC_GCP_E2E_AR_REPO            An ALREADY-PROVISIONED Artifact Registry
//!                                    remote repo id to pull the image through.
//!                                    Setting it does not create one. Default:
//!                                    unset = direct public GHCR (plan D3).
//!     GTC_GCP_E2E_RUNTIME_IMAGE_TAG  worker image tag (default: `develop`)
//!     GTC_GCP_E2E_RUNTIME_IMAGE_DIGEST  pin the worker image by digest
//!     GTC_GCP_E2E_BUNDLE_URI         `oci://…` bundle (default: the public
//!                                    webchat-bot demo bundle)
//!     GTC_GCP_E2E_BUNDLE_DIGEST      its `sha256:…` digest — MUST be set
//!                                    together with GTC_GCP_E2E_BUNDLE_URI
//!
//! Run it (a real project is billed; the gate must be `=1` exactly — `0`/unset
//! skip):
//!   GREENTIC_GCP_E2E=1 GTC_GCP_E2E_PROJECT=my-proj GTC_GCP_E2E_REGION=europe-west1 \
//!     cargo test --test gcp_cloudrun_e2e -- --nocapture
//!
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! Cleanup:
//! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//! On the happy path the final `op env destroy` reclaims everything the deployer
//! created (Services + the staged secrets) — unlike the AWS E2E, which cannot
//! archive its sole routed revision. That destroy is also the only live coverage
//! of the teardown path, so it is an ASSERTION, not just hygiene.
//!
//! A mid-run FAILURE leaves the Service and its secrets behind, so the run's
//! store is **deliberately persisted** (not a self-deleting `TempDir`) and the
//! reclaim command is printed BEFORE any resource exists. Re-run it by hand:
//!   greentic-deployer op --store-root <printed root> env destroy local --confirm
//! and delete the store dir afterwards. It is removed automatically only after a
//! successful teardown. Left alone, a leaked Service scales to zero and bills no
//! compute; the staged secrets bill the (tiny) Secret Manager active-version
//! footprint until deleted.
//!
//! (No in-test Drop guard on purpose: running cloud teardown while unwinding
//! would double-fault the panic and hide the real failure.)
//!
//! **A stuck provider call can hang this test.** `Command::output()` has no
//! deadline, and while the warm-readiness poll is bounded (300 s, see
//! `GREENTIC_GCP_WARM_READY_TIMEOUT_SECS`), the underlying create/update LRO
//! poll is not. A degraded Cloud Run API can therefore stall a run while
//! resources are live. This is operator-run in the foreground, so Ctrl+C is the
//! timeout — and because the store is persisted, the printed reclaim command
//! still works afterwards. (Bounding the LRO itself belongs in `real_target.rs`,
//! not here: the same unbounded poll would hang a real `op env up`.)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

/// Env that arms the test. Unset (the default in `cargo test`) → skip.
const E2E_GATE: &str = "GREENTIC_GCP_E2E";

/// The Cloud Run deployer env-pack the env binds to its `deployer` slot. The
/// `@1.0.0` pin resolves against `GcpCloudRunDeployerHandler::VERSION_REQ`
/// (`>=1.0.0-dev, <2.0.0`).
const DESCRIPTOR: &str = "greentic.deployer.gcp-cloudrun@1.0.0";

/// `local` is the env id the `LocalFsStore` CLI accepts without RBAC.
const ENV_ID: &str = "local";

/// Public demo bundle, pulled straight from GHCR by the *worker* at boot (plan
/// D3's default path — no Artifact Registry). Anonymously pullable, so the
/// runtime SA needs no registry credential. Digest-pinned: `:v1` is a moving tag
/// and Cloud Run caches tags for up to ~1h, so an unpinned ref could boot a
/// stale bundle (plan Risks).
const DEFAULT_BUNDLE_URI: &str = "oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:v1";
const DEFAULT_BUNDLE_DIGEST: &str =
    "sha256:4f560749ec709e75b6063cdeccab15ed5074c2e60bc5f772c2d3b7d4bd992363";

/// The liveness path to probe. **`/readyz`, deliberately NOT `/healthz`.**
///
/// Verified live 2026-07-17 against real Cloud Run: `GET /healthz` on a `*.run.app`
/// URL returns Google's own branded HTML 404 and **never reaches the container** —
/// no `server: Google Frontend` header, a `referrer-policy: no-referrer`, i.e. the
/// Google frontend answers it. Its siblings `/health`, `/livez`, `/readyz`,
/// `/status` (and any unknown path, which greentic-start 405s) all arrive
/// normally. So `/healthz` is swallowed somewhere in Google's infrastructure
/// before Cloud Run routes it.
///
/// Do NOT "fix" this back to `/healthz` because the k8s path uses it — that probe
/// runs inside the cluster and never crosses a Google frontend. This is a Cloud
/// Run-only hazard, and the first live run of this test is what found it: the
/// deploy was perfect and the probe 404'd.
///
/// Harmless for the deployer itself, which configures no HTTP probe (Cloud Run's
/// default TCP check on `$PORT` marks the revision Ready).
const LIVENESS_PATH: &str = "/readyz";

/// Bound on the liveness probe: a first request against a just-deployed Service
/// races a cold start (Cloud Run reports Ready when the container binds `$PORT`,
/// but the very first request can still land mid-start).
const LIVENESS_ATTEMPTS: u32 = 10;
const LIVENESS_BACKOFF: Duration = Duration::from_secs(3);

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

/// Exactly `Some("1")` arms the test; unset, `0`, `false`, or any other value
/// skips. Stricter than the K8s E2E's mere-presence check ON PURPOSE: this path
/// BILLS A REAL PROJECT, so `GREENTIC_GCP_E2E=0` (a common "disable it" reflex)
/// must NOT arm it. Pure (takes the value) so the gate is unit-tested without
/// touching the process env.
fn gate_armed(value: Option<&str>) -> bool {
    value == Some("1")
}

/// `true` when the test is armed (see [`gate_armed`]). Unset / non-`1` → the
/// caller returns early.
fn armed() -> bool {
    if gate_armed(std::env::var(E2E_GATE).ok().as_deref()) {
        return true;
    }
    eprintln!(
        "skipping live-project Cloud Run E2E: set {E2E_GATE}=1 exactly (bills a real project; \
         needs the GTC_GCP_E2E_* scope vars — see the module doc)"
    );
    false
}

/// A required scope var. Missing while armed is a hard failure with a precise
/// message, so an operator who sets the gate but forgets a var gets the exact
/// var name, not an opaque GCP error three calls later.
fn required_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{E2E_GATE} is set but required scope var {name} is missing — see the module doc")
    })
}

/// Whether `url` is a Cloud Run-issued service URL. Cloud Run mints
/// `https://<service>-<hash>.<region>.run.app` (and `….a.run.app`); asserting
/// the shape — not just "some string came back" — is what catches the deployer
/// echoing back a request field instead of the URL the API actually assigned.
/// Pure so it is unit-tested without a project.
fn is_run_app_url(url: &str) -> bool {
    url.strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|host| host.ends_with(".run.app") && !host.starts_with('.'))
}

/// Run `op … <args>` (optionally with `--answers <file>`) against `store`,
/// assert success, and return the parsed JSON envelope. Mirrors the AWS/K8s E2E
/// `op()` — the child inherits this process's env (the ambient ADC chain).
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

/// The bundle the worker OCI-pulls at boot. Both vars must move together: a
/// custom URI with the default digest would fail the integrity check at boot
/// with a confusing mismatch, so require the pair rather than let them drift.
fn bundle_ref() -> (String, String) {
    match (
        std::env::var("GTC_GCP_E2E_BUNDLE_URI").ok(),
        std::env::var("GTC_GCP_E2E_BUNDLE_DIGEST").ok(),
    ) {
        (None, None) => (
            DEFAULT_BUNDLE_URI.to_string(),
            DEFAULT_BUNDLE_DIGEST.to_string(),
        ),
        (Some(uri), Some(digest)) => (uri, digest),
        _ => panic!(
            "GTC_GCP_E2E_BUNDLE_URI and GTC_GCP_E2E_BUNDLE_DIGEST must be set together \
             (a custom bundle with the default digest fails the boot integrity check)"
        ),
    }
}

/// Assemble the Cloud Run deployer answers from the scope vars. Optional keys are
/// emitted only when their var is set, so the deployer's own defaults (runtime
/// SA formula, `secret_prefix`, direct-GHCR image path) stay in force —
/// exercising the SAME defaults a real operator gets rather than a fully
/// pinned-down fixture.
fn cloudrun_answers(secret_prefix: &str) -> Value {
    let mut answers = json!({
        "project": required_var("GTC_GCP_E2E_PROJECT"),
        "region": required_var("GTC_GCP_E2E_REGION"),
        // The URL must be reachable without a token for the liveness/status
        // probes (plan D12: Cloud Run is private by default).
        "access_mode": "public",
        "secret_prefix": secret_prefix,
    });
    let obj = answers.as_object_mut().expect("answers object");
    for (var, key) in [
        ("GTC_GCP_E2E_SERVICE_ACCOUNT", "service_account"),
        ("GTC_GCP_E2E_AR_REPO", "ar_repo"),
        ("GTC_GCP_E2E_RUNTIME_IMAGE_TAG", "runtime_image_tag"),
        ("GTC_GCP_E2E_RUNTIME_IMAGE_DIGEST", "runtime_image_digest"),
    ] {
        if let Ok(value) = std::env::var(var) {
            obj.insert(key.to_string(), json!(value));
        }
    }
    answers
}

/// A Secret Manager name prefix unique to THIS run.
///
/// Load-bearing for isolation, not cosmetics. The env id is fixed at `local`, so
/// the deployer's default prefix would be `gtc-local` for every run in the
/// project — and the H1 owner stamp is a function of the env id ALONE, so every
/// run would also stamp an identical owner. Two runs would then share
/// `gtc-local-environment`, each classify it as `Ours`, and the first to finish
/// would delete the secret the other's live Service still mounts, breaking it on
/// its next cold start. (This is the tracked `[H1-install]` gap — two installs of
/// one env name in one project — and a concurrent E2E is exactly that case.)
/// Distinct prefixes give distinct secrets, so the shared stamp stops mattering.
///
/// Services are already ULID-named and the runtime SA is deliberately shared, so
/// the secret is the only colliding resource.
///
/// `GTC_GCP_E2E_SECRET_PREFIX` overrides it — pointing two runs at one prefix is
/// then the operator's explicit choice.
fn run_secret_prefix() -> String {
    if let Ok(explicit) = std::env::var("GTC_GCP_E2E_SECRET_PREFIX") {
        return explicit;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after the epoch")
        .as_nanos();
    unique_secret_prefix(std::process::id(), nanos)
}

/// The prefix formula, pure (pid + clock passed in) so the properties that make
/// it safe are unit-tested without a project — see [`run_secret_prefix`] for why
/// uniqueness is load-bearing rather than cosmetic.
fn unique_secret_prefix(pid: u32, nanos: u128) -> String {
    // Secret Manager names are `[a-zA-Z0-9_-]{1,255}`; the `gtc-` lead keeps it
    // starting with a letter.
    format!("gtc-e2e-{pid}-{nanos}")
}

/// The `greentic.env-manifest.v1` document `op env up` consumes — the same
/// one-file shape the demo and `gtc start cloudrun` use, so this test covers the
/// documented path rather than a test-only assembly of granular verbs.
fn env_manifest(bundle_uri: &str, bundle_digest: &str, secret_prefix: &str) -> Value {
    json!({
        "schema": "greentic.env-manifest.v1",
        "environment": {"id": ENV_ID, "name": "cloudrun-e2e"},
        "trust_root": "bootstrap",
        "packs": [
            {
                "slot": "deployer",
                "kind": DESCRIPTOR,
                "pack_ref": "builtin",
                "answers": cloudrun_answers(secret_prefix),
            },
            {"slot": "secrets", "kind": "greentic.secrets.dev-store@1.0.0", "pack_ref": "builtin"},
        ],
        "bundles": [
            {
                "bundle_id": "cloudrun-e2e",
                "bundle_source_uri": bundle_uri,
                "bundle_digest": bundle_digest,
                "route_binding": {"path_prefixes": ["/"]},
            }
        ],
    })
}

/// GET `<url>`[`LIVENESS_PATH`] until it answers 200 or the attempts run out.
/// Returns the last status seen. greentic-start serves it as a static route, so a
/// 200 says the runtime process is up and serving — and nothing more (see
/// [`probe_status`] for the assertion that actually proves the deploy worked).
///
/// Retried because the first request after a deploy races a cold start.
fn probe_liveness(url: &str) -> Result<(), String> {
    let endpoint = format!("{}{LIVENESS_PATH}", url.trim_end_matches('/'));
    let mut last = String::from("never attempted");
    for attempt in 1..=LIVENESS_ATTEMPTS {
        match http().get(&endpoint).send() {
            Ok(resp) if resp.status().is_success() => {
                eprintln!(
                    "[gcp-e2e] {endpoint} → {} (attempt {attempt})",
                    resp.status()
                );
                return Ok(());
            }
            Ok(resp) => last = format!("HTTP {}", resp.status()),
            Err(e) => last = format!("transport error: {e}"),
        }
        eprintln!(
            "[gcp-e2e] {endpoint} not ready yet ({last}); attempt {attempt}/{LIVENESS_ATTEMPTS}"
        );
        std::thread::sleep(LIVENESS_BACKOFF);
    }
    Err(last)
}

/// GET `<url>/status` → greentic-start's `greentic.status.v1` diagnostics.
///
/// This — not the liveness probe — is what proves the deploy actually WORKED.
/// [`LIVENESS_PATH`] is a static route that answers 200 from a runtime with zero
/// bundles loaded, so on its own it only shows the container booted. `/status`
/// reports `bundles_active` / `revisions_active`, which are non-zero only once
/// the seeded environment.json resolved AND the bundle OCI-pulled AND its packs
/// loaded — the whole D2/D6 chain this deployer exists to set up.
///
/// (Learned the hard way on the webchat demo: a 200 from the static page that
/// HOSTS a feature is not evidence the feature works.)
///
/// **Cross-repo contract.** `schema` / `env_id` / `bundles_active` /
/// `revisions_active` are emitted by greentic-start, NOT by this repo — see its
/// `try_probe_response` in `src/revision_serve.rs`. Nothing compiles these field
/// names together, so a rename there breaks this assertion at runtime only, and
/// only when armed. This comment is the breadcrumb: if you are here because
/// `bundles_active` went missing, the rename is in greentic-start.
fn probe_status(url: &str) -> Value {
    let endpoint = format!("{}/status", url.trim_end_matches('/'));
    let resp = http()
        .get(&endpoint)
        .send()
        .unwrap_or_else(|e| panic!("GET {endpoint} failed: {e}"));
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    assert!(status.is_success(), "GET {endpoint} → {status}: {body}");
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("{endpoint} is not json ({e}): {body}"))
}

/// One HTTP client shape for every probe. The timeout is generous: a scale-to-
/// zero Service cold-starts on the first request after an idle period.
fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build http client")
}

/// The gate is pure, so this runs in the NORMAL `cargo test` suite (no env, no
/// GCP) — CI-runnable coverage in an otherwise operator-run file. Locks in that a
/// real-project run requires `GREENTIC_GCP_E2E=1` exactly and that `0`/`false` do
/// NOT arm it.
#[test]
fn gate_arms_only_on_exact_1() {
    assert!(gate_armed(Some("1")));
    assert!(!gate_armed(None));
    assert!(!gate_armed(Some("0")));
    assert!(!gate_armed(Some("false")));
    assert!(!gate_armed(Some("true")));
    assert!(!gate_armed(Some("")));
}

/// CI-runnable guard on the isolation property: two runs must never resolve to
/// one Secret Manager secret. Because the env id is fixed at `local`, the H1
/// owner stamp is identical across runs, so a shared secret name would be
/// classified `Ours` by BOTH and the first destroy would delete the other's live
/// seed. The prefix is the only thing keeping them apart — pin that it actually
/// varies, and that it stays inside Secret Manager's charset.
#[test]
fn run_secret_prefixes_are_unique_and_name_safe() {
    let a = unique_secret_prefix(1234, 1_000_000_000_000_000_000);
    let b = unique_secret_prefix(1234, 1_000_000_000_000_000_001);
    let other_proc = unique_secret_prefix(5678, 1_000_000_000_000_000_000);
    assert_ne!(a, b, "same pid, later clock → distinct prefix");
    assert_ne!(a, other_proc, "same clock, other pid → distinct prefix");

    for name in [&a, &b, &other_proc] {
        // The full secret is `<prefix>-environment`; both must satisfy
        // Secret Manager's `[a-zA-Z0-9_-]{1,255}`, leading letter.
        assert!(
            name.starts_with(|c: char| c.is_ascii_alphabetic()),
            "{name} must start with a letter"
        );
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{name} must stay in Secret Manager's charset"
        );
        assert!(
            name.len() + "-environment".len() <= 255,
            "{name}-environment must fit Secret Manager's 255-char limit"
        );
    }
}

/// Also CI-runnable: pins the URL shape the live assertion depends on, so a
/// mistake in the matcher surfaces without a project.
#[test]
fn run_app_urls_are_recognized() {
    assert!(is_run_app_url("https://gtc-local-abc123-ew.a.run.app"));
    assert!(is_run_app_url("https://svc-12345-uc.a.run.app/"));
    // Wrong scheme, wrong suffix, and the empty-host edge — each would let a
    // bogus "URL" through an endswith-only check.
    assert!(!is_run_app_url("http://gtc-local-abc123-ew.a.run.app"));
    assert!(!is_run_app_url("https://example.com"));
    assert!(!is_run_app_url("https://.run.app"));
    assert!(!is_run_app_url("gtc-local-abc123-ew.a.run.app"));
    // A path segment must not be mistaken for the host.
    assert!(!is_run_app_url("https://evil.example.com/x.run.app"));
}

/// Stage revision `label` from the OCI bundle, drive it to `Ready`
/// (desired-state), then LIVE-warm it on Cloud Run via `env apply-revision`.
/// Returns the revision id.
///
/// Staged by `bundle_source_uri` (not a local `bundle_path`): Cloud Run pulls the
/// bundle from the registry at boot — a local file on this machine is
/// unreachable from the container — and the source URI rides to the workload in
/// the seeded environment.json.
fn provision_warmed_revision(
    store: &Path,
    deployment_id: &str,
    label: &str,
    bundle_uri: &str,
    bundle_digest: &str,
) -> String {
    let stage = payload(
        store,
        &format!("stage-{label}.json"),
        json!({
            "environment_id": ENV_ID,
            "deployment_id": deployment_id,
            "bundle_source_uri": bundle_uri,
            "bundle_digest": bundle_digest,
        }),
    );
    let revision_id = op(store, Some(&stage), &["revisions", "stage"])["result"]["revision_id"]
        .as_str()
        .expect("revision_id")
        .to_string();

    let warm = payload(
        store,
        &format!("warm-{label}.json"),
        json!({"environment_id": ENV_ID, "revision_id": revision_id}),
    );
    let warmed = op(store, Some(&warm), &["revisions", "warm"]);
    assert_eq!(
        warmed["result"]["lifecycle"], "ready",
        "revision {label} reaches Ready (desired-state) before the live warm"
    );

    let applied = op(
        store,
        None,
        &["env", "apply-revision", ENV_ID, &revision_id],
    );
    assert_eq!(
        applied["result"]["action"], "warmed",
        "present revision {label} drives the live Cloud Run warm"
    );
    revision_id
}

/// Record `entries` as the deployment's split and push it LIVE to Cloud Run via
/// `env apply-traffic`. `set_traffic_split` is replace-by-deployment, so a later
/// call REPLACES the split — that is the blue/green shift. Returns the enforced
/// entries the CLI echoes back.
fn apply_split(store: &Path, deployment_id: &str, label: &str, entries: Value) -> Vec<Value> {
    let traffic = payload(
        store,
        &format!("traffic-{label}.json"),
        json!({
            "environment_id": ENV_ID,
            "deployment_id": deployment_id,
            "entries": entries,
            "idempotency_key": format!("gcp-cloudrun-e2e-{label}"),
        }),
    );
    op(store, Some(&traffic), &["traffic", "set"]);

    let shifted = op(
        store,
        None,
        &["env", "apply-traffic", ENV_ID, deployment_id],
    );
    shifted["result"]["applied_entries"]
        .as_array()
        .expect("applied_entries")
        .clone()
}

/// Full live lifecycle: `op env up` from a one-file manifest → assert the
/// `*.run.app` URL and that the workload SERVES → warm a second revision → split
/// 50/50 (plan D1's integer-percent conversion, against the real API) → SHIFT
/// 100 % to B → archive the drained A → `op env destroy` reclaims every Service
/// and staged secret.
///
/// Two revisions (not one) because the engine REFUSES to archive a revision still
/// referenced by a live traffic split, so a single-revision env can never drain
/// itself; both stage from one deployment so a single Cloud Run split shifts
/// between them.
///
/// One sequential test (not several) so the expensive real-project bring-up runs
/// once; each step depends on the prior.
#[test]
fn cloudrun_full_lifecycle_against_real_project() {
    if !armed() {
        return;
    }

    // The store OUTLIVES a failure on purpose. `TempDir` would delete itself as
    // the panic unwinds — taking the environment state with it and making the
    // reclaim command below impossible to run at exactly the moment it is needed
    // (a failure after `env up` leaves a live Service and a staged secret). So
    // detach it now and remove it explicitly only once teardown has succeeded.
    let store_path = tempfile::tempdir().expect("tempdir").keep();
    let store = store_path.as_path();
    let (bundle_uri, bundle_digest) = bundle_ref();
    let secret_prefix = run_secret_prefix();
    // Printed up front, not on the failure path: a panic (or a Ctrl+C out of a
    // stuck provider call) must leave these where the operator can see them.
    eprintln!("[gcp-e2e] store root:    {}", store.display());
    eprintln!("[gcp-e2e] secret prefix: {secret_prefix}");
    eprintln!(
        "[gcp-e2e] reclaim with: {} op --store-root {} env destroy {ENV_ID} --confirm",
        deployer_bin().display(),
        store.display()
    );

    // 1. ONE command: create the env, bind the Cloud Run deployer, add the
    //    bundle, warm revision A, and route 100 % to it. The headline UX.
    let manifest = payload(
        store,
        "cloudrun.env.json",
        env_manifest(&bundle_uri, &bundle_digest, &secret_prefix),
    );
    let up = op(store, Some(&manifest), &["env", "up", "--yes"]);
    assert_eq!(
        up["result"]["kind"], DESCRIPTOR,
        "the Cloud Run deployer ran"
    );

    // `endpoint_url` is the convenience field `cloudrun_env_up` emits only for a
    // one-deployment env (the general case reads `endpoints`), which is exactly
    // this fixture.
    let url = up["result"]["endpoint_url"]
        .as_str()
        .unwrap_or_else(|| panic!("`env up` returned no single-service `endpoint_url`: {up}"))
        .to_string();
    assert!(
        is_run_app_url(&url),
        "`env up` must return the Cloud Run-assigned service URL, got {url:?}"
    );
    eprintln!("[gcp-e2e] service URL: {url}");

    // 2. The boot proof: the container came up from the staged secret volumes.
    //    Everything before this only shows GCP ACCEPTED our calls.
    if let Err(last) = probe_liveness(&url) {
        panic!(
            "{url}{LIVENESS_PATH} never returned 200 ({last}). The Service deployed, so this \
             points at the seed/boot chain (secret volume mount, GREENTIC_SEED_DIR) rather than \
             the deploy glue — check the Cloud Run revision logs. Reclaim with the command \
             printed above."
        );
    }

    // 2b. The WORK proof — what the liveness probe structurally cannot tell us. See
    //     `probe_status`.
    let status = probe_status(&url);
    eprintln!("[gcp-e2e] /status: {status}");
    assert_eq!(
        status["env_id"], ENV_ID,
        "the runtime booted OUR seeded environment: {status}"
    );
    assert!(
        status["bundles_active"].as_u64().unwrap_or(0) >= 1,
        "the worker pulled and loaded the bundle (a 200 from the static liveness route alone \
         would not prove this): {status}"
    );
    assert!(
        status["revisions_active"].as_u64().unwrap_or(0) >= 1,
        "the worker activated a revision: {status}"
    );

    // 3. GREEN: warm a second revision on the same deployment.
    let deployment_id = up["result"]["endpoints"][0]["deployment_id"]
        .as_str()
        .expect("deployment_id from env up endpoints")
        .to_string();
    let rev_a = op(store, None, &["revisions", "list", ENV_ID])["result"]["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .find(|r| r["deployment_id"] == deployment_id.as_str())
        .and_then(|r| r["revision_id"].as_str())
        .expect("revision A from env up")
        .to_string();
    let rev_b = provision_warmed_revision(store, &deployment_id, "b", &bundle_uri, &bundle_digest);

    // 4. 50/50 — plan D1: 5000 bps each → 50 % each, summing to exactly 100, the
    //    only shape Cloud Run's integer `percent` accepts.
    let split = apply_split(
        store,
        &deployment_id,
        "split",
        json!([
            {"revision_id": rev_a, "weight_bps": 5000},
            {"revision_id": rev_b, "weight_bps": 5000},
        ]),
    );
    assert_eq!(split.len(), 2, "both revisions in the live split");
    assert!(
        split.iter().all(|e| e["weight_bps"] == 5000),
        "50/50 split enforced as recorded: {split:?}"
    );
    // Still serving mid-split: the URL is stable across a traffic re-point.
    probe_liveness(&url).expect("service still serves during the 50/50 split");

    // 5. SHIFT 100 % → B. Replaces the split, freeing A to archive.
    let shifted = apply_split(
        store,
        &deployment_id,
        "shift-b",
        json!([{"revision_id": rev_b, "weight_bps": 10000}]),
    );
    assert_eq!(shifted.len(), 1, "single entry after the shift");
    assert_eq!(shifted[0]["revision_id"], rev_b, "shifted to B");
    assert_eq!(shifted[0]["weight_bps"], 10000, "shifted 100 %");

    // 6. Archive the drained A (desired-state — now valid because no split
    //    references it), then apply-revision tears its Cloud Run revision down.
    let archive = payload(
        store,
        "archive-a.json",
        json!({"environment_id": ENV_ID, "revision_id": rev_a}),
    );
    let archived = op(store, Some(&archive), &["revisions", "archive"]);
    assert_eq!(
        archived["result"]["lifecycle"], "archived",
        "blue revision archived (desired-state) once drained"
    );
    let torn_down = op(store, None, &["env", "apply-revision", ENV_ID, &rev_a]);
    assert_eq!(
        torn_down["result"]["action"], "archived",
        "absent blue revision drives the live Cloud Run revision teardown"
    );

    // 7. Reclaim everything. The teardown runs inside the store's destroy flock
    //    and is the ONLY live coverage of delete_service + delete_secret + the H1
    //    owner-stamp check — assert it actually deleted, rather than treating the
    //    destroy as cleanup that may quietly no-op.
    let destroyed = op(store, None, &["env", "destroy", ENV_ID, "--confirm"]);
    let teardown = &destroyed["result"]["provider_teardown"];
    assert_eq!(
        teardown["provider"], "gcp-cloudrun",
        "the Cloud Run provider teardown ran, not a local-only purge: {destroyed}"
    );
    let services = teardown["deleted_services"]
        .as_array()
        .unwrap_or_else(|| panic!("destroy reported no deleted_services: {destroyed}"));
    assert!(
        !services.is_empty(),
        "destroy deleted the Cloud Run service(s)"
    );
    let secrets = teardown["deleted_secrets"]
        .as_array()
        .expect("deleted_secrets");
    assert!(
        !secrets.is_empty(),
        "destroy deleted the staged secret(s) — we own them, so the H1 ownership \
         check must classify them as ours, not skip them: {destroyed}"
    );
    assert_eq!(
        teardown["skipped_secrets"].as_array().map(Vec::len),
        Some(0),
        "nothing skipped as another environment's: {destroyed}"
    );

    // Only now is the store expendable: every provider resource is reclaimed and
    // every teardown assertion held, so there is nothing left to recover.
    // Anything that panicked before this point left it on disk deliberately.
    let _ = std::fs::remove_dir_all(store);

    eprintln!(
        "[gcp-e2e] destroyed: {} service(s), {} secret(s)",
        services.len(),
        secrets.len()
    );
}
