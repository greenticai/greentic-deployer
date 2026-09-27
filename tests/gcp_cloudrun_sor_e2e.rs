//! Live-project E2E for SoR units on the Cloud Run env-pack (SoRLa phase 3E).
//!
//! Proves what only a real project can: a sorx service pulls its pack from
//! Artifact Registry with the runtime service account's metadata token,
//! reaches a public-TLS Postgres, becomes ready on `/healthz`, is reachable at
//! its `*.run.app` URL only with the shared secret, its route document lands at
//! `default/_/sorla/<sor>`, the worker deploys after it, and `sor_units: []`
//! retires it.
//!
//! Gate: `GREENTIC_GCP_E2E=1` exactly (bills a real project).
//!   REQUIRED:
//!     GTC_GCP_E2E_PROJECT, GTC_GCP_E2E_REGION
//!     GTC_GCP_E2E_SORX_IMAGE        digest-pinned sorx image carrying the
//!                                   metadata-token pull fallback (spec §3)
//!     GTC_GCP_E2E_SOR_PACK_REF      oci://<region>-docker.pkg.dev/<project>/<repo>/sorla/landlord:e2e@sha256:<hex>
//!     GTC_GCP_E2E_SOR_POSTGRES_URL  public Postgres with TLS (`sslmode=require`)
//!   OPTIONAL:
//!     GTC_GCP_E2E_SERVICE_ACCOUNT, GTC_GCP_E2E_SOR_POSTGRES_CA_FILE (PEM path)
//!
//! Push the pack first:
//!   curl -fsSL -o /tmp/landlord.gtpack https://raw.githubusercontent.com/greenticai/greentic-sorla/5c0bb5528dfbd5b0fd171c1255c98d2b44fc45c7/examples/landlord-tenant/landlord-tenant-sor.gtpack
//!   oras push <region>-docker.pkg.dev/<project>/<repo>/sorla/landlord:e2e \
//!     /tmp/landlord.gtpack:application/vnd.greentic.gtpack.v1+zip
//!   oras manifest fetch --descriptor <same ref>   # take "digest"
//!
//! Run (`GTC_GCP_E2E_SORX_IMAGE` below is the sorx build that carries the
//! metadata-token pull fallback, sorx merge a220be9e / release
//! v0.2.36314292285 — substitute a newer digest-pinned release once one
//! ships):
//!   GREENTIC_GCP_E2E=1 GTC_GCP_E2E_PROJECT=… GTC_GCP_E2E_REGION=… \
//!   GTC_GCP_E2E_SORX_IMAGE=ghcr.io/greenticai/greentic-sorx:0.2.36314292285@sha256:d346f9aa8efb67bf9327f522aa1b78fac327b4a176da9a872d5c3e32836de3c7 \
//!   GTC_GCP_E2E_SOR_PACK_REF=…@sha256:… \
//!   GTC_GCP_E2E_SOR_POSTGRES_URL='postgres://…?sslmode=require' \
//!     cargo test -p greentic-deployer --test gcp_cloudrun_sor_e2e -- --nocapture
//!
//! A mid-run failure leaves resources behind; the store is persisted and the
//! reclaim command printed up front, exactly as in `gcp_cloudrun_e2e`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

const E2E_GATE: &str = "GREENTIC_GCP_E2E";
const DESCRIPTOR: &str = "greentic.deployer.gcp-cloudrun@1.0.0";
const SECRETS_KIND: &str = "greentic.secrets.dev-store@0.1.0";
const ENV_ID: &str = "local";
const DEFAULT_BUNDLE_URI: &str = "oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:v1";
const DEFAULT_BUNDLE_DIGEST: &str =
    "sha256:4f560749ec709e75b6063cdeccab15ed5074c2e60bc5f772c2d3b7d4bd992363";
const SOR_UNIT: &str = "landlord";
const SOR_KEY: &str = "landlord-tenant-sor";
const SOR_TENANT: &str = "acme";
/// A sorx route that demands the shared secret. NOT `/healthz`: Google's front
/// end swallows it for external requests (see `gcp_cloudrun_e2e::LIVENESS_PATH`).
const SOR_PROBE_PATH: &str = "/v1/sorx/routes";
const ATTEMPTS: u32 = 20;
const BACKOFF: Duration = Duration::from_secs(3);

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

fn gate_armed(value: Option<&str>) -> bool {
    value == Some("1")
}

fn armed() -> bool {
    if gate_armed(std::env::var(E2E_GATE).ok().as_deref()) {
        return true;
    }
    eprintln!("skipping live Cloud Run SoR E2E: set {E2E_GATE}=1 exactly (bills a real project)");
    false
}

fn required_var(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{E2E_GATE} is set but required var {name} is missing"))
}

fn is_digest_pinned(reference: &str) -> bool {
    reference
        .rsplit_once("@sha256:")
        .is_some_and(|(name, hex)| {
            !name.is_empty()
                && hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

fn is_run_app_url(url: &str) -> bool {
    url.strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|host| host.ends_with(".run.app") && !host.starts_with('.'))
}

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
    serde_json::from_str(stdout.trim()).expect("op stdout is json")
}

fn payload(store: &Path, name: &str, body: Value) -> PathBuf {
    let path = store.join(name);
    std::fs::write(&path, serde_json::to_vec(&body).expect("json")).expect("write payload");
    path
}

fn put(store: &Path, name: &str, value: &str) {
    let body = json!({
        "environment_id": ENV_ID,
        "path": format!("default/_/sor-{SOR_UNIT}/{name}"),
        "value": value,
    });
    op(
        store,
        Some(&payload(store, "sor-put.json", body)),
        &["secrets", "put"],
    );
}

fn manifest(store: &Path, secret_prefix: &str, sor_units: Value) -> PathBuf {
    let mut answers = json!({
        "project": required_var("GTC_GCP_E2E_PROJECT"),
        "region": required_var("GTC_GCP_E2E_REGION"),
        "access_mode": "public",
        "secret_prefix": secret_prefix,
    });
    if let Ok(sa) = std::env::var("GTC_GCP_E2E_SERVICE_ACCOUNT") {
        answers["service_account"] = json!(sa);
    }
    payload(
        store,
        "sor.env.json",
        json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": ENV_ID, "name": "cloudrun-sor-e2e"},
            "trust_root": "bootstrap",
            "packs": [
                {"slot": "deployer", "kind": DESCRIPTOR, "pack_ref": "builtin", "answers": answers},
                {"slot": "secrets", "kind": SECRETS_KIND, "pack_ref": "builtin"},
            ],
            "bundles": [{
                "bundle_id": "cloudrun-sor-e2e",
                "bundle_source_uri": DEFAULT_BUNDLE_URI,
                "bundle_digest": DEFAULT_BUNDLE_DIGEST,
                "route_binding": {"path_prefixes": ["/"]},
            }],
            "sor_units": sor_units,
        }),
    )
}

fn status_of(url: &str, token: Option<&str>) -> Result<u16, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client.get(format!("{url}{SOR_PROBE_PATH}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request
        .send()
        .map(|r| r.status().as_u16())
        .map_err(|e| e.to_string())
}

/// Retry through cold starts until `want` answers, or return the last status.
fn until(url: &str, token: Option<&str>, want: u16) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..ATTEMPTS {
        match status_of(url, token) {
            Ok(code) if code == want => return Ok(()),
            Ok(code) => last = format!("HTTP {code}"),
            Err(e) => last = e,
        }
        std::thread::sleep(BACKOFF);
    }
    Err(last)
}

#[test]
fn gate_arms_only_on_exact_1() {
    assert!(gate_armed(Some("1")));
    for v in [None, Some("0"), Some("true"), Some("")] {
        assert!(!gate_armed(v));
    }
}

#[test]
fn digest_pinning_is_recognized() {
    assert!(is_digest_pinned(&format!(
        "ghcr.io/greenticai/greentic-sorx@sha256:{}",
        "a".repeat(64)
    )));
    assert!(!is_digest_pinned(
        "ghcr.io/greenticai/greentic-sorx:develop"
    ));
    assert!(!is_digest_pinned(&format!("x@sha256:{}", "A".repeat(64))));
}

#[test]
fn cloudrun_sor_unit_against_real_project() {
    if !armed() {
        return;
    }
    let image = required_var("GTC_GCP_E2E_SORX_IMAGE");
    let pack_ref = required_var("GTC_GCP_E2E_SOR_PACK_REF");
    assert!(
        is_digest_pinned(&image),
        "GTC_GCP_E2E_SORX_IMAGE must be digest-pinned"
    );
    assert!(
        is_digest_pinned(&pack_ref),
        "GTC_GCP_E2E_SOR_PACK_REF must be digest-pinned"
    );
    let postgres_url = required_var("GTC_GCP_E2E_SOR_POSTGRES_URL");

    let store_path = tempfile::tempdir().expect("tempdir").keep();
    let store = store_path.as_path();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let secret_prefix = format!("gtc-e2e-sor-{}-{nanos}", std::process::id());
    let token = format!("e2e-sor-{}-{nanos}", std::process::id());
    eprintln!("[sor-e2e] store root: {}", store.display());
    eprintln!(
        "[sor-e2e] reclaim with: {} op --store-root {} env destroy {ENV_ID} --confirm",
        deployer_bin().display(),
        store.display()
    );

    // The designer's order: init → stage inputs → env up with sor_units.
    op(store, None, &["env", "init"]);
    let answers = json!({
        "server": {"bind": "0.0.0.0:8787",
                   "auth": {"mode": "shared_secret", "shared_secret_ref": "env:SORX_SHARED_SECRET"}},
        "providers": {"store": {"kind": "postgres"}},
        "tenant": {"tenant_id": SOR_TENANT, "environment": "production"},
    });
    put(store, "answers", &answers.to_string());
    put(store, "postgres_url", &postgres_url);
    put(store, "shared_secret", &token);
    let ca_ref = std::env::var("GTC_GCP_E2E_SOR_POSTGRES_CA_FILE")
        .ok()
        .map(|path| {
            put(
                store,
                "postgres_ca",
                &std::fs::read_to_string(path).expect("read CA"),
            );
            format!("default/_/sor-{SOR_UNIT}/postgres_ca")
        });
    let unit = json!({
        "unit_id": SOR_UNIT, "sor": SOR_KEY, "pack_ref": pack_ref, "image": image,
        "tenant_id": SOR_TENANT,
        "answers_ref": format!("default/_/sor-{SOR_UNIT}/answers"),
        "postgres_url_ref": format!("default/_/sor-{SOR_UNIT}/postgres_url"),
        "postgres_ca_ref": ca_ref,
        "shared_secret_ref": format!("default/_/sor-{SOR_UNIT}/shared_secret"),
    });

    let up = op(
        store,
        Some(&manifest(store, &secret_prefix, json!([unit]))),
        &["env", "up", "--yes"],
    );
    let reported = &up["result"]["sor_units"][0];
    assert_eq!(reported["unit_id"], SOR_UNIT);
    assert_eq!(reported["service"], format!("gtc-sor-{SOR_UNIT}").as_str());
    assert_eq!(reported["ready"], true);
    let url = reported["url"].as_str().expect("sor url").to_string();
    assert!(is_run_app_url(&url), "{url}");
    let printed = up.to_string();
    assert!(
        !printed.contains(&token),
        "the result never carries the token"
    );
    assert!(!printed.contains(&postgres_url), "nor the database URL");
    assert!(
        up["result"]["endpoint_url"].is_string(),
        "the worker deployed after the SoR"
    );

    let get = payload(
        store,
        "sor-get.json",
        json!({"environment_id": ENV_ID, "path": format!("default/_/sorla/{SOR_KEY}"), "reveal": true}),
    );
    let route: Value = serde_json::from_str(
        op(store, Some(&get), &["secrets", "get"])["result"]["value"]
            .as_str()
            .expect("route document"),
    )
    .expect("route json");
    assert_eq!(route["url"], url.as_str());
    assert_eq!(route["token"], token.as_str());
    assert_eq!(route["tenant"], SOR_TENANT);

    if let Err(last) = until(&url, Some(&token), 200) {
        panic!("{url}{SOR_PROBE_PATH} with the token never answered 200 ({last})");
    }
    assert_eq!(
        status_of(&url, None).expect("reachable"),
        401,
        "no token, no data (E5)"
    );

    // Retire it: the same manifest with `sor_units: []`.
    let down = op(
        store,
        Some(&manifest(store, &secret_prefix, json!([]))),
        &["env", "up", "--yes"],
    );
    assert!(down["result"].get("sor_units").is_none(), "{down}");
    assert_eq!(
        op(store, Some(&get), &["secrets", "get"])["result"]["present"],
        false
    );
    if let Err(last) = until(&url, Some(&token), 404) {
        panic!("the retired SoR service still answers ({last})");
    }

    op(store, None, &["env", "destroy", ENV_ID, "--confirm"]);
    let _ = std::fs::remove_dir_all(store);
}
