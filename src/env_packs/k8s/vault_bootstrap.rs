//! Native HTTP bootstrap for the in-cluster dev Vault — the Rust replacement
//! for `my_demos/k8s-vault-demo/vault-bootstrap.sh`.
//!
//! Teaches a dev-mode Vault to trust the worker pod's Kubernetes ServiceAccount
//! and hand it a read-only token scoped to one environment's KV path. Every
//! step is idempotent, so a re-run against a surviving Vault converges and a
//! re-run against a restarted (wiped, in-memory) dev Vault re-provisions from
//! scratch.
//!
//! Reached over a `kubectl port-forward` (`kube` 3.1 ships no `ws` feature, so
//! kube-rs `portforward` is unavailable): the caller hands `addr` as
//! `http://127.0.0.1:<port>`. The calls are plain `reqwest::blocking` and must
//! run OUTSIDE any tokio runtime (blocking reqwest builds its own), i.e. from
//! the synchronous `env up` flow, never inside `run_k8s_async`.
//!
//! DEV MODE ONLY. The dev Vault is unsealed, in-memory, and root-token-auth.

use std::time::Duration;

use reqwest::Method;
use reqwest::blocking::Client;
use serde_json::{Value, json};

/// The read-only policy name bound to the worker role.
const POLICY_NAME: &str = "gtc-worker-ro";
/// The worker token TTL the role grants.
const ROLE_TTL: &str = "1h";
/// HTTP client timeout — a hung dev Vault must not block `env up` forever.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection + scoping inputs for [`bootstrap`]. Non-secret except `token`,
/// the dev-mode admin/root token.
pub struct VaultBootstrapParams<'a> {
    /// Reachable Vault address, e.g. `http://127.0.0.1:8200` (a port-forward).
    pub addr: &'a str,
    /// Admin/root token (dev-mode `root` is fine) with rights to enable mounts,
    /// write policies, and bind roles.
    pub token: &'a str,
    /// KV v2 mount (provider default `secret`).
    pub kv_mount: &'a str,
    /// KV path prefix (provider default `greentic`).
    pub kv_prefix: &'a str,
    /// Transit mount (provider default `transit`).
    pub transit_mount: &'a str,
    /// Transit key (provider default `greentic`).
    pub transit_key: &'a str,
    /// Kubernetes auth mount (provider default `kubernetes`).
    pub auth_mount: &'a str,
    /// Environment id — the KV policy path segment the worker is scoped to.
    pub env_id: &'a str,
    /// Tenant — the KV policy path segment under the env.
    pub tenant: &'a str,
    /// Worker ServiceAccount name bound to the role.
    pub worker_sa: &'a str,
    /// Namespace the worker pods run in — bound alongside the SA name.
    pub worker_namespace: &'a str,
    /// Vault role name the worker logs in with.
    pub role: &'a str,
    /// API server URL Vault's Kubernetes auth reviews tokens against
    /// (`https://kubernetes.default.svc` from inside the cluster).
    pub kubernetes_host: &'a str,
}

/// Result of a [`bootstrap`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultBootstrapOutcome {
    /// `true` when the worker role already existed before this call — i.e. a
    /// surviving Vault that may already hold seeded secrets. `false` when the
    /// role was absent (a fresh or wiped in-memory dev Vault), so the seed phase
    /// must treat a missing secret as a hard error: a fresh Vault cannot already
    /// hold the value.
    pub was_already_configured: bool,
}

/// Failures the native bootstrap can surface.
#[derive(Debug, thiserror::Error)]
pub enum VaultBootstrapError {
    #[error("vault unreachable at {addr} (is the port-forward up?): {source}")]
    Unreachable {
        addr: String,
        source: reqwest::Error,
    },
    #[error("vault at {addr} is not ready (HTTP {status} on sys/health; sealed or uninitialized?)")]
    NotReady { addr: String, status: u16 },
    #[error("vault bootstrap step `{step}` failed: HTTP {status}: {body}")]
    Http {
        step: &'static str,
        status: u16,
        body: String,
    },
    #[error("vault bootstrap step `{step}` transport error: {source}")]
    Transport {
        step: &'static str,
        source: reqwest::Error,
    },
    #[error("failed to build vault HTTP client: {source}")]
    ClientBuild { source: reqwest::Error },
}

/// The read-only HCL policy the worker role carries: KV reads for this
/// env+tenant, metadata read/list for version lookups, and transit `decrypt`
/// only (the worker never re-encrypts — seeding uses a separate admin token).
pub fn render_policy_hcl(p: &VaultBootstrapParams) -> String {
    format!(
        "# KV v2 record reads for this environment + tenant only.\n\
         path \"{kv}/data/{prefix}/{env}/{tenant}/*\" {{\n  capabilities = [\"read\"]\n}}\n\
         # KV v2 metadata (version lookups / listing) for the same scope.\n\
         path \"{kv}/metadata/{prefix}/{env}/{tenant}/*\" {{\n  capabilities = [\"read\", \"list\"]\n}}\n\
         # Unwrap the per-secret data-encryption key on read (decrypt only).\n\
         path \"{transit}/decrypt/{key}\" {{\n  capabilities = [\"update\"]\n}}\n",
        kv = p.kv_mount,
        prefix = p.kv_prefix,
        env = p.env_id,
        tenant = p.tenant,
        transit = p.transit_mount,
        key = p.transit_key,
    )
}

/// Provision the dev Vault: enable KV v2 + transit, create the DEK key, enable
/// and configure Kubernetes auth, write the read-only policy, and bind the
/// worker SA to the role. Idempotent throughout. Returns whether Vault was
/// already configured (see [`VaultBootstrapOutcome`]).
pub fn bootstrap(p: &VaultBootstrapParams) -> Result<VaultBootstrapOutcome, VaultBootstrapError> {
    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|source| VaultBootstrapError::ClientBuild { source })?;
    let addr = p.addr.trim_end_matches('/');

    check_health(&client, addr)?;
    // Detect a surviving vs. fresh/wiped Vault BEFORE (re-)provisioning: the
    // role is the last object bootstrap writes, so its presence means a prior
    // bootstrap completed.
    let was_already_configured = role_exists(&client, addr, p)?;

    // 1. KV v2 mount (dev Vault already mounts `secret/` as kv-v2 → usually 400).
    write(
        &client,
        Method::POST,
        &format!("{addr}/v1/sys/mounts/{}", p.kv_mount),
        p.token,
        json!({ "type": "kv", "options": { "version": "2" } }),
        "enable kv mount",
        true,
    )?;
    // 2. Transit mount.
    write(
        &client,
        Method::POST,
        &format!("{addr}/v1/sys/mounts/{}", p.transit_mount),
        p.token,
        json!({ "type": "transit" }),
        "enable transit mount",
        true,
    )?;
    // 3. Transit DEK key (creating an existing key is a no-op).
    write(
        &client,
        Method::POST,
        &format!("{addr}/v1/{}/keys/{}", p.transit_mount, p.transit_key),
        p.token,
        json!({}),
        "create transit key",
        false,
    )?;
    // 4. Kubernetes auth method.
    write(
        &client,
        Method::POST,
        &format!("{addr}/v1/sys/auth/{}", p.auth_mount),
        p.token,
        json!({ "type": "kubernetes" }),
        "enable kubernetes auth",
        true,
    )?;
    // 5. Kubernetes auth config (Vault-the-pod reviews tokens with its own SA).
    write(
        &client,
        Method::POST,
        &format!("{addr}/v1/auth/{}/config", p.auth_mount),
        p.token,
        json!({ "kubernetes_host": p.kubernetes_host }),
        "configure kubernetes auth",
        false,
    )?;
    // 6. Read-only policy.
    write(
        &client,
        Method::PUT,
        &format!("{addr}/v1/sys/policies/acl/{POLICY_NAME}"),
        p.token,
        json!({ "policy": render_policy_hcl(p) }),
        "write policy",
        false,
    )?;
    // 7. Bind the worker SA → role → policy.
    write(
        &client,
        Method::POST,
        &format!("{addr}/v1/auth/{}/role/{}", p.auth_mount, p.role),
        p.token,
        json!({
            "bound_service_account_names": p.worker_sa,
            "bound_service_account_namespaces": p.worker_namespace,
            "policies": POLICY_NAME,
            "ttl": ROLE_TTL,
        }),
        "bind role",
        false,
    )?;

    Ok(VaultBootstrapOutcome {
        was_already_configured,
    })
}

/// Confirm Vault is reachable and ready. Dev-mode Vault answers `sys/health`
/// with 200 (initialized, unsealed, active); anything else is not-ready.
fn check_health(client: &Client, addr: &str) -> Result<(), VaultBootstrapError> {
    let resp = client
        .get(format!("{addr}/v1/sys/health"))
        .send()
        .map_err(|source| VaultBootstrapError::Unreachable {
            addr: addr.to_string(),
            source,
        })?;
    let status = resp.status().as_u16();
    // 200 = active. 429 = unsealed standby (single-node dev never returns it,
    // but tolerate it as "ready"). Everything else (sealed 503, uninit 501) is
    // not ready.
    if status == 200 || status == 429 {
        Ok(())
    } else {
        Err(VaultBootstrapError::NotReady {
            addr: addr.to_string(),
            status,
        })
    }
}

/// Whether the worker role already exists (200) — the surviving-Vault signal.
fn role_exists(
    client: &Client,
    addr: &str,
    p: &VaultBootstrapParams,
) -> Result<bool, VaultBootstrapError> {
    let resp = client
        .get(format!("{addr}/v1/auth/{}/role/{}", p.auth_mount, p.role))
        .header("X-Vault-Token", p.token)
        .send()
        .map_err(|source| VaultBootstrapError::Transport {
            step: "probe role",
            source,
        })?;
    match resp.status().as_u16() {
        200 => Ok(true),
        404 => Ok(false),
        status => Err(VaultBootstrapError::Http {
            step: "probe role",
            status,
            body: resp.text().unwrap_or_default(),
        }),
    }
}

/// One authenticated write. `tolerate_in_use` accepts a `400 "path is already
/// in use"` (mount/auth enable on a re-run) as success.
fn write(
    client: &Client,
    method: Method,
    url: &str,
    token: &str,
    body: Value,
    step: &'static str,
    tolerate_in_use: bool,
) -> Result<(), VaultBootstrapError> {
    let resp = client
        .request(method, url)
        .header("X-Vault-Token", token)
        .json(&body)
        .send()
        .map_err(|source| VaultBootstrapError::Transport { step, source })?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let code = status.as_u16();
    let text = resp.text().unwrap_or_default();
    if tolerate_in_use
        && code == 400
        && (text.contains("already in use") || text.contains("already enabled"))
    {
        return Ok(());
    }
    Err(VaultBootstrapError::Http {
        step,
        status: code,
        body: text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// One recorded request: method, path, and JSON body.
    #[derive(Clone)]
    struct Recorded {
        method: String,
        path: String,
        body: Value,
        token: String,
    }

    struct FakeVault {
        addr: String,
        requests: Arc<Mutex<Vec<Recorded>>>,
    }

    /// A path-routing fake Vault. Loops accepting requests on a detached thread
    /// (the test process reaps it), recording each and answering per route.
    /// `role_exists` drives the surviving-vs-fresh probe.
    fn start_fake_vault(role_exists: bool) -> FakeVault {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let requests: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut lines: Vec<String> = Vec::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let t = line.trim_end_matches(['\r', '\n']).to_string();
                    if t.is_empty() {
                        break;
                    }
                    lines.push(t);
                }
                if lines.is_empty() {
                    continue;
                }
                let mut parts = lines[0].split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let content_length: usize = lines
                    .iter()
                    .find(|l| l.to_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let token = lines
                    .iter()
                    .find(|l| l.to_lowercase().starts_with("x-vault-token:"))
                    .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
                    .unwrap_or_default();
                let mut raw = vec![0u8; content_length];
                if content_length > 0 {
                    reader.read_exact(&mut raw).unwrap();
                }
                let body: Value = if raw.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&raw).unwrap_or(Value::Null)
                };
                sink.lock().unwrap().push(Recorded {
                    method: method.clone(),
                    path: path.clone(),
                    body,
                    token,
                });

                let (status, resp_body): (u16, &str) = route(&method, &path, role_exists);
                let reason = match status {
                    200 => "OK",
                    204 => "No Content",
                    400 => "Bad Request",
                    404 => "Not Found",
                    _ => "OK",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        FakeVault { addr, requests }
    }

    fn route(method: &str, path: &str, role_exists: bool) -> (u16, &'static str) {
        match (method, path) {
            ("GET", "/v1/sys/health") => (200, r#"{"initialized":true,"sealed":false}"#),
            ("GET", p) if p.starts_with("/v1/auth/kubernetes/role/") => {
                if role_exists {
                    (200, r#"{"data":{}}"#)
                } else {
                    (404, r#"{"errors":[]}"#)
                }
            }
            // Dev Vault already has `secret/` mounted as kv-v2.
            ("POST", "/v1/sys/mounts/secret") => {
                (400, r#"{"errors":["path is already in use at secret/"]}"#)
            }
            _ => (204, ""),
        }
    }

    fn params<'a>(addr: &'a str) -> VaultBootstrapParams<'a> {
        VaultBootstrapParams {
            addr,
            token: "root",
            kv_mount: "secret",
            kv_prefix: "greentic",
            transit_mount: "transit",
            transit_key: "greentic",
            auth_mount: "kubernetes",
            env_id: "vault-demo",
            tenant: "org-1",
            worker_sa: "gtc-worker",
            worker_namespace: "greentic",
            role: "gtc-worker",
            kubernetes_host: "https://kubernetes.default.svc",
        }
    }

    #[test]
    fn bootstrap_runs_all_steps_and_reports_fresh() {
        let vault = start_fake_vault(false);
        let outcome = bootstrap(&params(&vault.addr)).expect("bootstrap succeeds");
        assert!(
            !outcome.was_already_configured,
            "absent role must report fresh"
        );

        let reqs = vault.requests.lock().unwrap();
        let hit = |m: &str, p: &str| reqs.iter().any(|r| r.method == m && r.path == p);
        // The 7 idempotent steps, each authenticated.
        assert!(hit("POST", "/v1/sys/mounts/secret"), "kv mount");
        assert!(hit("POST", "/v1/sys/mounts/transit"), "transit mount");
        assert!(hit("POST", "/v1/transit/keys/greentic"), "transit key");
        assert!(hit("POST", "/v1/sys/auth/kubernetes"), "k8s auth");
        assert!(hit("POST", "/v1/auth/kubernetes/config"), "auth config");
        assert!(hit("PUT", "/v1/sys/policies/acl/gtc-worker-ro"), "policy");
        assert!(hit("POST", "/v1/auth/kubernetes/role/gtc-worker"), "role");
        // Every mutating call carries the admin token (the health GET does not).
        assert!(
            reqs.iter()
                .filter(|r| r.method == "POST" || r.method == "PUT")
                .all(|r| r.token == "root"),
            "every write must carry the admin token"
        );
    }

    #[test]
    fn bootstrap_on_surviving_vault_reports_configured() {
        let vault = start_fake_vault(true);
        let outcome = bootstrap(&params(&vault.addr)).expect("bootstrap succeeds");
        assert!(
            outcome.was_already_configured,
            "present role must report already-configured"
        );
    }

    #[test]
    fn bootstrap_tolerates_path_already_in_use_and_writes_scoped_policy_and_role() {
        // The fake returns 400 "already in use" for the kv mount; bootstrap must
        // not fail on it.
        let vault = start_fake_vault(false);
        bootstrap(&params(&vault.addr)).expect("tolerates already-in-use");

        let reqs = vault.requests.lock().unwrap();
        let policy = reqs
            .iter()
            .find(|r| r.path == "/v1/sys/policies/acl/gtc-worker-ro")
            .expect("policy write recorded");
        let hcl = policy.body["policy"].as_str().unwrap();
        assert!(
            hcl.contains("secret/data/greentic/vault-demo/org-1/*"),
            "policy must scope KV reads to env+tenant: {hcl}"
        );
        assert!(
            hcl.contains("transit/decrypt/greentic"),
            "decrypt grant: {hcl}"
        );

        let role = reqs
            .iter()
            .find(|r| r.method == "POST" && r.path == "/v1/auth/kubernetes/role/gtc-worker")
            .expect("role write recorded");
        assert_eq!(role.body["bound_service_account_names"], "gtc-worker");
        assert_eq!(role.body["bound_service_account_namespaces"], "greentic");
        assert_eq!(role.body["policies"], "gtc-worker-ro");
    }

    #[test]
    fn bootstrap_fails_when_vault_is_unreachable() {
        // Nothing listening on this port.
        let mut p = params("http://127.0.0.1:1");
        p.addr = "http://127.0.0.1:1";
        let err = bootstrap(&p).unwrap_err();
        assert!(
            matches!(err, VaultBootstrapError::Unreachable { .. }),
            "got {err:?}"
        );
    }
}
