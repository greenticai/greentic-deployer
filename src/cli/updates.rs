//! `gtc op updates {enroll,status}` — P1b update-channel client-certificate
//! enrollment (Phase 1 of the Greentic updater).
//!
//! `enroll` mints a fresh key pair + CSR (via `greentic-update`), exchanges it
//! at the Cert-CA's `/v1/enroll` endpoint for a signed client certificate, and
//! persists the cert + key + issuing CA (and the CA URL) into the env's
//! configured secrets backend under the `tls` pack. Running it again overwrites
//! the stored material — so it is also the manual rotation path. `status` reads
//! the stored certificate back and reports its serial + validity window.
//!
//! Enrollment happens *before* the client holds a certificate, so it cannot use
//! the mTLS update channel itself: this verb drives `greentic-update::enroll`
//! over a plain server-auth bootstrap client. Persistence lives here (the
//! caller), not in `greentic-update`, which stays free of any secrets
//! dependency — the crate returns raw PEM and the operator persists it.

use greentic_deploy_spec::{EnvId, Environment};
use greentic_secrets_lib::core::rt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::secrets::{get_env_secret, put_env_secret, require_secrets_pack};
use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "updates";

/// Secrets pack (category) the update-channel TLS material lives under.
const TLS_PACK: &str = "tls";
/// Store-canonical secret names (single underscore — the runtime reader
/// collapses `__` to `_`, so a double-underscore name would never be found).
const CERT_NAME: &str = "updater_cert";
const KEY_NAME: &str = "updater_key";
const CA_NAME: &str = "updater_ca";
const CA_URL_NAME: &str = "updater_ca_url";

/// Payload for `op updates enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesEnrollPayload {
    pub environment_id: String,
    /// Base URL of the Cert-CA (`greentic-updates-server`). The `/v1/enroll`
    /// path is appended.
    pub ca_url: String,
}

/// Payload for `op updates status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesStatusPayload {
    pub environment_id: String,
}

/// The dev-store/Vault secret path for one TLS artifact: `<tenant>/_/tls/<name>`
/// (`<tenant>/<team>/<pack>/<name>` with the default team `_`).
fn tls_rel_path(tenant: &str, name: &str) -> String {
    format!("{tenant}/_/{TLS_PACK}/{name}")
}

/// The enrolled certificate's identity is the env's owning tenant, so an owner
/// is required. Mirrors `vault_seed_put`'s fail-closed tenant guard (a
/// Vault-backed env is single-tenant at the runtime) so the two write surfaces
/// agree on the tenant segment.
fn require_tenant(env: &Environment, env_id: &EnvId) -> Result<String, OpError> {
    env.host_config
        .tenant_org_id
        .clone()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            OpError::InvalidArgument(format!(
                "env `{env_id}` must be tenant-owned before update-channel enrollment; \
                 set the owner with `op env update {env_id} --tenant-org <tenant>`"
            ))
        })
}

/// `op updates enroll` — enroll with the Cert-CA and persist the signed client
/// certificate + key + issuing CA (and the CA URL) into the env secrets backend.
/// Idempotent by overwrite: re-running mints a fresh identity (manual rotation).
pub fn enroll(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdatesEnrollPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "enroll", enroll_schema()));
    }
    let payload = resolve_payload::<UpdatesEnrollPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    // Validate the CA URL before the authz gate / any network work.
    let ca_url = payload.ca_url.trim().to_string();
    if ca_url.is_empty() {
        return Err(OpError::InvalidArgument(
            "ca_url must not be empty".to_string(),
        ));
    }
    if !(ca_url.starts_with("https://") || ca_url.starts_with("http://")) {
        return Err(OpError::InvalidArgument(
            "ca_url must be an http(s) URL".to_string(),
        ));
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "enroll",
        // Audit target carries the CA URL and env, never key material.
        target: json!({"environment_id": env_id.as_str(), "ca_url": ca_url}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store.load(&env_id)?;
        let secrets = require_secrets_pack(&env, &env_id)?;
        let kind_path = secrets.kind.path();
        let tenant = require_tenant(&env, &env_id)?;

        // Enrollment predates the client cert, so drive it over a plain
        // server-auth client (not the mTLS one). Bridge the async call from
        // this synchronous verb, mirroring `vault_seed_put`.
        let enrollment = rt::sync_await(async {
            let client = reqwest::Client::new();
            greentic_update::enroll::enroll(&client, &ca_url, &tenant, env_id.as_str()).await
        })
        .map_err(|e| OpError::Conflict(format!("update-channel enrollment failed: {e}")))?;

        let stored = persist_enrollment(
            store,
            &env,
            &env_id,
            kind_path,
            &tenant,
            &ca_url,
            &enrollment,
        )?;

        let outcome = OpOutcome::new(
            NOUN,
            "enroll",
            json!({
                "environment_id": env_id.as_str(),
                "tenant": tenant,
                "serial": enrollment.serial,
                "not_after": enrollment.not_after,
                "secrets_kind": secrets.kind.to_string(),
                "stored": stored,
            }),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// Write the enrolled material into the env secrets backend. Returns the list of
/// `{name, store_uri}` written, for the outcome. Partial failure is recoverable
/// by re-running `enroll` (each write overwrites).
fn persist_enrollment(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    kind_path: &str,
    tenant: &str,
    ca_url: &str,
    enrollment: &greentic_update::enroll::Enrollment,
) -> Result<Vec<Value>, OpError> {
    let items = [
        (KEY_NAME, enrollment.client_key_pem.as_str()),
        (CERT_NAME, enrollment.client_cert_pem.as_str()),
        (CA_NAME, enrollment.ca_pem.as_str()),
        (CA_URL_NAME, ca_url),
    ];
    let mut stored = Vec::with_capacity(items.len());
    for (name, value) in items {
        let rel_path = tls_rel_path(tenant, name);
        let (store_uri, _extra) = put_env_secret(store, env, env_id, kind_path, &rel_path, value)?;
        stored.push(json!({"name": name, "store_uri": store_uri}));
    }
    Ok(stored)
}

/// `op updates status` — report whether the env holds an enrolled update-channel
/// certificate and, if so, its serial + validity window. Read-only (not
/// audited), so it never reveals the private key.
pub fn status(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdatesStatusPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "status", status_schema()));
    }
    let payload = resolve_payload::<UpdatesStatusPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;
    let secrets = require_secrets_pack(&env, &env_id)?;
    let kind_path = secrets.kind.path();
    let tenant = require_tenant(&env, &env_id)?;

    let cert_rel = tls_rel_path(&tenant, CERT_NAME);
    let (cert_pem, _store_uri, _extra) =
        get_env_secret(store, &env, &env_id, kind_path, &cert_rel)?;

    let body = match cert_pem {
        None => json!({
            "environment_id": env_id.as_str(),
            "tenant": tenant,
            "secrets_kind": secrets.kind.to_string(),
            "enrolled": false,
        }),
        Some(pem) => {
            let info = greentic_update::tls::parse_cert_info(&pem).map_err(|e| {
                OpError::Conflict(format!(
                    "stored update-channel certificate is unparseable: {e}"
                ))
            })?;
            json!({
                "environment_id": env_id.as_str(),
                "tenant": tenant,
                "secrets_kind": secrets.kind.to_string(),
                "enrolled": true,
                "serial": info.serial_hex,
                "not_before_epoch": info.not_before_epoch,
                "not_after_epoch": info.not_after_epoch,
            })
        }
    };
    Ok(OpOutcome::new(NOUN, "status", body))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn resolve_payload<T: serde::de::DeserializeOwned>(
    flags: &OpFlags,
    payload: Option<T>,
) -> Result<T, OpError> {
    if let Some(p) = payload {
        return Ok(p);
    }
    if let Some(path) = &flags.answers {
        return super::load_answers::<T>(path);
    }
    Err(OpError::InvalidArgument(
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn enroll_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdatesEnrollPayload",
        "type": "object",
        "required": ["environment_id", "ca_url"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "ca_url": {"type": "string", "description": "Base URL of the Cert-CA (greentic-updates-server); `/v1/enroll` is appended."}
        }
    })
}

fn status_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdatesStatusPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::secrets::{DEV_STORE_KIND_PATH, put_env_secret};
    use crate::cli::tests_common::{make_binding, make_env};
    use greentic_deploy_spec::CapabilitySlot;
    use tempfile::tempdir;

    // A self-signed X.509 cert (public material only) used to exercise the
    // `status` parse path without a running CA.
    const TEST_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUYapGXgtZrRNo/AWjUTX7ECfZenIwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVZ3JlZW50aWMtdXBkYXRlci10ZXN0MB4XDTI2MDcwMjA4
MjkzNVoXDTM2MDYyOTA4MjkzNVowIDEeMBwGA1UEAwwVZ3JlZW50aWMtdXBkYXRl
ci10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtIvlVwfBZr7V
GuUjcIgn4Uk+ONcdK2yraA3jhVulpYBepqhsN3bLE/XRPEOWeWdXcpfW/RQSx+sC
VFx2HWa0Ogh9pu75TnIxXlNPD/puEpWxJ9JcuLbujeAX1iGecKFUgfdKVFs3vAGG
MjN4ntvPt884TeoRlWoFdqY7xzHpWjnV4H/VLGGPo+7QaZKBLk7dCWfkGUTLFQSQ
p5utU4xLFdwB7dadhv6ZVp3aOAmfkYu3UuY7/YIYoYGZ6E2dg57UEv9sjbhdLBeO
wUpG7zisBhVcYwA9MwK65VzrCD32HCFX99XMf5Gd5VW03j2qHLyQuh4dQqKw2yCG
R2143vo4iQIDAQABo1MwUTAdBgNVHQ4EFgQUYIT+qBjsmFV4LvkTOd4NaXxNoGIw
HwYDVR0jBBgwFoAUYIT+qBjsmFV4LvkTOd4NaXxNoGIwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEABHXHVVGIsmYL0LaQPvRafHqsjVCh8kiLh62b
qrCeqSAeXQ7YgQVmmLGV/ZzL+nbC3SoLtT0HrYcOLHsuDLbl534w6M8U7ysliZdf
tRtAPghtrI0zcQyXVaq1fPFB0zc/ALB8oq6I7oAwHBs+9n76nfcVRKifsrYqJm6E
8XeewuLxi7lCULA/FfWteIE4kbx3HqzAG98eGbVebOApyMEAnf111PwjW0VTW4QB
L/P4PeKwohc0l4sRjlkvy+o9gnnvgjsTcMPGx1UXFXM/d8AoY1WC20cofmn0RlEd
uVbcKfZbU024RZ5zYGS0n3L4l6TVqpqQzrDfXjZNzyq0r/TK8g==
-----END CERTIFICATE-----
";

    fn dev_store_env_with_tenant() -> greentic_deploy_spec::Environment {
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        env.host_config.tenant_org_id = Some("acme".to_string());
        env
    }

    #[test]
    fn enroll_schema_only_returns_payload_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = enroll(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "enroll");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["ca_url"].is_object());
    }

    #[test]
    fn status_schema_only_returns_payload_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = status(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "status");
        assert!(out.result["properties"]["environment_id"].is_object());
    }

    #[test]
    fn enroll_rejects_empty_ca_url_before_network() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&dev_store_env_with_tenant()).unwrap();
        let err = enroll(
            &store,
            &OpFlags::default(),
            Some(UpdatesEnrollPayload {
                environment_id: "local".into(),
                ca_url: "   ".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn enroll_rejects_non_http_ca_url() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&dev_store_env_with_tenant()).unwrap();
        let err = enroll(
            &store,
            &OpFlags::default(),
            Some(UpdatesEnrollPayload {
                environment_id: "local".into(),
                ca_url: "ftp://ca.example".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn enroll_requires_tenant_owner() {
        // Env with a secrets pack but no tenant owner: enrollment must fail
        // closed (the cert identity is the owning tenant) before any network.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = enroll(
            &store,
            &OpFlags::default(),
            Some(UpdatesEnrollPayload {
                environment_id: "local".into(),
                ca_url: "https://ca.example".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn status_reports_not_enrolled_when_no_cert_stored() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&dev_store_env_with_tenant()).unwrap();
        let out = status(
            &store,
            &OpFlags::default(),
            Some(UpdatesStatusPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        assert_eq!(out.result["enrolled"], false);
    }

    #[test]
    fn status_reports_serial_and_validity_for_stored_cert() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = dev_store_env_with_tenant();
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // Seed the cert exactly where `enroll` would persist it.
        put_env_secret(
            &store,
            &env,
            &env_id,
            DEV_STORE_KIND_PATH,
            "acme/_/tls/updater_cert",
            TEST_CERT_PEM,
        )
        .unwrap();
        let out = status(
            &store,
            &OpFlags::default(),
            Some(UpdatesStatusPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        assert_eq!(out.result["enrolled"], true);
        // The reported fields come straight from parse_cert_info of the PEM.
        let info = greentic_update::tls::parse_cert_info(TEST_CERT_PEM).unwrap();
        assert_eq!(out.result["serial"].as_str().unwrap(), info.serial_hex);
        assert_eq!(
            out.result["not_after_epoch"].as_i64().unwrap(),
            info.not_after_epoch
        );
    }

    #[test]
    fn status_requires_tenant_owner() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = status(
            &store,
            &OpFlags::default(),
            Some(UpdatesStatusPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }
}
