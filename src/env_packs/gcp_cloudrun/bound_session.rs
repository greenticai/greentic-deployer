//! Resolve the GCP deployer's bound credential material for live Cloud Run verbs.
//!
//! The GCP analogue of [`crate::env_packs::aws::bound_session`]:
//! [`crate::cli::secrets::resolve_credentials_token`] is the backend-agnostic
//! base (env-var → dev-store → fail-closed). AWS decodes the bound material into
//! a short-lived [`AssumedSession`](crate::env_packs::aws::credentials::AssumedSession)
//! STS blob; GCP's bound material is instead the **credential JSON**
//! `google-cloud-auth` consumes directly — a service-account key
//! (`"type": "service_account"`) or a Workload-Identity-Federation
//! `external_account` config. This module parses + validates that JSON
//! (fail-closed on anything unparseable or of an unsupported `type`) and turns it
//! into a [`Credentials`] the real target injects into every Cloud Run / Secret
//! Manager client.
//!
//! Precedence: env-var → dev-store → fail closed. A bound ref with no readable
//! (or unparseable) material is an error, never a silent fall-back to the ambient
//! ADC identity — an env that declares a bound credential must not run as the
//! (often broader) ambient identity by accident. When **no** ref is bound the
//! caller falls back to [`ambient_adc_credentials`] (the GCP equivalent of AWS's
//! ambient credential chain).
//!
//! Behind the `deploy-gcp-cloudrun` feature: only the live-deploy path consumes
//! credentials, so — like the AWS `bound_session` — this module compiles with the
//! real target, not the SDK-free `creds-gcp` scaffold.

use google_cloud_auth::credentials::Credentials;
use greentic_deploy_spec::{EnvId, Environment};
use serde_json::Value;

use crate::cli::OpError;
use crate::environment::LocalFsStore;

/// OAuth scope every Cloud Run + Secret Manager call needs. Both APIs accept the
/// coarse `cloud-platform` scope; scoping tighter buys nothing here because the
/// deployer SA's IAM roles are the real authorization boundary.
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The shape of a bound GCP credential, keyed off the JSON `type` discriminator
/// `google-cloud-auth` itself dispatches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GcpCredentialKind {
    /// A downloaded service-account key (`"type": "service_account"`).
    ServiceAccount,
    /// A Workload-Identity-Federation config (`"type": "external_account"`).
    ExternalAccount,
}

/// Parsed, validated bound credential material for the GCP deployer.
///
/// Holds the raw JSON `google-cloud-auth` consumes plus the caller-identity
/// fields worth surfacing (`client_email` / `project_id`, present on a
/// service-account key). Build the live [`Credentials`] with
/// [`build_credentials`](Self::build_credentials).
#[derive(Debug, Clone)]
pub struct GcpCredentialMaterial {
    raw: Value,
    kind: GcpCredentialKind,
    /// The principal email, when the material is a service-account key. Absent
    /// for `external_account` (its principal is the federated subject).
    pub client_email: Option<String>,
    /// The credential's own project, when present on the JSON.
    pub project_id: Option<String>,
}

impl GcpCredentialMaterial {
    /// Parse bound material into a validated credential. Fail-closed: material
    /// that is not JSON, or whose `type` is neither `service_account` nor
    /// `external_account`, is rejected (re-bind / rotate) rather than silently
    /// treated as the ambient identity.
    fn parse(env_id: &EnvId, material: &str) -> Result<Self, OpError> {
        let raw: Value = serde_json::from_str(material).map_err(|e| bad_material(env_id, &e))?;
        let kind = match raw.get("type").and_then(Value::as_str) {
            Some("service_account") => GcpCredentialKind::ServiceAccount,
            Some("external_account") => GcpCredentialKind::ExternalAccount,
            other => {
                return Err(OpError::Conflict(format!(
                    "environment `{}` has a bound deployer credential, but its `type` is {}; \
                     expected a GCP service-account key (`service_account`) or a Workload Identity \
                     Federation config (`external_account`); re-bind the deployer credential \
                     (`op env bootstrap --bind`) or refresh it (`op credentials rotate`)",
                    env_id.as_str(),
                    match other {
                        Some(t) => format!("`{t}`"),
                        None => "missing".to_string(),
                    }
                )));
            }
        };
        let client_email = raw
            .get("client_email")
            .and_then(Value::as_str)
            .map(str::to_string);
        let project_id = raw
            .get("project_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(Self {
            raw,
            kind,
            client_email,
            project_id,
        })
    }

    /// Build the live `google-cloud-auth` [`Credentials`] from this material.
    /// Fail-closed on unparseable/invalid key JSON (the `type` was validated at
    /// [`parse`](Self::parse), but the SDK re-validates the full key here).
    pub fn build_credentials(&self) -> Result<Credentials, String> {
        match self.kind {
            GcpCredentialKind::ServiceAccount => {
                google_cloud_auth::credentials::service_account::Builder::new(self.raw.clone())
                    .build()
                    .map_err(|e| format!("bound service-account key is not usable: {e}"))
            }
            GcpCredentialKind::ExternalAccount => {
                google_cloud_auth::credentials::external_account::Builder::new(self.raw.clone())
                    .with_scopes([CLOUD_PLATFORM_SCOPE])
                    .build()
                    .map_err(|e| format!("bound external-account config is not usable: {e}"))
            }
        }
    }
}

/// Resolve `env.credentials_ref` to bound GCP credential material for a live
/// Cloud Run verb.
///
/// - `Ok(None)` — no `credentials_ref` is bound; the caller uses
///   [`ambient_adc_credentials`] (`GOOGLE_APPLICATION_CREDENTIALS` / gcloud ADC /
///   the metadata server).
/// - `Ok(Some(material))` — the ref resolved to a valid credential JSON.
/// - `Err(Conflict)` — a ref is bound but the material is missing (from the base
///   resolver) or not a valid GCP credential.
pub fn resolve_bound_credentials(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
) -> Result<Option<GcpCredentialMaterial>, OpError> {
    match crate::cli::secrets::resolve_credentials_token(store, env, env_id)? {
        None => Ok(None),
        Some(material) => Ok(Some(GcpCredentialMaterial::parse(env_id, &material)?)),
    }
}

/// Build ambient Application Default Credentials — the fall-back when no
/// `credentials_ref` is bound. Walks `GOOGLE_APPLICATION_CREDENTIALS`, the gcloud
/// ADC well-known file, then the metadata server, exactly like the rest of the
/// google-cloud tooling.
pub fn ambient_adc_credentials() -> Result<Credentials, String> {
    google_cloud_auth::credentials::Builder::default()
        .with_scopes([CLOUD_PLATFORM_SCOPE])
        .build()
        .map_err(|e| format!("no usable GCP Application Default Credentials resolved: {e}"))
}

/// Bound material that is not valid JSON is fail-closed (re-bind / rotate), not a
/// silent ambient fall-back.
fn bad_material(env_id: &EnvId, err: &serde_json::Error) -> OpError {
    OpError::Conflict(format!(
        "environment `{}` has a bound deployer credential, but its material is not valid GCP \
         credential JSON: {err}; re-bind the deployer credential (`op env bootstrap --bind`) or \
         refresh it (`op credentials rotate`)",
        env_id.as_str()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::EnvironmentStore;
    use tempfile::tempdir;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn service_account_key() -> String {
        serde_json::json!({
            "type": "service_account",
            "project_id": "greentic-local",
            "private_key_id": "abc",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----\n",
            "client_email": "gtc-local-deployer@greentic-local.iam.gserviceaccount.com",
            "client_id": "123",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string()
    }

    #[test]
    fn no_bound_ref_resolves_to_none() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local"); // no credentials_ref
        store.save(&env).unwrap();
        // No ref bound → ambient. MUST be `None`, never a fabricated credential.
        assert!(
            resolve_bound_credentials(&store, &env, &env_id())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn service_account_key_parses_and_extracts_identity() {
        let material = GcpCredentialMaterial::parse(&env_id(), &service_account_key()).unwrap();
        assert_eq!(material.kind, GcpCredentialKind::ServiceAccount);
        assert_eq!(
            material.client_email.as_deref(),
            Some("gtc-local-deployer@greentic-local.iam.gserviceaccount.com")
        );
        assert_eq!(material.project_id.as_deref(), Some("greentic-local"));
    }

    #[test]
    fn external_account_config_parses_without_email() {
        let json = serde_json::json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": { "file": "/var/run/token" },
        })
        .to_string();
        let material = GcpCredentialMaterial::parse(&env_id(), &json).unwrap();
        assert_eq!(material.kind, GcpCredentialKind::ExternalAccount);
        assert!(material.client_email.is_none());
    }

    #[test]
    fn unparseable_material_is_fail_closed() {
        let err = GcpCredentialMaterial::parse(&env_id(), "not json").unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(msg.contains("not valid GCP credential JSON"), "{msg}")
            }
            other => panic!("expected Conflict, got {other}"),
        }
    }

    #[test]
    fn unsupported_credential_type_is_fail_closed() {
        let json = serde_json::json!({ "type": "authorized_user", "client_id": "x" }).to_string();
        let err = GcpCredentialMaterial::parse(&env_id(), &json).unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("`authorized_user`"), "{msg}"),
            other => panic!("expected Conflict, got {other}"),
        }
    }

    #[test]
    fn missing_type_is_fail_closed() {
        let json = serde_json::json!({ "client_email": "x@y.iam.gserviceaccount.com" }).to_string();
        let err = GcpCredentialMaterial::parse(&env_id(), &json).unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("missing"), "{msg}"),
            other => panic!("expected Conflict, got {other}"),
        }
    }
}
