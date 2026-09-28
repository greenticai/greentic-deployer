//! Optional managed Ingress in front of the env's router (answers
//! `ingress_host`, `ingress_class`, `ingress_tls_secret`,
//! `ingress_cert_manager_issuer`).
//!
//! Absent answers render NOTHING: no object is added and no existing object
//! changes, so an env that never answers these keys renders byte-for-byte
//! what it rendered before they existed (pinned by
//! `unanswered_ingress_keeps_the_rendered_set_byte_identical`).
//!
//! When `ingress_host` is set the pack renders one `networking.k8s.io/v1`
//! Ingress named [`ROUTER_NAME`] routing `<host>/` to the router Service on
//! port 8080. The router — never a worker Service — is the backend, because
//! the router is what enforces the env's traffic split.
//!
//! TLS is one of three modes, never two at once:
//! - none: plain HTTP, `public_base_url` = `http://<host>`;
//! - `ingress_tls_secret`: the operator's own `kubernetes.io/tls` Secret;
//! - `ingress_cert_manager_issuer`: a cert-manager `ClusterIssuer` mints the
//!   certificate into [`INGRESS_TLS_SECRET_NAME`] via the
//!   `cert-manager.io/cluster-issuer` annotation.
//!
//! Like the other env-level objects, the Ingress is NEVER pruned: removing
//! the answers stops rendering it, it does not delete the object.

use serde_json::{Map, Value, json};

use super::{K8sParams, ROUTER_NAME, SERVE_PORT, answer_string, common_labels};
use greentic_deploy_spec::Environment;

/// Answer keys this module owns; `K8sParams::from_answers` admits them.
pub(super) const INGRESS_ANSWER_KEYS: &[&str] = &[
    "ingress_class",
    "ingress_host",
    "ingress_tls_secret",
    "ingress_cert_manager_issuer",
];

/// Secret cert-manager writes the certificate into when
/// `ingress_cert_manager_issuer` is answered. Reserved: no other answer may
/// name a Secret the same.
pub const INGRESS_TLS_SECRET_NAME: &str = "gtc-router-tls";

/// cert-manager's ingress-shim annotation naming a cluster-scoped issuer.
const CERT_MANAGER_CLUSTER_ISSUER_ANNOTATION: &str = "cert-manager.io/cluster-issuer";

/// How the Ingress terminates TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressTls {
    /// No TLS block — the host is served over plain HTTP.
    None,
    /// The operator's own `kubernetes.io/tls` Secret, by name.
    Secret(String),
    /// cert-manager `ClusterIssuer` name; the certificate lands in
    /// [`INGRESS_TLS_SECRET_NAME`].
    CertManager(String),
}

/// Parsed, validated Ingress answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressConfig {
    /// `spec.ingressClassName`; `None` → the cluster's default class.
    pub class: Option<String>,
    /// The public hostname (lowercased DNS name, at least two labels).
    pub host: String,
    pub tls: IngressTls,
}

impl IngressConfig {
    /// The URL the Ingress serves the router at: `https://<host>` with TLS,
    /// `http://<host>` without.
    pub fn public_base_url(&self) -> String {
        let scheme = match self.tls {
            IngressTls::None => "http",
            IngressTls::Secret(_) | IngressTls::CertManager(_) => "https",
        };
        format!("{scheme}://{}", self.host)
    }

    /// The Secret name carried in `spec.tls[].secretName`, if any.
    fn tls_secret_name(&self) -> Option<&str> {
        match &self.tls {
            IngressTls::None => None,
            IngressTls::Secret(name) => Some(name),
            IngressTls::CertManager(_) => Some(INGRESS_TLS_SECRET_NAME),
        }
    }
}

/// Parse the four Ingress answers. `Ok(None)` when none is answered.
///
/// Refuses: a class / TLS answer without `ingress_host`; both TLS modes at
/// once; a host that is not a lowercase DNS name with at least two labels
/// (wildcards and IP literals included); a class, Secret or issuer name that
/// is not a DNS-1123 subdomain; a TLS Secret named like an object this pack
/// already renders (`reserved`).
pub(super) fn parse(
    obj: &Map<String, Value>,
    reserved: &[&str],
) -> Result<Option<IngressConfig>, String> {
    let host = answer_string(obj, "ingress_host").map(|h| h.trim().to_ascii_lowercase());
    let class = answer_string(obj, "ingress_class");
    let tls_secret = answer_string(obj, "ingress_tls_secret");
    let issuer = answer_string(obj, "ingress_cert_manager_issuer");

    let Some(host) = host.filter(|h| !h.is_empty()) else {
        if class.is_some() || tls_secret.is_some() || issuer.is_some() {
            return Err(
                "ingress_host is required when ingress_class, ingress_tls_secret or \
                 ingress_cert_manager_issuer is set"
                    .to_string(),
            );
        }
        return Ok(None);
    };
    if !is_public_hostname(&host) {
        return Err(format!(
            "ingress_host `{host}` is not a valid DNS name (lowercase labels, at least \
             two of them, no wildcard, no IP address)"
        ));
    }
    if let Some(class) = &class
        && !is_dns1123_subdomain(class)
    {
        return Err(format!(
            "ingress_class `{class}` is not a valid Kubernetes object name"
        ));
    }
    let tls = match (tls_secret, issuer) {
        (Some(_), Some(_)) => {
            return Err(
                "ingress_tls_secret and ingress_cert_manager_issuer are mutually exclusive \
                 — name your own TLS Secret OR let cert-manager issue one, not both"
                    .to_string(),
            );
        }
        (Some(secret), None) => {
            if !is_dns1123_subdomain(&secret) {
                return Err(format!(
                    "ingress_tls_secret `{secret}` is not a valid Kubernetes Secret name"
                ));
            }
            if reserved.contains(&secret.as_str()) {
                return Err(format!(
                    "ingress_tls_secret `{secret}` collides with an object this pack already \
                     renders into the same namespace — choose a different name"
                ));
            }
            IngressTls::Secret(secret)
        }
        (None, Some(issuer)) => {
            if !is_dns1123_subdomain(&issuer) {
                return Err(format!(
                    "ingress_cert_manager_issuer `{issuer}` is not a valid ClusterIssuer name"
                ));
            }
            IngressTls::CertManager(issuer)
        }
        (None, None) => IngressTls::None,
    };
    Ok(Some(IngressConfig { class, host, tls }))
}

/// The Ingress, or `None` when `ingress_host` was not answered.
pub(super) fn render(env: &Environment, params: &K8sParams) -> Option<Value> {
    let ingress = params.ingress.as_ref()?;
    let mut metadata = json!({
        "name": ROUTER_NAME,
        "namespace": params.namespace,
        "labels": common_labels(env, "router-ingress"),
    });
    if let IngressTls::CertManager(issuer) = &ingress.tls {
        metadata["annotations"] = json!({ CERT_MANAGER_CLUSTER_ISSUER_ANNOTATION: issuer });
    }
    let mut spec = Map::new();
    if let Some(class) = &ingress.class {
        spec.insert("ingressClassName".into(), json!(class));
    }
    if let Some(secret) = ingress.tls_secret_name() {
        spec.insert(
            "tls".into(),
            json!([{ "hosts": [ingress.host], "secretName": secret }]),
        );
    }
    spec.insert(
        "rules".into(),
        json!([{
            "host": ingress.host,
            "http": { "paths": [{
                "path": "/",
                "pathType": "Prefix",
                "backend": { "service": {
                    "name": ROUTER_NAME,
                    "port": { "number": SERVE_PORT },
                }},
            }]},
        }]),
    );
    Some(json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": metadata,
        "spec": spec,
    }))
}

/// `public_base_url` for the reconcile report: `Some` only when the answers
/// configure an Ingress. Invalid answers yield `None` — the reconcile that
/// produced the report already refused them.
pub fn public_base_url_from_answers(env: &Environment, answers: Option<&Value>) -> Option<String> {
    K8sParams::from_answers(env, answers)
        .ok()?
        .ingress
        .map(|i| i.public_base_url())
}

/// DNS-1123 subdomain: dot-separated DNS-1123 labels, ≤ 253 chars.
fn is_dns1123_subdomain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.split('.').all(super::is_dns1123_label)
}

/// A public hostname: a DNS-1123 subdomain with at least two labels whose
/// last label is not all digits (so `10.0.0.1` is refused).
fn is_public_hostname(s: &str) -> bool {
    is_dns1123_subdomain(s)
        && s.contains('.')
        && s.rsplit('.')
            .next()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
#[path = "ingress_tests.rs"]
mod tests;
