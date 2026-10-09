//! K8s rendering of the telemetry answers (`crate::env_packs::telemetry`).
//!
//! Plain variables go straight into the pod env; the header credential goes
//! into its own Secret and is referenced with an OPTIONAL `secretKeyRef`, the
//! `gtc-oci-credentials` pattern: a single-revision warm ahead of the first
//! full reconcile has not applied env-level Secrets yet and must still boot.
//! Like that Secret, this one is env-level and never pruned — removing the
//! answer stops the pods referencing it, it does not delete the object.

use serde_json::{Value, json};

use super::{K8sParams, common_labels};
use crate::env_packs::telemetry::HEADER_ENV_NAMES;
use greentic_deploy_spec::Environment;

pub const TELEMETRY_HEADERS_SECRET_NAME: &str = "gtc-telemetry-headers";

/// Env entries for one pod role. Empty when no telemetry was answered.
pub(super) fn pod_env(params: &K8sParams, role: &str) -> Vec<Value> {
    let mut vars: Vec<Value> = params
        .telemetry
        .env_for_role(role)
        .into_iter()
        .map(|(name, value)| json!({"name": name, "value": value}))
        .collect();
    if params.telemetry.headers().is_some() {
        for name in HEADER_ENV_NAMES {
            vars.push(json!({
                "name": name,
                "valueFrom": {"secretKeyRef": {
                    "name": TELEMETRY_HEADERS_SECRET_NAME,
                    "key": "headers",
                    "optional": true,
                }},
            }));
        }
    }
    vars
}

pub(super) fn render_headers_secret(env: &Environment, params: &K8sParams) -> Option<Value> {
    let headers = params.telemetry.headers()?;
    Some(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": TELEMETRY_HEADERS_SECRET_NAME,
            "namespace": params.namespace,
            "labels": common_labels(env, "telemetry-headers"),
        },
        "stringData": {"headers": headers.expose()},
    }))
}
