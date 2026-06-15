//! Deterministic Kubernetes manifest rendering for the K8s deployer
//! env-pack (Phase D plan §6 steps 4/5/10/11).
//!
//! Pure functions: structured input ([`Environment`] + [`K8sParams`]) →
//! `serde_json::Value` manifests. No I/O, no clock, no cluster — the same
//! AWS-bootstrap precedent (`render_min_iam_rules_pack`) applied to the
//! K8s desired state. `gtc op env render` (follow-up PR) writes these to
//! disk; the [`Deployer`](super::deployer) verbs hand them to the
//! [`K8sCluster`](super::cluster::K8sCluster) seam.
//!
//! ## Runtime shape (plan §6 step 4/5, Zain v1)
//!
//! - One stable, HA **router** Deployment (≥2 replicas, PDB,
//!   topology-spread) receives all ingress for the env; the Gateway /
//!   Ingress (Zain's choice, Q4) sends 100% of matching traffic to the
//!   stable router Service. Provider-native revision weighting is
//!   deferred to Phase E.
//! - One **worker** Deployment + ClusterIP Service per revision, labeled
//!   `greentic.ai/revision: <ULID>`. The router resolves the deployment,
//!   applies the authoritative `TrafficSplit` from the runtime-config
//!   projection, and dispatches to the selected revision's Service.
//! - The `TrafficSplit` projection rides a ConfigMap
//!   ([`render_runtime_config_map`]) embedding the exact
//!   [`materialize_runtime_config`] output — `apply_traffic_split` is a
//!   ConfigMap upsert, never a `kubectl rollout`.
//!
//! ## Hardening (plan §6 step 11)
//!
//! Every pod spec rendered here passes the Restricted Pod Security
//! profile: non-root (`65532`), no privilege escalation, read-only root
//! filesystem, all capabilities dropped, `RuntimeDefault` seccomp,
//! resource requests/limits (S2 sandbox baseline: `250m/256Mi` requests,
//! `1/1Gi` limits). NetworkPolicies are default-deny with an explicit
//! allow-list (S3). Image digest-pinning is the operator's input
//! ([`K8sParams::runtime_image`]) — the sandbox default is a tag ref;
//! production acceptance requires a digest-pinned ref (the wizard
//! records it; the ship gate verifies it).
//!
//! ## Determinism
//!
//! All objects are built with fixed key order and serialize identically
//! for identical inputs (`serde_json`'s default map is ordered); a unit
//! test pins render-twice equality. Names are RFC 1123 labels: revision
//! ULIDs are lowercased for object NAMES (`gtc-worker-<ulid>`) but kept
//! uppercase in label VALUES (`greentic.ai/revision: <ULID>`) to match
//! the spec's canonical ULID rendering.

use greentic_deploy_spec::{EnvId, Environment, Revision};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::environment::runtime_config::materialize_runtime_config;

/// Sandbox-default runtime image (S1). Tag-pinned for the sandbox only —
/// production requires a digest-pinned ref supplied via the env-pack
/// wizard (`runtime_image`).
pub const DEFAULT_RUNTIME_IMAGE: &str = "ghcr.io/greenticai/greentic-start-distroless:latest";

/// Stable name of the router Deployment / Service / PDB.
pub const ROUTER_NAME: &str = "gtc-router";

/// Name of the runtime-config ConfigMap the router consumes.
pub const RUNTIME_CONFIG_MAP_NAME: &str = "gtc-runtime-config";

/// Port every Greentic pod serves on; Services expose the same port.
const SERVE_PORT: u16 = 8080;

/// Operator-tunable knobs for the rendered manifests.
///
/// [`K8sParams::for_env`] derives the sandbox defaults from the env
/// alone. [`K8sParams::from_answers`] overlays the binding's recorded
/// wizard answers (namespace, runtime image, router replicas) on top of
/// those defaults — `op env render` calls this path. The Deployer verbs
/// still use `for_env` until the PR-5.3 orchestration wiring threads
/// answers into them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sParams {
    /// Namespace every rendered object lands in. One namespace per
    /// `(tenant, environment)` pair (Q6 preferred pattern).
    pub namespace: String,
    /// Container image for router and worker pods.
    pub runtime_image: String,
    /// Router replica count. Plan step 11 mandates ≥ 2 for HA.
    pub router_replicas: u32,
}

impl K8sParams {
    /// Sandbox defaults: namespace `gtc-<env-id>`, the S1 default image,
    /// two router replicas.
    pub fn for_env(env: &Environment) -> Self {
        Self {
            namespace: namespace_for_env(&env.environment_id),
            runtime_image: DEFAULT_RUNTIME_IMAGE.to_string(),
            router_replicas: 2,
        }
    }

    /// Build params from the deployer binding's recorded wizard answers.
    ///
    /// `answers` is the flat JSON object keyed by wizard question id (the
    /// ecosystem's qa-spec answers convention). `None` (or an object with
    /// all relevant keys unset / blank) falls back to sandbox defaults —
    /// wizard questions are optional.
    ///
    /// Validation:
    /// - `namespace`: valid RFC 1123 label (used verbatim — the wizard
    ///   says it must match the namespace the bootstrap rules pack
    ///   provisioned). `null` / empty-string → default.
    /// - `runtime_image`: non-empty string matching `[a-z0-9.\-_/:@]+`.
    ///   `null` / empty-string → default.
    /// - `router_replicas`: JSON string or number parsed to `u32`; must
    ///   be >= 2 (the router must stay HA). `null` / empty-string →
    ///   default.
    /// - `kubeconfig_context`: silently accepted and ignored (client-
    ///   targeting knob, not a manifest knob — consumed by
    ///   [`kube_client::connect`](super::kube_client::connect)).
    /// - Any other key → `Err` (fail closed on wizard version skew or
    ///   typos).
    pub fn from_answers(
        env: &Environment,
        answers: Option<&serde_json::Value>,
    ) -> Result<Self, String> {
        let Some(answers) = answers else {
            return Ok(Self::for_env(env));
        };
        let obj = answers
            .as_object()
            .ok_or_else(|| "answers must be a JSON object".to_string())?;

        let defaults = Self::for_env(env);

        // Reject unknown keys first (fail closed on version skew).
        const KNOWN_KEYS: &[&str] = &[
            "kubeconfig_context",
            "namespace",
            "runtime_image",
            "router_replicas",
        ];
        for key in obj.keys() {
            if !KNOWN_KEYS.contains(&key.as_str()) {
                return Err(format!("unknown answer key `{key}`"));
            }
        }

        let namespace = match answer_string(obj, "namespace") {
            Some(ns) => {
                if !is_dns1123_label(&ns) {
                    return Err(format!("namespace `{ns}` is not a valid RFC 1123 label"));
                }
                ns
            }
            None => defaults.namespace,
        };

        let runtime_image = match answer_string(obj, "runtime_image") {
            Some(img) => {
                if !img
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_/:@".contains(&b))
                {
                    return Err(format!("runtime_image `{img}` contains invalid characters"));
                }
                img
            }
            None => defaults.runtime_image,
        };

        let router_replicas = match obj.get("router_replicas") {
            None | Some(serde_json::Value::Null) => defaults.router_replicas,
            Some(v) => {
                let n: u32 = match v {
                    serde_json::Value::String(s) if s.is_empty() => defaults.router_replicas,
                    serde_json::Value::String(s) => s
                        .parse::<u32>()
                        .map_err(|e| format!("router_replicas `{s}` is not a valid u32: {e}"))?,
                    serde_json::Value::Number(n) => n
                        .as_u64()
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or_else(|| format!("router_replicas `{n}` is not a valid u32"))?,
                    _ => {
                        return Err(format!(
                            "router_replicas must be a string or number, got {v}"
                        ));
                    }
                };
                if n < 2 {
                    return Err(format!(
                        "router_replicas must be >= 2 (HA requirement), got {n}"
                    ));
                }
                n
            }
        };

        // kubeconfig_context: silently accepted and ignored.

        Ok(Self {
            namespace,
            runtime_image,
            router_replicas,
        })
    }
}

/// Extract a non-empty string answer, treating JSON `null` and empty
/// strings as "left blank in the wizard" (unset).
fn answer_string(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) if s.is_empty() => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

/// Check whether `s` is a valid RFC 1123 DNS label: lowercase
/// alphanumeric + `-`, no leading/trailing `-`, length 1..=63.
pub fn is_dns1123_label(s: &str) -> bool {
    let len = s.len();
    if len == 0 || len > 63 {
        return false;
    }
    if s.starts_with('-') || s.ends_with('-') {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Default namespace for an env, derived from the env id.
///
/// Clean ids (already `[a-z0-9-]`, no leading/trailing `-`, and
/// `"gtc-" + id` fits in 63 chars) stay friendly: `gtc-<id>`.
/// Otherwise (any lossy character mapping or overflow) the namespace
/// gets a stable content-hash suffix: `gtc-<sanitized-prefix>-<hash8>`
/// where `hash8` = first 8 hex chars of SHA-256 over the RAW env id
/// string. Two distinct env ids can therefore never collide — the hash
/// discriminates when the sanitized form is ambiguous.
///
/// Env ids are unique per store, so hashing the env id alone suffices.
/// Cross-store collisions on one shared cluster are a production-
/// acceptance concern, out of scaffold scope.
pub fn namespace_for_env(env_id: &EnvId) -> String {
    let raw = env_id.as_str();
    let prefix = "gtc-";

    // Fast path: if the raw id is already clean RFC 1123 and fits, use
    // the friendly form directly — no hash needed.
    let is_clean = !raw.is_empty()
        && raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !raw.starts_with('-')
        && !raw.ends_with('-')
        && (prefix.len() + raw.len()) <= 63;

    if is_clean {
        return format!("{prefix}{raw}");
    }

    // Slow path: lossy/truncated derivation — append a content hash so
    // distinct env ids that sanitize identically still get unique
    // namespaces.
    let hash8 = {
        let digest = Sha256::digest(raw.as_bytes());
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        )
    };

    let sanitized = sanitize_dns1123_label(raw);
    if sanitized.is_empty() {
        // Degenerate ids (e.g. `...`) — the sanitized form is empty.
        return format!("{prefix}{hash8}");
    }

    // Truncate the sanitized prefix so `gtc-<prefix>-<hash8>` ≤ 63.
    // Layout: "gtc-" (4) + prefix + "-" (1) + hash8 (8) = 13 + prefix.
    let max_prefix_len = 63 - prefix.len() - 1 - hash8.len(); // 63 - 4 - 1 - 8 = 50
    let truncated = if sanitized.len() > max_prefix_len {
        sanitized[..max_prefix_len].trim_end_matches('-')
    } else {
        &sanitized
    };

    if truncated.is_empty() {
        format!("{prefix}{hash8}")
    } else {
        format!("{prefix}{truncated}-{hash8}")
    }
}

/// Name of a revision's worker Deployment AND Service (same name, two
/// kinds). ULIDs are Crockford base32 (uppercase alphanumerics), so the
/// lowercased form is a valid RFC 1123 label and stays unique.
pub fn worker_name(revision: &Revision) -> String {
    format!(
        "gtc-worker-{}",
        revision.revision_id.0.to_string().to_lowercase()
    )
}

/// Coerce a string into an RFC 1123 label fragment: lowercase,
/// `[a-z0-9-]` only (other characters map to `-`), no leading or
/// trailing `-`. Does NOT truncate — callers control length budgets.
/// Returns an empty string for degenerate inputs (all-separator).
fn sanitize_dns1123_label(raw: &str) -> String {
    let s: String = raw
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    s.trim_matches('-').to_string()
}

/// Label key identifying the owning environment, stamped on every
/// rendered object by `common_labels`. The kube client's ownership
/// guard reads it back — they MUST share this constant so a rename can't
/// silently turn the guard into a no-op.
pub const ENV_LABEL: &str = "greentic.ai/env";

/// Shared labels stamped on every object the env-pack renders.
fn common_labels(env: &Environment, component: &str) -> Value {
    let mut labels = json!({
        "app.kubernetes.io/managed-by": "greentic",
        "app.kubernetes.io/component": component,
    });
    labels[ENV_LABEL] = json!(env.environment_id.as_str());
    labels
}

/// Worker pod selector labels: the revision ULID is the identity (plan
/// step 4: `greentic.ai/revision: <ULID>`).
fn worker_selector_labels(env: &Environment, revision: &Revision) -> Value {
    let mut labels = common_labels(env, "worker");
    let map = labels.as_object_mut().expect("labels are an object");
    map.insert(
        "greentic.ai/revision".into(),
        json!(revision.revision_id.0.to_string()),
    );
    map.insert(
        "greentic.ai/deployment".into(),
        json!(revision.deployment_id.0.to_string()),
    );
    map.insert(
        "greentic.ai/bundle".into(),
        json!(revision.bundle_id.as_str()),
    );
    labels
}

/// Restricted-profile pod security context (step 11): non-root distroless
/// uid, RuntimeDefault seccomp.
fn pod_security_context() -> Value {
    json!({
        "runAsNonRoot": true,
        "runAsUser": 65532,
        "runAsGroup": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    })
}

/// Restricted-profile container security context + S2 resource baseline.
fn container_security_context() -> Value {
    json!({
        "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true,
        "capabilities": {"drop": ["ALL"]},
    })
}

fn resource_baseline() -> Value {
    json!({
        "requests": {"cpu": "250m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    })
}

/// The env's Namespace object. Rendered for `op env render` and the
/// bootstrap rules pack; whether Greentic or the customer's platform team
/// applies it is the Q6 ownership decision.
pub fn render_namespace(env: &Environment, params: &K8sParams) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": params.namespace,
            "labels": common_labels(env, "namespace"),
        },
    })
}

/// One revision's worker Deployment (plan step 4).
///
/// The pod carries its full revision identity as environment variables
/// (`GREENTIC_ENV_ID` / `GREENTIC_REVISION_ID` / `GREENTIC_DEPLOYMENT_ID`
/// / `GREENTIC_BUNDLE_ID` / `GREENTIC_BUNDLE_DIGEST`) so the runtime
/// entrypoint can resolve and verify its bundle. Bundle DELIVERY into the
/// pod (distributor-pull init container vs. baked image) is decided in
/// PR-5.3; the identity contract here is delivery-agnostic.
///
/// Readiness probes `/healthz` today; the per-revision
/// `/healthz/<revision_id>` route is the acceptance-gate target once
/// `greentic-start` serves it.
pub fn render_worker_deployment(
    env: &Environment,
    revision: &Revision,
    params: &K8sParams,
) -> Value {
    let labels = worker_selector_labels(env, revision);
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": worker_name(revision),
            "namespace": params.namespace,
            "labels": labels,
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {
                "greentic.ai/revision": revision.revision_id.0.to_string(),
            }},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "securityContext": pod_security_context(),
                    "containers": [{
                        "name": "worker",
                        "image": params.runtime_image,
                        "securityContext": container_security_context(),
                        "resources": resource_baseline(),
                        "ports": [{"name": "http", "containerPort": SERVE_PORT}],
                        "env": [
                            {"name": "GREENTIC_ENV_ID", "value": env.environment_id.as_str()},
                            {"name": "GREENTIC_REVISION_ID", "value": revision.revision_id.0.to_string()},
                            {"name": "GREENTIC_DEPLOYMENT_ID", "value": revision.deployment_id.0.to_string()},
                            {"name": "GREENTIC_BUNDLE_ID", "value": revision.bundle_id.as_str()},
                            {"name": "GREENTIC_BUNDLE_DIGEST", "value": revision.bundle_digest},
                        ],
                        "readinessProbe": {
                            "httpGet": {"path": "/healthz", "port": SERVE_PORT},
                            "initialDelaySeconds": 2,
                            "periodSeconds": 5,
                        },
                    }],
                },
            },
        },
    })
}

/// One revision's ClusterIP Service — the stable address the router
/// dispatches that revision's traffic to.
pub fn render_worker_service(env: &Environment, revision: &Revision, params: &K8sParams) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": worker_name(revision),
            "namespace": params.namespace,
            "labels": worker_selector_labels(env, revision),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": {
                "greentic.ai/revision": revision.revision_id.0.to_string(),
            },
            "ports": [{"name": "http", "port": SERVE_PORT, "targetPort": SERVE_PORT}],
        },
    })
}

/// Both worker objects for a revision, in apply order (Deployment first,
/// then Service). What [`Deployer::warm_revision`](super::deployer)
/// applies and [`Deployer::archive_revision`](super::deployer) deletes.
pub fn render_worker_manifests(
    env: &Environment,
    revision: &Revision,
    params: &K8sParams,
) -> Vec<Value> {
    vec![
        render_worker_deployment(env, revision, params),
        render_worker_service(env, revision, params),
    ]
}

/// The stable router Deployment (plan step 5): ≥2 replicas, topology
/// spread, runtime-config ConfigMap mounted read-only. The router is
/// authoritative for `TrafficSplit` enforcement in the Zain v1 pilot.
pub fn render_router_deployment(env: &Environment, params: &K8sParams) -> Value {
    let labels = common_labels(env, "router");
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": ROUTER_NAME,
            "namespace": params.namespace,
            "labels": labels,
        },
        "spec": {
            "replicas": params.router_replicas,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "securityContext": pod_security_context(),
                    "topologySpreadConstraints": [{
                        "maxSkew": 1,
                        "topologyKey": "kubernetes.io/hostname",
                        "whenUnsatisfiable": "ScheduleAnyway",
                        "labelSelector": {"matchLabels": labels},
                    }],
                    "containers": [{
                        "name": "router",
                        "image": params.runtime_image,
                        "securityContext": container_security_context(),
                        "resources": resource_baseline(),
                        "ports": [{"name": "http", "containerPort": SERVE_PORT}],
                        "env": [
                            {"name": "GREENTIC_ENV_ID", "value": env.environment_id.as_str()},
                            {
                                "name": "GREENTIC_RUNTIME_CONFIG",
                                "value": "/etc/greentic/runtime-config/runtime-config.json",
                            },
                        ],
                        "volumeMounts": [{
                            "name": "runtime-config",
                            "mountPath": "/etc/greentic/runtime-config",
                            "readOnly": true,
                        }],
                        "readinessProbe": {
                            "httpGet": {"path": "/healthz", "port": SERVE_PORT},
                            "initialDelaySeconds": 2,
                            "periodSeconds": 5,
                        },
                    }],
                    "volumes": [{
                        "name": "runtime-config",
                        "configMap": {"name": RUNTIME_CONFIG_MAP_NAME},
                    }],
                },
            },
        },
    })
}

/// The stable router Service — the single target the Gateway / Ingress
/// routes 100% of the env's traffic to.
pub fn render_router_service(env: &Environment, params: &K8sParams) -> Value {
    let labels = common_labels(env, "router");
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": ROUTER_NAME,
            "namespace": params.namespace,
            "labels": labels,
        },
        "spec": {
            "type": "ClusterIP",
            "selector": labels,
            "ports": [{"name": "http", "port": SERVE_PORT, "targetPort": SERVE_PORT}],
        },
    })
}

/// Router PodDisruptionBudget (step 11): voluntary disruptions keep at
/// least one router serving.
pub fn render_router_pdb(env: &Environment, params: &K8sParams) -> Value {
    let labels = common_labels(env, "router");
    json!({
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {
            "name": ROUTER_NAME,
            "namespace": params.namespace,
            "labels": labels,
        },
        "spec": {
            "minAvailable": 1,
            "selector": {"matchLabels": labels},
        },
    })
}

/// The runtime-config ConfigMap: the env's `TrafficSplit` projection
/// (exactly [`materialize_runtime_config`]) as `runtime-config.json`.
/// `apply_traffic_split` upserts this object; the router reloads it and
/// enforces the split in-process.
pub fn render_runtime_config_map(env: &Environment, params: &K8sParams) -> Value {
    let runtime_config = materialize_runtime_config(env);
    let payload = serde_json::to_string(&runtime_config)
        .expect("runtime-config projection serializes (pure spec types)");
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": RUNTIME_CONFIG_MAP_NAME,
            "namespace": params.namespace,
            "labels": common_labels(env, "router"),
        },
        "data": {"runtime-config.json": payload},
    })
}

/// Default-deny + allow-list NetworkPolicies (S3): deny everything, then
/// allow DNS egress for all pods, ingress→router on the serve port (the
/// Gateway/Ingress data-plane peer is refined per Q4), router→worker on
/// the serve port, and worker ingress from the router only.
pub fn render_network_policies(env: &Environment, params: &K8sParams) -> Vec<Value> {
    let router_labels = common_labels(env, "router");
    let worker_component = json!({"app.kubernetes.io/component": "worker"});
    let dns_ports = json!([
        {"protocol": "UDP", "port": 53},
        {"protocol": "TCP", "port": 53},
    ]);
    vec![
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "gtc-default-deny",
                "namespace": params.namespace,
                "labels": common_labels(env, "network-policy"),
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
            },
        }),
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "gtc-allow-dns",
                "namespace": params.namespace,
                "labels": common_labels(env, "network-policy"),
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [{"ports": dns_ports}],
            },
        }),
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "gtc-allow-router",
                "namespace": params.namespace,
                "labels": common_labels(env, "network-policy"),
            },
            "spec": {
                "podSelector": {"matchLabels": router_labels},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"ports": [{"protocol": "TCP", "port": SERVE_PORT}]}],
                "egress": [{
                    "to": [{"podSelector": {"matchLabels": worker_component}}],
                    "ports": [{"protocol": "TCP", "port": SERVE_PORT}],
                }],
            },
        }),
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "gtc-allow-workers",
                "namespace": params.namespace,
                "labels": common_labels(env, "network-policy"),
            },
            "spec": {
                "podSelector": {"matchLabels": worker_component},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": json!({
                        "app.kubernetes.io/component": "router",
                    })}}],
                    "ports": [{"protocol": "TCP", "port": SERVE_PORT}],
                }],
            },
        }),
    ]
}

/// Every environment-level object, in apply order: Namespace, runtime
/// ConfigMap (the router mounts it — must exist first), router
/// Deployment + Service + PDB, NetworkPolicies. Per-revision worker
/// objects are NOT included — they ride the revision lifecycle verbs.
/// `gtc op env render` emits this set (plus present-revision workers)
/// through the [`ManifestRenderer`](crate::env_packs::render::ManifestRenderer)
/// impl in [`super::render`].
pub fn render_environment_manifests(env: &Environment, params: &K8sParams) -> Vec<Value> {
    let mut manifests = vec![
        render_namespace(env, params),
        render_runtime_config_map(env, params),
        render_router_deployment(env, params),
        render_router_service(env, params),
        render_router_pdb(env, params),
    ];
    manifests.extend(render_network_policies(env, params));
    manifests
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    fn fixture() -> (Environment, K8sParams) {
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        (env, params)
    }

    #[test]
    fn params_for_env_derive_sandbox_defaults() {
        let (env, params) = fixture();
        assert_eq!(params.namespace, format!("gtc-{}", env.environment_id));
        assert_eq!(params.runtime_image, DEFAULT_RUNTIME_IMAGE);
        assert_eq!(params.router_replicas, 2, "plan step 11: router HA ≥ 2");
    }

    #[test]
    fn sanitize_dns1123_label_handles_env_id_charset() {
        // EnvId permits uppercase, `.` and `_` — namespaces do not.
        assert_eq!(sanitize_dns1123_label("Prod.EU_west"), "prod-eu-west");
        // Trailing separator junk is trimmed.
        assert_eq!(sanitize_dns1123_label("x-"), "x");
        // Degenerate input yields empty (caller handles fallback).
        assert_eq!(sanitize_dns1123_label("..."), "");
    }

    #[test]
    fn namespace_collision_proof_distinct_ids_never_share_namespace() {
        // `prod-eu-west` is clean → friendly `gtc-prod-eu-west`.
        let clean = EnvId::try_from("prod-eu-west").unwrap();
        let ns_clean = namespace_for_env(&clean);
        assert_eq!(ns_clean, "gtc-prod-eu-west");

        // `Prod.EU_west` sanitizes to the same fragment but is lossy →
        // gets a hash suffix → DIFFERENT namespace.
        let lossy = EnvId::try_from("Prod.EU_west").unwrap();
        let ns_lossy = namespace_for_env(&lossy);
        assert_ne!(
            ns_lossy, ns_clean,
            "lossy derivation must not collide with the clean id"
        );
        assert!(
            ns_lossy.starts_with("gtc-prod-eu-west-"),
            "lossy namespace must start with the sanitized prefix: {ns_lossy}"
        );
        // Hash suffix is 8 hex chars.
        let suffix = ns_lossy.strip_prefix("gtc-prod-eu-west-").unwrap();
        assert_eq!(suffix.len(), 8);
        assert!(
            suffix.chars().all(|c| c.is_ascii_hexdigit()),
            "suffix must be hex: {suffix}"
        );
    }

    #[test]
    fn namespace_long_ids_truncated_but_distinct() {
        // Two long ids that share a 50-char sanitized prefix but differ
        // after that — they must produce different namespaces, both ≤ 63.
        let base = "a".repeat(55);
        let id_a = EnvId::try_from(format!("{base}xxxxx")).unwrap();
        let id_b = EnvId::try_from(format!("{base}yyyyy")).unwrap();
        let ns_a = namespace_for_env(&id_a);
        let ns_b = namespace_for_env(&id_b);
        assert_ne!(ns_a, ns_b, "truncated long ids must not collide");
        assert!(ns_a.len() <= 63, "namespace must be ≤ 63 chars: {ns_a}");
        assert!(ns_b.len() <= 63, "namespace must be ≤ 63 chars: {ns_b}");
        // Both are valid RFC 1123.
        for ns in [&ns_a, &ns_b] {
            assert!(
                ns.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "invalid RFC 1123: {ns}"
            );
            assert!(
                !ns.starts_with('-') && !ns.ends_with('-'),
                "leading/trailing dash: {ns}"
            );
        }
    }

    #[test]
    fn namespace_derivation_is_deterministic() {
        let id = EnvId::try_from("Prod.EU_west").unwrap();
        let a = namespace_for_env(&id);
        let b = namespace_for_env(&id);
        assert_eq!(a, b, "same id must always produce the same namespace");
    }

    #[test]
    fn namespace_degenerate_id_gets_hash_only() {
        // An env id made entirely of dots: sanitizes to empty.
        let id = EnvId::try_from("...").unwrap();
        let ns = namespace_for_env(&id);
        assert!(ns.starts_with("gtc-"), "must have gtc- prefix: {ns}");
        // "gtc-" + 8 hex = 12 chars
        assert_eq!(ns.len(), 12);
        assert!(
            ns[4..].chars().all(|c| c.is_ascii_hexdigit()),
            "must be gtc-<hex8>: {ns}"
        );
    }

    #[test]
    fn worker_name_is_a_lowercase_rfc1123_label() {
        let (env, _) = fixture();
        let name = worker_name(&env.revisions[0]);
        assert!(name.starts_with("gtc-worker-"));
        assert!(name.len() <= 63);
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "name must be RFC 1123: {name}"
        );
        // Two revisions never collide.
        assert_ne!(name, worker_name(&env.revisions[1]));
    }

    #[test]
    fn rendering_is_deterministic() {
        let (env, params) = fixture();
        let a = render_environment_manifests(&env, &params);
        let b = render_environment_manifests(&env, &params);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "identical inputs must serialize identically"
        );
        let wa = render_worker_manifests(&env, &env.revisions[0], &params);
        let wb = render_worker_manifests(&env, &env.revisions[0], &params);
        assert_eq!(
            serde_json::to_string(&wa).unwrap(),
            serde_json::to_string(&wb).unwrap()
        );
    }

    #[test]
    fn worker_deployment_carries_revision_label_and_identity_env() {
        let (env, params) = fixture();
        let rev = &env.revisions[0];
        let d = render_worker_deployment(&env, rev, &params);
        let ulid = rev.revision_id.0.to_string();
        // Plan step 4: the revision label is the worker identity.
        assert_eq!(
            d["metadata"]["labels"]["greentic.ai/revision"],
            serde_json::json!(ulid)
        );
        assert_eq!(
            d["spec"]["selector"]["matchLabels"]["greentic.ai/revision"],
            serde_json::json!(ulid)
        );
        // Identity env vars for the runtime entrypoint.
        let envs = d["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = envs.iter().map(|e| e["name"].as_str().unwrap()).collect();
        for required in [
            "GREENTIC_ENV_ID",
            "GREENTIC_REVISION_ID",
            "GREENTIC_DEPLOYMENT_ID",
            "GREENTIC_BUNDLE_ID",
            "GREENTIC_BUNDLE_DIGEST",
        ] {
            assert!(names.contains(&required), "missing env var {required}");
        }
    }

    #[test]
    fn every_pod_spec_passes_the_restricted_hardening_gate() {
        let (env, params) = fixture();
        let pods = [
            render_worker_deployment(&env, &env.revisions[0], &params),
            render_router_deployment(&env, &params),
        ];
        for d in &pods {
            let pod = &d["spec"]["template"]["spec"];
            assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
            assert_eq!(pod["securityContext"]["runAsUser"], 65532);
            assert_eq!(
                pod["securityContext"]["seccompProfile"]["type"],
                "RuntimeDefault"
            );
            let c = &pod["containers"][0];
            assert_eq!(c["securityContext"]["allowPrivilegeEscalation"], false);
            assert_eq!(c["securityContext"]["readOnlyRootFilesystem"], true);
            assert_eq!(c["securityContext"]["capabilities"]["drop"][0], "ALL");
            assert!(c["resources"]["requests"]["cpu"].is_string());
            assert!(c["resources"]["limits"]["memory"].is_string());
            assert!(c["readinessProbe"]["httpGet"]["path"].is_string());
        }
    }

    #[test]
    fn router_is_ha_with_pdb_and_spread() {
        let (env, params) = fixture();
        let d = render_router_deployment(&env, &params);
        assert_eq!(d["spec"]["replicas"], 2);
        assert!(
            d["spec"]["template"]["spec"]["topologySpreadConstraints"][0]["topologyKey"]
                .is_string()
        );
        let pdb = render_router_pdb(&env, &params);
        assert_eq!(pdb["spec"]["minAvailable"], 1);
        // The router mounts the runtime-config ConfigMap read-only.
        let mount = &d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0];
        assert_eq!(mount["readOnly"], true);
        assert_eq!(
            d["spec"]["template"]["spec"]["volumes"][0]["configMap"]["name"],
            RUNTIME_CONFIG_MAP_NAME
        );
    }

    #[test]
    fn runtime_config_map_embeds_the_exact_projection() {
        let (env, params) = fixture();
        let cm = render_runtime_config_map(&env, &params);
        let payload = cm["data"]["runtime-config.json"].as_str().unwrap();
        let expected = serde_json::to_string(&materialize_runtime_config(&env)).unwrap();
        assert_eq!(payload, expected, "the ConfigMap IS the projection");
    }

    #[test]
    fn network_policies_default_deny_then_allowlist() {
        let (env, params) = fixture();
        let policies = render_network_policies(&env, &params);
        assert_eq!(policies[0]["metadata"]["name"], "gtc-default-deny");
        // Default-deny selects all pods, both directions, no allow rules.
        assert_eq!(policies[0]["spec"]["podSelector"], serde_json::json!({}));
        assert!(policies[0]["spec"].get("ingress").is_none());
        assert!(policies[0]["spec"].get("egress").is_none());
        let names: Vec<&str> = policies
            .iter()
            .map(|p| p["metadata"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "gtc-default-deny",
                "gtc-allow-dns",
                "gtc-allow-router",
                "gtc-allow-workers"
            ]
        );
    }

    #[test]
    fn environment_manifests_land_in_the_env_namespace_in_apply_order() {
        let (env, params) = fixture();
        let manifests = render_environment_manifests(&env, &params);
        // Namespace first, ConfigMap before the router Deployment that
        // mounts it.
        assert_eq!(manifests[0]["kind"], "Namespace");
        assert_eq!(manifests[1]["kind"], "ConfigMap");
        assert_eq!(manifests[2]["kind"], "Deployment");
        for m in &manifests[1..] {
            assert_eq!(
                m["metadata"]["namespace"],
                serde_json::json!(params.namespace),
                "{} must be namespaced",
                m["kind"]
            );
        }
    }

    // ---- from_answers + is_dns1123_label -----------------------------------

    #[test]
    fn from_answers_none_equals_for_env() {
        let env = build_fixture_env();
        assert_eq!(
            K8sParams::from_answers(&env, None).unwrap(),
            K8sParams::for_env(&env),
        );
    }

    #[test]
    fn from_answers_empty_object_equals_for_env() {
        let env = build_fixture_env();
        let empty = serde_json::json!({});
        assert_eq!(
            K8sParams::from_answers(&env, Some(&empty)).unwrap(),
            K8sParams::for_env(&env),
        );
    }

    #[test]
    fn from_answers_custom_namespace_propagates() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"namespace": "my-ns"});
        let params = K8sParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.namespace, "my-ns");
        // Custom namespace propagates into every rendered object.
        let manifests = render_environment_manifests(&env, &params);
        assert_eq!(manifests[0]["metadata"]["name"], "my-ns");
        for m in &manifests[1..] {
            assert_eq!(
                m["metadata"]["namespace"].as_str(),
                Some("my-ns"),
                "{} namespace mismatch",
                m["kind"]
            );
        }
        // Worker objects too.
        for rev in &env.revisions {
            let workers = render_worker_manifests(&env, rev, &params);
            for w in &workers {
                assert_eq!(
                    w["metadata"]["namespace"].as_str(),
                    Some("my-ns"),
                    "worker {} namespace mismatch",
                    w["kind"]
                );
            }
        }
    }

    #[test]
    fn from_answers_custom_runtime_image() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"runtime_image": "ghcr.io/acme/rt@sha256:abc123"});
        let params = K8sParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.runtime_image, "ghcr.io/acme/rt@sha256:abc123");
        // Router and worker containers use the image.
        let router = render_router_deployment(&env, &params);
        assert_eq!(
            router["spec"]["template"]["spec"]["containers"][0]["image"].as_str(),
            Some("ghcr.io/acme/rt@sha256:abc123")
        );
        let worker = render_worker_deployment(&env, &env.revisions[0], &params);
        assert_eq!(
            worker["spec"]["template"]["spec"]["containers"][0]["image"].as_str(),
            Some("ghcr.io/acme/rt@sha256:abc123")
        );
    }

    #[test]
    fn from_answers_router_replicas_override() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"router_replicas": "4"});
        let params = K8sParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.router_replicas, 4);
    }

    #[test]
    fn from_answers_router_replicas_as_number() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"router_replicas": 3});
        let params = K8sParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.router_replicas, 3);
    }

    #[test]
    fn from_answers_router_replicas_one_rejected() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"router_replicas": "1"});
        let err = K8sParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(err.contains("must be >= 2"), "got: {err}");
    }

    #[test]
    fn from_answers_unknown_key_rejected() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"bogus_key": "value"});
        let err = K8sParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(err.contains("bogus_key"), "got: {err}");
    }

    #[test]
    fn from_answers_invalid_namespace_rejected() {
        let env = build_fixture_env();
        // Uppercase is not valid RFC 1123.
        let answers = serde_json::json!({"namespace": "MyNS"});
        let err = K8sParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(err.contains("not a valid RFC 1123"), "got: {err}");
    }

    #[test]
    fn from_answers_namespace_too_long_rejected() {
        let env = build_fixture_env();
        let long = "a".repeat(64);
        let answers = serde_json::json!({"namespace": long});
        let err = K8sParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(err.contains("not a valid RFC 1123"), "got: {err}");
    }

    #[test]
    fn from_answers_non_object_rejected() {
        let env = build_fixture_env();
        let bad = serde_json::json!("not an object");
        let err = K8sParams::from_answers(&env, Some(&bad)).unwrap_err();
        assert!(err.contains("JSON object"), "got: {err}");
    }

    #[test]
    fn from_answers_empty_string_falls_back_to_default() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "namespace": "",
            "runtime_image": "",
            "router_replicas": "",
        });
        assert_eq!(
            K8sParams::from_answers(&env, Some(&answers)).unwrap(),
            K8sParams::for_env(&env),
        );
    }

    #[test]
    fn from_answers_null_values_fall_back_to_default() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "namespace": null,
            "runtime_image": null,
            "router_replicas": null,
            "kubeconfig_context": null,
        });
        assert_eq!(
            K8sParams::from_answers(&env, Some(&answers)).unwrap(),
            K8sParams::for_env(&env),
        );
    }

    #[test]
    fn from_answers_kubeconfig_context_ignored() {
        let env = build_fixture_env();
        let answers = serde_json::json!({"kubeconfig_context": "my-ctx"});
        let params = K8sParams::from_answers(&env, Some(&answers)).unwrap();
        // kubeconfig_context is a client-targeting knob, not a manifest
        // knob — it must not affect any rendered param.
        assert_eq!(params, K8sParams::for_env(&env));
    }

    #[test]
    fn is_dns1123_label_accepts_valid() {
        assert!(is_dns1123_label("my-ns"));
        assert!(is_dns1123_label("a"));
        assert!(is_dns1123_label("abc-123"));
        assert!(is_dns1123_label(&"a".repeat(63)));
    }

    #[test]
    fn is_dns1123_label_rejects_invalid() {
        assert!(!is_dns1123_label(""));
        assert!(!is_dns1123_label("-abc"));
        assert!(!is_dns1123_label("abc-"));
        assert!(!is_dns1123_label("ABC"));
        assert!(!is_dns1123_label("a.b"));
        assert!(!is_dns1123_label(&"a".repeat(64)));
    }
}
