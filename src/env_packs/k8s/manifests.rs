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
/// alone. The env-pack wizard (`wizard.qaspec.yaml`) records overrides on
/// the binding's `answers_ref`; plumbing those answers into this struct
/// rides the same Phase D answers-reader gap disclosed on the AWS-ECS
/// wizard (no `answers_ref` reader exists yet).
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
}

/// Default namespace for an env: `gtc-<env-id>`, sanitized to an RFC 1123
/// label (env ids permit `.`/`_`/uppercase; namespaces do not).
pub fn namespace_for_env(env_id: &EnvId) -> String {
    sanitize_dns1123_label(&format!("gtc-{}", env_id.as_str()))
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

/// Coerce a string into an RFC 1123 label: lowercase, `[a-z0-9-]` only
/// (other characters map to `-`), trimmed to 63 chars, no leading or
/// trailing `-`. Total functions only — a degenerate input yields `gtc`
/// rather than an invalid name.
fn sanitize_dns1123_label(raw: &str) -> String {
    let mut s: String = raw
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
    s.truncate(63);
    let trimmed = s.trim_matches('-');
    if trimmed.is_empty() {
        "gtc".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Shared labels stamped on every object the env-pack renders.
fn common_labels(env: &Environment, component: &str) -> Value {
    json!({
        "app.kubernetes.io/managed-by": "greentic",
        "app.kubernetes.io/component": component,
        "greentic.ai/env": env.environment_id.as_str(),
    })
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
/// the K8s apply PR; the identity contract here is delivery-agnostic.
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
/// The `gtc op env render` verb (follow-up PR) writes this set to disk.
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
        assert_eq!(
            sanitize_dns1123_label("gtc-Prod.EU_west"),
            "gtc-prod-eu-west"
        );
        // Trailing separator junk is trimmed.
        assert_eq!(sanitize_dns1123_label("gtc-x-"), "gtc-x");
        // 63-char cap.
        let long = format!("gtc-{}", "a".repeat(80));
        assert_eq!(sanitize_dns1123_label(&long).len(), 63);
        // Degenerate input still yields a valid label.
        assert_eq!(sanitize_dns1123_label("..."), "gtc");
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
}
