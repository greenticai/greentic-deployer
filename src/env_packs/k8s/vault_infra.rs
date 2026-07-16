//! Pure renderers for the in-cluster dev-mode Vault that `op env up` provisions
//! when the manifest declares `vault_bootstrap.deploy: "dev-in-cluster"`.
//!
//! Mirrors `my_demos/k8s-vault-demo/vault.yaml`: a ServiceAccount, the
//! `system:auth-delegator` ClusterRoleBinding (so Vault can `TokenReview` the
//! worker pod's projected SA token during `auth/kubernetes/login`), an
//! in-memory dev-mode Deployment, its Service, and a NetworkPolicy opening
//! Vault's ingress to the worker pods.
//!
//! The Deployment is OpenShift-restricted-SCC-compatible and dev-only:
//! `SKIP_SETCAP=true` (the entrypoint can't `setcap`), `HOME=/tmp` (the
//! assigned UID can't write `$HOME=/`), `VAULT_DISABLE_MLOCK=true` (dev mode
//! never mlocks). The server runs `-dev`: in-memory, auto-unsealed, root-token
//! auth. It exists so the worker can exercise the Kubernetes auth method end to
//! end inside kind — it is NOT a production Vault.
//!
//! The cluster-scoped ClusterRoleBinding is why `op env up` gates this phase
//! behind a `clusterrolebindings.create` `SelfSubjectAccessReview`: only an
//! admin kubeconfig (kind/local dev) can apply it. All objects are stamped with
//! the env-ownership label so [`KubeCluster::apply`](super::kube_client::KubeCluster)
//! converges a re-run and fail-closes against a different env's object of the
//! same name.

use serde_json::{Value, json};

use super::manifests::ENV_LABEL;

/// Vault's ServiceAccount / Deployment / Service name, and the in-cluster
/// component label its pods carry. The demo binding dials `vault.<ns>.svc:8200`,
/// so this name is load-bearing — it must match the env's Vault binding `addr`.
pub const VAULT_NAME: &str = "vault";

/// The worker pods' component label (see `manifests::render_worker_deployment`),
/// used as the NetworkPolicy ingress source selector.
const WORKER_COMPONENT: &str = "worker";

/// The dev Vault's HTTP API port.
const VAULT_PORT: u16 = 8200;

/// Inputs for the Vault infra renderers. All non-secret except `root_token`,
/// a dev-mode token templated into the `-dev` server args.
pub struct VaultInfraParams<'a> {
    /// Namespace the dev Vault runs in (`vault_bootstrap.namespace`). This is
    /// deliberately NOT the env namespace — it is created here, before the
    /// reconcile phase creates the env namespace.
    pub namespace: &'a str,
    /// Dev-mode Vault image.
    pub image: &'a str,
    /// Dev-mode root token id.
    pub root_token: &'a str,
    /// Owning env id, stamped as [`ENV_LABEL`] for the apply ownership guard.
    pub env_id: &'a str,
}

/// The cluster-scoped binding name — namespace-suffixed so two dev Vaults in
/// different namespaces get distinct bindings rather than clobbering one.
pub fn auth_delegator_crb_name(namespace: &str) -> String {
    format!("greentic-vault-auth-delegator-{namespace}")
}

/// Standard labels for every Vault object: managed-by + the `vault` component +
/// the env-ownership label the apply guard keys on.
fn vault_labels(env_id: &str) -> Value {
    let mut labels = json!({
        "app.kubernetes.io/managed-by": "greentic",
        "app.kubernetes.io/component": VAULT_NAME,
    });
    labels[ENV_LABEL] = json!(env_id);
    labels
}

/// The Vault namespace object. Its OWN namespace — `render_namespace` renders
/// the *env* namespace from an `&Environment`, which is the wrong one here.
pub fn render_vault_namespace(p: &VaultInfraParams) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": p.namespace,
            "labels": vault_labels(p.env_id),
        },
    })
}

/// The ServiceAccount Vault runs as. The `system:auth-delegator` binding grants
/// it the TokenReview rights Vault needs to validate worker SA tokens.
pub fn render_vault_service_account(p: &VaultInfraParams) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": VAULT_NAME,
            "namespace": p.namespace,
            "labels": vault_labels(p.env_id),
        },
    })
}

/// The cluster-scoped `system:auth-delegator` ClusterRoleBinding. Requires a
/// cluster-admin kubeconfig; `op env up` preflights `clusterrolebindings.create`
/// before applying it.
pub fn render_vault_auth_delegator_crb(p: &VaultInfraParams) -> Value {
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": auth_delegator_crb_name(p.namespace),
            "labels": vault_labels(p.env_id),
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "system:auth-delegator",
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": VAULT_NAME,
            "namespace": p.namespace,
        }],
    })
}

/// The in-memory dev-mode Vault Deployment. `-dev` auto-unseals with the given
/// root token; the SCC-compat env vars make it schedulable under OpenShift's
/// restricted profile too.
pub fn render_vault_deployment(p: &VaultInfraParams) -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": VAULT_NAME,
            "namespace": p.namespace,
            "labels": vault_labels(p.env_id),
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": { "app.kubernetes.io/component": VAULT_NAME },
            },
            "template": {
                "metadata": { "labels": vault_labels(p.env_id) },
                "spec": {
                    "serviceAccountName": VAULT_NAME,
                    "containers": [{
                        "name": VAULT_NAME,
                        "image": p.image,
                        "args": [
                            "server",
                            "-dev",
                            format!("-dev-listen-address=0.0.0.0:{VAULT_PORT}"),
                            format!("-dev-root-token-id={}", p.root_token),
                        ],
                        "env": [
                            { "name": "SKIP_SETCAP", "value": "true" },
                            { "name": "HOME", "value": "/tmp" },
                            { "name": "VAULT_DISABLE_MLOCK", "value": "true" },
                        ],
                        "ports": [{ "containerPort": VAULT_PORT }],
                        "readinessProbe": {
                            "httpGet": { "path": "/v1/sys/health", "port": VAULT_PORT },
                            "initialDelaySeconds": 3,
                            "periodSeconds": 5,
                        },
                    }],
                },
            },
        },
    })
}

/// The Vault Service (`vault.<ns>.svc:8200`), the address the worker dials and
/// the seed phase port-forwards to.
pub fn render_vault_service(p: &VaultInfraParams) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": VAULT_NAME,
            "namespace": p.namespace,
            "labels": vault_labels(p.env_id),
        },
        "spec": {
            "selector": { "app.kubernetes.io/component": VAULT_NAME },
            "ports": [{ "port": VAULT_PORT, "targetPort": VAULT_PORT }],
        },
    })
}

/// Open Vault's ingress to the worker pods. The deployer renders a
/// deny-by-default posture (`gtc-default-deny` selects every pod in the
/// namespace, including this operator-deployed Vault), and the CNI enforces
/// NetworkPolicies — so without this the worker's `auth/kubernetes/login` + KV
/// read to `vault.<ns>.svc:8200` is dropped at Vault's ingress and every
/// webhook 401s.
///
/// The workers do NOT share Vault's namespace: Vault runs in
/// `vault_bootstrap.namespace` (default `greentic`) while the workers run in the
/// env namespace (`gtc-<env>`) — see [`VaultInfraParams::namespace`]. A bare
/// `podSelector` in an ingress `from` matches only pods in the policy's OWN
/// namespace (here, Vault's), so it never matches the workers: under a
/// policy-enforcing CNI (e.g. Cilium) this silently denied worker->Vault and
/// every webhook 401'd; kindnet's laxer enforcement masked it. The `from`
/// therefore pairs the worker component selector with a `namespaceSelector` on
/// the env-ownership label ([`ENV_LABEL`]), which every env-owned namespace
/// (both the env namespace and this Vault namespace) carries.
pub fn render_vault_network_policy(p: &VaultInfraParams) -> Value {
    // `json!` keys must be literals, so build the env-namespace selector the same
    // way `vault_labels` stamps the ownership label.
    let mut env_ns_labels = json!({});
    env_ns_labels[ENV_LABEL] = json!(p.env_id);
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "allow-vault-ingress-from-workers",
            "namespace": p.namespace,
            "labels": vault_labels(p.env_id),
        },
        "spec": {
            "podSelector": {
                "matchLabels": { "app.kubernetes.io/component": VAULT_NAME },
            },
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{
                    "namespaceSelector": { "matchLabels": env_ns_labels },
                    "podSelector": {
                        "matchLabels": { "app.kubernetes.io/component": WORKER_COMPONENT },
                    },
                }],
                "ports": [{ "protocol": "TCP", "port": VAULT_PORT }],
            }],
        },
    })
}

/// All Vault objects in apply order: namespace first (so the namespaced objects
/// can be created into it), then SA, the cluster-scoped binding, Deployment,
/// Service, and the ingress NetworkPolicy.
pub fn render_vault_manifests(p: &VaultInfraParams) -> Vec<Value> {
    vec![
        render_vault_namespace(p),
        render_vault_service_account(p),
        render_vault_auth_delegator_crb(p),
        render_vault_deployment(p),
        render_vault_service(p),
        render_vault_network_policy(p),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> VaultInfraParams<'static> {
        VaultInfraParams {
            namespace: "greentic",
            image: "hashicorp/vault:1.17",
            root_token: "root",
            env_id: "vault-demo",
        }
    }

    #[test]
    fn render_vault_manifests_has_expected_kinds_in_apply_order() {
        let objects = render_vault_manifests(&params());
        // Namespace first; the cluster-scoped binding before the pods it feeds.
        let kinds: Vec<String> = objects
            .iter()
            .map(|o| o["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            kinds,
            vec![
                "Namespace",
                "ServiceAccount",
                "ClusterRoleBinding",
                "Deployment",
                "Service",
                "NetworkPolicy",
            ]
        );
    }

    #[test]
    fn every_object_carries_the_env_ownership_label() {
        for obj in render_vault_manifests(&params()) {
            assert_eq!(
                obj["metadata"]["labels"][ENV_LABEL], "vault-demo",
                "missing env label on {}",
                obj["kind"]
            );
        }
    }

    #[test]
    fn vault_ingress_netpol_allows_workers_from_the_env_namespace() {
        // Regression: a bare podSelector `from` matches only pods in the
        // policy's own (Vault) namespace, so it never matched the workers, which
        // live in the env namespace. The `from` must pair a namespaceSelector on
        // the env-ownership label with the worker podSelector.
        let np = render_vault_network_policy(&params());
        let from = &np["spec"]["ingress"][0]["from"][0];
        assert_eq!(
            from["namespaceSelector"]["matchLabels"][ENV_LABEL], "vault-demo",
            "ingress `from` must scope to the env namespace via the ownership label"
        );
        assert_eq!(
            from["podSelector"]["matchLabels"]["app.kubernetes.io/component"], "worker",
            "ingress `from` must still select the worker component"
        );
        assert_eq!(np["spec"]["ingress"][0]["ports"][0]["port"], VAULT_PORT);
    }

    #[test]
    fn only_the_namespace_and_crb_are_cluster_scoped() {
        for obj in render_vault_manifests(&params()) {
            let kind = obj["kind"].as_str().unwrap();
            let has_ns = obj["metadata"].get("namespace").is_some();
            match kind {
                "Namespace" | "ClusterRoleBinding" => {
                    assert!(!has_ns, "{kind} must be cluster-scoped (no namespace)");
                }
                _ => assert_eq!(
                    obj["metadata"]["namespace"], "greentic",
                    "{kind} must be namespaced into the vault namespace"
                ),
            }
        }
    }

    #[test]
    fn deployment_carries_dev_flags_and_the_root_token() {
        let dep = render_vault_deployment(&params());
        let container = &dep["spec"]["template"]["spec"]["containers"][0];
        let args: Vec<&str> = container["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert!(args.contains(&"-dev"));
        assert!(args.contains(&"-dev-root-token-id=root"));
        assert!(args.contains(&"-dev-listen-address=0.0.0.0:8200"));

        let env_names: Vec<&str> = container["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(env_names.contains(&"SKIP_SETCAP"));
        assert!(env_names.contains(&"HOME"));
        assert!(env_names.contains(&"VAULT_DISABLE_MLOCK"));
        assert_eq!(
            dep["spec"]["template"]["spec"]["serviceAccountName"],
            VAULT_NAME
        );
    }

    #[test]
    fn crb_binds_auth_delegator_to_the_vault_sa() {
        let crb = render_vault_auth_delegator_crb(&params());
        assert_eq!(
            crb["metadata"]["name"],
            "greentic-vault-auth-delegator-greentic"
        );
        assert_eq!(crb["roleRef"]["name"], "system:auth-delegator");
        assert_eq!(crb["roleRef"]["kind"], "ClusterRole");
        let subject = &crb["subjects"][0];
        assert_eq!(subject["kind"], "ServiceAccount");
        assert_eq!(subject["name"], VAULT_NAME);
        assert_eq!(subject["namespace"], "greentic");
    }

    #[test]
    fn network_policy_allows_worker_ingress_on_the_vault_port() {
        let np = render_vault_network_policy(&params());
        assert_eq!(
            np["spec"]["podSelector"]["matchLabels"]["app.kubernetes.io/component"],
            VAULT_NAME
        );
        let from = &np["spec"]["ingress"][0]["from"][0];
        assert_eq!(
            from["podSelector"]["matchLabels"]["app.kubernetes.io/component"],
            "worker"
        );
        assert_eq!(np["spec"]["ingress"][0]["ports"][0]["port"], 8200);
    }

    #[test]
    fn service_selects_the_vault_component_on_the_api_port() {
        let svc = render_vault_service(&params());
        assert_eq!(
            svc["spec"]["selector"]["app.kubernetes.io/component"],
            VAULT_NAME
        );
        assert_eq!(svc["spec"]["ports"][0]["port"], 8200);
        assert_eq!(svc["spec"]["ports"][0]["targetPort"], 8200);
    }
}
