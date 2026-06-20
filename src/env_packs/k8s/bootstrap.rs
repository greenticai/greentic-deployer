//! Bootstrap-time RBAC rules-pack emitter for the K8s env-pack (Phase D
//! plan §6 step 6).
//!
//! Renders the one-time, cluster-admin-applied bootstrap boundary as
//! reviewable YAML — the K8s analogue of the AWS-ECS IAM Terraform pack:
//!
//! - `k8s-min-rbac.yaml` — Namespace + ServiceAccount + namespaced Role
//!   (rules aggregated from the SAME operations list `validate` probes
//!   via `SelfSubjectAccessReview`) + RoleBinding.
//! - `README.md` — operator-facing review/apply/bind instructions.
//!
//! The customer is in the loop, by design: a cluster admin reviews the
//! YAML, applies it, mints a SHORT-LIVED token for the ServiceAccount
//! (`kubectl create token` — long-lived bearer tokens are not the
//! production default, per the plan), and binds it via `op credentials
//! rotate`. Greentic never executes against the admin credential.
//!
//! Namespace creation is cluster-scoped, steady-state deployment is
//! namespace-scoped (Q6): this pack is exactly that split — the ONLY
//! cluster-scoped object is the Namespace itself; the Role/RoleBinding
//! confine the deployer to it.

use std::fmt::Write as _;

use crate::credentials::{RulesPack, RulesPackEntry};

use super::credentials::K8sOperation;

/// Name of the ServiceAccount the rules pack provisions.
pub const DEPLOYER_SERVICE_ACCOUNT: &str = "greentic-deployer";

/// Filename of the RBAC manifest entry in the rendered rules pack. The
/// `--bind` path (`K8sDeployerCredentials::bootstrap`) extracts this exact
/// entry and applies it live, so the live apply and the offline
/// `kubectl apply -f` stay byte-identical — keep the renderer and the
/// extractor referencing this one constant.
pub(crate) const K8S_RBAC_MANIFEST_FILENAME: &str = "k8s-min-rbac.yaml";

/// Store-aligned path (under `secret://<env>/…`) where the deployer's bound
/// ServiceAccount token lives: `<tenant>/<team>/<category>/<name>`. It MUST be
/// store-aligned so `op secrets put` can write it and the resolver
/// (`cli::secrets::resolve_credentials_token`) can read it back via
/// `SecretRef::to_store_uri` — a non-aligned ref (e.g. `…/k8s/deployer-token`)
/// has no store location and fails to resolve. The bootstrap README advertises
/// `secret://<env>/{this}` so the documented binding matches what resolves.
pub(crate) const DEPLOYER_TOKEN_STORE_PATH: &str = "default/_/k8s-deployer/deployer_token";

/// Input shape for [`render_min_rbac_rules_pack`]. Borrowed; no heap cost.
pub struct K8sRulesPackInput<'a> {
    /// Env this pack is scoped to (names + labels).
    pub env_id: &'a str,
    /// Namespace the pack provisions and confines the deployer to.
    pub namespace: &'a str,
    /// Operator-supplied admin identity hint (kubeconfig context or
    /// admin name). Recorded in the README so reviewers see who was
    /// expected to apply the pack — never embedded as a credential.
    pub admin_context_hint: &'a str,
    /// Operations the Role allows. Mirrors the validate-time list 1:1 so
    /// the bootstrap-then-validate loop converges.
    pub operations: &'a [K8sOperation],
}

/// Render the rules pack. Pure function — no I/O; the shared writer
/// (`crate::credentials::write_rules_pack`) lands it on disk inside the
/// bootstrap flock.
pub fn render_min_rbac_rules_pack(input: &K8sRulesPackInput<'_>) -> RulesPack {
    RulesPack {
        entries: vec![
            RulesPackEntry {
                filename: K8S_RBAC_MANIFEST_FILENAME.into(),
                content: render_rbac_yaml(input),
                description: Some(format!(
                    "Namespace + minimum-privilege ServiceAccount/Role/RoleBinding for \
                     Greentic env `{}` (K8s rollout surface).",
                    input.env_id
                )),
            },
            RulesPackEntry {
                filename: "README.md".into(),
                content: render_readme(input),
                description: Some("Apply instructions for the K8s bootstrap rules pack.".into()),
            },
        ],
    }
}

/// Aggregate the flat operations list into Role rules: one rule per
/// `(group, resource)` in first-appearance order, verbs in list order.
fn group_rules(
    operations: &[K8sOperation],
) -> Vec<((&'static str, &'static str), Vec<&'static str>)> {
    let mut rules: Vec<((&'static str, &'static str), Vec<&'static str>)> = Vec::new();
    for operation in operations {
        let key = (operation.group, operation.resource);
        match rules.iter_mut().find(|(k, _)| *k == key) {
            Some((_, verbs)) => {
                if !verbs.contains(&operation.verb) {
                    verbs.push(operation.verb);
                }
            }
            None => rules.push((key, vec![operation.verb])),
        }
    }
    rules
}

fn render_rbac_yaml(input: &K8sRulesPackInput<'_>) -> String {
    let mut rules_yaml = String::new();
    for ((group, resource), verbs) in group_rules(input.operations) {
        let verbs_csv = verbs.join(", ");
        let _ = writeln!(rules_yaml, "  - apiGroups: [\"{group}\"]");
        let _ = writeln!(rules_yaml, "    resources: [\"{resource}\"]");
        let _ = writeln!(rules_yaml, "    verbs: [{verbs_csv}]");
    }

    format!(
        r#"# Greentic env-pack bootstrap — K8s deployer credentials (Phase D).
#
# Apply this with `kubectl apply -f k8s-min-rbac.yaml` using a CLUSTER
# ADMIN identity. It provisions the one-time bootstrap boundary for
# Greentic env `{env_id}`:
#
#   - Namespace `{namespace}` (the only cluster-scoped object here)
#   - ServiceAccount `{sa}` — the identity Greentic deploys as
#   - A namespaced Role with the minimum verbs the deployer exercises
#     (validated against this exact list by
#     `gtc op credentials requirements {env_id}`)
#   - A RoleBinding confining the ServiceAccount to the namespace
#
# Generated by greentic-deployer; safe to commit to source control.
apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
  labels:
    app.kubernetes.io/managed-by: greentic
    greentic.ai/env: "{env_id}"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {sa}
  namespace: {namespace}
  labels:
    app.kubernetes.io/managed-by: greentic
    greentic.ai/env: "{env_id}"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {sa}-min
  namespace: {namespace}
  labels:
    app.kubernetes.io/managed-by: greentic
    greentic.ai/env: "{env_id}"
rules:
{rules_yaml}---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {sa}-min
  namespace: {namespace}
  labels:
    app.kubernetes.io/managed-by: greentic
    greentic.ai/env: "{env_id}"
subjects:
  - kind: ServiceAccount
    name: {sa}
    namespace: {namespace}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {sa}-min
"#,
        env_id = input.env_id,
        namespace = input.namespace,
        sa = DEPLOYER_SERVICE_ACCOUNT,
        rules_yaml = rules_yaml,
    )
}

fn render_readme(input: &K8sRulesPackInput<'_>) -> String {
    let op_bullets = input
        .operations
        .iter()
        .map(|operation| {
            let group = if operation.group.is_empty() {
                "core"
            } else {
                operation.group
            };
            format!("- `{group}/{}: {}`", operation.resource, operation.verb)
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"# K8s bootstrap rules pack — env `{env_id}`

Generated by `gtc op credentials bootstrap {env_id}` for the
`greentic.deployer.k8s` env-pack.

Expected applier (operator-supplied hint, review before applying):

```
{admin_hint}
```

## What this is

The one-time bootstrap boundary your cluster admin reviews and applies.
Namespace creation is cluster-scoped; everything else is confined to
namespace `{namespace}`. The Role grants ONLY the operations Greentic's
K8s rollout surface exercises:

{op_bullets}

`gtc op credentials requirements {env_id}` probes this exact list via
`SelfSubjectAccessReview`, so applying this pack and re-running
requirements converges to green.

## How to apply

1. Review `k8s-min-rbac.yaml`. Adjust the namespace name or labels to
   your conventions if required (keep the Role verbs intact — removing
   one fails the matching requirements probe).

2. With cluster-admin credentials:

   ```sh
   kubectl apply -f k8s-min-rbac.yaml
   ```

3. Mint a SHORT-LIVED token for the deployer ServiceAccount (do not
   create long-lived ServiceAccount token Secrets):

   ```sh
   kubectl create token {sa} -n {namespace} --duration=1h
   ```

4. Bind the credential to env `{env_id}`:

   ```sh
   gtc op credentials rotate {env_id} --provided-credentials-ref \
     "secret://{env_id}/{store_path}"
   ```

5. Re-run requirements:

   ```sh
   gtc op credentials requirements {env_id}
   ```

   The `k8s.api.reachable` capability plus one capability per operation
   above must pass before deploys are honored.

## What this does NOT do

This pack only creates the deploy-time identity boundary. Workload
identity for pods (IRSA / AKS / GKE workload identity), secret-store
projection (ESO / CSI), and ingress wiring are separate decisions
recorded in the Zain alignment doc and land with the respective
env-packs.
"#,
        env_id = input.env_id,
        namespace = input.namespace,
        sa = DEPLOYER_SERVICE_ACCOUNT,
        admin_hint = input.admin_context_hint,
        op_bullets = op_bullets,
        store_path = DEPLOYER_TOKEN_STORE_PATH,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::k8s::credentials::VALIDATED_K8S_OPERATIONS;

    fn input<'a>() -> K8sRulesPackInput<'a> {
        K8sRulesPackInput {
            env_id: "zain-prod",
            namespace: "gtc-zain-prod",
            admin_context_hint: "zain-admin@nonprod",
            operations: VALIDATED_K8S_OPERATIONS,
        }
    }

    #[test]
    fn renders_two_entries_yaml_and_readme() {
        let pack = render_min_rbac_rules_pack(&input());
        let filenames: Vec<&str> = pack.entries.iter().map(|e| e.filename.as_str()).collect();
        assert_eq!(filenames, ["k8s-min-rbac.yaml", "README.md"]);
    }

    #[test]
    fn yaml_contains_all_four_objects_scoped_to_the_namespace() {
        let pack = render_min_rbac_rules_pack(&input());
        let yaml = &pack.entries[0].content;
        for kind in [
            "kind: Namespace",
            "kind: ServiceAccount",
            "kind: Role",
            "kind: RoleBinding",
        ] {
            assert!(yaml.contains(kind), "missing `{kind}`:\n{yaml}");
        }
        assert!(yaml.contains("name: gtc-zain-prod"));
        assert!(yaml.contains("namespace: gtc-zain-prod"));
        // The YAML parses (well-formed multi-document stream).
        for doc in yaml.split("\n---\n") {
            let parsed: serde_yaml_bw::Value =
                serde_yaml_bw::from_str(doc).expect("each document parses as YAML");
            assert!(parsed.is_mapping(), "each document is a mapping");
        }
    }

    #[test]
    fn role_rules_aggregate_one_rule_per_group_resource_with_every_verb() {
        let pack = render_min_rbac_rules_pack(&input());
        let yaml = &pack.entries[0].content;
        // One rule per (group, resource) — 5 distinct pairs in the list.
        assert_eq!(yaml.matches("- apiGroups:").count(), 5);
        assert!(yaml.contains("resources: [\"deployments\"]"));
        assert!(yaml.contains("verbs: [get, create, patch, delete]"));
        // Env-lifetime objects carry no delete.
        assert!(yaml.contains("resources: [\"configmaps\"]"));
        let configmap_rule = yaml
            .split("- apiGroups:")
            .find(|s| s.contains("configmaps"))
            .unwrap();
        assert!(
            configmap_rule.contains("verbs: [get, create, patch]"),
            "configmaps must not get delete:\n{configmap_rule}"
        );
        // Every validated verb appears somewhere in the Role.
        for operation in VALIDATED_K8S_OPERATIONS {
            assert!(yaml.contains(operation.verb));
            assert!(yaml.contains(operation.resource));
        }
    }

    #[test]
    fn readme_lists_every_operation_and_the_bind_loop() {
        let pack = render_min_rbac_rules_pack(&input());
        let readme = &pack.entries[1].content;
        assert!(readme.contains("zain-admin@nonprod"));
        assert!(readme.contains("kubectl apply -f k8s-min-rbac.yaml"));
        // Short-lived token guidance, not a long-lived Secret.
        assert!(readme.contains("kubectl create token greentic-deployer"));
        assert!(readme.contains("gtc op credentials rotate zain-prod"));
        for operation in VALIDATED_K8S_OPERATIONS {
            let group = if operation.group.is_empty() {
                "core"
            } else {
                operation.group
            };
            let bullet = format!("- `{group}/{}: {}`", operation.resource, operation.verb);
            assert!(readme.contains(&bullet), "missing bullet {bullet}");
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        let a = render_min_rbac_rules_pack(&input());
        let b = render_min_rbac_rules_pack(&input());
        assert_eq!(a.entries[0].content, b.entries[0].content);
        assert_eq!(a.entries[1].content, b.entries[1].content);
    }
}
