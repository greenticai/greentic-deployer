//! Orphan sweep for the K8s env-pack (`op env sweep`).
//!
//! `reconcile` prunes the workers of revisions it can still see in
//! `env.revisions`. A revision compacted out of the store (a removed bundle,
//! a hand-edited env) leaves its worker Deployment + Service running with
//! nothing that will ever reach them again. The sweep finds those by the
//! deployer's OWN labels and removes them:
//!
//! - it lists only objects carrying `app.kubernetes.io/managed-by=greentic`,
//!   `app.kubernetes.io/component=worker` and `greentic.ai/env=<env>` — an
//!   unlabeled object is never listed, so it is never touched;
//! - it re-checks those labels on every listed object (defence in depth
//!   against a cluster that ignores the selector);
//! - an object whose `greentic.ai/revision` names a revision still in the
//!   store is kept, whatever its lifecycle (`reconcile` owns those);
//! - dry-run is the default; `apply` deletes.
//!
//! Listing needs `list` on `deployments` and `services`, which the bootstrap
//! Role (derived from `VALIDATED_K8S_OPERATIONS`) does not grant — adding it
//! there would fail `op credentials requirements` for every env bound before
//! this. Run the sweep with an identity that can list (the ambient admin
//! kubeconfig), or grant the two verbs to the deployer Role by hand.

use std::collections::BTreeSet;

use greentic_deploy_spec::Environment;
use serde::Serialize;
use serde_json::Value;

use super::K8sDeployerHandler;
use super::deployer::{params_from_answers, provider};
use super::manifests::ENV_LABEL;
use crate::env_packs::deployer::DeployerError;

const MANAGED_BY: (&str, &str) = ("app.kubernetes.io/managed-by", "greentic");
const COMPONENT: (&str, &str) = ("app.kubernetes.io/component", "worker");
const REVISION_LABEL: &str = "greentic.ai/revision";

/// The label selector the sweep lists with.
pub fn worker_selector(env: &Environment) -> String {
    format!(
        "{}={},{}={},{ENV_LABEL}={}",
        MANAGED_BY.0,
        MANAGED_BY.1,
        COMPONENT.0,
        COMPONENT.1,
        env.environment_id.as_str()
    )
}

/// One worker object the sweep classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SweptObject {
    pub kind: String,
    pub name: String,
    pub revision_id: String,
}

/// A listed object the sweep refused to classify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedObject {
    pub kind: String,
    pub name: String,
    pub reason: String,
}

/// What a sweep found and (with `apply`) removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SweepReport {
    pub namespace: String,
    pub label_selector: String,
    pub dry_run: bool,
    /// Workers whose revision is absent from the store.
    pub orphans: Vec<SweptObject>,
    /// The orphans actually deleted (empty on a dry run).
    pub removed: Vec<SweptObject>,
    /// Workers whose revision the store still records.
    pub kept: Vec<SweptObject>,
    pub skipped: Vec<SkippedObject>,
}

impl K8sDeployerHandler {
    /// Find (and with `apply`, delete) worker Deployments/Services labeled for
    /// this env whose revision is absent from `env.revisions`.
    pub async fn sweep(
        &self,
        env: &Environment,
        answers: Option<&Value>,
        apply: bool,
    ) -> Result<SweepReport, DeployerError> {
        let params = params_from_answers(env, answers)?;
        let selector = worker_selector(env);
        let listed = self
            .cluster
            .list(&params.namespace, &selector)
            .await
            .map_err(provider)?;
        let known: BTreeSet<String> = env
            .revisions
            .iter()
            .map(|r| r.revision_id.0.to_string())
            .collect();
        let env_id = env.environment_id.as_str();

        let mut report = SweepReport {
            namespace: params.namespace.clone(),
            label_selector: selector,
            dry_run: !apply,
            orphans: Vec::new(),
            removed: Vec::new(),
            kept: Vec::new(),
            skipped: Vec::new(),
        };
        for item in listed {
            let skip = |reason: &str| SkippedObject {
                kind: item.object.kind.clone(),
                name: item.object.name.clone(),
                reason: reason.to_string(),
            };
            let label = |k: &str| item.labels.get(k).map(String::as_str);
            if label(MANAGED_BY.0) != Some(MANAGED_BY.1)
                || label(COMPONENT.0) != Some(COMPONENT.1)
                || label(ENV_LABEL) != Some(env_id)
            {
                report
                    .skipped
                    .push(skip("does not carry this env's worker labels"));
                continue;
            }
            if !matches!(item.object.kind.as_str(), "Deployment" | "Service") {
                report.skipped.push(skip("not a worker Deployment/Service"));
                continue;
            }
            let Some(revision_id) = label(REVISION_LABEL) else {
                report.skipped.push(skip("no `greentic.ai/revision` label"));
                continue;
            };
            let swept = SweptObject {
                kind: item.object.kind.clone(),
                name: item.object.name.clone(),
                revision_id: revision_id.to_string(),
            };
            if known.contains(revision_id) {
                report.kept.push(swept);
                continue;
            }
            if apply {
                self.cluster.delete(&item.object).await.map_err(provider)?;
                report.removed.push(swept.clone());
            }
            report.orphans.push(swept);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::cluster::{InMemoryCluster, K8sCluster, ObjectRef};

    /// Fixture env with one live worker (revision 0) plus, in the cluster:
    /// an orphaned worker pair for a revision the store no longer has, an
    /// unlabeled look-alike, and another env's worker.
    async fn seeded() -> (K8sDeployerHandler, Arc<InMemoryCluster>, Environment) {
        let cluster = Arc::new(InMemoryCluster::default());
        let h = K8sDeployerHandler::with_cluster(cluster.clone());
        let mut env = build_fixture_env();
        h.warm_revision(&env, env.revisions[0].revision_id, None)
            .await
            .unwrap();
        // Warm revision 1 too, then drop it from the store → orphan.
        h.warm_revision(&env, env.revisions[1].revision_id, None)
            .await
            .unwrap();
        env.revisions.remove(1);
        let ns = params_from_answers(&env, None).unwrap().namespace;
        cluster
            .apply(&json!({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "gtc-worker-handmade", "namespace": ns}}))
            .await
            .unwrap();
        cluster
            .apply(&json!({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "gtc-worker-other", "namespace": ns, "labels": {
                    "app.kubernetes.io/managed-by": "greentic",
                    "app.kubernetes.io/component": "worker",
                    "greentic.ai/env": "someone-else",
                    "greentic.ai/revision": "01ZZZZZZZZZZZZZZZZZZZZZZZZ"}}}))
            .await
            .unwrap();
        (h, cluster, env)
    }

    fn names(objs: &[SweptObject]) -> Vec<(String, String)> {
        objs.iter()
            .map(|o| (o.kind.clone(), o.name.clone()))
            .collect()
    }

    #[tokio::test]
    async fn dry_run_reports_orphans_and_deletes_nothing() {
        let (h, cluster, env) = seeded().await;
        let before = cluster.objects().len();
        let report = h.sweep(&env, None, false).await.unwrap();
        assert!(report.dry_run);
        assert_eq!(report.orphans.len(), 2, "{report:?}");
        assert!(report.removed.is_empty());
        assert_eq!(report.kept.len(), 2, "revision 0's worker pair");
        assert_eq!(cluster.objects().len(), before, "dry run mutates nothing");
    }

    #[tokio::test]
    async fn apply_removes_only_labeled_orphans() {
        let (h, cluster, env) = seeded().await;
        let report = h.sweep(&env, None, true).await.unwrap();
        assert!(!report.dry_run);
        assert_eq!(names(&report.removed), names(&report.orphans));
        assert_eq!(report.removed.len(), 2);
        let left: Vec<String> = cluster.objects().keys().map(|r| r.name.clone()).collect();
        assert!(
            left.iter().any(|n| n == "gtc-worker-handmade"),
            "unlabeled kept"
        );
        assert!(
            left.iter().any(|n| n == "gtc-worker-other"),
            "other env kept"
        );
        for orphan in &report.removed {
            assert!(!left.contains(&orphan.name), "{} removed", orphan.name);
        }
        // Idempotent: a second apply finds nothing.
        let again = h.sweep(&env, None, true).await.unwrap();
        assert!(again.orphans.is_empty());
    }

    #[tokio::test]
    async fn an_object_lacking_the_revision_label_is_skipped() {
        let cluster = Arc::new(InMemoryCluster::default());
        let h = K8sDeployerHandler::with_cluster(cluster.clone());
        let env = build_fixture_env();
        let ns = params_from_answers(&env, None).unwrap().namespace;
        let m = json!({"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "gtc-worker-x", "namespace": ns, "labels": {
                "app.kubernetes.io/managed-by": "greentic",
                "app.kubernetes.io/component": "worker",
                "greentic.ai/env": env.environment_id.as_str()}}});
        cluster.apply(&m).await.unwrap();
        let report = h.sweep(&env, None, true).await.unwrap();
        assert_eq!(report.skipped.len(), 1);
        assert!(report.orphans.is_empty());
        assert!(
            cluster
                .objects()
                .contains_key(&ObjectRef::from_manifest(&m).unwrap())
        );
    }

    #[tokio::test]
    async fn an_unconfigured_cluster_fails_honestly() {
        let h = K8sDeployerHandler::default();
        let err = h
            .sweep(&build_fixture_env(), None, false)
            .await
            .unwrap_err();
        assert!(matches!(err, DeployerError::Provider(_)), "{err:?}");
    }
}
