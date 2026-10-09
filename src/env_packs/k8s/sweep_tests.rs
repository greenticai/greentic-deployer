//! Tests for [`super`] (the orphan sweep).
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
    let h = K8sDeployerHandler::with_cluster(cluster.clone()).with_store_label(Some("s-a".into()));
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
    let h = K8sDeployerHandler::with_cluster(cluster.clone()).with_store_label(Some("s-a".into()));
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

/// H1: two stores, same env id, same namespace. Store A's sweep must never
/// touch store B's live workers, even though B's revisions are absent from A.
#[tokio::test]
async fn sweeping_store_a_never_touches_store_b_with_the_same_env_id() {
    let cluster = Arc::new(InMemoryCluster::default());
    let a = K8sDeployerHandler::with_cluster(cluster.clone()).with_store_label(Some("s-a".into()));
    let b = K8sDeployerHandler::with_cluster(cluster.clone()).with_store_label(Some("s-b".into()));
    let full = build_fixture_env();
    // Store A holds revision 0; store B holds revision 1. Same env id.
    let mut env_a = full.clone();
    env_a
        .revisions
        .retain(|r| r.revision_id == full.revisions[0].revision_id);
    let mut env_b = full.clone();
    env_b
        .revisions
        .retain(|r| r.revision_id == full.revisions[1].revision_id);
    a.warm_revision(&full, full.revisions[0].revision_id, None)
        .await
        .unwrap();
    b.warm_revision(&full, full.revisions[1].revision_id, None)
        .await
        .unwrap();
    let before = cluster.objects().len();

    let report = a.sweep(&env_a, None, true).await.unwrap();
    assert!(
        report.orphans.is_empty() && report.removed.is_empty(),
        "{report:?}"
    );
    assert_eq!(report.kept.len(), 2);
    assert_eq!(report.skipped.len(), 2, "B's pair is skipped: {report:?}");
    assert!(
        report
            .skipped
            .iter()
            .all(|s| s.reason.contains("another store"))
    );
    assert_eq!(
        cluster.objects().len(),
        before,
        "nothing of B's was deleted"
    );
    // And symmetrically.
    let report = b.sweep(&env_b, None, true).await.unwrap();
    assert!(report.removed.is_empty(), "{report:?}");
    assert_eq!(cluster.objects().len(), before);
}

#[tokio::test]
async fn a_worker_without_the_store_label_is_unattributed_and_kept() {
    let cluster = Arc::new(InMemoryCluster::default());
    let legacy = K8sDeployerHandler::with_cluster(cluster.clone()); // no store label
    let mut env = build_fixture_env();
    legacy
        .warm_revision(&env, env.revisions[1].revision_id, None)
        .await
        .unwrap();
    env.revisions.remove(1);
    let h = K8sDeployerHandler::with_cluster(cluster.clone()).with_store_label(Some("s-a".into()));
    let before = cluster.objects().len();
    let report = h.sweep(&env, None, true).await.unwrap();
    assert_eq!(report.unattributed.len(), 2, "{report:?}");
    assert!(report.orphans.is_empty() && report.removed.is_empty());
    assert_eq!(cluster.objects().len(), before);
}

#[tokio::test]
async fn an_unparseable_revision_label_is_skipped_never_an_orphan() {
    let cluster = Arc::new(InMemoryCluster::default());
    let h = K8sDeployerHandler::with_cluster(cluster.clone()).with_store_label(Some("s-a".into()));
    let env = build_fixture_env();
    let ns = params_from_answers(&env, None).unwrap().namespace;
    cluster
        .apply(&json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "gtc-worker-bad", "namespace": ns, "labels": {
                "app.kubernetes.io/managed-by": "greentic",
                "app.kubernetes.io/component": "worker",
                "greentic.ai/env": env.environment_id.as_str(),
                "greentic.ai/store": "s-a",
                "greentic.ai/revision": "not-a-ulid"}}}))
        .await
        .unwrap();
    let report = h.sweep(&env, None, true).await.unwrap();
    assert!(report.orphans.is_empty(), "{report:?}");
    assert!(report.skipped[0].reason.contains("unparseable"));
}

#[test]
fn store_label_is_stable_per_path_and_distinct_across_stores() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    assert_eq!(store_label_for(a.path()), store_label_for(a.path()));
    assert_ne!(store_label_for(a.path()), store_label_for(b.path()));
    assert!(store_label_for(a.path()).len() <= 63);
}

/// Validator fake: denies every `list`, or fails the review outright.
#[derive(Debug)]
struct Reviewer {
    deny_list: bool,
    fail: bool,
}

#[async_trait::async_trait]
impl K8sValidatorClient for Reviewer {
    async fn who_am_i(
        &self,
    ) -> Result<
        crate::env_packs::k8s::credentials::ClusterIdentity,
        crate::env_packs::k8s::credentials::K8sClientError,
    > {
        Ok(crate::env_packs::k8s::credentials::ClusterIdentity { user: "t".into() })
    }
    async fn review_access<'a>(
        &'a self,
        _namespace: &'a str,
        operations: &'a [crate::env_packs::k8s::credentials::K8sOperation],
    ) -> Result<
        Vec<crate::env_packs::k8s::credentials::OperationDecision>,
        crate::env_packs::k8s::credentials::K8sClientError,
    > {
        if self.fail {
            return Err(
                crate::env_packs::k8s::credentials::K8sClientError::ApiRejected("boom".into()),
            );
        }
        Ok(operations
            .iter()
            .map(|op| crate::env_packs::k8s::credentials::OperationDecision {
                operation: *op,
                decision: if self.deny_list && op.verb == "list" {
                    AccessDecision::Denied("rbac".into())
                } else {
                    AccessDecision::Allowed
                },
            })
            .collect())
    }
    async fn review_cluster_access<'a>(
        &'a self,
        operations: &'a [crate::env_packs::k8s::credentials::K8sOperation],
    ) -> Result<
        Vec<crate::env_packs::k8s::credentials::OperationDecision>,
        crate::env_packs::k8s::credentials::K8sClientError,
    > {
        self.review_access("", operations).await
    }
}

#[tokio::test]
async fn preflight_passes_when_list_is_granted() {
    let r = Reviewer {
        deny_list: false,
        fail: false,
    };
    require_sweep_access(&r, "zain", "gtc-zain").await.unwrap();
}

#[tokio::test]
async fn preflight_names_the_missing_permission_and_the_rebootstrap() {
    let r = Reviewer {
        deny_list: true,
        fail: false,
    };
    let err = require_sweep_access(&r, "zain", "gtc-zain")
        .await
        .unwrap_err();
    match &err {
        SweepPreflightError::MissingPermission { permissions, .. } => assert_eq!(
            permissions,
            &vec![
                "k8s.rbac.allow:apps/deployments:list".to_string(),
                "k8s.rbac.allow:core/services:list".to_string()
            ]
        ),
        other => panic!("expected MissingPermission, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(msg.contains("gtc op credentials bootstrap zain"), "{msg}");
    assert!(msg.contains("apps/deployments:list"), "{msg}");
}

#[tokio::test]
async fn preflight_fails_closed_when_the_review_fails() {
    let r = Reviewer {
        deny_list: false,
        fail: true,
    };
    assert!(matches!(
        require_sweep_access(&r, "zain", "gtc-zain").await,
        Err(SweepPreflightError::ReviewFailed(_))
    ));
}
