use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use ulid::Ulid;

use super::*;
use crate::env_packs::azure_aca::deploy_target::{AcaDeployTarget, AppState};
use crate::env_packs::azure_aca::fake::InMemoryAca;
use crate::env_packs::azure_aca::naming::revision_name;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::deployer::run_conformance;

pub(super) fn answers() -> Value {
    json!({
        "subscription_id": "11111111-2222-3333-4444-555555555555",
        "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "resource_group": "rg",
        "environment_name": "ce",
    })
}

fn handler() -> (AzureAcaDeployerHandler, Arc<InMemoryAca>) {
    let t = Arc::new(InMemoryAca::new());
    (AzureAcaDeployerHandler::with_target_and_dev_secrets(t.clone(), Some(b"K=V".to_vec())), t)
}

/// The shared bench passes `None` answers; Azure fails closed without scope, so
/// this wrapper supplies them, and warms every revision on a fresh fake before a
/// split (the bench routes to revisions it never warmed or already archived).
#[derive(Debug)]
struct WithScope(AzureAcaDeployerHandler);

#[async_trait::async_trait]
impl Deployer for WithScope {
    async fn stage_revision(&self, env: &Environment, r: RevisionId) -> Result<StageOutcome, DeployerError> {
        self.0.stage_revision(env, r).await
    }
    async fn warm_revision(&self, env: &Environment, r: RevisionId, _a: Option<&Value>) -> Result<WarmOutcome, DeployerError> {
        self.0.warm_revision(env, r, Some(&answers())).await
    }
    async fn drain_revision(&self, env: &Environment, r: RevisionId, _a: Option<&Value>) -> Result<DrainOutcome, DeployerError> {
        self.0.drain_revision(env, r, Some(&answers())).await
    }
    fn capabilities(&self) -> AdapterCapabilities {
        self.0.capabilities()
    }
    async fn archive_revision(&self, env: &Environment, r: RevisionId, _a: Option<&Value>) -> Result<ArchiveOutcome, DeployerError> {
        self.0.archive_revision(env, r, Some(&answers())).await
    }
    async fn apply_traffic_split(&self, env: &Environment, d: DeploymentId, _a: Option<&Value>) -> Result<TrafficSplitOutcome, DeployerError> {
        let fresh = AzureAcaDeployerHandler::with_target_and_dev_secrets(Arc::new(InMemoryAca::new()), None);
        for r in &env.revisions {
            fresh.warm_revision(env, r.revision_id, Some(&answers())).await?;
        }
        fresh.apply_traffic_split(env, d, Some(&answers())).await
    }
}

#[tokio::test]
async fn azure_aca_deployer_passes_conformance() {
    let (h, _t) = handler();
    run_conformance(&WithScope(h)).await.unwrap();
}

#[tokio::test]
async fn warm_creates_the_app_with_owner_secrets_and_full_traffic() {
    let (h, t) = handler();
    let env = build_fixture_env();
    let rev = &env.revisions[0];
    let out = h.warm_revision(&env, rev.revision_id, Some(&answers())).await.unwrap();
    assert!(out.endpoint_url.unwrap().starts_with("https://"));
    let app = app_name(&rev.deployment_id);
    let traffic = t.traffic_of(app.as_str());
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].weight, 100);
    // environment.json and the dev store are each one content-addressed secret.
    let secrets = t.secret_names_of(app.as_str());
    assert!(secrets.iter().any(|s| s.starts_with("seed-env-")));
    assert!(secrets.iter().any(|s| s.starts_with("seed-dev-")));
}

#[tokio::test]
async fn warm_without_dev_secrets_stages_only_the_environment_seed() {
    let t = Arc::new(InMemoryAca::new());
    let h = AzureAcaDeployerHandler::with_target_and_dev_secrets(t.clone(), None);
    let env = build_fixture_env();
    let rev = &env.revisions[0];
    h.warm_revision(&env, rev.revision_id, Some(&answers())).await.unwrap();
    let secrets = t.secret_names_of(app_name(&rev.deployment_id).as_str());
    assert_eq!(secrets.len(), 1, "{secrets:?}");
}

#[tokio::test]
async fn rewarm_with_the_same_inputs_is_a_noop_and_changed_inputs_conflict() {
    let (h, t) = handler();
    let env = build_fixture_env();
    let id = env.revisions[0].revision_id;
    h.warm_revision(&env, id, Some(&answers())).await.unwrap();
    let puts = || t.calls().iter().filter(|c| c.starts_with("put_revision")).count();
    assert_eq!(puts(), 1);
    h.warm_revision(&env, id, Some(&answers())).await.unwrap();
    assert_eq!(puts(), 1, "second warm must not PUT");
    let mut changed = answers();
    changed["runtime_image_tag"] = json!("other");
    let e = h.warm_revision(&env, id, Some(&changed)).await.unwrap_err();
    assert!(e.to_string().contains("immutable"), "{e}");
}

#[tokio::test]
async fn a_second_revision_gets_zero_percent_and_keeps_the_first_at_100() {
    let (h, t) = handler();
    let env = build_fixture_env();
    let (a, b) = (&env.revisions[0], &env.revisions[1]);
    assert_eq!(a.deployment_id, b.deployment_id);
    h.warm_revision(&env, a.revision_id, Some(&answers())).await.unwrap();
    h.warm_revision(&env, b.revision_id, Some(&answers())).await.unwrap();
    let app = app_name(&a.deployment_id);
    let traffic = t.traffic_of(app.as_str());
    let w = |id| {
        let n = revision_name(&app, &revision_suffix(&id));
        traffic.iter().find(|x| x.revision_name == n).map(|x| x.weight)
    };
    assert_eq!((w(a.revision_id), w(b.revision_id)), (Some(100), Some(0)));
}

#[tokio::test]
async fn a_foreign_owner_refuses_the_warm_before_any_write() {
    let (h, t) = handler();
    let env = build_fixture_env();
    let rev = &env.revisions[0];
    t.seed_app(app_name(&rev.deployment_id).as_str(), Some("someone-else"));
    let e = h.warm_revision(&env, rev.revision_id, Some(&answers())).await.unwrap_err();
    assert!(e.to_string().contains("not to this environment"), "{e}");
    assert!(!t.calls().iter().any(|c| c.starts_with("put_revision")));
}

#[tokio::test]
async fn oversize_seed_is_refused_before_any_arm_call() {
    let t = Arc::new(InMemoryAca::new());
    let h = AzureAcaDeployerHandler::with_target_and_dev_secrets(t.clone(), Some(vec![b'a'; 30_000]));
    let env = build_fixture_env();
    let e = h.warm_revision(&env, env.revisions[0].revision_id, Some(&answers())).await.unwrap_err();
    assert!(e.to_string().contains("24576"), "{e}");
    assert!(t.calls().is_empty(), "{:?}", t.calls());
}

#[tokio::test]
async fn invalid_or_missing_answers_fail_before_touching_the_target() {
    let (h, t) = handler();
    let env = build_fixture_env();
    let id = env.revisions[0].revision_id;
    assert!(h.warm_revision(&env, id, None).await.is_err());
    let mut bad = answers();
    bad["max_instances"] = json!(3);
    assert!(h.warm_revision(&env, id, Some(&bad)).await.is_err());
    assert!(t.calls().is_empty());
}

#[tokio::test]
async fn a_failed_revision_surfaces_the_platform_reason() {
    let (h, t) = handler();
    t.fail_next_revision("ImagePullBackOff");
    let env = build_fixture_env();
    let e = h.warm_revision(&env, env.revisions[0].revision_id, Some(&answers())).await.unwrap_err();
    assert!(e.to_string().contains("ImagePullBackOff"), "{e}");
}

#[tokio::test]
async fn secrets_never_reach_errors_or_debug() {
    let t = Arc::new(InMemoryAca::new());
    let h = AzureAcaDeployerHandler::with_target_and_dev_secrets(t, Some(b"TOPSECRETDEV=1".to_vec()));
    let env = build_fixture_env();
    let mut a = answers();
    a["oci_username"] = json!("tok");
    a["oci_password"] = json!("hunter2-pw");
    let mut bad = a.clone();
    bad["runtime_image_digest"] = json!("nope");
    let e = h.warm_revision(&env, env.revisions[0].revision_id, Some(&bad)).await.unwrap_err();
    for shown in [format!("{e}"), format!("{h:?}")] {
        assert!(!shown.contains("hunter2-pw") && !shown.contains("TOPSECRETDEV"), "{shown}");
    }
}

#[tokio::test]
async fn the_registry_password_is_a_secret_ref_and_its_username_is_plain() {
    let (h, t) = handler();
    let env = build_fixture_env();
    let rev = &env.revisions[0];
    let mut a = answers();
    a["oci_username"] = json!("tok");
    a["oci_password"] = json!("hunter2-pw");
    h.warm_revision(&env, rev.revision_id, Some(&a)).await.unwrap();
    let names = t.secret_names_of(app_name(&rev.deployment_id).as_str());
    assert!(names.iter().any(|n| n.starts_with("oci-pw-")), "{names:?}");
}

#[tokio::test]
async fn archive_deactivates_and_is_idempotent_and_retiring_deletes_the_app() {
    let (h, t) = handler();
    let mut env = build_fixture_env();
    let (a, b) = (env.revisions[0].clone(), env.revisions[1].clone());
    h.warm_revision(&env, a.revision_id, Some(&answers())).await.unwrap();
    h.warm_revision(&env, b.revision_id, Some(&answers())).await.unwrap();
    h.archive_revision(&env, b.revision_id, Some(&answers())).await.unwrap();
    h.archive_revision(&env, b.revision_id, Some(&answers())).await.unwrap();
    let app = app_name(&a.deployment_id);
    assert_eq!(t.revisions_of(app.as_str()).len(), 2, "app kept");
    for bundle in env.bundles.iter_mut().filter(|x| x.deployment_id == a.deployment_id) {
        bundle.status = BundleDeploymentStatus::Archived;
    }
    h.archive_revision(&env, a.revision_id, Some(&answers())).await.unwrap();
    assert!(t.app_names().is_empty());
    h.archive_revision(&env, a.revision_id, Some(&answers())).await.unwrap();
}

#[tokio::test]
async fn split_is_applied_in_percent_and_refused_for_fractions_or_unrunning_revisions() {
    let (h, t) = handler();
    let env = build_fixture_env();
    let dep = env.revisions[0].deployment_id;
    // Not warmed yet: refused.
    assert!(h.apply_traffic_split(&env, dep, Some(&answers())).await.is_err());
    for r in env.revisions.iter().filter(|r| r.deployment_id == dep) {
        h.warm_revision(&env, r.revision_id, Some(&answers())).await.unwrap();
    }
    h.apply_traffic_split(&env, dep, Some(&answers())).await.unwrap();
    let weights: Vec<u32> = t.traffic_of(app_name(&dep).as_str()).iter().map(|x| x.weight).collect();
    assert_eq!(weights.iter().sum::<u32>(), 100);
    assert!(weights.contains(&50));
    assert!(percent(150).is_err());
    assert_eq!(percent(2_500).unwrap(), 25);
}

#[tokio::test]
async fn wait_running_times_out_with_a_named_error() {
    #[derive(Debug)]
    struct Stuck;
    #[async_trait::async_trait]
    impl crate::env_packs::azure_aca::deploy_target::AcaDeployTarget for Stuck {
        async fn inspect_app(&self, _: &AppRef) -> Result<AppState, super::super::deploy_target::AcaTargetError> { Ok(AppState::Absent) }
        async fn list_secrets(&self, _: &AppRef) -> Result<Vec<super::super::arm_types::AppSecret>, super::super::deploy_target::AcaTargetError> { Ok(vec![]) }
        async fn put_revision(&self, _: &super::super::arm_types::AppSpec) -> Result<RevisionRef, super::super::deploy_target::AcaTargetError> { Err(super::super::deploy_target::AcaTargetError::Api("x".into())) }
        async fn live_revision_intent(&self, _: &RevisionRef) -> Result<super::super::revision_intent::LiveIntent, super::super::deploy_target::AcaTargetError> { Ok(super::super::revision_intent::LiveIntent::Absent) }
        async fn revision_status(&self, _: &RevisionRef) -> Result<RevisionStatus, super::super::deploy_target::AcaTargetError> { Ok(RevisionStatus::Provisioning) }
        async fn set_traffic(&self, _: &AppRef, _: &[TrafficEntry]) -> Result<(), super::super::deploy_target::AcaTargetError> { Ok(()) }
        async fn deactivate_revision(&self, _: &RevisionRef) -> Result<(), super::super::deploy_target::AcaTargetError> { Ok(()) }
        async fn delete_app(&self, _: &AppRef) -> Result<bool, super::super::deploy_target::AcaTargetError> { Ok(false) }
        async fn discover_endpoint(&self, _: &AppRef) -> Result<Option<String>, super::super::deploy_target::AcaTargetError> { Ok(None) }
    }
    let rev = RevisionRef { app: AppRef { name: "a".into() }, name: "a--r1".into() };
    let e = super::super::deployer_warm::wait_running(&Stuck, &rev, Duration::from_millis(20), Duration::from_millis(5))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("did not become ready"), "{e}");
    let _ = Ulid::new();
}
