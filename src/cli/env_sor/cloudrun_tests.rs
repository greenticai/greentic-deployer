//! The Cloud Run SoR phase end to end against the fakes and a real store.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use super::prepare_tests::seeded_for_cloud_run;
use super::*;
use crate::cli::env_sor::publish::route_rel_path;
use crate::cli::env_sor::tests_stale::resolvable_in_seed;
use crate::cli::secrets::{DEV_STORE_KIND_PATH, get_env_secret, put_env_secret};
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;
use crate::env_packs::gcp_cloudrun::deployer::env_owner_stamp;
use crate::env_packs::gcp_cloudrun::sor::fake::InMemorySorServices;
use crate::environment::sor_units::AppliedSorUnit;

/// One Secret Manager per project (secrets are project-scoped, so a
/// same-named secret in two projects is two secrets); one service fake keyed
/// by `(project, region, name)`.
#[derive(Default)]
struct FakeTargets {
    /// Project `proj`, the one the answers name.
    secrets: Arc<InMemoryCloudRun>,
    other_projects: Mutex<BTreeMap<String, Arc<InMemoryCloudRun>>>,
    services: Arc<InMemorySorServices>,
    asked: Mutex<Vec<(String, String)>>,
}

impl FakeTargets {
    fn secrets_in(&self, project: &str) -> Arc<InMemoryCloudRun> {
        if project == "proj" {
            return self.secrets.clone();
        }
        self.other_projects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(project.to_string())
            .or_default()
            .clone()
    }

    fn asked(&self) -> Vec<(String, String)> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl SorTargets for FakeTargets {
    async fn at(&self, project: &str, region: &str) -> Result<SorTargetPair, OpError> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((project.to_string(), region.to_string()));
        let secrets: Arc<dyn CloudRunTarget> = self.secrets_in(project);
        let services: Arc<dyn SorServiceTarget> = self.services.clone();
        Ok((secrets, services))
    }
}

fn params(env: &Environment) -> GcpCloudRunParams {
    GcpCloudRunParams::from_answers(
        env,
        Some(&json!({"project": "proj", "region": "europe-west1", "secret_prefix": "gtc-local"})),
    )
    .unwrap()
}

fn timing() -> SorReadyTiming {
    SorReadyTiming {
        timeout: Duration::from_millis(40),
        poll: Duration::from_millis(5),
    }
}

fn route(store: &LocalFsStore, env: &Environment, sor: &str) -> Option<serde_json::Value> {
    get_env_secret(
        store,
        env,
        &env.environment_id,
        DEV_STORE_KIND_PATH,
        &route_rel_path(sor),
    )
    .unwrap()
    .0
    .map(|v| serde_json::from_str(&v).unwrap())
}

fn entry_at(id: &str, project: &str, region: &str, prefix: &str) -> AppliedSorUnit {
    AppliedSorUnit {
        unit_id: id.into(),
        sor: format!("{id}-sor"),
        namespace: String::new(),
        cloud_run: Some(CloudRunSorPlacement::for_unit(project, region, prefix, id)),
        input_refs: ["answers", "postgres_url", "shared_secret"]
            .iter()
            .map(|n| format!("default/_/sor-{id}/{n}"))
            .collect(),
    }
}

fn cloud_run_entry(id: &str, region: &str, prefix: &str) -> AppliedSorUnit {
    entry_at(id, "proj", region, prefix)
}

fn record(store: &LocalFsStore, env: &Environment, entry: &AppliedSorUnit) {
    store
        .transact(&env.environment_id, |l| {
            l.save_sor_ledger(std::slice::from_ref(entry))
        })
        .unwrap();
}

fn ledger_ids(store: &LocalFsStore, env: &Environment) -> Vec<String> {
    store
        .load_sor_ledger(&env.environment_id)
        .unwrap()
        .into_iter()
        .map(|a| a.unit_id)
        .collect()
}

async fn up_with(
    store: &LocalFsStore,
    env: &Environment,
    targets: &FakeTargets,
) -> Result<Option<CloudRunSorRun>, OpError> {
    up(
        store,
        env,
        &params(env),
        &SecretsBackend::DevStore,
        targets,
        timing(),
    )
    .await
}

#[tokio::test]
async fn a_declared_unit_comes_up_and_its_route_document_names_the_run_app_url() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let targets = FakeTargets::default();
    let run = up_with(&store, &env, &targets)
        .await
        .unwrap()
        .expect("a SoR phase");
    let url = InMemorySorServices::url_for("gtc-sor-b");
    assert_eq!(
        route(&store, &env, "b-sor"),
        Some(json!({"url": url, "token": "s", "tenant": "acme"}))
    );
    assert_eq!(run.up.statuses[0].service, "gtc-sor-b");
    assert_eq!(
        targets.asked(),
        vec![("proj".to_string(), "europe-west1".to_string())]
    );
}

/// A plain `#[test]`: `resolvable_in_seed` runs its own runtime, which cannot
/// start inside a tokio test's.
#[test]
fn the_worker_seed_excludes_every_sor_input_but_keeps_the_route_document() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(up_with(&store, &env, &FakeTargets::default()))
        .unwrap()
        .expect("a SoR phase");
    let inputs: Vec<String> = ["answers", "postgres_url", "shared_secret"]
        .iter()
        .map(|n| format!("default/_/sor-b/{n}"))
        .collect();
    assert!(
        resolvable_in_seed(&store, &env, &inputs).is_empty(),
        "the SoR's own credentials never ride into a worker"
    );
    let route_rel = route_rel_path("b-sor");
    assert_eq!(
        resolvable_in_seed(&store, &env, std::slice::from_ref(&route_rel)),
        vec![route_rel]
    );
}

#[tokio::test]
async fn the_ledger_narrows_only_after_finish_and_a_retired_unit_is_deleted() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let env_id = env.environment_id.clone();
    record(
        &store,
        &env,
        &cloud_run_entry("a", "europe-west1", "gtc-local"),
    );
    // P10: the retired SoR's route document exists, so its absence below is
    // something the run did.
    put_env_secret(
        &store,
        &env,
        &env_id,
        DEV_STORE_KIND_PATH,
        &route_rel_path("a-sor"),
        r#"{"url":"https://old","token":"t","tenant":"acme"}"#,
    )
    .unwrap();
    assert!(route(&store, &env, "a-sor").is_some());
    let targets = FakeTargets::default();
    let owner = env_owner_stamp("local");
    targets.services.seed_service("gtc-sor-a", Some(&owner));
    targets.secrets.seed_secret("gtc-local-sor-a", Some(&owner));

    let run = up_with(&store, &env, &targets).await.unwrap().unwrap();
    assert_eq!(
        ledger_ids(&store, &env),
        vec!["a".to_string(), "b".to_string()]
    );
    assert!(
        targets.services.service("gtc-sor-a").is_some(),
        "not before the workers"
    );

    let notes = finish(&store, &env_id, &run, &targets).await.unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(ledger_ids(&store, &env), vec!["b".to_string()]);
    assert!(targets.services.service("gtc-sor-a").is_none());
    assert!(!targets.secrets.secrets().contains_key("gtc-local-sor-a"));
    assert!(route(&store, &env, "a-sor").is_none());
}

#[tokio::test]
async fn a_failed_retirement_keeps_the_whole_ledger_for_the_next_run() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let env_id = env.environment_id.clone();
    record(
        &store,
        &env,
        &cloud_run_entry("a", "europe-west1", "gtc-local"),
    );
    let targets = FakeTargets::default();
    targets
        .services
        .seed_service("gtc-sor-a", Some(&env_owner_stamp("local")));
    let run = up_with(&store, &env, &targets).await.unwrap().unwrap();
    targets.services.refuse_deletes("HTTP 503");

    let err = finish(&store, &env_id, &run, &targets)
        .await
        .expect_err("the retirement failed");
    assert!(err.to_string().contains("HTTP 503"), "{err}");
    assert_eq!(
        ledger_ids(&store, &env),
        vec!["a".to_string(), "b".to_string()],
        "still on record, so the next run retries the retirement"
    );
    assert!(targets.services.service("gtc-sor-a").is_some());
}

#[tokio::test]
async fn a_sor_that_never_becomes_ready_writes_no_route_document_and_keeps_the_ledger_widened() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let targets = FakeTargets::default();
    targets.services.fail_boot("gtc-sor-b", "boom");
    let msg = up_with(&store, &env, &targets)
        .await
        .map(|_| ())
        .expect_err("failed")
        .to_string();
    assert!(msg.contains("boom"), "{msg}");
    assert!(
        route(&store, &env, "b-sor").is_none(),
        "no route to a dead SoR"
    );
    assert_eq!(store.load_sor_ledger(&env.environment_id).unwrap().len(), 1);
}

#[tokio::test]
async fn nothing_declared_and_nothing_recorded_asks_no_target() {
    let (_d, store, env) = seeded_for_cloud_run(&[]);
    let targets = FakeTargets::default();
    assert!(up_with(&store, &env, &targets).await.unwrap().is_none());
    assert!(targets.asked().is_empty());
}

#[tokio::test]
async fn a_retired_unit_in_another_region_is_retired_through_that_regions_target() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let env_id = env.environment_id.clone();
    // The same unit, recorded in the old region: its same-named service there
    // goes, the one just brought up in the new region stays.
    record(
        &store,
        &env,
        &cloud_run_entry("b", "us-central1", "gtc-local"),
    );
    let targets = FakeTargets::default();
    let owner = env_owner_stamp("local");
    targets
        .services
        .seed_service_at("proj", "us-central1", "gtc-sor-b", Some(&owner));

    let run = up_with(&store, &env, &targets).await.unwrap().unwrap();
    finish(&store, &env_id, &run, &targets).await.unwrap();
    assert!(
        targets
            .asked()
            .contains(&("proj".to_string(), "us-central1".to_string()))
    );
    assert!(
        targets
            .services
            .service_at("proj", "us-central1", "gtc-sor-b")
            .is_none()
    );
    assert!(targets.services.service("gtc-sor-b").is_some());
    assert!(
        targets.secrets.secrets().contains_key("gtc-local-sor-b"),
        "the project-scoped secret the new region uses stays"
    );
}

#[tokio::test]
async fn a_unit_that_moved_project_is_retired_only_in_the_old_project() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let env_id = env.environment_id.clone();
    record(
        &store,
        &env,
        &entry_at("b", "old-proj", "europe-west1", "gtc-local"),
    );
    let targets = FakeTargets::default();
    let owner = env_owner_stamp("local");
    targets
        .services
        .seed_service_at("old-proj", "europe-west1", "gtc-sor-b", Some(&owner));
    let old_secrets = targets.secrets_in("old-proj");
    old_secrets.seed_secret("gtc-local-sor-b", Some(&owner));

    let run = up_with(&store, &env, &targets).await.unwrap().unwrap();
    finish(&store, &env_id, &run, &targets).await.unwrap();

    assert!(
        !old_secrets.secrets().contains_key("gtc-local-sor-b"),
        "the old project's secret is deleted through the old project's target"
    );
    assert!(
        targets.secrets.secrets().contains_key("gtc-local-sor-b"),
        "the same-named secret in the new project survives"
    );
    assert!(
        targets
            .services
            .service_at("old-proj", "europe-west1", "gtc-sor-b")
            .is_none()
    );
    assert!(targets.services.service("gtc-sor-b").is_some());
    assert!(
        targets
            .asked()
            .contains(&("old-proj".to_string(), "europe-west1".to_string()))
    );
}

#[tokio::test]
async fn a_secret_prefix_change_keeps_the_live_service_and_deletes_only_the_old_secret() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let env_id = env.environment_id.clone();
    record(
        &store,
        &env,
        &cloud_run_entry("b", "europe-west1", "old-prefix"),
    );
    let targets = FakeTargets::default();
    let owner = env_owner_stamp("local");
    targets
        .secrets
        .seed_secret("old-prefix-sor-b", Some(&owner));

    let run = up_with(&store, &env, &targets).await.unwrap().unwrap();
    finish(&store, &env_id, &run, &targets).await.unwrap();
    assert!(
        targets.services.service("gtc-sor-b").is_some(),
        "the live SoR stays"
    );
    assert!(!targets.secrets.secrets().contains_key("old-prefix-sor-b"));
    assert!(targets.secrets.secrets().contains_key("gtc-local-sor-b"));
    let ledger = store.load_sor_ledger(&env_id).unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(
        ledger[0].cloud_run.as_ref().map(|p| p.secret.as_str()),
        Some("gtc-local-sor-b")
    );
}

#[tokio::test]
async fn the_result_gains_sor_keys_only_when_there_is_something_to_say() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let run = up_with(&store, &env, &FakeTargets::default())
        .await
        .unwrap()
        .unwrap();
    let mut result = json!({"environment_id": "local"});
    add_to_result(&mut result, &run, vec![]);
    assert_eq!(
        result["sor_units"],
        json!([{
            "unit_id": "b", "sor": "b-sor", "service": "gtc-sor-b",
            "url": InMemorySorServices::url_for("gtc-sor-b"), "ready": true,
        }])
    );
    assert!(result.get("sor_notes").is_none());
    assert!(result.get("sor_skipped_input_refs").is_none());
    assert!(
        !result.to_string().contains("\"s\""),
        "no token in the result"
    );

    add_to_result(&mut result, &run, vec!["left something".into()]);
    assert_eq!(result["sor_notes"], json!(["left something"]));
}
