//! The Cloud Run half of `prepare`: where a unit is recorded, and the three
//! refusals only this lane needs (secrets pack, bind, auth).

use super::*;
use crate::cli::env_sor::tests::{applied, seeded_with};
use crate::cli::secrets::{DEV_STORE_KIND_PATH, put_env_secret};
use crate::environment::EnvironmentStore as _;
use crate::environment::sor_units::{AppliedSorUnit, CloudRunSorPlacement};
use greentic_deploy_spec::CapabilitySlot;

/// What the designer's `sorx_deploy::answers::remote_answers("acme")` sends.
pub(super) const GOOD_ANSWERS: &str = r#"{"server":{"bind":"0.0.0.0:8787","auth":{"mode":"shared_secret","shared_secret_ref":"env:SORX_SHARED_SECRET"}},"providers":{"store":{"kind":"postgres"}},"tenant":{"tenant_id":"acme","environment":"production"}}"#;

/// `seeded_with` plus Cloud-Run-valid answers for every unit.
pub(super) fn seeded_for_cloud_run(
    unit_ids: &[&str],
) -> (tempfile::TempDir, LocalFsStore, Environment) {
    let (dir, store, env) = seeded_with(unit_ids);
    for id in unit_ids {
        set_answers(&store, &env, id, GOOD_ANSWERS);
    }
    (dir, store, env)
}

fn set_answers(store: &LocalFsStore, env: &Environment, id: &str, answers: &str) {
    put_env_secret(
        store,
        env,
        &env.environment_id,
        DEV_STORE_KIND_PATH,
        &format!("default/_/sor-{id}/answers"),
        answers,
    )
    .unwrap();
}

fn cloud_run(store: &LocalFsStore, env: &Environment) -> Result<Option<PreparedSor>, OpError> {
    prepare_cloud_run_with_override(
        store,
        env,
        "proj",
        "europe-west1",
        "gtc-local",
        &SecretsBackend::DevStore,
        None,
    )
}

fn ledger(store: &LocalFsStore, env: &Environment) -> Vec<AppliedSorUnit> {
    store.load_sor_ledger(&env.environment_id).unwrap()
}

#[test]
fn a_cloud_run_unit_is_recorded_with_its_service_secret_project_and_region() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let prepared = cloud_run(&store, &env).unwrap().expect("a SoR phase");
    let recorded = ledger(&store, &env);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].namespace, "");
    assert_eq!(
        recorded[0].cloud_run,
        Some(CloudRunSorPlacement {
            service: "gtc-sor-b".into(),
            secret: "gtc-local-sor-b".into(),
            project: "proj".into(),
            region: "europe-west1".into(),
        })
    );
    assert_eq!(prepared.placed_units().count(), 1);
}

#[test]
fn a_region_change_retires_the_unit_where_it_was_deployed() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let old = AppliedSorUnit {
        namespace: String::new(),
        cloud_run: Some(CloudRunSorPlacement::for_unit(
            "proj",
            "us-central1",
            "gtc-local",
            "b",
        )),
        ..applied("b", "unused")
    };
    store
        .transact(&env.environment_id, |l| {
            l.save_sor_ledger(std::slice::from_ref(&old))
        })
        .unwrap();
    let prepared = cloud_run(&store, &env).unwrap().unwrap();
    assert_eq!(prepared.retired_units, vec![old]);
    assert!(
        prepared.retired_sors.is_empty(),
        "the SoR is still declared"
    );
}

#[test]
fn a_k8s_ledger_entry_refuses_a_cloud_run_run_before_anything_is_written() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let k8s = applied("a", "gtc-local");
    store
        .transact(&env.environment_id, |l| {
            l.save_sor_ledger(std::slice::from_ref(&k8s))
        })
        .unwrap();
    let msg = cloud_run(&store, &env).err().expect("refused").to_string();
    assert!(msg.contains("greentic.deployer.k8s"), "{msg}");
    assert_eq!(ledger(&store, &env), vec![k8s]);
}

#[test]
fn cloud_run_refuses_an_env_with_no_secrets_pack() {
    let (_d, store, mut env) = seeded_for_cloud_run(&["b"]);
    env.packs.retain(|p| p.slot != CapabilitySlot::Secrets);
    store.save(&env).unwrap();
    let msg = cloud_run(&store, &env).err().expect("refused").to_string();
    assert!(msg.contains("greentic.secrets.dev-store"), "{msg}");
    assert!(ledger(&store, &env).is_empty(), "nothing recorded");
}

#[test]
fn cloud_run_refuses_answers_bound_off_the_container_port() {
    for bind in ["127.0.0.1:8787", "0.0.0.0:9000"] {
        let (_d, store, env) = seeded_for_cloud_run(&["b"]);
        let answers = GOOD_ANSWERS.replace("0.0.0.0:8787", bind);
        set_answers(&store, &env, "b", &answers);
        let msg = cloud_run(&store, &env).err().expect("refused").to_string();
        assert!(msg.contains("server.bind"), "{msg}");
        assert!(msg.contains("0.0.0.0:8787"), "{msg}");
        assert!(ledger(&store, &env).is_empty(), "nothing recorded");
    }
    let (_d, store, env) = seeded_with(&["b"]);
    let msg = cloud_run(&store, &env)
        .err()
        .expect("no bind is refused")
        .to_string();
    assert!(msg.contains("server.bind"), "{msg}");
}

#[test]
fn cloud_run_refuses_answers_that_leave_the_public_service_unauthenticated() {
    let (_d, store, env) = seeded_for_cloud_run(&["b"]);
    let answers = GOOD_ANSWERS.replace(r#""mode":"shared_secret""#, r#""mode":"none""#);
    set_answers(&store, &env, "b", &answers);
    let msg = cloud_run(&store, &env).err().expect("refused").to_string();
    assert!(msg.contains("server.auth.mode"), "{msg}");
    assert!(msg.contains("shared_secret"), "{msg}");
    assert!(ledger(&store, &env).is_empty(), "nothing recorded");
}

#[test]
fn a_retire_only_cloud_run_run_needs_no_secrets_pack_and_no_answers() {
    let (_d, store, mut env) = seeded_for_cloud_run(&[]);
    env.packs.retain(|p| p.slot != CapabilitySlot::Secrets);
    store.save(&env).unwrap();
    let old = AppliedSorUnit {
        namespace: String::new(),
        cloud_run: Some(CloudRunSorPlacement::for_unit(
            "proj",
            "europe-west1",
            "gtc-local",
            "a",
        )),
        ..applied("a", "unused")
    };
    store
        .transact(&env.environment_id, |l| {
            l.save_sor_ledger(std::slice::from_ref(&old))
        })
        .unwrap();
    let prepared = cloud_run(&store, &env).unwrap().expect("a retire phase");
    assert_eq!(prepared.retired_units, vec![old]);
}
