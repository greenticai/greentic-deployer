use super::*;
use crate::cli::tests_common::{
    make_bundle_deployment, make_env, make_revision, make_traffic_split,
};
use greentic_deploy_spec::{BundleDeploymentStatus, RevisionLifecycle};
use tempfile::tempdir;

/// A live deployment with two Ready revisions, the first routed at 100 %.
fn seed(store: &LocalFsStore) -> (DeploymentId, RevisionId, RevisionId) {
    let mut env = make_env("local");
    let dep = make_bundle_deployment("local", "acme");
    let did = dep.deployment_id;
    let r1 = make_revision("local", "acme", &did, 1, RevisionLifecycle::Ready);
    let r2 = make_revision("local", "acme", &did, 2, RevisionLifecycle::Ready);
    let (rid1, rid2) = (r1.revision_id, r2.revision_id);
    env.traffic_splits
        .push(make_traffic_split("local", "acme", &did, &rid1, "seed"));
    env.bundles.push(dep);
    env.revisions.extend([r1, r2]);
    store.save(&env).expect("seed env");
    (did, rid1, rid2)
}

fn payload(did: DeploymentId, survivor: Option<RevisionId>) -> TrafficClearPayload {
    TrafficClearPayload {
        environment_id: "local".to_string(),
        deployment_id: did.to_string(),
        survivor: survivor.map(|r| r.to_string()),
        idempotency_key: None,
        updated_by: None,
    }
}

fn load(store: &LocalFsStore) -> greentic_deploy_spec::Environment {
    store
        .load(&EnvId::try_from("local").expect("env id"))
        .expect("load")
}

#[test]
fn survivor_takes_all_traffic_and_a_retry_replays() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (did, _, rid2) = seed(&store);
    let flags = OpFlags::default();
    let first = clear(&store, &flags, Some(payload(did, Some(rid2)))).expect("clear");
    assert_eq!(first.noun, "traffic");
    assert_eq!(first.op, "clear");
    assert_eq!(first.result["mode"], "survivor");
    assert_eq!(first.result["changed"], true);
    let split = &load(&store).traffic_splits[0];
    assert_eq!(split.entries.len(), 1);
    assert_eq!(split.entries[0].revision_id, rid2);
    assert_eq!(split.entries[0].weight_bps, 10_000);
    let generation = split.generation;

    let again = clear(&store, &flags, Some(payload(did, Some(rid2)))).expect("replay");
    assert_eq!(again.result["changed"], false);
    assert_eq!(load(&store).traffic_splits[0].generation, generation);
}

#[test]
fn survivor_must_be_ready() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (did, _, rid2) = seed(&store);
    let mut env = load(&store);
    if let Some(r) = env.revisions.iter_mut().find(|r| r.revision_id == rid2) {
        r.lifecycle = RevisionLifecycle::Failed;
    }
    store.save(&env).expect("save");
    let err = clear(&store, &OpFlags::default(), Some(payload(did, Some(rid2)))).unwrap_err();
    assert_eq!(err.kind(), "conflict", "{err}");
}

#[test]
fn clearing_a_live_deployment_without_a_survivor_is_refused() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (did, _, _) = seed(&store);
    let err = clear(&store, &OpFlags::default(), Some(payload(did, None))).unwrap_err();
    assert_eq!(err.kind(), "conflict", "{err}");
    assert!(err.to_string().contains("not retiring"), "{err}");
    assert_eq!(load(&store).traffic_splits.len(), 1, "split untouched");
}

#[test]
fn clearing_a_retiring_deployment_removes_the_split_idempotently() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (did, _, _) = seed(&store);
    let mut env = load(&store);
    env.bundles[0].status = BundleDeploymentStatus::Archived;
    store.save(&env).expect("save");
    let flags = OpFlags::default();
    let first = clear(&store, &flags, Some(payload(did, None))).expect("clears");
    assert_eq!(first.result["mode"], "cleared");
    assert_eq!(first.result["changed"], true);
    assert!(load(&store).traffic_splits.is_empty());
    let again = clear(&store, &flags, Some(payload(did, None))).expect("replay");
    assert_eq!(again.result["changed"], false);
}

#[test]
fn unknown_deployment_is_not_found() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    seed(&store);
    let err = clear(
        &store,
        &OpFlags::default(),
        Some(payload(DeploymentId::new(), None)),
    )
    .unwrap_err();
    assert_eq!(err.kind(), "not-found", "{err}");
}

#[test]
fn args_without_a_deployment_are_refused() {
    let err = payload_from_clear_args(TrafficClearArgs {
        env_id: Some("local".to_string()),
        deployment: None,
        survivor: None,
        idempotency_key: None,
    })
    .unwrap_err();
    assert_eq!(err.kind(), "invalid-argument");
    let none = payload_from_clear_args(TrafficClearArgs {
        env_id: None,
        deployment: None,
        survivor: None,
        idempotency_key: None,
    })
    .expect("blank args defer to --answers");
    assert!(none.is_none());
}
