use std::cell::{Cell, RefCell};

use super::*;
use crate::cli::tests_common::{
    make_binding, make_bundle_deployment, make_env, make_revision, make_traffic_split,
};
use greentic_deploy_spec::{
    BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, MessagingEndpoint,
    MessagingEndpointId, RevisionLifecycle, SchemaVersion,
};
use tempfile::tempdir;

/// Records every hook call; `fail_teardowns` makes the first N teardowns err.
#[derive(Default)]
struct RecordingHooks {
    calls: RefCell<Vec<(&'static str, RevisionId)>>,
    fail_teardowns: Cell<usize>,
}

impl RetireHooks for RecordingHooks {
    fn drain(&self, _: &EnvId, r: RevisionId) -> Result<HookResult, OpError> {
        self.calls.borrow_mut().push(("drain", r));
        Ok(HookResult::Done)
    }
    fn teardown(&self, _: &EnvId, r: RevisionId) -> Result<HookResult, OpError> {
        self.calls.borrow_mut().push(("teardown", r));
        if self.fail_teardowns.get() > 0 {
            self.fail_teardowns.set(self.fail_teardowns.get() - 1);
            return Err(OpError::Conflict("cluster unreachable".to_string()));
        }
        Ok(HookResult::Done)
    }
}

/// Deployment `acme`: a Ready revision routed at 100 % plus a Failed one.
fn seed(store: &LocalFsStore) -> (DeploymentId, RevisionId, RevisionId) {
    let mut env = make_env("local");
    let dep = make_bundle_deployment("local", "acme");
    let did = dep.deployment_id;
    let ready = make_revision("local", "acme", &did, 1, RevisionLifecycle::Ready);
    let failed = make_revision("local", "acme", &did, 2, RevisionLifecycle::Failed);
    let (rid_ready, rid_failed) = (ready.revision_id, failed.revision_id);
    env.traffic_splits.push(make_traffic_split(
        "local", "acme", &did, &rid_ready, "seed",
    ));
    env.bundles.push(dep);
    env.revisions.extend([ready, failed]);
    store.save(&env).expect("seed env");
    (did, rid_ready, rid_failed)
}

fn payload(bundle: &str) -> BundleRetirePayload {
    BundleRetirePayload {
        environment_id: "local".to_string(),
        bundle: bundle.to_string(),
        customer_id: None,
        store_only: false,
        force_drain: false,
        idempotency_key: None,
    }
}

fn load(store: &LocalFsStore) -> Environment {
    store
        .load(&EnvId::try_from("local").expect("env id"))
        .expect("load")
}

#[test]
fn retire_runs_the_whole_sequence_in_order() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (did, ready, failed) = seed(&store);
    let hooks = RecordingHooks::default();
    let out = retire_with_hooks(&store, &hooks, payload("acme")).expect("retires");
    assert_eq!(out.noun, "bundles");
    assert_eq!(out.op, "retire");
    assert_eq!(out.result["state"], "retired");
    assert_eq!(out.result["deployment_id"], did.to_string());
    assert_eq!(out.result["split_cleared"], true);
    assert_eq!(out.result["drained"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        out.result["pruned_revision_ids"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        *hooks.calls.borrow(),
        vec![("drain", ready), ("teardown", ready), ("teardown", failed)],
        "drain before any teardown; teardown for every revision"
    );
    let env = load(&store);
    assert!(env.bundles.is_empty() && env.revisions.is_empty());
    assert!(env.traffic_splits.is_empty());
}

#[test]
fn a_second_retire_reports_absent() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (did, _, _) = seed(&store);
    let hooks = RecordingHooks::default();
    retire_with_hooks(&store, &hooks, payload(&did.to_string())).expect("first");
    let again = retire_with_hooks(&store, &hooks, payload(&did.to_string())).expect("replay");
    assert_eq!(again.result["state"], "absent");
}

#[test]
fn a_failed_teardown_stops_before_remove_and_a_rerun_finishes() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (_, ready, failed) = seed(&store);
    let hooks = RecordingHooks::default();
    hooks.fail_teardowns.set(1);
    let err = retire_with_hooks(&store, &hooks, payload("acme")).unwrap_err();
    assert_eq!(err.kind(), "conflict", "{err}");
    let env = load(&store);
    assert_eq!(env.bundles.len(), 1, "deployment kept as the record");
    assert_eq!(env.bundles[0].status, BundleDeploymentStatus::Archived);
    assert!(env.traffic_splits.is_empty());
    assert!(
        env.revisions
            .iter()
            .all(|r| r.lifecycle != RevisionLifecycle::Archived),
        "a revision whose teardown did not happen is never archived"
    );

    hooks.calls.borrow_mut().clear();
    let out = retire_with_hooks(&store, &hooks, payload("acme")).expect("resumes");
    assert_eq!(out.result["state"], "retired");
    assert_eq!(out.result["marked_retiring"], false);
    assert_eq!(
        *hooks.calls.borrow(),
        vec![("drain", ready), ("teardown", ready), ("teardown", failed)],
        "resume re-drains the still-draining revision and retries every teardown"
    );
    assert!(load(&store).bundles.is_empty());
}

#[test]
fn only_revisions_whose_teardown_succeeded_are_archived() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (_, ready, failed) = seed(&store);
    let hooks = FailSecondTeardown::default();
    let err = retire_with_hooks(&store, &hooks, payload("acme")).unwrap_err();
    assert!(err.to_string().contains(&failed.to_string()), "{err}");
    let env = load(&store);
    let lifecycle = |id| {
        env.revisions
            .iter()
            .find(|r| r.revision_id == id)
            .map(|r| r.lifecycle)
    };
    assert_eq!(lifecycle(ready), Some(RevisionLifecycle::Archived));
    assert_eq!(lifecycle(failed), Some(RevisionLifecycle::Failed));
    assert_eq!(env.bundles.len(), 1, "record kept");
}

#[derive(Default)]
struct FailSecondTeardown {
    seen: Cell<usize>,
}

impl RetireHooks for FailSecondTeardown {
    fn drain(&self, _: &EnvId, _: RevisionId) -> Result<HookResult, OpError> {
        Ok(HookResult::Done)
    }
    fn teardown(&self, _: &EnvId, _: RevisionId) -> Result<HookResult, OpError> {
        self.seen.set(self.seen.get() + 1);
        if self.seen.get() == 2 {
            return Err(OpError::Conflict("cluster unreachable".to_string()));
        }
        Ok(HookResult::Done)
    }
}

#[test]
fn a_bound_deployer_that_cannot_tear_down_refuses_before_touching_anything() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    seed(&store);
    let mut env = load(&store);
    env.packs.push(make_binding(
        CapabilitySlot::Deployer,
        "greentic.deployer.local-process@0.1.0",
    ));
    store.save(&env).expect("save");
    let before = load(&store);
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();
    let hooks = ProviderHooks {
        store: &store,
        registry: &registry,
        force_drain: false,
    };
    let err = retire_with_hooks(&store, &hooks, payload("acme")).unwrap_err();
    assert_eq!(err.kind(), "conflict", "{err}");
    assert!(err.to_string().contains("`remove` capability"), "{err}");
    assert_eq!(load(&store), before, "nothing mutated");

    let mut store_only = payload("acme");
    store_only.store_only = true;
    let out = retire(&store, &registry, &OpFlags::default(), Some(store_only))
        .expect("--store-only accepts the risk explicitly");
    assert_eq!(out.result["state"], "retired");
}

#[test]
fn a_linked_endpoint_refuses_and_changes_nothing() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    seed(&store);
    let mut env = load(&store);
    let now = env.bundles[0].created_at;
    env.messaging_endpoints.push(MessagingEndpoint {
        schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
        env_id: env.environment_id.clone(),
        endpoint_id: MessagingEndpointId::new(),
        provider_id: "legal-bot".to_string(),
        provider_type: "messaging.telegram.bot".to_string(),
        display_name: "legal-bot".to_string(),
        secret_refs: Vec::new(),
        webhook_secret_ref: None,
        linked_bundles: vec![BundleId::new("acme")],
        welcome_flow: None,
        generation: 0,
        created_at: now,
        updated_at: now,
        updated_by: "test".to_string(),
    });
    store.save(&env).expect("save");
    let before = load(&store);
    let hooks = RecordingHooks::default();
    let err = retire_with_hooks(&store, &hooks, payload("acme")).unwrap_err();
    assert_eq!(err.kind(), "conflict", "{err}");
    assert!(err.to_string().contains("legal-bot"), "{err}");
    assert_eq!(load(&store), before);
    assert!(hooks.calls.borrow().is_empty());
}

#[test]
fn an_ambiguous_bundle_id_needs_a_customer() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    seed(&store);
    let mut env = load(&store);
    let mut other = make_bundle_deployment("local", "acme");
    other.customer_id = CustomerId::new("other");
    env.bundles.push(other);
    store.save(&env).expect("save");
    let hooks = RecordingHooks::default();
    let err = retire_with_hooks(&store, &hooks, payload("acme")).unwrap_err();
    assert_eq!(err.kind(), "invalid-argument", "{err}");

    let mut scoped = payload("acme");
    scoped.customer_id = Some("other".to_string());
    let out = retire_with_hooks(&store, &hooks, scoped).expect("scoped retire");
    assert_eq!(out.result["customer_id"], "other");
    assert_eq!(load(&store).bundles.len(), 1);
}

#[test]
fn provider_hooks_report_unavailable_without_a_deployer_binding() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    seed(&store);
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();
    let hooks = ProviderHooks {
        store: &store,
        registry: &registry,
        force_drain: false,
    };
    let out = retire_with_hooks(&store, &hooks, payload("acme")).expect("retires");
    let teardown = out.result["teardown"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(teardown.len(), 2);
    assert!(teardown.iter().all(|t| t["result"] == "unavailable"));
}

#[test]
fn retire_drains_revisions_concurrently_and_keeps_input_order() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    let ids: Vec<RevisionId> = (0..6).map(|_| RevisionId::new()).collect();
    let live = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let started = Instant::now();
    let results = drain_concurrently(&ids, |r| {
        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        live.fetch_sub(1, Ordering::SeqCst);
        if r == ids[4] {
            Err(OpError::Conflict("boom".to_string()))
        } else {
            Ok(HookResult::Done)
        }
    });
    // 6 revisions at 4 at a time = two batches, not six sequential waits.
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(peak.load(Ordering::SeqCst), DRAIN_CONCURRENCY);
    assert_eq!(results.len(), 6);
    assert!(results[4].is_err());
    assert!(results.iter().enumerate().all(|(i, r)| i == 4 || r.is_ok()));
}
