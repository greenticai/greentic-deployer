use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use chrono::{DateTime, Utc};

use super::*;
use crate::bundle_deployment::{BundleDeployment, RevenueShareEntry, RouteBinding, TenantSelector};
use crate::engine::{fresh_environment, remove_bundle};
use crate::environment::EnvironmentHostConfig;
use crate::ids::{CustomerId, MessagingEndpointId, PartyId};
use crate::messaging_endpoint::MessagingEndpoint;
use crate::retention::{HealthStatus, RetentionPolicy, RevocationConfig};
use crate::revision::Revision;
use crate::traffic_split::TrafficSplitEntry;
use crate::version::SchemaVersion;

fn env_id() -> EnvId {
    EnvId::try_from("local").expect("valid env id")
}

fn now() -> DateTime<Utc> {
    "2026-09-28T00:00:00Z".parse().expect("valid timestamp")
}

fn env() -> Environment {
    fresh_environment(
        &env_id(),
        "Local".to_string(),
        EnvironmentHostConfig {
            env_id: env_id(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
            gui_enabled: None,
            default_bundle: None,
        },
        RevocationConfig::default(),
        RetentionPolicy::default(),
        HealthStatus::default(),
    )
}

fn deployment(bundle: &str) -> BundleDeployment {
    BundleDeployment {
        pack_name: None,
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id: DeploymentId::new(),
        env_id: env_id(),
        bundle_id: BundleId::new(bundle),
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: RouteBinding {
            hosts: Vec::new(),
            path_prefixes: Vec::new(),
            tenant_selector: TenantSelector {
                tenant: "default".to_string(),
                team: "default".to_string(),
            },
        },
        revenue_share: vec![RevenueShareEntry {
            party_id: PartyId::new("greentic"),
            basis_points: 10_000,
        }],
        revenue_policy_ref: PathBuf::from("revenue.json"),
        usage: None,
        created_at: now(),
        authorization_ref: PathBuf::from("auth.json"),
        config_overrides: BTreeMap::new(),
    }
}

fn revision(dep: &BundleDeployment, lifecycle: RevisionLifecycle) -> Revision {
    Revision {
        schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
        revision_id: RevisionId::new(),
        env_id: env_id(),
        bundle_id: dep.bundle_id.clone(),
        deployment_id: dep.deployment_id,
        sequence: 1,
        created_at: now(),
        bundle_digest: "sha256:deadbeef".to_string(),
        bundle_source_uri: None,
        pack_list: Vec::new(),
        pack_list_lock_ref: PathBuf::from("pack-list.lock"),
        pack_config_refs: Vec::new(),
        config_digest: "sha256:cafe".to_string(),
        signature_sidecar_ref: PathBuf::from("rev.sig"),
        lifecycle,
        staged_at: None,
        warmed_at: None,
        drain_seconds: 0,
        abort_metrics: Vec::new(),
        runtime_image_digest: None,
    }
}

fn split(dep: &BundleDeployment, routed: &[RevisionId]) -> TrafficSplit {
    let n = u32::try_from(routed.len()).expect("small");
    TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: env_id(),
        deployment_id: dep.deployment_id,
        bundle_id: dep.bundle_id.clone(),
        generation: 0,
        entries: routed
            .iter()
            .map(|r| TrafficSplitEntry {
                revision_id: *r,
                weight_bps: 10_000 / n,
            })
            .collect(),
        updated_at: now(),
        updated_by: "test".to_string(),
        idempotency_key: "k".to_string(),
        authorization_ref: PathBuf::from("auth.json"),
        previous_split_ref: None,
    }
}

fn endpoint(name: &str, linked: &str) -> MessagingEndpoint {
    MessagingEndpoint {
        schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
        env_id: env_id(),
        endpoint_id: MessagingEndpointId::new(),
        provider_id: name.to_string(),
        provider_type: "messaging.telegram.bot".to_string(),
        display_name: name.to_string(),
        secret_refs: Vec::new(),
        webhook_secret_ref: None,
        linked_bundles: vec![BundleId::new(linked)],
        welcome_flow: None,
        generation: 0,
        created_at: now(),
        updated_at: now(),
        updated_by: "test".to_string(),
    }
}

/// One live deployment: a Ready revision routed at 100 %.
fn live() -> (Environment, DeploymentId, RevisionId) {
    let mut env = env();
    let dep = deployment("acme");
    let rev = revision(&dep, RevisionLifecycle::Ready);
    env.traffic_splits.push(split(&dep, &[rev.revision_id]));
    let (did, rid) = (dep.deployment_id, rev.revision_id);
    env.bundles.push(dep);
    env.revisions.push(rev);
    (env, did, rid)
}

#[test]
fn clear_refuses_an_active_deployment_and_touches_nothing() {
    let (mut env, did, _) = live();
    let before = env.clone();
    let err = clear_traffic_split(&mut env, did).unwrap_err();
    assert!(matches!(err, RemovalError::NotRetiring { .. }), "{err}");
    assert_eq!(env, before);
}

#[test]
fn clear_removes_a_retiring_split_and_is_idempotent() {
    let (mut env, did, _) = live();
    env.bundles[0].status = BundleDeploymentStatus::Archived;
    let first = clear_traffic_split(&mut env, did).expect("clears");
    assert!(first.mutated());
    assert!(env.traffic_splits.is_empty());
    let again = clear_traffic_split(&mut env, did).expect("replay is ok");
    assert!(!again.mutated());
}

#[test]
fn clear_rejects_an_unknown_deployment() {
    let (mut env, _, _) = live();
    let err = clear_traffic_split(&mut env, DeploymentId::new()).unwrap_err();
    assert!(matches!(err, RemovalError::DeploymentNotFound { .. }));
}

#[test]
fn begin_retire_marks_clears_and_replays_as_noop() {
    let (mut env, did, _) = live();
    let first = begin_retire(&mut env, did).expect("begins");
    assert!(first.marked_retiring && first.cleared.is_some());
    assert_eq!(env.bundles[0].status, BundleDeploymentStatus::Archived);
    let again = begin_retire(&mut env, did).expect("replay");
    assert!(!again.mutated());
}

#[test]
fn begin_retire_refuses_while_an_endpoint_links_the_bundle() {
    let (mut env, did, _) = live();
    env.messaging_endpoints.push(endpoint("legal-bot", "acme"));
    let before = env.clone();
    let err = begin_retire(&mut env, did).unwrap_err();
    match err {
        RemovalError::LinkedFromEndpoint { endpoints, .. } => {
            assert_eq!(endpoints, vec!["legal-bot".to_string()]);
        }
        other => panic!("unexpected {other}"),
    }
    assert_eq!(env, before, "refusal must not mutate");
}

#[test]
fn a_surviving_sibling_deployment_satisfies_the_endpoint_guard() {
    let (mut env, did, _) = live();
    let mut sibling = deployment("acme");
    sibling.customer_id = CustomerId::new("other");
    env.bundles.push(sibling);
    env.messaging_endpoints.push(endpoint("legal-bot", "acme"));
    begin_retire(&mut env, did).expect("sibling keeps the link valid");
}

#[test]
fn retire_steps_walk_to_a_removable_deployment() {
    let (mut env, did, ready) = live();
    let failed = revision(&env.bundles[0], RevisionLifecycle::Failed);
    let failed_id = failed.revision_id;
    env.revisions.push(failed);
    begin_retire(&mut env, did).expect("begins");
    let steps = retire_steps(&env, did).expect("steps");
    assert_eq!(steps.drain_stamp, vec![ready]);
    assert_eq!(steps.drain_hook, vec![ready]);
    assert_eq!(steps.archive, vec![ready, failed_id]);
    assert_eq!(steps.teardown, vec![ready, failed_id]);
    for r in &steps.drain_stamp {
        crate::engine::drain_revision(&mut env, *r).expect("drains");
    }
    for r in &steps.archive {
        crate::engine::archive_revision(&mut env, *r).expect("archives");
    }
    let resumed = retire_steps(&env, did).expect("steps");
    assert!(resumed.archive.is_empty() && resumed.drain_hook.is_empty());
    assert_eq!(resumed.teardown.len(), 2, "teardown re-runs on resume");
    let removed = remove_bundle(&mut env, did).expect("removable");
    assert_eq!(removed.pruned_revision_ids.len(), 2);
}

#[test]
fn prune_plan_touches_only_owned_deployments() {
    let (mut env, owned_gone, _) = live();
    let unowned = deployment("manual");
    let unowned_id = unowned.deployment_id;
    env.bundles.push(unowned);
    let owned: BTreeSet<_> = [owned_gone].into();
    let declared = BTreeSet::new();
    let plan = prune_plan(&env, &owned, &declared);
    assert_eq!(plan.retire, vec![owned_gone]);
    assert!(!plan.retire.contains(&unowned_id));
}

#[test]
fn prune_plan_never_names_a_declared_deployment_or_its_revisions() {
    let (mut env, did, _) = live();
    let dep = env.bundles[0].clone();
    // A warmed canary: Ready, unrouted.
    env.revisions.push(revision(&dep, RevisionLifecycle::Ready));
    let set: BTreeSet<_> = [did].into();
    assert!(prune_plan(&env, &set, &set).is_empty());
}

#[test]
fn a_retire_set_cannot_vouch_for_itself_on_endpoint_links() {
    let (mut env, first, _) = live();
    let mut second = deployment("acme");
    second.customer_id = CustomerId::new("other");
    let second_id = second.deployment_id;
    env.bundles.push(second);
    env.messaging_endpoints.push(endpoint("legal-bot", "acme"));
    // Each alone has a surviving sibling...
    check_retire_links(&env, first).expect("sibling survives");
    // ...but retiring both strands the endpoint.
    let err = check_retire_set_links(&env, &BTreeSet::from([first, second_id])).unwrap_err();
    assert!(
        matches!(err, RemovalError::LinkedFromEndpoint { .. }),
        "{err}"
    );
}

#[test]
fn a_retiring_sibling_is_not_a_survivor() {
    let (mut env, did, _) = live();
    let mut sibling = deployment("acme");
    sibling.customer_id = CustomerId::new("other");
    sibling.status = BundleDeploymentStatus::Archived;
    env.bundles.push(sibling);
    env.messaging_endpoints.push(endpoint("legal-bot", "acme"));
    let err = check_retire_links(&env, did).unwrap_err();
    assert!(
        matches!(err, RemovalError::LinkedFromEndpoint { .. }),
        "{err}"
    );
}
