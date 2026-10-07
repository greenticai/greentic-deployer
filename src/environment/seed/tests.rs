use std::borrow::Cow;

use chrono::{TimeZone, Utc};
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
    Environment, EnvironmentHostConfig, PackId, PackListEntry, PartyId, RevenueShareEntry,
    Revision, RevisionId, RevisionLifecycle, RouteBinding, SchemaVersion, TenantSelector,
    TrafficSplit, TrafficSplitEntry,
};

use super::{prune_for_seed, seed_environment_bytes};
use crate::environment::materialize_runtime_config;

/// Secret Manager's per-version payload cap.
const SECRET_VERSION_CAP: usize = 65_536;

fn env_id() -> EnvId {
    EnvId::try_from("prod").expect("valid env id")
}

fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn digest(n: u64) -> String {
    format!("sha256:{n:064x}")
}

fn revision(
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    sequence: u64,
    lifecycle: RevisionLifecycle,
) -> Revision {
    // A realistic revision carries several packs; that is where the ~1.8 KB
    // per revision measured in production comes from.
    let pack_list = (0..6)
        .map(|i| {
            PackListEntry::from_lock_primitives(
                PackId::new(format!("greentic.fixture.pack-{i}")),
                digest(sequence * 10 + i),
            )
        })
        .collect();
    Revision {
        schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
        revision_id: RevisionId::new(),
        env_id: env_id(),
        bundle_id: bundle_id.clone(),
        deployment_id,
        sequence,
        created_at: ts(),
        bundle_digest: digest(sequence),
        bundle_source_uri: Some(format!(
            "oci://europe-docker.pkg.dev/project/repo/{}:{sequence}",
            bundle_id.as_str()
        )),
        pack_list,
        pack_list_lock_ref: format!("revisions/{sequence}/pack-list.lock").into(),
        pack_config_refs: vec![format!("revisions/{sequence}/config.json").into()],
        config_digest: digest(sequence + 1),
        signature_sidecar_ref: format!("revisions/{sequence}/rev.sig").into(),
        lifecycle,
        staged_at: Some(ts()),
        warmed_at: Some(ts()),
        drain_seconds: 30,
        runtime_image_digest: None,
        abort_metrics: Vec::new(),
    }
}

fn deployment(deployment_id: DeploymentId, bundle_id: &BundleId) -> BundleDeployment {
    BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id,
        env_id: env_id(),
        bundle_id: bundle_id.clone(),
        customer_id: CustomerId::new("customer"),
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: RouteBinding {
            hosts: vec![format!("{}.example.test", bundle_id.as_str())],
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
        revenue_policy_ref: "revenue.json".into(),
        usage: None,
        created_at: ts(),
        authorization_ref: "auth.json".into(),
        config_overrides: Default::default(),
    }
}

fn split(
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    entries: Vec<(RevisionId, u32)>,
) -> TrafficSplit {
    TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: env_id(),
        deployment_id,
        bundle_id: bundle_id.clone(),
        generation: 1,
        entries: entries
            .into_iter()
            .map(|(revision_id, weight_bps)| TrafficSplitEntry {
                revision_id,
                weight_bps,
            })
            .collect(),
        updated_at: ts(),
        updated_by: "test".to_string(),
        idempotency_key: "k".to_string(),
        authorization_ref: "auth.json".into(),
        previous_split_ref: None,
    }
}

fn empty_env() -> Environment {
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id(),
        name: "prod".to_string(),
        host_config: EnvironmentHostConfig::new(env_id()),
        packs: Vec::new(),
        credentials_ref: None,
        bundles: Vec::new(),
        revisions: Vec::new(),
        traffic_splits: Vec::new(),
        messaging_endpoints: Vec::new(),
        extensions: Vec::new(),
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}

/// The shape measured on production: 9 bundles, 53 stored revisions. Per
/// bundle: one routed `Ready` revision, one superseded `Ready` revision no
/// split names, and the rest `Archived`.
struct Fixture {
    env: Environment,
    routed: Vec<RevisionId>,
    unrouted_ready: Vec<RevisionId>,
    archived: Vec<RevisionId>,
}

fn nine_bundle_fixture() -> Fixture {
    let mut env = empty_env();
    let (mut routed, mut unrouted_ready, mut archived) = (Vec::new(), Vec::new(), Vec::new());
    for unit in 0..9u64 {
        let bundle_id = BundleId::new(format!("unit-{unit}"));
        let deployment_id = DeploymentId::new();
        env.bundles.push(deployment(deployment_id, &bundle_id));
        // 8 bundles carry 6 revisions, the last one 5: 8 * 6 + 5 = 53.
        let count = if unit == 8 { 5 } else { 6 };
        let mut live = None;
        for seq in 1..=count {
            let lifecycle = if seq >= count - 1 {
                RevisionLifecycle::Ready
            } else {
                RevisionLifecycle::Archived
            };
            let rev = revision(deployment_id, &bundle_id, seq, lifecycle);
            if seq == count {
                live = Some(rev.revision_id);
                routed.push(rev.revision_id);
            } else if seq == count - 1 {
                unrouted_ready.push(rev.revision_id);
            } else {
                archived.push(rev.revision_id);
            }
            env.revisions.push(rev);
        }
        let live = live.expect("each bundle has a live revision");
        env.traffic_splits
            .push(split(deployment_id, &bundle_id, vec![(live, 10_000)]));
    }
    assert_eq!(env.revisions.len(), 53);
    env.validate().expect("fixture is a valid environment");
    Fixture {
        env,
        routed,
        unrouted_ready,
        archived,
    }
}

fn ids(env: &Environment) -> Vec<RevisionId> {
    env.revisions.iter().map(|r| r.revision_id).collect()
}

#[test]
fn archived_unreferenced_revisions_are_left_out_and_the_seed_shrinks() {
    let fx = nine_bundle_fixture();
    let full = serde_json::to_vec(&fx.env).unwrap();
    let seed = seed_environment_bytes(&fx.env, &[]).unwrap();
    println!(
        "full = {} bytes ({} revisions), seed = {} bytes ({} revisions)",
        full.len(),
        fx.env.revisions.len(),
        seed.len(),
        fx.env.revisions.len() - fx.archived.len()
    );
    assert!(
        full.len() > SECRET_VERSION_CAP,
        "fixture must reproduce the oversize seed, got {}",
        full.len()
    );
    assert!(seed.len() < full.len());
    assert!(
        seed.len() < SECRET_VERSION_CAP,
        "pruned seed must fit a Secret Manager version, got {}",
        seed.len()
    );
    let pruned: Environment = serde_json::from_slice(&seed).unwrap();
    for gone in &fx.archived {
        assert!(!ids(&pruned).contains(gone), "archived {gone} must be gone");
    }
    assert_eq!(pruned.revisions.len(), 53 - fx.archived.len());
}

#[test]
fn every_routed_or_non_archived_revision_survives() {
    let fx = nine_bundle_fixture();
    let pruned = prune_for_seed(&fx.env, &[]);
    for kept in fx.routed.iter().chain(&fx.unrouted_ready) {
        assert!(ids(&pruned).contains(kept), "{kept} must be kept");
    }
    // Every lifecycle other than `Archived` is kept, referenced or not.
    for rev in &fx.env.revisions {
        if rev.lifecycle != RevisionLifecycle::Archived {
            assert!(ids(&pruned).contains(&rev.revision_id));
        }
    }
}

#[test]
fn an_archived_revision_something_still_names_is_kept() {
    let mut fx = nine_bundle_fixture();
    // Four archived revisions of the SAME deployment (unit-0).
    let unit0: Vec<RevisionId> = fx
        .env
        .revisions
        .iter()
        .filter(|r| r.bundle_id.as_str() == "unit-0" && r.lifecycle == RevisionLifecycle::Archived)
        .map(|r| r.revision_id)
        .collect();
    let (in_split, in_current, in_keep, dropped) = (unit0[0], unit0[1], unit0[2], unit0[3]);

    // A split entry (even at 0 bps) naming an archived revision.
    fx.env.traffic_splits[0].entries.push(TrafficSplitEntry {
        revision_id: in_split,
        weight_bps: 0,
    });
    // A bundle's `current_revisions` (validation requires it to resolve).
    fx.env.bundles[0].current_revisions.push(in_current);
    fx.env.validate().expect("still valid");

    let pruned = prune_for_seed(&fx.env, &[in_keep]);
    let kept = ids(&pruned);
    assert!(kept.contains(&in_split), "split-referenced must be kept");
    assert!(kept.contains(&in_current), "current_revisions must be kept");
    assert!(kept.contains(&in_keep), "explicit keep must be kept");
    assert!(
        !kept.contains(&dropped),
        "an unreferenced archived one goes"
    );
    pruned.validate().expect("pruned seed must validate");
}

#[test]
fn the_runtime_reads_the_same_thing_from_the_pruned_seed() {
    let fx = nine_bundle_fixture();
    let bytes = seed_environment_bytes(&fx.env, &[]).unwrap();
    let pruned: Environment = serde_json::from_slice(&bytes).unwrap();
    pruned.validate().expect("the store validates on load");

    // What the worker derives from the document, per greentic-start:
    // the runtime-config projection (splits joined to revisions) ...
    assert_eq!(
        materialize_runtime_config(&fx.env),
        materialize_runtime_config(&pruned)
    );
    // ... the routed set `revision_pull` pulls, with each revision's own record ...
    let routed = |env: &Environment| -> Vec<Revision> {
        let in_split: Vec<RevisionId> = env
            .traffic_splits
            .iter()
            .flat_map(|s| s.entries.iter().map(|e| e.revision_id))
            .collect();
        env.revisions
            .iter()
            .filter(|r| in_split.contains(&r.revision_id))
            .cloned()
            .collect()
    };
    assert_eq!(routed(&fx.env), routed(&pruned));
    // ... and every other section it consumes.
    assert_eq!(fx.env.bundles, pruned.bundles);
    assert_eq!(fx.env.traffic_splits, pruned.traffic_splits);
    assert_eq!(fx.env.messaging_endpoints, pruned.messaging_endpoints);
    assert_eq!(fx.env.extensions, pruned.extensions);
    assert_eq!(fx.env.host_config, pruned.host_config);
    assert_eq!(fx.env.packs, pruned.packs);
    assert_eq!(fx.env.environment_id, pruned.environment_id);
    // The full document is untouched.
    assert_eq!(fx.env.revisions.len(), 53);
}

#[test]
fn nothing_to_prune_is_byte_identical() {
    let mut fx = nine_bundle_fixture();
    fx.env
        .revisions
        .retain(|r| r.lifecycle != RevisionLifecycle::Archived);
    let seed = seed_environment_bytes(&fx.env, &[]).unwrap();
    assert_eq!(seed, serde_json::to_vec(&fx.env).unwrap());
    assert!(matches!(prune_for_seed(&fx.env, &[]), Cow::Borrowed(_)));

    // And with no revisions at all.
    let empty = empty_env();
    assert_eq!(
        seed_environment_bytes(&empty, &[]).unwrap(),
        serde_json::to_vec(&empty).unwrap()
    );
}

#[test]
fn the_revision_being_warmed_is_never_dropped() {
    let fx = nine_bundle_fixture();
    let warming = fx.archived[0];
    assert!(!ids(&prune_for_seed(&fx.env, &[])).contains(&warming));
    assert!(ids(&prune_for_seed(&fx.env, &[warming])).contains(&warming));
}

#[test]
fn a_document_that_would_not_validate_is_staged_as_it_is() {
    let mut fx = nine_bundle_fixture();
    // Make the environment itself invalid: a bundle from another environment.
    fx.env.bundles[0].env_id = EnvId::try_from("other").unwrap();
    assert!(fx.env.validate().is_err());
    let pruned = prune_for_seed(&fx.env, &[]);
    assert!(matches!(pruned, Cow::Borrowed(_)));
    assert_eq!(pruned.revisions.len(), 53);
}
