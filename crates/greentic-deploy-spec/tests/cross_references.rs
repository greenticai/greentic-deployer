//! Cross-reference validation in `Environment::validate()`.
//!
//! Static referential-integrity checks: env_id ownership across nested docs,
//! revision/deployment ID membership, and split-entry revision matching the
//! split's deployment + bundle. Lifecycle state (e.g. `Ready` for split
//! entries) is apply-time, not enforced here.

use chrono::Utc;
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, DeploymentId,
    EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, PackDescriptor, PackId,
    PackListEntry, PartyId, RevenueShareEntry, Revision, RevisionId, RevisionLifecycle,
    RouteBinding, SchemaVersion, SemVer, SpecError, TenantSelector, TrafficSplit,
    TrafficSplitEntry,
};
use std::path::PathBuf;
use std::str::FromStr;

fn env_with(
    env_id: EnvId,
    bundles: Vec<BundleDeployment>,
    revisions: Vec<Revision>,
    traffic_splits: Vec<TrafficSplit>,
) -> Environment {
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id.clone(),
        name: "local".into(),
        host_config: EnvironmentHostConfig {
            env_id,
            region: None,
            tenant_org_id: None,
        },
        packs: vec![EnvPackBinding {
            slot: CapabilitySlot::Deployer,
            kind: PackDescriptor::try_new("greentic.deployer.local-process@1.0.0").unwrap(),
            pack_ref: PackId::new("p"),
            answers_ref: None,
            generation: 1,
            previous_binding_ref: None,
        }],
        credentials_ref: None,
        bundles,
        revisions,
        traffic_splits,
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}

fn local() -> EnvId {
    EnvId::from_str("local").unwrap()
}

fn revision(
    revision_id: RevisionId,
    env: EnvId,
    deployment: DeploymentId,
    bundle: BundleId,
) -> Revision {
    Revision {
        schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
        revision_id,
        env_id: env,
        bundle_id: bundle,
        deployment_id: deployment,
        sequence: 1,
        created_at: Utc::now(),
        bundle_digest: "sha256:0".into(),
        pack_list: vec![PackListEntry {
            pack_id: PackId::new("p"),
            version: SemVer::new(1, 0, 0),
            digest: "sha256:0".into(),
            source_uri: None,
        }],
        pack_list_lock_ref: PathBuf::from("revisions/lock"),
        config_digest: "sha256:0".into(),
        signature_sidecar_ref: PathBuf::from("revisions/sig"),
        lifecycle: RevisionLifecycle::Ready,
        staged_at: None,
        warmed_at: None,
        drain_seconds: 60,
        abort_metrics: vec![],
    }
}

fn bundle(
    deployment_id: DeploymentId,
    env: EnvId,
    bundle_id: BundleId,
    current_revisions: Vec<RevisionId>,
) -> BundleDeployment {
    BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id,
        env_id: env,
        bundle_id,
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions,
        route_binding: RouteBinding {
            hosts: vec!["e.com".into()],
            path_prefixes: vec!["/".into()],
            tenant_selector: TenantSelector {
                tenant: "acme".into(),
                team: "support".into(),
            },
        },
        revenue_share: vec![RevenueShareEntry {
            party_id: PartyId::new("g"),
            basis_points: 10_000,
        }],
        revenue_policy_ref: PathBuf::from("billing.sig"),
        usage: None,
        created_at: Utc::now(),
        authorization_ref: PathBuf::from("audit.json"),
    }
}

fn split(
    env: EnvId,
    deployment: DeploymentId,
    bundle: BundleId,
    entries: Vec<TrafficSplitEntry>,
) -> TrafficSplit {
    TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: env,
        deployment_id: deployment,
        bundle_id: bundle,
        generation: 1,
        entries,
        updated_at: Utc::now(),
        updated_by: "operator://test".into(),
        idempotency_key: "k".into(),
        authorization_ref: PathBuf::from("audit.json"),
        previous_split_ref: None,
    }
}

#[test]
fn host_config_env_id_must_match_environment_id() {
    let mut e = env_with(local(), vec![], vec![], vec![]);
    e.host_config.env_id = EnvId::from_str("prod").unwrap();
    let err = e.validate().unwrap_err();
    assert!(matches!(
        err,
        SpecError::EnvIdMismatch {
            context: "host_config",
            ..
        }
    ));
}

#[test]
fn revision_env_id_must_match_environment_id() {
    let r = revision(
        RevisionId::new(),
        EnvId::from_str("prod").unwrap(),
        DeploymentId::new(),
        BundleId::new("b"),
    );
    let e = env_with(local(), vec![], vec![r], vec![]);
    let err = e.validate().unwrap_err();
    assert!(matches!(
        err,
        SpecError::EnvIdMismatch {
            context: "revision",
            ..
        }
    ));
}

#[test]
fn bundle_env_id_must_match_environment_id() {
    let b = bundle(
        DeploymentId::new(),
        EnvId::from_str("prod").unwrap(),
        BundleId::new("b"),
        vec![],
    );
    let e = env_with(local(), vec![b], vec![], vec![]);
    let err = e.validate().unwrap_err();
    assert!(matches!(
        err,
        SpecError::EnvIdMismatch {
            context: "bundle_deployment",
            ..
        }
    ));
}

#[test]
fn traffic_split_env_id_must_match_environment_id() {
    let dep = DeploymentId::new();
    let b = bundle(dep, local(), BundleId::new("b"), vec![]);
    let s = split(
        EnvId::from_str("prod").unwrap(),
        dep,
        BundleId::new("b"),
        vec![],
    );
    // split's basis-points check fires first if entries empty (sum 0 != 10_000) —
    // give it one valid entry, but the entry references an unknown revision
    // which would fire first. Easier: keep entries empty and assert
    // EnvIdMismatch isn't ordered after basis-points by re-checking the
    // validate semantics: env_id is checked BEFORE split.validate(), so
    // EnvIdMismatch wins.
    let e = env_with(local(), vec![b], vec![], vec![s]);
    let err = e.validate().unwrap_err();
    assert!(matches!(
        err,
        SpecError::EnvIdMismatch {
            context: "traffic_split",
            ..
        }
    ));
}

#[test]
fn traffic_split_unknown_deployment_rejected() {
    let unknown = DeploymentId::new();
    let rev_id = RevisionId::new();
    let s = split(
        local(),
        unknown,
        BundleId::new("b"),
        vec![TrafficSplitEntry {
            revision_id: rev_id,
            weight_bps: 10_000,
        }],
    );
    let r = revision(rev_id, local(), unknown, BundleId::new("b"));
    let e = env_with(local(), vec![], vec![r], vec![s]);
    let err = e.validate().unwrap_err();
    assert_eq!(err, SpecError::UnknownDeployment(unknown));
}

#[test]
fn traffic_split_unknown_revision_rejected() {
    let dep = DeploymentId::new();
    let b = bundle(dep, local(), BundleId::new("b"), vec![]);
    let ghost_rev = RevisionId::new();
    let s = split(
        local(),
        dep,
        BundleId::new("b"),
        vec![TrafficSplitEntry {
            revision_id: ghost_rev,
            weight_bps: 10_000,
        }],
    );
    let e = env_with(local(), vec![b], vec![], vec![s]);
    let err = e.validate().unwrap_err();
    assert_eq!(err, SpecError::UnknownRevision(ghost_rev));
}

#[test]
fn split_entry_revision_must_match_deployment() {
    let dep_a = DeploymentId::new();
    let dep_b = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let b_a = bundle(dep_a, local(), bundle_id.clone(), vec![]);
    let b_b = bundle(dep_b, local(), bundle_id.clone(), vec![]);
    let rev = RevisionId::new();
    // revision actually belongs to dep_b
    let r = revision(rev, local(), dep_b, bundle_id.clone());
    // but the split for dep_a points at it
    let s = split(
        local(),
        dep_a,
        bundle_id,
        vec![TrafficSplitEntry {
            revision_id: rev,
            weight_bps: 10_000,
        }],
    );
    let e = env_with(local(), vec![b_a, b_b], vec![r], vec![s]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::SplitRevisionWrongDeployment {
            revision: rev,
            expected_deployment: dep_a,
            actual_deployment: dep_b,
        }
    );
}

#[test]
fn split_entry_revision_must_match_bundle() {
    let dep = DeploymentId::new();
    let split_bundle = BundleId::new("split-bundle");
    let rev_bundle = BundleId::new("rev-bundle");
    let b = bundle(dep, local(), split_bundle.clone(), vec![]);
    let rev = RevisionId::new();
    // revision claims a different bundle than the split
    let r = revision(rev, local(), dep, rev_bundle.clone());
    let s = split(
        local(),
        dep,
        split_bundle.clone(),
        vec![TrafficSplitEntry {
            revision_id: rev,
            weight_bps: 10_000,
        }],
    );
    let e = env_with(local(), vec![b], vec![r], vec![s]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::SplitRevisionWrongBundle {
            revision: rev,
            expected_bundle: split_bundle,
            actual_bundle: rev_bundle,
        }
    );
}

#[test]
fn bundle_current_revisions_must_belong_to_bundle_deployment() {
    let dep_a = DeploymentId::new();
    let dep_b = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev = RevisionId::new();
    // revision actually belongs to dep_b
    let r = revision(rev, local(), dep_b, bundle_id.clone());
    // but bundle A's current_revisions points at it
    let b_a = bundle(dep_a, local(), bundle_id.clone(), vec![rev]);
    let b_b = bundle(dep_b, local(), bundle_id, vec![]);
    let e = env_with(local(), vec![b_a, b_b], vec![r], vec![]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::BundleRevisionWrongDeployment {
            deployment: dep_a,
            revision: rev,
            actual_deployment: dep_b,
        }
    );
}

#[test]
fn bundle_current_revisions_must_reference_known_revision() {
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let ghost = RevisionId::new();
    let b = bundle(dep, local(), bundle_id, vec![ghost]);
    let e = env_with(local(), vec![b], vec![], vec![]);
    let err = e.validate().unwrap_err();
    assert_eq!(err, SpecError::UnknownRevision(ghost));
}

#[test]
fn well_formed_environment_with_split_and_bundle_passes() {
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_a = RevisionId::new();
    let rev_b = RevisionId::new();
    let r_a = revision(rev_a, local(), dep, bundle_id.clone());
    let r_b = revision(rev_b, local(), dep, bundle_id.clone());
    let b = bundle(dep, local(), bundle_id.clone(), vec![rev_a, rev_b]);
    let s = split(
        local(),
        dep,
        bundle_id,
        vec![
            TrafficSplitEntry {
                revision_id: rev_a,
                weight_bps: 9_000,
            },
            TrafficSplitEntry {
                revision_id: rev_b,
                weight_bps: 1_000,
            },
        ],
    );
    let e = env_with(local(), vec![b], vec![r_a, r_b], vec![s]);
    assert!(e.validate().is_ok());
}
