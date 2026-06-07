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
use std::collections::BTreeMap;
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
            listen_addr: None,
            public_base_url: None,
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
        messaging_endpoints: vec![],
        extensions: vec![],
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
        config_overrides: BTreeMap::new(),
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
fn bundle_current_revisions_must_match_bundle_id() {
    // Codex finding: BundleDeployment(D, bundle=A) with current_revisions
    // pointing at a Revision(D, bundle=B). Old validate() checked only the
    // deployment_id and let this through, so a deployment record could
    // route/bill another bundle's revisions.
    let dep = DeploymentId::new();
    let bundle_a = BundleId::new("a");
    let bundle_b = BundleId::new("b");
    let rev = RevisionId::new();
    let r = revision(rev, local(), dep, bundle_b.clone());
    let b = bundle(dep, local(), bundle_a.clone(), vec![rev]);
    let e = env_with(local(), vec![b], vec![r], vec![]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::BundleRevisionWrongBundle {
            deployment: dep,
            revision: rev,
            expected_bundle: bundle_a,
            actual_bundle: bundle_b,
        }
    );
}

#[test]
fn split_bundle_must_match_referenced_deployment_bundle() {
    // Codex finding: TrafficSplit(deployment=D, bundle=B) that resolves to
    // BundleDeployment(D, bundle=A). The split's revisions could all match
    // bundle=B and pass the existing per-entry checks, but the deployment
    // itself is anchored to bundle=A — the mismatch means split routing /
    // billing carries the wrong bundle identity.
    let dep = DeploymentId::new();
    let bundle_a = BundleId::new("a");
    let bundle_b = BundleId::new("b");
    let rev = RevisionId::new();
    // Bundle deployment is anchored to A.
    let b = bundle(dep, local(), bundle_a.clone(), vec![]);
    // Revision and split both claim B — internally consistent with each
    // other but inconsistent with the deployment record.
    let r = revision(rev, local(), dep, bundle_b.clone());
    let s = split(
        local(),
        dep,
        bundle_b.clone(),
        vec![TrafficSplitEntry {
            revision_id: rev,
            weight_bps: 10_000,
        }],
    );
    let e = env_with(local(), vec![b], vec![r], vec![s]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::SplitDeploymentBundleMismatch {
            deployment: dep,
            split_bundle: bundle_b,
            deployment_bundle: bundle_a,
        }
    );
}

// ----------------------------------------------------------------------------
// Codex round 2: env-scoped refs + nested schema discriminators
// ----------------------------------------------------------------------------

#[test]
fn credentials_ref_must_be_scoped_to_environment_id() {
    // Codex finding: credentials_ref documented as secret://<env>/...
    // but SecretRef::try_new accepted any non-empty secret:// URI and
    // Environment::validate did not enforce the scope. Without this
    // check a `local` env could persist a pointer into `prod`'s secrets
    // backend.
    use greentic_deploy_spec::SecretRef;
    let mut e = env_with(local(), vec![], vec![], vec![]);
    e.credentials_ref = Some(SecretRef::try_new("secret://prod/credentials/admin").unwrap());
    let err = e.validate().unwrap_err();
    match err {
        SpecError::CrossEnvRef {
            context,
            ref expected_env,
            ref actual_env,
            ..
        } => {
            assert_eq!(context, "credentials_ref");
            assert_eq!(expected_env, &local());
            assert_eq!(actual_env, "prod");
        }
        other => panic!("expected CrossEnvRef, got {other:?}"),
    }
}

#[test]
fn credentials_ref_matching_env_passes() {
    use greentic_deploy_spec::SecretRef;
    let mut e = env_with(local(), vec![], vec![], vec![]);
    e.credentials_ref = Some(SecretRef::try_new("secret://local/credentials/admin").unwrap());
    assert!(e.validate().is_ok());
}

#[test]
fn secret_ref_rejects_missing_env_segment() {
    use greentic_deploy_spec::{SecretRef, SecretRefParseError};
    let err = SecretRef::try_new("secret:///credentials/admin").unwrap_err();
    assert_eq!(err, SecretRefParseError::EmptyEnvSegment);
}

#[test]
fn runtime_ref_rejects_missing_env_segment() {
    use greentic_deploy_spec::{RuntimeRef, RuntimeRefParseError};
    let err = RuntimeRef::try_new("runtime:///discovered/x").unwrap_err();
    assert_eq!(err, RuntimeRefParseError::EmptyEnvSegment);
}

#[test]
fn credentials_validate_rejects_cross_env_provided_ref() {
    // The Credentials document is a separate top-level type; its own
    // validate() must scope every embedded SecretRef to self.env_id.
    use chrono::Utc;
    use greentic_deploy_spec::{
        Credentials, CredentialsMode, CredentialsValidation, CredentialsValidationResult,
        PackDescriptor, SchemaVersion, SecretRef,
    };
    let creds = Credentials {
        schema: SchemaVersion::new(SchemaVersion::CREDENTIALS_V1),
        env_id: local(),
        deployer_kind: PackDescriptor::try_new("greentic.deployer.local-process@1.0.0").unwrap(),
        mode: CredentialsMode::Requirements,
        provided_credentials_ref: SecretRef::try_new("secret://prod/credentials/admin").unwrap(),
        validation: CredentialsValidation {
            last_run_at: Utc::now(),
            result: CredentialsValidationResult::Pass,
            missing_capabilities: vec![],
        },
        bootstrap: None,
        expiry: None,
    };
    let err = creds.validate().unwrap_err();
    matches!(err, SpecError::CrossEnvRef { .. });
}

#[test]
fn revision_with_wrong_schema_rejected_by_environment() {
    // Codex finding: Environment::validate never verified Revision.schema,
    // BundleDeployment.schema, or TrafficSplit.schema against the v1
    // constants. A mixed-version document could survive a round-trip.
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let mut r = revision(RevisionId::new(), local(), dep, bundle_id.clone());
    r.schema = SchemaVersion::new("greentic.revision.v999");
    let e = env_with(local(), vec![], vec![r], vec![]);
    let err = e.validate().unwrap_err();
    match err {
        SpecError::SchemaMismatch { expected, .. } => {
            assert_eq!(expected, SchemaVersion::REVISION_V1);
        }
        other => panic!("expected nested-schema SchemaMismatch, got {other:?}"),
    }
}

#[test]
fn bundle_deployment_with_wrong_schema_rejected_by_environment() {
    let dep = DeploymentId::new();
    let mut b = bundle(dep, local(), BundleId::new("b"), vec![]);
    b.schema = SchemaVersion::new("greentic.bundle-deployment.v999");
    let e = env_with(local(), vec![b], vec![], vec![]);
    let err = e.validate().unwrap_err();
    match err {
        SpecError::SchemaMismatch { expected, .. } => {
            assert_eq!(expected, SchemaVersion::BUNDLE_DEPLOYMENT_V1);
        }
        other => panic!("expected nested-schema SchemaMismatch, got {other:?}"),
    }
}

#[test]
fn traffic_split_with_wrong_schema_rejected_by_environment() {
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_id = RevisionId::new();
    let r = revision(rev_id, local(), dep, bundle_id.clone());
    let b = bundle(dep, local(), bundle_id.clone(), vec![rev_id]);
    let mut s = split(
        local(),
        dep,
        bundle_id,
        vec![TrafficSplitEntry {
            revision_id: rev_id,
            weight_bps: 10_000,
        }],
    );
    s.schema = SchemaVersion::new("greentic.traffic-split.v999");
    let e = env_with(local(), vec![b], vec![r], vec![s]);
    let err = e.validate().unwrap_err();
    match err {
        SpecError::SchemaMismatch { expected, .. } => {
            assert_eq!(expected, SchemaVersion::TRAFFIC_SPLIT_V1);
        }
        other => panic!("expected nested-schema SchemaMismatch, got {other:?}"),
    }
}

// ----------------------------------------------------------------------------
// Phase M1: MessagingEndpoint cross-references
// ----------------------------------------------------------------------------

fn endpoint(
    env: EnvId,
    endpoint_id: greentic_deploy_spec::MessagingEndpointId,
    provider_type: &str,
    provider_id: &str,
    linked_bundles: Vec<BundleId>,
) -> greentic_deploy_spec::MessagingEndpoint {
    greentic_deploy_spec::MessagingEndpoint {
        schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
        env_id: env,
        endpoint_id,
        provider_id: provider_id.into(),
        provider_type: provider_type.into(),
        display_name: format!("{provider_type}: {provider_id}"),
        secret_refs: vec![],
        webhook_secret_ref: None,
        linked_bundles,
        welcome_flow: None,
        generation: 1,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        updated_by: "operator://test".into(),
    }
}

fn env_with_endpoints(
    bundles: Vec<BundleDeployment>,
    endpoints: Vec<greentic_deploy_spec::MessagingEndpoint>,
) -> Environment {
    let mut e = env_with(local(), bundles, vec![], vec![]);
    e.messaging_endpoints = endpoints;
    e
}

#[test]
fn messaging_endpoint_env_id_must_match_environment_id() {
    let prod = EnvId::from_str("prod").unwrap();
    let ep = endpoint(
        prod,
        greentic_deploy_spec::MessagingEndpointId::new(),
        "teams",
        "legal-bot",
        vec![],
    );
    let e = env_with_endpoints(vec![], vec![ep]);
    let err = e.validate().unwrap_err();
    assert!(matches!(
        err,
        SpecError::EnvIdMismatch {
            context: "messaging_endpoint",
            ..
        }
    ));
}

#[test]
fn duplicate_endpoint_id_rejected() {
    let id = greentic_deploy_spec::MessagingEndpointId::new();
    let a = endpoint(local(), id, "teams", "legal", vec![]);
    let b = endpoint(local(), id, "slack", "accounting", vec![]);
    let e = env_with_endpoints(vec![], vec![a, b]);
    let err = e.validate().unwrap_err();
    assert_eq!(err, SpecError::DuplicateMessagingEndpoint(id));
}

#[test]
fn duplicate_provider_instance_rejected() {
    let a = endpoint(
        local(),
        greentic_deploy_spec::MessagingEndpointId::new(),
        "teams",
        "legal-bot",
        vec![],
    );
    let b = endpoint(
        local(),
        greentic_deploy_spec::MessagingEndpointId::new(),
        "teams",
        "legal-bot",
        vec![],
    );
    let e = env_with_endpoints(vec![], vec![a, b]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::DuplicateProviderInstance {
            provider_type: "teams".into(),
            provider_id: "legal-bot".into(),
        }
    );
}

#[test]
fn distinct_provider_id_under_same_type_is_allowed() {
    let a = endpoint(
        local(),
        greentic_deploy_spec::MessagingEndpointId::new(),
        "teams",
        "legal-bot",
        vec![],
    );
    let b = endpoint(
        local(),
        greentic_deploy_spec::MessagingEndpointId::new(),
        "teams",
        "accounting-bot",
        vec![],
    );
    let e = env_with_endpoints(vec![], vec![a, b]);
    assert!(e.validate().is_ok());
}

#[test]
fn linked_bundle_must_exist_in_environment() {
    let id = greentic_deploy_spec::MessagingEndpointId::new();
    let ep = endpoint(
        local(),
        id,
        "teams",
        "legal-bot",
        vec![BundleId::new("missing-bundle")],
    );
    let e = env_with_endpoints(vec![], vec![ep]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::MessagingEndpointBundleNotLinked {
            endpoint: id,
            bundle: BundleId::new("missing-bundle"),
        }
    );
}

#[test]
fn welcome_flow_bundle_must_be_linked() {
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("legal-pack");
    let other_bundle = BundleId::new("accounting-pack");
    let b = bundle(dep, local(), bundle_id.clone(), vec![]);
    let id = greentic_deploy_spec::MessagingEndpointId::new();
    let mut ep = endpoint(local(), id, "teams", "legal-bot", vec![bundle_id.clone()]);
    ep.welcome_flow = Some(greentic_deploy_spec::WelcomeFlowRef {
        bundle_id: other_bundle.clone(),
        pack_id: PackId::new("legal"),
        flow_id: "main".into(),
    });
    let e = env_with_endpoints(vec![b], vec![ep]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::WelcomeFlowBundleNotLinked {
            endpoint: id,
            bundle: other_bundle,
        }
    );
}

#[test]
fn well_formed_messaging_endpoint_passes() {
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("legal-pack");
    let b = bundle(dep, local(), bundle_id.clone(), vec![]);
    let mut ep = endpoint(
        local(),
        greentic_deploy_spec::MessagingEndpointId::new(),
        "teams",
        "legal-bot",
        vec![bundle_id.clone()],
    );
    ep.welcome_flow = Some(greentic_deploy_spec::WelcomeFlowRef {
        bundle_id,
        pack_id: PackId::new("legal"),
        flow_id: "main".into(),
    });
    let e = env_with_endpoints(vec![b], vec![ep]);
    assert!(e.validate().is_ok());
}

#[test]
fn messaging_endpoint_secret_ref_must_be_scoped_to_env() {
    use greentic_deploy_spec::SecretRef;
    let id = greentic_deploy_spec::MessagingEndpointId::new();
    let mut ep = endpoint(local(), id, "teams", "legal-bot", vec![]);
    ep.secret_refs = vec![SecretRef::try_new("secret://prod/teams/legal-bot/token").unwrap()];
    let e = env_with_endpoints(vec![], vec![ep]);
    let err = e.validate().unwrap_err();
    match err {
        SpecError::CrossEnvRef {
            context,
            ref actual_env,
            ..
        } => {
            assert_eq!(context, "messaging_endpoint.secret_refs");
            assert_eq!(actual_env, "prod");
        }
        other => panic!("expected CrossEnvRef, got {other:?}"),
    }
}

// ----------------------------------------------------------------------------
// D.4: config_overrides pack-id cross-reference
// ----------------------------------------------------------------------------

/// Like [`revision`] but with a custom pack_list so tests can assert that
/// config_overrides keys are (or aren't) present in the revision's packs.
fn revision_with_packs(
    revision_id: RevisionId,
    env: EnvId,
    deployment: DeploymentId,
    bundle: BundleId,
    pack_ids: &[&str],
) -> Revision {
    Revision {
        pack_list: pack_ids
            .iter()
            .map(|id| PackListEntry {
                pack_id: PackId::new(*id),
                version: SemVer::new(1, 0, 0),
                digest: "sha256:0".into(),
                source_uri: None,
            })
            .collect(),
        ..revision(revision_id, env, deployment, bundle)
    }
}

#[test]
fn config_overrides_referencing_pack_in_revision_passes() {
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_id = RevisionId::new();
    let r = revision_with_packs(
        rev_id,
        local(),
        dep,
        bundle_id.clone(),
        &["messaging-telegram", "messaging-slack"],
    );
    let mut b = bundle(dep, local(), bundle_id, vec![rev_id]);
    b.config_overrides = BTreeMap::from([(
        "messaging-telegram".to_string(),
        BTreeMap::from([(
            "api_base_url".to_string(),
            serde_json::json!("https://staging.example.com"),
        )]),
    )]);
    let e = env_with(local(), vec![b], vec![r], vec![]);
    assert!(e.validate().is_ok());
}

#[test]
fn config_overrides_referencing_unknown_pack_rejected() {
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_id = RevisionId::new();
    let r = revision_with_packs(
        rev_id,
        local(),
        dep,
        bundle_id.clone(),
        &["messaging-telegram"],
    );
    let mut b = bundle(dep, local(), bundle_id, vec![rev_id]);
    b.config_overrides = BTreeMap::from([(
        "messaging-whatsapp".to_string(),
        BTreeMap::from([(
            "api_base_url".to_string(),
            serde_json::json!("https://wa.example.com"),
        )]),
    )]);
    let e = env_with(local(), vec![b], vec![r], vec![]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::ConfigOverridePackNotInRevisions {
            deployment: dep,
            pack_id: "messaging-whatsapp".to_string(),
        }
    );
}

#[test]
fn config_overrides_in_any_current_revision_passes_canary() {
    // Canary scenario: two current revisions; override pack exists in only
    // one of them. Loose semantics — the pack exists in at least one.
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_a = RevisionId::new();
    let rev_b = RevisionId::new();
    let r_a = revision_with_packs(
        rev_a,
        local(),
        dep,
        bundle_id.clone(),
        &["messaging-telegram"],
    );
    let r_b = revision_with_packs(rev_b, local(), dep, bundle_id.clone(), &["messaging-slack"]);
    let mut b = bundle(dep, local(), bundle_id, vec![rev_a, rev_b]);
    b.config_overrides = BTreeMap::from([
        (
            "messaging-telegram".to_string(),
            BTreeMap::from([(
                "api_base_url".to_string(),
                serde_json::json!("https://tg.example.com"),
            )]),
        ),
        (
            "messaging-slack".to_string(),
            BTreeMap::from([(
                "webhook_url".to_string(),
                serde_json::json!("https://slack.example.com"),
            )]),
        ),
    ]);
    let e = env_with(local(), vec![b], vec![r_a, r_b], vec![]);
    assert!(e.validate().is_ok());
}

#[test]
fn config_overrides_on_bundle_with_no_revisions_accepted_forward_looking() {
    // No revisions exist for this deployment yet → forward-looking
    // acceptance. The CLI flow runs `bundles add` (or `op deploy`'s add
    // step) BEFORE any `revisions stage` lands a revision, so this is the
    // normal path. The override gets re-validated on the next
    // `env.validate()` call once a revision is staged.
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let mut b = bundle(dep, local(), bundle_id, vec![]);
    b.config_overrides = BTreeMap::from([(
        "messaging-telegram".to_string(),
        BTreeMap::from([(
            "api_base_url".to_string(),
            serde_json::json!("https://staging.example.com"),
        )]),
    )]);
    let e = env_with(local(), vec![b], vec![], vec![]);
    assert!(e.validate().is_ok());
}

#[test]
fn empty_config_overrides_on_bundle_with_no_revisions_passes() {
    // No current_revisions + no overrides = fine.
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let b = bundle(dep, local(), bundle_id, vec![]);
    let e = env_with(local(), vec![b], vec![], vec![]);
    assert!(e.validate().is_ok());
}

#[test]
fn config_overrides_validated_against_env_revisions_for_deployment() {
    // The CLI's stage/warm/traffic path doesn't populate
    // `bundle.current_revisions`, but `env.revisions` does carry the
    // deployment's revisions. The cross-ref check must include those so
    // `op deploy --config-override ...` works after the stage step lands.
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_id = RevisionId::new();
    let r = revision_with_packs(
        rev_id,
        local(),
        dep,
        bundle_id.clone(),
        &["messaging-telegram"],
    );
    // Note: bundle.current_revisions is intentionally empty — matches the
    // CLI's actual state.
    let mut b = bundle(dep, local(), bundle_id, vec![]);
    b.config_overrides = BTreeMap::from([(
        "messaging-telegram".to_string(),
        BTreeMap::from([(
            "api_base_url".to_string(),
            serde_json::json!("https://staging.example.com"),
        )]),
    )]);
    let e = env_with(local(), vec![b], vec![r], vec![]);
    assert!(e.validate().is_ok());
}

#[test]
fn config_overrides_accepted_when_revision_pack_list_is_empty() {
    // CLI `--bundle` stage path persists pack ids in the on-disk pack-list
    // lock file and leaves `Revision.pack_list = Vec::new()` (see
    // `cli::revisions::stage`). The cross-ref must not couple to the
    // filesystem, so any non-empty config_overrides is forward-accepted
    // when there's no in-memory pack data to validate against.
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_id = RevisionId::new();
    // Empty pack_list — mirrors the bundle-staged shape.
    let r = revision_with_packs(rev_id, local(), dep, bundle_id.clone(), &[]);
    let mut b = bundle(dep, local(), bundle_id, vec![]);
    b.config_overrides = BTreeMap::from([(
        "messaging-telegram".to_string(),
        BTreeMap::from([(
            "api_base_url".to_string(),
            serde_json::json!("https://staging.example.com"),
        )]),
    )]);
    let e = env_with(local(), vec![b], vec![r], vec![]);
    assert!(e.validate().is_ok());
}

#[test]
fn config_overrides_unknown_pack_rejected_when_deployment_has_other_revisions() {
    // Bundle has no current_revisions, but env.revisions has a revision
    // for this deployment whose pack_list does NOT include the override's
    // pack_id → still rejects. Forward-looking acceptance only kicks in
    // when there are zero revisions for this deployment.
    let dep = DeploymentId::new();
    let bundle_id = BundleId::new("b");
    let rev_id = RevisionId::new();
    let r = revision_with_packs(
        rev_id,
        local(),
        dep,
        bundle_id.clone(),
        &["messaging-slack"],
    );
    let mut b = bundle(dep, local(), bundle_id, vec![]);
    b.config_overrides = BTreeMap::from([(
        "messaging-whatsapp".to_string(),
        BTreeMap::from([(
            "api_base_url".to_string(),
            serde_json::json!("https://wa.example.com"),
        )]),
    )]);
    let e = env_with(local(), vec![b], vec![r], vec![]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::ConfigOverridePackNotInRevisions {
            deployment: dep,
            pack_id: "messaging-whatsapp".to_string(),
        }
    );
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
