//! Shared test fixtures for `cli/*` unit tests.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, DeploymentId,
    EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, PackDescriptor, PackId,
    PackListEntry, RevenueShareEntry, Revision, RevisionId, RevisionLifecycle, RouteBinding,
    SchemaVersion, SemVer, TenantSelector, TrafficSplit, TrafficSplitEntry,
};
use greentic_distributor_client::signing::TrustedKey;

use crate::environment::trust_root::add_trusted_key;
use crate::operator_key::load_or_generate_at;

/// Seed the local operator key into an env's trust root so revenue-policy
/// writes succeed under the C2 "writer never mutates the trust root"
/// contract. Mirrors the production `gtc op trust-root bootstrap` flow,
/// which is exactly what real users will run once per env. The CLI
/// `bundles::add/update` paths resolve the operator key via
/// [`crate::operator_key::load_or_generate`] (default `~/.greentic/operator/key.pem`),
/// so the fixture seeds *that same key* — using
/// [`load_or_generate_at`] against an env-local path would leave the
/// production CLI staring at a different key that isn't in the trust root.
pub fn bootstrap_env_trust_root(env_dir: &Path) {
    let _ = load_or_generate_at; // silence unused-import warning when the
    // fixture only takes the no-path branch
    let key =
        crate::operator_key::load_or_generate().expect("load/generate operator key for tests");
    add_trusted_key(
        env_dir,
        TrustedKey {
            key_id: key.key_id,
            public_key_pem: key.public_pem,
        },
    )
    .expect("seed operator key into env trust root");
}

/// Minimal valid `Environment` for unit/integration tests.
pub fn make_env(env_id: &str) -> Environment {
    let env_id = EnvId::try_from(env_id).expect("test env_id");
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id.clone(),
        name: env_id.as_str().to_string(),
        host_config: EnvironmentHostConfig {
            env_id,
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        },
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

/// Make a binding with reasonable defaults.
pub fn make_binding(slot: CapabilitySlot, kind: &str) -> EnvPackBinding {
    EnvPackBinding {
        slot,
        kind: PackDescriptor::try_new(kind).expect("test pack descriptor"),
        pack_ref: PackId::new(kind.split('@').next().unwrap_or(kind)),
        answers_ref: None,
        generation: 0,
        previous_binding_ref: None,
    }
}

/// Build a `Revision` against a deployment.
pub fn make_revision(
    env_id: &str,
    bundle_id: &str,
    deployment_id: &DeploymentId,
    sequence: u64,
    lifecycle: RevisionLifecycle,
) -> Revision {
    Revision {
        schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
        revision_id: RevisionId::new(),
        env_id: EnvId::try_from(env_id).expect("test env_id"),
        bundle_id: BundleId::new(bundle_id),
        deployment_id: *deployment_id,
        sequence,
        created_at: Utc.with_ymd_and_hms(2026, 5, 18, 12, 0, 0).unwrap(),
        bundle_digest: "sha256:00".to_string(),
        pack_list: vec![PackListEntry {
            pack_id: PackId::new("greentic.test.pack"),
            version: SemVer::new(1, 0, 0),
            digest: "sha256:00".to_string(),
            source_uri: None,
        }],
        pack_list_lock_ref: PathBuf::from("pack-list.lock"),
        config_digest: "sha256:00".to_string(),
        signature_sidecar_ref: PathBuf::from("rev.sig"),
        lifecycle,
        staged_at: None,
        warmed_at: None,
        drain_seconds: 30,
        abort_metrics: Vec::new(),
    }
}

/// Build a `BundleDeployment` for the env.
pub fn make_bundle_deployment(env_id: &str, bundle_id: &str) -> BundleDeployment {
    BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id: DeploymentId::new(),
        env_id: EnvId::try_from(env_id).expect("test env_id"),
        bundle_id: BundleId::new(bundle_id),
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: RouteBinding {
            hosts: vec![format!("{bundle_id}.local")],
            path_prefixes: Vec::new(),
            tenant_selector: TenantSelector {
                tenant: "default".to_string(),
                team: "default".to_string(),
            },
        },
        revenue_share: vec![RevenueShareEntry {
            party_id: greentic_deploy_spec::PartyId::new("greentic"),
            basis_points: 10_000,
        }],
        revenue_policy_ref: PathBuf::from("revenue.json"),
        usage: None,
        created_at: Utc.with_ymd_and_hms(2026, 5, 18, 12, 0, 0).unwrap(),
        authorization_ref: PathBuf::from("auth.json"),
        config_overrides: BTreeMap::new(),
    }
}

/// Build a single-entry `TrafficSplit` pointing at one revision at 100 %.
pub fn make_traffic_split(
    env_id: &str,
    bundle_id: &str,
    deployment_id: &DeploymentId,
    revision_id: &RevisionId,
    idempotency_key: &str,
) -> TrafficSplit {
    TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: EnvId::try_from(env_id).expect("test env_id"),
        deployment_id: *deployment_id,
        bundle_id: BundleId::new(bundle_id),
        generation: 0,
        entries: vec![TrafficSplitEntry {
            revision_id: *revision_id,
            weight_bps: 10_000,
        }],
        updated_at: Utc.with_ymd_and_hms(2026, 5, 18, 12, 0, 0).unwrap(),
        updated_by: "test".to_string(),
        idempotency_key: idempotency_key.to_string(),
        authorization_ref: PathBuf::from("auth.json"),
        previous_split_ref: None,
    }
}
