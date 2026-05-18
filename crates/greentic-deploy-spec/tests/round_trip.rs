//! JSON+YAML round-trip for every top-level spec type.

use chrono::Utc;
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, CapabilitySlot, Credentials, CredentialsMode,
    CredentialsValidation, CredentialsValidationResult, CustomerId, DeploymentId, EnvId,
    EnvPackBinding, Environment, EnvironmentHostConfig, EnvironmentRuntime, PackConfig,
    PackDescriptor, PackId, PartyId, RevenueShareEntry, RevisionId, RevisionRuntimeBlock,
    RouteBinding, RuntimeConfig, SchemaVersion, SecretRef, TenantSelector, TrafficSplit,
    TrafficSplitEntry,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

fn env_id() -> EnvId {
    EnvId::from_str("local").unwrap()
}

fn sample_environment() -> Environment {
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id(),
        name: "local".into(),
        host_config: EnvironmentHostConfig {
            env_id: env_id(),
            region: Some("local".into()),
            tenant_org_id: None,
        },
        packs: vec![EnvPackBinding {
            slot: CapabilitySlot::Deployer,
            kind: PackDescriptor::try_new("greentic.deployer.local-process@1.0.0").unwrap(),
            pack_ref: PackId::new("pack-deployer-local"),
            answers_ref: Some(PathBuf::from("env-packs/deployer/answers.json")),
            generation: 1,
            previous_binding_ref: None,
        }],
        credentials_ref: None,
        bundles: vec![],
        revisions: vec![],
        traffic_splits: vec![],
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}

fn sample_environment_runtime() -> EnvironmentRuntime {
    let mut discovered = BTreeMap::new();
    discovered.insert("alb_dns".into(), serde_json::json!("alb.example.com"));
    EnvironmentRuntime {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
        environment_id: env_id(),
        discovered,
        generated_at: Utc::now(),
        generated_by: PackDescriptor::try_new("greentic.deployer.local-process@1.0.0").unwrap(),
        generation: 1,
    }
}

fn sample_traffic_split() -> TrafficSplit {
    TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: env_id(),
        deployment_id: DeploymentId::new(),
        bundle_id: "customer.support".into(),
        generation: 1,
        entries: vec![TrafficSplitEntry {
            revision_id: RevisionId::new(),
            weight_bps: 10_000,
        }],
        updated_at: Utc::now(),
        updated_by: "operator://local/test".into(),
        idempotency_key: "01JTKW5B4W4Q5Y1CQW93F7S5VH".into(),
        authorization_ref: PathBuf::from("audit/x.json"),
        previous_split_ref: None,
    }
}

fn sample_bundle_deployment() -> BundleDeployment {
    BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id: DeploymentId::new(),
        env_id: env_id(),
        bundle_id: "customer.support".into(),
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions: vec![RevisionId::new()],
        route_binding: RouteBinding {
            hosts: vec!["example.com".into()],
            path_prefixes: vec!["/".into()],
            tenant_selector: TenantSelector {
                tenant: "acme".into(),
                team: "support".into(),
            },
        },
        revenue_share: vec![RevenueShareEntry {
            party_id: PartyId::new("greentic"),
            basis_points: 10_000,
        }],
        revenue_policy_ref: PathBuf::from("billing/v1.json.sig"),
        usage: None,
        created_at: Utc::now(),
        authorization_ref: PathBuf::from("audit/x.json"),
    }
}

fn sample_credentials() -> Credentials {
    Credentials {
        schema: SchemaVersion::new(SchemaVersion::CREDENTIALS_V1),
        env_id: env_id(),
        deployer_kind: PackDescriptor::try_new("greentic.deployer.local-process@1.0.0").unwrap(),
        mode: CredentialsMode::Requirements,
        provided_credentials_ref: SecretRef::try_new("secret://local/credentials/local").unwrap(),
        validation: CredentialsValidation {
            last_run_at: Utc::now(),
            result: CredentialsValidationResult::Pass,
            missing_capabilities: vec![],
        },
        bootstrap: None,
        expiry: None,
    }
}

fn sample_pack_config() -> PackConfig {
    let mut non_secret = BTreeMap::new();
    non_secret.insert("default_locale".into(), serde_json::json!("en-GB"));
    PackConfig {
        schema: SchemaVersion::new(SchemaVersion::PACK_CONFIG_V1),
        pack_id: PackId::new("customer.support.flows"),
        revision_id: RevisionId::new(),
        non_secret,
        secret_refs: BTreeMap::new(),
        runtime_refs: BTreeMap::new(),
    }
}

fn sample_runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        schema: SchemaVersion::new(SchemaVersion::RUNTIME_CONFIG_V1),
        env_id: env_id(),
        revisions: vec![RevisionRuntimeBlock {
            deployment_id: DeploymentId::new(),
            revision_id: RevisionId::new(),
            bundle_id: "customer.support".into(),
            pack_list_refs: vec![PathBuf::from("revisions/01.../PackList.lock")],
            pack_config_refs: vec![PathBuf::from("revisions/01.../config.json")],
            weight_bps: 10_000,
        }],
    }
}

macro_rules! round_trip_json {
    ($name:ident, $factory:expr) => {
        #[test]
        fn $name() {
            let original = $factory;
            let json = serde_json::to_string(&original).unwrap();
            let back = serde_json::from_str(&json).unwrap();
            assert_eq!(original, back);
        }
    };
}

macro_rules! round_trip_yaml {
    ($name:ident, $factory:expr) => {
        #[test]
        fn $name() {
            let original = $factory;
            let yaml = serde_yaml_bw::to_string(&original).unwrap();
            let back = serde_yaml_bw::from_str(&yaml).unwrap();
            assert_eq!(original, back);
        }
    };
}

round_trip_json!(environment_json, sample_environment());
round_trip_json!(environment_runtime_json, sample_environment_runtime());
round_trip_json!(traffic_split_json, sample_traffic_split());
round_trip_json!(bundle_deployment_json, sample_bundle_deployment());
round_trip_json!(credentials_json, sample_credentials());
round_trip_json!(pack_config_json, sample_pack_config());
round_trip_json!(runtime_config_json, sample_runtime_config());

round_trip_yaml!(environment_yaml, sample_environment());
round_trip_yaml!(environment_runtime_yaml, sample_environment_runtime());
round_trip_yaml!(traffic_split_yaml, sample_traffic_split());
round_trip_yaml!(bundle_deployment_yaml, sample_bundle_deployment());
round_trip_yaml!(credentials_yaml, sample_credentials());
round_trip_yaml!(pack_config_yaml, sample_pack_config());
round_trip_yaml!(runtime_config_yaml, sample_runtime_config());
