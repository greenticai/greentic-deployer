use greentic_deploy_spec::{
    CapabilitySlot, EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, PackDescriptor,
    PackId, SchemaVersion, SpecError,
};
use std::str::FromStr;

fn binding(slot: CapabilitySlot, descriptor: &str, pack_id: &str) -> EnvPackBinding {
    EnvPackBinding {
        slot,
        kind: PackDescriptor::try_new(descriptor).unwrap(),
        pack_ref: PackId::new(pack_id),
        answers_ref: None,
        generation: 1,
        previous_binding_ref: None,
    }
}

fn env(packs: Vec<EnvPackBinding>) -> Environment {
    let env_id = EnvId::from_str("local").unwrap();
    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id.clone(),
        name: "local".into(),
        host_config: EnvironmentHostConfig {
            env_id,
            region: None,
            tenant_org_id: None,
        },
        packs,
        credentials_ref: None,
        bundles: vec![],
        revisions: vec![],
        traffic_splits: vec![],
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}

#[test]
fn valid_environment_with_unique_slots() {
    let e = env(vec![
        binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@1.0.0",
            "pack-deployer",
        ),
        binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@0.5.0",
            "pack-secrets",
        ),
        binding(
            CapabilitySlot::Telemetry,
            "greentic.telemetry.stdout@0.5.0",
            "pack-telemetry",
        ),
    ]);
    assert!(e.validate().is_ok());
}

#[test]
fn duplicate_slot_rejected() {
    let e = env(vec![
        binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@1.0.0",
            "pack-a",
        ),
        binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.k8s@1.0.0",
            "pack-b",
        ),
    ]);
    let err = e.validate().unwrap_err();
    assert_eq!(
        err,
        SpecError::DuplicateCapabilitySlot(CapabilitySlot::Deployer)
    );
}

#[test]
fn pack_for_slot_returns_binding() {
    let e = env(vec![binding(
        CapabilitySlot::State,
        "greentic.state.in-memory@0.5.0",
        "pack-state",
    )]);
    let found = e.pack_for_slot(CapabilitySlot::State).unwrap();
    assert_eq!(found.pack_ref.as_str(), "pack-state");
    assert!(e.pack_for_slot(CapabilitySlot::Telemetry).is_none());
}

#[test]
fn schema_discriminator_required() {
    let mut e = env(vec![]);
    e.schema = SchemaVersion::new("greentic.environment.v0");
    let err = e.validate().unwrap_err();
    assert!(matches!(err, SpecError::SchemaMismatch { .. }));
}
