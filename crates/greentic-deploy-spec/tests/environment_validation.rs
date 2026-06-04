use greentic_deploy_spec::{
    CapabilitySlot, EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, ExtensionBinding,
    ExtensionRef, PackDescriptor, PackId, SchemaVersion, SpecError,
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
            listen_addr: None,
        },
        packs,
        credentials_ref: None,
        bundles: vec![],
        revisions: vec![],
        traffic_splits: vec![],
        messaging_endpoints: vec![],
        extensions: vec![],
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

// --- extension bindings (Path 3) -----------------------------------------

fn extension(descriptor: &str, instance: Option<&str>) -> ExtensionBinding {
    ExtensionBinding {
        kind: PackDescriptor::try_new(descriptor).unwrap(),
        pack_ref: PackId::new("pack-ext"),
        instance_id: instance.map(str::to_string),
        answers_ref: None,
        generation: 0,
        previous_binding_ref: None,
    }
}

fn env_with_extensions(extensions: Vec<ExtensionBinding>) -> Environment {
    let mut e = env(vec![]);
    e.extensions = extensions;
    e
}

#[test]
fn duplicate_extension_same_path_no_instance_rejected() {
    let e = env_with_extensions(vec![
        extension("acme.oauth.auth0@1.0.0", None),
        extension("acme.oauth.auth0@2.0.0", None),
    ]);
    let err = e.validate().unwrap_err();
    assert!(
        matches!(err, SpecError::DuplicateExtension { ref path, instance_id: None } if path == "acme.oauth.auth0"),
        "got {err:?}"
    );
}

#[test]
fn duplicate_extension_same_path_same_instance_rejected() {
    let e = env_with_extensions(vec![
        extension("acme.oauth.auth0@1.0.0", Some("primary")),
        extension("acme.oauth.auth0@1.0.0", Some("primary")),
    ]);
    let err = e.validate().unwrap_err();
    assert!(
        matches!(err, SpecError::DuplicateExtension { .. }),
        "got {err:?}"
    );
}

#[test]
fn default_and_named_instances_coexist() {
    // None + two distinct Some(..) on the same path are all unique keys.
    let e = env_with_extensions(vec![
        extension("acme.oauth.auth0@1.0.0", None),
        extension("acme.oauth.auth0@1.0.0", Some("primary")),
        extension("acme.oauth.auth0@1.0.0", Some("secondary")),
    ]);
    e.validate()
        .expect("distinct (path, instance_id) keys are valid");
}

#[test]
fn invalid_instance_id_rejected() {
    let e = env_with_extensions(vec![extension("acme.oauth.auth0@1.0.0", Some("Bad/Id"))]);
    let err = e.validate().unwrap_err();
    assert!(
        matches!(err, SpecError::InvalidExtensionInstanceId { .. }),
        "got {err:?}"
    );
}

#[test]
fn extension_for_ref_selects_by_path_and_instance() {
    let e = env_with_extensions(vec![
        extension("acme.oauth.auth0@1.0.0", None),
        extension("acme.oauth.auth0@1.0.0", Some("primary")),
    ]);
    let default = e
        .extension_for_ref(&ExtensionRef::try_new("ext://acme.oauth.auth0").unwrap())
        .expect("default instance resolves");
    assert_eq!(default.instance_id, None);
    let named = e
        .extension_for_ref(&ExtensionRef::try_new("ext://acme.oauth.auth0/primary").unwrap())
        .expect("named instance resolves");
    assert_eq!(named.instance_id.as_deref(), Some("primary"));
    // A path/instance with no binding resolves to None.
    assert!(
        e.extension_for_ref(&ExtensionRef::try_new("ext://acme.oauth.auth0/missing").unwrap())
            .is_none()
    );
}
