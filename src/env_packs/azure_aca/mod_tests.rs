use greentic_deploy_spec::PackDescriptor;

use super::*;

#[test]
fn handler_serves_the_deployer_slot_under_the_azure_path() {
    let h = AzureAcaDeployerHandler::default();
    assert_eq!(h.slot(), CapabilitySlot::Deployer);
    assert_eq!(h.descriptor_path(), "greentic.deployer.azure-aca");
}

#[test]
fn version_req_accepts_ga_and_dev_and_rejects_the_next_major() {
    let req = AzureAcaDeployerHandler::default().supported_versions();
    for (raw, ok) in [
        ("greentic.deployer.azure-aca@1.0.0", true),
        ("greentic.deployer.azure-aca@1.4.2", true),
        ("greentic.deployer.azure-aca@1.0.0-dev.1", true),
        ("greentic.deployer.azure-aca@2.0.0", false),
        ("greentic.deployer.azure-aca@0.9.0", false),
    ] {
        let d = PackDescriptor::try_new(raw).unwrap();
        assert_eq!(req.matches(&d.version().0), ok, "{raw} vs {req}");
    }
}

#[test]
fn wizard_yaml_pins_its_id_and_requires_the_scope_answers() {
    let yaml = AzureAcaDeployerHandler::default()
        .wizard_qaspec_yaml()
        .unwrap();
    let spec: qa_spec::FormSpec = serde_yaml_bw::from_str(yaml).unwrap();
    assert_eq!(spec.id, "greentic.deployer.azure-aca.wizard");
    for key in [
        "subscription_id",
        "tenant_id",
        "resource_group",
        "environment_name",
    ] {
        let q = spec.questions.iter().find(|q| q.id == key).unwrap();
        assert!(q.required, "{key}");
    }
}

#[test]
fn every_wizard_question_is_an_accepted_answer_key() {
    let yaml = AzureAcaDeployerHandler::default()
        .wizard_qaspec_yaml()
        .unwrap();
    let spec: qa_spec::FormSpec = serde_yaml_bw::from_str(yaml).unwrap();
    let mut answers = serde_json::Map::new();
    for q in &spec.questions {
        let v = match q.id.as_str() {
            "subscription_id" | "tenant_id" => "11111111-2222-3333-4444-555555555555",
            "min_instances" => "0",
            "max_instances" => "1",
            "acr_login_server" => "a.azurecr.io",
            "runtime_image_digest" => "",
            _ => "abc",
        };
        answers.insert(q.id.clone(), serde_json::Value::String(v.to_string()));
    }
    let a = serde_json::Value::Object(answers);
    AcaParams::from_answers(Some(&a)).unwrap();
}

#[test]
fn debug_of_the_handler_never_prints_dev_secret_bytes() {
    let h = AzureAcaDeployerHandler::with_target_and_dev_secrets(
        Arc::new(UnconfiguredAcaTarget),
        Some(b"SUPERSECRET".to_vec()),
    );
    let shown = format!("{h:?}");
    assert!(
        !shown.contains("SUPERSECRET") && shown.contains("<redacted 11 bytes>"),
        "{shown}"
    );
}

#[test]
fn descriptor_path_is_registered_for_provider_teardown() {
    assert!(
        crate::environment::PROVIDER_TEARDOWN_DESCRIPTORS
            .contains(&AzureAcaDeployerHandler::DESCRIPTOR_PATH)
    );
}

#[test]
fn the_registry_resolves_the_azure_pack_and_refuses_other_versions() {
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();
    let ok = PackDescriptor::try_new("greentic.deployer.azure-aca@1.0.0").unwrap();
    assert!(
        registry
            .resolve_for_slot(CapabilitySlot::Deployer, &ok)
            .is_ok()
    );
    let bad = PackDescriptor::try_new("greentic.deployer.azure-aca@2.0.0").unwrap();
    assert!(
        registry
            .resolve_for_slot(CapabilitySlot::Deployer, &bad)
            .is_err()
    );
}

#[test]
fn exposes_credentials_and_the_deployer_impl_but_no_manifest_renderer() {
    let h = AzureAcaDeployerHandler::default();
    assert!(h.deployer_credentials().is_some());
    assert!((&h as &dyn EnvPackHandler).as_deployer().is_some());
    assert!((&h as &dyn EnvPackHandler).as_manifest_renderer().is_none());
}
