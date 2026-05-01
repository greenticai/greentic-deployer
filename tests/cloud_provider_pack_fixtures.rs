use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/packs")
        .join(name)
}

fn load_json(path: &Path) -> JsonValue {
    let text = fs::read_to_string(path).expect("read json fixture");
    serde_json::from_str(&text).expect("parse json fixture")
}

fn validate_with_schema(schema_path: &Path, instance_path: &Path) {
    let schema = load_json(schema_path);
    let instance = load_json(instance_path);
    let compiled = jsonschema::validator_for(&schema).expect("compile schema");
    let errors = compiled.iter_errors(&instance).collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema {} rejected {}: {:?}",
        schema_path.display(),
        instance_path.display(),
        errors
    );
}

fn assert_pack_fixture(provider: &str, module_path: &str, remote_state_backend: &str) {
    let root = fixture_root(provider);
    let contract_path = root.join("contract.greentic.deployer.v1.json");
    let contract: DeployerContractV1 =
        serde_json::from_value(load_json(&contract_path)).expect("parse contract");
    contract.validate().expect("valid contract");

    for capability in &contract.capabilities {
        for path in [
            capability.input_schema_ref.as_deref(),
            capability.output_schema_ref.as_deref(),
            capability.execution_output_schema_ref.as_deref(),
            capability.qa_spec_ref.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                root.join(path).exists(),
                "missing referenced asset {}",
                path
            );
        }
        for example in &capability.example_refs {
            assert!(root.join(example).exists(), "missing example {}", example);
        }
    }

    validate_with_schema(
        &root.join("assets/schemas/generate-input.schema.json"),
        &root.join("assets/examples/generate-request.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/generate-output.schema.json"),
        &root.join("assets/examples/generate-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/plan-output.schema.json"),
        &root.join("assets/examples/plan-output.json"),
    );

    let generate_request = load_json(&root.join("assets/examples/generate-request.json"));
    assert!(generate_request.get("cloud").is_none());
    assert_eq!(
        generate_request["remote_state_backend"].as_str(),
        Some(remote_state_backend)
    );

    let generate_output = load_json(&root.join("assets/examples/generate-output.json"));
    assert_eq!(generate_output["provider"].as_str(), Some(provider));
    assert_eq!(
        generate_output["supported_clouds"]
            .as_array()
            .expect("supported_clouds")
            .len(),
        1
    );
    assert_eq!(
        generate_output["cloud_modules"][provider].as_str(),
        Some(module_path)
    );

    let plan_output = load_json(&root.join("assets/examples/plan-output.json"));
    assert_eq!(plan_output["provider"].as_str(), Some(provider));

    let status_output = load_json(&root.join("assets/examples/status-output.json"));
    assert_eq!(status_output["provider"].as_str(), Some(provider));
    let expected_pack_id = format!("greentic.deploy.{provider}");
    assert_eq!(
        status_output["pack_id"].as_str(),
        Some(expected_pack_id.as_str())
    );
}

#[test]
fn aws_pack_fixture_is_provider_specific() {
    assert_pack_fixture("aws", "modules/operator", "s3");
}

#[test]
fn azure_pack_fixture_is_provider_specific() {
    assert_pack_fixture("azure", "modules/operator-azure", "azurerm");
}

#[test]
fn gcp_pack_fixture_is_provider_specific() {
    assert_pack_fixture("gcp", "modules/operator-gcp", "gcs");
}
