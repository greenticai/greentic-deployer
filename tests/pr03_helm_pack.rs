use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;
use serde_yaml_bw as serde_yaml;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/helm")
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

#[test]
fn helm_contract_references_existing_assets() {
    let root = fixture_root();
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
}

#[test]
fn helm_examples_validate_against_pack_schemas() {
    let root = fixture_root();
    validate_with_schema(
        &root.join("assets/schemas/generate-input.schema.json"),
        &root.join("assets/examples/generate-request.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/generate-output.schema.json"),
        &root.join("assets/examples/generate-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/apply-execution-output.schema.json"),
        &root.join("assets/examples/apply-execution-output.json"),
    );
}

#[test]
fn helm_chart_has_required_structure() {
    let root = fixture_root().join("chart");
    for path in [
        "Chart.yaml",
        "values.yaml",
        "templates/deployment.yaml",
        "templates/service.yaml",
        "templates/ingress.yaml",
        "templates/configmap.yaml",
        "templates/networkpolicy.yaml",
        "templates/serviceaccount.yaml",
        "templates/rbac.yaml",
        "templates/hpa.yaml",
    ] {
        assert!(root.join(path).exists(), "missing chart file {}", path);
    }
}

#[test]
fn helm_chart_values_pin_image_digest_and_protect_admin_api() {
    let root = fixture_root().join("chart");
    let values_text = fs::read_to_string(root.join("values.yaml")).expect("read values");
    let values: serde_yaml::Value = serde_yaml::from_str(&values_text).expect("parse values");

    assert_eq!(
        values["image"]["digest"].as_str(),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(values["adminApi"]["public"].as_bool(), Some(false));
    assert_eq!(values["bundle"]["mode"].as_str(), Some("oci"));
}

#[test]
fn helm_templates_include_security_defaults_and_no_shell_generate() {
    let root = fixture_root().join("chart/templates");
    let deployment = fs::read_to_string(root.join("deployment.yaml")).expect("read deployment");
    assert!(deployment.contains("readOnlyRootFilesystem: true"));
    assert!(deployment.contains("allowPrivilegeEscalation: false"));
    assert!(deployment.contains("@{{ .Values.image.digest }}") || deployment.contains("@{{"));
    assert!(deployment.contains("GREENTIC_ADMIN_LISTEN"));

    let all_templates = [
        "deployment.yaml",
        "service.yaml",
        "ingress.yaml",
        "configmap.yaml",
        "networkpolicy.yaml",
        "serviceaccount.yaml",
        "rbac.yaml",
        "hpa.yaml",
        "_helpers.tpl",
    ]
    .into_iter()
    .map(|name| fs::read_to_string(root.join(name)).expect("read template"))
    .collect::<Vec<_>>()
    .join("\n");

    assert!(!all_templates.contains("exec "));
    assert!(!all_templates.contains("kubectl "));
    assert!(!all_templates.contains("helm template "));
    assert!(!all_templates.contains("sh -c"));
}

#[test]
fn helm_generate_output_declares_commands_and_guidance() {
    let output = load_json(&fixture_root().join("assets/examples/generate-output.json"));
    assert!(
        output["helm_upgrade_command"]
            .as_str()
            .expect("helm upgrade command")
            .contains("helm upgrade --install")
    );
    assert!(
        output["rollback_command_template"]
            .as_str()
            .expect("rollback command")
            .contains("helm rollback")
    );
    assert!(
        !output["values_diff_guidance"]
            .as_str()
            .expect("values diff guidance")
            .is_empty()
    );
}

#[test]
fn helm_rollback_example_matches_command_shape() {
    let text = fs::read_to_string(fixture_root().join("assets/examples/rollback-command.txt"))
        .expect("read rollback command");
    assert!(text.contains("helm rollback"));
    assert!(text.contains("<REVISION>"));
}
