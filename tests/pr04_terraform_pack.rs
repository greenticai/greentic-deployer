use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/terraform")
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
fn terraform_contract_references_existing_assets() {
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
fn terraform_examples_validate_against_pack_schemas() {
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
        &root.join("assets/schemas/plan-output.schema.json"),
        &root.join("assets/examples/plan-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/apply-execution-output.schema.json"),
        &root.join("assets/examples/apply-execution-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/destroy-execution-output.schema.json"),
        &root.join("assets/examples/destroy-execution-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/status-output.schema.json"),
        &root.join("assets/examples/status-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/status-execution-output.schema.json"),
        &root.join("assets/examples/status-execution-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/rollback-execution-output.schema.json"),
        &root.join("assets/examples/rollback-execution-output.json"),
    );
}

#[test]
fn terraform_root_contains_required_files_and_modules() {
    let root = fixture_root().join("terraform");
    for path in [
        "main.tf",
        "variables.tf",
        "outputs.tf",
        "providers.tf",
        "staging.tfvars.example",
        "modules/operator/main.tf",
        "modules/dns/main.tf",
        "modules/registry/main.tf",
        "modules/redis/main.tf",
    ] {
        assert!(root.join(path).exists(), "missing terraform file {}", path);
    }
}

#[test]
fn terraform_files_are_deterministic_and_secret_free() {
    let root = fixture_root().join("terraform");
    let combined = [
        "main.tf",
        "variables.tf",
        "outputs.tf",
        "providers.tf",
        "staging.tfvars.example",
        "modules/operator/main.tf",
        "modules/dns/main.tf",
        "modules/registry/main.tf",
        "modules/redis/main.tf",
    ]
    .into_iter()
    .map(|path| fs::read_to_string(root.join(path)).expect("read terraform file"))
    .collect::<Vec<_>>()
    .join("\n");

    assert!(!combined.contains("password ="));
    assert!(!combined.contains("secret_value"));
    assert!(
        combined
            .contains("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    assert!(
        combined
            .contains("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
    );
}

#[test]
fn terraform_plan_output_declares_commands_and_variables() {
    let output = load_json(&fixture_root().join("assets/examples/plan-output.json"));
    assert!(
        output["terraform_init_command"]
            .as_str()
            .expect("terraform init command")
            .contains("terraform init")
    );
    assert!(
        output["terraform_plan_command"]
            .as_str()
            .expect("terraform plan command")
            .contains("terraform plan")
    );

    let vars = output["expected_variables"]
        .as_array()
        .expect("expected variables")
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(vars.contains(&"operator_image_digest"));
    assert!(vars.contains(&"bundle_digest"));
    assert!(vars.contains(&"dns_name"));
    assert!(vars.contains(&"remote_state_backend"));
}

#[test]
fn terraform_status_and_destroy_examples_capture_lifecycle_expectations() {
    let status = load_json(&fixture_root().join("assets/examples/status-output.json"));
    assert_eq!(status["kind"].as_str(), Some("status"));
    assert_eq!(status["flow_id"].as_str(), Some("status_terraform"));

    let status_execution =
        load_json(&fixture_root().join("assets/examples/status-execution-output.json"));
    assert_eq!(status_execution["kind"].as_str(), Some("status"));
    assert_eq!(status_execution["state"].as_str(), Some("handoff_ready"));
    assert!(
        status_execution["health_checks"]
            .as_array()
            .expect("health checks")
            .iter()
            .filter_map(|value| value.as_str())
            .any(|value| value == "terraform_root:present")
    );

    let destroy = load_json(&fixture_root().join("assets/examples/destroy-execution-output.json"));
    assert_eq!(destroy["kind"].as_str(), Some("destroy"));
    assert_eq!(destroy["state"].as_str(), Some("destroyed"));
    assert!(
        destroy["destroyed_resources"]
            .as_array()
            .expect("destroyed resources")
            .len()
            >= 2
    );
}

#[test]
fn terraform_providers_and_remote_state_are_templated() {
    let providers =
        fs::read_to_string(fixture_root().join("terraform/providers.tf")).expect("read providers");
    assert!(providers.contains("backend \"s3\" {}"));
    assert!(providers.contains("provider \"kubernetes\" {}"));
    assert!(providers.contains("provider \"aws\" {}"));
}

#[test]
fn terraform_runtime_module_uses_distroless_command_and_admin_secrets() {
    let main_tf = fs::read_to_string(fixture_root().join("terraform/main.tf")).expect("read main");
    let module_tf = fs::read_to_string(fixture_root().join("terraform/modules/operator/main.tf"))
        .expect("read module");

    assert!(main_tf.contains("ghcr.io/greenticai/gtc-distroless@"));
    assert!(module_tf.contains("\"start\""));
    assert!(module_tf.contains("\"--bundle\""));
    assert!(module_tf.contains("GREENTIC_ADMIN_CA_PEM"));
    assert!(module_tf.contains("GREENTIC_ADMIN_SERVER_CERT_PEM"));
    assert!(module_tf.contains("GREENTIC_ADMIN_SERVER_KEY_PEM"));
    assert!(module_tf.contains("GREENTIC_ADMIN_ALLOWED_CLIENTS"));
    assert!(module_tf.contains("PUBLIC_BASE_URL"));
}
