use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/gcp")
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
fn gcp_contract_references_existing_assets() {
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
fn gcp_contract_uses_gcp_specific_flow_ids() {
    let root = fixture_root();
    let contract: DeployerContractV1 =
        serde_json::from_value(load_json(&root.join("contract.greentic.deployer.v1.json")))
            .expect("parse contract");

    let flow_ids: Vec<&str> = contract
        .capabilities
        .iter()
        .map(|cap| cap.flow_id.as_str())
        .collect();
    for expected in [
        "generate_gcp",
        "plan_gcp",
        "apply_gcp",
        "destroy_gcp",
        "status_gcp",
        "rollback_gcp",
    ] {
        assert!(
            flow_ids.contains(&expected),
            "expected flow_id {expected} in {flow_ids:?}"
        );
    }
}

#[test]
fn gcp_examples_validate_against_pack_schemas() {
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
fn gcp_root_contains_required_files_and_modules() {
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
fn gcp_fixture_omits_other_cloud_modules() {
    let root = fixture_root().join("terraform");
    for path in ["modules/operator-azure", "modules/operator-gcp"] {
        assert!(
            !root.join(path).exists(),
            "gcp fixture should not ship {}; the GCP module lives at modules/operator/",
            path
        );
    }
}

#[test]
fn gcp_files_are_deterministic_and_secret_free() {
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
fn gcp_providers_pin_gcs_backend_and_omit_other_cloud_providers() {
    let providers =
        fs::read_to_string(fixture_root().join("terraform/providers.tf")).expect("read providers");
    assert!(providers.contains("backend \"gcs\" {}"));
    assert!(providers.contains("hashicorp/google"));
    assert!(!providers.contains("backend \"s3\""));
    assert!(!providers.contains("backend \"azurerm\""));
    assert!(!providers.contains("provider \"azurerm\""));
    assert!(!providers.contains("hashicorp/azurerm"));
}

#[test]
fn gcp_main_tf_only_wires_gcp_operator_module() {
    let main_tf = fs::read_to_string(fixture_root().join("terraform/main.tf")).expect("read main");
    assert!(main_tf.contains("module \"operator_gcp\""));
    assert!(main_tf.contains("source = \"./modules/operator\""));
    assert!(!main_tf.contains("module \"operator_aws\""));
    assert!(!main_tf.contains("module \"operator_azure\""));
}

#[test]
fn gcp_outputs_resolve_directly_against_gcp_operator_module() {
    let outputs =
        fs::read_to_string(fixture_root().join("terraform/outputs.tf")).expect("read outputs");
    assert!(outputs.contains("module.operator_gcp.operator_endpoint"));
    assert!(outputs.contains("module.operator_gcp.admin_ca_secret_ref"));
    assert!(outputs.contains("module.operator_gcp.admin_relay_token_secret_ref"));
    assert!(!outputs.contains("module.operator_aws"));
    assert!(!outputs.contains("module.operator_azure"));
}

#[test]
fn gcp_generate_output_advertises_gcp_only_layout() {
    let generate = load_json(
        &fixture_root()
            .join("assets")
            .join("examples")
            .join("generate-output.json"),
    );

    let supported = generate["supported_clouds"]
        .as_array()
        .expect("supported_clouds array");
    assert_eq!(supported.len(), 1);
    assert_eq!(supported[0].as_str(), Some("gcp"));

    let modules = generate["cloud_modules"]
        .as_object()
        .expect("cloud_modules object");
    assert_eq!(modules.len(), 1);
    assert_eq!(
        modules.get("gcp").and_then(|value| value.as_str()),
        Some("modules/operator")
    );
}

#[test]
fn gcp_plan_output_declares_terraform_commands_and_variables() {
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
fn gcp_module_materializes_secret_manager_and_cloud_run_resources() {
    let main_tf = fs::read_to_string(fixture_root().join("terraform/modules/operator/main.tf"))
        .expect("read module main");
    let outputs_tf =
        fs::read_to_string(fixture_root().join("terraform/modules/operator/outputs.tf"))
            .expect("read module outputs");
    let variables_tf =
        fs::read_to_string(fixture_root().join("terraform/modules/operator/variables.tf"))
            .expect("read module variables");

    assert!(main_tf.contains("resource \"google_secret_manager_secret\" \"admin_ca\""));
    assert!(main_tf.contains("resource \"google_secret_manager_secret\" \"admin_server_cert\""));
    assert!(main_tf.contains("resource \"google_secret_manager_secret\" \"admin_server_key\""));
    assert!(main_tf.contains("resource \"google_secret_manager_secret\" \"admin_client_cert\""));
    assert!(main_tf.contains("resource \"google_secret_manager_secret\" \"admin_client_key\""));
    assert!(main_tf.contains("resource \"google_secret_manager_secret\" \"admin_relay_token\""));
    assert!(main_tf.contains("resource \"google_cloud_run_v2_service\" \"this\""));
    assert!(
        main_tf.contains("resource \"google_cloud_run_v2_service_iam_member\" \"public_invoker\"")
    );
    assert!(main_tf.contains("GREENTIC_ADMIN_CA_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_SERVER_CERT_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_SERVER_KEY_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_RELAY_TOKEN"));

    assert!(outputs_tf.contains("output \"admin_access_mode\""));
    assert!(outputs_tf.contains("output \"admin_public_endpoint\""));
    assert!(outputs_tf.contains("output \"admin_relay_token_secret_ref\""));
    assert!(outputs_tf.contains("/admin-relay/v1"));

    assert!(variables_tf.contains("variable \"admin_access_mode\""));
    assert!(variables_tf.contains("default = \"http-bearer-relay\""));
    assert!(variables_tf.contains("variable \"gcp_project_id\""));
    assert!(variables_tf.contains("variable \"gcp_region\""));
}
