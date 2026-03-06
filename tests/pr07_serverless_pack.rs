use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/serverless")
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
fn serverless_contract_references_existing_assets() {
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
fn serverless_examples_validate_against_pack_schemas() {
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
}

#[test]
fn serverless_descriptor_models_env_contract_and_tmp_only_filesystem() {
    let descriptor = load_json(&fixture_root().join("assets/examples/deployment-descriptor.json"));
    let env = descriptor["environment"]
        .as_object()
        .expect("environment map");
    assert!(env.contains_key("REDIS_URL"));
    assert!(env.contains_key("GREENTIC_BUNDLE_SOURCE"));
    assert!(env.contains_key("GREENTIC_STARTUP_FETCH_TIMEOUT_SECONDS"));
    assert_eq!(
        descriptor["filesystem"]["writable"]
            .as_array()
            .expect("writable dirs")
            .len(),
        1
    );
    assert_eq!(
        descriptor["filesystem"]["writable"][0].as_str(),
        Some("/tmp")
    );
    assert_eq!(
        descriptor["filesystem"]["durable"]
            .as_array()
            .expect("durable dirs")
            .len(),
        0
    );
}

#[test]
fn serverless_input_rejects_mount_required_mode() {
    let schema = load_json(&fixture_root().join("assets/schemas/generate-input.schema.json"));
    let invalid = serde_json::json!({
        "runtime_family": "cloud_run",
        "image": "ghcr.io/greentic-ai/operator-distroless:serverless",
        "redis_url": "redis://redis.example.internal:6379/0",
        "bundle_source": "oci://registry.greentic.ai/bundles/operator",
        "startup_fetch_timeout_seconds": 45,
        "warm_failure_behavior": "degraded",
        "retry_policy": { "max_attempts": 5, "backoff_seconds": 3 },
        "mount_mode": "mount_required",
        "admin_api_exposure": "private_only"
    });
    let compiled = jsonschema::validator_for(&schema).expect("compile schema");
    let errors = compiled.iter_errors(&invalid).collect::<Vec<_>>();
    assert!(!errors.is_empty(), "mount_required should be rejected");
}

#[test]
fn serverless_plan_and_generate_outputs_capture_runtime_constraints() {
    let plan = load_json(&fixture_root().join("assets/examples/plan-output.json"));
    assert!(
        plan["startup_contract"]
            .as_str()
            .expect("startup contract")
            .contains("verifies digest")
    );
    let generate = load_json(&fixture_root().join("assets/examples/generate-output.json"));
    let endpoints = generate["health_endpoints"]
        .as_array()
        .expect("health endpoints")
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(endpoints.contains(&"/healthz"));
    assert!(endpoints.contains(&"/readyz"));
}

#[test]
fn serverless_admin_api_is_private_only_or_disabled() {
    let request = load_json(&fixture_root().join("assets/examples/generate-request.json"));
    assert_eq!(request["admin_api_exposure"].as_str(), Some("private_only"));
}
