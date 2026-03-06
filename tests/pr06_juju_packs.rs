use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;
use serde_yaml_bw as serde_yaml;

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

fn machine_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/juju-machine")
}

fn k8s_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/juju-k8s")
}

fn assert_contract_assets(root: &Path) {
    let contract: DeployerContractV1 =
        serde_json::from_value(load_json(&root.join("contract.greentic.deployer.v1.json")))
            .expect("parse contract");
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
fn juju_machine_contract_and_examples_are_valid() {
    let root = machine_root();
    assert_contract_assets(&root);
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
fn juju_machine_charm_has_required_files_and_relations() {
    let root = machine_root().join("charm");
    for path in [
        "charmcraft.yaml",
        "metadata.yaml",
        "config.yaml",
        "src/charm.py",
        "README.md",
    ] {
        assert!(
            root.join(path).exists(),
            "missing machine charm file {}",
            path
        );
    }
    let metadata: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(root.join("metadata.yaml")).expect("metadata"))
            .expect("parse metadata");
    let requires = &metadata["requires"];
    for rel in ["redis", "ingress", "observability"] {
        assert!(requires.get(rel).is_some(), "missing relation {}", rel);
    }
}

#[test]
fn juju_machine_plan_declares_exact_command_set() {
    let plan = load_json(&machine_root().join("assets/examples/plan-output.json"));
    for field in [
        "deploy_command",
        "config_set_command",
        "upgrade_command",
        "refresh_bundle_command",
        "remove_command",
    ] {
        assert!(
            !plan[field].as_str().expect("command").is_empty(),
            "empty {}",
            field
        );
    }
    assert_eq!(
        plan["integrate_commands"]
            .as_array()
            .map(|entries| entries.len()),
        Some(3)
    );
}

#[test]
fn juju_k8s_contract_and_examples_are_valid() {
    let root = k8s_root();
    assert_contract_assets(&root);
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
fn juju_k8s_charm_has_required_files_and_digest_pinned_workload() {
    let root = k8s_root().join("charm");
    for path in [
        "charmcraft.yaml",
        "metadata.yaml",
        "config.yaml",
        "src/charm.py",
    ] {
        assert!(root.join(path).exists(), "missing k8s charm file {}", path);
    }
    let plan = load_json(&k8s_root().join("assets/examples/plan-output.json"));
    assert!(
        plan["deploy_command"]
            .as_str()
            .expect("deploy command")
            .contains("@sha256:")
    );
}

#[test]
fn juju_k8s_charm_models_status_mapping_and_private_admin() {
    let charm = fs::read_to_string(k8s_root().join("charm/src/charm.py")).expect("read charm");
    assert!(charm.contains("\"warming\": \"waiting\""));
    assert!(charm.contains("\"ready\": \"active\""));
    assert!(charm.contains("\"degraded\": \"blocked\""));

    let request = load_json(&k8s_root().join("assets/examples/generate-request.json"));
    assert_eq!(request["admin_listener"].as_str(), Some("127.0.0.1:8081"));
}
