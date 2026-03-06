use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;
use serde_yaml_bw as serde_yaml;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/snap")
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

fn load_snapcraft(path: &Path) -> serde_yaml::Value {
    let text = fs::read_to_string(path).expect("read snapcraft");
    serde_yaml::from_str(&text).expect("parse snapcraft")
}

#[test]
fn snap_contract_references_existing_assets() {
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
fn snap_examples_validate_against_pack_schemas() {
    let root = fixture_root();
    validate_with_schema(
        &root.join("assets/schemas/generate-input.schema.json"),
        &root.join("assets/examples/fetch-request.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/generate-input.schema.json"),
        &root.join("assets/examples/embedded-request.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/generate-output.schema.json"),
        &root.join("assets/examples/fetch-output.json"),
    );
    validate_with_schema(
        &root.join("assets/schemas/generate-output.schema.json"),
        &root.join("assets/examples/embedded-output.json"),
    );
}

#[test]
fn snap_fixture_has_both_fetch_and_embedded_outputs() {
    let root = fixture_root();
    assert!(root.join("snap/fetch/snapcraft.yaml").exists());
    assert!(root.join("snap/embedded/snapcraft.yaml").exists());
}

#[test]
fn snap_fetch_mode_models_runtime_fetch_and_writable_dirs() {
    let snapcraft = load_snapcraft(&fixture_root().join("snap/fetch/snapcraft.yaml"));
    let env = &snapcraft["apps"]["operator"]["environment"];

    assert_eq!(env["GREENTIC_BUNDLE_MODE"].as_str(), Some("fetch"));
    assert!(
        env["GREENTIC_BUNDLE_DIGEST"]
            .as_str()
            .expect("bundle digest")
            .starts_with("sha256:")
    );
    assert_eq!(
        env["GREENTIC_BUNDLE_READER"].as_str(),
        Some("userspace-squashfs")
    );
    assert_eq!(
        env["GREENTIC_STATE_PATH"].as_str(),
        Some("$SNAP_COMMON/state")
    );
    assert_eq!(
        env["GREENTIC_CACHE_PATH"].as_str(),
        Some("$SNAP_COMMON/cache")
    );
    assert_eq!(env["GREENTIC_LOG_PATH"].as_str(), Some("$SNAP_COMMON/logs"));
}

#[test]
fn snap_embedded_mode_requires_internal_bundle_path() {
    let snapcraft = load_snapcraft(&fixture_root().join("snap/embedded/snapcraft.yaml"));
    let env = &snapcraft["apps"]["operator"]["environment"];

    assert_eq!(env["GREENTIC_BUNDLE_MODE"].as_str(), Some("embedded"));
    assert_eq!(
        env["GREENTIC_BUNDLE_PATH"].as_str(),
        Some("$SNAP/bundles/operator.bundle")
    );
    assert_eq!(
        env["GREENTIC_BUNDLE_READER"].as_str(),
        Some("userspace-squashfs")
    );
}

#[test]
fn snap_security_defaults_avoid_shell_and_privileged_mounts() {
    let fetch = fs::read_to_string(fixture_root().join("snap/fetch/snapcraft.yaml"))
        .expect("read fetch snapcraft");
    let embedded = fs::read_to_string(fixture_root().join("snap/embedded/snapcraft.yaml"))
        .expect("read embedded snapcraft");
    let combined = format!("{fetch}\n{embedded}");

    assert!(!combined.contains("sh -c"));
    assert!(!combined.contains("mount-control"));
    assert!(!combined.contains("privileged"));
    assert!(combined.contains("network-bind"));
}

#[test]
fn snap_admin_and_runtime_paths_are_private_and_documented() {
    let fetch = load_snapcraft(&fixture_root().join("snap/fetch/snapcraft.yaml"));
    let env = &fetch["apps"]["operator"]["environment"];
    assert_eq!(
        env["GREENTIC_ADMIN_LISTEN"].as_str(),
        Some("127.0.0.1:8081")
    );
    assert_eq!(env["REDIS_URL"].as_str(), Some("redis://127.0.0.1:6379/0"));
    assert_eq!(env["GREENTIC_CACHE_SIZE_HINT_MB"].as_str(), Some("512"));
}
