use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/terraform")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).expect("read fixture file")
}

fn load_json(path: &Path) -> JsonValue {
    serde_json::from_str(&read(path)).expect("parse fixture json")
}

#[test]
fn azure_module_materializes_key_vault_and_runtime_resources() {
    let root = fixture_root()
        .join("terraform")
        .join("modules")
        .join("operator-azure");
    let main_tf = read(&root.join("main.tf"));
    let outputs_tf = read(&root.join("outputs.tf"));
    let variables_tf = read(&root.join("variables.tf"));

    assert!(main_tf.contains("resource \"azurerm_key_vault_secret\" \"admin_ca\""));
    assert!(main_tf.contains("resource \"azurerm_key_vault_secret\" \"admin_server_cert\""));
    assert!(main_tf.contains("resource \"azurerm_key_vault_secret\" \"admin_server_key\""));
    assert!(main_tf.contains("resource \"azurerm_key_vault_secret\" \"admin_client_cert\""));
    assert!(main_tf.contains("resource \"azurerm_key_vault_secret\" \"admin_client_key\""));
    assert!(main_tf.contains("resource \"azurerm_key_vault_secret\" \"admin_relay_token\""));
    assert!(main_tf.contains("resource \"azurerm_log_analytics_workspace\" \"this\""));
    assert!(main_tf.contains("resource \"azurerm_container_app_environment\" \"this\""));
    assert!(main_tf.contains("resource \"azurerm_container_app\" \"this\""));
    assert!(main_tf.contains("GREENTIC_ADMIN_CA_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_SERVER_CERT_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_SERVER_KEY_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_CERT_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_KEY_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_RELAY_TOKEN"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CA_SECRET_REF"));
    assert!(main_tf.contains("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF"));
    assert!(main_tf.contains("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_CERT_SECRET_REF"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_KEY_SECRET_REF"));
    assert!(main_tf.contains("GREENTIC_ADMIN_RELAY_TOKEN_SECRET_REF"));

    assert!(outputs_tf.contains("output \"admin_access_mode\""));
    assert!(outputs_tf.contains("output \"admin_public_endpoint\""));
    assert!(outputs_tf.contains("output \"admin_client_cert_secret_ref\""));
    assert!(outputs_tf.contains("output \"admin_client_key_secret_ref\""));
    assert!(outputs_tf.contains("output \"admin_relay_token_secret_ref\""));
    assert!(outputs_tf.contains("/admin-relay/v1"));

    assert!(variables_tf.contains("variable \"admin_access_mode\""));
    assert!(variables_tf.contains("default = \"http-bearer-relay\""));
}

#[test]
fn gcp_module_materializes_secret_manager_and_cloud_run_resources() {
    let root = fixture_root()
        .join("terraform")
        .join("modules")
        .join("operator-gcp");
    let main_tf = read(&root.join("main.tf"));
    let outputs_tf = read(&root.join("outputs.tf"));
    let variables_tf = read(&root.join("variables.tf"));

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
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_CERT_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_KEY_PEM"));
    assert!(main_tf.contains("GREENTIC_ADMIN_RELAY_TOKEN"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_CERT_SECRET_REF"));
    assert!(main_tf.contains("GREENTIC_ADMIN_CLIENT_KEY_SECRET_REF"));
    assert!(main_tf.contains("GREENTIC_ADMIN_RELAY_TOKEN_SECRET_REF"));
    assert!(main_tf.contains("deletion_protection = false"));
    assert!(!main_tf.contains("GREENTIC_ADMIN_CA_SECRET_REF"));
    assert!(!main_tf.contains("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF"));
    assert!(!main_tf.contains("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF"));

    assert!(outputs_tf.contains("output \"admin_access_mode\""));
    assert!(outputs_tf.contains("output \"admin_public_endpoint\""));
    assert!(outputs_tf.contains("output \"admin_client_cert_secret_ref\""));
    assert!(outputs_tf.contains("output \"admin_client_key_secret_ref\""));
    assert!(outputs_tf.contains("output \"admin_relay_token_secret_ref\""));
    assert!(outputs_tf.contains("/admin-relay/v1"));

    assert!(variables_tf.contains("variable \"admin_access_mode\""));
    assert!(variables_tf.contains("default = \"http-bearer-relay\""));
}

#[test]
fn generate_examples_capture_cloud_specific_runtime_inputs() {
    let root = fixture_root().join("assets").join("examples");
    let azure = load_json(&root.join("generate-request.azure.json"));
    let gcp = load_json(&root.join("generate-request.gcp.json"));

    assert_eq!(azure["cloud"].as_str(), Some("azure"));
    assert_eq!(azure["remote_state_backend"].as_str(), Some("azurerm"));
    assert!(azure["azure_key_vault_id"].as_str().is_some());
    assert!(azure["azure_location"].as_str().is_some());

    assert_eq!(gcp["cloud"].as_str(), Some("gcp"));
    assert_eq!(gcp["remote_state_backend"].as_str(), Some("gcs"));
    assert!(gcp["gcp_project_id"].as_str().is_some());
    assert!(gcp["gcp_region"].as_str().is_some());
}

#[test]
fn generate_output_advertises_multicloud_module_layout() {
    let generate = load_json(
        &fixture_root()
            .join("assets")
            .join("examples")
            .join("generate-output.json"),
    );

    let supported = generate["supported_clouds"]
        .as_array()
        .expect("supported_clouds array");
    assert!(supported.iter().any(|entry| entry.as_str() == Some("aws")));
    assert!(
        supported
            .iter()
            .any(|entry| entry.as_str() == Some("azure"))
    );
    assert!(supported.iter().any(|entry| entry.as_str() == Some("gcp")));

    let modules = generate["cloud_modules"]
        .as_object()
        .expect("cloud_modules object");
    assert_eq!(
        modules.get("azure").and_then(|value| value.as_str()),
        Some("modules/operator-azure")
    );
    assert_eq!(
        modules.get("gcp").and_then(|value| value.as_str()),
        Some("modules/operator-gcp")
    );
}
