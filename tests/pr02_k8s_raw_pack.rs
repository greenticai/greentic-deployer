use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use greentic_deployer::contract::DeployerContractV1;
use serde_json::Value as JsonValue;
use serde_yaml_bw as serde_yaml;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/packs/k8s-raw")
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

fn load_manifest_docs() -> Vec<serde_yaml::Value> {
    let yaml = fs::read_to_string(fixture_root().join("assets/examples/rendered-manifests.yaml"))
        .expect("read rendered manifests");
    yaml.split("\n---\n")
        .map(|doc| serde_yaml::from_str::<serde_yaml::Value>(doc).expect("parse yaml doc"))
        .collect()
}

fn doc_by_kind<'a>(docs: &'a [serde_yaml::Value], kind: &str) -> &'a serde_yaml::Value {
    docs.iter()
        .find(|doc| doc.get("kind").and_then(|v| v.as_str()) == Some(kind))
        .unwrap_or_else(|| panic!("missing kind {kind}"))
}

#[test]
fn k8s_raw_contract_references_existing_assets() {
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
fn k8s_raw_examples_validate_against_pack_schemas() {
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
fn k8s_raw_manifests_include_required_resource_set() {
    let docs = load_manifest_docs();
    let mut kinds = docs
        .iter()
        .filter_map(|doc| doc.get("kind").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    kinds.sort_unstable();

    let expected = vec![
        "ConfigMap",
        "Deployment",
        "HorizontalPodAutoscaler",
        "Ingress",
        "Namespace",
        "NetworkPolicy",
        "PodDisruptionBudget",
        "Role",
        "RoleBinding",
        "Service",
        "ServiceAccount",
    ];
    for kind in expected {
        assert!(
            kinds.iter().any(|existing| existing == &kind),
            "missing {kind}"
        );
    }
}

#[test]
fn k8s_raw_deployment_enforces_security_and_probes() {
    let docs = load_manifest_docs();
    let deployment = doc_by_kind(&docs, "Deployment");
    let container = &deployment["spec"]["template"]["spec"]["containers"][0];

    assert_eq!(
        deployment["spec"]["template"]["spec"]["securityContext"]["runAsNonRoot"].as_bool(),
        Some(true)
    );
    assert_eq!(
        deployment["spec"]["template"]["spec"]["securityContext"]["runAsUser"].as_i64(),
        Some(65532)
    );
    assert_eq!(
        container["securityContext"]["readOnlyRootFilesystem"].as_bool(),
        Some(true)
    );
    assert_eq!(
        container["securityContext"]["allowPrivilegeEscalation"].as_bool(),
        Some(false)
    );
    assert!(
        container["image"]
            .as_str()
            .expect("image")
            .contains("distroless")
    );

    let mount_paths = container["volumeMounts"]
        .as_sequence()
        .expect("volume mounts")
        .iter()
        .filter_map(|mount| mount.get("mountPath").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(mount_paths, vec!["/tmp", "/var/cache/greentic"]);

    let env_names = container["env"]
        .as_sequence()
        .expect("env")
        .iter()
        .filter_map(|env| env.get("name").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    for name in [
        "REDIS_URL",
        "GREENTIC_BUNDLE_SOURCE",
        "GREENTIC_ADMIN_LISTEN",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "GREENTIC_SAFE_MODE",
    ] {
        assert!(env_names.contains(&name), "missing env {name}");
    }

    assert_eq!(
        container["livenessProbe"]["httpGet"]["path"].as_str(),
        Some("/healthz")
    );
    assert_eq!(
        container["readinessProbe"]["httpGet"]["path"].as_str(),
        Some("/readyz")
    );
    assert_eq!(
        container["startupProbe"]["httpGet"]["path"].as_str(),
        Some("/status")
    );
}

#[test]
fn k8s_raw_network_policy_and_hpa_match_policy_requirements() {
    let docs = load_manifest_docs();
    let network_policy = doc_by_kind(&docs, "NetworkPolicy");
    let egress = network_policy["spec"]["egress"]
        .as_sequence()
        .expect("egress rules");
    assert_eq!(
        network_policy["spec"]["policyTypes"]
            .as_sequence()
            .map(|s| s.len()),
        Some(2)
    );
    assert!(egress.iter().any(|rule| {
        rule["ports"]
            .as_sequence()
            .is_some_and(|ports| ports.iter().any(|port| port["port"].as_i64() == Some(6379)))
    }));
    assert!(egress.iter().any(|rule| {
        rule["ports"]
            .as_sequence()
            .is_some_and(|ports| ports.iter().any(|port| port["port"].as_i64() == Some(4317)))
    }));
    assert!(egress.iter().any(|rule| {
        rule["ports"]
            .as_sequence()
            .is_some_and(|ports| ports.iter().any(|port| port["port"].as_i64() == Some(443)))
    }));

    let hpa = doc_by_kind(&docs, "HorizontalPodAutoscaler");
    assert_eq!(hpa["spec"]["minReplicas"].as_i64(), Some(2));
    assert_eq!(hpa["spec"]["maxReplicas"].as_i64(), Some(6));

    let pdb = doc_by_kind(&docs, "PodDisruptionBudget");
    assert_eq!(pdb["spec"]["minAvailable"].as_i64(), Some(1));
}

#[test]
fn k8s_raw_generate_output_declares_upgrade_modes() {
    let output = load_json(&fixture_root().join("assets/examples/generate-output.json"));
    let modes = output["supported_upgrade_modes"]
        .as_array()
        .expect("upgrade modes")
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(modes, vec!["rolling", "blue_green", "canary_external"]);
}

#[test]
fn k8s_raw_manifest_names_are_consistent() {
    let docs = load_manifest_docs();
    let mut names = BTreeMap::new();
    for kind in [
        "ServiceAccount",
        "Role",
        "RoleBinding",
        "Deployment",
        "Service",
        "Ingress",
        "NetworkPolicy",
        "HorizontalPodAutoscaler",
        "PodDisruptionBudget",
    ] {
        let doc = doc_by_kind(&docs, kind);
        names.insert(
            kind,
            doc["metadata"]["name"].as_str().expect("metadata.name"),
        );
    }

    for (_, name) in names {
        assert_eq!(name, "greentic-operator");
    }
}
