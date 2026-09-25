//! One SoR unit's Kubernetes shape (contract C3, amendment 5).
//!
//! A Secret holding the unit's inputs, a Deployment running
//! `greentic-sorx start <pack_ref> --answers env:SORX_ANSWERS --non-interactive`,
//! and a ClusterIP Service on 8787. Every input reaches the pod through
//! `valueFrom.secretKeyRef` (or, for the CA, a read-only file), so reading the
//! Deployment never reveals a value. Not part of `render_environment_manifests`:
//! these objects carry the SoR's own credentials, and `op env render` prints
//! its output.

use base64::Engine as _;
use greentic_deploy_spec::Environment;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    ENV_LABEL, K8sParams, common_labels, container_security_context, oci_pull_env,
    pod_security_context, resource_baseline,
};
use crate::environment::sor_units::SorUnit;
use crate::runtime_secrets::SecretValue;

pub const SOR_PORT: u16 = 8787;
pub const SOR_COMPONENT: &str = "sor";
pub const SOR_UNIT_LABEL: &str = "greentic.ai/sor-unit";
pub const SOR_ANSWERS_KEY: &str = "SORX_ANSWERS";
pub const SOR_POSTGRES_URL_KEY: &str = "SORX_POSTGRES_URL";
pub const SOR_POSTGRES_CA_KEY: &str = "SORX_POSTGRES_CA";
pub const SOR_SHARED_SECRET_KEY: &str = "SORX_SHARED_SECRET";
pub const SOR_INPUTS_HASH_ANNOTATION: &str = "greentic.ai/sor-inputs-hash";

const SOR_NAME_PREFIX: &str = "gtc-sor-";
const SOR_POSTGRES_CA_DIR: &str = "/etc/sorx/postgres-ca";
const SOR_POSTGRES_CA_FILE: &str = "ca.pem";
/// The image's `HOME` (uid 65532, distroless `nonroot`).
const SOR_HOME: &str = "/home/nonroot";
const TMP_VOLUME: &str = "tmp";
const HOME_VOLUME: &str = "sorx-home";
const CA_VOLUME: &str = "postgres-ca";
/// `0o440`: group-readable through `fsGroup: 65532`, never world-readable.
const CA_FILE_MODE: u32 = 0o440;

/// A unit's decrypted inputs. `SecretValue` redacts `Debug`, so logging this
/// struct cannot leak a value.
#[derive(Debug, Clone)]
pub struct SorUnitInputs {
    pub answers: SecretValue,
    pub postgres_url: SecretValue,
    pub postgres_ca: Option<SecretValue>,
    pub shared_secret: SecretValue,
}

/// Name of the unit's Secret, Deployment AND Service.
pub fn sor_object_name(unit_id: &str) -> String {
    format!("{SOR_NAME_PREFIX}{unit_id}")
}

fn sor_labels(env: &Environment, unit_id: &str) -> Value {
    let mut labels = common_labels(env, SOR_COMPONENT);
    labels[SOR_UNIT_LABEL] = json!(unit_id);
    labels
}

fn sor_selector(env: &Environment, unit_id: &str) -> Value {
    let mut selector = Map::new();
    selector.insert(SOR_UNIT_LABEL.to_string(), json!(unit_id));
    selector.insert(ENV_LABEL.to_string(), json!(env.environment_id.as_str()));
    Value::Object(selector)
}

/// sha256 over every input, each length-prefixed so no two input sets
/// collide by concatenation. Hex; not reversible to a value.
pub fn sor_inputs_hash(inputs: &SorUnitInputs) -> String {
    let mut hasher = Sha256::new();
    let empty = String::new();
    for part in [
        inputs.answers.expose(),
        inputs.postgres_url.expose(),
        inputs
            .postgres_ca
            .as_ref()
            .map_or(empty.as_str(), SecretValue::expose),
        inputs.shared_secret.expose(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update([u8::from(inputs.postgres_ca.is_some())]);
    hex::encode(hasher.finalize())
}

pub fn render_sor_secret(
    env: &Environment,
    unit: &SorUnit,
    inputs: &SorUnitInputs,
    params: &K8sParams,
) -> Value {
    let b64 = |value: &SecretValue| {
        Value::String(base64::engine::general_purpose::STANDARD.encode(value.expose()))
    };
    let mut data = Map::new();
    data.insert(SOR_ANSWERS_KEY.to_string(), b64(&inputs.answers));
    data.insert(SOR_POSTGRES_URL_KEY.to_string(), b64(&inputs.postgres_url));
    data.insert(
        SOR_SHARED_SECRET_KEY.to_string(),
        b64(&inputs.shared_secret),
    );
    if let Some(ca) = &inputs.postgres_ca {
        data.insert(SOR_POSTGRES_CA_KEY.to_string(), b64(ca));
    }
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": sor_object_name(&unit.unit_id),
            "namespace": params.namespace,
            "labels": sor_labels(env, &unit.unit_id),
        },
        "data": Value::Object(data),
    })
}

pub fn render_sor_deployment(
    env: &Environment,
    unit: &SorUnit,
    inputs: &SorUnitInputs,
    params: &K8sParams,
) -> Value {
    let name = sor_object_name(&unit.unit_id);
    let from_secret =
        |key: &str| json!({"name": key, "valueFrom": {"secretKeyRef": {"name": name, "key": key}}});
    let mut env_vars = vec![
        from_secret(SOR_ANSWERS_KEY),
        from_secret(SOR_POSTGRES_URL_KEY),
        from_secret(SOR_SHARED_SECRET_KEY),
    ];
    let mut mounts = vec![
        json!({"name": TMP_VOLUME, "mountPath": "/tmp"}),
        json!({"name": HOME_VOLUME, "mountPath": SOR_HOME}),
    ];
    let mut volumes = vec![
        json!({"name": TMP_VOLUME, "emptyDir": {}}),
        json!({"name": HOME_VOLUME, "emptyDir": {}}),
    ];
    if inputs.postgres_ca.is_some() {
        env_vars.push(json!({
            "name": "SORX_POSTGRES_CA_FILE",
            "value": format!("{SOR_POSTGRES_CA_DIR}/{SOR_POSTGRES_CA_FILE}"),
        }));
        mounts.push(json!({
            "name": CA_VOLUME,
            "mountPath": SOR_POSTGRES_CA_DIR,
            "readOnly": true,
        }));
        volumes.push(json!({
            "name": CA_VOLUME,
            "secret": {
                "secretName": name,
                "defaultMode": CA_FILE_MODE,
                "items": [{"key": SOR_POSTGRES_CA_KEY, "path": SOR_POSTGRES_CA_FILE}],
            },
        }));
    }
    env_vars.extend(oci_pull_env(params));

    let labels = sor_labels(env, &unit.unit_id);
    let mut annotations = Map::new();
    annotations.insert(
        SOR_INPUTS_HASH_ANNOTATION.to_string(),
        Value::String(sor_inputs_hash(inputs)),
    );
    let mut deployment = json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": params.namespace, "labels": labels},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": sor_selector(env, &unit.unit_id)},
            "template": {
                "metadata": {"labels": labels, "annotations": Value::Object(annotations)},
                "spec": {
                    "automountServiceAccountToken": false,
                    "securityContext": pod_security_context(),
                    "containers": [{
                        "name": "sor",
                        "image": unit.image,
                        "args": [
                            "start", unit.pack_ref, "--answers",
                            format!("env:{SOR_ANSWERS_KEY}"), "--non-interactive",
                        ],
                        "securityContext": container_security_context(),
                        "resources": resource_baseline(),
                        "ports": [{"name": "http", "containerPort": SOR_PORT}],
                        "env": Value::Array(env_vars),
                        "volumeMounts": Value::Array(mounts),
                        "readinessProbe": {
                            "httpGet": {"path": "/healthz", "port": SOR_PORT},
                            "initialDelaySeconds": 2,
                            "periodSeconds": 5,
                        },
                    }],
                    "volumes": Value::Array(volumes),
                },
            },
        },
    });
    if let Some(pull_secret) = &params.image_pull_secret {
        deployment["spec"]["template"]["spec"]["imagePullSecrets"] = json!([{"name": pull_secret}]);
    }
    deployment
}

pub fn render_sor_service(env: &Environment, unit: &SorUnit, params: &K8sParams) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": sor_object_name(&unit.unit_id),
            "namespace": params.namespace,
            "labels": sor_labels(env, &unit.unit_id),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": sor_selector(env, &unit.unit_id),
            "ports": [{"name": "http", "port": SOR_PORT, "targetPort": SOR_PORT}],
        },
    })
}

/// Apply order: the Secret the pod reads, then the Deployment, then the Service.
pub fn render_sor_manifests(
    env: &Environment,
    unit: &SorUnit,
    inputs: &SorUnitInputs,
    params: &K8sParams,
) -> Vec<Value> {
    vec![
        render_sor_secret(env, unit, inputs, params),
        render_sor_deployment(env, unit, inputs, params),
        render_sor_service(env, unit, params),
    ]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    pub(crate) fn unit() -> SorUnit {
        SorUnit {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            pack_ref: format!(
                "oci://reg.example/greentic/sor-landlord:t1@sha256:{}",
                "d".repeat(64)
            ),
            image: "ghcr.io/greenticai/greentic-sorx:0.2.36114419551".into(),
            tenant_id: "acme".into(),
            answers_ref: "default/_/sor-landlord/answers".into(),
            postgres_url_ref: "default/_/sor-landlord/postgres_url".into(),
            postgres_ca_ref: None,
            shared_secret_ref: "default/_/sor-landlord/shared_secret".into(),
        }
    }

    pub(crate) fn inputs(with_ca: bool) -> SorUnitInputs {
        SorUnitInputs {
            answers: SecretValue::from(r#"{"tenant":{"tenant_id":"acme"}}"#.to_string()),
            postgres_url: SecretValue::from("postgres://u:pw-SECRET@db:5432/sor".to_string()),
            postgres_ca: with_ca
                .then(|| SecretValue::from("-----BEGIN CA-SECRET-----".to_string())),
            shared_secret: SecretValue::from("shared-SECRET-token".to_string()),
        }
    }

    fn env_var<'a>(deployment: &'a Value, name: &str) -> Option<&'a Value> {
        deployment
            .pointer("/spec/template/spec/containers/0/env")?
            .as_array()?
            .iter()
            .find(|v| v["name"] == name)
    }

    #[test]
    fn the_deployment_runs_sorx_non_interactively_from_the_pinned_pack() {
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        let d = render_sor_deployment(&env, &unit(), &inputs(false), &params);
        assert_eq!(d.pointer("/metadata/name").unwrap(), "gtc-sor-landlord");
        assert_eq!(
            d.pointer("/metadata/namespace").unwrap(),
            params.namespace.as_str()
        );
        assert_eq!(
            d.pointer("/metadata/labels/app.kubernetes.io~1component")
                .unwrap(),
            "sor"
        );
        assert_eq!(
            d.pointer("/metadata/labels/greentic.ai~1sor-unit").unwrap(),
            "landlord"
        );
        assert_eq!(
            d.pointer("/spec/template/metadata/labels/greentic.ai~1sor-unit")
                .unwrap(),
            "landlord"
        );
        assert_eq!(
            d.pointer("/spec/selector/matchLabels/greentic.ai~1sor-unit")
                .unwrap(),
            "landlord"
        );
        let c = d.pointer("/spec/template/spec/containers/0").unwrap();
        assert_eq!(c["image"], unit().image.as_str());
        assert_eq!(
            c["args"],
            serde_json::json!([
                "start",
                unit().pack_ref,
                "--answers",
                "env:SORX_ANSWERS",
                "--non-interactive"
            ])
        );
        assert_eq!(c.pointer("/ports/0/containerPort").unwrap(), 8787);
        assert_eq!(
            c.pointer("/readinessProbe/httpGet/path").unwrap(),
            "/healthz"
        );
        assert_eq!(c.pointer("/readinessProbe/httpGet/port").unwrap(), 8787);
        assert_eq!(
            d.pointer("/spec/template/spec/automountServiceAccountToken")
                .unwrap(),
            false
        );
    }

    #[test]
    fn every_input_arrives_through_a_secret_key_ref_and_no_value_is_in_the_pod_spec() {
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        let d = render_sor_deployment(&env, &unit(), &inputs(true), &params);
        for key in [SOR_ANSWERS_KEY, SOR_POSTGRES_URL_KEY, SOR_SHARED_SECRET_KEY] {
            let var = env_var(&d, key).unwrap_or_else(|| panic!("{key} missing"));
            assert_eq!(
                var.pointer("/valueFrom/secretKeyRef/name").unwrap(),
                "gtc-sor-landlord"
            );
            assert_eq!(var.pointer("/valueFrom/secretKeyRef/key").unwrap(), key);
        }
        assert!(
            env_var(&d, SOR_POSTGRES_CA_KEY).is_none(),
            "the CA is a file, never an env var"
        );
        assert_eq!(
            env_var(&d, "SORX_POSTGRES_CA_FILE").unwrap()["value"],
            "/etc/sorx/postgres-ca/ca.pem"
        );
        let text = d.to_string();
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        for leaked in ["pw-SECRET", "shared-SECRET-token", "CA-SECRET", "tenant_id"] {
            assert!(!text.contains(leaked), "pod spec must not carry `{leaked}`");
            assert!(!text.contains(&b64(leaked)));
        }
    }

    #[test]
    fn the_secret_carries_each_input_as_base64_data_and_the_ca_only_when_set() {
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let s = render_sor_secret(&env, &unit(), &inputs(false), &params);
        assert_eq!(s.pointer("/kind").unwrap(), "Secret");
        assert_eq!(s.pointer("/metadata/name").unwrap(), "gtc-sor-landlord");
        assert!(
            s.get("stringData").is_none(),
            "amendment 5: data, never stringData"
        );
        assert_eq!(
            s.pointer("/data/SORX_POSTGRES_URL").unwrap(),
            b64("postgres://u:pw-SECRET@db:5432/sor").as_str()
        );
        assert_eq!(
            s.pointer("/data/SORX_SHARED_SECRET").unwrap(),
            b64("shared-SECRET-token").as_str()
        );
        assert!(s.pointer("/data/SORX_ANSWERS").is_some());
        assert!(s.pointer("/data/SORX_POSTGRES_CA").is_none());
        let with_ca = render_sor_secret(&env, &unit(), &inputs(true), &params);
        assert_eq!(
            with_ca.pointer("/data/SORX_POSTGRES_CA").unwrap(),
            b64("-----BEGIN CA-SECRET-----").as_str()
        );
    }

    #[test]
    fn tmp_and_home_are_writable_empty_dirs_and_the_ca_is_a_read_only_file() {
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        let d = render_sor_deployment(&env, &unit(), &inputs(true), &params);
        let pod = d.pointer("/spec/template/spec").unwrap();
        let volume = |name: &str| {
            pod["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == name)
                .cloned()
                .unwrap()
        };
        let mount = |path: &str| {
            pod.pointer("/containers/0/volumeMounts")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["mountPath"] == path)
                .cloned()
                .unwrap()
        };
        assert!(volume(mount("/tmp")["name"].as_str().unwrap())["emptyDir"].is_object());
        assert!(volume(mount("/home/nonroot")["name"].as_str().unwrap())["emptyDir"].is_object());
        let ca_mount = mount("/etc/sorx/postgres-ca");
        assert_eq!(ca_mount["readOnly"], true);
        let ca = volume(ca_mount["name"].as_str().unwrap());
        assert_eq!(
            ca.pointer("/secret/secretName").unwrap(),
            "gtc-sor-landlord"
        );
        assert_eq!(
            ca.pointer("/secret/items/0/key").unwrap(),
            "SORX_POSTGRES_CA"
        );
        assert_eq!(ca.pointer("/secret/items/0/path").unwrap(), "ca.pem");
        let without = render_sor_deployment(&env, &unit(), &inputs(false), &params);
        assert!(!without.to_string().contains("postgres-ca"));
    }

    #[test]
    fn registry_credentials_reuse_the_env_oci_secret_and_answers() {
        let env = build_fixture_env();
        let mut params = K8sParams::for_env(&env);
        params.oci_username = Some("robot".into());
        params.oci_password = Some("robot-pw".into());
        params.oci_insecure_registries = vec!["reg.example:5000".into()];
        params.image_pull_secret = Some("gtc-pull".into());
        let d = render_sor_deployment(&env, &unit(), &inputs(false), &params);
        assert_eq!(env_var(&d, "OCI_USERNAME").unwrap()["value"], "robot");
        let pw = env_var(&d, "OCI_PASSWORD").unwrap();
        assert_eq!(
            pw.pointer("/valueFrom/secretKeyRef/name").unwrap(),
            "gtc-oci-credentials"
        );
        assert_eq!(
            pw.pointer("/valueFrom/secretKeyRef/key").unwrap(),
            "password"
        );
        assert_eq!(
            pw.pointer("/valueFrom/secretKeyRef/optional").unwrap(),
            true
        );
        assert_eq!(
            env_var(&d, "GREENTIC_OCI_INSECURE_REGISTRIES").unwrap()["value"],
            "reg.example:5000"
        );
        assert_eq!(
            d.pointer("/spec/template/spec/imagePullSecrets/0/name")
                .unwrap(),
            "gtc-pull"
        );
        assert!(!d.to_string().contains("robot-pw"));
    }

    #[test]
    fn the_service_is_cluster_ip_on_8787_selecting_this_unit_only() {
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        let s = render_sor_service(&env, &unit(), &params);
        assert_eq!(s.pointer("/metadata/name").unwrap(), "gtc-sor-landlord");
        assert_eq!(s.pointer("/spec/type").unwrap(), "ClusterIP");
        assert_eq!(s.pointer("/spec/ports/0/port").unwrap(), 8787);
        assert_eq!(s.pointer("/spec/ports/0/targetPort").unwrap(), 8787);
        assert_eq!(
            s.pointer("/spec/selector/greentic.ai~1sor-unit").unwrap(),
            "landlord"
        );
        let kinds: Vec<String> = render_sor_manifests(&env, &unit(), &inputs(false), &params)
            .iter()
            .map(|m| m["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            kinds,
            ["Secret", "Deployment", "Service"],
            "the Secret precedes the pod that reads it"
        );
    }

    #[test]
    fn the_inputs_hash_rolls_the_pod_only_when_an_input_changes() {
        let env = build_fixture_env();
        let params = K8sParams::for_env(&env);
        let hash = |i: &SorUnitInputs| {
            render_sor_deployment(&env, &unit(), i, &params)
                .pointer("/spec/template/metadata/annotations/greentic.ai~1sor-inputs-hash")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        };
        let base = hash(&inputs(false));
        assert_eq!(base, hash(&inputs(false)), "same inputs, same hash");
        let mut rotated = inputs(false);
        rotated.postgres_url = SecretValue::from("postgres://u:rotated@db:5432/sor".to_string());
        assert_ne!(base, hash(&rotated));
        let mut new_answers = inputs(false);
        new_answers.answers =
            SecretValue::from(r#"{"tenant":{"tenant_id":"acme"},"x":1}"#.to_string());
        assert_ne!(base, hash(&new_answers));
        assert_ne!(base, hash(&inputs(true)), "adding a CA is a change");
        assert!(!base.contains("pw-SECRET"));
    }
}
