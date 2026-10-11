use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{DeployerError, Result};

pub const DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1: &str = "greentic.ai/v1alpha1";
pub const DEPLOYMENT_SPEC_KIND: &str = "Deployment";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSpecV1 {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: DeploymentMetadata,
    pub spec: DeploymentSpecBody,
}

impl DeploymentSpecV1 {
    pub fn from_yaml_str(input: &str) -> Result<Self> {
        let spec = serde_yaml_bw::from_str::<Self>(input).map_err(|err| {
            DeployerError::Config(format!("failed to parse deployment spec as YAML: {err}"))
        })?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn from_json_str(input: &str) -> Result<Self> {
        let spec = serde_json::from_str::<Self>(input).map_err(|err| {
            DeployerError::Config(format!("failed to parse deployment spec as JSON: {err}"))
        })?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|err| {
            DeployerError::Config(format!(
                "failed to read deployment spec {}: {err}",
                path.display()
            ))
        })?;

        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => Self::from_json_str(&contents),
            Some("yaml") | Some("yml") => Self::from_yaml_str(&contents),
            _ => match Self::from_yaml_str(&contents) {
                Ok(spec) => Ok(spec),
                Err(yaml_err) => Self::from_json_str(&contents).map_err(|json_err| {
                    let yaml_err = yaml_err.to_string();
                    let json_err = json_err.to_string();
                    DeployerError::Config(format!(
                        "failed to parse deployment spec {} as YAML ({}) or JSON ({})",
                        path.display(),
                        yaml_err,
                        json_err
                    ))
                }),
            },
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_rendered_values()?;
        if self.api_version != DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1 {
            return Err(DeployerError::Config(format!(
                "unsupported deployment spec apiVersion {}; expected {}",
                self.api_version, DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1
            )));
        }

        if self.kind != DEPLOYMENT_SPEC_KIND {
            return Err(DeployerError::Config(format!(
                "unsupported deployment spec kind {}; expected {}",
                self.kind, DEPLOYMENT_SPEC_KIND
            )));
        }

        if self.metadata.name.trim().is_empty() {
            return Err(DeployerError::Config(
                "deployment metadata.name must not be empty".to_string(),
            ));
        }

        if self.spec.runtime.arch != LinuxArch::X86_64 {
            return Err(DeployerError::Config(format!(
                "runtime.arch must be x86_64 for OSS single-vm v1; got {:?}",
                self.spec.runtime.arch
            )));
        }

        if self.spec.runtime.admin.mtls.ca_file.as_os_str().is_empty()
            || self
                .spec
                .runtime
                .admin
                .mtls
                .cert_file
                .as_os_str()
                .is_empty()
            || self.spec.runtime.admin.mtls.key_file.as_os_str().is_empty()
        {
            return Err(DeployerError::Config(
                "runtime.admin.mtls caFile/certFile/keyFile must all be set".to_string(),
            ));
        }

        let bind = self.spec.runtime.admin.bind.as_str();
        if bind.is_empty() {
            return Err(DeployerError::Config(
                "runtime.admin.bind must not be empty".to_string(),
            ));
        }
        if bind == "0.0.0.0:8433" {
            return Err(DeployerError::Config(
                "runtime.admin.bind must stay on localhost, never 0.0.0.0:8433".to_string(),
            ));
        }
        if !(bind == "127.0.0.1:8433" || bind == "localhost:8433" || bind == "[::1]:8433") {
            return Err(DeployerError::Config(format!(
                "runtime.admin.bind must be localhost on port 8433; got {bind}"
            )));
        }

        Ok(())
    }

    // These values are rendered into systemd directives, Docker arguments and
    // environment files. Reject expansion/control syntax before rendering;
    // invoking docker without a shell does not make systemd interpolation safe.
    fn validate_rendered_values(&self) -> Result<()> {
        if self.metadata.name.contains('/') || self.metadata.name.contains('\\') {
            return Err(DeployerError::Config(
                "deployment metadata.name must not contain path separators".into(),
            ));
        }
        validate_token("metadata.name", &self.metadata.name, 128, b"-_")?;
        validate_token("service.user", &self.spec.service.user, 32, b"-_")?;
        validate_token("service.group", &self.spec.service.group, 32, b"-_")?;
        validate_token("runtime.image", &self.spec.runtime.image, 512, b"-_.:/@")?;
        let source = &self.spec.bundle.source;
        if let Some(path) = source.strip_prefix("file://") {
            validate_path("bundle.source", Path::new(path))?;
        } else if source.starts_with('/') {
            validate_path("bundle.source", Path::new(source))?;
        } else if source.starts_with("oci://") || source.starts_with("https://") {
            validate_token("bundle.source", source, 4096, b"-_.:/@")?;
        } else {
            return Err(DeployerError::Config(
                "bundle.source must be an absolute path, file://, https:// or oci:// reference"
                    .into(),
            ));
        }
        for (field, path) in [
            ("storage.stateDir", &self.spec.storage.state_dir),
            ("storage.cacheDir", &self.spec.storage.cache_dir),
            ("storage.logDir", &self.spec.storage.log_dir),
            ("storage.tempDir", &self.spec.storage.temp_dir),
            (
                "runtime.admin.mtls.caFile",
                &self.spec.runtime.admin.mtls.ca_file,
            ),
            (
                "runtime.admin.mtls.certFile",
                &self.spec.runtime.admin.mtls.cert_file,
            ),
            (
                "runtime.admin.mtls.keyFile",
                &self.spec.runtime.admin.mtls.key_file,
            ),
        ] {
            validate_path(field, path)?;
        }
        for (field, path) in [
            ("health.readinessPath", &self.spec.health.readiness_path),
            ("health.livenessPath", &self.spec.health.liveness_path),
        ] {
            if path != "/" {
                validate_path(field, Path::new(path))?;
            }
        }
        if !(1..=300).contains(&self.spec.health.startup_timeout_seconds) {
            return Err(DeployerError::Config(
                "health.startupTimeoutSeconds must be 1..=300".into(),
            ));
        }
        Ok(())
    }
}

fn validate_token(field: &str, value: &str, max: usize, punctuation: &[u8]) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
    {
        return Err(DeployerError::Config(format!(
            "{field} contains unsupported characters or exceeds its length limit"
        )));
    }
    Ok(())
}

fn validate_path(field: &str, path: &Path) -> Result<()> {
    let value = path.to_str().unwrap_or_default();
    if value.len() < 2
        || value.len() > 4096
        || !value.starts_with('/')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || value[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(DeployerError::Config(format!(
            "{field} must be a literal absolute path without traversal, expansion or mount options"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentMetadata {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSpecBody {
    pub target: DeploymentTarget,
    pub bundle: BundleSpec,
    pub runtime: RuntimeSpec,
    pub storage: StorageSpec,
    pub service: ServiceSpec,
    pub health: HealthSpec,
    pub rollout: RolloutSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentTarget {
    SingleVm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleSpec {
    pub source: String,
    pub format: BundleFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BundleFormat {
    Squashfs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSpec {
    pub image: String,
    pub arch: LinuxArch,
    pub admin: AdminEndpointSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinuxArch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminEndpointSpec {
    pub bind: String,
    pub mtls: MtlsSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MtlsSpec {
    #[serde(rename = "caFile")]
    pub ca_file: PathBuf,
    #[serde(rename = "certFile")]
    pub cert_file: PathBuf,
    #[serde(rename = "keyFile")]
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageSpec {
    #[serde(rename = "stateDir")]
    pub state_dir: PathBuf,
    #[serde(rename = "cacheDir")]
    pub cache_dir: PathBuf,
    #[serde(rename = "logDir")]
    pub log_dir: PathBuf,
    #[serde(rename = "tempDir")]
    pub temp_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub manager: ServiceManager,
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceManager {
    Systemd,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthSpec {
    #[serde(rename = "readinessPath")]
    pub readiness_path: String,
    #[serde(rename = "livenessPath")]
    pub liveness_path: String,
    #[serde(rename = "startupTimeoutSeconds")]
    pub startup_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RolloutSpec {
    pub strategy: RolloutStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RolloutStrategy {
    Recreate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_spec() -> DeploymentSpecV1 {
        DeploymentSpecV1::from_yaml_str(include_str!("../examples/single-vm.deployment.yaml"))
            .expect("reference spec")
    }

    #[test]
    fn unsupported_host_requests_are_not_silently_ignored() {
        let original = serde_json::to_value(reference_spec()).unwrap();
        for pointer in [
            "",
            "/metadata",
            "/spec",
            "/spec/bundle",
            "/spec/runtime",
            "/spec/runtime/admin",
            "/spec/runtime/admin/mtls",
            "/spec/storage",
            "/spec/service",
            "/spec/health",
            "/spec/rollout",
        ] {
            let mut value = original.clone();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("privileged".into(), serde_json::json!(true));
            assert!(
                DeploymentSpecV1::from_json_str(&value.to_string()).is_err(),
                "{pointer}"
            );
            assert!(
                DeploymentSpecV1::from_yaml_str(&serde_yaml_bw::to_string(&value).unwrap())
                    .is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn render_injection_is_rejected_before_planning() {
        let original = serde_json::to_value(reference_spec()).unwrap();
        for pointer in [
            "/metadata/name",
            "/spec/runtime/image",
            "/spec/runtime/admin/bind",
            "/spec/bundle/source",
            "/spec/service/user",
            "/spec/service/group",
            "/spec/storage/stateDir",
            "/spec/runtime/admin/mtls/keyFile",
            "/spec/health/readinessPath",
        ] {
            for suffix in [
                "\nExecStart=/bin/false",
                " --privileged",
                "%n",
                "${EVIL}",
                "\"",
                "\\",
                "\u{0000}",
            ] {
                let mut value = original.clone();
                let field = value.pointer_mut(pointer).unwrap();
                *field = serde_json::json!(format!("{}{suffix}", field.as_str().unwrap()));
                // Directly deserialize too: in-memory callers must share the check.
                let spec: DeploymentSpecV1 = serde_json::from_value(value).unwrap();
                assert!(
                    crate::single_vm::plan_single_vm_spec(&spec).is_err(),
                    "{pointer}: {suffix:?}"
                );
            }
        }
    }

    #[test]
    fn paths_and_timeouts_are_bounded() {
        for path in [
            "/",
            "relative",
            "/tmp/../etc",
            "/tmp//data",
            "/tmp/./data",
            "/data:/:rw",
        ] {
            let mut spec = reference_spec();
            spec.spec.storage.state_dir = path.into();
            assert!(spec.validate().is_err(), "{path}");
        }
        for timeout in [0, 301, u64::MAX] {
            let mut spec = reference_spec();
            spec.spec.health.startup_timeout_seconds = timeout;
            assert!(spec.validate().is_err());
        }
        let mut spec = reference_spec();
        spec.metadata.name = "a".repeat(129);
        assert!(spec.validate().is_err());
        spec = reference_spec();
        spec.spec.health.readiness_path = "/".into();
        spec.validate().unwrap();
    }

    #[test]
    fn literal_digest_references_remain_supported() {
        for source in [
            "/srv/greentic/home.squashfs".to_string(),
            "https://artifacts.example/home.squashfs".to_string(),
            format!("oci://registry.example/home@sha256:{}", "a".repeat(64)),
        ] {
            let mut spec = reference_spec();
            spec.spec.bundle.source = source;
            spec.spec.runtime.image = format!("registry.example/runtime@sha256:{}", "b".repeat(64));
            crate::single_vm::plan_single_vm_spec(&spec).unwrap();
        }
    }

    #[test]
    fn deployment_spec_v1_accepts_single_vm_linux_localhost_mtls() {
        let spec = DeploymentSpecV1::from_yaml_str(
            r#"
apiVersion: greentic.ai/v1alpha1
kind: Deployment
metadata:
  name: acme-prod
spec:
  target: single-vm
  bundle:
    source: file:///opt/greentic/bundles/acme.squashfs
    format: squashfs
  runtime:
    image: "ghcr.io/greentic-ai/operator-distroless:0.1.0-distroless"
    arch: x86_64
    admin:
      bind: 127.0.0.1:8433
      mtls:
        caFile: /etc/greentic/admin/ca.crt
        certFile: /etc/greentic/admin/server.crt
        keyFile: /etc/greentic/admin/server.key
  storage:
    stateDir: /var/lib/greentic/state
    cacheDir: /var/lib/greentic/cache
    logDir: /var/log/greentic
    tempDir: /var/lib/greentic/tmp
  service:
    manager: systemd
    user: greentic
    group: greentic
  health:
    readinessPath: /ready
    livenessPath: /health
    startupTimeoutSeconds: 120
  rollout:
    strategy: recreate
"#,
        )
        .expect("parse spec");

        assert_eq!(spec.spec.target, DeploymentTarget::SingleVm);
        assert_eq!(spec.spec.runtime.arch, LinuxArch::X86_64);
    }

    #[test]
    fn deployment_spec_v1_loads_json_from_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deployment.json");
        std::fs::write(
            &path,
            r#"{
  "apiVersion": "greentic.ai/v1alpha1",
  "kind": "Deployment",
  "metadata": { "name": "acme-prod" },
  "spec": {
    "target": "single-vm",
    "bundle": {
      "source": "file:///opt/greentic/bundles/acme.squashfs",
      "format": "squashfs"
    },
    "runtime": {
      "image": "ghcr.io/greentic-ai/operator-distroless:0.1.0-distroless",
      "arch": "x86_64",
      "admin": {
        "bind": "127.0.0.1:8433",
        "mtls": {
          "caFile": "/etc/greentic/admin/ca.crt",
          "certFile": "/etc/greentic/admin/server.crt",
          "keyFile": "/etc/greentic/admin/server.key"
        }
      }
    },
    "storage": {
      "stateDir": "/var/lib/greentic/state",
      "cacheDir": "/var/lib/greentic/cache",
      "logDir": "/var/log/greentic",
      "tempDir": "/var/lib/greentic/tmp"
    },
    "service": {
      "manager": "systemd",
      "user": "greentic",
      "group": "greentic"
    },
    "health": {
      "readinessPath": "/ready",
      "livenessPath": "/health",
      "startupTimeoutSeconds": 120
    },
    "rollout": {
      "strategy": "recreate"
    }
  }
}"#,
        )
        .expect("write json");

        let spec = DeploymentSpecV1::from_path(&path).expect("load spec");
        assert_eq!(spec.spec.runtime.arch, LinuxArch::X86_64);
    }

    #[test]
    fn deployment_spec_v1_rejects_non_localhost_admin_bind() {
        let spec = DeploymentSpecV1 {
            api_version: DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1.to_string(),
            kind: DEPLOYMENT_SPEC_KIND.to_string(),
            metadata: DeploymentMetadata {
                name: "acme-prod".to_string(),
            },
            spec: DeploymentSpecBody {
                target: DeploymentTarget::SingleVm,
                bundle: BundleSpec {
                    source: "file:///tmp/demo.squashfs".to_string(),
                    format: BundleFormat::Squashfs,
                },
                runtime: RuntimeSpec {
                    image: "ghcr.io/greentic-ai/operator-distroless:0.1.0-distroless".to_string(),
                    arch: LinuxArch::X86_64,
                    admin: AdminEndpointSpec {
                        bind: "0.0.0.0:8433".to_string(),
                        mtls: MtlsSpec {
                            ca_file: "/etc/greentic/admin/ca.crt".into(),
                            cert_file: "/etc/greentic/admin/server.crt".into(),
                            key_file: "/etc/greentic/admin/server.key".into(),
                        },
                    },
                },
                storage: StorageSpec {
                    state_dir: "/var/lib/greentic/state".into(),
                    cache_dir: "/var/lib/greentic/cache".into(),
                    log_dir: "/var/log/greentic".into(),
                    temp_dir: "/var/lib/greentic/tmp".into(),
                },
                service: ServiceSpec {
                    manager: ServiceManager::Systemd,
                    user: "greentic".to_string(),
                    group: "greentic".to_string(),
                },
                health: HealthSpec {
                    readiness_path: "/ready".to_string(),
                    liveness_path: "/health".to_string(),
                    startup_timeout_seconds: 120,
                },
                rollout: RolloutSpec {
                    strategy: RolloutStrategy::Recreate,
                },
            },
        };

        let err = spec.validate().expect_err("bind must be rejected");
        assert!(err.to_string().contains("localhost"));
    }

    #[test]
    fn deployment_spec_v1_rejects_non_x86_64_arch() {
        let mut spec = DeploymentSpecV1::from_yaml_str(
            r#"
apiVersion: greentic.ai/v1alpha1
kind: Deployment
metadata:
  name: acme-prod
spec:
  target: single-vm
  bundle:
    source: file:///opt/greentic/bundles/acme.squashfs
    format: squashfs
  runtime:
    image: "ghcr.io/greentic-ai/operator-distroless:0.1.0-distroless"
    arch: x86_64
    admin:
      bind: 127.0.0.1:8433
      mtls:
        caFile: /etc/greentic/admin/ca.crt
        certFile: /etc/greentic/admin/server.crt
        keyFile: /etc/greentic/admin/server.key
  storage:
    stateDir: /var/lib/greentic/state
    cacheDir: /var/lib/greentic/cache
    logDir: /var/log/greentic
    tempDir: /var/lib/greentic/tmp
  service:
    manager: systemd
    user: greentic
    group: greentic
  health:
    readinessPath: /ready
    livenessPath: /health
    startupTimeoutSeconds: 120
  rollout:
    strategy: recreate
"#,
        )
        .expect("parse spec");
        spec.spec.runtime.arch = LinuxArch::Aarch64;

        let err = spec.validate().expect_err("arch must be rejected");
        assert!(err.to_string().contains("x86_64"));
    }
}
