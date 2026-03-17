use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{DeployerError, Result};

pub const DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1: &str = "greentic.ai/v1alpha1";
pub const DEPLOYMENT_SPEC_KIND: &str = "Deployment";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
            _ => Self::from_yaml_str(&contents).or_else(|yaml_err| {
                Self::from_json_str(&contents).map_err(|json_err| {
                    DeployerError::Config(format!(
                        "failed to parse deployment spec {} as YAML ({yaml_err}) or JSON ({json_err})",
                        path.display()
                    ))
                })
            }),
        }
    }

    pub fn validate(&self) -> Result<()> {
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

        let bind = self.spec.runtime.admin.bind.trim();
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentMetadata {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
pub struct AdminEndpointSpec {
    pub bind: String,
    pub mtls: MtlsSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MtlsSpec {
    #[serde(rename = "caFile")]
    pub ca_file: PathBuf,
    #[serde(rename = "certFile")]
    pub cert_file: PathBuf,
    #[serde(rename = "keyFile")]
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
pub struct HealthSpec {
    #[serde(rename = "readinessPath")]
    pub readiness_path: String,
    #[serde(rename = "livenessPath")]
    pub liveness_path: String,
    #[serde(rename = "startupTimeoutSeconds")]
    pub startup_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
