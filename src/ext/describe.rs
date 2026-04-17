use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::ext::errors::{ExtensionError, ExtensionResult};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployExtensionDescribe {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    #[serde(default)]
    pub engine: Engine,
    #[serde(default)]
    pub capabilities: Capabilities,
    pub runtime: RuntimeSpec,
    pub contributions: DeployContributions,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Engine {
    #[serde(default)]
    pub ext_runtime: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct Capabilities {
    #[serde(default)]
    pub offered: Vec<serde_json::Value>,
    #[serde(default)]
    pub required: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSpec {
    pub component: String,
    #[serde(default)]
    pub memory_limit_mb: Option<u32>,
    #[serde(default)]
    pub permissions: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeployContributions {
    pub targets: Vec<DeployTargetContribution>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployTargetContribution {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon_path: Option<PathBuf>,
    #[serde(default)]
    pub supports_rollback: bool,
    pub execution: Execution,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Execution {
    Builtin {
        backend: String,
        #[serde(default)]
        handler: Option<String>,
    },
    Wasm,
}

pub fn parse_describe(path: &Path) -> ExtensionResult<DeployExtensionDescribe> {
    let contents = std::fs::read_to_string(path).map_err(|e| ExtensionError::DescribeParse {
        path: path.to_path_buf(),
        source: serde::de::Error::custom(format!("io: {e}")),
    })?;
    serde_json::from_str(&contents).map_err(|source| ExtensionError::DescribeParse {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_json(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    const VALID_BUILTIN: &str = r#"{
        "apiVersion": "greentic.ai/v1",
        "kind": "DeployExtension",
        "metadata": { "id": "greentic.deploy-desktop", "version": "0.1.0" },
        "runtime": { "component": "extension.wasm", "memoryLimitMB": 64, "permissions": {} },
        "contributions": {
            "targets": [{
                "id": "docker-compose-local",
                "displayName": "Local Docker Compose",
                "supportsRollback": true,
                "execution": { "kind": "builtin", "backend": "desktop", "handler": "docker-compose" }
            }]
        }
    }"#;

    const VALID_WASM: &str = r#"{
        "apiVersion": "greentic.ai/v1",
        "kind": "DeployExtension",
        "metadata": { "id": "greentic.deploy-cisco", "version": "0.1.0" },
        "runtime": { "component": "extension.wasm", "memoryLimitMB": 128, "permissions": {} },
        "contributions": {
            "targets": [{
                "id": "cisco-box",
                "displayName": "Cisco Box",
                "execution": { "kind": "wasm" }
            }]
        }
    }"#;

    const MALFORMED: &str = r#"{ "apiVersion": "greentic.ai/v1", "kind": "DeployExtension" }"#;

    const UNKNOWN_EXECUTION_KIND: &str = r#"{
        "apiVersion": "greentic.ai/v1",
        "kind": "DeployExtension",
        "metadata": { "id": "greentic.bad", "version": "0.1.0" },
        "runtime": { "component": "extension.wasm" },
        "contributions": { "targets": [{
            "id": "x", "displayName": "X",
            "execution": { "kind": "docker" }
        }]}
    }"#;

    #[test]
    fn parses_builtin_execution() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", VALID_BUILTIN);
        let d = parse_describe(&p).expect("parse");
        assert_eq!(d.metadata.id, "greentic.deploy-desktop");
        assert_eq!(d.contributions.targets.len(), 1);
        let t = &d.contributions.targets[0];
        assert_eq!(t.id, "docker-compose-local");
        assert!(t.supports_rollback);
        match &t.execution {
            Execution::Builtin { backend, handler } => {
                assert_eq!(backend, "desktop");
                assert_eq!(handler.as_deref(), Some("docker-compose"));
            }
            _ => panic!("expected Builtin"),
        }
    }

    #[test]
    fn parses_wasm_execution() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", VALID_WASM);
        let d = parse_describe(&p).expect("parse");
        assert!(matches!(
            d.contributions.targets[0].execution,
            Execution::Wasm
        ));
    }

    #[test]
    fn rejects_malformed_missing_contributions() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", MALFORMED);
        let err = parse_describe(&p).unwrap_err();
        assert!(matches!(err, ExtensionError::DescribeParse { .. }));
    }

    #[test]
    fn rejects_unknown_execution_kind() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", UNKNOWN_EXECUTION_KIND);
        let err = parse_describe(&p).unwrap_err();
        assert!(matches!(err, ExtensionError::DescribeParse { .. }));
    }
}
