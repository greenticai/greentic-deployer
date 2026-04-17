use jsonschema::Validator;

use crate::ext::builtin_bridge::{self, BridgeResolved};
use crate::ext::describe::Execution;
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::ext::registry::ExtensionRegistry;
use crate::ext::wasm::{DiagnosticSeverity, WasmInvoker};

#[derive(Debug, Clone)]
pub enum DispatchAction {
    Builtin(BridgeResolved),
}

pub struct DispatchInput<'a> {
    pub target_id: &'a str,
    pub creds_json: &'a str,
    pub config_json: &'a str,
    pub strict_validate: bool,
}

pub fn dispatch_extension(
    registry: &ExtensionRegistry,
    invoker: &dyn WasmInvoker,
    input: DispatchInput<'_>,
) -> ExtensionResult<DispatchAction> {
    let resolved = registry.resolve(input.target_id)?;
    let ext_id = resolved.ext_id.clone();
    let execution = resolved.contribution.execution.clone();
    let target_id = input.target_id;

    let schema_creds = invoker.credential_schema(&ext_id, target_id)?;
    validate_against_schema(&schema_creds, input.creds_json, "credentials")?;

    let schema_config = invoker.config_schema(&ext_id, target_id)?;
    validate_against_schema(&schema_config, input.config_json, "config")?;

    let diagnostics = invoker.validate_credentials(&ext_id, target_id, input.creds_json)?;
    let fatal = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DiagnosticSeverity::Error))
        .count();
    let warn_count = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DiagnosticSeverity::Warning))
        .count();
    if fatal > 0 || (input.strict_validate && warn_count > 0) {
        return Err(ExtensionError::ValidationFailed {
            n: fatal + warn_count,
        });
    }

    match &execution {
        Execution::Builtin { .. } => {
            let bridge = builtin_bridge::resolve(&execution, target_id)?;
            Ok(DispatchAction::Builtin(bridge))
        }
        Execution::Wasm => Err(ExtensionError::ModeBNotImplemented),
    }
}

fn validate_against_schema(schema_str: &str, value_str: &str, label: &str) -> ExtensionResult<()> {
    let schema_val: serde_json::Value =
        serde_json::from_str(schema_str).map_err(|e| ExtensionError::DescribeParse {
            path: std::path::PathBuf::from(format!("<schema:{label}>")),
            source: e,
        })?;
    let value_val: serde_json::Value =
        serde_json::from_str(value_str).map_err(|e| ExtensionError::DescribeParse {
            path: std::path::PathBuf::from(format!("<value:{label}>")),
            source: e,
        })?;
    // jsonschema 0.45 uses `Validator::new` (no `JSONSchema::compile`).
    let compiled = Validator::new(&schema_val)
        .map_err(|e| ExtensionError::WasmRuntime(anyhow::anyhow!("invalid {label} schema: {e}")))?;
    // `iter_errors` returns an iterator of `ValidationError`; count to get n.
    let n = compiled.iter_errors(&value_val).count();
    if n > 0 {
        return Err(ExtensionError::ValidationFailed { n });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::describe::{
        Capabilities, DeployContributions, DeployExtensionDescribe, DeployTargetContribution,
        Engine, Metadata, RuntimeSpec,
    };
    use crate::ext::loader::LoadedExtension;
    use crate::ext::wasm::{Diagnostic, MockInvoker};
    use std::path::PathBuf;

    fn registry_with(ext_id: &str, target_id: &str, exec: Execution) -> ExtensionRegistry {
        ExtensionRegistry::build(vec![LoadedExtension {
            root_dir: PathBuf::from("/tmp/fake"),
            wasm_path: PathBuf::from("/tmp/fake/extension.wasm"),
            describe: DeployExtensionDescribe {
                api_version: "greentic.ai/v1".into(),
                kind: "DeployExtension".into(),
                metadata: Metadata {
                    id: ext_id.into(),
                    version: "0.1.0".into(),
                    summary: None,
                },
                engine: Engine::default(),
                capabilities: Capabilities::default(),
                runtime: RuntimeSpec {
                    component: "extension.wasm".into(),
                    memory_limit_mb: None,
                    permissions: serde_json::Value::Null,
                },
                contributions: DeployContributions {
                    targets: vec![DeployTargetContribution {
                        id: target_id.into(),
                        display_name: target_id.into(),
                        description: None,
                        icon_path: None,
                        supports_rollback: false,
                        execution: exec,
                    }],
                },
            },
        }])
    }

    #[test]
    fn dispatch_builtin_happy_path() {
        let reg = registry_with(
            "greentic.a",
            "docker-compose-local",
            Execution::Builtin {
                backend: "terraform".into(),
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.schemas_creds.insert(
            ("greentic.a".into(), "docker-compose-local".into()),
            r#"{"type":"object"}"#.into(),
        );
        invoker.schemas_config.insert(
            ("greentic.a".into(), "docker-compose-local".into()),
            r#"{"type":"object"}"#.into(),
        );
        let action = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "docker-compose-local",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap();
        match action {
            DispatchAction::Builtin(b) => {
                assert_eq!(b.backend, crate::extension::BuiltinBackendId::Terraform);
            }
        }
    }

    #[test]
    fn dispatch_wasm_execution_returns_mode_b_not_implemented() {
        let reg = registry_with("greentic.b", "t", Execution::Wasm);
        let invoker = MockInvoker::default();
        let err = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ExtensionError::ModeBNotImplemented));
    }

    #[test]
    fn dispatch_schema_violation_fails_validation() {
        let reg = registry_with(
            "greentic.a",
            "t",
            Execution::Builtin {
                backend: "terraform".into(),
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.schemas_creds.insert(
            ("greentic.a".into(), "t".into()),
            r#"{"type":"object","required":["api_key"]}"#.into(),
        );
        let err = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: r#"{}"#,
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ExtensionError::ValidationFailed { .. }));
    }

    #[test]
    fn dispatch_fatal_diagnostic_blocks() {
        let reg = registry_with(
            "greentic.a",
            "t",
            Execution::Builtin {
                backend: "terraform".into(),
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.validate_diagnostics.insert(
            ("greentic.a".into(), "t".into()),
            vec![Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "bad-creds".into(),
                message: "bad".into(),
                path: None,
            }],
        );
        let err = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ExtensionError::ValidationFailed { .. }));
    }

    #[test]
    fn dispatch_warning_passes_without_strict() {
        let reg = registry_with(
            "greentic.a",
            "t",
            Execution::Builtin {
                backend: "terraform".into(),
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.validate_diagnostics.insert(
            ("greentic.a".into(), "t".into()),
            vec![Diagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "soft".into(),
                message: "warn".into(),
                path: None,
            }],
        );
        let action = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap();
        assert!(matches!(action, DispatchAction::Builtin(_)));
    }
}
