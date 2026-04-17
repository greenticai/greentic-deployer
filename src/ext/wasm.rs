use std::path::Path;

use crate::ext::errors::{ExtensionError, ExtensionResult};

// Re-export so existing call sites using `crate::ext::wasm::Diagnostic` keep working.
pub use crate::ext::diagnostic::{Diagnostic, DiagnosticSeverity};

/// The deploy-specific slice of extension surface that the dispatcher calls into.
/// `deploy`/`poll`/`rollback` are intentionally NOT on this trait in Phase A —
/// Mode A routes them to the built-in bridge; Mode B returns `ModeBNotImplemented`.
pub trait WasmInvoker: Send + Sync {
    fn list_targets(&self, ext_id: &str) -> ExtensionResult<String>;
    fn credential_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String>;
    fn config_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String>;
    fn validate_credentials(
        &self,
        ext_id: &str,
        target_id: &str,
        creds_json: &str,
    ) -> ExtensionResult<Vec<Diagnostic>>;
}

/// Production invoker: wraps `greentic_ext_runtime::ExtensionRuntime`.
///
/// Adaptation notes vs. the spec:
/// - `RuntimeConfig::default()` does not exist in the actual crate; we use
///   `RuntimeConfig::from_paths(DiscoveryPaths::new(dummy_path))` with a
///   placeholder path because ext dirs are registered via `register_loaded_from_dir`.
/// - `register_loaded_from_dir` takes `&mut self`, so registration must happen
///   before the runtime is wrapped in `Arc`. The `Arc` is only created after
///   all dirs are registered.
/// - `invoke_tool` returns `Result<String, RuntimeError>` (not `anyhow::Error`);
///   we map via `anyhow::anyhow!()` since `RuntimeError: std::fmt::Display`.
#[cfg(feature = "extensions")]
pub struct WasmtimeInvoker {
    runtime: std::sync::Arc<greentic_ext_runtime::ExtensionRuntime>,
}

#[cfg(feature = "extensions")]
impl WasmtimeInvoker {
    pub fn new(ext_dirs: &[&Path]) -> ExtensionResult<Self> {
        // RuntimeConfig requires a DiscoveryPaths; use the first ext_dir as the
        // user path if available, otherwise a temporary placeholder. The dirs are
        // also registered explicitly via register_loaded_from_dir below.
        let user_path = ext_dirs
            .first()
            .copied()
            .unwrap_or_else(|| Path::new("/tmp"))
            .to_path_buf();
        let paths = greentic_ext_runtime::DiscoveryPaths::new(user_path);
        let config = greentic_ext_runtime::RuntimeConfig::from_paths(paths);
        let mut runtime = greentic_ext_runtime::ExtensionRuntime::new(config)
            .map_err(|e| ExtensionError::WasmRuntime(anyhow::anyhow!("{e}")))?;
        for d in ext_dirs {
            runtime
                .register_loaded_from_dir(d)
                .map_err(|e| ExtensionError::WasmRuntime(anyhow::anyhow!("{e}")))?;
        }
        Ok(Self {
            runtime: std::sync::Arc::new(runtime),
        })
    }
}

#[cfg(feature = "extensions")]
impl WasmInvoker for WasmtimeInvoker {
    fn list_targets(&self, ext_id: &str) -> ExtensionResult<String> {
        self.runtime
            .invoke_tool(ext_id, "list-targets", "{}")
            .map_err(|e| ExtensionError::WasmRuntime(anyhow::anyhow!("{e}")))
    }

    fn credential_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        let args = serde_json::json!({ "targetId": target_id }).to_string();
        self.runtime
            .invoke_tool(ext_id, "credential-schema", &args)
            .map_err(|e| ExtensionError::WasmRuntime(anyhow::anyhow!("{e}")))
    }

    fn config_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        let args = serde_json::json!({ "targetId": target_id }).to_string();
        self.runtime
            .invoke_tool(ext_id, "config-schema", &args)
            .map_err(|e| ExtensionError::WasmRuntime(anyhow::anyhow!("{e}")))
    }

    fn validate_credentials(
        &self,
        ext_id: &str,
        target_id: &str,
        creds_json: &str,
    ) -> ExtensionResult<Vec<Diagnostic>> {
        let args = serde_json::json!({
            "targetId": target_id,
            "credsJson": creds_json,
        })
        .to_string();
        let out = self
            .runtime
            .invoke_tool(ext_id, "validate-credentials", &args)
            .map_err(|e| ExtensionError::WasmRuntime(anyhow::anyhow!("{e}")))?;
        let diags: Vec<Diagnostic> = serde_json::from_str(&out).map_err(|e| {
            ExtensionError::WasmRuntime(anyhow::anyhow!(
                "parse diagnostics from wasm extension '{ext_id}' for target '{target_id}': {e}"
            ))
        })?;
        Ok(diags)
    }
}

/// Mock invoker for tests (in-binary tests and integration tests).
#[cfg(any(test, feature = "test-utils"))]
#[derive(Default)]
pub struct MockInvoker {
    pub schemas_creds: std::collections::HashMap<(String, String), String>,
    pub schemas_config: std::collections::HashMap<(String, String), String>,
    pub validate_diagnostics: std::collections::HashMap<(String, String), Vec<Diagnostic>>,
    pub list_targets_response: std::collections::HashMap<String, String>,
}

#[cfg(any(test, feature = "test-utils"))]
impl WasmInvoker for MockInvoker {
    fn list_targets(&self, ext_id: &str) -> ExtensionResult<String> {
        Ok(self
            .list_targets_response
            .get(ext_id)
            .cloned()
            .unwrap_or("[]".into()))
    }

    fn credential_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        Ok(self
            .schemas_creds
            .get(&(ext_id.to_string(), target_id.to_string()))
            .cloned()
            .unwrap_or("{}".into()))
    }

    fn config_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        Ok(self
            .schemas_config
            .get(&(ext_id.to_string(), target_id.to_string()))
            .cloned()
            .unwrap_or("{}".into()))
    }

    fn validate_credentials(
        &self,
        ext_id: &str,
        target_id: &str,
        _creds_json: &str,
    ) -> ExtensionResult<Vec<Diagnostic>> {
        Ok(self
            .validate_diagnostics
            .get(&(ext_id.to_string(), target_id.to_string()))
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_invoker_returns_defaults() {
        let m = MockInvoker::default();
        assert_eq!(m.list_targets("any").unwrap(), "[]");
        assert_eq!(m.credential_schema("e", "t").unwrap(), "{}");
        assert_eq!(m.config_schema("e", "t").unwrap(), "{}");
        assert!(m.validate_credentials("e", "t", "{}").unwrap().is_empty());
    }

    #[test]
    fn mock_invoker_returns_configured_values() {
        let mut m = MockInvoker::default();
        m.schemas_creds.insert(
            ("greentic.a".into(), "t1".into()),
            r#"{"type":"object"}"#.into(),
        );
        assert_eq!(
            m.credential_schema("greentic.a", "t1").unwrap(),
            r#"{"type":"object"}"#
        );
    }
}
