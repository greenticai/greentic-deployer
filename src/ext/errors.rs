use std::path::PathBuf;

use crate::extension::BuiltinBackendId;

#[derive(thiserror::Error, Debug)]
pub enum ExtensionError {
    #[error("extension directory not found: {0}")]
    DirNotFound(PathBuf),

    #[error("invalid describe.json at {path}: {source}")]
    DescribeParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("extension '{id}' signature verification failed")]
    SignatureInvalid { id: String },

    #[error("target '{target_id}' provided by both '{a}' and '{b}'")]
    TargetConflict {
        target_id: String,
        a: String,
        b: String,
    },

    #[error("target '{0}' not registered (try: `greentic-deployer ext list`)")]
    TargetNotFound(String),

    #[error("builtin backend '{backend}' unknown for target '{target_id}'")]
    UnknownBuiltinBackend { backend: String, target_id: String },

    #[error("builtin backend '{backend}' does not support handler '{handler:?}'")]
    UnsupportedHandler {
        backend: String,
        handler: Option<String>,
    },

    #[error("credential validation failed with {n} error(s)")]
    ValidationFailed {
        n: usize,
        diagnostics: Vec<crate::ext::diagnostic::Diagnostic>,
    },

    #[error("WASM invocation failed: {0}")]
    WasmRuntime(#[from] anyhow::Error),

    #[error("Mode B (full WASM execution) not yet implemented — see spec §8 Phase B")]
    ModeBNotImplemented,

    #[error("failed to read creds file '{path}': {source}")]
    CredsReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read config file '{path}': {source}")]
    ConfigReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws, Gcp, Azure)"
    )]
    AdapterNotImplemented { backend: BuiltinBackendId },

    #[error("backend '{backend:?}' execution failed: {source}")]
    BackendExecutionFailed {
        backend: BuiltinBackendId,
        #[source]
        source: anyhow::Error,
    },
}

pub type ExtensionResult<T> = Result<T, ExtensionError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension::BuiltinBackendId;
    use std::io::ErrorKind;

    #[test]
    fn creds_read_error_displays_path() {
        let err = ExtensionError::CredsReadError {
            path: PathBuf::from("/nope/creds.json"),
            source: std::io::Error::new(ErrorKind::NotFound, "not found"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/nope/creds.json"), "got: {msg}");
        assert!(msg.contains("creds"), "got: {msg}");
    }

    #[test]
    fn config_read_error_displays_path() {
        let err = ExtensionError::ConfigReadError {
            path: PathBuf::from("/nope/config.json"),
            source: std::io::Error::new(ErrorKind::PermissionDenied, "denied"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/nope/config.json"), "got: {msg}");
        assert!(msg.contains("config"), "got: {msg}");
    }

    #[test]
    fn adapter_not_implemented_displays_backend() {
        let err = ExtensionError::AdapterNotImplemented {
            backend: BuiltinBackendId::Terraform,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Terraform"), "got: {msg}");
        assert!(msg.contains("Desktop"), "got: {msg}");
        assert!(msg.contains("SingleVm"), "got: {msg}");
        assert!(msg.contains("Aws"), "got: {msg}");
        assert!(msg.contains("Gcp"), "got: {msg}");
        assert!(msg.contains("Azure"), "got: {msg}");
    }

    #[test]
    fn backend_execution_failed_displays_source() {
        let err = ExtensionError::BackendExecutionFailed {
            backend: BuiltinBackendId::Desktop,
            source: anyhow::anyhow!("docker-compose: exit 1"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Desktop"), "got: {msg}");
    }
}
