use std::path::PathBuf;

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
}

pub type ExtensionResult<T> = Result<T, ExtensionError>;
