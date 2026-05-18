//! `gtc op` command surface (`A3` of `plans/next-gen-deployment.md`).
//!
//! Library-level command implementations for the operator wizard. Each
//! submodule exposes one noun:
//!
//! - [`env`] — Environment CRUD (`create`, `update`, `list`, `show`, `doctor`, `destroy`)
//! - [`env_packs`] — Env-pack bindings (`add`, `update`, `remove`, `rollback`, `list`)
//! - [`bundles`] — Application bundle deployments (`add`, `update`, `remove`, `list`)
//! - [`revisions`] — Revision lifecycle (`stage`, `warm`, `drain`, `archive`, `list`)
//! - [`traffic`] — Traffic-split management (`set`, `show`, `rollback`)
//! - [`config`] — Host/setup/runtime config inspection (`show`, `set`)
//! - [`credentials`] — Credential modes (`requirements`, `bootstrap`, `rotate`)
//! - [`secrets`] — Secrets management (`list`, `put`, `get`, `rotate`)
//!
//! Every command pair honors:
//!
//! - `--schema` — dump the JSON schema of the input payload it would accept,
//!   then exit `0`. Useful for non-interactive callers wanting to generate an
//!   `--answers` payload programmatically.
//! - `--answers <path>` — read a JSON/YAML payload from disk for a
//!   non-interactive replay. Interactive prompting is out of scope for A3;
//!   wizard rendering lands in A10.
//!
//! Heavy logic that depends on env-pack handlers (deployer dispatch, secrets
//! backend, telemetry exporter, etc.) is deferred to later Phase A gates (A5,
//! A7, A9) and Phase C. A3 wires the command *surface* against the
//! `EnvironmentStore` from A2 and intentionally stubs paths that would
//! require those gates with a clear `not-yet-implemented` error.
//!
//! ## Output
//!
//! Every command writes structured JSON to a `Write` sink chosen by the
//! caller. Stable schema: `{ "op": "<verb>", "noun": "<noun>", "result": ... }`
//! for success; `{ "op": "<verb>", "noun": "<noun>", "error": { ... } }` for
//! failure. Human-readable rendering is layered on by the caller (operator
//! binary or `gtc op` passthrough); the library stays output-format-neutral.

use std::path::PathBuf;

pub mod env;
pub mod env_packs;
// Wired in subsequent A3 commits:
// pub mod bundles;
// pub mod revisions;
// pub mod traffic;
// pub mod config;
// pub mod credentials;
// pub mod secrets;

#[cfg(test)]
mod tests_common;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::environment::StoreError;
use greentic_deploy_spec::SpecError;

/// Top-level error shared across `op` command implementations.
#[derive(Debug, Error)]
pub enum OpError {
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    #[error("spec validation failed: {0}")]
    Spec(#[from] SpecError),
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid json/yaml in {path}: {message}")]
    AnswersParse { path: PathBuf, message: String },
    #[error("schema generation failed: {0}")]
    SchemaGeneration(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("not yet implemented in Phase A: {0}")]
    NotYetImplemented(&'static str),
    #[error("conflict: {0}")]
    Conflict(String),
}

impl OpError {
    /// Short machine code for the error envelope (`error.kind`).
    pub fn kind(&self) -> &'static str {
        match self {
            OpError::Store(_) => "store",
            OpError::Spec(_) => "spec",
            OpError::Io { .. } => "io",
            OpError::AnswersParse { .. } => "answers-parse",
            OpError::SchemaGeneration(_) => "schema-generation",
            OpError::InvalidArgument(_) => "invalid-argument",
            OpError::NotFound(_) => "not-found",
            OpError::NotYetImplemented(_) => "not-yet-implemented",
            OpError::Conflict(_) => "conflict",
        }
    }
}

/// Mode flags shared by every `op` subcommand.
#[derive(Debug, Clone, Default)]
pub struct OpFlags {
    /// When set, the command prints the JSON schema of its input payload and
    /// exits without touching the store.
    pub schema_only: bool,
    /// When set, the command reads its payload from this path (JSON or YAML)
    /// instead of prompting interactively.
    pub answers: Option<PathBuf>,
}

/// Standard success envelope.
#[derive(Debug, Clone, Serialize)]
pub struct OpOutcome {
    pub op: &'static str,
    pub noun: &'static str,
    pub result: Value,
}

impl OpOutcome {
    pub fn new(noun: &'static str, op: &'static str, result: Value) -> Self {
        Self { op, noun, result }
    }
}

/// Read an answers payload from disk as JSON or YAML. The path extension
/// disambiguates: `.json` → JSON, `.yaml`/`.yml` → YAML. Other extensions
/// fall back to JSON (with a YAML retry on parse failure) so callers can pipe
/// `gtc … --schema | jq … > answers.txt` without re-extensioning.
pub fn load_answers<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T, OpError> {
    let bytes = std::fs::read(path).map_err(|source| OpError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("yaml") | Some("yml") => {
            serde_yaml_bw::from_slice(&bytes).map_err(|e| OpError::AnswersParse {
                path: path.to_path_buf(),
                message: format!("yaml: {e}"),
            })
        }
        Some("json") => serde_json::from_slice(&bytes).map_err(|e| OpError::AnswersParse {
            path: path.to_path_buf(),
            message: format!("json: {e}"),
        }),
        _ => {
            // Heuristic: try JSON first, then YAML.
            serde_json::from_slice(&bytes).or_else(|json_err| {
                serde_yaml_bw::from_slice(&bytes).map_err(|yaml_err| OpError::AnswersParse {
                    path: path.to_path_buf(),
                    message: format!("json: {json_err}; yaml: {yaml_err}"),
                })
            })
        }
    }
}

/// Render an `OpError` into the standard JSON error envelope.
pub fn render_error(noun: &'static str, op: &'static str, err: &OpError) -> Value {
    serde_json::json!({
        "op": op,
        "noun": noun,
        "error": {
            "kind": err.kind(),
            "message": err.to_string(),
        }
    })
}
