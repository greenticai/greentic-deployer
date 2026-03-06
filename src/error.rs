use std::io;

use serde_json;
use thiserror::Error;

use greentic_distributor_client::error::DistributorError;

#[derive(Debug, Error)]
pub enum DeployerError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("pack parsing error: {0}")]
    Pack(String),

    #[error("deployer contract error: {0}")]
    Contract(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("manifest decode error: {0}")]
    ManifestDecode(#[from] greentic_types::cbor::CborError),

    #[error("distributor error: {0}")]
    Distributor(#[from] DistributorError),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("telemetry initialization error: {0}")]
    Telemetry(String),

    #[error("secret backend error: {0}")]
    Secret(String),

    #[error(
        "missing secrets for pack {pack_id} {pack_version}: {missing:?}. Remediate via: {hint}"
    )]
    MissingSecrets {
        pack_id: String,
        pack_version: String,
        missing: Vec<String>,
        hint: String,
    },

    #[error("offline mode incompatible with requested operation: {0}")]
    OfflineDisallowed(String),

    #[error(
        "deployment packs not wired yet for capability={capability}, provider={provider}, strategy={strategy}"
    )]
    DeploymentPackUnsupported {
        capability: String,
        provider: String,
        strategy: String,
    },

    #[error("unexpected error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DeployerError>;
