//! `greentic.credentials.v1` (`§5.5`).
//!
//! Admin credentials are never intentionally persisted; only
//! `admin_credential_consumed_at` records the fact that they were used.

use crate::capability_slot::PackDescriptor;
use crate::refs::SecretRef;
use crate::version::SchemaVersion;
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialsMode {
    Requirements,
    Bootstrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialsValidationResult {
    Pass,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialsValidation {
    pub last_run_at: DateTime<Utc>,
    pub result: CredentialsValidationResult,
    #[serde(default)]
    pub missing_capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialsBootstrap {
    pub admin_credential_consumed_at: DateTime<Utc>,
    /// Env-relative path to the generated rules pack.
    pub rules_pack_ref: PathBuf,
    pub generated_credentials_ref: SecretRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialsExpiry {
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub schema: SchemaVersion,
    pub env_id: EnvId,
    pub deployer_kind: PackDescriptor,
    pub mode: CredentialsMode,
    pub provided_credentials_ref: SecretRef,
    pub validation: CredentialsValidation,
    /// Populated only when `mode = bootstrap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<CredentialsBootstrap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<CredentialsExpiry>,
}

impl Credentials {
    pub fn schema_str() -> &'static str {
        SchemaVersion::CREDENTIALS_V1
    }
}
