//! `greentic.credentials.v1` (`§5.5`).
//!
//! Admin credentials are never intentionally persisted; only
//! `admin_credential_consumed_at` records the fact that they were used.

use crate::capability_slot::PackDescriptor;
use crate::error::SpecError;
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

    /// Validate the credentials document against its own invariants:
    /// schema discriminator equals `greentic.credentials.v1`, and every
    /// embedded [`SecretRef`] is scoped to `self.env_id`. Without the
    /// scope check a Credentials document for env A could carry pointers
    /// into env B's secrets backend, bypassing tenant isolation.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema.as_str() != SchemaVersion::CREDENTIALS_V1 {
            return Err(SpecError::SchemaMismatch {
                expected: SchemaVersion::CREDENTIALS_V1,
                actual: self.schema.as_str().to_string(),
            });
        }
        check_secret_ref_env(
            "credentials.provided_credentials_ref",
            &self.provided_credentials_ref,
            &self.env_id,
        )?;
        if let Some(bootstrap) = &self.bootstrap {
            check_secret_ref_env(
                "credentials.bootstrap.generated_credentials_ref",
                &bootstrap.generated_credentials_ref,
                &self.env_id,
            )?;
        }
        Ok(())
    }
}

fn check_secret_ref_env(
    context: &'static str,
    secret_ref: &SecretRef,
    expected_env: &EnvId,
) -> Result<(), SpecError> {
    let actual = secret_ref.env_segment();
    if actual != expected_env.as_str() {
        return Err(SpecError::CrossEnvRef {
            context,
            uri: secret_ref.as_str().to_string(),
            expected_env: expected_env.clone(),
            actual_env: actual.to_string(),
        });
    }
    Ok(())
}
