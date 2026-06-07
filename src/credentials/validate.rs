//! Requirements-flow driver for [`super::DeployerCredentials`].
//!
//! `validate_requirements` reads the env, resolves the bound deployer
//! handler through the registry, runs the handler's probes, and returns
//! both a [`Credentials`] doc (ready for the caller to persist) and the
//! [`RequirementsReport`] for the CLI envelope.
//!
//! The runner does NOT write the doc — that's the caller's choice (the
//! `rotate` verb persists; `requirements` returns the report and lets the
//! caller decide). This keeps the runner pure-ish (one store read, no
//! store write) and lets tests assert the probe output without observing a
//! filesystem mutation.

use std::path::Path;

use chrono::Utc;
use greentic_deploy_spec::{
    CapabilitySlot, Credentials, CredentialsMode, CredentialsValidation,
    CredentialsValidationResult, EnvId, SchemaVersion,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::env_packs::{EnvPackRegistry, RegistryError};
use crate::environment::{EnvironmentStore, LocalFsStore, StoreError};

/// A single capability the deployer's credentials must satisfy.
///
/// `id` is a stable, machine-readable identifier (e.g.
/// `local-process.fs.writable`); `description` is the operator-facing
/// label rendered in the CLI report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub description: String,
}

impl Capability {
    pub fn new(id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
        }
    }
}

/// Outcome for one capability probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Probe ran and the credentials satisfy this capability.
    Pass,
    /// Probe ran and the credentials do NOT satisfy this capability.
    Fail { reason: String },
    /// Probe could not run today (e.g. needs Phase D infrastructure that
    /// is not wired in Phase A). The capability is reported as missing in
    /// the persisted [`Credentials`] doc so an operator never sees a
    /// false-pass for unsupported probes.
    Skipped { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCheck {
    pub capability: Capability,
    #[serde(flatten)]
    pub status: CapabilityStatus,
}

/// Result of a full validate run — one entry per capability in the order
/// the handler declared them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementsReport {
    pub checks: Vec<CapabilityCheck>,
}

impl RequirementsReport {
    pub fn new(checks: Vec<CapabilityCheck>) -> Self {
        Self { checks }
    }

    /// True when no capability is in [`CapabilityStatus::Fail`]. `Skipped`
    /// entries do NOT block the overall pass (they record "we couldn't
    /// check"), but they do surface in [`missing`](Self::missing) so the
    /// persisted `Credentials` doc reflects that the check was incomplete.
    pub fn passed(&self) -> bool {
        self.checks
            .iter()
            .all(|c| !matches!(c.status, CapabilityStatus::Fail { .. }))
    }

    /// Capability IDs that did NOT pass (Fail OR Skipped). Fed into
    /// [`CredentialsValidation::missing_capabilities`] on the persisted
    /// doc.
    pub fn missing(&self) -> Vec<String> {
        self.checks
            .iter()
            .filter(|c| !matches!(c.status, CapabilityStatus::Pass))
            .map(|c| c.capability.id.clone())
            .collect()
    }
}

/// Per-call context passed to [`super::DeployerCredentials::validate`].
///
/// Probes use `env_root` to test filesystem permissions on the env's own
/// state dir without depending on `$HOME` being readable. `env_id` is
/// borrowed for diagnostics only.
#[derive(Debug)]
pub struct ValidationContext<'a> {
    pub env_id: &'a EnvId,
    pub env_root: &'a Path,
}

#[derive(Debug, Error)]
pub enum ValidateError {
    #[error("env `{0}` has no deployer slot bound; bind one with `op env-packs add` first")]
    NoDeployerBound(EnvId),
    #[error("env `{0}` has no credentials_ref; run `op credentials bootstrap` first or supply one")]
    NoCredentialsRef(EnvId),
    #[error(
        "deployer env-pack `{kind}` has no native credentials handler registered (Phase D plug-in)"
    )]
    HandlerNotRegistered { kind: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Drive a `requirements` flow against the env's bound deployer env-pack.
///
/// Steps:
/// 1. Load the env; require a deployer slot and a `credentials_ref`.
/// 2. Resolve the deployer's handler via the registry (also rejects slot
///    or version mismatches per A9).
/// 3. Read the handler's [`super::DeployerCredentials`] (None ⇒ Phase D
///    handler that hasn't registered a credentials contract yet).
/// 4. Run the handler's probes against `ValidationContext { env_root }`.
/// 5. Build a [`Credentials`] doc stamped with `last_run_at` + result.
///
/// Returns both the doc and the report so the CLI can render the per-check
/// detail while the persisted doc carries only the structured summary.
pub fn validate_requirements(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &EnvId,
) -> Result<(Credentials, RequirementsReport), ValidateError> {
    let env = store.load(env_id)?;
    let deployer = env
        .pack_for_slot(CapabilitySlot::Deployer)
        .ok_or_else(|| ValidateError::NoDeployerBound(env_id.clone()))?;
    let creds_ref = env
        .credentials_ref
        .clone()
        .ok_or_else(|| ValidateError::NoCredentialsRef(env_id.clone()))?;

    let handler = registry.resolve_for_slot(CapabilitySlot::Deployer, &deployer.kind)?;
    let creds =
        handler
            .deployer_credentials()
            .ok_or_else(|| ValidateError::HandlerNotRegistered {
                kind: deployer.kind.as_str().to_string(),
            })?;

    let env_root = store.env_dir(env_id)?;
    let ctx = ValidationContext {
        env_id,
        env_root: &env_root,
    };
    let report = creds.validate(&ctx);

    let result = if report.passed() {
        CredentialsValidationResult::Pass
    } else {
        CredentialsValidationResult::Fail
    };
    let doc = Credentials {
        schema: SchemaVersion::new(SchemaVersion::CREDENTIALS_V1),
        env_id: env_id.clone(),
        deployer_kind: deployer.kind.clone(),
        mode: CredentialsMode::Requirements,
        provided_credentials_ref: creds_ref,
        validation: CredentialsValidation {
            last_run_at: Utc::now(),
            result,
            missing_capabilities: report.missing(),
        },
        bootstrap: None,
        expiry: None,
    };
    Ok((doc, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(id: &str) -> Capability {
        Capability::new(id, format!("description for {id}"))
    }

    #[test]
    fn passed_true_when_no_failures() {
        let report = RequirementsReport::new(vec![
            CapabilityCheck {
                capability: cap("a"),
                status: CapabilityStatus::Pass,
            },
            CapabilityCheck {
                capability: cap("b"),
                status: CapabilityStatus::Skipped {
                    reason: "no backend".into(),
                },
            },
        ]);
        assert!(report.passed(), "Skipped does not block overall pass");
        assert_eq!(report.missing(), vec!["b".to_string()]);
    }

    #[test]
    fn passed_false_when_any_fail() {
        let report = RequirementsReport::new(vec![
            CapabilityCheck {
                capability: cap("a"),
                status: CapabilityStatus::Pass,
            },
            CapabilityCheck {
                capability: cap("b"),
                status: CapabilityStatus::Fail {
                    reason: "denied".into(),
                },
            },
        ]);
        assert!(!report.passed());
        assert_eq!(report.missing(), vec!["b".to_string()]);
    }

    #[test]
    fn empty_report_passes() {
        let report = RequirementsReport::new(vec![]);
        assert!(report.passed());
        assert!(report.missing().is_empty());
    }
}
