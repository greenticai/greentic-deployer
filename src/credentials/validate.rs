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
    CredentialsValidationResult, EnvId, EnvironmentHostConfig, SchemaVersion, SecretRef,
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
/// borrowed for diagnostics only. `host_config` carries the env's
/// network bind address so port probes can target the configured
/// `listen_addr` rather than hardcoding `127.0.0.1`.
#[derive(Debug)]
pub struct ValidationContext<'a> {
    pub env_id: &'a EnvId,
    pub env_root: &'a Path,
    pub host_config: &'a EnvironmentHostConfig,
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
/// 3. Use `creds_override` when the caller supplies one, else read the
///    handler's [`super::DeployerCredentials`] (None ⇒ Phase D handler
///    that hasn't registered a credentials contract yet).
/// 4. Run the probes against `ValidationContext { env_root }`.
/// 5. Build a [`Credentials`] doc stamped with `last_run_at` + result.
///
/// `creds_override`, when `Some`, replaces the handler's own probe (step 3)
/// — the K8s `requirements` CLI path injects a live-cluster-connected
/// [`K8sValidatorClient`](crate::env_packs::k8s::K8sValidatorClient) this
/// way (the handler's default credentials hold no client and fail closed).
/// The handler is still resolved unconditionally so the A9 slot/version
/// check runs regardless of the override.
///
/// Returns both the doc and the report so the CLI can render the per-check
/// detail while the persisted doc carries only the structured summary.
pub fn validate_requirements(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &EnvId,
    creds_override: Option<&dyn super::DeployerCredentials>,
) -> Result<(Credentials, RequirementsReport), ValidateError> {
    let env = store.load(env_id)?;
    let deployer = env
        .pack_for_slot(CapabilitySlot::Deployer)
        .ok_or_else(|| ValidateError::NoDeployerBound(env_id.clone()))?;

    // Resolve the handler even when an override is supplied: this is where
    // the A9 slot/version match is enforced.
    let handler = registry.resolve_for_slot(CapabilitySlot::Deployer, &deployer.kind)?;
    let creds: &dyn super::DeployerCredentials =
        match creds_override {
            Some(c) => c,
            None => handler.deployer_credentials().ok_or_else(|| {
                ValidateError::HandlerNotRegistered {
                    kind: deployer.kind.as_str().to_string(),
                }
            })?,
        };

    // No-material deployers (e.g. local-process) can pass validation
    // without a credentials_ref. For deployers that require material,
    // the env must already have one (the user ran `op credentials
    // bootstrap` or supplied one out-of-band).
    let creds_ref = if creds.requires_credentials_material() {
        env.credentials_ref
            .clone()
            .ok_or_else(|| ValidateError::NoCredentialsRef(env_id.clone()))?
    } else {
        // Use the env's ref if present; otherwise a sentinel that
        // signals "no material required". The deploy-spec's
        // `provided_credentials_ref` field is required, so we use a
        // well-known sentinel rather than making it optional.
        env.credentials_ref.clone().unwrap_or_else(|| {
            SecretRef::try_new(format!(
                "secret://{}/local-process/no-material-required",
                env_id.as_str()
            ))
            .expect("sentinel SecretRef is well-formed")
        })
    };

    let env_root = store.env_dir(env_id)?;
    let ctx = ValidationContext {
        env_id,
        env_root: &env_root,
        host_config: &env.host_config,
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

    /// A sentinel credentials probe used to prove the runner honors
    /// `creds_override` instead of the handler's own probe.
    #[derive(Debug)]
    struct FakeCreds;
    impl crate::credentials::DeployerCredentials for FakeCreds {
        fn requires_credentials_material(&self) -> bool {
            false
        }
        fn required_capabilities(&self) -> Vec<Capability> {
            vec![cap("fake.only")]
        }
        fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
            RequirementsReport::new(vec![CapabilityCheck {
                capability: cap("fake.only"),
                status: CapabilityStatus::Pass,
            }])
        }
        fn bootstrap(
            &self,
            _input: &crate::credentials::BootstrapInput<'_>,
        ) -> Result<crate::credentials::BootstrapOutcome, crate::credentials::BootstrapError>
        {
            unreachable!("the override test never bootstraps")
        }
    }

    /// When the caller supplies `creds_override`, the runner validates with
    /// it and ignores the handler's own probe — the seam the K8s
    /// `requirements` CLI uses to inject a live-cluster validator.
    #[test]
    fn validate_requirements_honors_creds_override() {
        use crate::cli::tests_common::{make_binding, make_env};
        use crate::environment::EnvironmentStore;
        use greentic_deploy_spec::CapabilitySlot;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            // A registered deployer so the A9 resolve still succeeds; its
            // own probe declares 2 caps, distinct from the fake's 1.
            "greentic.deployer.local-process@0.1.0",
        ));
        store.save(&env).unwrap();

        let registry = EnvPackRegistry::with_builtins();
        let fake = FakeCreds;
        let (_doc, report) = validate_requirements(
            &store,
            &registry,
            &EnvId::try_from("local").unwrap(),
            Some(&fake),
        )
        .expect("override path validates");

        assert_eq!(report.checks.len(), 1, "override report, not handler's");
        assert_eq!(report.checks[0].capability.id, "fake.only");
    }
}
