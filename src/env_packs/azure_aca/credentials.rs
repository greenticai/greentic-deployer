//! Credential validation for the Azure Container Apps deployer.
//!
//! `validate` proves three things through the [`AzureValidatorClient`] seam: an
//! Entra token can be acquired and the managed environment is readable, and the
//! identity's effective permissions cover every action in
//! [`REQUIRED_ACTIONS`](super::rbac::REQUIRED_ACTIONS). Without a wired client the
//! default resolves one from the `AZURE_*` variables (only with
//! `deploy-azure-aca`); a build without it fails every capability honestly.
//!
//! Like the AWS and GCP validators, the default probes the AMBIENT variables, not
//! the binding's answers (the trait receives none).

use std::sync::Arc;

use async_trait::async_trait;

use super::bootstrap::{RulesInput, render_rules_pack};
use super::rbac::{Permission, REQUIRED_ACTIONS, action_allowed, is_broad};
use crate::credentials::{
    BootstrapError, BootstrapInput, BootstrapOutcome, Capability, CapabilityCheck,
    CapabilityStatus, DeployerCredentials, RequirementsReport, ValidationContext,
};

pub(crate) const TOKEN_CAP: &str = "azure-aca.token";
pub(crate) const ENVIRONMENT_CAP: &str = "azure-aca.environment.read";

/// Probe seam: the real one speaks ARM, tests script it.
#[async_trait]
pub trait AzureValidatorClient: std::fmt::Debug + Send + Sync {
    /// Acquire a token and read the managed environment.
    async fn check_environment(&self) -> Result<(), String>;
    /// Effective permissions at the resource-group scope.
    async fn effective_permissions(&self) -> Result<Vec<Permission>, String>;
}

#[derive(Debug, Default)]
pub struct AzureAcaDeployerCredentials {
    client: Option<Arc<dyn AzureValidatorClient>>,
}

impl AzureAcaDeployerCredentials {
    pub fn with_client(client: Arc<dyn AzureValidatorClient>) -> Self {
        Self {
            client: Some(client),
        }
    }

    fn action_cap(action: &str) -> Capability {
        Capability::new(
            format!("azure-aca.rbac.{action}"),
            format!("ARM action `{action}` is permitted"),
        )
    }

    fn caps() -> Vec<Capability> {
        let mut caps = vec![
            Capability::new(TOKEN_CAP, "Entra client-credentials token acquired for ARM"),
            Capability::new(ENVIRONMENT_CAP, "managed environment is readable"),
        ];
        caps.extend(REQUIRED_ACTIONS.iter().map(|a| Self::action_cap(a)));
        caps
    }

    fn all_failed(reason: &str) -> RequirementsReport {
        RequirementsReport::new(
            Self::caps()
                .into_iter()
                .map(|capability| CapabilityCheck {
                    capability,
                    status: CapabilityStatus::Fail {
                        reason: reason.to_string(),
                    },
                })
                .collect(),
        )
    }

    fn resolve_client(&self) -> Result<Arc<dyn AzureValidatorClient>, String> {
        if let Some(c) = &self.client {
            return Ok(Arc::clone(c));
        }
        default_client()
    }
}

#[cfg(feature = "deploy-azure-aca")]
fn default_client() -> Result<Arc<dyn AzureValidatorClient>, String> {
    super::real_validator::from_env().map(|c| Arc::new(c) as Arc<dyn AzureValidatorClient>)
}

#[cfg(not(feature = "deploy-azure-aca"))]
fn default_client() -> Result<Arc<dyn AzureValidatorClient>, String> {
    Err(
        "this build was compiled without the `deploy-azure-aca` feature; it cannot probe Azure"
            .to_string(),
    )
}

/// Sync -> async bridge on a scoped thread; a failed runtime build is an error,
/// never a panic.
pub(crate) fn run_async<F, T>(fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("cannot build an async runtime: {e}"))?;
                Ok(rt.block_on(fut))
            })
            .join()
            .map_err(|_| "the Azure probe thread panicked".to_string())?
    })
}

pub(crate) fn report_for(
    env_check: Result<(), String>,
    perms: Result<Vec<Permission>, String>,
) -> RequirementsReport {
    let mut checks = Vec::new();
    let token_env = match &env_check {
        Ok(()) => (CapabilityStatus::Pass, CapabilityStatus::Pass),
        Err(e) => (
            CapabilityStatus::Fail { reason: e.clone() },
            CapabilityStatus::Fail { reason: e.clone() },
        ),
    };
    checks.push(CapabilityCheck {
        capability: Capability::new(TOKEN_CAP, "Entra client-credentials token acquired for ARM"),
        status: token_env.0,
    });
    checks.push(CapabilityCheck {
        capability: Capability::new(ENVIRONMENT_CAP, "managed environment is readable"),
        status: token_env.1,
    });
    for action in REQUIRED_ACTIONS {
        let status = match &perms {
            Ok(p) if action_allowed(p, action) => CapabilityStatus::Pass,
            Ok(p) if p.is_empty() => CapabilityStatus::Fail {
                reason: format!("no permissions returned; `{action}` is not granted"),
            },
            Ok(_) => CapabilityStatus::Fail {
                reason: format!("`{action}` is not granted at the resource group"),
            },
            Err(e) => CapabilityStatus::Fail {
                reason: format!("could not read permissions: {e}"),
            },
        };
        checks.push(CapabilityCheck {
            capability: AzureAcaDeployerCredentials::action_cap(action),
            status,
        });
    }
    if let Ok(p) = &perms
        && is_broad(p)
    {
        tracing::warn!(
            "the Azure identity holds a blanket wildcard grant; the least-privilege role from \
             `op credentials bootstrap` is recommended"
        );
    }
    RequirementsReport::new(checks)
}

impl DeployerCredentials for AzureAcaDeployerCredentials {
    fn required_capabilities(&self) -> Vec<Capability> {
        Self::caps()
    }

    fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
        let client = match self.resolve_client() {
            Ok(c) => c,
            Err(reason) => return Self::all_failed(&reason),
        };
        let probed = run_async(async move {
            let env = client.check_environment().await;
            let perms = if env.is_ok() {
                client.effective_permissions().await
            } else {
                Err("skipped: environment unreachable".to_string())
            };
            (env, perms)
        });
        match probed {
            Ok((env, perms)) => report_for(env, perms),
            Err(reason) => Self::all_failed(&reason),
        }
    }

    fn bootstrap(&self, input: &BootstrapInput<'_>) -> Result<BootstrapOutcome, BootstrapError> {
        // Render-only: the Azure admin reviews and runs the script, then binds the
        // service principal with `op credentials rotate`.
        Ok(BootstrapOutcome {
            rules_pack: render_rules_pack(&RulesInput {
                env_id: input.env_id.as_str(),
            }),
            bound_credentials_ref: None,
            bound_expiry: None,
            bound_secret_material: None,
        })
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
