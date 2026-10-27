//! Azure Container Apps deployer env-pack (`greentic.deployer.azure-aca@1.0.0`).
//!
//! Layering mirrors the AWS pack: pure modules (answers, naming, sizing, seed,
//! revision intent, boot env, ARM bodies), an [`deploy_target::AcaDeployTarget`]
//! seam with an in-memory fake, the `Deployer` verbs over that seam, a credentials
//! validator and an RBAC bootstrap. The live ARM REST client sits behind
//! `deploy-azure-aca`. Nothing here was exercised against Azure; see
//! `docs/azure-aca-seed-and-bundle-delivery.md`.

pub(crate) mod arm_body;
pub(crate) mod arm_http;
pub(crate) mod arm_paths;
pub(crate) mod arm_types;
pub(crate) mod boot_env;
pub(crate) mod bootstrap;
#[cfg(feature = "deploy-azure-aca")]
pub(crate) mod bound_session;
pub mod credentials;
pub(crate) mod deploy_target;
pub mod deployer;
pub(crate) mod deployer_warm;
#[cfg(test)]
pub(crate) mod fake;
pub(crate) mod lro;
pub(crate) mod naming;
pub mod params;
pub mod rbac;
#[cfg(feature = "deploy-azure-aca")]
pub(crate) mod real_target;
#[cfg(feature = "deploy-azure-aca")]
pub(crate) mod real_validator;
pub(crate) mod registry_credential;
#[cfg(feature = "deploy-azure-aca")]
pub(crate) mod reqwest_http;
pub(crate) mod revision_intent;
pub(crate) mod seed;
pub(crate) mod sizing;
pub(crate) mod status;
pub(crate) mod teardown;
pub(crate) mod token;

pub use credentials::{AzureAcaDeployerCredentials, AzureValidatorClient};
pub use params::{AcaParams, AcaParamsError};

use std::sync::Arc;

use greentic_deploy_spec::CapabilitySlot;
use semver::{Comparator, Op, Prerelease, VersionReq};

use self::deploy_target::{AcaDeployTarget, UnconfiguredAcaTarget};
use super::slot::EnvPackHandler;

/// Raw dev-store bytes. `Debug` redacts the content.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DevSecrets(Vec<u8>);

impl DevSecrets {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for DevSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

/// Native handler for the Azure Container Apps deployer env-pack.
#[derive(Debug)]
pub struct AzureAcaDeployerHandler {
    creds: AzureAcaDeployerCredentials,
    pub(crate) target: Arc<dyn AcaDeployTarget>,
    pub(crate) dev_secrets: Option<DevSecrets>,
}

impl Default for AzureAcaDeployerHandler {
    fn default() -> Self {
        Self {
            creds: AzureAcaDeployerCredentials::default(),
            target: Arc::new(UnconfiguredAcaTarget),
            dev_secrets: None,
        }
    }
}

impl AzureAcaDeployerHandler {
    /// Version-independent descriptor path used as the registry key.
    pub const DESCRIPTOR_PATH: &'static str = "greentic.deployer.azure-aca";
    /// Documented version requirement (`>=1.0.0-dev, <2.0.0`).
    pub const VERSION_REQ: &'static str = ">=1.0.0-dev, <2.0.0";

    pub(crate) fn with_target_and_dev_secrets(
        target: Arc<dyn AcaDeployTarget>,
        dev_secrets: Option<Vec<u8>>,
    ) -> Self {
        Self {
            creds: AzureAcaDeployerCredentials::default(),
            target,
            dev_secrets: dev_secrets.map(DevSecrets),
        }
    }
}

fn comparator(op: Op, major: u64, pre: Prerelease) -> Comparator {
    Comparator {
        op,
        major,
        minor: Some(0),
        patch: Some(0),
        pre,
    }
}

impl EnvPackHandler for AzureAcaDeployerHandler {
    fn slot(&self) -> CapabilitySlot {
        CapabilitySlot::Deployer
    }

    fn descriptor_path(&self) -> &str {
        Self::DESCRIPTOR_PATH
    }

    fn supported_versions(&self) -> VersionReq {
        // Built from parts so no parse can fail at run time. If the `dev`
        // pre-release identifier were ever invalid the floor falls back to the
        // stricter plain `1.0.0` (rejecting dev builds, never admitting extras).
        let floor_pre = Prerelease::new("dev").unwrap_or(Prerelease::EMPTY);
        VersionReq {
            comparators: vec![
                comparator(Op::GreaterEq, 1, floor_pre),
                comparator(Op::Less, 2, Prerelease::EMPTY),
            ],
        }
    }

    fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
        Some(&self.creds)
    }

    fn wizard_qaspec_yaml(&self) -> Option<&'static str> {
        Some(include_str!("wizard.qaspec.yaml"))
    }

    fn as_deployer(&self) -> Option<&dyn crate::env_packs::deployer::Deployer> {
        Some(self)
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
