//! GCP Cloud Run deployer env-pack.
//!
//! Backs the optional `greentic.deployer.gcp-cloudrun@1.0.0` binding. Ships:
//!
//! - The [`EnvPackHandler`] surface — slot, descriptor path, supported
//!   versions, and the accessors returning the credentials + deployer impls.
//! - A [`DeployerCredentials`](crate::credentials::DeployerCredentials) impl
//!   ([`GcpDeployerCredentials`]) validating the ADC principal + a
//!   `projects.testIamPermissions` probe over the Cloud Run / Secret Manager /
//!   IAM permission surface (typed API, not `gcloud` shell-out).
//! - A bootstrap path ([`bootstrap`]) that emits a minimum-privilege deployer
//!   service account + custom IAM role Terraform module under `rules/<env>/`.
//! - A [`Deployer`](crate::env_packs::deployer::Deployer) impl ([`deployer`])
//!   driving the Cloud Run revision lifecycle (warm / archive / traffic-split)
//!   through the [`CloudRunTarget`](deploy_target::CloudRunTarget) seam. The
//!   real `google-cloud-*`-backed target and the ADC/WIF session resolver land
//!   in follow-up PRs behind the `deploy-gcp-cloudrun` feature; today the verbs
//!   run against the in-memory fake and a default
//!   [`UnconfiguredCloudRunTarget`](deploy_target::UnconfiguredCloudRunTarget)
//!   that fails honestly when no real client is wired.
//!
//! Behind the `creds-gcp` cargo feature (default-on). Disabling the feature
//! drops the handler from the registry; an env that binds
//! `greentic.deployer.gcp-cloudrun@<v>` then surfaces as `Unknown` through the
//! env-pack registry — the honest answer for a binary built without GCP
//! support.

pub mod bootstrap;
pub mod credentials;
pub mod deploy_target;
pub mod deployer;

use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;

use super::slot::EnvPackHandler;
use crate::tool_check::ToolCheck;

pub use credentials::{GcpDeployerCredentials, GcpValidatorClient};

/// Native handler for the GCP Cloud Run deployer env-pack.
#[derive(Debug)]
pub struct GcpCloudRunDeployerHandler {
    creds: GcpDeployerCredentials,
    /// Side-effect seam the [`Deployer`](crate::env_packs::deployer::Deployer)
    /// verbs drive. Crate-visible so `deployer.rs` reaches it. Defaults to
    /// [`UnconfiguredCloudRunTarget`](deploy_target::UnconfiguredCloudRunTarget)
    /// (fails verbs honestly); the real `google-cloud-*`-backed target is wired
    /// in a follow-up PR behind the `deploy-gcp-cloudrun` feature.
    pub(crate) target: std::sync::Arc<dyn deploy_target::CloudRunTarget>,
}

impl Default for GcpCloudRunDeployerHandler {
    fn default() -> Self {
        Self {
            creds: GcpDeployerCredentials::default(),
            target: std::sync::Arc::new(deploy_target::UnconfiguredCloudRunTarget),
        }
    }
}

impl GcpCloudRunDeployerHandler {
    /// Version-independent descriptor path used as the registry key.
    pub const DESCRIPTOR_PATH: &'static str = "greentic.deployer.gcp-cloudrun";

    /// Descriptor versions this handler implements. `>=1.0.0-dev` accepts both
    /// the eventual `1.0.0` GA release and the dev pre-releases shipping before
    /// GA.
    pub const VERSION_REQ: &'static str = ">=1.0.0-dev, <2.0.0";

    /// Construct with a pluggable GCP validator client. Tests pass a mock;
    /// production uses [`GcpDeployerCredentials::default`] which builds the real
    /// client once the `deploy-gcp-cloudrun` real target lands.
    pub fn with_client(client: std::sync::Arc<dyn GcpValidatorClient>) -> Self {
        Self {
            creds: GcpDeployerCredentials::with_client(client),
            target: std::sync::Arc::new(deploy_target::UnconfiguredCloudRunTarget),
        }
    }

    /// Construct with a pluggable deploy-target seam. Tests pass the in-memory
    /// fake; the orchestration wiring passes a connected `google-cloud-*`-backed
    /// target.
    pub fn with_target(target: std::sync::Arc<dyn deploy_target::CloudRunTarget>) -> Self {
        Self {
            creds: GcpDeployerCredentials::default(),
            target,
        }
    }
}

impl EnvPackHandler for GcpCloudRunDeployerHandler {
    fn slot(&self) -> CapabilitySlot {
        CapabilitySlot::Deployer
    }

    fn descriptor_path(&self) -> &str {
        Self::DESCRIPTOR_PATH
    }

    fn supported_versions(&self) -> VersionReq {
        Self::VERSION_REQ
            .parse()
            .expect("gcp-cloudrun version-req is valid (guarded by tests)")
    }

    fn preflight(&self) -> Vec<ToolCheck> {
        // Validation is via the typed GCP API (ADC + testIamPermissions) — no
        // shell-out to `gcloud`. Deploy is a typed SDK too, so no preflight
        // tool is mandatory.
        Vec::new()
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
    // No `as_manifest_renderer` override — Cloud Run is imperative (one command
    // → live URL), like AWS-ECS. `op env render` reports it as non-renderable.
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::PackDescriptor;

    #[test]
    fn handler_serves_deployer_slot_with_gcp_cloudrun_path() {
        let h = GcpCloudRunDeployerHandler::default();
        assert_eq!(h.slot(), CapabilitySlot::Deployer);
        assert_eq!(h.descriptor_path(), "greentic.deployer.gcp-cloudrun");
        let _ = h.supported_versions();
    }

    #[test]
    fn version_req_accepts_ga_and_dev_releases() {
        let h = GcpCloudRunDeployerHandler::default();
        let req = h.supported_versions();
        let ga = PackDescriptor::try_new("greentic.deployer.gcp-cloudrun@1.0.0").unwrap();
        assert!(req.matches(&ga.version().0), "{req} must accept 1.0.0");
        let dev = PackDescriptor::try_new("greentic.deployer.gcp-cloudrun@1.0.0-dev.1").unwrap();
        assert!(
            req.matches(&dev.version().0),
            "{req} must accept dev pre-release"
        );
        let next_major = PackDescriptor::try_new("greentic.deployer.gcp-cloudrun@2.0.0").unwrap();
        assert!(
            !req.matches(&next_major.version().0),
            "{req} must reject 2.0.0 (breaking bump)"
        );
    }

    #[test]
    fn exposes_credentials_contract_and_deployer_impl() {
        let h = GcpCloudRunDeployerHandler::default();
        let creds = h
            .deployer_credentials()
            .expect("gcp-cloudrun handler must expose credentials");
        assert!(creds.requires_credentials_material());
        assert!(
            (&h as &dyn EnvPackHandler).as_deployer().is_some(),
            "EnvPackHandler::as_deployer must surface the Cloud Run Deployer impl"
        );
        assert!(
            (&h as &dyn EnvPackHandler).as_manifest_renderer().is_none(),
            "Cloud Run is imperative; it must not expose a manifest renderer"
        );
    }

    /// Pins the wizard YAML to its canonical `id` and asserts the fields with no
    /// sensible default (`project`, `region`) plus the trust-boundary
    /// `access_mode` choice are present. Round-trip `qa_spec::FormSpec`
    /// deserialization is covered by the registry-level parametrized test.
    #[test]
    fn wizard_qaspec_yaml_pins_id_and_requires_project_region() {
        let yaml = GcpCloudRunDeployerHandler::default()
            .wizard_qaspec_yaml()
            .expect("gcp-cloudrun handler ships a wizard QASpec");
        let spec: qa_spec::FormSpec =
            serde_yaml_bw::from_str(yaml).expect("wizard.qaspec.yaml parses as FormSpec");
        assert_eq!(spec.id, "greentic.deployer.gcp-cloudrun.wizard");
        for required in ["project", "region", "access_mode"] {
            assert!(
                spec.questions.iter().any(|q| q.id == required),
                "gcp-cloudrun wizard must collect `{required}`",
            );
        }
    }
}
