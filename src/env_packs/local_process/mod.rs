//! Local-process deployer env-pack (C2 reference impl).
//!
//! Backs the default `local` env's `Deployer` slot binding
//! (`greentic.deployer.local-process@0.1.0` per [`crate::defaults`]).
//! Unlike the metadata-only [`BuiltinHandler`](super::slot::BuiltinHandler)
//! that previously stood in here, this handler ships a
//! [`DeployerCredentials`](crate::credentials::DeployerCredentials) impl
//! so `gtc op credentials requirements local` returns real probe results
//! today (C1 + C2 together).
//!
//! Reference shape for downstream deployers (Phase D AWS / K8s / GCP /
//! Azure). The structure is:
//!
//! - `mod.rs` (this file) wires the [`EnvPackHandler`] surface — slot,
//!   descriptor path, supported versions, and the accessor returning the
//!   credentials handler.
//! - [`credentials`] holds the [`DeployerCredentials`] impl
//!   ([`LocalProcessCredentials`]) with the per-capability probes.

pub mod credentials;

use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;

use super::slot::EnvPackHandler;
use crate::tool_check::ToolCheck;

pub use credentials::LocalProcessCredentials;

/// Native handler for the local-process deployer env-pack.
#[derive(Debug, Default)]
pub struct LocalProcessDeployerHandler {
    creds: LocalProcessCredentials,
}

impl LocalProcessDeployerHandler {
    /// Version-independent descriptor path used as the registry key.
    /// Must stay in lock-step with [`crate::defaults::LOCAL_DEPLOYER_PACK`]'s
    /// path component (the part before `@`).
    pub const DESCRIPTOR_PATH: &'static str = "greentic.deployer.local-process";

    /// Descriptor versions this handler implements. Same `^0.1.0`
    /// requirement the metadata-only `BuiltinHandler` previously declared,
    /// so the existing `local` env's `greentic.deployer.local-process@0.1.0`
    /// binding continues to resolve.
    pub const VERSION_REQ: &'static str = "^0.1.0";

    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an overridden port range for the
    /// `local-process.port.available` capability probe. Lets tests
    /// exercise the probe with a known-free or known-busy range without
    /// gambling on the default `8080..=8090`.
    pub fn with_port_range(range: std::ops::RangeInclusive<u16>) -> Self {
        Self {
            creds: LocalProcessCredentials::with_port_range(range),
        }
    }
}

impl EnvPackHandler for LocalProcessDeployerHandler {
    fn slot(&self) -> CapabilitySlot {
        CapabilitySlot::Deployer
    }

    fn descriptor_path(&self) -> &str {
        Self::DESCRIPTOR_PATH
    }

    fn supported_versions(&self) -> VersionReq {
        Self::VERSION_REQ
            .parse()
            .expect("local-process version-req is valid (guarded by tests)")
    }

    fn preflight(&self) -> Vec<ToolCheck> {
        // No external tools — local-process spawns child processes
        // directly and does not shell out to a provider CLI. Matches the
        // honest answer the prior `BuiltinHandler` returned (default).
        Vec::new()
    }

    fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
        Some(&self.creds)
    }

    fn wizard_qaspec_yaml(&self) -> Option<&'static str> {
        Some(include_str!("wizard.qaspec.yaml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::LOCAL_DEPLOYER_PACK;
    use greentic_deploy_spec::PackDescriptor;

    #[test]
    fn handler_serves_deployer_slot_with_local_process_path() {
        let h = LocalProcessDeployerHandler::default();
        assert_eq!(h.slot(), CapabilitySlot::Deployer);
        assert_eq!(h.descriptor_path(), "greentic.deployer.local-process");
        // Version req is valid.
        let _ = h.supported_versions();
    }

    #[test]
    fn version_req_accepts_default_local_binding_descriptor() {
        let h = LocalProcessDeployerHandler::default();
        let pd = PackDescriptor::try_new(LOCAL_DEPLOYER_PACK).expect("descriptor parses");
        assert!(
            h.supported_versions().matches(&pd.version().0),
            "version req {} must accept the default {} binding's version",
            h.supported_versions(),
            LOCAL_DEPLOYER_PACK
        );
    }

    #[test]
    fn exposes_credentials_contract() {
        let h = LocalProcessDeployerHandler::default();
        let creds = h
            .deployer_credentials()
            .expect("local-process handler must expose credentials");
        // Sanity: contract returns the two C2 capabilities.
        let caps = creds.required_capabilities();
        assert_eq!(caps.len(), 2);
    }

    /// C6: the shipped `wizard.qaspec.yaml` deserializes into a
    /// `qa_spec::FormSpec`. Guards against a typo / drift between the
    /// YAML and the qa-spec schema landing at build time instead of at
    /// the operator's wizard-driver call site.
    #[test]
    fn wizard_qaspec_yaml_deserializes_into_form_spec() {
        let yaml = LocalProcessDeployerHandler::default()
            .wizard_qaspec_yaml()
            .expect("local-process handler ships a wizard QASpec");
        let spec: qa_spec::FormSpec =
            serde_yaml_bw::from_str(yaml).expect("wizard.qaspec.yaml parses as FormSpec");
        assert_eq!(spec.id, "greentic.deployer.local-process.wizard");
        assert!(
            !spec.questions.is_empty(),
            "wizard QASpec must declare at least one question to drive the operator's wizard",
        );
    }
}
