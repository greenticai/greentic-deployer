//! AWS-ECS deployer env-pack (C3 stub).
//!
//! Backs the optional `greentic.deployer.aws-ecs@1.0.0` binding. The C3 stub
//! ships:
//!
//! - The [`EnvPackHandler`] surface — slot, descriptor path, supported
//!   versions, the accessor returning the credentials handler.
//! - A real
//!   [`DeployerCredentials`](crate::credentials::DeployerCredentials) impl
//!   ([`AwsDeployerCredentials`]) with typed STS + IAM
//!   `SimulatePrincipalPolicy` validation (plan §C3 rule: typed SDK, NOT
//!   shell-out to `aws` CLI).
//! - A bootstrap path that emits a minimum-privilege IAM role + inline-policy
//!   Terraform module under `rules/<env>/`. VPC / ECR / ALB Terraform is
//!   deferred to Phase D's D-AWS-1 train.
//!
//! Phase D adds the actual ECS deploy / `apply_traffic_split` /
//! `report_runtime_config` machinery; the env-pack registers here so the C3
//! credentials surface can be exercised end-to-end against a real AWS account
//! today.
//!
//! Behind the `creds-aws` cargo feature (default-on). Disabling the feature
//! drops the aws-sdk-{sts,iam} deps and the handler from the registry; an
//! env that binds `greentic.deployer.aws-ecs@<v>` then surfaces as `Unknown`
//! through the env-pack registry, which is the honest answer for a binary
//! built without AWS support.

pub mod bootstrap;
pub mod credentials;

use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;

use super::slot::EnvPackHandler;
use crate::tool_check::ToolCheck;

pub use credentials::{AwsDeployerCredentials, AwsValidatorClient};

/// Native handler for the AWS-ECS deployer env-pack (C3 stub).
#[derive(Debug, Default)]
pub struct AwsEcsDeployerHandler {
    creds: AwsDeployerCredentials,
}

impl AwsEcsDeployerHandler {
    /// Version-independent descriptor path used as the registry key.
    /// Matches `greentic.deployer.aws-ecs@1.0.0` from the Phase D plan §6.
    pub const DESCRIPTOR_PATH: &'static str = "greentic.deployer.aws-ecs";

    /// Descriptor versions this handler implements. `^1.0.0-dev` accepts
    /// both the eventual `1.0.0` GA release and the C3-stub-era dev
    /// pre-releases that may ship before Phase D lands.
    pub const VERSION_REQ: &'static str = ">=1.0.0-dev, <2.0.0";

    /// Construct with a pluggable AWS client. Tests pass a mock; production
    /// uses [`AwsDeployerCredentials::default`] which builds the real SDK
    /// client lazily on first validate.
    pub fn with_client(client: std::sync::Arc<dyn AwsValidatorClient>) -> Self {
        Self {
            creds: AwsDeployerCredentials::with_client(client),
        }
    }
}

impl EnvPackHandler for AwsEcsDeployerHandler {
    fn slot(&self) -> CapabilitySlot {
        CapabilitySlot::Deployer
    }

    fn descriptor_path(&self) -> &str {
        Self::DESCRIPTOR_PATH
    }

    fn supported_versions(&self) -> VersionReq {
        Self::VERSION_REQ
            .parse()
            .expect("aws-ecs version-req is valid (guarded by tests)")
    }

    fn preflight(&self) -> Vec<ToolCheck> {
        // Validation is via typed aws-sdk-sts / aws-sdk-iam — no shell-out
        // to the `aws` CLI per plan §C3 ("typed cloud APIs where possible;
        // CLI wrappers are fallback adapters"). Phase D's ECS deploy may
        // surface `terraform` / `tofu` here if the bootstrap emits HCL the
        // operator must apply; today the C3 rules-pack is hand-applied by
        // the customer's admin, so no preflight tool is mandatory.
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
    use greentic_deploy_spec::PackDescriptor;

    #[test]
    fn handler_serves_deployer_slot_with_aws_ecs_path() {
        let h = AwsEcsDeployerHandler::default();
        assert_eq!(h.slot(), CapabilitySlot::Deployer);
        assert_eq!(h.descriptor_path(), "greentic.deployer.aws-ecs");
        // Version req is valid (the parse in `supported_versions` would
        // panic in production if this fails — guard with a test).
        let _ = h.supported_versions();
    }

    #[test]
    fn version_req_accepts_ga_and_dev_releases() {
        let h = AwsEcsDeployerHandler::default();
        let req = h.supported_versions();
        // GA target from Phase D plan.
        let ga = PackDescriptor::try_new("greentic.deployer.aws-ecs@1.0.0").unwrap();
        assert!(req.matches(&ga.version().0), "{req} must accept 1.0.0");
        // C3-era dev pre-release.
        let dev = PackDescriptor::try_new("greentic.deployer.aws-ecs@1.0.0-dev.1").unwrap();
        assert!(
            req.matches(&dev.version().0),
            "{req} must accept dev pre-release"
        );
        // 2.0.0 is a breaking bump — must NOT match the C3 handler.
        let next_major = PackDescriptor::try_new("greentic.deployer.aws-ecs@2.0.0").unwrap();
        assert!(
            !req.matches(&next_major.version().0),
            "{req} must reject 2.0.0 (breaking bump)"
        );
    }

    #[test]
    fn exposes_credentials_contract() {
        let h = AwsEcsDeployerHandler::default();
        let creds = h
            .deployer_credentials()
            .expect("aws-ecs handler must expose credentials");
        // Sanity: requires_credentials_material is true (deferred Phase D
        // makes this dishonest only when the env supplies its own AWS
        // creds via the env's secret backend, which C3 doesn't wire).
        assert!(creds.requires_credentials_material());
    }

    /// C6: pins this handler's wizard YAML to its canonical `id` and
    /// asserts a `region` question is present (the only field with no
    /// sensible default and the one Phase D's IAM/STS probes can't scope
    /// without). Round-trip `qa_spec::FormSpec` deserialization is
    /// covered by the registry-level parametrized test in `registry.rs`.
    #[test]
    fn wizard_qaspec_yaml_pins_id_and_requires_region() {
        let yaml = AwsEcsDeployerHandler::default()
            .wizard_qaspec_yaml()
            .expect("aws-ecs handler ships a wizard QASpec");
        let spec: qa_spec::FormSpec =
            serde_yaml_bw::from_str(yaml).expect("wizard.qaspec.yaml parses as FormSpec");
        assert_eq!(spec.id, "greentic.deployer.aws-ecs.wizard");
        assert!(
            spec.questions.iter().any(|q| q.id == "region"),
            "aws-ecs wizard must collect the AWS region (no sensible default)",
        );
    }
}
