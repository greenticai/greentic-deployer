//! AWS-ECS deployer env-pack.
//!
//! Backs the optional `greentic.deployer.aws-ecs@1.0.0` binding. Ships:
//!
//! - The [`EnvPackHandler`] surface — slot, descriptor path, supported
//!   versions, and the accessors returning the credentials + deployer impls.
//! - A [`DeployerCredentials`](crate::credentials::DeployerCredentials) impl
//!   ([`AwsDeployerCredentials`]) with typed STS + IAM
//!   `SimulatePrincipalPolicy` validation (plan §C3 rule: typed SDK, NOT
//!   shell-out to `aws` CLI).
//! - A bootstrap path that emits a minimum-privilege IAM role + inline-policy
//!   Terraform module under `rules/<env>/`. VPC / ECR / ALB Terraform is
//!   deferred to the D-AWS-1 train.
//! - A [`Deployer`](crate::env_packs::deployer::Deployer) impl ([`deployer`])
//!   driving the ECS task-set lifecycle (warm / archive / traffic-split)
//!   through the [`EcsDeployTarget`](deploy_target::EcsDeployTarget) seam.
//!   The real aws-sdk-backed target and the STS session minter land in
//!   follow-up PRs; today the verbs run against the in-memory fake and a
//!   default [`UnconfiguredEcsTarget`](deploy_target::UnconfiguredEcsTarget)
//!   that fails honestly when no real client is wired.
//!
//! Behind the `creds-aws` cargo feature (default-on). Disabling the feature
//! drops the aws-sdk-{sts,iam} deps and the handler from the registry; an
//! env that binds `greentic.deployer.aws-ecs@<v>` then surfaces as `Unknown`
//! through the env-pack registry, which is the honest answer for a binary
//! built without AWS support.

pub mod bootstrap;
pub mod credentials;
pub mod deploy_target;
pub mod deployer;
#[cfg(feature = "deploy-aws-ecs")]
pub mod real_target;

use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;

use super::slot::EnvPackHandler;
use crate::tool_check::ToolCheck;

pub use credentials::{AwsDeployerCredentials, AwsValidatorClient};

/// Native handler for the AWS-ECS deployer env-pack.
#[derive(Debug)]
pub struct AwsEcsDeployerHandler {
    creds: AwsDeployerCredentials,
    /// Side-effect seam the [`Deployer`](crate::env_packs::deployer::Deployer)
    /// verbs drive. Crate-visible so `deployer.rs` reaches it. Defaults to
    /// [`UnconfiguredEcsTarget`](deploy_target::UnconfiguredEcsTarget) (fails
    /// verbs honestly); the real aws-sdk-backed target is wired in a follow-up
    /// PR behind the `deploy-aws-ecs` feature.
    pub(crate) target: std::sync::Arc<dyn deploy_target::EcsDeployTarget>,
}

impl Default for AwsEcsDeployerHandler {
    fn default() -> Self {
        Self {
            creds: AwsDeployerCredentials::default(),
            target: std::sync::Arc::new(deploy_target::UnconfiguredEcsTarget),
        }
    }
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
            target: std::sync::Arc::new(deploy_target::UnconfiguredEcsTarget),
        }
    }

    /// Construct with a pluggable deploy-target seam. Tests pass the in-memory
    /// fake; the orchestration wiring passes a connected aws-sdk-backed target.
    pub fn with_target(target: std::sync::Arc<dyn deploy_target::EcsDeployTarget>) -> Self {
        Self {
            creds: AwsDeployerCredentials::default(),
            target,
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

    fn as_deployer(&self) -> Option<&dyn crate::env_packs::deployer::Deployer> {
        Some(self)
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
    fn exposes_credentials_contract_and_deployer_impl() {
        let h = AwsEcsDeployerHandler::default();
        let creds = h
            .deployer_credentials()
            .expect("aws-ecs handler must expose credentials");
        assert!(creds.requires_credentials_material());
        // The second half of the Phase D pluggability contract: the handler
        // now surfaces its Deployer impl (verbs run against the seam).
        assert!(
            (&h as &dyn EnvPackHandler).as_deployer().is_some(),
            "EnvPackHandler::as_deployer must surface the AWS-ECS Deployer impl"
        );
        // Imperative deployer — no declarative manifest renderer (no
        // `op env render` / `reconcile` for AWS).
        assert!(
            (&h as &dyn EnvPackHandler).as_manifest_renderer().is_none(),
            "AWS-ECS is imperative; it must not expose a manifest renderer"
        );
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
