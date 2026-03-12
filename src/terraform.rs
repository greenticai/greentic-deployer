use std::path::PathBuf;

use crate::config::{DeployerConfig, DeployerRequest, OutputFormat, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};
use crate::multi_target;
use crate::plan::PlanContext;

/// Library-facing request for the explicit terraform adapter surface.
#[derive(Debug, Clone)]
pub struct TerraformRequest {
    pub capability: DeployerCapability,
    pub tenant: String,
    pub pack_path: PathBuf,
    pub provider_pack: Option<PathBuf>,
    pub deploy_pack_id_override: Option<String>,
    pub deploy_flow_id_override: Option<String>,
    pub environment: Option<String>,
    pub pack_id: Option<String>,
    pub pack_version: Option<String>,
    pub pack_digest: Option<String>,
    pub distributor_url: Option<String>,
    pub distributor_token: Option<String>,
    pub preview: bool,
    pub dry_run: bool,
    pub execute_local: bool,
    pub output: OutputFormat,
    pub config_path: Option<PathBuf>,
    pub allow_remote_in_offline: bool,
    pub providers_dir: PathBuf,
    pub packs_dir: PathBuf,
}

impl TerraformRequest {
    pub fn new(
        capability: DeployerCapability,
        tenant: impl Into<String>,
        pack_path: PathBuf,
    ) -> Self {
        Self {
            capability,
            tenant: tenant.into(),
            pack_path,
            provider_pack: None,
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            environment: None,
            pack_id: None,
            pack_version: None,
            pack_digest: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: OutputFormat::Text,
            config_path: None,
            allow_remote_in_offline: false,
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
        }
    }

    pub fn into_deployer_request(self) -> DeployerRequest {
        DeployerRequest {
            capability: self.capability,
            provider: Provider::Generic,
            strategy: "terraform".to_string(),
            tenant: self.tenant,
            environment: self.environment,
            pack_path: self.pack_path,
            providers_dir: self.providers_dir,
            packs_dir: self.packs_dir,
            provider_pack: self.provider_pack,
            pack_id: self.pack_id,
            pack_version: self.pack_version,
            pack_digest: self.pack_digest,
            distributor_url: self.distributor_url,
            distributor_token: self.distributor_token,
            preview: self.preview,
            dry_run: self.dry_run,
            execute_local: self.execute_local,
            output: self.output,
            config_path: self.config_path,
            allow_remote_in_offline: self.allow_remote_in_offline,
            deploy_pack_id_override: self.deploy_pack_id_override,
            deploy_flow_id_override: self.deploy_flow_id_override,
        }
    }
}

pub fn resolve_config(request: TerraformRequest) -> Result<DeployerConfig> {
    DeployerConfig::resolve(request.into_deployer_request())
}

pub fn ensure_terraform_config(config: &DeployerConfig) -> Result<()> {
    if config.provider != Provider::Generic || config.strategy != "terraform" {
        return Err(DeployerError::Config(format!(
            "terraform adapter requires provider=generic strategy=terraform, got provider={} strategy={}",
            config.provider.as_str(),
            config.strategy
        )));
    }
    Ok(())
}

pub async fn run(request: TerraformRequest) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config(config).await
}

pub async fn run_config(config: DeployerConfig) -> Result<multi_target::OperationResult> {
    ensure_terraform_config(&config)?;
    multi_target::run(config).await
}

pub async fn run_with_plan(
    request: TerraformRequest,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config_with_plan(config, plan).await
}

pub async fn run_config_with_plan(
    config: DeployerConfig,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    ensure_terraform_config(&config)?;
    multi_target::run_with_plan(config, plan).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terraform_request_defaults_to_generic_terraform_target() {
        let request =
            TerraformRequest::new(DeployerCapability::Plan, "acme", PathBuf::from("pack-dir"))
                .into_deployer_request();

        assert_eq!(request.provider, Provider::Generic);
        assert_eq!(request.strategy, "terraform");
        assert_eq!(request.tenant, "acme");
        assert_eq!(request.pack_path, PathBuf::from("pack-dir"));
    }

    #[test]
    fn terraform_config_guard_rejects_non_terraform_multi_target_configs() {
        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: PathBuf::from("pack-dir"),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: OutputFormat::Text,
            greentic: greentic_config::ConfigResolver::new()
                .load()
                .expect("load default config")
                .config,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
        };

        let err = ensure_terraform_config(&config).expect_err("non-terraform config rejected");
        assert!(format!("{err}").contains("provider=generic strategy=terraform"));
    }
}
