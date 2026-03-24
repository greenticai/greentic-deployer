use std::path::PathBuf;

use crate::config::{DeployerConfig, DeployerRequest, OutputFormat, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};
use crate::multi_target;
use crate::plan::PlanContext;

/// Library-facing request for the explicit GCP adapter surface.
#[derive(Debug, Clone)]
pub struct GcpRequest {
    pub capability: DeployerCapability,
    pub tenant: String,
    pub pack_path: PathBuf,
    pub bundle_source: Option<String>,
    pub bundle_digest: Option<String>,
    pub repo_registry_base: Option<String>,
    pub store_registry_base: Option<String>,
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

impl GcpRequest {
    pub fn new(
        capability: DeployerCapability,
        tenant: impl Into<String>,
        pack_path: PathBuf,
    ) -> Self {
        Self {
            capability,
            tenant: tenant.into(),
            pack_path,
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
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
            provider: Provider::Gcp,
            strategy: "iac-only".to_string(),
            tenant: self.tenant,
            environment: self.environment,
            pack_path: self.pack_path,
            bundle_source: self.bundle_source,
            bundle_digest: self.bundle_digest,
            repo_registry_base: self.repo_registry_base,
            store_registry_base: self.store_registry_base,
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

pub fn resolve_config(request: GcpRequest) -> Result<DeployerConfig> {
    DeployerConfig::resolve(request.into_deployer_request())
}

pub fn ensure_gcp_config(config: &DeployerConfig) -> Result<()> {
    if config.provider != Provider::Gcp || config.strategy != "iac-only" {
        return Err(DeployerError::Config(format!(
            "gcp adapter requires provider=gcp strategy=iac-only, got provider={} strategy={}",
            config.provider.as_str(),
            config.strategy
        )));
    }
    Ok(())
}

pub async fn run(request: GcpRequest) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config(config).await
}

pub async fn run_config(config: DeployerConfig) -> Result<multi_target::OperationResult> {
    ensure_gcp_config(&config)?;
    multi_target::run(config).await
}

pub async fn run_with_plan(
    request: GcpRequest,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config_with_plan(config, plan).await
}

pub async fn run_config_with_plan(
    config: DeployerConfig,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    ensure_gcp_config(&config)?;
    multi_target::run_with_plan(config, plan).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcp_request_defaults_to_gcp_iac_target() {
        let request = GcpRequest::new(DeployerCapability::Plan, "acme", PathBuf::from("pack-dir"))
            .into_deployer_request();

        assert_eq!(request.provider, Provider::Gcp);
        assert_eq!(request.strategy, "iac-only");
        assert_eq!(request.tenant, "acme");
    }
}
