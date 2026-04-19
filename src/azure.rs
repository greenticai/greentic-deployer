use std::path::PathBuf;

use crate::config::{DeployerConfig, DeployerRequest, OutputFormat, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};
use crate::multi_target;
use crate::plan::PlanContext;

/// Library-facing request for the explicit Azure adapter surface.
#[derive(Debug, Clone)]
pub struct AzureRequest {
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

impl AzureRequest {
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
            provider: Provider::Azure,
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

/// Configuration shape consumed by `ext apply --target azure-container-apps-local`.
///
/// Mirrors the JSON schema declared by the `deploy-azure` reference extension.
/// Keys use camelCase on the wire; Rust field names use snake_case with serde rename.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureContainerAppsExtConfig {
    pub location: String,
    pub key_vault_uri: String,
    pub key_vault_id: String,
    pub environment: String,
    pub operator_image_digest: String,
    pub bundle_source: String,
    pub bundle_digest: String,
    pub remote_state_backend: String,
    pub dns_name: Option<String>,
    pub public_base_url: Option<String>,
    pub repo_registry_base: Option<String>,
    pub store_registry_base: Option<String>,
    pub admin_allowed_clients: Option<String>,
    #[serde(default = "default_ext_tenant")]
    pub tenant: String,
}

fn default_ext_tenant() -> String {
    "default".to_string()
}

pub fn resolve_config(request: AzureRequest) -> Result<DeployerConfig> {
    DeployerConfig::resolve(request.into_deployer_request())
}

pub fn ensure_azure_config(config: &DeployerConfig) -> Result<()> {
    if config.provider != Provider::Azure || config.strategy != "iac-only" {
        return Err(DeployerError::Config(format!(
            "azure adapter requires provider=azure strategy=iac-only, got provider={} strategy={}",
            config.provider.as_str(),
            config.strategy
        )));
    }
    Ok(())
}

pub async fn run(request: AzureRequest) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config(config).await
}

pub async fn run_config(config: DeployerConfig) -> Result<multi_target::OperationResult> {
    ensure_azure_config(&config)?;
    multi_target::run(config).await
}

pub async fn run_with_plan(
    request: AzureRequest,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config_with_plan(config, plan).await
}

pub async fn run_config_with_plan(
    config: DeployerConfig,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    ensure_azure_config(&config)?;
    multi_target::run_with_plan(config, plan).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_request_defaults_to_azure_iac_target() {
        let request =
            AzureRequest::new(DeployerCapability::Plan, "acme", PathBuf::from("pack-dir"))
                .into_deployer_request();

        assert_eq!(request.provider, Provider::Azure);
        assert_eq!(request.strategy, "iac-only");
        assert_eq!(request.tenant, "acme");
    }

    #[test]
    fn ext_config_parses_minimum_fields() {
        let json = r#"{
            "location": "eastus",
            "keyVaultUri": "https://my-vault.vault.azure.net/",
            "keyVaultId": "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "azurerm://storage/container/key"
        }"#;
        let cfg: AzureContainerAppsExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.location, "eastus");
        assert_eq!(cfg.key_vault_uri, "https://my-vault.vault.azure.net/");
        assert_eq!(cfg.tenant, "default");
        assert!(cfg.dns_name.is_none());
    }

    #[test]
    fn ext_config_accepts_all_optionals() {
        let json = r#"{
            "location": "eastus",
            "keyVaultUri": "https://my-vault.vault.azure.net/",
            "keyVaultId": "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault",
            "environment": "prod",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "azurerm://...",
            "dnsName": "api.example.com",
            "publicBaseUrl": "https://api.example.com",
            "repoRegistryBase": "https://repo.example.com",
            "storeRegistryBase": "https://store.example.com",
            "adminAllowedClients": "CN=admin",
            "tenant": "acme"
        }"#;
        let cfg: AzureContainerAppsExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dns_name.as_deref(), Some("api.example.com"));
        assert_eq!(cfg.tenant, "acme");
    }

    #[test]
    fn ext_config_rejects_missing_location() {
        let json = r#"{
            "keyVaultUri": "https://my-vault.vault.azure.net/",
            "keyVaultId": "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "azurerm://..."
        }"#;
        let err = serde_json::from_str::<AzureContainerAppsExtConfig>(json).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("location"), "got: {msg}");
    }
}
