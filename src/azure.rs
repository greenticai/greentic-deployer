use std::io::Write;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};

use crate::config::{DeployerConfig, DeployerRequest, OutputFormat, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};
use crate::multi_target;
use crate::plan::PlanContext;
use crate::runtime_secrets::{
    PromoteRuntimeSecretsReport, ResolvedRuntimeSecret, default_cloud_secret_prefix,
    flat_cloud_secret_name, resolve_for_cloud_apply,
};

/// Library-facing request for the explicit Azure adapter surface.
#[derive(Debug, Clone)]
pub struct AzureRequest {
    pub capability: DeployerCapability,
    pub tenant: String,
    pub pack_path: Option<PathBuf>,
    pub bundle_root: Option<PathBuf>,
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
        pack_path: Option<PathBuf>,
    ) -> Self {
        Self {
            capability,
            tenant: tenant.into(),
            pack_path,
            bundle_root: None,
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
            bundle_root: self.bundle_root,
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

/// Build an `AzureRequest` from the extension-provided config.
fn build_azure_request_from_ext(
    capability: DeployerCapability,
    cfg: &AzureContainerAppsExtConfig,
    pack_path: Option<&std::path::Path>,
) -> AzureRequest {
    AzureRequest {
        capability,
        tenant: cfg.tenant.clone(),
        pack_path: pack_path.map(std::path::Path::to_path_buf),
        bundle_root: None,
        bundle_source: Some(cfg.bundle_source.clone()),
        bundle_digest: Some(cfg.bundle_digest.clone()),
        repo_registry_base: cfg.repo_registry_base.clone(),
        store_registry_base: cfg.store_registry_base.clone(),
        provider_pack: None,
        deploy_pack_id_override: None,
        deploy_flow_id_override: None,
        environment: Some(cfg.environment.clone()),
        pack_id: None,
        pack_version: None,
        pack_digest: None,
        distributor_url: None,
        distributor_token: None,
        preview: false,
        dry_run: false,
        execute_local: true,
        output: crate::config::OutputFormat::Text,
        config_path: None,
        allow_remote_in_offline: false,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    }
}

/// Extension-driven apply entry point: parse JSON config, build request,
/// delegate to existing `resolve_config` + `apply::run` pipeline.
///
/// `_creds_json` is reserved for future secret URI resolution (Phase B #2);
/// today, Azure credentials come from the ambient Azure auth chain
/// (`az login`, `AZURE_*` env vars, or managed identity).
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AzureContainerAppsExtConfig =
        serde_json::from_str(config_json).context("parse azure container-apps config JSON")?;
    let request = build_azure_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve Azure deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for Azure deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run Azure deployment pipeline")?;
    Ok(())
}

/// Extension-driven destroy entry point.
pub fn destroy_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AzureContainerAppsExtConfig =
        serde_json::from_str(config_json).context("parse azure container-apps config JSON")?;
    let request = build_azure_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve Azure deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for Azure destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run Azure destroy pipeline")?;
    Ok(())
}

pub async fn run(request: AzureRequest) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config(config).await
}

pub async fn run_config(config: DeployerConfig) -> Result<multi_target::OperationResult> {
    ensure_azure_config(&config)?;
    promote_runtime_secrets_for_apply(&config).await?;
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
    promote_runtime_secrets_for_apply(&config).await?;
    multi_target::run_with_plan(config, plan).await
}

async fn promote_runtime_secrets_for_apply(config: &DeployerConfig) -> Result<()> {
    let Some(resolution) = resolve_for_cloud_apply(config).await? else {
        return Ok(());
    };
    let vault_name = azure_key_vault_name()?;
    let prefix = default_cloud_secret_prefix(&config.environment, &config.tenant, None);
    promote_to_azure_key_vault(&resolution.resolved, &vault_name, &prefix).await?;
    Ok(())
}

async fn promote_to_azure_key_vault(
    resolved: &[ResolvedRuntimeSecret],
    vault_name: &str,
    prefix: &str,
) -> Result<PromoteRuntimeSecretsReport> {
    let mut report = PromoteRuntimeSecretsReport::default();
    for secret in resolved {
        let remote_name = flat_cloud_secret_name(
            prefix,
            &secret.requirement.provider_id,
            &secret.requirement.key,
            127,
        );
        set_azure_key_vault_secret(vault_name, &remote_name, secret.value.expose())?;
        report
            .promoted
            .push(crate::runtime_secrets::PromotedRuntimeSecret {
                uri: secret.requirement.uri.clone(),
                remote_name,
            });
    }
    Ok(report)
}

fn azure_key_vault_name() -> Result<String> {
    if let Some(value) = std::env::var("GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_NAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(value);
    }
    if let Some(value) = std::env::var("GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_URI")
        .ok()
        .and_then(|value| key_vault_name_from_uri(&value))
    {
        return Ok(value);
    }
    if let Some(value) = std::env::var("GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_ID")
        .ok()
        .and_then(|value| key_vault_name_from_id(&value))
    {
        return Ok(value);
    }
    Err(DeployerError::Config(
        "Azure runtime secret promotion requires GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_NAME, _URI, or _ID"
            .to_string(),
    ))
}

fn key_vault_name_from_uri(uri: &str) -> Option<String> {
    let host = uri
        .trim()
        .trim_end_matches('/')
        .strip_prefix("https://")
        .unwrap_or(uri.trim())
        .split('/')
        .next()?;
    host.split('.')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn key_vault_name_from_id(id: &str) -> Option<String> {
    id.trim()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn set_azure_key_vault_secret(vault_name: &str, secret_name: &str, value: &str) -> Result<()> {
    let mut temp = tempfile::NamedTempFile::new()
        .map_err(|err| DeployerError::Other(format!("create temporary secret file: {err}")))?;
    temp.write_all(value.as_bytes())?;
    temp.flush()?;

    let status = ProcessCommand::new("az")
        .args([
            "keyvault",
            "secret",
            "set",
            "--vault-name",
            vault_name,
            "--name",
            secret_name,
            "--file",
            temp.path().to_str().ok_or_else(|| {
                DeployerError::Other("temporary secret path is not UTF-8".to_string())
            })?,
            "--only-show-errors",
            "--output",
            "none",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|err| DeployerError::Other(format!("run az keyvault secret set: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(DeployerError::Other(format!(
            "set Azure Key Vault secret {secret_name} in vault {vault_name} failed"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_request_defaults_to_azure_iac_target() {
        let request = AzureRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(PathBuf::from("pack-dir")),
        )
        .into_deployer_request();

        assert_eq!(request.provider, Provider::Azure);
        assert_eq!(request.strategy, "iac-only");
        assert_eq!(request.tenant, "acme");
    }

    #[test]
    fn azure_request_preserves_all_passthrough_fields() {
        let mut request = AzureRequest::new(
            DeployerCapability::Apply,
            "acme",
            Some(PathBuf::from("pack-dir")),
        );
        request.bundle_root = Some(PathBuf::from("bundle-root"));
        request.bundle_source = Some("azblob://container/bundle.gtbundle".into());
        request.bundle_digest = Some("sha256:abc".into());
        request.repo_registry_base = Some("https://repo.example".into());
        request.store_registry_base = Some("https://store.example".into());
        request.provider_pack = Some(PathBuf::from("providers/deployer/azure.gtpack"));
        request.deploy_pack_id_override = Some("greentic.deploy.azure".into());
        request.deploy_flow_id_override = Some("apply_terraform".into());
        request.environment = Some("prod".into());
        request.pack_id = Some("pack-id".into());
        request.pack_version = Some("1.2.3".into());
        request.pack_digest = Some("sha256:def".into());
        request.distributor_url = Some("https://dist.example".into());
        request.distributor_token = Some("token".into());
        request.preview = true;
        request.dry_run = true;
        request.execute_local = true;
        request.output = OutputFormat::Json;
        request.config_path = Some(PathBuf::from("greentic.toml"));
        request.allow_remote_in_offline = true;
        request.providers_dir = PathBuf::from("providers");
        request.packs_dir = PathBuf::from("packs-dir");

        let deployer = request.into_deployer_request();

        assert_eq!(deployer.capability, DeployerCapability::Apply);
        assert_eq!(deployer.provider, Provider::Azure);
        assert_eq!(
            deployer.bundle_root.as_deref(),
            Some(std::path::Path::new("bundle-root"))
        );
        assert_eq!(
            deployer.bundle_source.as_deref(),
            Some("azblob://container/bundle.gtbundle")
        );
        assert_eq!(deployer.bundle_digest.as_deref(), Some("sha256:abc"));
        assert_eq!(
            deployer.repo_registry_base.as_deref(),
            Some("https://repo.example")
        );
        assert_eq!(
            deployer.store_registry_base.as_deref(),
            Some("https://store.example")
        );
        assert_eq!(
            deployer.provider_pack.as_deref(),
            Some(std::path::Path::new("providers/deployer/azure.gtpack"))
        );
        assert_eq!(
            deployer.deploy_pack_id_override.as_deref(),
            Some("greentic.deploy.azure")
        );
        assert_eq!(
            deployer.deploy_flow_id_override.as_deref(),
            Some("apply_terraform")
        );
        assert_eq!(deployer.environment.as_deref(), Some("prod"));
        assert_eq!(deployer.pack_id.as_deref(), Some("pack-id"));
        assert_eq!(deployer.pack_version.as_deref(), Some("1.2.3"));
        assert_eq!(deployer.pack_digest.as_deref(), Some("sha256:def"));
        assert_eq!(
            deployer.distributor_url.as_deref(),
            Some("https://dist.example")
        );
        assert_eq!(deployer.distributor_token.as_deref(), Some("token"));
        assert!(deployer.preview);
        assert!(deployer.dry_run);
        assert!(deployer.execute_local);
        assert_eq!(deployer.output, OutputFormat::Json);
        assert_eq!(
            deployer.config_path.as_deref(),
            Some(std::path::Path::new("greentic.toml"))
        );
        assert!(deployer.allow_remote_in_offline);
        assert_eq!(deployer.providers_dir, PathBuf::from("providers"));
        assert_eq!(deployer.packs_dir, PathBuf::from("packs-dir"));
    }

    #[test]
    fn ensure_azure_config_rejects_non_azure_provider() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut request = AzureRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(tmp.path().to_path_buf()),
        )
        .into_deployer_request();
        request.provider = Provider::Gcp;
        let config = DeployerConfig::resolve(request).expect("resolve config");

        let err = ensure_azure_config(&config).expect_err("non-azure config should fail");
        assert!(
            err.to_string().contains("provider=gcp strategy=iac-only"),
            "got: {err}"
        );
    }

    #[test]
    fn ensure_azure_config_accepts_azure_iac_config() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let request = AzureRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(tmp.path().to_path_buf()),
        )
        .into_deployer_request();
        let config = DeployerConfig::resolve(request).expect("resolve config");

        ensure_azure_config(&config).expect("azure config");
    }

    #[test]
    fn parses_key_vault_name_from_uri_and_id() {
        assert_eq!(
            key_vault_name_from_uri("https://my-vault.vault.azure.net/").as_deref(),
            Some("my-vault")
        );
        assert_eq!(
            key_vault_name_from_id(
                "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault"
            )
            .as_deref(),
            Some("my-vault")
        );
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
    fn build_azure_request_from_ext_maps_cloud_bundle_fields() {
        let cfg = AzureContainerAppsExtConfig {
            location: "eastus".to_string(),
            key_vault_uri: "https://my-vault.vault.azure.net/".to_string(),
            key_vault_id:
                "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault"
                    .to_string(),
            environment: "prod".to_string(),
            operator_image_digest: "sha256:0000".to_string(),
            bundle_source: "oci://registry.example/acme/prod".to_string(),
            bundle_digest: "sha256:1111".to_string(),
            remote_state_backend: "azurerm://state/prod".to_string(),
            dns_name: Some("api.example.com".to_string()),
            public_base_url: Some("https://api.example.com".to_string()),
            repo_registry_base: Some("https://repo.example.com".to_string()),
            store_registry_base: Some("https://store.example.com".to_string()),
            admin_allowed_clients: Some("CN=admin".to_string()),
            tenant: "acme".to_string(),
        };

        let request = build_azure_request_from_ext(
            DeployerCapability::Destroy,
            &cfg,
            Some(std::path::Path::new("pack")),
        );

        assert_eq!(request.capability, DeployerCapability::Destroy);
        assert_eq!(request.tenant, "acme");
        assert_eq!(request.pack_path, Some(PathBuf::from("pack")));
        assert_eq!(
            request.bundle_source.as_deref(),
            Some("oci://registry.example/acme/prod")
        );
        assert_eq!(request.bundle_digest.as_deref(), Some("sha256:1111"));
        assert_eq!(
            request.repo_registry_base.as_deref(),
            Some("https://repo.example.com")
        );
        assert_eq!(
            request.store_registry_base.as_deref(),
            Some("https://store.example.com")
        );
        assert_eq!(request.environment.as_deref(), Some("prod"));
        assert!(request.execute_local);
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

    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let err = apply_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }

    #[test]
    fn apply_from_ext_rejects_missing_required_field() {
        let json = r#"{"location":"eastus"}"#;
        let err = apply_from_ext(json, "{}", None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing field")
                || msg.contains("keyVaultUri")
                || msg.contains("key_vault_uri"),
            "got: {msg}"
        );
    }

    #[test]
    fn destroy_from_ext_rejects_invalid_json() {
        let err = destroy_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }
}
