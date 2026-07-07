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

/// Library-facing request for the explicit GCP adapter surface.
#[derive(Debug, Clone)]
pub struct GcpRequest {
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
    /// Extra environment variables injected onto the deploy subprocess (e.g.
    /// resolved BYOC cloud credentials). Empty by default → ambient-only behavior.
    pub extra_env: std::collections::BTreeMap<String, String>,
}

impl GcpRequest {
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
            extra_env: std::collections::BTreeMap::new(),
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
            extra_env: self.extra_env,
        }
    }
}

/// Configuration shape consumed by `ext apply --target gcp-cloud-run-local`.
///
/// Mirrors the JSON schema declared by the `deploy-gcp` reference extension.
/// Keys use camelCase on the wire; Rust field names use snake_case with serde rename.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudRunExtConfig {
    pub project_id: String,
    pub region: String,
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

/// Build a `GcpRequest` from the extension-provided config. Used by
/// `apply_from_ext` / `destroy_from_ext`. Fields unused by the extension
/// path default to `None` / `false` / sensible defaults.
fn build_gcp_request_from_ext(
    capability: DeployerCapability,
    cfg: &GcpCloudRunExtConfig,
    pack_path: Option<&std::path::Path>,
) -> GcpRequest {
    GcpRequest {
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
        extra_env: std::collections::BTreeMap::new(),
    }
}

/// Extension-driven apply entry point: parse JSON config, build request,
/// delegate to existing `resolve_config` + `apply::run` pipeline.
///
/// `_creds_json` is reserved for future secret URI resolution (Phase B #2);
/// today, GCP credentials come from the ambient Google Application Default
/// Credentials (ADC) chain (`gcloud auth application-default login` or
/// `GOOGLE_APPLICATION_CREDENTIALS`).
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: GcpCloudRunExtConfig =
        serde_json::from_str(config_json).context("parse gcp cloud-run config JSON")?;
    let request = build_gcp_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve GCP deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for GCP deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run GCP deployment pipeline")?;
    Ok(())
}

/// Extension-driven destroy entry point: same shape as `apply_from_ext`
/// with `capability: Destroy`.
pub fn destroy_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: GcpCloudRunExtConfig =
        serde_json::from_str(config_json).context("parse gcp cloud-run config JSON")?;
    let request = build_gcp_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve GCP deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for GCP destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run GCP destroy pipeline")?;
    Ok(())
}

pub async fn run(request: GcpRequest) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config(config).await
}

pub async fn run_config(config: DeployerConfig) -> Result<multi_target::OperationResult> {
    ensure_gcp_config(&config)?;
    promote_runtime_secrets_for_apply(&config).await?;
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
    promote_runtime_secrets_for_apply(&config).await?;
    multi_target::run_with_plan(config, plan).await
}

async fn promote_runtime_secrets_for_apply(config: &DeployerConfig) -> Result<()> {
    let Some(resolution) = resolve_for_cloud_apply(config).await? else {
        return Ok(());
    };
    let project_id = gcp_project_id()?;
    let prefix = default_cloud_secret_prefix(&config.environment, &config.tenant, None);
    promote_to_gcp_secret_manager(&resolution.resolved, &project_id, &prefix).await?;
    Ok(())
}

async fn promote_to_gcp_secret_manager(
    resolved: &[ResolvedRuntimeSecret],
    project_id: &str,
    prefix: &str,
) -> Result<PromoteRuntimeSecretsReport> {
    let mut report = PromoteRuntimeSecretsReport::default();
    for secret in resolved {
        let remote_name = flat_cloud_secret_name(
            prefix,
            &secret.requirement.provider_id,
            &secret.requirement.key,
            255,
        );
        ensure_gcp_secret(project_id, &remote_name)?;
        add_gcp_secret_version(project_id, &remote_name, secret.value.expose())?;
        report
            .promoted
            .push(crate::runtime_secrets::PromotedRuntimeSecret {
                uri: secret.requirement.uri.clone(),
                remote_name,
            });
    }
    Ok(report)
}

fn gcp_project_id() -> Result<String> {
    std::env::var("GREENTIC_DEPLOY_TERRAFORM_VAR_GCP_PROJECT_ID")
        .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
        .or_else(|_| std::env::var("GCLOUD_PROJECT"))
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            DeployerError::Config(
                "GCP runtime secret promotion requires GREENTIC_DEPLOY_TERRAFORM_VAR_GCP_PROJECT_ID, GOOGLE_CLOUD_PROJECT, or GCLOUD_PROJECT"
                    .to_string(),
            )
        })
}

fn ensure_gcp_secret(project_id: &str, secret_name: &str) -> Result<()> {
    let status = ProcessCommand::new("gcloud")
        .args([
            "secrets",
            "create",
            secret_name,
            "--project",
            project_id,
            "--replication-policy",
            "automatic",
            "--quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|err| DeployerError::Other(format!("run gcloud secrets create: {err}")))?;
    if status.success() {
        return Ok(());
    }

    let describe = ProcessCommand::new("gcloud")
        .args([
            "secrets",
            "describe",
            secret_name,
            "--project",
            project_id,
            "--quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| DeployerError::Other(format!("run gcloud secrets describe: {err}")))?;
    if describe.success() {
        Ok(())
    } else {
        Err(DeployerError::Other(format!(
            "create GCP Secret Manager secret {secret_name} failed"
        )))
    }
}

fn add_gcp_secret_version(project_id: &str, secret_name: &str, value: &str) -> Result<()> {
    let mut child = ProcessCommand::new("gcloud")
        .args([
            "secrets",
            "versions",
            "add",
            secret_name,
            "--project",
            project_id,
            "--data-file",
            "-",
            "--quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| DeployerError::Other(format!("run gcloud secrets versions add: {err}")))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(value.as_bytes())?;
    }
    let output = child.wait_with_output().map_err(|err| {
        DeployerError::Other(format!("wait for gcloud secrets versions add: {err}"))
    })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DeployerError::Other(format!(
            "add GCP Secret Manager version for {secret_name} failed"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcp_request_defaults_to_gcp_iac_target() {
        let request = GcpRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(PathBuf::from("pack-dir")),
        )
        .into_deployer_request();

        assert_eq!(request.provider, Provider::Gcp);
        assert_eq!(request.strategy, "iac-only");
        assert_eq!(request.tenant, "acme");
    }

    #[test]
    fn gcp_request_preserves_all_passthrough_fields() {
        let mut request = GcpRequest::new(
            DeployerCapability::Apply,
            "acme",
            Some(PathBuf::from("pack-dir")),
        );
        request.bundle_root = Some(PathBuf::from("bundle-root"));
        request.bundle_source = Some("gs://bucket/bundle.gtbundle".into());
        request.bundle_digest = Some("sha256:abc".into());
        request.repo_registry_base = Some("https://repo.example".into());
        request.store_registry_base = Some("https://store.example".into());
        request.provider_pack = Some(PathBuf::from("providers/deployer/gcp.gtpack"));
        request.deploy_pack_id_override = Some("greentic.deploy.gcp".into());
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
        request.output = OutputFormat::Yaml;
        request.config_path = Some(PathBuf::from("greentic.toml"));
        request.allow_remote_in_offline = true;
        request.providers_dir = PathBuf::from("providers");
        request.packs_dir = PathBuf::from("packs-dir");

        let deployer = request.into_deployer_request();

        assert_eq!(deployer.capability, DeployerCapability::Apply);
        assert_eq!(deployer.provider, Provider::Gcp);
        assert_eq!(
            deployer.bundle_root.as_deref(),
            Some(std::path::Path::new("bundle-root"))
        );
        assert_eq!(
            deployer.bundle_source.as_deref(),
            Some("gs://bucket/bundle.gtbundle")
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
            Some(std::path::Path::new("providers/deployer/gcp.gtpack"))
        );
        assert_eq!(
            deployer.deploy_pack_id_override.as_deref(),
            Some("greentic.deploy.gcp")
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
        assert_eq!(deployer.output, OutputFormat::Yaml);
        assert_eq!(
            deployer.config_path.as_deref(),
            Some(std::path::Path::new("greentic.toml"))
        );
        assert!(deployer.allow_remote_in_offline);
        assert_eq!(deployer.providers_dir, PathBuf::from("providers"));
        assert_eq!(deployer.packs_dir, PathBuf::from("packs-dir"));
    }

    #[test]
    fn ensure_gcp_config_rejects_non_gcp_provider() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut request = GcpRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(tmp.path().to_path_buf()),
        )
        .into_deployer_request();
        request.provider = Provider::Aws;
        let config = DeployerConfig::resolve(request).expect("resolve config");

        let err = ensure_gcp_config(&config).expect_err("non-gcp config should fail");
        assert!(
            err.to_string().contains("provider=aws strategy=iac-only"),
            "got: {err}"
        );
    }

    #[test]
    fn ensure_gcp_config_accepts_gcp_iac_config() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let request = GcpRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(tmp.path().to_path_buf()),
        )
        .into_deployer_request();
        let config = DeployerConfig::resolve(request).expect("resolve config");

        ensure_gcp_config(&config).expect("gcp config");
    }

    #[test]
    fn gcp_secret_names_are_flat_and_bounded() {
        let name = flat_cloud_secret_name(
            "greentic/dev/demo/_",
            "messaging-telegram",
            "TELEGRAM_BOT_TOKEN",
            255,
        );
        assert_eq!(
            name,
            "greentic-dev-demo-messaging-telegram-telegram-bot-token"
        );
    }

    #[test]
    fn ext_config_parses_minimum_fields() {
        let json = r#"{
            "projectId": "my-gcp-project-12345",
            "region": "us-central1",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "gs://my-tf-state-bucket/greentic/staging"
        }"#;
        let cfg: GcpCloudRunExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.project_id, "my-gcp-project-12345");
        assert_eq!(cfg.region, "us-central1");
        assert_eq!(cfg.environment, "staging");
        assert_eq!(cfg.tenant, "default");
        assert!(cfg.dns_name.is_none());
        assert!(cfg.public_base_url.is_none());
    }

    #[test]
    fn ext_config_accepts_all_optionals() {
        let json = r#"{
            "projectId": "my-gcp-project-12345",
            "region": "us-central1",
            "environment": "prod",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "gs://my-tf-state-bucket/greentic/prod",
            "dnsName": "api.example.com",
            "publicBaseUrl": "https://api.example.com",
            "repoRegistryBase": "https://repo.example.com",
            "storeRegistryBase": "https://store.example.com",
            "adminAllowedClients": "CN=admin",
            "tenant": "acme"
        }"#;
        let cfg: GcpCloudRunExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dns_name.as_deref(), Some("api.example.com"));
        assert_eq!(
            cfg.public_base_url.as_deref(),
            Some("https://api.example.com")
        );
        assert_eq!(cfg.tenant, "acme");
    }

    #[test]
    fn build_gcp_request_from_ext_maps_cloud_bundle_fields() {
        let cfg = GcpCloudRunExtConfig {
            project_id: "project-123".to_string(),
            region: "europe-west1".to_string(),
            environment: "prod".to_string(),
            operator_image_digest: "sha256:0000".to_string(),
            bundle_source: "oci://registry.example/acme/prod".to_string(),
            bundle_digest: "sha256:1111".to_string(),
            remote_state_backend: "gs://state/greentic/prod".to_string(),
            dns_name: Some("api.example.com".to_string()),
            public_base_url: Some("https://api.example.com".to_string()),
            repo_registry_base: Some("https://repo.example.com".to_string()),
            store_registry_base: Some("https://store.example.com".to_string()),
            admin_allowed_clients: Some("CN=admin".to_string()),
            tenant: "acme".to_string(),
        };

        let request = build_gcp_request_from_ext(
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
    fn ext_config_rejects_missing_project_id() {
        let json = r#"{
            "region": "us-central1",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "gs://..."
        }"#;
        let err = serde_json::from_str::<GcpCloudRunExtConfig>(json).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("projectId") || msg.contains("project_id"),
            "got: {msg}"
        );
    }

    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let err = apply_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }

    #[test]
    fn apply_from_ext_rejects_missing_required_field() {
        let json = r#"{"projectId":"my-project"}"#;
        let err = apply_from_ext(json, "{}", None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing field")
                || msg.contains("bundleSource")
                || msg.contains("bundle_source"),
            "got: {msg}"
        );
    }

    #[test]
    fn destroy_from_ext_rejects_invalid_json() {
        let err = destroy_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }
}
