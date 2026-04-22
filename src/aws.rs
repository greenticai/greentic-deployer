use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use serde_json::Value;

use crate::admin_access::{
    load_terraform_outputs, resolve_latest_deploy_dir, terraform_output_string,
    tunnel_admin_cert_dir,
};
use crate::config::{DeployerConfig, DeployerRequest, OutputFormat, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};
use crate::multi_target;
use crate::plan::PlanContext;

/// Library-facing request for the explicit AWS adapter surface.
#[derive(Debug, Clone)]
pub struct AwsRequest {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsAdminTunnelRequest {
    pub bundle_dir: PathBuf,
    pub local_port: String,
    pub container: String,
}

/// Configuration shape consumed by `ext apply --target aws-ecs-fargate-local`.
///
/// Mirrors the JSON schema declared by the `deploy-aws` reference extension.
/// Keys use camelCase on the wire; Rust field names use snake_case with serde rename.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEcsFargateExtConfig {
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

impl AwsRequest {
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
            provider: Provider::Aws,
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

pub fn resolve_config(request: AwsRequest) -> Result<DeployerConfig> {
    DeployerConfig::resolve(request.into_deployer_request())
}

pub fn ensure_aws_config(config: &DeployerConfig) -> Result<()> {
    if config.provider != Provider::Aws || config.strategy != "iac-only" {
        return Err(DeployerError::Config(format!(
            "aws adapter requires provider=aws strategy=iac-only, got provider={} strategy={}",
            config.provider.as_str(),
            config.strategy
        )));
    }
    Ok(())
}

/// Build an `AwsRequest` from the extension-provided config. Used by
/// `apply_from_ext` / `destroy_from_ext`. Fields unused by the extension
/// path default to `None` / `false` / sensible defaults.
fn build_aws_request_from_ext(
    capability: DeployerCapability,
    cfg: &AwsEcsFargateExtConfig,
    pack_path: Option<&std::path::Path>,
) -> AwsRequest {
    AwsRequest {
        capability,
        tenant: cfg.tenant.clone(),
        pack_path: pack_path
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default(),
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
/// today, AWS credentials come from the ambient provider chain.
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AwsEcsFargateExtConfig =
        serde_json::from_str(config_json).context("parse aws ecs-fargate config JSON")?;
    let request = build_aws_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve AWS deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for AWS deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run AWS deployment pipeline")?;
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
    let cfg: AwsEcsFargateExtConfig =
        serde_json::from_str(config_json).context("parse aws ecs-fargate config JSON")?;
    let request = build_aws_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve AWS deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for AWS destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run AWS destroy pipeline")?;
    Ok(())
}

pub async fn run(request: AwsRequest) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config(config).await
}

pub async fn run_config(config: DeployerConfig) -> Result<multi_target::OperationResult> {
    ensure_aws_config(&config)?;
    multi_target::run(config).await
}

pub async fn run_with_plan(
    request: AwsRequest,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    let config = resolve_config(request)?;
    run_config_with_plan(config, plan).await
}

pub async fn run_config_with_plan(
    config: DeployerConfig,
    plan: PlanContext,
) -> Result<multi_target::OperationResult> {
    ensure_aws_config(&config)?;
    multi_target::run_with_plan(config, plan).await
}

pub fn run_admin_tunnel(args: AwsAdminTunnelRequest) -> Result<()> {
    let deploy_dir = resolve_latest_deploy_dir(&args.bundle_dir, "aws")?;
    let outputs_path = deploy_dir.join("terraform-outputs.json");
    let outputs = load_terraform_outputs(&outputs_path)?;
    let Some(admin_ca_secret_ref) = terraform_output_string(&outputs, "admin_ca_secret_ref") else {
        return Err(DeployerError::Other(format!(
            "missing admin_ca_secret_ref in {}; deploy the bundle first",
            outputs_path.display()
        )));
    };

    let Some(region) = aws_region_from_secret_arn(&admin_ca_secret_ref) else {
        return Err(DeployerError::Other(
            "failed to derive AWS region from admin secret ref".to_string(),
        ));
    };
    let Some(name_prefix) = deploy_name_prefix_from_secret_arn(&admin_ca_secret_ref) else {
        return Err(DeployerError::Other(
            "failed to derive deploy name prefix from admin secret ref".to_string(),
        ));
    };

    let cluster = format!("{name_prefix}-cluster");
    let service = format!("{name_prefix}-service");

    let task_arn = aws_cli_capture(
        &[
            "ecs",
            "list-tasks",
            "--region",
            &region,
            "--cluster",
            &cluster,
            "--service-name",
            &service,
            "--query",
            "taskArns[0]",
            "--output",
            "text",
        ],
        "aws ecs list-tasks",
    )?;
    if task_arn.is_empty() || task_arn == "None" {
        return Err(DeployerError::Other(format!(
            "no running ECS task found for service {service}"
        )));
    }

    let runtime_query = format!(
        "tasks[0].containers[?name=='{}'].runtimeId | [0]",
        args.container
    );
    let runtime_id = aws_cli_capture(
        &[
            "ecs",
            "describe-tasks",
            "--region",
            &region,
            "--cluster",
            &cluster,
            "--tasks",
            &task_arn,
            "--query",
            &runtime_query,
            "--output",
            "text",
        ],
        "aws ecs describe-tasks",
    )?;
    if runtime_id.is_empty() || runtime_id == "None" {
        return Err(DeployerError::Other(format!(
            "no runtimeId found for container {}",
            args.container
        )));
    }

    let Some(task_id) = task_id_from_arn(&task_arn) else {
        return Err(DeployerError::Other(
            "failed to derive task id from task ARN".to_string(),
        ));
    };

    maybe_write_tunnel_admin_certs(&args.bundle_dir, &outputs, &region, &name_prefix)?;

    let target = format!("ecs:{cluster}_{task_id}_{runtime_id}");
    let parameters = format!(
        "{{\"host\":[\"127.0.0.1\"],\"portNumber\":[\"8433\"],\"localPortNumber\":[\"{}\"]}}",
        args.local_port
    );

    println!(
        "Opening admin tunnel on https://127.0.0.1:{}",
        args.local_port
    );
    let cert_dir = tunnel_admin_cert_dir(&args.bundle_dir, &name_prefix);
    if cert_dir.is_dir() {
        println!("admin certs: {}", cert_dir.display());
        println!(
            "example: curl --cacert {0}/ca.crt --cert {0}/client.crt --key {0}/client.key https://127.0.0.1:{1}/admin/v1/health",
            cert_dir.display(),
            args.local_port
        );
    }
    if let Some(value) = terraform_output_string(&outputs, "admin_client_cert_secret_ref") {
        println!("admin_client_cert_secret_ref: {value}");
    } else {
        println!("note: this deployment does not publish admin client cert refs yet");
    }
    if let Some(value) = terraform_output_string(&outputs, "admin_client_key_secret_ref") {
        println!("admin_client_key_secret_ref: {value}");
    }
    println!("Press Ctrl+C to stop.");

    let status = ProcessCommand::new("aws")
        .args([
            "ssm",
            "start-session",
            "--region",
            &region,
            "--target",
            &target,
            "--document-name",
            "AWS-StartPortForwardingSessionToRemoteHost",
            "--parameters",
            &parameters,
        ])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(DeployerError::Other(format!(
            "admin tunnel exited with status {status}"
        )))
    }
}

fn aws_region_from_secret_arn(secret_arn: &str) -> Option<String> {
    secret_arn.split(':').nth(3).map(|value| value.to_string())
}

fn maybe_write_tunnel_admin_certs(
    bundle_dir: &Path,
    outputs: &Value,
    region: &str,
    deploy_name_prefix: &str,
) -> Result<()> {
    let Some(client_cert_ref) = terraform_output_string(outputs, "admin_client_cert_secret_ref")
    else {
        return Ok(());
    };
    let Some(client_key_ref) = terraform_output_string(outputs, "admin_client_key_secret_ref")
    else {
        return Ok(());
    };
    let Some(ca_ref) = terraform_output_string(outputs, "admin_ca_secret_ref") else {
        return Ok(());
    };

    let cert_dir = tunnel_admin_cert_dir(bundle_dir, deploy_name_prefix);
    fs::create_dir_all(&cert_dir)?;
    fs::write(
        cert_dir.join("ca.crt"),
        aws_cli_capture(
            &[
                "secretsmanager",
                "get-secret-value",
                "--region",
                region,
                "--secret-id",
                &ca_ref,
                "--query",
                "SecretString",
                "--output",
                "text",
            ],
            "aws secretsmanager get-secret-value (admin ca)",
        )?,
    )?;
    fs::write(
        cert_dir.join("client.crt"),
        aws_cli_capture(
            &[
                "secretsmanager",
                "get-secret-value",
                "--region",
                region,
                "--secret-id",
                &client_cert_ref,
                "--query",
                "SecretString",
                "--output",
                "text",
            ],
            "aws secretsmanager get-secret-value (admin client cert)",
        )?,
    )?;
    fs::write(
        cert_dir.join("client.key"),
        aws_cli_capture(
            &[
                "secretsmanager",
                "get-secret-value",
                "--region",
                region,
                "--secret-id",
                &client_key_ref,
                "--query",
                "SecretString",
                "--output",
                "text",
            ],
            "aws secretsmanager get-secret-value (admin client key)",
        )?,
    )?;
    Ok(())
}

fn deploy_name_prefix_from_secret_arn(secret_arn: &str) -> Option<String> {
    let marker = ":secret:greentic/admin/";
    let start = secret_arn.find(marker)? + marker.len();
    let rest = &secret_arn[start..];
    let prefix = rest.split('/').next()?;
    if prefix.is_empty() {
        None
    } else {
        Some(prefix.to_string())
    }
}

fn task_id_from_arn(task_arn: &str) -> Option<String> {
    task_arn.rsplit('/').next().map(|value| value.to_string())
}

fn aws_cli_capture(args: &[&str], label: &str) -> Result<String> {
    let output = ProcessCommand::new("aws").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err(DeployerError::Other(format!(
                "{label} failed with status {}",
                output.status
            )));
        }
        return Err(DeployerError::Other(format!("{label} failed: {stderr}")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_request_defaults_to_aws_iac_target() {
        let request = AwsRequest::new(DeployerCapability::Plan, "acme", PathBuf::from("pack-dir"))
            .into_deployer_request();

        assert_eq!(request.provider, Provider::Aws);
        assert_eq!(request.strategy, "iac-only");
        assert_eq!(request.tenant, "acme");
    }

    #[test]
    fn ext_config_parses_minimum_fields() {
        let json = r#"{
            "region": "us-east-1",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "s3://my-tf-state-bucket/greentic/staging"
        }"#;
        let cfg: AwsEcsFargateExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.environment, "staging");
        assert_eq!(cfg.tenant, "default");
        assert!(cfg.dns_name.is_none());
        assert!(cfg.public_base_url.is_none());
    }

    #[test]
    fn ext_config_accepts_all_optionals() {
        let json = r#"{
            "region": "us-east-1",
            "environment": "prod",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "s3://my-tf-state-bucket/greentic/prod",
            "dnsName": "api.example.com",
            "publicBaseUrl": "https://api.example.com",
            "repoRegistryBase": "https://repo.example.com",
            "storeRegistryBase": "https://store.example.com",
            "adminAllowedClients": "CN=admin",
            "tenant": "acme"
        }"#;
        let cfg: AwsEcsFargateExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dns_name.as_deref(), Some("api.example.com"));
        assert_eq!(
            cfg.public_base_url.as_deref(),
            Some("https://api.example.com")
        );
        assert_eq!(cfg.tenant, "acme");
    }

    #[test]
    fn ext_config_rejects_missing_region() {
        let json = r#"{
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "s3://..."
        }"#;
        let err = serde_json::from_str::<AwsEcsFargateExtConfig>(json).unwrap_err();
        assert!(format!("{err}").contains("region"), "got: {err}");
    }

    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let err = apply_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }

    #[test]
    fn apply_from_ext_rejects_missing_required_field() {
        let json = r#"{"region":"us-east-1"}"#;
        let err = apply_from_ext(json, "{}", None).unwrap_err();
        // Use alternate display to include the full error chain (context + serde cause)
        let msg = format!("{err:#}");
        // serde error mentions missing field by name — either the Rust field or the JSON key
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
