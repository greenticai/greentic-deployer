use std::fs;
#[cfg(feature = "runtime-secrets-aws")]
use std::io::Write;
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
use crate::runtime_secrets::{
    PromoteRuntimeSecretsReport, ResolvedRuntimeSecret, default_cloud_secret_prefix,
    resolve_for_cloud_apply,
};

/// Library-facing request for the explicit AWS adapter surface.
#[derive(Debug, Clone)]
pub struct AwsRequest {
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
    pub redis_url: Option<String>,
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
            provider: Provider::Aws,
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
    promote_runtime_secrets_for_apply(&config).await?;
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
    promote_runtime_secrets_for_apply(&config).await?;
    multi_target::run_with_plan(config, plan).await
}

async fn promote_runtime_secrets_for_apply(config: &DeployerConfig) -> Result<()> {
    let Some(resolution) = resolve_for_cloud_apply(config).await? else {
        return Ok(());
    };
    let prefix = default_cloud_secret_prefix(&config.environment, &config.tenant, None);
    promote_to_aws_secrets_manager(
        &resolution.resolved,
        &prefix,
        config.bundle_digest.as_deref(),
        &config.environment,
        &config.tenant,
        None,
    )
    .await?;
    Ok(())
}

#[cfg(feature = "runtime-secrets-aws")]
async fn promote_to_aws_secrets_manager(
    resolved: &[ResolvedRuntimeSecret],
    prefix: &str,
    bundle_digest: Option<&str>,
    environment: &str,
    tenant: &str,
    team: Option<&str>,
) -> Result<PromoteRuntimeSecretsReport> {
    let sink = AwsCliSecretSink {
        region: aws_runtime_secrets_region(),
    };
    crate::runtime_secret_sink::promote_runtime_secrets(
        &sink,
        resolved,
        prefix,
        bundle_digest,
        environment,
        tenant,
        team.unwrap_or("_"),
        "aws",
        "aws-secrets-manager",
    )
}

/// [`RuntimeSecretSink`](crate::runtime_secret_sink::RuntimeSecretSink) backed by
/// the `aws secretsmanager` CLI. Kept thin so the promotion orchestration is
/// exercised against an in-memory mock instead of this.
#[cfg(feature = "runtime-secrets-aws")]
struct AwsCliSecretSink {
    region: String,
}

#[cfg(feature = "runtime-secrets-aws")]
impl crate::runtime_secret_sink::RuntimeSecretSink for AwsCliSecretSink {
    fn upsert(
        &self,
        name: &str,
        value: &str,
        tags: &[(String, String)],
    ) -> Result<crate::runtime_secret_sink::UpsertOutcome> {
        use crate::runtime_secret_sink::UpsertOutcome;

        let mut temp = tempfile::NamedTempFile::new()
            .map_err(|err| DeployerError::Other(format!("create temporary secret file: {err}")))?;
        temp.write_all(value.as_bytes())?;
        temp.flush()?;
        let secret_file = format!(
            "file://{}",
            temp.path().to_str().ok_or_else(|| {
                DeployerError::Other("temporary secret path is not UTF-8".to_string())
            })?
        );

        let mut create = ProcessCommand::new("aws");
        create.args([
            "secretsmanager",
            "create-secret",
            "--region",
            &self.region,
            "--name",
            name,
            "--secret-string",
            &secret_file,
        ]);
        // A single `--tags` with all tags: repeating the flag makes the AWS CLI
        // keep only the last one, which silently dropped every tag but one.
        if !tags.is_empty() {
            create.arg("--tags");
            for (key, value) in tags {
                create.arg(format!("Key={key},Value={value}"));
            }
        }

        let create = create
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| {
                DeployerError::Other(format!("run aws secretsmanager create-secret: {err}"))
            })?;
        if create.status.success() {
            return Ok(UpsertOutcome::Created);
        }

        let create_stderr = String::from_utf8_lossy(&create.stderr);
        if !create_stderr.contains("ResourceExistsException") {
            return Err(DeployerError::Other(format!(
                "create AWS Secrets Manager secret {name}: {}",
                create_stderr.trim()
            )));
        }

        let update = ProcessCommand::new("aws")
            .args([
                "secretsmanager",
                "put-secret-value",
                "--region",
                &self.region,
                "--secret-id",
                name,
                "--secret-string",
                &secret_file,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| {
                DeployerError::Other(format!("run aws secretsmanager put-secret-value: {err}"))
            })?;
        if update.status.success() {
            // put-secret-value updates the value but not tags, so a pre-existing
            // secret stays untagged (this is why `list-secrets --filters
            // tag-key=greentic:managed-by` came back empty). Apply tags
            // explicitly; this is best-effort metadata, so don't fail the deploy.
            if !tags.is_empty() {
                let mut tag = ProcessCommand::new("aws");
                tag.args([
                    "secretsmanager",
                    "tag-resource",
                    "--region",
                    &self.region,
                    "--secret-id",
                    name,
                    "--tags",
                ]);
                for (key, value) in tags {
                    tag.arg(format!("Key={key},Value={value}"));
                }
                match tag.stdout(Stdio::null()).stderr(Stdio::piped()).output() {
                    Ok(out) if out.status.success() => {}
                    Ok(out) => tracing::warn!(
                        secret = %name,
                        stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                        "failed to tag existing secret on update"
                    ),
                    Err(err) => tracing::warn!(
                        secret = %name,
                        %err,
                        "failed to invoke aws secretsmanager tag-resource"
                    ),
                }
            }
            Ok(UpsertOutcome::Updated)
        } else {
            Err(DeployerError::Other(format!(
                "update AWS Secrets Manager secret {name}: {}",
                String::from_utf8_lossy(&update.stderr).trim()
            )))
        }
    }
}

#[cfg(feature = "runtime-secrets-aws")]
fn aws_runtime_secrets_region() -> String {
    std::env::var("AWS_REGION")
        .ok()
        .filter(|region| !region.trim().is_empty())
        .or_else(|| {
            std::env::var("AWS_DEFAULT_REGION")
                .ok()
                .filter(|region| !region.trim().is_empty())
        })
        .or_else(aws_cli_config_region)
        .unwrap_or_else(|| "eu-north-1".to_string())
}

#[cfg(feature = "runtime-secrets-aws")]
fn aws_cli_config_region() -> Option<String> {
    let output = ProcessCommand::new("aws")
        .args(["configure", "get", "region"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let region = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!region.is_empty()).then_some(region)
}

#[cfg(not(feature = "runtime-secrets-aws"))]
async fn promote_to_aws_secrets_manager(
    _resolved: &[ResolvedRuntimeSecret],
    _prefix: &str,
    _bundle_digest: Option<&str>,
    _environment: &str,
    _tenant: &str,
    _team: Option<&str>,
) -> Result<PromoteRuntimeSecretsReport> {
    Err(DeployerError::Config(
        "AWS runtime secret promotion is not enabled".to_string(),
    ))
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

    use tempfile::tempdir;

    #[test]
    fn aws_request_defaults_to_aws_iac_target() {
        let request = AwsRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(PathBuf::from("pack-dir")),
        )
        .into_deployer_request();

        assert_eq!(request.provider, Provider::Aws);
        assert_eq!(request.strategy, "iac-only");
        assert_eq!(request.tenant, "acme");
    }

    #[test]
    fn aws_request_forwards_extra_env() {
        use std::collections::BTreeMap;
        let mut req = AwsRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(PathBuf::from("pack-dir")),
        );
        req.extra_env = BTreeMap::from([("AWS_ACCESS_KEY_ID".to_string(), "AKIA".to_string())]);
        let dr = req.into_deployer_request();
        assert_eq!(
            dr.extra_env.get("AWS_ACCESS_KEY_ID").map(String::as_str),
            Some("AKIA")
        );
    }

    #[test]
    fn aws_request_preserves_all_passthrough_fields() {
        let mut request = AwsRequest::new(
            DeployerCapability::Apply,
            "acme",
            Some(PathBuf::from("pack-dir")),
        );
        request.bundle_root = Some(PathBuf::from("bundle-root"));
        request.bundle_source = Some("s3://bucket/bundle.gtbundle".into());
        request.bundle_digest = Some("sha256:abc".into());
        request.repo_registry_base = Some("https://repo.example".into());
        request.store_registry_base = Some("https://store.example".into());
        request.provider_pack = Some(PathBuf::from("providers/deployer/aws.gtpack"));
        request.deploy_pack_id_override = Some("greentic.deploy.aws".into());
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
        assert_eq!(deployer.provider, Provider::Aws);
        assert_eq!(
            deployer.bundle_root.as_deref(),
            Some(Path::new("bundle-root"))
        );
        assert_eq!(
            deployer.bundle_source.as_deref(),
            Some("s3://bucket/bundle.gtbundle")
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
            Some(Path::new("providers/deployer/aws.gtpack"))
        );
        assert_eq!(
            deployer.deploy_pack_id_override.as_deref(),
            Some("greentic.deploy.aws")
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
            Some(Path::new("greentic.toml"))
        );
        assert!(deployer.allow_remote_in_offline);
        assert_eq!(deployer.providers_dir, PathBuf::from("providers"));
        assert_eq!(deployer.packs_dir, PathBuf::from("packs-dir"));
    }

    #[test]
    fn ensure_aws_config_rejects_non_aws_provider() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut request = AwsRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(tmp.path().to_path_buf()),
        )
        .into_deployer_request();
        request.provider = Provider::Gcp;
        let config = DeployerConfig::resolve(request).expect("resolve config");

        let err = ensure_aws_config(&config).expect_err("non-aws config should fail");
        assert!(
            err.to_string().contains("provider=gcp strategy=iac-only"),
            "got: {err}"
        );
    }

    #[test]
    fn ensure_aws_config_accepts_aws_iac_config() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let request = AwsRequest::new(
            DeployerCapability::Plan,
            "acme",
            Some(tmp.path().to_path_buf()),
        )
        .into_deployer_request();
        let config = DeployerConfig::resolve(request).expect("resolve config");

        ensure_aws_config(&config).expect("aws config");
    }

    #[test]
    fn build_aws_request_from_ext_maps_cloud_bundle_fields() {
        let cfg = AwsEcsFargateExtConfig {
            region: "eu-north-1".to_string(),
            environment: "prod".to_string(),
            operator_image_digest: "sha256:0000".to_string(),
            bundle_source: "oci://registry.example/acme/prod".to_string(),
            bundle_digest: "sha256:1111".to_string(),
            remote_state_backend: "s3://state/greentic/prod".to_string(),
            redis_url: Some("redis://cache.example:6379/0".to_string()),
            dns_name: Some("admin.example.com".to_string()),
            public_base_url: Some("https://admin.example.com".to_string()),
            repo_registry_base: Some("https://repo.example.com".to_string()),
            store_registry_base: Some("https://store.example.com".to_string()),
            admin_allowed_clients: Some("CN=admin".to_string()),
            tenant: "acme".to_string(),
        };

        let request =
            build_aws_request_from_ext(DeployerCapability::Destroy, &cfg, Some(Path::new("pack")));

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
        assert_eq!(request.providers_dir, PathBuf::from("providers/deployer"));
        assert_eq!(request.packs_dir, PathBuf::from("packs"));
    }

    #[test]
    fn build_aws_request_from_ext_uses_empty_pack_when_missing() {
        let cfg = AwsEcsFargateExtConfig {
            region: "eu-north-1".to_string(),
            environment: "dev".to_string(),
            operator_image_digest: "sha256:0000".to_string(),
            bundle_source: "s3://bucket/bundle.gtbundle".to_string(),
            bundle_digest: "sha256:1111".to_string(),
            remote_state_backend: "s3://state".to_string(),
            redis_url: None,
            dns_name: None,
            public_base_url: None,
            repo_registry_base: None,
            store_registry_base: None,
            admin_allowed_clients: None,
            tenant: default_ext_tenant(),
        };

        let request = build_aws_request_from_ext(DeployerCapability::Apply, &cfg, None);

        assert_eq!(request.capability, DeployerCapability::Apply);
        assert_eq!(request.tenant, "default");
        assert_eq!(request.pack_path, None);
        assert_eq!(
            request.bundle_source.as_deref(),
            Some("s3://bucket/bundle.gtbundle")
        );
        assert_eq!(request.bundle_digest.as_deref(), Some("sha256:1111"));
        assert!(request.repo_registry_base.is_none());
        assert!(request.store_registry_base.is_none());
        assert_eq!(request.output, OutputFormat::Text);
        assert!(request.execute_local);
        assert!(!request.preview);
        assert!(!request.dry_run);
    }

    #[test]
    fn run_admin_tunnel_reports_missing_admin_ca_before_aws_cli() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bundle_dir = tmp.path().join("bundle");
        let deploy_dir = bundle_dir
            .join(".greentic")
            .join("deploy")
            .join("aws")
            .join("acme")
            .join("staging");
        fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        fs::write(
            deploy_dir.join("terraform-outputs.json"),
            serde_json::to_vec_pretty(&serde_json::json!({})).expect("serialize outputs"),
        )
        .expect("write outputs");

        let err = run_admin_tunnel(AwsAdminTunnelRequest {
            bundle_dir: bundle_dir.clone(),
            local_port: "9443".to_string(),
            container: "operator".to_string(),
        })
        .expect_err("missing ca ref should fail");

        assert!(
            err.to_string().contains("missing admin_ca_secret_ref"),
            "got: {err}"
        );
    }

    #[test]
    fn run_admin_tunnel_rejects_malformed_admin_ca_ref_before_aws_cli() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bundle_dir = tmp.path().join("bundle");
        let deploy_dir = bundle_dir
            .join(".greentic")
            .join("deploy")
            .join("aws")
            .join("acme")
            .join("staging");
        fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        fs::write(
            deploy_dir.join("terraform-outputs.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "admin_ca_secret_ref": { "value": "not-an-arn" }
            }))
            .expect("serialize outputs"),
        )
        .expect("write outputs");

        let err = run_admin_tunnel(AwsAdminTunnelRequest {
            bundle_dir,
            local_port: "9443".to_string(),
            container: "operator".to_string(),
        })
        .expect_err("malformed ca ref should fail");

        assert!(
            err.to_string().contains("failed to derive AWS region"),
            "got: {err}"
        );
    }

    #[test]
    fn aws_admin_tunnel_helpers_parse_secret_and_task_refs() {
        let secret_arn =
            "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/acme-prod/ca";
        assert_eq!(
            aws_region_from_secret_arn(secret_arn).as_deref(),
            Some("eu-north-1")
        );
        assert_eq!(
            deploy_name_prefix_from_secret_arn(secret_arn).as_deref(),
            Some("acme-prod")
        );
        assert_eq!(
            deploy_name_prefix_from_secret_arn(
                "arn:aws:secretsmanager:eu-north-1:123:secret:other/path"
            ),
            None
        );
        assert_eq!(
            deploy_name_prefix_from_secret_arn(
                "arn:aws:secretsmanager:eu-north-1:123:secret:greentic/admin//ca"
            ),
            None
        );
        assert_eq!(aws_region_from_secret_arn("not-an-arn"), None);
        assert_eq!(
            aws_region_from_secret_arn("arn:aws:secretsmanager::123:secret:name").as_deref(),
            Some("")
        );
        assert_eq!(
            task_id_from_arn("arn:aws:ecs:eu-north-1:123456789012:task/acme-prod-cluster/abc123")
                .as_deref(),
            Some("abc123")
        );
        assert_eq!(task_id_from_arn("abc123").as_deref(), Some("abc123"));
        assert_eq!(task_id_from_arn("cluster/").as_deref(), Some(""));
    }

    #[test]
    fn maybe_write_tunnel_admin_certs_skips_when_refs_are_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let outputs = serde_json::json!({
            "admin_ca_secret_ref": {
                "value": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/acme-prod/ca"
            }
        });

        maybe_write_tunnel_admin_certs(tmp.path(), &outputs, "eu-north-1", "acme-prod")
            .expect("missing optional refs should skip");

        assert!(!tunnel_admin_cert_dir(tmp.path(), "acme-prod").exists());
    }

    #[test]
    fn maybe_write_tunnel_admin_certs_skips_for_each_missing_ref() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ca_ref =
            "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/acme-prod/ca";
        let cert_ref = "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/acme-prod/client-cert";
        let key_ref = "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/acme-prod/client-key";

        for outputs in [
            serde_json::json!({
                "admin_client_cert_secret_ref": { "value": cert_ref },
                "admin_client_key_secret_ref": { "value": key_ref }
            }),
            serde_json::json!({
                "admin_client_cert_secret_ref": { "value": cert_ref },
                "admin_ca_secret_ref": { "value": ca_ref }
            }),
            serde_json::json!({
                "admin_client_key_secret_ref": { "value": key_ref },
                "admin_ca_secret_ref": { "value": ca_ref }
            }),
        ] {
            maybe_write_tunnel_admin_certs(tmp.path(), &outputs, "eu-north-1", "acme-prod")
                .expect("incomplete cert refs should skip without shelling out");
        }

        assert!(!tunnel_admin_cert_dir(tmp.path(), "acme-prod").exists());
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
        assert!(cfg.redis_url.is_none());
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
            "redisUrl": "redis://shared.example.com:6379/0",
            "dnsName": "api.example.com",
            "publicBaseUrl": "https://api.example.com",
            "repoRegistryBase": "https://repo.example.com",
            "storeRegistryBase": "https://store.example.com",
            "adminAllowedClients": "CN=admin",
            "tenant": "acme"
        }"#;
        let cfg: AwsEcsFargateExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg.redis_url.as_deref(),
            Some("redis://shared.example.com:6379/0")
        );
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

    #[test]
    fn destroy_from_ext_rejects_missing_required_field() {
        let json = r#"{"region":"eu-north-1"}"#;
        let err = destroy_from_ext(json, "{}", None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing field")
                || msg.contains("bundleSource")
                || msg.contains("bundle_source"),
            "got: {msg}"
        );
    }

    #[test]
    fn build_aws_request_from_ext_populates_extension_fields() {
        let cfg = AwsEcsFargateExtConfig {
            region: "eu-north-1".to_string(),
            environment: "prod".to_string(),
            operator_image_digest: "sha256:deadbeef".to_string(),
            bundle_source: "oci://registry.example/app@sha256:1111".to_string(),
            bundle_digest: "sha256:2222".to_string(),
            remote_state_backend: "s3://demo/state".to_string(),
            redis_url: None,
            dns_name: Some("api.example.com".to_string()),
            public_base_url: Some("https://api.example.com".to_string()),
            repo_registry_base: Some("https://repo.example.com".to_string()),
            store_registry_base: Some("https://store.example.com".to_string()),
            admin_allowed_clients: Some("CN=admin".to_string()),
            tenant: "acme".to_string(),
        };

        let request = build_aws_request_from_ext(
            DeployerCapability::Destroy,
            &cfg,
            Some(Path::new("/tmp/demo-pack")),
        );

        assert_eq!(request.capability, DeployerCapability::Destroy);
        assert_eq!(request.tenant, "acme");
        assert_eq!(request.pack_path, Some(PathBuf::from("/tmp/demo-pack")));
        assert_eq!(
            request.bundle_source.as_deref(),
            Some("oci://registry.example/app@sha256:1111")
        );
        assert_eq!(request.bundle_digest.as_deref(), Some("sha256:2222"));
        assert_eq!(request.environment.as_deref(), Some("prod"));
        assert_eq!(
            request.repo_registry_base.as_deref(),
            Some("https://repo.example.com")
        );
        assert_eq!(
            request.store_registry_base.as_deref(),
            Some("https://store.example.com")
        );
        assert!(request.execute_local);
        assert_eq!(request.output, OutputFormat::Text);
    }

    #[test]
    fn helper_parsers_extract_expected_aws_values() {
        assert_eq!(
            aws_region_from_secret_arn(
                "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/demo/ca"
            )
            .as_deref(),
            Some("eu-north-1")
        );
        assert_eq!(aws_region_from_secret_arn("invalid"), None);

        assert_eq!(
            deploy_name_prefix_from_secret_arn(
                "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/demo/ca"
            )
            .as_deref(),
            Some("demo")
        );
        assert_eq!(
            deploy_name_prefix_from_secret_arn(
                "arn:aws:secretsmanager:eu-north-1:123456789012:secret:other/demo/ca"
            ),
            None
        );

        assert_eq!(
            task_id_from_arn("arn:aws:ecs:eu-north-1:123456789012:task/demo-cluster/task-123")
                .as_deref(),
            Some("task-123")
        );
    }

    #[test]
    fn maybe_write_tunnel_admin_certs_skips_when_secret_refs_are_missing() {
        let temp = tempdir().expect("tempdir");
        let outputs = serde_json::json!({
            "admin_ca_secret_ref": {
                "value": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/demo/ca"
            }
        });

        maybe_write_tunnel_admin_certs(temp.path(), &outputs, "eu-north-1", "demo")
            .expect("skip missing refs");

        assert!(!tunnel_admin_cert_dir(temp.path(), "demo").exists());
    }

    #[test]
    fn run_admin_tunnel_reports_missing_admin_ca_secret_ref() {
        let temp = tempdir().expect("tempdir");
        let bundle_dir = temp.path().join("bundle");
        let deploy_dir = bundle_dir
            .join(".greentic")
            .join("deploy")
            .join("aws")
            .join("demo")
            .join("state");
        fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        fs::write(deploy_dir.join("terraform-outputs.json"), b"{}").expect("write outputs");

        let err = run_admin_tunnel(AwsAdminTunnelRequest {
            bundle_dir,
            local_port: "8443".to_string(),
            container: "app".to_string(),
        })
        .unwrap_err();

        assert!(format!("{err}").contains("missing admin_ca_secret_ref"));
    }

    #[test]
    fn run_admin_tunnel_rejects_secret_refs_without_deploy_prefix() {
        let temp = tempdir().expect("tempdir");
        let bundle_dir = temp.path().join("bundle");
        let deploy_dir = bundle_dir
            .join(".greentic")
            .join("deploy")
            .join("aws")
            .join("demo")
            .join("state");
        fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        fs::write(
            deploy_dir.join("terraform-outputs.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "admin_ca_secret_ref": {
                    "value": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:other/demo/ca"
                }
            }))
            .expect("serialize outputs"),
        )
        .expect("write outputs");

        let err = run_admin_tunnel(AwsAdminTunnelRequest {
            bundle_dir,
            local_port: "8443".to_string(),
            container: "app".to_string(),
        })
        .unwrap_err();

        assert!(format!("{err}").contains("failed to derive deploy name prefix"));
    }

    #[test]
    fn run_admin_tunnel_rejects_secret_refs_without_region() {
        let temp = tempdir().expect("tempdir");
        let bundle_dir = temp.path().join("bundle");
        let deploy_dir = bundle_dir
            .join(".greentic")
            .join("deploy")
            .join("aws")
            .join("demo")
            .join("state");
        fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        fs::write(
            deploy_dir.join("terraform-outputs.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "admin_ca_secret_ref": {
                    "value": "invalid-secret-ref"
                }
            }))
            .expect("serialize outputs"),
        )
        .expect("write outputs");

        let err = run_admin_tunnel(AwsAdminTunnelRequest {
            bundle_dir,
            local_port: "8443".to_string(),
            container: "app".to_string(),
        })
        .unwrap_err();

        assert!(format!("{err}").contains("failed to derive AWS region"));
    }
}
