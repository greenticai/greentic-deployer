use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

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
    let deploy_dir = resolve_latest_aws_deploy_dir(&args.bundle_dir)?;
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

fn resolve_latest_aws_deploy_dir(bundle_dir: &Path) -> Result<PathBuf> {
    let mut candidates = vec![bundle_dir.join(".greentic").join("deploy").join("aws")];
    if let Some(parent) = bundle_dir.parent() {
        candidates.push(parent.join(".greentic").join("deploy").join("aws"));
    }
    if let Some(home_dir) = env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home_dir)
                .join(".greentic")
                .join("deploy")
                .join("aws"),
        );
    }
    let mut latest: Option<(SystemTime, PathBuf)> = None;
    for root in candidates {
        if root.as_os_str().is_empty() || !root.exists() {
            continue;
        }
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(&dir)?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let outputs = path.join("terraform-outputs.json");
                    if outputs.is_file() {
                        let modified = fs::metadata(&outputs)
                            .and_then(|meta| meta.modified())
                            .unwrap_or(UNIX_EPOCH);
                        match latest.as_ref() {
                            Some((current, _)) if modified <= *current => {}
                            _ => latest = Some((modified, path.clone())),
                        }
                    }
                    stack.push(path);
                }
            }
        }
    }

    latest.map(|(_, path)| path).ok_or_else(|| {
        DeployerError::Other(format!(
            "aws deploy state not found under {}, its parent workspace, or ~/.greentic/deploy/aws; deploy the bundle first",
            bundle_dir.join(".greentic").join("deploy").join("aws").display()
        ))
    })
}

fn load_terraform_outputs(path: &Path) -> Result<Value> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn terraform_output_string(outputs: &Value, key: &str) -> Option<String> {
    outputs
        .get(key)
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str)
        .map(|value| value.to_string())
}

fn aws_region_from_secret_arn(secret_arn: &str) -> Option<String> {
    secret_arn.split(':').nth(3).map(|value| value.to_string())
}

fn tunnel_admin_cert_dir(bundle_dir: &Path, deploy_name_prefix: &str) -> PathBuf {
    bundle_dir
        .join(".greentic")
        .join("admin")
        .join("tunnels")
        .join(deploy_name_prefix)
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
}
