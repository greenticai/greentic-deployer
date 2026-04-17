use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml_bw as serde_yaml;

use crate::config::{OutputFormat, Provider};
use crate::error::{DeployerError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminSecretRefs {
    pub admin_ca_secret_ref: Option<String>,
    pub admin_server_cert_secret_ref: Option<String>,
    pub admin_server_key_secret_ref: Option<String>,
    pub admin_client_cert_secret_ref: Option<String>,
    pub admin_client_key_secret_ref: Option<String>,
    pub admin_relay_token_secret_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdminAccessMode {
    AwsSsmPortForward,
    LoopbackOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminTunnelSupport {
    pub supported: bool,
    pub mode: Option<AdminAccessMode>,
    pub reason: Option<String>,
    pub command_hint: Option<String>,
    pub local_port_default: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminAccessInfo {
    pub provider: String,
    pub bundle_dir: PathBuf,
    pub deploy_dir: PathBuf,
    pub local_cert_dir: PathBuf,
    pub admin_access_mode: Option<String>,
    pub admin_public_endpoint: Option<String>,
    pub operator_endpoint: Option<String>,
    pub deployment_name_prefix: Option<String>,
    pub operator_host: Option<String>,
    pub provider_details: AdminProviderDetails,
    pub admin_listener: String,
    pub admin_secret_refs: AdminSecretRefs,
    pub client_credentials_available: bool,
    pub missing_requirements: Vec<String>,
    pub tunnel_support: AdminTunnelSupport,
    pub suggested_commands: Vec<String>,
    pub curl_health_example: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaterializedAdminCerts {
    pub provider: String,
    pub cert_dir: PathBuf,
    pub ca_cert_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaterializedAdminRelayToken {
    pub provider: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminHealthProbe {
    pub provider: String,
    pub endpoint: String,
    pub status: u16,
    pub ok: bool,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AdminProviderDetails {
    pub aws_region: Option<String>,
    pub aws_cluster_name: Option<String>,
    pub aws_service_name: Option<String>,
    pub azure_resource_group_name: Option<String>,
    pub azure_container_app_name: Option<String>,
    pub gcp_project_id: Option<String>,
    pub gcp_cloud_run_service_name: Option<String>,
}

pub fn resolve_admin_access(bundle_dir: &Path, provider: Provider) -> Result<AdminAccessInfo> {
    match provider {
        Provider::Aws => resolve_provider_admin_access(bundle_dir, "aws", provider),
        Provider::Azure => resolve_provider_admin_access(bundle_dir, "azure", provider),
        Provider::Gcp => resolve_provider_admin_access(bundle_dir, "gcp", provider),
        other => Err(DeployerError::Other(format!(
            "admin access is only available for cloud providers (aws, azure, gcp), got {}",
            other.as_str()
        ))),
    }
}

pub fn render_admin_access(info: &AdminAccessInfo, output: OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Text => Ok(render_admin_access_text(info)),
        OutputFormat::Json => {
            serde_json::to_string_pretty(info).map_err(|err| DeployerError::Other(err.to_string()))
        }
        OutputFormat::Yaml => {
            serde_yaml::to_string(info).map_err(|err| DeployerError::Other(err.to_string()))
        }
    }
}

pub fn materialize_admin_client_certs(
    bundle_dir: &Path,
    provider: Provider,
) -> Result<MaterializedAdminCerts> {
    let info = resolve_admin_access(bundle_dir, provider)?;
    let cert_dir = local_admin_cert_dir(&info);
    fs::create_dir_all(&cert_dir)?;

    let ca_ref = info
        .admin_secret_refs
        .admin_ca_secret_ref
        .as_deref()
        .ok_or_else(|| DeployerError::Other("missing admin_ca_secret_ref".to_string()))?;
    let client_cert_ref = info
        .admin_secret_refs
        .admin_client_cert_secret_ref
        .as_deref()
        .ok_or_else(|| DeployerError::Other("missing admin_client_cert_secret_ref".to_string()))?;
    let client_key_ref = info
        .admin_secret_refs
        .admin_client_key_secret_ref
        .as_deref()
        .ok_or_else(|| DeployerError::Other("missing admin_client_key_secret_ref".to_string()))?;

    fs::write(
        cert_dir.join("ca.crt"),
        fetch_secret_value(provider, ca_ref, &info)?,
    )?;
    fs::write(
        cert_dir.join("client.crt"),
        fetch_secret_value(provider, client_cert_ref, &info)?,
    )?;
    fs::write(
        cert_dir.join("client.key"),
        fetch_secret_value(provider, client_key_ref, &info)?,
    )?;

    Ok(MaterializedAdminCerts {
        provider: provider.as_str().to_string(),
        cert_dir: cert_dir.clone(),
        ca_cert_path: cert_dir.join("ca.crt"),
        client_cert_path: cert_dir.join("client.crt"),
        client_key_path: cert_dir.join("client.key"),
    })
}

pub fn render_materialized_admin_certs(
    value: &MaterializedAdminCerts,
    output: OutputFormat,
) -> Result<String> {
    match output {
        OutputFormat::Text => Ok(format!(
            "provider: {}\ncert_dir: {}\nca_cert_path: {}\nclient_cert_path: {}\nclient_key_path: {}",
            value.provider,
            value.cert_dir.display(),
            value.ca_cert_path.display(),
            value.client_cert_path.display(),
            value.client_key_path.display()
        )),
        OutputFormat::Json => {
            serde_json::to_string_pretty(value).map_err(|err| DeployerError::Other(err.to_string()))
        }
        OutputFormat::Yaml => {
            serde_yaml::to_string(value).map_err(|err| DeployerError::Other(err.to_string()))
        }
    }
}

pub fn materialize_admin_relay_token(bundle_dir: &Path, provider: Provider) -> Result<String> {
    let info = resolve_admin_access(bundle_dir, provider)?;
    let token_ref = info
        .admin_secret_refs
        .admin_relay_token_secret_ref
        .as_deref()
        .ok_or_else(|| DeployerError::Other("missing admin_relay_token_secret_ref".to_string()))?;
    fetch_secret_value(provider, token_ref, &info)
}

pub fn render_materialized_admin_relay_token(
    provider: Provider,
    _token: &str,
    output: OutputFormat,
) -> Result<String> {
    let value = MaterializedAdminRelayToken {
        provider: provider.as_str().to_string(),
        token: "[REDACTED]".to_string(),
    };
    match output {
        OutputFormat::Text => Ok("[REDACTED]".to_string()),
        OutputFormat::Json => serde_json::to_string_pretty(&value)
            .map_err(|err| DeployerError::Other(err.to_string())),
        OutputFormat::Yaml => {
            serde_yaml::to_string(&value).map_err(|err| DeployerError::Other(err.to_string()))
        }
    }
}

pub fn probe_admin_health(bundle_dir: &Path, provider: Provider) -> Result<AdminHealthProbe> {
    let info = resolve_admin_access(bundle_dir, provider)?;
    let endpoint = info
        .admin_public_endpoint
        .clone()
        .ok_or_else(|| DeployerError::Other("missing admin_public_endpoint".to_string()))?;
    let token = materialize_admin_relay_token(bundle_dir, provider)?;
    let url = format!("{}/health", endpoint.trim_end_matches('/'));
    let response = reqwest::blocking::Client::builder()
        .build()
        .map_err(|err| DeployerError::Other(format!("build admin health client: {err}")))?
        .get(&url)
        .bearer_auth(token)
        .send()
        .map_err(|err| DeployerError::Other(format!("request admin health endpoint: {err}")))?;
    let status = response.status().as_u16();
    let ok = response.status().is_success();
    let body = response
        .text()
        .map_err(|err| DeployerError::Other(format!("read admin health response: {err}")))?;

    Ok(AdminHealthProbe {
        provider: provider.as_str().to_string(),
        endpoint: url,
        status,
        ok,
        body,
    })
}

pub fn render_admin_health_probe(value: &AdminHealthProbe, output: OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Text => Ok(format!(
            "provider: {}\nendpoint: {}\nstatus: {}\nok: {}\nbody: {}",
            value.provider, value.endpoint, value.status, value.ok, value.body
        )),
        OutputFormat::Json => {
            serde_json::to_string_pretty(value).map_err(|err| DeployerError::Other(err.to_string()))
        }
        OutputFormat::Yaml => {
            serde_yaml::to_string(value).map_err(|err| DeployerError::Other(err.to_string()))
        }
    }
}

pub(crate) fn resolve_latest_deploy_dir(bundle_dir: &Path, provider: &str) -> Result<PathBuf> {
    let mut candidates = Vec::new();
    for ancestor in bundle_dir.ancestors() {
        candidates.push(ancestor.join(".greentic").join("deploy").join(provider));
    }
    if let Some(home_dir) = env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home_dir)
                .join(".greentic")
                .join("deploy")
                .join(provider),
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
            "{} deploy state not found under {} or any parent workspace .greentic/deploy/{}, or ~/.greentic/deploy/{}; deploy the bundle first",
            provider,
            bundle_dir.join(".greentic").join("deploy").join(provider).display(),
            provider,
            provider
        ))
    })
}

pub(crate) fn load_terraform_outputs(path: &Path) -> Result<Value> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub(crate) fn terraform_output_string(outputs: &Value, key: &str) -> Option<String> {
    outputs
        .get(key)
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str)
        .map(|value| value.to_string())
}

pub(crate) fn tunnel_admin_cert_dir(bundle_dir: &Path, deploy_name_prefix: &str) -> PathBuf {
    bundle_dir
        .join(".greentic")
        .join("admin")
        .join("tunnels")
        .join(deploy_name_prefix)
}

fn resolve_provider_admin_access(
    bundle_dir: &Path,
    provider_name: &str,
    provider: Provider,
) -> Result<AdminAccessInfo> {
    let deploy_dir = resolve_latest_deploy_dir(bundle_dir, provider_name)?;
    let outputs = load_terraform_outputs(&deploy_dir.join("terraform-outputs.json"))?;
    let deployment_name_prefix = deployment_name_prefix(&outputs, provider);
    let operator_host = operator_host(&outputs);
    let local_cert_dir = local_admin_cert_dir_for_values(
        bundle_dir,
        deployment_name_prefix.as_deref(),
        operator_host.as_deref(),
        provider.as_str(),
    );

    Ok(AdminAccessInfo {
        provider: provider.as_str().to_string(),
        bundle_dir: bundle_dir.to_path_buf(),
        deploy_dir,
        local_cert_dir,
        admin_access_mode: terraform_output_string(&outputs, "admin_access_mode"),
        admin_public_endpoint: terraform_output_string(&outputs, "admin_public_endpoint"),
        operator_endpoint: terraform_output_string(&outputs, "operator_endpoint"),
        deployment_name_prefix,
        operator_host,
        provider_details: provider_details(&outputs, provider),
        admin_listener: "127.0.0.1:8433".to_string(),
        admin_secret_refs: AdminSecretRefs {
            admin_ca_secret_ref: terraform_output_string(&outputs, "admin_ca_secret_ref"),
            admin_server_cert_secret_ref: terraform_output_string(
                &outputs,
                "admin_server_cert_secret_ref",
            ),
            admin_server_key_secret_ref: terraform_output_string(
                &outputs,
                "admin_server_key_secret_ref",
            ),
            admin_client_cert_secret_ref: terraform_output_string(
                &outputs,
                "admin_client_cert_secret_ref",
            ),
            admin_client_key_secret_ref: terraform_output_string(
                &outputs,
                "admin_client_key_secret_ref",
            ),
            admin_relay_token_secret_ref: terraform_output_string(
                &outputs,
                "admin_relay_token_secret_ref",
            ),
        },
        client_credentials_available: client_credentials_available(&outputs),
        missing_requirements: missing_requirements(&outputs, provider),
        tunnel_support: tunnel_support_for_provider(provider),
        suggested_commands: suggested_commands(&outputs, provider),
        curl_health_example: curl_health_example(provider),
        notes: notes_for_provider(provider),
    })
}

fn deployment_name_prefix(outputs: &Value, provider: Provider) -> Option<String> {
    let admin_ca_ref = terraform_output_string(outputs, "admin_ca_secret_ref")?;
    match provider {
        Provider::Aws => deploy_name_prefix_from_aws_secret_arn(&admin_ca_ref),
        Provider::Azure => deploy_name_prefix_from_azure_secret_ref(&admin_ca_ref),
        Provider::Gcp => deploy_name_prefix_from_gcp_secret_ref(&admin_ca_ref),
        _ => None,
    }
}

fn operator_host(outputs: &Value) -> Option<String> {
    let endpoint = terraform_output_string(outputs, "operator_endpoint")?;
    host_from_url(&endpoint)
}

fn provider_details(outputs: &Value, provider: Provider) -> AdminProviderDetails {
    let deployment_name_prefix = deployment_name_prefix(outputs, provider);
    let operator_host = operator_host(outputs);
    let admin_ca_ref = terraform_output_string(outputs, "admin_ca_secret_ref");

    match provider {
        Provider::Aws => {
            let aws_region = admin_ca_ref.as_deref().and_then(aws_region_from_secret_arn);
            let aws_cluster_name = deployment_name_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}-cluster"));
            let aws_service_name = deployment_name_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}-service"));
            AdminProviderDetails {
                aws_region,
                aws_cluster_name,
                aws_service_name,
                ..Default::default()
            }
        }
        Provider::Azure => {
            let azure_resource_group_name = deployment_name_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}-rg"));
            let azure_container_app_name = operator_host
                .as_deref()
                .and_then(azure_container_app_name_from_host)
                .or_else(|| {
                    deployment_name_prefix
                        .as_ref()
                        .map(|prefix| format!("{prefix}-app"))
                });
            AdminProviderDetails {
                azure_resource_group_name,
                azure_container_app_name,
                ..Default::default()
            }
        }
        Provider::Gcp => {
            let gcp_project_id = admin_ca_ref
                .as_deref()
                .and_then(gcp_project_id_from_secret_ref);
            let gcp_cloud_run_service_name = operator_host
                .as_deref()
                .and_then(gcp_cloud_run_service_name_from_host)
                .or_else(|| {
                    deployment_name_prefix
                        .as_ref()
                        .map(|prefix| format!("{prefix}-run"))
                });
            AdminProviderDetails {
                gcp_project_id,
                gcp_cloud_run_service_name,
                ..Default::default()
            }
        }
        _ => AdminProviderDetails::default(),
    }
}

fn tunnel_support_for_provider(provider: Provider) -> AdminTunnelSupport {
    match provider {
        Provider::Aws => AdminTunnelSupport {
            supported: true,
            mode: Some(AdminAccessMode::AwsSsmPortForward),
            reason: None,
            command_hint: Some(
                "greentic-deployer aws admin-tunnel --bundle-dir <BUNDLE_DIR> --local-port 8443"
                    .to_string(),
            ),
            local_port_default: 8443,
        },
        Provider::Azure => AdminTunnelSupport {
            supported: false,
            mode: Some(AdminAccessMode::LoopbackOnly),
            reason: Some(
                "the admin server stays loopback-only inside Azure Container Apps; use the public HTTPS admin relay instead of a direct tunnel".to_string(),
            ),
            command_hint: None,
            local_port_default: 8443,
        },
        Provider::Gcp => AdminTunnelSupport {
            supported: false,
            mode: Some(AdminAccessMode::LoopbackOnly),
            reason: Some(
                "the admin server stays loopback-only inside Cloud Run; use the public HTTPS admin relay instead of a direct tunnel".to_string(),
            ),
            command_hint: None,
            local_port_default: 8443,
        },
        _ => AdminTunnelSupport {
            supported: false,
            mode: None,
            reason: Some("admin access is only defined for cloud deployment targets".to_string()),
            command_hint: None,
            local_port_default: 8443,
        },
    }
}

fn notes_for_provider(provider: Provider) -> Vec<String> {
    match provider {
        Provider::Aws => vec![
            "AWS admin access is currently implemented through ECS Exec / SSM port forwarding."
                .to_string(),
            "The admin endpoint itself remains mTLS-protected and loopback-bound in the runtime."
                .to_string(),
        ],
        Provider::Azure => vec![
            "Azure deploys the admin server inside Container Apps with a loopback-only listener."
                .to_string(),
            "greentic-start now exposes a public HTTPS admin relay path guarded by a bearer token and an internal mTLS hop.".to_string(),
            "Direct Azure tunnel parity with AWS SSM is still not implemented.".to_string(),
        ],
        Provider::Gcp => vec![
            "GCP deploys the admin server inside Cloud Run with a loopback-only listener."
                .to_string(),
            "greentic-start now exposes a public HTTPS admin relay path guarded by a bearer token and an internal mTLS hop.".to_string(),
            "Direct GCP tunnel parity with AWS SSM is still not implemented.".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn client_credentials_available(outputs: &Value) -> bool {
    terraform_output_string(outputs, "admin_client_cert_secret_ref").is_some()
        && terraform_output_string(outputs, "admin_client_key_secret_ref").is_some()
}

fn missing_requirements(outputs: &Value, provider: Provider) -> Vec<String> {
    let mut missing = Vec::new();
    let has_public_relay = matches!(provider, Provider::Azure | Provider::Gcp)
        && terraform_output_string(outputs, "admin_public_endpoint").is_some()
        && terraform_output_string(outputs, "admin_relay_token_secret_ref").is_some();
    if terraform_output_string(outputs, "admin_client_cert_secret_ref").is_none() {
        missing.push("admin client certificate reference".to_string());
    }
    if terraform_output_string(outputs, "admin_client_key_secret_ref").is_none() {
        missing.push("admin client key reference".to_string());
    }
    if matches!(provider, Provider::Azure | Provider::Gcp)
        && terraform_output_string(outputs, "admin_relay_token_secret_ref").is_none()
    {
        missing.push("admin relay token secret reference".to_string());
    }
    if matches!(provider, Provider::Azure | Provider::Gcp)
        && terraform_output_string(outputs, "admin_public_endpoint").is_none()
    {
        missing.push("public admin relay endpoint".to_string());
    }
    if !(tunnel_support_for_provider(provider).supported || has_public_relay) {
        missing.push("cloud-side tunnel or controlled admin access path".to_string());
    }
    missing
}

fn suggested_commands(outputs: &Value, provider: Provider) -> Vec<String> {
    let details = provider_details(outputs, provider);
    let mut commands = Vec::new();

    match provider {
        Provider::Aws => {
            commands
                .push("greentic-deployer aws admin-certs --bundle-dir <BUNDLE_DIR>".to_string());
            if let (Some(region), Some(cluster), Some(service)) = (
                details.aws_region.as_deref(),
                details.aws_cluster_name.as_deref(),
                details.aws_service_name.as_deref(),
            ) {
                commands.push(format!(
                    "aws ecs list-tasks --region {region} --cluster {cluster} --service-name {service}"
                ));
                commands.push(
                    "greentic-deployer aws admin-tunnel --bundle-dir <BUNDLE_DIR> --local-port 8443"
                        .to_string(),
                );
                commands.push(
                    "curl --cacert <CERT_DIR>/ca.crt --cert <CERT_DIR>/client.crt --key <CERT_DIR>/client.key https://127.0.0.1:8443/admin/v1/health".to_string(),
                );
            }
        }
        Provider::Azure => {
            commands
                .push("greentic-deployer azure admin-certs --bundle-dir <BUNDLE_DIR>".to_string());
            commands
                .push("greentic-deployer azure admin-token --bundle-dir <BUNDLE_DIR>".to_string());
            if let Some(app_name) = details.azure_container_app_name.as_deref() {
                let resource_group = details.azure_resource_group_name.clone().or_else(|| {
                    app_name
                        .strip_suffix("-app")
                        .map(|prefix| format!("{prefix}-rg"))
                });
                if let Some(resource_group) = resource_group {
                    commands.push(format!(
                        "az containerapp show --resource-group {resource_group} --name {app_name}"
                    ));
                    commands.push(format!(
                        "az containerapp logs show --resource-group {resource_group} --name {app_name} --follow"
                    ));
                }
            }
        }
        Provider::Gcp => {
            commands
                .push("greentic-deployer gcp admin-certs --bundle-dir <BUNDLE_DIR>".to_string());
            commands
                .push("greentic-deployer gcp admin-token --bundle-dir <BUNDLE_DIR>".to_string());
            if let (Some(project_id), Some(service_name)) = (
                details.gcp_project_id.as_deref(),
                details.gcp_cloud_run_service_name.as_deref(),
            ) {
                commands.push(format!(
                    "gcloud run services describe {service_name} --project {project_id}"
                ));
                commands.push(format!(
                    "gcloud run services logs read {service_name} --project {project_id} --region us-central1"
                ));
            }
        }
        _ => {}
    }

    commands
}

fn curl_health_example(provider: Provider) -> Option<String> {
    match provider {
        Provider::Aws => Some(
            "curl --cacert <CERT_DIR>/ca.crt --cert <CERT_DIR>/client.crt --key <CERT_DIR>/client.key https://127.0.0.1:8443/admin/v1/health".to_string(),
        ),
        Provider::Azure | Provider::Gcp => Some(
            "curl -H 'Authorization: Bearer <TOKEN>' <ADMIN_PUBLIC_ENDPOINT>/health".to_string(),
        ),
        _ => None,
    }
}

fn render_admin_access_text(info: &AdminAccessInfo) -> String {
    let mut lines = vec![
        format!("provider: {}", info.provider),
        format!("bundle_dir: {}", info.bundle_dir.display()),
        format!("deploy_dir: {}", info.deploy_dir.display()),
        format!("local_cert_dir: {}", info.local_cert_dir.display()),
        format!(
            "admin_access_mode: {}",
            info.admin_access_mode.as_deref().unwrap_or("(missing)")
        ),
        format!(
            "admin_public_endpoint: {}",
            info.admin_public_endpoint.as_deref().unwrap_or("(missing)")
        ),
        format!(
            "operator_endpoint: {}",
            info.operator_endpoint.as_deref().unwrap_or("(missing)")
        ),
        format!(
            "operator_host: {}",
            info.operator_host.as_deref().unwrap_or("(missing)")
        ),
        format!(
            "deployment_name_prefix: {}",
            info.deployment_name_prefix
                .as_deref()
                .unwrap_or("(missing)")
        ),
        format!("admin_listener: {}", info.admin_listener),
        format!(
            "client_credentials_available: {}",
            info.client_credentials_available
        ),
        format!("tunnel_supported: {}", info.tunnel_support.supported),
    ];

    if let Some(mode) = &info.tunnel_support.mode {
        lines.push(format!("tunnel_mode: {:?}", mode));
    }
    if let Some(reason) = &info.tunnel_support.reason {
        lines.push(format!("tunnel_reason: {reason}"));
    }
    if let Some(command_hint) = &info.tunnel_support.command_hint {
        lines.push(format!("command_hint: {command_hint}"));
    }
    if let Some(example) = &info.curl_health_example {
        lines.push(format!("curl_health_example: {example}"));
    }

    for (label, value) in [
        (
            "admin_ca_secret_ref",
            info.admin_secret_refs.admin_ca_secret_ref.as_deref(),
        ),
        (
            "admin_server_cert_secret_ref",
            info.admin_secret_refs
                .admin_server_cert_secret_ref
                .as_deref(),
        ),
        (
            "admin_server_key_secret_ref",
            info.admin_secret_refs
                .admin_server_key_secret_ref
                .as_deref(),
        ),
        (
            "admin_client_cert_secret_ref",
            info.admin_secret_refs
                .admin_client_cert_secret_ref
                .as_deref(),
        ),
        (
            "admin_client_key_secret_ref",
            info.admin_secret_refs
                .admin_client_key_secret_ref
                .as_deref(),
        ),
        (
            "admin_relay_token_secret_ref",
            info.admin_secret_refs
                .admin_relay_token_secret_ref
                .as_deref(),
        ),
    ] {
        lines.push(format!("{}: {}", label, value.unwrap_or("(missing)")));
    }

    for (label, value) in [
        ("aws_region", info.provider_details.aws_region.as_deref()),
        (
            "aws_cluster_name",
            info.provider_details.aws_cluster_name.as_deref(),
        ),
        (
            "aws_service_name",
            info.provider_details.aws_service_name.as_deref(),
        ),
        (
            "azure_resource_group_name",
            info.provider_details.azure_resource_group_name.as_deref(),
        ),
        (
            "azure_container_app_name",
            info.provider_details.azure_container_app_name.as_deref(),
        ),
        (
            "gcp_project_id",
            info.provider_details.gcp_project_id.as_deref(),
        ),
        (
            "gcp_cloud_run_service_name",
            info.provider_details.gcp_cloud_run_service_name.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            lines.push(format!("{label}: {value}"));
        }
    }

    if !info.notes.is_empty() {
        lines.push("notes:".to_string());
        for note in &info.notes {
            lines.push(format!("- {note}"));
        }
    }

    if !info.missing_requirements.is_empty() {
        lines.push("missing_requirements:".to_string());
        for requirement in &info.missing_requirements {
            lines.push(format!("- {requirement}"));
        }
    }

    if !info.suggested_commands.is_empty() {
        lines.push("suggested_commands:".to_string());
        for command in &info.suggested_commands {
            lines.push(format!("- {command}"));
        }
    }

    lines.join("\n")
}

fn local_admin_cert_dir(info: &AdminAccessInfo) -> PathBuf {
    local_admin_cert_dir_for_values(
        &info.bundle_dir,
        info.deployment_name_prefix.as_deref(),
        info.operator_host.as_deref(),
        &info.provider,
    )
}

fn local_admin_cert_dir_for_values(
    bundle_dir: &Path,
    deployment_name_prefix: Option<&str>,
    operator_host: Option<&str>,
    provider: &str,
) -> PathBuf {
    let suffix = deployment_name_prefix
        .or(operator_host)
        .unwrap_or(provider)
        .replace('/', "_");
    tunnel_admin_cert_dir(bundle_dir, &suffix)
}

fn fetch_secret_value(
    provider: Provider,
    secret_ref: &str,
    info: &AdminAccessInfo,
) -> Result<String> {
    match provider {
        Provider::Aws => {
            let region = info.provider_details.aws_region.as_deref().ok_or_else(|| {
                DeployerError::Other("missing aws region for admin secret fetch".to_string())
            })?;
            cli_capture(
                "aws secretsmanager get-secret-value",
                &[
                    "aws",
                    "secretsmanager",
                    "get-secret-value",
                    "--region",
                    region,
                    "--secret-id",
                    secret_ref,
                    "--query",
                    "SecretString",
                    "--output",
                    "text",
                ],
            )
        }
        Provider::Azure => cli_capture(
            "az keyvault secret show",
            &[
                "az", "keyvault", "secret", "show", "--id", secret_ref, "--query", "value",
                "--output", "tsv",
            ],
        )
        .or_else(|_| azure_secret_value_from_terraform_state(info, secret_ref)),
        Provider::Gcp => {
            let (project_id, secret_name) = parse_gcp_secret_ref(secret_ref)?;
            cli_capture(
                "gcloud secrets versions access",
                &[
                    "gcloud",
                    "secrets",
                    "versions",
                    "access",
                    "latest",
                    "--project",
                    &project_id,
                    "--secret",
                    &secret_name,
                ],
            )
            .or_else(|_| gcp_secret_value_from_terraform_state(info, secret_ref))
        }
        other => Err(DeployerError::Other(format!(
            "admin cert materialization is only available for aws, azure, gcp; got {}",
            other.as_str()
        ))),
    }
}

fn cli_capture(label: &str, args: &[&str]) -> Result<String> {
    let (program, rest) = args
        .split_first()
        .ok_or_else(|| DeployerError::Other(format!("{label}: missing program")))?;
    let output = ProcessCommand::new(program).args(rest).output()?;
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

fn parse_gcp_secret_ref(secret_ref: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = secret_ref.split('/').collect();
    let project_idx = parts
        .iter()
        .position(|part| *part == "projects")
        .ok_or_else(|| DeployerError::Other(format!("invalid GCP secret ref: {secret_ref}")))?;
    let secret_idx = parts
        .iter()
        .position(|part| *part == "secrets")
        .ok_or_else(|| DeployerError::Other(format!("invalid GCP secret ref: {secret_ref}")))?;
    let project_id = parts
        .get(project_idx + 1)
        .ok_or_else(|| DeployerError::Other(format!("invalid GCP secret ref: {secret_ref}")))?;
    let secret_name = parts
        .get(secret_idx + 1)
        .ok_or_else(|| DeployerError::Other(format!("invalid GCP secret ref: {secret_ref}")))?;
    Ok(((*project_id).to_string(), (*secret_name).to_string()))
}

fn gcp_secret_value_from_terraform_state(
    info: &AdminAccessInfo,
    secret_ref: &str,
) -> Result<String> {
    for state_path in [
        info.deploy_dir.join("terraform").join("terraform.tfstate"),
        info.deploy_dir
            .join("terraform")
            .join("terraform.tfstate.backup"),
    ] {
        if !state_path.is_file() {
            continue;
        }
        let raw = fs::read_to_string(&state_path)?;
        let state: Value = serde_json::from_str(&raw)?;
        let Some(resources) = state.get("resources").and_then(Value::as_array) else {
            continue;
        };
        for resource in resources {
            if resource.get("type").and_then(Value::as_str)
                != Some("google_secret_manager_secret_version")
            {
                continue;
            }
            let Some(instances) = resource.get("instances").and_then(Value::as_array) else {
                continue;
            };
            for instance in instances {
                let Some(attributes) = instance.get("attributes").and_then(Value::as_object) else {
                    continue;
                };
                if attributes.get("secret").and_then(Value::as_str) != Some(secret_ref) {
                    continue;
                }
                if let Some(secret_data) = attributes.get("secret_data").and_then(Value::as_str) {
                    return Ok(secret_data.to_string());
                }
            }
        }
    }

    Err(DeployerError::Other(format!(
        "gcp secret value not found in terraform state for {secret_ref}"
    )))
}

fn azure_secret_value_from_terraform_state(
    info: &AdminAccessInfo,
    secret_ref: &str,
) -> Result<String> {
    for state_path in [
        info.deploy_dir.join("terraform").join("terraform.tfstate"),
        info.deploy_dir
            .join("terraform")
            .join("terraform.tfstate.backup"),
    ] {
        if !state_path.is_file() {
            continue;
        }
        let raw = fs::read_to_string(&state_path)?;
        let state: Value = serde_json::from_str(&raw)?;
        let Some(resources) = state.get("resources").and_then(Value::as_array) else {
            continue;
        };
        for resource in resources {
            if resource.get("type").and_then(Value::as_str) != Some("azurerm_key_vault_secret") {
                continue;
            }
            let Some(instances) = resource.get("instances").and_then(Value::as_array) else {
                continue;
            };
            for instance in instances {
                let Some(attributes) = instance.get("attributes").and_then(Value::as_object) else {
                    continue;
                };
                if attributes.get("versionless_id").and_then(Value::as_str) != Some(secret_ref) {
                    continue;
                }
                if let Some(value) = attributes.get("value").and_then(Value::as_str) {
                    return Ok(value.to_string());
                }
            }
        }
    }

    Err(DeployerError::Other(format!(
        "azure secret value not found in terraform state for {secret_ref}"
    )))
}

fn host_from_url(value: &str) -> Option<String> {
    let without_scheme = value.split("://").nth(1)?;
    let host_port = without_scheme.split('/').next()?;
    let host = host_port.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn aws_region_from_secret_arn(secret_arn: &str) -> Option<String> {
    secret_arn.split(':').nth(3).map(|value| value.to_string())
}

fn deploy_name_prefix_from_aws_secret_arn(secret_arn: &str) -> Option<String> {
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

fn deploy_name_prefix_from_azure_secret_ref(secret_ref: &str) -> Option<String> {
    let _ = secret_ref;
    None
}

fn deploy_name_prefix_from_gcp_secret_ref(secret_ref: &str) -> Option<String> {
    let _ = secret_ref;
    None
}

fn gcp_project_id_from_secret_ref(secret_ref: &str) -> Option<String> {
    let parts: Vec<&str> = secret_ref.split('/').collect();
    let project_idx = parts.iter().position(|part| *part == "projects")?;
    parts.get(project_idx + 1).map(|value| value.to_string())
}

fn azure_container_app_name_from_host(host: &str) -> Option<String> {
    let app_name = host.split("--").next()?;
    if app_name.is_empty() {
        None
    } else {
        Some(app_name.to_string())
    }
}

fn gcp_cloud_run_service_name_from_host(host: &str) -> Option<String> {
    let prefix = host.split('.').next()?;
    let trimmed = prefix
        .strip_suffix("-uc")
        .or_else(|| prefix.strip_suffix("-eu"))
        .unwrap_or(prefix);
    let mut parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() >= 2 {
        parts.pop();
        let candidate = parts.join("-");
        if !candidate.is_empty() {
            return Some(candidate);
        }
    }
    if prefix.is_empty() {
        None
    } else {
        Some(prefix.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn terraform_output_string_reads_string_values() {
        let outputs: Value = serde_json::json!({
            "operator_endpoint": {
                "value": "https://example.test"
            }
        });

        assert_eq!(
            terraform_output_string(&outputs, "operator_endpoint").as_deref(),
            Some("https://example.test")
        );
        assert_eq!(terraform_output_string(&outputs, "missing"), None);
    }

    #[test]
    fn tunnel_admin_cert_dir_uses_bundle_local_admin_tunnels_path() {
        let path = tunnel_admin_cert_dir(Path::new("/tmp/demo-bundle"), "greentic-1234");
        assert_eq!(
            path,
            PathBuf::from("/tmp/demo-bundle/.greentic/admin/tunnels/greentic-1234")
        );
    }

    #[test]
    fn resolve_admin_access_reports_aws_tunnel_support() {
        let tmp = tempdir().expect("tempdir");
        let bundle_dir = tmp.path().join("bundle");
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
                "operator_endpoint": { "value": "https://example.aws.test" },
                "admin_access_mode": { "value": "aws-ssm-port-forward" },
                "admin_ca_secret_ref": { "value": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:greentic/admin/demo/ca" }
            }))
            .expect("serialize outputs"),
        )
        .expect("write outputs");

        let info = resolve_admin_access(&bundle_dir, Provider::Aws).expect("resolve");
        assert_eq!(info.provider, "aws");
        assert!(info.tunnel_support.supported);
        assert_eq!(
            info.operator_endpoint.as_deref(),
            Some("https://example.aws.test")
        );
        assert_eq!(
            info.admin_access_mode.as_deref(),
            Some("aws-ssm-port-forward")
        );
        assert!(
            info.suggested_commands
                .iter()
                .any(|value| value.contains("aws admin-certs"))
        );
        assert!(
            info.curl_health_example
                .as_deref()
                .is_some_and(|value| value.contains("/admin/v1/health"))
        );
    }

    #[test]
    fn resolve_admin_access_reports_azure_loopback_only_status() {
        let tmp = tempdir().expect("tempdir");
        let bundle_dir = tmp.path().join("bundle");
        let deploy_dir = bundle_dir
            .join(".greentic")
            .join("deploy")
            .join("azure")
            .join("demo")
            .join("state");
        fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        fs::write(
            deploy_dir.join("terraform-outputs.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "operator_endpoint": { "value": "https://example.azure.test" },
                "admin_access_mode": { "value": "internal" }
            }))
            .expect("serialize outputs"),
        )
        .expect("write outputs");

        let info = resolve_admin_access(&bundle_dir, Provider::Azure).expect("resolve");
        assert_eq!(info.provider, "azure");
        assert!(!info.tunnel_support.supported);
        assert_eq!(info.admin_access_mode.as_deref(), Some("internal"));
        assert_eq!(
            info.tunnel_support.reason.as_deref(),
            Some(
                "the admin server stays loopback-only inside Azure Container Apps; use the public HTTPS admin relay instead of a direct tunnel"
            )
        );
    }

    #[test]
    fn resolve_latest_deploy_dir_finds_state_in_repo_root_for_nested_bundle() {
        let tmp = tempdir().expect("tempdir");
        let bundle_dir = tmp.path().join("gcp3").join("cloud-deploy-demo-bundle");
        let deploy_dir = tmp
            .path()
            .join(".greentic")
            .join("deploy")
            .join("gcp")
            .join("demo")
            .join("state");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");
        fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        fs::write(deploy_dir.join("terraform-outputs.json"), b"{}").expect("write outputs");

        let resolved = resolve_latest_deploy_dir(&bundle_dir, "gcp").expect("resolve");
        assert_eq!(resolved, deploy_dir);
    }

    #[test]
    fn parse_gcp_secret_ref_extracts_project_and_secret_name() {
        let (project_id, secret_name) =
            parse_gcp_secret_ref("projects/demo-project/secrets/admin-client-cert").expect("parse");
        assert_eq!(project_id, "demo-project");
        assert_eq!(secret_name, "admin-client-cert");
    }

    #[test]
    fn gcp_secret_value_from_terraform_state_reads_secret_data() {
        let tmp = tempdir().expect("tempdir");
        let deploy_dir = tmp.path().join("deploy");
        fs::create_dir_all(deploy_dir.join("terraform")).expect("create terraform dir");
        fs::write(
            deploy_dir.join("terraform").join("terraform.tfstate"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "resources": [
                    {
                        "type": "google_secret_manager_secret_version",
                        "instances": [
                            {
                                "attributes": {
                                    "secret": "projects/demo-project/secrets/admin-relay-token",
                                    "secret_data": "demo-token"
                                }
                            }
                        ]
                    }
                ]
            }))
            .expect("serialize state"),
        )
        .expect("write state");

        let info = AdminAccessInfo {
            provider: "gcp".to_string(),
            bundle_dir: tmp.path().join("bundle"),
            deploy_dir,
            local_cert_dir: tmp.path().join("certs"),
            admin_access_mode: None,
            admin_public_endpoint: None,
            operator_endpoint: None,
            deployment_name_prefix: None,
            operator_host: None,
            provider_details: AdminProviderDetails::default(),
            admin_listener: "127.0.0.1:8433".to_string(),
            admin_secret_refs: AdminSecretRefs {
                admin_ca_secret_ref: None,
                admin_server_cert_secret_ref: None,
                admin_server_key_secret_ref: None,
                admin_client_cert_secret_ref: None,
                admin_client_key_secret_ref: None,
                admin_relay_token_secret_ref: None,
            },
            client_credentials_available: false,
            missing_requirements: Vec::new(),
            tunnel_support: AdminTunnelSupport {
                supported: false,
                mode: None,
                reason: None,
                command_hint: None,
                local_port_default: 8443,
            },
            suggested_commands: Vec::new(),
            curl_health_example: None,
            notes: Vec::new(),
        };

        let value = gcp_secret_value_from_terraform_state(
            &info,
            "projects/demo-project/secrets/admin-relay-token",
        )
        .expect("read token");
        assert_eq!(value, "demo-token");
    }

    #[test]
    fn azure_secret_value_from_terraform_state_reads_value() {
        let tmp = tempdir().expect("tempdir");
        let deploy_dir = tmp.path().join("deploy");
        fs::create_dir_all(deploy_dir.join("terraform")).expect("create terraform dir");
        fs::write(
            deploy_dir.join("terraform").join("terraform.tfstate"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "resources": [
                    {
                        "type": "azurerm_key_vault_secret",
                        "instances": [
                            {
                                "attributes": {
                                    "versionless_id": "https://vault.example.net/secrets/admin-relay-token",
                                    "value": "demo-azure-token"
                                }
                            }
                        ]
                    }
                ]
            }))
            .expect("serialize state"),
        )
        .expect("write state");

        let info = AdminAccessInfo {
            provider: "azure".to_string(),
            bundle_dir: tmp.path().join("bundle"),
            deploy_dir,
            local_cert_dir: tmp.path().join("certs"),
            admin_access_mode: None,
            admin_public_endpoint: None,
            operator_endpoint: None,
            deployment_name_prefix: None,
            operator_host: None,
            provider_details: AdminProviderDetails::default(),
            admin_listener: "127.0.0.1:8433".to_string(),
            admin_secret_refs: AdminSecretRefs {
                admin_ca_secret_ref: None,
                admin_server_cert_secret_ref: None,
                admin_server_key_secret_ref: None,
                admin_client_cert_secret_ref: None,
                admin_client_key_secret_ref: None,
                admin_relay_token_secret_ref: None,
            },
            client_credentials_available: false,
            missing_requirements: Vec::new(),
            tunnel_support: AdminTunnelSupport {
                supported: false,
                mode: None,
                reason: None,
                command_hint: None,
                local_port_default: 8443,
            },
            suggested_commands: Vec::new(),
            curl_health_example: None,
            notes: Vec::new(),
        };

        let value = azure_secret_value_from_terraform_state(
            &info,
            "https://vault.example.net/secrets/admin-relay-token",
        )
        .expect("read token");
        assert_eq!(value, "demo-azure-token");
    }

    #[test]
    fn render_materialized_admin_certs_text_lists_paths() {
        let value = MaterializedAdminCerts {
            provider: "gcp".to_string(),
            cert_dir: PathBuf::from("/tmp/demo"),
            ca_cert_path: PathBuf::from("/tmp/demo/ca.crt"),
            client_cert_path: PathBuf::from("/tmp/demo/client.crt"),
            client_key_path: PathBuf::from("/tmp/demo/client.key"),
        };

        let rendered = render_materialized_admin_certs(&value, OutputFormat::Text).expect("render");
        assert!(rendered.contains("provider: gcp"));
        assert!(rendered.contains("ca_cert_path: /tmp/demo/ca.crt"));
        assert!(rendered.contains("client_cert_path: /tmp/demo/client.crt"));
        assert!(rendered.contains("client_key_path: /tmp/demo/client.key"));
    }

    #[test]
    fn render_materialized_admin_relay_token_redacts_secret_value() {
        let rendered = render_materialized_admin_relay_token(
            Provider::Aws,
            "super-secret-token",
            OutputFormat::Json,
        )
        .expect("render");
        assert!(rendered.contains("\"token\": \"[REDACTED]\""));
        assert!(!rendered.contains("super-secret-token"));
    }
}
