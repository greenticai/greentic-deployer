use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use greentic_deployer::{
    AdminEndpointSpec, BundleFormat, BundleSpec, CloudTargetRequirementsV1,
    DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1, DEPLOYMENT_SPEC_KIND, DeployerCapability, DeployerConfig,
    DeployerRequest, DeploymentMetadata, DeploymentSpecBody, DeploymentSpecV1, DeploymentTarget,
    HealthSpec, LinuxArch, MtlsSpec, OutputFormat, Provider, RolloutSpec, RolloutStrategy,
    RuntimeSpec, ServiceManager, ServiceSpec, SingleVmApplyOptions, SingleVmDestroyOptions,
    StorageSpec, apply_single_vm_plan_output_with_options, aws, azure,
    destroy_single_vm_plan_output_with_options, gcp, helm, juju_k8s, juju_machine, k8s_raw,
    multi_target, operator, plan_single_vm_spec_path, preview_single_vm_apply_plan_output,
    preview_single_vm_destroy_plan_output, render_operation_result, render_single_vm_apply_report,
    render_single_vm_destroy_report, render_single_vm_plan_output, render_single_vm_status_report,
    resolve_builtin_extension_for_provider, serverless, single_vm_builtin_extension, snap,
    status_single_vm_plan_output, terraform,
};

#[derive(Parser)]
#[command(name = "greentic-deployer", version, about = "Greentic deployer CLI")]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Subcommand)]
enum TopLevelCommand {
    TargetRequirements(TargetRequirementsArgs),
    ExtensionResolve(ExtensionResolveArgs),
    SingleVm(SingleVmCommand),
    MultiTarget(MultiTargetCommand),
    Aws(AwsCommand),
    Azure(AzureCommand),
    Gcp(GcpCommand),
    Helm(HelmCommand),
    JujuK8s(JujuK8sCommand),
    JujuMachine(JujuMachineCommand),
    K8sRaw(K8sRawCommand),
    Operator(OperatorCommand),
    Serverless(ServerlessCommand),
    Snap(SnapCommand),
    Terraform(TerraformCommand),
}

#[derive(Parser)]
struct TargetRequirementsArgs {
    #[arg(long, value_enum)]
    provider: CliProvider,
}

#[derive(Parser)]
struct ExtensionResolveArgs {
    #[arg(long)]
    target: String,
}

#[derive(Parser)]
struct SingleVmCommand {
    #[command(subcommand)]
    command: SingleVmSubcommand,
}

#[derive(Parser)]
struct MultiTargetCommand {
    #[command(subcommand)]
    command: MultiTargetSubcommand,
}

#[derive(Parser)]
struct TerraformCommand {
    #[command(subcommand)]
    command: TerraformSubcommand,
}

#[derive(Parser)]
struct K8sRawCommand {
    #[command(subcommand)]
    command: K8sRawSubcommand,
}

#[derive(Parser)]
struct HelmCommand {
    #[command(subcommand)]
    command: HelmSubcommand,
}

#[derive(Parser)]
struct AwsCommand {
    #[command(subcommand)]
    command: AwsSubcommand,
}

#[derive(Parser)]
struct AzureCommand {
    #[command(subcommand)]
    command: AzureSubcommand,
}

#[derive(Parser)]
struct GcpCommand {
    #[command(subcommand)]
    command: GcpSubcommand,
}

#[derive(Parser)]
struct JujuK8sCommand {
    #[command(subcommand)]
    command: JujuK8sSubcommand,
}

#[derive(Parser)]
struct JujuMachineCommand {
    #[command(subcommand)]
    command: JujuMachineSubcommand,
}

#[derive(Parser)]
struct OperatorCommand {
    #[command(subcommand)]
    command: OperatorSubcommand,
}

#[derive(Parser)]
struct ServerlessCommand {
    #[command(subcommand)]
    command: ServerlessSubcommand,
}

#[derive(Parser)]
struct SnapCommand {
    #[command(subcommand)]
    command: SnapSubcommand,
}

#[derive(Subcommand)]
enum SingleVmSubcommand {
    RenderSpec(SingleVmRenderSpecArgs),
    Plan(SingleVmPlanArgs),
    Apply(SingleVmApplyArgs),
    Destroy(SingleVmDestroyArgs),
    Status(SingleVmStatusArgs),
}

#[derive(Subcommand)]
enum MultiTargetSubcommand {
    Generate(MultiTargetArgs),
    Plan(MultiTargetArgs),
    Apply(MultiTargetArgs),
    Destroy(MultiTargetArgs),
    Status(MultiTargetArgs),
    Rollback(MultiTargetArgs),
}

#[derive(Subcommand)]
enum TerraformSubcommand {
    Generate(TerraformArgs),
    Plan(TerraformArgs),
    Apply(TerraformArgs),
    Destroy(TerraformArgs),
    Status(TerraformArgs),
    Rollback(TerraformArgs),
}

#[derive(Subcommand)]
enum K8sRawSubcommand {
    Generate(K8sRawArgs),
    Plan(K8sRawArgs),
    Apply(K8sRawArgs),
    Destroy(K8sRawArgs),
    Status(K8sRawArgs),
    Rollback(K8sRawArgs),
}

#[derive(Subcommand)]
enum HelmSubcommand {
    Generate(HelmArgs),
    Plan(HelmArgs),
    Apply(HelmArgs),
    Destroy(HelmArgs),
    Status(HelmArgs),
    Rollback(HelmArgs),
}

#[derive(Subcommand)]
enum AwsSubcommand {
    Generate(AwsArgs),
    Plan(AwsArgs),
    Apply(AwsArgs),
    Destroy(AwsArgs),
    Status(AwsArgs),
    Rollback(AwsArgs),
    AdminTunnel(AwsAdminTunnelArgs),
}

#[derive(Subcommand)]
enum AzureSubcommand {
    Generate(AzureArgs),
    Plan(AzureArgs),
    Apply(AzureArgs),
    Destroy(AzureArgs),
    Status(AzureArgs),
    Rollback(AzureArgs),
}

#[derive(Subcommand)]
enum GcpSubcommand {
    Generate(GcpArgs),
    Plan(GcpArgs),
    Apply(GcpArgs),
    Destroy(GcpArgs),
    Status(GcpArgs),
    Rollback(GcpArgs),
}

#[derive(Subcommand)]
enum JujuK8sSubcommand {
    Generate(JujuK8sArgs),
    Plan(JujuK8sArgs),
    Apply(JujuK8sArgs),
    Destroy(JujuK8sArgs),
    Status(JujuK8sArgs),
    Rollback(JujuK8sArgs),
}

#[derive(Subcommand)]
enum JujuMachineSubcommand {
    Generate(JujuMachineArgs),
    Plan(JujuMachineArgs),
    Apply(JujuMachineArgs),
    Destroy(JujuMachineArgs),
    Status(JujuMachineArgs),
    Rollback(JujuMachineArgs),
}

#[derive(Subcommand)]
enum OperatorSubcommand {
    Generate(OperatorArgs),
    Plan(OperatorArgs),
    Apply(OperatorArgs),
    Destroy(OperatorArgs),
    Status(OperatorArgs),
    Rollback(OperatorArgs),
}

#[derive(Subcommand)]
enum ServerlessSubcommand {
    Generate(ServerlessArgs),
    Plan(ServerlessArgs),
    Apply(ServerlessArgs),
    Destroy(ServerlessArgs),
    Status(ServerlessArgs),
    Rollback(ServerlessArgs),
}

#[derive(Subcommand)]
enum SnapSubcommand {
    Generate(SnapArgs),
    Plan(SnapArgs),
    Apply(SnapArgs),
    Destroy(SnapArgs),
    Status(SnapArgs),
    Rollback(SnapArgs),
}

#[derive(Parser)]
struct SingleVmRenderSpecArgs {
    #[arg(long)]
    out: std::path::PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long = "bundle-source")]
    bundle_source: String,
    #[arg(long)]
    state_dir: std::path::PathBuf,
    #[arg(long)]
    cache_dir: std::path::PathBuf,
    #[arg(long)]
    log_dir: std::path::PathBuf,
    #[arg(long)]
    temp_dir: std::path::PathBuf,
    #[arg(long, default_value = "127.0.0.1:8433")]
    admin_bind: String,
    #[arg(long = "admin-ca-file")]
    admin_ca_file: std::path::PathBuf,
    #[arg(long = "admin-cert-file")]
    admin_cert_file: std::path::PathBuf,
    #[arg(long = "admin-key-file")]
    admin_key_file: std::path::PathBuf,
    #[arg(
        long,
        default_value = "ghcr.io/greentic-ai/operator-distroless:0.1.0-distroless"
    )]
    image: String,
}

#[derive(Parser)]
struct SingleVmPlanArgs {
    #[arg(long)]
    spec: std::path::PathBuf,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Text)]
    output: CliOutputFormat,
}

#[derive(Parser)]
struct SingleVmApplyArgs {
    #[arg(long)]
    spec: std::path::PathBuf,
    #[arg(long)]
    execute: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser)]
struct SingleVmDestroyArgs {
    #[arg(long)]
    spec: std::path::PathBuf,
    #[arg(long)]
    execute: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser)]
struct SingleVmStatusArgs {
    #[arg(long)]
    spec: std::path::PathBuf,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct MultiTargetArgs {
    #[arg(long, value_enum)]
    provider: CliProvider,
    #[arg(long, default_value = "iac-only")]
    strategy: String,
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct TerraformArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct K8sRawArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct HelmArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct AwsArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    bundle_source: Option<String>,
    #[arg(long)]
    bundle_digest: Option<String>,
    #[arg(long)]
    repo_registry_base: Option<String>,
    #[arg(long)]
    store_registry_base: Option<String>,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct AwsAdminTunnelArgs {
    #[arg(long)]
    bundle_dir: PathBuf,
    #[arg(long, default_value = "8443")]
    local_port: String,
    #[arg(long, default_value = "app")]
    container: String,
}

#[derive(Parser, Clone)]
struct AzureArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    bundle_source: Option<String>,
    #[arg(long)]
    bundle_digest: Option<String>,
    #[arg(long)]
    repo_registry_base: Option<String>,
    #[arg(long)]
    store_registry_base: Option<String>,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct GcpArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    bundle_source: Option<String>,
    #[arg(long)]
    bundle_digest: Option<String>,
    #[arg(long)]
    repo_registry_base: Option<String>,
    #[arg(long)]
    store_registry_base: Option<String>,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct JujuK8sArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct JujuMachineArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct OperatorArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct ServerlessArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Parser, Clone)]
struct SnapArgs {
    #[arg(long)]
    tenant: String,
    #[arg(
        long = "bundle-pack",
        visible_alias = "pack",
        help = "Path to the canonical app pack selected from the bundle for deployment dispatch"
    )]
    pack: std::path::PathBuf,
    #[arg(long)]
    provider_pack: Option<std::path::PathBuf>,
    #[arg(long)]
    deploy_pack_id: Option<String>,
    #[arg(long)]
    deploy_flow_id: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    pack_id: Option<String>,
    #[arg(long)]
    pack_version: Option<String>,
    #[arg(long)]
    pack_digest: Option<String>,
    #[arg(long)]
    distributor_url: Option<String>,
    #[arg(long)]
    distributor_token: Option<String>,
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[arg(long)]
    allow_remote_in_offline: bool,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CliOutputFormat {
    Text,
    Json,
    Yaml,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CliProvider {
    Local,
    Aws,
    Azure,
    Gcp,
    K8s,
    Generic,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Text => OutputFormat::Text,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Yaml => OutputFormat::Yaml,
        }
    }
}

impl From<CliProvider> for Provider {
    fn from(value: CliProvider) -> Self {
        match value {
            CliProvider::Local => Provider::Local,
            CliProvider::Aws => Provider::Aws,
            CliProvider::Azure => Provider::Azure,
            CliProvider::Gcp => Provider::Gcp,
            CliProvider::K8s => Provider::K8s,
            CliProvider::Generic => Provider::Generic,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        TopLevelCommand::TargetRequirements(args) => run_target_requirements(args),
        TopLevelCommand::ExtensionResolve(args) => run_extension_resolve(args),
        TopLevelCommand::SingleVm(command) => run_single_vm(command),
        TopLevelCommand::MultiTarget(command) => run_multi_target(command),
        TopLevelCommand::Aws(command) => run_aws(command),
        TopLevelCommand::Azure(command) => run_azure(command),
        TopLevelCommand::Gcp(command) => run_gcp(command),
        TopLevelCommand::Helm(command) => run_helm(command),
        TopLevelCommand::JujuK8s(command) => run_juju_k8s(command),
        TopLevelCommand::JujuMachine(command) => run_juju_machine(command),
        TopLevelCommand::K8sRaw(command) => run_k8s_raw(command),
        TopLevelCommand::Operator(command) => run_operator(command),
        TopLevelCommand::Serverless(command) => run_serverless(command),
        TopLevelCommand::Snap(command) => run_snap(command),
        TopLevelCommand::Terraform(command) => run_terraform(command),
    }
}

fn run_target_requirements(args: TargetRequirementsArgs) -> Result<()> {
    let provider: Provider = args.provider.into();
    let requirements = CloudTargetRequirementsV1::for_provider(provider).ok_or_else(|| {
        anyhow::anyhow!(
            "target requirements are only available for cloud providers (aws, azure, gcp), got {}",
            provider.as_str()
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&requirements)?);
    Ok(())
}

fn run_extension_resolve(args: ExtensionResolveArgs) -> Result<()> {
    let descriptor = match args.target.trim() {
        "single-vm" | "single_vm" => Some(single_vm_builtin_extension()),
        "local" => resolve_builtin_extension_for_provider(Provider::Local),
        "aws" => resolve_builtin_extension_for_provider(Provider::Aws),
        "azure" => resolve_builtin_extension_for_provider(Provider::Azure),
        "gcp" => resolve_builtin_extension_for_provider(Provider::Gcp),
        "k8s" => resolve_builtin_extension_for_provider(Provider::K8s),
        "generic" => resolve_builtin_extension_for_provider(Provider::Generic),
        _ => None,
    }
    .ok_or_else(|| anyhow::anyhow!("unknown built-in deployment extension target: {}", args.target))?;
    println!("{}", serde_json::to_string_pretty(&descriptor)?);
    Ok(())
}

fn run_single_vm(command: SingleVmCommand) -> Result<()> {
    match command.command {
        SingleVmSubcommand::RenderSpec(args) => run_single_vm_render_spec(args),
        SingleVmSubcommand::Plan(args) => {
            let output = plan_single_vm_spec_path(&args.spec)?;
            println!(
                "{}",
                render_single_vm_plan_output(&output, args.output.into())?
            );
            Ok(())
        }
        SingleVmSubcommand::Apply(args) => {
            let output = plan_single_vm_spec_path(&args.spec)?;
            let report = if args.execute {
                apply_single_vm_plan_output_with_options(
                    &output,
                    &SingleVmApplyOptions {
                        pull_image: true,
                        daemon_reload: true,
                        enable_service: true,
                        restart_service: true,
                    },
                )?
            } else {
                preview_single_vm_apply_plan_output(&output)
            };
            print_single_vm_apply_report(&report, args.output.into())
        }
        SingleVmSubcommand::Destroy(args) => {
            let output = plan_single_vm_spec_path(&args.spec)?;
            let report = if args.execute {
                destroy_single_vm_plan_output_with_options(
                    &output,
                    &SingleVmDestroyOptions {
                        stop_service: true,
                        disable_service: true,
                    },
                )?
            } else {
                preview_single_vm_destroy_plan_output(&output)
            };
            print_single_vm_destroy_report(&report, args.output.into())
        }
        SingleVmSubcommand::Status(args) => {
            let output = plan_single_vm_spec_path(&args.spec)?;
            let report = status_single_vm_plan_output(&output)?;
            print_single_vm_status_report(&report, args.output.into())
        }
    }
}

fn run_single_vm_render_spec(args: SingleVmRenderSpecArgs) -> Result<()> {
    let spec = DeploymentSpecV1 {
        api_version: DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1.to_string(),
        kind: DEPLOYMENT_SPEC_KIND.to_string(),
        metadata: DeploymentMetadata { name: args.name },
        spec: DeploymentSpecBody {
            target: DeploymentTarget::SingleVm,
            bundle: BundleSpec {
                source: args.bundle_source,
                format: BundleFormat::Squashfs,
            },
            runtime: RuntimeSpec {
                image: args.image,
                arch: LinuxArch::X86_64,
                admin: AdminEndpointSpec {
                    bind: args.admin_bind,
                    mtls: MtlsSpec {
                        ca_file: args.admin_ca_file,
                        cert_file: args.admin_cert_file,
                        key_file: args.admin_key_file,
                    },
                },
            },
            storage: StorageSpec {
                state_dir: args.state_dir,
                cache_dir: args.cache_dir,
                log_dir: args.log_dir,
                temp_dir: args.temp_dir,
            },
            service: ServiceSpec {
                manager: ServiceManager::Systemd,
                user: "greentic".to_string(),
                group: "greentic".to_string(),
            },
            health: HealthSpec {
                readiness_path: "/ready".to_string(),
                liveness_path: "/health".to_string(),
                startup_timeout_seconds: 120,
            },
            rollout: RolloutSpec {
                strategy: RolloutStrategy::Recreate,
            },
        },
    };
    spec.validate()?;
    if let Some(parent) = args.out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.out, serde_yaml_bw::to_string(&spec)?)?;
    Ok(())
}

fn run_multi_target(command: MultiTargetCommand) -> Result<()> {
    let (capability, args) = match command.command {
        MultiTargetSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        MultiTargetSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        MultiTargetSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        MultiTargetSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        MultiTargetSubcommand::Status(args) => (DeployerCapability::Status, args),
        MultiTargetSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    run_multi_target_request(DeployerRequest {
        capability,
        provider: args.provider.into(),
        strategy: args.strategy,
        tenant: args.tenant,
        environment: args.environment,
        pack_path: args.pack,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
        provider_pack: args.provider_pack,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: false,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        bundle_source: None,
        bundle_digest: None,
        repo_registry_base: None,
        store_registry_base: None,
    })
}

fn run_terraform(command: TerraformCommand) -> Result<()> {
    let (capability, args) = match command.command {
        TerraformSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        TerraformSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        TerraformSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        TerraformSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        TerraformSubcommand::Status(args) => (DeployerCapability::Status, args),
        TerraformSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = terraform::TerraformRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = terraform::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(terraform::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_k8s_raw(command: K8sRawCommand) -> Result<()> {
    let (capability, args) = match command.command {
        K8sRawSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        K8sRawSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        K8sRawSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        K8sRawSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        K8sRawSubcommand::Status(args) => (DeployerCapability::Status, args),
        K8sRawSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = k8s_raw::K8sRawRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: false,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = k8s_raw::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(k8s_raw::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_helm(command: HelmCommand) -> Result<()> {
    let (capability, args) = match command.command {
        HelmSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        HelmSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        HelmSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        HelmSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        HelmSubcommand::Status(args) => (DeployerCapability::Status, args),
        HelmSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = helm::HelmRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: false,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = helm::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(helm::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_aws(command: AwsCommand) -> Result<()> {
    if let AwsSubcommand::AdminTunnel(args) = command.command {
        return run_aws_admin_tunnel(args);
    }

    let (capability, args) = match command.command {
        AwsSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        AwsSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        AwsSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        AwsSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        AwsSubcommand::Status(args) => (DeployerCapability::Status, args),
        AwsSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
        AwsSubcommand::AdminTunnel(_) => unreachable!("handled above"),
    };

    let request = aws::AwsRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        bundle_source: args.bundle_source,
        bundle_digest: args.bundle_digest,
        repo_registry_base: args.repo_registry_base,
        store_registry_base: args.store_registry_base,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = aws::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(aws::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_aws_admin_tunnel(args: AwsAdminTunnelArgs) -> Result<()> {
    let deploy_dir = resolve_latest_aws_deploy_dir(&args.bundle_dir)?;
    let outputs_path = deploy_dir.join("terraform-outputs.json");
    let outputs = load_terraform_outputs(&outputs_path)?;
    let Some(admin_ca_secret_ref) = terraform_output_string(&outputs, "admin_ca_secret_ref") else {
        anyhow::bail!(
            "missing admin_ca_secret_ref in {}; deploy the bundle first",
            outputs_path.display()
        );
    };

    let Some(region) = aws_region_from_secret_arn(&admin_ca_secret_ref) else {
        anyhow::bail!("failed to derive AWS region from admin secret ref");
    };
    let Some(name_prefix) = deploy_name_prefix_from_secret_arn(&admin_ca_secret_ref) else {
        anyhow::bail!("failed to derive deploy name prefix from admin secret ref");
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
        anyhow::bail!("no running ECS task found for service {service}");
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
        anyhow::bail!("no runtimeId found for container {}", args.container);
    }

    let Some(task_id) = task_id_from_arn(&task_arn) else {
        anyhow::bail!("failed to derive task id from task ARN");
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
        anyhow::bail!("admin tunnel exited with status {status}");
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
        anyhow::anyhow!(
            "aws deploy state not found under {}, its parent workspace, or ~/.greentic/deploy/aws; deploy the bundle first",
            bundle_dir.join(".greentic").join("deploy").join("aws").display()
        )
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
            anyhow::bail!("{label} failed with status {}", output.status);
        }
        anyhow::bail!("{label} failed: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_azure(command: AzureCommand) -> Result<()> {
    let (capability, args) = match command.command {
        AzureSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        AzureSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        AzureSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        AzureSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        AzureSubcommand::Status(args) => (DeployerCapability::Status, args),
        AzureSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = azure::AzureRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        bundle_source: args.bundle_source,
        bundle_digest: args.bundle_digest,
        repo_registry_base: args.repo_registry_base,
        store_registry_base: args.store_registry_base,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = azure::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(azure::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_gcp(command: GcpCommand) -> Result<()> {
    let (capability, args) = match command.command {
        GcpSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        GcpSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        GcpSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        GcpSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        GcpSubcommand::Status(args) => (DeployerCapability::Status, args),
        GcpSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = gcp::GcpRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        bundle_source: args.bundle_source,
        bundle_digest: args.bundle_digest,
        repo_registry_base: args.repo_registry_base,
        store_registry_base: args.store_registry_base,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = gcp::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(gcp::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_operator(command: OperatorCommand) -> Result<()> {
    let (capability, args) = match command.command {
        OperatorSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        OperatorSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        OperatorSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        OperatorSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        OperatorSubcommand::Status(args) => (DeployerCapability::Status, args),
        OperatorSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = operator::OperatorRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = operator::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(operator::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_serverless(command: ServerlessCommand) -> Result<()> {
    let (capability, args) = match command.command {
        ServerlessSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        ServerlessSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        ServerlessSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        ServerlessSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        ServerlessSubcommand::Status(args) => (DeployerCapability::Status, args),
        ServerlessSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = serverless::ServerlessRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = serverless::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(serverless::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_snap(command: SnapCommand) -> Result<()> {
    let (capability, args) = match command.command {
        SnapSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        SnapSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        SnapSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        SnapSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        SnapSubcommand::Status(args) => (DeployerCapability::Status, args),
        SnapSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = snap::SnapRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = snap::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(snap::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_juju_machine(command: JujuMachineCommand) -> Result<()> {
    let (capability, args) = match command.command {
        JujuMachineSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        JujuMachineSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        JujuMachineSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        JujuMachineSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        JujuMachineSubcommand::Status(args) => (DeployerCapability::Status, args),
        JujuMachineSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = juju_machine::JujuMachineRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = juju_machine::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(juju_machine::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_juju_k8s(command: JujuK8sCommand) -> Result<()> {
    let (capability, args) = match command.command {
        JujuK8sSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        JujuK8sSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        JujuK8sSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        JujuK8sSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        JujuK8sSubcommand::Status(args) => (DeployerCapability::Status, args),
        JujuK8sSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = juju_k8s::JujuK8sRequest {
        capability,
        tenant: args.tenant,
        pack_path: args.pack,
        provider_pack: args.provider_pack,
        deploy_pack_id_override: args.deploy_pack_id,
        deploy_flow_id_override: args.deploy_flow_id,
        environment: args.environment,
        pack_id: args.pack_id,
        pack_version: args.pack_version,
        pack_digest: args.pack_digest,
        distributor_url: args.distributor_url,
        distributor_token: args.distributor_token,
        preview: args.preview,
        dry_run: args.dry_run,
        execute_local: args.execute,
        output: args.output.into(),
        config_path: args.config,
        allow_remote_in_offline: args.allow_remote_in_offline,
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    };
    let config = juju_k8s::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(juju_k8s::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_multi_target_request(request: DeployerRequest) -> Result<()> {
    let config = DeployerConfig::resolve(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(multi_target::run(config))?;
    print_multi_target_operation_result(&result, output_format)
}

#[cfg(test)]
mod tests {
    use super::run_extension_resolve;

    #[test]
    fn extension_resolve_supports_single_vm_builtin_target() {
        let args = super::ExtensionResolveArgs {
            target: "single-vm".to_string(),
        };
        run_extension_resolve(args).expect("single-vm extension");
    }

    #[test]
    fn extension_resolve_supports_cloud_builtin_target() {
        let args = super::ExtensionResolveArgs {
            target: "aws".to_string(),
        };
        run_extension_resolve(args).expect("aws extension");
    }
}

fn print_single_vm_apply_report(
    value: &greentic_deployer::SingleVmApplyReport,
    format: OutputFormat,
) -> Result<()> {
    let rendered = render_single_vm_apply_report(value, format)?;
    println!("{rendered}");
    Ok(())
}

fn print_single_vm_destroy_report(
    value: &greentic_deployer::SingleVmDestroyReport,
    format: OutputFormat,
) -> Result<()> {
    let rendered = render_single_vm_destroy_report(value, format)?;
    println!("{rendered}");
    Ok(())
}

fn print_single_vm_status_report(
    value: &greentic_deployer::SingleVmStatusReport,
    format: OutputFormat,
) -> Result<()> {
    let rendered = render_single_vm_status_report(value, format)?;
    println!("{rendered}");
    Ok(())
}

fn print_multi_target_operation_result(
    value: &greentic_deployer::OperationResult,
    format: OutputFormat,
) -> Result<()> {
    let rendered = render_operation_result(value, format)?;
    println!("{rendered}");
    Ok(())
}
