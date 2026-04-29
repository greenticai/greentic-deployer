use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use serde_yaml_bw as serde_yaml;
use std::future::Future;
use std::path::{Path, PathBuf};

mod cli_builtin_dispatch;

use greentic_deployer::{
    AwsAdminTunnelRequest, BuiltinBackendId, CloudTargetRequirementsV1, DeployerCapability,
    DeployerConfig, DeployerRequest, DeploymentExtensionSourceOptions, OutputFormat, Provider,
    SingleVmApplyOptions, SingleVmDestroyOptions, SingleVmRenderSpecRequest,
    apply_single_vm_plan_output_with_options, aws, azure,
    destroy_single_vm_plan_output_with_options, gcp, helm, juju_k8s, juju_machine, k8s_raw,
    list_deployment_extension_contracts_from_sources_with_options, materialize_admin_client_certs,
    materialize_admin_relay_token, operator, plan_single_vm_spec_path,
    preview_single_vm_apply_plan_output, preview_single_vm_destroy_plan_output, probe_admin_health,
    render_admin_health_probe, render_operation_result, render_single_vm_apply_report,
    render_single_vm_destroy_report, render_single_vm_plan_output, render_single_vm_status_report,
    resolve_admin_access,
    resolve_deployment_extension_contract_for_target_name_from_sources_with_options,
    run_builtin_extension, serverless, snap, status_single_vm_plan_output, terraform,
    write_single_vm_spec,
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
    ExtensionList(ExtensionListArgs),
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

enum BuiltinBackendCommand {
    Terraform(TerraformCommand),
    K8sRaw(K8sRawCommand),
    Helm(HelmCommand),
    Aws(AwsCommand),
    Azure(AzureCommand),
    Gcp(GcpCommand),
    JujuK8s(JujuK8sCommand),
    JujuMachine(JujuMachineCommand),
    Operator(OperatorCommand),
    Serverless(ServerlessCommand),
    Snap(SnapCommand),
}

impl BuiltinBackendCommand {
    fn backend_id(&self) -> BuiltinBackendId {
        match self {
            Self::Terraform(_) => BuiltinBackendId::Terraform,
            Self::K8sRaw(_) => BuiltinBackendId::K8sRaw,
            Self::Helm(_) => BuiltinBackendId::Helm,
            Self::Aws(_) => BuiltinBackendId::Aws,
            Self::Azure(_) => BuiltinBackendId::Azure,
            Self::Gcp(_) => BuiltinBackendId::Gcp,
            Self::JujuK8s(_) => BuiltinBackendId::JujuK8s,
            Self::JujuMachine(_) => BuiltinBackendId::JujuMachine,
            Self::Operator(_) => BuiltinBackendId::Operator,
            Self::Serverless(_) => BuiltinBackendId::Serverless,
            Self::Snap(_) => BuiltinBackendId::Snap,
        }
    }
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
    #[arg(long = "pack")]
    pack_paths: Vec<PathBuf>,
}

#[derive(Parser)]
struct ExtensionListArgs {
    #[arg(long = "pack")]
    pack_paths: Vec<PathBuf>,
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
    RenderSpec(Box<SingleVmRenderSpecArgs>),
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
    AdminAccess(AdminAccessArgs),
    AdminCerts(AdminAccessArgs),
    AdminToken(AdminAccessArgs),
    AdminHealth(AdminAccessArgs),
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
    AdminAccess(AdminAccessArgs),
    AdminCerts(AdminAccessArgs),
    AdminToken(AdminAccessArgs),
    AdminHealth(AdminAccessArgs),
}

#[derive(Subcommand)]
enum GcpSubcommand {
    Generate(GcpArgs),
    Plan(GcpArgs),
    Apply(GcpArgs),
    Destroy(GcpArgs),
    Status(GcpArgs),
    Rollback(GcpArgs),
    AdminAccess(AdminAccessArgs),
    AdminCerts(AdminAccessArgs),
    AdminToken(AdminAccessArgs),
    AdminHealth(AdminAccessArgs),
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
struct AdminAccessArgs {
    #[arg(long)]
    bundle_dir: PathBuf,
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Json)]
    output: CliOutputFormat,
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

#[derive(Clone)]
struct CommonRequestData {
    tenant: String,
    pack_path: PathBuf,
    provider_pack: Option<PathBuf>,
    deploy_pack_id_override: Option<String>,
    deploy_flow_id_override: Option<String>,
    environment: Option<String>,
    pack_id: Option<String>,
    pack_version: Option<String>,
    pack_digest: Option<String>,
    distributor_url: Option<String>,
    distributor_token: Option<String>,
    preview: bool,
    dry_run: bool,
    output: OutputFormat,
    config_path: Option<PathBuf>,
    allow_remote_in_offline: bool,
}

#[derive(Clone)]
struct ExecutableRequestData {
    common: CommonRequestData,
    execute_local: bool,
}

#[derive(Clone)]
struct CloudRequestData {
    executable: ExecutableRequestData,
    bundle_source: Option<String>,
    bundle_digest: Option<String>,
    repo_registry_base: Option<String>,
    store_registry_base: Option<String>,
}

trait HasCommonRequestArgs {
    fn tenant(&self) -> &str;
    fn pack(&self) -> &PathBuf;
    fn provider_pack(&self) -> Option<PathBuf>;
    fn deploy_pack_id(&self) -> Option<String>;
    fn deploy_flow_id(&self) -> Option<String>;
    fn environment(&self) -> Option<String>;
    fn pack_id(&self) -> Option<String>;
    fn pack_version(&self) -> Option<String>;
    fn pack_digest(&self) -> Option<String>;
    fn distributor_url(&self) -> Option<String>;
    fn distributor_token(&self) -> Option<String>;
    fn preview(&self) -> bool;
    fn dry_run(&self) -> bool;
    fn output(&self) -> OutputFormat;
    fn config(&self) -> Option<PathBuf>;
    fn allow_remote_in_offline(&self) -> bool;
}

trait HasExecutableRequestArgs: HasCommonRequestArgs {
    fn execute(&self) -> bool;
}

trait HasCloudRequestArgs: HasExecutableRequestArgs {
    fn bundle_source(&self) -> Option<String>;
    fn bundle_digest(&self) -> Option<String>;
    fn repo_registry_base(&self) -> Option<String>;
    fn store_registry_base(&self) -> Option<String>;
}

macro_rules! impl_common_request_args {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl HasCommonRequestArgs for $ty {
                fn tenant(&self) -> &str { &self.tenant }
                fn pack(&self) -> &PathBuf { &self.pack }
                fn provider_pack(&self) -> Option<PathBuf> { self.provider_pack.clone() }
                fn deploy_pack_id(&self) -> Option<String> { self.deploy_pack_id.clone() }
                fn deploy_flow_id(&self) -> Option<String> { self.deploy_flow_id.clone() }
                fn environment(&self) -> Option<String> { self.environment.clone() }
                fn pack_id(&self) -> Option<String> { self.pack_id.clone() }
                fn pack_version(&self) -> Option<String> { self.pack_version.clone() }
                fn pack_digest(&self) -> Option<String> { self.pack_digest.clone() }
                fn distributor_url(&self) -> Option<String> { self.distributor_url.clone() }
                fn distributor_token(&self) -> Option<String> { self.distributor_token.clone() }
                fn preview(&self) -> bool { self.preview }
                fn dry_run(&self) -> bool { self.dry_run }
                fn output(&self) -> OutputFormat { self.output.into() }
                fn config(&self) -> Option<PathBuf> { self.config.clone() }
                fn allow_remote_in_offline(&self) -> bool { self.allow_remote_in_offline }
            }
        )+
    };
}

macro_rules! impl_executable_request_args {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl HasExecutableRequestArgs for $ty {
                fn execute(&self) -> bool { self.execute }
            }
        )+
    };
}

macro_rules! impl_cloud_request_args {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl HasCloudRequestArgs for $ty {
                fn bundle_source(&self) -> Option<String> { self.bundle_source.clone() }
                fn bundle_digest(&self) -> Option<String> { self.bundle_digest.clone() }
                fn repo_registry_base(&self) -> Option<String> { self.repo_registry_base.clone() }
                fn store_registry_base(&self) -> Option<String> { self.store_registry_base.clone() }
            }
        )+
    };
}

impl_common_request_args!(
    MultiTargetArgs,
    TerraformArgs,
    K8sRawArgs,
    HelmArgs,
    AwsArgs,
    AzureArgs,
    GcpArgs,
    JujuK8sArgs,
    JujuMachineArgs,
    OperatorArgs,
    ServerlessArgs,
    SnapArgs,
);

impl_executable_request_args!(
    TerraformArgs,
    AwsArgs,
    AzureArgs,
    GcpArgs,
    JujuK8sArgs,
    JujuMachineArgs,
    OperatorArgs,
    ServerlessArgs,
    SnapArgs,
);

impl_cloud_request_args!(AwsArgs, AzureArgs, GcpArgs,);

fn common_request_data(args: &impl HasCommonRequestArgs) -> CommonRequestData {
    CommonRequestData {
        tenant: args.tenant().to_string(),
        pack_path: args.pack().clone(),
        provider_pack: args.provider_pack(),
        deploy_pack_id_override: args.deploy_pack_id(),
        deploy_flow_id_override: args.deploy_flow_id(),
        environment: args.environment(),
        pack_id: args.pack_id(),
        pack_version: args.pack_version(),
        pack_digest: args.pack_digest(),
        distributor_url: args.distributor_url(),
        distributor_token: args.distributor_token(),
        preview: args.preview(),
        dry_run: args.dry_run(),
        output: args.output(),
        config_path: args.config(),
        allow_remote_in_offline: args.allow_remote_in_offline(),
    }
}

fn executable_request_data(args: &impl HasExecutableRequestArgs) -> ExecutableRequestData {
    ExecutableRequestData {
        common: common_request_data(args),
        execute_local: args.execute(),
    }
}

fn cloud_request_data(args: &impl HasCloudRequestArgs) -> CloudRequestData {
    CloudRequestData {
        executable: executable_request_data(args),
        bundle_source: args.bundle_source(),
        bundle_digest: args.bundle_digest(),
        repo_registry_base: args.repo_registry_base(),
        store_registry_base: args.store_registry_base(),
    }
}

fn default_providers_dir() -> PathBuf {
    PathBuf::from("providers/deployer")
}

fn default_packs_dir() -> PathBuf {
    PathBuf::from("packs")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        TopLevelCommand::TargetRequirements(args) => run_target_requirements(args),
        TopLevelCommand::ExtensionResolve(args) => run_extension_resolve(args),
        TopLevelCommand::ExtensionList(args) => run_extension_list(args),
        TopLevelCommand::SingleVm(command) => run_single_vm(command),
        TopLevelCommand::MultiTarget(command) => run_multi_target(command),
        TopLevelCommand::Aws(command) => cli_builtin_dispatch::dispatch_builtin_backend_command(
            BuiltinBackendCommand::Aws(command),
        ),
        TopLevelCommand::Azure(command) => cli_builtin_dispatch::dispatch_builtin_backend_command(
            BuiltinBackendCommand::Azure(command),
        ),
        TopLevelCommand::Gcp(command) => cli_builtin_dispatch::dispatch_builtin_backend_command(
            BuiltinBackendCommand::Gcp(command),
        ),
        TopLevelCommand::Helm(command) => cli_builtin_dispatch::dispatch_builtin_backend_command(
            BuiltinBackendCommand::Helm(command),
        ),
        TopLevelCommand::JujuK8s(command) => {
            cli_builtin_dispatch::dispatch_builtin_backend_command(BuiltinBackendCommand::JujuK8s(
                command,
            ))
        }
        TopLevelCommand::JujuMachine(command) => {
            cli_builtin_dispatch::dispatch_builtin_backend_command(
                BuiltinBackendCommand::JujuMachine(command),
            )
        }
        TopLevelCommand::K8sRaw(command) => cli_builtin_dispatch::dispatch_builtin_backend_command(
            BuiltinBackendCommand::K8sRaw(command),
        ),
        TopLevelCommand::Operator(command) => {
            cli_builtin_dispatch::dispatch_builtin_backend_command(BuiltinBackendCommand::Operator(
                command,
            ))
        }
        TopLevelCommand::Serverless(command) => {
            cli_builtin_dispatch::dispatch_builtin_backend_command(
                BuiltinBackendCommand::Serverless(command),
            )
        }
        TopLevelCommand::Snap(command) => cli_builtin_dispatch::dispatch_builtin_backend_command(
            BuiltinBackendCommand::Snap(command),
        ),
        TopLevelCommand::Terraform(command) => {
            cli_builtin_dispatch::dispatch_builtin_backend_command(
                BuiltinBackendCommand::Terraform(command),
            )
        }
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
    let options = DeploymentExtensionSourceOptions {
        pack_paths: args.pack_paths,
    };
    let descriptor =
        resolve_deployment_extension_contract_for_target_name_from_sources_with_options(
            &args.target,
            &options,
        )
        .ok_or_else(|| anyhow::anyhow!("unknown deployment extension target: {}", args.target))?;
    println!("{}", serde_json::to_string_pretty(&descriptor)?);
    Ok(())
}

fn run_extension_list(args: ExtensionListArgs) -> Result<()> {
    let options = DeploymentExtensionSourceOptions {
        pack_paths: args.pack_paths,
    };
    let contracts = list_deployment_extension_contracts_from_sources_with_options(&options);
    println!("{}", serde_json::to_string_pretty(&contracts)?);
    Ok(())
}

fn run_single_vm(command: SingleVmCommand) -> Result<()> {
    match command.command {
        SingleVmSubcommand::RenderSpec(args) => run_single_vm_render_spec(*args),
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
    Ok(write_single_vm_spec(&SingleVmRenderSpecRequest {
        out: args.out,
        name: args.name,
        bundle_source: args.bundle_source,
        state_dir: args.state_dir,
        cache_dir: args.cache_dir,
        log_dir: args.log_dir,
        temp_dir: args.temp_dir,
        admin_bind: args.admin_bind,
        admin_ca_file: args.admin_ca_file,
        admin_cert_file: args.admin_cert_file,
        admin_key_file: args.admin_key_file,
        image: args.image,
    })?)
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
    let shared = common_request_data(&args);

    run_multi_target_request(DeployerRequest {
        capability,
        provider: args.provider.into(),
        strategy: args.strategy,
        tenant: shared.tenant,
        environment: shared.environment,
        pack_path: shared.pack_path,
        providers_dir: default_providers_dir(),
        packs_dir: default_packs_dir(),
        provider_pack: shared.provider_pack,
        pack_id: shared.pack_id,
        pack_version: shared.pack_version,
        pack_digest: shared.pack_digest,
        distributor_url: shared.distributor_url,
        distributor_token: shared.distributor_token,
        preview: shared.preview,
        dry_run: shared.dry_run,
        execute_local: false,
        output: shared.output,
        config_path: shared.config_path,
        allow_remote_in_offline: shared.allow_remote_in_offline,
        deploy_pack_id_override: shared.deploy_pack_id_override,
        deploy_flow_id_override: shared.deploy_flow_id_override,
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
    run_executable_backend(
        capability,
        args,
        |capability, shared| terraform::TerraformRequest {
            capability,
            tenant: shared.common.tenant,
            pack_path: shared.common.pack_path,
            provider_pack: shared.common.provider_pack,
            deploy_pack_id_override: shared.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.common.deploy_flow_id_override,
            environment: shared.common.environment,
            pack_id: shared.common.pack_id,
            pack_version: shared.common.pack_version,
            pack_digest: shared.common.pack_digest,
            distributor_url: shared.common.distributor_url,
            distributor_token: shared.common.distributor_token,
            preview: shared.common.preview,
            dry_run: shared.common.dry_run,
            execute_local: shared.execute_local,
            output: shared.common.output,
            config_path: shared.common.config_path,
            allow_remote_in_offline: shared.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        terraform::resolve_config,
        terraform::run_config,
    )
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
    run_common_backend(
        capability,
        args,
        |capability, shared| k8s_raw::K8sRawRequest {
            capability,
            tenant: shared.tenant,
            pack_path: shared.pack_path,
            provider_pack: shared.provider_pack,
            deploy_pack_id_override: shared.deploy_pack_id_override,
            deploy_flow_id_override: shared.deploy_flow_id_override,
            environment: shared.environment,
            pack_id: shared.pack_id,
            pack_version: shared.pack_version,
            pack_digest: shared.pack_digest,
            distributor_url: shared.distributor_url,
            distributor_token: shared.distributor_token,
            preview: shared.preview,
            dry_run: shared.dry_run,
            execute_local: false,
            output: shared.output,
            config_path: shared.config_path,
            allow_remote_in_offline: shared.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        k8s_raw::resolve_config,
        k8s_raw::run_config,
    )
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
    run_common_backend(
        capability,
        args,
        |capability, shared| helm::HelmRequest {
            capability,
            tenant: shared.tenant,
            pack_path: shared.pack_path,
            provider_pack: shared.provider_pack,
            deploy_pack_id_override: shared.deploy_pack_id_override,
            deploy_flow_id_override: shared.deploy_flow_id_override,
            environment: shared.environment,
            pack_id: shared.pack_id,
            pack_version: shared.pack_version,
            pack_digest: shared.pack_digest,
            distributor_url: shared.distributor_url,
            distributor_token: shared.distributor_token,
            preview: shared.preview,
            dry_run: shared.dry_run,
            execute_local: false,
            output: shared.output,
            config_path: shared.config_path,
            allow_remote_in_offline: shared.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        helm::resolve_config,
        helm::run_config,
    )
}

fn run_aws(command: AwsCommand) -> Result<()> {
    if let AwsSubcommand::AdminAccess(args) = &command.command {
        return run_admin_access_command(Provider::Aws, args.clone());
    }
    if let AwsSubcommand::AdminCerts(args) = &command.command {
        return run_admin_certs_command(Provider::Aws, args.clone());
    }
    if let AwsSubcommand::AdminToken(args) = &command.command {
        return run_admin_token_command(Provider::Aws, args.clone());
    }
    if let AwsSubcommand::AdminHealth(args) = &command.command {
        return run_admin_health_command(Provider::Aws, args.clone());
    }
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
        AwsSubcommand::AdminAccess(_) => unreachable!("handled above"),
        AwsSubcommand::AdminCerts(_) => unreachable!("handled above"),
        AwsSubcommand::AdminToken(_) => unreachable!("handled above"),
        AwsSubcommand::AdminHealth(_) => unreachable!("handled above"),
        AwsSubcommand::AdminTunnel(_) => unreachable!("handled above"),
    };
    run_cloud_backend(
        capability,
        args,
        |capability, shared| aws::AwsRequest {
            capability,
            tenant: shared.executable.common.tenant,
            pack_path: shared.executable.common.pack_path,
            bundle_source: shared.bundle_source,
            bundle_digest: shared.bundle_digest,
            repo_registry_base: shared.repo_registry_base,
            store_registry_base: shared.store_registry_base,
            provider_pack: shared.executable.common.provider_pack,
            deploy_pack_id_override: shared.executable.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.executable.common.deploy_flow_id_override,
            environment: shared.executable.common.environment,
            pack_id: shared.executable.common.pack_id,
            pack_version: shared.executable.common.pack_version,
            pack_digest: shared.executable.common.pack_digest,
            distributor_url: shared.executable.common.distributor_url,
            distributor_token: shared.executable.common.distributor_token,
            preview: shared.executable.common.preview,
            dry_run: shared.executable.common.dry_run,
            execute_local: shared.executable.execute_local,
            output: shared.executable.common.output,
            config_path: shared.executable.common.config_path,
            allow_remote_in_offline: shared.executable.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        aws::resolve_config,
        aws::run_config,
    )
}

fn run_aws_admin_tunnel(args: AwsAdminTunnelArgs) -> Result<()> {
    Ok(aws::run_admin_tunnel(AwsAdminTunnelRequest {
        bundle_dir: args.bundle_dir,
        local_port: args.local_port,
        container: args.container,
    })?)
}

fn run_azure(command: AzureCommand) -> Result<()> {
    if let AzureSubcommand::AdminAccess(args) = &command.command {
        return run_admin_access_command(Provider::Azure, args.clone());
    }
    if let AzureSubcommand::AdminCerts(args) = &command.command {
        return run_admin_certs_command(Provider::Azure, args.clone());
    }
    if let AzureSubcommand::AdminToken(args) = &command.command {
        return run_admin_token_command(Provider::Azure, args.clone());
    }
    if let AzureSubcommand::AdminHealth(args) = &command.command {
        return run_admin_health_command(Provider::Azure, args.clone());
    }
    let (capability, args) = match command.command {
        AzureSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        AzureSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        AzureSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        AzureSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        AzureSubcommand::Status(args) => (DeployerCapability::Status, args),
        AzureSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
        AzureSubcommand::AdminAccess(_) => unreachable!("handled above"),
        AzureSubcommand::AdminCerts(_) => unreachable!("handled above"),
        AzureSubcommand::AdminToken(_) => unreachable!("handled above"),
        AzureSubcommand::AdminHealth(_) => unreachable!("handled above"),
    };
    run_cloud_backend(
        capability,
        args,
        |capability, shared| azure::AzureRequest {
            capability,
            tenant: shared.executable.common.tenant,
            pack_path: shared.executable.common.pack_path,
            bundle_source: shared.bundle_source,
            bundle_digest: shared.bundle_digest,
            repo_registry_base: shared.repo_registry_base,
            store_registry_base: shared.store_registry_base,
            provider_pack: shared.executable.common.provider_pack,
            deploy_pack_id_override: shared.executable.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.executable.common.deploy_flow_id_override,
            environment: shared.executable.common.environment,
            pack_id: shared.executable.common.pack_id,
            pack_version: shared.executable.common.pack_version,
            pack_digest: shared.executable.common.pack_digest,
            distributor_url: shared.executable.common.distributor_url,
            distributor_token: shared.executable.common.distributor_token,
            preview: shared.executable.common.preview,
            dry_run: shared.executable.common.dry_run,
            execute_local: shared.executable.execute_local,
            output: shared.executable.common.output,
            config_path: shared.executable.common.config_path,
            allow_remote_in_offline: shared.executable.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        azure::resolve_config,
        azure::run_config,
    )
}

fn run_gcp(command: GcpCommand) -> Result<()> {
    if let GcpSubcommand::AdminAccess(args) = &command.command {
        return run_admin_access_command(Provider::Gcp, args.clone());
    }
    if let GcpSubcommand::AdminCerts(args) = &command.command {
        return run_admin_certs_command(Provider::Gcp, args.clone());
    }
    if let GcpSubcommand::AdminToken(args) = &command.command {
        return run_admin_token_command(Provider::Gcp, args.clone());
    }
    if let GcpSubcommand::AdminHealth(args) = &command.command {
        return run_admin_health_command(Provider::Gcp, args.clone());
    }
    let (capability, args) = match command.command {
        GcpSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        GcpSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        GcpSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        GcpSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        GcpSubcommand::Status(args) => (DeployerCapability::Status, args),
        GcpSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
        GcpSubcommand::AdminAccess(_) => unreachable!("handled above"),
        GcpSubcommand::AdminCerts(_) => unreachable!("handled above"),
        GcpSubcommand::AdminToken(_) => unreachable!("handled above"),
        GcpSubcommand::AdminHealth(_) => unreachable!("handled above"),
    };
    run_cloud_backend(
        capability,
        args,
        |capability, shared| gcp::GcpRequest {
            capability,
            tenant: shared.executable.common.tenant,
            pack_path: shared.executable.common.pack_path,
            bundle_source: shared.bundle_source,
            bundle_digest: shared.bundle_digest,
            repo_registry_base: shared.repo_registry_base,
            store_registry_base: shared.store_registry_base,
            provider_pack: shared.executable.common.provider_pack,
            deploy_pack_id_override: shared.executable.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.executable.common.deploy_flow_id_override,
            environment: shared.executable.common.environment,
            pack_id: shared.executable.common.pack_id,
            pack_version: shared.executable.common.pack_version,
            pack_digest: shared.executable.common.pack_digest,
            distributor_url: shared.executable.common.distributor_url,
            distributor_token: shared.executable.common.distributor_token,
            preview: shared.executable.common.preview,
            dry_run: shared.executable.common.dry_run,
            execute_local: shared.executable.execute_local,
            output: shared.executable.common.output,
            config_path: shared.executable.common.config_path,
            allow_remote_in_offline: shared.executable.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        gcp::resolve_config,
        gcp::run_config,
    )
}

fn run_admin_access_command(provider: Provider, args: AdminAccessArgs) -> Result<()> {
    let info = resolve_admin_access(&args.bundle_dir, provider)?;
    println!(
        "{}",
        render_admin_access_summary(provider, info.tunnel_support.supported, args.output.into(),)?
    );
    Ok(())
}

fn run_admin_certs_command(provider: Provider, args: AdminAccessArgs) -> Result<()> {
    materialize_admin_client_certs(&args.bundle_dir, provider)?;
    println!(
        "{}",
        render_admin_certs_summary(provider, args.output.into())?
    );
    Ok(())
}

fn run_admin_token_command(provider: Provider, args: AdminAccessArgs) -> Result<()> {
    let token = materialize_admin_relay_token(&args.bundle_dir, provider)?;
    let info = resolve_admin_access(&args.bundle_dir, provider)?;
    std::fs::create_dir_all(&info.local_cert_dir)?;
    let token_path = info.local_cert_dir.join("relay.token");
    std::fs::write(&token_path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!(
        "{}",
        render_materialized_admin_relay_token_path(provider, &token_path, args.output.into())?
    );
    Ok(())
}

fn render_materialized_admin_relay_token_path(
    provider: Provider,
    token_path: &Path,
    output: OutputFormat,
) -> Result<String> {
    let provider_name = provider.as_str();
    let token_path = token_path.display().to_string();
    match output {
        OutputFormat::Text => Ok(format!(
            "provider: {provider_name}\ntoken_path: {token_path}"
        )),
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "provider": provider_name,
            "token_path": token_path,
        }))?),
        OutputFormat::Yaml => Ok(serde_yaml::to_string(&serde_json::json!({
            "provider": provider_name,
            "token_path": token_path,
        }))?),
    }
}

fn render_admin_access_summary(
    provider: Provider,
    tunnel_supported: bool,
    output: OutputFormat,
) -> Result<String> {
    let provider_name = provider.as_str();
    match output {
        OutputFormat::Text => Ok(format!(
            "provider: {provider_name}\ntunnel_supported: {tunnel_supported}"
        )),
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "provider": provider_name,
            "tunnel_supported": tunnel_supported,
        }))?),
        OutputFormat::Yaml => Ok(serde_yaml::to_string(&serde_json::json!({
            "provider": provider_name,
            "tunnel_supported": tunnel_supported,
        }))?),
    }
}

fn render_admin_certs_summary(provider: Provider, output: OutputFormat) -> Result<String> {
    let provider_name = provider.as_str();
    match output {
        OutputFormat::Text => Ok(format!(
            "provider: {provider_name}\ncerts_materialized: true"
        )),
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "provider": provider_name,
            "certs_materialized": true,
        }))?),
        OutputFormat::Yaml => Ok(serde_yaml::to_string(&serde_json::json!({
            "provider": provider_name,
            "certs_materialized": true,
        }))?),
    }
}

fn run_admin_health_command(provider: Provider, args: AdminAccessArgs) -> Result<()> {
    let probe = probe_admin_health(&args.bundle_dir, provider)?;
    println!("{}", render_admin_health_probe(&probe, args.output.into())?);
    Ok(())
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
    run_executable_backend(
        capability,
        args,
        |capability, shared| operator::OperatorRequest {
            capability,
            tenant: shared.common.tenant,
            pack_path: shared.common.pack_path,
            provider_pack: shared.common.provider_pack,
            deploy_pack_id_override: shared.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.common.deploy_flow_id_override,
            environment: shared.common.environment,
            pack_id: shared.common.pack_id,
            pack_version: shared.common.pack_version,
            pack_digest: shared.common.pack_digest,
            distributor_url: shared.common.distributor_url,
            distributor_token: shared.common.distributor_token,
            preview: shared.common.preview,
            dry_run: shared.common.dry_run,
            execute_local: shared.execute_local,
            output: shared.common.output,
            config_path: shared.common.config_path,
            allow_remote_in_offline: shared.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        operator::resolve_config,
        operator::run_config,
    )
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
    run_executable_backend(
        capability,
        args,
        |capability, shared| serverless::ServerlessRequest {
            capability,
            tenant: shared.common.tenant,
            pack_path: shared.common.pack_path,
            provider_pack: shared.common.provider_pack,
            deploy_pack_id_override: shared.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.common.deploy_flow_id_override,
            environment: shared.common.environment,
            pack_id: shared.common.pack_id,
            pack_version: shared.common.pack_version,
            pack_digest: shared.common.pack_digest,
            distributor_url: shared.common.distributor_url,
            distributor_token: shared.common.distributor_token,
            preview: shared.common.preview,
            dry_run: shared.common.dry_run,
            execute_local: shared.execute_local,
            output: shared.common.output,
            config_path: shared.common.config_path,
            allow_remote_in_offline: shared.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        serverless::resolve_config,
        serverless::run_config,
    )
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
    run_executable_backend(
        capability,
        args,
        |capability, shared| snap::SnapRequest {
            capability,
            tenant: shared.common.tenant,
            pack_path: shared.common.pack_path,
            provider_pack: shared.common.provider_pack,
            deploy_pack_id_override: shared.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.common.deploy_flow_id_override,
            environment: shared.common.environment,
            pack_id: shared.common.pack_id,
            pack_version: shared.common.pack_version,
            pack_digest: shared.common.pack_digest,
            distributor_url: shared.common.distributor_url,
            distributor_token: shared.common.distributor_token,
            preview: shared.common.preview,
            dry_run: shared.common.dry_run,
            execute_local: shared.execute_local,
            output: shared.common.output,
            config_path: shared.common.config_path,
            allow_remote_in_offline: shared.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        snap::resolve_config,
        snap::run_config,
    )
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
    run_executable_backend(
        capability,
        args,
        |capability, shared| juju_machine::JujuMachineRequest {
            capability,
            tenant: shared.common.tenant,
            pack_path: shared.common.pack_path,
            provider_pack: shared.common.provider_pack,
            deploy_pack_id_override: shared.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.common.deploy_flow_id_override,
            environment: shared.common.environment,
            pack_id: shared.common.pack_id,
            pack_version: shared.common.pack_version,
            pack_digest: shared.common.pack_digest,
            distributor_url: shared.common.distributor_url,
            distributor_token: shared.common.distributor_token,
            preview: shared.common.preview,
            dry_run: shared.common.dry_run,
            execute_local: shared.execute_local,
            output: shared.common.output,
            config_path: shared.common.config_path,
            allow_remote_in_offline: shared.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        juju_machine::resolve_config,
        juju_machine::run_config,
    )
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
    run_executable_backend(
        capability,
        args,
        |capability, shared| juju_k8s::JujuK8sRequest {
            capability,
            tenant: shared.common.tenant,
            pack_path: shared.common.pack_path,
            provider_pack: shared.common.provider_pack,
            deploy_pack_id_override: shared.common.deploy_pack_id_override,
            deploy_flow_id_override: shared.common.deploy_flow_id_override,
            environment: shared.common.environment,
            pack_id: shared.common.pack_id,
            pack_version: shared.common.pack_version,
            pack_digest: shared.common.pack_digest,
            distributor_url: shared.common.distributor_url,
            distributor_token: shared.common.distributor_token,
            preview: shared.common.preview,
            dry_run: shared.common.dry_run,
            execute_local: shared.execute_local,
            output: shared.common.output,
            config_path: shared.common.config_path,
            allow_remote_in_offline: shared.common.allow_remote_in_offline,
            providers_dir: default_providers_dir(),
            packs_dir: default_packs_dir(),
        },
        juju_k8s::resolve_config,
        juju_k8s::run_config,
    )
}

fn run_multi_target_request(request: DeployerRequest) -> Result<()> {
    let config = DeployerConfig::resolve(request)?;
    run_backend_operation(config.output, run_builtin_extension(config))
}

fn run_backend_operation<Fut>(output_format: OutputFormat, future: Fut) -> Result<()>
where
    Fut: Future<Output = greentic_deployer::error::Result<greentic_deployer::OperationResult>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(future)?;
    print_multi_target_operation_result(&result, output_format)
}

fn run_common_backend<Args, Req, BuildReq, ResolveCfg, RunCfg, Fut>(
    capability: DeployerCapability,
    args: Args,
    build_request: BuildReq,
    resolve_config: ResolveCfg,
    run_config: RunCfg,
) -> Result<()>
where
    Args: HasCommonRequestArgs,
    BuildReq: FnOnce(DeployerCapability, CommonRequestData) -> Req,
    ResolveCfg: FnOnce(Req) -> greentic_deployer::error::Result<DeployerConfig>,
    RunCfg: FnOnce(DeployerConfig) -> Fut,
    Fut: Future<Output = greentic_deployer::error::Result<greentic_deployer::OperationResult>>,
{
    let shared = common_request_data(&args);
    let config = resolve_config(build_request(capability, shared))?;
    run_backend_operation(config.output, run_config(config))
}

fn run_executable_backend<Args, Req, BuildReq, ResolveCfg, RunCfg, Fut>(
    capability: DeployerCapability,
    args: Args,
    build_request: BuildReq,
    resolve_config: ResolveCfg,
    run_config: RunCfg,
) -> Result<()>
where
    Args: HasExecutableRequestArgs,
    BuildReq: FnOnce(DeployerCapability, ExecutableRequestData) -> Req,
    ResolveCfg: FnOnce(Req) -> greentic_deployer::error::Result<DeployerConfig>,
    RunCfg: FnOnce(DeployerConfig) -> Fut,
    Fut: Future<Output = greentic_deployer::error::Result<greentic_deployer::OperationResult>>,
{
    let shared = executable_request_data(&args);
    let config = resolve_config(build_request(capability, shared))?;
    run_backend_operation(config.output, run_config(config))
}

fn run_cloud_backend<Args, Req, BuildReq, ResolveCfg, RunCfg, Fut>(
    capability: DeployerCapability,
    args: Args,
    build_request: BuildReq,
    resolve_config: ResolveCfg,
    run_config: RunCfg,
) -> Result<()>
where
    Args: HasCloudRequestArgs,
    BuildReq: FnOnce(DeployerCapability, CloudRequestData) -> Req,
    ResolveCfg: FnOnce(Req) -> greentic_deployer::error::Result<DeployerConfig>,
    RunCfg: FnOnce(DeployerConfig) -> Fut,
    Fut: Future<Output = greentic_deployer::error::Result<greentic_deployer::OperationResult>>,
{
    let shared = cloud_request_data(&args);
    let config = resolve_config(build_request(capability, shared))?;
    run_backend_operation(config.output, run_config(config))
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

#[cfg(test)]
mod tests {
    use super::run_extension_resolve;

    #[test]
    fn extension_resolve_supports_single_vm_builtin_target() {
        let args = super::ExtensionResolveArgs {
            target: "single-vm".to_string(),
            pack_paths: Vec::new(),
        };
        run_extension_resolve(args).expect("single-vm extension");
    }

    #[test]
    fn extension_resolve_supports_cloud_builtin_target() {
        let args = super::ExtensionResolveArgs {
            target: "aws".to_string(),
            pack_paths: Vec::new(),
        };
        run_extension_resolve(args).expect("aws extension");
    }
}
