use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

use greentic_deployer::{
    DeployerCapability, DeployerConfig, DeployerRequest, OutputFormat, Provider,
    SingleVmApplyOptions, SingleVmDestroyOptions, apply_single_vm_plan_output_with_options, aws,
    azure, destroy_single_vm_plan_output_with_options, gcp, helm, juju_k8s, juju_machine, k8s_raw,
    multi_target, operator, plan_single_vm_spec_path, preview_single_vm_apply_plan_output,
    preview_single_vm_destroy_plan_output, render_operation_result, render_single_vm_apply_report,
    render_single_vm_destroy_report, render_single_vm_plan_output, render_single_vm_status_report,
    serverless, snap, status_single_vm_plan_output, terraform,
};

#[derive(Parser)]
#[command(name = "greentic-deployer", version, about = "Greentic deployer CLI")]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Subcommand)]
enum TopLevelCommand {
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
    #[arg(long)]
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
    #[arg(long)]
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
    #[arg(long)]
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
    #[arg(long)]
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
    #[arg(long)]
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
struct AzureArgs {
    #[arg(long)]
    tenant: String,
    #[arg(long)]
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
struct GcpArgs {
    #[arg(long)]
    tenant: String,
    #[arg(long)]
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
struct JujuK8sArgs {
    #[arg(long)]
    tenant: String,
    #[arg(long)]
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
    #[arg(long)]
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
    #[arg(long)]
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
    #[arg(long)]
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
    #[arg(long)]
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

fn run_single_vm(command: SingleVmCommand) -> Result<()> {
    match command.command {
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
    let (capability, args) = match command.command {
        AwsSubcommand::Generate(args) => (DeployerCapability::Generate, args),
        AwsSubcommand::Plan(args) => (DeployerCapability::Plan, args),
        AwsSubcommand::Apply(args) => (DeployerCapability::Apply, args),
        AwsSubcommand::Destroy(args) => (DeployerCapability::Destroy, args),
        AwsSubcommand::Status(args) => (DeployerCapability::Status, args),
        AwsSubcommand::Rollback(args) => (DeployerCapability::Rollback, args),
    };

    let request = aws::AwsRequest {
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
    let config = aws::resolve_config(request)?;
    let output_format = config.output;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(aws::run_config(config))?;
    print_multi_target_operation_result(&result, output_format)
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
