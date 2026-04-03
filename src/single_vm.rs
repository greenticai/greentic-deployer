use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::config::OutputFormat;
use crate::error::{DeployerError, Result};
use crate::spec::{
    AdminEndpointSpec, BundleFormat, BundleSpec, DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1,
    DEPLOYMENT_SPEC_KIND, DeploymentMetadata, DeploymentSpecBody, DeploymentSpecV1,
    DeploymentTarget, HealthSpec, LinuxArch, MtlsSpec, RolloutSpec, RolloutStrategy, RuntimeSpec,
    ServiceManager, ServiceSpec, StorageSpec,
};

const DEFAULT_RUNTIME_SERVICE_NAME: &str = "greentic-runtime";
const DEFAULT_BUNDLE_MOUNT_ROOT: &str = "/mnt/greentic/bundles";
const DEFAULT_ENV_FILE_ROOT: &str = "/etc/greentic";
const DEFAULT_STATE_FILE_NAME: &str = "single-vm-state.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmPlan {
    pub deployment_name: String,
    pub service_name: String,
    pub arch: LinuxArch,
    pub runtime: SingleVmRuntimePlan,
    pub bundle: SingleVmBundlePlan,
    pub storage: SingleVmStoragePlan,
    pub admin: SingleVmAdminPlan,
    pub service: SingleVmServicePlan,
    pub health: SingleVmHealthPlan,
    pub rollout: SingleVmRolloutPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmRuntimePlan {
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmBundlePlan {
    pub source: String,
    pub format: BundleFormat,
    pub read_only: bool,
    pub mount_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmStoragePlan {
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub log_dir: PathBuf,
    pub temp_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmAdminPlan {
    pub bind: String,
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmServicePlan {
    pub manager: ServiceManager,
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmHealthPlan {
    pub readiness_path: String,
    pub liveness_path: String,
    pub startup_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmRolloutPlan {
    pub strategy: RolloutStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmPlanOutput {
    pub plan: SingleVmPlan,
    pub service_unit_name: String,
    pub env_file_path: PathBuf,
    pub directories: Vec<PathBuf>,
    pub files: Vec<SingleVmPlannedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmPlannedFile {
    pub path: PathBuf,
    pub kind: SingleVmPlannedFileKind,
    pub contents: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SingleVmPlannedFileKind {
    SystemdUnit,
    EnvironmentFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmApplyReport {
    pub directories_created: Vec<PathBuf>,
    pub files_written: Vec<PathBuf>,
    pub commands_run: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmDestroyReport {
    pub files_removed: Vec<PathBuf>,
    pub directories_removed: Vec<PathBuf>,
    pub commands_run: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmPersistedState {
    pub deployment_name: String,
    pub service_unit_name: String,
    pub runtime_image: String,
    pub bundle_source: String,
    pub admin_bind: String,
    pub last_action: SingleVmLastAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SingleVmLastAction {
    Apply,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVmStatusReport {
    pub state_path: PathBuf,
    pub status: SingleVmDeploymentStatus,
    pub service_unit_name: String,
    pub service_unit_path: PathBuf,
    pub env_file_path: PathBuf,
    pub state_exists: bool,
    pub bundle_mount_exists: bool,
    pub present_directories: Vec<PathBuf>,
    pub missing_directories: Vec<PathBuf>,
    pub present_files: Vec<PathBuf>,
    pub missing_files: Vec<PathBuf>,
    pub state: Option<SingleVmPersistedState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SingleVmDeploymentStatus {
    NotInstalled,
    Partial,
    Applied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SingleVmApplyOptions {
    pub pull_image: bool,
    pub daemon_reload: bool,
    pub enable_service: bool,
    pub restart_service: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SingleVmDestroyOptions {
    pub stop_service: bool,
    pub disable_service: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleVmRenderSpecRequest {
    pub out: PathBuf,
    pub name: String,
    pub bundle_source: String,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub log_dir: PathBuf,
    pub temp_dir: PathBuf,
    pub admin_bind: String,
    pub admin_ca_file: PathBuf,
    pub admin_cert_file: PathBuf,
    pub admin_key_file: PathBuf,
    pub image: String,
}

pub fn write_single_vm_spec(args: &SingleVmRenderSpecRequest) -> Result<()> {
    let spec = DeploymentSpecV1 {
        api_version: DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1.to_string(),
        kind: DEPLOYMENT_SPEC_KIND.to_string(),
        metadata: DeploymentMetadata {
            name: args.name.clone(),
        },
        spec: DeploymentSpecBody {
            target: DeploymentTarget::SingleVm,
            bundle: BundleSpec {
                source: args.bundle_source.clone(),
                format: BundleFormat::Squashfs,
            },
            runtime: RuntimeSpec {
                image: args.image.clone(),
                arch: LinuxArch::X86_64,
                admin: AdminEndpointSpec {
                    bind: args.admin_bind.clone(),
                    mtls: MtlsSpec {
                        ca_file: args.admin_ca_file.clone(),
                        cert_file: args.admin_cert_file.clone(),
                        key_file: args.admin_key_file.clone(),
                    },
                },
            },
            storage: StorageSpec {
                state_dir: args.state_dir.clone(),
                cache_dir: args.cache_dir.clone(),
                log_dir: args.log_dir.clone(),
                temp_dir: args.temp_dir.clone(),
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
    let spec_yaml = serde_yaml_bw::to_string(&spec).map_err(|err| {
        DeployerError::Other(format!("failed to serialize single-vm spec: {err}"))
    })?;
    fs::write(&args.out, spec_yaml)?;
    Ok(())
}

pub fn build_single_vm_plan(spec: &DeploymentSpecV1) -> Result<SingleVmPlan> {
    spec.validate()?;

    if spec.spec.target != DeploymentTarget::SingleVm {
        return Err(DeployerError::Config(format!(
            "single-vm planner does not support target {:?}",
            spec.spec.target
        )));
    }

    if spec.metadata.name.contains('/') || spec.metadata.name.contains('\\') {
        return Err(DeployerError::Config(
            "deployment metadata.name must not contain path separators".to_string(),
        ));
    }

    let service_name = sanitize_service_name(&spec.metadata.name);
    let mount_path = PathBuf::from(DEFAULT_BUNDLE_MOUNT_ROOT).join(&spec.metadata.name);

    Ok(SingleVmPlan {
        deployment_name: spec.metadata.name.clone(),
        service_name,
        arch: spec.spec.runtime.arch.clone(),
        runtime: SingleVmRuntimePlan {
            image: spec.spec.runtime.image.clone(),
        },
        bundle: SingleVmBundlePlan {
            source: spec.spec.bundle.source.clone(),
            format: spec.spec.bundle.format.clone(),
            read_only: true,
            mount_path,
        },
        storage: SingleVmStoragePlan {
            state_dir: spec.spec.storage.state_dir.clone(),
            cache_dir: spec.spec.storage.cache_dir.clone(),
            log_dir: spec.spec.storage.log_dir.clone(),
            temp_dir: spec.spec.storage.temp_dir.clone(),
        },
        admin: SingleVmAdminPlan {
            bind: spec.spec.runtime.admin.bind.clone(),
            ca_file: spec.spec.runtime.admin.mtls.ca_file.clone(),
            cert_file: spec.spec.runtime.admin.mtls.cert_file.clone(),
            key_file: spec.spec.runtime.admin.mtls.key_file.clone(),
        },
        service: SingleVmServicePlan {
            manager: spec.spec.service.manager.clone(),
            user: spec.spec.service.user.clone(),
            group: spec.spec.service.group.clone(),
        },
        health: SingleVmHealthPlan {
            readiness_path: spec.spec.health.readiness_path.clone(),
            liveness_path: spec.spec.health.liveness_path.clone(),
            startup_timeout_seconds: spec.spec.health.startup_timeout_seconds,
        },
        rollout: SingleVmRolloutPlan {
            strategy: spec.spec.rollout.strategy.clone(),
        },
    })
}

pub fn plan_single_vm_spec(spec: &DeploymentSpecV1) -> Result<SingleVmPlanOutput> {
    let plan = build_single_vm_plan(spec)?;
    Ok(render_single_vm_plan(&plan))
}

pub fn plan_single_vm_spec_path(path: impl AsRef<std::path::Path>) -> Result<SingleVmPlanOutput> {
    let spec = DeploymentSpecV1::from_path(path)?;
    plan_single_vm_spec(&spec)
}

pub fn render_single_vm_plan(plan: &SingleVmPlan) -> SingleVmPlanOutput {
    let service_unit_name = format!("{}.service", plan.service_name);
    let env_file_path =
        PathBuf::from(DEFAULT_ENV_FILE_ROOT).join(format!("{}.env", plan.service_name));
    let service_unit_path = PathBuf::from("/etc/systemd/system").join(&service_unit_name);

    let directories = vec![
        plan.storage.state_dir.clone(),
        plan.storage.cache_dir.clone(),
        plan.storage.log_dir.clone(),
        plan.storage.temp_dir.clone(),
        plan.bundle.mount_path.clone(),
        env_file_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(DEFAULT_ENV_FILE_ROOT))
            .to_path_buf(),
    ];

    let files = vec![
        SingleVmPlannedFile {
            path: service_unit_path,
            kind: SingleVmPlannedFileKind::SystemdUnit,
            contents: render_systemd_unit(plan, &env_file_path),
        },
        SingleVmPlannedFile {
            path: env_file_path.clone(),
            kind: SingleVmPlannedFileKind::EnvironmentFile,
            contents: render_env_file(plan),
        },
    ];

    SingleVmPlanOutput {
        plan: plan.clone(),
        service_unit_name,
        env_file_path,
        directories,
        files,
    }
}

pub fn apply_single_vm_plan_output(output: &SingleVmPlanOutput) -> Result<SingleVmApplyReport> {
    apply_single_vm_plan_output_with_options(output, &SingleVmApplyOptions::default())
}

pub fn preview_single_vm_apply_plan_output(output: &SingleVmPlanOutput) -> SingleVmApplyReport {
    SingleVmApplyReport {
        directories_created: output.directories.clone(),
        files_written: output.files.iter().map(|file| file.path.clone()).collect(),
        commands_run: Vec::new(),
    }
}

pub fn apply_single_vm_plan_output_with_options(
    output: &SingleVmPlanOutput,
    options: &SingleVmApplyOptions,
) -> Result<SingleVmApplyReport> {
    let mut directories_created = Vec::new();
    let mut files_written = Vec::new();
    let mut commands_run = Vec::new();

    for dir in &output.directories {
        fs::create_dir_all(dir).map_err(|err| {
            DeployerError::Io(std::io::Error::new(
                err.kind(),
                format!("failed to create directory {}: {err}", dir.display()),
            ))
        })?;
        directories_created.push(dir.clone());
    }

    for file in &output.files {
        if let Some(parent) = file.path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                DeployerError::Io(std::io::Error::new(
                    err.kind(),
                    format!(
                        "failed to create parent directory {} for {}: {err}",
                        parent.display(),
                        file.path.display()
                    ),
                ))
            })?;
        }
        fs::write(&file.path, &file.contents).map_err(|err| {
            DeployerError::Io(std::io::Error::new(
                err.kind(),
                format!("failed to write {}: {err}", file.path.display()),
            ))
        })?;
        files_written.push(file.path.clone());
    }

    if options.pull_image {
        run_command(
            &mut commands_run,
            "docker",
            &["pull", output.plan.runtime.image.as_str()],
        )?;
    }
    if options.daemon_reload {
        run_command(&mut commands_run, "systemctl", &["daemon-reload"])?;
    }
    if options.enable_service {
        run_command(
            &mut commands_run,
            "systemctl",
            &["enable", output.service_unit_name.as_str()],
        )?;
    }
    if options.restart_service {
        run_command(
            &mut commands_run,
            "systemctl",
            &["restart", output.service_unit_name.as_str()],
        )?;
    }

    write_single_vm_state(output)?;

    Ok(SingleVmApplyReport {
        directories_created,
        files_written,
        commands_run,
    })
}

pub fn apply_single_vm_spec(spec: &DeploymentSpecV1) -> Result<SingleVmApplyReport> {
    let output = plan_single_vm_spec(spec)?;
    apply_single_vm_plan_output(&output)
}

pub fn apply_single_vm_spec_path(path: impl AsRef<Path>) -> Result<SingleVmApplyReport> {
    let output = plan_single_vm_spec_path(path)?;
    apply_single_vm_plan_output(&output)
}

pub fn destroy_single_vm_plan_output(output: &SingleVmPlanOutput) -> Result<SingleVmDestroyReport> {
    destroy_single_vm_plan_output_with_options(output, &SingleVmDestroyOptions::default())
}

pub fn preview_single_vm_destroy_plan_output(output: &SingleVmPlanOutput) -> SingleVmDestroyReport {
    SingleVmDestroyReport {
        files_removed: output.files.iter().map(|file| file.path.clone()).collect(),
        directories_removed: output.directories.clone(),
        commands_run: Vec::new(),
    }
}

pub fn destroy_single_vm_plan_output_with_options(
    output: &SingleVmPlanOutput,
    options: &SingleVmDestroyOptions,
) -> Result<SingleVmDestroyReport> {
    let mut files_removed = Vec::new();
    let mut directories_removed = Vec::new();
    let mut commands_run = Vec::new();

    if options.stop_service {
        run_command(
            &mut commands_run,
            "systemctl",
            &["stop", output.service_unit_name.as_str()],
        )?;
    }
    if options.disable_service {
        run_command(
            &mut commands_run,
            "systemctl",
            &["disable", output.service_unit_name.as_str()],
        )?;
    }

    let state_path = single_vm_state_path(&output.plan);
    if state_path.exists() {
        fs::remove_file(&state_path).map_err(|err| {
            DeployerError::Io(std::io::Error::new(
                err.kind(),
                format!("failed to remove {}: {err}", state_path.display()),
            ))
        })?;
        files_removed.push(state_path);
    }

    for file in &output.files {
        if file.path.exists() {
            fs::remove_file(&file.path).map_err(|err| {
                DeployerError::Io(std::io::Error::new(
                    err.kind(),
                    format!("failed to remove {}: {err}", file.path.display()),
                ))
            })?;
            files_removed.push(file.path.clone());
        }
    }

    let mut dirs = output.directories.clone();
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    dirs.dedup();
    for dir in dirs {
        if dir.exists() && is_directory_empty(&dir)? {
            fs::remove_dir(&dir).map_err(|err| {
                DeployerError::Io(std::io::Error::new(
                    err.kind(),
                    format!("failed to remove directory {}: {err}", dir.display()),
                ))
            })?;
            directories_removed.push(dir);
        }
    }

    Ok(SingleVmDestroyReport {
        files_removed,
        directories_removed,
        commands_run,
    })
}

pub fn destroy_single_vm_spec(spec: &DeploymentSpecV1) -> Result<SingleVmDestroyReport> {
    let output = plan_single_vm_spec(spec)?;
    destroy_single_vm_plan_output(&output)
}

pub fn destroy_single_vm_spec_path(path: impl AsRef<Path>) -> Result<SingleVmDestroyReport> {
    let output = plan_single_vm_spec_path(path)?;
    destroy_single_vm_plan_output(&output)
}

pub fn status_single_vm_plan_output(output: &SingleVmPlanOutput) -> Result<SingleVmStatusReport> {
    let state_path = single_vm_state_path(&output.plan);
    let state = load_single_vm_state(&state_path)?;

    let mut present_directories = Vec::new();
    let mut missing_directories = Vec::new();
    for dir in &output.directories {
        if dir.exists() {
            present_directories.push(dir.clone());
        } else {
            missing_directories.push(dir.clone());
        }
    }

    let mut present_files = Vec::new();
    let mut missing_files = Vec::new();
    for file in &output.files {
        if file.path.exists() {
            present_files.push(file.path.clone());
        } else {
            missing_files.push(file.path.clone());
        }
    }

    let bundle_mount_exists = output.plan.bundle.mount_path.exists();
    let status = if state.is_some() && missing_files.is_empty() {
        SingleVmDeploymentStatus::Applied
    } else if state.is_none()
        && missing_files.len() == output.files.len()
        && missing_directories.len() == output.directories.len()
        && !bundle_mount_exists
    {
        SingleVmDeploymentStatus::NotInstalled
    } else {
        SingleVmDeploymentStatus::Partial
    };

    Ok(SingleVmStatusReport {
        state_path,
        status,
        service_unit_name: output.service_unit_name.clone(),
        service_unit_path: output
            .files
            .iter()
            .find(|file| matches!(file.kind, SingleVmPlannedFileKind::SystemdUnit))
            .map(|file| file.path.clone())
            .unwrap_or_else(|| {
                PathBuf::from("/etc/systemd/system").join(&output.service_unit_name)
            }),
        env_file_path: output.env_file_path.clone(),
        state_exists: state.is_some(),
        bundle_mount_exists,
        present_directories,
        missing_directories,
        present_files,
        missing_files,
        state,
    })
}

pub fn status_single_vm_spec(spec: &DeploymentSpecV1) -> Result<SingleVmStatusReport> {
    let output = plan_single_vm_spec(spec)?;
    status_single_vm_plan_output(&output)
}

pub fn status_single_vm_spec_path(path: impl AsRef<Path>) -> Result<SingleVmStatusReport> {
    let output = plan_single_vm_spec_path(path)?;
    status_single_vm_plan_output(&output)
}

pub fn render_single_vm_plan_output(
    output: &SingleVmPlanOutput,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(output).map_err(|err| {
            DeployerError::Other(format!("failed to render single-vm plan as JSON: {err}"))
        }),
        OutputFormat::Yaml => serde_yaml_bw::to_string(output).map_err(|err| {
            DeployerError::Other(format!("failed to render single-vm plan as YAML: {err}"))
        }),
        OutputFormat::Text => Ok(render_single_vm_plan_output_text(output)),
    }
}

pub fn render_single_vm_apply_report(
    report: &SingleVmApplyReport,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|err| {
            DeployerError::Other(format!(
                "failed to render single-vm apply report as JSON: {err}"
            ))
        }),
        OutputFormat::Yaml => serde_yaml_bw::to_string(report).map_err(|err| {
            DeployerError::Other(format!(
                "failed to render single-vm apply report as YAML: {err}"
            ))
        }),
        OutputFormat::Text => Ok(render_single_vm_apply_report_text(report)),
    }
}

pub fn render_single_vm_destroy_report(
    report: &SingleVmDestroyReport,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|err| {
            DeployerError::Other(format!(
                "failed to render single-vm destroy report as JSON: {err}"
            ))
        }),
        OutputFormat::Yaml => serde_yaml_bw::to_string(report).map_err(|err| {
            DeployerError::Other(format!(
                "failed to render single-vm destroy report as YAML: {err}"
            ))
        }),
        OutputFormat::Text => Ok(render_single_vm_destroy_report_text(report)),
    }
}

pub fn render_single_vm_status_report(
    report: &SingleVmStatusReport,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|err| {
            DeployerError::Other(format!(
                "failed to render single-vm status report as JSON: {err}"
            ))
        }),
        OutputFormat::Yaml => serde_yaml_bw::to_string(report).map_err(|err| {
            DeployerError::Other(format!(
                "failed to render single-vm status report as YAML: {err}"
            ))
        }),
        OutputFormat::Text => Ok(render_single_vm_status_report_text(report)),
    }
}

fn render_single_vm_plan_output_text(output: &SingleVmPlanOutput) -> String {
    let mut lines = vec![
        format!("deployment: {}", output.plan.deployment_name),
        format!("service: {}", output.service_unit_name),
        format!("image: {}", output.plan.runtime.image),
        format!("arch: {:?}", output.plan.arch),
        format!("bundle source: {}", output.plan.bundle.source),
        format!("bundle mount: {}", output.plan.bundle.mount_path.display()),
        format!("admin bind: {}", output.plan.admin.bind),
        "directories:".to_string(),
    ];
    for dir in &output.directories {
        lines.push(format!("  - {}", dir.display()));
    }
    lines.push("files:".to_string());
    for file in &output.files {
        lines.push(format!("  - {:?}: {}", file.kind, file.path.display()));
    }
    lines.join("\n")
}

fn render_single_vm_apply_report_text(report: &SingleVmApplyReport) -> String {
    let mut lines = vec![
        "apply report:".to_string(),
        "directories created:".to_string(),
    ];
    for dir in &report.directories_created {
        lines.push(format!("  - {}", dir.display()));
    }
    lines.push("files written:".to_string());
    for file in &report.files_written {
        lines.push(format!("  - {}", file.display()));
    }
    lines.push("commands run:".to_string());
    if report.commands_run.is_empty() {
        lines.push("  - none".to_string());
    } else {
        for cmd in &report.commands_run {
            lines.push(format!("  - {cmd}"));
        }
    }
    lines.join("\n")
}

fn render_single_vm_destroy_report_text(report: &SingleVmDestroyReport) -> String {
    let mut lines = vec!["destroy report:".to_string(), "files removed:".to_string()];
    if report.files_removed.is_empty() {
        lines.push("  - none".to_string());
    } else {
        for file in &report.files_removed {
            lines.push(format!("  - {}", file.display()));
        }
    }
    lines.push("directories removed:".to_string());
    if report.directories_removed.is_empty() {
        lines.push("  - none".to_string());
    } else {
        for dir in &report.directories_removed {
            lines.push(format!("  - {}", dir.display()));
        }
    }
    lines.push("commands run:".to_string());
    if report.commands_run.is_empty() {
        lines.push("  - none".to_string());
    } else {
        for cmd in &report.commands_run {
            lines.push(format!("  - {cmd}"));
        }
    }
    lines.join("\n")
}

fn render_single_vm_status_report_text(report: &SingleVmStatusReport) -> String {
    let mut lines = vec![
        "status report:".to_string(),
        format!("status: {:?}", report.status),
        format!("service: {}", report.service_unit_name),
        format!("state path: {}", report.state_path.display()),
        format!("bundle mount exists: {}", report.bundle_mount_exists),
        "present files:".to_string(),
    ];
    if report.present_files.is_empty() {
        lines.push("  - none".to_string());
    } else {
        for path in &report.present_files {
            lines.push(format!("  - {}", path.display()));
        }
    }
    lines.push("missing files:".to_string());
    if report.missing_files.is_empty() {
        lines.push("  - none".to_string());
    } else {
        for path in &report.missing_files {
            lines.push(format!("  - {}", path.display()));
        }
    }
    lines.join("\n")
}

pub fn render_systemd_unit(plan: &SingleVmPlan, env_file_path: &std::path::Path) -> String {
    let bundle_mounts = render_bundle_source_mounts(&plan.bundle.source);
    let admin_mounts = render_admin_cert_mounts(&plan.admin);
    format!(
        "[Unit]
Description=Greentic runtime for deployment {deployment_name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={group}
EnvironmentFile={env_file}
ExecStart=/usr/bin/docker run --rm \\
  --name {service_name} \\
  --read-only \\
  --env-file {env_file} \\
  -p 127.0.0.1:8433:8433 \\
  -v {bundle_mount}:{bundle_mount}:ro \\
  -v {state_dir}:{state_dir} \\
  -v {cache_dir}:{cache_dir} \\
  -v {log_dir}:{log_dir} \\
  -v {temp_dir}:{temp_dir} \\
{bundle_mounts}\
{admin_mounts}\
  {image}
ExecStop=/usr/bin/docker stop {service_name}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
",
        deployment_name = plan.deployment_name,
        user = plan.service.user,
        group = plan.service.group,
        env_file = env_file_path.display(),
        service_name = plan.service_name,
        bundle_mount = plan.bundle.mount_path.display(),
        state_dir = plan.storage.state_dir.display(),
        cache_dir = plan.storage.cache_dir.display(),
        log_dir = plan.storage.log_dir.display(),
        temp_dir = plan.storage.temp_dir.display(),
        bundle_mounts = bundle_mounts,
        admin_mounts = admin_mounts,
        image = plan.runtime.image,
    )
}

pub fn render_env_file(plan: &SingleVmPlan) -> String {
    format!(
        "GREENTIC_BUNDLE_SOURCE={bundle_source}
GREENTIC_BUNDLE_FORMAT={bundle_format}
GREENTIC_BUNDLE_MOUNT={bundle_mount}
GREENTIC_STATE_DIR={state_dir}
GREENTIC_CACHE_DIR={cache_dir}
GREENTIC_LOG_DIR={log_dir}
GREENTIC_TEMP_DIR={temp_dir}
GREENTIC_ADMIN_BIND={admin_bind}
GREENTIC_ADMIN_LISTEN={admin_bind}
GREENTIC_ADMIN_CA_FILE={ca_file}
GREENTIC_ADMIN_CERT_FILE={cert_file}
GREENTIC_ADMIN_KEY_FILE={key_file}
GREENTIC_HEALTH_READINESS_PATH={readiness_path}
GREENTIC_HEALTH_LIVENESS_PATH={liveness_path}
GREENTIC_HEALTH_STARTUP_TIMEOUT_SECONDS={startup_timeout_seconds}
",
        bundle_source = plan.bundle.source,
        bundle_format = match plan.bundle.format {
            BundleFormat::Squashfs => "squashfs",
        },
        bundle_mount = plan.bundle.mount_path.display(),
        state_dir = plan.storage.state_dir.display(),
        cache_dir = plan.storage.cache_dir.display(),
        log_dir = plan.storage.log_dir.display(),
        temp_dir = plan.storage.temp_dir.display(),
        admin_bind = plan.admin.bind,
        ca_file = plan.admin.ca_file.display(),
        cert_file = plan.admin.cert_file.display(),
        key_file = plan.admin.key_file.display(),
        readiness_path = plan.health.readiness_path,
        liveness_path = plan.health.liveness_path,
        startup_timeout_seconds = plan.health.startup_timeout_seconds,
    )
}

fn render_bundle_source_mounts(source: &str) -> String {
    local_bundle_source_path(source)
        .map(|path| format!("  -v {}:{}:ro \\\n", path.display(), path.display()))
        .unwrap_or_default()
}

fn render_admin_cert_mounts(admin: &SingleVmAdminPlan) -> String {
    let mut mounts = String::new();
    for path in [&admin.ca_file, &admin.cert_file, &admin.key_file] {
        mounts.push_str(&format!(
            "  -v {}:{}:ro \\\n",
            path.display(),
            path.display()
        ));
    }
    mounts
}

fn local_bundle_source_path(source: &str) -> Option<PathBuf> {
    source
        .strip_prefix("file://")
        .map(PathBuf::from)
        .or_else(|| {
            let path = PathBuf::from(source);
            path.is_absolute().then_some(path)
        })
}

fn sanitize_service_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + DEFAULT_RUNTIME_SERVICE_NAME.len() + 1);
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        DEFAULT_RUNTIME_SERVICE_NAME.to_string()
    } else {
        format!("{trimmed}-{DEFAULT_RUNTIME_SERVICE_NAME}")
    }
}

fn is_directory_empty(path: &Path) -> Result<bool> {
    let mut entries = fs::read_dir(path).map_err(|err| {
        DeployerError::Io(std::io::Error::new(
            err.kind(),
            format!("failed to read directory {}: {err}", path.display()),
        ))
    })?;
    Ok(entries.next().is_none())
}

fn run_command(commands_run: &mut Vec<String>, program: &str, args: &[&str]) -> Result<()> {
    commands_run.push(format!("{program} {}", args.join(" ")));
    let status = Command::new(program).args(args).status().map_err(|err| {
        DeployerError::Io(std::io::Error::new(
            err.kind(),
            format!("failed to execute {program}: {err}"),
        ))
    })?;
    if !status.success() {
        return Err(DeployerError::Other(format!(
            "command failed: {program} {} (exit={})",
            args.join(" "),
            status.code().unwrap_or(1)
        )));
    }
    Ok(())
}

fn single_vm_state_path(plan: &SingleVmPlan) -> PathBuf {
    plan.storage.state_dir.join(DEFAULT_STATE_FILE_NAME)
}

fn write_single_vm_state(output: &SingleVmPlanOutput) -> Result<()> {
    let state_path = single_vm_state_path(&output.plan);
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DeployerError::Io(std::io::Error::new(
                err.kind(),
                format!(
                    "failed to create parent directory {} for {}: {err}",
                    parent.display(),
                    state_path.display()
                ),
            ))
        })?;
    }
    let state = SingleVmPersistedState {
        deployment_name: output.plan.deployment_name.clone(),
        service_unit_name: output.service_unit_name.clone(),
        runtime_image: output.plan.runtime.image.clone(),
        bundle_source: output.plan.bundle.source.clone(),
        admin_bind: output.plan.admin.bind.clone(),
        last_action: SingleVmLastAction::Apply,
    };
    let bytes = serde_json::to_vec_pretty(&state)?;
    fs::write(&state_path, bytes).map_err(|err| {
        DeployerError::Io(std::io::Error::new(
            err.kind(),
            format!("failed to write {}: {err}", state_path.display()),
        ))
    })?;
    Ok(())
}

fn load_single_vm_state(path: &Path) -> Result<Option<SingleVmPersistedState>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|err| {
        DeployerError::Io(std::io::Error::new(
            err.kind(),
            format!("failed to read {}: {err}", path.display()),
        ))
    })?;
    let state = serde_json::from_slice(&bytes)?;
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::DeploymentSpecV1;

    fn sample_spec() -> DeploymentSpecV1 {
        DeploymentSpecV1::from_yaml_str(
            r#"
apiVersion: greentic.ai/v1alpha1
kind: Deployment
metadata:
  name: acme-prod
spec:
  target: single-vm
  bundle:
    source: file:///opt/greentic/bundles/acme.squashfs
    format: squashfs
  runtime:
    image: ghcr.io/greentic-ai/operator-distroless:0.1.0-distroless
    arch: x86_64
    admin:
      bind: 127.0.0.1:8433
      mtls:
        caFile: /etc/greentic/admin/ca.crt
        certFile: /etc/greentic/admin/server.crt
        keyFile: /etc/greentic/admin/server.key
  storage:
    stateDir: /var/lib/greentic/state
    cacheDir: /var/lib/greentic/cache
    logDir: /var/log/greentic
    tempDir: /var/lib/greentic/tmp
  service:
    manager: systemd
    user: greentic
    group: greentic
  health:
    readinessPath: /ready
    livenessPath: /health
    startupTimeoutSeconds: 120
  rollout:
    strategy: recreate
"#,
        )
        .expect("sample spec")
    }

    #[test]
    fn build_single_vm_plan_normalizes_runtime_layout() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        assert_eq!(plan.service_name, "acme-prod-greentic-runtime");
        assert_eq!(
            plan.bundle.mount_path,
            PathBuf::from("/mnt/greentic/bundles/acme-prod")
        );
        assert!(plan.bundle.read_only);
    }

    #[test]
    fn build_single_vm_plan_rejects_path_like_names() {
        let mut spec = sample_spec();
        spec.metadata.name = "prod/blue".to_string();
        let err = build_single_vm_plan(&spec).expect_err("must reject path separators");
        assert!(err.to_string().contains("path separators"));
    }

    #[test]
    fn render_single_vm_plan_emits_systemd_unit_and_env_file() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let output = render_single_vm_plan(&plan);
        assert_eq!(
            output.service_unit_name,
            "acme-prod-greentic-runtime.service"
        );
        assert_eq!(output.files.len(), 2);
        assert!(
            output
                .files
                .iter()
                .any(|file| matches!(file.kind, SingleVmPlannedFileKind::SystemdUnit))
        );
        assert!(
            output
                .files
                .iter()
                .any(|file| matches!(file.kind, SingleVmPlannedFileKind::EnvironmentFile))
        );
    }

    #[test]
    fn render_env_file_contains_admin_and_storage_layout() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let rendered = render_env_file(&plan);
        assert!(rendered.contains("GREENTIC_ADMIN_BIND=127.0.0.1:8433"));
        assert!(rendered.contains("GREENTIC_ADMIN_LISTEN=127.0.0.1:8433"));
        assert!(rendered.contains("GREENTIC_STATE_DIR=/var/lib/greentic/state"));
        assert!(rendered.contains("GREENTIC_BUNDLE_FORMAT=squashfs"));
    }

    #[test]
    fn render_systemd_unit_uses_env_file_and_mounts_local_inputs() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let rendered = render_systemd_unit(&plan, Path::new("/etc/greentic/acme.env"));
        assert!(rendered.contains("EnvironmentFile=/etc/greentic/acme.env"));
        assert!(rendered.contains("--env-file /etc/greentic/acme.env"));
        assert!(rendered.contains(
            "-v /opt/greentic/bundles/acme.squashfs:/opt/greentic/bundles/acme.squashfs:ro"
        ));
        assert!(rendered.contains("-v /etc/greentic/admin/ca.crt:/etc/greentic/admin/ca.crt:ro"));
        assert!(
            rendered
                .contains("-v /etc/greentic/admin/server.crt:/etc/greentic/admin/server.crt:ro")
        );
        assert!(
            rendered
                .contains("-v /etc/greentic/admin/server.key:/etc/greentic/admin/server.key:ro")
        );
    }

    #[test]
    fn plan_single_vm_spec_renders_yaml_output() {
        let output = plan_single_vm_spec(&sample_spec()).expect("planned");
        let rendered =
            render_single_vm_plan_output(&output, OutputFormat::Yaml).expect("yaml render");
        assert!(rendered.contains("service_unit_name: acme-prod-greentic-runtime.service"));
    }

    #[test]
    fn apply_single_vm_plan_output_writes_directories_and_files() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let mut output = render_single_vm_plan(&plan);
        let dir = tempfile::tempdir().expect("tempdir");

        output.plan.storage.state_dir = dir.path().join("state");
        output.plan.storage.cache_dir = dir.path().join("cache");
        output.plan.storage.log_dir = dir.path().join("logs");
        output.plan.storage.temp_dir = dir.path().join("tmp");
        output.directories = vec![
            output.plan.storage.state_dir.clone(),
            output.plan.storage.cache_dir.clone(),
            output.plan.storage.log_dir.clone(),
            output.plan.storage.temp_dir.clone(),
        ];
        output.files = vec![
            SingleVmPlannedFile {
                path: dir.path().join("systemd").join("greentic-runtime.service"),
                kind: SingleVmPlannedFileKind::SystemdUnit,
                contents: "unit".to_string(),
            },
            SingleVmPlannedFile {
                path: dir.path().join("env").join("greentic-runtime.env"),
                kind: SingleVmPlannedFileKind::EnvironmentFile,
                contents: "ENV=1\n".to_string(),
            },
        ];

        let report = apply_single_vm_plan_output(&output).expect("apply");
        assert_eq!(report.directories_created.len(), 4);
        assert_eq!(report.files_written.len(), 2);
        assert!(report.commands_run.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("systemd").join("greentic-runtime.service"))
                .expect("read unit"),
            "unit"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("env").join("greentic-runtime.env"))
                .expect("read env"),
            "ENV=1\n"
        );
    }

    #[test]
    fn preview_single_vm_apply_plan_output_reports_paths_without_writing() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let output = render_single_vm_plan(&plan);

        let report = preview_single_vm_apply_plan_output(&output);
        assert_eq!(report.directories_created, output.directories);
        assert_eq!(
            report.files_written,
            output
                .files
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>()
        );
        assert!(report.commands_run.is_empty());
    }

    #[test]
    fn destroy_single_vm_plan_output_removes_written_files_and_empty_dirs() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let mut output = render_single_vm_plan(&plan);
        let dir = tempfile::tempdir().expect("tempdir");

        output.plan.storage.state_dir = dir.path().join("state");
        let systemd_dir = dir.path().join("systemd");
        let env_dir = dir.path().join("env");
        output.directories = vec![
            output.plan.storage.state_dir.clone(),
            systemd_dir.clone(),
            env_dir.clone(),
        ];
        output.files = vec![
            SingleVmPlannedFile {
                path: systemd_dir.join("greentic-runtime.service"),
                kind: SingleVmPlannedFileKind::SystemdUnit,
                contents: "unit".to_string(),
            },
            SingleVmPlannedFile {
                path: env_dir.join("greentic-runtime.env"),
                kind: SingleVmPlannedFileKind::EnvironmentFile,
                contents: "ENV=1\n".to_string(),
            },
        ];

        apply_single_vm_plan_output(&output).expect("apply");
        let report = destroy_single_vm_plan_output(&output).expect("destroy");
        assert_eq!(report.files_removed.len(), 3);
        assert_eq!(report.directories_removed.len(), 3);
        assert!(report.commands_run.is_empty());
        assert!(!output.plan.storage.state_dir.exists());
        assert!(!systemd_dir.exists());
        assert!(!env_dir.exists());
    }

    #[test]
    fn preview_single_vm_destroy_plan_output_reports_paths_without_removing() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let output = render_single_vm_plan(&plan);

        let report = preview_single_vm_destroy_plan_output(&output);
        assert_eq!(
            report.files_removed,
            output
                .files
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(report.directories_removed, output.directories);
        assert!(report.commands_run.is_empty());
    }

    #[test]
    fn apply_single_vm_plan_output_writes_persisted_state() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let mut output = render_single_vm_plan(&plan);
        let dir = tempfile::tempdir().expect("tempdir");

        output.directories = vec![
            dir.path().join("state"),
            dir.path().join("cache"),
            dir.path().join("logs"),
            dir.path().join("tmp"),
        ];
        output.plan.storage.state_dir = dir.path().join("state");
        output.files = vec![];

        apply_single_vm_plan_output(&output).expect("apply");
        let state = load_single_vm_state(&dir.path().join("state").join(DEFAULT_STATE_FILE_NAME))
            .expect("load state")
            .expect("state exists");
        assert_eq!(state.last_action, SingleVmLastAction::Apply);
        assert_eq!(state.service_unit_name, output.service_unit_name);
    }

    #[test]
    fn status_single_vm_plan_output_reports_applied_installation() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let mut output = render_single_vm_plan(&plan);
        let dir = tempfile::tempdir().expect("tempdir");

        output.plan.storage.state_dir = dir.path().join("state");
        output.directories = vec![
            output.plan.storage.state_dir.clone(),
            dir.path().join("cache"),
            dir.path().join("logs"),
        ];
        output.files = vec![SingleVmPlannedFile {
            path: dir.path().join("systemd").join("greentic-runtime.service"),
            kind: SingleVmPlannedFileKind::SystemdUnit,
            contents: "unit".to_string(),
        }];

        apply_single_vm_plan_output(&output).expect("apply");
        let status = status_single_vm_plan_output(&output).expect("status");
        assert_eq!(status.status, SingleVmDeploymentStatus::Applied);
        assert!(status.state_exists);
        assert!(status.missing_files.is_empty());
    }

    #[test]
    fn status_single_vm_plan_output_reports_not_installed_when_artifacts_missing() {
        let plan = build_single_vm_plan(&sample_spec()).expect("plan");
        let mut output = render_single_vm_plan(&plan);
        let dir = tempfile::tempdir().expect("tempdir");

        output.plan.storage.state_dir = dir.path().join("state");
        output.directories = vec![dir.path().join("state"), dir.path().join("cache")];
        output.files = vec![SingleVmPlannedFile {
            path: dir.path().join("systemd").join("greentic-runtime.service"),
            kind: SingleVmPlannedFileKind::SystemdUnit,
            contents: "unit".to_string(),
        }];

        let status = status_single_vm_plan_output(&output).expect("status");
        assert_eq!(status.status, SingleVmDeploymentStatus::NotInstalled);
        assert!(!status.state_exists);
    }

    #[test]
    fn render_single_vm_apply_report_text_mentions_no_commands() {
        let report = SingleVmApplyReport {
            directories_created: vec!["/tmp/state".into()],
            files_written: vec!["/tmp/greentic.env".into()],
            commands_run: Vec::new(),
        };

        let rendered =
            render_single_vm_apply_report(&report, OutputFormat::Text).expect("render text");
        assert!(rendered.contains("apply report:"));
        assert!(rendered.contains("/tmp/state"));
        assert!(rendered.contains("  - none"));
    }

    #[test]
    fn render_single_vm_destroy_report_text_mentions_removed_files() {
        let report = SingleVmDestroyReport {
            files_removed: vec!["/tmp/greentic.env".into()],
            directories_removed: vec!["/tmp/state".into()],
            commands_run: vec!["systemctl stop acme.service".to_string()],
        };

        let rendered =
            render_single_vm_destroy_report(&report, OutputFormat::Text).expect("render text");
        assert!(rendered.contains("destroy report:"));
        assert!(rendered.contains("/tmp/greentic.env"));
        assert!(rendered.contains("systemctl stop acme.service"));
    }

    #[test]
    fn render_single_vm_status_report_text_mentions_status() {
        let report = SingleVmStatusReport {
            state_path: "/tmp/state/single-vm-state.json".into(),
            status: SingleVmDeploymentStatus::Applied,
            service_unit_name: "acme.service".to_string(),
            service_unit_path: "/etc/systemd/system/acme.service".into(),
            env_file_path: "/etc/greentic/acme.env".into(),
            state_exists: true,
            bundle_mount_exists: true,
            present_directories: vec!["/tmp/state".into()],
            missing_directories: Vec::new(),
            present_files: vec!["/etc/systemd/system/acme.service".into()],
            missing_files: Vec::new(),
            state: None,
        };

        let rendered =
            render_single_vm_status_report(&report, OutputFormat::Text).expect("render text");
        assert!(rendered.contains("status report:"));
        assert!(rendered.contains("Applied"));
        assert!(rendered.contains("acme.service"));
    }
}
