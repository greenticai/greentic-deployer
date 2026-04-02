//! Legacy/provider-oriented multi-target deployment orchestration.
//!
//! This module still contains the older generic deployment-pack execution path
//! used for non-single-vm targets. The stable OSS single-VM path lives in
//! `crate::single_vm`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{info, info_span};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::config::{DeployerConfig, OutputFormat};
use crate::contract::{
    DeployerCapability, ResolvedCapabilityContract, ResolvedDeployerContract, copy_pack_subtree,
    read_pack_asset, resolve_deployer_contract_assets,
};
use crate::deployment::{
    DeploymentPackSelection, DeploymentTarget, ExecutionOutcome, ExecutionOutcomePayload,
    execute_deployment_pack, resolve_deployment_pack,
};
use crate::error::{DeployerError, Result};
use crate::pack_introspect;
use crate::plan::PlanContext;
use crate::telemetry;
use greentic_telemetry::{TelemetryCtx, set_current_telemetry_ctx};
use serde_json;
use serde_yaml_bw as serde_yaml;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperationPayload {
    Plan(Box<PlanPayload>),
    Generate(Box<GeneratePayload>),
    Apply(Box<ApplyPayload>),
    Destroy(Box<DestroyPayload>),
    Status(Box<StatusPayload>),
    Rollback(Box<RollbackPayload>),
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanPayload {
    pub plan: PlanContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered_output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityPayload {
    pub capability: String,
    pub provider: String,
    pub strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered_output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratePayload {
    pub capability: String,
    pub provider: String,
    pub strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qa_spec_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub example_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered_output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyPayload {
    pub capability: String,
    pub provider: String,
    pub strategy: String,
    pub pack_id: String,
    pub flow_id: String,
    pub output_dir: String,
    pub plan_path: String,
    pub invoke_path: String,
    pub runner_cmd: Vec<String>,
    pub runner_env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DestroyPayload {
    pub capability: String,
    pub provider: String,
    pub strategy: String,
    pub pack_id: String,
    pub flow_id: String,
    pub output_dir: String,
    pub plan_path: String,
    pub invoke_path: String,
    pub runner_cmd: Vec<String>,
    pub runner_env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusPayload {
    pub capability: String,
    pub provider: String,
    pub strategy: String,
    pub pack_id: String,
    pub flow_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered_output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackPayload {
    pub capability: String,
    pub provider: String,
    pub strategy: String,
    pub pack_id: String,
    pub flow_id: String,
    pub target_capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered_output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputValidation {
    pub schema_path: String,
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutionReport {
    pub output_dir: String,
    pub plan_path: String,
    pub invoke_path: String,
    pub handoff_path: String,
    pub runner_command_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_files: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_payload: Option<ExecutionOutcomePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_validation: Option<OutputValidation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperationResult {
    pub capability: String,
    pub executed: bool,
    pub preview: bool,
    pub output_dir: String,
    pub plan_path: String,
    pub invoke_path: String,
    pub pack_id: String,
    pub flow_id: String,
    pub pack_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<ResolvedDeployerContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_contract: Option<ResolvedCapabilityContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<OperationPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_validation: Option<OutputValidation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionReport>,
}

pub fn render_operation_result(value: &OperationResult, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_operation_result_text(value)),
        OutputFormat::Json => {
            serde_json::to_string_pretty(value).map_err(|err| DeployerError::Other(err.to_string()))
        }
        OutputFormat::Yaml => {
            serde_yaml::to_string(value).map_err(|err| DeployerError::Other(err.to_string()))
        }
    }
}

fn render_operation_result_text(value: &OperationResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "capability={} executed={} preview={}\n",
        value.capability, value.executed, value.preview
    ));
    out.push_str(&format!("pack_id={}\n", value.pack_id));
    out.push_str(&format!("flow_id={}\n", value.flow_id));
    out.push_str(&format!("pack_path={}\n", value.pack_path));
    out.push_str(&format!("output_dir={}\n", value.output_dir));
    out.push_str(&format!("plan_path={}\n", value.plan_path));
    out.push_str(&format!("invoke_path={}\n", value.invoke_path));

    if let Some(payload) = value.payload.as_ref() {
        render_operation_payload_text(payload, &mut out);
    }
    if let Some(validation) = value.output_validation.as_ref() {
        render_output_validation_text("output_validation", validation, &mut out);
    }
    if let Some(execution) = value.execution.as_ref() {
        render_execution_report_text(execution, &mut out);
    }
    append_terraform_runtime_text(value, &mut out);

    out
}

fn render_operation_payload_text(payload: &OperationPayload, out: &mut String) {
    match payload {
        OperationPayload::Plan(payload) => {
            out.push_str("payload_kind=plan\n");
            out.push_str(&format!("target={}\n", payload.plan.target.as_str()));
            out.push_str(&format!("components={}\n", payload.plan.components.len()));
        }
        OperationPayload::Generate(payload) => {
            out.push_str("payload_kind=generate\n");
            out.push_str(&format!("provider={}\n", payload.provider));
            out.push_str(&format!("strategy={}\n", payload.strategy));
            if let Some(path) = payload.input_schema_path.as_ref() {
                out.push_str(&format!("input_schema={path}\n"));
            }
            if let Some(path) = payload.output_schema_path.as_ref() {
                out.push_str(&format!("output_schema={path}\n"));
            }
            if let Some(path) = payload.qa_spec_path.as_ref() {
                out.push_str(&format!("qa_spec={path}\n"));
            }
            if !payload.example_paths.is_empty() {
                out.push_str(&format!("examples={}\n", payload.example_paths.join(", ")));
            }
        }
        OperationPayload::Apply(payload) => {
            out.push_str("payload_kind=apply\n");
            out.push_str(&format!("provider={}\n", payload.provider));
            out.push_str(&format!("strategy={}\n", payload.strategy));
            out.push_str(&format!("runner_cmd={}\n", payload.runner_cmd.join(" ")));
        }
        OperationPayload::Destroy(payload) => {
            out.push_str("payload_kind=destroy\n");
            out.push_str(&format!("provider={}\n", payload.provider));
            out.push_str(&format!("strategy={}\n", payload.strategy));
            out.push_str(&format!("runner_cmd={}\n", payload.runner_cmd.join(" ")));
        }
        OperationPayload::Status(payload) => {
            out.push_str("payload_kind=status\n");
            out.push_str(&format!("provider={}\n", payload.provider));
            out.push_str(&format!("strategy={}\n", payload.strategy));
        }
        OperationPayload::Rollback(payload) => {
            out.push_str("payload_kind=rollback\n");
            out.push_str(&format!("provider={}\n", payload.provider));
            out.push_str(&format!("strategy={}\n", payload.strategy));
            out.push_str(&format!(
                "target_capability={}\n",
                payload.target_capability
            ));
        }
    }
}

fn render_output_validation_text(label: &str, validation: &OutputValidation, out: &mut String) {
    out.push_str(&format!("{label}.schema={}\n", validation.schema_path));
    out.push_str(&format!("{label}.valid={}\n", validation.valid));
    if !validation.errors.is_empty() {
        out.push_str(&format!(
            "{label}.errors={}\n",
            validation.errors.join(" | ")
        ));
    }
}

fn render_execution_report_text(execution: &ExecutionReport, out: &mut String) {
    out.push_str("execution.present=true\n");
    out.push_str(&format!("execution.output_dir={}\n", execution.output_dir));
    out.push_str(&format!(
        "execution.handoff_path={}\n",
        execution.handoff_path
    ));
    out.push_str(&format!(
        "execution.runner_command_path={}\n",
        execution.runner_command_path
    ));
    if let Some(status) = execution.status.as_ref() {
        out.push_str(&format!("execution.status={status}\n"));
    }
    if let Some(message) = execution.message.as_ref() {
        out.push_str(&format!("execution.message={message}\n"));
    }
    if !execution.output_files.is_empty() {
        out.push_str(&format!(
            "execution.output_files={}\n",
            execution.output_files.join(", ")
        ));
    }
    if let Some(validation) = execution.outcome_validation.as_ref() {
        render_output_validation_text("execution.validation", validation, out);
    }
}

fn append_terraform_runtime_text(value: &OperationResult, out: &mut String) {
    let runtime_path = Path::new(&value.output_dir).join("terraform-runtime.json");
    let Ok(bytes) = fs::read(&runtime_path) else {
        return;
    };
    let Ok(metadata) = serde_json::from_slice::<TerraformRuntimeMetadata>(&bytes) else {
        return;
    };

    out.push_str("terraform_runtime.present=true\n");
    out.push_str(&format!(
        "terraform_runtime.root={}\n",
        metadata.terraform_root
    ));
    out.push_str(&format!(
        "terraform_runtime.copied_files={}\n",
        metadata.copied_files.join(", ")
    ));
    out.push_str(&format!(
        "terraform_runtime.status_command={}\n",
        metadata.status_command
    ));
}

pub async fn run(config: DeployerConfig) -> Result<OperationResult> {
    telemetry::init(&config)?;
    let plan = {
        let span = stage_span("plan", &config);
        let _enter = span.enter();
        install_telemetry_context("plan", &config);
        pack_introspect::build_plan(&config)?
    };
    run_with_plan(config, plan).await
}

/// Executes a deployment given an already constructed [`PlanContext`].
///
/// This is the entry point greentic-runner/control planes should invoke after producing the plan.
/// Callers are expected to have initialised telemetry already (e.g. via `telemetry::init`).
pub async fn run_with_plan(config: DeployerConfig, plan: PlanContext) -> Result<OperationResult> {
    let plan_summary = plan.summary();
    info!("built deployment plan: {}", plan_summary);

    let plan_target = DeploymentTarget {
        provider: plan.deployment.provider.clone(),
        strategy: plan.deployment.strategy.clone(),
    };
    if plan_target.provider != config.provider.as_str() || plan_target.strategy != config.strategy {
        info!(
            "deployment plan target provider={} strategy={} (requested {}::{})",
            plan_target.provider,
            plan_target.strategy,
            config.provider.as_str(),
            config.strategy
        );
    }
    let selection = resolve_deployment_pack(&config, &plan_target)?;
    info!(
        capability = %selection.dispatch.capability.as_str(),
        provider = %plan_target.provider,
        strategy = %plan_target.strategy,
        pack_id = %selection.dispatch.pack_id,
        flow_id = %selection.dispatch.flow_id,
        pack_path = %selection.pack_path.display(),
        origin = %selection.origin,
        candidates = ?selection.candidates,
        "resolved deployment pack"
    );
    let dispatch = &selection.dispatch;

    let deploy_dir = config.provider_output_dir();
    fs::create_dir_all(&deploy_dir)?;
    let runtime_artifacts = persist_runtime_artifacts(&config, &plan, &selection, &deploy_dir)?;
    let contract = resolve_deployer_contract_assets(&selection.manifest, &selection.pack_path)?;
    let capability_contract = contract
        .as_ref()
        .and_then(|contract| {
            contract
                .capabilities
                .iter()
                .find(|entry| entry.capability == selection.dispatch.capability)
        })
        .cloned();
    info!(
        plan_path = %runtime_artifacts.plan.display(),
        invoke_path = %runtime_artifacts.invoke.display(),
        "persisted runtime invocation metadata"
    );

    let executed_payload = operation_payload(
        config.capability,
        &plan,
        &plan_target,
        &runtime_artifacts,
        capability_contract.as_ref(),
        None,
    );
    let executed_output_validation = match executed_payload.as_ref() {
        Some(payload) => validation_for_payload(
            output_schema_for_operation(
                config.capability,
                contract.as_ref(),
                capability_contract.as_ref(),
            ),
            payload,
        )?,
        None => None,
    };

    if let Some(execution_outcome) = execute_deployment_pack(&config, &plan, dispatch).await? {
        info!("deployment plan executed via deployment pack");
        return Ok(build_operation_result(
            &config,
            &selection,
            &runtime_artifacts,
            OperationResultData {
                contract,
                capability_contract,
                payload: executed_payload,
                output_validation: executed_output_validation,
                execution_outcome: Some(execution_outcome),
                executed: true,
            },
        ));
    }

    if let Some(execution_outcome) =
        synthesize_local_execution_outcome(&config, &runtime_artifacts)?
    {
        info!("deployment status synthesized from local runtime artifacts");
        return Ok(build_operation_result(
            &config,
            &selection,
            &runtime_artifacts,
            OperationResultData {
                contract,
                capability_contract,
                payload: executed_payload,
                output_validation: executed_output_validation,
                execution_outcome: Some(execution_outcome),
                executed: true,
            },
        ));
    }

    let render_text = config.capability != DeployerCapability::Plan
        || matches!(config.output, OutputFormat::Text);
    if render_text {
        println!("{}", plan.summary());
        println!(
            "Deployment executor not registered; runtime metadata stored under {}",
            deploy_dir.display()
        );
    }

    match config.capability {
        DeployerCapability::Plan => {
            let rendered_output = render_plan_output(&config, &plan)?;
            let payload = operation_payload(
                config.capability,
                &plan,
                &plan_target,
                &runtime_artifacts,
                capability_contract.as_ref(),
                rendered_output,
            )
            .expect("plan payload");
            let output_validation = validation_for_payload(
                output_schema_for_operation(
                    config.capability,
                    contract.as_ref(),
                    capability_contract.as_ref(),
                ),
                &payload,
            )?;
            if config.preview {
                println!("Preview mode: nothing was applied.");
            }
            Ok(build_operation_result(
                &config,
                &selection,
                &runtime_artifacts,
                OperationResultData {
                    contract,
                    capability_contract: capability_contract.clone(),
                    payload: Some(payload),
                    output_validation,
                    execution_outcome: None,
                    executed: false,
                },
            ))
        }
        DeployerCapability::Generate
        | DeployerCapability::Status
        | DeployerCapability::Rollback => {
            let rendered_output =
                render_contract_summary(&config, &plan, capability_contract.as_ref())?;
            let payload = operation_payload(
                config.capability,
                &plan,
                &plan_target,
                &runtime_artifacts,
                capability_contract.as_ref(),
                rendered_output,
            )
            .expect("capability payload");
            let output_validation = validation_for_payload(
                output_schema_for_operation(
                    config.capability,
                    contract.as_ref(),
                    capability_contract.as_ref(),
                ),
                &payload,
            )?;
            if config.preview {
                println!("Preview mode: skipping {}.", config.capability.as_str());
            }
            Ok(build_operation_result(
                &config,
                &selection,
                &runtime_artifacts,
                OperationResultData {
                    contract,
                    capability_contract: capability_contract.clone(),
                    payload: Some(payload),
                    output_validation,
                    execution_outcome: None,
                    executed: false,
                },
            ))
        }
        DeployerCapability::Apply => {
            if config.preview {
                println!("Preview mode: skipping apply.");
                let payload = operation_payload(
                    config.capability,
                    &plan,
                    &plan_target,
                    &runtime_artifacts,
                    capability_contract.as_ref(),
                    None,
                )
                .expect("apply payload");
                let output_validation = validation_for_payload(
                    output_schema_for_operation(
                        config.capability,
                        contract.as_ref(),
                        capability_contract.as_ref(),
                    ),
                    &payload,
                )?;
                return Ok(build_operation_result(
                    &config,
                    &selection,
                    &runtime_artifacts,
                    OperationResultData {
                        contract,
                        capability_contract: capability_contract.clone(),
                        payload: Some(payload),
                        output_validation,
                        execution_outcome: None,
                        executed: false,
                    },
                ));
            }
            Err(DeployerError::DeploymentPackUnsupported {
                provider: config.provider.as_str().to_string(),
                strategy: config.strategy.clone(),
                capability: config.capability.as_str().to_string(),
            })
        }
        DeployerCapability::Destroy => {
            if config.preview {
                println!("Preview mode: skipping destroy.");
                let payload = operation_payload(
                    config.capability,
                    &plan,
                    &plan_target,
                    &runtime_artifacts,
                    capability_contract.as_ref(),
                    None,
                )
                .expect("destroy payload");
                let output_validation = validation_for_payload(
                    output_schema_for_operation(
                        config.capability,
                        contract.as_ref(),
                        capability_contract.as_ref(),
                    ),
                    &payload,
                )?;
                return Ok(build_operation_result(
                    &config,
                    &selection,
                    &runtime_artifacts,
                    OperationResultData {
                        contract,
                        capability_contract: capability_contract.clone(),
                        payload: Some(payload),
                        output_validation,
                        execution_outcome: None,
                        executed: false,
                    },
                ));
            }
            Err(DeployerError::DeploymentPackUnsupported {
                provider: config.provider.as_str().to_string(),
                strategy: config.strategy.clone(),
                capability: config.capability.as_str().to_string(),
            })
        }
    }
}

fn synthesize_local_execution_outcome(
    config: &DeployerConfig,
    runtime_artifacts: &RuntimeArtifacts,
) -> Result<Option<ExecutionOutcome>> {
    if config.execute_local && uses_terraform_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_terraform_operation(config, runtime_artifacts, "apply");
            }
            DeployerCapability::Destroy => {
                return execute_local_terraform_operation(config, runtime_artifacts, "destroy");
            }
            _ => {}
        }
    }
    if config.execute_local && uses_operator_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "operator-apply.sh",
                    "operator-apply",
                    "applied",
                    ScriptedPayloadKind::Apply,
                    "operator apply executed locally",
                );
            }
            DeployerCapability::Destroy => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "operator-delete.sh",
                    "operator-destroy",
                    "destroyed",
                    ScriptedPayloadKind::Destroy,
                    "operator destroy executed locally",
                );
            }
            _ => {}
        }
    }
    if config.execute_local && uses_serverless_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "serverless-deploy.sh",
                    "serverless-apply",
                    "applied",
                    ScriptedPayloadKind::Apply,
                    "serverless apply executed locally",
                );
            }
            DeployerCapability::Destroy => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "serverless-destroy.sh",
                    "serverless-destroy",
                    "destroyed",
                    ScriptedPayloadKind::Destroy,
                    "serverless destroy executed locally",
                );
            }
            _ => {}
        }
    }
    if config.execute_local && uses_snap_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "snap-install.sh",
                    "snap-apply",
                    "applied",
                    ScriptedPayloadKind::Apply,
                    "snap apply executed locally",
                );
            }
            DeployerCapability::Destroy => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "snap-remove.sh",
                    "snap-destroy",
                    "destroyed",
                    ScriptedPayloadKind::Destroy,
                    "snap destroy executed locally",
                );
            }
            _ => {}
        }
    }
    if config.execute_local && uses_juju_machine_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "juju-machine-deploy.sh",
                    "juju-machine-apply",
                    "applied",
                    ScriptedPayloadKind::Apply,
                    "juju-machine apply executed locally",
                );
            }
            DeployerCapability::Destroy => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "juju-machine-remove.sh",
                    "juju-machine-destroy",
                    "destroyed",
                    ScriptedPayloadKind::Destroy,
                    "juju-machine destroy executed locally",
                );
            }
            _ => {}
        }
    }
    if config.execute_local && uses_juju_k8s_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "juju-k8s-deploy.sh",
                    "juju-k8s-apply",
                    "applied",
                    ScriptedPayloadKind::Apply,
                    "juju-k8s apply executed locally",
                );
            }
            DeployerCapability::Destroy => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "juju-k8s-remove.sh",
                    "juju-k8s-destroy",
                    "destroyed",
                    ScriptedPayloadKind::Destroy,
                    "juju-k8s destroy executed locally",
                );
            }
            _ => {}
        }
    }
    if config.capability == DeployerCapability::Status && uses_terraform_handoff(config) {
        return synthesize_local_terraform_status(config, runtime_artifacts);
    }
    if config.capability == DeployerCapability::Status && uses_operator_handoff(config) {
        return synthesize_scripted_handoff_status(
            config,
            runtime_artifacts,
            "operator-handoff.txt",
            vec![
                ("operator_manifest", "operator/rendered-manifests.yaml"),
                ("operator_apply_script", "operator-apply.sh"),
                ("operator_delete_script", "operator-delete.sh"),
                ("operator_status_script", "operator-status.sh"),
            ],
            "operator status synthesized from local handoff artifacts",
        );
    }
    if config.capability == DeployerCapability::Status && uses_serverless_handoff(config) {
        return synthesize_scripted_handoff_status(
            config,
            runtime_artifacts,
            "serverless-handoff.txt",
            vec![
                (
                    "serverless_descriptor",
                    "serverless/deployment-descriptor.json",
                ),
                ("serverless_deploy_script", "serverless-deploy.sh"),
                ("serverless_destroy_script", "serverless-destroy.sh"),
                ("serverless_status_script", "serverless-status.sh"),
            ],
            "serverless status synthesized from local handoff artifacts",
        );
    }
    if config.capability == DeployerCapability::Status && uses_snap_handoff(config) {
        return synthesize_scripted_handoff_status(
            config,
            runtime_artifacts,
            "snap-handoff.txt",
            vec![
                ("snap_fetch", "snap/fetch/snapcraft.yaml"),
                ("snap_embedded", "snap/embedded/snapcraft.yaml"),
                ("snap_install", "snap-install.sh"),
                ("snap_remove", "snap-remove.sh"),
                ("snap_status", "snap-status.sh"),
            ],
            "snap status synthesized from local handoff artifacts",
        );
    }
    if config.capability == DeployerCapability::Status && uses_juju_machine_handoff(config) {
        return synthesize_scripted_handoff_status(
            config,
            runtime_artifacts,
            "juju-machine-handoff.txt",
            vec![
                ("juju_machine_charm", "juju-machine-charm/charmcraft.yaml"),
                ("juju_machine_deploy", "juju-machine-deploy.sh"),
                ("juju_machine_remove", "juju-machine-remove.sh"),
                ("juju_machine_status", "juju-machine-status.sh"),
            ],
            "juju-machine status synthesized from local handoff artifacts",
        );
    }
    if config.capability == DeployerCapability::Status && uses_juju_k8s_handoff(config) {
        return synthesize_scripted_handoff_status(
            config,
            runtime_artifacts,
            "juju-k8s-handoff.txt",
            vec![
                ("juju_k8s_charm", "juju-k8s-charm/charmcraft.yaml"),
                ("juju_k8s_deploy", "juju-k8s-deploy.sh"),
                ("juju_k8s_remove", "juju-k8s-remove.sh"),
                ("juju_k8s_status", "juju-k8s-status.sh"),
            ],
            "juju-k8s status synthesized from local handoff artifacts",
        );
    }
    Ok(None)
}

fn uses_terraform_handoff(config: &DeployerConfig) -> bool {
    (config.provider == crate::config::Provider::Generic && config.strategy == "terraform")
        || (matches!(
            config.provider,
            crate::config::Provider::Aws
                | crate::config::Provider::Azure
                | crate::config::Provider::Gcp
        ) && config.strategy == "iac-only")
}

fn uses_operator_handoff(config: &DeployerConfig) -> bool {
    config.provider == crate::config::Provider::K8s && config.strategy == "operator"
}

fn uses_serverless_handoff(config: &DeployerConfig) -> bool {
    config.provider == crate::config::Provider::Generic && config.strategy == "serverless-container"
}

fn uses_snap_handoff(config: &DeployerConfig) -> bool {
    config.provider == crate::config::Provider::Local && config.strategy == "snap"
}

fn uses_juju_machine_handoff(config: &DeployerConfig) -> bool {
    config.provider == crate::config::Provider::Local && config.strategy == "juju-machine"
}

fn uses_juju_k8s_handoff(config: &DeployerConfig) -> bool {
    config.provider == crate::config::Provider::K8s && config.strategy == "juju-k8s"
}

enum ScriptedPayloadKind {
    Apply,
    Destroy,
}

fn execute_local_terraform_operation(
    config: &DeployerConfig,
    runtime_artifacts: &RuntimeArtifacts,
    operation: &str,
) -> Result<Option<ExecutionOutcome>> {
    let script_name = match operation {
        "apply" => "terraform-apply.sh",
        "destroy" => "terraform-destroy.sh",
        other => {
            return Err(DeployerError::Config(format!(
                "unsupported terraform local operation {other}"
            )));
        }
    };
    let script_path = runtime_artifacts.deploy_dir.join(script_name);
    if !script_path.exists() {
        return Ok(None);
    }

    let stdout_log = format!("terraform-{operation}.stdout.log");
    let stderr_log = format!("terraform-{operation}.stderr.log");
    let output = run_script_capture_logs(
        &script_path,
        &runtime_artifacts.deploy_dir,
        runtime_artifacts,
        &stdout_log,
        &stderr_log,
    )?;

    if !output.status.success() {
        if operation == "destroy" && config.provider == crate::config::Provider::Aws {
            let cleanup_script = runtime_artifacts
                .deploy_dir
                .join("terraform-aws-cleanup.sh");
            if cleanup_script.exists() {
                let cleanup_stdout = "terraform-destroy-cleanup.stdout.log";
                let cleanup_stderr = "terraform-destroy-cleanup.stderr.log";
                let cleanup = run_script_capture_logs(
                    &cleanup_script,
                    &runtime_artifacts.deploy_dir,
                    runtime_artifacts,
                    cleanup_stdout,
                    cleanup_stderr,
                )?;
                if cleanup.status.success() {
                    let retry_stdout = "terraform-destroy-retry.stdout.log";
                    let retry_stderr = "terraform-destroy-retry.stderr.log";
                    let retry = run_script_capture_logs(
                        &script_path,
                        &runtime_artifacts.deploy_dir,
                        runtime_artifacts,
                        retry_stdout,
                        retry_stderr,
                    )?;
                    if retry.status.success() {
                        let payload = ExecutionOutcomePayload::Destroy(
                            crate::deployment::DestroyExecutionOutcome {
                                deployment_id: runtime_artifacts.handoff.output_dir.clone(),
                                state: "destroyed".to_string(),
                                destroyed_resources: Vec::new(),
                            },
                        );
                        return Ok(Some(ExecutionOutcome {
                            status: Some("destroyed".to_string()),
                            message: Some(format!(
                                "terraform destroy executed locally via {} after AWS cleanup fallback",
                                script_path.display()
                            )),
                            output_files: vec![
                                stdout_log,
                                stderr_log,
                                cleanup_stdout.to_string(),
                                cleanup_stderr.to_string(),
                                retry_stdout.to_string(),
                                retry_stderr.to_string(),
                            ],
                            payload: Some(payload),
                        }));
                    }
                }
            }
        }
        let code = output
            .status
            .code()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(DeployerError::Other(format!(
            "terraform {operation} failed with exit {code}; see {stdout_log} and {stderr_log}"
        )));
    }

    let state = if operation == "apply" {
        "applied"
    } else {
        "destroyed"
    };
    if operation == "apply" {
        let _ = capture_terraform_outputs(runtime_artifacts);
    }
    let endpoints = if operation == "apply" {
        collect_runtime_endpoints(runtime_artifacts)
    } else {
        Vec::new()
    };
    let output_refs = if operation == "apply" {
        collect_terraform_output_refs(runtime_artifacts)
    } else {
        BTreeMap::new()
    };
    let payload = if operation == "apply" {
        ExecutionOutcomePayload::Apply(crate::deployment::ApplyExecutionOutcome {
            deployment_id: runtime_artifacts.handoff.output_dir.clone(),
            state: state.to_string(),
            provider: Some(config.provider.as_str().to_string()),
            strategy: Some(config.strategy.clone()),
            endpoints,
            output_refs,
        })
    } else {
        ExecutionOutcomePayload::Destroy(crate::deployment::DestroyExecutionOutcome {
            deployment_id: runtime_artifacts.handoff.output_dir.clone(),
            state: state.to_string(),
            destroyed_resources: Vec::new(),
        })
    };

    Ok(Some(ExecutionOutcome {
        status: Some(state.to_string()),
        message: Some(format!(
            "terraform {operation} executed locally via {}",
            script_path.display()
        )),
        output_files: vec![stdout_log, stderr_log],
        payload: Some(payload),
    }))
}

fn run_script_capture_logs(
    script_path: &Path,
    current_dir: &Path,
    runtime_artifacts: &RuntimeArtifacts,
    stdout_log: &str,
    stderr_log: &str,
) -> Result<std::process::Output> {
    let output = Command::new(script_path)
        .current_dir(current_dir)
        .output()
        .map_err(DeployerError::Io)?;
    fs::write(
        runtime_artifacts.deploy_dir.join(stdout_log),
        &output.stdout,
    )?;
    fs::write(
        runtime_artifacts.deploy_dir.join(stderr_log),
        &output.stderr,
    )?;
    Ok(output)
}

fn execute_local_scripted_operation(
    config: &DeployerConfig,
    runtime_artifacts: &RuntimeArtifacts,
    script_name: &str,
    log_prefix: &str,
    state: &str,
    payload_kind: ScriptedPayloadKind,
    message: &str,
) -> Result<Option<ExecutionOutcome>> {
    let script_path = runtime_artifacts.deploy_dir.join(script_name);
    if !script_path.exists() {
        return Ok(None);
    }

    let output = Command::new(&script_path)
        .current_dir(&runtime_artifacts.deploy_dir)
        .output()
        .map_err(DeployerError::Io)?;

    let stdout_log = format!("{log_prefix}.stdout.log");
    let stderr_log = format!("{log_prefix}.stderr.log");
    fs::write(
        runtime_artifacts.deploy_dir.join(&stdout_log),
        &output.stdout,
    )?;
    fs::write(
        runtime_artifacts.deploy_dir.join(&stderr_log),
        &output.stderr,
    )?;

    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(DeployerError::Other(format!(
            "{script_name} failed with exit {code}; see {stdout_log} and {stderr_log}"
        )));
    }

    let endpoints = if matches!(payload_kind, ScriptedPayloadKind::Apply) {
        collect_runtime_endpoints(runtime_artifacts)
    } else {
        Vec::new()
    };
    let output_refs = if matches!(payload_kind, ScriptedPayloadKind::Apply) {
        collect_terraform_output_refs(runtime_artifacts)
    } else {
        BTreeMap::new()
    };
    let payload = match payload_kind {
        ScriptedPayloadKind::Apply => {
            ExecutionOutcomePayload::Apply(crate::deployment::ApplyExecutionOutcome {
                deployment_id: runtime_artifacts.handoff.output_dir.clone(),
                state: state.to_string(),
                provider: Some(config.provider.as_str().to_string()),
                strategy: Some(config.strategy.clone()),
                endpoints,
                output_refs,
            })
        }
        ScriptedPayloadKind::Destroy => {
            ExecutionOutcomePayload::Destroy(crate::deployment::DestroyExecutionOutcome {
                deployment_id: runtime_artifacts.handoff.output_dir.clone(),
                state: state.to_string(),
                destroyed_resources: Vec::new(),
            })
        }
    };

    Ok(Some(ExecutionOutcome {
        status: Some(state.to_string()),
        message: Some(format!("{message} via {}", script_path.display())),
        output_files: vec![stdout_log, stderr_log],
        payload: Some(payload),
    }))
}

fn synthesize_local_terraform_status(
    config: &DeployerConfig,
    runtime_artifacts: &RuntimeArtifacts,
) -> Result<Option<ExecutionOutcome>> {
    let runtime_path = runtime_artifacts.deploy_dir.join("terraform-runtime.json");
    let bytes = match fs::read(&runtime_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(DeployerError::Io(err)),
    };
    let metadata: TerraformRuntimeMetadata =
        serde_json::from_slice(&bytes).map_err(|err| DeployerError::Other(err.to_string()))?;

    let terraform_root = PathBuf::from(&metadata.terraform_root);
    let mut health_checks = Vec::new();
    health_checks.push(format!("terraform_runtime_json:{}", runtime_path.display()));
    health_checks.push(format!(
        "terraform_root:{}",
        if terraform_root.exists() {
            "present"
        } else {
            "missing"
        }
    ));
    for script in &metadata.scripts {
        let present = runtime_artifacts.deploy_dir.join(script).exists();
        health_checks.push(format!(
            "script:{}:{}",
            script,
            if present { "present" } else { "missing" }
        ));
    }

    let ready = terraform_root.exists()
        && metadata
            .scripts
            .iter()
            .all(|script| runtime_artifacts.deploy_dir.join(script).exists());
    let state = if ready {
        "handoff_ready"
    } else {
        "handoff_incomplete"
    };
    let endpoints = collect_runtime_endpoints(runtime_artifacts);
    let output_refs = collect_terraform_output_refs(runtime_artifacts);

    Ok(Some(ExecutionOutcome {
        status: Some(state.to_string()),
        message: Some("terraform status synthesized from local handoff artifacts".into()),
        output_files: vec![
            "terraform-runtime.json".into(),
            "terraform-handoff.txt".into(),
            "terraform-init.sh".into(),
            "terraform-plan.sh".into(),
            "terraform-apply.sh".into(),
            "terraform-destroy.sh".into(),
            "terraform-status.sh".into(),
        ],
        payload: Some(ExecutionOutcomePayload::Status(
            crate::deployment::StatusExecutionOutcome {
                deployment_id: runtime_artifacts.handoff.output_dir.clone(),
                state: state.to_string(),
                provider: Some(config.provider.as_str().to_string()),
                strategy: Some(config.strategy.clone()),
                status_source: Some("terraform_handoff".into()),
                endpoints,
                health_checks,
                output_refs,
            },
        )),
    }))
}

fn collect_runtime_endpoints(runtime_artifacts: &RuntimeArtifacts) -> Vec<String> {
    let outputs_path = runtime_artifacts.deploy_dir.join("terraform-outputs.json");
    if let Ok(contents) = fs::read_to_string(&outputs_path) {
        let endpoints = parse_terraform_output_endpoints(&contents);
        if !endpoints.is_empty() {
            return endpoints;
        }
    }

    let terraform_root = runtime_artifacts.deploy_dir.join("terraform");
    let Some(tfvars_path) = select_tfvars_path(&terraform_root) else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(tfvars_path) else {
        return Vec::new();
    };

    parse_dns_name_endpoint(&contents).into_iter().collect()
}

fn collect_terraform_output_refs(runtime_artifacts: &RuntimeArtifacts) -> BTreeMap<String, String> {
    let outputs_path = runtime_artifacts.deploy_dir.join("terraform-outputs.json");
    let Ok(contents) = fs::read_to_string(outputs_path) else {
        return BTreeMap::new();
    };
    parse_terraform_output_refs(&contents)
}

fn capture_terraform_outputs(runtime_artifacts: &RuntimeArtifacts) -> Result<()> {
    let terraform_root = runtime_artifacts.deploy_dir.join("terraform");
    if !terraform_root.exists() {
        return Ok(());
    }

    let terraform_bin = if terraform_root.join("terraform").exists() {
        terraform_root.join("terraform")
    } else {
        PathBuf::from("terraform")
    };
    let output = Command::new(terraform_bin)
        .current_dir(&terraform_root)
        .arg("output")
        .arg("-json")
        .output()
        .map_err(DeployerError::Io)?;

    if !output.status.success() {
        return Ok(());
    }

    fs::write(
        runtime_artifacts.deploy_dir.join("terraform-outputs.json"),
        output.stdout,
    )
    .map_err(DeployerError::Io)
}

fn select_tfvars_path(terraform_root: &Path) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(terraform_root)
        .ok()?
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| {
                        value.ends_with(".tfvars") || value.ends_with(".tfvars.example")
                    })
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| {
                    value.ends_with(".tfvars") && !value.ends_with(".tfvars.example")
                })
        })
        .cloned()
        .or_else(|| candidates.into_iter().next())
}

fn parse_dns_name_endpoint(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let (key, value) = trimmed.split_once('=')?;
        if key.trim() != "dns_name" {
            continue;
        }
        let dns_name = value
            .split('#')
            .next()
            .and_then(|segment| segment.split("//").next())
            .map(str::trim)
            .map(|segment| segment.trim_matches('"'))
            .filter(|segment| !segment.is_empty())?;
        return Some(format!("https://{dns_name}"));
    }
    None
}

fn parse_terraform_output_endpoints(contents: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(contents) else {
        return Vec::new();
    };
    let Some(map) = value.as_object() else {
        return Vec::new();
    };

    let mut endpoints = Vec::new();
    for (key, value) in map {
        let lower = key.to_ascii_lowercase();
        if !lower.contains("endpoint") && !lower.contains("url") && !lower.contains("dns") {
            continue;
        }
        let Some(output_value) = value.get("value") else {
            continue;
        };
        if let Some(url) = output_value.as_str() {
            endpoints.push(url.to_string());
        }
    }
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

fn parse_terraform_output_refs(contents: &str) -> BTreeMap<String, String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(contents) else {
        return BTreeMap::new();
    };
    let Some(map) = value.as_object() else {
        return BTreeMap::new();
    };

    let mut refs = BTreeMap::new();
    for (key, value) in map {
        let Some(output_value) = value.get("value") else {
            continue;
        };
        if let Some(text) = output_value.as_str() {
            refs.insert(key.clone(), text.to_string());
        }
    }
    refs
}

fn synthesize_scripted_handoff_status(
    config: &DeployerConfig,
    runtime_artifacts: &RuntimeArtifacts,
    handoff_note: &str,
    checks: Vec<(&str, &str)>,
    message: &str,
) -> Result<Option<ExecutionOutcome>> {
    let note_path = runtime_artifacts.deploy_dir.join(handoff_note);
    if !note_path.exists() {
        return Ok(None);
    }

    let mut health_checks = Vec::new();
    let mut ready = true;
    let mut output_files = vec![handoff_note.to_string()];
    for (name, relative_path) in checks {
        let path = runtime_artifacts.deploy_dir.join(relative_path);
        let present = path.exists();
        ready &= present;
        health_checks.push(format!(
            "{}:{}",
            name,
            if present { "present" } else { "missing" }
        ));
        if path.is_file() {
            output_files.push(relative_path.to_string());
        }
    }
    let state = if ready {
        "handoff_ready"
    } else {
        "handoff_incomplete"
    };

    Ok(Some(ExecutionOutcome {
        status: Some(state.to_string()),
        message: Some(message.to_string()),
        output_files,
        payload: Some(ExecutionOutcomePayload::Status(
            crate::deployment::StatusExecutionOutcome {
                deployment_id: runtime_artifacts.handoff.output_dir.clone(),
                state: state.to_string(),
                provider: Some(config.provider.as_str().to_string()),
                strategy: Some(config.strategy.clone()),
                status_source: Some("scripted_handoff".into()),
                endpoints: Vec::new(),
                health_checks,
                output_refs: BTreeMap::new(),
            },
        )),
    }))
}

fn operation_payload(
    capability: DeployerCapability,
    plan: &PlanContext,
    target: &DeploymentTarget,
    runtime_artifacts: &RuntimeArtifacts,
    capability_contract: Option<&ResolvedCapabilityContract>,
    rendered_output: Option<String>,
) -> Option<OperationPayload> {
    match capability {
        DeployerCapability::Plan => Some(OperationPayload::Plan(Box::new(PlanPayload {
            plan: plan.clone(),
            rendered_output,
        }))),
        DeployerCapability::Generate => {
            Some(OperationPayload::Generate(Box::new(GeneratePayload {
                capability: capability.as_str().to_string(),
                provider: target.provider.clone(),
                strategy: target.strategy.clone(),
                input_schema_path: capability_contract
                    .and_then(|entry| entry.input_schema.as_ref())
                    .map(|asset| asset.path.clone()),
                output_schema_path: capability_contract
                    .and_then(|entry| entry.output_schema.as_ref())
                    .map(|asset| asset.path.clone()),
                qa_spec_path: capability_contract
                    .and_then(|entry| entry.qa_spec.as_ref())
                    .map(|asset| asset.path.clone()),
                example_paths: capability_contract
                    .map(|entry| {
                        entry
                            .examples
                            .iter()
                            .map(|asset| asset.path.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                rendered_output,
            })))
        }
        DeployerCapability::Apply => Some(OperationPayload::Apply(Box::new(ApplyPayload {
            capability: capability.as_str().to_string(),
            provider: target.provider.clone(),
            strategy: target.strategy.clone(),
            pack_id: runtime_artifacts.handoff.pack_id.clone(),
            flow_id: runtime_artifacts.handoff.flow_id.clone(),
            output_dir: runtime_artifacts.handoff.output_dir.clone(),
            plan_path: runtime_artifacts.plan.display().to_string(),
            invoke_path: runtime_artifacts.invoke.display().to_string(),
            runner_cmd: runtime_artifacts.handoff.runner_cmd.clone(),
            runner_env: runtime_artifacts.handoff.runner_env.clone(),
        }))),
        DeployerCapability::Destroy => Some(OperationPayload::Destroy(Box::new(DestroyPayload {
            capability: capability.as_str().to_string(),
            provider: target.provider.clone(),
            strategy: target.strategy.clone(),
            pack_id: runtime_artifacts.handoff.pack_id.clone(),
            flow_id: runtime_artifacts.handoff.flow_id.clone(),
            output_dir: runtime_artifacts.handoff.output_dir.clone(),
            plan_path: runtime_artifacts.plan.display().to_string(),
            invoke_path: runtime_artifacts.invoke.display().to_string(),
            runner_cmd: runtime_artifacts.handoff.runner_cmd.clone(),
            runner_env: runtime_artifacts.handoff.runner_env.clone(),
        }))),
        DeployerCapability::Status => Some(OperationPayload::Status(Box::new(StatusPayload {
            capability: capability.as_str().to_string(),
            provider: target.provider.clone(),
            strategy: target.strategy.clone(),
            pack_id: runtime_artifacts.handoff.pack_id.clone(),
            flow_id: runtime_artifacts.handoff.flow_id.clone(),
            rendered_output,
        }))),
        DeployerCapability::Rollback => {
            Some(OperationPayload::Rollback(Box::new(RollbackPayload {
                capability: capability.as_str().to_string(),
                provider: target.provider.clone(),
                strategy: target.strategy.clone(),
                pack_id: runtime_artifacts.handoff.pack_id.clone(),
                flow_id: runtime_artifacts.handoff.flow_id.clone(),
                target_capability: DeployerCapability::Apply.as_str().to_string(),
                rendered_output,
            })))
        }
    }
}

fn output_schema_for_operation<'a>(
    capability: DeployerCapability,
    contract: Option<&'a ResolvedDeployerContract>,
    capability_contract: Option<&'a ResolvedCapabilityContract>,
) -> Option<&'a crate::contract::ContractAsset> {
    match capability {
        DeployerCapability::Plan => contract
            .as_ref()
            .and_then(|entry| entry.planner.output_schema.as_ref()),
        DeployerCapability::Generate
        | DeployerCapability::Apply
        | DeployerCapability::Destroy
        | DeployerCapability::Status
        | DeployerCapability::Rollback => capability_contract
            .as_ref()
            .and_then(|entry| entry.output_schema.as_ref()),
    }
}

struct OperationResultData {
    contract: Option<ResolvedDeployerContract>,
    capability_contract: Option<ResolvedCapabilityContract>,
    payload: Option<OperationPayload>,
    output_validation: Option<OutputValidation>,
    execution_outcome: Option<ExecutionOutcome>,
    executed: bool,
}

fn build_operation_result(
    config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    runtime_artifacts: &RuntimeArtifacts,
    data: OperationResultData,
) -> OperationResult {
    let execution = data.executed.then(|| {
        build_execution_report(
            runtime_artifacts,
            data.capability_contract.as_ref(),
            data.execution_outcome,
        )
    });
    OperationResult {
        capability: config.capability.as_str().to_string(),
        executed: data.executed,
        preview: config.preview,
        output_dir: config.provider_output_dir().display().to_string(),
        plan_path: runtime_artifacts.plan.display().to_string(),
        invoke_path: runtime_artifacts.invoke.display().to_string(),
        pack_id: selection.dispatch.pack_id.clone(),
        flow_id: selection.dispatch.flow_id.clone(),
        pack_path: selection.pack_path.display().to_string(),
        contract: data.contract,
        capability_contract: data.capability_contract,
        payload: data.payload,
        output_validation: data.output_validation,
        execution,
    }
}

fn build_execution_report(
    runtime_artifacts: &RuntimeArtifacts,
    capability_contract: Option<&ResolvedCapabilityContract>,
    execution_outcome: Option<ExecutionOutcome>,
) -> ExecutionReport {
    let status = execution_outcome
        .as_ref()
        .and_then(|outcome| outcome.status.clone());
    let message = execution_outcome
        .as_ref()
        .and_then(|outcome| outcome.message.clone());
    let outcome_payload = execution_outcome
        .as_ref()
        .and_then(|outcome| outcome.payload.clone());
    let outcome_validation = validation_for_execution_outcome(
        capability_contract.and_then(|contract| contract.execution_output_schema.as_ref()),
        outcome_payload.as_ref(),
    )
    .unwrap_or_else(|err| {
        Some(OutputValidation {
            schema_path: capability_contract
                .and_then(|contract| contract.execution_output_schema.as_ref())
                .map(|asset| asset.path.clone())
                .unwrap_or_default(),
            valid: false,
            errors: vec![err.to_string()],
        })
    });
    let mut output_files = collect_output_files(&runtime_artifacts.deploy_dir);
    if let Some(outcome) = execution_outcome.as_ref() {
        for file in &outcome.output_files {
            if !output_files.iter().any(|existing| existing == file) {
                output_files.push(file.clone());
            }
        }
        output_files.sort();
    }
    ExecutionReport {
        output_dir: runtime_artifacts.handoff.output_dir.clone(),
        plan_path: runtime_artifacts.plan.display().to_string(),
        invoke_path: runtime_artifacts.invoke.display().to_string(),
        handoff_path: runtime_artifacts.handoff_path.display().to_string(),
        runner_command_path: runtime_artifacts.runner_command_path.display().to_string(),
        status,
        message,
        output_files,
        outcome_payload,
        outcome_validation,
    }
}

fn collect_output_files(output_dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(output_dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && let Some(name) = path.file_name().and_then(|name| name.to_str())
        {
            files.push(name.to_string());
        }
    }
    files.sort();
    files
}

fn validation_for_payload(
    schema: Option<&crate::contract::ContractAsset>,
    payload: &OperationPayload,
) -> Result<Option<OutputValidation>> {
    validation_for_json_value(
        schema,
        serde_json::to_value(payload).map_err(|err| DeployerError::Other(err.to_string())),
    )
}

fn validation_for_execution_outcome(
    schema: Option<&crate::contract::ContractAsset>,
    payload: Option<&ExecutionOutcomePayload>,
) -> Result<Option<OutputValidation>> {
    let Some(payload) = payload else {
        return Ok(None);
    };
    validation_for_json_value(
        schema,
        serde_json::to_value(payload).map_err(|err| DeployerError::Other(err.to_string())),
    )
}

fn validation_for_json_value(
    schema: Option<&crate::contract::ContractAsset>,
    payload: Result<JsonValue>,
) -> Result<Option<OutputValidation>> {
    let Some(schema) = schema else {
        return Ok(None);
    };
    let Some(schema_json) = schema.json.as_ref() else {
        return Ok(Some(OutputValidation {
            schema_path: schema.path.clone(),
            valid: false,
            errors: vec![format!("schema asset {} is not valid JSON", schema.path)],
        }));
    };

    let compiled = jsonschema::validator_for(schema_json).map_err(|err| {
        DeployerError::Contract(format!(
            "failed to compile output schema {}: {}",
            schema.path, err
        ))
    })?;
    let instance = payload?;

    let errors = compiled
        .iter_errors(&instance)
        .map(|err| err.to_string())
        .collect::<Vec<_>>();

    Ok(Some(OutputValidation {
        schema_path: schema.path.clone(),
        valid: errors.is_empty(),
        errors,
    }))
}

struct RuntimeArtifacts {
    deploy_dir: PathBuf,
    plan: PathBuf,
    invoke: PathBuf,
    handoff: DeployerInvocation,
    handoff_path: PathBuf,
    runner_command_path: PathBuf,
}

fn persist_runtime_artifacts(
    config: &DeployerConfig,
    plan: &PlanContext,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<RuntimeArtifacts> {
    let runtime_dir = config.runtime_output_dir();
    fs::create_dir_all(&runtime_dir)?;

    let plan_path = runtime_dir.join("plan.json");
    let plan_file = fs::File::create(&plan_path)?;
    serde_json::to_writer_pretty(plan_file, plan)?;

    let invocation = RuntimeInvocation {
        capability: selection.dispatch.capability.as_str().to_string(),
        provider: config.provider.as_str().to_string(),
        strategy: config.strategy.clone(),
        tenant: config.tenant.clone(),
        environment: config.environment.clone(),
        output_dir: deploy_dir.display().to_string(),
        plan_path: plan_path.display().to_string(),
        pack_id: selection.dispatch.pack_id.clone(),
        flow_id: selection.dispatch.flow_id.clone(),
        pack_path: selection.pack_path.display().to_string(),
    };
    let invoke_path = runtime_dir.join("invoke.json");
    let invoke_file = fs::File::create(&invoke_path)?;
    serde_json::to_writer_pretty(invoke_file, &invocation)?;

    materialize_adapter_handoff_assets(config, selection, deploy_dir)?;
    let handoff = write_runner_diagnostics(config, deploy_dir, selection, &plan_path)?;

    Ok(RuntimeArtifacts {
        deploy_dir: deploy_dir.to_path_buf(),
        plan: plan_path,
        invoke: invoke_path,
        handoff: handoff.invocation,
        handoff_path: handoff.handoff_path,
        runner_command_path: handoff.runner_command_path,
    })
}

fn materialize_adapter_handoff_assets(
    config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    if uses_terraform_handoff(config) {
        materialize_terraform_handoff_assets(config, selection, deploy_dir)?;
    } else if config.provider == crate::config::Provider::K8s && config.strategy == "raw-manifests"
    {
        materialize_k8s_raw_handoff_assets(config, selection, deploy_dir)?;
    } else if config.provider == crate::config::Provider::K8s && config.strategy == "operator" {
        materialize_operator_handoff_assets(config, selection, deploy_dir)?;
    } else if config.provider == crate::config::Provider::K8s && config.strategy == "helm" {
        materialize_helm_handoff_assets(config, selection, deploy_dir)?;
    } else if config.provider == crate::config::Provider::Generic
        && config.strategy == "serverless-container"
    {
        materialize_serverless_handoff_assets(config, selection, deploy_dir)?;
    } else if uses_snap_handoff(config) {
        materialize_snap_handoff_assets(config, selection, deploy_dir)?;
    } else if uses_juju_machine_handoff(config) {
        materialize_juju_machine_handoff_assets(config, selection, deploy_dir)?;
    } else if uses_juju_k8s_handoff(config) {
        materialize_juju_k8s_handoff_assets(config, selection, deploy_dir)?;
    }
    Ok(())
}

fn materialize_terraform_handoff_assets(
    config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let terraform_root = deploy_dir.join("terraform");
    let copied = copy_pack_subtree(&selection.pack_path, "terraform", &terraform_root)?;
    if copied.is_empty() {
        return Ok(());
    }
    let local_terraform = terraform_root.join("terraform");
    if local_terraform.exists() {
        set_executable_if_unix(&local_terraform)?;
    }
    prune_generated_terraform_root(config, &terraform_root)?;
    configure_terraform_backend(config, &terraform_root, deploy_dir)?;

    let tfvars_example = resolve_tfvars_example_name(&terraform_root, &config.environment)?;
    let generated_tfvars = materialize_generated_tfvars(config, &terraform_root, &tfvars_example)?;
    let init_script = "terraform-init.sh";
    let plan_script = "terraform-plan.sh";
    let apply_script = "terraform-apply.sh";
    let destroy_script = "terraform-destroy.sh";
    let status_script = "terraform-status.sh";
    let aws_cleanup_script = "terraform-aws-cleanup.sh";
    write_executable_script(&deploy_dir.join(init_script), terraform_init_script())?;
    write_executable_script(
        &deploy_dir.join(plan_script),
        terraform_plan_like_script("plan", generated_tfvars.as_deref(), &tfvars_example),
    )?;
    write_executable_script(
        &deploy_dir.join(apply_script),
        terraform_plan_like_script("apply", generated_tfvars.as_deref(), &tfvars_example),
    )?;
    write_executable_script(
        &deploy_dir.join(destroy_script),
        terraform_plan_like_script("destroy", generated_tfvars.as_deref(), &tfvars_example),
    )?;
    write_executable_script(
        &deploy_dir.join(status_script),
        terraform_script_prelude("\"$TERRAFORM_BIN\" show -json \"$@\""),
    )?;
    let mut scripts = vec![
        init_script.to_string(),
        plan_script.to_string(),
        apply_script.to_string(),
        destroy_script.to_string(),
        status_script.to_string(),
    ];
    if config.provider == crate::config::Provider::Aws {
        write_executable_script(
            &deploy_dir.join(aws_cleanup_script),
            terraform_aws_cleanup_script(generated_tfvars.as_deref(), &tfvars_example),
        )?;
        scripts.push(aws_cleanup_script.to_string());
    }

    let metadata = TerraformRuntimeMetadata {
        terraform_root: terraform_root.display().to_string(),
        copied_files: copied.clone(),
        scripts,
        generated_tfvars: generated_tfvars.clone(),
        init_command: format!("./{init_script}"),
        plan_command: format!("./{plan_script}"),
        apply_command: format!("./{apply_script}"),
        destroy_command: format!("./{destroy_script}"),
        status_command: format!("./{status_script}"),
    };
    fs::write(
        deploy_dir.join("terraform-runtime.json"),
        serde_json::to_vec_pretty(&metadata)
            .map_err(|err| DeployerError::Other(err.to_string()))?,
    )?;

    let mut note = String::new();
    note.push_str("Terraform handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!("terraform_root={}\n", terraform_root.display()));
    note.push_str(&format!(
        "suggested_tfvars_example={}\n",
        terraform_root.join(&tfvars_example).display()
    ));
    if let Some(tfvars) = generated_tfvars.as_ref() {
        note.push_str(&format!(
            "generated_tfvars={}\n",
            terraform_root.join(tfvars).display()
        ));
    }
    note.push_str("terraform_env_override_prefix=GREENTIC_DEPLOY_TERRAFORM_VAR_\n");
    note.push_str(
        "scripts=terraform-init.sh, terraform-plan.sh, terraform-apply.sh, terraform-destroy.sh, terraform-status.sh\n",
    );
    if config.provider == crate::config::Provider::Aws {
        note.push_str("aws_cleanup_command=./terraform-aws-cleanup.sh\n");
    }
    note.push_str(&format!("status_command={}\n", metadata.status_command));
    note.push_str("copied_files:\n");
    for path in copied {
        note.push_str(&format!("- {path}\n"));
    }
    fs::write(deploy_dir.join("terraform-handoff.txt"), note)?;
    Ok(())
}

fn prune_generated_terraform_root(config: &DeployerConfig, terraform_root: &Path) -> Result<()> {
    let (module_name, module_source, module_inputs) = match config.provider {
        crate::config::Provider::Aws => (
            "operator",
            "./modules/operator",
            r#"  cloud                 = var.cloud
  operator_image        = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  bundle_source         = var.bundle_source
  bundle_digest         = var.bundle_digest
  repo_registry_base    = var.repo_registry_base
  store_registry_base   = var.store_registry_base
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url       = var.public_base_url"#,
        ),
        crate::config::Provider::Azure => (
            "operator",
            "./modules/operator-azure",
            r#"  cloud                 = var.cloud
  environment           = var.environment
  bundle_digest         = var.bundle_digest
  bundle_source         = var.bundle_source
  repo_registry_base    = var.repo_registry_base
  store_registry_base   = var.store_registry_base
  operator_image        = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url       = var.public_base_url
  azure_key_vault_uri   = var.azure_key_vault_uri
  azure_key_vault_id    = var.azure_key_vault_id
  azure_location        = var.azure_location"#,
        ),
        crate::config::Provider::Gcp => (
            "operator",
            "./modules/operator-gcp",
            r#"  cloud                 = var.cloud
  environment           = var.environment
  bundle_digest         = var.bundle_digest
  bundle_source         = var.bundle_source
  repo_registry_base    = var.repo_registry_base
  store_registry_base   = var.store_registry_base
  operator_image        = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url       = var.public_base_url
  gcp_project_id        = var.gcp_project_id
  gcp_region            = var.gcp_region"#,
        ),
        _ => return Ok(()),
    };

    let main_tf = format!(
        "module \"{module_name}\" {{\n  source = \"{module_source}\"\n\n{module_inputs}\n}}\n\nmodule \"dns\" {{\n  count  = var.dns_name != \"\" ? 1 : 0\n  source = \"./modules/dns\"\n\n  dns_name = var.dns_name\n}}\n\nmodule \"registry\" {{\n  source = \"./modules/registry\"\n\n  bundle_source = var.bundle_source\n  bundle_digest = var.bundle_digest\n}}\n"
    );
    fs::write(terraform_root.join("main.tf"), main_tf)?;

    let outputs_tf = format!(
        r#"output "operator_endpoint" {{
  value = module.{module_name}.operator_endpoint
}}

output "cloud_provider" {{
  value = var.cloud
}}

output "admin_ca_secret_ref" {{
  value = module.{module_name}.admin_ca_secret_ref
}}

output "admin_server_cert_secret_ref" {{
  value = module.{module_name}.admin_server_cert_secret_ref
}}

output "admin_server_key_secret_ref" {{
  value = module.{module_name}.admin_server_key_secret_ref
}}

output "admin_client_cert_secret_ref" {{
  value = module.{module_name}.admin_client_cert_secret_ref
}}

output "admin_client_key_secret_ref" {{
  value = module.{module_name}.admin_client_key_secret_ref
}}
"#
    );
    fs::write(terraform_root.join("outputs.tf"), outputs_tf)?;

    Ok(())
}

fn materialize_generated_tfvars(
    config: &DeployerConfig,
    terraform_root: &Path,
    tfvars_example: &str,
) -> Result<Option<String>> {
    if config.bundle_source.is_none()
        && config.bundle_digest.is_none()
        && terraform_env_overrides().is_empty()
    {
        return Ok(None);
    }

    let example_path = terraform_root.join(tfvars_example);
    let output_name = format!("{}.tfvars", config.environment);
    let output_path = terraform_root.join(&output_name);

    let mut contents = if example_path.exists() {
        fs::read_to_string(&example_path)?
    } else {
        String::new()
    };

    if let Some(bundle_source) = config.bundle_source.as_ref() {
        replace_tfvars_assignment(&mut contents, "bundle_source", bundle_source);
    }
    if let Some(bundle_digest) = config.bundle_digest.as_ref() {
        replace_tfvars_assignment(&mut contents, "bundle_digest", bundle_digest);
    }
    if let Some(repo_registry_base) = config.repo_registry_base.as_ref() {
        replace_tfvars_assignment(&mut contents, "repo_registry_base", repo_registry_base);
    }
    if let Some(store_registry_base) = config.store_registry_base.as_ref() {
        replace_tfvars_assignment(&mut contents, "store_registry_base", store_registry_base);
    }
    for (key, value) in terraform_env_overrides() {
        replace_tfvars_assignment(&mut contents, &key, &value);
    }

    fs::write(output_path, contents)?;
    Ok(Some(output_name))
}

fn resolve_tfvars_example_name(terraform_root: &Path, environment: &str) -> Result<String> {
    let preferred = format!("{environment}.tfvars.example");
    if terraform_root.join(&preferred).exists() {
        return Ok(preferred);
    }

    let mut candidates = fs::read_dir(terraform_root)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_file() {
                return None;
            }
            let name = entry.file_name();
            let name = name.to_str()?;
            name.ends_with(".tfvars.example").then(|| name.to_string())
        })
        .collect::<Vec<_>>();
    candidates.sort();

    Ok(candidates.into_iter().next().unwrap_or(preferred))
}

fn terraform_env_overrides() -> Vec<(String, String)> {
    const PREFIX: &str = "GREENTIC_DEPLOY_TERRAFORM_VAR_";
    let mut overrides = std::env::vars()
        .filter_map(|(key, value)| {
            let suffix = key.strip_prefix(PREFIX)?;
            let normalized = suffix.trim();
            if normalized.is_empty() {
                return None;
            }
            Some((normalized.to_ascii_lowercase(), value))
        })
        .map(|(key, value)| (key.replace("__", "-").replace('_', "."), value))
        .map(|(key, value)| (key.replace('.', "_"), value))
        .collect::<Vec<_>>();
    overrides.sort_by(|a, b| a.0.cmp(&b.0));
    overrides
}

fn replace_tfvars_assignment(contents: &mut String, key: &str, value: &str) {
    let replacement = format!(
        "{key} = {}",
        serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
    );

    let mut rewritten = Vec::new();
    let mut replaced = false;
    for line in contents.lines() {
        let trimmed = line.trim_start();
        if !replaced && trimmed.starts_with(&format!("{key} =")) {
            rewritten.push(replacement.clone());
            replaced = true;
        } else {
            rewritten.push(line.to_string());
        }
    }
    if !replaced {
        rewritten.push(replacement);
    }
    *contents = rewritten.join("\n");
    contents.push('\n');
}

fn materialize_k8s_raw_handoff_assets(
    _config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let manifests = read_pack_asset(
        &selection.pack_path,
        "assets/examples/rendered-manifests.yaml",
    )?;
    let k8s_root = deploy_dir.join("k8s");
    fs::create_dir_all(&k8s_root)?;
    fs::write(k8s_root.join("rendered-manifests.yaml"), manifests)?;
    write_executable_script(
        &deploy_dir.join("kubectl-apply.sh"),
        kubectl_script("apply -f \"$K8S_ROOT/rendered-manifests.yaml\" \"$@\""),
    )?;
    write_executable_script(
        &deploy_dir.join("kubectl-delete.sh"),
        kubectl_script("delete -f \"$K8S_ROOT/rendered-manifests.yaml\" \"$@\""),
    )?;
    write_executable_script(
        &deploy_dir.join("kubectl-status.sh"),
        kubectl_script("get -f \"$K8S_ROOT/rendered-manifests.yaml\" \"$@\""),
    )?;

    let mut note = String::new();
    note.push_str("K8s raw handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!(
        "manifest_path={}\n",
        k8s_root.join("rendered-manifests.yaml").display()
    ));
    note.push_str("scripts=kubectl-apply.sh, kubectl-delete.sh, kubectl-status.sh\n");
    fs::write(deploy_dir.join("k8s-handoff.txt"), note)?;
    Ok(())
}

fn materialize_helm_handoff_assets(
    config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let chart_root = deploy_dir.join("helm-chart");
    let copied = copy_pack_subtree(&selection.pack_path, "chart", &chart_root)?;
    if copied.is_empty() {
        return Ok(());
    }

    let release_name = format!("greentic-{}", config.tenant);
    write_executable_script(
        &deploy_dir.join("helm-upgrade.sh"),
        helm_script(&format!(
            "upgrade --install {release_name} \"$CHART_ROOT\" \"$@\""
        )),
    )?;
    write_executable_script(
        &deploy_dir.join("helm-rollback.sh"),
        helm_script(&format!("rollback {release_name} \"$@\"")),
    )?;
    write_executable_script(
        &deploy_dir.join("helm-status.sh"),
        helm_script(&format!("status {release_name} \"$@\"")),
    )?;

    let mut note = String::new();
    note.push_str("Helm handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!("chart_root={}\n", chart_root.display()));
    note.push_str(&format!("release_name={release_name}\n"));
    note.push_str("scripts=helm-upgrade.sh, helm-rollback.sh, helm-status.sh\n");
    note.push_str("copied_files:\n");
    for path in copied {
        note.push_str(&format!("- {path}\n"));
    }
    fs::write(deploy_dir.join("helm-handoff.txt"), note)?;
    Ok(())
}

fn materialize_operator_handoff_assets(
    _config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let manifests = read_pack_asset(
        &selection.pack_path,
        "assets/examples/rendered-manifests.yaml",
    )?;
    let operator_root = deploy_dir.join("operator");
    fs::create_dir_all(&operator_root)?;
    fs::write(operator_root.join("rendered-manifests.yaml"), manifests)?;
    write_executable_script(
        &deploy_dir.join("operator-apply.sh"),
        kubectl_root_script(
            "OPERATOR_ROOT",
            "apply -f \"$OPERATOR_ROOT/rendered-manifests.yaml\" \"$@\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("operator-delete.sh"),
        kubectl_root_script(
            "OPERATOR_ROOT",
            "delete -f \"$OPERATOR_ROOT/rendered-manifests.yaml\" \"$@\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("operator-status.sh"),
        kubectl_root_script(
            "OPERATOR_ROOT",
            "get -f \"$OPERATOR_ROOT/rendered-manifests.yaml\" \"$@\"",
        ),
    )?;

    let mut note = String::new();
    note.push_str("Operator handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!(
        "manifest_path={}\n",
        operator_root.join("rendered-manifests.yaml").display()
    ));
    note.push_str("scripts=operator-apply.sh, operator-delete.sh, operator-status.sh\n");
    note.push_str("admin_api=localhost_only_https_mtls\n");
    fs::write(deploy_dir.join("operator-handoff.txt"), note)?;
    Ok(())
}

fn materialize_serverless_handoff_assets(
    _config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let descriptor = read_pack_asset(
        &selection.pack_path,
        "assets/examples/deployment-descriptor.json",
    )?;
    let serverless_root = deploy_dir.join("serverless");
    fs::create_dir_all(&serverless_root)?;
    fs::write(
        serverless_root.join("deployment-descriptor.json"),
        descriptor,
    )?;
    write_executable_script(
        &deploy_dir.join("serverless-deploy.sh"),
        generic_root_script(
            "SERVERLESS_ROOT",
            "echo \"serverless deploy descriptor: $SERVERLESS_ROOT/deployment-descriptor.json\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("serverless-status.sh"),
        generic_root_script(
            "SERVERLESS_ROOT",
            "echo \"serverless status descriptor: $SERVERLESS_ROOT/deployment-descriptor.json\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("serverless-destroy.sh"),
        generic_root_script(
            "SERVERLESS_ROOT",
            "echo \"serverless destroy descriptor: $SERVERLESS_ROOT/deployment-descriptor.json\"",
        ),
    )?;

    let mut note = String::new();
    note.push_str("Serverless handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!(
        "descriptor_path={}\n",
        serverless_root.join("deployment-descriptor.json").display()
    ));
    note.push_str("scripts=serverless-deploy.sh, serverless-destroy.sh, serverless-status.sh\n");
    note.push_str("filesystem_hint=tmp_only\n");
    fs::write(deploy_dir.join("serverless-handoff.txt"), note)?;
    Ok(())
}

fn materialize_snap_handoff_assets(
    _config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let snap_root = deploy_dir.join("snap");
    let copied = copy_pack_subtree(&selection.pack_path, "snap", &snap_root)?;
    if copied.is_empty() {
        return Ok(());
    }
    write_executable_script(
        &deploy_dir.join("snap-install.sh"),
        generic_root_script(
            "SNAP_ROOT",
            "echo \"snap install scaffold from $SNAP_ROOT/fetch/snapcraft.yaml\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("snap-remove.sh"),
        generic_root_script(
            "SNAP_ROOT",
            "echo \"snap remove scaffold from $SNAP_ROOT/embedded/snapcraft.yaml\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("snap-status.sh"),
        generic_root_script(
            "SNAP_ROOT",
            "echo \"snap status scaffold from $SNAP_ROOT/fetch/snapcraft.yaml\"",
        ),
    )?;

    let mut note = String::new();
    note.push_str("Snap handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!("snap_root={}\n", snap_root.display()));
    note.push_str("scripts=snap-install.sh, snap-remove.sh, snap-status.sh\n");
    note.push_str("copied_files:\n");
    for path in copied {
        note.push_str(&format!("- {path}\n"));
    }
    fs::write(deploy_dir.join("snap-handoff.txt"), note)?;
    Ok(())
}

fn materialize_juju_machine_handoff_assets(
    _config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let charm_root = deploy_dir.join("juju-machine-charm");
    let copied = copy_pack_subtree(&selection.pack_path, "charm", &charm_root)?;
    if copied.is_empty() {
        return Ok(());
    }
    write_executable_script(
        &deploy_dir.join("juju-machine-deploy.sh"),
        juju_script(
            "juju-machine-charm",
            "deploy \"$CHARM_ROOT\" greentic-operator \"$@\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("juju-machine-remove.sh"),
        juju_script(
            "juju-machine-charm",
            "remove-application greentic-operator \"$@\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("juju-machine-status.sh"),
        juju_script("juju-machine-charm", "status greentic-operator \"$@\""),
    )?;

    let mut note = String::new();
    note.push_str("Juju machine handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!("charm_root={}\n", charm_root.display()));
    note.push_str(
        "scripts=juju-machine-deploy.sh, juju-machine-remove.sh, juju-machine-status.sh\n",
    );
    note.push_str("copied_files:\n");
    for path in copied {
        note.push_str(&format!("- {path}\n"));
    }
    fs::write(deploy_dir.join("juju-machine-handoff.txt"), note)?;
    Ok(())
}

fn materialize_juju_k8s_handoff_assets(
    _config: &DeployerConfig,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    let charm_root = deploy_dir.join("juju-k8s-charm");
    let copied = copy_pack_subtree(&selection.pack_path, "charm", &charm_root)?;
    if copied.is_empty() {
        return Ok(());
    }
    write_executable_script(
        &deploy_dir.join("juju-k8s-deploy.sh"),
        juju_script(
            "juju-k8s-charm",
            "deploy \"$CHARM_ROOT\" greentic-operator-k8s \"$@\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("juju-k8s-remove.sh"),
        juju_script(
            "juju-k8s-charm",
            "remove-application greentic-operator-k8s \"$@\"",
        ),
    )?;
    write_executable_script(
        &deploy_dir.join("juju-k8s-status.sh"),
        juju_script("juju-k8s-charm", "status greentic-operator-k8s \"$@\""),
    )?;

    let mut note = String::new();
    note.push_str("Juju k8s handoff assets were materialized from the deployment pack.\n");
    note.push_str(&format!("charm_root={}\n", charm_root.display()));
    note.push_str("scripts=juju-k8s-deploy.sh, juju-k8s-remove.sh, juju-k8s-status.sh\n");
    note.push_str("copied_files:\n");
    for path in copied {
        note.push_str(&format!("- {path}\n"));
    }
    fs::write(deploy_dir.join("juju-k8s-handoff.txt"), note)?;
    Ok(())
}

fn terraform_script_prelude(command: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nTF_ROOT=\"${{SCRIPT_DIR}}/terraform\"\ncd \"$TF_ROOT\"\nTERRAFORM_BIN=\"terraform\"\nif [ -x \"$TF_ROOT/terraform\" ]; then\n  TERRAFORM_BIN=\"$TF_ROOT/terraform\"\nfi\n{command}\n"
    )
}

fn terraform_init_script() -> String {
    "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nTF_ROOT=\"${SCRIPT_DIR}/terraform\"\ncd \"$TF_ROOT\"\nTERRAFORM_BIN=\"terraform\"\nif [ -x \"$TF_ROOT/terraform\" ]; then\n  TERRAFORM_BIN=\"$TF_ROOT/terraform\"\nfi\nif [ -f \"${SCRIPT_DIR}/backend.hcl\" ]; then\n  \"$TERRAFORM_BIN\" init -backend-config=\"${SCRIPT_DIR}/backend.hcl\" \"$@\"\nelse\n  \"$TERRAFORM_BIN\" init \"$@\"\nfi\n"
        .to_string()
}

fn terraform_plan_like_script(
    operation: &str,
    generated_tfvars: Option<&str>,
    tfvars_example: &str,
) -> String {
    let extra_args = match operation {
        "apply" | "destroy" => " -auto-approve -input=false",
        _ => " -input=false",
    };
    let tfvars_lookup = if let Some(generated_tfvars) = generated_tfvars {
        format!(
            "if [ -f \"{generated_tfvars}\" ]; then\n  VAR_FILE=\"{generated_tfvars}\"\nelif [ -f \"{tfvars_example}\" ]; then\n  VAR_FILE=\"{tfvars_example}\"\nelse\n  for candidate in *.tfvars *.tfvars.example; do\n    if [ -f \"$candidate\" ]; then\n      VAR_FILE=\"$candidate\"\n      break\n    fi\n  done\nfi"
        )
    } else {
        format!(
            "if [ -f \"{tfvars_example}\" ]; then\n  VAR_FILE=\"{tfvars_example}\"\nelse\n  for candidate in *.tfvars *.tfvars.example; do\n    if [ -f \"$candidate\" ]; then\n      VAR_FILE=\"$candidate\"\n      break\n    fi\n  done\nfi"
        )
    };
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nTF_ROOT=\"${{SCRIPT_DIR}}/terraform\"\ncd \"$TF_ROOT\"\nTERRAFORM_BIN=\"terraform\"\nif [ -x \"$TF_ROOT/terraform\" ]; then\n  TERRAFORM_BIN=\"$TF_ROOT/terraform\"\nfi\nBACKEND_ARGS=()\nif [ -f \"${{SCRIPT_DIR}}/backend.hcl\" ]; then\n  BACKEND_ARGS=(-backend-config=\"${{SCRIPT_DIR}}/backend.hcl\")\nfi\n\"$TERRAFORM_BIN\" init -input=false \"${{BACKEND_ARGS[@]}}\"\nVAR_FILE=\"\"\n{tfvars_lookup}\nif [ -n \"$VAR_FILE\" ]; then\n  \"$TERRAFORM_BIN\" {operation}{extra_args} -var-file=\"$VAR_FILE\" \"$@\"\nelse\n  \"$TERRAFORM_BIN\" {operation}{extra_args} \"$@\"\nfi\n"
    )
}

fn terraform_aws_cleanup_script(generated_tfvars: Option<&str>, tfvars_example: &str) -> String {
    let tfvars_lookup = if let Some(generated_tfvars) = generated_tfvars {
        format!(
            "if [ -f \"{generated_tfvars}\" ]; then\n  VAR_FILE=\"{generated_tfvars}\"\nelif [ -f \"{tfvars_example}\" ]; then\n  VAR_FILE=\"{tfvars_example}\"\nelse\n  for candidate in *.tfvars *.tfvars.example; do\n    if [ -f \"$candidate\" ]; then\n      VAR_FILE=\"$candidate\"\n      break\n    fi\n  done\nfi"
        )
    } else {
        format!(
            "if [ -f \"{tfvars_example}\" ]; then\n  VAR_FILE=\"{tfvars_example}\"\nelse\n  for candidate in *.tfvars *.tfvars.example; do\n    if [ -f \"$candidate\" ]; then\n      VAR_FILE=\"$candidate\"\n      break\n    fi\n  done\nfi"
        )
    };
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nTF_ROOT=\"${{SCRIPT_DIR}}/terraform\"\ncd \"$TF_ROOT\"\nVAR_FILE=\"\"\n{tfvars_lookup}\nif ! command -v aws >/dev/null 2>&1; then\n  echo \"aws cli not found; skipping AWS cleanup fallback\"\n  exit 0\nfi\nBUNDLE_DIGEST=\"\"\nif [ -n \"$VAR_FILE\" ] && [ -f \"$VAR_FILE\" ]; then\n  BUNDLE_DIGEST=$(sed -n 's/^bundle_digest = \"\\(.*\\)\"$/\\1/p' \"$VAR_FILE\" | head -n 1)\nfi\nif [ -z \"$BUNDLE_DIGEST\" ]; then\n  echo \"bundle_digest not found; skipping AWS cleanup fallback\"\n  exit 0\nfi\nAWS_REGION_VALUE=\"${{AWS_REGION:-${{AWS_DEFAULT_REGION:-}}}}\"\nif [ -z \"$AWS_REGION_VALUE\" ]; then\n  echo \"AWS region not set; skipping AWS cleanup fallback\"\n  exit 0\nfi\nSHORT_ID=$(printf '%s' \"$BUNDLE_DIGEST\" | md5sum | awk '{{print substr($1,1,8)}}')\nNAME_PREFIX=\"greentic-${{SHORT_ID}}\"\nSECRET_PREFIX=\"greentic/admin/${{NAME_PREFIX}}/\"\nLOG_GROUP=\"/greentic/demo/${{NAME_PREFIX}}\"\nROLE_NAME=\"${{NAME_PREFIX}}-task-exec\"\nCLUSTER_NAME=\"${{NAME_PREFIX}}-cluster\"\nSERVICE_NAME=\"${{NAME_PREFIX}}-service\"\nLB_NAME=\"${{NAME_PREFIX}}-alb\"\naws logs delete-log-group --region \"$AWS_REGION_VALUE\" --log-group-name \"$LOG_GROUP\" >/dev/null 2>&1 || true\nSECRET_ARNS=$(aws secretsmanager list-secrets --region \"$AWS_REGION_VALUE\" --filters Key=name,Values=\"$SECRET_PREFIX\" --query 'SecretList[].ARN' --output text 2>/dev/null || true)\nfor secret_arn in $SECRET_ARNS; do\n  aws secretsmanager delete-secret --region \"$AWS_REGION_VALUE\" --secret-id \"$secret_arn\" --force-delete-without-recovery >/dev/null 2>&1 || true\ndone\nINLINE_POLICIES=$(aws iam list-role-policies --role-name \"$ROLE_NAME\" --query 'PolicyNames[]' --output text 2>/dev/null || true)\nfor policy_name in $INLINE_POLICIES; do\n  aws iam delete-role-policy --role-name \"$ROLE_NAME\" --policy-name \"$policy_name\" >/dev/null 2>&1 || true\ndone\nATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name \"$ROLE_NAME\" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || true)\nfor policy_arn in $ATTACHED_POLICIES; do\n  aws iam detach-role-policy --role-name \"$ROLE_NAME\" --policy-arn \"$policy_arn\" >/dev/null 2>&1 || true\ndone\naws iam delete-role --role-name \"$ROLE_NAME\" >/dev/null 2>&1 || true\nLB_ARN=$(aws elbv2 describe-load-balancers --region \"$AWS_REGION_VALUE\" --names \"$LB_NAME\" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)\nif [ -n \"$LB_ARN\" ] && [ \"$LB_ARN\" != \"None\" ]; then\n  aws elbv2 delete-load-balancer --region \"$AWS_REGION_VALUE\" --load-balancer-arn \"$LB_ARN\" >/dev/null 2>&1 || true\nfi\naws ecs update-service --region \"$AWS_REGION_VALUE\" --cluster \"$CLUSTER_NAME\" --service \"$SERVICE_NAME\" --desired-count 0 >/dev/null 2>&1 || true\naws ecs delete-service --region \"$AWS_REGION_VALUE\" --cluster \"$CLUSTER_NAME\" --service \"$SERVICE_NAME\" --force >/dev/null 2>&1 || true\naws ecs delete-cluster --region \"$AWS_REGION_VALUE\" --cluster \"$CLUSTER_NAME\" >/dev/null 2>&1 || true\n"
    )
}

fn configure_terraform_backend(
    config: &DeployerConfig,
    terraform_root: &Path,
    deploy_dir: &Path,
) -> Result<()> {
    let providers_path = terraform_root.join("providers.tf");
    if !providers_path.exists() {
        return Ok(());
    }

    let contents = fs::read_to_string(&providers_path)?;
    if !contents.contains("backend \"s3\" {}") {
        return Ok(());
    }

    if let Some(bucket) = std::env::var("GREENTIC_TERRAFORM_BACKEND_BUCKET")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        let region = std::env::var("GREENTIC_TERRAFORM_BACKEND_REGION")
            .ok()
            .or_else(|| std::env::var("AWS_REGION").ok())
            .unwrap_or_else(|| "us-east-1".to_string());
        let key = std::env::var("GREENTIC_TERRAFORM_BACKEND_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                format!(
                    "greentic/{}/{}/{}/terraform.tfstate",
                    config.provider.as_str(),
                    config.tenant,
                    config.environment
                )
            });
        let backend_hcl =
            format!("bucket = \"{bucket}\"\nkey = \"{key}\"\nregion = \"{region}\"\n");
        fs::write(deploy_dir.join("backend.hcl"), backend_hcl)?;
        return Ok(());
    }

    let rewritten = match config.provider {
        crate::config::Provider::Aws => {
            "terraform {\n  required_version = \">= 1.8.0\"\n  backend \"local\" {\n    path = \"terraform.tfstate\"\n  }\n}\n".to_string()
        }
        crate::config::Provider::Azure => {
            "terraform {\n  required_version = \">= 1.8.0\"\n  backend \"local\" {\n    path = \"terraform.tfstate\"\n  }\n\n  required_providers {\n    azurerm = {\n      source = \"hashicorp/azurerm\"\n    }\n  }\n}\n\nprovider \"azurerm\" {\n  features {}\n}\n".to_string()
        }
        crate::config::Provider::Gcp => {
            "terraform {\n  required_version = \">= 1.8.0\"\n  backend \"local\" {\n    path = \"terraform.tfstate\"\n  }\n\n  required_providers {\n    google = {\n      source = \"hashicorp/google\"\n    }\n  }\n}\n\nprovider \"google\" {\n  project = trimspace(var.gcp_project_id) != \"\" ? var.gcp_project_id : \"greentic-placeholder\"\n  region  = trimspace(var.gcp_region) != \"\" ? var.gcp_region : \"us-central1\"\n}\n".to_string()
        }
        _ => contents.replace(
            "backend \"s3\" {}",
            "backend \"local\" {\n    path = \"terraform.tfstate\"\n  }",
        ),
    };
    fs::write(providers_path, rewritten)?;
    Ok(())
}

fn kubectl_script(command: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nK8S_ROOT=\"${{SCRIPT_DIR}}/k8s\"\n{command}\n"
    )
}

fn kubectl_root_script(root_var: &str, command: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n{root_var}=\"${{SCRIPT_DIR}}/{}\"\nkubectl {command}\n",
        root_var.to_ascii_lowercase().trim_end_matches("_root")
    )
}

fn helm_script(command: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nCHART_ROOT=\"${{SCRIPT_DIR}}/helm-chart\"\nhelm {command}\n"
    )
}

fn juju_script(charm_dir: &str, command: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nCHARM_ROOT=\"${{SCRIPT_DIR}}/{charm_dir}\"\njuju {command}\n"
    )
}

fn generic_root_script(root_var: &str, command: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n{root_var}=\"${{SCRIPT_DIR}}/{}\"\n{command}\n",
        root_var.to_ascii_lowercase().trim_end_matches("_root")
    )
}

fn write_executable_script(path: &Path, contents: String) -> Result<()> {
    fs::write(path, contents)?;
    set_executable_if_unix(path)?;
    Ok(())
}

fn set_executable_if_unix(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct RuntimeInvocation {
    capability: String,
    provider: String,
    strategy: String,
    tenant: String,
    environment: String,
    output_dir: String,
    plan_path: String,
    pack_id: String,
    flow_id: String,
    pack_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeployerInvocation {
    capability: String,
    pack_id: String,
    flow_id: String,
    pack_path: String,
    output_dir: String,
    runner_cmd: Vec<String>,
    runner_env: Vec<(String, String)>,
}

struct WrittenDiagnostics {
    invocation: DeployerInvocation,
    handoff_path: PathBuf,
    runner_command_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TerraformRuntimeMetadata {
    terraform_root: String,
    copied_files: Vec<String>,
    scripts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_tfvars: Option<String>,
    init_command: String,
    plan_command: String,
    apply_command: String,
    destroy_command: String,
    status_command: String,
}

fn write_runner_diagnostics(
    config: &DeployerConfig,
    deploy_dir: &Path,
    selection: &DeploymentPackSelection,
    plan_path: &Path,
) -> Result<WrittenDiagnostics> {
    let diag = build_deployer_invocation(config, deploy_dir, selection, plan_path);

    let runner_cmd = diag.runner_cmd.clone();
    let runner_env = diag.runner_env.clone();

    let diag_path = deploy_dir.join("._deployer_invocation.json");
    let diag_file = fs::File::create(&diag_path)?;
    serde_json::to_writer_pretty(diag_file, &diag)?;

    let mut doc = String::from("Runner command:\n");
    doc.push_str(&runner_cmd.join(" "));
    doc.push('\n');
    doc.push_str("Environment:\n");
    for (key, value) in runner_env {
        doc.push_str(&format!("{key}={value}\n"));
    }
    let runner_command_path = deploy_dir.join("._runner_cmd.txt");
    fs::write(&runner_command_path, doc)?;
    Ok(WrittenDiagnostics {
        invocation: diag,
        handoff_path: diag_path,
        runner_command_path,
    })
}

fn build_deployer_invocation(
    config: &DeployerConfig,
    deploy_dir: &Path,
    selection: &DeploymentPackSelection,
    plan_path: &Path,
) -> DeployerInvocation {
    DeployerInvocation {
        capability: selection.dispatch.capability.as_str().to_string(),
        pack_id: selection.dispatch.pack_id.clone(),
        flow_id: selection.dispatch.flow_id.clone(),
        pack_path: selection.pack_path.display().to_string(),
        output_dir: deploy_dir.display().to_string(),
        runner_cmd: vec![
            "greentic-runner".to_string(),
            "--pack".to_string(),
            selection.pack_path.display().to_string(),
            "--flow".to_string(),
            selection.dispatch.flow_id.clone(),
            "--plan".to_string(),
            plan_path.display().to_string(),
            "--output".to_string(),
            deploy_dir.display().to_string(),
        ],
        runner_env: vec![
            (
                "GREENTIC_PROVIDER".to_string(),
                config.provider.as_str().to_string(),
            ),
            ("GREENTIC_STRATEGY".to_string(), config.strategy.clone()),
            ("GREENTIC_TENANT".to_string(), config.tenant.clone()),
            (
                "GREENTIC_ENVIRONMENT".to_string(),
                config.environment.clone(),
            ),
            (
                "GREENTIC_DEPLOYMENT_CAPABILITY".to_string(),
                selection.dispatch.capability.as_str().to_string(),
            ),
            (
                "GREENTIC_DEPLOYMENT_PACK_ID".to_string(),
                selection.dispatch.pack_id.clone(),
            ),
            (
                "GREENTIC_DEPLOYMENT_FLOW_ID".to_string(),
                selection.dispatch.flow_id.clone(),
            ),
        ],
    }
}

fn stage_span(stage: &str, config: &DeployerConfig) -> tracing::Span {
    let span = info_span!(
        "deployment",
        stage,
        tenant = %config.tenant,
        environment = %config.environment,
        provider = %config.provider.as_str()
    );
    span.record("greentic.deployer.provider", config.provider.as_str());
    span.record("greentic.deployer.tenant", config.tenant.as_str());
    span.record("greentic.deployer.environment", config.environment.as_str());
    span
}

fn install_telemetry_context(stage: &str, config: &DeployerConfig) {
    let session = format!("{stage}/{env}", stage = stage, env = config.environment);
    let ctx = TelemetryCtx::new(config.tenant.clone())
        .with_provider(config.provider.as_str())
        .with_session(session);
    set_current_telemetry_ctx(ctx);
}

fn render_plan_output(config: &DeployerConfig, plan: &PlanContext) -> Result<Option<String>> {
    match config.output {
        OutputFormat::Text => {
            let rendered = render_component_summary(plan);
            print!("{rendered}");
            Ok(Some(rendered))
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(plan)
                .map_err(|err| DeployerError::Other(err.to_string()))?;
            println!("{json}");
            Ok(Some(json))
        }
        OutputFormat::Yaml => {
            let yaml =
                serde_yaml::to_string(plan).map_err(|err| DeployerError::Other(err.to_string()))?;
            println!("{yaml}");
            Ok(Some(yaml))
        }
    }
}

fn render_component_summary(plan: &PlanContext) -> String {
    if plan.components.is_empty() {
        return "No component role/profile mappings available.\n".to_string();
    }

    let mut out = format!("Component mappings for target {}:\n", plan.target.as_str());
    for component in &plan.components {
        out.push_str(&format!(
            "- {}: role={} profile={} infra={}",
            component.id,
            component.role.as_str(),
            component.profile.as_str(),
            component.infra.summary
        ));
        out.push('\n');
        if !component.infra.resources.is_empty() {
            out.push_str(&format!(
                "  resources: {}\n",
                component.infra.resources.join(", ")
            ));
        }
        if let Some(inference) = &component.inference {
            if !inference.warnings.is_empty() {
                for warning in &inference.warnings {
                    out.push_str(&format!("  warning: {warning}\n"));
                }
            } else {
                out.push_str(&format!("  info: {}\n", inference.source));
            }
        }
    }
    out
}

fn render_contract_summary(
    config: &DeployerConfig,
    plan: &PlanContext,
    capability_contract: Option<&ResolvedCapabilityContract>,
) -> Result<Option<String>> {
    let rendered = match config.output {
        OutputFormat::Text => {
            let mut text = format!(
                "{} prepared for provider={} strategy={}\n",
                config.capability.as_str(),
                plan.deployment.provider,
                plan.deployment.strategy
            );
            if let Some(contract) = capability_contract {
                text.push_str(&format!("flow_id={}\n", contract.flow_id));
                if let Some(schema) = &contract.input_schema {
                    text.push_str(&format!("input_schema={}\n", schema.path));
                }
                if let Some(schema) = &contract.output_schema {
                    text.push_str(&format!("output_schema={}\n", schema.path));
                }
                if let Some(qa_spec) = &contract.qa_spec {
                    text.push_str(&format!("qa_spec={}\n", qa_spec.path));
                }
            }
            text
        }
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "capability": config.capability.as_str(),
            "provider": plan.deployment.provider,
            "strategy": plan.deployment.strategy,
            "contract": capability_contract,
        }))
        .map_err(|err| DeployerError::Other(err.to_string()))?,
        OutputFormat::Yaml => serde_yaml::to_string(&serde_json::json!({
            "capability": config.capability.as_str(),
            "provider": plan.deployment.provider,
            "strategy": plan.deployment.strategy,
            "contract": capability_contract,
        }))
        .map_err(|err| DeployerError::Other(err.to_string()))?,
    };
    println!("{rendered}");
    Ok(Some(rendered))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeployerConfig, Provider};
    use crate::contract::{
        CapabilitySpecV1, DeployerCapability, DeployerContractV1, PlannerSpecV1,
        set_deployer_contract_v1,
    };
    use crate::deployment::{EXECUTOR_TEST_LOCK, clear_deployment_executor};
    use greentic_types::cbor::encode_pack_manifest;
    use greentic_types::component::{ComponentCapabilities, ComponentManifest, ComponentProfiles};
    use greentic_types::flow::{Flow, FlowHasher, FlowKind, FlowMetadata};
    use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest};
    use greentic_types::{ComponentId, FlowId, PackId};
    use indexmap::IndexMap;
    use semver::Version;
    use std::path::PathBuf;
    use std::str::FromStr;
    use tar::Builder;

    fn config_for(pack_path: PathBuf, capability: DeployerCapability) -> DeployerConfig {
        DeployerConfig {
            capability,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Json,
            greentic: greentic_config::ConfigResolver::new()
                .load()
                .expect("load default config")
                .config,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
        }
    }

    fn write_test_pack(with_contract: bool) -> PathBuf {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let mut manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::from_str("greentic.deploy.aws").unwrap(),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Application,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: vec![ComponentManifest {
                id: ComponentId::from_str("dev.greentic.component").unwrap(),
                version: Version::new(0, 1, 0),
                supports: Vec::new(),
                world: "greentic:test/world".to_string(),
                profiles: ComponentProfiles::default(),
                capabilities: ComponentCapabilities::default(),
                configurators: None,
                operations: Vec::new(),
                config_schema: None,
                resources: Default::default(),
                dev_flows: Default::default(),
            }],
            flows: vec![
                flow_entry("deploy_aws_iac"),
                flow_entry("plan_pack"),
                flow_entry("generate_pack"),
                flow_entry("destroy_pack"),
                flow_entry("status_pack"),
                flow_entry("rollback_pack"),
            ],
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        };
        if with_contract {
            set_deployer_contract_v1(
                &mut manifest,
                DeployerContractV1 {
                    schema_version: 1,
                    planner: PlannerSpecV1 {
                        flow_id: "plan_pack".into(),
                        input_schema_ref: None,
                        output_schema_ref: Some("assets/schemas/plan-output.schema.json".into()),
                        qa_spec_ref: None,
                    },
                    capabilities: vec![
                        CapabilitySpecV1 {
                            capability: DeployerCapability::Plan,
                            flow_id: "plan_pack".into(),
                            input_schema_ref: None,
                            output_schema_ref: Some(
                                "assets/schemas/plan-output.schema.json".into(),
                            ),
                            execution_output_schema_ref: None,
                            qa_spec_ref: None,
                            example_refs: Vec::new(),
                        },
                        CapabilitySpecV1 {
                            capability: DeployerCapability::Generate,
                            flow_id: "generate_pack".into(),
                            input_schema_ref: Some(
                                "assets/schemas/generate-input.schema.json".into(),
                            ),
                            output_schema_ref: Some(
                                "assets/schemas/generate-output.schema.json".into(),
                            ),
                            execution_output_schema_ref: None,
                            qa_spec_ref: Some("assets/qa/generate.qa.json".into()),
                            example_refs: vec!["assets/examples/generate.example.json".into()],
                        },
                        CapabilitySpecV1 {
                            capability: DeployerCapability::Apply,
                            flow_id: "deploy_aws_iac".into(),
                            input_schema_ref: None,
                            output_schema_ref: None,
                            execution_output_schema_ref: Some(
                                "assets/schemas/apply-execution-output.schema.json".into(),
                            ),
                            qa_spec_ref: None,
                            example_refs: Vec::new(),
                        },
                        CapabilitySpecV1 {
                            capability: DeployerCapability::Destroy,
                            flow_id: "destroy_pack".into(),
                            input_schema_ref: None,
                            output_schema_ref: None,
                            execution_output_schema_ref: Some(
                                "assets/schemas/destroy-execution-output.schema.json".into(),
                            ),
                            qa_spec_ref: None,
                            example_refs: Vec::new(),
                        },
                        CapabilitySpecV1 {
                            capability: DeployerCapability::Status,
                            flow_id: "status_pack".into(),
                            input_schema_ref: None,
                            output_schema_ref: Some(
                                "assets/schemas/status-output.schema.json".into(),
                            ),
                            execution_output_schema_ref: Some(
                                "assets/schemas/status-execution-output.schema.json".into(),
                            ),
                            qa_spec_ref: None,
                            example_refs: Vec::new(),
                        },
                        CapabilitySpecV1 {
                            capability: DeployerCapability::Rollback,
                            flow_id: "rollback_pack".into(),
                            input_schema_ref: None,
                            output_schema_ref: Some(
                                "assets/schemas/rollback-output.schema.json".into(),
                            ),
                            execution_output_schema_ref: None,
                            qa_spec_ref: None,
                            example_refs: Vec::new(),
                        },
                    ],
                },
            )
            .unwrap();
        }
        let encoded = encode_pack_manifest(&manifest).expect("encode manifest");
        let mut builder = Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(encoded.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.cbor", encoded.as_slice())
            .expect("append manifest");
        if with_contract {
            append_tar_entry(
                &mut builder,
                "assets/schemas/plan-output.schema.json",
                br#"{"type":"object","required":["kind","plan"],"properties":{"kind":{"const":"plan"},"plan":{"type":"object"}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/generate-input.schema.json",
                br#"{"type":"object","properties":{"provider":{"type":"string"}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/generate-output.schema.json",
                br#"{"type":"object","required":["kind","capability","provider","strategy","input_schema_path","output_schema_path","qa_spec_path","example_paths"],"properties":{"kind":{"const":"generate"},"capability":{"const":"generate"},"provider":{"type":"string"},"strategy":{"type":"string"},"input_schema_path":{"const":"assets/schemas/generate-input.schema.json"},"output_schema_path":{"const":"assets/schemas/generate-output.schema.json"},"qa_spec_path":{"const":"assets/qa/generate.qa.json"},"example_paths":{"type":"array","items":{"type":"string"},"contains":{"const":"assets/examples/generate.example.json"}}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/qa/generate.qa.json",
                br#"{"questions":[{"id":"provider","kind":"select"}]}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/examples/generate.example.json",
                br#"{"provider":"aws","strategy":"iac-only"}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/examples/rendered-manifests.yaml",
                br#"apiVersion: v1
kind: Namespace
metadata:
  name: greentic
"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/apply-execution-output.schema.json",
                br#"{"type":"object","required":["kind","deployment_id","state","endpoints"],"properties":{"kind":{"const":"apply"},"deployment_id":{"type":"string"},"state":{"type":"string"},"provider":{"type":"string"},"strategy":{"type":"string"},"endpoints":{"type":"array","items":{"type":"string"}},"output_refs":{"type":"object","additionalProperties":{"type":"string"}}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/destroy-execution-output.schema.json",
                br#"{"type":"object","required":["kind","deployment_id","state"],"properties":{"kind":{"const":"destroy"},"deployment_id":{"type":"string"},"state":{"type":"string"}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/status-output.schema.json",
                br#"{"type":"object","required":["kind","capability","provider","strategy","pack_id","flow_id"],"properties":{"kind":{"const":"status"},"capability":{"const":"status"},"provider":{"type":"string"},"strategy":{"type":"string"},"pack_id":{"type":"string"},"flow_id":{"type":"string"}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/status-execution-output.schema.json",
                br#"{"type":"object","required":["kind","deployment_id","state","health_checks"],"properties":{"kind":{"const":"status"},"deployment_id":{"type":"string"},"state":{"type":"string"},"provider":{"type":"string"},"strategy":{"type":"string"},"status_source":{"type":"string"},"endpoints":{"type":"array","items":{"type":"string"}},"health_checks":{"type":"array","items":{"type":"string"}},"output_refs":{"type":"object","additionalProperties":{"type":"string"}}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/rollback-output.schema.json",
                br#"{"type":"object","required":["kind","capability","provider","strategy","pack_id","flow_id","target_capability"],"properties":{"kind":{"const":"rollback"},"capability":{"const":"rollback"},"provider":{"type":"string"},"strategy":{"type":"string"},"pack_id":{"type":"string"},"flow_id":{"type":"string"},"target_capability":{"const":"apply"}}}"#,
            );
            append_tar_entry(&mut builder, "terraform/main.tf", br#"module "root" {}"#);
            append_tar_entry(
                &mut builder,
                "terraform/staging.tfvars.example",
                br#"dns_name = "acme.example.test""#,
            );
            append_tar_entry(
                &mut builder,
                "terraform/modules/operator/main.tf",
                br#"module "operator" {}"#,
            );
            append_tar_entry(
                &mut builder,
                "terraform/terraform",
                br#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> terraform-invocation.args
if [ "${1:-}" = "output" ] && [ "${2:-}" = "-json" ]; then
cat <<'EOF'
{"operator_endpoint":{"value":"http://terraform-output.example.test"}}
EOF
fi
"#,
            );
            append_tar_entry(
                &mut builder,
                "chart/Chart.yaml",
                br#"apiVersion: v2
name: greentic
version: 0.1.0
"#,
            );
            append_tar_entry(
                &mut builder,
                "chart/values.yaml",
                br#"image:
  repository: ghcr.io/greentic-ai/operator-distroless
"#,
            );
            append_tar_entry(
                &mut builder,
                "chart/templates/deployment.yaml",
                br#"apiVersion: apps/v1
kind: Deployment
"#,
            );
        }
        let bytes = builder.into_inner().expect("tar bytes");
        let path = dir.path().join("sample.gtpack");
        std::fs::write(&path, bytes).expect("write pack");
        let _persisted = dir.keep();
        path
    }

    fn flow_entry(id: &str) -> PackFlowEntry {
        PackFlowEntry {
            id: FlowId::from_str(id).unwrap(),
            kind: FlowKind::Messaging,
            flow: Flow {
                schema_version: "flowir-v1".to_string(),
                id: FlowId::from_str(id).unwrap(),
                kind: FlowKind::Messaging,
                entrypoints: Default::default(),
                nodes: IndexMap::<_, _, FlowHasher>::default(),
                metadata: FlowMetadata::default(),
            },
            tags: Vec::new(),
            entrypoints: Vec::new(),
        }
    }

    fn append_tar_entry(builder: &mut Builder<Vec<u8>>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .expect("append tar entry");
    }

    #[test]
    fn collect_output_files_returns_sorted_files_only() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        std::fs::write(dir.path().join("b.txt"), "b").expect("write b");
        std::fs::write(dir.path().join("a.txt"), "a").expect("write a");
        std::fs::create_dir(dir.path().join("nested")).expect("create nested dir");

        let files = collect_output_files(dir.path());
        assert_eq!(files, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn build_execution_report_merges_executor_payload() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");

        let deploy_dir = dir.path().join("deploy");
        std::fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        std::fs::write(deploy_dir.join("local.json"), "{}").expect("write local file");
        let plan_path = dir.path().join("plan.json");
        let invoke_path = dir.path().join("invoke.json");
        let handoff_path = deploy_dir.join("._deployer_invocation.json");
        let runner_command_path = deploy_dir.join("._runner_cmd.txt");
        std::fs::write(&plan_path, "{}").expect("write plan");
        std::fs::write(&invoke_path, "{}").expect("write invoke");
        std::fs::write(&handoff_path, "{}").expect("write handoff");
        std::fs::write(&runner_command_path, "cmd").expect("write runner cmd");

        let runtime_artifacts = RuntimeArtifacts {
            deploy_dir: deploy_dir.clone(),
            plan: plan_path,
            invoke: invoke_path,
            handoff: DeployerInvocation {
                capability: "apply".into(),
                pack_id: "greentic.deploy.aws".into(),
                flow_id: "deploy_aws_iac".into(),
                pack_path: "/tmp/sample.gtpack".into(),
                output_dir: deploy_dir.display().to_string(),
                runner_cmd: vec!["greentic-runner".into()],
                runner_env: vec![("GREENTIC_DEPLOYMENT_CAPABILITY".into(), "apply".into())],
            },
            handoff_path,
            runner_command_path,
        };
        let capability_contract = ResolvedCapabilityContract {
            capability: DeployerCapability::Apply,
            flow_id: "deploy_aws_iac".into(),
            input_schema: None,
            output_schema: None,
            execution_output_schema: Some(crate::contract::ContractAsset {
                path: "assets/schemas/apply-execution-output.schema.json".into(),
                json: Some(serde_json::json!({
                    "type": "object",
                    "required": ["kind", "deployment_id", "state", "endpoints"],
                    "properties": {
                        "kind": { "const": "apply" },
                        "deployment_id": { "type": "string" },
                        "state": { "type": "string" },
                        "provider": { "type": "string" },
                        "strategy": { "type": "string" },
                        "endpoints": { "type": "array", "items": { "type": "string" } },
                        "output_refs": {
                            "type": "object",
                            "additionalProperties": { "type": "string" }
                        }
                    }
                })),
                text: None,
                size_bytes: 0,
            }),
            qa_spec: None,
            examples: Vec::new(),
        };

        let report = build_execution_report(
            &runtime_artifacts,
            Some(&capability_contract),
            Some(ExecutionOutcome {
                status: Some("applied".into()),
                message: Some("ok".into()),
                output_files: vec!["remote.json".into()],
                payload: Some(ExecutionOutcomePayload::Apply(
                    crate::deployment::ApplyExecutionOutcome {
                        deployment_id: "dep-42".into(),
                        state: "ready".into(),
                        provider: Some("aws".into()),
                        strategy: Some("iac-only".into()),
                        endpoints: vec!["https://ready.example.test".into()],
                        output_refs: BTreeMap::new(),
                    },
                )),
            }),
        );

        assert_eq!(report.status.as_deref(), Some("applied"));
        assert_eq!(report.message.as_deref(), Some("ok"));
        assert_eq!(
            report.output_files,
            vec![
                "._deployer_invocation.json".to_string(),
                "._runner_cmd.txt".to_string(),
                "local.json".to_string(),
                "remote.json".to_string()
            ]
        );
        match report.outcome_payload.expect("outcome payload") {
            ExecutionOutcomePayload::Apply(payload) => {
                assert_eq!(payload.deployment_id, "dep-42");
                assert_eq!(payload.state, "ready");
            }
            other => panic!("unexpected outcome payload: {:?}", other),
        }
        assert!(
            report
                .outcome_validation
                .as_ref()
                .expect("validation")
                .valid
        );
    }

    #[test]
    fn build_execution_report_validates_destroy_outcome_payload() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");

        let deploy_dir = dir.path().join("deploy");
        std::fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        let runtime_artifacts = RuntimeArtifacts {
            deploy_dir: deploy_dir.clone(),
            plan: dir.path().join("plan.json"),
            invoke: dir.path().join("invoke.json"),
            handoff: DeployerInvocation {
                capability: "destroy".into(),
                pack_id: "greentic.deploy.aws".into(),
                flow_id: "destroy_pack".into(),
                pack_path: "/tmp/sample.gtpack".into(),
                output_dir: deploy_dir.display().to_string(),
                runner_cmd: vec!["greentic-runner".into()],
                runner_env: vec![("GREENTIC_DEPLOYMENT_CAPABILITY".into(), "destroy".into())],
            },
            handoff_path: deploy_dir.join("._deployer_invocation.json"),
            runner_command_path: deploy_dir.join("._runner_cmd.txt"),
        };
        let capability_contract = ResolvedCapabilityContract {
            capability: DeployerCapability::Destroy,
            flow_id: "destroy_pack".into(),
            input_schema: None,
            output_schema: None,
            execution_output_schema: Some(crate::contract::ContractAsset {
                path: "assets/schemas/destroy-execution-output.schema.json".into(),
                json: Some(serde_json::json!({
                    "type": "object",
                    "required": ["kind", "deployment_id", "state", "destroyed_resources"],
                    "properties": {
                        "kind": { "const": "destroy" },
                        "deployment_id": { "type": "string" },
                        "state": { "type": "string" },
                        "destroyed_resources": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    }
                })),
                text: None,
                size_bytes: 0,
            }),
            qa_spec: None,
            examples: Vec::new(),
        };

        let report = build_execution_report(
            &runtime_artifacts,
            Some(&capability_contract),
            Some(ExecutionOutcome {
                status: Some("destroyed".into()),
                message: None,
                output_files: Vec::new(),
                payload: Some(ExecutionOutcomePayload::Destroy(
                    crate::deployment::DestroyExecutionOutcome {
                        deployment_id: "dep-42".into(),
                        state: "deleted".into(),
                        destroyed_resources: Vec::new(),
                    },
                )),
            }),
        );

        assert!(
            report
                .outcome_validation
                .as_ref()
                .expect("validation")
                .valid
        );
    }

    #[test]
    fn build_execution_report_validates_status_outcome_payload() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");

        let deploy_dir = dir.path().join("deploy");
        std::fs::create_dir_all(&deploy_dir).expect("create deploy dir");
        let runtime_artifacts = RuntimeArtifacts {
            deploy_dir: deploy_dir.clone(),
            plan: dir.path().join("plan.json"),
            invoke: dir.path().join("invoke.json"),
            handoff: DeployerInvocation {
                capability: "status".into(),
                pack_id: "greentic.deploy.aws".into(),
                flow_id: "status_pack".into(),
                pack_path: "/tmp/sample.gtpack".into(),
                output_dir: deploy_dir.display().to_string(),
                runner_cmd: vec!["greentic-runner".into()],
                runner_env: vec![("GREENTIC_DEPLOYMENT_CAPABILITY".into(), "status".into())],
            },
            handoff_path: deploy_dir.join("._deployer_invocation.json"),
            runner_command_path: deploy_dir.join("._runner_cmd.txt"),
        };
        let capability_contract = ResolvedCapabilityContract {
            capability: DeployerCapability::Status,
            flow_id: "status_pack".into(),
            input_schema: None,
            output_schema: Some(crate::contract::ContractAsset {
                path: "assets/schemas/status-output.schema.json".into(),
                json: None,
                text: None,
                size_bytes: 0,
            }),
            execution_output_schema: Some(crate::contract::ContractAsset {
                path: "assets/schemas/status-execution-output.schema.json".into(),
                json: Some(serde_json::json!({
                    "type": "object",
                    "required": ["kind", "deployment_id", "state", "health_checks"],
                    "properties": {
                        "kind": { "const": "status" },
                        "deployment_id": { "type": "string" },
                        "state": { "type": "string" },
                        "provider": { "type": "string" },
                        "strategy": { "type": "string" },
                        "status_source": { "type": "string" },
                        "endpoints": { "type": "array", "items": { "type": "string" } },
                        "health_checks": { "type": "array", "items": { "type": "string" } },
                        "output_refs": {
                            "type": "object",
                            "additionalProperties": { "type": "string" }
                        }
                    }
                })),
                text: None,
                size_bytes: 0,
            }),
            qa_spec: None,
            examples: Vec::new(),
        };

        let report = build_execution_report(
            &runtime_artifacts,
            Some(&capability_contract),
            Some(ExecutionOutcome {
                status: Some("ready".into()),
                message: None,
                output_files: Vec::new(),
                payload: Some(ExecutionOutcomePayload::Status(
                    crate::deployment::StatusExecutionOutcome {
                        deployment_id: "dep-42".into(),
                        state: "healthy".into(),
                        provider: Some("aws".into()),
                        strategy: Some("iac-only".into()),
                        status_source: Some("terraform_handoff".into()),
                        endpoints: vec!["https://ready.example.test".into()],
                        health_checks: vec!["http:ok".into()],
                        output_refs: BTreeMap::new(),
                    },
                )),
            }),
        );

        assert!(
            report
                .outcome_validation
                .as_ref()
                .expect("validation")
                .valid
        );
    }

    #[tokio::test]
    async fn plan_result_contains_typed_payload() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(true);
        let result = run(config_for(pack_path, DeployerCapability::Plan))
            .await
            .expect("plan runs");
        match result.payload.expect("payload") {
            OperationPayload::Plan(payload) => {
                assert_eq!(payload.plan.plan.tenant, "acme");
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert!(result.output_validation.as_ref().expect("validation").valid);
    }

    #[tokio::test]
    async fn terraform_status_synthesizes_local_execution_outcome() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let pack_path = write_test_pack(true);

        let mut greentic = greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config;
        greentic.paths.state_dir = dir.path().join(".greentic-state");

        let result = run(DeployerConfig {
            capability: DeployerCapability::Status,
            provider: Provider::Generic,
            strategy: "terraform".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Text,
            greentic,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
        })
        .await
        .expect("terraform status runs");

        assert!(result.executed);
        assert_eq!(result.capability, "status");
        let execution = result.execution.expect("execution report");
        assert_eq!(execution.status.as_deref(), Some("handoff_ready"));
        match execution.outcome_payload.expect("outcome payload") {
            ExecutionOutcomePayload::Status(payload) => {
                assert_eq!(payload.state, "handoff_ready");
                assert!(
                    payload
                        .health_checks
                        .iter()
                        .any(|entry| entry == "terraform_root:present")
                );
                assert!(
                    payload
                        .health_checks
                        .iter()
                        .any(|entry| entry == "script:terraform-status.sh:present")
                );
            }
            other => panic!("unexpected outcome payload: {:?}", other),
        }
    }

    #[tokio::test]
    async fn terraform_apply_execute_runs_local_script_via_fake_terraform() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(&base).expect("temp dir");
        let pack_path = write_test_pack(true);
        let mut greentic = greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config;
        greentic.paths.state_dir = dir.path().join(".greentic-state");

        let result = run(DeployerConfig {
            capability: DeployerCapability::Apply,
            provider: Provider::Generic,
            strategy: "terraform".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: true,
            output: crate::config::OutputFormat::Text,
            greentic,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: Some("file:///tmp/apply-test.gtbundle".into()),
            bundle_digest: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
            repo_registry_base: None,
            store_registry_base: None,
        })
        .await
        .expect("terraform apply runs");
        assert!(result.executed);
        let execution = result.execution.expect("execution report");
        assert_eq!(execution.status.as_deref(), Some("applied"));
        match execution.outcome_payload.expect("outcome payload") {
            ExecutionOutcomePayload::Apply(payload) => {
                assert_eq!(
                    payload.endpoints,
                    vec!["http://terraform-output.example.test"]
                );
            }
            other => panic!("unexpected outcome payload: {:?}", other),
        }
        assert!(
            execution
                .output_files
                .iter()
                .any(|entry| entry == "terraform-apply.stdout.log")
        );
        let applied_args = std::fs::read_to_string(
            Path::new(&result.output_dir)
                .join("terraform")
                .join("terraform-invocation.args"),
        )
        .expect("read fake terraform args");
        assert!(applied_args.contains("apply -auto-approve -input=false"));
        assert!(applied_args.contains("-var-file=staging.tfvars"));
        assert!(applied_args.contains("output -json"));
    }

    #[test]
    fn parse_dns_name_endpoint_extracts_https_endpoint() {
        let endpoint = parse_dns_name_endpoint(
            r#"
            dns_name = "acme.example.test"
            "#,
        );
        assert_eq!(endpoint.as_deref(), Some("https://acme.example.test"));
    }

    #[test]
    fn persist_runtime_artifacts_materializes_terraform_handoff_assets() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let pack_path = write_test_pack(true);

        let mut greentic = greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config;
        greentic.paths.state_dir = dir.path().join(".greentic-state");

        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Generic,
            strategy: "terraform".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path.clone()),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Json,
            greentic,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: Some("file:///tmp/demo.gtbundle".into()),
            bundle_digest: Some(
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".into(),
            ),
            repo_registry_base: None,
            store_registry_base: None,
        };
        let plan = pack_introspect::build_plan(&config).expect("build plan");
        let deploy_dir = dir.path().join("output");
        std::fs::create_dir_all(&deploy_dir).expect("create output dir");
        let selection = DeploymentPackSelection {
            dispatch: crate::deployment::DeploymentDispatch {
                capability: DeployerCapability::Plan,
                pack_id: "greentic.deploy.terraform".into(),
                flow_id: "plan_terraform".into(),
            },
            pack_path,
            manifest: PackManifest {
                schema_version: "pack-v1".to_string(),
                pack_id: PackId::from_str("greentic.deploy.terraform").unwrap(),
                name: None,
                version: Version::new(0, 1, 0),
                kind: PackKind::Application,
                publisher: "greentic".to_string(),
                secret_requirements: Vec::new(),
                components: Vec::new(),
                flows: Vec::new(),
                dependencies: Vec::new(),
                capabilities: Vec::new(),
                signatures: Default::default(),
                bootstrap: None,
                extensions: None,
            },
            origin: "test".into(),
            candidates: Vec::new(),
        };

        let artifacts = persist_runtime_artifacts(&config, &plan, &selection, &deploy_dir)
            .expect("persist runtime artifacts");

        assert!(artifacts.deploy_dir.join("terraform/main.tf").exists());
        assert!(
            artifacts
                .deploy_dir
                .join("terraform/modules/operator/main.tf")
                .exists()
        );
        assert!(artifacts.deploy_dir.join("terraform-init.sh").exists());
        assert!(artifacts.deploy_dir.join("terraform-plan.sh").exists());
        assert!(artifacts.deploy_dir.join("terraform-apply.sh").exists());
        assert!(artifacts.deploy_dir.join("terraform-destroy.sh").exists());
        assert!(artifacts.deploy_dir.join("terraform-status.sh").exists());
        let metadata: TerraformRuntimeMetadata = serde_json::from_slice(
            &std::fs::read(artifacts.deploy_dir.join("terraform-runtime.json"))
                .expect("read terraform runtime metadata"),
        )
        .expect("parse terraform runtime metadata");
        assert_eq!(
            metadata.scripts,
            vec![
                "terraform-init.sh".to_string(),
                "terraform-plan.sh".to_string(),
                "terraform-apply.sh".to_string(),
                "terraform-destroy.sh".to_string(),
                "terraform-status.sh".to_string()
            ]
        );
        assert_eq!(metadata.generated_tfvars.as_deref(), Some("staging.tfvars"));
        assert_eq!(metadata.status_command, "./terraform-status.sh");
        let note = std::fs::read_to_string(artifacts.deploy_dir.join("terraform-handoff.txt"))
            .expect("read terraform handoff note");
        assert!(note.contains("terraform_root="));
        assert!(note.contains("generated_tfvars="));
        assert!(note.contains("copied_files:"));
        assert!(note.contains("modules/operator/main.tf"));
        assert!(note.contains("status_command=./terraform-status.sh"));
    }

    #[test]
    fn persist_runtime_artifacts_materializes_aws_cleanup_helper_for_aws() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let pack_path = write_test_pack(true);

        let mut greentic = greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config;
        greentic.paths.state_dir = dir.path().join(".greentic-state");

        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path.clone()),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Json,
            greentic,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: Some("file:///tmp/demo.gtbundle".into()),
            bundle_digest: Some(
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".into(),
            ),
            repo_registry_base: None,
            store_registry_base: None,
        };
        let plan = pack_introspect::build_plan(&config).expect("build plan");
        let deploy_dir = dir.path().join("output");
        std::fs::create_dir_all(&deploy_dir).expect("create output dir");
        let selection = DeploymentPackSelection {
            dispatch: crate::deployment::DeploymentDispatch {
                capability: DeployerCapability::Plan,
                pack_id: "greentic.deploy.terraform".into(),
                flow_id: "plan_terraform".into(),
            },
            pack_path,
            manifest: PackManifest {
                schema_version: "pack-v1".to_string(),
                pack_id: PackId::from_str("greentic.deploy.terraform").unwrap(),
                name: None,
                version: Version::new(0, 1, 0),
                kind: PackKind::Application,
                publisher: "greentic".to_string(),
                secret_requirements: Vec::new(),
                components: Vec::new(),
                flows: Vec::new(),
                dependencies: Vec::new(),
                capabilities: Vec::new(),
                signatures: Default::default(),
                bootstrap: None,
                extensions: None,
            },
            origin: "test".into(),
            candidates: Vec::new(),
        };

        let artifacts = persist_runtime_artifacts(&config, &plan, &selection, &deploy_dir)
            .expect("persist runtime artifacts");
        assert!(
            artifacts
                .deploy_dir
                .join("terraform-aws-cleanup.sh")
                .exists()
        );

        let metadata: TerraformRuntimeMetadata = serde_json::from_slice(
            &std::fs::read(artifacts.deploy_dir.join("terraform-runtime.json"))
                .expect("read terraform runtime metadata"),
        )
        .expect("parse terraform runtime metadata");
        assert!(
            metadata
                .scripts
                .iter()
                .any(|entry| entry == "terraform-aws-cleanup.sh")
        );

        let cleanup =
            std::fs::read_to_string(artifacts.deploy_dir.join("terraform-aws-cleanup.sh"))
                .expect("read aws cleanup script");
        assert!(cleanup.contains("bundle_digest not found; skipping AWS cleanup fallback"));
        assert!(cleanup.contains("aws secretsmanager delete-secret"));
        assert!(cleanup.contains("aws iam delete-role"));
        assert!(cleanup.contains("aws ecs delete-service"));
    }

    #[test]
    fn persist_runtime_artifacts_falls_back_to_available_tfvars_example() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let pack_path = write_test_pack(true);

        let mut greentic = greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config;
        greentic.paths.state_dir = dir.path().join(".greentic-state");

        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Generic,
            strategy: "terraform".into(),
            tenant: "acme".into(),
            environment: "dev".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path.clone()),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Json,
            greentic,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: Some("file:///tmp/demo.gtbundle".into()),
            bundle_digest: Some(
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".into(),
            ),
            repo_registry_base: None,
            store_registry_base: None,
        };
        let plan = pack_introspect::build_plan(&config).expect("build plan");
        let deploy_dir = dir.path().join("output");
        std::fs::create_dir_all(&deploy_dir).expect("create output dir");
        let selection = DeploymentPackSelection {
            dispatch: crate::deployment::DeploymentDispatch {
                capability: DeployerCapability::Plan,
                pack_id: "greentic.deploy.terraform".into(),
                flow_id: "plan_terraform".into(),
            },
            pack_path,
            manifest: PackManifest {
                schema_version: "pack-v1".to_string(),
                pack_id: PackId::from_str("greentic.deploy.terraform").unwrap(),
                name: None,
                version: Version::new(0, 1, 0),
                kind: PackKind::Application,
                publisher: "greentic".to_string(),
                secret_requirements: Vec::new(),
                components: Vec::new(),
                flows: Vec::new(),
                dependencies: Vec::new(),
                capabilities: Vec::new(),
                signatures: Default::default(),
                bootstrap: None,
                extensions: None,
            },
            origin: "test".into(),
            candidates: Vec::new(),
        };

        let artifacts = persist_runtime_artifacts(&config, &plan, &selection, &deploy_dir)
            .expect("persist runtime artifacts");
        let metadata: TerraformRuntimeMetadata = serde_json::from_slice(
            &std::fs::read(artifacts.deploy_dir.join("terraform-runtime.json"))
                .expect("read terraform runtime metadata"),
        )
        .expect("parse terraform runtime metadata");
        assert_eq!(metadata.generated_tfvars.as_deref(), Some("dev.tfvars"));

        let generated = std::fs::read_to_string(artifacts.deploy_dir.join("terraform/dev.tfvars"))
            .expect("read generated tfvars");
        assert!(generated.contains("bundle_source = \"file:///tmp/demo.gtbundle\""));
        assert!(generated.contains(
            "bundle_digest = \"sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\""
        ));

        let destroy_script =
            std::fs::read_to_string(artifacts.deploy_dir.join("terraform-destroy.sh"))
                .expect("read destroy script");
        assert!(destroy_script.contains("VAR_FILE=\"dev.tfvars\""));
        assert!(destroy_script.contains("elif [ -f \"staging.tfvars.example\" ]; then"));
    }

    #[test]
    fn render_operation_result_text_includes_terraform_runtime_summary() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let output_dir = dir.path().join("deploy");
        std::fs::create_dir_all(&output_dir).expect("create output dir");
        std::fs::write(
            output_dir.join("terraform-runtime.json"),
            serde_json::to_vec_pretty(&TerraformRuntimeMetadata {
                terraform_root: output_dir.join("terraform").display().to_string(),
                copied_files: vec!["main.tf".into(), "modules/operator/main.tf".into()],
                scripts: vec!["terraform-status.sh".into()],
                generated_tfvars: None,
                init_command: "./terraform-init.sh".into(),
                plan_command: "./terraform-plan.sh".into(),
                apply_command: "./terraform-apply.sh".into(),
                destroy_command: "./terraform-destroy.sh".into(),
                status_command: "./terraform-status.sh".into(),
            })
            .expect("encode terraform runtime metadata"),
        )
        .expect("write runtime metadata");

        let rendered = render_operation_result_text(&OperationResult {
            capability: "status".into(),
            executed: false,
            preview: false,
            output_dir: output_dir.display().to_string(),
            plan_path: "/tmp/plan.json".into(),
            invoke_path: "/tmp/invoke.json".into(),
            pack_id: "greentic.deploy.terraform".into(),
            flow_id: "status_terraform".into(),
            pack_path: "/tmp/provider.gtpack".into(),
            contract: None,
            capability_contract: None,
            payload: Some(OperationPayload::Status(Box::new(StatusPayload {
                capability: "status".into(),
                provider: "generic".into(),
                strategy: "terraform".into(),
                pack_id: "greentic.deploy.terraform".into(),
                flow_id: "status_terraform".into(),
                rendered_output: None,
            }))),
            output_validation: None,
            execution: None,
        });

        assert!(rendered.contains("terraform_runtime.present=true"));
        assert!(
            rendered.contains("terraform_runtime.copied_files=main.tf, modules/operator/main.tf")
        );
        assert!(rendered.contains("terraform_runtime.status_command=./terraform-status.sh"));
    }

    #[test]
    fn persist_runtime_artifacts_materializes_k8s_raw_handoff_assets() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let pack_path = write_test_pack(true);

        let mut greentic = greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config;
        greentic.paths.state_dir = dir.path().join(".greentic-state");

        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::K8s,
            strategy: "raw-manifests".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path.clone()),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Json,
            greentic,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
        };
        let plan = pack_introspect::build_plan(&config).expect("build plan");
        let deploy_dir = dir.path().join("output");
        std::fs::create_dir_all(&deploy_dir).expect("create output dir");
        let selection = DeploymentPackSelection {
            dispatch: crate::deployment::DeploymentDispatch {
                capability: DeployerCapability::Plan,
                pack_id: "greentic.deploy.k8s".into(),
                flow_id: "plan_k8s_raw".into(),
            },
            pack_path,
            manifest: PackManifest {
                schema_version: "pack-v1".to_string(),
                pack_id: PackId::from_str("greentic.deploy.k8s").unwrap(),
                name: None,
                version: Version::new(0, 1, 0),
                kind: PackKind::Application,
                publisher: "greentic".to_string(),
                secret_requirements: Vec::new(),
                components: Vec::new(),
                flows: Vec::new(),
                dependencies: Vec::new(),
                capabilities: Vec::new(),
                signatures: Default::default(),
                bootstrap: None,
                extensions: None,
            },
            origin: "test".into(),
            candidates: Vec::new(),
        };

        let artifacts = persist_runtime_artifacts(&config, &plan, &selection, &deploy_dir)
            .expect("persist runtime artifacts");

        assert!(
            artifacts
                .deploy_dir
                .join("k8s/rendered-manifests.yaml")
                .exists()
        );
        assert!(artifacts.deploy_dir.join("kubectl-apply.sh").exists());
        assert!(artifacts.deploy_dir.join("kubectl-delete.sh").exists());
        assert!(artifacts.deploy_dir.join("kubectl-status.sh").exists());
        let note = std::fs::read_to_string(artifacts.deploy_dir.join("k8s-handoff.txt"))
            .expect("read k8s handoff note");
        assert!(note.contains("manifest_path="));
        assert!(note.contains("kubectl-apply.sh"));
    }

    #[test]
    fn persist_runtime_artifacts_materializes_helm_handoff_assets() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let pack_path = write_test_pack(true);

        let mut greentic = greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config;
        greentic.paths.state_dir = dir.path().join(".greentic-state");

        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::K8s,
            strategy: "helm".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path: pack_path.clone(),
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: Some(pack_path.clone()),
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Json,
            greentic,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
        };
        let plan = pack_introspect::build_plan(&config).expect("build plan");
        let deploy_dir = dir.path().join("output");
        std::fs::create_dir_all(&deploy_dir).expect("create output dir");
        let selection = DeploymentPackSelection {
            dispatch: crate::deployment::DeploymentDispatch {
                capability: DeployerCapability::Plan,
                pack_id: "greentic.deploy.helm".into(),
                flow_id: "plan_helm".into(),
            },
            pack_path,
            manifest: PackManifest {
                schema_version: "pack-v1".to_string(),
                pack_id: PackId::from_str("greentic.deploy.helm").unwrap(),
                name: None,
                version: Version::new(0, 1, 0),
                kind: PackKind::Application,
                publisher: "greentic".to_string(),
                secret_requirements: Vec::new(),
                components: Vec::new(),
                flows: Vec::new(),
                dependencies: Vec::new(),
                capabilities: Vec::new(),
                signatures: Default::default(),
                bootstrap: None,
                extensions: None,
            },
            origin: "test".into(),
            candidates: Vec::new(),
        };

        let artifacts = persist_runtime_artifacts(&config, &plan, &selection, &deploy_dir)
            .expect("persist runtime artifacts");

        assert!(artifacts.deploy_dir.join("helm-chart/Chart.yaml").exists());
        assert!(
            artifacts
                .deploy_dir
                .join("helm-chart/templates/deployment.yaml")
                .exists()
        );
        assert!(artifacts.deploy_dir.join("helm-upgrade.sh").exists());
        assert!(artifacts.deploy_dir.join("helm-rollback.sh").exists());
        assert!(artifacts.deploy_dir.join("helm-status.sh").exists());
        let note = std::fs::read_to_string(artifacts.deploy_dir.join("helm-handoff.txt"))
            .expect("read helm handoff note");
        assert!(note.contains("chart_root="));
        assert!(note.contains("release_name=greentic-acme"));
    }

    #[tokio::test]
    async fn plan_result_without_contract_schema_skips_validation() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(false);
        let result = run(config_for(pack_path, DeployerCapability::Plan))
            .await
            .expect("plan runs");
        assert!(result.output_validation.is_none());
    }

    #[tokio::test]
    async fn generate_result_contains_capability_payload() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(true);
        let result = run(config_for(pack_path, DeployerCapability::Generate))
            .await
            .expect("generate prepares");
        match result.payload.expect("payload") {
            OperationPayload::Generate(payload) => {
                assert_eq!(payload.capability, "generate");
                assert_eq!(payload.provider, "aws");
                assert_eq!(
                    payload.input_schema_path.as_deref(),
                    Some("assets/schemas/generate-input.schema.json")
                );
                assert_eq!(
                    payload.output_schema_path.as_deref(),
                    Some("assets/schemas/generate-output.schema.json")
                );
                assert_eq!(
                    payload.qa_spec_path.as_deref(),
                    Some("assets/qa/generate.qa.json")
                );
                assert_eq!(
                    payload.example_paths,
                    vec!["assets/examples/generate.example.json".to_string()]
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert_eq!(
            result
                .capability_contract
                .as_ref()
                .expect("capability contract")
                .flow_id,
            "generate_pack"
        );
        assert!(result.output_validation.as_ref().expect("validation").valid);
    }

    #[tokio::test]
    async fn preview_destroy_result_uses_destroy_payload_kind() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(true);
        let mut config = config_for(pack_path, DeployerCapability::Destroy);
        config.preview = true;
        let result = run(config).await.expect("destroy preview prepares");
        match result.payload.expect("payload") {
            OperationPayload::Destroy(payload) => {
                assert_eq!(payload.capability, "destroy");
                assert_eq!(payload.strategy, "iac-only");
                assert_eq!(payload.flow_id, "destroy_pack");
                assert!(payload.runner_cmd.iter().any(|arg| arg == "--flow"));
                assert!(
                    payload
                        .runner_env
                        .iter()
                        .any(|(key, value)| key == "GREENTIC_DEPLOYMENT_CAPABILITY"
                            && value == "destroy")
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[tokio::test]
    async fn preview_apply_result_contains_runner_handoff() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(true);
        let mut config = config_for(pack_path, DeployerCapability::Apply);
        config.preview = true;
        let result = run(config).await.expect("apply preview prepares");
        match result.payload.expect("payload") {
            OperationPayload::Apply(payload) => {
                assert_eq!(payload.capability, "apply");
                assert_eq!(payload.pack_id, "greentic.deploy.aws");
                assert_eq!(payload.flow_id, "deploy_aws_iac");
                assert!(
                    payload
                        .runner_cmd
                        .iter()
                        .any(|arg| arg == "greentic-runner")
                );
                assert!(payload.plan_path.ends_with("plan.json"));
                assert!(payload.invoke_path.ends_with("invoke.json"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[tokio::test]
    async fn status_result_contains_dispatch_metadata() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(true);
        let result = run(config_for(pack_path, DeployerCapability::Status))
            .await
            .expect("status prepares");
        match result.payload.expect("payload") {
            OperationPayload::Status(payload) => {
                assert_eq!(payload.capability, "status");
                assert_eq!(payload.pack_id, "greentic.deploy.aws");
                assert_eq!(payload.flow_id, "status_pack");
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert!(result.output_validation.as_ref().expect("validation").valid);
    }

    #[tokio::test]
    async fn rollback_result_contains_target_capability() {
        let _guard = EXECUTOR_TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(true);
        let result = run(config_for(pack_path, DeployerCapability::Rollback))
            .await
            .expect("rollback prepares");
        match result.payload.expect("payload") {
            OperationPayload::Rollback(payload) => {
                assert_eq!(payload.capability, "rollback");
                assert_eq!(payload.target_capability, "apply");
                assert_eq!(payload.flow_id, "rollback_pack");
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert!(result.output_validation.as_ref().expect("validation").valid);
    }
}
