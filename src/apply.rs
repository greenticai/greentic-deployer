//! Legacy/provider-oriented multi-target deployment orchestration.
//!
//! This module still contains the older generic deployment-pack execution path
//! used for non-single-vm targets. The stable OSS single-VM path lives in
//! `crate::single_vm`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use tracing::{info, info_span};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::Provider;
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

const SECRETS_PROVIDER_BINDING_RELATIVE_PATH: &str = "state/config/platform/secrets-provider.json";
const SECRETS_PROVIDER_BINDING_SCHEMA_VERSION: &str = "greentic.secrets.binding.v1";

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
    pub handler_id: String,
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
    pub handler_id: String,
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
        OutputFormat::Json => match apply_success_webchat_url(value) {
            Some(webchat_url) => serde_json::to_string_pretty(&serde_json::json!({
                "webchat_url": webchat_url,
            }))
            .map_err(|err| DeployerError::Other(err.to_string())),
            None => serde_json::to_string_pretty(value)
                .map_err(|err| DeployerError::Other(err.to_string())),
        },
        OutputFormat::Yaml => match apply_success_webchat_url(value) {
            Some(webchat_url) => serde_yaml::to_string(&serde_json::json!({
                "webchat_url": webchat_url,
            }))
            .map_err(|err| DeployerError::Other(err.to_string())),
            None => {
                serde_yaml::to_string(value).map_err(|err| DeployerError::Other(err.to_string()))
            }
        },
    }
}

fn render_operation_result_text(value: &OperationResult) -> String {
    if let Some(summary) = render_apply_success_summary(value) {
        return summary;
    }

    let mut out = String::new();
    out.push_str(&format!(
        "capability={} executed={} preview={}\n",
        value.capability, value.executed, value.preview
    ));
    out.push_str(&format!("pack_id={}\n", value.pack_id));
    out.push_str(&format!("flow_id={}\n", value.flow_id));
    out.push_str(&format!("handler_id={}\n", value.handler_id));
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

fn render_apply_success_summary(value: &OperationResult) -> Option<String> {
    apply_success_webchat_url(value).map(|webchat_url| format!("{webchat_url}\n"))
}

fn apply_success_webchat_url(value: &OperationResult) -> Option<String> {
    if value.capability != "apply" || !value.executed || value.preview {
        return None;
    }
    let execution = value.execution.as_ref()?;
    let ExecutionOutcomePayload::Apply(payload) = execution.outcome_payload.as_ref()? else {
        return None;
    };
    if payload.state != "applied" {
        return None;
    }

    let endpoint = payload
        .output_refs
        .get("operator_endpoint")
        .or_else(|| payload.endpoints.first())?;
    let tenant = operation_result_tenant(value).unwrap_or("demo");
    Some(webchat_gui_url(endpoint, tenant))
}

fn operation_result_tenant(value: &OperationResult) -> Option<&str> {
    let OperationPayload::Apply(payload) = value.payload.as_ref()? else {
        return None;
    };
    payload
        .runner_env
        .iter()
        .find_map(|(key, value)| (key == "GREENTIC_TENANT").then_some(value.as_str()))
}

fn webchat_gui_url(endpoint: &str, tenant: &str) -> String {
    format!(
        "{}/v1/web/webchat/{}/",
        endpoint.trim_end_matches('/'),
        tenant.trim_matches('/')
    )
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
    if config.execute_local && uses_k8s_raw_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "kubectl-apply.sh",
                    "k8s-raw-apply",
                    "applied",
                    ScriptedPayloadKind::Apply,
                    "k8s-raw apply executed locally",
                );
            }
            DeployerCapability::Destroy => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "kubectl-delete.sh",
                    "k8s-raw-destroy",
                    "destroyed",
                    ScriptedPayloadKind::Destroy,
                    "k8s-raw destroy executed locally",
                );
            }
            _ => {}
        }
    }
    if config.execute_local && uses_helm_handoff(config) {
        match config.capability {
            DeployerCapability::Apply => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "helm-upgrade.sh",
                    "helm-apply",
                    "applied",
                    ScriptedPayloadKind::Apply,
                    "helm apply executed locally",
                );
            }
            DeployerCapability::Destroy => {
                return execute_local_scripted_operation(
                    config,
                    runtime_artifacts,
                    "helm-rollback.sh",
                    "helm-destroy",
                    "destroyed",
                    ScriptedPayloadKind::Destroy,
                    "helm destroy executed locally",
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
    if config.capability == DeployerCapability::Status && uses_k8s_raw_handoff(config) {
        return synthesize_scripted_handoff_status(
            config,
            runtime_artifacts,
            "k8s-handoff.txt",
            vec![
                ("k8s_manifest", "k8s/rendered-manifests.yaml"),
                ("k8s_apply_script", "kubectl-apply.sh"),
                ("k8s_delete_script", "kubectl-delete.sh"),
                ("k8s_status_script", "kubectl-status.sh"),
            ],
            "k8s-raw status synthesized from local handoff artifacts",
        );
    }
    if config.capability == DeployerCapability::Status && uses_helm_handoff(config) {
        return synthesize_scripted_handoff_status(
            config,
            runtime_artifacts,
            "helm-handoff.txt",
            vec![
                ("helm_chart", "helm-chart/Chart.yaml"),
                ("helm_upgrade_script", "helm-upgrade.sh"),
                ("helm_rollback_script", "helm-rollback.sh"),
                ("helm_status_script", "helm-status.sh"),
            ],
            "helm status synthesized from local handoff artifacts",
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

fn uses_k8s_raw_handoff(config: &DeployerConfig) -> bool {
    config.provider == crate::config::Provider::K8s && config.strategy == "raw-manifests"
}

fn uses_helm_handoff(config: &DeployerConfig) -> bool {
    config.provider == crate::config::Provider::K8s && config.strategy == "helm"
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
        config.provider,
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
                    config.provider,
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
                        config.provider,
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
        let _ = capture_terraform_outputs(config.provider, runtime_artifacts);
        wait_for_runtime_readiness(config.provider, runtime_artifacts)?;
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

fn apply_default_cloud_envs(command: &mut Command, provider: crate::config::Provider) {
    if provider == crate::config::Provider::Aws {
        if std::env::var_os("AWS_REGION").is_none() {
            command.env("AWS_REGION", "eu-north-1");
        }
        if std::env::var_os("AWS_DEFAULT_REGION").is_none() {
            command.env("AWS_DEFAULT_REGION", "eu-north-1");
        }
    }
}

fn run_script_capture_logs(
    script_path: &Path,
    current_dir: &Path,
    provider: crate::config::Provider,
    runtime_artifacts: &RuntimeArtifacts,
    stdout_log: &str,
    stderr_log: &str,
) -> Result<std::process::Output> {
    // Accepted risk: script_path is a deployer-generated executable path and is invoked without a shell.
    // foxguard: ignore[rs/no-command-injection]
    let mut command = Command::new(script_path);
    command.current_dir(current_dir);
    apply_default_cloud_envs(&mut command, provider);
    let output = command.output().map_err(DeployerError::Io)?;
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

    let output = Command::new("bash")
        .current_dir(&runtime_artifacts.deploy_dir)
        .arg(&script_path)
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

fn wait_for_runtime_readiness(
    provider: crate::config::Provider,
    runtime_artifacts: &RuntimeArtifacts,
) -> Result<()> {
    if provider != crate::config::Provider::Azure {
        return Ok(());
    }
    if std::env::var("GREENTIC_DEPLOY_SKIP_ENDPOINT_READY_CHECK")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
    {
        return Ok(());
    }

    let endpoints = collect_runtime_endpoints(runtime_artifacts);
    let Some(endpoint) = endpoints.first() else {
        return Err(DeployerError::Other(
            "azure apply completed without operator endpoint output".to_string(),
        ));
    };
    let ready_url = format!("{}/readyz", endpoint.trim_end_matches('/'));
    let max_attempts = std::env::var("GREENTIC_DEPLOY_ENDPOINT_READY_MAX_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(18);
    let retry_delay_seconds = std::env::var("GREENTIC_DEPLOY_ENDPOINT_READY_RETRY_DELAY_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10);

    for attempt in 1..=max_attempts {
        let status = Command::new("curl")
            .arg("-sS")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("--max-time")
            .arg("10")
            .arg(&ready_url)
            .output();

        match status {
            Ok(output) if output.status.success() => {
                let code = String::from_utf8_lossy(&output.stdout);
                if code.trim() == "200" {
                    return Ok(());
                }
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {}
        }

        if attempt < max_attempts {
            sleep(Duration::from_secs(retry_delay_seconds));
        }
    }

    Err(DeployerError::Other(format!(
        "azure endpoint readiness check failed for {}; /readyz did not return 200",
        ready_url
    )))
}

fn capture_terraform_outputs(
    provider: crate::config::Provider,
    runtime_artifacts: &RuntimeArtifacts,
) -> Result<()> {
    let terraform_root = runtime_artifacts.deploy_dir.join("terraform");
    if !terraform_root.exists() {
        return Ok(());
    }

    let terraform_bin = if terraform_root.join("terraform").exists() {
        terraform_root.join("terraform")
    } else {
        PathBuf::from("terraform")
    };
    // Accepted risk: terraform_bin is either the generated local Terraform binary or the fixed PATH lookup "terraform"; no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let mut command = Command::new(terraform_bin);
    command
        .current_dir(&terraform_root)
        .arg("output")
        .arg("-json");
    apply_default_cloud_envs(&mut command, provider);
    let output = command.output().map_err(DeployerError::Io)?;

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
            &selection.dispatch.handler_id,
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
        handler_id: selection.dispatch.handler_id.clone(),
        pack_path: selection.pack_path.display().to_string(),
        contract: data.contract,
        capability_contract: data.capability_contract,
        payload: data.payload,
        output_validation: data.output_validation,
        execution,
    }
}

fn build_execution_report(
    handler_id: &str,
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
        handler_id: handler_id.to_string(),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SecretsProviderBinding {
    schema_version: String,
    provider_id: String,
    pack: String,
    config: BTreeMap<String, String>,
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
        handler_id: selection.dispatch.handler_id.clone(),
        pack_path: selection.pack_path.display().to_string(),
    };
    let invoke_path = runtime_dir.join("invoke.json");
    let invoke_file = fs::File::create(&invoke_path)?;
    serde_json::to_writer_pretty(invoke_file, &invocation)?;

    materialize_adapter_handoff_assets(config, plan, selection, deploy_dir)?;
    materialize_secrets_provider_binding(config, deploy_dir)?;
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

fn materialize_secrets_provider_binding(config: &DeployerConfig, deploy_dir: &Path) -> Result<()> {
    let Some(binding) = secrets_provider_binding_for_target(config) else {
        return Ok(());
    };
    let bytes =
        serde_json::to_vec_pretty(&binding).map_err(|err| DeployerError::Other(err.to_string()))?;
    // Write to the deploy output (the deployer's emitted artifacts) AND, when a
    // bundle root is known, into it too. The runtime `.gtbundle` the worker
    // loads is (re)built from the bundle root, so writing only to the deploy
    // dir meant a cloud-deployed worker never saw the secrets-provider binding.
    write_secrets_provider_binding(deploy_dir, &bytes)?;
    if let Some(bundle_root) = config.bundle_root.as_deref() {
        write_secrets_provider_binding(bundle_root, &bytes)?;
    }
    Ok(())
}

/// Write the secrets-provider binding under `root` at the canonical relative
/// path, creating the parent directory. Used for both the deploy output and the
/// bundle root.
fn write_secrets_provider_binding(root: &Path, bytes: &[u8]) -> Result<()> {
    let path = root.join(SECRETS_PROVIDER_BINDING_RELATIVE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn secrets_provider_binding_for_target(config: &DeployerConfig) -> Option<SecretsProviderBinding> {
    let (provider_id, pack) = match config.provider {
        crate::config::Provider::Aws => {
            ("greentic.secrets.aws-sm", "providers/secrets/aws-sm.gtpack")
        }
        crate::config::Provider::Gcp => {
            ("greentic.secrets.gcp-sm", "providers/secrets/gcp-sm.gtpack")
        }
        crate::config::Provider::Azure => (
            "greentic.secrets.azure-kv",
            "providers/secrets/azure-kv.gtpack",
        ),
        crate::config::Provider::Local => ("greentic.secrets.dev", "providers/secrets/dev.gtpack"),
        _ => return None,
    };
    let namespace_prefix = crate::runtime_secrets::default_cloud_secret_prefix(
        &config.environment,
        &config.tenant,
        None,
    );
    let mut binding_config = BTreeMap::new();
    binding_config.insert("environment".to_string(), config.environment.clone());
    binding_config.insert("tenant".to_string(), config.tenant.clone());
    binding_config.insert("team".to_string(), "_".to_string());
    binding_config.insert("namespace_prefix".to_string(), namespace_prefix.clone());
    binding_config.insert("prefix".to_string(), namespace_prefix);

    Some(SecretsProviderBinding {
        schema_version: SECRETS_PROVIDER_BINDING_SCHEMA_VERSION.to_string(),
        provider_id: provider_id.to_string(),
        pack: pack.to_string(),
        config: binding_config,
    })
}

fn materialize_adapter_handoff_assets(
    config: &DeployerConfig,
    plan: &PlanContext,
    selection: &DeploymentPackSelection,
    deploy_dir: &Path,
) -> Result<()> {
    if uses_terraform_handoff(config) {
        materialize_terraform_handoff_assets(config, plan, selection, deploy_dir)?;
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
    plan: &PlanContext,
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
    // The operator-module rewriting (`prune_generated_terraform_root` /
    // `normalize_terraform_main_tf`) wires a Greentic app bundle into the
    // standard `operator` module. A self-contained service pack ships its own
    // complete terraform (its own `main.tf` plus bespoke modules) and has no
    // `operator` module, so rewriting would both clobber the pack's terraform
    // and fail writing into a non-existent module directory. Serviceless plans
    // (no app bundle) treat the pack's terraform as authoritative and skip the
    // operator rewrite; only the generic backend rewrite applies.
    if !plan.serviceless {
        prune_generated_terraform_root(config, &terraform_root)?;
        configure_terraform_backend(config, &terraform_root, deploy_dir)?;
        normalize_terraform_main_tf(config, &terraform_root)?;
    } else {
        configure_terraform_backend(config, &terraform_root, deploy_dir)?;
    }

    let tfvars_example = resolve_tfvars_example_name(&terraform_root, &config.environment)?;
    let generated_tfvars = materialize_generated_tfvars(config, &terraform_root, &tfvars_example)?;
    let script_tfvars = generated_tfvars.clone().or_else(|| {
        let env_tfvars = format!("{}.tfvars", config.environment);
        terraform_root
            .join(&env_tfvars)
            .exists()
            .then_some(env_tfvars)
    });
    let init_script = "terraform-init.sh";
    let plan_script = "terraform-plan.sh";
    let apply_script = "terraform-apply.sh";
    let destroy_script = "terraform-destroy.sh";
    let status_script = "terraform-status.sh";
    let aws_cleanup_script = "terraform-aws-cleanup.sh";
    write_executable_script(&deploy_dir.join(init_script), terraform_init_script())?;
    write_executable_script(
        &deploy_dir.join(plan_script),
        terraform_plan_like_script(
            "plan",
            config.provider,
            script_tfvars.as_deref(),
            &tfvars_example,
        ),
    )?;
    write_executable_script(
        &deploy_dir.join(apply_script),
        terraform_plan_like_script(
            "apply",
            config.provider,
            script_tfvars.as_deref(),
            &tfvars_example,
        ),
    )?;
    write_executable_script(
        &deploy_dir.join(destroy_script),
        terraform_plan_like_script(
            "destroy",
            config.provider,
            script_tfvars.as_deref(),
            &tfvars_example,
        ),
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
            terraform_aws_cleanup_script(script_tfvars.as_deref(), &tfvars_example),
        )?;
        scripts.push(aws_cleanup_script.to_string());
    }

    let metadata = TerraformRuntimeMetadata {
        terraform_root: terraform_root.display().to_string(),
        copied_files: copied.clone(),
        scripts,
        generated_tfvars: generated_tfvars.clone(),
        secrets_provider_binding: secrets_provider_binding_for_target(config)
            .map(|_| SECRETS_PROVIDER_BINDING_RELATIVE_PATH.to_string()),
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
    if secrets_provider_binding_for_target(config).is_some() {
        note.push_str(&format!(
            "secrets_provider_binding={}\n",
            deploy_dir
                .join(SECRETS_PROVIDER_BINDING_RELATIVE_PATH)
                .display()
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
  tenant                = var.tenant
  deployment_name_prefix = var.deployment_name_prefix
  operator_image        = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  bundle_source         = var.bundle_source
  bundle_s3_object_ref  = var.bundle_s3_object_ref
  bundle_s3_object_arn  = var.bundle_s3_object_arn
  bundle_digest         = var.bundle_digest
  repo_registry_base    = var.repo_registry_base
  store_registry_base   = var.store_registry_base
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url       = var.public_base_url
  runtime_secret_prefix = var.runtime_secret_prefix
  runtime_secret_env    = var.runtime_secret_env
  secrets_map           = var.secrets_map"#,
        ),
        crate::config::Provider::Azure => (
            "operator",
            "./modules/operator-azure",
            r#"  cloud                 = var.cloud
  tenant                = var.tenant
  environment           = var.environment
  deployment_name_prefix = var.deployment_name_prefix
  bundle_digest         = var.bundle_digest
  bundle_source         = var.bundle_source
  repo_registry_base    = var.repo_registry_base
  store_registry_base   = var.store_registry_base
  operator_image        = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url       = var.public_base_url
  azure_key_vault_uri   = var.azure_key_vault_uri
  azure_key_vault_id    = var.azure_key_vault_id
  azure_location        = var.azure_location
  runtime_secret_prefix = var.runtime_secret_prefix
  runtime_secret_env    = var.runtime_secret_env
  secrets_map           = var.secrets_map"#,
        ),
        crate::config::Provider::Gcp => (
            "operator",
            "./modules/operator-gcp",
            r#"  cloud                 = var.cloud
  tenant                = var.tenant
  environment           = var.environment
  deployment_name_prefix = var.deployment_name_prefix
  bundle_digest         = var.bundle_digest
  bundle_source         = var.bundle_source
  repo_registry_base    = var.repo_registry_base
  store_registry_base   = var.store_registry_base
  operator_image        = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url       = var.public_base_url
  gcp_project_id        = var.gcp_project_id
  gcp_region            = var.gcp_region
  runtime_secret_prefix = var.runtime_secret_prefix
  runtime_secret_env    = var.runtime_secret_env
  secrets_map           = var.secrets_map"#,
        ),
        _ => return Ok(()),
    };

    let main_tf = format!(
        "module \"{module_name}\" {{\n  source = \"{module_source}\"\n\n{module_inputs}\n}}\n\nmodule \"dns\" {{\n  count  = var.dns_name != \"\" ? 1 : 0\n  source = \"./modules/dns\"\n\n  dns_name = var.dns_name\n}}\n\nmodule \"registry\" {{\n  source = \"./modules/registry\"\n\n  bundle_source = var.bundle_source\n  bundle_digest = var.bundle_digest\n}}\n"
    );
    fs::write(terraform_root.join("main.tf"), main_tf)?;

    let relay_outputs = match config.provider {
        crate::config::Provider::Azure | crate::config::Provider::Gcp => format!(
            r#"
output "admin_access_mode" {{
  value = module.{module_name}.admin_access_mode
}}

output "admin_public_endpoint" {{
  value = module.{module_name}.admin_public_endpoint
}}

output "admin_relay_token_secret_ref" {{
  value = module.{module_name}.admin_relay_token_secret_ref
}}
"#
        ),
        _ => String::new(),
    };

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
{relay_outputs}"#
    );
    fs::write(terraform_root.join("outputs.tf"), outputs_tf)?;
    ensure_terraform_variable_declared(
        &terraform_root.join("variables.tf"),
        "deployment_name_prefix",
        "string",
        Some(""),
    )?;
    ensure_terraform_variable_declared(
        &terraform_root.join("variables.tf"),
        "bundle_s3_object_ref",
        "string",
        Some(""),
    )?;
    ensure_terraform_variable_declared(
        &terraform_root.join("variables.tf"),
        "bundle_s3_object_arn",
        "string",
        Some(""),
    )?;
    ensure_terraform_variable_declared(
        &terraform_root.join("variables.tf"),
        "runtime_secret_prefix",
        "string",
        Some(""),
    )?;
    ensure_terraform_variable_declared(
        &terraform_root.join("variables.tf"),
        "runtime_secret_env",
        "map(string)",
        Some("{}"),
    )?;
    ensure_terraform_variable_declared(
        &terraform_root.join("variables.tf"),
        "secrets_map",
        "map(string)",
        Some("{}"),
    )?;
    let module_variables = match config.provider {
        crate::config::Provider::Aws => Some(terraform_root.join("modules/operator/variables.tf")),
        crate::config::Provider::Azure => {
            Some(terraform_root.join("modules/operator-azure/variables.tf"))
        }
        crate::config::Provider::Gcp => {
            Some(terraform_root.join("modules/operator-gcp/variables.tf"))
        }
        _ => None,
    };
    if let Some(module_variables) = module_variables {
        ensure_terraform_variable_declared(
            &module_variables,
            "deployment_name_prefix",
            "string",
            Some(""),
        )?;
        ensure_terraform_variable_declared(
            &module_variables,
            "bundle_s3_object_ref",
            "string",
            Some(""),
        )?;
        ensure_terraform_variable_declared(
            &module_variables,
            "bundle_s3_object_arn",
            "string",
            Some(""),
        )?;
        ensure_terraform_variable_declared(
            &module_variables,
            "runtime_secret_prefix",
            "string",
            Some(""),
        )?;
        ensure_terraform_variable_declared(
            &module_variables,
            "runtime_secret_env",
            "map(string)",
            Some("{}"),
        )?;
        ensure_terraform_variable_declared(
            &module_variables,
            "secrets_map",
            "map(string)",
            Some("{}"),
        )?;
    }
    if config.provider == crate::config::Provider::Aws {
        ensure_aws_runtime_secret_wiring(&terraform_root.join("modules/operator/main.tf"))?;
    }

    Ok(())
}

fn ensure_aws_runtime_secret_wiring(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut contents = fs::read_to_string(path)?;
    if contents.contains("runtime_secret_env")
        && contents.contains("task_runtime_secrets")
        && contents.contains("task_bundle_s3_object")
    {
        return Ok(());
    }
    if !contents.contains(r#"data "aws_caller_identity" "current""#) {
        contents = format!("data \"aws_caller_identity\" \"current\" {{}}\n\n{contents}");
    }
    if !contents.contains("task_runtime_secrets") {
        let marker = r#"resource "aws_ecs_task_definition" "this" {"#;
        let policy = r#"resource "aws_iam_role_policy" "task_runtime_secrets" {
  count = trimspace(var.runtime_secret_prefix) != "" ? 1 : 0
  name  = "${local.name_prefix}-task-runtime-secrets"
  role  = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${trim(var.runtime_secret_prefix, "/")}/*"
        ]
      }
    ]
  })
}

"#;
        contents = contents.replacen(marker, &format!("{policy}{marker}"), 1);
    }
    if !contents.contains("task_bundle_s3_object") {
        let marker = r#"resource "aws_ecs_task_definition" "this" {"#;
        let policy = r#"resource "aws_iam_role_policy" "task_bundle_s3_object" {
  count = trimspace(var.bundle_s3_object_arn) != "" ? 1 : 0
  name  = "${local.name_prefix}-task-bundle-s3-object"
  role  = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = var.bundle_s3_object_arn
      }
    ]
  })
}

"#;
        contents = contents.replacen(marker, &format!("{policy}{marker}"), 1);
    }
    if !contents.contains("bundle_fetcher_enabled") {
        if let Some(line) = contents
            .lines()
            .find(|line| line.trim_start().starts_with("admin_secret_prefix ="))
            .map(str::to_string)
        {
            let replacement = format!(
                "{line}\n  bundle_fetcher_enabled = trimspace(var.bundle_s3_object_ref) != \"\"\n  operator_bundle_source = local.bundle_fetcher_enabled ? \"/greentic-bundle/bundle.gtbundle\" : var.bundle_source"
            );
            contents = contents.replacen(&line, &replacement, 1);
        }
        contents = contents.replace(
            r#"  task_role_arn            = aws_iam_role.task_execution.arn

  container_definitions = jsonencode(["#,
            r#"  task_role_arn            = aws_iam_role.task_execution.arn

  volume {
    name = "greentic-bundle"
  }

  container_definitions = jsonencode(concat(
    local.bundle_fetcher_enabled ? [
      {
        name      = "bundle-fetcher"
        image     = "public.ecr.aws/aws-cli/aws-cli:latest"
        essential = false
        command = [
          "s3",
          "cp",
          var.bundle_s3_object_ref,
          local.operator_bundle_source
        ]
        mountPoints = [
          {
            sourceVolume  = "greentic-bundle"
            containerPath = "/greentic-bundle"
            readOnly      = false
          }
        ]
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            awslogs-group         = aws_cloudwatch_log_group.this.name
            awslogs-region        = data.aws_region.current.name
            awslogs-stream-prefix = "bundle-fetcher"
          }
        }
      }
    ] : [],
    ["#,
        );
        contents = contents.replace("var.bundle_source,", "local.operator_bundle_source,");
        contents = contents.replace(
            r#"            name  = "GREENTIC_BUNDLE_SOURCE"
            value = var.bundle_source"#,
            r#"            name  = "GREENTIC_BUNDLE_SOURCE"
            value = local.operator_bundle_source"#,
        );
        contents = contents.replace(
            r#"      portMappings = ["#,
            r#"      dependsOn = local.bundle_fetcher_enabled ? [
        {
          containerName = "bundle-fetcher"
          condition     = "SUCCESS"
        }
      ] : []
      mountPoints = local.bundle_fetcher_enabled ? [
        {
          sourceVolume  = "greentic-bundle"
          containerPath = "/greentic-bundle"
          readOnly      = true
        }
      ] : []
      portMappings = ["#,
        );
        contents = contents.replace(
            r#"    }
  ])

  tags = local.common_tags"#,
            r#"    }
    ]
  ))

  tags = local.common_tags"#,
        );
    }
    fs::write(path, contents)?;
    Ok(())
}

fn ensure_terraform_variable_declared(
    path: &Path,
    name: &str,
    ty: &str,
    default: Option<&str>,
) -> Result<()> {
    let declaration = match default {
        Some(value) => {
            let rendered_default = if ty.starts_with("map(") && value == "{}" {
                "{}".to_string()
            } else {
                serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
            };
            format!(
                "variable \"{name}\" {{\n  type    = {ty}\n  default = {rendered_default}\n}}\n"
            )
        }
        None => format!("variable \"{name}\" {{\n  type = {ty}\n}}\n"),
    };

    let mut contents = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };
    if contents.contains(&format!("variable \"{name}\"")) {
        return Ok(());
    }
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&declaration);
    fs::write(path, contents)?;
    Ok(())
}

fn aws_bundle_s3_object_arn(bundle_source: &str) -> Option<String> {
    let rest = bundle_source.trim().strip_prefix("s3://")?;
    let (bucket, key) = rest.split_once('/')?;
    let key = key.trim_start_matches('/');
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some(format!("arn:aws:s3:::{bucket}/{key}"))
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

    replace_tfvars_assignment(&mut contents, "cloud", config.provider.as_str());
    replace_tfvars_assignment(&mut contents, "tenant", &config.tenant);
    replace_tfvars_assignment(&mut contents, "environment", &config.environment);
    let deployment_name_prefix = resolve_terraform_deployment_name_prefix(config, &output_path);
    replace_tfvars_assignment(
        &mut contents,
        "deployment_name_prefix",
        &deployment_name_prefix,
    );

    for (key, value) in terraform_contract_default_overrides(config.provider) {
        replace_tfvars_assignment(&mut contents, &key, &value);
    }

    if let Some(bundle_source) = config.bundle_source.as_ref() {
        replace_tfvars_assignment(&mut contents, "bundle_source", bundle_source);
        if let Some(s3_arn) = aws_bundle_s3_object_arn(bundle_source) {
            replace_tfvars_assignment(&mut contents, "bundle_s3_object_arn", &s3_arn);
        }
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
    if matches!(
        config.provider,
        crate::config::Provider::Aws
            | crate::config::Provider::Azure
            | crate::config::Provider::Gcp
    ) {
        replace_tfvars_assignment(
            &mut contents,
            "runtime_secret_prefix",
            &crate::runtime_secrets::default_cloud_secret_prefix(
                &config.environment,
                &config.tenant,
                None,
            ),
        );
        let runtime_secret_env = crate::runtime_secrets::runtime_secret_env_map_for_cloud(config)?;
        replace_tfvars_map_assignment(&mut contents, "runtime_secret_env", &runtime_secret_env);
    }
    for (key, value) in terraform_env_overrides() {
        replace_tfvars_assignment(&mut contents, &key, &value);
    }
    apply_operator_secrets_map_tfvar(&mut contents);
    normalize_public_base_url_assignment(&mut contents);

    fs::write(output_path, contents)?;
    Ok(Some(output_name))
}

/// PR-08: lift operator secrets into the generated tfvars file so the AWS
/// operator module materialises them as Secrets Manager entries and injects
/// them into the ECS task definition's `secrets` block.
///
/// Source contract (v1): a JSON object at the path indicated by
/// `GREENTIC_OPERATOR_SECRETS_JSON`, mapping canonical `secrets://...` URIs
/// to UTF-8 string values. When the env var is unset, the file is missing,
/// or the JSON is empty, no `secrets_map` assignment is written and the
/// terraform default (`{}`) applies — no operator-secret resources are
/// created. The bundle artifact never carries these values.
///
/// A future `gtc secrets export --json <path>` will be the canonical
/// producer; meanwhile the env-var contract lets operators or CI assemble
/// the JSON out-of-band and hand it to `gtc deploy`.
///
/// Logging policy: only the count is printed. Values, keys, and the file
/// path never leave the deployer process via stdout/stderr.
fn apply_operator_secrets_map_tfvar(contents: &mut String) {
    let Some(map) = load_operator_secrets_map() else {
        return;
    };
    if map.is_empty() {
        return;
    }
    let rendered = render_terraform_map(&map);
    replace_tfvars_assignment_literal(contents, "secrets_map", &rendered);
    eprintln!(
        "operator secrets: applied {} entr{} to tfvars (source=GREENTIC_OPERATOR_SECRETS_JSON)",
        map.len(),
        if map.len() == 1 { "y" } else { "ies" }
    );
}

fn load_operator_secrets_map() -> Option<std::collections::BTreeMap<String, String>> {
    let path = std::env::var("GREENTIC_OPERATOR_SECRETS_JSON")
        .ok()
        .map(std::path::PathBuf::from)?;
    if !path.is_file() {
        return None;
    }
    let raw = fs::read_to_string(&path).ok()?;
    let parsed: std::collections::BTreeMap<String, String> = serde_json::from_str(&raw).ok()?;
    Some(parsed)
}

/// Render a Rust map as a terraform HCL map literal.
///
/// Values are JSON-quoted (the same escape contract `replace_tfvars_assignment`
/// uses for plain strings), so the result is `{ "k" = "v", ... }` with each
/// pair on its own line for readability. Terraform marks the variable
/// `sensitive` at the schema level, so plan/apply suppresses values.
fn render_terraform_map(map: &std::collections::BTreeMap<String, String>) -> String {
    let mut out = String::from("{\n");
    for (key, value) in map {
        let key_q = serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\""));
        let value_q = serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""));
        out.push_str(&format!("  {key_q} = {value_q}\n"));
    }
    out.push('}');
    out
}

/// Like `replace_tfvars_assignment` but treats `value` as an already-rendered
/// HCL literal (map/list/etc.) instead of JSON-quoting it as a string.
fn replace_tfvars_assignment_literal(contents: &mut String, key: &str, value_literal: &str) {
    let replacement = format!("{key} = {value_literal}");
    let mut rewritten = Vec::new();
    let mut replaced = false;
    let mut iter = contents.lines().peekable();
    while let Some(line) = iter.next() {
        if !replaced && line.trim_start().starts_with(&format!("{key} = ")) {
            rewritten.push(replacement.clone());
            // Skip continuation lines of a previous multi-line literal until
            // we see a top-level closing `}` (terraform map/list literal).
            if line.trim_end().ends_with('{') || line.trim_end().ends_with('[') {
                for cont in iter.by_ref() {
                    if cont.trim() == "}" || cont.trim() == "]" {
                        break;
                    }
                }
            }
            replaced = true;
            continue;
        }
        rewritten.push(line.to_string());
    }
    if !replaced {
        if !contents.is_empty() && !contents.ends_with('\n') {
            rewritten.push(String::new());
        }
        rewritten.push(replacement);
    }
    let mut joined = rewritten.join("\n");
    if !joined.ends_with('\n') {
        joined.push('\n');
    }
    *contents = joined;
}

fn resolve_terraform_deployment_name_prefix(config: &DeployerConfig, output_path: &Path) -> String {
    if let Some(prefix) = explicit_deployment_name_prefix() {
        return prefix;
    }

    if let Ok(existing) = fs::read_to_string(output_path)
        && let Some(prefix) = read_tfvars_assignment(&existing, "deployment_name_prefix")
            .filter(|value| !value.trim().is_empty())
        && prefix != legacy_shared_deployment_name_prefix(config)
    {
        return prefix;
    }

    stable_deployment_name_prefix(config)
}

fn stable_deployment_name_prefix(config: &DeployerConfig) -> String {
    let seed = format!(
        "{}\0{}\0{}\0{}",
        config.provider.as_str(),
        config.tenant,
        config.environment,
        local_deployment_identity_seed(config),
    );
    format!("greentic-{:08x}", fnv1a32(seed.as_bytes()))
}

fn legacy_shared_deployment_name_prefix(config: &DeployerConfig) -> String {
    let seed = format!(
        "{}\0{}\0{}",
        config.provider.as_str(),
        config.tenant,
        config.environment,
    );
    format!("greentic-{:08x}", fnv1a32(seed.as_bytes()))
}

fn explicit_deployment_name_prefix() -> Option<String> {
    std::env::var("GREENTIC_DEPLOY_TERRAFORM_VAR_DEPLOYMENT_NAME_PREFIX")
        .ok()
        .or_else(|| std::env::var("GREENTIC_DEPLOYMENT_NAME_PREFIX").ok())
        .and_then(|value| {
            let normalized = normalize_deployment_name_prefix(&value);
            (!normalized.is_empty()).then_some(normalized)
        })
}

fn local_deployment_identity_seed(config: &DeployerConfig) -> String {
    std::env::var("GREENTIC_DEPLOYMENT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            let owner = std::env::var("GREENTIC_DEPLOYMENT_OWNER")
                .ok()
                .or_else(|| std::env::var("USER").ok())
                .or_else(|| std::env::var("USERNAME").ok())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "unknown".to_string());
            let workspace = config
                .bundle_root
                .as_ref()
                .and_then(|path| path.canonicalize().ok())
                .or_else(|| std::env::current_dir().ok())
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            format!("{owner}\0{workspace}")
        })
}

fn normalize_deployment_name_prefix(value: &str) -> String {
    let mut normalized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while normalized.contains("--") {
        normalized = normalized.replace("--", "-");
    }
    normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        return normalized;
    }
    if !normalized
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
    {
        normalized = format!("greentic-{normalized}");
    }
    if normalized.len() > 24 {
        normalized.truncate(24);
        normalized = normalized.trim_end_matches('-').to_string();
    }
    normalized
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    const OFFSET: u32 = 0x811c9dc5;
    const PRIME: u32 = 0x01000193;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn normalize_public_base_url_assignment(contents: &mut String) {
    let dns_name = read_tfvars_assignment(contents, "dns_name");
    let public_base_url = read_tfvars_assignment(contents, "public_base_url");

    if let Some(dns_name) = dns_name.filter(|value| !value.trim().is_empty()) {
        replace_tfvars_assignment(contents, "public_base_url", &format!("https://{dns_name}"));
        return;
    }

    if let Some(public_base_url) = public_base_url {
        let normalized = public_base_url
            .trim()
            .trim_end_matches('/')
            .to_ascii_lowercase();
        let is_placeholder = normalized.is_empty()
            || normalized.contains("example.com")
            || normalized.contains("localhost")
            || normalized.contains("127.0.0.1");
        if is_placeholder {
            replace_tfvars_assignment(contents, "public_base_url", "");
        }
    }
}

fn terraform_contract_default_overrides(provider: Provider) -> Vec<(String, String)> {
    let Some(requirements) = crate::contract::CloudTargetRequirementsV1::for_provider(provider)
    else {
        return Vec::new();
    };

    let mut overrides = requirements
        .variable_requirements
        .into_iter()
        .filter_map(|entry| {
            let key = normalize_terraform_requirement_name(&entry.name)?;
            let value = entry.default_value?;
            Some((key, value))
        })
        .collect::<Vec<_>>();
    overrides.sort_by(|a, b| a.0.cmp(&b.0));
    overrides
}

fn normalize_terraform_requirement_name(name: &str) -> Option<String> {
    const PREFIX: &str = "GREENTIC_DEPLOY_TERRAFORM_VAR_";
    let suffix = name.strip_prefix(PREFIX)?;
    let normalized = suffix.trim();
    if normalized.is_empty() {
        return None;
    }
    Some(
        normalized
            .to_ascii_lowercase()
            .replace("__", "-")
            .replace('_', ".")
            .replace('.', "_"),
    )
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

fn replace_tfvars_map_assignment(
    contents: &mut String,
    key: &str,
    values: &BTreeMap<String, String>,
) {
    let replacement = if values.is_empty() {
        format!("{key} = {{}}")
    } else {
        let mut out = format!("{key} = {{\n");
        for (map_key, value) in values {
            out.push_str(&format!(
                "  {} = {}\n",
                serde_json::to_string(map_key).unwrap_or_else(|_| format!("\"{map_key}\"")),
                serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
            ));
        }
        out.push('}');
        out
    };

    let mut rewritten = Vec::new();
    let mut replaced = false;
    let mut skipping_multiline = false;
    for line in contents.lines() {
        let trimmed = line.trim_start();
        if skipping_multiline {
            if trimmed == "}" {
                skipping_multiline = false;
            }
            continue;
        }
        if !replaced && trimmed.starts_with(&format!("{key} =")) {
            rewritten.push(replacement.clone());
            replaced = true;
            if trimmed.ends_with('{') && !trimmed.contains('}') {
                skipping_multiline = true;
            }
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

fn read_tfvars_assignment(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let (lhs, rhs) = trimmed.split_once('=')?;
        if lhs.trim() != key {
            continue;
        }
        let value = rhs
            .split('#')
            .next()
            .map(str::trim)
            .map(|segment| segment.trim_matches('"'))
            .unwrap_or_default();
        return Some(value.to_string());
    }
    None
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

fn terraform_hash_string_function() -> &'static str {
    r#"hash_string() {
  if command -v md5sum >/dev/null 2>&1; then
    printf '%s' "$1" | md5sum | awk '{print substr($1,1,8)}'
  else
    printf '%s' "$1" | md5 -q | awk '{print substr($1,1,8)}'
  fi
}
"#
}

fn terraform_plan_like_script(
    operation: &str,
    provider: crate::config::Provider,
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
    let pre_apply_hook = if operation == "apply" && provider == crate::config::Provider::Aws {
        r#"
if command -v aws >/dev/null 2>&1; then
  MODULE_ADDR=""
  if grep -q 'module "operator_aws"' main.tf; then
    MODULE_ADDR="module.operator_aws[0]"
  elif grep -q 'module "operator"' main.tf; then
    MODULE_ADDR="module.operator"
  fi
  if [ -n "$MODULE_ADDR" ]; then
    BUNDLE_DIGEST_VALUE=""
    DEPLOYMENT_NAME_PREFIX_VALUE=""
    AWS_REGION_VALUE="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
    if [ -n "$VAR_FILE" ] && [ -f "$VAR_FILE" ]; then
      BUNDLE_DIGEST_VALUE=$(sed -n 's/^bundle_digest = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
      DEPLOYMENT_NAME_PREFIX_VALUE=$(sed -n 's/^deployment_name_prefix = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
    fi
    NAME_PREFIX="$DEPLOYMENT_NAME_PREFIX_VALUE"
    if [ -z "$NAME_PREFIX" ] && [ -n "$BUNDLE_DIGEST_VALUE" ]; then
      SHORT_ID="$(hash_string "$BUNDLE_DIGEST_VALUE")"
      NAME_PREFIX="greentic-${SHORT_ID}"
    fi
    if [ -n "$NAME_PREFIX" ] && [ -n "$AWS_REGION_VALUE" ]; then
      export AWS_REGION="$AWS_REGION_VALUE"
      export AWS_DEFAULT_REGION="$AWS_REGION_VALUE"
      import_if_missing() {
        local address="$1"
        local id="$2"
        if "$TERRAFORM_BIN" state show "$address" >/dev/null 2>&1; then
          return 0
        fi
        if [ -n "$VAR_FILE" ] && [ -f "$VAR_FILE" ]; then
          "$TERRAFORM_BIN" import -input=false -var-file="$VAR_FILE" "$address" "$id"
        else
          "$TERRAFORM_BIN" import -input=false "$address" "$id"
        fi
      }
      SECURITY_GROUP_ALB_NAME="${NAME_PREFIX}-alb"
      SECURITY_GROUP_SERVICE_NAME="${NAME_PREFIX}-svc"
      ALB_NAME="${NAME_PREFIX}-alb"
      CLUSTER_NAME="${NAME_PREFIX}-cluster"
      LOG_GROUP_NAME="/greentic/demo/${NAME_PREFIX}"
      ROLE_NAME="${NAME_PREFIX}-task-exec"
      SERVICE_NAME="${NAME_PREFIX}-service"
      ALB_GROUP_ID=$(aws ec2 describe-security-groups --region "$AWS_REGION_VALUE" --filters Name=group-name,Values="$SECURITY_GROUP_ALB_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
      if [ -n "$ALB_GROUP_ID" ] && [ "$ALB_GROUP_ID" != "None" ]; then
        import_if_missing "${MODULE_ADDR}.aws_security_group.alb" "$ALB_GROUP_ID"
      fi
      SERVICE_GROUP_ID=$(aws ec2 describe-security-groups --region "$AWS_REGION_VALUE" --filters Name=group-name,Values="$SECURITY_GROUP_SERVICE_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
      if [ -n "$SERVICE_GROUP_ID" ] && [ "$SERVICE_GROUP_ID" != "None" ]; then
        import_if_missing "${MODULE_ADDR}.aws_security_group.service" "$SERVICE_GROUP_ID"
      fi
      ALB_ARN=$(aws elbv2 describe-load-balancers --region "$AWS_REGION_VALUE" --names "$ALB_NAME" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)
      if [ -n "$ALB_ARN" ] && [ "$ALB_ARN" != "None" ]; then
        import_if_missing "${MODULE_ADDR}.aws_lb.this" "$ALB_ARN"
        LISTENER_ARN=$(aws elbv2 describe-listeners --region "$AWS_REGION_VALUE" --load-balancer-arn "$ALB_ARN" --query 'Listeners[?Port==`80` && Protocol==`HTTP`].ListenerArn | [0]' --output text 2>/dev/null || true)
        if [ -n "$LISTENER_ARN" ] && [ "$LISTENER_ARN" != "None" ]; then
          import_if_missing "${MODULE_ADDR}.aws_lb_listener.http" "$LISTENER_ARN"
        fi
      fi
      CLUSTER_FOUND=$(aws ecs describe-clusters --region "$AWS_REGION_VALUE" --clusters "$CLUSTER_NAME" --query 'clusters[?status==`ACTIVE`].clusterName | [0]' --output text 2>/dev/null || true)
      if [ -n "$CLUSTER_FOUND" ] && [ "$CLUSTER_FOUND" != "None" ] && [ "$CLUSTER_FOUND" != "MISSING" ]; then
        import_if_missing "${MODULE_ADDR}.aws_ecs_cluster.this" "$CLUSTER_NAME"
      fi
      LOG_GROUP_FOUND=$(aws logs describe-log-groups --region "$AWS_REGION_VALUE" --log-group-name-prefix "$LOG_GROUP_NAME" --query 'logGroups[?logGroupName==`'"$LOG_GROUP_NAME"'`].logGroupName | [0]' --output text 2>/dev/null || true)
      if [ -n "$LOG_GROUP_FOUND" ] && [ "$LOG_GROUP_FOUND" != "None" ]; then
        import_if_missing "${MODULE_ADDR}.aws_cloudwatch_log_group.this" "$LOG_GROUP_NAME"
      fi
      if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
        import_if_missing "${MODULE_ADDR}.aws_iam_role.task_execution" "$ROLE_NAME"
      fi
      SERVICE_FOUND=$(aws ecs describe-services --region "$AWS_REGION_VALUE" --cluster "$CLUSTER_NAME" --services "$SERVICE_NAME" --query 'services[?status==`ACTIVE`].serviceName | [0]' --output text 2>/dev/null || true)
      if [ -n "$SERVICE_FOUND" ] && [ "$SERVICE_FOUND" != "None" ] && [ "$SERVICE_FOUND" != "MISSING" ]; then
        import_if_missing "${MODULE_ADDR}.aws_ecs_service.this" "${CLUSTER_NAME}/${SERVICE_NAME}"
      fi
    fi
  fi
fi
"#
        .to_string()
    } else if operation == "apply" && provider == crate::config::Provider::Azure {
        r#"
if command -v az >/dev/null 2>&1 && [ -n "${ARM_SUBSCRIPTION_ID:-}" ]; then
  MODULE_ADDR=""
  if grep -q 'module "operator_azure"' main.tf; then
    MODULE_ADDR="module.operator_azure[0]"
  elif grep -q 'module "operator"' main.tf; then
    MODULE_ADDR="module.operator"
  fi
    if [ -n "$MODULE_ADDR" ]; then
      BUNDLE_DIGEST_VALUE=""
      ENVIRONMENT_VALUE="dev"
      CLOUD_VALUE=""
      OPERATOR_IMAGE_DIGEST_VALUE=""
      BUNDLE_SOURCE_VALUE=""
      REMOTE_STATE_BACKEND_VALUE=""
      KEY_VAULT_ID_VALUE=""
      DEPLOYMENT_NAME_PREFIX_VALUE=""
      if [ -n "$VAR_FILE" ] && [ -f "$VAR_FILE" ]; then
        CLOUD_VALUE=$(sed -n 's/^cloud = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
        BUNDLE_DIGEST_VALUE=$(sed -n 's/^bundle_digest = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
        ENVIRONMENT_VALUE=$(sed -n 's/^environment = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
        OPERATOR_IMAGE_DIGEST_VALUE=$(sed -n 's/^operator_image_digest = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
        BUNDLE_SOURCE_VALUE=$(sed -n 's/^bundle_source = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
        REMOTE_STATE_BACKEND_VALUE=$(sed -n 's/^remote_state_backend = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
        KEY_VAULT_ID_VALUE=$(sed -n 's/^azure_key_vault_id = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
        DEPLOYMENT_NAME_PREFIX_VALUE=$(sed -n 's/^deployment_name_prefix = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
      fi
      if [ -n "$BUNDLE_DIGEST_VALUE" ]; then
        export TF_VAR_cloud="${CLOUD_VALUE:-azure}"
        export TF_VAR_environment="${ENVIRONMENT_VALUE:-dev}"
        export TF_VAR_operator_image_digest="$OPERATOR_IMAGE_DIGEST_VALUE"
        export TF_VAR_bundle_source="$BUNDLE_SOURCE_VALUE"
        export TF_VAR_bundle_digest="$BUNDLE_DIGEST_VALUE"
        export TF_VAR_remote_state_backend="$REMOTE_STATE_BACKEND_VALUE"
        export TF_VAR_azure_key_vault_id="$KEY_VAULT_ID_VALUE"
        export TF_VAR_azure_location="${GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_LOCATION:-}"
        NAME_PREFIX="$DEPLOYMENT_NAME_PREFIX_VALUE"
        if [ -z "$NAME_PREFIX" ]; then
          SHORT_ID="$(hash_string "$BUNDLE_DIGEST_VALUE")"
          NAME_PREFIX="greentic-${SHORT_ID}"
        fi
        RESOURCE_GROUP_NAME="${NAME_PREFIX}-rg"
      LOG_ANALYTICS_NAME="${NAME_PREFIX}-logs"
      CONTAINER_ENV_NAME="${NAME_PREFIX}-cae"
      CONTAINER_APP_NAME="${NAME_PREFIX}-app"
        import_if_missing() {
          local address="$1"
          local id="$2"
          if "$TERRAFORM_BIN" state show "$address" >/dev/null 2>&1; then
            return 0
          fi
          if [ -n "$VAR_FILE" ] && [ -f "$VAR_FILE" ]; then
            "$TERRAFORM_BIN" import -input=false -var-file="$VAR_FILE" "$address" "$id"
          else
            "$TERRAFORM_BIN" import -input=false "$address" "$id"
          fi
        }
      if az group show --name "$RESOURCE_GROUP_NAME" >/dev/null 2>&1; then
        import_if_missing "${MODULE_ADDR}.azurerm_resource_group.this" "/subscriptions/${ARM_SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}"
      fi
      LOG_ANALYTICS_ID=$(az monitor log-analytics workspace show --resource-group "$RESOURCE_GROUP_NAME" --workspace-name "$LOG_ANALYTICS_NAME" --query id -o tsv 2>/dev/null || true)
      if [ -n "$LOG_ANALYTICS_ID" ]; then
        import_if_missing "${MODULE_ADDR}.azurerm_log_analytics_workspace.this" "$LOG_ANALYTICS_ID"
      fi
      CONTAINER_ENV_ID=$(az resource show --ids "/subscriptions/${ARM_SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}/providers/Microsoft.App/managedEnvironments/${CONTAINER_ENV_NAME}" --query id -o tsv 2>/dev/null || true)
      if [ -n "$CONTAINER_ENV_ID" ]; then
        import_if_missing "${MODULE_ADDR}.azurerm_container_app_environment.this" "$CONTAINER_ENV_ID"
      fi
      CONTAINER_APP_ID=$(az resource show --ids "/subscriptions/${ARM_SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}/providers/Microsoft.App/containerApps/${CONTAINER_APP_NAME}" --query id -o tsv 2>/dev/null || true)
      if [ -n "$CONTAINER_APP_ID" ]; then
        import_if_missing "${MODULE_ADDR}.azurerm_container_app.this" "$CONTAINER_APP_ID"
      fi
      if [ -n "$KEY_VAULT_ID_VALUE" ]; then
        KEY_VAULT_NAME=$(basename "$KEY_VAULT_ID_VALUE")
        ADMIN_CA_SECRET_ID=$(az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name "greentic-admin-ca-${ENVIRONMENT_VALUE}" --query id -o tsv 2>/dev/null || true)
        if [ -n "$ADMIN_CA_SECRET_ID" ]; then
          import_if_missing "${MODULE_ADDR}.azurerm_key_vault_secret.admin_ca[0]" "$ADMIN_CA_SECRET_ID"
        fi
        ADMIN_SERVER_CERT_SECRET_ID=$(az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name "greentic-admin-server-cert-${ENVIRONMENT_VALUE}" --query id -o tsv 2>/dev/null || true)
        if [ -n "$ADMIN_SERVER_CERT_SECRET_ID" ]; then
          import_if_missing "${MODULE_ADDR}.azurerm_key_vault_secret.admin_server_cert[0]" "$ADMIN_SERVER_CERT_SECRET_ID"
        fi
        ADMIN_SERVER_KEY_SECRET_ID=$(az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name "greentic-admin-server-key-${ENVIRONMENT_VALUE}" --query id -o tsv 2>/dev/null || true)
        if [ -n "$ADMIN_SERVER_KEY_SECRET_ID" ]; then
          import_if_missing "${MODULE_ADDR}.azurerm_key_vault_secret.admin_server_key[0]" "$ADMIN_SERVER_KEY_SECRET_ID"
        fi
      fi
    fi
  fi
fi
"# 
        .to_string()
    } else if operation == "apply" && provider == crate::config::Provider::Gcp {
        r#"
if command -v gcloud >/dev/null 2>&1; then
  MODULE_ADDR=""
  if grep -q 'module "operator_gcp"' main.tf; then
    MODULE_ADDR="module.operator_gcp[0]"
  elif grep -q 'module "operator"' main.tf; then
    MODULE_ADDR="module.operator"
  fi
  if [ -n "$MODULE_ADDR" ]; then
    GCP_PROJECT_ID_VALUE=""
    GCP_REGION_VALUE="us-central1"
    ENVIRONMENT_VALUE="dev"
    BUNDLE_DIGEST_VALUE=""
    DEPLOYMENT_NAME_PREFIX_VALUE=""
    if [ -n "$VAR_FILE" ] && [ -f "$VAR_FILE" ]; then
      GCP_PROJECT_ID_VALUE=$(sed -n 's/^gcp_project_id = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
      GCP_REGION_VALUE=$(sed -n 's/^gcp_region = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
      ENVIRONMENT_VALUE=$(sed -n 's/^environment = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
      BUNDLE_DIGEST_VALUE=$(sed -n 's/^bundle_digest = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
      DEPLOYMENT_NAME_PREFIX_VALUE=$(sed -n 's/^deployment_name_prefix = "\(.*\)"$/\1/p' "$VAR_FILE" | head -n 1)
    fi
    if [ -n "$GCP_PROJECT_ID_VALUE" ]; then
      import_if_missing() {
        local address="$1"
        local id="$2"
        if "$TERRAFORM_BIN" state show "$address" >/dev/null 2>&1; then
          return 0
        fi
        if [ -n "$VAR_FILE" ] && [ -f "$VAR_FILE" ]; then
          "$TERRAFORM_BIN" import -input=false -var-file="$VAR_FILE" "$address" "$id"
        else
          "$TERRAFORM_BIN" import -input=false "$address" "$id"
        fi
      }
      import_gcp_secret_if_exists() {
        local address="$1"
        local secret_name="$2"
        local secret_id
        secret_id=$(gcloud secrets describe "$secret_name" --project "$GCP_PROJECT_ID_VALUE" --format='value(name)' 2>/dev/null || true)
        if [ -n "$secret_id" ]; then
          import_if_missing "$address" "$secret_id"
        fi
      }
      import_gcp_secret_if_exists "${MODULE_ADDR}.google_secret_manager_secret.admin_ca" "greentic-admin-ca-${ENVIRONMENT_VALUE}"
      import_gcp_secret_if_exists "${MODULE_ADDR}.google_secret_manager_secret.admin_server_cert" "greentic-admin-server-cert-${ENVIRONMENT_VALUE}"
      import_gcp_secret_if_exists "${MODULE_ADDR}.google_secret_manager_secret.admin_server_key" "greentic-admin-server-key-${ENVIRONMENT_VALUE}"
      import_gcp_secret_if_exists "${MODULE_ADDR}.google_secret_manager_secret.admin_client_cert" "greentic-admin-client-cert-${ENVIRONMENT_VALUE}"
      import_gcp_secret_if_exists "${MODULE_ADDR}.google_secret_manager_secret.admin_client_key" "greentic-admin-client-key-${ENVIRONMENT_VALUE}"
      import_gcp_secret_if_exists "${MODULE_ADDR}.google_secret_manager_secret.admin_relay_token" "greentic-admin-relay-token-${ENVIRONMENT_VALUE}"
      if [ -n "$BUNDLE_DIGEST_VALUE" ]; then
        NAME_PREFIX="$DEPLOYMENT_NAME_PREFIX_VALUE"
        if [ -z "$NAME_PREFIX" ]; then
          SHORT_ID="$(hash_string "$BUNDLE_DIGEST_VALUE")"
          NAME_PREFIX="greentic-${SHORT_ID}"
        fi
        CLOUD_RUN_SERVICE_NAME="${NAME_PREFIX}-run"
        CLOUD_RUN_SERVICE_ID=$(gcloud run services describe "$CLOUD_RUN_SERVICE_NAME" --project "$GCP_PROJECT_ID_VALUE" --region "$GCP_REGION_VALUE" --format='value(metadata.name)' 2>/dev/null || true)
        if [ -n "$CLOUD_RUN_SERVICE_ID" ]; then
          import_if_missing "${MODULE_ADDR}.google_cloud_run_v2_service.this" "projects/${GCP_PROJECT_ID_VALUE}/locations/${GCP_REGION_VALUE}/services/${CLOUD_RUN_SERVICE_NAME}"
        fi
      fi
    fi
  fi
fi
"#
        .to_string()
    } else {
        String::new()
    };
    let apply_invocation = format!(
        "if [ -n \"$VAR_FILE\" ]; then\n  \"$TERRAFORM_BIN\" {operation}{extra_args} -var-file=\"$VAR_FILE\" \"$@\"\nelse\n  \"$TERRAFORM_BIN\" {operation}{extra_args} \"$@\"\nfi"
    );
    let apply_invocation_with_redirection = if apply_invocation.contains("-var-file=\"$VAR_FILE\"")
    {
        "  if [ -n \"$VAR_FILE\" ]; then\n    \"$TERRAFORM_BIN\" apply -auto-approve -input=false -var-file=\"$VAR_FILE\" \"$@\" >\"$stdout_file\" 2>\"$stderr_file\"\n  else\n    \"$TERRAFORM_BIN\" apply -auto-approve -input=false \"$@\" >\"$stdout_file\" 2>\"$stderr_file\"\n  fi"
    } else {
        "  \"$TERRAFORM_BIN\" apply -auto-approve -input=false \"$@\" >\"$stdout_file\" 2>\"$stderr_file\""
    };
    let operation_block = if operation == "apply" && provider == crate::config::Provider::Azure {
        format!(
            "AZURE_APPLY_MAX_ATTEMPTS=\"${{GREENTIC_AZURE_APPLY_MAX_ATTEMPTS:-6}}\"\nAZURE_APPLY_RETRY_DELAY_SECONDS=\"${{GREENTIC_AZURE_APPLY_RETRY_DELAY_SECONDS:-20}}\"\nattempt=1\nwhile true; do\n  stdout_file=\"$(mktemp)\"\n  stderr_file=\"$(mktemp)\"\n  set +e\n{apply_invocation_with_redirection}\n  status=$?\n  set -e\n  cat \"$stdout_file\"\n  cat \"$stderr_file\" >&2\n  if [ \"$status\" -eq 0 ]; then\n    rm -f \"$stdout_file\" \"$stderr_file\"\n    break\n  fi\n  retry_reason=\"\"\n  if grep -q 'ResourceGroupBeingDeleted' \"$stderr_file\"; then\n    retry_reason='resource group is still being deleted'\n  elif grep -q 'ManagedEnvironmentNotProvisioned' \"$stderr_file\"; then\n    retry_reason='container app environment is not fully provisioned yet'\n  elif grep -q 'Operation was canceled' \"$stderr_file\"; then\n    retry_reason='azure control plane canceled the previous environment operation'\n  fi\n  if [ -n \"$retry_reason\" ] && [ \"$attempt\" -lt \"$AZURE_APPLY_MAX_ATTEMPTS\" ]; then\n    echo \"Azure apply hit transient condition: $retry_reason; retrying in ${{AZURE_APPLY_RETRY_DELAY_SECONDS}}s (attempt ${{attempt}}/${{AZURE_APPLY_MAX_ATTEMPTS}})\" >&2\n    rm -f \"$stdout_file\" \"$stderr_file\" .terraform.tfstate.lock.info\n    sleep \"$AZURE_APPLY_RETRY_DELAY_SECONDS\"\n    attempt=$((attempt + 1))\n    continue\n  fi\n  rm -f \"$stdout_file\" \"$stderr_file\"\n  exit \"$status\"\ndone",
            apply_invocation_with_redirection = apply_invocation_with_redirection
        )
    } else if operation == "apply" && provider == crate::config::Provider::Aws {
        format!(
            "AWS_APPLY_MAX_ATTEMPTS=\"${{GREENTIC_AWS_APPLY_MAX_ATTEMPTS:-6}}\"\nAWS_APPLY_RETRY_DELAY_SECONDS=\"${{GREENTIC_AWS_APPLY_RETRY_DELAY_SECONDS:-20}}\"\nattempt=1\nwhile true; do\n  stdout_file=\"$(mktemp)\"\n  stderr_file=\"$(mktemp)\"\n  set +e\n{apply_invocation_with_redirection}\n  status=$?\n  set -e\n  cat \"$stdout_file\"\n  cat \"$stderr_file\" >&2\n  if [ \"$status\" -eq 0 ]; then\n    rm -f \"$stdout_file\" \"$stderr_file\"\n    break\n  fi\n  retry_reason=\"\"\n  if grep -q 'DuplicateLoadBalancerName' \"$stderr_file\"; then\n    retry_reason='load balancer is still being deleted or reused'\n  elif grep -q 'EntityAlreadyExists' \"$stderr_file\"; then\n    retry_reason='iam or log resource still exists while aws control plane converges'\n  elif grep -q 'already exists' \"$stderr_file\"; then\n    retry_reason='aws resource name is still reserved while the previous deployment is converging'\n  elif grep -q 'OperationAborted' \"$stderr_file\"; then\n    retry_reason='aws control plane reported an in-progress conflicting operation'\n  fi\n  if [ -n \"$retry_reason\" ] && [ \"$attempt\" -lt \"$AWS_APPLY_MAX_ATTEMPTS\" ]; then\n    echo \"AWS apply hit transient condition: $retry_reason; retrying in ${{AWS_APPLY_RETRY_DELAY_SECONDS}}s (attempt ${{attempt}}/${{AWS_APPLY_MAX_ATTEMPTS}})\" >&2\n    rm -f \"$stdout_file\" \"$stderr_file\" .terraform.tfstate.lock.info\n    sleep \"$AWS_APPLY_RETRY_DELAY_SECONDS\"\n    attempt=$((attempt + 1))\n    continue\n  fi\n  rm -f \"$stdout_file\" \"$stderr_file\"\n  exit \"$status\"\ndone",
            apply_invocation_with_redirection = apply_invocation_with_redirection
        )
    } else if operation == "apply" && provider == crate::config::Provider::Gcp {
        format!(
            "GCP_APPLY_MAX_ATTEMPTS=\"${{GREENTIC_GCP_APPLY_MAX_ATTEMPTS:-6}}\"\nGCP_APPLY_RETRY_DELAY_SECONDS=\"${{GREENTIC_GCP_APPLY_RETRY_DELAY_SECONDS:-20}}\"\nattempt=1\nwhile true; do\n  stdout_file=\"$(mktemp)\"\n  stderr_file=\"$(mktemp)\"\n  set +e\n{apply_invocation_with_redirection}\n  status=$?\n  set -e\n  cat \"$stdout_file\"\n  cat \"$stderr_file\" >&2\n  if [ \"$status\" -eq 0 ]; then\n    rm -f \"$stdout_file\" \"$stderr_file\"\n    break\n  fi\n  retry_reason=\"\"\n  if grep -q 'being deleted' \"$stderr_file\"; then\n    retry_reason='gcp resource is still being deleted'\n  elif grep -q 'already exists' \"$stderr_file\"; then\n    retry_reason='gcp resource name is still reserved while the previous deployment is converging'\n  elif grep -q 'operation is already in progress' \"$stderr_file\"; then\n    retry_reason='gcp control plane already has an operation in progress'\n  fi\n  if [ -n \"$retry_reason\" ] && [ \"$attempt\" -lt \"$GCP_APPLY_MAX_ATTEMPTS\" ]; then\n    echo \"GCP apply hit transient condition: $retry_reason; retrying in ${{GCP_APPLY_RETRY_DELAY_SECONDS}}s (attempt ${{attempt}}/${{GCP_APPLY_MAX_ATTEMPTS}})\" >&2\n    rm -f \"$stdout_file\" \"$stderr_file\" .terraform.tfstate.lock.info\n    sleep \"$GCP_APPLY_RETRY_DELAY_SECONDS\"\n    attempt=$((attempt + 1))\n    continue\n  fi\n  rm -f \"$stdout_file\" \"$stderr_file\"\n  exit \"$status\"\ndone",
            apply_invocation_with_redirection = apply_invocation_with_redirection
        )
    } else {
        apply_invocation
    };
    let hash_helper = terraform_hash_string_function();
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nTF_ROOT=\"${{SCRIPT_DIR}}/terraform\"\ncd \"$TF_ROOT\"\nTERRAFORM_BIN=\"terraform\"\nif [ -x \"$TF_ROOT/terraform\" ]; then\n  TERRAFORM_BIN=\"$TF_ROOT/terraform\"\nfi\nINIT_ARGS=(-input=false)\nif [ -f \"${{SCRIPT_DIR}}/backend.hcl\" ]; then\n  INIT_ARGS+=(\"-backend-config=${{SCRIPT_DIR}}/backend.hcl\")\nfi\n\"$TERRAFORM_BIN\" init \"${{INIT_ARGS[@]}}\"\n{hash_helper}VAR_FILE=\"\"\n{tfvars_lookup}\n{pre_apply_hook}{operation_block}\n"
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
    let hash_helper = terraform_hash_string_function();
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nTF_ROOT=\"${{SCRIPT_DIR}}/terraform\"\ncd \"$TF_ROOT\"\n{hash_helper}VAR_FILE=\"\"\n{tfvars_lookup}\nif ! command -v aws >/dev/null 2>&1; then\n  echo \"aws cli not found; skipping AWS cleanup fallback\"\n  exit 0\nfi\nBUNDLE_DIGEST=\"\"\nNAME_PREFIX=\"\"\nif [ -n \"$VAR_FILE\" ] && [ -f \"$VAR_FILE\" ]; then\n  BUNDLE_DIGEST=$(sed -n 's/^bundle_digest = \"\\(.*\\)\"$/\\1/p' \"$VAR_FILE\" | head -n 1)\n  NAME_PREFIX=$(sed -n 's/^deployment_name_prefix = \"\\(.*\\)\"$/\\1/p' \"$VAR_FILE\" | head -n 1)\nfi\nif [ -z \"$NAME_PREFIX\" ]; then\n  if [ -z \"$BUNDLE_DIGEST\" ]; then\n    echo \"bundle_digest not found; skipping AWS cleanup fallback\"\n    exit 0\n  fi\n  SHORT_ID=\"$(hash_string \"$BUNDLE_DIGEST\")\"\n  NAME_PREFIX=\"greentic-${{SHORT_ID}}\"\nfi\nAWS_REGION_VALUE=\"${{AWS_REGION:-${{AWS_DEFAULT_REGION:-}}}}\"\nif [ -z \"$AWS_REGION_VALUE\" ]; then\n  echo \"AWS region not set; skipping AWS cleanup fallback\"\n  exit 0\nfi\nSECRET_PREFIX=\"greentic/admin/${{NAME_PREFIX}}/\"\nLOG_GROUP=\"/greentic/demo/${{NAME_PREFIX}}\"\nROLE_NAME=\"${{NAME_PREFIX}}-task-exec\"\nCLUSTER_NAME=\"${{NAME_PREFIX}}-cluster\"\nSERVICE_NAME=\"${{NAME_PREFIX}}-service\"\nLB_NAME=\"${{NAME_PREFIX}}-alb\"\naws logs delete-log-group --region \"$AWS_REGION_VALUE\" --log-group-name \"$LOG_GROUP\" >/dev/null 2>&1 || true\nSECRET_ARNS=$(aws secretsmanager list-secrets --region \"$AWS_REGION_VALUE\" --filters Key=name,Values=\"$SECRET_PREFIX\" --query 'SecretList[].ARN' --output text 2>/dev/null || true)\nfor secret_arn in $SECRET_ARNS; do\n  aws secretsmanager delete-secret --region \"$AWS_REGION_VALUE\" --secret-id \"$secret_arn\" --force-delete-without-recovery >/dev/null 2>&1 || true\ndone\nINLINE_POLICIES=$(aws iam list-role-policies --role-name \"$ROLE_NAME\" --query 'PolicyNames[]' --output text 2>/dev/null || true)\nfor policy_name in $INLINE_POLICIES; do\n  aws iam delete-role-policy --role-name \"$ROLE_NAME\" --policy-name \"$policy_name\" >/dev/null 2>&1 || true\ndone\nATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name \"$ROLE_NAME\" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || true)\nfor policy_arn in $ATTACHED_POLICIES; do\n  aws iam detach-role-policy --role-name \"$ROLE_NAME\" --policy-arn \"$policy_arn\" >/dev/null 2>&1 || true\ndone\naws iam delete-role --role-name \"$ROLE_NAME\" >/dev/null 2>&1 || true\nLB_ARN=$(aws elbv2 describe-load-balancers --region \"$AWS_REGION_VALUE\" --names \"$LB_NAME\" --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)\nif [ -n \"$LB_ARN\" ] && [ \"$LB_ARN\" != \"None\" ]; then\n  aws elbv2 delete-load-balancer --region \"$AWS_REGION_VALUE\" --load-balancer-arn \"$LB_ARN\" >/dev/null 2>&1 || true\nfi\naws ecs update-service --region \"$AWS_REGION_VALUE\" --cluster \"$CLUSTER_NAME\" --service \"$SERVICE_NAME\" --desired-count 0 >/dev/null 2>&1 || true\naws ecs delete-service --region \"$AWS_REGION_VALUE\" --cluster \"$CLUSTER_NAME\" --service \"$SERVICE_NAME\" --force >/dev/null 2>&1 || true\naws ecs delete-cluster --region \"$AWS_REGION_VALUE\" --cluster \"$CLUSTER_NAME\" >/dev/null 2>&1 || true\n"
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
            .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
            .unwrap_or_else(|| "eu-north-1".to_string());
        let key = std::env::var("GREENTIC_TERRAFORM_BACKEND_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                let deployment_name_prefix = explicit_deployment_name_prefix()
                    .unwrap_or_else(|| stable_deployment_name_prefix(config));
                format!(
                    "greentic/{}/{}/{}/{}/terraform.tfstate",
                    config.provider.as_str(),
                    config.tenant,
                    config.environment,
                    deployment_name_prefix
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

fn normalize_terraform_main_tf(config: &DeployerConfig, terraform_root: &Path) -> Result<()> {
    // The `operator_image` local in main.tf decides which greentic-start image the
    // operator module runs. Older published deploy packs (e.g. the `:stable`
    // aws.gtpack) HARDCODE the GHCR image and never reference `var.operator_image`,
    // so the `GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE` override is silently
    // dropped (the tfvar is written but unused). Rewrite the `operator_image` local
    // on EVERY cloud target so the override always wins:
    //   - override set  -> force the literal image (works even when var.operator_image
    //                      is undeclared in an old pack).
    //   - override unset-> ensure the `var.operator_image != "" ? ...` conditional.
    // This was previously GCP-only, which is why AWS deploys ignored the override.
    let override_img = std::env::var("GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let main_tf_path = terraform_root.join("main.tf");
    if main_tf_path.exists() {
        let contents = fs::read_to_string(&main_tf_path)?;
        let mut rewritten = Vec::with_capacity(contents.lines().count() + 1);
        let mut changed = false;
        for line in contents.lines() {
            let trimmed = line.trim_start();
            let is_operator_image_local = trimmed.starts_with("operator_image")
                && trimmed.contains("ghcr.io/greenticai/greentic-start-distroless");
            if is_operator_image_local && let Some(eq) = line.find('=') {
                let lhs = &line[..=eq]; // keep original indentation + alignment
                if let Some(img) = &override_img {
                    rewritten.push(format!("{lhs} {}", serde_json::json!(img)));
                    changed = true;
                    continue;
                } else if !trimmed.contains("var.operator_image !=") {
                    rewritten.push(format!(
                        "{lhs} var.operator_image != \"\" ? var.operator_image : \"ghcr.io/greenticai/greentic-start-distroless@${{var.operator_image_digest}}\""
                    ));
                    changed = true;
                    continue;
                }
            }
            rewritten.push(line.to_string());
        }
        if changed {
            fs::write(&main_tf_path, rewritten.join("\n") + "\n")?;
        }
    }

    if config.provider == crate::config::Provider::Gcp {
        normalize_gcp_operator_module_main_tf(terraform_root)?;
    }
    Ok(())
}

fn normalize_gcp_operator_module_main_tf(terraform_root: &Path) -> Result<()> {
    let module_main_tf_path = terraform_root.join("modules/operator-gcp/main.tf");
    if !module_main_tf_path.exists() {
        return Ok(());
    }

    let mut contents = fs::read_to_string(&module_main_tf_path)?;
    contents = contents.replace(
        r#"        name  = "GREENTIC_ADMIN_CA_SECRET_REF"
        value = google_secret_manager_secret.admin_ca.id"#,
        r#"        name  = "GREENTIC_ADMIN_CA_PEM"
        value = tls_self_signed_cert.admin_ca.cert_pem"#,
    );
    contents = contents.replace(
        r#"        name  = "GREENTIC_ADMIN_SERVER_CERT_SECRET_REF"
        value = google_secret_manager_secret.admin_server_cert.id"#,
        r#"        name  = "GREENTIC_ADMIN_SERVER_CERT_PEM"
        value = tls_locally_signed_cert.admin_server.cert_pem"#,
    );
    contents = contents.replace(
        r#"        name  = "GREENTIC_ADMIN_SERVER_KEY_SECRET_REF"
        value = google_secret_manager_secret.admin_server_key.id"#,
        r#"        name  = "GREENTIC_ADMIN_SERVER_KEY_PEM"
        value = tls_private_key.admin_server.private_key_pem"#,
    );
    contents = contents.replace(
        "  ingress  = \"INGRESS_TRAFFIC_ALL\"\n\n  template {",
        "  ingress  = \"INGRESS_TRAFFIC_ALL\"\n  deletion_protection = false\n\n  template {",
    );

    for snippet in [
        r#"
      env {
        name = "GREENTIC_ADMIN_CA_PEM"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.admin_ca.secret_id
            version = "latest"
          }
        }
      }
"#,
        r#"
      env {
        name = "GREENTIC_ADMIN_SERVER_CERT_PEM"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.admin_server_cert.secret_id
            version = "latest"
          }
        }
      }
"#,
        r#"
      env {
        name = "GREENTIC_ADMIN_SERVER_KEY_PEM"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.admin_server_key.secret_id
            version = "latest"
          }
        }
      }
"#,
        r#"
resource "google_service_account" "runtime" {
  project      = var.gcp_project_id
  account_id   = "${local.name_prefix}-run"
  display_name = "Greentic runtime"
}
"#,
        r#"
resource "google_secret_manager_secret_iam_member" "runtime_admin_ca_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.admin_ca.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}
"#,
        r#"
resource "google_secret_manager_secret_iam_member" "runtime_admin_server_cert_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.admin_server_cert.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}
"#,
        r#"
resource "google_secret_manager_secret_iam_member" "runtime_admin_server_key_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.admin_server_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}
"#,
        r#"
resource "google_secret_manager_secret_iam_member" "runtime_admin_ca_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.admin_ca.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.runtime_service_account_email}"
}
"#,
        r#"
resource "google_secret_manager_secret_iam_member" "runtime_admin_server_cert_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.admin_server_cert.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.runtime_service_account_email}"
}
"#,
        r#"
resource "google_secret_manager_secret_iam_member" "runtime_admin_server_key_accessor" {
  project   = var.gcp_project_id
  secret_id = google_secret_manager_secret.admin_server_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.runtime_service_account_email}"
}
"#,
        r#"  project_number                = split("/", google_secret_manager_secret.admin_ca.id)[1]
  runtime_service_account_email = "${local.project_number}-compute@developer.gserviceaccount.com"
"#,
        r#"  depends_on = [
    google_secret_manager_secret_iam_member.runtime_admin_ca_accessor,
    google_secret_manager_secret_iam_member.runtime_admin_server_cert_accessor,
    google_secret_manager_secret_iam_member.runtime_admin_server_key_accessor,
  ]
"#,
        r#"    service_account = google_service_account.runtime.email
"#,
    ] {
        contents = contents.replace(snippet, "");
    }

    fs::write(module_main_tf_path, contents)?;
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
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| DeployerError::Other(format!("invalid script path {}", path.display())))?;
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp"));
    fs::write(&tmp_path, contents)?;
    set_executable_if_unix(&tmp_path)?;
    fs::rename(&tmp_path, path)?;
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
    handler_id: String,
    pack_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeployerInvocation {
    capability: String,
    pack_id: String,
    flow_id: String,
    handler_id: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    secrets_provider_binding: Option<String>,
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
        handler_id: selection.dispatch.handler_id.clone(),
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
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
            agents: Default::default(),
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
                handler_id: "builtin.aws".into(),
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
            "builtin.aws",
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
                handler_id: "builtin.aws".into(),
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
            "builtin.aws",
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
                handler_id: "builtin.aws".into(),
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
            "builtin.aws",
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
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
                handler_id: "builtin.terraform".into(),
            },
            pack_path,
            manifest: PackManifest {
                agents: Default::default(),
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
    fn secrets_provider_binding_maps_targets_to_provider_packs() {
        let pack_path = PathBuf::from("/tmp/provider.gtpack");
        let mut config = config_for(pack_path, DeployerCapability::Apply);
        config.tenant = "demo".into();
        config.environment = "dev".into();

        let cases = [
            (
                Provider::Aws,
                "greentic.secrets.aws-sm",
                "providers/secrets/aws-sm.gtpack",
            ),
            (
                Provider::Gcp,
                "greentic.secrets.gcp-sm",
                "providers/secrets/gcp-sm.gtpack",
            ),
            (
                Provider::Azure,
                "greentic.secrets.azure-kv",
                "providers/secrets/azure-kv.gtpack",
            ),
            (
                Provider::Local,
                "greentic.secrets.dev",
                "providers/secrets/dev.gtpack",
            ),
        ];

        for (provider, provider_id, pack) in cases {
            config.provider = provider;
            let binding = secrets_provider_binding_for_target(&config).expect("binding for target");
            assert_eq!(
                binding.schema_version,
                SECRETS_PROVIDER_BINDING_SCHEMA_VERSION
            );
            assert_eq!(binding.provider_id, provider_id);
            assert_eq!(binding.pack, pack);
            assert_eq!(
                binding.config.get("environment").map(String::as_str),
                Some("dev")
            );
            assert_eq!(
                binding.config.get("tenant").map(String::as_str),
                Some("demo")
            );
            assert_eq!(binding.config.get("team").map(String::as_str), Some("_"));
            assert_eq!(
                binding.config.get("namespace_prefix").map(String::as_str),
                Some("greentic/dev/demo/_")
            );
            assert_eq!(
                binding.config.get("prefix").map(String::as_str),
                Some("greentic/dev/demo/_")
            );
        }

        config.provider = Provider::Generic;
        assert!(secrets_provider_binding_for_target(&config).is_none());
    }

    #[test]
    fn persist_runtime_artifacts_materializes_aws_secrets_provider_binding() {
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
        let bundle_root_dir = dir.path().join("bundle");
        std::fs::create_dir_all(&bundle_root_dir).expect("create bundle root");

        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "demo".into(),
            environment: "dev".into(),
            pack_path: Some(pack_path.clone()),
            bundle_root: Some(bundle_root_dir.clone()),
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
            bundle_source: Some("s3://bucket/bundle.gtbundle".into()),
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
                pack_id: "greentic.deploy.aws".into(),
                flow_id: "plan_pack".into(),
                handler_id: "builtin.aws".into(),
            },
            pack_path,
            manifest: PackManifest {
                schema_version: "pack-v1".to_string(),
                pack_id: PackId::from_str("greentic.deploy.aws").unwrap(),
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
                agents: Default::default(),
            },
            origin: "test".into(),
            candidates: Vec::new(),
        };

        let artifacts = persist_runtime_artifacts(&config, &plan, &selection, &deploy_dir)
            .expect("persist runtime artifacts");
        let binding_path = artifacts
            .deploy_dir
            .join(SECRETS_PROVIDER_BINDING_RELATIVE_PATH);
        let binding: SecretsProviderBinding = serde_json::from_slice(
            &std::fs::read(&binding_path).expect("read secrets provider binding"),
        )
        .expect("parse secrets provider binding");

        assert_eq!(binding.schema_version, "greentic.secrets.binding.v1");
        assert_eq!(binding.provider_id, "greentic.secrets.aws-sm");
        assert_eq!(binding.pack, "providers/secrets/aws-sm.gtpack");
        assert_eq!(
            binding.config.get("namespace_prefix").map(String::as_str),
            Some("greentic/dev/demo/_")
        );
        let metadata: TerraformRuntimeMetadata = serde_json::from_slice(
            &std::fs::read(artifacts.deploy_dir.join("terraform-runtime.json"))
                .expect("read terraform runtime metadata"),
        )
        .expect("parse terraform runtime metadata");
        assert_eq!(
            metadata.secrets_provider_binding.as_deref(),
            Some(SECRETS_PROVIDER_BINDING_RELATIVE_PATH)
        );
        let note = std::fs::read_to_string(artifacts.deploy_dir.join("terraform-handoff.txt"))
            .expect("read terraform handoff note");
        assert!(note.contains("secrets_provider_binding="));

        // The binding must ALSO land in the bundle root, so the rebuilt
        // .gtbundle artifact the worker loads contains it — not only the deploy
        // output. Regression for the cloud secrets-binding handoff gap (#311).
        let bundle_binding: SecretsProviderBinding = serde_json::from_slice(
            &std::fs::read(bundle_root_dir.join(SECRETS_PROVIDER_BINDING_RELATIVE_PATH))
                .expect("read bundle-root secrets provider binding"),
        )
        .expect("parse bundle-root secrets provider binding");
        assert_eq!(bundle_binding.provider_id, "greentic.secrets.aws-sm");
        assert_eq!(bundle_binding.pack, "providers/secrets/aws-sm.gtpack");
    }

    #[test]
    fn terraform_apply_script_for_azure_imports_existing_resources() {
        let rendered = terraform_plan_like_script(
            "apply",
            Provider::Azure,
            Some("dev.tfvars"),
            "staging.tfvars.example",
        );
        assert!(rendered.contains("az keyvault secret show"));
        assert!(rendered.contains("azurerm_container_app_environment.this"));
        assert!(rendered.contains("azurerm_container_app.this"));
        assert!(rendered.contains("module.operator_azure[0]"));
        assert!(rendered.contains("module.operator"));
        assert!(rendered.contains("import -input=false"));
    }

    #[test]
    fn terraform_apply_script_for_gcp_imports_existing_secrets() {
        let rendered = terraform_plan_like_script(
            "apply",
            Provider::Gcp,
            Some("dev.tfvars"),
            "staging.tfvars.example",
        );
        assert!(rendered.contains("gcloud secrets describe"));
        assert!(rendered.contains("google_secret_manager_secret.admin_ca"));
        assert!(rendered.contains("google_secret_manager_secret.admin_server_cert"));
        assert!(rendered.contains("google_secret_manager_secret.admin_server_key"));
        assert!(rendered.contains("gcloud run services describe"));
        assert!(rendered.contains("google_cloud_run_v2_service.this"));
        assert!(rendered.contains("module.operator_gcp[0]"));
        assert!(rendered.contains("import -input=false"));
        assert!(rendered.contains("GCP apply hit transient condition"));
    }

    #[test]
    fn normalize_terraform_main_tf_for_gcp_respects_operator_image_override() {
        let dir = tempfile::tempdir().expect("tempdir");
        let terraform_root = dir.path().join("terraform");
        std::fs::create_dir_all(&terraform_root).expect("terraform root");
        let main_tf = terraform_root.join("main.tf");
        std::fs::write(
            &main_tf,
            r#"
module "operator" {
  source = "./modules/operator-gcp"
  operator_image        = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
}
"#,
        )
        .expect("write main.tf");

        let config = DeployerConfig {
            provider: Provider::Gcp,
            ..config_for(terraform_root.clone(), DeployerCapability::Apply)
        };
        normalize_terraform_main_tf(&config, &terraform_root).expect("normalize main.tf");

        let rendered = std::fs::read_to_string(main_tf).expect("read main.tf");
        assert!(rendered.contains(
            r#"operator_image        = var.operator_image != "" ? var.operator_image : "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}""#
        ));
    }

    #[test]
    fn normalize_terraform_main_tf_for_gcp_switches_operator_module_to_direct_pem_envs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let terraform_root = dir.path().join("terraform");
        let module_root = terraform_root.join("modules/operator-gcp");
        std::fs::create_dir_all(&module_root).expect("module root");
        let main_tf = terraform_root.join("main.tf");
        std::fs::write(
            &main_tf,
            r#"
module "operator" {
  source = "./modules/operator-gcp"
  operator_image        = var.operator_image != "" ? var.operator_image : "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
}
"#,
        )
        .expect("write main.tf");
        let module_main_tf = module_root.join("main.tf");
        std::fs::write(
            &module_main_tf,
            r#"
resource "google_secret_manager_secret_version" "admin_server_key" {
  secret      = google_secret_manager_secret.admin_server_key.id
  secret_data = tls_private_key.admin_server.private_key_pem
}

resource "google_cloud_run_v2_service" "this" {
  name     = local.service_name
  location = var.gcp_region
  project  = var.gcp_project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    env {
        name  = "GREENTIC_ADMIN_CA_SECRET_REF"
        value = google_secret_manager_secret.admin_ca.id
    }

    env {
        name  = "GREENTIC_ADMIN_SERVER_CERT_SECRET_REF"
        value = google_secret_manager_secret.admin_server_cert.id
    }

    env {
        name  = "GREENTIC_ADMIN_SERVER_KEY_SECRET_REF"
        value = google_secret_manager_secret.admin_server_key.id
    }
  }
}
"#,
        )
        .expect("write module main.tf");

        let config = DeployerConfig {
            provider: Provider::Gcp,
            ..config_for(terraform_root.clone(), DeployerCapability::Apply)
        };
        normalize_terraform_main_tf(&config, &terraform_root).expect("normalize main.tf");

        let rendered = std::fs::read_to_string(module_main_tf).expect("read module main.tf");
        assert!(rendered.contains("GREENTIC_ADMIN_CA_PEM"));
        assert!(rendered.contains("tls_self_signed_cert.admin_ca.cert_pem"));
        assert!(rendered.contains("GREENTIC_ADMIN_SERVER_CERT_PEM"));
        assert!(rendered.contains("tls_locally_signed_cert.admin_server.cert_pem"));
        assert!(rendered.contains("GREENTIC_ADMIN_SERVER_KEY_PEM"));
        assert!(rendered.contains("tls_private_key.admin_server.private_key_pem"));
        assert!(!rendered.contains("GREENTIC_ADMIN_CA_SECRET_REF"));
        assert!(!rendered.contains("runtime_admin_ca_accessor"));
    }

    #[test]
    fn terraform_apply_script_for_aws_imports_existing_fixed_name_resources() {
        let rendered = terraform_plan_like_script(
            "apply",
            Provider::Aws,
            Some("dev.tfvars"),
            "staging.tfvars.example",
        );
        assert!(rendered.contains("module.operator_aws[0]"));
        assert!(rendered.contains("aws ec2 describe-security-groups"));
        assert!(rendered.contains("aws elbv2 describe-load-balancers"));
        assert!(rendered.contains("aws elbv2 describe-listeners"));
        assert!(rendered.contains("aws_lb_listener.http"));
        assert!(rendered.contains("aws ecs describe-clusters"));
        assert!(rendered.contains("aws ecs describe-services"));
        assert!(rendered.contains("aws_cloudwatch_log_group.this"));
        assert!(rendered.contains("aws_iam_role.task_execution"));
        assert!(rendered.contains("AWS apply hit transient condition"));
        assert!(rendered.contains("INIT_ARGS=(-input=false)"));
        assert!(rendered.contains("\"$TERRAFORM_BIN\" init \"${INIT_ARGS[@]}\""));
        assert!(!rendered.contains("BACKEND_ARGS"));
        assert!(rendered.contains("hash_string()"));
        assert!(rendered.contains("command -v md5sum"));
        assert!(rendered.contains("md5 -q"));
        assert!(rendered.contains("SHORT_ID=\"$(hash_string \"$BUNDLE_DIGEST_VALUE\")\""));
        assert!(!rendered.contains("SHORT_ID=$(printf '%s' \"$BUNDLE_DIGEST_VALUE\" | md5sum"));
    }

    #[test]
    fn prune_generated_terraform_root_for_aws_includes_tenant_argument() {
        let dir = tempfile::tempdir().expect("tempdir");
        let terraform_root = dir.path().join("terraform");
        std::fs::create_dir_all(&terraform_root).expect("terraform root");
        std::fs::create_dir_all(terraform_root.join("modules/operator")).expect("module root");
        std::fs::write(terraform_root.join("variables.tf"), "").expect("write variables.tf");
        std::fs::write(terraform_root.join("modules/operator/variables.tf"), "")
            .expect("write module variables.tf");
        std::fs::write(
            terraform_root.join("modules/operator/main.tf"),
            r#"resource "aws_iam_role_policy" "task_execution_ecs_exec" {
  name = "${local.name_prefix}-task-exec-ecs-exec"
  role = aws_iam_role.task_execution.id
}

resource "aws_ecs_task_definition" "this" {
  container_definitions = jsonencode([
    {
      environment = concat(
        [
          {
            name  = "GREENTIC_BUNDLE_SOURCE"
            value = var.bundle_source
          }
        ],
        [
          {
            name  = "PUBLIC_BASE_URL"
            value = local.effective_public_base_url
          }
        ]
      )
    }
  ])
}

data "aws_region" "current" {}
"#,
        )
        .expect("write module main.tf");

        let config = DeployerConfig {
            provider: Provider::Aws,
            ..config_for(terraform_root.clone(), DeployerCapability::Apply)
        };

        prune_generated_terraform_root(&config, &terraform_root).expect("prune terraform root");

        let rendered =
            std::fs::read_to_string(terraform_root.join("main.tf")).expect("read main.tf");
        assert!(rendered.contains(r#"tenant                = var.tenant"#));
        let variables =
            std::fs::read_to_string(terraform_root.join("variables.tf")).expect("read variables");
        assert!(variables.contains(r#"variable "bundle_s3_object_ref""#));
        assert!(variables.contains(r#"variable "bundle_s3_object_arn""#));
        assert!(variables.contains(r#"variable "runtime_secret_prefix""#));
        let module_variables =
            std::fs::read_to_string(terraform_root.join("modules/operator/variables.tf"))
                .expect("read module variables");
        assert!(module_variables.contains(r#"variable "bundle_s3_object_ref""#));
        assert!(module_variables.contains(r#"variable "bundle_s3_object_arn""#));
        assert!(module_variables.contains(r#"variable "runtime_secret_prefix""#));
        let module_main = std::fs::read_to_string(terraform_root.join("modules/operator/main.tf"))
            .expect("read module main");
        assert!(!module_main.contains("GREENTIC_SECRETS_BACKEND"));
        assert!(!module_main.contains("GREENTIC_ALLOW_ENV_SECRETS"));
        assert!(!module_main.contains("for name, secret_name in var.runtime_secret_env"));
        assert!(module_main.contains("task_runtime_secrets"));
        assert!(module_main.contains("task_bundle_s3_object"));
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
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
                handler_id: "builtin.terraform".into(),
            },
            pack_path,
            manifest: PackManifest {
                agents: Default::default(),
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
        assert!(cleanup.contains("hash_string()"));
        assert!(cleanup.contains("md5 -q"));
        assert!(cleanup.contains("SHORT_ID=\"$(hash_string \"$BUNDLE_DIGEST\")\""));
        assert!(!cleanup.contains("SHORT_ID=$(printf '%s' \"$BUNDLE_DIGEST\" | md5sum"));
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
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "acme".into(),
            environment: "dev".into(),
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
                handler_id: "builtin.terraform".into(),
            },
            pack_path,
            manifest: PackManifest {
                agents: Default::default(),
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
        let generated = std::fs::read_to_string(artifacts.deploy_dir.join("terraform/dev.tfvars"))
            .expect("read generated tfvars");
        assert!(generated.contains("cloud = \"aws\""));
        assert!(generated.contains("environment = \"dev\""));
        assert!(generated.contains("deployment_name_prefix = \"greentic-"));
        assert!(generated.contains("bundle_source = \"file:///tmp/demo.gtbundle\""));
        assert!(generated.contains(
            "bundle_digest = \"sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\""
        ));
        assert!(generated.contains(&format!(
            "operator_image_digest = \"{}\"",
            crate::contract::DEFAULT_OPERATOR_IMAGE_DIGEST
        )));
        assert!(!generated.contains(
            "operator_image_digest = \"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""
        ));

        let destroy_script =
            std::fs::read_to_string(artifacts.deploy_dir.join("terraform-destroy.sh"))
                .expect("read destroy script");
        assert!(destroy_script.contains("VAR_FILE=\"dev.tfvars\""));
        assert!(destroy_script.contains("elif [ -f \"staging.tfvars.example\" ]; then"));
    }

    #[test]
    fn generated_tfvars_ignores_legacy_bundle_digest_prefix_for_new_cloud_identity() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let terraform_root = dir.path().join("terraform");
        std::fs::create_dir_all(&terraform_root).expect("create terraform dir");
        std::fs::write(
            terraform_root.join("staging.tfvars.example"),
            "cloud = \"aws\"\nenvironment = \"staging\"\n",
        )
        .expect("write example");
        std::fs::write(
            terraform_root.join("dev.tfvars"),
            "bundle_digest = \"sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\"\n",
        )
        .expect("write existing tfvars");

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
            environment: "dev".into(),
            pack_path: Some(dir.path().join("bundle")),
            bundle_root: None,
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
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
            bundle_source: Some("file:///tmp/demo-v2.gtbundle".into()),
            bundle_digest: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
            repo_registry_base: None,
            store_registry_base: None,
        };
        let legacy_shared_prefix = legacy_shared_deployment_name_prefix(&config);
        std::fs::write(
            terraform_root.join("dev.tfvars"),
            format!(
                "deployment_name_prefix = \"{legacy_shared_prefix}\"\nbundle_digest = \"sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\"\n"
            ),
        )
        .expect("write existing tfvars");

        let generated =
            materialize_generated_tfvars(&config, &terraform_root, "staging.tfvars.example")
                .expect("generate tfvars")
                .expect("generated filename");
        let contents =
            std::fs::read_to_string(terraform_root.join(generated)).expect("read generated tfvars");
        assert!(contents.contains("deployment_name_prefix = \"greentic-"));
        assert!(!contents.contains(&format!(
            "deployment_name_prefix = \"{legacy_shared_prefix}\""
        )));
    }

    #[test]
    fn generated_aws_tfvars_omit_runtime_secret_env_when_provider_binding_exists() {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let bundle_root = dir.path();
        let terraform_root = bundle_root.join("terraform");
        std::fs::create_dir_all(&terraform_root).expect("terraform root");
        std::fs::write(
            terraform_root.join("staging.tfvars.example"),
            r#"
cloud = "aws"
tenant = "demo"
environment = "dev"
runtime_secret_env = {}
"#,
        )
        .expect("write tfvars example");

        let pack_path = bundle_root.join("packs/messaging-webchat-gui");
        std::fs::create_dir_all(&pack_path).expect("pack dir");
        std::fs::write(
            pack_path.join("pack.manifest.json"),
            r#"{
  "extensions": {
    "greentic.generated-secrets.v1": {
      "inline": {
        "secrets": [{
          "key": "jwt_signing_key",
          "required": true,
          "policy": "random",
          "length": 20,
          "encoding": "raw_text",
          "scope": {"level": "tenant", "team": "_"}
        }]
      }
    }
  }
}"#,
        )
        .expect("write manifest");

        let config = DeployerConfig {
            provider: Provider::Aws,
            tenant: "demo".into(),
            environment: "dev".into(),
            pack_path: Some(pack_path.clone()),
            bundle_root: Some(bundle_root.to_path_buf()),
            provider_pack: None,
            bundle_source: Some("s3://bucket/bundle.gtbundle".into()),
            ..config_for(pack_path, DeployerCapability::Apply)
        };

        let generated =
            materialize_generated_tfvars(&config, &terraform_root, "staging.tfvars.example")
                .expect("generate tfvars")
                .expect("tfvars generated");
        let contents =
            std::fs::read_to_string(terraform_root.join(generated)).expect("read generated tfvars");

        assert!(contents.contains("runtime_secret_env = {}"));
        assert!(!contents.contains("GREENTIC_SECRET__"));
        assert!(!contents.contains("\"jwt_signing_key\""));
        assert!(
            !contents.contains("\"secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key\""),
            "runtime_secret_env must not include runtime secret aliases when provider binding is present: {contents}"
        );
    }

    #[test]
    fn deployment_name_prefix_normalization_keeps_cloud_names_bounded() {
        assert_eq!(
            normalize_deployment_name_prefix(" Maarten/Deep Research Demo!!! "),
            "maarten-deep-research-de"
        );
        assert_eq!(
            normalize_deployment_name_prefix("123-dev"),
            "greentic-123-dev"
        );
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
                secrets_provider_binding: None,
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
            handler_id: "builtin.terraform".into(),
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
        assert!(rendered.contains("handler_id=builtin.terraform"));
        assert!(
            rendered.contains("terraform_runtime.copied_files=main.tf, modules/operator/main.tf")
        );
        assert!(rendered.contains("terraform_runtime.status_command=./terraform-status.sh"));
    }

    #[test]
    fn render_operation_result_text_summarizes_apply_success_with_webchat_url() {
        let rendered = render_operation_result_text(&OperationResult {
            capability: "apply".into(),
            executed: true,
            preview: false,
            output_dir: "/tmp/deploy".into(),
            plan_path: "/tmp/plan.json".into(),
            invoke_path: "/tmp/invoke.json".into(),
            pack_id: "greentic.deploy.aws".into(),
            flow_id: "apply_terraform".into(),
            handler_id: "pack.greentic.deploy.aws".into(),
            pack_path: "/tmp/aws.gtpack".into(),
            contract: None,
            capability_contract: None,
            payload: Some(OperationPayload::Apply(Box::new(ApplyPayload {
                capability: "apply".into(),
                provider: "aws".into(),
                strategy: "iac-only".into(),
                pack_id: "greentic.deploy.aws".into(),
                flow_id: "apply_terraform".into(),
                output_dir: "/tmp/deploy".into(),
                plan_path: "/tmp/plan.json".into(),
                invoke_path: "/tmp/invoke.json".into(),
                runner_cmd: vec![],
                runner_env: vec![("GREENTIC_TENANT".into(), "demo".into())],
            }))),
            output_validation: None,
            execution: Some(ExecutionReport {
                output_dir: "/tmp/deploy".into(),
                plan_path: "/tmp/plan.json".into(),
                invoke_path: "/tmp/invoke.json".into(),
                handoff_path: "/tmp/handoff.json".into(),
                runner_command_path: "/tmp/runner.txt".into(),
                handler_id: "pack.greentic.deploy.aws".into(),
                status: Some("applied".into()),
                message: None,
                output_files: vec![],
                outcome_payload: Some(ExecutionOutcomePayload::Apply(
                    crate::deployment::ApplyExecutionOutcome {
                        deployment_id: "/tmp/deploy".into(),
                        state: "applied".into(),
                        provider: Some("aws".into()),
                        strategy: Some("iac-only".into()),
                        endpoints: vec!["http://greentic.example.elb.amazonaws.com".into()],
                        output_refs: BTreeMap::new(),
                    },
                )),
                outcome_validation: None,
            }),
        });

        assert_eq!(
            rendered,
            "http://greentic.example.elb.amazonaws.com/v1/web/webchat/demo/\n"
        );
        assert!(!rendered.contains("capability=apply"));
    }

    #[test]
    fn render_operation_result_json_summarizes_apply_success_with_webchat_url() {
        let rendered = render_operation_result(
            &OperationResult {
                capability: "apply".into(),
                executed: true,
                preview: false,
                output_dir: "/tmp/deploy".into(),
                plan_path: "/tmp/plan.json".into(),
                invoke_path: "/tmp/invoke.json".into(),
                pack_id: "greentic.deploy.aws".into(),
                flow_id: "apply_terraform".into(),
                handler_id: "pack.greentic.deploy.aws".into(),
                pack_path: "/tmp/aws.gtpack".into(),
                contract: None,
                capability_contract: None,
                payload: Some(OperationPayload::Apply(Box::new(ApplyPayload {
                    capability: "apply".into(),
                    provider: "aws".into(),
                    strategy: "iac-only".into(),
                    pack_id: "greentic.deploy.aws".into(),
                    flow_id: "apply_terraform".into(),
                    output_dir: "/tmp/deploy".into(),
                    plan_path: "/tmp/plan.json".into(),
                    invoke_path: "/tmp/invoke.json".into(),
                    runner_cmd: vec![],
                    runner_env: vec![("GREENTIC_TENANT".into(), "demo".into())],
                }))),
                output_validation: None,
                execution: Some(ExecutionReport {
                    output_dir: "/tmp/deploy".into(),
                    plan_path: "/tmp/plan.json".into(),
                    invoke_path: "/tmp/invoke.json".into(),
                    handoff_path: "/tmp/handoff.json".into(),
                    runner_command_path: "/tmp/runner.txt".into(),
                    handler_id: "pack.greentic.deploy.aws".into(),
                    status: Some("applied".into()),
                    message: None,
                    output_files: vec![],
                    outcome_payload: Some(ExecutionOutcomePayload::Apply(
                        crate::deployment::ApplyExecutionOutcome {
                            deployment_id: "/tmp/deploy".into(),
                            state: "applied".into(),
                            provider: Some("aws".into()),
                            strategy: Some("iac-only".into()),
                            endpoints: vec!["http://greentic.example.elb.amazonaws.com".into()],
                            output_refs: BTreeMap::new(),
                        },
                    )),
                    outcome_validation: None,
                }),
            },
            OutputFormat::Json,
        )
        .expect("render json");

        assert_eq!(
            rendered,
            "{\n  \"webchat_url\": \"http://greentic.example.elb.amazonaws.com/v1/web/webchat/demo/\"\n}"
        );
        assert!(!rendered.contains("contract"));
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
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
                handler_id: "builtin.k8s_raw".into(),
            },
            pack_path,
            manifest: PackManifest {
                agents: Default::default(),
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
            pack_path: Some(pack_path.clone()),
            bundle_root: None,
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
                handler_id: "builtin.helm".into(),
            },
            pack_path,
            manifest: PackManifest {
                agents: Default::default(),
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

    // ------------------------------------------------------------------
    // PR-08 — operator secrets map tfvar emission
    // ------------------------------------------------------------------

    #[test]
    fn render_terraform_map_emits_quoted_key_value_pairs() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "secrets://dev/demo/_/messaging-webchat/jwt_signing_key".to_string(),
            "secret-value".to_string(),
        );
        map.insert(
            "secrets://dev/demo/_/deep-research-demo/api_key_secret".to_string(),
            "another".to_string(),
        );

        let rendered = render_terraform_map(&map);

        assert!(rendered.starts_with("{\n"));
        assert!(rendered.ends_with('}'));
        // BTreeMap iterates sorted, so the api_key entry lands first.
        assert!(
            rendered.contains(
                "\"secrets://dev/demo/_/deep-research-demo/api_key_secret\" = \"another\""
            ),
            "rendered map should contain canonical URI as key: {rendered}"
        );
        assert!(rendered.contains(
            "\"secrets://dev/demo/_/messaging-webchat/jwt_signing_key\" = \"secret-value\""
        ));
    }

    #[test]
    fn render_terraform_map_escapes_special_characters() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "k".to_string(),
            "value with \"quotes\" and \\backslash".to_string(),
        );
        let rendered = render_terraform_map(&map);
        // JSON-style escapes survive into the HCL literal.
        assert!(
            rendered.contains(r#"value with \"quotes\" and \\backslash"#),
            "escapes preserved: {rendered}"
        );
    }

    #[test]
    fn replace_tfvars_assignment_literal_inserts_new_map_assignment() {
        let mut contents = String::from("cloud = \"aws\"\ntenant = \"demo\"\n");
        let map_literal = "{\n  \"k\" = \"v\"\n}";
        replace_tfvars_assignment_literal(&mut contents, "secrets_map", map_literal);
        assert!(contents.contains("secrets_map = {\n  \"k\" = \"v\"\n}"));
        assert!(contents.contains("cloud = \"aws\""));
        assert!(contents.contains("tenant = \"demo\""));
    }

    #[test]
    fn replace_tfvars_assignment_literal_replaces_existing_multiline_map() {
        // A previous deploy emitted a 3-line map; the next emit must replace
        // both the assignment and the continuation lines so the file does
        // not accumulate duplicate entries.
        let mut contents = String::from(
            "cloud = \"aws\"\nsecrets_map = {\n  \"old\" = \"old\"\n}\ntenant = \"demo\"\n",
        );
        let new_literal = "{\n  \"new\" = \"value\"\n}";
        replace_tfvars_assignment_literal(&mut contents, "secrets_map", new_literal);
        assert!(contents.contains("secrets_map = {\n  \"new\" = \"value\"\n}"));
        assert!(!contents.contains("\"old\""));
        assert_eq!(contents.matches("secrets_map = ").count(), 1);
        assert!(contents.contains("tenant = \"demo\""));
    }
}
