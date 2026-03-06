use std::fs;
use std::path::{Path, PathBuf};

use tracing::{info, info_span};

use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::config::{DeployerConfig, OutputFormat};
use crate::contract::{
    DeployerCapability, ResolvedCapabilityContract, ResolvedDeployerContract,
    resolve_deployer_contract_assets,
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
    let runtime_dir = config
        .greentic
        .paths
        .state_dir
        .join("runtime")
        .join(&config.tenant)
        .join(&config.environment);
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
    use crate::deployment::clear_deployment_executor;
    use greentic_types::cbor::encode_pack_manifest;
    use greentic_types::component::{ComponentCapabilities, ComponentManifest, ComponentProfiles};
    use greentic_types::flow::{Flow, FlowHasher, FlowKind, FlowMetadata};
    use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest};
    use greentic_types::{ComponentId, FlowId, PackId};
    use indexmap::IndexMap;
    use once_cell::sync::Lazy;
    use semver::Version;
    use std::path::PathBuf;
    use std::str::FromStr;
    use tar::Builder;
    use tokio::sync::Mutex;

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
            output: crate::config::OutputFormat::Json,
            greentic: greentic_config::ConfigResolver::new()
                .load()
                .expect("load default config")
                .config,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
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
                "assets/schemas/apply-execution-output.schema.json",
                br#"{"type":"object","required":["kind","deployment_id","state","endpoints"],"properties":{"kind":{"const":"apply"},"deployment_id":{"type":"string"},"state":{"type":"string"},"endpoints":{"type":"array","items":{"type":"string"}}}}"#,
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
                br#"{"type":"object","required":["kind","deployment_id","state","health_checks"],"properties":{"kind":{"const":"status"},"deployment_id":{"type":"string"},"state":{"type":"string"},"health_checks":{"type":"array","items":{"type":"string"}}}}"#,
            );
            append_tar_entry(
                &mut builder,
                "assets/schemas/rollback-output.schema.json",
                br#"{"type":"object","required":["kind","capability","provider","strategy","pack_id","flow_id","target_capability"],"properties":{"kind":{"const":"rollback"},"capability":{"const":"rollback"},"provider":{"type":"string"},"strategy":{"type":"string"},"pack_id":{"type":"string"},"flow_id":{"type":"string"},"target_capability":{"const":"apply"}}}"#,
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
                        "endpoints": { "type": "array", "items": { "type": "string" } }
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
                        endpoints: vec!["https://ready.example.test".into()],
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
                    "required": ["kind", "deployment_id", "state"],
                    "properties": {
                        "kind": { "const": "destroy" },
                        "deployment_id": { "type": "string" },
                        "state": { "type": "string" }
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
                        "health_checks": { "type": "array", "items": { "type": "string" } }
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
                        health_checks: vec!["http:ok".into()],
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
        let _guard = TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(true);
        let result = run(config_for(pack_path, DeployerCapability::Plan))
            .await
            .expect("plan runs");
        match result.payload.expect("payload") {
            OperationPayload::Plan(payload) => {
                assert_eq!(payload.plan.plan.tenant, "acme");
                assert!(payload.rendered_output.is_some());
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert!(result.output_validation.as_ref().expect("validation").valid);
    }

    #[tokio::test]
    async fn plan_result_without_contract_schema_skips_validation() {
        let _guard = TEST_LOCK.lock().await;
        clear_deployment_executor();
        let pack_path = write_test_pack(false);
        let result = run(config_for(pack_path, DeployerCapability::Plan))
            .await
            .expect("plan runs");
        assert!(result.output_validation.is_none());
    }

    #[tokio::test]
    async fn generate_result_contains_capability_payload() {
        let _guard = TEST_LOCK.lock().await;
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
        let _guard = TEST_LOCK.lock().await;
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
        let _guard = TEST_LOCK.lock().await;
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
        let _guard = TEST_LOCK.lock().await;
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
        let _guard = TEST_LOCK.lock().await;
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
