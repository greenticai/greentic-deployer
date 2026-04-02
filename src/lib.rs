#![forbid(unsafe_code)]

pub mod adapter;
/// Legacy/provider-oriented multi-target implementation module.
///
/// Prefer `multi_target` or `surface::multi_target` for new call sites.
pub mod apply;
pub mod aws;
pub mod azure;
pub mod config;
pub mod contract;
pub mod deployment;
pub mod error;
pub mod extension;
pub mod gcp;
pub mod helm;
pub mod juju_k8s;
pub mod juju_machine;
pub mod k8s_raw;
pub mod multi_target;
pub mod operator;
pub mod pack_introspect;
pub mod path_safety;
pub mod plan;
pub mod serverless;
pub mod single_vm;
pub mod snap;
pub mod spec;
pub mod surface;
pub mod telemetry;
pub mod terraform;

pub use adapter::{AdapterFamily, MultiTargetKind, UnifiedTargetSelection};
pub use aws::AwsRequest;
pub use azure::AzureRequest;
pub use config::{DeployerConfig, DeployerRequest, OutputFormat, Provider};
pub use contract::{
    CapabilitySpecV1, CloudCredentialKind, CloudTargetRequirementsV1, ContractAsset,
    CredentialRequirementV1, DeployerCapability, DeployerContractV1, PlannerSpecV1,
    ResolvedCapabilityContract, ResolvedDeployerContract, ResolvedPlannerContract,
    VariableRequirementV1,
};
pub use deployment::{
    ApplyExecutionOutcome, DestroyExecutionOutcome, ExecutionOutcome, ExecutionOutcomePayload,
    StatusExecutionOutcome,
};
pub use error::DeployerError;
pub use extension::{
    DeploymentExtensionDescriptor, DeploymentExtensionKind, resolve_builtin_extension_for_provider,
    single_vm_builtin_extension,
};
pub use gcp::GcpRequest;
pub use helm::HelmRequest;
pub use juju_k8s::JujuK8sRequest;
pub use juju_machine::JujuMachineRequest;
pub use k8s_raw::K8sRawRequest;
pub use multi_target::{
    ApplyPayload, CapabilityPayload, DestroyPayload, ExecutionReport, GeneratePayload,
    OperationPayload, OperationResult, OutputValidation, PlanPayload, RollbackPayload,
    StatusPayload, render_operation_result,
};
pub use operator::OperatorRequest;
pub use plan::{
    ChannelContext, ComponentRole, DeploymentProfile, InferenceNotes, InfraPlan, MessagingContext,
    PlanContext, PlannedComponent, Target, TelemetryContext,
};
pub use serverless::ServerlessRequest;
pub use single_vm::{
    SingleVmAdminPlan, SingleVmApplyOptions, SingleVmApplyReport, SingleVmBundlePlan,
    SingleVmDeploymentStatus, SingleVmDestroyOptions, SingleVmDestroyReport, SingleVmHealthPlan,
    SingleVmLastAction, SingleVmPersistedState, SingleVmPlan, SingleVmPlanOutput,
    SingleVmPlannedFile, SingleVmPlannedFileKind, SingleVmRolloutPlan, SingleVmRuntimePlan,
    SingleVmServicePlan, SingleVmStatusReport, SingleVmStoragePlan, apply_single_vm_plan_output,
    apply_single_vm_plan_output_with_options, apply_single_vm_spec, apply_single_vm_spec_path,
    build_single_vm_plan, destroy_single_vm_plan_output,
    destroy_single_vm_plan_output_with_options, destroy_single_vm_spec,
    destroy_single_vm_spec_path, plan_single_vm_spec, plan_single_vm_spec_path,
    preview_single_vm_apply_plan_output, preview_single_vm_destroy_plan_output, render_env_file,
    render_single_vm_apply_report, render_single_vm_destroy_report, render_single_vm_plan,
    render_single_vm_plan_output, render_single_vm_status_report, render_systemd_unit,
    status_single_vm_plan_output, status_single_vm_spec, status_single_vm_spec_path,
};
pub use snap::SnapRequest;
pub use spec::{
    AdminEndpointSpec, BundleFormat, BundleSpec, DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1,
    DEPLOYMENT_SPEC_KIND, DeploymentMetadata, DeploymentSpecBody, DeploymentSpecV1,
    DeploymentTarget, HealthSpec, LinuxArch, MtlsSpec, RolloutSpec, RolloutStrategy, RuntimeSpec,
    ServiceManager, ServiceSpec, StorageSpec,
};
pub use terraform::TerraformRequest;
