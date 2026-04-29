#![forbid(unsafe_code)]

pub mod adapter;
pub mod admin_access;
/// Legacy/provider-oriented multi-target implementation module.
///
/// Prefer `multi_target` or `surface::multi_target` for new call sites.
pub mod apply;
pub mod aws;
pub mod azure;
pub mod config;
pub mod contract;
pub mod deployment;
pub mod desktop;
pub mod error;
pub mod extension;
pub mod extension_sources;
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
pub use admin_access::{
    AdminAccessInfo, AdminAccessMode, AdminHealthProbe, AdminSecretRefs, AdminTunnelSupport,
    MaterializedAdminCerts, MaterializedAdminRelayToken, materialize_admin_client_certs,
    materialize_admin_relay_token, probe_admin_health, render_admin_access,
    render_admin_health_probe, render_materialized_admin_certs,
    render_materialized_admin_relay_token, resolve_admin_access,
};
pub use aws::{AwsAdminTunnelRequest, AwsRequest};
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
    BuiltinBackendDescriptor, BuiltinBackendExecutionKind, BuiltinBackendHandlerId,
    BuiltinBackendId, BuiltinExtensionBackendDescriptor, BuiltinExtensionDescriptor,
    BuiltinHandlerDescriptor, DeploymentExtensionContract, DeploymentExtensionDescriptor,
    DeploymentExtensionKind, DeploymentExtensionSourceKind, DeploymentHandlerDescriptor,
    list_builtin_extensions, list_builtin_handlers, list_deployment_extension_contracts,
    list_deployment_extension_contracts_from_sources,
    list_deployment_extension_contracts_from_sources_with_options,
    resolve_builtin_backend_descriptor, resolve_builtin_extension_detail_for_provider,
    resolve_builtin_extension_detail_for_target_name, resolve_builtin_extension_for_config,
    resolve_builtin_extension_for_provider, resolve_builtin_extension_for_target_name,
    resolve_builtin_handler_descriptor, resolve_deployment_extension_contract_for_provider,
    resolve_deployment_extension_contract_for_provider_from_sources,
    resolve_deployment_extension_contract_for_provider_from_sources_with_options,
    resolve_deployment_extension_contract_for_target_name,
    resolve_deployment_extension_contract_for_target_name_from_sources,
    resolve_deployment_extension_contract_for_target_name_from_sources_with_options,
    run_builtin_extension, single_vm_builtin_extension,
};
pub use extension_sources::DeploymentExtensionSourceOptions;
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
    SingleVmPlannedFile, SingleVmPlannedFileKind, SingleVmRenderSpecRequest, SingleVmRolloutPlan,
    SingleVmRuntimePlan, SingleVmServicePlan, SingleVmStatusReport, SingleVmStoragePlan,
    apply_single_vm_plan_output, apply_single_vm_plan_output_with_options, apply_single_vm_spec,
    apply_single_vm_spec_path, build_single_vm_plan, destroy_single_vm_plan_output,
    destroy_single_vm_plan_output_with_options, destroy_single_vm_spec,
    destroy_single_vm_spec_path, plan_single_vm_spec, plan_single_vm_spec_path,
    preview_single_vm_apply_plan_output, preview_single_vm_destroy_plan_output, render_env_file,
    render_single_vm_apply_report, render_single_vm_destroy_report, render_single_vm_plan,
    render_single_vm_plan_output, render_single_vm_status_report, render_systemd_unit,
    status_single_vm_plan_output, status_single_vm_spec, status_single_vm_spec_path,
    write_single_vm_spec,
};
pub use snap::SnapRequest;
pub use spec::{
    AdminEndpointSpec, BundleFormat, BundleSpec, DEPLOYMENT_SPEC_API_VERSION_V1ALPHA1,
    DEPLOYMENT_SPEC_KIND, DeploymentMetadata, DeploymentSpecBody, DeploymentSpecV1,
    DeploymentTarget, HealthSpec, LinuxArch, MtlsSpec, RolloutSpec, RolloutStrategy, RuntimeSpec,
    ServiceManager, ServiceSpec, StorageSpec,
};
pub use terraform::TerraformRequest;
