#![forbid(unsafe_code)]

pub mod apply;
pub mod config;
pub mod contract;
pub mod deployment;
pub mod error;
pub mod pack_introspect;
pub mod path_safety;
pub mod plan;
pub mod telemetry;

pub use apply::{
    ApplyPayload, CapabilityPayload, DestroyPayload, ExecutionReport, GeneratePayload,
    OperationPayload, OperationResult, OutputValidation, PlanPayload, RollbackPayload,
    StatusPayload,
};
pub use config::{DeployerConfig, DeployerRequest, OutputFormat, Provider};
pub use contract::{
    CapabilitySpecV1, ContractAsset, DeployerCapability, DeployerContractV1, PlannerSpecV1,
    ResolvedCapabilityContract, ResolvedDeployerContract, ResolvedPlannerContract,
};
pub use deployment::{
    ApplyExecutionOutcome, DestroyExecutionOutcome, ExecutionOutcome, ExecutionOutcomePayload,
    StatusExecutionOutcome,
};
pub use error::DeployerError;
pub use plan::{
    ChannelContext, ComponentRole, DeploymentProfile, InferenceNotes, InfraPlan, MessagingContext,
    PlanContext, PlannedComponent, Target, TelemetryContext,
};
