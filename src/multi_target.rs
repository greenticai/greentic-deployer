//! Explicit wrapper around the legacy/provider-oriented deployment flow.
//!
//! The current repo contains two different execution families:
//! - `single_vm`: the stable OSS single-VM adapter
//! - `multi_target`: the older provider-oriented deployment-pack flow used as
//!   the integration point for non-single-vm adapters
//!
//! This module does not change behavior. It only makes the boundary explicit so
//! future work can evolve a unified deployer surface over isolated adapters.

use crate::apply;
use crate::config::{DeployerConfig, OutputFormat};
use crate::error::Result;
use crate::plan::PlanContext;

pub use crate::apply::{
    ApplyPayload, CapabilityPayload, DestroyPayload, ExecutionReport, GeneratePayload,
    OperationPayload, OperationResult, OutputValidation, PlanPayload, RollbackPayload,
    StatusPayload,
};

/// Runs the provider-oriented multi-target deployment flow.
///
/// This is intentionally separate from the dedicated `single_vm` adapter path.
pub async fn run(config: DeployerConfig) -> Result<OperationResult> {
    apply::run(config).await
}

/// Runs the provider-oriented multi-target deployment flow with a prebuilt plan.
pub async fn run_with_plan(config: DeployerConfig, plan: PlanContext) -> Result<OperationResult> {
    apply::run_with_plan(config, plan).await
}

pub fn render_operation_result(value: &OperationResult, format: OutputFormat) -> Result<String> {
    apply::render_operation_result(value, format)
}
