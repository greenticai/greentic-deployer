//! Unified deployer surface over isolated adapter families.
//!
//! This module exists to make the intended public shape explicit:
//! - `surface::single_vm` for the stable OSS single-VM adapter
//! - `surface::multi_target` for the provider-oriented adapter family
//! - `surface::aws` for the AWS adapter surface
//! - `surface::azure` for the Azure adapter surface
//! - `surface::gcp` for the GCP adapter surface
//! - `surface::helm` for the Helm adapter surface
//! - `surface::juju_k8s` for the Juju k8s adapter surface
//! - `surface::juju_machine` for the Juju machine adapter surface
//! - `surface::k8s_raw` for the raw-manifests k8s adapter surface
//! - `surface::operator` for the k8s operator adapter surface
//! - `surface::serverless` for the serverless adapter surface
//! - `surface::snap` for the Snap adapter surface
//! - `surface::terraform` for the first explicit multi-target adapter surface
//!
//! Existing top-level exports remain for compatibility while the repo evolves
//! toward this clearer separation.

/// Stable OSS single-VM adapter surface.
pub mod single_vm {
    pub use crate::single_vm::*;
}

/// Provider-oriented multi-target adapter surface.
pub mod multi_target {
    pub use crate::multi_target::*;
}

/// Explicit AWS adapter surface layered over the multi-target family.
pub mod aws {
    pub use crate::aws::*;
}

/// Explicit Azure adapter surface layered over the multi-target family.
pub mod azure {
    pub use crate::azure::*;
}

/// Explicit GCP adapter surface layered over the multi-target family.
pub mod gcp {
    pub use crate::gcp::*;
}

/// Explicit Helm adapter surface layered over the multi-target family.
pub mod helm {
    pub use crate::helm::*;
}

/// Explicit Juju k8s adapter surface layered over the multi-target family.
pub mod juju_k8s {
    pub use crate::juju_k8s::*;
}

/// Explicit Juju machine adapter surface layered over the multi-target family.
pub mod juju_machine {
    pub use crate::juju_machine::*;
}

/// Explicit k8s raw-manifests adapter surface layered over the multi-target family.
pub mod k8s_raw {
    pub use crate::k8s_raw::*;
}

/// Explicit k8s operator adapter surface layered over the multi-target family.
pub mod operator {
    pub use crate::operator::*;
}

/// Explicit serverless adapter surface layered over the multi-target family.
pub mod serverless {
    pub use crate::serverless::*;
}

/// Explicit Snap adapter surface layered over the multi-target family.
pub mod snap {
    pub use crate::snap::*;
}

/// Explicit terraform adapter surface layered over the multi-target family.
pub mod terraform {
    pub use crate::terraform::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate as greentic_deployer;

    #[test]
    fn surface_single_vm_namespace_exposes_types() {
        let _ = std::mem::size_of::<single_vm::SingleVmPlanOutput>();
        let _ = std::mem::size_of::<single_vm::SingleVmStatusReport>();
    }

    #[test]
    fn surface_multi_target_namespace_exposes_types() {
        let _ = std::mem::size_of::<multi_target::OperationResult>();
        let _ = std::mem::size_of::<multi_target::PlanPayload>();
    }

    #[test]
    fn surface_aws_namespace_exposes_types() {
        let _ = std::mem::size_of::<aws::AwsRequest>();
    }

    #[test]
    fn surface_azure_namespace_exposes_types() {
        let _ = std::mem::size_of::<azure::AzureRequest>();
    }

    #[test]
    fn surface_gcp_namespace_exposes_types() {
        let _ = std::mem::size_of::<gcp::GcpRequest>();
    }

    #[test]
    fn surface_helm_namespace_exposes_types() {
        let _ = std::mem::size_of::<helm::HelmRequest>();
    }

    #[test]
    fn surface_juju_k8s_namespace_exposes_types() {
        let _ = std::mem::size_of::<juju_k8s::JujuK8sRequest>();
    }

    #[test]
    fn surface_juju_machine_namespace_exposes_types() {
        let _ = std::mem::size_of::<juju_machine::JujuMachineRequest>();
    }

    #[test]
    fn surface_k8s_raw_namespace_exposes_types() {
        let _ = std::mem::size_of::<k8s_raw::K8sRawRequest>();
    }

    #[test]
    fn surface_operator_namespace_exposes_types() {
        let _ = std::mem::size_of::<operator::OperatorRequest>();
    }

    #[test]
    fn surface_serverless_namespace_exposes_types() {
        let _ = std::mem::size_of::<serverless::ServerlessRequest>();
    }

    #[test]
    fn surface_snap_namespace_exposes_types() {
        let _ = std::mem::size_of::<snap::SnapRequest>();
    }

    #[test]
    fn surface_terraform_namespace_exposes_types() {
        let _ = std::mem::size_of::<terraform::TerraformRequest>();
    }

    #[test]
    fn top_level_multi_target_exports_remain_available() {
        let _ = std::mem::size_of::<greentic_deployer::OperationResult>();
        let _ = std::mem::size_of::<greentic_deployer::PlanPayload>();
    }
}
