use serde::{Deserialize, Serialize};

use crate::adapter::{AdapterFamily, MultiTargetKind, UnifiedTargetSelection};
use crate::config::Provider;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentExtensionKind {
    Builtin,
    Pack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentExtensionDescriptor {
    pub id: String,
    pub kind: DeploymentExtensionKind,
    pub target: UnifiedTargetSelection,
    pub summary: String,
}

impl DeploymentExtensionDescriptor {
    pub fn builtin(
        id: impl Into<String>,
        target: UnifiedTargetSelection,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind: DeploymentExtensionKind::Builtin,
            target,
            summary: summary.into(),
        }
    }

    pub fn adapter_family(&self) -> AdapterFamily {
        self.target.adapter_family()
    }
}

pub fn resolve_builtin_extension_for_provider(
    provider: Provider,
) -> Option<DeploymentExtensionDescriptor> {
    let descriptor = match provider {
        Provider::Local => DeploymentExtensionDescriptor::builtin(
            "builtin.multi_target.local",
            UnifiedTargetSelection::MultiTarget(MultiTargetKind::Local),
            "Built-in local multi-target deployment extension",
        ),
        Provider::Aws => DeploymentExtensionDescriptor::builtin(
            "builtin.multi_target.aws",
            UnifiedTargetSelection::MultiTarget(MultiTargetKind::Aws),
            "Built-in AWS multi-target deployment extension",
        ),
        Provider::Azure => DeploymentExtensionDescriptor::builtin(
            "builtin.multi_target.azure",
            UnifiedTargetSelection::MultiTarget(MultiTargetKind::Azure),
            "Built-in Azure multi-target deployment extension",
        ),
        Provider::Gcp => DeploymentExtensionDescriptor::builtin(
            "builtin.multi_target.gcp",
            UnifiedTargetSelection::MultiTarget(MultiTargetKind::Gcp),
            "Built-in GCP multi-target deployment extension",
        ),
        Provider::K8s => DeploymentExtensionDescriptor::builtin(
            "builtin.multi_target.k8s",
            UnifiedTargetSelection::MultiTarget(MultiTargetKind::K8s),
            "Built-in Kubernetes multi-target deployment extension",
        ),
        Provider::Generic => DeploymentExtensionDescriptor::builtin(
            "builtin.multi_target.generic",
            UnifiedTargetSelection::MultiTarget(MultiTargetKind::Generic),
            "Built-in generic multi-target deployment extension",
        ),
    };
    Some(descriptor)
}

pub fn single_vm_builtin_extension() -> DeploymentExtensionDescriptor {
    DeploymentExtensionDescriptor::builtin(
        "builtin.single_vm.core",
        UnifiedTargetSelection::SingleVm,
        "Built-in single-vm deployment extension",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_providers_resolve_to_builtin_multi_target_extensions() {
        let aws = resolve_builtin_extension_for_provider(Provider::Aws).expect("aws extension");
        assert_eq!(aws.id, "builtin.multi_target.aws");
        assert_eq!(aws.kind, DeploymentExtensionKind::Builtin);
        assert_eq!(aws.adapter_family(), AdapterFamily::MultiTarget);
    }

    #[test]
    fn single_vm_extension_stays_in_single_vm_family() {
        let descriptor = single_vm_builtin_extension();
        assert_eq!(descriptor.id, "builtin.single_vm.core");
        assert_eq!(descriptor.kind, DeploymentExtensionKind::Builtin);
        assert_eq!(descriptor.adapter_family(), AdapterFamily::SingleVm);
    }
}
