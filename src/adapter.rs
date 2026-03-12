use serde::{Deserialize, Serialize};

use crate::config::Provider;
use crate::spec::DeploymentTarget;

/// Top-level execution family behind the unified deployer surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterFamily {
    /// Stable OSS path for one Linux VM running one active bundle.
    SingleVm,
    /// Provider-oriented multi-target path used for cloud/k8s/generic adapters.
    ///
    /// Today this mostly represents the older generic deployer layer and is the
    /// integration point for future non-single-vm adapters.
    MultiTarget,
}

/// Unified deployment target selection used to keep adapter families explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", content = "target", rename_all = "snake_case")]
pub enum UnifiedTargetSelection {
    SingleVm,
    MultiTarget(MultiTargetKind),
}

impl UnifiedTargetSelection {
    pub fn adapter_family(self) -> AdapterFamily {
        match self {
            Self::SingleVm => AdapterFamily::SingleVm,
            Self::MultiTarget(_) => AdapterFamily::MultiTarget,
        }
    }
}

/// Provider-oriented target kinds that must stay outside the single-vm adapter path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiTargetKind {
    Local,
    Aws,
    Azure,
    Gcp,
    K8s,
    Generic,
}

impl MultiTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Gcp => "gcp",
            Self::K8s => "k8s",
            Self::Generic => "generic",
        }
    }
}

impl From<Provider> for MultiTargetKind {
    fn from(value: Provider) -> Self {
        match value {
            Provider::Local => Self::Local,
            Provider::Aws => Self::Aws,
            Provider::Azure => Self::Azure,
            Provider::Gcp => Self::Gcp,
            Provider::K8s => Self::K8s,
            Provider::Generic => Self::Generic,
        }
    }
}

impl From<DeploymentTarget> for UnifiedTargetSelection {
    fn from(value: DeploymentTarget) -> Self {
        match value {
            DeploymentTarget::SingleVm => Self::SingleVm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_vm_target_stays_in_single_vm_family() {
        let selection = UnifiedTargetSelection::from(DeploymentTarget::SingleVm);
        assert_eq!(selection, UnifiedTargetSelection::SingleVm);
        assert_eq!(selection.adapter_family(), AdapterFamily::SingleVm);
    }

    #[test]
    fn provider_targets_are_classified_as_multi_target_family() {
        for provider in [
            Provider::Local,
            Provider::Aws,
            Provider::Azure,
            Provider::Gcp,
            Provider::K8s,
            Provider::Generic,
        ] {
            let selection = UnifiedTargetSelection::MultiTarget(MultiTargetKind::from(provider));
            assert_eq!(selection.adapter_family(), AdapterFamily::MultiTarget);
        }
    }
}
