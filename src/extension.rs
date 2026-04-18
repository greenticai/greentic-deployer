use serde::{Deserialize, Serialize};

use crate::adapter::{AdapterFamily, MultiTargetKind, UnifiedTargetSelection};
use crate::config::{DeployerConfig, Provider};
use crate::contract::DeployerCapability;
use crate::error::{DeployerError, Result};
use crate::extension_sources::{
    DeploymentExtensionSourceOptions, list_pack_deployment_extension_contracts,
};
use crate::multi_target::OperationResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinBackendId {
    Terraform,
    K8sRaw,
    Helm,
    Aws,
    Azure,
    Gcp,
    JujuK8s,
    JujuMachine,
    Operator,
    Serverless,
    Snap,
    Desktop,
    SingleVm,
}

impl BuiltinBackendId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::K8sRaw => "k8s_raw",
            Self::Helm => "helm",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Gcp => "gcp",
            Self::JujuK8s => "juju_k8s",
            Self::JujuMachine => "juju_machine",
            Self::Operator => "operator",
            Self::Serverless => "serverless",
            Self::Snap => "snap",
            Self::Desktop => "desktop",
            Self::SingleVm => "single_vm",
        }
    }

    /// Return `true` iff this backend accepts the given handler string.
    /// Desktop accepts `None`, `"docker-compose"`, or `"podman"`.
    /// All other backends have a single implicit handler; `None` matches
    /// and any explicit value is rejected.
    pub fn handler_matches(self, handler: Option<&str>) -> bool {
        match self {
            Self::Desktop => matches!(handler, None | Some("docker-compose") | Some("podman")),
            _ => handler.is_none(),
        }
    }
}

impl std::str::FromStr for BuiltinBackendId {
    type Err = UnknownBuiltinBackendStr;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "terraform" => Self::Terraform,
            "k8s_raw" => Self::K8sRaw,
            "helm" => Self::Helm,
            "aws" => Self::Aws,
            "azure" => Self::Azure,
            "gcp" => Self::Gcp,
            "juju_k8s" => Self::JujuK8s,
            "juju_machine" => Self::JujuMachine,
            "operator" => Self::Operator,
            "serverless" => Self::Serverless,
            "snap" => Self::Snap,
            "desktop" => Self::Desktop,
            "single_vm" => Self::SingleVm,
            other => return Err(UnknownBuiltinBackendStr(other.to_string())),
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown builtin backend id: '{0}'")]
pub struct UnknownBuiltinBackendStr(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinBackendExecutionKind {
    Common,
    Executable,
    Cloud,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinBackendHandlerId {
    Terraform,
    K8sRaw,
    Helm,
    Aws,
    Azure,
    Gcp,
    JujuK8s,
    JujuMachine,
    Operator,
    Serverless,
    Snap,
    Desktop,
    SingleVm,
}

impl BuiltinBackendHandlerId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::K8sRaw => "k8s_raw",
            Self::Helm => "helm",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Gcp => "gcp",
            Self::JujuK8s => "juju_k8s",
            Self::JujuMachine => "juju_machine",
            Self::Operator => "operator",
            Self::Serverless => "serverless",
            Self::Snap => "snap",
            Self::Desktop => "desktop",
            Self::SingleVm => "single_vm",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentExtensionKind {
    Builtin,
    Pack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentExtensionSourceKind {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltinBackendDescriptor {
    pub backend_id: BuiltinBackendId,
    pub execution_kind: BuiltinBackendExecutionKind,
    pub handler_id: BuiltinBackendHandlerId,
    pub extension: DeploymentExtensionDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltinExtensionBackendDescriptor {
    pub backend_id: BuiltinBackendId,
    pub execution_kind: BuiltinBackendExecutionKind,
    pub handler_id: BuiltinBackendHandlerId,
    pub supported_capabilities: Vec<DeployerCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltinHandlerDescriptor {
    pub handler_id: BuiltinBackendHandlerId,
    pub backend_id: BuiltinBackendId,
    pub execution_kind: BuiltinBackendExecutionKind,
    pub supported_capabilities: Vec<DeployerCapability>,
    pub extension: DeploymentExtensionDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltinExtensionDescriptor {
    pub extension: DeploymentExtensionDescriptor,
    pub provider: Option<Provider>,
    pub aliases: Vec<String>,
    pub backends: Vec<BuiltinExtensionBackendDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentHandlerDescriptor {
    pub id: String,
    pub execution_kind: BuiltinBackendExecutionKind,
    pub supported_capabilities: Vec<DeployerCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentExtensionContract {
    pub source: DeploymentExtensionSourceKind,
    pub extension: DeploymentExtensionDescriptor,
    pub provider: Option<Provider>,
    pub aliases: Vec<String>,
    pub handlers: Vec<DeploymentHandlerDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BuiltinBackendBinding {
    backend_id: BuiltinBackendId,
    execution_kind: BuiltinBackendExecutionKind,
    handler_id: BuiltinBackendHandlerId,
    supported_capabilities: &'static [DeployerCapability],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BuiltinExtensionRegistration {
    provider: Option<Provider>,
    aliases: &'static [&'static str],
    extension_id: &'static str,
    target: UnifiedTargetSelection,
    summary: &'static str,
    backends: &'static [BuiltinBackendBinding],
}

const STANDARD_DEPLOYER_CAPABILITIES: &[DeployerCapability] = &[
    DeployerCapability::Generate,
    DeployerCapability::Plan,
    DeployerCapability::Apply,
    DeployerCapability::Destroy,
    DeployerCapability::Status,
    DeployerCapability::Rollback,
];

const GENERIC_EXECUTABLE_BACKENDS: &[BuiltinBackendBinding] = &[
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::Terraform,
        execution_kind: BuiltinBackendExecutionKind::Executable,
        handler_id: BuiltinBackendHandlerId::Terraform,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::Serverless,
        execution_kind: BuiltinBackendExecutionKind::Executable,
        handler_id: BuiltinBackendHandlerId::Serverless,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
];

const K8S_BACKENDS: &[BuiltinBackendBinding] = &[
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::K8sRaw,
        execution_kind: BuiltinBackendExecutionKind::Common,
        handler_id: BuiltinBackendHandlerId::K8sRaw,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::Helm,
        execution_kind: BuiltinBackendExecutionKind::Common,
        handler_id: BuiltinBackendHandlerId::Helm,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::JujuK8s,
        execution_kind: BuiltinBackendExecutionKind::Executable,
        handler_id: BuiltinBackendHandlerId::JujuK8s,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::Operator,
        execution_kind: BuiltinBackendExecutionKind::Executable,
        handler_id: BuiltinBackendHandlerId::Operator,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
];

const LOCAL_BACKENDS: &[BuiltinBackendBinding] = &[
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::JujuMachine,
        execution_kind: BuiltinBackendExecutionKind::Executable,
        handler_id: BuiltinBackendHandlerId::JujuMachine,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
    BuiltinBackendBinding {
        backend_id: BuiltinBackendId::Snap,
        execution_kind: BuiltinBackendExecutionKind::Executable,
        handler_id: BuiltinBackendHandlerId::Snap,
        supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
    },
];

const AWS_BACKENDS: &[BuiltinBackendBinding] = &[BuiltinBackendBinding {
    backend_id: BuiltinBackendId::Aws,
    execution_kind: BuiltinBackendExecutionKind::Cloud,
    handler_id: BuiltinBackendHandlerId::Aws,
    supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
}];

const AZURE_BACKENDS: &[BuiltinBackendBinding] = &[BuiltinBackendBinding {
    backend_id: BuiltinBackendId::Azure,
    execution_kind: BuiltinBackendExecutionKind::Cloud,
    handler_id: BuiltinBackendHandlerId::Azure,
    supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
}];

const GCP_BACKENDS: &[BuiltinBackendBinding] = &[BuiltinBackendBinding {
    backend_id: BuiltinBackendId::Gcp,
    execution_kind: BuiltinBackendExecutionKind::Cloud,
    handler_id: BuiltinBackendHandlerId::Gcp,
    supported_capabilities: STANDARD_DEPLOYER_CAPABILITIES,
}];

const SINGLE_VM_BACKENDS: &[BuiltinBackendBinding] = &[];

const BUILTIN_EXTENSION_REGISTRATIONS: &[BuiltinExtensionRegistration] = &[
    BuiltinExtensionRegistration {
        provider: None,
        aliases: &["single-vm", "single_vm"],
        extension_id: "builtin.single_vm.core",
        target: UnifiedTargetSelection::SingleVm,
        summary: "Built-in single-vm deployment extension",
        backends: SINGLE_VM_BACKENDS,
    },
    BuiltinExtensionRegistration {
        provider: Some(Provider::Local),
        aliases: &["local"],
        extension_id: "builtin.multi_target.local",
        target: UnifiedTargetSelection::MultiTarget(MultiTargetKind::Local),
        summary: "Built-in local multi-target deployment extension",
        backends: LOCAL_BACKENDS,
    },
    BuiltinExtensionRegistration {
        provider: Some(Provider::Aws),
        aliases: &["aws"],
        extension_id: "builtin.multi_target.aws",
        target: UnifiedTargetSelection::MultiTarget(MultiTargetKind::Aws),
        summary: "Built-in AWS multi-target deployment extension",
        backends: AWS_BACKENDS,
    },
    BuiltinExtensionRegistration {
        provider: Some(Provider::Azure),
        aliases: &["azure"],
        extension_id: "builtin.multi_target.azure",
        target: UnifiedTargetSelection::MultiTarget(MultiTargetKind::Azure),
        summary: "Built-in Azure multi-target deployment extension",
        backends: AZURE_BACKENDS,
    },
    BuiltinExtensionRegistration {
        provider: Some(Provider::Gcp),
        aliases: &["gcp"],
        extension_id: "builtin.multi_target.gcp",
        target: UnifiedTargetSelection::MultiTarget(MultiTargetKind::Gcp),
        summary: "Built-in GCP multi-target deployment extension",
        backends: GCP_BACKENDS,
    },
    BuiltinExtensionRegistration {
        provider: Some(Provider::K8s),
        aliases: &["k8s"],
        extension_id: "builtin.multi_target.k8s",
        target: UnifiedTargetSelection::MultiTarget(MultiTargetKind::K8s),
        summary: "Built-in Kubernetes multi-target deployment extension",
        backends: K8S_BACKENDS,
    },
    BuiltinExtensionRegistration {
        provider: Some(Provider::Generic),
        aliases: &["generic"],
        extension_id: "builtin.multi_target.generic",
        target: UnifiedTargetSelection::MultiTarget(MultiTargetKind::Generic),
        summary: "Built-in generic multi-target deployment extension",
        backends: GENERIC_EXECUTABLE_BACKENDS,
    },
];

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

fn descriptor_from_registration(
    registration: &BuiltinExtensionRegistration,
) -> DeploymentExtensionDescriptor {
    DeploymentExtensionDescriptor::builtin(
        registration.extension_id,
        registration.target,
        registration.summary,
    )
}

fn builtin_extension_descriptor_from_registration(
    registration: &BuiltinExtensionRegistration,
) -> BuiltinExtensionDescriptor {
    BuiltinExtensionDescriptor {
        extension: descriptor_from_registration(registration),
        provider: registration.provider,
        aliases: registration
            .aliases
            .iter()
            .map(|alias| (*alias).to_string())
            .collect(),
        backends: registration
            .backends
            .iter()
            .map(|binding| BuiltinExtensionBackendDescriptor {
                backend_id: binding.backend_id,
                execution_kind: binding.execution_kind,
                handler_id: binding.handler_id,
                supported_capabilities: binding.supported_capabilities.to_vec(),
            })
            .collect(),
    }
}

fn builtin_handler_descriptor_from_parts(
    registration: &BuiltinExtensionRegistration,
    binding: &BuiltinBackendBinding,
) -> BuiltinHandlerDescriptor {
    BuiltinHandlerDescriptor {
        handler_id: binding.handler_id,
        backend_id: binding.backend_id,
        execution_kind: binding.execution_kind,
        supported_capabilities: binding.supported_capabilities.to_vec(),
        extension: descriptor_from_registration(registration),
    }
}

fn deployment_extension_contract_from_registration(
    registration: &BuiltinExtensionRegistration,
) -> DeploymentExtensionContract {
    DeploymentExtensionContract {
        source: DeploymentExtensionSourceKind::Builtin,
        extension: descriptor_from_registration(registration),
        provider: registration.provider,
        aliases: registration
            .aliases
            .iter()
            .map(|alias| (*alias).to_string())
            .collect(),
        handlers: registration
            .backends
            .iter()
            .map(|binding| DeploymentHandlerDescriptor {
                id: format!("builtin.{}", binding.handler_id.as_str()),
                execution_kind: binding.execution_kind,
                supported_capabilities: binding.supported_capabilities.to_vec(),
            })
            .collect(),
    }
}

pub fn list_builtin_extensions() -> Vec<BuiltinExtensionDescriptor> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .map(builtin_extension_descriptor_from_registration)
        .collect()
}

pub fn list_deployment_extension_contracts() -> Vec<DeploymentExtensionContract> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .map(deployment_extension_contract_from_registration)
        .collect()
}

pub fn list_deployment_extension_contracts_from_sources() -> Vec<DeploymentExtensionContract> {
    list_deployment_extension_contracts_from_sources_with_options(
        &DeploymentExtensionSourceOptions::default(),
    )
}

pub fn list_deployment_extension_contracts_from_sources_with_options(
    options: &DeploymentExtensionSourceOptions,
) -> Vec<DeploymentExtensionContract> {
    let mut contracts = list_deployment_extension_contracts();
    contracts.extend(list_pack_deployment_extension_contracts(options));
    contracts
}

pub fn list_builtin_handlers() -> Vec<BuiltinHandlerDescriptor> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .flat_map(|registration| {
            registration
                .backends
                .iter()
                .map(move |binding| builtin_handler_descriptor_from_parts(registration, binding))
        })
        .collect()
}

pub fn resolve_builtin_extension_detail_for_provider(
    provider: Provider,
) -> Option<BuiltinExtensionDescriptor> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .find(|registration| registration.provider == Some(provider))
        .map(builtin_extension_descriptor_from_registration)
}

pub fn resolve_deployment_extension_contract_for_provider(
    provider: Provider,
) -> Option<DeploymentExtensionContract> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .find(|registration| registration.provider == Some(provider))
        .map(deployment_extension_contract_from_registration)
}

pub fn resolve_deployment_extension_contract_for_provider_from_sources(
    provider: Provider,
) -> Option<DeploymentExtensionContract> {
    resolve_deployment_extension_contract_for_provider_from_sources_with_options(
        provider,
        &DeploymentExtensionSourceOptions::default(),
    )
}

pub fn resolve_deployment_extension_contract_for_provider_from_sources_with_options(
    provider: Provider,
    options: &DeploymentExtensionSourceOptions,
) -> Option<DeploymentExtensionContract> {
    list_deployment_extension_contracts_from_sources_with_options(options)
        .into_iter()
        .find(|contract| contract.provider == Some(provider))
}

pub fn resolve_builtin_extension_detail_for_target_name(
    target: &str,
) -> Option<BuiltinExtensionDescriptor> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .find(|registration| {
            registration
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(target.trim()))
        })
        .map(builtin_extension_descriptor_from_registration)
}

pub fn resolve_deployment_extension_contract_for_target_name(
    target: &str,
) -> Option<DeploymentExtensionContract> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .find(|registration| {
            registration
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(target.trim()))
        })
        .map(deployment_extension_contract_from_registration)
}

pub fn resolve_deployment_extension_contract_for_target_name_from_sources(
    target: &str,
) -> Option<DeploymentExtensionContract> {
    resolve_deployment_extension_contract_for_target_name_from_sources_with_options(
        target,
        &DeploymentExtensionSourceOptions::default(),
    )
}

pub fn resolve_deployment_extension_contract_for_target_name_from_sources_with_options(
    target: &str,
    options: &DeploymentExtensionSourceOptions,
) -> Option<DeploymentExtensionContract> {
    list_deployment_extension_contracts_from_sources_with_options(options)
        .into_iter()
        .find(|contract| {
            contract
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(target.trim()))
        })
}

pub fn resolve_builtin_handler_descriptor(
    handler_id: BuiltinBackendHandlerId,
) -> Option<BuiltinHandlerDescriptor> {
    BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .find_map(|registration| {
            registration
                .backends
                .iter()
                .find(|binding| binding.handler_id == handler_id)
                .map(|binding| builtin_handler_descriptor_from_parts(registration, binding))
        })
}

pub fn resolve_builtin_extension_for_provider(
    provider: Provider,
) -> Option<DeploymentExtensionDescriptor> {
    resolve_builtin_extension_detail_for_provider(provider).map(|detail| detail.extension)
}

pub fn single_vm_builtin_extension() -> DeploymentExtensionDescriptor {
    resolve_builtin_extension_for_target_name("single-vm")
        .expect("single-vm extension registration must exist")
}

pub fn resolve_builtin_extension_for_target_name(
    target: &str,
) -> Option<DeploymentExtensionDescriptor> {
    resolve_builtin_extension_detail_for_target_name(target).map(|detail| detail.extension)
}

pub fn resolve_builtin_backend_descriptor(
    backend_id: BuiltinBackendId,
) -> Option<BuiltinBackendDescriptor> {
    let registration = BUILTIN_EXTENSION_REGISTRATIONS
        .iter()
        .find_map(|registration| {
            registration
                .backends
                .iter()
                .find(|binding| binding.backend_id == backend_id)
                .map(|binding| (registration, binding))
        })?;
    Some(BuiltinBackendDescriptor {
        backend_id: registration.1.backend_id,
        execution_kind: registration.1.execution_kind,
        handler_id: registration.1.handler_id,
        extension: descriptor_from_registration(registration.0),
    })
}

pub fn resolve_builtin_extension_for_config(
    config: &DeployerConfig,
) -> Option<DeploymentExtensionDescriptor> {
    resolve_builtin_extension_for_provider(config.provider)
}

pub async fn run_builtin_extension(config: DeployerConfig) -> Result<OperationResult> {
    let descriptor = resolve_builtin_extension_for_config(&config).ok_or_else(|| {
        DeployerError::Other(format!(
            "no built-in deployment extension registered for provider {}",
            config.provider.as_str()
        ))
    })?;

    match descriptor.target {
        UnifiedTargetSelection::MultiTarget(_) => crate::multi_target::run(config).await,
        UnifiedTargetSelection::SingleVm => Err(DeployerError::Other(
            "single-vm execution must use the single-vm adapter path, not multi-target dispatch"
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeployerRequest, OutputFormat};
    use crate::contract::DeployerCapability;
    use std::path::PathBuf;

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

    #[test]
    fn resolve_builtin_extension_for_config_uses_provider() {
        let base = std::env::current_dir().unwrap().join("target/tmp-tests");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();

        let request = DeployerRequest {
            capability: DeployerCapability::Apply,
            provider: Provider::Aws,
            strategy: "iac-only".to_string(),
            tenant: "demo".to_string(),
            environment: Some("dev".to_string()),
            pack_path: dir.path().to_path_buf(),
            bundle_source: None,
            bundle_digest: None,
            repo_registry_base: None,
            store_registry_base: None,
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
            pack_id: None,
            pack_version: None,
            pack_digest: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: OutputFormat::Json,
            config_path: None,
            allow_remote_in_offline: false,
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
        };
        let config = DeployerConfig::resolve(request).expect("config");
        let descriptor = resolve_builtin_extension_for_config(&config).expect("descriptor");
        assert_eq!(descriptor.id, "builtin.multi_target.aws");
    }

    #[test]
    fn builtin_backend_descriptor_maps_backend_to_extension() {
        let aws = resolve_builtin_backend_descriptor(BuiltinBackendId::Aws).expect("aws backend");
        assert_eq!(aws.backend_id, BuiltinBackendId::Aws);
        assert_eq!(aws.execution_kind, BuiltinBackendExecutionKind::Cloud);
        assert_eq!(aws.handler_id, BuiltinBackendHandlerId::Aws);
        assert_eq!(aws.extension.id, "builtin.multi_target.aws");

        let terraform = resolve_builtin_backend_descriptor(BuiltinBackendId::Terraform)
            .expect("terraform backend");
        assert_eq!(terraform.backend_id, BuiltinBackendId::Terraform);
        assert_eq!(
            terraform.execution_kind,
            BuiltinBackendExecutionKind::Executable
        );
        assert_eq!(terraform.handler_id, BuiltinBackendHandlerId::Terraform);
        assert_eq!(terraform.extension.id, "builtin.multi_target.generic");
    }

    #[test]
    fn builtin_extension_target_name_resolution_supports_single_vm_and_cloud_targets() {
        let single_vm =
            resolve_builtin_extension_for_target_name("single-vm").expect("single-vm target");
        assert_eq!(single_vm.id, "builtin.single_vm.core");

        let aws = resolve_builtin_extension_for_target_name("aws").expect("aws target");
        assert_eq!(aws.id, "builtin.multi_target.aws");

        assert!(resolve_builtin_extension_for_target_name("unknown").is_none());
    }

    #[test]
    fn builtin_extension_detail_exposes_aliases_provider_and_backends() {
        let aws = resolve_builtin_extension_detail_for_provider(Provider::Aws)
            .expect("aws extension detail");
        assert_eq!(aws.extension.id, "builtin.multi_target.aws");
        assert_eq!(aws.provider, Some(Provider::Aws));
        assert!(aws.aliases.iter().any(|alias| alias == "aws"));
        assert_eq!(aws.backends.len(), 1);
        assert_eq!(aws.backends[0].backend_id, BuiltinBackendId::Aws);
        assert_eq!(
            aws.backends[0].execution_kind,
            BuiltinBackendExecutionKind::Cloud
        );
        assert_eq!(aws.backends[0].handler_id, BuiltinBackendHandlerId::Aws);
        assert_eq!(
            aws.backends[0].supported_capabilities,
            STANDARD_DEPLOYER_CAPABILITIES
        );
    }

    #[test]
    fn list_builtin_extensions_returns_single_registry_view() {
        let extensions = list_builtin_extensions();
        assert!(
            extensions
                .iter()
                .any(|detail| detail.extension.id == "builtin.multi_target.aws")
        );
        assert!(
            extensions
                .iter()
                .any(|detail| detail.extension.id == "builtin.single_vm.core")
        );
    }

    #[test]
    fn builtin_handler_descriptor_exposes_extension_and_capabilities() {
        let handler =
            resolve_builtin_handler_descriptor(BuiltinBackendHandlerId::Aws).expect("aws handler");
        assert_eq!(handler.backend_id, BuiltinBackendId::Aws);
        assert_eq!(handler.extension.id, "builtin.multi_target.aws");
        assert_eq!(
            handler.supported_capabilities,
            STANDARD_DEPLOYER_CAPABILITIES
        );
    }

    #[test]
    fn list_builtin_handlers_returns_registry_level_handler_view() {
        let handlers = list_builtin_handlers();
        assert!(
            handlers
                .iter()
                .any(|handler| handler.handler_id == BuiltinBackendHandlerId::Terraform)
        );
        assert!(
            handlers
                .iter()
                .any(|handler| handler.handler_id == BuiltinBackendHandlerId::Aws)
        );
    }

    #[test]
    fn deployment_extension_contract_exposes_generic_handler_contract() {
        let aws = resolve_deployment_extension_contract_for_provider(Provider::Aws)
            .expect("aws deployment extension contract");
        assert_eq!(aws.extension.id, "builtin.multi_target.aws");
        assert_eq!(aws.provider, Some(Provider::Aws));
        assert!(
            aws.handlers
                .iter()
                .any(|handler| handler.id == "builtin.aws")
        );
        assert!(
            aws.handlers.iter().all(|handler| {
                handler.supported_capabilities == STANDARD_DEPLOYER_CAPABILITIES
            })
        );
    }

    #[test]
    fn list_deployment_extension_contracts_returns_generic_registry_view() {
        let contracts = list_deployment_extension_contracts();
        assert!(
            contracts
                .iter()
                .any(|contract| contract.extension.id == "builtin.multi_target.aws")
        );
        assert!(
            contracts
                .iter()
                .any(|contract| contract.extension.id == "builtin.single_vm.core")
        );
    }
}

#[cfg(test)]
mod ext_roundtrip_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn from_str_all_variants_roundtrip() {
        let cases = [
            ("terraform", BuiltinBackendId::Terraform),
            ("k8s_raw", BuiltinBackendId::K8sRaw),
            ("helm", BuiltinBackendId::Helm),
            ("aws", BuiltinBackendId::Aws),
            ("azure", BuiltinBackendId::Azure),
            ("gcp", BuiltinBackendId::Gcp),
            ("juju_k8s", BuiltinBackendId::JujuK8s),
            ("juju_machine", BuiltinBackendId::JujuMachine),
            ("operator", BuiltinBackendId::Operator),
            ("serverless", BuiltinBackendId::Serverless),
            ("snap", BuiltinBackendId::Snap),
        ];
        for (s, expected) in cases {
            assert_eq!(BuiltinBackendId::from_str(s).unwrap(), expected);
            assert_eq!(expected.as_str(), s);
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        let err = BuiltinBackendId::from_str("mystery").unwrap_err();
        assert!(err.to_string().contains("mystery"));
    }

    #[test]
    fn from_str_is_case_sensitive() {
        assert!(BuiltinBackendId::from_str("AWS").is_err());
        assert!(BuiltinBackendId::from_str("Terraform").is_err());
    }

    #[test]
    fn handler_matches_permits_none_for_all() {
        for b in [
            BuiltinBackendId::Terraform,
            BuiltinBackendId::Aws,
            BuiltinBackendId::Helm,
        ] {
            assert!(b.handler_matches(None));
        }
    }

    #[test]
    fn handler_matches_rejects_unknown_for_all_existing() {
        assert!(!BuiltinBackendId::Aws.handler_matches(Some("eks")));
    }

    #[test]
    fn desktop_variant_roundtrip() {
        use std::str::FromStr;
        assert_eq!(
            BuiltinBackendId::from_str("desktop").unwrap(),
            BuiltinBackendId::Desktop
        );
        assert_eq!(BuiltinBackendId::Desktop.as_str(), "desktop");
    }

    #[test]
    fn desktop_handler_matches_docker_compose_and_podman() {
        assert!(BuiltinBackendId::Desktop.handler_matches(Some("docker-compose")));
        assert!(BuiltinBackendId::Desktop.handler_matches(Some("podman")));
        assert!(!BuiltinBackendId::Desktop.handler_matches(Some("kubernetes")));
        assert!(BuiltinBackendId::Desktop.handler_matches(None));
    }

    #[test]
    fn single_vm_variant_roundtrip() {
        use std::str::FromStr;
        assert_eq!(
            BuiltinBackendId::from_str("single_vm").unwrap(),
            BuiltinBackendId::SingleVm
        );
        assert_eq!(BuiltinBackendId::SingleVm.as_str(), "single_vm");
    }

    #[test]
    fn single_vm_handler_matches_rejects_any_handler() {
        assert!(BuiltinBackendId::SingleVm.handler_matches(None));
        assert!(!BuiltinBackendId::SingleVm.handler_matches(Some("docker")));
        assert!(!BuiltinBackendId::SingleVm.handler_matches(Some("foo")));
    }
}
