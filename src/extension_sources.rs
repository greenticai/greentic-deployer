use std::path::{Path, PathBuf};

use crate::adapter::{MultiTargetKind, UnifiedTargetSelection};
use crate::config::Provider;
use crate::contract::{DeployerCapability, get_deployer_contract_v1};
use crate::error::Result;
use crate::extension::{
    BuiltinBackendExecutionKind, DeploymentExtensionContract, DeploymentExtensionDescriptor,
    DeploymentExtensionKind, DeploymentExtensionSourceKind, DeploymentHandlerDescriptor,
};
use crate::pack_introspect::{read_manifest_from_directory, read_manifest_from_gtpack};

#[derive(Debug, Clone, Default)]
pub struct DeploymentExtensionSourceOptions {
    pub pack_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackDeploymentDispatch {
    pub capability: DeployerCapability,
    pub pack_id: String,
    pub flow_id: String,
    pub handler_id: String,
}

fn read_manifest(path: &Path) -> Result<greentic_types::pack_manifest::PackManifest> {
    if path.is_dir() {
        read_manifest_from_directory(path)
    } else {
        read_manifest_from_gtpack(path)
    }
}

fn default_target_for_pack_contract() -> UnifiedTargetSelection {
    UnifiedTargetSelection::MultiTarget(MultiTargetKind::Generic)
}

fn infer_provider_from_pack_id(pack_id: &str) -> Provider {
    let normalized = pack_id.trim().to_ascii_lowercase();
    if normalized.contains(".aws") || normalized.ends_with("aws") {
        Provider::Aws
    } else if normalized.contains(".azure") || normalized.ends_with("azure") {
        Provider::Azure
    } else if normalized.contains(".gcp") || normalized.ends_with("gcp") {
        Provider::Gcp
    } else if normalized.contains(".k8s") || normalized.ends_with("k8s") {
        Provider::K8s
    } else if normalized.contains(".local") || normalized.ends_with("local") {
        Provider::Local
    } else {
        Provider::Generic
    }
}

fn infer_target_for_provider(provider: Provider) -> UnifiedTargetSelection {
    match provider {
        Provider::Local => UnifiedTargetSelection::MultiTarget(MultiTargetKind::Local),
        Provider::Aws => UnifiedTargetSelection::MultiTarget(MultiTargetKind::Aws),
        Provider::Azure => UnifiedTargetSelection::MultiTarget(MultiTargetKind::Azure),
        Provider::Gcp => UnifiedTargetSelection::MultiTarget(MultiTargetKind::Gcp),
        Provider::K8s => UnifiedTargetSelection::MultiTarget(MultiTargetKind::K8s),
        Provider::Generic => default_target_for_pack_contract(),
    }
}

fn capabilities_from_contract(
    contract: &crate::contract::DeployerContractV1,
) -> Vec<DeployerCapability> {
    let mut capabilities: Vec<DeployerCapability> = contract
        .capabilities
        .iter()
        .map(|entry| entry.capability)
        .collect();
    if !capabilities.contains(&DeployerCapability::Plan) {
        capabilities.push(DeployerCapability::Plan);
    }
    capabilities
}

pub fn resolve_pack_deployment_dispatch(
    path: &Path,
    capability: DeployerCapability,
) -> Result<Option<PackDeploymentDispatch>> {
    let manifest = read_manifest(path)?;
    let pack_id = manifest.pack_id.to_string();
    let handler_id = format!("pack.{pack_id}");

    if let Some(contract) = get_deployer_contract_v1(&manifest)? {
        let flow_id = match capability {
            DeployerCapability::Plan => contract.planner.flow_id,
            _ => contract
                .capability(capability)
                .map(|spec| spec.flow_id.clone())
                .or_else(|| manifest.flows.first().map(|flow| flow.id.to_string()))
                .ok_or_else(|| {
                    crate::error::DeployerError::Config(format!(
                        "deployment pack {} does not declare `{}` and has no fallback flows",
                        pack_id,
                        capability.as_str()
                    ))
                })?,
        };
        return Ok(Some(PackDeploymentDispatch {
            capability,
            pack_id,
            flow_id,
            handler_id,
        }));
    }

    let Some(first_flow) = manifest.flows.first() else {
        return Err(crate::error::DeployerError::Config(format!(
            "deployment pack {} has no contract and no flows",
            pack_id
        )));
    };

    Ok(Some(PackDeploymentDispatch {
        capability,
        pack_id,
        flow_id: first_flow.id.to_string(),
        handler_id,
    }))
}

fn load_pack_deployment_extension_contract(
    path: &Path,
) -> Result<Option<DeploymentExtensionContract>> {
    let manifest = read_manifest(path)?;
    let Some(contract) = get_deployer_contract_v1(&manifest)? else {
        return Ok(None);
    };
    let pack_id = manifest.pack_id.to_string();
    let handler_id = format!("pack.{pack_id}");
    let capabilities = capabilities_from_contract(&contract);
    let provider = infer_provider_from_pack_id(&pack_id);
    Ok(Some(DeploymentExtensionContract {
        source: DeploymentExtensionSourceKind::Pack,
        extension: DeploymentExtensionDescriptor {
            id: pack_id.clone(),
            kind: DeploymentExtensionKind::Pack,
            target: infer_target_for_provider(provider),
            summary: format!(
                "Deployment extension contract loaded from {}",
                path.display()
            ),
        },
        provider: Some(provider),
        aliases: vec![pack_id.clone(), provider.as_str().to_string()],
        handlers: vec![DeploymentHandlerDescriptor {
            id: handler_id,
            execution_kind: BuiltinBackendExecutionKind::Executable,
            supported_capabilities: capabilities,
        }],
    }))
}

pub fn list_pack_deployment_extension_contracts(
    options: &DeploymentExtensionSourceOptions,
) -> Vec<DeploymentExtensionContract> {
    options
        .pack_paths
        .iter()
        .filter_map(|path| load_pack_deployment_extension_contract(path).ok().flatten())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_distributor_client::PackId;
    use greentic_types::cbor::encode_pack_manifest;
    use greentic_types::pack_manifest::{PackKind, PackManifest};
    use semver::Version;

    use crate::contract::{
        CapabilitySpecV1, DeployerContractV1, PlannerSpecV1, set_deployer_contract_v1,
    };

    fn sample_contract() -> DeployerContractV1 {
        DeployerContractV1 {
            schema_version: 1,
            planner: PlannerSpecV1 {
                flow_id: "plan_flow".into(),
                input_schema_ref: None,
                output_schema_ref: None,
                qa_spec_ref: None,
            },
            capabilities: vec![
                CapabilitySpecV1 {
                    capability: DeployerCapability::Plan,
                    flow_id: "plan_flow".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    execution_output_schema_ref: None,
                    qa_spec_ref: None,
                    example_refs: Vec::new(),
                },
                CapabilitySpecV1 {
                    capability: DeployerCapability::Apply,
                    flow_id: "apply_flow".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    execution_output_schema_ref: None,
                    qa_spec_ref: None,
                    example_refs: Vec::new(),
                },
            ],
        }
    }

    fn write_pack_dir_with_contract() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::try_from("greentic.deploy.external").expect("pack id"),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Provider,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        };
        set_deployer_contract_v1(&mut manifest, sample_contract()).expect("set contract");
        let bytes = encode_pack_manifest(&manifest).expect("encode manifest");
        std::fs::write(dir.path().join("manifest.cbor"), bytes).expect("write manifest");
        dir
    }

    #[test]
    fn pack_source_lists_extension_contract_from_pack_dir() {
        let dir = write_pack_dir_with_contract();
        let contracts =
            list_pack_deployment_extension_contracts(&DeploymentExtensionSourceOptions {
                pack_paths: vec![dir.path().to_path_buf()],
            });
        assert_eq!(contracts.len(), 1);
        let contract = &contracts[0];
        assert_eq!(contract.source, DeploymentExtensionSourceKind::Pack);
        assert_eq!(contract.extension.id, "greentic.deploy.external");
        assert_eq!(contract.provider, Some(Provider::Generic));
        assert_eq!(
            contract.aliases,
            vec![
                "greentic.deploy.external".to_string(),
                "generic".to_string()
            ]
        );
        assert_eq!(contract.handlers.len(), 1);
        assert_eq!(contract.handlers[0].id, "pack.greentic.deploy.external");
        assert!(
            contract.handlers[0]
                .supported_capabilities
                .contains(&DeployerCapability::Plan)
        );
        assert!(
            contract.handlers[0]
                .supported_capabilities
                .contains(&DeployerCapability::Apply)
        );
    }

    #[test]
    fn pack_source_ignores_paths_without_deployer_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::try_from("greentic.no.contract").expect("pack id"),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Provider,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        };
        let bytes = encode_pack_manifest(&manifest).expect("encode manifest");
        std::fs::write(dir.path().join("manifest.cbor"), bytes).expect("write manifest");

        let contracts =
            list_pack_deployment_extension_contracts(&DeploymentExtensionSourceOptions {
                pack_paths: vec![dir.path().to_path_buf()],
            });
        assert!(contracts.is_empty());
    }

    #[test]
    fn pack_source_resolves_execution_dispatch_from_contract() {
        let dir = write_pack_dir_with_contract();
        let dispatch = resolve_pack_deployment_dispatch(dir.path(), DeployerCapability::Apply)
            .expect("resolve dispatch")
            .expect("dispatch");
        assert_eq!(dispatch.pack_id, "greentic.deploy.external");
        assert_eq!(dispatch.flow_id, "apply_flow");
        assert_eq!(dispatch.handler_id, "pack.greentic.deploy.external");
        assert_eq!(dispatch.capability, DeployerCapability::Apply);
    }

    #[test]
    fn pack_source_infers_provider_and_target_from_pack_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::try_from("greentic.deploy.aws").expect("pack id"),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Provider,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        };
        set_deployer_contract_v1(&mut manifest, sample_contract()).expect("set contract");
        let bytes = encode_pack_manifest(&manifest).expect("encode manifest");
        std::fs::write(dir.path().join("manifest.cbor"), bytes).expect("write manifest");

        let contracts =
            list_pack_deployment_extension_contracts(&DeploymentExtensionSourceOptions {
                pack_paths: vec![dir.path().to_path_buf()],
            });
        let contract = &contracts[0];
        assert_eq!(contract.provider, Some(Provider::Aws));
        assert_eq!(
            contract.extension.target,
            UnifiedTargetSelection::MultiTarget(MultiTargetKind::Aws)
        );
        assert!(contract.aliases.iter().any(|alias| alias == "aws"));
    }
}
