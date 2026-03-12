use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::config::DeployerConfig;
use crate::contract::{DeployerCapability, get_deployer_contract_v1};
use crate::error::{DeployerError, Result};
use crate::pack_introspect::{read_manifest_from_directory, read_manifest_from_gtpack};
use crate::plan::PlanContext;
use async_trait::async_trait;
use greentic_types::pack_manifest::PackManifest;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// Logical deployment target keyed by provider + strategy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeploymentTarget {
    pub provider: String,
    pub strategy: String,
}

/// Dispatch details describing which deployment pack/flow to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentDispatch {
    pub capability: DeployerCapability,
    pub pack_id: String,
    pub flow_id: String,
}

/// Resolved deployment pack selection including discovered manifest.
#[derive(Debug)]
pub struct DeploymentPackSelection {
    pub dispatch: DeploymentDispatch,
    pub pack_path: PathBuf,
    pub manifest: PackManifest,
    pub origin: String,
    pub candidates: Vec<String>,
}

/// Built-in provider/strategy defaults. Override them with `DEPLOY_TARGET_*` env vars as
/// deployment packs become available in your environment.
pub fn default_dispatch_table() -> HashMap<DeploymentTarget, DeploymentDispatch> {
    let mut map = HashMap::new();
    map.insert(
        DeploymentTarget {
            provider: "aws".into(),
            strategy: "iac-only".into(),
        },
        DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.aws".into(),
            flow_id: "deploy_aws_iac".into(),
        },
    );
    map.insert(
        DeploymentTarget {
            provider: "local".into(),
            strategy: "iac-only".into(),
        },
        DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.local".into(),
            flow_id: "deploy_local_iac".into(),
        },
    );
    map.insert(
        DeploymentTarget {
            provider: "azure".into(),
            strategy: "iac-only".into(),
        },
        DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.azure".into(),
            flow_id: "deploy_azure_iac".into(),
        },
    );
    map.insert(
        DeploymentTarget {
            provider: "gcp".into(),
            strategy: "iac-only".into(),
        },
        DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.gcp".into(),
            flow_id: "deploy_gcp_iac".into(),
        },
    );
    map.insert(
        DeploymentTarget {
            provider: "k8s".into(),
            strategy: "iac-only".into(),
        },
        DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.k8s".into(),
            flow_id: "deploy_k8s_iac".into(),
        },
    );
    map.insert(
        DeploymentTarget {
            provider: "generic".into(),
            strategy: "iac-only".into(),
        },
        DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.generic".into(),
            flow_id: "deploy_generic_iac".into(),
        },
    );
    map
}

/// Resolve the dispatch entry for a target, honoring environment overrides.
pub fn resolve_dispatch(target: &DeploymentTarget) -> Result<DeploymentDispatch> {
    resolve_dispatch_with_env(target, |key| env::var(key).ok())
}

pub fn resolve_deployment_pack(
    config: &DeployerConfig,
    target: &DeploymentTarget,
) -> Result<DeploymentPackSelection> {
    resolve_deployment_pack_for_capability(config, target, config.capability)
}

pub fn resolve_deployment_pack_for_capability(
    config: &DeployerConfig,
    target: &DeploymentTarget,
    capability: DeployerCapability,
) -> Result<DeploymentPackSelection> {
    let default_dispatch = if let Some(dispatch) = explicit_dispatch_override(config, capability)? {
        dispatch
    } else if let Some(dispatch) = dispatch_from_provider_pack(config, capability)? {
        dispatch
    } else {
        resolve_dispatch(target)?
    };
    let mut discovery = find_pack_for_dispatch(config, target, &default_dispatch)?;
    let dispatch = resolve_contract_dispatch(&discovery.manifest, capability, &default_dispatch)?;
    ensure_flow_available(&dispatch, &discovery.manifest)?;
    discovery.candidates.push(format!(
        "capability={} flow={}",
        dispatch.capability.as_str(),
        dispatch.flow_id
    ));
    Ok(DeploymentPackSelection {
        dispatch,
        pack_path: discovery.pack_path,
        manifest: discovery.manifest,
        origin: discovery.origin,
        candidates: discovery.candidates,
    })
}

fn explicit_dispatch_override(
    config: &DeployerConfig,
    capability: DeployerCapability,
) -> Result<Option<DeploymentDispatch>> {
    match (
        config.deploy_pack_id_override.as_ref(),
        config.deploy_flow_id_override.as_ref(),
    ) {
        (Some(pack_id), Some(flow_id)) => Ok(Some(DeploymentDispatch {
            capability,
            pack_id: pack_id.clone(),
            flow_id: flow_id.clone(),
        })),
        (None, None) => Ok(None),
        _ => Err(DeployerError::Config(
            "deploy_pack_id_override and deploy_flow_id_override must be set together".to_string(),
        )),
    }
}

fn dispatch_from_provider_pack(
    config: &DeployerConfig,
    capability: DeployerCapability,
) -> Result<Option<DeploymentDispatch>> {
    let Some(path) = config.provider_pack.as_ref() else {
        return Ok(None);
    };
    let manifest = load_manifest(path)?;
    let pack_id = manifest.pack_id.to_string();

    if let Some(contract) = get_deployer_contract_v1(&manifest)? {
        let flow_id = match capability {
            DeployerCapability::Plan => contract.planner.flow_id,
            _ => contract
                .capability(capability)
                .map(|spec| spec.flow_id.clone())
                .or_else(|| manifest.flows.first().map(|flow| flow.id.to_string()))
                .ok_or_else(|| {
                    DeployerError::Config(format!(
                        "deployment pack {} does not declare `{}` and has no fallback flows",
                        pack_id,
                        capability.as_str()
                    ))
                })?,
        };
        return Ok(Some(DeploymentDispatch {
            capability,
            pack_id,
            flow_id,
        }));
    }

    let Some(first_flow) = manifest.flows.first() else {
        return Err(DeployerError::Config(format!(
            "deployment pack {} has no contract and no flows",
            pack_id
        )));
    };

    Ok(Some(DeploymentDispatch {
        capability,
        pack_id,
        flow_id: first_flow.id.to_string(),
    }))
}

fn resolve_contract_dispatch(
    manifest: &PackManifest,
    capability: DeployerCapability,
    fallback: &DeploymentDispatch,
) -> Result<DeploymentDispatch> {
    let Some(contract) = get_deployer_contract_v1(manifest)? else {
        return Ok(DeploymentDispatch {
            capability,
            pack_id: fallback.pack_id.clone(),
            flow_id: fallback.flow_id.clone(),
        });
    };

    let Some(spec) = contract.capability(capability) else {
        return Err(DeployerError::Contract(format!(
            "deployment pack {} does not declare `{}` capability in {}",
            manifest.pack_id,
            capability.as_str(),
            crate::contract::EXT_DEPLOYER_V1
        )));
    };

    Ok(DeploymentDispatch {
        capability,
        pack_id: manifest.pack_id.to_string(),
        flow_id: spec.flow_id.clone(),
    })
}

fn resolve_dispatch_with_env<F>(target: &DeploymentTarget, get_env: F) -> Result<DeploymentDispatch>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(dispatch) = env_override(target, &get_env)? {
        return Ok(dispatch);
    }

    let mut defaults = default_dispatch_table();
    if let Some(dispatch) = defaults.remove(target) {
        return Ok(dispatch);
    }

    Err(DeployerError::Config(format!(
        "No deployment pack mapping for provider={} strategy={}. Configure DEPLOY_TARGET_{}_{}_PACK_ID / _FLOW_ID or extend the defaults.",
        target.provider,
        target.strategy,
        sanitize_key(&target.provider),
        sanitize_key(&target.strategy),
    )))
}

fn env_override<F>(target: &DeploymentTarget, get_env: &F) -> Result<Option<DeploymentDispatch>>
where
    F: Fn(&str) -> Option<String>,
{
    let strategy_prefix = format!(
        "DEPLOY_TARGET_{}_{}",
        sanitize_key(&target.provider),
        sanitize_key(&target.strategy)
    );
    if let Some(dispatch) = env_override_with_prefix(&strategy_prefix, get_env)? {
        return Ok(Some(dispatch));
    }
    let provider_prefix = format!("DEPLOY_TARGET_{}", sanitize_key(&target.provider));
    env_override_with_prefix(&provider_prefix, get_env)
}

fn env_override_with_prefix<F>(prefix: &str, get_env: &F) -> Result<Option<DeploymentDispatch>>
where
    F: Fn(&str) -> Option<String>,
{
    let pack_key = format!("{prefix}_PACK_ID");
    let flow_key = format!("{prefix}_FLOW_ID");
    let pack = get_env(&pack_key);
    let flow = get_env(&flow_key);
    match (pack, flow) {
        (Some(pack_id), Some(flow_id)) => Ok(Some(DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id,
            flow_id,
        })),
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(DeployerError::Config(format!(
            "Incomplete deployment mapping overrides. Both {pack_key} and {flow_key} must be set."
        ))),
    }
}

struct SearchPath {
    label: &'static str,
    path: PathBuf,
}

struct PackDiscovery {
    pack_path: PathBuf,
    manifest: PackManifest,
    origin: String,
    candidates: Vec<String>,
}

fn find_pack_for_dispatch(
    config: &DeployerConfig,
    target: &DeploymentTarget,
    dispatch: &DeploymentDispatch,
) -> Result<PackDiscovery> {
    if let Some(ref override_path) = config.provider_pack {
        let manifest = load_manifest(override_path)?;
        let actual = manifest.pack_id.to_string();
        return Ok(PackDiscovery {
            pack_path: override_path.clone(),
            manifest,
            origin: format!("override -> {}", override_path.display()),
            candidates: vec![format!(
                "{} (override {}, requested {})",
                actual,
                override_path.display(),
                dispatch.pack_id
            )],
        });
    }

    if let Some((direct_path, manifest)) =
        resolve_direct_pack_path(config, target).and_then(|direct_path| {
            if !direct_path.exists() {
                return None;
            }
            match load_manifest(&direct_path) {
                Ok(manifest) if manifest.pack_id.to_string() == dispatch.pack_id => {
                    Some((direct_path, manifest))
                }
                _ => None,
            }
        })
    {
        let candidate_display = direct_path.display().to_string();
        let entry = format!("{} ({})", manifest.pack_id, candidate_display);
        return Ok(PackDiscovery {
            pack_path: direct_path.clone(),
            manifest,
            origin: format!("providers-dir -> {}", candidate_display),
            candidates: vec![entry],
        });
    }

    let search_paths = build_search_paths(config);
    let mut candidates = Vec::new();
    for search in &search_paths {
        for candidate in gather_candidates(&search.path) {
            if let Ok(manifest) = load_manifest(&candidate) {
                let entry = format!("{} ({})", manifest.pack_id, candidate.display());
                candidates.push(entry.clone());
                if manifest.pack_id.to_string() == dispatch.pack_id {
                    let candidate_display = candidate.display().to_string();
                    let pack_path = candidate.clone();
                    return Ok(PackDiscovery {
                        pack_path,
                        manifest,
                        origin: format!("{} -> {}", search.label, candidate_display),
                        candidates,
                    });
                }
            }
        }
    }

    let summary = build_search_summary(&search_paths);
    Err(DeployerError::Config(format!(
        "Deployment pack {} not found; searched {} (candidates: {})",
        dispatch.pack_id,
        summary,
        if candidates.is_empty() {
            "none".into()
        } else {
            candidates.join("; ")
        }
    )))
}

fn ensure_flow_available(dispatch: &DeploymentDispatch, manifest: &PackManifest) -> Result<()> {
    let available: Vec<String> = manifest
        .flows
        .iter()
        .map(|entry| entry.id.to_string())
        .collect();
    if available.iter().any(|flow| flow == &dispatch.flow_id) {
        return Ok(());
    }

    Err(DeployerError::Config(format!(
        "Flow {} not found in {} (available flows: {})",
        dispatch.flow_id,
        dispatch.pack_id,
        if available.is_empty() {
            "none".into()
        } else {
            available.join(", ")
        }
    )))
}

fn build_search_paths(config: &DeployerConfig) -> Vec<SearchPath> {
    vec![
        SearchPath {
            label: "providers-dir",
            path: config.providers_dir.clone(),
        },
        SearchPath {
            label: "packs-dir",
            path: config.packs_dir.clone(),
        },
        SearchPath {
            label: "dist",
            path: PathBuf::from("dist"),
        },
        SearchPath {
            label: "examples",
            path: PathBuf::from("examples"),
        },
    ]
}

fn resolve_direct_pack_path(config: &DeployerConfig, target: &DeploymentTarget) -> Option<PathBuf> {
    let pack_path = config.providers_dir.join(&target.provider);
    if pack_path.exists() {
        Some(pack_path)
    } else {
        None
    }
}

fn gather_candidates(path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let candidate = entry.path();
            if candidate.is_dir()
                || candidate.extension().and_then(|ext| ext.to_str()) == Some("gtpack")
            {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

fn load_manifest(path: &Path) -> Result<PackManifest> {
    if path.is_dir() {
        read_manifest_from_directory(path)
    } else {
        read_manifest_from_gtpack(path)
    }
}

fn build_search_summary(paths: &[SearchPath]) -> String {
    paths
        .iter()
        .map(|entry| format!("{} ({})", entry.label, entry.path.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sanitize_key(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Executes the resolved deployment pack via a registered executor.
///
/// Returns `Ok(true)` when an executor was registered and ran, `Ok(false)` when no executor is
/// available yet, and `Err` on fatal failures.
pub async fn execute_deployment_pack(
    config: &DeployerConfig,
    plan: &PlanContext,
    dispatch: &DeploymentDispatch,
) -> Result<Option<ExecutionOutcome>> {
    if let Some(executor) = deployment_executor() {
        let outcome = executor.execute(config, plan, dispatch).await?;
        return Ok(Some(outcome));
    }
    tracing::info!(
        capability = %dispatch.capability.as_str(),
        provider = %plan.deployment.provider,
        strategy = %plan.deployment.strategy,
        pack_id = %dispatch.pack_id,
        flow_id = %dispatch.flow_id,
        "deployment executor not registered"
    );
    Ok(None)
}

#[async_trait]
pub trait DeploymentExecutor: Send + Sync {
    async fn execute(
        &self,
        config: &DeployerConfig,
        plan: &PlanContext,
        dispatch: &DeploymentDispatch,
    ) -> Result<ExecutionOutcome>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub status: Option<String>,
    pub message: Option<String>,
    pub output_files: Vec<String>,
    pub payload: Option<ExecutionOutcomePayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecutionOutcomePayload {
    Apply(ApplyExecutionOutcome),
    Destroy(DestroyExecutionOutcome),
    Status(StatusExecutionOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyExecutionOutcome {
    pub deployment_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestroyExecutionOutcome {
    pub deployment_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusExecutionOutcome {
    pub deployment_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_checks: Vec<String>,
}

static EXECUTOR: Lazy<RwLock<Option<Arc<dyn DeploymentExecutor>>>> =
    Lazy::new(|| RwLock::new(None));

pub fn set_deployment_executor(executor: Arc<dyn DeploymentExecutor>) {
    let mut slot = EXECUTOR.write().expect("deployment executor lock poisoned");
    *slot = Some(executor);
}

#[cfg(test)]
pub fn clear_deployment_executor() {
    let mut slot = EXECUTOR.write().expect("deployment executor lock poisoned");
    *slot = None;
}

fn deployment_executor() -> Option<Arc<dyn DeploymentExecutor>> {
    EXECUTOR
        .read()
        .expect("deployment executor lock poisoned")
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeployerConfig, Provider};
    use crate::contract::{
        CapabilitySpecV1, DeployerCapability, DeployerContractV1, PlannerSpecV1,
        set_deployer_contract_v1,
    };
    use crate::pack_introspect;
    use greentic_types::cbor::encode_pack_manifest;
    use greentic_types::component::{ComponentCapabilities, ComponentManifest, ComponentProfiles};
    use greentic_types::pack_manifest::{PackKind, PackManifest};
    use greentic_types::{ComponentId, PackId};
    use semver::Version;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn resolves_default_entry() {
        let target = DeploymentTarget {
            provider: "generic".into(),
            strategy: "iac-only".into(),
        };
        let dispatch = resolve_dispatch(&target).expect("default mapping");
        assert_eq!(dispatch.pack_id, "greentic.deploy.generic");
        assert_eq!(dispatch.flow_id, "deploy_generic_iac");
        assert_eq!(dispatch.capability, DeployerCapability::Apply);
    }

    #[test]
    fn honors_env_override() {
        let target = DeploymentTarget {
            provider: "aws".into(),
            strategy: "serverless".into(),
        };
        let dispatch = resolve_dispatch_with_env(&target, |key| match key {
            "DEPLOY_TARGET_AWS_SERVERLESS_PACK_ID" => Some("custom.pack".into()),
            "DEPLOY_TARGET_AWS_SERVERLESS_FLOW_ID" => Some("flow_one".into()),
            _ => None,
        })
        .expect("env mapping");
        assert_eq!(dispatch.pack_id, "custom.pack");
        assert_eq!(dispatch.flow_id, "flow_one");
    }

    #[test]
    fn honors_provider_only_override() {
        let target = DeploymentTarget {
            provider: "aws".into(),
            strategy: "serverless".into(),
        };
        let dispatch = resolve_dispatch_with_env(&target, |key| match key {
            "DEPLOY_TARGET_AWS_PACK_ID" => Some("provider.pack".into()),
            "DEPLOY_TARGET_AWS_FLOW_ID" => Some("provider_flow".into()),
            _ => None,
        })
        .expect("provider fallback");
        assert_eq!(dispatch.pack_id, "provider.pack");
        assert_eq!(dispatch.flow_id, "provider_flow");
    }

    #[test]
    fn errors_when_override_incomplete() {
        let target = DeploymentTarget {
            provider: "aws".into(),
            strategy: "serverless".into(),
        };
        let err = resolve_dispatch_with_env(&target, |key| {
            if key == "DEPLOY_TARGET_AWS_SERVERLESS_PACK_ID" {
                Some("only-pack".into())
            } else {
                None
            }
        })
        .expect_err("missing flow");
        assert!(format!("{err}").contains("Incomplete deployment mapping overrides"));
    }

    struct TestExecutor {
        hits: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DeploymentExecutor for TestExecutor {
        async fn execute(
            &self,
            _config: &DeployerConfig,
            _plan: &PlanContext,
            _dispatch: &DeploymentDispatch,
        ) -> Result<ExecutionOutcome> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionOutcome {
                status: Some("applied".into()),
                message: Some("runner completed".into()),
                output_files: vec!["result.json".into()],
                payload: Some(ExecutionOutcomePayload::Apply(ApplyExecutionOutcome {
                    deployment_id: "dep-123".into(),
                    state: "ready".into(),
                    endpoints: vec!["https://deploy.example.test".into()],
                })),
            })
        }
    }

    #[tokio::test]
    async fn executes_via_registered_executor() {
        clear_deployment_executor();
        let hits = Arc::new(AtomicUsize::new(0));
        set_deployment_executor(Arc::new(TestExecutor { hits: hits.clone() }));
        let pack_path = write_test_pack();
        let config = DeployerConfig {
            capability: DeployerCapability::Plan,
            provider: Provider::Aws,
            strategy: "iac-only".into(),
            tenant: "acme".into(),
            environment: "staging".into(),
            pack_path,
            providers_dir: PathBuf::from("providers/deployer"),
            packs_dir: PathBuf::from("packs"),
            provider_pack: None,
            pack_ref: None,
            distributor_url: None,
            distributor_token: None,
            preview: false,
            dry_run: false,
            execute_local: false,
            output: crate::config::OutputFormat::Text,
            greentic: greentic_config::ConfigResolver::new()
                .load()
                .expect("load default config")
                .config,
            provenance: greentic_config::ProvenanceMap::new(),
            config_warnings: Vec::new(),
            deploy_pack_id_override: None,
            deploy_flow_id_override: None,
        };
        let plan = pack_introspect::build_plan(&config).expect("plan builds");
        let dispatch = DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "test.pack".into(),
            flow_id: "deploy_flow".into(),
        };
        let ran = execute_deployment_pack(&config, &plan, &dispatch)
            .await
            .expect("executor runs");
        let outcome = ran.expect("outcome");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.status.as_deref(), Some("applied"));
        assert_eq!(outcome.message.as_deref(), Some("runner completed"));
        assert_eq!(outcome.output_files, vec!["result.json".to_string()]);
        match outcome.payload.expect("payload") {
            ExecutionOutcomePayload::Apply(payload) => {
                assert_eq!(payload.deployment_id, "dep-123");
                assert_eq!(payload.state, "ready");
                assert_eq!(payload.endpoints, vec!["https://deploy.example.test"]);
            }
            other => panic!("unexpected outcome payload: {:?}", other),
        }
        clear_deployment_executor();
    }

    #[allow(deprecated)]
    fn write_test_pack() -> PathBuf {
        let base = env::current_dir().expect("cwd").join("target/tmp-tests");
        std::fs::create_dir_all(&base).expect("create tmp base");
        let dir = tempfile::tempdir_in(base).expect("temp dir");
        let manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::try_from("dev.greentic.sample").unwrap(),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Application,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: vec![ComponentManifest {
                id: ComponentId::try_from("dev.greentic.component").unwrap(),
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
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        };
        let bytes = encode_pack_manifest(&manifest).expect("encode manifest");
        std::fs::write(dir.path().join("manifest.cbor"), bytes).expect("write manifest");
        dir.into_path()
    }

    #[test]
    fn contract_owned_capability_flow_overrides_default_flow() {
        let manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::try_from("greentic.deploy.aws").unwrap(),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Provider,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: vec![],
            flows: vec![],
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        };
        let mut manifest = manifest;
        set_deployer_contract_v1(
            &mut manifest,
            DeployerContractV1 {
                schema_version: 1,
                planner: PlannerSpecV1 {
                    flow_id: "plan_pack".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    qa_spec_ref: None,
                },
                capabilities: vec![
                    CapabilitySpecV1 {
                        capability: DeployerCapability::Plan,
                        flow_id: "plan_pack".into(),
                        input_schema_ref: None,
                        output_schema_ref: None,
                        execution_output_schema_ref: None,
                        qa_spec_ref: None,
                        example_refs: Vec::new(),
                    },
                    CapabilitySpecV1 {
                        capability: DeployerCapability::Apply,
                        flow_id: "apply_pack".into(),
                        input_schema_ref: None,
                        output_schema_ref: None,
                        execution_output_schema_ref: None,
                        qa_spec_ref: None,
                        example_refs: Vec::new(),
                    },
                    CapabilitySpecV1 {
                        capability: DeployerCapability::Destroy,
                        flow_id: "destroy_pack".into(),
                        input_schema_ref: None,
                        output_schema_ref: None,
                        execution_output_schema_ref: None,
                        qa_spec_ref: None,
                        example_refs: Vec::new(),
                    },
                ],
            },
        )
        .unwrap();

        let fallback = DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.aws".into(),
            flow_id: "deploy_aws_iac".into(),
        };
        let resolved =
            resolve_contract_dispatch(&manifest, DeployerCapability::Destroy, &fallback).unwrap();
        assert_eq!(resolved.pack_id, "greentic.deploy.aws");
        assert_eq!(resolved.flow_id, "destroy_pack");
        assert_eq!(resolved.capability, DeployerCapability::Destroy);
    }

    #[test]
    fn missing_contract_capability_errors() {
        let mut manifest = PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::try_from("greentic.deploy.aws").unwrap(),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Provider,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: vec![],
            flows: vec![],
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        };
        set_deployer_contract_v1(
            &mut manifest,
            DeployerContractV1 {
                schema_version: 1,
                planner: PlannerSpecV1 {
                    flow_id: "plan_pack".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    qa_spec_ref: None,
                },
                capabilities: vec![CapabilitySpecV1 {
                    capability: DeployerCapability::Plan,
                    flow_id: "plan_pack".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    execution_output_schema_ref: None,
                    qa_spec_ref: None,
                    example_refs: Vec::new(),
                }],
            },
        )
        .unwrap();

        let fallback = DeploymentDispatch {
            capability: DeployerCapability::Apply,
            pack_id: "greentic.deploy.aws".into(),
            flow_id: "deploy_aws_iac".into(),
        };
        let err = resolve_contract_dispatch(&manifest, DeployerCapability::Rollback, &fallback)
            .unwrap_err();
        assert!(format!("{err}").contains("does not declare `rollback` capability"));
    }
}
