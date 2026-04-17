use std::collections::HashMap;
use std::path::PathBuf;

use crate::ext::describe::DeployTargetContribution;
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::ext::loader::LoadedExtension;

/// A resolved target: where it came from (ext id) and how to execute it.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub ext_id: String,
    pub wasm_path: PathBuf,
    pub contribution: DeployTargetContribution,
}

/// Registry unifying loaded WASM extensions' targets. (Built-in backends are
/// dispatched directly through `cli_builtin_dispatch` and do not appear here —
/// extensions are the only way to contribute *new* target-ids.)
pub struct ExtensionRegistry {
    entries: HashMap<String, ResolvedTarget>,
    conflicts: Vec<ConflictRecord>,
}

#[derive(Debug, Clone)]
pub struct ConflictRecord {
    pub target_id: String,
    pub providers: Vec<String>,
}

impl ExtensionRegistry {
    pub fn build(loaded: Vec<LoadedExtension>) -> Self {
        let mut entries: HashMap<String, ResolvedTarget> = HashMap::new();
        let mut providers: HashMap<String, Vec<String>> = HashMap::new();

        for ext in loaded {
            let ext_id = ext.describe.metadata.id.clone();
            for contrib in ext.describe.contributions.targets {
                providers
                    .entry(contrib.id.clone())
                    .or_default()
                    .push(ext_id.clone());
                entries.entry(contrib.id.clone()).or_insert(ResolvedTarget {
                    ext_id: ext_id.clone(),
                    wasm_path: ext.wasm_path.clone(),
                    contribution: contrib,
                });
            }
        }

        let conflicts: Vec<ConflictRecord> = providers
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(target_id, providers)| ConflictRecord {
                target_id,
                providers,
            })
            .collect();

        for c in &conflicts {
            tracing::warn!(
                target_id = %c.target_id,
                providers = ?c.providers,
                "target provided by multiple extensions"
            );
        }

        Self { entries, conflicts }
    }

    pub fn resolve(&self, target_id: &str) -> ExtensionResult<&ResolvedTarget> {
        if let Some(c) = self.conflicts.iter().find(|c| c.target_id == target_id) {
            return Err(ExtensionError::TargetConflict {
                target_id: target_id.into(),
                a: c.providers.first().cloned().unwrap_or_default(),
                b: c.providers.get(1).cloned().unwrap_or_default(),
            });
        }
        self.entries
            .get(target_id)
            .ok_or_else(|| ExtensionError::TargetNotFound(target_id.into()))
    }

    pub fn list(&self) -> impl Iterator<Item = &ResolvedTarget> {
        self.entries.values()
    }

    pub fn conflicts(&self) -> &[ConflictRecord] {
        &self.conflicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::describe::{
        Capabilities, DeployContributions, DeployExtensionDescribe, DeployTargetContribution,
        Engine, Execution, Metadata, RuntimeSpec,
    };

    fn make_ext(id: &str, target_ids: &[&str]) -> LoadedExtension {
        LoadedExtension {
            root_dir: PathBuf::from("/tmp/fake"),
            wasm_path: PathBuf::from("/tmp/fake/extension.wasm"),
            describe: DeployExtensionDescribe {
                api_version: "greentic.ai/v1".into(),
                kind: "DeployExtension".into(),
                metadata: Metadata {
                    id: id.into(),
                    version: "0.1.0".into(),
                    summary: None,
                },
                engine: Engine::default(),
                capabilities: Capabilities::default(),
                runtime: RuntimeSpec {
                    component: "extension.wasm".into(),
                    memory_limit_mb: None,
                    permissions: serde_json::Value::Null,
                },
                contributions: DeployContributions {
                    targets: target_ids
                        .iter()
                        .map(|t| DeployTargetContribution {
                            id: (*t).into(),
                            display_name: format!("{t} display"),
                            description: None,
                            icon_path: None,
                            supports_rollback: false,
                            execution: Execution::Builtin {
                                backend: "terraform".into(),
                                handler: None,
                            },
                        })
                        .collect(),
                },
            },
        }
    }

    #[test]
    fn build_unique_targets_resolves() {
        let r = ExtensionRegistry::build(vec![
            make_ext("greentic.a", &["t1", "t2"]),
            make_ext("greentic.b", &["t3"]),
        ]);
        assert!(r.conflicts().is_empty());
        assert_eq!(r.list().count(), 3);
        assert_eq!(r.resolve("t1").unwrap().ext_id, "greentic.a");
        assert_eq!(r.resolve("t3").unwrap().ext_id, "greentic.b");
    }

    #[test]
    fn conflict_recorded_and_resolve_errors() {
        let r = ExtensionRegistry::build(vec![
            make_ext("greentic.a", &["dup"]),
            make_ext("greentic.b", &["dup"]),
        ]);
        assert_eq!(r.conflicts().len(), 1);
        let err = r.resolve("dup").unwrap_err();
        assert!(matches!(err, ExtensionError::TargetConflict { .. }));
    }

    #[test]
    fn resolve_missing_target_errors() {
        let r = ExtensionRegistry::build(vec![make_ext("greentic.a", &["t1"])]);
        let err = r.resolve("nope").unwrap_err();
        assert!(matches!(err, ExtensionError::TargetNotFound(_)));
    }
}
