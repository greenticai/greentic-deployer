use std::path::{Path, PathBuf};

use crate::ext::describe::{parse_describe, DeployExtensionDescribe};
use crate::ext::errors::{ExtensionError, ExtensionResult};

/// Default on-disk root for deploy extensions.
pub const DEFAULT_DIR_ENV: &str = "GREENTIC_DEPLOY_EXT_DIR";

/// A successfully-loaded extension: describe.json parsed + wasm path recorded.
/// wasmtime::Component instantiation is lazy; see `wasm.rs`.
#[derive(Debug, Clone)]
pub struct LoadedExtension {
    pub root_dir: PathBuf,
    pub describe: DeployExtensionDescribe,
    pub wasm_path: PathBuf,
}

/// Resolve the directory to scan: explicit override > env var > default (`~/.greentic/extensions/deploy/`).
pub fn resolve_extension_dir(explicit: Option<&Path>) -> PathBuf {
    resolve_extension_dir_with_env(explicit, |k| std::env::var(k).ok())
}

fn resolve_extension_dir_with_env(
    explicit: Option<&Path>,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Some(e) = env_lookup(DEFAULT_DIR_ENV) {
        if !e.is_empty() {
            return PathBuf::from(e);
        }
    }
    dirs_root_default()
}

fn dirs_root_default() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".greentic").join("extensions").join("deploy");
    }
    PathBuf::from("/var/empty/greentic/extensions/deploy")
}

/// Scan `dir` for extension subdirectories. Each valid extension is a directory
/// containing `describe.json` + the referenced `runtime.component` wasm file.
/// Missing dirs return empty (not an error — allows first-run UX).
/// Malformed extensions are skipped with a warning.
pub fn scan(dir: &Path) -> ExtensionResult<Vec<LoadedExtension>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    if !dir.is_dir() {
        return Err(ExtensionError::DirNotFound(dir.to_path_buf()));
    }
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|_| ExtensionError::DirNotFound(dir.to_path_buf()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        match load_one(&path) {
            Ok(ext) => out.push(ext),
            Err(e) => tracing::warn!(
                extension_dir = %path.display(),
                error = %e,
                "skipping malformed extension"
            ),
        }
    }
    out.sort_by(|a, b| a.describe.metadata.id.cmp(&b.describe.metadata.id));
    Ok(out)
}

fn load_one(dir: &Path) -> ExtensionResult<LoadedExtension> {
    let describe_path = dir.join("describe.json");
    let describe = parse_describe(&describe_path)?;
    let wasm_path = dir.join(&describe.runtime.component);
    if !wasm_path.exists() {
        return Err(ExtensionError::DescribeParse {
            path: describe_path,
            source: serde::de::Error::custom(format!(
                "referenced component {:?} not found",
                describe.runtime.component
            )),
        });
    }
    Ok(LoadedExtension {
        root_dir: dir.to_path_buf(),
        describe,
        wasm_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn seed_ext(root: &Path, id: &str, targets_json: &str) -> PathBuf {
        let dir = root.join(id);
        fs::create_dir_all(&dir).unwrap();
        let describe = format!(
            r#"{{
            "apiVersion": "greentic.ai/v1",
            "kind": "DeployExtension",
            "metadata": {{ "id": "{id}", "version": "0.1.0" }},
            "runtime": {{ "component": "extension.wasm" }},
            "contributions": {{ "targets": {targets_json} }}
        }}"#
        );
        fs::write(dir.join("describe.json"), describe).unwrap();
        fs::write(dir.join("extension.wasm"), b"\x00asm\x01\x00\x00\x00").unwrap();
        dir
    }

    #[test]
    fn scan_empty_dir_returns_empty() {
        let td = tempfile::tempdir().unwrap();
        let v = scan(td.path()).expect("scan");
        assert!(v.is_empty());
    }

    #[test]
    fn scan_missing_dir_returns_empty() {
        let td = tempfile::tempdir().unwrap();
        let missing = td.path().join("nope");
        let v = scan(&missing).expect("scan");
        assert!(v.is_empty());
    }

    #[test]
    fn scan_discovers_two_extensions_sorted() {
        let td = tempfile::tempdir().unwrap();
        seed_ext(
            td.path(),
            "greentic.deploy-zed",
            r#"[{"id":"t1","displayName":"T1","execution":{"kind":"wasm"}}]"#,
        );
        seed_ext(
            td.path(),
            "greentic.deploy-aardvark",
            r#"[{"id":"t2","displayName":"T2","execution":{"kind":"wasm"}}]"#,
        );
        let v = scan(td.path()).expect("scan");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].describe.metadata.id, "greentic.deploy-aardvark");
        assert_eq!(v[1].describe.metadata.id, "greentic.deploy-zed");
    }

    #[test]
    fn scan_skips_malformed_but_returns_others() {
        let td = tempfile::tempdir().unwrap();
        seed_ext(
            td.path(),
            "greentic.good",
            r#"[{"id":"t","displayName":"T","execution":{"kind":"wasm"}}]"#,
        );
        let bad = td.path().join("greentic.bad");
        fs::create_dir_all(&bad).unwrap();
        fs::write(bad.join("describe.json"), "{ not json").unwrap();
        let v = scan(td.path()).expect("scan");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].describe.metadata.id, "greentic.good");
    }

    #[test]
    fn scan_skips_ext_missing_wasm_component() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().join("greentic.nowasm");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("describe.json"),
            r#"{"apiVersion":"greentic.ai/v1","kind":"DeployExtension",
                "metadata":{"id":"greentic.nowasm","version":"0.1.0"},
                "runtime":{"component":"extension.wasm"},
                "contributions":{"targets":[]}}"#,
        )
        .unwrap();
        let v = scan(td.path()).expect("scan");
        assert!(v.is_empty());
    }

    #[test]
    fn resolve_env_override_wins() {
        let td = tempfile::tempdir().unwrap();
        let td_path = td.path().to_path_buf();
        let resolved = resolve_extension_dir_with_env(None, |k| {
            if k == DEFAULT_DIR_ENV {
                Some(td_path.display().to_string())
            } else {
                None
            }
        });
        assert_eq!(resolved, td.path());
    }
}
