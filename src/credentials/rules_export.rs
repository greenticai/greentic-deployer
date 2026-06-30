//! Rules-pack writer for the bootstrap flow.
//!
//! When a deployer's [`super::DeployerCredentials::bootstrap`] succeeds,
//! it returns a [`RulesPack`] — a bag of IaC files (Terraform / OpenTofu
//! HCL, kubectl YAML, Helm values, Pulumi / Bicep, anything the deployer
//! wants) that the customer's admin can review and apply offline so the
//! same minimum-privilege roles/policies/SAs/secrets-paths exist on
//! whichever target environment they govern.
//!
//! The writer lays the entries down under `<env_root>/rules/` with a
//! per-pack subdirectory keyed by the deployer's `PackDescriptor`. Each
//! entry's `filename` is treated as path-relative and rejected if it
//! escapes the per-pack subdir (no `..`, no absolute, no symlink
//! components — same posture as the bundle extractors hardened in
//! P0.4). An `index.json` summary lands alongside so a reviewer can see
//! every rendered artifact at a glance.
//!
//! Files are written atomically (NamedTempFile → flush → fsync(parent)
//! pattern, same shape as [`crate::environment::atomic_write_bytes`]).

use std::path::{Component, Path, PathBuf};

use greentic_deploy_spec::PackDescriptor;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesPackEntry {
    /// Relative filename under `<env_root>/rules/<deployer-path>/`.
    /// Rejected if it contains `..`, is absolute, or otherwise tries to
    /// escape the per-pack subdir.
    pub filename: String,
    /// File contents. Format is implicit in the filename's extension
    /// (e.g. `.tf` → Terraform HCL).
    pub content: String,
    /// Optional one-line description for the `index.json` summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesPack {
    pub entries: Vec<RulesPackEntry>,
}

impl RulesPack {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum RulesExportError {
    #[error("rules entry filename `{0}` is empty")]
    EmptyFilename(String),
    #[error("rules entry filename `{0}` escapes the per-pack subdir")]
    UnsafeFilename(String),
    #[error("symlink detected at `{path}` under env root — refusing to write through it")]
    SymlinkAncestor { path: PathBuf },
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("serializing rules index failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Write `pack` to `<env_root>/rules/<deployer-path>/` and return the
/// env-relative path to the directory (for `CredentialsBootstrap.rules_pack_ref`).
///
/// Empty packs return a path to an empty directory — kept structural so
/// the bootstrap doc always has a `rules_pack_ref` regardless of whether
/// the deployer emitted any IaC. An empty pack is honest about
/// deployers (like local-process) that have nothing to apply offline;
/// they should prefer [`super::BootstrapError::NotApplicable`] over an
/// empty pack, but the writer accepts both.
pub fn write_rules_pack(
    env_root: &Path,
    deployer: &PackDescriptor,
    pack: &RulesPack,
) -> Result<PathBuf, RulesExportError> {
    let pack_subdir = PathBuf::from("rules").join(deployer.path());
    let pack_dir = env_root.join(&pack_subdir);

    // P0.4-equivalent posture: reject any existing symlink component under
    // env_root before creating directories or writing files. Without this
    // check, a pre-existing symlink at `env_root/rules/` or
    // `env_root/rules/<deployer-path>` would cause `create_dir_all` to
    // succeed (following the symlink) and writes would land outside the
    // per-pack rules directory.
    crate::path_safety::assert_no_symlink_ancestors(env_root, &pack_dir)
        .map_err(map_path_safety)?;

    create_dir_all(&pack_dir)?;

    for entry in &pack.entries {
        validate_filename(&entry.filename)?;
        let target = pack_dir.join(&entry.filename);
        atomic_write(&target, entry.content.as_bytes())?;
    }

    let index_path = pack_dir.join("index.json");
    let index_json = serde_json::to_vec_pretty(&IndexFile::from(pack))?;
    atomic_write(&index_path, &index_json)?;

    Ok(pack_subdir)
}

fn validate_filename(name: &str) -> Result<(), RulesExportError> {
    if name.is_empty() {
        return Err(RulesExportError::EmptyFilename(name.to_string()));
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return Err(RulesExportError::UnsafeFilename(name.to_string()));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            // `.` is the only no-op we allow; anything else (`..`,
            // `RootDir`, `Prefix`) is rejected.
            Component::CurDir => {}
            _ => return Err(RulesExportError::UnsafeFilename(name.to_string())),
        }
    }
    Ok(())
}

fn create_dir_all(path: &Path) -> Result<(), RulesExportError> {
    std::fs::create_dir_all(path).map_err(|source| RulesExportError::Io {
        path: path.to_path_buf(),
        source,
    })
}

// `assert_no_symlink_ancestors` lives in `crate::path_safety` — the shared
// home for P0.4-style symlink-TOCTOU defenses so future extractors and
// writers consult the same gate. Local mapping of its typed error into
// `RulesExportError` is in `map_path_safety` below.

fn map_path_safety(e: crate::path_safety::PathSafetyError) -> RulesExportError {
    use crate::path_safety::PathSafetyError;
    match e {
        PathSafetyError::SymlinkAncestor { path } => RulesExportError::SymlinkAncestor { path },
        PathSafetyError::Io { path, source } => RulesExportError::Io { path, source },
    }
}

/// Delegate to the canonical atomic-write helper in
/// `crate::environment::atomic_write` (the same NamedTempFile → flush →
/// sync_all → persist → fsync(parent) pipeline the store uses for env
/// state). Map the typed error into [`RulesExportError`] so callers get
/// the rules-pack error envelope.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RulesExportError> {
    use crate::environment::atomic_write::{AtomicWriteError, atomic_write_bytes};
    atomic_write_bytes(path, bytes).map_err(|e| match e {
        AtomicWriteError::Io { path, source } => RulesExportError::Io { path, source },
        AtomicWriteError::NoParent(path) => RulesExportError::Io {
            path,
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir"),
        },
        AtomicWriteError::Persist { target, source } => RulesExportError::Io {
            path: target,
            source: source.error,
        },
        other => RulesExportError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(other.to_string()),
        },
    })
}

#[derive(Serialize)]
struct IndexFile {
    schema: &'static str,
    entries: Vec<IndexEntry>,
}

#[derive(Serialize)]
struct IndexEntry {
    filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    bytes: usize,
}

impl From<&RulesPack> for IndexFile {
    fn from(pack: &RulesPack) -> Self {
        Self {
            schema: "greentic.rules-pack.index.v1",
            entries: pack
                .entries
                .iter()
                .map(|e| IndexEntry {
                    filename: e.filename.clone(),
                    description: e.description.clone(),
                    bytes: e.content.len(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn descriptor(raw: &str) -> PackDescriptor {
        PackDescriptor::try_new(raw).expect("descriptor parses")
    }

    #[test]
    fn writes_entries_and_index_under_deployer_path() {
        let dir = tempdir().unwrap();
        let pack = RulesPack {
            entries: vec![
                RulesPackEntry {
                    filename: "iam-policy.json".into(),
                    content: "{\"Version\":\"2012-10-17\"}".into(),
                    description: Some("min IAM policy".into()),
                },
                RulesPackEntry {
                    filename: "trust.tf".into(),
                    content: "resource \"aws_iam_role\" \"x\" {}".into(),
                    description: None,
                },
            ],
        };
        let rel = write_rules_pack(
            dir.path(),
            &descriptor("greentic.deployer.aws-ecs@1.0.0"),
            &pack,
        )
        .unwrap();
        assert_eq!(
            rel,
            PathBuf::from("rules").join("greentic.deployer.aws-ecs")
        );

        let pack_dir = dir.path().join(&rel);
        assert!(pack_dir.join("iam-policy.json").exists());
        assert!(pack_dir.join("trust.tf").exists());
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(pack_dir.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["schema"], "greentic.rules-pack.index.v1");
        assert_eq!(index["entries"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn empty_pack_writes_only_index() {
        let dir = tempdir().unwrap();
        let rel = write_rules_pack(
            dir.path(),
            &descriptor("greentic.deployer.local-process@0.1.0"),
            &RulesPack::empty(),
        )
        .unwrap();
        let pack_dir = dir.path().join(rel);
        assert!(pack_dir.join("index.json").exists());
        let entries: Vec<_> = std::fs::read_dir(&pack_dir).unwrap().collect();
        assert_eq!(
            entries.len(),
            1,
            "only index.json should be written for an empty pack"
        );
    }

    #[test]
    fn rejects_dot_dot_filename() {
        let dir = tempdir().unwrap();
        let pack = RulesPack {
            entries: vec![RulesPackEntry {
                filename: "../escape.tf".into(),
                content: "x".into(),
                description: None,
            }],
        };
        let err = write_rules_pack(
            dir.path(),
            &descriptor("greentic.deployer.aws-ecs@1.0.0"),
            &pack,
        )
        .unwrap_err();
        assert!(matches!(err, RulesExportError::UnsafeFilename(_)));
    }

    #[test]
    fn rejects_absolute_filename() {
        let dir = tempdir().unwrap();
        let pack = RulesPack {
            entries: vec![RulesPackEntry {
                filename: "/etc/passwd".into(),
                content: "x".into(),
                description: None,
            }],
        };
        let err = write_rules_pack(
            dir.path(),
            &descriptor("greentic.deployer.aws-ecs@1.0.0"),
            &pack,
        )
        .unwrap_err();
        assert!(matches!(err, RulesExportError::UnsafeFilename(_)));
    }

    #[test]
    fn rejects_empty_filename() {
        let dir = tempdir().unwrap();
        let pack = RulesPack {
            entries: vec![RulesPackEntry {
                filename: "".into(),
                content: "x".into(),
                description: None,
            }],
        };
        let err = write_rules_pack(
            dir.path(),
            &descriptor("greentic.deployer.aws-ecs@1.0.0"),
            &pack,
        )
        .unwrap_err();
        assert!(matches!(err, RulesExportError::EmptyFilename(_)));
    }

    /// Regression: if `<env_root>/rules` already exists as a symlink
    /// pointing outside the env root, `write_rules_pack` must reject
    /// instead of following the symlink and writing outside the env.
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_rules_dir() {
        let env_root = tempdir().unwrap();
        let escape_target = tempdir().unwrap();
        let rules_link = env_root.path().join("rules");
        std::os::unix::fs::symlink(escape_target.path(), &rules_link).unwrap();

        let pack = RulesPack {
            entries: vec![RulesPackEntry {
                filename: "policy.json".into(),
                content: "{}".into(),
                description: None,
            }],
        };
        let err = write_rules_pack(
            env_root.path(),
            &descriptor("greentic.deployer.aws-ecs@1.0.0"),
            &pack,
        )
        .unwrap_err();
        assert!(
            matches!(err, RulesExportError::SymlinkAncestor { .. }),
            "got {err:?}"
        );
        // Verify nothing was written to the escape target.
        assert!(
            std::fs::read_dir(escape_target.path())
                .unwrap()
                .next()
                .is_none(),
            "escape target should be empty"
        );
    }
}
