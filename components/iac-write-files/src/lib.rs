//! Minimal `write-files` component that writes text files under `/out`.
//! This implements the `greentic:host/iac-write-files@1.0.0` contract.
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_OUT_DIR: &str = "/out";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSpec {
    pub path: String,
    pub content: String,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct WriteError {
    pub code: u32,
    pub message: String,
    pub path: Option<String>,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "write error [{}]: {}", self.code, self.message)?;
        if let Some(path) = &self.path {
            write!(f, " ({})", path)?;
        }
        Ok(())
    }
}

impl std::error::Error for WriteError {}

pub fn write_files(files: &[FileSpec], out_dir: &Path) -> Result<Vec<PathBuf>, WriteError> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut written = Vec::with_capacity(files.len());

    for spec in files {
        let sanitized = sanitize_rel_path(&spec.path).map_err(|msg| WriteError {
            code: 2,
            message: msg,
            path: Some(spec.path.clone()),
        })?;
        let target = out_dir.join(&sanitized);
        if !spec.overwrite && (target.exists() || target.is_file()) {
            return Err(WriteError {
                code: 3,
                message: "file exists and overwrite is false".to_string(),
                path: Some(sanitized.display().to_string()),
            });
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|err| WriteError {
                code: 4,
                message: format!("failed to create parent directories: {err:#}"),
                path: Some(parent.display().to_string()),
            })?;
        }

        fs::write(&target, spec.content.as_bytes()).map_err(|err| WriteError {
            code: 5,
            message: format!("failed to write file: {err:#}"),
            path: Some(sanitized.display().to_string()),
        })?;

        written.push(sanitized);
    }

    Ok(written)
}

fn sanitize_rel_path(path: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Err("absolute paths are not allowed".into());
    }
    if candidate
        .components()
        .any(|comp| matches!(comp, std::path::Component::ParentDir))
    {
        return Err("path traversal is not allowed".into());
    }
    Ok(candidate.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_files_under_out() {
        let temp = tempdir().unwrap();
        let out = temp.path().join("out");
        let specs = vec![
            FileSpec {
                path: "README.md".into(),
                content: "hello".into(),
                overwrite: false,
            },
            FileSpec {
                path: "iac.placeholder".into(),
                content: "provider: local".into(),
                overwrite: true,
            },
        ];
        let result = write_files(&specs, &out).expect("write succeeds");
        assert_eq!(result.len(), 2);
        assert!(out.join("README.md").exists());
        assert!(out.join("iac.placeholder").exists());
    }

    #[test]
    fn rejects_absolute_path() {
        let temp = tempdir().unwrap();
        let err = write_files(
            &[FileSpec {
                path: "/etc/passwd".into(),
                content: "".into(),
                overwrite: false,
            }],
            temp.path(),
        )
        .unwrap_err();
        assert!(err.message.contains("absolute"));
    }

    #[test]
    fn rejects_path_traversal() {
        let temp = tempdir().unwrap();
        let err = write_files(
            &[FileSpec {
                path: "../secret".into(),
                content: "".into(),
                overwrite: false,
            }],
            temp.path(),
        )
        .unwrap_err();
        assert!(err.message.contains("traversal"));
    }
}
