use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use thiserror::Error;

/// Structured errors from the typed path-safety helpers
/// ([`assert_no_symlink_ancestors`]). [`normalize_under_root`] keeps its
/// anyhow shape for backwards compatibility with the existing
/// `pack_introspect` consumer.
#[derive(Debug, Error)]
pub enum PathSafetyError {
    #[error("path component `{}` is a symlink (escape risk)", .path.display())]
    SymlinkAncestor { path: PathBuf },
    #[error("io error on `{}`: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Walk every existing ancestor of `target` that is a proper descendant of
/// `root` (inclusive of `target` itself) and reject if any is a symlink.
///
/// Only existing ancestors are checked — non-existent path segments are
/// fine (callers typically follow this with `create_dir_all`). Same posture
/// as the P0.4 symlink-TOCTOU defense in the bundle extractors: the check
/// must run immediately before the write, under whatever flock the caller
/// holds, so the race window is bounded to that flock's scope.
///
/// Returns `Ok(())` (no-op) when `target` is not under `root`; callers that
/// need that to be an error should validate the prefix themselves before
/// calling.
pub fn assert_no_symlink_ancestors(root: &Path, target: &Path) -> Result<(), PathSafetyError> {
    let suffix = match target.strip_prefix(root) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let mut current = root.to_path_buf();
    for component in suffix.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_symlink() => {
                return Err(PathSafetyError::SymlinkAncestor { path: current });
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(PathSafetyError::Io {
                    path: current,
                    source: e,
                });
            }
        }
    }
    Ok(())
}

/// Normalize a user-supplied path and ensure it stays within an allowed root.
/// Rejects absolute paths and any that escape via `..`.
pub fn normalize_under_root(root: &Path, candidate: &Path) -> Result<PathBuf> {
    if candidate.is_absolute() {
        anyhow::bail!("absolute paths are not allowed: {}", candidate.display());
    }

    let root_canon = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;
    let joined = root_canon.join(candidate);
    let canon = joined
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", joined.display()))?;

    if !canon.starts_with(&root_canon) {
        anyhow::bail!(
            "path escapes root ({}): {}",
            root_canon.display(),
            canon.display()
        );
    }

    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn assert_no_symlink_ancestors_passes_on_plain_dirs() {
        let root = tempdir().unwrap();
        let nested = root.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let target = nested.join("c.txt");
        assert!(assert_no_symlink_ancestors(root.path(), &target).is_ok());
    }

    #[test]
    fn assert_no_symlink_ancestors_passes_on_nonexistent_tail() {
        let root = tempdir().unwrap();
        // `a/` doesn't exist; the walk stops at the first NotFound.
        let target = root.path().join("a").join("b").join("c.txt");
        assert!(assert_no_symlink_ancestors(root.path(), &target).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn assert_no_symlink_ancestors_rejects_symlink_component() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        // Pre-create `root/rules` as a symlink to a sibling dir.
        symlink(elsewhere.path(), root.path().join("rules")).unwrap();
        let target = root.path().join("rules").join("aws-ecs").join("policy.tf");
        let err = assert_no_symlink_ancestors(root.path(), &target).unwrap_err();
        assert!(
            matches!(err, PathSafetyError::SymlinkAncestor { ref path } if path.ends_with("rules")),
            "expected SymlinkAncestor at the `rules` segment, got {err:?}"
        );
    }

    #[test]
    fn assert_no_symlink_ancestors_noop_when_target_outside_root() {
        // strip_prefix fails when target is not under root — contract is
        // explicit no-op (callers validate prefix themselves if needed).
        let root = tempdir().unwrap();
        let other = tempdir().unwrap();
        assert!(assert_no_symlink_ancestors(root.path(), other.path()).is_ok());
    }
}
