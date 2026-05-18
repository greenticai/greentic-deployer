//! Atomic file write helpers for the [`EnvironmentStore`](super::EnvironmentStore).
//!
//! The store mutates persistent state through the same pattern everywhere:
//!
//! 1. Create a `NamedTempFile` in the **same directory** as the target so the
//!    final `rename` is intra-filesystem (otherwise rename would fall back to
//!    copy+unlink and lose atomicity).
//! 2. Write the bytes; `flush()` + `sync_all()` so the data hits disk.
//! 3. `persist(target)` atomically renames over the existing target.
//! 4. On Unix, `fsync()` the parent directory so the rename itself is durable
//!    across power loss.
//!
//! Callers that want to back up the current target before clobbering it should
//! call [`copy_to_backup`] first.

use std::fs;
use std::io::Write;
use std::path::Path;

use chrono::Utc;
use serde::Serialize;
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AtomicWriteError {
    #[error("target path has no parent directory: {0}")]
    NoParent(std::path::PathBuf),
    #[error("io error on {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("serde_json error on {path}: {source}")]
    Json {
        path: std::path::PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not persist temp file over {target}: {source}")]
    Persist {
        target: std::path::PathBuf,
        #[source]
        source: tempfile::PersistError,
    },
}

/// Atomically write `bytes` to `target`, fsyncing the parent directory afterward.
pub fn atomic_write_bytes(target: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
    let parent = target
        .parent()
        .ok_or_else(|| AtomicWriteError::NoParent(target.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|e| AtomicWriteError::Io {
        path: parent.to_path_buf(),
        source: e,
    })?;
    let mut tmp = NamedTempFile::new_in(parent).map_err(|e| AtomicWriteError::Io {
        path: parent.to_path_buf(),
        source: e,
    })?;
    tmp.write_all(bytes).map_err(|e| AtomicWriteError::Io {
        path: tmp.path().to_path_buf(),
        source: e,
    })?;
    tmp.flush().map_err(|e| AtomicWriteError::Io {
        path: tmp.path().to_path_buf(),
        source: e,
    })?;
    tmp.as_file().sync_all().map_err(|e| AtomicWriteError::Io {
        path: tmp.path().to_path_buf(),
        source: e,
    })?;
    tmp.persist(target).map_err(|e| AtomicWriteError::Persist {
        target: target.to_path_buf(),
        source: e,
    })?;
    fsync_parent(parent)?;
    Ok(())
}

/// Atomically write `value` as pretty-printed JSON (trailing newline) to `target`.
pub fn atomic_write_json<T: Serialize>(target: &Path, value: &T) -> Result<(), AtomicWriteError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| AtomicWriteError::Json {
        path: target.to_path_buf(),
        source: e,
    })?;
    bytes.push(b'\n');
    atomic_write_bytes(target, &bytes)
}

/// If `target` exists, copy it to `<backup_dir>/<target.file_name>.<rfc3339-utc>.bak`
/// and return the backup path. If it does not exist, return `Ok(None)`.
pub fn copy_to_backup(
    target: &Path,
    backup_dir: &Path,
) -> Result<Option<std::path::PathBuf>, AtomicWriteError> {
    if !target.exists() {
        return Ok(None);
    }
    fs::create_dir_all(backup_dir).map_err(|e| AtomicWriteError::Io {
        path: backup_dir.to_path_buf(),
        source: e,
    })?;
    let filename = target
        .file_name()
        .ok_or_else(|| AtomicWriteError::NoParent(target.to_path_buf()))?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
    let mut backup = backup_dir.join(filename);
    let new_name = format!(
        "{}.{}.bak",
        backup
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("backup"),
        stamp
    );
    backup.set_file_name(new_name);
    fs::copy(target, &backup).map_err(|e| AtomicWriteError::Io {
        path: backup.clone(),
        source: e,
    })?;
    Ok(Some(backup))
}

#[cfg(unix)]
fn fsync_parent(parent: &Path) -> Result<(), AtomicWriteError> {
    let dir = fs::File::open(parent).map_err(|e| AtomicWriteError::Io {
        path: parent.to_path_buf(),
        source: e,
    })?;
    dir.sync_all().map_err(|e| AtomicWriteError::Io {
        path: parent.to_path_buf(),
        source: e,
    })
}

#[cfg(not(unix))]
fn fsync_parent(_parent: &Path) -> Result<(), AtomicWriteError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_bytes_round_trip() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("hello.txt");
        atomic_write_bytes(&target, b"hello world").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"hello world");
    }

    #[test]
    fn write_json_round_trip() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("doc.json");
        let value = serde_json::json!({ "k": [1, 2, 3] });
        atomic_write_json(&target, &value).unwrap();
        let read: serde_json::Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(read, value);
        let raw = fs::read_to_string(&target).unwrap();
        assert!(raw.ends_with('\n'), "expected trailing newline");
    }

    #[test]
    fn write_creates_missing_parent() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("a/b/c/file.json");
        atomic_write_json(&target, &serde_json::json!({})).unwrap();
        assert!(target.exists());
    }

    #[test]
    fn overwrites_existing_file() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("doc.json");
        atomic_write_bytes(&target, b"first").unwrap();
        atomic_write_bytes(&target, b"second").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
    }

    #[test]
    fn copy_to_backup_no_target() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("never.json");
        let backup = tmp.path().join("backups");
        assert!(copy_to_backup(&target, &backup).unwrap().is_none());
        assert!(!backup.exists());
    }

    #[test]
    fn copy_to_backup_creates_timestamped_copy() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("doc.json");
        atomic_write_bytes(&target, b"v1").unwrap();
        let backup_dir = tmp.path().join("backups");
        let backup_path = copy_to_backup(&target, &backup_dir)
            .unwrap()
            .expect("backup should be Some when target exists");
        assert_eq!(fs::read(&backup_path).unwrap(), b"v1");
        assert!(backup_path.starts_with(&backup_dir));
        let name = backup_path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("doc.json."), "got: {name}");
        assert!(name.ends_with(".bak"), "got: {name}");
    }

    #[test]
    fn no_partial_state_if_serialization_succeeds() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("doc.json");
        // After two writes, only the second should survive — there should be
        // no orphaned tempfiles left in the parent dir.
        atomic_write_bytes(&target, b"first").unwrap();
        atomic_write_bytes(&target, b"second").unwrap();
        let entries: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
