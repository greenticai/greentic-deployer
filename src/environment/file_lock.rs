//! Per-env exclusive file lock used by [`LocalFsStore`](super::LocalFsStore).
//!
//! Each environment has a sentinel file at `<env_root>/.lock`. The store opens
//! it and takes a blocking exclusive `flock`/`LockFileEx` via the `fs4` crate.
//! The lock is bound to the file descriptor — closing the file releases it,
//! so [`EnvFlock`] is just an owning wrapper over [`std::fs::File`] and Drop
//! does the right thing without any unsafe self-reference tricks.
//!
//! Locks coordinate concurrent writers in the same process and across
//! processes on the same host. They do NOT replace generations/ETags for
//! distributed scenarios (that's A8 in `plans/next-gen-deployment.md`).

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockError {
    #[error("could not open or create lock file at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not acquire exclusive lock at {path}: {source}")]
    Acquire {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// RAII exclusive lock on a single env's `.lock` file. Dropping the value
/// closes the file descriptor, which releases the OS-level lock.
#[derive(Debug)]
pub struct EnvFlock {
    _file: File,
}

impl EnvFlock {
    /// Blocking exclusive acquire. Creates the lock file if missing.
    pub fn acquire(lock_path: &Path) -> Result<Self, LockError> {
        let file = open_lock_file(lock_path)?;
        file.lock_exclusive().map_err(|source| LockError::Acquire {
            path: lock_path.to_path_buf(),
            source,
        })?;
        Ok(Self { _file: file })
    }

    /// Non-blocking exclusive acquire. Returns `Ok(None)` if the lock is held.
    pub fn try_acquire(lock_path: &Path) -> Result<Option<Self>, LockError> {
        let file = open_lock_file(lock_path)?;
        match file.try_lock_exclusive() {
            Ok(true) => Ok(Some(Self { _file: file })),
            Ok(false) => Ok(None),
            Err(source) => Err(LockError::Acquire {
                path: lock_path.to_path_buf(),
                source,
            }),
        }
    }
}

fn open_lock_file(lock_path: &Path) -> Result<File, LockError> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| LockError::Open {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|source| LockError::Open {
            path: lock_path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn acquire_and_release() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join(".lock");
        {
            let _guard = EnvFlock::acquire(&lock_path).unwrap();
            assert!(lock_path.exists());
        }
        // After drop, we can re-acquire.
        let _again = EnvFlock::acquire(&lock_path).unwrap();
    }

    #[test]
    fn try_acquire_returns_none_when_held() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join(".lock");
        let _held = EnvFlock::acquire(&lock_path).unwrap();
        let attempt = EnvFlock::try_acquire(&lock_path).unwrap();
        assert!(attempt.is_none(), "expected try_acquire to fail while held");
    }

    #[test]
    fn try_acquire_succeeds_after_drop() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join(".lock");
        {
            let _held = EnvFlock::acquire(&lock_path).unwrap();
        }
        let attempt = EnvFlock::try_acquire(&lock_path).unwrap();
        assert!(attempt.is_some());
    }

    #[test]
    fn creates_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("nested/dir/.lock");
        let _g = EnvFlock::acquire(&lock_path).unwrap();
        assert!(lock_path.exists());
    }
}
