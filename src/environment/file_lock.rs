//! Per-env exclusive file lock used by [`LocalFsStore`](super::LocalFsStore).
//!
//! Each environment has a sentinel file at `<env_root>/.lock`. The store opens
//! it and takes a blocking exclusive `flock`/`LockFileEx` via the `fs4` crate.
//! The lock is bound to the file descriptor — closing the file releases it,
//! so [`EnvFlock`] is just an owning wrapper over [`std::fs::File`] and Drop
//! does the right thing without any unsafe self-reference tricks.
//!
//! On unix, `acquire` and `try_acquire` verify the locked fd's inode identity
//! against the on-disk path after each successful lock. `op env destroy`
//! renames the env dir (and the lock file inside it) while waiters may be
//! blocked on the old fd; when the rename lands, the locked inode no longer
//! guards the canonical path. The staleness check detects this and re-opens
//! the canonical path so post-destroy waiters coordinate on a fresh lock.
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

/// Maximum retries for the inode-staleness loop before giving up.
const MAX_LOCK_RETRIES: u32 = 64;

impl EnvFlock {
    /// Blocking exclusive acquire. Creates the lock file if missing.
    ///
    /// On unix, after `lock_exclusive` succeeds, verifies the locked fd's
    /// inode still matches the on-disk path (see module-level doc). If the
    /// inode was renamed away (by `destroy_environment`), drops the stale fd
    /// and retries.
    pub fn acquire(lock_path: &Path) -> Result<Self, LockError> {
        for _ in 0..MAX_LOCK_RETRIES {
            let file = open_lock_file(lock_path)?;
            file.lock_exclusive().map_err(|source| LockError::Acquire {
                path: lock_path.to_path_buf(),
                source,
            })?;
            if is_stale(&file, lock_path) {
                // fd points to the renamed-away inode; drop releases the
                // stale lock, loop re-opens the canonical path.
                continue;
            }
            return Ok(Self { _file: file });
        }
        Err(LockError::Acquire {
            path: lock_path.to_path_buf(),
            source: std::io::Error::other("lock path kept changing identity after 64 retries"),
        })
    }

    /// Non-blocking exclusive acquire. Returns `Ok(None)` if the lock is held.
    ///
    /// On unix, the same inode-staleness guard as [`acquire`](Self::acquire)
    /// applies to the `Ok(true)` arm.
    pub fn try_acquire(lock_path: &Path) -> Result<Option<Self>, LockError> {
        for _ in 0..MAX_LOCK_RETRIES {
            let file = open_lock_file(lock_path)?;
            match file.try_lock_exclusive() {
                Ok(true) => {
                    if is_stale(&file, lock_path) {
                        continue;
                    }
                    return Ok(Some(Self { _file: file }));
                }
                Ok(false) => return Ok(None),
                Err(source) => {
                    return Err(LockError::Acquire {
                        path: lock_path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        Err(LockError::Acquire {
            path: lock_path.to_path_buf(),
            source: std::io::Error::other("lock path kept changing identity after 64 retries"),
        })
    }
}

/// `true` when the locked fd no longer corresponds to the on-disk path
/// (path gone or different dev/ino). Unix-only; on other platforms the
/// single-shot behavior is preserved.
#[cfg(unix)]
fn is_stale(file: &File, lock_path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(fd_meta) = file.metadata() else {
        return false;
    };
    match std::fs::metadata(lock_path) {
        Ok(path_meta) => fd_meta.dev() != path_meta.dev() || fd_meta.ino() != path_meta.ino(),
        Err(_) => true, // path gone: inode was renamed away
    }
}

#[cfg(not(unix))]
fn is_stale(_file: &File, _lock_path: &Path) -> bool {
    // dev/ino identity comparison is unix-only.
    false
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

    /// Verifies the inode-staleness guard: a waiter blocked on a lock whose
    /// parent dir is renamed away (as `destroy_environment` does) must
    /// re-acquire on the canonical path, not the stale renamed-away inode.
    #[cfg(unix)]
    #[test]
    fn acquire_detects_renamed_inode_and_relocks_canonical_path() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path().join("env");
        std::fs::create_dir_all(&env_dir).unwrap();
        let lock_path = env_dir.join(".lock");

        // A holds the lock on the canonical path.
        let guard_a = EnvFlock::acquire(&lock_path).unwrap();

        let (tx_acquired, rx_acquired) = mpsc::sync_channel::<()>(0);
        let (tx_drop, rx_drop) = mpsc::sync_channel::<()>(0);
        let lp = lock_path.clone();
        let handle = thread::spawn(move || {
            // B blocks until A drops (after rename).
            let guard_b = EnvFlock::acquire(&lp).unwrap();
            tx_acquired.send(()).unwrap();
            // Park until main signals to drop.
            rx_drop.recv().unwrap();
            drop(guard_b);
        });

        // Give B time to block on the flock.
        thread::sleep(Duration::from_millis(200));

        // Simulate destroy: rename the env dir (moving the locked inode).
        let moved = tmp.path().join("env-moved");
        std::fs::rename(&env_dir, &moved).unwrap();

        // Release A: B wakes, detects the stale inode, re-acquires canonical.
        drop(guard_a);

        // Wait for B to signal it acquired.
        rx_acquired
            .recv_timeout(Duration::from_secs(5))
            .expect("B must acquire within 5s");

        // B holds the CANONICAL path's lock. A try_acquire on the canonical
        // path must fail (Ok(None)).
        let probe = EnvFlock::try_acquire(&lock_path).unwrap();
        assert!(
            probe.is_none(),
            "B must hold the canonical lock, not the renamed-away inode"
        );

        // Signal B to drop, join.
        tx_drop.send(()).unwrap();
        handle.join().unwrap();

        // After B drops, try_acquire succeeds.
        let probe = EnvFlock::try_acquire(&lock_path).unwrap();
        assert!(probe.is_some(), "lock must be free after B drops");
    }
}
