//! Ownership of everything a tunnel started: helper processes, hooks and
//! scratch files.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};

/// A private temporary directory (mode 0700) for files a helper needs, e.g. a
/// secret copied out of the operator's file. Deleted when dropped.
#[derive(Debug)]
pub struct ScratchDir {
    dir: tempfile::TempDir,
}

impl ScratchDir {
    pub fn new() -> std::io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("greentic-tunnel-")
            .tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Do not rely on the crate's default mode.
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Write `bytes` to `<scratch>/<name>` with mode 0600 and return the path.
    /// `name` must be a plain file name; an existing file is never replaced.
    pub fn write_secret(&self, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
        let path = self.create_private(name)?.1;
        let mut file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.write_all(bytes)?;
        Ok(path)
    }

    /// Create an empty `<scratch>/<name>` with mode 0600, exclusively, and
    /// return it open for writing (a helper's stderr log, for instance).
    pub fn create_private(&self, name: &str) -> std::io::Result<(std::fs::File, PathBuf)> {
        if name.is_empty() || name.contains('/') || name.contains('\0') || name == ".." {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scratch file name must be a plain file name",
            ));
        }
        let path = self.dir.path().join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok((file, path))
    }
}

/// Tears a tunnel down on drop: kills and reaps the adopted children (last
/// adopted first), runs the `on_drop` hooks, then deletes the scratch dirs.
#[derive(Default)]
pub struct TunnelGuard {
    children: Vec<Adopted>,
    hooks: Vec<Box<dyn FnOnce() + Send>>,
    scratch: Vec<ScratchDir>,
}

/// A helper process and whether it leads its own process group (so its
/// grandchildren, e.g. `ocproxy` under `openconnect`, are reached too).
struct Adopted {
    child: Child,
    group: bool,
}

impl TunnelGuard {
    /// A guard that owns nothing (a tunnel that needs no cleanup).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Take ownership of a helper process; returns its index for
    /// [`TunnelGuard::child_exit`].
    pub fn adopt_child(&mut self, child: Child) -> usize {
        self.children.push(Adopted {
            child,
            group: false,
        });
        self.children.len() - 1
    }

    /// Like [`adopt_child`](Self::adopt_child) for a helper spawned with
    /// `process_group(0)`: on teardown the whole group is signalled (SIGTERM,
    /// a short grace, then SIGKILL), so helpers it started die with it.
    pub fn adopt_group_leader(&mut self, child: Child) -> usize {
        self.children.push(Adopted { child, group: true });
        self.children.len() - 1
    }

    /// `Some(status)` once the adopted child `index` has exited.
    pub fn child_exit(&mut self, index: usize) -> Option<ExitStatus> {
        self.children
            .get_mut(index)
            .and_then(|a| a.child.try_wait().ok().flatten())
    }

    /// Take ownership of a scratch directory.
    pub fn adopt_scratch(&mut self, scratch: ScratchDir) {
        self.scratch.push(scratch);
    }

    /// Run `hook` when the tunnel is torn down, after the children are gone.
    pub fn on_drop(&mut self, hook: impl FnOnce() + Send + 'static) {
        self.hooks.push(Box::new(hook));
    }

    pub fn is_empty(&self) -> bool {
        self.children.is_empty() && self.hooks.is_empty() && self.scratch.is_empty()
    }
}

impl fmt::Debug for TunnelGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelGuard")
            .field("children", &self.children.len())
            .field("hooks", &self.hooks.len())
            .field("scratch_dirs", &self.scratch.len())
            .finish()
    }
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        while let Some(adopted) = self.children.pop() {
            terminate(adopted);
        }
        for hook in self.hooks.drain(..).rev() {
            hook();
        }
        // `scratch` is dropped after this body, which removes the directories.
    }
}

/// Stop one helper. Best effort throughout: it may already have exited.
fn terminate(mut adopted: Adopted) {
    #[cfg(unix)]
    if adopted.group
        && let Some(pid) = rustix::process::Pid::from_raw(adopted.child.id() as i32)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if matches!(adopted.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // The leader may be gone while a grandchild is not: always follow up.
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        let _ = adopted.child.wait();
        return;
    }
    let _ = adopted.group;
    let _ = adopted.child.kill();
    let _ = adopted.child.wait();
}
