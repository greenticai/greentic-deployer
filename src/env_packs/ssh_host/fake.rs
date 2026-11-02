//! Test double for [`Remote`]: a tiny simulated VM.
//!
//! It understands exactly the command vocabulary the deployer emits and nothing
//! else — an unknown command answers `127`, so a deployer that drifts to a new
//! command fails its tests loudly instead of silently "succeeding" against a
//! fake that accepts anything. State (files, symlinks, enabled/running services,
//! restart count) persists across calls, which is what lets the tests prove
//! idempotency (a second warm changes nothing and restarts nothing) and
//! atomicity (a failed step leaves the live store untouched).
//!
//! This proves the deployer's command sequence and decision logic against the
//! simulated semantics below. It does NOT prove those semantics match a real
//! sshd, coreutils or systemd — see `docs/ssh-host-internals.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

use super::remote::{Remote, RemoteError, RemoteOutput, RemoteTarget};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    Run(Vec<String>),
    Upload(String),
}

#[derive(Debug, Default)]
pub(crate) struct Sim {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
    symlinks: BTreeMap<String, String>,
    exec_bits: BTreeSet<String>,
    enabled: BTreeSet<String>,
    running: BTreeSet<String>,
    restarts: u32,
    calls: Vec<Call>,
    failures: Vec<(String, RemoteOutput)>,
    upload_failures: Vec<String>,
}

/// A simulated VM. Defaults: reachable, x86_64, systemd present, passwordless
/// sudo, logged in as a non-root user who owns `/opt/greentic`.
#[derive(Debug)]
pub(crate) struct FakeRemote {
    pub(crate) sim: Mutex<Sim>,
    pub(crate) is_root: bool,
    pub(crate) sudo_works: bool,
    pub(crate) unreachable: bool,
    pub(crate) arch: String,
    pub(crate) systemd_present: bool,
    pub(crate) glibc: String,
}

impl Default for FakeRemote {
    fn default() -> Self {
        let remote = Self {
            sim: Mutex::new(Sim::default()),
            is_root: false,
            sudo_works: true,
            unreachable: false,
            arch: "x86_64".into(),
            systemd_present: true,
            glibc: "2.39".into(),
        };
        remote.add_dir("/opt/greentic");
        remote.add_dir("/etc/systemd/system");
        remote
    }
}

fn prefixes(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut acc = String::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        acc.push('/');
        acc.push_str(seg);
        out.push(acc.clone());
    }
    out
}

impl Sim {
    fn resolve(&self, path: &str) -> String {
        let mut current = path.to_string();
        for _ in 0..8 {
            let hit = self
                .symlinks
                .iter()
                .find(|(link, _)| current == **link || current.starts_with(&format!("{link}/")))
                .map(|(link, target)| (link.clone(), target.clone()));
            match hit {
                Some((link, target)) => current = format!("{target}{}", &current[link.len()..]),
                None => break,
            }
        }
        current
    }

    fn parent_exists(&self, path: &str) -> bool {
        let resolved = self.resolve(path);
        match resolved.rsplit_once('/') {
            Some(("", _)) | None => true,
            Some((parent, _)) => self.dirs.contains(parent),
        }
    }

    fn exists(&self, path: &str) -> bool {
        let r = self.resolve(path);
        self.files.contains_key(&r) || self.dirs.contains(&r)
    }
}

fn err(status: i32, msg: &str) -> RemoteOutput {
    RemoteOutput::failed(status, msg)
}

impl FakeRemote {
    pub(crate) fn add_dir(&self, path: &str) {
        let mut sim = self.sim.lock().unwrap();
        for p in prefixes(path) {
            sim.dirs.insert(p);
        }
    }

    pub(crate) fn put_file(&self, path: &str, bytes: &[u8]) {
        let mut sim = self.sim.lock().unwrap();
        let resolved = sim.resolve(path);
        sim.files.insert(resolved, bytes.to_vec());
    }

    /// A present, executable file (an already-installed binary).
    pub(crate) fn put_executable(&self, path: &str, bytes: &[u8]) {
        self.put_file(path, bytes);
        let mut sim = self.sim.lock().unwrap();
        let resolved = sim.resolve(path);
        sim.exec_bits.insert(resolved);
    }

    pub(crate) fn file(&self, path: &str) -> Option<Vec<u8>> {
        let sim = self.sim.lock().unwrap();
        sim.files.get(&sim.resolve(path)).cloned()
    }

    pub(crate) fn file_text(&self, path: &str) -> Option<String> {
        self.file(path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    pub(crate) fn symlink_target(&self, path: &str) -> Option<String> {
        self.sim.lock().unwrap().symlinks.get(path).cloned()
    }

    pub(crate) fn is_running(&self, service: &str) -> bool {
        self.sim.lock().unwrap().running.contains(service)
    }

    pub(crate) fn is_enabled(&self, service: &str) -> bool {
        self.sim.lock().unwrap().enabled.contains(service)
    }

    pub(crate) fn restarts(&self) -> u32 {
        self.sim.lock().unwrap().restarts
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.sim.lock().unwrap().calls.clone()
    }

    /// Every command run, space-joined, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Run(argv) => Some(argv.join(" ")),
                Call::Upload(_) => None,
            })
            .collect()
    }

    pub(crate) fn uploads(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Upload(p) => Some(p),
                Call::Run(_) => None,
            })
            .collect()
    }

    pub(crate) fn clear_calls(&self) {
        self.sim.lock().unwrap().calls.clear();
    }

    /// Any command whose space-joined text contains `needle` answers `output`.
    pub(crate) fn fail_command(&self, needle: &str, output: RemoteOutput) {
        self.sim
            .lock()
            .unwrap()
            .failures
            .push((needle.to_string(), output));
    }

    /// An upload whose remote path contains `needle` fails.
    pub(crate) fn fail_upload(&self, needle: &str) {
        self.sim
            .lock()
            .unwrap()
            .upload_failures
            .push(needle.to_string());
    }

    fn exec(&self, sim: &mut Sim, argv: &[String], stdin: Option<&[u8]>) -> RemoteOutput {
        let mut args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let mut privileged = self.is_root;
        if args.first() == Some(&"sudo") {
            if args.get(1) != Some(&"-n") {
                return err(2, "sudo: unexpected form (the deployer must use `sudo -n`)");
            }
            if !self.sudo_works {
                return err(1, "sudo: a password is required");
            }
            privileged = true;
            args.drain(..2);
        }
        let Some((&cmd, rest)) = args.split_first() else {
            return err(127, "empty command");
        };
        match cmd {
            "true" | "sleep" => RemoteOutput::ok(),
            // Running an uploaded file: only `--version`, and only a non-empty
            // executable "runs" (an empty file is `Exec format error`, as on Linux).
            path if path.starts_with('/') && rest == ["--version"] => {
                match sim.files.get(&sim.resolve(path)) {
                    Some(bytes) if !bytes.is_empty() && sim.executable(path) => {
                        RemoteOutput::with_stdout("greentic-start 0.0.0-fake\n")
                    }
                    Some(_) => err(126, "cannot execute binary file: Exec format error"),
                    None => err(127, "No such file or directory"),
                }
            }
            "id" if rest == ["-u"] => {
                RemoteOutput::with_stdout(if privileged { "0\n" } else { "1000\n" })
            }
            "id" if rest.len() == 2 && rest[0] == "-u" => RemoteOutput::with_stdout("1001\n"),
            "chown" if rest.len() >= 4 && rest[0] == "-R" && rest[1] == "-h" => {
                if !privileged {
                    return err(1, "chown: Operation not permitted");
                }
                for path in &rest[3..] {
                    if !sim.exists(path.trim_end_matches("/.")) {
                        return err(1, "chown: cannot access: No such file or directory");
                    }
                }
                RemoteOutput::ok()
            }
            "uname" if rest == ["-m"] => RemoteOutput::with_stdout(format!("{}\n", self.arch)),
            "getconf" if rest == ["GNU_LIBC_VERSION"] => {
                RemoteOutput::with_stdout(format!("glibc {}\n", self.glibc))
            }
            "ldd" if rest == ["--version"] => RemoteOutput::with_stdout(format!(
                "ldd (Ubuntu GLIBC {}-0ubuntu8) {}\n",
                self.glibc, self.glibc
            )),
            "cp" if rest.len() == 3 && rest[0] == "-p" => {
                let from = sim.resolve(rest[1]);
                match sim.files.get(&from).cloned() {
                    Some(bytes) => {
                        let to = sim.resolve(rest[2]);
                        let exec = sim.exec_bits.contains(&from);
                        sim.files.insert(to.clone(), bytes);
                        if exec {
                            sim.exec_bits.insert(to);
                        }
                        RemoteOutput::ok()
                    }
                    None => err(1, "cp: cannot stat: No such file or directory"),
                }
            }
            "mkdir" if rest.first() == Some(&"-p") => {
                for path in &rest[1..] {
                    if !privileged && !sim.parent_exists_or_user_writable(path) {
                        return err(1, "mkdir: Permission denied");
                    }
                    for p in prefixes(path) {
                        sim.dirs.insert(p);
                    }
                }
                RemoteOutput::ok()
            }
            "test" if rest.len() == 2 => {
                let ok = match rest[0] {
                    "-x" => {
                        sim.files.contains_key(&sim.resolve(rest[1])) && sim.executable(rest[1])
                    }
                    "-f" => sim.files.contains_key(&sim.resolve(rest[1])),
                    "-w" | "-d" => sim.dirs.contains(&sim.resolve(rest[1])),
                    "-e" => sim.exists(rest[1]),
                    _ => return err(2, "test: unsupported operator"),
                };
                RemoteOutput {
                    status: i32::from(!ok),
                    ..RemoteOutput::ok()
                }
            }
            "sha256sum" if rest.len() == 1 => match sim.files.get(&sim.resolve(rest[0])) {
                Some(bytes) => RemoteOutput::with_stdout(format!(
                    "{}  {}\n",
                    super::hex_sha256(bytes),
                    rest[0]
                )),
                None => err(1, "sha256sum: No such file or directory"),
            },
            "cat" if rest.len() == 1 => match sim.files.get(&sim.resolve(rest[0])) {
                Some(bytes) => RemoteOutput::with_stdout(String::from_utf8_lossy(bytes)),
                None => err(1, "cat: No such file or directory"),
            },
            "readlink" if rest.len() == 1 => match sim.symlinks.get(rest[0]) {
                Some(t) => RemoteOutput::with_stdout(format!("{t}\n")),
                None => err(1, ""),
            },
            "chmod" if rest.len() == 2 => {
                let path = sim.resolve(rest[1]);
                if !sim.files.contains_key(&path) {
                    return err(1, "chmod: No such file or directory");
                }
                if rest[0] == "0755" {
                    sim.exec_bits.insert(path);
                }
                RemoteOutput::ok()
            }
            "mv" if rest.len() == 3 && (rest[0] == "-f" || rest[0] == "-T") => {
                let (src, dst) = (rest[1], rest[2]);
                if rest[0] == "-T" {
                    if let Some(target) = sim.symlinks.get(src).cloned() {
                        if sim.dirs.contains(dst) && !sim.symlinks.contains_key(dst) {
                            return err(1, "mv: cannot overwrite directory with non-directory");
                        }
                        sim.symlinks.remove(src);
                        sim.symlinks.insert(dst.to_string(), target);
                        return RemoteOutput::ok();
                    }
                    return err(1, "mv: -T is only simulated for symlinks");
                }
                let from = sim.resolve(src);
                let to = sim.resolve(dst);
                match sim.files.remove(&from) {
                    Some(bytes) => {
                        let exec = sim.exec_bits.remove(&from);
                        sim.files.insert(to.clone(), bytes);
                        if exec {
                            sim.exec_bits.insert(to);
                        }
                        RemoteOutput::ok()
                    }
                    None => err(1, "mv: cannot stat: No such file or directory"),
                }
            }
            "rm" if rest.len() == 2 && (rest[0] == "-rf" || rest[0] == "-f") => {
                let root = sim.resolve(rest[1]);
                let under = format!("{root}/");
                sim.files
                    .retain(|p, _| p != &root && !p.starts_with(&under));
                sim.dirs.retain(|p| p != &root && !p.starts_with(&under));
                let raw_under = format!("{}/", rest[1]);
                sim.symlinks
                    .retain(|link, _| link != rest[1] && !link.starts_with(&raw_under));
                RemoteOutput::ok()
            }
            "ln" if rest.len() == 3 && rest[0] == "-sfn" => {
                sim.symlinks
                    .insert(rest[2].to_string(), rest[1].to_string());
                RemoteOutput::ok()
            }
            "tar" if rest.len() == 4 && rest[0] == "-xf" && rest[2] == "-C" => {
                let bytes = if rest[1] == "-" {
                    match stdin {
                        Some(b) => b.to_vec(),
                        None => return err(2, "tar: no data on stdin"),
                    }
                } else {
                    return err(2, "tar: the deployer must stream the archive on stdin");
                };
                let dest = sim.resolve(rest[3]);
                if !sim.dirs.contains(&dest) {
                    return err(2, "tar: destination does not exist");
                }
                let mut archive = tar::Archive::new(bytes.as_slice());
                let Ok(entries) = archive.entries() else {
                    return err(2, "tar: not an archive");
                };
                for entry in entries {
                    let Ok(mut entry) = entry else {
                        return err(2, "tar: corrupt entry");
                    };
                    let rel = entry
                        .path()
                        .unwrap()
                        .to_string_lossy()
                        .trim_end_matches('/')
                        .to_string();
                    let full = format!("{dest}/{rel}");
                    if entry.header().entry_type().is_dir() {
                        for p in prefixes(&full) {
                            sim.dirs.insert(p);
                        }
                    } else {
                        let mut content = Vec::new();
                        entry.read_to_end(&mut content).unwrap();
                        sim.files.insert(full, content);
                    }
                }
                RemoteOutput::ok()
            }
            "cmp" if rest.len() == 3 && rest[0] == "-s" => {
                let a = sim.files.get(&sim.resolve(rest[1]));
                let b = sim.files.get(&sim.resolve(rest[2]));
                RemoteOutput {
                    status: i32::from(!(a.is_some() && a == b)),
                    ..RemoteOutput::ok()
                }
            }
            "install" if rest.len() == 8 && rest[0] == "-m" => {
                if !privileged {
                    return err(1, "install: Permission denied");
                }
                let (src, dst) = (rest[6], rest[7]);
                match sim.files.get(&sim.resolve(src)).cloned() {
                    Some(bytes) => {
                        let to = sim.resolve(dst);
                        sim.files.insert(to, bytes);
                        RemoteOutput::ok()
                    }
                    None => err(1, "install: cannot stat: No such file or directory"),
                }
            }
            "systemctl" => self.systemctl(sim, rest, privileged),
            _ => err(
                127,
                &format!("{cmd}: command not found (not part of the simulated vocabulary)"),
            ),
        }
    }

    fn systemctl(&self, sim: &mut Sim, rest: &[&str], privileged: bool) -> RemoteOutput {
        if !self.systemd_present {
            return err(127, "systemctl: command not found");
        }
        let unit_exists = |sim: &Sim, svc: &str| {
            sim.files
                .contains_key(&format!("/etc/systemd/system/{svc}.service"))
        };
        match rest {
            ["--version"] => RemoteOutput::with_stdout("systemd 252 (252.22-1)\n"),
            ["is-active", svc] => {
                if sim.running.contains(*svc) {
                    RemoteOutput::with_stdout("active\n")
                } else {
                    RemoteOutput {
                        status: 3,
                        stdout: "inactive\n".into(),
                        stderr: String::new(),
                    }
                }
            }
            _ if !privileged => err(
                1,
                "Failed to connect to bus: Access denied (interactive authentication required)",
            ),
            ["daemon-reload"] => RemoteOutput::ok(),
            ["enable", svc] | ["enable", "--now", svc] => {
                if !unit_exists(sim, svc) {
                    return err(1, "Failed to enable unit: Unit file does not exist");
                }
                sim.enabled.insert((*svc).to_string());
                if rest[1] == "--now" {
                    sim.running.insert((*svc).to_string());
                }
                RemoteOutput::ok()
            }
            ["restart", svc] => {
                if !unit_exists(sim, svc) {
                    return err(5, "Unit not found");
                }
                sim.restarts += 1;
                sim.running.insert((*svc).to_string());
                RemoteOutput::ok()
            }
            ["stop", svc] => {
                if !unit_exists(sim, svc) {
                    return err(5, "Unit not loaded");
                }
                sim.running.remove(*svc);
                RemoteOutput::ok()
            }
            _ => err(127, "systemctl: unsupported form"),
        }
    }
}

impl Sim {
    fn executable(&self, path: &str) -> bool {
        self.exec_bits.contains(&self.resolve(path))
    }

    /// A non-privileged mkdir succeeds when it stays inside a directory the
    /// login user owns (`/opt/greentic` in the default fixture) or the parent
    /// already exists below it.
    fn parent_exists_or_user_writable(&self, path: &str) -> bool {
        self.dirs.contains(path)
            || path.rsplit_once('/').is_some_and(|(parent, _)| {
                self.dirs.contains(parent) && parent.starts_with("/opt/greentic")
            })
            || path.starts_with("/opt/greentic/")
    }
}

impl Remote for FakeRemote {
    fn run(&self, _target: &RemoteTarget, argv: &[String]) -> Result<RemoteOutput, RemoteError> {
        if self.unreachable {
            return Err(RemoteError::Transport(
                "ssh: connect to host vm.example.com port 22: Connection timed out".into(),
            ));
        }
        let mut sim = self.sim.lock().unwrap();
        sim.calls.push(Call::Run(argv.to_vec()));
        let joined = argv.join(" ");
        if let Some((_, out)) = sim
            .failures
            .iter()
            .find(|(needle, _)| joined.contains(needle))
        {
            return Ok(out.clone());
        }
        Ok(self.exec(&mut sim, argv, None))
    }

    fn run_with_stdin(
        &self,
        _target: &RemoteTarget,
        argv: &[String],
        stdin_file: &Path,
    ) -> Result<RemoteOutput, RemoteError> {
        if self.unreachable {
            return Err(RemoteError::Transport("Connection timed out".into()));
        }
        let bytes = std::fs::read(stdin_file)
            .map_err(|e| RemoteError::Io(format!("opening local file: {e}")))?;
        let mut sim = self.sim.lock().unwrap();
        sim.calls.push(Call::Run(argv.to_vec()));
        let joined = argv.join(" ");
        if let Some((_, out)) = sim
            .failures
            .iter()
            .find(|(needle, _)| joined.contains(needle))
        {
            return Ok(out.clone());
        }
        Ok(self.exec(&mut sim, argv, Some(&bytes)))
    }

    fn upload(
        &self,
        _target: &RemoteTarget,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), RemoteError> {
        if self.unreachable {
            return Err(RemoteError::Transport("Connection timed out".into()));
        }
        let mut sim = self.sim.lock().unwrap();
        sim.calls.push(Call::Upload(remote_path.to_string()));
        if sim.upload_failures.iter().any(|n| remote_path.contains(n)) {
            return Err(RemoteError::Io(format!(
                "upload to {remote_path} failed (exit 1): No space left on device"
            )));
        }
        if !sim.parent_exists(remote_path) {
            return Err(RemoteError::Io(format!(
                "upload to {remote_path} failed (exit 1): No such file or directory"
            )));
        }
        let bytes = std::fs::read(local_path)
            .map_err(|e| RemoteError::Io(format!("opening local file: {e}")))?;
        let to = sim.resolve(remote_path);
        sim.files.insert(to, bytes);
        Ok(())
    }
}
