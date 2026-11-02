//! The warm / drain procedures, as a sequence of small remote steps.
//!
//! Every step is idempotent and re-checks the VM rather than trusting local
//! memory of a previous run:
//!
//! 1. create `<install_dir>/{bin,home,logs}` (`home` is the service's writable
//!    `HOME`; `logs` outlives store changes);
//! 2. the binary — copied (and swapped atomically with `mv`) only when its
//!    SHA-256 differs from the installed one, or verified present;
//! 3. the store — a deterministic snapshot ([`super::snapshot`]) is STREAMED over
//!    ssh into `tar -xf -` in the INACTIVE one of two slots (`store-a` /
//!    `store-b`), the runtime-written `revision-signing.key` is carried over from
//!    the active slot and `logs` is linked to the persistent directory, then the
//!    `store` symlink is renamed into place (`mv -T`, one `rename(2)`). So
//!    `<install_dir>/store` is always either the old complete store or the new
//!    complete one, and a rsync-style delete can never eat the runtime's state.
//!    A snapshot whose hash matches the marker already on the VM is not sent;
//! 4. the systemd unit — installed only when it differs from the installed one;
//! 5. enable and start; restart only when step 2, 3 or 4 changed something.
//!
//! No archive is ever written to the VM's disk: the snapshot goes
//! stdin-to-`tar` and the only local copy is a 0600 temp file.
//!
//! A failure returns a [`DeployerError::Provider`] naming the step and the VM.
//! Nothing is rolled back: a failed step leaves the previous binary, store and
//! unit in place (the swaps are the last action of their step), and the next
//! warm converges from wherever the VM is.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use greentic_deploy_spec::{Environment, RevisionId};
use sha2::{Digest, Sha256};

use super::params::SshHostParams;
use super::remote::{Remote, RemoteOutput, RemoteTarget};
use super::render::render_unit;
use super::snapshot::{SnapshotInput, build_store_archive};
use super::{RUNTIME_KEY_FILE, STORE_MARKER_FILE, STORE_SLOTS};
use crate::env_packs::deployer::{DeployerError, WarmOutcome};

/// One VM, one set of validated params.
pub(super) struct Session<'a> {
    pub(super) remote: &'a dyn Remote,
    pub(super) target: RemoteTarget,
    pub(super) params: &'a SshHostParams,
}

impl<'a> Session<'a> {
    pub(super) fn new(remote: &'a dyn Remote, params: &'a SshHostParams) -> Self {
        Self {
            remote,
            target: RemoteTarget::from(params),
            params,
        }
    }

    fn fail(&self, step: &str, detail: impl std::fmt::Display) -> DeployerError {
        DeployerError::Provider(format!(
            "ssh-host: {step} on {host} failed: {detail}",
            host = self.params.host
        ))
    }

    /// Run a command; only a transport failure is an error.
    pub(super) fn run(&self, step: &str, argv: &[&str]) -> Result<RemoteOutput, DeployerError> {
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        self.remote
            .run(&self.target, &argv)
            .map_err(|e| self.fail(step, e))
    }

    /// Run a command that must exit 0.
    pub(super) fn run_ok(&self, step: &str, argv: &[&str]) -> Result<RemoteOutput, DeployerError> {
        let out = self.run(step, argv)?;
        if out.success() {
            Ok(out)
        } else {
            Err(self.fail(
                step,
                format!(
                    "`{}` exited {}: {}",
                    argv.join(" "),
                    out.status,
                    out.stderr.trim()
                ),
            ))
        }
    }

    /// `argv` with the `sudo -n` prefix when the binding asked for it.
    pub(super) fn privileged(&self, argv: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(argv.len() + 2);
        if self.params.use_sudo {
            out.push("sudo".into());
            out.push("-n".into());
        }
        out.extend(argv.iter().map(|a| a.to_string()));
        out
    }

    pub(super) fn run_privileged(
        &self,
        step: &str,
        argv: &[&str],
    ) -> Result<RemoteOutput, DeployerError> {
        let full = self.privileged(argv);
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        self.run(step, &refs)
    }

    pub(super) fn run_privileged_ok(
        &self,
        step: &str,
        argv: &[&str],
    ) -> Result<RemoteOutput, DeployerError> {
        let full = self.privileged(argv);
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        self.run_ok(step, &refs)
    }

    fn upload(&self, step: &str, local: &Path, remote_path: &str) -> Result<(), DeployerError> {
        self.remote
            .upload(&self.target, local, remote_path)
            .map_err(|e| self.fail(step, e))
    }

    fn upload_bytes(
        &self,
        step: &str,
        bytes: &[u8],
        remote_path: &str,
    ) -> Result<(), DeployerError> {
        // `NamedTempFile` is created 0600 and removed on drop, so snapshot bytes
        // are never readable by another local user, even briefly.
        let mut file = tempfile::NamedTempFile::new()
            .map_err(|e| self.fail(step, format!("creating a local temp file: {e}")))?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .map_err(|e| self.fail(step, format!("writing a local temp file: {e}")))?;
        self.upload(step, file.path(), remote_path)
    }
}

pub(crate) fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Everything `warm` needs, owned so it can cross into `spawn_blocking`.
pub(super) struct WarmInput {
    pub env: Environment,
    pub revision_id: RevisionId,
    pub store_root: PathBuf,
    pub dev_secrets: Option<Vec<u8>>,
}

pub(super) fn warm(session: &Session<'_>, input: &WarmInput) -> Result<WarmOutcome, DeployerError> {
    let p = session.params;
    session.run_ok(
        "creating the install directories",
        &[
            "mkdir",
            "-p",
            &p.path("bin"),
            &p.path("home"),
            &p.path("logs"),
        ],
    )?;
    let mut changed = sync_binary(session)?;
    changed |= sync_store(session, input)?;
    changed |= install_unit(session, &input.env)?;
    start_service(session, changed)?;
    Ok(WarmOutcome {
        // Only a network-reachable bind is an endpoint; a loopback bind is
        // reached through the operator's own reverse proxy.
        endpoint_url: p
            .expose
            .then(|| format!("http://{}:{}", p.host, p.listen_port)),
    })
}

fn sync_binary(session: &Session<'_>) -> Result<bool, DeployerError> {
    let p = session.params;
    let installed = p.path("bin/greentic-start");
    let Some(local) = &p.start_binary else {
        let probe = session.run("checking for greentic-start", &["test", "-x", &installed])?;
        if probe.success() {
            return Ok(false);
        }
        return Err(session.fail(
            "checking for greentic-start",
            format!(
                "{installed} is missing or not executable. Install greentic-start there, or set \
                 the `start_binary` answer to a local greentic-start binary so the deployer \
                 copies it"
            ),
        ));
    };
    let local_hash = hash_file(local).map_err(|e| {
        session.fail(
            "reading start_binary",
            format!("cannot read {}: {e}", local.display()),
        )
    })?;
    let current = session.run(
        "hashing the installed greentic-start",
        &["sha256sum", &installed],
    )?;
    let current_hash = current
        .success()
        .then(|| current.stdout.split_whitespace().next().map(str::to_owned))
        .flatten();
    if current_hash.as_deref() == Some(local_hash.as_str()) {
        return Ok(false);
    }
    let staged = format!("{installed}.new");
    session.upload("copying greentic-start", local, &staged)?;
    session.run_ok(
        "making greentic-start executable",
        &["chmod", "0755", &staged],
    )?;
    session.run_ok(
        "installing greentic-start",
        &["mv", "-f", &staged, &installed],
    )?;
    Ok(true)
}

fn sync_store(session: &Session<'_>, input: &WarmInput) -> Result<bool, DeployerError> {
    let p = session.params;
    let archive = build_store_archive(&SnapshotInput {
        store_root: &input.store_root,
        env: &input.env,
        revision_id: input.revision_id,
        dev_secrets: input.dev_secrets.as_deref(),
        params: p,
    })?;
    let marker = session.run(
        "reading the store marker",
        &["cat", &p.path(&format!("store/{STORE_MARKER_FILE}"))],
    )?;
    if marker.success() && marker.stdout.trim() == archive.content_sha256 {
        return Ok(false);
    }

    let live = p.path("store");
    let next_link = p.path("store.next");
    // Which slot is active is read from the VM, but only one of OUR two slot
    // paths is ever acted on: whatever else `readlink` prints is ignored.
    let active = session.run("reading the active store slot", &["readlink", &live])?;
    let active_slot = active
        .success()
        .then(|| active.stdout.trim().to_string())
        .and_then(|target| STORE_SLOTS.iter().position(|s| p.path(s) == target));
    let next_slot = match active_slot {
        Some(0) => 1,
        _ => 0,
    };
    let slot = p.path(STORE_SLOTS[next_slot]);

    session.run_ok("clearing the inactive store slot", &["rm", "-rf", &slot])?;
    session.run_ok("creating the inactive store slot", &["mkdir", "-p", &slot])?;
    stream_archive(session, &archive.bytes, &slot)?;

    // Runtime-written state must survive a store change: the signing key is
    // copied from the active slot (a first deploy has none), and `logs` is a
    // link to a directory that is not part of any slot.
    if let Some(active_idx) = active_slot {
        let old_key = p.path(&format!("{}/{RUNTIME_KEY_FILE}", STORE_SLOTS[active_idx]));
        if session
            .run(
                "looking for the runtime signing key",
                &["test", "-f", &old_key],
            )?
            .success()
        {
            session.run_ok(
                "carrying over the runtime signing key",
                &["cp", "-p", &old_key, &format!("{slot}/{RUNTIME_KEY_FILE}")],
            )?;
        }
    }
    session.run_ok(
        "linking the persistent logs directory",
        &["ln", "-sfn", &p.path("logs"), &format!("{slot}/logs")],
    )?;

    session.run_ok(
        "preparing the store switch",
        &["ln", "-sfn", &slot, &next_link],
    )?;
    session.run_ok("activating the new store", &["mv", "-T", &next_link, &live])?;
    Ok(true)
}

/// Stream the archive into `tar -xf -` over ssh. The only local copy is a
/// 0600 temp file removed on drop; nothing is written to the VM but the
/// extracted files.
fn stream_archive(session: &Session<'_>, bytes: &[u8], slot: &str) -> Result<(), DeployerError> {
    let step = "extracting the store snapshot";
    let mut file = tempfile::NamedTempFile::new()
        .map_err(|e| session.fail(step, format!("creating a local temp file: {e}")))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|e| session.fail(step, format!("writing a local temp file: {e}")))?;
    let argv: Vec<String> = ["tar", "-xf", "-", "-C", slot]
        .iter()
        .map(|a| a.to_string())
        .collect();
    let out = session
        .remote
        .run_with_stdin(&session.target, &argv, file.path())
        .map_err(|e| session.fail(step, e))?;
    if out.success() {
        Ok(())
    } else {
        Err(session.fail(
            step,
            format!(
                "`tar -xf - -C {slot}` exited {}: {}",
                out.status,
                out.stderr.trim()
            ),
        ))
    }
}

fn install_unit(session: &Session<'_>, env: &Environment) -> Result<bool, DeployerError> {
    let p = session.params;
    let staged = p.path(&format!("{}.service.new", p.service_name));
    let installed = p.unit_path();
    session.upload_bytes(
        "uploading the systemd unit",
        render_unit(env, p).as_bytes(),
        &staged,
    )?;
    if session
        .run(
            "comparing the systemd unit",
            &["cmp", "-s", &staged, &installed],
        )?
        .success()
    {
        return Ok(false);
    }
    session.run_privileged_ok(
        "installing the systemd unit",
        &[
            "install", "-m", "0644", "-o", "root", "-g", "root", &staged, &installed,
        ],
    )?;
    session.run_privileged_ok("reloading systemd", &["systemctl", "daemon-reload"])?;
    Ok(true)
}

fn start_service(session: &Session<'_>, changed: bool) -> Result<(), DeployerError> {
    let service = session.params.service_name.as_str();
    if changed {
        session.run_privileged_ok("enabling the service", &["systemctl", "enable", service])?;
        session.run_privileged_ok("restarting the service", &["systemctl", "restart", service])?;
    } else {
        session.run_privileged_ok(
            "starting the service",
            &["systemctl", "enable", "--now", service],
        )?;
    }
    let state = session.run("checking the service", &["systemctl", "is-active", service])?;
    if state.success() && state.stdout.trim() == "active" {
        return Ok(());
    }
    Err(session.fail(
        "checking the service",
        format!(
            "{service} is not active after start (systemctl says {:?}); inspect it on the VM \
             with `journalctl -u {service}`",
            state.stdout.trim()
        ),
    ))
}

/// Stop the service. A unit that is not installed (systemd exit 5) is already
/// stopped.
pub(super) fn stop(session: &Session<'_>) -> Result<(), DeployerError> {
    let service = session.params.service_name.as_str();
    let out = session.run_privileged("stopping the service", &["systemctl", "stop", service])?;
    if out.success() || out.status == 5 {
        Ok(())
    } else {
        Err(session.fail(
            "stopping the service",
            format!(
                "`systemctl stop {service}` exited {}: {}",
                out.status,
                out.stderr.trim()
            ),
        ))
    }
}
