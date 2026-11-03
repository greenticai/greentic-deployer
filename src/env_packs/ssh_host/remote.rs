//! The one seam through which the ssh-host deployer touches a VM.
//!
//! [`Remote`] has two small operations — run a command, upload a file — so the
//! whole deployer is testable without a network ([`FakeRemote`] in tests) and
//! the real transport ([`SystemSsh`]) is a thin, auditable wrapper over the
//! system `ssh` binary.
//!
//! ## What [`SystemSsh`] guarantees
//!
//! * `ssh` is spawned with an **argument array** (`std::process::Command`),
//!   never through a local shell.
//! * The remote command is one string, because that is what the ssh protocol
//!   carries; every argv element is single-quoted by [`shell_quote`] unless it
//!   is made only of characters no shell treats specially. Callers also validate
//!   their inputs ([`super::params`]); the quoting is the second layer.
//! * Host keys are always verified (`StrictHostKeyChecking=yes`) and nothing
//!   ever prompts (`BatchMode=yes`). There is no switch to turn either off.
//! * The identity file path is redacted from `Debug` and scrubbed from any
//!   transport error text before it can reach a log or an error message.
//!
//! Uploads stream the local file into `cat > <path>` over ssh rather than using
//! `scp`: one binary, no legacy-scp filename handling, and no dependency on the
//! target's sftp subsystem.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use thiserror::Error;

use super::params::SshHostParams;

/// Seconds `ssh` waits to establish the connection.
pub const CONNECT_TIMEOUT_SECS: u32 = 10;
/// `ssh` exits 255 when the connection itself fails (as opposed to the remote
/// command failing). A remote command that exits 255 is indistinguishable.
const SSH_TRANSPORT_FAILURE: i32 = 255;
/// Most stderr text kept in an error.
const MAX_STDERR_CHARS: usize = 600;

/// Where and as whom to connect.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<PathBuf>,
    pub known_hosts_file: Option<PathBuf>,
    pub connect_timeout_secs: u32,
}

impl fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTarget")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field(
                "identity_file",
                &self.identity_file.as_ref().map(|_| "<redacted>"),
            )
            .field("known_hosts_file", &self.known_hosts_file)
            .finish()
    }
}

impl From<&SshHostParams> for RemoteTarget {
    fn from(p: &SshHostParams) -> Self {
        Self {
            host: p.host.clone(),
            port: p.port,
            user: p.user.clone(),
            identity_file: p.identity_file.clone(),
            known_hosts_file: p.known_hosts_file.clone(),
            connect_timeout_secs: CONNECT_TIMEOUT_SECS,
        }
    }
}

/// What a finished remote command reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RemoteOutput {
    pub fn ok() -> Self {
        Self {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    pub fn with_stdout(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            ..Self::ok()
        }
    }

    pub fn failed(status: i32, stderr: impl Into<String>) -> Self {
        Self {
            status,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// The transport could not run the operation at all (as opposed to the remote
/// command running and failing, which is a [`RemoteOutput`] with a non-zero
/// status).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteError {
    #[error("could not start `ssh`: {0}")]
    Spawn(String),
    #[error("ssh connection failed: {0}")]
    Transport(String),
    #[error("{0}")]
    Io(String),
    #[error("refusing to send a command containing a NUL byte")]
    NulInCommand,
}

/// Run commands on, and upload files to, one VM.
pub trait Remote: fmt::Debug + Send + Sync {
    /// Run `argv` on the VM. `Err` only when the transport failed; a command
    /// that ran and exited non-zero is `Ok` with that status.
    fn run(&self, target: &RemoteTarget, argv: &[String]) -> Result<RemoteOutput, RemoteError>;

    /// Run `argv` on the VM with the local file streamed to its stdin (for
    /// `tar -xf -`). Same error contract as [`Remote::run`].
    fn run_with_stdin(
        &self,
        target: &RemoteTarget,
        argv: &[String],
        stdin_file: &Path,
    ) -> Result<RemoteOutput, RemoteError>;

    /// Copy the local file to `remote_path` (created or truncated).
    fn upload(
        &self,
        target: &RemoteTarget,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), RemoteError>;
}

/// POSIX single-quote `arg` unless it is made only of characters no shell
/// treats specially.
pub fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '/' | '-' | '=' | ':' | '@' | '%' | '+' | ',')
        });
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

/// The remote command string for `argv`.
pub fn remote_command(argv: &[String]) -> Result<String, RemoteError> {
    if argv.iter().any(|a| a.contains('\0')) {
        return Err(RemoteError::NulInCommand);
    }
    Ok(argv
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" "))
}

/// `ssh` options common to every invocation, ending with the destination.
/// Pure, so the security-relevant flags are pinned by tests.
pub fn ssh_args(target: &RemoteTarget) -> Vec<String> {
    let mut args: Vec<String> = [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.push("-o".into());
    args.push(format!("ConnectTimeout={}", target.connect_timeout_secs));
    if let Some(known_hosts) = &target.known_hosts_file {
        args.push("-o".into());
        args.push(format!("UserKnownHostsFile={}", known_hosts.display()));
    }
    if let Some(identity) = &target.identity_file {
        args.push("-o".into());
        args.push("IdentitiesOnly=yes".into());
        args.push("-i".into());
        args.push(identity.display().to_string());
    }
    args.push("-p".into());
    args.push(target.port.to_string());
    args.push("--".into());
    args.push(format!("{}@{}", target.user, target.host));
    args
}

/// Real transport: the system `ssh` binary.
#[derive(Debug, Clone, Default)]
pub struct SystemSsh {
    _private: (),
}

impl SystemSsh {
    pub fn new() -> Self {
        Self::default()
    }

    fn spawn(
        &self,
        target: &RemoteTarget,
        command: &str,
        stdin: Option<&Path>,
    ) -> Result<RemoteOutput, RemoteError> {
        let mut args = ssh_args(target);
        args.push(command.to_string());
        let mut child = Command::new("ssh")
            .args(&args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RemoteError::Spawn(scrub(target, &e.to_string())))?;

        // Feed stdin from a thread so a large upload cannot deadlock against
        // the output pipes filling up.
        let feeder = match (stdin, child.stdin.take()) {
            (Some(path), Some(mut pipe)) => {
                let mut file = std::fs::File::open(path)
                    .map_err(|e| RemoteError::Io(format!("opening {}: {e}", path.display())))?;
                Some(std::thread::spawn(move || {
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        match file.read(&mut buf) {
                            Ok(0) => return Ok(()),
                            Ok(n) => pipe.write_all(&buf[..n])?,
                            Err(e) => return Err(e),
                        }
                    }
                }))
            }
            _ => None,
        };
        let output = child
            .wait_with_output()
            .map_err(|e| RemoteError::Io(scrub(target, &e.to_string())))?;
        if let Some(handle) = feeder {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Ok(Err(e)) => return Err(RemoteError::Io(scrub(target, &e.to_string()))),
                Err(_) => return Err(RemoteError::Io("upload thread panicked".into())),
            }
        }
        let status = output.status.code().unwrap_or(SSH_TRANSPORT_FAILURE);
        let stderr = scrub(target, &String::from_utf8_lossy(&output.stderr));
        if status == SSH_TRANSPORT_FAILURE {
            return Err(RemoteError::Transport(truncate(stderr.trim())));
        }
        Ok(RemoteOutput {
            status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: truncate(stderr.trim()),
        })
    }
}

impl Remote for SystemSsh {
    fn run(&self, target: &RemoteTarget, argv: &[String]) -> Result<RemoteOutput, RemoteError> {
        let command = remote_command(argv)?;
        self.spawn(target, &command, None)
    }

    fn run_with_stdin(
        &self,
        target: &RemoteTarget,
        argv: &[String],
        stdin_file: &Path,
    ) -> Result<RemoteOutput, RemoteError> {
        let command = remote_command(argv)?;
        self.spawn(target, &command, Some(stdin_file))
    }

    fn upload(
        &self,
        target: &RemoteTarget,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), RemoteError> {
        if remote_path.contains('\0') {
            return Err(RemoteError::NulInCommand);
        }
        // `umask 077`: an uploaded file (a store snapshot, a unit) is private to
        // the login user until a later step deliberately widens it.
        let command = format!("umask 077 && cat > {}", shell_quote(remote_path));
        let out = self.spawn(target, &command, Some(local_path))?;
        if out.success() {
            Ok(())
        } else {
            Err(RemoteError::Io(format!(
                "upload to {remote_path} failed (exit {}): {}",
                out.status, out.stderr
            )))
        }
    }
}

/// Remove the identity file path from text that may be logged.
fn scrub(target: &RemoteTarget, text: &str) -> String {
    match &target.identity_file {
        Some(identity) => text.replace(&identity.display().to_string(), "<identity_file>"),
        None => text.to_string(),
    }
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= MAX_STDERR_CHARS {
        text.to_string()
    } else {
        let cut: String = text.chars().take(MAX_STDERR_CHARS).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> RemoteTarget {
        RemoteTarget {
            host: "vm.example.com".into(),
            port: 2222,
            user: "ops".into(),
            identity_file: Some("/home/ops/.ssh/id_ed25519".into()),
            known_hosts_file: Some("/home/ops/.ssh/kh".into()),
            connect_timeout_secs: 7,
        }
    }

    #[test]
    fn ssh_args_pin_the_security_relevant_options() {
        let args = ssh_args(&target());
        let joined = args.join(" ");
        assert!(joined.contains("BatchMode=yes"));
        assert!(joined.contains("StrictHostKeyChecking=yes"));
        assert!(joined.contains("ClearAllForwardings=yes"));
        assert!(joined.contains("ConnectTimeout=7"));
        assert!(joined.contains("UserKnownHostsFile=/home/ops/.ssh/kh"));
        assert!(joined.contains("IdentitiesOnly=yes"));
        assert!(joined.contains("-i /home/ops/.ssh/id_ed25519"));
        assert!(joined.contains("-p 2222"));
        assert!(!joined.contains("StrictHostKeyChecking=no"));
        assert!(!joined.contains("StrictHostKeyChecking=accept-new"));
        // The destination is last and follows `--`, so it cannot be an option.
        let n = args.len();
        assert_eq!(args[n - 2], "--");
        assert_eq!(args[n - 1], "ops@vm.example.com");
    }

    #[test]
    fn ssh_args_omit_optional_options_when_unset() {
        let mut t = target();
        t.identity_file = None;
        t.known_hosts_file = None;
        let joined = ssh_args(&t).join(" ");
        assert!(!joined.contains("UserKnownHostsFile"));
        assert!(!joined.contains("IdentitiesOnly"));
        assert!(!joined.contains("-i "));
    }

    #[test]
    fn shell_quote_leaves_safe_words_and_quotes_everything_else() {
        assert_eq!(
            shell_quote("/opt/greentic/bin/x-1.2"),
            "/opt/greentic/bin/x-1.2"
        );
        assert_eq!(shell_quote("--store-root"), "--store-root");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
        assert_eq!(shell_quote("$(id)"), "'$(id)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("a\nb"), "'a\nb'");
    }

    #[test]
    fn remote_command_quotes_each_element_and_refuses_nul() {
        let argv = vec!["echo".to_string(), "a b".to_string(), "$HOME".to_string()];
        assert_eq!(remote_command(&argv).unwrap(), "echo 'a b' '$HOME'");
        assert_eq!(
            remote_command(&["a\0b".to_string()]),
            Err(RemoteError::NulInCommand)
        );
    }

    #[test]
    fn target_debug_and_scrub_hide_the_identity_file() {
        let t = target();
        assert!(!format!("{t:?}").contains("id_ed25519"));
        let scrubbed = scrub(
            &t,
            "Warning: Identity file /home/ops/.ssh/id_ed25519 not accessible",
        );
        assert!(!scrubbed.contains("id_ed25519"), "{scrubbed}");
        assert!(scrubbed.contains("<identity_file>"));
    }

    #[test]
    fn truncate_bounds_long_stderr() {
        let long = "x".repeat(MAX_STDERR_CHARS + 50);
        let cut = truncate(&long);
        assert!(cut.chars().count() <= MAX_STDERR_CHARS + 1);
        assert!(cut.ends_with('…'));
        assert_eq!(truncate("short"), "short");
    }
}
