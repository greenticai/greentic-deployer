//! `openconnect`: an SSL VPN gateway (Cisco AnyConnect first) in userspace.
//!
//! `openconnect --script-tun --script "ocproxy -D <port>"` logs in and hands the
//! tunnel to `ocproxy`, which exposes it as a SOCKS5 listener on loopback; no
//! kernel interface, no root. The deployer's destination gate sits in front of
//! that listener and forwards only the VM (see [`super::gate`]).
//!
//! ## What can be automated, and what cannot
//!
//! Automated: user + password, and password + a TOTP code that THIS module
//! computes from the customer's seed (RFC 6238, see [`super::totp`]). Not
//! automatable: SAML / single sign-on, push or approval MFA (Duo, Okta Verify),
//! and gateways that demand HostScan / Cisco Secure Desktop posture checks. The
//! error says so and points at a service account exempt from those, or a runner
//! inside the customer's network.
//!
//! ## Rules this provider keeps
//!
//! * **One attempt.** A failed login is never retried: gateways lock accounts
//!   after a few failures. The tunnel is also single-use per `env up`.
//! * The password and the seed are read from `0600` files, held in zeroizing
//!   memory, and reach `openconnect` only on its stdin
//!   (`--passwd-on-stdin`). Neither is in argv or the environment.
//! * `servercert=pin-sha256:...` is mandatory (it also disables system trust),
//!   so a man in the middle of the gateway cannot be accepted.
//! * The host clock must be plausible, and a code is never computed in the last
//!   seconds of its 30 s step.
//! * `openconnect`'s own output goes to a `0600` scratch file that is only
//!   classified into a fixed sentence; it is never quoted, because it can echo
//!   the user name or form fields.
//!
//! Settings: `server`, `servercert`, `user`, `password_file` (required);
//! `protocol` (`anyconnect`), `authgroup`, `usergroup`, `totp_seed_file`,
//! `totp_mode` (`second_prompt`, the default: the code answers the gateway's
//! second prompt; `append`: the code is appended to the password).
//!
//! Not run against a real gateway; see docs/ssh-host-internals.md.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::gate::{HelperWatch, Upstream, publish};
use super::support::{check_literal_target, free_loopback_port, read_secret_file, shell_quote_all};
use super::{
    ScratchDir, SettingSpec, TunnelContext, TunnelError, TunnelGuard, TunnelProvider, TunnelUp,
    ValueKind, totp, validate_settings,
};

const SPECS: &[SettingSpec] = &[
    SettingSpec::required("server", ValueKind::Host),
    SettingSpec::required("servercert", ValueKind::PinSha256),
    SettingSpec::required("user", ValueKind::Account),
    SettingSpec::required("password_file", ValueKind::Path),
    SettingSpec::optional("protocol", ValueKind::Choice(&["anyconnect"])),
    SettingSpec::optional("authgroup", ValueKind::Word),
    SettingSpec::optional("usergroup", ValueKind::Word),
    SettingSpec::optional("totp_seed_file", ValueKind::Path),
    SettingSpec::optional("totp_mode", ValueKind::Choice(&["second_prompt", "append"])),
];

const KIND: &str = "openconnect";

/// Where to find the helpers, and the clock (injectable for tests).
#[derive(Debug, Clone)]
pub struct OpenConnect {
    binary: String,
    ocproxy: String,
    now_unix: fn() -> u64,
}

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Default for OpenConnect {
    fn default() -> Self {
        Self {
            binary: "openconnect".into(),
            ocproxy: "ocproxy".into(),
            now_unix: system_now,
        }
    }
}

impl OpenConnect {
    /// Use other binaries and clock (tests drive a stub `openconnect`).
    #[cfg(test)]
    pub(crate) fn with(binary: &str, ocproxy: &str, now_unix: fn() -> u64) -> Self {
        Self {
            binary: binary.into(),
            ocproxy: ocproxy.into(),
            now_unix,
        }
    }
}

/// The `openconnect` argv (without the program name). Pure. The password and the
/// code are NOT here: they go on stdin.
pub(crate) fn argv(
    settings: &BTreeMap<String, String>,
    ocproxy: &str,
    socks_port: u16,
) -> Vec<String> {
    let get = |k: &str| settings.get(k).map(String::as_str);
    let script = shell_quote_all(&[
        ocproxy.to_string(),
        "-D".into(),
        socks_port.to_string(),
        "-k".into(),
        "30".into(),
    ]);
    let mut args = vec![
        format!("--protocol={}", get("protocol").unwrap_or("anyconnect")),
        "--non-inter".into(),
        "--passwd-on-stdin".into(),
        format!("--user={}", get("user").unwrap_or_default()),
        format!("--servercert={}", get("servercert").unwrap_or_default()),
        "--no-dtls".into(),
        "--script-tun".into(),
        "--script".into(),
        script,
    ];
    if let Some(group) = get("authgroup") {
        args.push(format!("--authgroup={group}"));
    }
    let mut url = format!("https://{}", get("server").unwrap_or_default());
    if let Some(usergroup) = get("usergroup") {
        url.push('/');
        url.push_str(usergroup);
    }
    args.push(url);
    args
}

/// What goes on stdin: the password line, then the code line (or the two joined).
pub(crate) fn stdin_payload(
    password: &str,
    code: Option<&str>,
    mode_append: bool,
) -> Zeroizing<String> {
    let mut text = String::with_capacity(password.len() + 16);
    text.push_str(password);
    match code {
        Some(code) if mode_append => text.push_str(code),
        Some(code) => {
            text.push('\n');
            text.push_str(code);
        }
        None => {}
    }
    text.push('\n');
    Zeroizing::new(text)
}

const SAML: &str = "the gateway asks for single sign-on in a browser (SAML), which cannot run \
    unattended; ask the customer for a service account that is exempt from SSO and MFA, or run \
    the deploy from a runner inside their network";
const PUSH: &str = "the gateway asks for a push or approval on a phone, which cannot run \
    unattended; ask the customer for a service account that is exempt from MFA, give a TOTP seed \
    (`totp_seed_file`), or use a runner inside their network";
const POSTURE: &str = "the gateway requires a HostScan / Cisco Secure Desktop posture check, \
    which is not supported; ask the customer for an account or group that skips it, or use a \
    runner inside their network";
const REFUSED: &str = "the gateway refused the login (wrong password or code, or a locked \
    account). It was tried ONCE and not retried; check the account before running again, because \
    repeated failures can lock it";
const PIN: &str = "the gateway's certificate does not match `servercert` (pin-sha256); check the \
    pin with the customer, and treat an unexpected change as a possible interception";
const UNREACHABLE: &str = "the gateway could not be reached (name, network or TLS)";

/// Turn `openconnect`'s output into one fixed sentence. Never quotes the output.
pub(crate) fn classify_failure(log: &str, status: Option<ExitStatus>) -> String {
    let l = log.to_ascii_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    let why = if any(&[
        "saml",
        "external browser",
        "single-sign-on",
        "single sign-on",
        "sso login",
    ]) {
        SAML
    } else if any(&["hostscan", "host scan", "secure desktop", "csd", "posture"]) {
        POSTURE
    } else if any(&["duo", "push notification", "approve the", "approval"]) {
        PUSH
    } else if any(&["pin-sha256", "certificate", "not match", "verify failed"]) {
        PIN
    } else if any(&[
        "authentication failed",
        "login failed",
        "failed to complete authentication",
        "invalid password",
        "access denied",
        "login denied",
    ]) {
        REFUSED
    } else if any(&[
        "failed to open https",
        "resolve",
        "connection refused",
        "timed out",
        "unreachable",
    ]) {
        UNREACHABLE
    } else {
        return match status.and_then(|s| s.code()) {
            Some(code) => format!("openconnect exited with status {code} before the tunnel was up"),
            None => "openconnect was stopped before the tunnel was up".to_string(),
        };
    };
    why.to_string()
}

fn read_log(path: &std::path::Path) -> String {
    // Bounded: a chatty helper must not be read whole.
    use std::io::Read;
    let mut text = String::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(64 * 1024).read_to_string(&mut text);
    }
    text
}

impl TunnelProvider for OpenConnect {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn validate(&self, settings: &BTreeMap<String, String>) -> Result<(), TunnelError> {
        validate_settings(KIND, SPECS, settings)?;
        if let Some(server) = settings.get("server") {
            check_literal_target(server)
                .map_err(|why| TunnelError::invalid(KIND, "server", why))?;
        }
        if settings.contains_key("totp_mode") && !settings.contains_key("totp_seed_file") {
            return Err(TunnelError::invalid(
                KIND,
                "totp_mode",
                "only applies with `totp_seed_file`",
            ));
        }
        Ok(())
    }

    fn up(&self, ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError> {
        let fail = |d: String| TunnelError::up(KIND, d);
        let get = |k: &str| ctx.settings.get(k).map(String::as_str);

        let password = read_secret_file("password_file", get("password_file").unwrap_or_default())
            .map_err(fail)?;
        let code = match get("totp_seed_file") {
            None => None,
            Some(path) => {
                let seed_text = read_secret_file("totp_seed_file", path).map_err(fail)?;
                let seed = totp::decode_base32(&seed_text).map_err(|e| fail(e.to_string()))?;
                let mut now = (self.now_unix)();
                if let Some(problem) = totp::clock_problem(now) {
                    return Err(fail(problem));
                }
                let wait = totp::wait_for_fresh_step(now);
                if wait > 0 {
                    std::thread::sleep(Duration::from_secs(wait));
                    now += wait;
                }
                Some(totp::code(&seed, now))
            }
        };
        let append = get("totp_mode") == Some("append");
        let payload = stdin_payload(&password, code.as_deref().map(String::as_str), append);

        let scratch =
            ScratchDir::new().map_err(|e| fail(format!("no scratch directory ({})", e.kind())))?;
        let (log_file, log_path) = scratch
            .create_private("openconnect.log")
            .map_err(|e| fail(format!("no scratch log ({})", e.kind())))?;
        let socks_port = free_loopback_port()
            .map_err(|e| fail(format!("no free loopback port ({})", e.kind())))?;

        let mut command = Command::new(&self.binary);
        command
            .args(argv(ctx.settings, &self.ocproxy, socks_port))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file));
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(|e| {
            fail(format!(
                "could not start `{}` ({}); is the openconnect package installed?",
                self.binary,
                e.kind()
            ))
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            // A helper that died already closed the pipe; its exit explains why.
            let _ = stdin.write_all(payload.as_bytes());
        }
        drop(payload);

        let mut guard = TunnelGuard::empty();
        guard.adopt_scratch(scratch);
        let index = guard.adopt_group_leader(child);
        let upstream = Upstream::Socks5 {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port)),
            auth: None,
        };
        let watch = HelperWatch {
            index,
            explain: Box::new(move |status| classify_failure(&read_log(&log_path), Some(status))),
        };
        publish(KIND, ctx, upstream, guard, Some(watch))
    }
}
