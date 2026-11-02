//! Binding answers for the ssh-host deployer, parsed and validated strictly.
//!
//! Every value that ends up inside a command the REMOTE shell will see
//! (`install_dir`, `service_name`, the env id) is restricted to
//! [`is_safe_remote_char`] — letters, digits, `.`, `_`, `/`, `-` — so there is
//! nothing for a shell to interpret. Values that only ever reach a LOCAL `argv`
//! (host, user, identity file, known-hosts file, binary path) are validated for
//! option injection (a leading `-`) and control characters instead; they are
//! never spliced into a shell string.
//!
//! Unknown keys are rejected (deny-by-default, as the Cloud Run / AWS params do).
//! `identity_file` is never echoed in an error message and is redacted from
//! `Debug`.

use std::fmt;
use std::path::PathBuf;

use greentic_deploy_spec::Environment;
use serde_json::Value;
use thiserror::Error;

/// Default SSH port.
pub const DEFAULT_SSH_PORT: u16 = 22;
/// Default install directory on the VM.
pub const DEFAULT_INSTALL_DIR: &str = "/opt/greentic";
/// Default port greentic-start serves on.
pub const DEFAULT_LISTEN_PORT: u16 = 8080;

/// Answer keys this deployer accepts, in wizard order.
pub const ANSWER_KEYS: &[&str] = &[
    "host",
    "port",
    "user",
    "identity_file",
    "known_hosts_file",
    "install_dir",
    "service_name",
    "start_binary",
    "listen_port",
    "expose",
    "use_sudo",
];

/// Why the binding's answers were refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SshHostParamsError {
    #[error("ssh-host: answers must be a JSON object")]
    NotAnObject,
    #[error("ssh-host: unknown answer key `{0}`")]
    UnknownKey(String),
    #[error("ssh-host: answer `{0}` is required")]
    Missing(&'static str),
    /// `detail` never contains the rejected value for secret-adjacent keys.
    #[error("ssh-host: answer `{key}` is invalid: {detail}")]
    Invalid { key: String, detail: String },
}

fn invalid(key: &str, detail: impl Into<String>) -> SshHostParamsError {
    SshHostParamsError::Invalid {
        key: key.to_string(),
        detail: detail.into(),
    }
}

/// Characters allowed in any value interpolated into a remote command.
pub fn is_safe_remote_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-')
}

/// Validated binding answers.
#[derive(Clone, PartialEq, Eq)]
pub struct SshHostParams {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Local path to the private key. Never logged, never in an error.
    pub identity_file: Option<PathBuf>,
    /// Local path to a dedicated known_hosts file (host keys are always
    /// verified; this only chooses WHICH file).
    pub known_hosts_file: Option<PathBuf>,
    /// Absolute, normalized, safe-charset install directory on the VM.
    pub install_dir: String,
    pub service_name: String,
    /// Local greentic-start binary to copy to the VM, when the VM may not pull.
    pub start_binary: Option<PathBuf>,
    pub listen_port: u16,
    /// Bind `0.0.0.0` (plain HTTP, reachable from the network) instead of the
    /// default `127.0.0.1`, which needs a reverse proxy in front.
    pub expose: bool,
    pub use_sudo: bool,
}

impl fmt::Debug for SshHostParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshHostParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field(
                "identity_file",
                &self.identity_file.as_ref().map(|_| "<redacted>"),
            )
            .field("known_hosts_file", &self.known_hosts_file)
            .field("install_dir", &self.install_dir)
            .field("service_name", &self.service_name)
            .field("start_binary", &self.start_binary)
            .field("listen_port", &self.listen_port)
            .field("expose", &self.expose)
            .field("use_sudo", &self.use_sudo)
            .finish()
    }
}

impl SshHostParams {
    /// Parse the binding answers for `env`. `host` and `user` are required;
    /// everything else has a default.
    pub fn from_answers(env: &Environment, answers: &Value) -> Result<Self, SshHostParamsError> {
        let obj = answers.as_object().ok_or(SshHostParamsError::NotAnObject)?;
        for key in obj.keys() {
            if !ANSWER_KEYS.contains(&key.as_str()) {
                return Err(SshHostParamsError::UnknownKey(key.clone()));
            }
        }
        let env_id = env.environment_id.as_str();
        check_env_id(env_id)?;

        let host = parse_host(required_string(obj.get("host"), "host")?)?;
        let user = parse_user(required_string(obj.get("user"), "user")?)?;
        let port = match obj.get("port") {
            Some(v) => parse_port("port", v)?,
            None => DEFAULT_SSH_PORT,
        };
        let listen_port = match obj.get("listen_port") {
            Some(v) => parse_port("listen_port", v)?,
            None => DEFAULT_LISTEN_PORT,
        };
        let install_dir = match optional_string(obj.get("install_dir"), "install_dir")? {
            Some(s) => parse_install_dir(&s)?,
            None => DEFAULT_INSTALL_DIR.to_string(),
        };
        let service_name = match optional_string(obj.get("service_name"), "service_name")? {
            Some(s) => parse_service_name(&s)?,
            None => default_service_name(env_id),
        };
        let expose = match obj.get("expose") {
            Some(v) => parse_bool("expose", v)?,
            None => false,
        };
        let use_sudo = match obj.get("use_sudo") {
            Some(v) => parse_bool("use_sudo", v)?,
            None => user != "root",
        };
        Ok(Self {
            host,
            port,
            identity_file: optional_local_path(obj.get("identity_file"), "identity_file", true)?,
            known_hosts_file: optional_local_path(
                obj.get("known_hosts_file"),
                "known_hosts_file",
                false,
            )?,
            user,
            install_dir,
            service_name,
            start_binary: optional_local_path(obj.get("start_binary"), "start_binary", false)?,
            listen_port,
            expose,
            use_sudo,
        })
    }

    /// `<install_dir>/<rel>` — `rel` is always one of this module's constants.
    pub fn path(&self, rel: &str) -> String {
        format!("{}/{rel}", self.install_dir)
    }

    /// Address greentic-start binds: loopback unless `expose` is set.
    pub fn bind_addr(&self) -> &'static str {
        if self.expose { "0.0.0.0" } else { "127.0.0.1" }
    }

    /// The systemd unit file path for this service.
    pub fn unit_path(&self) -> String {
        format!("/etc/systemd/system/{}.service", self.service_name)
    }
}

/// `greentic-<env_id>` with anything outside `[A-Za-z0-9_-]` mapped to `-`.
pub fn default_service_name(env_id: &str) -> String {
    let mapped: String = env_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("greentic-{mapped}")
}

/// The env id is interpolated into `ExecStart=` and the store path.
fn check_env_id(env_id: &str) -> Result<(), SshHostParamsError> {
    if env_id.is_empty()
        || env_id.starts_with('-')
        || env_id == "."
        || env_id == ".."
        || !env_id.chars().all(|c| is_safe_remote_char(c) && c != '/')
    {
        return Err(invalid(
            "environment_id",
            format!(
                "env id {env_id:?} cannot be used on a remote command line; allowed characters \
                 are letters, digits, `.`, `_` and `-`"
            ),
        ));
    }
    Ok(())
}

fn required_string<'a>(
    value: Option<&'a Value>,
    key: &'static str,
) -> Result<&'a str, SshHostParamsError> {
    match value {
        None | Some(Value::Null) => Err(SshHostParamsError::Missing(key)),
        Some(Value::String(s)) if s.trim().is_empty() => Err(SshHostParamsError::Missing(key)),
        Some(Value::String(s)) => Ok(s.trim()),
        Some(_) => Err(invalid(key, "must be a string")),
    }
}

fn optional_string(
    value: Option<&Value>,
    key: &'static str,
) -> Result<Option<String>, SshHostParamsError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(_) => Err(invalid(key, "must be a string")),
    }
}

fn parse_host(raw: &str) -> Result<String, SshHostParamsError> {
    let ok = !raw.is_empty()
        && raw.len() <= 253
        && !raw.starts_with('-')
        && !raw.starts_with('.')
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if ok {
        Ok(raw.to_string())
    } else {
        Err(invalid(
            "host",
            format!(
                "{raw:?} is not a hostname or IPv4 address (letters, digits, `.` and `-` only, \
                 no leading `-`; IPv6 literals are not supported — use a hostname)"
            ),
        ))
    }
}

fn parse_user(raw: &str) -> Result<String, SshHostParamsError> {
    let ok = !raw.is_empty()
        && raw.len() <= 32
        && !raw.starts_with('-')
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(raw.to_string())
    } else {
        Err(invalid(
            "user",
            format!("{raw:?} is not a valid login name (letters, digits, `.`, `_`, `-`)"),
        ))
    }
}

fn parse_port(key: &str, value: &Value) -> Result<u16, SshHostParamsError> {
    let n = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    match n {
        Some(p) if (1..=65535).contains(&p) => Ok(p as u16),
        _ => Err(invalid(key, "must be a port number between 1 and 65535")),
    }
}

fn parse_bool(key: &str, value: &Value) -> Result<bool, SshHostParamsError> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s.trim().eq_ignore_ascii_case("true") => Ok(true),
        Value::String(s) if s.trim().eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(invalid(key, "must be true or false")),
    }
}

/// Absolute, `[A-Za-z0-9._/-]` only, no `..`/`.` segment, no empty segment
/// (`//`), not the filesystem root. A trailing `/` is dropped.
fn parse_install_dir(raw: &str) -> Result<String, SshHostParamsError> {
    let key = "install_dir";
    let trimmed = raw.strip_suffix('/').unwrap_or(raw);
    if !trimmed.starts_with('/') {
        return Err(invalid(key, "must be an absolute path"));
    }
    if !trimmed.chars().all(is_safe_remote_char) {
        return Err(invalid(
            key,
            "may contain only letters, digits, `.`, `_`, `/` and `-`",
        ));
    }
    let segments: Vec<&str> = trimmed[1..].split('/').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(invalid(
            key,
            "must not be `/` or contain an empty segment (`//`)",
        ));
    }
    if segments.iter().any(|s| *s == ".." || *s == ".") {
        return Err(invalid(key, "must not contain `.` or `..` segments"));
    }
    Ok(trimmed.to_string())
}

fn parse_service_name(raw: &str) -> Result<String, SshHostParamsError> {
    let ok = !raw.is_empty()
        && raw.len() <= 64
        && !raw.starts_with('-')
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    if ok {
        Ok(raw.to_string())
    } else {
        Err(invalid(
            "service_name",
            "may contain only letters, digits, `_` and `-` (max 64, no leading `-`)",
        ))
    }
}

/// Local paths only reach a local `argv`, so the rules are: absolute, no
/// control characters. `redact` keeps the offending value out of the message.
fn optional_local_path(
    value: Option<&Value>,
    key: &'static str,
    redact: bool,
) -> Result<Option<PathBuf>, SshHostParamsError> {
    let Some(raw) = optional_string(value, key)? else {
        return Ok(None);
    };
    let shown = if redact {
        "<redacted>".to_string()
    } else {
        format!("{raw:?}")
    };
    if !raw.starts_with('/') {
        return Err(invalid(key, format!("{shown} must be an absolute path")));
    }
    if raw.chars().any(char::is_control) {
        return Err(invalid(key, "must not contain control characters"));
    }
    Ok(Some(PathBuf::from(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use serde_json::json;

    fn env() -> Environment {
        build_fixture_env()
    }

    fn base() -> Value {
        json!({"host": "vm.example.com", "user": "greentic"})
    }

    fn with(key: &str, value: Value) -> Value {
        let mut v = base();
        v[key] = value;
        v
    }

    #[test]
    fn minimal_answers_get_defaults() {
        let p = SshHostParams::from_answers(&env(), &base()).unwrap();
        assert_eq!(p.host, "vm.example.com");
        assert_eq!(p.port, 22);
        assert_eq!(p.user, "greentic");
        assert_eq!(p.install_dir, "/opt/greentic");
        assert_eq!(p.service_name, "greentic-conformance");
        assert_eq!(p.listen_port, 8080);
        assert!(p.use_sudo, "non-root user defaults to sudo");
        assert!(!p.expose, "loopback unless the operator opts in");
        assert_eq!(p.bind_addr(), "127.0.0.1");
        assert!(p.identity_file.is_none() && p.start_binary.is_none());
    }

    #[test]
    fn root_defaults_to_no_sudo() {
        let p = SshHostParams::from_answers(&env(), &json!({"host": "h", "user": "root"})).unwrap();
        assert!(!p.use_sudo);
    }

    #[test]
    fn full_answers_round_trip_and_accept_string_numbers() {
        let p = SshHostParams::from_answers(
            &env(),
            &json!({
                "host": "10.0.0.7", "port": "2222", "user": "ops",
                "identity_file": "/home/ops/.ssh/id_ed25519",
                "known_hosts_file": "/home/ops/.ssh/known_hosts_greentic",
                "install_dir": "/srv/greentic/", "service_name": "gt_prod-1",
                "start_binary": "/usr/local/bin/greentic-start",
                "listen_port": 9090, "expose": "true", "use_sudo": "false"
            }),
        )
        .unwrap();
        assert_eq!((p.port, p.listen_port, p.use_sudo), (2222, 9090, false));
        assert_eq!(p.bind_addr(), "0.0.0.0");
        assert_eq!(p.install_dir, "/srv/greentic", "trailing slash dropped");
        assert_eq!(p.service_name, "gt_prod-1");
    }

    #[test]
    fn required_keys_and_unknown_keys() {
        let e = env();
        assert_eq!(
            SshHostParams::from_answers(&e, &json!({"user": "u"})).unwrap_err(),
            SshHostParamsError::Missing("host")
        );
        assert_eq!(
            SshHostParams::from_answers(&e, &json!({"host": "h"})).unwrap_err(),
            SshHostParamsError::Missing("user")
        );
        assert_eq!(
            SshHostParams::from_answers(&e, &with("sudo_password", json!("x"))).unwrap_err(),
            SshHostParamsError::UnknownKey("sudo_password".into())
        );
        assert_eq!(
            SshHostParams::from_answers(&e, &json!("nope")).unwrap_err(),
            SshHostParamsError::NotAnObject
        );
    }

    #[test]
    fn install_dir_rejects_every_injection_shape() {
        let e = env();
        for bad in [
            "/opt/green tic",
            "/opt/greentic;rm -rf /",
            "/opt/$(id)",
            "/opt/`id`",
            "/opt/a&b",
            "/opt/a|b",
            "/opt/a'b",
            "/opt/a\"b",
            "/opt/a\nb",
            "/opt/../etc",
            "/opt/./x",
            "/opt//x",
            "/",
            "relative/path",
            "~/greentic",
            "/opt/gréen",
        ] {
            let err = SshHostParams::from_answers(&e, &with("install_dir", json!(bad)))
                .expect_err(&format!("{bad:?} must be rejected"));
            assert!(
                matches!(&err, SshHostParamsError::Invalid { key, .. } if key == "install_dir"),
                "{bad:?} -> {err:?}"
            );
        }
    }

    #[test]
    fn service_name_rejects_injection_and_dots() {
        let e = env();
        let too_long = "x".repeat(65);
        for bad in [
            "a b",
            "a;b",
            "a$(x)",
            "a.service",
            "-x",
            "a/b",
            too_long.as_str(),
        ] {
            assert!(
                SshHostParams::from_answers(&e, &with("service_name", json!(bad))).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn host_and_user_cannot_smuggle_ssh_options() {
        let e = env();
        for bad in [
            "-oProxyCommand=id",
            "h;id",
            "h h",
            "h$(id)",
            "[::1]",
            "::1",
            ".h",
            "h\nx",
        ] {
            assert!(
                SshHostParams::from_answers(&e, &json!({"host": bad, "user": "u"})).is_err(),
                "host {bad:?}"
            );
        }
        for bad in ["-oFoo", "u;id", "u u", "u@h", "u$(id)"] {
            assert!(
                SshHostParams::from_answers(&e, &json!({"host": "h", "user": bad})).is_err(),
                "user {bad:?}"
            );
        }
    }

    #[test]
    fn ports_and_bools_are_strict() {
        let e = env();
        for bad in [
            json!(0),
            json!(65536),
            json!("abc"),
            json!(-1),
            json!(22.5),
            json!(true),
        ] {
            assert!(
                SshHostParams::from_answers(&e, &with("port", bad.clone())).is_err(),
                "{bad}"
            );
        }
        for bad in [json!("yes"), json!(1), json!([])] {
            assert!(
                SshHostParams::from_answers(&e, &with("use_sudo", bad.clone())).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn local_paths_must_be_absolute_and_identity_is_never_echoed() {
        let e = env();
        let err =
            SshHostParams::from_answers(&e, &with("identity_file", json!("secret/relative_key")))
                .unwrap_err();
        let text = err.to_string();
        assert!(
            !text.contains("relative_key"),
            "identity path leaked: {text}"
        );
        assert!(
            SshHostParams::from_answers(&e, &with("start_binary", json!("bin/greentic-start")))
                .is_err()
        );
        assert!(
            SshHostParams::from_answers(&e, &with("known_hosts_file", json!("/x/\u{7}y"))).is_err()
        );
    }

    #[test]
    fn debug_redacts_the_identity_file() {
        let p = SshHostParams::from_answers(
            &env(),
            &with("identity_file", json!("/home/ops/.ssh/very_secret_key")),
        )
        .unwrap();
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("very_secret_key"), "{dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn env_ids_that_could_pass_as_options_or_dots_are_refused() {
        // `EnvId` already limits itself to `[A-Za-z0-9._-]`, which still admits
        // an id that reads as an option or a dot segment on a command line.
        for bad in ["-lead", ".", ".."] {
            let mut e = env();
            e.environment_id = greentic_deploy_spec::EnvId::try_from(bad)
                .unwrap_or_else(|err| panic!("{bad:?} should be a valid EnvId: {err}"));
            assert!(SshHostParams::from_answers(&e, &base()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn default_service_name_maps_unsafe_characters() {
        assert_eq!(default_service_name("prod.eu"), "greentic-prod-eu");
        assert_eq!(default_service_name("a_b-c"), "greentic-a_b-c");
    }
}
