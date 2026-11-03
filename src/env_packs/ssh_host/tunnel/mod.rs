//! Reaching a VM that is not directly reachable: the `tunnel` answer.
//!
//! The ssh-host answers take an optional, strict object
//! `"tunnel": {"kind": "...", "settings": {"<key>": "<string>"}}` (the shape of
//! the contract type `VmTunnel`). Without it nothing changes: `ssh` is spawned
//! with exactly the argv it always was (pinned by a golden test).
//!
//! ## One mechanism
//!
//! A hosted deployer has no `NET_ADMIN` and no `/dev/net/tun`, so every kind
//! works in userspace and ends the same way: **`ssh -o ProxyCommand=<cmd>`**.
//!
//! * Helper kinds (`openconnect`, later `wireguard`, `tailscale`) start a helper
//!   that exposes a SOCKS5 listener on `127.0.0.1:<random port>`. `ssh` never
//!   talks to it: the deployer runs its own destination [`gate`] on a second
//!   loopback port, which forwards ONLY `target_host:target_port` and dials the
//!   helper. The `ProxyCommand` is `nc -X 5 -x 127.0.0.1:<gate port> %h %p`.
//! * `proxy` points the same gate at the customer's SOCKS5 / HTTP CONNECT proxy.
//! * `jump` needs no helper: the `ProxyCommand` is a second `ssh -W %h:%p` to the
//!   bastion, with its own mandatory `known_hosts` file and strict host checking.
//!
//! The proxy rides on [`RemoteTarget::proxy_command`](super::remote::RemoteTarget),
//! so commands, `tar` streams and uploads all take the same route and the
//! [`Remote`](super::remote::Remote) trait is unchanged.
//!
//! ## The provider contract
//!
//! Implement [`TunnelProvider`] and register it in [`TunnelRegistry::builtin`].
//!
//! * `kind()` is the wire name. It must be a lowercase word.
//! * `validate(settings)` runs when the answers are parsed, before anything is
//!   started or touched, and must reject unknown keys, missing required keys and
//!   malformed values with [`validate_settings`]. Values are allow-list checked
//!   (no whitespace, `;`, `$(`, backtick, quotes, `..`, newline, leading `-`).
//!   Errors name the key and the rule, never the value.
//! * `up(ctx)` is called **once per `env up`** (once per `warm`, `drain` or
//!   credentials `validate`), never per command. It must:
//!   1. start whatever it needs and return only when the tunnel is PROVEN usable
//!      by [`gate::publish`] (a SOCKS5 CONNECT through the gate that gets an
//!      `SSH-` banner from the target). A listener that merely accepts is not
//!      proof: wireproxy's, tailscaled's and ocproxy's all accept before the
//!      tunnel carries traffic;
//!   2. give up after `ctx.ready_timeout` ([`DEFAULT_READY_TIMEOUT`], 60 s);
//!   3. never retry a failed authentication: a retry can lock a VPN account;
//!   4. get a free port from [`support::free_loopback_port`], never a fixed one;
//!   5. keep secrets out of argv, environment, logs and errors: write them with
//!      [`ScratchDir::write_secret`] (mode 0600, in a 0700 directory) or pass them
//!      on the helper's stdin; spawn helpers with [`support::spawn_silent`] or
//!      with stderr redirected to a scratch file you classify, never quote;
//!   6. put every child process, hook and scratch directory into the returned
//!      [`TunnelUp::guard`]. Dropping the guard kills and reaps the children,
//!      runs the hooks, and deletes the scratch directories.
//! * A kind this build recognises but cannot bring up still validates, and `up`
//!   answers [`TunnelError::NotImplemented`] before anything is started.
//!
//! The registry checks the target address ([`support::check_literal_target`]) before
//! any provider runs, so a provider never sees a loopback / link-local / metadata
//! destination.
//!
//! ## Packages the image needs
//!
//! `openssh-client`, `netcat-openbsd` (the OpenBSD `nc`, for `-X`), and per kind:
//! `openconnect` + `ocproxy`; `wireproxy`; `tailscale` (`tailscaled`). The
//! deployer does not install anything.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

pub mod gate;
pub mod guard;
pub mod jump;
pub mod none;
pub mod openconnect;
pub mod proxy;
pub mod settings;
pub mod support;
pub mod totp;
pub mod unavailable;

pub use guard::{ScratchDir, TunnelGuard};
pub use settings::{SettingSpec, ValueKind, validate_settings};

/// How long `up` may take to prove the tunnel usable.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// The `tunnel` answer, validated.
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub kind: String,
    pub settings: BTreeMap<String, String>,
}

impl fmt::Debug for TunnelConfig {
    /// Setting values can name secret files; show the keys only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfig")
            .field("kind", &self.kind)
            .field("settings", &self.settings.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Why a tunnel was refused or could not be brought up. Never carries a setting
/// value, a secret, or helper output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelError {
    UnknownKind {
        kind: String,
        known: Vec<&'static str>,
    },
    Invalid {
        kind: String,
        key: String,
        detail: String,
    },
    NotImplemented {
        kind: String,
        detail: String,
    },
    Up {
        kind: String,
        detail: String,
    },
}

impl TunnelError {
    pub fn invalid(kind: &str, key: &str, detail: impl Into<String>) -> Self {
        Self::Invalid {
            kind: kind.to_string(),
            key: key.to_string(),
            detail: detail.into(),
        }
    }

    pub fn up(kind: &str, detail: impl Into<String>) -> Self {
        Self::Up {
            kind: kind.to_string(),
            detail: detail.into(),
        }
    }
}

fn shown(s: &str) -> String {
    s.chars().take(40).flat_map(char::escape_debug).collect()
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind { kind, known } => write!(
                f,
                "tunnel kind `{}` is not known (known kinds: {})",
                shown(kind),
                known.join(", ")
            ),
            Self::Invalid { kind, key, detail } => {
                write!(
                    f,
                    "tunnel `{}` setting `{key}` is invalid: {detail}",
                    shown(kind)
                )
            }
            Self::NotImplemented { kind, detail } => {
                write!(
                    f,
                    "tunnel kind `{kind}` is not available in this build: {detail}"
                )
            }
            Self::Up { kind, detail } => {
                write!(f, "tunnel `{kind}` could not be brought up: {detail}")
            }
        }
    }
}

impl std::error::Error for TunnelError {}

/// What a provider is told when it is asked to bring a tunnel up.
#[derive(Debug, Clone, Copy)]
pub struct TunnelContext<'a> {
    /// The provider's validated `settings`.
    pub settings: &'a BTreeMap<String, String>,
    /// The ssh login user (a `jump` bastion defaults to it).
    pub login_user: &'a str,
    /// The VM, as `ssh` will ask for it (`%h`), already checked.
    pub target_host: &'a str,
    /// The VM's ssh port (`%p`).
    pub target_port: u16,
    pub ready_timeout: Duration,
}

/// A tunnel that is up. Dropping it tears everything down.
#[derive(Debug)]
pub struct TunnelUp {
    /// The `ssh -o ProxyCommand=` value. `None` means connect directly.
    pub proxy_command: Option<String>,
    /// Owns the helpers, hooks and scratch files of this tunnel.
    pub guard: TunnelGuard,
}

/// One way of reaching a VM. See the module docs for the contract.
pub trait TunnelProvider: fmt::Debug + Send + Sync {
    /// The wire name of this kind.
    fn kind(&self) -> &'static str;

    /// Check `settings` without starting or touching anything.
    fn validate(&self, settings: &BTreeMap<String, String>) -> Result<(), TunnelError>;

    /// Bring the tunnel up and prove it usable, once.
    fn up(&self, ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError>;
}

/// The known kinds.
#[derive(Debug)]
pub struct TunnelRegistry {
    providers: Vec<Box<dyn TunnelProvider>>,
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl TunnelRegistry {
    /// Every kind this build knows. Kinds that need a runner or a binary this
    /// build does not drive are registered as recognised-but-unavailable.
    pub fn builtin() -> Self {
        Self::with_providers(vec![
            Box::new(none::NoTunnel),
            Box::new(jump::Jump),
            Box::new(proxy::Proxy::default()),
            Box::new(openconnect::OpenConnect::default()),
            Box::new(unavailable::NotYetAvailable::wireguard()),
            Box::new(unavailable::NotYetAvailable::tailscale()),
            Box::new(unavailable::NotYetAvailable::openvpn()),
            Box::new(unavailable::NotYetAvailable::ikev2()),
            Box::new(unavailable::NotYetAvailable::zerotier()),
        ])
    }

    pub fn with_providers(providers: Vec<Box<dyn TunnelProvider>>) -> Self {
        Self { providers }
    }

    pub fn kinds(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.kind()).collect()
    }

    pub fn get(&self, kind: &str) -> Result<&dyn TunnelProvider, TunnelError> {
        self.providers
            .iter()
            .find(|p| p.kind() == kind)
            .map(|p| p.as_ref())
            .ok_or_else(|| TunnelError::UnknownKind {
                kind: kind.to_string(),
                known: self.kinds(),
            })
    }

    /// Validate a whole `tunnel` answer.
    pub fn validate(&self, config: &TunnelConfig) -> Result<(), TunnelError> {
        self.get(&config.kind)?.validate(&config.settings)
    }

    /// Bring `config` up for a VM at `target_host:target_port`.
    pub fn up(
        &self,
        config: &TunnelConfig,
        login_user: &str,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelUp, TunnelError> {
        let provider = self.get(&config.kind)?;
        provider.validate(&config.settings)?;
        if provider.kind() != "none"
            && let Err(why) = support::check_literal_target(target_host)
        {
            return Err(TunnelError::up(provider.kind(), why));
        }
        provider.up(&TunnelContext {
            settings: &config.settings,
            login_user,
            target_host,
            target_port,
            ready_timeout: DEFAULT_READY_TIMEOUT,
        })
    }
}

/// The target to use for `params`, and the guard that keeps its tunnel alive.
/// No `tunnel` answer (or `none`) gives the direct target and no guard, so the
/// `ssh` argv is exactly what it was before tunnels existed.
pub fn connect(
    params: &super::params::SshHostParams,
    registry: &TunnelRegistry,
) -> Result<(super::remote::RemoteTarget, Option<TunnelGuard>), TunnelError> {
    let target = super::remote::RemoteTarget::from(params);
    let Some(config) = &params.tunnel else {
        return Ok((target, None));
    };
    let up = registry.up(config, &params.user, &params.host, params.port)?;
    let guard = (!up.guard.is_empty()).then_some(up.guard);
    Ok((target.with_proxy_command(up.proxy_command), guard))
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_openconnect;
