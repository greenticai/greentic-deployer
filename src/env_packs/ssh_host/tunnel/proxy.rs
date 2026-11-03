//! `proxy`: reach the VM through the customer's own SOCKS5 or HTTP CONNECT proxy.
//!
//! Nothing is started. The deployer's destination gate (see [`super::gate`])
//! listens on a loopback port and forwards ONLY the VM, through the customer's
//! proxy; `ssh` talks to the gate with `nc -X 5`. Credentials, when the proxy
//! wants them, are read from a `0600` file and kept in memory only: they appear
//! in no argv, no environment and no scratch file.
//!
//! Settings: `proxy_type` (`socks5` or `http`), `proxy_host`, `proxy_port`
//! (all required); `proxy_user` + `proxy_password_file` (both or neither).
//!
//! The proxy host is resolved here, once, and the address is PINNED for the
//! tunnel's life. A loopback, link-local (cloud metadata) or unspecified proxy
//! address is refused, so the setting cannot aim the deployer at itself.

use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};

use zeroize::Zeroizing;

use super::gate::{Upstream, publish};
use super::support::{BasicAuth, read_secret_file, refused_address_class};
use super::{
    SettingSpec, TunnelContext, TunnelError, TunnelGuard, TunnelProvider, TunnelUp, ValueKind,
    validate_settings,
};

const SPECS: &[SettingSpec] = &[
    SettingSpec::required("proxy_type", ValueKind::Choice(&["socks5", "http"])),
    SettingSpec::required("proxy_host", ValueKind::Host),
    SettingSpec::required("proxy_port", ValueKind::Port),
    SettingSpec::optional("proxy_user", ValueKind::Account),
    SettingSpec::optional("proxy_password_file", ValueKind::Path),
];

#[derive(Debug, Clone, Copy, Default)]
pub struct Proxy {
    /// Tests run their fake proxy on loopback; production never allows it.
    #[cfg(test)]
    pub(crate) allow_loopback: bool,
}

fn resolve(host: &str, port: u16, allow_loopback: bool) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("the proxy host cannot be resolved ({})", e.kind()))?
        .collect();
    if addrs.is_empty() {
        return Err("the proxy host resolved to no address".into());
    }
    if !allow_loopback && let Some(class) = addrs.iter().find_map(|a| refused_address_class(a.ip()))
    {
        return Err(format!(
            "the proxy address is {class}, which is never used as a proxy"
        ));
    }
    Ok(addrs[0])
}

impl TunnelProvider for Proxy {
    fn kind(&self) -> &'static str {
        "proxy"
    }

    fn validate(&self, settings: &BTreeMap<String, String>) -> Result<(), TunnelError> {
        validate_settings("proxy", SPECS, settings)?;
        match (
            settings.get("proxy_user"),
            settings.get("proxy_password_file"),
        ) {
            (Some(_), None) => Err(TunnelError::invalid(
                "proxy",
                "proxy_password_file",
                "is required when `proxy_user` is set",
            )),
            (None, Some(_)) => Err(TunnelError::invalid(
                "proxy",
                "proxy_user",
                "is required when `proxy_password_file` is set",
            )),
            _ => Ok(()),
        }
    }

    fn up(&self, ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError> {
        let fail = |d: String| TunnelError::up("proxy", d);
        let get = |k: &str| ctx.settings.get(k).map(String::as_str).unwrap_or_default();
        let port: u16 = get("proxy_port")
            .parse()
            .map_err(|_| fail("bad proxy_port".into()))?;
        #[cfg(test)]
        let allow_loopback = self.allow_loopback;
        #[cfg(not(test))]
        let allow_loopback = false;
        let addr = resolve(get("proxy_host"), port, allow_loopback).map_err(fail)?;
        let auth = match ctx.settings.get("proxy_user") {
            Some(user) => {
                let password = read_secret_file("proxy_password_file", get("proxy_password_file"))
                    .map_err(fail)?;
                Some(BasicAuth {
                    user: Zeroizing::new(user.clone()),
                    password,
                })
            }
            None => None,
        };
        let upstream = match get("proxy_type") {
            "http" => Upstream::HttpConnect { addr, auth },
            _ => Upstream::Socks5 { addr, auth },
        };
        publish("proxy", ctx, upstream, TunnelGuard::empty(), None)
    }
}
