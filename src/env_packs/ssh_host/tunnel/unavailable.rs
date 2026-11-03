//! Kinds this build recognises but cannot bring up yet.
//!
//! They validate (so an answers file written for a later build is not rejected
//! as an unknown kind) and `up` refuses before anything is started or touched.

use std::collections::BTreeMap;

use super::settings::validate_unspecified;
use super::{TunnelContext, TunnelError, TunnelProvider, TunnelUp};

#[derive(Debug, Clone, Copy)]
pub struct NotYetAvailable {
    kind: &'static str,
    why: &'static str,
}

const NEEDS_RUNNER: &str = "it needs a kernel network interface (NET_ADMIN and /dev/net/tun), \
    which a hosted deployer container does not have; it needs a runner that does, and none is \
    available yet. Use `openconnect`, `jump` or `proxy`, or reach the VM another way";

impl NotYetAvailable {
    pub const fn wireguard() -> Self {
        Self {
            kind: "wireguard",
            why: "the userspace WireGuard helper (wireproxy) is not wired in this build yet",
        }
    }
    pub const fn tailscale() -> Self {
        Self {
            kind: "tailscale",
            why: "the userspace Tailscale helper (tailscaled --tun=userspace-networking) is not \
                  wired in this build yet",
        }
    }
    pub const fn openvpn() -> Self {
        Self {
            kind: "openvpn",
            why: NEEDS_RUNNER,
        }
    }
    pub const fn ikev2() -> Self {
        Self {
            kind: "ikev2",
            why: NEEDS_RUNNER,
        }
    }
    pub const fn zerotier() -> Self {
        Self {
            kind: "zerotier",
            why: NEEDS_RUNNER,
        }
    }
}

impl TunnelProvider for NotYetAvailable {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn validate(&self, settings: &BTreeMap<String, String>) -> Result<(), TunnelError> {
        validate_unspecified(self.kind, settings)
    }

    fn up(&self, _ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError> {
        Err(TunnelError::NotImplemented {
            kind: self.kind.to_string(),
            detail: self.why.to_string(),
        })
    }
}
