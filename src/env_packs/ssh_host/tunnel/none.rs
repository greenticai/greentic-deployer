//! `none`: connect directly. Brings nothing up.

use std::collections::BTreeMap;

use super::{TunnelContext, TunnelError, TunnelGuard, TunnelProvider, TunnelUp, validate_settings};

#[derive(Debug, Clone, Copy)]
pub struct NoTunnel;

impl TunnelProvider for NoTunnel {
    fn kind(&self) -> &'static str {
        "none"
    }

    fn validate(&self, settings: &BTreeMap<String, String>) -> Result<(), TunnelError> {
        validate_settings("none", &[], settings)
    }

    fn up(&self, _ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError> {
        Ok(TunnelUp {
            proxy_command: None,
            guard: TunnelGuard::empty(),
        })
    }
}
