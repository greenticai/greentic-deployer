//! `jump`: reach the VM through an SSH bastion.
//!
//! The `ProxyCommand` is a second `ssh ... -W %h:%p` to the bastion, rather than
//! `-J`/`ProxyJump`, so the bastion gets its OWN `known_hosts` file and identity:
//! `-J` would verify the bastion against the VM's file and offer the VM's key.
//! The bastion's host key is always verified (`StrictHostKeyChecking=yes`) against
//! a `jump_known_hosts_file` that is REQUIRED; there is no setting to turn that
//! off.
//!
//! Settings: `jump_host` (required), `jump_known_hosts_file` (required),
//! `jump_user` (default: the login user), `jump_port` (default 22),
//! `jump_identity_file` (optional).
//!
//! Tested through argv only (the pure [`proxy_command`]); it has not been run
//! against a real bastion.

use std::collections::BTreeMap;

use super::support::{check_literal_target, shell_quote_all};
use super::{
    SettingSpec, TunnelContext, TunnelError, TunnelGuard, TunnelProvider, TunnelUp, ValueKind,
    validate_settings,
};
use crate::env_packs::ssh_host::remote::CONNECT_TIMEOUT_SECS;

const SPECS: &[SettingSpec] = &[
    SettingSpec::required("jump_host", ValueKind::Host),
    SettingSpec::required("jump_known_hosts_file", ValueKind::Path),
    SettingSpec::optional("jump_user", ValueKind::Account),
    SettingSpec::optional("jump_port", ValueKind::Port),
    SettingSpec::optional("jump_identity_file", ValueKind::Path),
];

#[derive(Debug, Clone, Copy)]
pub struct Jump;

/// The `ProxyCommand` value. Pure; `settings` must have passed validation.
pub fn proxy_command(settings: &BTreeMap<String, String>, login_user: &str) -> String {
    let get = |k: &str| settings.get(k).map(String::as_str);
    let user = get("jump_user").unwrap_or(login_user);
    let host = get("jump_host").unwrap_or_default();
    let port = get("jump_port").unwrap_or("22");
    let mut argv: Vec<String> = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        &format!("ConnectTimeout={CONNECT_TIMEOUT_SECS}"),
        "-o",
        &format!(
            "UserKnownHostsFile={}",
            get("jump_known_hosts_file").unwrap_or_default()
        ),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(identity) = get("jump_identity_file") {
        argv.extend(["-o", "IdentitiesOnly=yes", "-i", identity].map(String::from));
    }
    argv.extend(["-p", port, "-W", "%h:%p", "--"].map(String::from));
    argv.push(format!("{user}@{host}"));
    shell_quote_all(&argv)
}

impl TunnelProvider for Jump {
    fn kind(&self) -> &'static str {
        "jump"
    }

    fn validate(&self, settings: &BTreeMap<String, String>) -> Result<(), TunnelError> {
        validate_settings("jump", SPECS, settings)?;
        if let Some(host) = settings.get("jump_host") {
            check_literal_target(host)
                .map_err(|why| TunnelError::invalid("jump", "jump_host", why))?;
        }
        Ok(())
    }

    fn up(&self, ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError> {
        // Nothing to start: `ssh` runs the bastion hop itself, per connection.
        Ok(TunnelUp {
            proxy_command: Some(proxy_command(ctx.settings, ctx.login_user)),
            guard: TunnelGuard::empty(),
        })
    }
}
