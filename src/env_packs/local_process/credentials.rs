//! [`DeployerCredentials`] impl for the local-process deployer.
//!
//! The local-process deployer needs **no real credential material** —
//! there are no IAM roles or cluster RBAC to provision locally. The
//! credentials story reduces to "can the deployer actually run here":
//!
//! - [`FS_WRITABLE_CAP`] — the env's state directory must be writable
//!   (the deployer writes runtime config + cached artifacts there).
//! - [`PORT_AVAILABLE_CAP`] — at least one port in the configured range
//!   must be bindable on `127.0.0.1` (the deployer spawns child
//!   processes that listen on these).
//!
//! The probes touch only the local filesystem and a single bind+drop
//! socket each; sub-100ms.
//!
//! [`bootstrap`](DeployerCredentials::bootstrap) returns
//! [`BootstrapError::NotApplicable`] — local-process has no admin
//! escalation path, so the honest answer to `gtc op credentials bootstrap
//! local` is "nothing to bootstrap, run `requirements` instead". Returning
//! `Ok` with a sentinel `credentials_ref` would leave the env pointing at
//! material that doesn't exist.
//!
//! Reference shape for Phase D deployers: own [`required_capabilities`]
//! ID strings, per-probe `Pass | Fail { reason } | Skipped { reason }`,
//! `bootstrap` either runs or refuses with a structured message.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::ops::RangeInclusive;
use std::path::Path;

use greentic_deploy_spec::EnvironmentHostConfig;

use crate::credentials::{
    BootstrapError, BootstrapInput, BootstrapOutcome, Capability, CapabilityCheck,
    CapabilityStatus, DeployerCredentials, RequirementsReport, ValidationContext,
};

/// Stable ID for the "env state dir is writable" capability.
pub const FS_WRITABLE_CAP: &str = "local-process.fs.writable";

/// Stable ID for the "at least one port in the range is bindable"
/// capability.
pub const PORT_AVAILABLE_CAP: &str = "local-process.port.available";

/// Default port range the local-process deployer treats as its child
/// process listening pool. Picked to match what `greentic-start`'s
/// default config range expects today; can be overridden per-handler
/// via [`LocalProcessCredentials::with_port_range`].
pub const DEFAULT_PORT_RANGE: RangeInclusive<u16> = 8080..=8090;

/// Credentials handler for the local-process deployer.
///
/// Holds the configured port range (defaults to [`DEFAULT_PORT_RANGE`]).
/// The handler is the same singleton for the whole process — there is
/// nothing per-env to remember today.
#[derive(Debug, Clone)]
pub struct LocalProcessCredentials {
    port_range: RangeInclusive<u16>,
}

impl Default for LocalProcessCredentials {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProcessCredentials {
    pub fn new() -> Self {
        Self {
            port_range: DEFAULT_PORT_RANGE,
        }
    }

    pub fn with_port_range(range: RangeInclusive<u16>) -> Self {
        Self { port_range: range }
    }

    fn fs_writable_capability(&self) -> Capability {
        Capability::new(
            FS_WRITABLE_CAP,
            "Env state directory is writable for the local-process deployer",
        )
    }

    fn port_available_capability(&self, host_config: Option<&EnvironmentHostConfig>) -> Capability {
        let description = if let Some(addr) = host_config.and_then(|hc| hc.listen_addr) {
            format!("Configured listen_addr {addr} is bindable")
        } else {
            format!(
                "At least one port in [{}-{}] is bindable on 127.0.0.1",
                self.port_range.start(),
                self.port_range.end()
            )
        };
        Capability::new(PORT_AVAILABLE_CAP, description)
    }
}

impl DeployerCredentials for LocalProcessCredentials {
    fn requires_credentials_material(&self) -> bool {
        false
    }

    fn required_capabilities(&self) -> Vec<Capability> {
        vec![
            self.fs_writable_capability(),
            self.port_available_capability(None),
        ]
    }

    fn validate(&self, ctx: &ValidationContext<'_>) -> RequirementsReport {
        let fs_status = probe_fs_writable(ctx.env_root);
        let port_status = probe_port_available(self.port_range.clone(), ctx.host_config);
        RequirementsReport::new(vec![
            CapabilityCheck {
                capability: self.fs_writable_capability(),
                status: fs_status,
            },
            CapabilityCheck {
                capability: self.port_available_capability(Some(ctx.host_config)),
                status: port_status,
            },
        ])
    }

    fn bootstrap(&self, _input: &BootstrapInput<'_>) -> Result<BootstrapOutcome, BootstrapError> {
        Err(BootstrapError::NotApplicable(
            "the local-process deployer has no admin escalation path — there are no \
             IAM roles or cluster RBAC to provision locally. Run \
             `gtc op credentials requirements <env>` instead."
                .to_string(),
        ))
    }
}

/// Probe whether the env's state dir is writable by exercising the
/// canonical `crate::environment::atomic_write::atomic_write_bytes`
/// helper (NamedTempFile → flush → sync_all → persist → fsync parent).
/// Catches read-only mounts and filesystems that accept buffered writes
/// but fail on sync or rename — the original tempfile-only probe missed
/// those. Sharing the helper guarantees the probe stays in lock-step
/// with what the store actually does at runtime.
///
/// The probe writes `.local-process-creds-probe` under `env_root`, then
/// deletes it on success. On atomic-write failure the partial file is
/// cleaned up by the helper's NamedTempFile Drop.
///
/// **Limitation:** probes only `env_root` itself. The deployer writes
/// under several subdirs (`runtime-config.json`, `revisions/`,
/// `messaging/`, `env-packs/`, `backups/`); a read-only sub-mount on a
/// child could still fail at startup. Enumerating subdirs is fragile
/// (the list rotates as Phase B/D add artifacts), so this probe covers
/// the parent and documents the gap.
fn probe_fs_writable(env_root: &Path) -> CapabilityStatus {
    if !env_root.exists() {
        return CapabilityStatus::Fail {
            reason: format!(
                "env root `{}` does not exist (run `gtc op env init` first)",
                env_root.display()
            ),
        };
    }
    let probe_target = env_root.join(".local-process-creds-probe");
    match crate::environment::atomic_write::atomic_write_bytes(
        &probe_target,
        b"local-process-creds-probe",
    ) {
        Ok(()) => {
            // Clean up the probe file. A failure to remove is non-fatal —
            // the deployer would tolerate a stray probe file on a
            // writable mount, and the probe has already proven its point.
            let _ = std::fs::remove_file(&probe_target);
            CapabilityStatus::Pass
        }
        Err(e) => CapabilityStatus::Fail {
            reason: format!(
                "atomic write probe at `{}` failed: {e}",
                probe_target.display()
            ),
        },
    }
}

/// Probe whether the deployer can bind a network listener.
///
/// When `host_config.listen_addr` is `Some(addr)`, probes that exact
/// address — the env has an explicit bind target and the handler's port
/// range is irrelevant. When `None`, falls back to the handler-level
/// range on `127.0.0.1`.
///
/// **TOCTOU caveat:** Bind-and-drop is best-effort; the port may be
/// claimed by another process between probe and deployer startup. Treat
/// `Pass` as advisory, not a guarantee.
fn probe_port_available(
    range: RangeInclusive<u16>,
    host_config: &EnvironmentHostConfig,
) -> CapabilityStatus {
    // Explicit listen_addr on the env — probe that exact address.
    if let Some(addr) = host_config.listen_addr {
        return if TcpListener::bind(addr).is_ok() {
            CapabilityStatus::Pass
        } else {
            CapabilityStatus::Fail {
                reason: format!(
                    "configured listen_addr {addr} is not bindable — \
                     another process may be using it"
                ),
            }
        };
    }

    // No explicit listen_addr — fall back to the handler range.
    let start = *range.start();
    let end = *range.end();
    if start > end {
        return CapabilityStatus::Fail {
            reason: format!("invalid port range [{start}-{end}]"),
        };
    }
    for port in range {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if TcpListener::bind(addr).is_ok() {
            return CapabilityStatus::Pass;
        }
    }
    CapabilityStatus::Fail {
        reason: format!(
            "no port in [{}-{}] is bindable on 127.0.0.1 — every port in the range is occupied",
            start, end
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{BootstrapError, ZeroizedAdmin};
    use greentic_deploy_spec::{EnvId, EnvironmentHostConfig};
    use tempfile::tempdir;

    fn default_host_config(env_id: &EnvId) -> EnvironmentHostConfig {
        EnvironmentHostConfig {
            env_id: env_id.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }
    }

    fn ctx<'a>(
        env_root: &'a Path,
        env_id: &'a EnvId,
        host_config: &'a EnvironmentHostConfig,
    ) -> ValidationContext<'a> {
        ValidationContext {
            env_id,
            env_root,
            host_config,
        }
    }

    #[test]
    fn required_capabilities_are_the_documented_two() {
        let creds = LocalProcessCredentials::default();
        let caps: Vec<_> = creds
            .required_capabilities()
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(caps, vec![FS_WRITABLE_CAP, PORT_AVAILABLE_CAP]);
    }

    #[test]
    fn requires_credentials_material_is_false() {
        let creds = LocalProcessCredentials::default();
        assert!(
            !creds.requires_credentials_material(),
            "local-process deployer needs no credential material"
        );
    }

    #[test]
    fn validate_passes_on_writable_dir_with_free_port() {
        // tempdir is writable; pick a range likely to have a free port
        // (very high range; if every port in 49000..=49100 is taken on
        // the test runner we have bigger problems).
        let dir = tempdir().unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        let hc = default_host_config(&env_id);
        let creds = LocalProcessCredentials::with_port_range(49000..=49100);
        let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
        assert!(report.passed(), "report: {report:?}");
        assert!(
            report.missing().is_empty(),
            "no missing caps; got {:?}",
            report.missing()
        );
    }

    #[test]
    fn validate_fails_fs_when_env_root_missing() {
        let env_id = EnvId::try_from("local").unwrap();
        let hc = default_host_config(&env_id);
        let creds = LocalProcessCredentials::default();
        let missing_root = Path::new("/this/path/does/not/exist/for/probing");
        let report = creds.validate(&ctx(missing_root, &env_id, &hc));
        assert!(!report.passed());
        let fs_check = report
            .checks
            .iter()
            .find(|c| c.capability.id == FS_WRITABLE_CAP)
            .unwrap();
        match &fs_check.status {
            CapabilityStatus::Fail { reason } => {
                assert!(reason.contains("does not exist"), "reason: {reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// Bind every port in a tiny range first, then assert the probe
    /// reports Fail for that range. Holds the listeners for the
    /// duration of the probe so the bind contention is real, not
    /// flaky.
    #[test]
    fn validate_fails_port_when_range_is_occupied() {
        // Bind two arbitrary high ports the OS gives us, then ask the
        // probe to scan that exact pair. We must hold the listeners
        // through the probe call; dropping them releases the ports.
        let l1 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let l2 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let p1 = l1.local_addr().unwrap().port();
        let p2 = l2.local_addr().unwrap().port();
        let (lo, hi) = if p1 <= p2 { (p1, p2) } else { (p2, p1) };

        let creds = LocalProcessCredentials::with_port_range(lo..=hi);
        // If `lo..=hi` contains a port other than p1/p2 that happens to
        // be free, the probe legitimately passes — that's not a probe
        // bug, it's the probe doing its job. Only assert Fail when the
        // range is exactly two contiguous ports we hold.
        if hi == lo + 1 {
            let env_id = EnvId::try_from("local").unwrap();
            let hc = default_host_config(&env_id);
            let dir = tempdir().unwrap();
            let report = creds.validate(&ctx(dir.path(), &env_id, &hc));
            let port_check = report
                .checks
                .iter()
                .find(|c| c.capability.id == PORT_AVAILABLE_CAP)
                .unwrap();
            assert!(
                matches!(port_check.status, CapabilityStatus::Fail { .. }),
                "expected Fail (every port in [{lo}-{hi}] is bound), got {:?}",
                port_check.status
            );
        }
        // Hold the listeners until the assertions complete.
        drop(l1);
        drop(l2);
    }

    #[test]
    fn bootstrap_rejects_as_not_applicable() {
        let creds = LocalProcessCredentials::default();
        let env_id = EnvId::try_from("local").unwrap();
        let dir = tempdir().unwrap();
        let admin = ZeroizedAdmin::new("admin", "irrelevant".to_string());
        let input = BootstrapInput {
            env_id: &env_id,
            env_root: dir.path(),
            admin: &admin,
        };
        let err = creds.bootstrap(&input).unwrap_err();
        match err {
            BootstrapError::NotApplicable(msg) => {
                assert!(msg.contains("no admin escalation"), "msg: {msg}");
                assert!(
                    msg.contains("requirements"),
                    "msg should point user at `requirements`: {msg}"
                );
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    #[test]
    fn invalid_port_range_fails_loudly() {
        // RangeInclusive::new(10, 9) is constructible but empty; the
        // probe must report Fail rather than vacuously Pass. Construct
        // via `new` to dodge clippy::reversed_empty_ranges on literal
        // syntax — the lint protects against accidental reversal, but
        // here the reversal is the test subject.
        let range = std::ops::RangeInclusive::new(10u16, 9u16);
        let env_id = EnvId::try_from("local").unwrap();
        let hc = default_host_config(&env_id);
        let status = probe_port_available(range, &hc);
        match status {
            CapabilityStatus::Fail { reason } => {
                assert!(reason.contains("invalid port range"), "reason: {reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// When `host_config.listen_addr` is set, the port probe targets
    /// that exact address instead of scanning the handler range. Binding
    /// the address first makes the probe fail — confirming it respects
    /// the env's configured listen_addr.
    #[test]
    fn probe_port_available_respects_host_config_listen_addr() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let bound_addr = listener.local_addr().unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        let hc = EnvironmentHostConfig {
            env_id: env_id.clone(),
            region: None,
            tenant_org_id: None,
            listen_addr: Some(bound_addr),
            public_base_url: None,
        };
        // With the port occupied and listen_addr pointing at it, probe
        // must report Fail.
        let status = probe_port_available(DEFAULT_PORT_RANGE, &hc);
        match status {
            CapabilityStatus::Fail { reason } => {
                assert!(
                    reason.contains(&bound_addr.to_string()),
                    "reason should mention the configured addr, got: {reason}"
                );
            }
            other => panic!("expected Fail for occupied listen_addr, got {other:?}"),
        }
        // After releasing the port, probe must Pass.
        drop(listener);
        let status = probe_port_available(DEFAULT_PORT_RANGE, &hc);
        assert!(
            matches!(status, CapabilityStatus::Pass),
            "expected Pass after releasing listen_addr, got {status:?}"
        );
    }

    /// The atomic-write probe fails on a read-only directory (Unix
    /// only — uses `chmod 0o555`).
    #[cfg(unix)]
    #[test]
    fn probe_fs_writable_fails_on_read_only_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        // Make the directory read-only.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let status = probe_fs_writable(dir.path());
        // Restore write permission before assertions so the tempdir
        // cleanup doesn't fail.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        match status {
            CapabilityStatus::Fail { reason } => {
                assert!(
                    reason.contains("could not create probe file")
                        || reason.contains("persist")
                        || reason.contains("write probe"),
                    "reason should indicate a write failure, got: {reason}"
                );
            }
            other => panic!("expected Fail on read-only dir, got {other:?}"),
        }
    }
}
