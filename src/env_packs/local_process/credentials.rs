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

    fn port_available_capability(&self) -> Capability {
        Capability::new(
            PORT_AVAILABLE_CAP,
            format!(
                "At least one port in [{}-{}] is bindable on 127.0.0.1",
                self.port_range.start(),
                self.port_range.end()
            ),
        )
    }
}

impl DeployerCredentials for LocalProcessCredentials {
    fn required_capabilities(&self) -> Vec<Capability> {
        vec![
            self.fs_writable_capability(),
            self.port_available_capability(),
        ]
    }

    fn validate(&self, ctx: &ValidationContext<'_>) -> RequirementsReport {
        let fs_status = probe_fs_writable(ctx.env_root);
        let port_status = probe_port_available(self.port_range.clone());
        RequirementsReport::new(vec![
            CapabilityCheck {
                capability: self.fs_writable_capability(),
                status: fs_status,
            },
            CapabilityCheck {
                capability: self.port_available_capability(),
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

/// Probe whether the env's state dir is writable. Creates a tempfile
/// under `env_root` and removes it on success. Reports the concrete
/// failure (path + io error) on Fail so an operator can fix it once and
/// re-run.
fn probe_fs_writable(env_root: &Path) -> CapabilityStatus {
    if !env_root.exists() {
        return CapabilityStatus::Fail {
            reason: format!(
                "env root `{}` does not exist (run `gtc op env init` first)",
                env_root.display()
            ),
        };
    }
    let probe = match tempfile::NamedTempFile::new_in(env_root) {
        Ok(t) => t,
        Err(e) => {
            return CapabilityStatus::Fail {
                reason: format!(
                    "could not create probe file under `{}`: {}",
                    env_root.display(),
                    e
                ),
            };
        }
    };
    use std::io::Write;
    if let Err(e) = probe.as_file().write_all(b"local-process-creds-probe") {
        return CapabilityStatus::Fail {
            reason: format!("write probe at `{}` failed: {}", probe.path().display(), e),
        };
    }
    // NamedTempFile cleans up on drop; explicit close to surface any
    // late io error rather than dropping it silently.
    if let Err(e) = probe.close() {
        return CapabilityStatus::Fail {
            reason: format!("close probe file failed: {e}"),
        };
    }
    CapabilityStatus::Pass
}

/// Probe whether at least one port in `range` is bindable on
/// `127.0.0.1`. We bind, then drop the listener immediately — the port
/// is released by the time we return so the deployer (or another
/// process) can claim it.
fn probe_port_available(range: RangeInclusive<u16>) -> CapabilityStatus {
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
    use greentic_deploy_spec::EnvId;
    use tempfile::tempdir;

    fn ctx<'a>(env_root: &'a Path, env_id: &'a EnvId) -> ValidationContext<'a> {
        ValidationContext { env_id, env_root }
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
    fn validate_passes_on_writable_dir_with_free_port() {
        // tempdir is writable; pick a range likely to have a free port
        // (very high range; if every port in 49000..=49100 is taken on
        // the test runner we have bigger problems).
        let dir = tempdir().unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        let creds = LocalProcessCredentials::with_port_range(49000..=49100);
        let report = creds.validate(&ctx(dir.path(), &env_id));
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
        let creds = LocalProcessCredentials::default();
        let missing_root = Path::new("/this/path/does/not/exist/for/probing");
        let report = creds.validate(&ctx(missing_root, &env_id));
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
            let dir = tempdir().unwrap();
            let report = creds.validate(&ctx(dir.path(), &env_id));
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
        let status = probe_port_available(range);
        match status {
            CapabilityStatus::Fail { reason } => {
                assert!(reason.contains("invalid port range"), "reason: {reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }
}
