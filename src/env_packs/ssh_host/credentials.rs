//! [`DeployerCredentials`] impl for the ssh-host deployer.
//!
//! ## Credential material: none stored, therefore `requires_credentials_material() == false`
//!
//! The only secret this deployer uses is the operator's SSH private key, and it
//! is referenced BY PATH (`identity_file`) — it is never read into, copied to or
//! minted by the env store. There is no bound credential to bootstrap, rotate or
//! strip from a runtime seed, so this follows `local-process` (no material),
//! not K8s / AWS (a bound token in the dev-store). Consequences:
//! `requirements` does not demand a `credentials_ref`; `bootstrap` is
//! [`BootstrapError::NotApplicable`]; `bound_credential_store_path` is `None`.
//!
//! ## Probes fail closed until a target is bound
//!
//! The checks run real commands on the VM through [`Remote`]. A handler built
//! with no target (the registry default) reports every capability as
//! [`CapabilityStatus::Fail`] — never `Skipped`, which `RequirementsReport::passed`
//! treats as non-blocking and would persist a green result with nothing
//! verified (the K8s precedent). If the host is unreachable the remaining
//! probes fail as "not probed", not as "assumed fine".
//!
//! The CLI binds the target: `op credentials requirements` reads the binding's
//! answers (`answers_ref`) and builds these credentials with
//! [`SshHostCredentials::with_target`] (`cli::ssh_host::connected_credentials`),
//! the K8s `with_client` analogue. Only a binding that records NO answers still
//! reaches the fail-closed default below.

use std::sync::Arc;

use crate::credentials::{
    BootstrapError, BootstrapInput, BootstrapOutcome, Capability, CapabilityCheck,
    CapabilityStatus, DeployerCredentials, RequirementsReport, ValidationContext,
};

use super::params::SshHostParams;
use super::remote::{Remote, RemoteTarget};
use super::tunnel::{TunnelRegistry, connect};

pub const REACHABLE_CAP: &str = "ssh-host.reachable";
pub const ARCH_CAP: &str = "ssh-host.arch";
pub const GLIBC_CAP: &str = "ssh-host.glibc";
pub const SYSTEMD_CAP: &str = "ssh-host.systemd";
pub const INSTALL_DIR_WRITABLE_CAP: &str = "ssh-host.install-dir-writable";
pub const PRIVILEGE_CAP: &str = "ssh-host.privilege";
/// Listed first, and only when the answers configure a tunnel other than `none`.
pub const TUNNEL_CAP: &str = "ssh-host.tunnel";

/// Oldest glibc the greentic-start release binaries run on (they are built on
/// ubuntu-24.04). Debian 12 (2.36) and Ubuntu 22.04 (2.35) are too old; Ubuntu
/// 24.04 (2.39) and Debian 13 (2.41) are fine. Unverified on real Linux.
pub const MIN_GLIBC: (u32, u32) = (2, 39);

/// Architectures greentic-start is published for.
pub const SUPPORTED_ARCHES: &[&str] = &["x86_64", "aarch64"];

/// A reachable VM and the params to probe it with.
#[derive(Debug, Clone)]
struct Binding {
    remote: Arc<dyn Remote>,
    params: SshHostParams,
}

/// Credentials contract for the ssh-host deployer.
#[derive(Debug, Clone, Default)]
pub struct SshHostCredentials {
    binding: Option<Binding>,
    tunnels: Arc<TunnelRegistry>,
}

impl SshHostCredentials {
    /// Bind the VM to probe. Builder-style, like K8s `with_client`.
    pub fn with_target(remote: Arc<dyn Remote>, params: SshHostParams) -> Self {
        Self {
            binding: Some(Binding { remote, params }),
            tunnels: Arc::default(),
        }
    }

    /// Use these tunnel kinds instead of the built-in ones (builder-style).
    pub fn with_tunnels(mut self, tunnels: Arc<TunnelRegistry>) -> Self {
        self.tunnels = tunnels;
        self
    }

    /// Whether the bound answers ask for a tunnel that brings something up.
    fn tunnel_listed(&self) -> bool {
        self.binding
            .as_ref()
            .and_then(|b| b.params.tunnel.as_ref())
            .is_some_and(|t| t.kind != "none")
    }

    fn probe(
        &self,
        binding: &Binding,
        caps: Vec<Capability>,
        target: RemoteTarget,
    ) -> RequirementsReport {
        let params = &binding.params;
        let prober = Prober {
            remote: binding.remote.as_ref(),
            target,
        };

        match prober.succeeds(&["true"]) {
            Ok(true) => {}
            Ok(false) => return all_failed(caps, "the VM accepted the login but `true` failed"),
            Err(e) => {
                let mut checks = Vec::with_capacity(caps.len());
                for (i, capability) in caps.into_iter().enumerate() {
                    let reason = if i == 0 {
                        format!(
                            "cannot reach {}:{} as {}: {e}",
                            params.host, params.port, params.user
                        )
                    } else {
                        "not probed: the VM is unreachable".to_string()
                    };
                    checks.push(CapabilityCheck {
                        capability,
                        status: CapabilityStatus::Fail { reason },
                    });
                }
                return RequirementsReport::new(checks);
            }
        }

        let arch = match prober.run(&["uname", "-m"]) {
            Ok(out) if out.success() => {
                let machine = out.stdout.trim().to_string();
                pass_or(SUPPORTED_ARCHES.contains(&machine.as_str()), || {
                    format!(
                        "unsupported architecture {machine:?}; greentic-start is published for {}",
                        SUPPORTED_ARCHES.join(", ")
                    )
                })
            }
            Ok(out) => CapabilityStatus::Fail {
                reason: format!("`uname -m` exited {}", out.status),
            },
            Err(e) => CapabilityStatus::Fail { reason: e },
        };
        let glibc = probe_glibc(&prober);
        let systemd = match prober.succeeds(&["systemctl", "--version"]) {
            Ok(ok) => pass_or(ok, || {
                "`systemctl --version` failed — the VM does not run systemd".to_string()
            }),
            Err(e) => CapabilityStatus::Fail { reason: e },
        };
        let dir = &params.install_dir;
        let writable = (|| -> Result<bool, String> {
            if prober.succeeds(&["test", "-d", dir])? {
                return prober.succeeds(&["test", "-w", dir]);
            }
            // Not there yet: `mkdir -p` at warm time needs a writable ancestor.
            let mut ancestor = dir.as_str();
            while let Some((parent, _)) = ancestor.rsplit_once('/') {
                let parent = if parent.is_empty() { "/" } else { parent };
                if prober.succeeds(&["test", "-d", parent])? {
                    return prober.succeeds(&["test", "-w", parent]);
                }
                if parent == "/" {
                    break;
                }
                ancestor = parent;
            }
            Ok(false)
        })();
        let install_dir = match writable {
            Ok(ok) => pass_or(ok, || {
                format!(
                    "the login user cannot write {dir} (or its nearest existing parent); create \
                     it once with `sudo install -d -o {} {dir}`",
                    params.user
                )
            }),
            Err(e) => CapabilityStatus::Fail { reason: e },
        };
        let privilege = if params.use_sudo {
            match prober.succeeds(&["sudo", "-n", "true"]) {
                Ok(ok) => pass_or(ok, || {
                    "`sudo -n true` failed — the login user needs passwordless sudo, or set \
                     use_sudo=false and log in as root"
                        .to_string()
                }),
                Err(e) => CapabilityStatus::Fail { reason: e },
            }
        } else {
            match prober.run(&["id", "-u"]) {
                Ok(out) => pass_or(out.success() && out.stdout.trim() == "0", || {
                    "use_sudo is false but the login user is not root".to_string()
                }),
                Err(e) => CapabilityStatus::Fail { reason: e },
            }
        };

        let mut statuses = vec![
            CapabilityStatus::Pass,
            arch,
            glibc,
            systemd,
            install_dir,
            privilege,
        ];
        RequirementsReport::new(
            caps.into_iter()
                .zip(statuses.drain(..))
                .map(|(capability, status)| CapabilityCheck { capability, status })
                .collect(),
        )
    }

    fn capabilities(&self) -> Vec<Capability> {
        let dir = self
            .binding
            .as_ref()
            .map(|b| b.params.install_dir.as_str())
            .unwrap_or("the install directory");
        let mut caps = Vec::new();
        if self.tunnel_listed() {
            caps.push(Capability::new(
                TUNNEL_CAP,
                "The configured tunnel comes up and carries traffic to the VM's SSH port",
            ));
        }
        caps.extend([
            Capability::new(REACHABLE_CAP, "The VM accepts a non-interactive SSH login"),
            Capability::new(
                ARCH_CAP,
                format!(
                    "The VM's CPU architecture is one of {}",
                    SUPPORTED_ARCHES.join(", ")
                ),
            ),
            Capability::new(
                GLIBC_CAP,
                format!(
                    "The VM's glibc is at least {}.{} (the greentic-start release binaries need it)",
                    MIN_GLIBC.0, MIN_GLIBC.1
                ),
            ),
            Capability::new(SYSTEMD_CAP, "The VM runs systemd (`systemctl --version`)"),
            Capability::new(
                INSTALL_DIR_WRITABLE_CAP,
                format!("The login user can write {dir} (or create it)"),
            ),
            Capability::new(
                PRIVILEGE_CAP,
                "The login user can install and control a systemd unit (root, or passwordless sudo)",
            ),
        ]);
        caps
    }
}

fn all_failed(caps: Vec<Capability>, reason: &str) -> RequirementsReport {
    RequirementsReport::new(
        caps.into_iter()
            .map(|capability| CapabilityCheck {
                capability,
                status: CapabilityStatus::Fail {
                    reason: reason.to_string(),
                },
            })
            .collect(),
    )
}

fn pass_or(ok: bool, reason: impl FnOnce() -> String) -> CapabilityStatus {
    if ok {
        CapabilityStatus::Pass
    } else {
        CapabilityStatus::Fail { reason: reason() }
    }
}

struct Prober<'a> {
    remote: &'a dyn Remote,
    target: RemoteTarget,
}

impl Prober<'_> {
    /// `Ok(output)` for a command that ran; `Err(reason)` when the transport
    /// failed.
    fn run(&self, argv: &[&str]) -> Result<super::remote::RemoteOutput, String> {
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        self.remote
            .run(&self.target, &argv)
            .map_err(|e| e.to_string())
    }

    fn succeeds(&self, argv: &[&str]) -> Result<bool, String> {
        self.run(argv).map(|o| o.success())
    }
}

/// Extract `major.minor` from `getconf GNU_LIBC_VERSION` (`glibc 2.39`) or the
/// first line of `ldd --version` (`ldd (Ubuntu GLIBC 2.39-0ubuntu8) 2.39`).
/// A musl `ldd` is recognised and rejected rather than misparsed.
pub(crate) fn parse_glibc_version(text: &str) -> Result<(u32, u32), String> {
    if text.to_ascii_lowercase().contains("musl") {
        return Err("this is a musl system, not glibc".to_string());
    }
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_digit()) {
            let major_end = bytes[i..]
                .iter()
                .position(|b| !b.is_ascii_digit())
                .map_or(bytes.len(), |n| i + n);
            if bytes.get(major_end) == Some(&b'.')
                && bytes.get(major_end + 1).is_some_and(u8::is_ascii_digit)
            {
                let minor_end = bytes[major_end + 1..]
                    .iter()
                    .position(|b| !b.is_ascii_digit())
                    .map_or(bytes.len(), |n| major_end + 1 + n);
                let major = text[i..major_end]
                    .parse::<u32>()
                    .map_err(|e| e.to_string())?;
                let minor = text[major_end + 1..minor_end]
                    .parse::<u32>()
                    .map_err(|e| e.to_string())?;
                return Ok((major, minor));
            }
            i = major_end;
        } else {
            i += 1;
        }
    }
    Err(format!("no version number in {:?}", text.trim()))
}

fn probe_glibc(prober: &Prober<'_>) -> CapabilityStatus {
    let need = format!("{}.{}", MIN_GLIBC.0, MIN_GLIBC.1);
    let mut detail = String::new();
    for argv in [
        &["getconf", "GNU_LIBC_VERSION"][..],
        &["ldd", "--version"][..],
    ] {
        match prober.run(argv) {
            Ok(out) if out.success() => {
                return match parse_glibc_version(out.stdout.lines().next().unwrap_or_default()) {
                    Ok(v) if v >= MIN_GLIBC => CapabilityStatus::Pass,
                    Ok((major, minor)) => CapabilityStatus::Fail {
                        reason: format!(
                            "glibc {major}.{minor} is older than {need}: the greentic-start \
                             release binaries will not run here (Debian 12 and Ubuntu 22.04 are \
                             too old; use Ubuntu 24.04 or Debian 13, or copy a binary built for \
                             this host with `start_binary`)"
                        ),
                    },
                    Err(e) => CapabilityStatus::Fail {
                        reason: format!(
                            "cannot establish a glibc >= {need}: {e}; the release binaries need it"
                        ),
                    },
                };
            }
            Ok(out) => detail = format!("`{}` exited {}", argv.join(" "), out.status),
            Err(e) => return CapabilityStatus::Fail { reason: e },
        }
    }
    CapabilityStatus::Fail {
        reason: format!("cannot read the glibc version ({detail}); glibc >= {need} is required"),
    }
}

impl DeployerCredentials for SshHostCredentials {
    fn requires_credentials_material(&self) -> bool {
        false
    }

    fn required_capabilities(&self) -> Vec<Capability> {
        self.capabilities()
    }

    fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
        let mut caps = self.capabilities();
        let Some(binding) = &self.binding else {
            return all_failed(
                caps,
                "no SSH target is bound to these credentials: the ssh-host binding records no \
                 answers (`answers_ref` with at least `host` and `user`) — failing closed",
            );
        };
        if !self.tunnel_listed() {
            return self.probe(binding, caps, RemoteTarget::from(&binding.params));
        }
        // The tunnel is brought up ONCE for all the probes below, and torn down
        // when `_guard` drops at the end of this function.
        let tunnel_cap = caps.remove(0);
        match connect(&binding.params, &self.tunnels) {
            Ok((target, _guard)) => {
                let mut checks = vec![CapabilityCheck {
                    capability: tunnel_cap,
                    status: CapabilityStatus::Pass,
                }];
                checks.extend(self.probe(binding, caps, target).checks);
                RequirementsReport::new(checks)
            }
            Err(e) => {
                let mut checks = vec![CapabilityCheck {
                    capability: tunnel_cap,
                    status: CapabilityStatus::Fail {
                        reason: e.to_string(),
                    },
                }];
                checks.extend(caps.into_iter().map(|capability| CapabilityCheck {
                    capability,
                    status: CapabilityStatus::Fail {
                        reason: "not probed: the tunnel is not up".to_string(),
                    },
                }));
                RequirementsReport::new(checks)
            }
        }
    }

    fn bootstrap(&self, _input: &BootstrapInput<'_>) -> Result<BootstrapOutcome, BootstrapError> {
        Err(BootstrapError::NotApplicable(
            "the ssh-host deployer mints no credential: it uses the SSH key you reference with \
             the `identity_file` answer, and never stores it. Provision the login user and the \
             install directory on the VM yourself, then run \
             `gtc op credentials requirements <env>`."
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use greentic_deploy_spec::EnvironmentHostConfig;
    use serde_json::json;

    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::ssh_host::fake::FakeRemote;
    use crate::env_packs::ssh_host::remote::RemoteOutput;

    fn params(extra: serde_json::Value) -> SshHostParams {
        let mut answers = json!({"host": "vm.example.com", "user": "greentic"});
        for (k, v) in extra.as_object().unwrap() {
            answers[k] = v.clone();
        }
        SshHostParams::from_answers(&build_fixture_env(), &answers).unwrap()
    }

    fn validate(creds: &SshHostCredentials) -> RequirementsReport {
        let env = build_fixture_env();
        let hc = EnvironmentHostConfig::new(env.environment_id.clone());
        let dir = tempfile::tempdir().unwrap();
        creds.validate(&ValidationContext {
            env_id: &env.environment_id,
            env_root: dir.path(),
            host_config: &hc,
        })
    }

    fn status<'a>(report: &'a RequirementsReport, id: &str) -> &'a CapabilityStatus {
        &report
            .checks
            .iter()
            .find(|c| c.capability.id == id)
            .unwrap_or_else(|| panic!("no check {id}"))
            .status
    }

    #[test]
    fn declares_no_credential_material_and_six_capabilities() {
        let creds = SshHostCredentials::default();
        assert!(!creds.requires_credentials_material());
        assert!(creds.bound_credential_store_path().is_none());
        let ids: Vec<String> = creds
            .required_capabilities()
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(
            ids,
            [
                REACHABLE_CAP,
                ARCH_CAP,
                GLIBC_CAP,
                SYSTEMD_CAP,
                INSTALL_DIR_WRITABLE_CAP,
                PRIVILEGE_CAP
            ]
        );
    }

    #[test]
    fn unbound_fails_every_capability_closed() {
        let report = validate(&SshHostCredentials::default());
        assert!(!report.passed());
        assert_eq!(report.missing().len(), 6);
        for check in &report.checks {
            match &check.status {
                CapabilityStatus::Fail { reason } => {
                    assert!(reason.contains("no SSH target is bound"), "{reason}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_healthy_vm_passes_every_probe() {
        let remote = Arc::new(FakeRemote::default());
        let creds = SshHostCredentials::with_target(remote, params(json!({})));
        let report = validate(&creds);
        assert!(report.passed(), "{report:?}");
        assert!(report.missing().is_empty(), "{report:?}");
    }

    #[test]
    fn an_unreachable_vm_fails_all_and_names_the_target() {
        let remote = Arc::new(FakeRemote {
            unreachable: true,
            ..FakeRemote::default()
        });
        let creds = SshHostCredentials::with_target(remote, params(json!({})));
        let report = validate(&creds);
        assert!(!report.passed());
        assert_eq!(report.missing().len(), 6);
        match status(&report, REACHABLE_CAP) {
            CapabilityStatus::Fail { reason } => {
                assert!(reason.contains("vm.example.com"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
        match status(&report, ARCH_CAP) {
            CapabilityStatus::Fail { reason } => assert!(reason.contains("not probed"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unsupported_architecture_fails_only_the_arch_probe() {
        let remote = Arc::new(FakeRemote {
            arch: "riscv64".into(),
            ..FakeRemote::default()
        });
        let report = validate(&SshHostCredentials::with_target(remote, params(json!({}))));
        assert!(
            matches!(status(&report, ARCH_CAP), CapabilityStatus::Fail { reason } if reason.contains("riscv64"))
        );
        assert_eq!(report.missing(), vec![ARCH_CAP.to_string()]);
    }

    #[test]
    fn parses_glibc_versions_from_getconf_and_ldd() {
        assert_eq!(parse_glibc_version("glibc 2.39"), Ok((2, 39)));
        assert_eq!(parse_glibc_version("glibc 2.36\n"), Ok((2, 36)));
        assert_eq!(
            parse_glibc_version("ldd (Ubuntu GLIBC 2.39-0ubuntu8) 2.39"),
            Ok((2, 39))
        );
        assert_eq!(
            parse_glibc_version("ldd (Debian GLIBC 2.41-12) 2.41"),
            Ok((2, 41))
        );
        assert!(parse_glibc_version("musl libc (x86_64)\nVersion 1.2.4").is_err());
        assert!(parse_glibc_version("garbage").is_err());
        assert!(parse_glibc_version("").is_err());
    }

    #[test]
    fn glibc_older_than_2_39_fails_with_the_distro_hint() {
        for old in ["2.36", "2.35", "2.38"] {
            let remote = Arc::new(FakeRemote {
                glibc: old.into(),
                ..FakeRemote::default()
            });
            let report = validate(&SshHostCredentials::with_target(remote, params(json!({}))));
            assert_eq!(report.missing(), vec![GLIBC_CAP.to_string()], "{old}");
            match status(&report, GLIBC_CAP) {
                CapabilityStatus::Fail { reason } => {
                    assert!(reason.contains(old) && reason.contains("2.39"), "{reason}");
                    assert!(
                        reason.contains("Debian 12") && reason.contains("Ubuntu 22.04"),
                        "{reason}"
                    );
                }
                other => panic!("{other:?}"),
            }
        }
        for ok in ["2.39", "2.40", "2.41", "3.0"] {
            let remote = Arc::new(FakeRemote {
                glibc: ok.into(),
                ..FakeRemote::default()
            });
            assert!(
                validate(&SshHostCredentials::with_target(remote, params(json!({})))).passed(),
                "{ok}"
            );
        }
    }

    #[test]
    fn glibc_falls_back_to_ldd_and_fails_closed_when_neither_answers() {
        let remote = Arc::new(FakeRemote::default());
        remote.fail_command("getconf", RemoteOutput::failed(127, "not found"));
        let report = validate(&SshHostCredentials::with_target(
            remote.clone(),
            params(json!({})),
        ));
        assert!(report.passed(), "ldd fallback: {report:?}");

        remote.fail_command("ldd", RemoteOutput::failed(127, "not found"));
        let report = validate(&SshHostCredentials::with_target(remote, params(json!({}))));
        assert_eq!(report.missing(), vec![GLIBC_CAP.to_string()]);
    }

    #[test]
    fn no_systemd_fails_the_systemd_probe() {
        let remote = Arc::new(FakeRemote {
            systemd_present: false,
            ..FakeRemote::default()
        });
        let report = validate(&SshHostCredentials::with_target(remote, params(json!({}))));
        assert_eq!(report.missing(), vec![SYSTEMD_CAP.to_string()]);
    }

    #[test]
    fn a_missing_install_dir_passes_when_its_parent_is_writable_and_fails_otherwise() {
        let remote = Arc::new(FakeRemote::default());
        // The fake's login user owns `/opt/greentic` and nothing else.
        let creds = SshHostCredentials::with_target(
            remote.clone(),
            params(json!({"install_dir": "/opt/greentic/sub/dir"})),
        );
        assert!(
            validate(&creds).passed(),
            "ancestor /opt/greentic is writable"
        );

        let creds = SshHostCredentials::with_target(
            remote,
            params(json!({"install_dir": "/srv/greentic"})),
        );
        let report = validate(&creds);
        assert_eq!(report.missing(), vec![INSTALL_DIR_WRITABLE_CAP.to_string()]);
    }

    #[test]
    fn missing_passwordless_sudo_fails_the_privilege_probe() {
        let remote = Arc::new(FakeRemote {
            sudo_works: false,
            ..FakeRemote::default()
        });
        let report = validate(&SshHostCredentials::with_target(remote, params(json!({}))));
        assert_eq!(report.missing(), vec![PRIVILEGE_CAP.to_string()]);
    }

    #[test]
    fn use_sudo_false_requires_a_root_login() {
        let non_root = Arc::new(FakeRemote::default());
        let report = validate(&SshHostCredentials::with_target(
            non_root,
            params(json!({"use_sudo": false})),
        ));
        assert_eq!(report.missing(), vec![PRIVILEGE_CAP.to_string()]);

        let root = Arc::new(FakeRemote {
            is_root: true,
            ..FakeRemote::default()
        });
        let report = validate(&SshHostCredentials::with_target(
            root,
            params(json!({"user": "root", "use_sudo": false})),
        ));
        assert!(report.passed(), "{report:?}");
    }

    #[test]
    fn a_failing_true_is_not_treated_as_reachable() {
        let remote = Arc::new(FakeRemote::default());
        remote.fail_command("true", RemoteOutput::failed(1, "weird shell"));
        let report = validate(&SshHostCredentials::with_target(remote, params(json!({}))));
        assert!(!report.passed());
        assert_eq!(report.missing().len(), 6);
    }

    #[test]
    fn bootstrap_is_not_applicable() {
        use crate::credentials::ZeroizedAdmin;
        let env_id = greentic_deploy_spec::EnvId::try_from("e").unwrap();
        let admin = ZeroizedAdmin::new("profile", "material".to_string());
        let dir = tempfile::tempdir().unwrap();
        let creds = SshHostCredentials::default();
        let err = creds
            .bootstrap(&BootstrapInput {
                env_id: &env_id,
                env_root: dir.path(),
                admin: &admin,
            })
            .unwrap_err();
        assert!(matches!(err, BootstrapError::NotApplicable(_)), "{err:?}");
    }
}
