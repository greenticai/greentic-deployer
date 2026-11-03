//! SSH-host deployer env-pack: deploy greentic-start to a plain Linux VM over SSH.
//!
//! Backs `greentic.deployer.ssh-host@0.1.0`. Opt-in per env (bind it with
//! `op env-packs add`); it is NOT part of the default `local` bindings.
//!
//! greentic-start does not run a single bundle file: it reads the env store
//! (`greentic-start start --store-root <dir> --env <env_id>`). Deploying to a VM
//! is therefore *synchronize the store, then (re)start a systemd service*. All
//! SSH traffic goes through the [`Remote`] seam so the whole deployer is tested
//! without a network.
//!
//! Module map — details and invariants in `docs/ssh-host-internals.md`:
//!
//! - [`params`] — strict parsing/validation of the binding's answers.
//! - [`remote`] — the [`Remote`] trait and the `ssh`-binary transport
//!   [`SystemSsh`].
//! - [`render`] — pure: the systemd unit.
//! - [`snapshot`] — the filtered store archive shipped to the VM.
//! - [`steps`] — the idempotent warm / drain procedure.
//! - [`deployer`] — `impl Deployer`, passes `run_conformance`.
//! - [`credentials`] — `impl DeployerCredentials` (VM capability probes).

pub mod credentials;
pub mod deployer;
#[cfg(test)]
pub(crate) mod fake;
pub mod params;
pub mod remote;
pub mod render;
pub mod snapshot;
mod steps;

use std::path::PathBuf;
use std::sync::Arc;

use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;
use sha2::{Digest, Sha256};

use super::slot::EnvPackHandler;
use crate::tool_check::{ToolCheck, check_binary_present};

pub use credentials::SshHostCredentials;
pub use params::SshHostParams;
pub use remote::{Remote, RemoteError, RemoteOutput, RemoteTarget, SystemSsh};

/// Name of the content marker inside the store (see [`render::StoreArchive`]).
pub(crate) const STORE_MARKER_FILE: &str = ".greentic-store.sha256";
/// The runtime-written signing key at the store root; carried across store
/// changes, never shipped from the local machine.
pub(crate) const RUNTIME_KEY_FILE: &str = "revision-signing.key";
/// The two directories the store snapshot alternates between; `store` is a
/// symlink to the active one.
pub(crate) const STORE_SLOTS: [&str; 2] = ["store-a", "store-b"];

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// What one warm did, for operator output (`op env up`). `warm_revision` itself
/// reports only the [`WarmOutcome`](crate::env_packs::deployer::WarmOutcome)
/// every deployer shares; this is the ssh-host-specific superset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmReport {
    /// `http://<host>:<listen_port>` only when the service is exposed.
    pub endpoint_url: Option<String>,
    pub service_name: String,
    /// The address greentic-start binds on the VM, e.g. `127.0.0.1:8080`.
    pub listen_addr: String,
    pub install_dir: String,
    /// Whether the binary, the store or the unit changed (and the service was
    /// restarted). `false` means the VM was already converged.
    pub changed: bool,
    /// `store-a` / `store-b`: which store slot is live after the warm.
    /// `None` when it could not be read back.
    pub active_slot: Option<String>,
}

/// Native handler for the ssh-host deployer env-pack.
#[derive(Debug)]
pub struct SshHostDeployerHandler {
    creds: SshHostCredentials,
    /// Transport. [`SystemSsh`] by default; tests inject a fake.
    pub(crate) remote: Arc<dyn Remote>,
    /// Params used when a verb receives no answers. `None` in production: an SSH
    /// target cannot be defaulted, so the verb refuses. Tests (and the
    /// conformance bench, which passes `None`) inject one.
    pub(crate) fallback_params: Option<SshHostParams>,
    /// The local store ROOT (what `--store-root` points at); the snapshot is
    /// `<store_root>/<env_id>/`. Injected by the caller — a `Deployer` verb is
    /// not handed the store. `None` makes `warm_revision` refuse.
    pub(crate) store_root: Option<PathBuf>,
    /// The env's encrypted dev-store, to ship in the snapshot. Must be the
    /// FILTERED bytes (`cli::env::read_dev_secrets_bytes`), exactly as the Cloud
    /// Run lane injects them; `None` ships no dev-store at all.
    pub(crate) dev_secrets: Option<Vec<u8>>,
}

impl Default for SshHostDeployerHandler {
    fn default() -> Self {
        Self {
            creds: SshHostCredentials::default(),
            remote: Arc::new(SystemSsh::new()),
            fallback_params: None,
            store_root: None,
            dev_secrets: None,
        }
    }
}

impl SshHostDeployerHandler {
    /// Version-independent descriptor path used as the registry key.
    pub const DESCRIPTOR_PATH: &'static str = "greentic.deployer.ssh-host";

    /// Descriptor versions this handler implements.
    pub const VERSION_REQ: &'static str = "^0.1.0";

    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an injected transport and fallback params — the seam the
    /// tests and the conformance bench use. The same params are also bound to
    /// the credentials probes.
    pub fn with_remote(remote: Arc<dyn Remote>, fallback_params: Option<SshHostParams>) -> Self {
        let creds = match &fallback_params {
            Some(params) => SshHostCredentials::with_target(Arc::clone(&remote), params.clone()),
            None => SshHostCredentials::default(),
        };
        Self {
            creds,
            remote,
            fallback_params,
            store_root: None,
            dev_secrets: None,
        }
    }

    /// Bind the local store to synchronize and the filtered dev-store bytes to
    /// ship with it (builder-style). See [`snapshot`] for what is shipped.
    pub fn with_local_store(mut self, store_root: PathBuf, dev_secrets: Option<Vec<u8>>) -> Self {
        self.store_root = Some(store_root);
        self.dev_secrets = dev_secrets;
        self
    }
}

impl EnvPackHandler for SshHostDeployerHandler {
    fn slot(&self) -> CapabilitySlot {
        CapabilitySlot::Deployer
    }

    fn descriptor_path(&self) -> &str {
        Self::DESCRIPTOR_PATH
    }

    fn supported_versions(&self) -> VersionReq {
        Self::VERSION_REQ
            .parse()
            .expect("ssh-host version-req is valid (guarded by tests)")
    }

    fn preflight(&self) -> Vec<ToolCheck> {
        vec![check_binary_present(
            "ssh",
            "ssh",
            &["-V"],
            "Install an OpenSSH client (`ssh`) on the machine running the deployer.",
        )]
    }

    fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
        Some(&self.creds)
    }

    fn wizard_qaspec_yaml(&self) -> Option<&'static str> {
        Some(include_str!("wizard.qaspec.yaml"))
    }

    fn as_deployer(&self) -> Option<&dyn crate::env_packs::deployer::Deployer> {
        Some(self)
    }
}

#[cfg(test)]
mod tests;
