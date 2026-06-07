//! Env-pack handler abstraction (`A9`).
//!
//! An [`EnvPackHandler`] is the native counterpart of a [`PackDescriptor`] bound
//! to a [`CapabilitySlot`]: it declares which slot and which descriptor versions
//! it serves. Phase A handlers are **metadata-only** — the slot-specific
//! behavior (deploy, read a secret, emit a span) lands in Phase D. The trait is
//! the seam Phase D plug-ins implement when they register through
//! [`EnvPackRegistry::register`](super::registry::EnvPackRegistry::register).
//!
//! The built-in set ([`BUILTIN_HANDLERS`]) covers the five default `local`
//! bindings. The registry locates a handler by its version-independent
//! [`descriptor_path`](EnvPackHandler::descriptor_path), then validates the
//! requested `@<semver>` against the handler's
//! [`supported_versions`](EnvPackHandler::supported_versions) requirement, so a
//! binding can't pin a version the native handler does not implement.

use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;

use crate::tool_check::ToolCheck;

/// Native handler bound to one [`CapabilitySlot`].
///
/// Object-safe so the registry can hold `Box<dyn EnvPackHandler>` and Phase D
/// plug-ins can register their own implementations.
pub trait EnvPackHandler: std::fmt::Debug + Send + Sync {
    /// The capability slot this handler serves.
    fn slot(&self) -> CapabilitySlot;

    /// Version-independent descriptor path (e.g. `greentic.deployer.local-process`).
    /// This is the registry key — `kind@<semver>` resolves on the path alone.
    fn descriptor_path(&self) -> &str;

    /// Descriptor versions this native handler implements.
    ///
    /// A binding's `kind@<semver>` is rejected when its version does not match
    /// this requirement, so an operator cannot pin a version the binary does
    /// not support and discover the skew only at deploy time. Returning a
    /// [`VersionReq`] (not a string) makes an unparseable requirement
    /// unrepresentable.
    fn supported_versions(&self) -> VersionReq;

    /// Preflight checks the handler needs to pass before it can do real work.
    /// Returns the list of [`ToolCheck`] results — handlers compose the
    /// primitives + named-tool catalog in [`crate::tool_check`].
    ///
    /// The default returns an empty vec, which is the honest answer for the
    /// in-process built-ins (`local-process`, `dev-store`, `stdout`,
    /// `in-memory`): they need no external tools. Handlers that shell out
    /// (K8s, cloud) override this to compose the named-tool checks.
    fn preflight(&self) -> Vec<ToolCheck> {
        Vec::new()
    }

    /// Deployer-only: credentials contract (C1).
    ///
    /// Returns `Some(_)` only on `Deployer`-slot handlers that ship a
    /// [`DeployerCredentials`](crate::credentials::DeployerCredentials)
    /// impl (C2 reference: local-process; Phase D adds AWS / K8s / etc.).
    /// `None` for non-deployer handlers AND for deployer handlers that
    /// haven't registered a credentials contract yet — the latter surface
    /// as `HandlerNotRegistered` through the requirements/bootstrap CLI
    /// flows, so deployer authors are nudged to ship one rather than
    /// silently producing pass-through credential operations.
    fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
        None
    }
}

/// A built-in, metadata-only handler. One value per default `local` binding.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinHandler {
    slot: CapabilitySlot,
    descriptor_path: &'static str,
    /// Validity is guarded by a unit test, so the parse in `supported_versions`
    /// is infallible.
    version_req: &'static str,
}

impl EnvPackHandler for BuiltinHandler {
    fn slot(&self) -> CapabilitySlot {
        self.slot
    }
    fn descriptor_path(&self) -> &str {
        self.descriptor_path
    }
    fn supported_versions(&self) -> VersionReq {
        self.version_req
            .parse()
            .expect("built-in version-req is valid (guarded by tests)")
    }

    fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
        if self.slot == CapabilitySlot::Deployer {
            Some(&BuiltinLocalProcessCredentials)
        } else {
            None
        }
    }
}

/// Stub credentials for the built-in local-process deployer (C1 contract
/// registration gate). This is the C1-layer contract; C2's
/// `LocalProcessCredentials` may override with richer probes. The stub
/// declares `requires_credentials_material() = false` because the
/// local-process deployer has no IAM roles or cloud credentials to manage.
#[derive(Debug)]
struct BuiltinLocalProcessCredentials;

impl crate::credentials::DeployerCredentials for BuiltinLocalProcessCredentials {
    fn requires_credentials_material(&self) -> bool {
        false
    }

    fn required_capabilities(&self) -> Vec<crate::credentials::Capability> {
        Vec::new()
    }

    fn validate(
        &self,
        _ctx: &crate::credentials::ValidationContext<'_>,
    ) -> crate::credentials::RequirementsReport {
        crate::credentials::RequirementsReport::new(Vec::new())
    }

    fn bootstrap(
        &self,
        _input: &crate::credentials::BootstrapInput<'_>,
    ) -> Result<crate::credentials::BootstrapOutcome, crate::credentials::BootstrapError> {
        Err(crate::credentials::BootstrapError::NotApplicable(
            "local-process deployer has no admin escalation path \
             — use `op credentials requirements` instead"
                .to_string(),
        ))
    }
}

/// Metadata-only built-in handlers backing the default `local` environment.
///
/// Four entries (Secrets / Telemetry / Sessions / State) — the Deployer
/// slot's handler ships behavior (C2's
/// [`LocalProcessDeployerHandler`](super::local_process::LocalProcessDeployerHandler))
/// and is registered separately in
/// [`EnvPackRegistry::with_builtins`](super::registry::EnvPackRegistry::with_builtins).
///
/// The combined `(slot, descriptor_path)` set across `BUILTIN_HANDLERS` plus
/// the local-process deployer mirrors [`crate::defaults::LOCAL_DEFAULT_BINDINGS`]
/// (a test asserts they stay in lock-step).
pub const BUILTIN_HANDLERS: &[BuiltinHandler] = &[
    BuiltinHandler {
        slot: CapabilitySlot::Secrets,
        descriptor_path: "greentic.secrets.dev-store",
        version_req: "^0.1.0",
    },
    BuiltinHandler {
        slot: CapabilitySlot::Telemetry,
        descriptor_path: "greentic.telemetry.stdout",
        version_req: "^0.1.0",
    },
    BuiltinHandler {
        slot: CapabilitySlot::Sessions,
        descriptor_path: "greentic.sessions.in-memory",
        version_req: "^0.1.0",
    },
    BuiltinHandler {
        slot: CapabilitySlot::State,
        descriptor_path: "greentic.state.in-memory",
        version_req: "^0.1.0",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::PackDescriptor;

    #[test]
    fn builtin_table_matches_default_bindings() {
        // The registry's built-in set across BUILTIN_HANDLERS and the
        // C2 LocalProcessDeployerHandler must stay in lock-step with the
        // bootstrap `local` bindings: same slots, same descriptor paths.
        use crate::env_packs::local_process::LocalProcessDeployerHandler;
        let mut handlers: Vec<(CapabilitySlot, String)> = BUILTIN_HANDLERS
            .iter()
            .map(|h| (h.slot, h.descriptor_path.to_string()))
            .collect();
        // Compose the C2 deployer handler — its slot+path participates in
        // the same lock-step contract even though it lives outside
        // BUILTIN_HANDLERS (it ships behavior, not just metadata).
        let lpdh = LocalProcessDeployerHandler::default();
        handlers.push((lpdh.slot(), lpdh.descriptor_path().to_string()));
        handlers.sort_by(|a, b| a.1.cmp(&b.1));

        let mut defaults: Vec<(CapabilitySlot, String)> = crate::defaults::LOCAL_DEFAULT_BINDINGS
            .iter()
            .map(|(slot, descriptor)| {
                let path = PackDescriptor::try_new(*descriptor)
                    .expect("default descriptor parses")
                    .path()
                    .to_string();
                (*slot, path)
            })
            .collect();
        defaults.sort_by(|a, b| a.1.cmp(&b.1));

        assert_eq!(handlers, defaults);
    }

    #[test]
    fn builtin_version_reqs_accept_their_default_binding_version() {
        // Every built-in's VersionReq must parse and must accept the version
        // the bootstrap `local` binding pins — otherwise `doctor` would flag
        // the defaults we ship as version-skewed. Composes BUILTIN_HANDLERS
        // and the C2 LocalProcessDeployerHandler the same way
        // `with_builtins()` registers them.
        use crate::env_packs::local_process::LocalProcessDeployerHandler;
        let lpdh = LocalProcessDeployerHandler::default();
        for (slot, descriptor) in crate::defaults::LOCAL_DEFAULT_BINDINGS {
            let pd = PackDescriptor::try_new(*descriptor).expect("default descriptor parses");
            let req = BUILTIN_HANDLERS
                .iter()
                .find(|h| h.descriptor_path() == pd.path())
                .map(|h| h.supported_versions())
                .or_else(|| {
                    if lpdh.descriptor_path() == pd.path() {
                        Some(lpdh.supported_versions())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("no built-in handler for {slot}"));
            assert!(
                req.matches(&pd.version().0),
                "{descriptor}: req {req} rejects its own default version"
            );
        }
    }
}
