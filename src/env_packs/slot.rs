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
}

/// The five built-in handlers backing the default `local` environment.
///
/// The `(slot, descriptor_path)` pairs mirror [`crate::defaults::LOCAL_DEFAULT_BINDINGS`]
/// (a test asserts they stay in lock-step); the registry registers each one
/// under its `descriptor_path`.
pub const BUILTIN_HANDLERS: &[BuiltinHandler] = &[
    BuiltinHandler {
        slot: CapabilitySlot::Deployer,
        descriptor_path: "greentic.deployer.local-process",
        version_req: "^0.1.0",
    },
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
        // The registry's built-in set must stay in lock-step with the
        // bootstrap `local` bindings: same slots, same descriptor paths.
        let mut handlers: Vec<(CapabilitySlot, &str)> = BUILTIN_HANDLERS
            .iter()
            .map(|h| (h.slot, h.descriptor_path))
            .collect();
        handlers.sort_by_key(|(_, path)| *path);

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

        let defaults_refs: Vec<(CapabilitySlot, &str)> =
            defaults.iter().map(|(s, p)| (*s, p.as_str())).collect();
        assert_eq!(handlers, defaults_refs);
    }

    #[test]
    fn builtin_version_reqs_accept_their_default_binding_version() {
        // Every built-in's VersionReq must parse and must accept the version
        // the bootstrap `local` binding pins — otherwise `doctor` would flag
        // the defaults we ship as version-skewed.
        for (slot, descriptor) in crate::defaults::LOCAL_DEFAULT_BINDINGS {
            let pd = PackDescriptor::try_new(*descriptor).expect("default descriptor parses");
            let handler = BUILTIN_HANDLERS
                .iter()
                .find(|h| h.descriptor_path() == pd.path())
                .unwrap_or_else(|| panic!("no built-in handler for {slot}"));
            let req = handler.supported_versions();
            assert!(
                req.matches(&pd.version().0),
                "{descriptor}: req {req} rejects its own default version"
            );
        }
    }
}
