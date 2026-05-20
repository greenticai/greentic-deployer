//! Env-pack handler abstraction (`A9`).
//!
//! An [`EnvPackHandler`] is the native counterpart of a [`PackDescriptor`] bound
//! to a [`CapabilitySlot`]: it declares which slot it serves and carries the
//! metadata callers need to describe the binding. Phase A handlers are
//! **metadata-only** — the slot-specific behavior (deploy, read a secret, emit a
//! span) lands in Phase D. The trait is the seam Phase D plug-ins implement when
//! they register through [`EnvPackRegistry::register`](super::registry::EnvPackRegistry::register).
//!
//! The built-in set ([`BUILTIN_HANDLERS`]) covers the five default `local`
//! bindings. The registry keys handlers by their version-independent
//! [`descriptor_path`](EnvPackHandler::descriptor_path), so any `@<semver>` of a
//! built-in resolves to the same handler.

use greentic_deploy_spec::CapabilitySlot;
use serde::{Deserialize, Serialize};

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

    /// Human-friendly handler name for CLI/telemetry output.
    fn label(&self) -> &str;

    /// One-line description of what this handler provides.
    fn summary(&self) -> &str;

    /// Serializable snapshot of this handler's identity.
    fn describe(&self) -> HandlerInfo {
        HandlerInfo {
            slot: self.slot(),
            descriptor_path: self.descriptor_path().to_string(),
            label: self.label().to_string(),
            summary: self.summary().to_string(),
            builtin: true,
        }
    }
}

/// Serializable handler metadata, surfaced in CLI envelopes and `doctor` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerInfo {
    pub slot: CapabilitySlot,
    pub descriptor_path: String,
    pub label: String,
    pub summary: String,
    pub builtin: bool,
}

/// A built-in, metadata-only handler. One value per default `local` binding.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinHandler {
    slot: CapabilitySlot,
    descriptor_path: &'static str,
    label: &'static str,
    summary: &'static str,
}

impl EnvPackHandler for BuiltinHandler {
    fn slot(&self) -> CapabilitySlot {
        self.slot
    }
    fn descriptor_path(&self) -> &str {
        self.descriptor_path
    }
    fn label(&self) -> &str {
        self.label
    }
    fn summary(&self) -> &str {
        self.summary
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
        label: "Local process deployer",
        summary: "Runs bundles as local child processes under ~/.greentic.",
    },
    BuiltinHandler {
        slot: CapabilitySlot::Secrets,
        descriptor_path: "greentic.secrets.dev-store",
        label: "Dev-store secrets backend",
        summary: "File-backed developer secret store for the local environment.",
    },
    BuiltinHandler {
        slot: CapabilitySlot::Telemetry,
        descriptor_path: "greentic.telemetry.stdout",
        label: "Stdout telemetry exporter",
        summary: "Writes spans and metrics to stdout for local inspection.",
    },
    BuiltinHandler {
        slot: CapabilitySlot::Sessions,
        descriptor_path: "greentic.sessions.in-memory",
        label: "In-memory session store",
        summary: "Process-local session storage; cleared on restart.",
    },
    BuiltinHandler {
        slot: CapabilitySlot::State,
        descriptor_path: "greentic.state.in-memory",
        label: "In-memory state store",
        summary: "Process-local working-memory store; cleared on restart.",
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
    fn describe_reports_builtin_identity() {
        let info = BUILTIN_HANDLERS[0].describe();
        assert_eq!(info.slot, CapabilitySlot::Deployer);
        assert_eq!(info.descriptor_path, "greentic.deployer.local-process");
        assert!(info.builtin);
    }
}
