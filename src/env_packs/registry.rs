//! Env-pack registry (`A9`).
//!
//! [`EnvPackRegistry`] maps a [`PackDescriptor`] to its native
//! [`EnvPackHandler`]. Lookup locates the handler by the descriptor's
//! version-independent [`path`](PackDescriptor::path), then validates the
//! requested `@<semver>` against the handler's
//! [`supported_versions`](EnvPackHandler::supported_versions): a version the
//! native handler does not implement is rejected with
//! [`RegistryError::VersionUnsupported`] rather than silently certified.
//! [`with_builtins`](EnvPackRegistry::with_builtins) registers the five default
//! `local` handlers; [`register`](EnvPackRegistry::register) is the Phase D
//! plug-in hook.
//!
//! Phase A handlers are metadata-only (see [`slot`](super::slot)); resolution
//! itself is real and is what `op env doctor` uses to flag bindings whose
//! `kind` no native handler backs, or whose pinned version no handler supports.

use std::collections::BTreeMap;

use greentic_deploy_spec::{CapabilitySlot, PackDescriptor};
use thiserror::Error;

use super::slot::{BUILTIN_HANDLERS, EnvPackHandler};

/// Resolution failures from [`EnvPackRegistry`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("no env-pack handler registered for `{0}`")]
    Unknown(String),
    #[error("env-pack `{kind}` is a `{actual}` handler but was bound to the `{expected}` slot")]
    SlotMismatch {
        kind: String,
        expected: CapabilitySlot,
        actual: CapabilitySlot,
    },
    #[error(
        "env-pack `{kind}` pins version `{requested}` but the native handler implements `{supported}`"
    )]
    VersionUnsupported {
        kind: String,
        requested: String,
        supported: String,
    },
    #[error("an env-pack handler is already registered for path `{0}`")]
    DuplicateRegistration(String),
}

/// Binds [`PackDescriptor`] paths to native [`EnvPackHandler`]s.
#[derive(Debug, Default)]
pub struct EnvPackRegistry {
    handlers: BTreeMap<String, Box<dyn EnvPackHandler>>,
}

impl EnvPackRegistry {
    /// An empty registry with no handlers registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry pre-loaded with the built-in `local` handlers
    /// ([`BUILTIN_HANDLERS`]).
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        for handler in BUILTIN_HANDLERS {
            registry
                .register(Box::new(*handler))
                .expect("built-in handler paths are unique");
        }
        registry
    }

    /// Register a handler under its [`descriptor_path`](EnvPackHandler::descriptor_path).
    ///
    /// The Phase D plug-in hook. Rejects a path already registered so a
    /// plug-in cannot silently shadow a built-in handler.
    pub fn register(&mut self, handler: Box<dyn EnvPackHandler>) -> Result<(), RegistryError> {
        let path = handler.descriptor_path().to_string();
        if self.handlers.contains_key(&path) {
            return Err(RegistryError::DuplicateRegistration(path));
        }
        self.handlers.insert(path, handler);
        Ok(())
    }

    /// Resolve a descriptor to its handler.
    ///
    /// Locates the handler by the version-independent path, then rejects a
    /// pinned version the handler does not implement
    /// ([`RegistryError::VersionUnsupported`]) so version skew can't pass as
    /// healthy.
    pub fn resolve(&self, kind: &PackDescriptor) -> Result<&dyn EnvPackHandler, RegistryError> {
        let handler = self
            .handlers
            .get(kind.path())
            .map(|h| h.as_ref())
            .ok_or_else(|| RegistryError::Unknown(kind.as_str().to_string()))?;
        let req = handler.supported_versions();
        if !req.matches(&kind.version().0) {
            return Err(RegistryError::VersionUnsupported {
                kind: kind.as_str().to_string(),
                requested: kind.version().to_string(),
                supported: req.to_string(),
            });
        }
        Ok(handler)
    }

    /// Resolve a descriptor and assert its handler serves `expected`.
    ///
    /// Catches a binding that points a slot at a handler for a different slot
    /// (e.g. the `Secrets` slot bound to a deployer descriptor).
    pub fn resolve_for_slot(
        &self,
        expected: CapabilitySlot,
        kind: &PackDescriptor,
    ) -> Result<&dyn EnvPackHandler, RegistryError> {
        let handler = self.resolve(kind)?;
        let actual = handler.slot();
        if actual != expected {
            return Err(RegistryError::SlotMismatch {
                kind: kind.as_str().to_string(),
                expected,
                actual,
            });
        }
        Ok(handler)
    }

    /// Number of registered handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether the registry has no handlers.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::{LOCAL_DEPLOYER_PACK, LOCAL_SECRETS_PACK};

    fn descriptor(raw: &str) -> PackDescriptor {
        PackDescriptor::try_new(raw).expect("descriptor parses")
    }

    #[test]
    fn with_builtins_registers_five_handlers() {
        let registry = EnvPackRegistry::with_builtins();
        assert_eq!(registry.len(), 5);
    }

    #[test]
    fn resolve_built_in_descriptor() {
        let registry = EnvPackRegistry::with_builtins();
        let handler = registry.resolve(&descriptor(LOCAL_SECRETS_PACK)).unwrap();
        assert_eq!(handler.slot(), CapabilitySlot::Secrets);
        assert_eq!(handler.descriptor_path(), "greentic.secrets.dev-store");
    }

    #[test]
    fn resolve_accepts_compatible_version() {
        let registry = EnvPackRegistry::with_builtins();
        // A patch within the supported `^0.1.0` line resolves.
        let handler = registry
            .resolve(&descriptor("greentic.secrets.dev-store@0.1.7"))
            .unwrap();
        assert_eq!(handler.slot(), CapabilitySlot::Secrets);
    }

    #[test]
    fn resolve_rejects_unsupported_version() {
        let registry = EnvPackRegistry::with_builtins();
        // The path is known, but the built-in implements only `^0.1.0`; a
        // future major must not pass as healthy.
        let err = registry
            .resolve(&descriptor("greentic.secrets.dev-store@9.9.9"))
            .unwrap_err();
        assert!(matches!(
            err,
            RegistryError::VersionUnsupported {
                requested,
                supported,
                ..
            } if requested == "9.9.9" && supported == "^0.1.0"
        ));
    }

    #[test]
    fn resolve_unknown_descriptor_errors() {
        let registry = EnvPackRegistry::with_builtins();
        let err = registry
            .resolve(&descriptor("greentic.secrets.acme-vault@1.0.0"))
            .unwrap_err();
        assert!(matches!(err, RegistryError::Unknown(k) if k.contains("acme-vault")));
    }

    #[test]
    fn resolve_for_slot_accepts_matching_slot() {
        let registry = EnvPackRegistry::with_builtins();
        registry
            .resolve_for_slot(CapabilitySlot::Deployer, &descriptor(LOCAL_DEPLOYER_PACK))
            .unwrap();
    }

    #[test]
    fn resolve_for_slot_rejects_mismatched_slot() {
        let registry = EnvPackRegistry::with_builtins();
        // The deployer descriptor resolves, but it serves the Deployer slot.
        let err = registry
            .resolve_for_slot(CapabilitySlot::Secrets, &descriptor(LOCAL_DEPLOYER_PACK))
            .unwrap_err();
        assert!(matches!(
            err,
            RegistryError::SlotMismatch {
                expected: CapabilitySlot::Secrets,
                actual: CapabilitySlot::Deployer,
                ..
            }
        ));
    }

    #[test]
    fn register_rejects_duplicate_path() {
        let mut registry = EnvPackRegistry::with_builtins();
        // BUILTIN_HANDLERS[0] is already registered by with_builtins.
        let err = registry
            .register(Box::new(super::super::slot::BUILTIN_HANDLERS[0]))
            .unwrap_err();
        assert!(matches!(err, RegistryError::DuplicateRegistration(_)));
    }

    #[test]
    fn new_registry_is_empty() {
        let registry = EnvPackRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    /// A Phase-D-style plug-in handler serving the open `Extension` slot.
    #[derive(Debug)]
    struct ExtHandler;

    impl EnvPackHandler for ExtHandler {
        fn slot(&self) -> CapabilitySlot {
            CapabilitySlot::Extension
        }
        fn descriptor_path(&self) -> &str {
            "acme.oauth.auth0"
        }
        fn supported_versions(&self) -> semver::VersionReq {
            "^1.0.0".parse().unwrap()
        }
    }

    #[test]
    fn resolve_for_slot_accepts_a_registered_extension_handler() {
        let mut registry = EnvPackRegistry::with_builtins();
        registry.register(Box::new(ExtHandler)).unwrap();
        // A registered extension handler resolves under the Extension slot.
        registry
            .resolve_for_slot(
                CapabilitySlot::Extension,
                &descriptor("acme.oauth.auth0@1.2.0"),
            )
            .unwrap();
        // Binding the same descriptor under a core slot is a slot mismatch.
        let err = registry
            .resolve_for_slot(
                CapabilitySlot::Secrets,
                &descriptor("acme.oauth.auth0@1.2.0"),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            RegistryError::SlotMismatch {
                expected: CapabilitySlot::Secrets,
                actual: CapabilitySlot::Extension,
                ..
            }
        ));
    }

    #[test]
    fn unregistered_extension_is_unknown() {
        // With no extension handler registered, an extension binding surfaces
        // as Unknown — exactly what `doctor` reports until Phase D plug-ins
        // register real handlers.
        let registry = EnvPackRegistry::with_builtins();
        let err = registry
            .resolve_for_slot(
                CapabilitySlot::Extension,
                &descriptor("acme.oauth.auth0@1.0.0"),
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::Unknown(_)));
    }
}
