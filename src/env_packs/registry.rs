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
    #[error(
        "deployer env-pack `{kind}` does not ship a credentials contract (DeployerCredentials impl)"
    )]
    DeployerMissingCredentials { kind: String },
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

    /// A registry pre-loaded with the built-in `local` handlers.
    ///
    /// Registers the four metadata-only [`BUILTIN_HANDLERS`] (Secrets,
    /// Telemetry, Sessions, State) plus the C2 deployer handler that
    /// ships a real
    /// [`DeployerCredentials`](crate::credentials::DeployerCredentials)
    /// impl
    /// ([`LocalProcessDeployerHandler`](super::local_process::LocalProcessDeployerHandler)).
    ///
    /// When the `creds-aws` feature is on (default), also registers the
    /// C3 AWS-ECS deployer handler
    /// ([`AwsEcsDeployerHandler`](super::aws::AwsEcsDeployerHandler))
    /// under `greentic.deployer.aws-ecs`. The handler is NOT part of the
    /// `local` env's default bindings — it must be bound explicitly via
    /// `gtc op env-packs add <env> --slot deployer --kind
    /// greentic.deployer.aws-ecs@1.0.0` — but the registry resolves the
    /// descriptor so `gtc op credentials requirements` can probe a real
    /// AWS account today.
    ///
    /// Also registers the Phase D K8s deployer handler
    /// ([`K8sDeployerHandler`](super::k8s::K8sDeployerHandler)) under
    /// `greentic.deployer.k8s` — likewise opt-in per env, never a `local`
    /// default. Unconditional (the scaffold carries no heavy SDK deps);
    /// the typed cluster client lands behind its own seam.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        for handler in BUILTIN_HANDLERS {
            registry
                .register(Box::new(*handler))
                .expect("built-in handler paths are unique");
        }
        registry
            .register(Box::new(
                super::local_process::LocalProcessDeployerHandler::default(),
            ))
            .expect("local-process deployer handler path is unique");
        #[cfg(feature = "creds-aws")]
        registry
            .register(Box::new(super::aws::AwsEcsDeployerHandler::default()))
            .expect("aws-ecs deployer handler path is unique");
        #[cfg(feature = "creds-gcp")]
        registry
            .register(Box::new(
                super::gcp_cloudrun::GcpCloudRunDeployerHandler::default(),
            ))
            .expect("gcp-cloudrun deployer handler path is unique");
        registry
            .register(Box::new(super::k8s::K8sDeployerHandler::default()))
            .expect("k8s deployer handler path is unique");
        registry
    }

    /// Register a handler under its [`descriptor_path`](EnvPackHandler::descriptor_path).
    ///
    /// The Phase D plug-in hook. Rejects:
    /// - A path already registered (no silent shadowing of built-ins).
    /// - A `Deployer`-slot handler whose `deployer_credentials()` returns
    ///   `None` — every deployer env-pack must ship a credentials contract.
    pub fn register(&mut self, handler: Box<dyn EnvPackHandler>) -> Result<(), RegistryError> {
        let path = handler.descriptor_path().to_string();
        if self.handlers.contains_key(&path) {
            return Err(RegistryError::DuplicateRegistration(path));
        }
        if handler.slot() == CapabilitySlot::Deployer && handler.deployer_credentials().is_none() {
            return Err(RegistryError::DeployerMissingCredentials { kind: path });
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

    /// Resolve a descriptor and return the handler's
    /// [`wizard_qaspec_yaml`](EnvPackHandler::wizard_qaspec_yaml) (C6).
    ///
    /// Reuses [`resolve`](Self::resolve)'s version-supported check, so a
    /// caller asking for an env-pack's wizard at a version the handler
    /// does not implement gets [`RegistryError::VersionUnsupported`]
    /// before any YAML is returned. The outer `Result` distinguishes
    /// "no handler / wrong version" from the inner `Option` ("handler
    /// resolves but ships no wizard" — the metadata-only built-ins).
    pub fn wizard_qaspec_yaml_for_descriptor(
        &self,
        kind: &PackDescriptor,
    ) -> Result<Option<&'static str>, RegistryError> {
        Ok(self.resolve(kind)?.wizard_qaspec_yaml())
    }

    /// Number of registered handlers.
    /// Every registered handler, in `descriptor_path` order.
    ///
    /// Lets cross-cutting invariants be checked against the *whole* registry
    /// rather than a hard-coded list of built-ins — e.g. the conformance guard
    /// in [`credentials::store_paths`](crate::credentials::store_paths) that
    /// requires every deployer declaring a bound-credential landing path to have
    /// that path in the runtime-seed denylist.
    pub fn handlers(&self) -> impl Iterator<Item = &dyn EnvPackHandler> {
        self.handlers.values().map(|handler| handler.as_ref())
    }

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
    fn with_builtins_registers_baseline_handlers() {
        // Five `local` handlers (Secrets / Telemetry / Sessions / State +
        // local-process Deployer) plus the Phase D K8s deployer (6 baseline).
        // Each cloud deployer adds one when its feature is on: `creds-aws` for
        // AWS-ECS, `creds-gcp` for GCP Cloud Run. Neither cloud handler is part
        // of the `local` env's default bindings, but the registry resolves them
        // so `gtc op env-packs add … --kind greentic.deployer.<cloud>` resolves.
        let registry = EnvPackRegistry::with_builtins();
        let expected =
            6 + cfg!(feature = "creds-aws") as usize + cfg!(feature = "creds-gcp") as usize;
        assert_eq!(registry.len(), expected);
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

    /// A deployer handler that returns `deployer_credentials() = None`
    /// must be rejected at registration time — every deployer env-pack
    /// must ship a credentials contract.
    #[derive(Debug)]
    struct DeployerWithoutCredentials;

    impl EnvPackHandler for DeployerWithoutCredentials {
        fn slot(&self) -> CapabilitySlot {
            CapabilitySlot::Deployer
        }
        fn descriptor_path(&self) -> &str {
            "acme.deployer.no-creds"
        }
        fn supported_versions(&self) -> semver::VersionReq {
            "^1.0.0".parse().unwrap()
        }
        // deployer_credentials() defaults to None — that's the gap.
    }

    #[test]
    fn register_rejects_deployer_without_credentials() {
        let mut registry = EnvPackRegistry::new();
        let err = registry
            .register(Box::new(DeployerWithoutCredentials))
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::DeployerMissingCredentials { .. }),
            "got {err:?}"
        );
    }

    /// C6 (parametrized): every handler that ships a wizard YAML must
    /// deserialize cleanly as a `qa_spec::FormSpec` with at least one
    /// question. Centralized here so a new handler shipping a wizard
    /// automatically inherits the contract — no per-handler boilerplate.
    #[test]
    fn every_handler_with_a_wizard_ships_a_well_formed_qaspec() {
        let registry = EnvPackRegistry::with_builtins();
        let mut checked = 0;
        for (path, handler) in &registry.handlers {
            let Some(yaml) = handler.wizard_qaspec_yaml() else {
                continue;
            };
            let spec: qa_spec::FormSpec = serde_yaml_bw::from_str(yaml)
                .unwrap_or_else(|e| panic!("`{path}` wizard.qaspec.yaml parses: {e}"));
            assert!(
                !spec.questions.is_empty(),
                "`{path}` wizard QASpec declares zero questions — the operator's wizard \
                 driver has nothing to ask",
            );
            checked += 1;
        }
        assert!(
            checked >= 1,
            "no built-in handler ships a wizard QASpec — the C6 seam is unexercised",
        );
    }

    /// C6: the registry helper returns the deployer's wizard YAML when
    /// the descriptor resolves, `None` for descriptors whose handler
    /// ships no wizard (metadata-only built-ins), and `VersionUnsupported`
    /// when the pinned version exceeds what the handler implements.
    #[test]
    fn wizard_qaspec_yaml_for_descriptor_resolves_local_process() {
        let registry = EnvPackRegistry::with_builtins();
        let yaml = registry
            .wizard_qaspec_yaml_for_descriptor(&descriptor(LOCAL_DEPLOYER_PACK))
            .expect("local-process deployer descriptor resolves")
            .expect("local-process deployer ships a wizard QASpec");
        assert!(yaml.contains("greentic.deployer.local-process.wizard"));
    }

    #[test]
    fn wizard_qaspec_yaml_for_descriptor_none_for_metadata_only_handler() {
        let registry = EnvPackRegistry::with_builtins();
        // The dev-store secrets handler is metadata-only — no wizard.
        let yaml = registry
            .wizard_qaspec_yaml_for_descriptor(&descriptor(LOCAL_SECRETS_PACK))
            .expect("dev-store secrets descriptor resolves");
        assert!(
            yaml.is_none(),
            "metadata-only handler must not surface a wizard QASpec",
        );
    }

    #[test]
    fn wizard_qaspec_yaml_for_descriptor_propagates_version_skew() {
        let registry = EnvPackRegistry::with_builtins();
        // Path resolves but version is past what the handler implements —
        // wizard lookup MUST inherit `resolve`'s version check, not silently
        // return YAML for an unsupported version.
        let err = registry
            .wizard_qaspec_yaml_for_descriptor(&descriptor("greentic.secrets.dev-store@9.9.9"))
            .unwrap_err();
        assert!(matches!(err, RegistryError::VersionUnsupported { .. }));
    }

    /// The built-in local-process deployer ships a credentials contract
    /// and registers successfully.
    #[test]
    fn builtin_deployer_has_credentials_contract() {
        let registry = EnvPackRegistry::with_builtins();
        let handler = registry.resolve(&descriptor(LOCAL_DEPLOYER_PACK)).unwrap();
        assert!(
            handler.deployer_credentials().is_some(),
            "built-in deployer must ship a credentials contract"
        );
    }
}
