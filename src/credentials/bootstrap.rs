//! Bootstrap-flow driver for [`super::DeployerCredentials`].
//!
//! `run_bootstrap` consumes a one-shot admin credential via
//! [`ZeroizedAdmin`], delegates to the bound deployer handler, and
//! persists:
//!
//! 1. A reviewable rules-pack under `rules/<env_id>/` so the customer's
//!    admin can apply the equivalent IaC offline (see
//!    [`rules_export`](super::rules_export)).
//! 2. A [`Credentials`] doc with `mode = Bootstrap`,
//!    `admin_credential_consumed_at` stamped to the call time, and — when
//!    the handler bound material directly — the env's `credentials_ref`.
//!
//! When the handler returns `bound_credentials_ref = None` (e.g. AWS C3
//! where the admin runs Terraform offline), the env stays uncredentialed:
//! `credentials_ref` is NOT written, so a follow-up `op credentials
//! bootstrap` is not locked out by `AlreadyBootstrapped`, and downstream
//! `op credentials requirements` will correctly reject with
//! `NoCredentialsRef` until the admin binds the real value via `op
//! credentials rotate`.
//!
//! ## Admin credentials posture
//!
//! Admin credentials are received in a [`ZeroizedAdmin`] wrapper whose
//! `Drop` zeroizes the in-process buffer. This is best-effort: the OS
//! may have paged the buffer, the cloud SDK may hold its own copy, and
//! ambient profile chains (e.g. `~/.aws/credentials`) live outside this
//! process. The contract is honest about that and does NOT claim
//! process-wide memory erasure. Operators that need strong guarantees
//! should run bootstrap on a short-lived process (CI runner, dedicated
//! VM).
//!
//! ## Phase A constraint
//!
//! Same constraint as [`validate`](super::validate): Phase A's secrets
//! handler is metadata-only, so the runner cannot actually *write* the
//! generated secret material to a real backend yet. The
//! [`BootstrapOutcome`] returned by the handler is honored and stamped
//! into the persisted `Credentials` doc; the secret-backend write is a
//! Phase D follow-on. Today, deployers that have no admin escalation
//! (local-process, C2) cleanly return
//! [`BootstrapError::NotApplicable`].

use std::path::Path;

use chrono::Utc;
use greentic_deploy_spec::{
    CapabilitySlot, Credentials, CredentialsBootstrap, CredentialsMode, CredentialsValidation,
    CredentialsValidationResult, EnvId, SchemaVersion, SecretRef,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::env_packs::{EnvPackRegistry, RegistryError};
use crate::environment::{LocalFsStore, StoreError};

use super::rules_export::{RulesExportError, RulesPack, write_rules_pack};

/// One-shot admin credential material. `Drop` zeroizes the in-process
/// buffer; see the module docstring for the limits of that guarantee.
///
/// Wrap the credential at the boundary closest to where it was supplied
/// (e.g. read from an interactive prompt or a one-time ENV var) and pass
/// the wrapper through to [`run_bootstrap`]. Do NOT clone the inner
/// string out — `as_str()` borrows for the duration of the call.
pub struct ZeroizedAdmin {
    inner: Zeroizing<String>,
    /// Profile / handle the user named (e.g. an AWS named profile or a
    /// kubeconfig context). Not sensitive itself, but kept alongside the
    /// material for diagnostics.
    profile: String,
}

impl std::fmt::Debug for ZeroizedAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroizedAdmin")
            .field("profile", &self.profile)
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl ZeroizedAdmin {
    /// Wrap admin credential material. The caller is responsible for
    /// ensuring `material` was not copied through an intermediate
    /// allocation that survives this call.
    pub fn new(profile: impl Into<String>, material: String) -> Self {
        Self {
            inner: Zeroizing::new(material),
            profile: profile.into(),
        }
    }

    /// Sentinel "I have no real admin material" wrapper for deployers
    /// whose [`super::DeployerCredentials::bootstrap`] does not need any
    /// (currently none — every real deployer needs *something* — but C2
    /// uses this to test the rejection path).
    pub fn sentinel(profile: impl Into<String>) -> Self {
        Self {
            inner: Zeroizing::new(String::new()),
            profile: profile.into(),
        }
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

/// Input passed to [`super::DeployerCredentials::bootstrap`].
///
/// Borrows the admin credential and the env context. Handlers MUST NOT
/// store the `admin` reference past the call return — by the time
/// `run_bootstrap` returns to the operator, the `ZeroizedAdmin` has
/// dropped and its buffer is zeroized.
#[derive(Debug)]
pub struct BootstrapInput<'a> {
    pub env_id: &'a EnvId,
    pub env_root: &'a Path,
    pub admin: &'a ZeroizedAdmin,
}

/// Successful bootstrap output.
///
/// The handler returns this; the runner persists the rules pack and
/// stamps the env's [`Credentials`] doc. The handler does NOT touch the
/// store directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapOutcome {
    /// Rules-pack content the customer's admin can review and apply.
    /// Empty for deployers that need no offline IaC step (e.g.
    /// local-process — though those should use
    /// [`BootstrapError::NotApplicable`] rather than reach here).
    pub rules_pack: RulesPack,
    /// When `Some`, the runner sets `env.credentials_ref` to this value
    /// — the env is now credentialed and downstream validates will run
    /// the deployer's real probes against it. When `None`, the bootstrap
    /// emitted only an IaC rules pack; the env stays uncredentialed
    /// until `op credentials rotate <env> --provided-credentials-ref
    /// <uri>` binds the real value the customer's admin produces by
    /// applying the rules pack offline.
    ///
    /// AWS C3 stub returns `None` (admin runs Terraform); Phase D AWS
    /// will return `Some` once the deployer can mint a session token
    /// directly. Local-process never reaches here (returns
    /// `BootstrapError::NotApplicable`).
    pub bound_credentials_ref: Option<SecretRef>,
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The deployer has no admin escalation path — the user should run
    /// `requirements` instead. Returned by local-process (C2).
    #[error("{0}")]
    NotApplicable(String),
    /// Admin credential rejected by the cloud provider (wrong account,
    /// expired session, insufficient privileges).
    #[error("admin credential rejected: {0}")]
    AdminRejected(String),
    /// Bootstrap ran but a downstream provisioning step failed.
    #[error("bootstrap failed during {step}: {message}")]
    ProvisioningFailed { step: String, message: String },
}

#[derive(Debug, Error)]
pub enum RunBootstrapError {
    #[error("env `{0}` has no deployer slot bound; bind one with `op env-packs add` first")]
    NoDeployerBound(EnvId),
    #[error("env `{0}` already has credentials_ref; use `rotate` instead of `bootstrap`")]
    AlreadyBootstrapped(EnvId),
    #[error(
        "deployer env-pack `{kind}` has no native credentials handler registered (Phase D plug-in)"
    )]
    HandlerNotRegistered { kind: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
    #[error(transparent)]
    RulesExport(#[from] RulesExportError),
}

/// Drive a `bootstrap` flow against the env's bound deployer env-pack,
/// inside a single transactional scope.
///
/// The entire flow — load env, assert `credentials_ref` absent, invoke the
/// handler's bootstrap path, write the rules pack, persist the new
/// `credentials_ref` — runs while holding the env's exclusive flock. This
/// prevents two concurrent invocations from both passing the absence check,
/// consuming admin credentials, and racing on the final write.
///
/// **Trade-off:** Bootstrap may be long-running (handler calls out to a
/// cloud provider), so the env flock is held for the full duration of the
/// call. This is acceptable because (a) bootstrap is a one-shot admin
/// operation, not a hot path, and (b) other verbs that need the flock
/// (requirements, rotate, traffic mutations) will simply block until
/// bootstrap completes, which is the correct serialization.
pub fn run_bootstrap(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &EnvId,
    admin: &ZeroizedAdmin,
) -> Result<Credentials, RunBootstrapError> {
    store.transact(env_id, |locked| {
        let mut env = locked.load()?;
        let deployer = env
            .pack_for_slot(CapabilitySlot::Deployer)
            .ok_or_else(|| RunBootstrapError::NoDeployerBound(env_id.clone()))?;
        if env.credentials_ref.is_some() {
            return Err(RunBootstrapError::AlreadyBootstrapped(env_id.clone()));
        }

        let handler = registry.resolve_for_slot(CapabilitySlot::Deployer, &deployer.kind)?;
        let creds = handler.deployer_credentials().ok_or_else(|| {
            RunBootstrapError::HandlerNotRegistered {
                kind: deployer.kind.as_str().to_string(),
            }
        })?;

        let env_root = store.env_dir(env_id)?;
        let input = BootstrapInput {
            env_id,
            env_root: &env_root,
            admin,
        };
        let outcome = creds.bootstrap(&input)?;

        let consumed_at = Utc::now();
        let rules_pack_ref = write_rules_pack(&env_root, &deployer.kind, &outcome.rules_pack)?;
        // Snapshot the deployer kind before the &env borrow ends below.
        let deployer_kind = deployer.kind.clone();

        // When the handler bound credentials directly (e.g. Phase D AWS
        // mints a session token), the env is immediately credentialed.
        // When `None` (e.g. C3 AWS where the admin runs Terraform
        // offline), use a doc-only sentinel so the returned Credentials
        // doc is honest about the incomplete state — but do NOT write it
        // to env.credentials_ref.
        let (doc_ref, validation_result, missing_caps) =
            if let Some(ref bound) = outcome.bound_credentials_ref {
                (bound.clone(), CredentialsValidationResult::Pass, Vec::new())
            } else {
                let sentinel = SecretRef::try_new(format!(
                    "secret://{}/{}/bootstrap-incomplete",
                    env_id.as_str(),
                    deployer_kind.as_str()
                ))
                .expect("sentinel SecretRef is well-formed");
                (
                    sentinel,
                    CredentialsValidationResult::Fail,
                    vec!["credentials.bind-pending".to_string()],
                )
            };

        let doc = Credentials {
            schema: SchemaVersion::new(SchemaVersion::CREDENTIALS_V1),
            env_id: env_id.clone(),
            deployer_kind,
            mode: CredentialsMode::Bootstrap,
            provided_credentials_ref: doc_ref.clone(),
            validation: CredentialsValidation {
                last_run_at: consumed_at,
                result: validation_result,
                missing_capabilities: missing_caps,
            },
            bootstrap: Some(CredentialsBootstrap {
                admin_credential_consumed_at: consumed_at,
                rules_pack_ref,
                generated_credentials_ref: doc_ref,
            }),
            expiry: None,
        };

        // Only persist credentials_ref when the handler actually bound
        // material. When `None`, the env stays uncredentialed — bootstrap
        // can be re-run after the admin applies the rules pack and binds
        // credentials via `op credentials rotate`.
        if outcome.bound_credentials_ref.is_some() {
            env.credentials_ref = Some(doc.provided_credentials_ref.clone());
            locked.save(&env)?;
        }

        Ok(doc)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroized_admin_redacts_in_debug_output() {
        let admin = ZeroizedAdmin::new("p1", "AKIASUPERSECRET".to_string());
        let dbg = format!("{admin:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("AKIASUPERSECRET"));
    }

    #[test]
    fn zeroized_admin_as_str_returns_material() {
        let admin = ZeroizedAdmin::new("p1", "x".to_string());
        assert_eq!(admin.as_str(), "x");
        assert_eq!(admin.profile(), "p1");
    }

    #[test]
    fn sentinel_has_empty_material() {
        let admin = ZeroizedAdmin::sentinel("p1");
        assert!(admin.as_str().is_empty());
    }
}
