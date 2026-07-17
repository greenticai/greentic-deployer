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

use chrono::{DateTime, Utc};
use greentic_deploy_spec::{
    CapabilitySlot, Credentials, CredentialsBootstrap, CredentialsExpiry, CredentialsMode,
    CredentialsValidation, CredentialsValidationResult, EnvId, SchemaVersion, SecretRef,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::env_packs::{EnvPackRegistry, RegistryError};
use crate::environment::{LocalFsStore, StoreError};

use super::rules_export::{RulesExportError, RulesPack, write_rules_pack};
use super::store_paths;

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
/// The handler returns this; the runner persists the rules pack, writes any
/// bound secret material to the secret backend, and stamps the env's
/// [`Credentials`] doc. The handler does NOT touch the env store directly.
#[derive(Clone, Serialize, Deserialize)]
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
    /// AWS C3 stub returns `None` (admin runs Terraform); the K8s
    /// `--bind` path returns `Some` once it has minted a ServiceAccount
    /// token directly. Local-process never reaches here (returns
    /// `BootstrapError::NotApplicable`).
    pub bound_credentials_ref: Option<SecretRef>,
    /// When the handler minted a credential with a bounded lifetime (e.g.
    /// a K8s `TokenRequest` token), the absolute expiry the cluster
    /// granted. The runner stamps it into [`Credentials::expiry`] so the
    /// re-bind deadline is visible; `None` for non-expiring or render-only
    /// bootstraps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_expiry: Option<DateTime<Utc>>,
    /// Secret material the handler minted that the runner must persist to
    /// the env's secret backend (the location `resolve_credentials_token`
    /// reads it back from) BEFORE recording `credentials_ref`.
    ///
    /// `#[serde(skip)]` — material is never serialized into the persisted
    /// [`Credentials`] doc or any audit record; it lives only for the
    /// in-process handler→runner handoff and is zeroized on drop. `None`
    /// for render-only bootstraps (the admin supplies the material
    /// out-of-band and binds it via `op credentials rotate`).
    #[serde(skip)]
    pub bound_secret_material: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for BootstrapOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render `bound_secret_material` — it carries live token
        // material (and `Zeroizing<String>`'s own Debug would print it).
        // Surface only its presence.
        f.debug_struct("BootstrapOutcome")
            .field("rules_pack", &self.rules_pack)
            .field("bound_credentials_ref", &self.bound_credentials_ref)
            .field("bound_expiry", &self.bound_expiry)
            .field(
                "bound_secret_material",
                &self.bound_secret_material.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Sink the runner calls to persist bound secret material into the env's
/// secret backend. Inverted dependency: the runner owns the env flock and
/// the write-before-persist ordering, while the caller (the CLI) owns the
/// dev-store specifics. Receives the env root, the ref the material binds
/// to, and the material; `Ok(())` ⇒ durably stored, `Err(msg)` aborts the
/// bootstrap before `credentials_ref` is recorded.
pub type BoundSecretSink<'a> = dyn Fn(&Path, &SecretRef, &str) -> Result<(), String> + 'a;

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
        "deployer env-pack `{deployer_kind}` minted bound credential material but its landing \
         path is not covered by the runtime-seed denylist (declared: {declared:?}, actual \
         landing: {landing:?}); refusing to \
         write it. Bootstrap writes material before recording `credentials_ref`, so a crash in \
         between would orphan a credential no seed exclusion can strip, leaking it into every \
         workload this env deploys. Declare the path via \
         `DeployerCredentials::bound_credential_store_path` and add it to \
         `credentials::store_paths::BOUND_CREDENTIAL_STORE_PATHS`."
    )]
    UndeclaredCredentialPath {
        deployer_kind: String,
        declared: Option<String>,
        /// Where the material would actually have landed (`<env>:<rel path>`),
        /// versionless. `None` when `bound_credentials_ref` is not a parseable
        /// store-aligned URI at all — which is itself a refusal reason: an
        /// unparseable ref cannot be matched by any exclusion.
        landing: Option<String>,
    },
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
    #[error("failed to persist bound credential material: {0}")]
    SecretWrite(String),
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
    creds_override: Option<&dyn super::DeployerCredentials>,
    secret_sink: &BoundSecretSink<'_>,
) -> Result<Credentials, RunBootstrapError> {
    store.transact(env_id, |locked| {
        let mut env = locked.load()?;
        let deployer = env
            .pack_for_slot(CapabilitySlot::Deployer)
            .ok_or_else(|| RunBootstrapError::NoDeployerBound(env_id.clone()))?;
        if env.credentials_ref.is_some() {
            return Err(RunBootstrapError::AlreadyBootstrapped(env_id.clone()));
        }

        // Resolve the handler even when an override is supplied: this is
        // where the A9 slot/version match is enforced. The override (the
        // CLI's admin-connected K8s credentials for `--bind`) then replaces
        // the handler's own bootstrap path — mirrors the `creds_override`
        // seam in `validate_requirements`.
        let handler = registry.resolve_for_slot(CapabilitySlot::Deployer, &deployer.kind)?;
        let creds: &dyn super::DeployerCredentials = match creds_override {
            Some(c) => c,
            None => handler.deployer_credentials().ok_or_else(|| {
                RunBootstrapError::HandlerNotRegistered {
                    kind: deployer.kind.as_str().to_string(),
                }
            })?,
        };

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
        // Kept for diagnostics: `deployer_kind` moves into the `Credentials` doc below.
        let deployer_kind_label = deployer_kind.as_str().to_string();

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
            expiry: outcome.bound_expiry.map(|expires_at| CredentialsExpiry {
                expires_at,
                rotate_at: None,
            }),
        };

        // Fail closed BEFORE anything is written or persisted: bound credential
        // material may only ever land where the runtime-seed denylist can strip
        // it. See `store_paths::landing_is_covered` for the full invariant.
        //
        // Gated on the REF, not on the material: a handler returning
        // `Some(rogue_ref)` with no material writes nothing now, but persisting
        // that ref makes it the env's credential location — and `run_rotate`
        // later writes real material at exactly that persisted ref. Gating only
        // the material-carrying case would leave that path open.
        if let Some(bound_ref) = outcome.bound_credentials_ref.as_ref() {
            let declared = creds.bound_credential_store_path();
            let (ok, landing) = store_paths::landing_is_covered(bound_ref, env_id, declared);
            if !ok {
                return Err(RunBootstrapError::UndeclaredCredentialPath {
                    deployer_kind: deployer_kind_label,
                    declared: declared.map(str::to_string),
                    landing,
                });
            }
        }

        // Persist bound secret material (when the handler minted it) to the
        // secret backend BEFORE recording credentials_ref: the env must
        // never point at a credential whose material isn't there. On write
        // failure, return WITHOUT persisting credentials_ref so bootstrap
        // stays re-runnable (no AlreadyBootstrapped lockout).
        if let (Some(bound_ref), Some(material)) = (
            outcome.bound_credentials_ref.as_ref(),
            outcome.bound_secret_material.as_ref(),
        ) {
            secret_sink(&env_root, bound_ref, material.as_str())
                .map_err(RunBootstrapError::SecretWrite)?;
        }

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
