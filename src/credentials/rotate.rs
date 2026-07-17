//! Rotation-flow driver for [`super::DeployerCredentials`].
//!
//! `run_rotate` re-mints an env's bound deployer credential in place and
//! re-persists the fresh material, WITHOUT changing `env.credentials_ref`
//! (the ref URI is stable; only the material behind it changes). It is the
//! systemic fix for the bound-token-expiry residual: an operator (or a
//! scheduled job calling `op credentials rotate --if-needed`) refreshes the
//! token before it lapses instead of running a full `--bind` bootstrap again.
//!
//! ## Re-mint engine
//!
//! For the K8s `--bind` path, re-running the handler's
//! [`bootstrap`](super::DeployerCredentials::bootstrap) IS rotation: it
//! re-applies the (idempotent) RBAC, mints a fresh `TokenRequest` token, and
//! overwrites the in-cluster identity Secret in place. `run_rotate` reuses
//! that path rather than duplicating the mint/persist machinery — it just
//! inverts the precondition (`credentials_ref` MUST already exist) and
//! overwrites the dev-store material instead of binding a new ref.
//!
//! ## Failure posture
//!
//! Unlike bootstrap, rotation does NOT roll back on a partial failure.
//! Re-mint overwrites material in place, so a failure after the in-cluster
//! Secret is written but before the dev-store sink commits leaves BOTH the
//! old and the new token valid (independent `TokenRequest` tokens); the
//! resolver prefers the still-valid dev-store entry and the next run retries.
//! Calling [`rollback_bound_material`](super::DeployerCredentials::rollback_bound_material)
//! here would wrongly DELETE the live identity Secret.

use chrono::{DateTime, Utc};
use greentic_deploy_spec::{CapabilitySlot, CredentialsExpiry, EnvId, SecretRef};
use thiserror::Error;

use crate::env_packs::{EnvPackRegistry, RegistryError};
use crate::environment::{LocalFsStore, StoreError};

use super::bootstrap::{BootstrapError, BootstrapInput, BoundSecretSink, ZeroizedAdmin};

/// Fraction of a bound token's lifetime after which `--if-needed` rotates.
/// Mirrors kubelet's projected-token refresh (rotate at 80% of lifetime),
/// so a token the API server clamped short (e.g. to 1h) still rotates
/// proportionally rather than churning every run or lapsing.
const ROTATE_AT_LIFETIME_FRACTION: f64 = 0.8;

/// Result of a successful rotation — the (unchanged) ref plus the refreshed
/// expiry window for the CLI to surface. `expiry` is `None` only for a
/// rotated credential the handler minted with no bounded lifetime.
#[derive(Debug, Clone)]
pub struct RotateOutcome {
    pub credentials_ref: SecretRef,
    pub expiry: Option<CredentialsExpiry>,
}

#[derive(Debug, Error)]
pub enum RunRotateError {
    #[error("env `{0}` has no deployer slot bound; bind one with `op env-packs add` first")]
    NoDeployerBound(EnvId),
    #[error("env `{0}` has no credentials_ref; run `op credentials bootstrap` first")]
    NotBootstrapped(EnvId),
    /// The deployer minted no bound material (e.g. a render-only bootstrap),
    /// so there is no live token to re-mint.
    #[error("{0}")]
    RotationUnsupported(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
    #[error("failed to persist rotated credential material: {0}")]
    SecretWrite(String),
}

/// Re-mint the env's bound deployer credential and re-persist the fresh
/// material, holding the env's exclusive flock for the whole flow (so a
/// concurrent reconcile / bootstrap / rotate serializes).
///
/// `bind_creds` is the admin-connected override the CLI builds for the K8s
/// `--bind` path — rotation always re-mints AS THE ADMIN (the bound
/// identity itself lacks `serviceaccounts/token` create rights by design),
/// so a render-only / no-override handler surfaces as
/// [`RunRotateError::RotationUnsupported`].
pub fn run_rotate(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &EnvId,
    admin: &ZeroizedAdmin,
    bind_creds: &dyn super::DeployerCredentials,
    secret_sink: &BoundSecretSink<'_>,
) -> Result<RotateOutcome, RunRotateError> {
    store.transact(env_id, |locked| {
        let env = locked.load()?;
        let deployer = env
            .pack_for_slot(CapabilitySlot::Deployer)
            .ok_or_else(|| RunRotateError::NoDeployerBound(env_id.clone()))?;
        // Authoritative inside-the-flock precondition: rotation refreshes an
        // EXISTING bound credential (the inverse of bootstrap's absence
        // check). The env resolves its credential from `credentials_ref`, so
        // that — not the deployer's default minted ref — is where the fresh
        // material must land for live verbs to pick it up.
        let active_ref = env
            .credentials_ref
            .clone()
            .ok_or_else(|| RunRotateError::NotBootstrapped(env_id.clone()))?;

        // Resolve the handler unconditionally so the A9 slot/version match
        // still runs; the admin-connected override then provides the actual
        // re-mint path (mirrors `run_bootstrap`).
        let _handler = registry.resolve_for_slot(CapabilitySlot::Deployer, &deployer.kind)?;

        let env_root = store.env_dir(env_id)?;
        let input = BootstrapInput {
            env_id,
            env_root: &env_root,
            admin,
        };
        // Re-mint: for the K8s bind path this re-applies idempotent RBAC,
        // mints a fresh TokenRequest token, and overwrites the in-cluster
        // identity Secret in place.
        let outcome = bind_creds.bootstrap(&input)?;

        // `bound_credentials_ref` being `Some` is the proof the deployer
        // actually minted material (render-only bootstraps return `None`).
        let (Some(_minted_ref), Some(material)) = (
            outcome.bound_credentials_ref.as_ref(),
            outcome.bound_secret_material.as_ref(),
        ) else {
            return Err(RunRotateError::RotationUnsupported(format!(
                "deployer env-pack `{}` minted no bound material to rotate; live rotation is \
                 supported only for the K8s `--bind` credential",
                deployer.kind.as_str()
            )));
        };

        // Overwrite the material at the env's ACTIVE `credentials_ref` — the
        // location the resolver reads — BEFORE returning success (the
        // in-cluster identity Secret was already overwritten inside
        // `bootstrap`). In the canonical `bootstrap --bind` flow the active ref
        // equals the deployer's minted ref, so this is unchanged; when an
        // operator bound a different same-env ref out of band, writing here
        // (not at the minted ref) is what keeps live verbs from resolving the
        // stale token. `env.credentials_ref` itself is NOT rewritten (the URI
        // is stable; only the material behind it changes).
        secret_sink(&env_root, &active_ref, material.as_str())
            .map_err(RunRotateError::SecretWrite)?;

        let expiry = outcome.bound_expiry.map(|expires_at| CredentialsExpiry {
            expires_at,
            rotate_at: bind_creds.rotate_at(material.as_str()),
        });

        Ok(RotateOutcome {
            credentials_ref: active_ref,
            expiry,
        })
    })
}

/// The absolute time a bound credential should be rotated, from its lifetime
/// window: `iat + (exp - iat) * 0.8`. A degenerate / already-expired window
/// (`exp <= iat`) returns `iat` (rotate now).
///
/// Shared rotation *policy* across backends: each
/// [`super::DeployerCredentials::rotate_at`] impl decodes its own material
/// into the `(iat, exp)` window, then calls this. Keeping the 80% fraction in
/// one place means K8s and any future backend rotate on the same schedule.
pub(crate) fn rotate_at_from_window(iat: DateTime<Utc>, exp: DateTime<Utc>) -> DateTime<Utc> {
    let lifetime_secs = (exp - iat).num_seconds();
    if lifetime_secs <= 0 {
        return iat;
    }
    let offset = (lifetime_secs as f64 * ROTATE_AT_LIFETIME_FRACTION) as i64;
    iat + chrono::Duration::seconds(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(unix: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(unix, 0).unwrap()
    }

    #[test]
    fn rotate_at_from_window_is_eighty_percent_through_the_lifetime() {
        // 1000s lifetime ⇒ rotate at iat + 800s.
        let iat = 1_000_000;
        assert_eq!(
            rotate_at_from_window(ts(iat), ts(iat + 1000)),
            ts(iat + 800)
        );
    }

    #[test]
    fn rotate_at_from_window_degenerate_lifetime_is_iat() {
        // Zero / negative window ⇒ rotate now (at iat).
        let iat = 3_000_000;
        assert_eq!(rotate_at_from_window(ts(iat), ts(iat)), ts(iat));
        assert_eq!(rotate_at_from_window(ts(iat), ts(iat - 500)), ts(iat));
    }

    use crate::credentials::{
        BootstrapError, BootstrapInput, BootstrapOutcome, Capability, DeployerCredentials,
        RequirementsReport, RulesPack, ValidationContext, ZeroizedAdmin,
    };
    use crate::environment::EnvironmentStore;
    use greentic_deploy_spec::{CapabilitySlot, SecretRef};

    /// A deployer credentials fake that mints a (configurable) bearer +
    /// expiry on `bootstrap` — the re-mint engine `run_rotate` drives. Its
    /// `rotate_at` is a plain field, decoupling the engine's rotate-point
    /// wiring from any backend's material-decode format.
    #[derive(Debug)]
    struct MintingCreds {
        bearer: Option<String>,
        expiry: Option<DateTime<Utc>>,
        bound_ref: Option<String>,
        rotate_at: Option<DateTime<Utc>>,
    }

    impl DeployerCredentials for MintingCreds {
        fn bound_credential_store_path(&self) -> Option<&'static str> {
            None
        }

        fn required_capabilities(&self) -> Vec<Capability> {
            vec![]
        }
        fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
            unreachable!("rotation never validates")
        }
        fn rotate_at(&self, _material: &str) -> Option<DateTime<Utc>> {
            self.rotate_at
        }
        fn bootstrap(
            &self,
            _input: &BootstrapInput<'_>,
        ) -> Result<BootstrapOutcome, BootstrapError> {
            Ok(BootstrapOutcome {
                rules_pack: RulesPack::empty(),
                bound_credentials_ref: self
                    .bound_ref
                    .as_ref()
                    .map(|u| SecretRef::try_new(u.as_str()).unwrap()),
                bound_expiry: self.expiry,
                bound_secret_material: self
                    .bearer
                    .as_ref()
                    .map(|b| zeroize::Zeroizing::new(b.clone())),
            })
        }
    }

    fn bootstrapped_env_store() -> (tempfile::TempDir, LocalFsStore, &'static str) {
        use crate::cli::tests_common::{make_binding, make_env};
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@0.1.0",
        ));
        let ref_uri = "secret://local/default/_/k8s-deployer/deployer_token";
        env.credentials_ref = Some(SecretRef::try_new(ref_uri).unwrap());
        store.save(&env).unwrap();
        (dir, store, ref_uri)
    }

    #[test]
    fn run_rotate_remints_persists_material_and_refreshes_expiry() {
        use std::cell::RefCell;

        let (_dir, store, ref_uri) = bootstrapped_env_store();
        let iat = 5_000_000;
        let bearer = "bound-token-material".to_string();
        let creds = MintingCreds {
            bearer: Some(bearer.clone()),
            expiry: Some(ts(iat + 1000)),
            bound_ref: Some(ref_uri.to_string()),
            rotate_at: Some(ts(iat + 800)),
        };
        let written: RefCell<Option<(String, String)>> = RefCell::new(None);
        let sink = |_root: &std::path::Path, r: &SecretRef, v: &str| -> Result<(), String> {
            *written.borrow_mut() = Some((r.as_str().to_string(), v.to_string()));
            Ok(())
        };

        let outcome = run_rotate(
            &store,
            &EnvPackRegistry::with_builtins(),
            &"local".try_into().unwrap(),
            &ZeroizedAdmin::new("admin-ctx", "material".to_string()),
            &creds,
            &sink,
        )
        .expect("rotate succeeds");

        // Fresh bearer persisted to the sink at the (unchanged) bound ref.
        let (wrote_ref, wrote_val) = written.into_inner().expect("sink invoked");
        assert_eq!(wrote_ref, ref_uri);
        assert_eq!(wrote_val, bearer);
        // Expiry surfaces with rotate_at at 80% of the minted token's lifetime.
        let expiry = outcome.expiry.expect("bounded expiry");
        assert_eq!(
            expiry.expires_at,
            DateTime::from_timestamp(iat + 1000, 0).unwrap()
        );
        assert_eq!(
            expiry.rotate_at,
            Some(DateTime::from_timestamp(iat + 800, 0).unwrap())
        );
        assert_eq!(outcome.credentials_ref.as_str(), ref_uri);
        // The env's credentials_ref is unchanged — rotation overwrites the
        // material in place, it does not re-point the ref.
        let reloaded = store.load(&"local".try_into().unwrap()).unwrap();
        assert_eq!(
            reloaded.credentials_ref.as_ref().map(|r| r.as_str()),
            Some(ref_uri)
        );
    }

    #[test]
    fn run_rotate_writes_to_the_active_ref_not_the_minted_ref() {
        use crate::cli::tests_common::{make_binding, make_env};
        use std::cell::RefCell;

        // Env's active `credentials_ref` differs from the deployer's default
        // minted ref (an out-of-band binding). Rotation must write the fresh
        // token where the RESOLVER reads (the active ref), not where the
        // deployer minted — otherwise live verbs keep the stale token.
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@0.1.0",
        ));
        let active_ref = "secret://local/default/_/custom/active-token";
        let minted_ref = "secret://local/default/_/k8s-deployer/deployer_token";
        env.credentials_ref = Some(SecretRef::try_new(active_ref).unwrap());
        store.save(&env).unwrap();

        let iat = 7_000_000;
        let bearer = "bound-token-material".to_string();
        let creds = MintingCreds {
            bearer: Some(bearer.clone()),
            expiry: Some(ts(iat + 1000)),
            bound_ref: Some(minted_ref.to_string()), // deployer mints at its default
            rotate_at: None,
        };
        let written: RefCell<Option<(String, String)>> = RefCell::new(None);
        let sink = |_root: &std::path::Path, r: &SecretRef, v: &str| -> Result<(), String> {
            *written.borrow_mut() = Some((r.as_str().to_string(), v.to_string()));
            Ok(())
        };

        let outcome = run_rotate(
            &store,
            &EnvPackRegistry::with_builtins(),
            &"local".try_into().unwrap(),
            &ZeroizedAdmin::new("admin-ctx", "material".to_string()),
            &creds,
            &sink,
        )
        .expect("rotate succeeds");

        let (wrote_ref, wrote_val) = written.into_inner().expect("sink invoked");
        assert_eq!(
            wrote_ref, active_ref,
            "fresh token must land at the env's active ref, not the deployer's minted ref"
        );
        assert_eq!(wrote_val, bearer);
        assert_eq!(outcome.credentials_ref.as_str(), active_ref);
    }

    #[test]
    fn run_rotate_rejects_a_render_only_deployer() {
        let (_dir, store, _ref_uri) = bootstrapped_env_store();
        // No bound material minted ⇒ nothing to rotate.
        let creds = MintingCreds {
            bearer: None,
            expiry: None,
            bound_ref: None,
            rotate_at: None,
        };
        let sink = |_root: &std::path::Path, _r: &SecretRef, _v: &str| -> Result<(), String> {
            panic!("sink must not be called when there is no material to persist")
        };
        let err = run_rotate(
            &store,
            &EnvPackRegistry::with_builtins(),
            &"local".try_into().unwrap(),
            &ZeroizedAdmin::new("admin-ctx", "material".to_string()),
            &creds,
            &sink,
        )
        .unwrap_err();
        assert!(
            matches!(err, RunRotateError::RotationUnsupported(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn run_rotate_rejects_an_env_without_a_credentials_ref() {
        use crate::cli::tests_common::{make_binding, make_env};
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@0.1.0",
        ));
        store.save(&env).unwrap(); // no credentials_ref
        let creds = MintingCreds {
            bearer: None,
            expiry: None,
            bound_ref: None,
            rotate_at: None,
        };
        let sink = |_root: &std::path::Path, _r: &SecretRef, _v: &str| -> Result<(), String> {
            unreachable!("precondition fails before any persist")
        };
        let err = run_rotate(
            &store,
            &EnvPackRegistry::with_builtins(),
            &"local".try_into().unwrap(),
            &ZeroizedAdmin::new("admin-ctx", "material".to_string()),
            &creds,
            &sink,
        )
        .unwrap_err();
        assert!(
            matches!(err, RunRotateError::NotBootstrapped(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rotation_due_is_false_before_threshold_and_true_at_or_after() {
        let creds = MintingCreds {
            bearer: None,
            expiry: None,
            bound_ref: None,
            rotate_at: Some(ts(2_000_800)),
        };
        assert!(
            !creds.rotation_due("material", ts(2_000_799)),
            "before threshold: not due"
        );
        assert!(
            creds.rotation_due("material", ts(2_000_800)),
            "at threshold: due"
        );
        assert!(
            creds.rotation_due("material", ts(2_000_801)),
            "after threshold: due"
        );
    }

    #[test]
    fn rotation_due_fails_open_when_rotate_at_is_none() {
        // A deployer whose material carries no decodable lifetime is always
        // treated as due, so `--if-needed` never silently skips it.
        let creds = MintingCreds {
            bearer: None,
            expiry: None,
            bound_ref: None,
            rotate_at: None,
        };
        assert!(creds.rotation_due("opaque", ts(0)));
        assert!(creds.rotation_due("", ts(1_000_000)));
    }
}
