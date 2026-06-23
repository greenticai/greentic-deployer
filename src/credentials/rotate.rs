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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    #[error(
        "deployer env-pack `{kind}` has no native credentials handler registered (Phase D plug-in)"
    )]
    HandlerNotRegistered { kind: String },
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
        // check). Without a ref there is nothing to rotate.
        if env.credentials_ref.is_none() {
            return Err(RunRotateError::NotBootstrapped(env_id.clone()));
        }

        // Resolve the handler unconditionally so the A9 slot/version match
        // still runs; the admin-connected override then provides the actual
        // re-mint path (mirrors `run_bootstrap`).
        let _handler = registry.resolve_for_slot(CapabilitySlot::Deployer, &deployer.kind)?;
        let deployer_kind = deployer.kind.clone();

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

        let (Some(bound_ref), Some(material)) = (
            outcome.bound_credentials_ref.as_ref(),
            outcome.bound_secret_material.as_ref(),
        ) else {
            return Err(RunRotateError::RotationUnsupported(format!(
                "deployer env-pack `{}` minted no bound material to rotate; live rotation is \
                 supported only for the K8s `--bind` credential",
                deployer_kind.as_str()
            )));
        };

        // Overwrite the dev-store material BEFORE returning success (the
        // in-cluster Secret was already overwritten inside `bootstrap`). The
        // ref URI is unchanged, so `env.credentials_ref` is NOT rewritten.
        secret_sink(&env_root, bound_ref, material.as_str())
            .map_err(RunRotateError::SecretWrite)?;

        let expiry = outcome.bound_expiry.map(|expires_at| CredentialsExpiry {
            expires_at,
            rotate_at: rotate_at_for(material.as_str()),
        });

        Ok(RotateOutcome {
            credentials_ref: bound_ref.clone(),
            expiry,
        })
    })
}

/// Whether a bound bearer is at/past its rotation point (≥ 80% of lifetime
/// elapsed). Fails OPEN: a token whose lifetime claims can't be decoded is
/// treated as due, so `--if-needed` errs toward rotating rather than letting
/// an opaque token silently lapse.
pub fn rotation_due(bearer: &str, now: DateTime<Utc>) -> bool {
    match rotate_at_for(bearer) {
        Some(rotate_at) => now >= rotate_at,
        None => true,
    }
}

/// The absolute time a bound bearer should be rotated: `iat + lifetime*0.8`,
/// derived from the token's own `iat`/`exp` claims. `None` when the bearer
/// is not a decodable JWT with both claims.
fn rotate_at_for(bearer: &str) -> Option<DateTime<Utc>> {
    let (iat, exp) = decode_token_lifetime(bearer)?;
    let lifetime_secs = (exp - iat).num_seconds();
    if lifetime_secs <= 0 {
        // Degenerate / already-expired window — rotate now.
        return Some(iat);
    }
    let offset = (lifetime_secs as f64 * ROTATE_AT_LIFETIME_FRACTION) as i64;
    Some(iat + chrono::Duration::seconds(offset))
}

/// Decode a JWT bearer's `iat`/`exp` claims (the projected ServiceAccount
/// token is a signed JWT). Signature is NOT verified — this reads OUR OWN
/// token's self-reported lifetime to schedule a proactive re-mint, never to
/// authorize anything. Returns `None` on any structural failure.
fn decode_token_lifetime(bearer: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let payload_b64 = bearer.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let iat = DateTime::from_timestamp(claims.get("iat")?.as_i64()?, 0)?;
    let exp = DateTime::from_timestamp(claims.get("exp")?.as_i64()?, 0)?;
    Some((iat, exp))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a JWT-shaped bearer carrying the given `iat`/`exp` unix seconds
    /// (header + signature are inert — only the payload is decoded).
    fn fake_jwt(iat: i64, exp: i64) -> String {
        let payload = serde_json::json!({ "iat": iat, "exp": exp, "sub": "system:serviceaccount" });
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("aGVhZGVy.{body}.c2ln")
    }

    #[test]
    fn rotate_at_is_eighty_percent_through_the_lifetime() {
        // 1000s lifetime ⇒ rotate at iat + 800s.
        let iat = 1_000_000;
        let bearer = fake_jwt(iat, iat + 1000);
        let rotate_at = rotate_at_for(&bearer).expect("decodable");
        assert_eq!(rotate_at, DateTime::from_timestamp(iat + 800, 0).unwrap());
    }

    #[test]
    fn rotation_due_false_before_threshold_true_after() {
        let iat = 2_000_000;
        let bearer = fake_jwt(iat, iat + 1000); // rotate_at = iat + 800
        let before = DateTime::from_timestamp(iat + 799, 0).unwrap();
        let at = DateTime::from_timestamp(iat + 800, 0).unwrap();
        assert!(!rotation_due(&bearer, before), "799s in: not due");
        assert!(rotation_due(&bearer, at), "800s in: due (>= threshold)");
    }

    #[test]
    fn rotation_due_fails_open_for_an_opaque_token() {
        // Not a JWT, no claims, empty — every shape must be treated as due
        // so `--if-needed` never silently skips an undecodable token.
        let now = Utc::now();
        assert!(rotation_due("not-a-jwt", now));
        assert!(rotation_due("", now));
        assert!(rotation_due("a.b.c", now), "non-base64 payload");
    }

    #[test]
    fn rotate_at_for_degenerate_lifetime_is_iat() {
        let iat = 3_000_000;
        let bearer = fake_jwt(iat, iat); // zero lifetime
        assert_eq!(
            rotate_at_for(&bearer),
            Some(DateTime::from_timestamp(iat, 0).unwrap())
        );
    }

    use crate::credentials::{
        BootstrapError, BootstrapInput, BootstrapOutcome, Capability, DeployerCredentials,
        RequirementsReport, RulesPack, ValidationContext, ZeroizedAdmin,
    };
    use crate::environment::EnvironmentStore;
    use greentic_deploy_spec::{CapabilitySlot, SecretRef};

    /// A deployer credentials fake that mints a (configurable) bearer +
    /// expiry on `bootstrap` — the re-mint engine `run_rotate` drives.
    #[derive(Debug)]
    struct MintingCreds {
        bearer: Option<String>,
        expiry: Option<DateTime<Utc>>,
        bound_ref: Option<String>,
    }

    impl DeployerCredentials for MintingCreds {
        fn required_capabilities(&self) -> Vec<Capability> {
            vec![]
        }
        fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
            unreachable!("rotation never validates")
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
        let bearer = fake_jwt(iat, iat + 1000); // rotate_at = iat + 800
        let creds = MintingCreds {
            bearer: Some(bearer.clone()),
            expiry: Some(DateTime::from_timestamp(iat + 1000, 0).unwrap()),
            bound_ref: Some(ref_uri.to_string()),
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
    fn run_rotate_rejects_a_render_only_deployer() {
        let (_dir, store, _ref_uri) = bootstrapped_env_store();
        // No bound material minted ⇒ nothing to rotate.
        let creds = MintingCreds {
            bearer: None,
            expiry: None,
            bound_ref: None,
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
}
