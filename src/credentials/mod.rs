//! C1: credentials contract for deployer env-packs.
//!
//! Every deployer env-pack ships a [`DeployerCredentials`] implementation
//! that declares what capabilities its credentials must satisfy and how to
//! probe them. Phase A's CLI surface (`gtc op credentials …`) drives this
//! contract through the env-pack registry — `requirements` validates against
//! the bound deployer, `bootstrap` runs the deployer's bootstrap path.
//!
//! Admin credentials are never intentionally persisted. The
//! [`ZeroizedAdmin`] wrapper zeroizes its in-process buffer on drop where
//! the language/runtime allows it. The contract is honest about what it
//! cannot guarantee: process-wide memory erasure is impossible (the OS may
//! have paged the buffer, the cloud SDK may hold its own copy, ambient
//! profile chains live outside our control). Callers should run on
//! short-lived processes when this matters.
//!
//! ## Phase A constraint
//!
//! Env-pack handlers are metadata-only in Phase A (see
//! [`env_packs::slot`](crate::env_packs::slot)) — there is no wired secrets
//! backend yet. Probes that need credential material (reading a key from
//! AWS-SM, calling AWS STS) cannot run today; impls report
//! [`CapabilityStatus::Skipped`] for those entries instead of panicking.
//! Local-process credentials work today because they probe only the local
//! environment (filesystem writability, port availability) and need no
//! credential material at all (C2).

pub mod bootstrap;
pub mod rotate;
pub mod rules_export;
pub mod store_paths;
pub mod validate;

pub use bootstrap::{
    BootstrapError, BootstrapInput, BootstrapOutcome, BoundSecretSink, RunBootstrapError,
    ZeroizedAdmin, run_bootstrap,
};
pub use rotate::{RotateOutcome, RunRotateError, run_rotate};
pub use rules_export::{RulesExportError, RulesPack, RulesPackEntry, write_rules_pack};
pub use validate::{
    Capability, CapabilityCheck, CapabilityStatus, RequirementsReport, ValidateError,
    ValidationContext, validate_requirements,
};

use chrono::{DateTime, Utc};

/// Contract a deployer env-pack handler implements to surface its
/// credentials story to the `gtc op credentials` CLI.
///
/// Object-safe so the env-pack registry can return `&dyn`. Implementations
/// must be `Send + Sync` because the registry is shared across the
/// operator's request handlers.
pub trait DeployerCredentials: std::fmt::Debug + Send + Sync {
    /// Whether this deployer requires real credential material at all.
    ///
    /// Deployers that run purely locally (e.g. local-process — no IAM
    /// roles, no cluster RBAC, no cloud credentials) return `false`.
    /// When `false`:
    /// - `validate_requirements` skips the `NoCredentialsRef` rejection
    ///   for envs that have no `credentials_ref`.
    /// - `bootstrap` should return [`BootstrapError::NotApplicable`].
    ///
    /// Default is `true`, preserving Phase D AWS/K8s/GCP/Azure behavior.
    fn requires_credentials_material(&self) -> bool {
        true
    }

    /// The set of capabilities the deployer's credentials must satisfy.
    /// Order is stable — the CLI renders this as the column order in
    /// `gtc op credentials requirements` output. Used both as the
    /// declaration of what *would* be checked (`--schema`-like surface) and
    /// as the iteration order for [`validate`](Self::validate).
    fn required_capabilities(&self) -> Vec<Capability>;

    /// Probe the env's local state against [`required_capabilities`]. The
    /// validator MUST NOT mutate `ctx` and MUST NOT panic on probe failure;
    /// it returns a structured [`Failed`](CapabilityStatus::Fail) or
    /// [`Skipped`](CapabilityStatus::Skipped) entry instead.
    fn validate(&self, ctx: &ValidationContext<'_>) -> RequirementsReport;

    /// Run the deployer's bootstrap path against ephemeral admin
    /// credentials.
    ///
    /// Implementations with no admin escalation (e.g. the local-process
    /// deployer — there are no IAM roles or cluster RBAC to provision
    /// locally) MUST return [`BootstrapError::NotApplicable`] with a
    /// message telling the user to run `requirements` instead. Returning
    /// `Ok` with an empty outcome would be dishonest (no admin was
    /// actually consumed) and would leave a sentinel `credentials_ref`
    /// pointing at nothing.
    fn bootstrap(&self, input: &BootstrapInput<'_>) -> Result<BootstrapOutcome, BootstrapError>;

    /// Best-effort compensating cleanup for a bootstrap that wrote durable
    /// credential material to a REMOTE backend (e.g. the K8s `--bind` path
    /// writes the minted bearer into an in-cluster Secret) but then failed a
    /// later persistence step. Without this a failed bootstrap could leave a
    /// live bearer in the backend while the env stays unbound. The CLI calls it
    /// on the bootstrap error path; the delete is idempotent (a never-written
    /// Secret 404s harmlessly), so an unconditional call is safe.
    ///
    /// Default is a no-op — deployers that bind no remote material (the
    /// local-process / render-only paths) have nothing to undo. Implementations
    /// MUST NOT panic; cleanup failures are swallowed (the caller already has a
    /// bootstrap error to report). It does NOT cover a hard process crash
    /// between the remote write and the local commit — short-lived bound tokens
    /// + rotation are the systemic mitigation for that residual window.
    fn rollback_bound_material(&self, _env_id: &greentic_deploy_spec::EnvId) {}

    /// The absolute time the given bound credential *material* should be
    /// rotated, derived from the material's own self-reported lifetime (e.g.
    /// the K8s projected-ServiceAccount-token JWT's `iat`/`exp` claims).
    /// Returns `None` when the lifetime can't be determined.
    ///
    /// Default is `None`: deployers that mint no time-bounded material (the
    /// render-only / local paths, and AWS until its STS producer lands) have
    /// no rotation point to compute. Backends that mint bounded credentials
    /// override this to decode their own material format — the rotation
    /// *policy* (rotate at 80% of lifetime) stays shared in
    /// [`rotate::rotate_at_from_window`], only the decode varies.
    fn rotate_at(&self, _material: &str) -> Option<DateTime<Utc>> {
        None
    }

    /// Whether the given bound material is at/past its rotation point.
    ///
    /// Fails OPEN: material whose lifetime can't be decoded
    /// ([`rotate_at`](Self::rotate_at) returns `None`) is treated as due, so
    /// `op credentials rotate --if-needed` errs toward rotating rather than
    /// letting an opaque token silently lapse. The policy lives here; only the
    /// per-backend `rotate_at` decode is overridden, so impls should not need
    /// to override this.
    fn rotation_due(&self, material: &str, now: DateTime<Utc>) -> bool {
        match self.rotate_at(material) {
            Some(rotate_at) => now >= rotate_at,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Minimal stub implementing the trait with all defaults, so the
    /// default-method coverage is exercised without a real deployer.
    #[derive(Debug)]
    struct StubCredentials;

    impl DeployerCredentials for StubCredentials {
        fn required_capabilities(&self) -> Vec<Capability> {
            vec![]
        }

        fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
            RequirementsReport { checks: vec![] }
        }

        fn bootstrap(
            &self,
            _input: &BootstrapInput<'_>,
        ) -> Result<BootstrapOutcome, BootstrapError> {
            Err(BootstrapError::NotApplicable(
                "stub has no bootstrap".into(),
            ))
        }
    }

    /// Stub that overrides `rotate_at` to return a fixed point.
    #[derive(Debug)]
    struct TimedCredentials {
        rotate_at: DateTime<Utc>,
    }

    impl DeployerCredentials for TimedCredentials {
        fn required_capabilities(&self) -> Vec<Capability> {
            vec![]
        }

        fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
            RequirementsReport { checks: vec![] }
        }

        fn bootstrap(
            &self,
            _input: &BootstrapInput<'_>,
        ) -> Result<BootstrapOutcome, BootstrapError> {
            Err(BootstrapError::NotApplicable("stub".into()))
        }

        fn rotate_at(&self, _material: &str) -> Option<DateTime<Utc>> {
            Some(self.rotate_at)
        }
    }

    #[test]
    fn default_requires_credentials_material_is_true() {
        let stub = StubCredentials;
        assert!(stub.requires_credentials_material());
    }

    #[test]
    fn default_rotate_at_returns_none() {
        let stub = StubCredentials;
        assert!(stub.rotate_at("any-material").is_none());
    }

    #[test]
    fn default_rotation_due_fails_open_when_rotate_at_is_none() {
        let stub = StubCredentials;
        let now = Utc::now();
        assert!(
            stub.rotation_due("opaque-token", now),
            "rotation_due must fail open (true) when rotate_at returns None"
        );
    }

    #[test]
    fn rotation_due_false_before_rotate_at() {
        let rotate_at = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        let creds = TimedCredentials { rotate_at };
        let now = Utc::now();
        assert!(
            !creds.rotation_due("material", now),
            "rotation should not be due when rotate_at is in the future"
        );
    }

    #[test]
    fn rotation_due_true_at_or_after_rotate_at() {
        let rotate_at = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let creds = TimedCredentials { rotate_at };
        let now = Utc::now();
        assert!(
            creds.rotation_due("material", now),
            "rotation should be due when rotate_at is in the past"
        );
    }

    #[test]
    fn default_rollback_bound_material_is_noop() {
        let stub = StubCredentials;
        let env_id = greentic_deploy_spec::EnvId::try_from("local").unwrap();
        // Must not panic.
        stub.rollback_bound_material(&env_id);
    }
}
