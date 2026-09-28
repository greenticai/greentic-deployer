//! Enforced drain (P5-R2): the shared half every deployer uses.
//!
//! Retiring a revision is a sequence, not a delete: clear its traffic weight
//! → drain (wait the revision's `drain_seconds`, then CONFIRM it serves
//! nothing) → archive → remove. This module owns the provider-agnostic part:
//!
//! - [`DrainPolicy`] — how long a drain may wait (bounded, configurable) and
//!   how long it keeps probing for confirmation afterwards.
//! - [`DrainEvidence`] — what the provider showed that proves the drain.
//! - [`confirm_within`] — the probe loop: a probe that stays
//!   [`DrainProbe::Pending`] past the confirm deadline becomes a typed
//!   [`DeployerError::NotDrained`] naming the revision.
//! - [`require_unrouted`] — the pure-spec precondition an adapter that stops
//!   the revision's workers (K8s) runs first, so it never scales down a
//!   revision the recorded split still sends traffic to.
//!
//! The per-provider probe (K8s ready endpoints, Cloud Run live traffic
//! percent) lives with each env-pack.

use std::future::Future;
use std::time::Duration;

use greentic_deploy_spec::{Environment, Revision, RevisionId};
use serde::Serialize;
use tokio::time::{Instant, sleep};

use super::trait_def::DeployerError;

/// Env override (whole seconds) for [`DrainPolicy::max_wait`]: the upper bound
/// on the drain window, whatever a revision's `drain_seconds` asks for.
pub const DRAIN_MAX_WAIT_ENV: &str = "GREENTIC_DEPLOYER_DRAIN_MAX_SECONDS";

/// Env override (whole seconds) for [`DrainPolicy::confirm_timeout`].
pub const DRAIN_CONFIRM_TIMEOUT_ENV: &str = "GREENTIC_DEPLOYER_DRAIN_CONFIRM_TIMEOUT_SECS";

/// Default cap on the drain window (10 minutes). A revision recording a
/// longer `drain_seconds` waits this long, never longer — a drain verb must
/// not hold an operator's terminal (or a rollout lease) open unboundedly.
pub const DEFAULT_DRAIN_MAX_WAIT: Duration = Duration::from_secs(600);

/// Default time allowed, after the window, for the provider to report the
/// revision drained (pods terminating, a traffic write settling).
pub const DEFAULT_DRAIN_CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

/// Hard ceiling on any drain duration read from the environment (24 h). Keeps
/// an absurd override from overflowing `Instant` arithmetic.
pub const DRAIN_DURATION_CEILING: Duration = Duration::from_secs(24 * 60 * 60);

/// Poll cadence while waiting for confirmation.
pub const DEFAULT_DRAIN_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How a drain waits and confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainPolicy {
    /// Upper bound on the drain window (`min(drain_seconds, max_wait)`).
    pub max_wait: Duration,
    /// How long confirmation may keep probing after the window.
    pub confirm_timeout: Duration,
    /// Delay between confirmation probes.
    pub poll_interval: Duration,
}

impl Default for DrainPolicy {
    fn default() -> Self {
        Self {
            max_wait: DEFAULT_DRAIN_MAX_WAIT,
            confirm_timeout: DEFAULT_DRAIN_CONFIRM_TIMEOUT,
            poll_interval: DEFAULT_DRAIN_POLL_INTERVAL,
        }
    }
}

impl DrainPolicy {
    /// Defaults, with [`DRAIN_MAX_WAIT_ENV`] / [`DRAIN_CONFIRM_TIMEOUT_ENV`]
    /// applied when set to a parseable seconds value. An unparseable value
    /// falls back to the default rather than to zero: a typo must not turn a
    /// drain into an immediate teardown.
    pub fn from_env() -> Self {
        let read = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(|secs| Duration::from_secs(secs).min(DRAIN_DURATION_CEILING))
        };
        let default = Self::default();
        Self {
            max_wait: read(DRAIN_MAX_WAIT_ENV).unwrap_or(default.max_wait),
            confirm_timeout: read(DRAIN_CONFIRM_TIMEOUT_ENV).unwrap_or(default.confirm_timeout),
            poll_interval: default.poll_interval,
        }
    }

    /// No wait, a single confirmation probe. For tests and for the archive
    /// gate, which checks the provider state as it is right now.
    pub fn immediate() -> Self {
        Self {
            max_wait: Duration::ZERO,
            confirm_timeout: Duration::ZERO,
            poll_interval: Duration::ZERO,
        }
    }

    /// The drain window for `revision`: its recorded `drain_seconds`, capped at
    /// [`Self::max_wait`].
    pub fn window(&self, revision: &Revision) -> Duration {
        Duration::from_secs(u64::from(revision.drain_seconds))
            .min(self.max_wait)
            .min(DRAIN_DURATION_CEILING)
    }
}

/// What the provider showed that proves a revision is drained.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DrainEvidence {
    /// The adapter cannot confirm a drain (capability `drain` is false). The
    /// default so a deployer that never looked cannot claim it did.
    #[default]
    Unsupported,
    /// K8s: the revision's worker Deployment runs no pod, so its Service has
    /// zero ready endpoints. The router exposes no per-revision in-flight
    /// count, so this is the confirmation signal (see `docs/k8s-deployment.md`).
    ZeroReadyEndpoints {
        /// Worker Deployment name.
        deployment: String,
        /// `true` when the Deployment does not exist at all.
        absent: bool,
    },
    /// Cloud Run whole-bundle retire: the deployment is retiring and no
    /// messaging endpoint references its bundle, so after the window the
    /// whole Service is deleted (its last revision can never reach 0 %).
    ServiceRetiring {
        /// Cloud Run Service name.
        service: String,
    },
    /// The drain gate was skipped with `--force-drain`; nothing was confirmed.
    Forced,
    /// Cloud Run: the Service's live `traffic[]` gives the revision 0 %.
    ZeroTrafficPercent {
        /// Cloud Run Service name.
        service: String,
        /// `true` when the Service does not exist at all.
        service_absent: bool,
    },
}

/// One confirmation probe's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainProbe {
    /// Drained, with the evidence.
    Drained(DrainEvidence),
    /// Not drained yet; the detail names what is still serving.
    Pending(String),
}

/// Weight (bps) the recorded traffic split still routes to `revision_id`.
pub fn recorded_weight_bps(env: &Environment, revision_id: RevisionId) -> u32 {
    env.traffic_splits
        .iter()
        .flat_map(|s| s.entries.iter())
        .filter(|e| e.revision_id == revision_id)
        .map(|e| e.weight_bps)
        .sum()
}

/// Pure-spec drain precondition: the recorded split routes nothing to the
/// revision. Checked BEFORE any provider call by adapters whose drain stops
/// the revision's workers — draining a routed revision is an outage.
pub fn require_unrouted(env: &Environment, revision_id: RevisionId) -> Result<(), DeployerError> {
    let weight = recorded_weight_bps(env, revision_id);
    if weight == 0 {
        return Ok(());
    }
    Err(DeployerError::NotDrained {
        revision_id,
        reason: format!(
            "the recorded traffic split still routes {weight} bps to it; move its weight \
             to the surviving revisions first (`op traffic set`), then drain"
        ),
    })
}

/// Probe until the revision reports drained or `policy.confirm_timeout`
/// elapses. Always probes at least once, so [`DrainPolicy::immediate`] is a
/// single point-in-time check.
pub async fn confirm_within<F, Fut>(
    revision_id: RevisionId,
    policy: &DrainPolicy,
    mut probe: F,
) -> Result<DrainEvidence, DeployerError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<DrainProbe, DeployerError>>,
{
    let timeout = policy.confirm_timeout.min(DRAIN_DURATION_CEILING);
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        match probe().await? {
            DrainProbe::Drained(evidence) => return Ok(evidence),
            DrainProbe::Pending(detail) => {
                if Instant::now() >= deadline {
                    return Err(DeployerError::NotDrained {
                        revision_id,
                        reason: detail,
                    });
                }
            }
        }
        sleep(policy.poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    #[test]
    fn window_is_capped_by_max_wait() {
        let env = build_fixture_env();
        let mut rev = env.revisions[1].clone();
        rev.drain_seconds = 900;
        let policy = DrainPolicy {
            max_wait: Duration::from_secs(60),
            ..DrainPolicy::default()
        };
        assert_eq!(policy.window(&rev), Duration::from_secs(60));
        rev.drain_seconds = 5;
        assert_eq!(policy.window(&rev), Duration::from_secs(5));
        assert_eq!(DrainPolicy::immediate().window(&rev), Duration::ZERO);
    }

    #[test]
    fn require_unrouted_names_the_revision_and_its_weight() {
        let env = build_fixture_env();
        let r = env.revisions[1].revision_id;
        let err = require_unrouted(&env, r).unwrap_err();
        assert!(err.to_string().contains(&r.to_string()), "{err}");
        match err {
            DeployerError::NotDrained {
                revision_id,
                reason,
            } => {
                assert_eq!(revision_id, r);
                assert!(reason.contains("5000 bps"), "{reason}");
            }
            other => panic!("expected NotDrained, got {other:?}"),
        }
    }

    #[test]
    fn require_unrouted_passes_for_a_zero_weight_revision() {
        let mut env = build_fixture_env();
        env.traffic_splits[0].entries[0].weight_bps = 10_000;
        env.traffic_splits[0].entries[1].weight_bps = 0;
        require_unrouted(&env, env.revisions[1].revision_id).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn confirm_within_retries_until_drained() {
        let env = build_fixture_env();
        let r = env.revisions[1].revision_id;
        let mut calls = 0;
        let policy = DrainPolicy {
            confirm_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(2),
            ..DrainPolicy::default()
        };
        let evidence = confirm_within(r, &policy, || {
            calls += 1;
            let n = calls;
            async move {
                Ok(if n < 3 {
                    DrainProbe::Pending("1 pod".into())
                } else {
                    DrainProbe::Drained(DrainEvidence::ZeroReadyEndpoints {
                        deployment: "w".into(),
                        absent: false,
                    })
                })
            }
        })
        .await
        .unwrap();
        assert!(matches!(evidence, DrainEvidence::ZeroReadyEndpoints { .. }));
        assert_eq!(calls, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn confirm_within_times_out_with_a_typed_error() {
        let env = build_fixture_env();
        let r = env.revisions[1].revision_id;
        let policy = DrainPolicy {
            confirm_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_secs(2),
            ..DrainPolicy::default()
        };
        let err = confirm_within(r, &policy, || async {
            Ok(DrainProbe::Pending("2 pods still running".into()))
        })
        .await
        .unwrap_err();
        assert!(
            matches!(err, DeployerError::NotDrained { revision_id, ref reason }
                if revision_id == r && reason.contains("2 pods")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn immediate_policy_probes_exactly_once() {
        let env = build_fixture_env();
        let r = env.revisions[1].revision_id;
        let mut calls = 0;
        let err = confirm_within(r, &DrainPolicy::immediate(), || {
            calls += 1;
            async { Ok(DrainProbe::Pending("serving".into())) }
        })
        .await
        .unwrap_err();
        assert!(matches!(err, DeployerError::NotDrained { .. }));
        assert_eq!(calls, 1);
    }
}
