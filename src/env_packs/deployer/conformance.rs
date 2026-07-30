//! Black-box conformance bench for [`Deployer`] impls.
//!
//! [`run_conformance`] drives a candidate deployer through a small fixed
//! [`Environment`] and asserts the contract documented on the trait:
//! idempotency on every verb, structured rejection of `sum != 10000bps`
//! splits, independence across `deployment_id`, and projection
//! consistency for `report_runtime_config`. K8s/AWS slices call this
//! from a single integration test as the entry gate to declaring the
//! impl done.
//!
//! The fixture builds a 2-deployment / 3-revision env in memory — no
//! [`crate::environment::LocalFsStore`], no filesystem, no clock — so the
//! same harness runs identically against an in-process local-process
//! deployer and a kubectl-shelling-out K8s deployer.

use chrono::{TimeZone, Utc};
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
    Environment, EnvironmentHostConfig, PackId, PackListEntry, PartyId, RevenueShareEntry,
    Revision, RevisionId, RevisionLifecycle, RouteBinding, SchemaVersion, TenantSelector,
    TrafficSplit, TrafficSplitEntry,
};
use thiserror::Error;
use ulid::Ulid;

use super::trait_def::{Deployer, DeployerError};

/// What can go wrong while running the bench.
///
/// Each variant pins the exact contract clause that failed so the
/// failing impl's author has a single line to chase.
#[derive(Debug, Error)]
pub enum ConformanceFailure {
    #[error("{verb}: first call returned Err: {source}")]
    HappyPathFailed {
        verb: &'static str,
        source: DeployerError,
    },

    #[error("{verb}: idempotent second call returned Err (impl is not idempotent): {source}")]
    NotIdempotent {
        verb: &'static str,
        source: DeployerError,
    },

    #[error(
        "apply_traffic_split: expected `DeployerError::InvalidSplit` for a sum={sum} split, got `Ok(_)` instead"
    )]
    InvalidSplitAccepted { sum: u64 },

    #[error(
        "apply_traffic_split: expected `DeployerError::InvalidSplit` for a sum={sum} split, got a different error variant: {source}"
    )]
    InvalidSplitWrongError { sum: u64, source: DeployerError },

    #[error(
        "apply_traffic_split: expected `DeployerError::SplitNotFound` for a deployment with no recorded split, got `Ok(_)` instead"
    )]
    MissingSplitAccepted,

    #[error(
        "apply_traffic_split: expected `DeployerError::SplitNotFound` for an unrecorded deployment, got a different error variant: {source}"
    )]
    MissingSplitWrongError { source: DeployerError },

    #[error(
        "{verb}: expected `DeployerError::RevisionNotFound` for an unknown revision id, got `Ok(_)` instead"
    )]
    UnknownRevisionAccepted { verb: &'static str },

    #[error(
        "{verb}: expected `DeployerError::RevisionNotFound` for an unknown revision id, got a different error variant: {source}"
    )]
    UnknownRevisionWrongError {
        verb: &'static str,
        source: DeployerError,
    },

    #[error(
        "report_runtime_config: projection does not match `materialize_runtime_config(env)`. \
         Override only if you splice provider-discovered values into existing blocks; do not \
         drop or reshape the spec projection."
    )]
    RuntimeConfigDrift,

    #[error(
        "apply_traffic_split: the impl's self-reported TrafficSplitOutcome does not match the \
         targeted deployment_id or the env's recorded entries (cross-deployment independence \
         violated or wrong deployment applied)"
    )]
    CrossDeploymentInterference,
}

/// Run the conformance bench against `deployer`.
///
/// On success, returns `Ok(())`. On failure, returns a single typed
/// [`ConformanceFailure`] naming the contract clause that broke — the
/// bench short-circuits at the first failure so the caller's test output
/// points at one cause, not a cascade.
pub async fn run_conformance<D: Deployer + ?Sized>(deployer: &D) -> Result<(), ConformanceFailure> {
    let env = build_fixture_env();
    let r_warm = env.revisions[0].revision_id;
    let r_drain = env.revisions[1].revision_id;
    let r_archive = env.revisions[2].revision_id;
    let dep_a = env.bundles[0].deployment_id;
    let dep_b = env.bundles[1].deployment_id;

    check_idempotent(
        "stage_revision",
        || deployer.stage_revision(&env, r_warm),
        || deployer.stage_revision(&env, r_warm),
    )
    .await?;
    check_idempotent(
        "warm_revision",
        || deployer.warm_revision(&env, r_warm, None),
        || deployer.warm_revision(&env, r_warm, None),
    )
    .await?;
    check_idempotent(
        "drain_revision",
        || deployer.drain_revision(&env, r_drain),
        || deployer.drain_revision(&env, r_drain),
    )
    .await?;
    check_idempotent(
        "archive_revision",
        || deployer.archive_revision(&env, r_archive, None),
        || deployer.archive_revision(&env, r_archive, None),
    )
    .await?;

    check_unknown_revision_rejected(deployer).await?;
    check_invalid_split_rejected(deployer).await?;
    check_missing_split_rejected(deployer).await?;

    check_idempotent(
        "apply_traffic_split",
        || deployer.apply_traffic_split(&env, dep_a, None),
        || deployer.apply_traffic_split(&env, dep_a, None),
    )
    .await?;
    check_idempotent(
        "apply_traffic_split[dep_b]",
        || deployer.apply_traffic_split(&env, dep_b, None),
        || deployer.apply_traffic_split(&env, dep_b, None),
    )
    .await?;
    check_cross_deployment_independence(deployer, &env, dep_a, dep_b).await?;

    check_runtime_config_projection(deployer, &env)?;

    Ok(())
}

async fn check_idempotent<T, Fut, F1, F2>(
    verb: &'static str,
    first: F1,
    second: F2,
) -> Result<(), ConformanceFailure>
where
    Fut: std::future::Future<Output = Result<T, DeployerError>>,
    F1: FnOnce() -> Fut,
    F2: FnOnce() -> Fut,
{
    if let Err(source) = first().await {
        return Err(ConformanceFailure::HappyPathFailed { verb, source });
    }
    match second().await {
        Ok(_) => Ok(()),
        Err(source) => Err(ConformanceFailure::NotIdempotent { verb, source }),
    }
}

async fn check_unknown_revision_rejected<D: Deployer + ?Sized>(
    deployer: &D,
) -> Result<(), ConformanceFailure> {
    let env = build_fixture_env();
    // 0xFFFF is distinct from every fixture ULID (those use small
    // single-digit u128 seeds — see `build_fixture_env`).
    let unknown = RevisionId(Ulid::from(0xFFFF_u128));
    classify_unknown_revision(
        "stage_revision",
        deployer.stage_revision(&env, unknown).await.map(|_| ()),
    )?;
    classify_unknown_revision(
        "warm_revision",
        deployer
            .warm_revision(&env, unknown, None)
            .await
            .map(|_| ()),
    )?;
    classify_unknown_revision(
        "drain_revision",
        deployer.drain_revision(&env, unknown).await.map(|_| ()),
    )?;
    classify_unknown_revision(
        "archive_revision",
        deployer
            .archive_revision(&env, unknown, None)
            .await
            .map(|_| ()),
    )?;
    Ok(())
}

fn classify_unknown_revision(
    verb: &'static str,
    result: Result<(), DeployerError>,
) -> Result<(), ConformanceFailure> {
    match result {
        Ok(()) => Err(ConformanceFailure::UnknownRevisionAccepted { verb }),
        Err(DeployerError::RevisionNotFound { .. }) => Ok(()),
        Err(source) => Err(ConformanceFailure::UnknownRevisionWrongError { verb, source }),
    }
}

async fn check_invalid_split_rejected<D: Deployer + ?Sized>(
    deployer: &D,
) -> Result<(), ConformanceFailure> {
    let env = build_env_with_invalid_split();
    let dep = env.bundles[0].deployment_id;
    let sum: u64 = env.traffic_splits[0]
        .entries
        .iter()
        .map(|e| u64::from(e.weight_bps))
        .sum();
    match deployer.apply_traffic_split(&env, dep, None).await {
        Ok(_) => Err(ConformanceFailure::InvalidSplitAccepted { sum }),
        Err(DeployerError::InvalidSplit { .. }) => Ok(()),
        Err(source) => Err(ConformanceFailure::InvalidSplitWrongError { sum, source }),
    }
}

async fn check_missing_split_rejected<D: Deployer + ?Sized>(
    deployer: &D,
) -> Result<(), ConformanceFailure> {
    let env = build_env_without_split();
    let dep = env.bundles[0].deployment_id;
    match deployer.apply_traffic_split(&env, dep, None).await {
        Ok(_) => Err(ConformanceFailure::MissingSplitAccepted),
        Err(DeployerError::SplitNotFound { .. }) => Ok(()),
        Err(source) => Err(ConformanceFailure::MissingSplitWrongError { source }),
    }
}

async fn check_cross_deployment_independence<D: Deployer + ?Sized>(
    deployer: &D,
    env: &Environment,
    dep_a: DeploymentId,
    dep_b: DeploymentId,
) -> Result<(), ConformanceFailure> {
    let expected_a = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == dep_a)
        .map(|s| s.entries.clone())
        .unwrap_or_default();
    let expected_b = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == dep_b)
        .map(|s| s.entries.clone())
        .unwrap_or_default();

    let outcome_a = deployer
        .apply_traffic_split(env, dep_a, None)
        .await
        .map_err(|source| ConformanceFailure::HappyPathFailed {
            verb: "apply_traffic_split[cross-dep:a]",
            source,
        })?;
    if outcome_a.applied_deployment_id != dep_a || outcome_a.applied_entries != expected_a {
        return Err(ConformanceFailure::CrossDeploymentInterference);
    }

    let outcome_b = deployer
        .apply_traffic_split(env, dep_b, None)
        .await
        .map_err(|source| ConformanceFailure::HappyPathFailed {
            verb: "apply_traffic_split[cross-dep:b]",
            source,
        })?;
    if outcome_b.applied_deployment_id != dep_b || outcome_b.applied_entries != expected_b {
        return Err(ConformanceFailure::CrossDeploymentInterference);
    }
    Ok(())
}

fn check_runtime_config_projection<D: Deployer + ?Sized>(
    deployer: &D,
    env: &Environment,
) -> Result<(), ConformanceFailure> {
    let reported = deployer.report_runtime_config(env);
    let expected = crate::environment::runtime_config::materialize_runtime_config(env);
    if reported != expected {
        return Err(ConformanceFailure::RuntimeConfigDrift);
    }
    Ok(())
}

// ---------- Fixture builders (internal — keep narrow) ----------

const FIXTURE_ENV_ID: &str = "conformance";
const FIXTURE_BUNDLE_A: &str = "bundle.a";
const FIXTURE_BUNDLE_B: &str = "bundle.b";

/// The bench's 2-deployment / 3-revision fixture. `pub(crate)` so sibling
/// deployer env-packs (K8s) can unit-test their render/verb logic against
/// the exact env shape the bench drives them with.
pub(crate) fn build_fixture_env() -> Environment {
    // Deterministic u128 seeds — fixture revisions/deployments stay
    // distinct from the unknown-revision sentinel (0xFFFF) used in
    // `check_unknown_revision_rejected`.
    let env_id = EnvId::try_from(FIXTURE_ENV_ID).expect("fixture env_id is valid");
    let dep_a = DeploymentId(Ulid::from(0x01_u128));
    let dep_b = DeploymentId(Ulid::from(0x02_u128));
    let bundle_a = BundleId::new(FIXTURE_BUNDLE_A);
    let bundle_b = BundleId::new(FIXTURE_BUNDLE_B);
    let r_warm = RevisionId(Ulid::from(0x10_u128));
    let r_drain = RevisionId(Ulid::from(0x20_u128));
    let r_archive = RevisionId(Ulid::from(0x30_u128));

    Environment {
        schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
        environment_id: env_id.clone(),
        name: env_id.as_str().to_string(),
        host_config: EnvironmentHostConfig::new(env_id.clone()),
        packs: Vec::new(),
        credentials_ref: None,
        bundles: vec![
            make_bundle(&env_id, dep_a, &bundle_a),
            make_bundle(&env_id, dep_b, &bundle_b),
        ],
        revisions: vec![
            make_revision(&env_id, dep_a, &bundle_a, r_warm, RevisionLifecycle::Ready),
            make_revision(&env_id, dep_a, &bundle_a, r_drain, RevisionLifecycle::Ready),
            make_revision(
                &env_id,
                dep_b,
                &bundle_b,
                r_archive,
                RevisionLifecycle::Inactive,
            ),
        ],
        traffic_splits: vec![
            make_split(
                &env_id,
                dep_a,
                &bundle_a,
                vec![(r_warm, 5000), (r_drain, 5000)],
            ),
            make_split(&env_id, dep_b, &bundle_b, vec![(r_archive, 10000)]),
        ],
        messaging_endpoints: Vec::new(),
        extensions: Vec::new(),
        revocation: Default::default(),
        retention: Default::default(),
        health: Default::default(),
    }
}

fn build_env_with_invalid_split() -> Environment {
    let mut env = build_fixture_env();
    // First split now sums to 9000 — violates the 10000-bps invariant.
    env.traffic_splits[0].entries = vec![
        TrafficSplitEntry {
            revision_id: env.revisions[0].revision_id,
            weight_bps: 4000,
        },
        TrafficSplitEntry {
            revision_id: env.revisions[1].revision_id,
            weight_bps: 5000,
        },
    ];
    env
}

fn build_env_without_split() -> Environment {
    let mut env = build_fixture_env();
    let dep_a = env.bundles[0].deployment_id;
    env.traffic_splits.retain(|s| s.deployment_id != dep_a);
    env
}

fn make_bundle(
    env_id: &EnvId,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
) -> BundleDeployment {
    BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id,
        env_id: env_id.clone(),
        bundle_id: bundle_id.clone(),
        customer_id: CustomerId::new("conformance-customer"),
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: RouteBinding {
            hosts: vec![format!("{}.conformance.local", bundle_id.as_str())],
            path_prefixes: Vec::new(),
            tenant_selector: TenantSelector {
                tenant: "default".to_string(),
                team: "default".to_string(),
            },
        },
        revenue_share: vec![RevenueShareEntry {
            party_id: PartyId::new("greentic"),
            basis_points: 10_000,
        }],
        revenue_policy_ref: std::path::PathBuf::from("revenue.json"),
        usage: None,
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap(),
        authorization_ref: std::path::PathBuf::from("auth.json"),
        config_overrides: Default::default(),
    }
}

fn make_revision(
    env_id: &EnvId,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    revision_id: RevisionId,
    lifecycle: RevisionLifecycle,
) -> Revision {
    Revision {
        schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
        revision_id,
        env_id: env_id.clone(),
        bundle_id: bundle_id.clone(),
        deployment_id,
        sequence: 1,
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap(),
        bundle_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        bundle_source_uri: None,
        pack_list: vec![PackListEntry::from_lock_primitives(
            PackId::new("greentic.fixture.pack"),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )],
        pack_list_lock_ref: std::path::PathBuf::from("pack-list.lock"),
        pack_config_refs: Vec::new(),
        config_digest: "sha256:0000".to_string(),
        signature_sidecar_ref: std::path::PathBuf::from("rev.sig"),
        lifecycle,
        staged_at: None,
        warmed_at: None,
        drain_seconds: 30,
        abort_metrics: Vec::new(),
    }
}

fn make_split(
    env_id: &EnvId,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    entries: Vec<(RevisionId, u32)>,
) -> TrafficSplit {
    TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: env_id.clone(),
        deployment_id,
        bundle_id: bundle_id.clone(),
        generation: 1,
        entries: entries
            .into_iter()
            .map(|(revision_id, weight_bps)| TrafficSplitEntry {
                revision_id,
                weight_bps,
            })
            .collect(),
        updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap(),
        updated_by: "conformance".to_string(),
        idempotency_key: "conformance".to_string(),
        authorization_ref: std::path::PathBuf::from("auth.json"),
        previous_split_ref: None,
    }
}

#[cfg(test)]
mod tests {
    //! Self-checks on the bench itself, using a couple of stub `Deployer`
    //! impls. These guard the bench's assertion shape against drift — a
    //! real impl (local-process / K8s / AWS) gets a single
    //! `run_conformance` call from its own integration test, not these.

    use super::*;
    use async_trait::async_trait;

    /// A trivially-passing deployer: every verb succeeds, all
    /// preconditions checked correctly, default `report_runtime_config`.
    #[derive(Debug, Default)]
    struct NoopDeployer;

    #[async_trait]
    impl Deployer for NoopDeployer {
        async fn stage_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<StageOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(StageOutcome::default())
        }

        async fn warm_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<WarmOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(WarmOutcome::default())
        }

        async fn drain_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<DrainOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(DrainOutcome::default())
        }

        async fn archive_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<ArchiveOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(ArchiveOutcome::default())
        }

        async fn apply_traffic_split(
            &self,
            env: &Environment,
            deployment_id: DeploymentId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<TrafficSplitOutcome, DeployerError> {
            enforce_split_invariants(env, deployment_id)
        }
    }

    /// Imports `Deployer`'s associated outcome types + shared precondition
    /// helpers into scope so the test stubs line up with the canonical
    /// shape every Phase D impl uses.
    use super::super::trait_def::{
        ArchiveOutcome, DrainOutcome, StageOutcome, TrafficSplitOutcome, WarmOutcome,
        enforce_split_invariants, require_revision,
    };

    #[tokio::test]
    async fn noop_deployer_passes() {
        let d = NoopDeployer;
        run_conformance(&d)
            .await
            .expect("noop impl satisfies the contract");
    }

    /// Deployer that breaks idempotency on `warm_revision` — the bench
    /// must surface `NotIdempotent` pointing at that verb.
    #[derive(Debug, Default)]
    struct OneShotWarm {
        called: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Deployer for OneShotWarm {
        async fn stage_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<StageOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(StageOutcome::default())
        }

        async fn warm_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<WarmOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            if self.called.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Err(DeployerError::Provider("already warmed".to_string()));
            }
            Ok(WarmOutcome::default())
        }

        async fn drain_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<DrainOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(DrainOutcome::default())
        }

        async fn archive_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<ArchiveOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(ArchiveOutcome::default())
        }

        async fn apply_traffic_split(
            &self,
            env: &Environment,
            deployment_id: DeploymentId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<TrafficSplitOutcome, DeployerError> {
            enforce_split_invariants(env, deployment_id)
        }
    }

    #[tokio::test]
    async fn bench_detects_non_idempotent_warm() {
        let d = OneShotWarm::default();
        let err = run_conformance(&d)
            .await
            .expect_err("warm is non-idempotent");
        assert!(
            matches!(
                err,
                ConformanceFailure::NotIdempotent {
                    verb: "warm_revision",
                    ..
                }
            ),
            "expected NotIdempotent(warm_revision), got {err:?}"
        );
    }

    /// Deployer that accepts an out-of-spec split sum — bench must
    /// surface `InvalidSplitAccepted`.
    #[derive(Debug, Default)]
    struct LaxSplit;

    #[async_trait]
    impl Deployer for LaxSplit {
        async fn stage_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<StageOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(StageOutcome::default())
        }
        async fn warm_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<WarmOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(WarmOutcome::default())
        }
        async fn drain_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<DrainOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(DrainOutcome::default())
        }
        async fn archive_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<ArchiveOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(ArchiveOutcome::default())
        }
        async fn apply_traffic_split(
            &self,
            _env: &Environment,
            deployment_id: DeploymentId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<TrafficSplitOutcome, DeployerError> {
            // Doesn't check the sum — should fail the bench.
            Ok(TrafficSplitOutcome {
                applied_deployment_id: deployment_id,
                applied_entries: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn bench_detects_lax_split_validation() {
        let d = LaxSplit;
        let err = run_conformance(&d)
            .await
            .expect_err("invalid split must be rejected");
        assert!(
            matches!(err, ConformanceFailure::InvalidSplitAccepted { .. }),
            "expected InvalidSplitAccepted, got {err:?}"
        );
    }

    /// Deployer that always reports a fixed wrong `applied_deployment_id`
    /// in its `TrafficSplitOutcome`, regardless of the actual input.
    /// The bench must surface `CrossDeploymentInterference`.
    #[derive(Debug, Default)]
    struct WrongDeploymentReporter;

    #[async_trait]
    impl Deployer for WrongDeploymentReporter {
        async fn stage_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<StageOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(StageOutcome::default())
        }
        async fn warm_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<WarmOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(WarmOutcome::default())
        }
        async fn drain_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
        ) -> Result<DrainOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(DrainOutcome::default())
        }
        async fn archive_revision(
            &self,
            env: &Environment,
            revision_id: RevisionId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<ArchiveOutcome, DeployerError> {
            require_revision(env, revision_id)?;
            Ok(ArchiveOutcome::default())
        }
        async fn apply_traffic_split(
            &self,
            env: &Environment,
            deployment_id: DeploymentId,
            _answers: Option<&serde_json::Value>,
        ) -> Result<TrafficSplitOutcome, DeployerError> {
            // Borrow the shared precondition path, then corrupt the
            // self-report so the bench's cross-deployment check fires.
            let mut outcome = enforce_split_invariants(env, deployment_id)?;
            outcome.applied_deployment_id = DeploymentId(Ulid::from(0xDEAD_u128));
            Ok(outcome)
        }
    }

    #[tokio::test]
    async fn bench_detects_wrong_deployment_id_in_outcome() {
        let d = WrongDeploymentReporter;
        let err = run_conformance(&d)
            .await
            .expect_err("wrong deployment id in outcome must be caught");
        assert!(
            matches!(err, ConformanceFailure::CrossDeploymentInterference),
            "expected CrossDeploymentInterference, got {err:?}"
        );
    }
}
