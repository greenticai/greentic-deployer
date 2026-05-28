//! `gtc op deploy` — the one-shot bundle deployment orchestrator.
//!
//! The default, "just works" path: add the bundle deployment (when new),
//! stage a revision from the local `.gtbundle`, warm it, and route 100 % of
//! traffic to it. It reuses the four single-purpose verbs — `bundles add`,
//! `revisions stage`, `revisions warm`, `traffic set` — so all of the
//! audit / signing / revenue-policy logic stays single-sourced; this module
//! only threads the minted ids between them and fills in sensible defaults.
//!
//! A real local `.gtbundle` is required on every path — `deploy` refuses to
//! publish an artifact-less revision (placeholder digests + an empty pack-list
//! lock would be admissible by traffic yet broken at boot).
//!
//! Re-deploying a bundle that is already deployed in the env stages a NEW
//! revision and shifts 100 % traffic onto it (blue-green): because
//! `traffic set` replaces the whole split, the previously-live revision
//! leaves the routing table and drains at runtime. The superseded revision
//! is retained (not archived) so `gtc op traffic rollback` still works.
//!
//! Each invocation is its own rollout: without a caller-supplied
//! `--idempotency-key`, the cut-over key is derived from the freshly-minted
//! revision, so a re-run stages another revision rather than deduplicating.
//! Supply a stable `--idempotency-key` to make retries idempotent — a repeat
//! with a key that already routed returns the existing outcome without minting
//! a new revision or disturbing the rollback target.
//!
//! The deployer records desired state only; it carries no health-check
//! producers (B9), so `warm` runs a no-op gate and the result reports
//! `routed`, not a runtime liveness claim. greentic-start's watcher reloads
//! and begins serving once the split is written.
//!
//! Prerequisites are required, never auto-created: the env must already exist
//! (`gtc op env init`) and its trust root must carry the operator key
//! (`gtc op trust-root bootstrap`). The deploy path never seeds signing keys
//! — that would grant signing rights as a side effect of a deploy (C2).
//!
//! The four verbs remain the advanced / fine-tune surface, untouched.

use std::path::PathBuf;

use greentic_deploy_spec::EnvId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::bundles::{BundleAddPayload, BundleSummary, RouteBindingPayload};
use super::revisions::{RevisionStagePayload, RevisionSummary, RevisionTransitionPayload};
use super::traffic::{TrafficSetEntryPayload, TrafficSetPayload};
use super::{OpError, OpFlags, OpOutcome};

const NOUN: &str = "deploy";
const VERB: &str = "run";

/// 100 % of traffic, in basis points.
const FULL_TRAFFIC_BPS: u32 = 10_000;

/// Input to [`deploy`]. Everything but `bundle_id` and `bundle_path` has a
/// sensible default; the CLI requires `--bundle` and derives `bundle_id` from
/// its filename stem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDeployPayload {
    #[serde(default = "default_environment_id")]
    pub environment_id: String,
    pub bundle_id: String,
    /// Billing principal (P6). Defaults to `local-dev` on the `local` env;
    /// required for every other env. Forwarded verbatim to `bundles add`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    /// Local `.gtbundle` to stage. Required (on every path): `deploy` refuses
    /// to publish an artifact-less revision. Optional in the struct only so an
    /// `--answers` payload that omits it fails with a clear error rather than a
    /// deserialization error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<PathBuf>,
    /// Idempotency key for the traffic cut-over. Defaults to a value derived
    /// from the freshly-minted revision id, so each deploy is a distinct
    /// (non-replay) cut-over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

fn default_environment_id() -> String {
    crate::defaults::LOCAL_ENV_ID.to_string()
}

/// Combined summary of an orchestrated deploy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploySummary {
    pub environment_id: String,
    pub bundle_id: String,
    pub deployment_id: String,
    pub revision_id: String,
    /// `true` when the bundle was already deployed and this call reused the
    /// existing deployment (a blue-green version bump).
    pub reused_deployment: bool,
    /// Revisions that were live before this deploy and have now left the
    /// routing table (they drain at runtime; retained for rollback).
    pub superseded_revisions: Vec<String>,
    pub traffic: String,
    pub status: String,
}

impl DeploySummary {
    /// A routed deploy: the 100 %-traffic split is written. `status` is
    /// `routed` (desired state), not a runtime liveness claim — see module docs.
    fn routed(
        env_id: &EnvId,
        bundle_id: String,
        deployment_id: String,
        revision_id: String,
        reused_deployment: bool,
        superseded_revisions: Vec<String>,
    ) -> Self {
        Self {
            environment_id: env_id.as_str().to_string(),
            bundle_id,
            deployment_id,
            revision_id,
            reused_deployment,
            superseded_revisions,
            traffic: format!("100% ({FULL_TRAFFIC_BPS} bps)"),
            status: "routed".to_string(),
        }
    }

    fn into_outcome(self) -> OpOutcome {
        OpOutcome::new(
            NOUN,
            VERB,
            serde_json::to_value(self).expect("DeploySummary is json-safe"),
        )
    }
}

/// Orchestrate add → stage → warm → traffic-set with defaults.
pub fn deploy(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<BundleDeployPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, VERB, deploy_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let bundle_id = payload.bundle_id.trim().to_string();
    if bundle_id.is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_id must not be empty".to_string(),
        ));
    }

    // `op deploy` always stages from a real `.gtbundle`: an artifact-less
    // stage would record placeholder digests and an empty pack-list lock —
    // warmable by the no-op gate, admissible by traffic, and broken at boot.
    // Reject it here, before any mutation, so a bad call never creates a
    // deployment it then can't fill. (The legacy verbatim stage path stays
    // reachable only through the explicit `revisions stage --answers` verb.)
    let bundle_path = payload.bundle_path.clone().ok_or_else(|| {
        OpError::InvalidArgument(
            "deploy requires a local `.gtbundle`: pass `--bundle <PATH>`".to_string(),
        )
    })?;
    if !bundle_path.is_file() {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{}` is not a file",
            bundle_path.display()
        )));
    }

    // Preflight: the env must already exist. We never auto-create it, because
    // `env init` is the only path that legitimately seeds the trust root (C2),
    // and a deploy must not grant signing rights as a side effect.
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!(
            "environment `{env_id}` not found — run `gtc op env init` \
             (then `gtc op trust-root bootstrap {env_id}`) before deploying"
        )));
    }

    // Resolve the billing principal the same way `bundles add` does so the
    // reuse scan keys on the real (env_id, bundle_id, customer_id) anchor.
    let customer_id = super::bundles::resolve_customer_id(&env_id, payload.customer_id.clone())?;

    // Operation-level idempotency: if the caller supplied a key and the bundle
    // already has a traffic split under that key, this deploy already ran —
    // return the existing outcome without minting a duplicate revision or
    // moving the rollback target. (`traffic set` alone keys only the cut-over,
    // so a keyed retry would otherwise stage a fresh revision and then conflict
    // at the split, orphaning a Ready revision.)
    let env = store.load(&env_id)?;
    let existing = env
        .bundles
        .iter()
        .find(|b| b.bundle_id.as_str() == bundle_id && b.customer_id == customer_id);

    if let Some(key) = payload.idempotency_key.as_deref()
        && let Some(b) = existing
        && let Some(split) = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id == b.deployment_id && s.idempotency_key == key)
    {
        let revision_id = split
            .entries
            .first()
            .map(|e| e.revision_id.to_string())
            .unwrap_or_default();
        return Ok(DeploySummary::routed(
            &env_id,
            bundle_id,
            b.deployment_id.to_string(),
            revision_id,
            true,
            Vec::new(),
        )
        .into_outcome());
    }

    let (deployment_id, reused, superseded_revisions) = match existing {
        Some(b) => {
            let dep = b.deployment_id;
            let superseded: Vec<String> = env
                .traffic_splits
                .iter()
                .find(|s| s.deployment_id == dep)
                .map(|s| {
                    s.entries
                        .iter()
                        .map(|e| e.revision_id.to_string())
                        .collect()
                })
                .unwrap_or_default();
            (dep.to_string(), true, superseded)
        }
        None => {
            let add_payload = BundleAddPayload {
                environment_id: payload.environment_id.clone(),
                bundle_id: bundle_id.clone(),
                customer_id: payload.customer_id.clone(),
                route_binding: RouteBindingPayload {
                    hosts: Vec::new(),
                    path_prefixes: Vec::new(),
                    tenant_selector: None,
                },
                revenue_share: super::bundles::default_revenue_share(),
                authorization_ref: super::bundles::default_authorization_ref(),
            };
            let outcome = super::bundles::add(store, flags, Some(add_payload))?;
            let summary: BundleSummary = parse_summary(outcome, "bundle")?;
            (summary.deployment_id, false, Vec::new())
        }
    };
    // Drop the borrow on `env` before the mutating steps below.
    drop(env);

    // Stage a fresh revision from the bundle. With `bundle_path` set, stage
    // derives the real bundle_digest / pack_list / lock ref from the artifact;
    // config_digest / signature_sidecar_ref / drain_seconds are still recorded
    // verbatim, so use the same canonical defaults the `stage --answers` path
    // applies rather than re-spelling the literals here.
    let stage_payload = RevisionStagePayload {
        environment_id: payload.environment_id.clone(),
        deployment_id: deployment_id.clone(),
        bundle_path: Some(bundle_path),
        bundle_digest: super::revisions::default_bundle_digest(),
        pack_list: Vec::new(),
        pack_list_lock_ref: PathBuf::new(),
        config_digest: super::revisions::default_config_digest(),
        signature_sidecar_ref: super::revisions::default_signature_sidecar_ref(),
        drain_seconds: super::revisions::default_drain_seconds(),
    };
    let stage_outcome = super::revisions::stage(store, flags, Some(stage_payload))?;
    let staged: RevisionSummary = parse_summary(stage_outcome, "revision")?;
    let revision_id = staged.revision_id;

    // Warm it to Ready.
    super::revisions::warm(
        store,
        flags,
        Some(RevisionTransitionPayload {
            environment_id: payload.environment_id.clone(),
            revision_id: revision_id.clone(),
        }),
    )?;

    // Route 100 % of traffic to the new revision. `traffic set` is a full
    // replacement, so any previously-live revision drops out of the split
    // (blue-green). Without a caller-supplied key, each deploy is its own
    // rollout: the revision-derived key guarantees a distinct cut-over. Supply
    // `--idempotency-key` to make retries idempotent (handled above).
    let idempotency_key = payload
        .idempotency_key
        .clone()
        .unwrap_or_else(|| format!("deploy:{deployment_id}:{revision_id}"));
    super::traffic::set(
        store,
        flags,
        Some(TrafficSetPayload {
            environment_id: payload.environment_id.clone(),
            deployment_id: deployment_id.clone(),
            entries: vec![TrafficSetEntryPayload {
                revision_id: revision_id.clone(),
                weight_bps: Some(FULL_TRAFFIC_BPS),
                weight_percent: None,
            }],
            updated_by: super::traffic::default_updated_by(),
            idempotency_key,
            authorization_ref: super::traffic::default_authorization_ref(),
        }),
    )?;

    // `status` is "routed" (desired-state split written), not a runtime
    // liveness claim — the deployer has no health-check producers (B9); see
    // `DeploySummary::routed` and the module docs.
    Ok(DeploySummary::routed(
        &env_id,
        bundle_id,
        deployment_id,
        revision_id,
        reused,
        superseded_revisions,
    )
    .into_outcome())
}

/// Build a [`BundleDeployPayload`] from direct CLI args, or `None` when no
/// args were supplied (deferring to `--answers` / `--schema`). Mirrors
/// `revisions::payload_from_stage_args`: all clap fields are optional so the
/// answers / schema paths keep working unchanged.
pub fn payload_from_deploy_args(
    args: super::dispatch::BundleDeployArgs,
) -> Result<Option<BundleDeployPayload>, OpError> {
    let super::dispatch::BundleDeployArgs {
        bundle,
        env,
        bundle_id,
        customer_id,
        idempotency_key,
    } = args;
    if bundle.is_none()
        && env.is_none()
        && bundle_id.is_none()
        && customer_id.is_none()
        && idempotency_key.is_none()
    {
        return Ok(None);
    }
    let bundle_path = bundle.ok_or_else(|| {
        OpError::InvalidArgument(
            "deploy: missing `--bundle <PATH>` (the local .gtbundle to deploy)".to_string(),
        )
    })?;
    let bundle_id = match bundle_id {
        Some(id) => id,
        None => bundle_path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OpError::InvalidArgument(format!(
                    "deploy: cannot derive bundle_id from `{}` — pass `--bundle-id <ID>`",
                    bundle_path.display()
                ))
            })?,
    };
    Ok(Some(BundleDeployPayload {
        environment_id: env.unwrap_or_else(default_environment_id),
        bundle_id,
        customer_id,
        bundle_path: Some(bundle_path),
        idempotency_key,
    }))
}

/// Deserialize an [`OpOutcome`]'s `result` into a step summary, mapping any
/// failure to an internal-error `OpError` (the sub-verbs are typed, so this
/// should never fire in practice).
fn parse_summary<T: serde::de::DeserializeOwned>(
    outcome: OpOutcome,
    what: &str,
) -> Result<T, OpError> {
    serde_json::from_value(outcome.result).map_err(|e| {
        OpError::InvalidArgument(format!("internal: failed to parse {what} summary: {e}"))
    })
}

fn resolve_payload<T: serde::de::DeserializeOwned>(
    flags: &OpFlags,
    payload: Option<T>,
) -> Result<T, OpError> {
    if let Some(p) = payload {
        return Ok(p);
    }
    if let Some(path) = &flags.answers {
        return super::load_answers::<T>(path);
    }
    Err(OpError::InvalidArgument(
        "no payload provided: pass --bundle <path>, --answers <path>, or supply the payload directly"
            .to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn deploy_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "BundleDeployPayload",
        "type": "object",
        "required": ["bundle_id", "bundle_path"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string", "default": "local"},
            "bundle_id": {"type": "string"},
            "customer_id": {"type": "string"},
            "bundle_path": {"type": "string", "description": "local .gtbundle path (required)"},
            "idempotency_key": {"type": "string", "description": "supply to make retries idempotent"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{bootstrap_env_trust_root, make_env};
    use tempfile::tempdir;

    fn seeded_store() -> (tempfile::TempDir, LocalFsStore) {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        bootstrap_env_trust_root(&env_dir);
        (dir, store)
    }

    /// The real `.gtbundle` test fixture — extracted (pure-Rust squashfs) and
    /// pinned into a pack-list lock by the stage step, so the orchestration is
    /// exercised against an artifact-backed revision, not a placeholder.
    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/perf-smoke-bundle.gtbundle")
    }

    fn payload(bundle_id: &str) -> BundleDeployPayload {
        BundleDeployPayload {
            environment_id: "local".to_string(),
            bundle_id: bundle_id.to_string(),
            customer_id: None,
            bundle_path: Some(fixture()),
            idempotency_key: None,
        }
    }

    fn deploy_summary(outcome: OpOutcome) -> DeploySummary {
        serde_json::from_value(outcome.result).expect("DeploySummary")
    }

    #[test]
    fn fresh_deploy_creates_and_routes() {
        let (_dir, store) = seeded_store();
        let outcome = deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap();
        let s = deploy_summary(outcome);
        assert!(!s.reused_deployment);
        assert!(!s.deployment_id.is_empty());
        assert!(!s.revision_id.is_empty());
        assert!(s.superseded_revisions.is_empty());
        assert_eq!(s.status, "routed");

        // One deployment, one live split at 100 % on the new revision, and the
        // revision is artifact-backed (real digest derived from the .gtbundle).
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.bundles.len(), 1);
        assert_eq!(env.traffic_splits.len(), 1);
        let split = &env.traffic_splits[0];
        assert_eq!(split.entries.len(), 1);
        assert_eq!(split.entries[0].weight_bps, FULL_TRAFFIC_BPS);
        assert_eq!(split.entries[0].revision_id.to_string(), s.revision_id);
        let rev = env
            .revisions
            .iter()
            .find(|r| r.revision_id.to_string() == s.revision_id)
            .expect("revision persisted");
        assert!(
            rev.bundle_digest.starts_with("sha256:") && rev.bundle_digest != "sha256:00",
            "deploy must stage a real artifact digest, got {}",
            rev.bundle_digest
        );
    }

    #[test]
    fn deploy_without_bundle_path_rejected() {
        // The artifact is required on every path, including `--answers` payloads
        // that omit it: deploy must never publish a placeholder-digest revision.
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.bundle_path = None;
        let err = deploy(&store, &OpFlags::default(), Some(p)).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => assert!(msg.contains("--bundle"), "got {msg}"),
            other => panic!("expected InvalidArgument requiring --bundle, got {other:?}"),
        }
        // No partial state: nothing was added before the rejection.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert!(env.bundles.is_empty());
    }

    #[test]
    fn redeploy_with_same_idempotency_key_is_noop() {
        let (_dir, store) = seeded_store();
        let mut p = payload("quickstart");
        p.idempotency_key = Some("rollout-1".to_string());
        let first = deploy_summary(deploy(&store, &OpFlags::default(), Some(p.clone())).unwrap());
        let second = deploy_summary(deploy(&store, &OpFlags::default(), Some(p)).unwrap());

        // The keyed retry returns the existing rollout, mints no new revision,
        // and leaves the rollback target untouched.
        assert_eq!(second.revision_id, first.revision_id);
        assert_eq!(second.deployment_id, first.deployment_id);
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(
            env.revisions.len(),
            1,
            "no duplicate revision on keyed retry"
        );
        let split = &env.traffic_splits[0];
        assert!(
            split.previous_split_ref.is_none(),
            "rollback target must not be disturbed by an idempotent retry"
        );
    }

    #[test]
    fn redeploy_reuses_deployment_and_blue_green_shifts_traffic() {
        let (_dir, store) = seeded_store();
        let first = deploy_summary(
            deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap(),
        );
        let second = deploy_summary(
            deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap(),
        );

        assert!(second.reused_deployment);
        assert_eq!(second.deployment_id, first.deployment_id);
        assert_ne!(second.revision_id, first.revision_id);
        // The first revision was live before; it is now superseded.
        assert_eq!(second.superseded_revisions, vec![first.revision_id.clone()]);

        // Still a single deployment; the live split now points 100 % at rev2.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.bundles.len(), 1);
        let split = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id.to_string() == second.deployment_id)
            .expect("split for deployment");
        assert_eq!(split.entries.len(), 1);
        assert_eq!(split.entries[0].revision_id.to_string(), second.revision_id);
        // The superseded revision is retained (not archived) for rollback.
        assert!(
            env.revisions
                .iter()
                .any(|r| r.revision_id.to_string() == first.revision_id)
        );
    }

    #[test]
    fn missing_env_errors_with_init_hint() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // No env saved.
        let err = deploy(&store, &OpFlags::default(), Some(payload("quickstart"))).unwrap_err();
        match err {
            OpError::NotFound(msg) => assert!(msg.contains("env init"), "got {msg}"),
            other => panic!("expected NotFound with init hint, got {other:?}"),
        }
    }

    #[test]
    fn empty_bundle_id_rejected() {
        let (_dir, store) = seeded_store();
        let err = deploy(&store, &OpFlags::default(), Some(payload("  "))).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn derives_bundle_id_from_filename_stem() {
        let args = super::super::dispatch::BundleDeployArgs {
            bundle: Some(PathBuf::from("/tmp/quickstart.gtbundle")),
            env: None,
            bundle_id: None,
            customer_id: None,
            idempotency_key: None,
        };
        let p = payload_from_deploy_args(args).unwrap().unwrap();
        assert_eq!(p.bundle_id, "quickstart");
        assert_eq!(p.environment_id, "local");
    }

    #[test]
    fn no_args_defers_to_answers() {
        let args = super::super::dispatch::BundleDeployArgs {
            bundle: None,
            env: None,
            bundle_id: None,
            customer_id: None,
            idempotency_key: None,
        };
        assert!(payload_from_deploy_args(args).unwrap().is_none());
    }

    #[test]
    fn missing_bundle_with_other_args_errors() {
        let args = super::super::dispatch::BundleDeployArgs {
            bundle: None,
            env: Some("local".to_string()),
            bundle_id: None,
            customer_id: None,
            idempotency_key: None,
        };
        let err = payload_from_deploy_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }
}
