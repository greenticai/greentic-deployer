//! `gtc op traffic {set,show,rollback}` (`A3`).
//!
//! Manages `Environment.traffic_splits: Vec<TrafficSplit>`. Each split is
//! per-`deployment_id`. The CLI accepts percentages or basis points and
//! validates the entries sum to exactly 10,000 bps via
//! [`TrafficSplit::validate`].
//!
//! Rollback: the prior `TrafficSplit` is stashed inline under
//! `previous_split_ref` using the `inline://<base64>` token scheme from
//! `greentic_deploy_spec::engine::inline_stash` so rollback works without a
//! sidecar history file. Multi-step history is A8's contract.
//!
//! In-process router wiring (the `RevisionDispatcher` in `greentic-start`)
//! is Phase B. A3 only mutates the spec object; making it observable in the
//! live runtime is a separate gate.

use std::path::PathBuf;

use greentic_deploy_spec::{DeploymentId, EnvId, RevisionId, TrafficSplit, TrafficSplitEntry};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::dispatch::{TrafficSetArgs, TrafficTargetArgs};
use super::{
    AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record, map_store_err_preserving_noun,
    resolve_idempotency_key,
};

const NOUN: &str = "traffic";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSetPayload {
    pub environment_id: String,
    pub deployment_id: String,
    pub entries: Vec<TrafficSetEntryPayload>,
    #[serde(default = "default_updated_by")]
    pub updated_by: String,
    pub idempotency_key: String,
    #[serde(default = "default_authorization_ref")]
    pub authorization_ref: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSetEntryPayload {
    pub revision_id: String,
    /// Basis points. `weight_bps` and `weight_percent` are mutually
    /// exclusive at the payload level; if both are set, `weight_bps` wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_bps: Option<u32>,
    /// Percentage 0..=100, converted to basis points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_percent: Option<u32>,
}

pub(super) fn default_updated_by() -> String {
    "operator".to_string()
}
pub(super) fn default_authorization_ref() -> PathBuf {
    PathBuf::from("auth.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSummary {
    pub environment_id: String,
    pub deployment_id: String,
    pub bundle_id: String,
    pub generation: u64,
    pub entries: Vec<TrafficSummaryEntry>,
    pub has_previous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSummaryEntry {
    pub revision_id: String,
    pub weight_bps: u32,
}

impl TrafficSummary {
    pub(crate) fn from(env_id: &EnvId, split: &TrafficSplit) -> Self {
        Self {
            environment_id: env_id.as_str().to_string(),
            deployment_id: split.deployment_id.to_string(),
            bundle_id: split.bundle_id.as_str().to_string(),
            generation: split.generation,
            entries: split
                .entries
                .iter()
                .map(|e| TrafficSummaryEntry {
                    revision_id: e.revision_id.to_string(),
                    weight_bps: e.weight_bps,
                })
                .collect(),
            has_previous: split.previous_split_ref.is_some(),
        }
    }
}

/// `op traffic set`. Replaces the entire entries list for one deployment.
/// Validates sum == 10,000 bps before saving. Stashes the prior split for
/// one-step rollback.
pub fn set(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrafficSetPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "set", set_schema()));
    }
    let payload = resolve_payload::<TrafficSetPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    // Pre-parse + pre-validate the entries outside the lock. If anything
    // here is malformed the caller hears about it without contending for
    // the env's flock.
    let parsed_entries = parse_entries(&payload.entries)?;
    // Revision-belongs-to-deployment check (operator-friendly error
    // instead of waiting for the store's defense-in-depth guard to fire
    // with a less specific error variant).
    {
        let env = store.load(&env_id)?;
        for entry in &parsed_entries {
            let rev = env
                .revisions
                .iter()
                .find(|r| r.revision_id == entry.revision_id)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "revision `{}` not found in env `{env_id}`",
                        entry.revision_id
                    ))
                })?;
            if rev.deployment_id != deployment_id {
                return Err(OpError::InvalidArgument(format!(
                    "revision `{}` belongs to deployment `{}`, not `{}`",
                    entry.revision_id, rev.deployment_id, deployment_id,
                )));
            }
        }
    }
    let idempotency_key = greentic_deploy_spec::IdempotencyKey::new(payload.idempotency_key)
        .map_err(|e| OpError::InvalidArgument(format!("idempotency_key: {e}")))?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "set",
        target: json!({"deployment_id": deployment_id.to_string()}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let outcome = store
            .set_traffic_split(
                &env_id,
                greentic_deploy_spec::SetTrafficSplitPayload {
                    deployment_id,
                    entries: parsed_entries,
                    updated_by: payload.updated_by,
                    authorization_ref: Some(
                        payload.authorization_ref.to_string_lossy().into_owned(),
                    ),
                },
                idempotency_key,
            )
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_traffic_store_err)?;
        emit_applied_telemetry(&outcome);
        let gens = super::AuditGens {
            previous: outcome.previous_generation,
            new: outcome.new_generation,
        };
        let op_outcome = OpOutcome::new(
            NOUN,
            "set",
            serde_json::to_value(TrafficSummary::from(&env_id, &outcome.split))
                .expect("TrafficSummary is json-safe"),
        );
        Ok((op_outcome, gens))
    })
}

/// C5.3: emit `TrafficSplitApplied` from the outcome's env snapshot — the
/// same env the store just persisted, so tenant attribution has no TOCTOU
/// window with a concurrent writer, local or remote. The idempotent no-op
/// replay carries `new_generation: None` and must NOT double-count the
/// transition.
pub(crate) fn emit_applied_telemetry(outcome: &crate::environment::ApplyTrafficSplitOutcome) {
    if outcome.new_generation.is_some() {
        crate::rollout_telemetry::emit_traffic_split_applied(
            &outcome.environment,
            outcome.split.deployment_id,
            &outcome.split.bundle_id,
            outcome.split.generation,
        );
    }
}

/// C5.3: emit `TrafficSplitApplied` for the rollback path too — a rollback
/// advances generation and materializes into runtime-config exactly like a
/// forward `set`, so monitoring pipelines need the same lifecycle event.
pub(crate) fn emit_rollback_telemetry(outcome: &crate::environment::RollbackTrafficSplitOutcome) {
    crate::rollout_telemetry::emit_traffic_split_applied(
        &outcome.environment,
        outcome.restored.deployment_id,
        &outcome.restored.bundle_id,
        outcome.restored.generation,
    );
}

/// Build a [`TrafficSetPayload`] from clap-derived args.
///
/// Returns `Ok(None)` when no clap args were supplied — the caller falls back
/// to `--answers` / `--payload-json`. Returns `Ok(Some(_))` when the user
/// passed positional args. A partial set (e.g. `env_id` without
/// `--deployment`) is a clap-level user error and surfaces as
/// [`OpError::InvalidArgument`] so the user gets one clear message instead
/// of being silently routed to the answers path.
pub fn payload_from_set_args(args: TrafficSetArgs) -> Result<Option<TrafficSetPayload>, OpError> {
    let TrafficSetArgs {
        env_id,
        entries,
        deployment,
        idempotency_key,
        updated_by,
        authorization_ref,
    } = args;
    // No positional args at all → answers/schema path.
    if env_id.is_none() && deployment.is_none() && entries.is_empty() {
        return Ok(None);
    }
    let environment_id = env_id.ok_or_else(|| {
        OpError::InvalidArgument("traffic set: missing positional `<env_id>`".to_string())
    })?;
    let deployment_id = deployment.ok_or_else(|| {
        OpError::InvalidArgument("traffic set: missing `--deployment <ULID>`".to_string())
    })?;
    if entries.is_empty() {
        return Err(OpError::InvalidArgument(
            "traffic set: at least one `<revision_id>=<weight>` entry is required".to_string(),
        ));
    }
    // Required: an auto-generated key per-invocation would break the
    // rollback target preservation contract — a same-argv retry after a
    // lost response would look like a brand-new mutation, snapshotting the
    // already-live split as `previous_split_ref` and overwriting the real
    // rollback target. The answers-path schema treats `idempotency_key`
    // as required; the direct-args path matches.
    let idempotency_key = idempotency_key.ok_or_else(|| {
        OpError::InvalidArgument(
            "traffic set: missing `--idempotency-key <KEY>`. Pass any stable string \
             (ULID, UUID, ticket id) — re-running the same command with the same key \
             is a no-op replay; a different key (or omitting it) destroys the one-step \
             rollback target."
                .to_string(),
        )
    })?;
    let entries = entries
        .iter()
        .map(|raw| parse_entry_arg(raw))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(TrafficSetPayload {
        environment_id,
        deployment_id,
        entries,
        updated_by: updated_by.unwrap_or_else(default_updated_by),
        idempotency_key,
        authorization_ref: authorization_ref.unwrap_or_else(default_authorization_ref),
    }))
}

/// Build a [`TrafficShowPayload`] for `op traffic show` and `op traffic rollback`.
/// Same fallthrough semantics as [`payload_from_set_args`].
pub fn payload_from_target_args(
    args: TrafficTargetArgs,
) -> Result<Option<TrafficShowPayload>, OpError> {
    let TrafficTargetArgs { env_id, deployment } = args;
    if env_id.is_none() && deployment.is_none() {
        return Ok(None);
    }
    let environment_id = env_id.ok_or_else(|| {
        OpError::InvalidArgument("traffic: missing positional `<env_id>`".to_string())
    })?;
    let deployment_id = deployment.ok_or_else(|| {
        OpError::InvalidArgument("traffic: missing `--deployment <ULID>`".to_string())
    })?;
    Ok(Some(TrafficShowPayload {
        environment_id,
        deployment_id,
        idempotency_key: None,
    }))
}

/// Parse a `<revision_id>=<weight>` CLI argument into a payload entry.
///
/// Weight forms:
/// - `N` or `N%` — percent (`0..=100`)
/// - `Nbps` — basis points (`0..=10_000`)
fn parse_entry_arg(raw: &str) -> Result<TrafficSetEntryPayload, OpError> {
    let (rid, weight) = raw.split_once('=').ok_or_else(|| {
        OpError::InvalidArgument(format!(
            "entry `{raw}` must be `<revision_id>=<percent>` or `<revision_id>=<N>bps`"
        ))
    })?;
    if rid.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "entry `{raw}` has an empty revision_id"
        )));
    }
    let weight = weight.trim();
    if weight.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "entry `{raw}` has an empty weight"
        )));
    }
    let (weight_bps, weight_percent) = if let Some(rest) = weight.strip_suffix("bps") {
        let bps: u32 = rest.trim().parse().map_err(|e| {
            OpError::InvalidArgument(format!("entry `{raw}`: parse basis points: {e}"))
        })?;
        (Some(bps), None)
    } else {
        let pct_str = weight.strip_suffix('%').unwrap_or(weight).trim();
        let pct: u32 = pct_str
            .parse()
            .map_err(|e| OpError::InvalidArgument(format!("entry `{raw}`: parse percent: {e}")))?;
        (None, Some(pct))
    };
    Ok(TrafficSetEntryPayload {
        revision_id: rid.to_string(),
        weight_bps,
        weight_percent,
    })
}

pub(crate) fn parse_entries(
    entries: &[TrafficSetEntryPayload],
) -> Result<Vec<TrafficSplitEntry>, OpError> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let bps = match (entry.weight_bps, entry.weight_percent) {
            (Some(bps), _) => bps,
            (None, Some(pct)) => {
                if pct > 100 {
                    return Err(OpError::InvalidArgument(format!(
                        "weight_percent {pct} > 100"
                    )));
                }
                pct.saturating_mul(100)
            }
            (None, None) => {
                return Err(OpError::InvalidArgument(
                    "each entry must set weight_bps or weight_percent".to_string(),
                ));
            }
        };
        let revision_id = parse_revision_id(&entry.revision_id)?;
        out.push(TrafficSplitEntry {
            revision_id,
            weight_bps: bps,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficShowPayload {
    pub environment_id: String,
    pub deployment_id: String,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

pub fn show(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrafficShowPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "show", show_schema()));
    }
    let payload = resolve_payload::<TrafficShowPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let split = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == deployment_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "no traffic split for deployment `{deployment_id}` in env `{env_id}`"
            ))
        })?;
    Ok(OpOutcome::new(
        NOUN,
        "show",
        serde_json::to_value(TrafficSummary::from(&env_id, split))
            .expect("TrafficSummary is json-safe"),
    ))
}

pub fn rollback(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrafficShowPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "rollback", show_schema()));
    }
    let payload = resolve_payload::<TrafficShowPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rollback",
        target: json!({"deployment_id": deployment_id.to_string()}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let outcome = store
            .rollback_traffic_split(&env_id, deployment_id, idempotency_key)
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_traffic_store_err)?;
        emit_rollback_telemetry(&outcome);
        let gens = super::AuditGens {
            previous: Some(outcome.previous_generation),
            new: Some(outcome.new_generation),
        };
        let op_outcome = OpOutcome::new(
            NOUN,
            "rollback",
            serde_json::to_value(TrafficSummary::from(&env_id, &outcome.restored))
                .expect("TrafficSummary is json-safe"),
        );
        Ok((op_outcome, gens))
    })
}

// --- internals -----------------------------------------------------------

/// Traffic-specific `StoreError → OpError` mapper that peels
/// [`crate::environment::StoreError::Spec`] into [`OpError::Spec`] before
/// falling through to [`map_store_err_preserving_noun`]. The Spec variant
/// is unique to traffic (validate sum == 10,000 bps) and the shared
/// mapper doesn't cover it.
pub(crate) fn map_traffic_store_err(e: crate::environment::StoreError) -> OpError {
    match e {
        crate::environment::StoreError::Spec(s) => OpError::Spec(s),
        other => map_store_err_preserving_noun(other),
    }
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
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn parse_deployment_id(raw: &str) -> Result<DeploymentId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("deployment_id: {e}")))?;
    Ok(DeploymentId(ulid))
}

fn parse_revision_id(raw: &str) -> Result<RevisionId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("revision_id: {e}")))?;
    Ok(RevisionId(ulid))
}

fn set_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrafficSetPayload",
        "type": "object",
        "required": ["environment_id", "deployment_id", "entries", "idempotency_key"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "deployment_id": {"type": "string", "description": "ULID"},
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["revision_id"],
                    "properties": {
                        "revision_id": {"type": "string", "description": "ULID"},
                        "weight_bps": {"type": "integer", "minimum": 0, "maximum": 10000},
                        "weight_percent": {"type": "integer", "minimum": 0, "maximum": 100}
                    }
                }
            },
            "updated_by": {"type": "string", "default": "operator"},
            "idempotency_key": {"type": "string"},
            "authorization_ref": {"type": "string"}
        }
    })
}

fn show_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrafficShowPayload",
        "type": "object",
        "required": ["environment_id", "deployment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "deployment_id": {"type": "string", "description": "ULID"},
            "idempotency_key": {"type": "string"}
        }
    })
}

// The `inline://` stash scheme moved to
// `greentic_deploy_spec::engine::inline_stash` in PR-4.2c — the pure
// traffic transforms write/read the tokens, so both backends must share
// one implementation.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_bundle_deployment, make_env, make_revision};
    use greentic_deploy_spec::{RevisionLifecycle, SchemaVersion};
    use tempfile::tempdir;

    fn seed_env(store: &LocalFsStore) -> (DeploymentId, RevisionId, RevisionId) {
        let mut env = make_env("local");
        let deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        let r1 = make_revision("local", "fast2flow", &did, 1, RevisionLifecycle::Ready);
        let r2 = make_revision("local", "fast2flow", &did, 2, RevisionLifecycle::Ready);
        let rid1 = r1.revision_id;
        let rid2 = r2.revision_id;
        env.bundles.push(deployment);
        env.revisions.push(r1);
        env.revisions.push(r2);
        store.save(&env).unwrap();
        (did, rid1, rid2)
    }

    #[test]
    fn set_then_show_returns_split() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        let outcome = set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_bps: Some(10_000),
                    weight_percent: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("generation").and_then(|v| v.as_u64()),
            Some(0)
        );
        let shown = show(
            &store,
            &OpFlags::default(),
            Some(TrafficShowPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let entries = shown
            .result
            .get("entries")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn set_rejects_sum_not_10000() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        let err = set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![
                    TrafficSetEntryPayload {
                        revision_id: rid1.to_string(),
                        weight_percent: Some(60),
                        weight_bps: None,
                    },
                    TrafficSetEntryPayload {
                        revision_id: rid2.to_string(),
                        weight_percent: Some(30),
                        weight_bps: None,
                    },
                ],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Spec(_)), "got {err:?}");
    }

    #[test]
    fn set_then_rollback_restores_previous() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        // First split: 100% rev1.
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_percent: Some(100),
                    weight_bps: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();
        // Second split: 50/50.
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![
                    TrafficSetEntryPayload {
                        revision_id: rid1.to_string(),
                        weight_percent: Some(50),
                        weight_bps: None,
                    },
                    TrafficSetEntryPayload {
                        revision_id: rid2.to_string(),
                        weight_percent: Some(50),
                        weight_bps: None,
                    },
                ],
                updated_by: "test".to_string(),
                idempotency_key: "k2".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();
        // Rollback: should restore split-1 with 100% rev1.
        let rolled = rollback(
            &store,
            &OpFlags::default(),
            Some(TrafficShowPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let entries = rolled
            .result
            .get("entries")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].get("weight_bps").and_then(|v| v.as_u64()),
            Some(10_000)
        );
    }

    #[test]
    fn set_rejects_revision_from_other_deployment() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // Seed env with two deployments, two revisions, one in each.
        let mut env = make_env("local");
        let d1 = make_bundle_deployment("local", "fast2flow");
        let did1 = d1.deployment_id;
        let mut d2 = make_bundle_deployment("local", "llm-router");
        d2.customer_id = greentic_deploy_spec::CustomerId::new("local-dev");
        // Force a distinct (bundle, customer) — they already differ on bundle.
        let did2 = d2.deployment_id;
        let r1 = make_revision("local", "fast2flow", &did1, 1, RevisionLifecycle::Ready);
        let r2 = make_revision("local", "llm-router", &did2, 1, RevisionLifecycle::Ready);
        let rid2 = r2.revision_id;
        env.bundles.push(d1);
        env.bundles.push(d2);
        env.revisions.push(r1);
        env.revisions.push(r2);
        store.save(&env).unwrap();

        let err = set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did1.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    // Cross-deployment revision_id — must be rejected.
                    revision_id: rid2.to_string(),
                    weight_percent: Some(100),
                    weight_bps: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn set_same_idempotency_key_same_payload_is_no_op() {
        // Codex regression: a retried set with the same key + same entries
        // must not snapshot the current split as its own previous_split_ref
        // (which would orphan the real rollback target). Verify generation
        // stays put and previous_split_ref stays empty.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        let payload = TrafficSetPayload {
            environment_id: "local".to_string(),
            deployment_id: did.to_string(),
            entries: vec![TrafficSetEntryPayload {
                revision_id: rid1.to_string(),
                weight_bps: Some(10_000),
                weight_percent: None,
            }],
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: default_authorization_ref(),
        };
        let first = set(&store, &OpFlags::default(), Some(payload.clone())).unwrap();
        assert_eq!(
            first.result.get("generation").and_then(|v| v.as_u64()),
            Some(0)
        );
        // Retry with the same key + same payload — must replay as no-op.
        let retry = set(&store, &OpFlags::default(), Some(payload)).unwrap();
        assert_eq!(
            retry.result.get("generation").and_then(|v| v.as_u64()),
            Some(0),
            "generation must stay at 0 on idempotent retry"
        );
        assert_eq!(
            retry.result.get("has_previous").and_then(|v| v.as_bool()),
            Some(false),
            "previous_split_ref must stay empty on idempotent retry"
        );
    }

    #[test]
    fn set_same_idempotency_key_different_payload_conflicts() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        let p1 = TrafficSetPayload {
            environment_id: "local".to_string(),
            deployment_id: did.to_string(),
            entries: vec![TrafficSetEntryPayload {
                revision_id: rid1.to_string(),
                weight_bps: Some(10_000),
                weight_percent: None,
            }],
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: default_authorization_ref(),
        };
        set(&store, &OpFlags::default(), Some(p1)).unwrap();
        // Same key, different entries.
        let p2 = TrafficSetPayload {
            environment_id: "local".to_string(),
            deployment_id: did.to_string(),
            entries: vec![
                TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_percent: Some(50),
                    weight_bps: None,
                },
                TrafficSetEntryPayload {
                    revision_id: rid2.to_string(),
                    weight_percent: Some(50),
                    weight_bps: None,
                },
            ],
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: default_authorization_ref(),
        };
        let err = set(&store, &OpFlags::default(), Some(p2)).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn set_retry_preserves_rollback_target() {
        // Codex regression: prior to the idempotency check, a retried set
        // would overwrite previous_split_ref with itself, and a later
        // rollback would land on the retried split instead of the pre-change
        // traffic. Verify the rollback target is still the pre-change split.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        // k1: 100% rev1.
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_bps: Some(10_000),
                    weight_percent: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();
        // k2: 50/50. This is the change rollback must undo.
        let k2_payload = TrafficSetPayload {
            environment_id: "local".to_string(),
            deployment_id: did.to_string(),
            entries: vec![
                TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_percent: Some(50),
                    weight_bps: None,
                },
                TrafficSetEntryPayload {
                    revision_id: rid2.to_string(),
                    weight_percent: Some(50),
                    weight_bps: None,
                },
            ],
            updated_by: "test".to_string(),
            idempotency_key: "k2".to_string(),
            authorization_ref: default_authorization_ref(),
        };
        set(&store, &OpFlags::default(), Some(k2_payload.clone())).unwrap();
        // Retry k2 — should be no-op, must not overwrite previous_split_ref.
        set(&store, &OpFlags::default(), Some(k2_payload)).unwrap();
        // Rollback: must restore 100% rev1, not the retried 50/50.
        let rolled = rollback(
            &store,
            &OpFlags::default(),
            Some(TrafficShowPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let entries = rolled
            .result
            .get("entries")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(
            entries.len(),
            1,
            "rollback must restore the single-entry k1 split, not the retried k2"
        );
        assert_eq!(
            entries[0].get("weight_bps").and_then(|v| v.as_u64()),
            Some(10_000)
        );
    }

    #[test]
    fn set_records_idempotency_key_and_generation_in_audit() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_bps: Some(10_000),
                    weight_percent: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();
        let log = dir.path().join("local").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).unwrap();
        let event: crate::environment::AuditEvent = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(event.noun, "traffic");
        assert_eq!(event.verb, "set");
        assert_eq!(event.idempotency_key.as_deref(), Some("k1"));
        assert_eq!(event.previous_generation, None);
        assert_eq!(event.new_generation, Some(0));
    }

    #[test]
    fn set_materializes_runtime_config_on_disk() {
        // B4 producer: a traffic set must (re)write runtime-config.json — the
        // file greentic-start boots from (B0) and routes on (B3) — and the
        // projection must satisfy B0's per-deployment weight invariant.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![
                    TrafficSetEntryPayload {
                        revision_id: rid1.to_string(),
                        weight_percent: Some(90),
                        weight_bps: None,
                    },
                    TrafficSetEntryPayload {
                        revision_id: rid2.to_string(),
                        weight_percent: Some(10),
                        weight_bps: None,
                    },
                ],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();

        let path = dir.path().join("local").join("runtime-config.json");
        assert!(path.exists(), "runtime-config.json must be materialized");
        let cfg: greentic_deploy_spec::RuntimeConfig =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(cfg.schema.as_str(), SchemaVersion::RUNTIME_CONFIG_V1);
        assert_eq!(cfg.env_id.as_str(), "local");
        assert_eq!(cfg.revisions.len(), 2);
        let sum: u32 = cfg.revisions.iter().map(|b| b.weight_bps).sum();
        assert_eq!(sum, 10_000);
    }

    #[test]
    fn refresh_deletes_runtime_config_when_no_splits_remain() {
        // B0 rejects an empty-revisions config, so when the last split is gone
        // the producer must delete the stale file rather than write an empty one.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_bps: Some(10_000),
                    weight_percent: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();
        let path = dir.path().join("local").join("runtime-config.json");
        assert!(path.exists());

        // Drop the split out-of-band, then refresh under the lock.
        let env_id = EnvId::try_from("local").unwrap();
        let mut env = store.load(&env_id).unwrap();
        env.traffic_splits.clear();
        store.save(&env).unwrap();
        store
            .transact(&env_id, |locked| {
                let env = locked.load()?;
                locked.refresh_runtime_config(&env)
            })
            .unwrap();
        assert!(
            !path.exists(),
            "runtime-config.json must be removed when no split routes a revision"
        );
    }

    #[test]
    fn refresh_is_noop_when_projection_unchanged() {
        // Change-detection guard: refreshing without a traffic mutation must
        // not rewrite or back up the file.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    revision_id: rid1.to_string(),
                    weight_bps: Some(10_000),
                    weight_percent: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();
        let path = dir.path().join("local").join("runtime-config.json");
        let before = std::fs::read(&path).unwrap();

        let env_id = EnvId::try_from("local").unwrap();
        store
            .transact(&env_id, |locked| {
                let env = locked.load()?;
                locked.refresh_runtime_config(&env)
            })
            .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), before);
        let backups = dir.path().join("local").join("backups");
        let backup_count = std::fs::read_dir(&backups)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("runtime-config.json")
                    })
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(backup_count, 0, "no-op refresh must not back up the config");
    }

    #[test]
    fn set_rejects_non_ready_revision_and_materializes_nothing() {
        // §5.3 admission: routing traffic to a Staged revision must be refused,
        // and no runtime-config may be produced.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let dep = make_bundle_deployment("local", "fast2flow");
        let did = dep.deployment_id;
        let staged = make_revision("local", "fast2flow", &did, 1, RevisionLifecycle::Staged);
        let rid = staged.revision_id;
        env.bundles.push(dep);
        env.revisions.push(staged);
        store.save(&env).unwrap();

        let err = set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![TrafficSetEntryPayload {
                    revision_id: rid.to_string(),
                    weight_bps: Some(10_000),
                    weight_percent: None,
                }],
                updated_by: "test".to_string(),
                idempotency_key: "k1".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
        assert!(
            !dir.path()
                .join("local")
                .join("runtime-config.json")
                .exists(),
            "a rejected set must not leave a runtime-config behind"
        );
    }

    #[test]
    fn rollback_refuses_when_restored_revision_no_longer_ready() {
        // §5.3 admission on the restore path: a historical split routing a
        // since-archived revision must not be brought live.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        let base = |key: &str, rid: &RevisionId| TrafficSetPayload {
            environment_id: "local".to_string(),
            deployment_id: did.to_string(),
            entries: vec![TrafficSetEntryPayload {
                revision_id: rid.to_string(),
                weight_bps: Some(10_000),
                weight_percent: None,
            }],
            updated_by: "test".to_string(),
            idempotency_key: key.to_string(),
            authorization_ref: default_authorization_ref(),
        };
        // k1 routes rid1; k2 routes rid2 (so the rollback target is k1/rid1).
        set(&store, &OpFlags::default(), Some(base("k1", &rid1))).unwrap();
        set(&store, &OpFlags::default(), Some(base("k2", &rid2))).unwrap();

        // rid1 retires out-of-band (it is not in the live k2 split).
        let env_id = EnvId::try_from("local").unwrap();
        let mut env = store.load(&env_id).unwrap();
        let i = env
            .revisions
            .iter()
            .position(|r| r.revision_id == rid1)
            .unwrap();
        env.revisions[i].lifecycle = RevisionLifecycle::Archived;
        store.save(&env).unwrap();

        let err = rollback(
            &store,
            &OpFlags::default(),
            Some(TrafficShowPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn idempotent_retry_reconciles_stale_runtime_config() {
        // A publish that failed after environment.json was durable must be
        // repaired by a same-key retry, not hidden by the no-op replay.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        let payload = TrafficSetPayload {
            environment_id: "local".to_string(),
            deployment_id: did.to_string(),
            entries: vec![TrafficSetEntryPayload {
                revision_id: rid1.to_string(),
                weight_bps: Some(10_000),
                weight_percent: None,
            }],
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: default_authorization_ref(),
        };
        set(&store, &OpFlags::default(), Some(payload.clone())).unwrap();
        let path = dir.path().join("local").join("runtime-config.json");
        assert!(path.exists());

        // Simulate a refresh that failed after the split was already saved.
        std::fs::remove_file(&path).unwrap();

        // Idempotent retry (same key + entries) must reconcile the file.
        set(&store, &OpFlags::default(), Some(payload)).unwrap();
        assert!(
            path.exists(),
            "idempotent retry must reconcile a stale runtime-config"
        );
    }

    // --- clap-arg parser tests -----------------------------------------

    #[test]
    fn parse_entry_arg_accepts_plain_percent() {
        let e = parse_entry_arg("01H000000000000000000000R1=99").unwrap();
        assert_eq!(e.revision_id, "01H000000000000000000000R1");
        assert_eq!(e.weight_bps, None);
        assert_eq!(e.weight_percent, Some(99));
    }

    #[test]
    fn parse_entry_arg_accepts_percent_suffix() {
        let e = parse_entry_arg("rev1=50%").unwrap();
        assert_eq!(e.weight_percent, Some(50));
        assert_eq!(e.weight_bps, None);
    }

    #[test]
    fn parse_entry_arg_accepts_basis_points() {
        let e = parse_entry_arg("rev1=2500bps").unwrap();
        assert_eq!(e.weight_bps, Some(2500));
        assert_eq!(e.weight_percent, None);
    }

    #[test]
    fn parse_entry_arg_rejects_missing_separator() {
        let err = parse_entry_arg("rev1-99").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn parse_entry_arg_rejects_empty_revision_id() {
        let err = parse_entry_arg("=99").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn parse_entry_arg_rejects_empty_weight() {
        let err = parse_entry_arg("rev1=").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn parse_entry_arg_rejects_non_numeric_weight() {
        let err = parse_entry_arg("rev1=many").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn parse_entry_arg_rejects_non_numeric_bps() {
        let err = parse_entry_arg("rev1=manybps").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn payload_from_set_args_returns_none_when_blank() {
        let args = TrafficSetArgs {
            env_id: None,
            entries: Vec::new(),
            deployment: None,
            idempotency_key: None,
            updated_by: None,
            authorization_ref: None,
        };
        assert!(payload_from_set_args(args).unwrap().is_none());
    }

    #[test]
    fn payload_from_set_args_requires_deployment_when_env_present() {
        let args = TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: vec!["rev1=100".to_string()],
            deployment: None,
            idempotency_key: None,
            updated_by: None,
            authorization_ref: None,
        };
        let err = payload_from_set_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn payload_from_set_args_requires_entries() {
        let args = TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: Vec::new(),
            deployment: Some(DeploymentId::new().to_string()),
            idempotency_key: None,
            updated_by: None,
            authorization_ref: None,
        };
        let err = payload_from_set_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn payload_from_set_args_requires_idempotency_key() {
        // Direct-arg path mirrors the answers-schema contract: idempotency
        // key is required. Auto-generating one per invocation would let a
        // same-argv retry advance generation and overwrite the rollback
        // target — see `clap_retry_preserves_rollback_target`.
        let did = DeploymentId::new();
        let args = TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: vec!["rev1=100".to_string()],
            deployment: Some(did.to_string()),
            idempotency_key: None,
            updated_by: None,
            authorization_ref: None,
        };
        let err = payload_from_set_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        let OpError::InvalidArgument(msg) = err else {
            unreachable!()
        };
        assert!(
            msg.contains("--idempotency-key"),
            "error must mention the flag, got `{msg}`"
        );
    }

    #[test]
    fn payload_from_set_args_builds_full_payload_with_defaults() {
        let did = DeploymentId::new();
        let args = TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: vec!["rev1=90".to_string(), "rev2=10bps".to_string()],
            deployment: Some(did.to_string()),
            idempotency_key: Some("k-test".to_string()),
            updated_by: None,
            authorization_ref: None,
        };
        let payload = payload_from_set_args(args).unwrap().unwrap();
        assert_eq!(payload.environment_id, "local");
        assert_eq!(payload.deployment_id, did.to_string());
        assert_eq!(payload.entries.len(), 2);
        assert_eq!(payload.entries[0].weight_percent, Some(90));
        assert_eq!(payload.entries[1].weight_bps, Some(10));
        assert_eq!(payload.updated_by, "operator", "default actor");
        assert_eq!(
            payload.authorization_ref,
            PathBuf::from("auth.json"),
            "default authorization ref"
        );
        assert_eq!(payload.idempotency_key, "k-test");
    }

    #[test]
    fn payload_from_set_args_honors_explicit_overrides() {
        let did = DeploymentId::new();
        let args = TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: vec!["rev1=100".to_string()],
            deployment: Some(did.to_string()),
            idempotency_key: Some("k-explicit".to_string()),
            updated_by: Some("ci".to_string()),
            authorization_ref: Some(PathBuf::from("custom.json")),
        };
        let payload = payload_from_set_args(args).unwrap().unwrap();
        assert_eq!(payload.idempotency_key, "k-explicit");
        assert_eq!(payload.updated_by, "ci");
        assert_eq!(payload.authorization_ref, PathBuf::from("custom.json"));
    }

    #[test]
    fn payload_from_target_args_returns_none_when_blank() {
        let args = TrafficTargetArgs {
            env_id: None,
            deployment: None,
        };
        assert!(payload_from_target_args(args).unwrap().is_none());
    }

    #[test]
    fn payload_from_target_args_requires_both_when_either_present() {
        let args = TrafficTargetArgs {
            env_id: Some("local".to_string()),
            deployment: None,
        };
        let err = payload_from_target_args(args).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn payload_from_target_args_builds_payload() {
        let did = DeploymentId::new();
        let args = TrafficTargetArgs {
            env_id: Some("local".to_string()),
            deployment: Some(did.to_string()),
        };
        let payload = payload_from_target_args(args).unwrap().unwrap();
        assert_eq!(payload.environment_id, "local");
        assert_eq!(payload.deployment_id, did.to_string());
    }

    #[test]
    fn clap_set_payload_drives_real_traffic_set() {
        // End-to-end smoke: payload_from_set_args + traffic::set against a
        // real store. Verifies the CLI surface drives the library happy path
        // with no answers file in sight.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        let args = TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: vec![format!("{rid1}=90"), format!("{rid2}=10")],
            deployment: Some(did.to_string()),
            idempotency_key: Some("k-clap".to_string()),
            updated_by: Some("test".to_string()),
            authorization_ref: None,
        };
        let payload = payload_from_set_args(args).unwrap();
        let outcome = set(&store, &OpFlags::default(), payload).unwrap();
        let entries = outcome
            .result
            .get("entries")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(entries.len(), 2);
        let total: u64 = entries
            .iter()
            .map(|e| e.get("weight_bps").and_then(|v| v.as_u64()).unwrap())
            .sum();
        assert_eq!(total, 10_000, "clap-built payload must satisfy spec sum");
    }

    #[test]
    fn clap_retry_preserves_rollback_target() {
        // Regression: a retried direct-args invocation with the same
        // --idempotency-key must replay as a no-op, NOT advance the
        // generation and snapshot the live split as previous_split_ref —
        // otherwise the one-step rollback target is destroyed.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);

        // A: 100% rev1 (k1).
        let a_args = TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: vec![format!("{rid1}=100")],
            deployment: Some(did.to_string()),
            idempotency_key: Some("k1".to_string()),
            updated_by: Some("test".to_string()),
            authorization_ref: None,
        };
        set(
            &store,
            &OpFlags::default(),
            payload_from_set_args(a_args).unwrap(),
        )
        .unwrap();

        // B: 50/50 (k2). This is the change a rollback should undo.
        let b_args = || TrafficSetArgs {
            env_id: Some("local".to_string()),
            entries: vec![format!("{rid1}=50"), format!("{rid2}=50")],
            deployment: Some(did.to_string()),
            idempotency_key: Some("k2".to_string()),
            updated_by: Some("test".to_string()),
            authorization_ref: None,
        };
        set(
            &store,
            &OpFlags::default(),
            payload_from_set_args(b_args()).unwrap(),
        )
        .unwrap();

        // Retry B through the clap path — must be a no-op replay because
        // the key matches. Without the explicit-key requirement, the CLI
        // would generate a fresh ULID here and the library would treat it
        // as a new mutation, overwriting the (A) rollback target.
        let retry = set(
            &store,
            &OpFlags::default(),
            payload_from_set_args(b_args()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            retry.result.get("generation").and_then(|v| v.as_u64()),
            Some(1),
            "retry must replay B's generation, not advance"
        );

        // Rollback must restore A (100% rev1), not the retried B (50/50).
        let rolled = rollback(
            &store,
            &OpFlags::default(),
            Some(TrafficShowPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let entries = rolled
            .result
            .get("entries")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(
            entries.len(),
            1,
            "rollback must land on A (single entry), not the retried B"
        );
        assert_eq!(
            entries[0].get("weight_bps").and_then(|v| v.as_u64()),
            Some(10_000),
            "rollback must restore 100% rev1"
        );
    }

    // -------------------------------------------------------------------
    // C5.3 — end-to-end rollout-event capture for traffic verbs
    //
    // Uses the shared global capture from
    // `crate::rollout_telemetry::test_capture` (see that module's doc for
    // why a global subscriber is required instead of per-test
    // `with_default` — `tracing`'s callsite interest cache races under
    // parallel test execution). Asserts:
    // - `set` on a genuine mutation emits `rollout.traffic_split.applied`.
    // - `set` on an idempotent same-key-same-entries replay does NOT
    //   double-emit (regression guard for the early-return guard).
    // - `rollback` emits `rollout.traffic_split.applied` exactly like a
    //   forward `set` (parity with the runtime mutation profile).
    // -------------------------------------------------------------------

    use crate::rollout_telemetry::test_capture::{capture_events, count};
    use std::collections::BTreeSet;

    fn observed(events: &[String]) -> BTreeSet<String> {
        events.iter().cloned().collect()
    }

    fn set_payload(did: &DeploymentId, rid: &RevisionId, key: &str) -> TrafficSetPayload {
        TrafficSetPayload {
            environment_id: "local".to_string(),
            deployment_id: did.to_string(),
            entries: vec![TrafficSetEntryPayload {
                revision_id: rid.to_string(),
                weight_bps: Some(10_000),
                weight_percent: None,
            }],
            updated_by: "test".to_string(),
            idempotency_key: key.to_string(),
            authorization_ref: default_authorization_ref(),
        }
    }

    #[test]
    fn set_emits_traffic_split_applied() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        let (res, events) = capture_events(|| {
            set(
                &store,
                &OpFlags::default(),
                Some(set_payload(&did, &rid1, "k1")),
            )
        });
        res.unwrap();
        let observed = observed(&events);
        assert!(
            observed.contains("rollout.traffic_split.applied"),
            "observed events: {observed:?}"
        );
    }

    /// Regression guard: a same-key-same-entries replay returns the early
    /// `AuditGens::NONE` from inside the transact, BEFORE reaching the
    /// `emit_traffic_split_applied` call. The replay must NOT double-count
    /// the transition — exactly one event should appear across both calls.
    #[test]
    fn set_idempotent_replay_does_not_double_emit() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, _) = seed_env(&store);
        let (res, events) = capture_events(|| {
            set(
                &store,
                &OpFlags::default(),
                Some(set_payload(&did, &rid1, "k1")),
            )
            .unwrap();
            // Replay: same key, same entries → no-op success per the
            // idempotency contract; must NOT emit a second event.
            set(
                &store,
                &OpFlags::default(),
                Some(set_payload(&did, &rid1, "k1")),
            )
        });
        res.unwrap();
        assert_eq!(
            count(&events, "rollout.traffic_split.applied"),
            1,
            "expected exactly one TrafficSplitApplied event across set + replay; \
             captured: {:?}",
            observed(&events)
        );
    }

    /// `rollback` advances generation and materializes into runtime-config
    /// exactly like a forward `set`, so it must emit the same lifecycle
    /// event. Without this an emergency rollback would produce zero
    /// telemetry confirmation.
    #[test]
    fn rollback_emits_traffic_split_applied() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (did, rid1, rid2) = seed_env(&store);
        // Establish a prior split (k1, 100% rev1), then overwrite (k2,
        // 50/50). Now there's a previous_split_ref for rollback to consume.
        set(
            &store,
            &OpFlags::default(),
            Some(set_payload(&did, &rid1, "k1")),
        )
        .unwrap();
        set(
            &store,
            &OpFlags::default(),
            Some(TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                entries: vec![
                    TrafficSetEntryPayload {
                        revision_id: rid1.to_string(),
                        weight_bps: Some(5_000),
                        weight_percent: None,
                    },
                    TrafficSetEntryPayload {
                        revision_id: rid2.to_string(),
                        weight_bps: Some(5_000),
                        weight_percent: None,
                    },
                ],
                updated_by: "test".to_string(),
                idempotency_key: "k2".to_string(),
                authorization_ref: default_authorization_ref(),
            }),
        )
        .unwrap();

        let (res, events) = capture_events(|| {
            rollback(
                &store,
                &OpFlags::default(),
                Some(TrafficShowPayload {
                    environment_id: "local".to_string(),
                    deployment_id: did.to_string(),
                    idempotency_key: None,
                }),
            )
        });
        res.unwrap();
        assert_eq!(
            count(&events, "rollout.traffic_split.applied"),
            1,
            "rollback must emit exactly one TrafficSplitApplied; \
             captured: {:?}",
            observed(&events)
        );
    }

    // --- PR-3a.11: schema regression tests for idempotency_key ---------------

    /// `TrafficSetPayload` accepts `idempotency_key`; the schema published
    /// via `--schema` MUST list it so schema-driven callers can supply the
    /// A8 retry key.
    #[test]
    fn set_schema_lists_idempotency_key() {
        let schema = set_schema();
        assert!(
            schema.pointer("/properties/idempotency_key").is_some(),
            "set_schema must list `idempotency_key` (schema: {schema:#})"
        );
    }

    /// Same gate for the show/rollback schema: `TrafficShowPayload` now
    /// accepts `idempotency_key`, so the schema must list it under
    /// `properties` (especially because `additionalProperties: false`
    /// would reject it otherwise).
    #[test]
    fn show_schema_lists_idempotency_key() {
        let schema = show_schema();
        assert!(
            schema.pointer("/properties/idempotency_key").is_some(),
            "show_schema must list `idempotency_key` (schema: {schema:#})"
        );
    }
}
