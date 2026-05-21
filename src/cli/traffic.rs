//! `gtc op traffic {set,show,rollback}` (`A3`).
//!
//! Manages `Environment.traffic_splits: Vec<TrafficSplit>`. Each split is
//! per-`deployment_id`. The CLI accepts percentages or basis points and
//! validates the entries sum to exactly 10,000 bps via
//! [`TrafficSplit::validate`].
//!
//! Rollback: the prior `TrafficSplit` is stashed inline under
//! `previous_split_ref` using the same `inline://<base64>` token scheme as
//! `env_packs::stash_previous` so rollback works without a sidecar history
//! file. Multi-step history is A8's contract.
//!
//! In-process router wiring (the `RevisionDispatcher` in `greentic-start`)
//! is Phase B. A3 only mutates the spec object; making it observable in the
//! live runtime is a separate gate.

use std::path::PathBuf;

use chrono::Utc;
use greentic_deploy_spec::{
    BundleId, DeploymentId, EnvId, Environment, RevisionId, RevisionLifecycle, SchemaVersion,
    TrafficSplit, TrafficSplitEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "traffic";
const PREV_PREFIX: &str = "inline://";

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

fn default_updated_by() -> String {
    "operator".to_string()
}
fn default_authorization_ref() -> PathBuf {
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
    fn from(env_id: &EnvId, split: &TrafficSplit) -> Self {
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "set",
        target: json!({"deployment_id": deployment_id.to_string()}),
        idempotency_key: Some(payload.idempotency_key.clone()),
    };
    audit_and_record(store, ctx, || {
        let (split, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let deployment = env
                .bundles
                .iter()
                .find(|b| b.deployment_id == deployment_id)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "deployment `{deployment_id}` not found in env `{env_id}`"
                    ))
                })?;
            let bundle_id: BundleId = deployment.bundle_id.clone();
            // Revision-belongs-to-deployment check (operator-friendly error
            // instead of waiting for Environment::validate to fire).
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
            // Idempotency check: a retry with the same key against the same
            // (deployment, entries) is a no-op success; same key + different
            // payload is a conflict; new key advances generation.
            let prev_split_idx = env
                .traffic_splits
                .iter()
                .position(|s| s.deployment_id == deployment_id);
            if let Some(idx) = prev_split_idx {
                let prev = &env.traffic_splits[idx];
                if prev.idempotency_key == payload.idempotency_key {
                    if entries_match(&prev.entries, &parsed_entries) {
                        // No-op replay. Reconcile the derived runtime-config
                        // before returning so a retry repairs a publish that
                        // failed after environment.json was already durable.
                        locked.refresh_runtime_config(&env)?;
                        return Ok((prev.clone(), super::AuditGens::NONE));
                    }
                    return Err(OpError::Conflict(format!(
                        "idempotency key `{}` already used for deployment `{}` with different entries",
                        payload.idempotency_key, deployment_id
                    )));
                }
            }
            // §5.3 admission, on the apply path only: the idempotent no-op
            // replay above must stay a success even if a routed revision later
            // drains, so a stale split is never rejected on retry.
            assert_entries_all_ready(&env, &parsed_entries, &env_id)?;
            let (generation, previous_split_ref, prev_gen) = match prev_split_idx {
                Some(idx) => {
                    let prev = &env.traffic_splits[idx];
                    let snapshot = serde_json::to_value(prev).map_err(|e| {
                        OpError::InvalidArgument(format!("snapshot prior split: {e}"))
                    })?;
                    (
                        prev.generation + 1,
                        Some(stash_inline(snapshot)),
                        Some(prev.generation),
                    )
                }
                None => (0, None, None),
            };
            let split = TrafficSplit {
                schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
                env_id: env_id.clone(),
                deployment_id,
                bundle_id,
                generation,
                entries: parsed_entries.clone(),
                updated_at: Utc::now(),
                updated_by: payload.updated_by.clone(),
                idempotency_key: payload.idempotency_key.clone(),
                authorization_ref: payload.authorization_ref.clone(),
                previous_split_ref,
            };
            split.validate().map_err(OpError::Spec)?;
            match prev_split_idx {
                Some(idx) => env.traffic_splits[idx] = split.clone(),
                None => env.traffic_splits.push(split.clone()),
            }
            locked.save(&env)?;
            locked.refresh_runtime_config(&env)?;
            let gens = super::AuditGens {
                previous: prev_gen,
                new: Some(generation),
            };
            Ok::<_, OpError>((split, gens))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "set",
            serde_json::to_value(TrafficSummary::from(&env_id, &split))
                .expect("TrafficSummary is json-safe"),
        );
        Ok((outcome, gens))
    })
}

fn parse_entries(entries: &[TrafficSetEntryPayload]) -> Result<Vec<TrafficSplitEntry>, OpError> {
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

/// §5.3 admission: every entry's revision must exist and be `Ready` before its
/// split goes live, since the split materializes into runtime routing. Shared
/// by the `set` apply path and the `rollback` restore path so the rule lives in
/// one place.
fn assert_entries_all_ready(
    env: &Environment,
    entries: &[TrafficSplitEntry],
    env_id: &EnvId,
) -> Result<(), OpError> {
    for entry in entries {
        let rev = env
            .revisions
            .iter()
            .find(|r| r.revision_id == entry.revision_id)
            .ok_or_else(|| {
                OpError::Conflict(format!(
                    "revision `{}` not found in env `{env_id}`",
                    entry.revision_id
                ))
            })?;
        if rev.lifecycle != RevisionLifecycle::Ready {
            return Err(OpError::Conflict(format!(
                "revision `{}` is `{:?}`; only `Ready` revisions may receive traffic",
                entry.revision_id, rev.lifecycle
            )));
        }
    }
    Ok(())
}

/// Order-insensitive equality on basis-points-per-revision_id. Two payloads
/// that route the same percentage to the same revision_id (in any
/// permutation) collapse to "same" for idempotency purposes.
fn entries_match(a: &[TrafficSplitEntry], b: &[TrafficSplitEntry]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_sorted: Vec<(&RevisionId, u32)> =
        a.iter().map(|e| (&e.revision_id, e.weight_bps)).collect();
    let mut b_sorted: Vec<(&RevisionId, u32)> =
        b.iter().map(|e| (&e.revision_id, e.weight_bps)).collect();
    a_sorted.sort_by_key(|(r, _)| r.to_string());
    b_sorted.sort_by_key(|(r, _)| r.to_string());
    a_sorted == b_sorted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficShowPayload {
    pub environment_id: String,
    pub deployment_id: String,
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rollback",
        target: json!({"deployment_id": deployment_id.to_string()}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
        let (restored, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let idx = env
                .traffic_splits
                .iter()
                .position(|s| s.deployment_id == deployment_id)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "no traffic split for deployment `{deployment_id}` in env `{env_id}`"
                    ))
                })?;
            let prev_split_generation = env.traffic_splits[idx].generation;
            let prev_ref = env.traffic_splits[idx]
                .previous_split_ref
                .clone()
                .ok_or_else(|| {
                    OpError::Conflict(format!(
                        "traffic split for `{deployment_id}` has no prior version to roll back to"
                    ))
                })?;
            let prev_value = load_inline(&prev_ref).ok_or_else(|| {
                OpError::NotFound(format!(
                    "previous split payload `{}` missing",
                    prev_ref.display()
                ))
            })?;
            let mut restored: TrafficSplit = serde_json::from_value(prev_value).map_err(|e| {
                OpError::InvalidArgument(format!("deserialise previous split: {e}"))
            })?;
            restored.generation = prev_split_generation + 1;
            restored.previous_split_ref = None;
            restored.updated_at = Utc::now();
            restored.idempotency_key =
                format!("rollback-{}", env.traffic_splits[idx].idempotency_key);
            restored.validate().map_err(OpError::Spec)?;
            // §5.3 admission on the restore path: a historical split may route
            // to revisions that have since been archived, failed, or removed.
            assert_entries_all_ready(&env, &restored.entries, &env_id)?;
            env.traffic_splits[idx] = restored.clone();
            locked.save(&env)?;
            locked.refresh_runtime_config(&env)?;
            let gens = super::AuditGens {
                previous: Some(prev_split_generation),
                new: Some(prev_split_generation + 1),
            };
            Ok::<_, OpError>((restored, gens))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "rollback",
            serde_json::to_value(TrafficSummary::from(&env_id, &restored))
                .expect("TrafficSummary is json-safe"),
        );
        Ok((outcome, gens))
    })
}

// --- internals -----------------------------------------------------------

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
            "deployment_id": {"type": "string", "description": "ULID"}
        }
    })
}

// Inline base64 token re-used from env_packs. Duplicated rather than promoted
// to a shared module to keep the surface area small while we figure out
// whether multi-step history (A8) really wants this scheme at all.

fn stash_inline(snapshot: Value) -> PathBuf {
    let mut encoded = String::from(PREV_PREFIX);
    let raw = serde_json::to_string(&snapshot).expect("Value re-serialises");
    encoded.push_str(&crate::cli::env_packs::base64_encode_public(raw.as_bytes()));
    PathBuf::from(encoded)
}

fn load_inline(prev_ref: &std::path::Path) -> Option<Value> {
    let token = prev_ref.to_str()?;
    let encoded = token.strip_prefix(PREV_PREFIX)?;
    let bytes = crate::cli::env_packs::base64_decode_public(encoded)?;
    let raw = std::str::from_utf8(&bytes).ok()?;
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_bundle_deployment, make_env, make_revision};
    use greentic_deploy_spec::RevisionLifecycle;
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
}
