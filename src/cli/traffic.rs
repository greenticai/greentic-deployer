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
    BundleId, DeploymentId, EnvId, RevisionId, SchemaVersion, TrafficSplit, TrafficSplitEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{OpError, OpFlags, OpOutcome};

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
    let mut env = store.load(&env_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
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
    // Convert entries to basis points.
    let mut entries: Vec<TrafficSplitEntry> = Vec::with_capacity(payload.entries.len());
    for entry in &payload.entries {
        let bps = match (entry.weight_bps, entry.weight_percent) {
            (Some(bps), _) => bps,
            (None, Some(pct)) => {
                if pct > 100 {
                    return Err(OpError::InvalidArgument(format!(
                        "weight_percent {pct} > 100",
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
        // Sanity: the revision must exist in this env and belong to this
        // deployment. Environment::validate would catch a mismatch but the
        // operator-side check yields a cleaner error.
        let rev = env
            .revisions
            .iter()
            .find(|r| r.revision_id == revision_id)
            .ok_or_else(|| {
                OpError::NotFound(format!(
                    "revision `{revision_id}` not found in env `{env_id}`"
                ))
            })?;
        if rev.deployment_id != deployment_id {
            return Err(OpError::InvalidArgument(format!(
                "revision `{}` belongs to deployment `{}`, not `{}`",
                revision_id, rev.deployment_id, deployment_id,
            )));
        }
        entries.push(TrafficSplitEntry {
            revision_id,
            weight_bps: bps,
        });
    }
    let prev_split_idx = env
        .traffic_splits
        .iter()
        .position(|s| s.deployment_id == deployment_id);
    let (generation, previous_split_ref) = match prev_split_idx {
        Some(idx) => {
            let prev = &env.traffic_splits[idx];
            let snapshot = serde_json::to_value(prev)
                .map_err(|e| OpError::InvalidArgument(format!("snapshot prior split: {e}")))?;
            (prev.generation + 1, Some(stash_inline(snapshot)))
        }
        None => (0, None),
    };
    let split = TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id: env_id.clone(),
        deployment_id,
        bundle_id,
        generation,
        entries,
        updated_at: Utc::now(),
        updated_by: payload.updated_by,
        idempotency_key: payload.idempotency_key,
        authorization_ref: payload.authorization_ref,
        previous_split_ref,
    };
    // Validate sum == 10_000 before we touch disk.
    split.validate().map_err(OpError::Spec)?;
    match prev_split_idx {
        Some(idx) => env.traffic_splits[idx] = split.clone(),
        None => env.traffic_splits.push(split.clone()),
    }
    store.save(&env)?;
    Ok(OpOutcome::new(
        NOUN,
        "set",
        serde_json::to_value(TrafficSummary::from(&env_id, &split))
            .expect("TrafficSummary is json-safe"),
    ))
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
    let mut env = store.load(&env_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let idx = env
        .traffic_splits
        .iter()
        .position(|s| s.deployment_id == deployment_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "no traffic split for deployment `{deployment_id}` in env `{env_id}`"
            ))
        })?;
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
    let mut restored: TrafficSplit = serde_json::from_value(prev_value)
        .map_err(|e| OpError::InvalidArgument(format!("deserialise previous split: {e}")))?;
    // Bump generation past the current one so rollback is monotonic.
    restored.generation = env.traffic_splits[idx].generation + 1;
    restored.previous_split_ref = None;
    restored.updated_at = Utc::now();
    restored.idempotency_key = format!("rollback-{}", env.traffic_splits[idx].idempotency_key);
    restored.validate().map_err(OpError::Spec)?;
    env.traffic_splits[idx] = restored.clone();
    store.save(&env)?;
    Ok(OpOutcome::new(
        NOUN,
        "rollback",
        serde_json::to_value(TrafficSummary::from(&env_id, &restored))
            .expect("TrafficSummary is json-safe"),
    ))
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
}
