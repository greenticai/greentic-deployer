//! `op traffic clear` (unified release Phase 5, PD1).
//!
//! Two shapes, both explicit and both idempotent:
//!
//! - `--survivor <revision>` — the split moves to 100 % on that revision.
//!   Runs through the same `set_traffic_split` verb as `op traffic set`, so
//!   §5.3 admission (the survivor must be `Ready`), the one-step rollback
//!   stash and the telemetry are unchanged. With no caller key the
//!   idempotency key is derived from `(deployment, survivor)`, so a retry
//!   replays instead of advancing the generation.
//! - no survivor — the split is removed outright. Accepted only for a
//!   deployment already marked retiring (status `archived`); on a live one
//!   it would take the deployment offline, which is `op bundles retire`'s
//!   decision to make, not a traffic verb's.

use greentic_deploy_spec::{DeploymentId, EnvId, IdempotencyKey, RevisionId, TrafficSplitEntry};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::dispatch::TrafficClearArgs;
use super::traffic::{TrafficSummary, emit_applied_telemetry, map_traffic_store_err};
use super::{AuditCtx, AuditGens, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "traffic";
const VERB: &str = "clear";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficClearPayload {
    pub environment_id: String,
    pub deployment_id: String,
    /// Revision that keeps 100 % of the traffic. Absent = remove the split
    /// (retiring deployments only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub survivor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

/// Build the payload from clap args; `None` when no positional/flag was
/// given (the payload then comes from `--answers`).
pub fn payload_from_clear_args(
    args: TrafficClearArgs,
) -> Result<Option<TrafficClearPayload>, OpError> {
    let TrafficClearArgs {
        env_id,
        deployment,
        survivor,
        idempotency_key,
    } = args;
    if env_id.is_none() && deployment.is_none() && survivor.is_none() {
        return Ok(None);
    }
    let environment_id = env_id.ok_or_else(|| {
        OpError::InvalidArgument("traffic clear: missing positional `<env_id>`".to_string())
    })?;
    let deployment_id = deployment.ok_or_else(|| {
        OpError::InvalidArgument("traffic clear: missing `--deployment <ULID>`".to_string())
    })?;
    Ok(Some(TrafficClearPayload {
        environment_id,
        deployment_id,
        survivor,
        idempotency_key,
        updated_by: None,
    }))
}

pub fn clear(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<TrafficClearPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, VERB, clear_schema()));
    }
    let payload = match payload {
        Some(p) => p,
        None => match &flags.answers {
            Some(path) => super::load_answers::<TrafficClearPayload>(path)?,
            None => {
                return Err(OpError::InvalidArgument(
                    "no payload provided: pass `<env_id> --deployment <ULID>` or --answers <path>"
                        .to_string(),
                ));
            }
        },
    };
    let env_id = EnvId::try_from(payload.environment_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))?;
    let deployment_id = DeploymentId(parse_ulid("deployment_id", &payload.deployment_id)?);
    let survivor = payload
        .survivor
        .as_deref()
        .map(|raw| parse_ulid("survivor", raw).map(RevisionId))
        .transpose()?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let key = match (&payload.idempotency_key, survivor) {
        (Some(raw), _) => IdempotencyKey::new(raw.clone()),
        (None, Some(rev)) => IdempotencyKey::new(format!("traffic-clear:{deployment_id}:{rev}")),
        (None, None) => IdempotencyKey::new(format!("traffic-clear:{deployment_id}")),
    }
    .map_err(|e| OpError::InvalidArgument(format!("idempotency_key: {e}")))?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: VERB,
        target: json!({
            "deployment_id": deployment_id.to_string(),
            "survivor": survivor.map(|r| r.to_string()),
        }),
        idempotency_key: Some(key.as_str().to_string()),
    };
    let updated_by = payload
        .updated_by
        .unwrap_or_else(super::traffic::default_updated_by);
    audit_and_record(store, ctx, |committed| match survivor {
        Some(rev) => to_survivor(
            store,
            &env_id,
            deployment_id,
            rev,
            key,
            updated_by,
            committed,
        ),
        None => remove_split(store, &env_id, deployment_id, committed),
    })
}

fn to_survivor(
    store: &LocalFsStore,
    env_id: &EnvId,
    deployment_id: DeploymentId,
    survivor: RevisionId,
    key: IdempotencyKey,
    updated_by: String,
    committed: &super::CommitMarker,
) -> Result<(OpOutcome, AuditGens), OpError> {
    let outcome = store
        .set_traffic_split(
            env_id,
            greentic_deploy_spec::SetTrafficSplitPayload {
                deployment_id,
                entries: vec![TrafficSplitEntry {
                    revision_id: survivor,
                    weight_bps: 10_000,
                }],
                updated_by,
                authorization_ref: None,
            },
            key,
        )
        .inspect_err(|err| {
            if err.is_committed_after_save() {
                committed.mark_committed();
            }
        })
        .map_err(map_traffic_store_err)?;
    emit_applied_telemetry(&outcome);
    let split = serde_json::to_value(TrafficSummary::from(env_id, &outcome.split))
        .map_err(|e| OpError::SchemaGeneration(format!("traffic summary: {e}")))?;
    let result = json!({
        "environment_id": env_id.as_str(),
        "deployment_id": deployment_id.to_string(),
        "mode": "survivor",
        "survivor": survivor.to_string(),
        "changed": outcome.new_generation.is_some(),
        "split": split,
    });
    let gens = AuditGens {
        previous: outcome.previous_generation,
        new: outcome.new_generation,
    };
    Ok((OpOutcome::new(NOUN, VERB, result), gens))
}

fn remove_split(
    store: &LocalFsStore,
    env_id: &EnvId,
    deployment_id: DeploymentId,
    committed: &super::CommitMarker,
) -> Result<(OpOutcome, AuditGens), OpError> {
    let outcome = store
        .clear_traffic_split(env_id, deployment_id)
        .inspect_err(|err| {
            if err.is_committed_after_save() {
                committed.mark_committed();
            }
        })
        .map_err(super::map_store_err_preserving_noun)?;
    let result = json!({
        "environment_id": env_id.as_str(),
        "deployment_id": deployment_id.to_string(),
        "mode": "cleared",
        "changed": outcome.mutated(),
        "cleared_generation": outcome.cleared.as_ref().map(|s| s.generation),
    });
    let gens = AuditGens {
        previous: outcome.cleared.as_ref().map(|s| s.generation),
        new: None,
    };
    Ok((OpOutcome::new(NOUN, VERB, result), gens))
}

fn parse_ulid(field: &str, raw: &str) -> Result<ulid::Ulid, OpError> {
    use std::str::FromStr;
    ulid::Ulid::from_str(raw).map_err(|e| OpError::InvalidArgument(format!("{field}: {e}")))
}

fn clear_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TrafficClearPayload",
        "type": "object",
        "required": ["environment_id", "deployment_id"],
        "properties": {
            "environment_id": {"type": "string"},
            "deployment_id": {"type": "string", "description": "Deployment ULID"},
            "survivor": {
                "type": "string",
                "description": "Revision ULID that keeps 100 % of the traffic. Absent = remove \
                                the split (only for a deployment already retiring)."
            },
            "idempotency_key": {"type": "string"},
            "updated_by": {"type": "string"}
        },
        "additionalProperties": false
    })
}

#[cfg(test)]
#[path = "traffic_clear_tests.rs"]
mod tests;
