//! `gtc op env-packs {add,update,remove,rollback,list}` (`A3`).
//!
//! Manages `Environment.packs: Vec<EnvPackBinding>` — the env's bound
//! capability slots. The actual *resolution* of a `PackDescriptor` to a
//! native handler (deployer, secrets, telemetry, sessions, state) lives in
//! the env-pack registry (A9) and the wizard QASpec rendering lands in A10;
//! A3 builds only the binding-storage surface so the operator can declare
//! intent today.
//!
//! Mutations bump `EnvPackBinding.generation` and stash the prior binding
//! (full JSON) under `Environment` so `rollback` can restore it without a
//! database. Multi-step rollback (history > 1) is left to A8.

use std::path::PathBuf;

use greentic_deploy_spec::{CapabilitySlot, EnvId, EnvPackBinding, PackDescriptor, PackId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{
    AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record, map_store_err_preserving_noun,
    resolve_idempotency_key,
};

const NOUN: &str = "env-packs";

/// Payload for `op env-packs add` / `op env-packs update`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPackBindingPayload {
    pub environment_id: String,
    pub slot: CapabilitySlot,
    pub kind: String,
    pub pack_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_ref: Option<PathBuf>,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation. Operators
    /// wanting safe lost-response retries (HTTP backend, PR-3b) supply a
    /// stable key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Returned by every mutating call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingSummary {
    pub environment_id: String,
    pub slot: CapabilitySlot,
    pub kind: String,
    pub pack_ref: String,
    pub generation: u64,
    pub has_previous: bool,
}

impl BindingSummary {
    pub(crate) fn from_binding(env_id: &EnvId, b: &EnvPackBinding) -> Self {
        Self {
            environment_id: env_id.as_str().to_string(),
            slot: b.slot,
            kind: b.kind.to_string(),
            pack_ref: b.pack_ref.as_str().to_string(),
            generation: b.generation,
            has_previous: b.previous_binding_ref.is_some(),
        }
    }
}

pub fn add(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EnvPackBindingPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "add", payload_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let binding = build_binding(&payload, 0, None)?;
    let target = json!({"slot": payload.slot, "kind": payload.kind});
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target,
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let added = store
            .add_pack_binding(&env_id, binding, idempotency_key)
            .map_err(map_store_err_preserving_noun)?;
        let summary = BindingSummary::from_binding(&env_id, &added);
        let outcome = OpOutcome::new(
            NOUN,
            "add",
            serde_json::to_value(summary).expect("BindingSummary is json-safe"),
        );
        Ok((
            outcome,
            super::AuditGens {
                previous: None,
                new: Some(0),
            },
        ))
    })
}

pub fn update(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EnvPackBindingPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "update", payload_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let slot = payload.slot;
    let binding = build_binding(&payload, 0, None)?;
    let target = json!({"slot": payload.slot, "kind": payload.kind});
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "update",
        target,
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let (new_binding, new_generation) = store
            .update_pack_binding(&env_id, slot, binding, idempotency_key)
            .map_err(map_store_err_preserving_noun)?;
        let summary = BindingSummary::from_binding(&env_id, &new_binding);
        let gens = super::AuditGens {
            previous: Some(new_generation.saturating_sub(1)),
            new: Some(new_generation),
        };
        let outcome = OpOutcome::new(
            NOUN,
            "update",
            serde_json::to_value(summary).expect("BindingSummary is json-safe"),
        );
        Ok((outcome, gens))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPackRemovePayload {
    pub environment_id: String,
    pub slot: CapabilitySlot,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

pub fn remove(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EnvPackRemovePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "remove", remove_schema()));
    }
    let payload = resolve_payload::<EnvPackRemovePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let slot = payload.slot;
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({"slot": slot}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let (removed, removed_generation) = store
            .remove_pack_binding(&env_id, slot, idempotency_key)
            .map_err(map_store_err_preserving_noun)?;
        let summary = BindingSummary::from_binding(&env_id, &removed);
        let gens = super::AuditGens {
            previous: Some(removed_generation),
            new: None,
        };
        let outcome = OpOutcome::new(
            NOUN,
            "remove",
            serde_json::to_value(summary).expect("BindingSummary is json-safe"),
        );
        Ok((outcome, gens))
    })
}

pub fn rollback(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EnvPackRemovePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "rollback", remove_schema()));
    }
    let payload = resolve_payload::<EnvPackRemovePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let slot = payload.slot;
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rollback",
        target: json!({"slot": slot}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let (restored, new_generation) = store
            .rollback_pack_binding(&env_id, slot, idempotency_key)
            .map_err(map_store_err_preserving_noun)?;
        let summary = BindingSummary::from_binding(&env_id, &restored);
        let gens = super::AuditGens {
            previous: Some(new_generation.saturating_sub(1)),
            new: Some(new_generation),
        };
        let outcome = OpOutcome::new(
            NOUN,
            "rollback",
            serde_json::to_value(summary).expect("BindingSummary is json-safe"),
        );
        Ok((outcome, gens))
    })
}

pub fn list(store: &LocalFsStore, flags: &OpFlags, env_id: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "list",
            json!({"input_schema": "env_id positional"}),
        ));
    }
    let env_id = parse_env_id(env_id)?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let bindings: Vec<BindingSummary> = env
        .packs
        .iter()
        .map(|b| BindingSummary::from_binding(&env_id, b))
        .collect();
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({"environment_id": env_id.as_str(), "bindings": bindings}),
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

pub(crate) fn build_binding(
    payload: &EnvPackBindingPayload,
    generation: u64,
    previous_binding_ref: Option<PathBuf>,
) -> Result<EnvPackBinding, OpError> {
    // N-per-env slots (Messaging, Extension) live in their own collections,
    // never in `packs`. Reject them here with a pointer to the right noun so a
    // binding can't be wedged into `packs` where its second instance would be
    // falsely rejected as a duplicate slot.
    if !payload.slot.binds_in_packs() {
        let noun = match payload.slot {
            CapabilitySlot::Messaging => "op messaging endpoint",
            CapabilitySlot::Extension => "op extensions",
            _ => unreachable!("binds_in_packs() is false only for Messaging/Extension"),
        };
        return Err(OpError::InvalidArgument(format!(
            "slot `{}` is N-per-env and is not bound via `op env-packs`; use `{noun}` instead",
            payload.slot
        )));
    }
    let kind = PackDescriptor::try_new(payload.kind.clone())
        .map_err(|e| OpError::InvalidArgument(format!("kind: {e}")))?;
    Ok(EnvPackBinding {
        slot: payload.slot,
        kind,
        pack_ref: PackId::new(payload.pack_ref.clone()),
        answers_ref: payload.answers_ref.clone(),
        generation,
        previous_binding_ref,
    })
}

fn payload_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "EnvPackBindingPayload",
        "type": "object",
        "required": ["environment_id", "slot", "kind", "pack_ref"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "slot": {"type": "string", "enum": ["deployer", "secrets", "telemetry", "sessions", "state", "revocation"]},
            "kind": {"type": "string", "description": "PackDescriptor — `<namespace>.<id>@<semver>`."},
            "pack_ref": {"type": "string"},
            "answers_ref": {"type": ["string", "null"]},
            "idempotency_key": {
                "type": "string",
                "description": "Optional A8 §2 caller-supplied key for safe retry replay; minted per-invocation when omitted."
            }
        }
    })
}

fn remove_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "EnvPackRemovePayload",
        "type": "object",
        "required": ["environment_id", "slot"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "slot": {"type": "string", "enum": ["deployer", "secrets", "telemetry", "sessions", "state", "revocation"]},
            "idempotency_key": {
                "type": "string",
                "description": "Optional A8 §2 caller-supplied key for safe retry replay; minted per-invocation when omitted."
            }
        }
    })
}

// The previous-binding stash (one-step rollback, `inline://` base64
// tokens) lives in `greentic_deploy_spec::engine::inline_stash`; the
// binding verbs that write/read it moved to
// `greentic_deploy_spec::engine::bindings` in PR-4.2d, so this module no
// longer touches the encoding directly.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::LocalFsStore;
    use tempfile::tempdir;

    fn local_payload(slot: CapabilitySlot, kind: &str) -> EnvPackBindingPayload {
        EnvPackBindingPayload {
            environment_id: "local".to_string(),
            slot,
            kind: kind.to_string(),
            pack_ref: kind.split('@').next().unwrap_or(kind).to_string(),
            answers_ref: None,
            idempotency_key: None,
        }
    }

    #[test]
    fn add_then_list_returns_binding() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(local_payload(
                CapabilitySlot::Secrets,
                "greentic.secrets.dev-store@1.0.0",
            )),
        )
        .unwrap();
        assert_eq!(outcome.op, "add");
        let list_outcome = list(&store, &OpFlags::default(), "local").unwrap();
        let bindings = list_outcome
            .result
            .get("bindings")
            .and_then(|v| v.as_array())
            .expect("bindings array");
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].get("slot").and_then(|v| v.as_str()),
            Some("secrets")
        );
    }

    #[test]
    fn add_rejects_duplicate_slot() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let p = local_payload(CapabilitySlot::Secrets, "greentic.secrets.dev-store@1.0.0");
        add(&store, &OpFlags::default(), Some(p.clone())).unwrap();
        let err = add(&store, &OpFlags::default(), Some(p)).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn update_then_rollback_restores_previous() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let p1 = local_payload(CapabilitySlot::Secrets, "greentic.secrets.dev-store@1.0.0");
        add(&store, &OpFlags::default(), Some(p1.clone())).unwrap();

        let p2 = local_payload(CapabilitySlot::Secrets, "greentic.secrets.aws-sm@1.0.0");
        let updated = update(&store, &OpFlags::default(), Some(p2.clone())).unwrap();
        assert_eq!(
            updated.result.get("kind").and_then(|v| v.as_str()),
            Some("greentic.secrets.aws-sm@1.0.0")
        );
        assert_eq!(
            updated.result.get("generation").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            updated.result.get("has_previous").and_then(|v| v.as_bool()),
            Some(true)
        );

        let rolled = rollback(
            &store,
            &OpFlags::default(),
            Some(EnvPackRemovePayload {
                environment_id: "local".to_string(),
                slot: CapabilitySlot::Secrets,
                idempotency_key: None,
            }),
        )
        .unwrap();
        assert_eq!(
            rolled.result.get("kind").and_then(|v| v.as_str()),
            Some("greentic.secrets.dev-store@1.0.0")
        );
        assert_eq!(
            rolled.result.get("generation").and_then(|v| v.as_u64()),
            Some(2),
            "rollback bumps the generation past the update"
        );
    }

    #[test]
    fn remove_then_list_empty() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let p = local_payload(CapabilitySlot::Telemetry, "greentic.telemetry.stdout@1.0.0");
        add(&store, &OpFlags::default(), Some(p)).unwrap();
        remove(
            &store,
            &OpFlags::default(),
            Some(EnvPackRemovePayload {
                environment_id: "local".to_string(),
                slot: CapabilitySlot::Telemetry,
                idempotency_key: None,
            }),
        )
        .unwrap();
        let list_outcome = list(&store, &OpFlags::default(), "local").unwrap();
        let bindings = list_outcome
            .result
            .get("bindings")
            .and_then(|v| v.as_array())
            .expect("bindings array");
        assert!(bindings.is_empty());
    }

    #[test]
    fn rollback_without_history_errors() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let p = local_payload(CapabilitySlot::State, "greentic.state.in-memory@1.0.0");
        add(&store, &OpFlags::default(), Some(p)).unwrap();
        let err = rollback(
            &store,
            &OpFlags::default(),
            Some(EnvPackRemovePayload {
                environment_id: "local".to_string(),
                slot: CapabilitySlot::State,
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn add_rejects_n_per_env_slots() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        // Extension and Messaging are N-per-env: they live in their own
        // collections, not `packs`. `op env-packs` must refuse them with a
        // pointer to the right noun rather than wedge them into `packs`.
        for slot in [CapabilitySlot::Extension, CapabilitySlot::Messaging] {
            let err = add(
                &store,
                &OpFlags::default(),
                Some(local_payload(slot, "acme.oauth.auth0@1.0.0")),
            )
            .unwrap_err();
            assert!(
                matches!(err, OpError::InvalidArgument(_)),
                "slot {slot} should be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn concurrent_pack_adds_both_land() {
        // Codex regression: previously every mutator did bare
        // `store.load() → mutate → store.save()`, with the per-env flock
        // only held during save. Two parallel `add`s could both read the
        // same preimage and the later save would clobber the earlier
        // mutation. With every mutator now wrapped in `transact()`, both
        // bindings must survive.
        use std::sync::Arc;
        use std::thread;
        let dir = tempdir().unwrap();
        let store = Arc::new(LocalFsStore::new(dir.path()));
        store.save(&make_env("local")).unwrap();
        let store_a = Arc::clone(&store);
        let store_b = Arc::clone(&store);
        // Two slots, two threads. Without transact, one of these stomps
        // the other roughly half the time on a busy system.
        let h_a = thread::spawn(move || {
            add(
                &store_a,
                &OpFlags::default(),
                Some(local_payload(
                    CapabilitySlot::Secrets,
                    "greentic.secrets.dev-store@1.0.0",
                )),
            )
        });
        let h_b = thread::spawn(move || {
            add(
                &store_b,
                &OpFlags::default(),
                Some(local_payload(
                    CapabilitySlot::Telemetry,
                    "greentic.telemetry.stdout@1.0.0",
                )),
            )
        });
        h_a.join().unwrap().unwrap();
        h_b.join().unwrap().unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let bindings = listed
            .result
            .get("bindings")
            .and_then(|v| v.as_array())
            .expect("bindings array");
        assert_eq!(
            bindings.len(),
            2,
            "both slot bindings must survive concurrent transact()s"
        );
    }

    #[test]
    fn update_records_previous_and_new_generation_in_audit() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let p1 = local_payload(CapabilitySlot::Secrets, "greentic.secrets.dev-store@1.0.0");
        add(&store, &OpFlags::default(), Some(p1)).unwrap();
        let p2 = local_payload(CapabilitySlot::Secrets, "greentic.secrets.aws-sm@1.0.0");
        update(&store, &OpFlags::default(), Some(p2)).unwrap();
        let log = dir.path().join("local").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2, "add + update each emit one audit event");
        let update_event: crate::environment::AuditEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(update_event.verb, "update");
        assert_eq!(update_event.previous_generation, Some(0));
        assert_eq!(update_event.new_generation, Some(1));
    }

    // --- PR-3a.8: schema regression tests for idempotency_key ---------------

    /// `EnvPackBindingPayload` accepts `idempotency_key`; the schema
    /// published via `--schema` MUST list it so schema-driven callers can
    /// supply the A8 retry key.
    #[test]
    fn add_schema_lists_idempotency_key() {
        let schema = payload_schema();
        assert!(
            schema.pointer("/properties/idempotency_key").is_some(),
            "payload_schema must list `idempotency_key` (schema: {schema:#})"
        );
    }

    /// Same gate for the remove/rollback schema.
    #[test]
    fn remove_schema_lists_idempotency_key() {
        let schema = remove_schema();
        assert!(
            schema.pointer("/properties/idempotency_key").is_some(),
            "remove_schema must list `idempotency_key` (schema: {schema:#})"
        );
    }

    /// Audit events emitted by the typed-verb path carry the resolved
    /// idempotency key (either caller-supplied or freshly minted).
    #[test]
    fn add_audit_event_carries_idempotency_key() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let p = local_payload(CapabilitySlot::Secrets, "greentic.secrets.dev-store@1.0.0");
        add(&store, &OpFlags::default(), Some(p)).unwrap();
        let log = dir.path().join("local").join("audit").join("events.jsonl");
        let raw = std::fs::read_to_string(&log).unwrap();
        let event: crate::environment::AuditEvent =
            serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert!(
            event.idempotency_key.is_some(),
            "add audit event must carry an idempotency_key"
        );
    }

    /// Typed `remove_pack_binding` via the CLI correctly maps
    /// `StoreError::DependentNotFound` to `OpError::NotFound`.
    #[test]
    fn remove_missing_slot_returns_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = remove(
            &store,
            &OpFlags::default(),
            Some(EnvPackRemovePayload {
                environment_id: "local".to_string(),
                slot: CapabilitySlot::Secrets,
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    /// Typed `rollback_pack_binding` via the CLI correctly maps
    /// `StoreError::DependentNotFound` to `OpError::NotFound`.
    #[test]
    fn rollback_missing_slot_returns_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = rollback(
            &store,
            &OpFlags::default(),
            Some(EnvPackRemovePayload {
                environment_id: "local".to_string(),
                slot: CapabilitySlot::Secrets,
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }
}
