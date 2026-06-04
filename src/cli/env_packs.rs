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

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

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
    fn from_binding(env_id: &EnvId, b: &EnvPackBinding) -> Self {
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({"slot": payload.slot, "kind": payload.kind}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let summary = store.transact(&env_id, |locked| -> Result<BindingSummary, OpError> {
            let mut env = locked.load()?;
            if env.pack_for_slot(binding.slot).is_some() {
                return Err(OpError::Conflict(format!(
                    "slot `{}` already bound on env `{}`; use update",
                    binding.slot, env_id
                )));
            }
            env.packs.push(binding.clone());
            locked.save(&env)?;
            Ok(BindingSummary::from_binding(
                &env_id,
                env.packs.last().expect("just pushed"),
            ))
        })?;
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "update",
        target: json!({"slot": payload.slot, "kind": payload.kind}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let (summary, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let idx = env
                .packs
                .iter()
                .position(|b| b.slot == payload.slot)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "slot `{}` not bound on env `{}`",
                        payload.slot, env_id
                    ))
                })?;
            let prev_generation = env.packs[idx].generation;
            let prev_snapshot = serde_json::to_value(&env.packs[idx])
                .map_err(|e| OpError::InvalidArgument(format!("snapshot prior binding: {e}")))?;
            let mut new_binding = build_binding(&payload, prev_generation + 1, None)?;
            new_binding.previous_binding_ref = Some(stash_previous(prev_snapshot));
            env.packs[idx] = new_binding;
            locked.save(&env)?;
            let gens = super::AuditGens {
                previous: Some(prev_generation),
                new: Some(prev_generation + 1),
            };
            Ok::<_, OpError>((BindingSummary::from_binding(&env_id, &env.packs[idx]), gens))
        })?;
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({"slot": payload.slot}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let (summary, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let idx = env
                .packs
                .iter()
                .position(|b| b.slot == payload.slot)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "slot `{}` not bound on env `{}`",
                        payload.slot, env_id
                    ))
                })?;
            let removed = env.packs.remove(idx);
            locked.save(&env)?;
            let gens = super::AuditGens {
                previous: Some(removed.generation),
                new: None,
            };
            Ok::<_, OpError>((BindingSummary::from_binding(&env_id, &removed), gens))
        })?;
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rollback",
        target: json!({"slot": payload.slot}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let (summary, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let idx = env
                .packs
                .iter()
                .position(|b| b.slot == payload.slot)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "slot `{}` not bound on env `{}`",
                        payload.slot, env_id
                    ))
                })?;
            let prev_generation = env.packs[idx].generation;
            let prev_ref = env.packs[idx].previous_binding_ref.clone().ok_or_else(|| {
                OpError::Conflict(format!(
                    "slot `{}` on env `{}` has no previous binding to roll back to",
                    payload.slot, env_id
                ))
            })?;
            let prev_value = load_previous(&prev_ref).ok_or_else(|| {
                OpError::NotFound(format!(
                    "previous binding payload `{}` missing for slot `{}`",
                    prev_ref.display(),
                    payload.slot
                ))
            })?;
            let mut restored: EnvPackBinding = serde_json::from_value(prev_value).map_err(|e| {
                OpError::InvalidArgument(format!("deserialise previous binding: {e}"))
            })?;
            restored.generation = prev_generation + 1;
            restored.previous_binding_ref = None;
            env.packs[idx] = restored;
            locked.save(&env)?;
            let gens = super::AuditGens {
                previous: Some(prev_generation),
                new: Some(prev_generation + 1),
            };
            Ok::<_, OpError>((BindingSummary::from_binding(&env_id, &env.packs[idx]), gens))
        })?;
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

fn build_binding(
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
            "answers_ref": {"type": ["string", "null"]}
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
            "slot": {"type": "string", "enum": ["deployer", "secrets", "telemetry", "sessions", "state", "revocation"]}
        }
    })
}

// Stash + reload previous binding payload.
//
// Phase A keeps the operator's local-only `EnvironmentStore` surface
// dependency-free; rather than adding a sibling history-log file (which
// would need its own backup/lock contract), we stash the previous JSON
// inside the new binding's `previous_binding_ref` *by encoding it directly*
// as a base64 JSON token under a sentinel path prefix. This is intentionally
// minimal — one step of rollback, no history — and matches the plan's note
// that multi-step history is A8's contract.

const PREV_PREFIX: &str = "inline://";

/// Stash a binding snapshot inline so `rollback` can restore it without a
/// sidecar history file. Reused by sibling N-collection nouns (e.g.
/// `extensions`) that share the one-step-rollback contract.
pub(crate) fn stash_previous(snapshot: Value) -> PathBuf {
    let mut encoded = String::from(PREV_PREFIX);
    let raw = serde_json::to_string(&snapshot).expect("Value re-serialises");
    encoded.push_str(&base64_encode(raw.as_bytes()));
    PathBuf::from(encoded)
}

pub(crate) fn load_previous(prev_ref: &std::path::Path) -> Option<Value> {
    let token = prev_ref.to_str()?;
    let encoded = token.strip_prefix(PREV_PREFIX)?;
    let bytes = base64_decode(encoded)?;
    let raw = std::str::from_utf8(&bytes).ok()?;
    serde_json::from_str(raw).ok()
}

// Minimal URL-safe base64 (no_pad). Keeps the crate dep tree clean — `base64`
// is not currently a deployer dep, and pulling it in for an encoding used
// only by this one short path is the wrong trade.

/// Re-export for sibling cli modules (e.g. `traffic`) that want to reuse the
/// same `inline://` stash scheme.
pub(crate) fn base64_encode_public(input: &[u8]) -> String {
    base64_encode(input)
}

/// Re-export for sibling cli modules. Returns `None` on any malformed input.
pub(crate) fn base64_decode_public(input: &str) -> Option<Vec<u8>> {
    base64_decode(input)
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = val(bytes[i])?;
        let b1 = val(*bytes.get(i + 1)?)?;
        let b2 = bytes.get(i + 2).copied().and_then(val);
        let b3 = bytes.get(i + 3).copied().and_then(val);
        let triple = ((b0 as u32) << 18)
            | ((b1 as u32) << 12)
            | ((b2.unwrap_or(0) as u32) << 6)
            | (b3.unwrap_or(0) as u32);
        out.push(((triple >> 16) & 0xFF) as u8);
        if b2.is_some() {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if b3.is_some() {
            out.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Some(out)
}

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
    fn base64_roundtrip_smoke() {
        let cases = [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"hello world"[..],
            &b"\xff\x00\x42"[..],
        ];
        for case in cases {
            let encoded = base64_encode(case);
            let decoded = base64_decode(&encoded).expect("decode");
            assert_eq!(decoded.as_slice(), case);
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
}
