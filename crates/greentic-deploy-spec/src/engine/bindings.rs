//! Pure pack/extension-binding verb semantics (Phase D PR-4.2d).
//!
//! The bindings verb group (`op env-packs add | update | remove | rollback`
//! and `op extensions add | update | remove | rollback`) follows the
//! PR-4.2a engine contract: pure `&mut Environment` transforms with no
//! I/O and no key material. Both `LocalFsStore` (greentic-deployer,
//! behind a flock) and the operator-store-server (behind SQLite CAS)
//! drive the SAME functions, so the one-step-rollback stash contract and
//! the 1-per-slot rule cannot drift between local and remote.
//!
//! # Persist rule (read before calling)
//!
//! The simplest of the verb groups: every check runs BEFORE the single
//! mutation at the end of each transform, and there is no idempotent
//! no-op branch —
//!
//! - any `Ok(_)` — the env was mutated; persist it.
//! - any `Err(_)` — the env was not mutated; nothing to persist.
//!
//! The A8 `Idempotency-Key` is transport metadata only here (unlike the
//! traffic group, where it is domain state): the engine never sees it,
//! the server echoes it into the audit record, and replay caching is the
//! PR-4.3 ledger.
//!
//! # Stash bounding
//!
//! `update_*_binding` snapshots the prior binding into the new binding's
//! `previous_binding_ref` via [`inline_stash`] so one-step `rollback`
//! works without a sidecar history file. The snapshot is taken from a
//! clone with `previous_binding_ref` cleared — stashing the field as-is
//! would nest every prior stash inside the next (geometric growth across
//! routine updates) for history that one-step rollback can never reach
//! (`rollback_*_binding` clears the restored ref). Same fix and
//! regression-test shape as the traffic group's split stash.
//!
//! # Wire shapes
//!
//! [`PackBindingPayload`] / [`ExtensionBindingPayload`] /
//! [`ExtensionKeyedPayload`] double as the A8 request bodies (the
//! `/environments/{env}/packs[/{slot}[/rollback]]` and
//! `/environments/{env}/extensions[/rollback]` routes);
//! [`BindingGenerationOutcome`] is the response body for the verbs that
//! return `(binding, generation)` (`add` returns the bare binding). The
//! wire-format tests at the bottom pin the encoding the PR-3b client
//! established.
//!
//! # One place stricter than the moved local code
//!
//! [`add_pack_binding`] / [`update_pack_binding`] reject N-per-env slots
//! (`messaging` / `extension`) via [`CapabilitySlot::binds_in_packs`].
//! The deployer CLI already rejects these upstream (`op env-packs`
//! points at the right noun), so the check was unreachable through the
//! local path — but the store-server takes the binding straight off the
//! wire, and without the guard a remote client could wedge an N-per-env
//! binding into `packs`, where its second instance would be falsely
//! rejected as a duplicate slot. [`update_extension_binding`] similarly
//! rejects a replacement binding whose `(kind_path, instance_id)` differs
//! from the target key (`ExtensionKeyMismatch`, the pack family's
//! `SlotMismatch` mirror); CLI callers derive both from one payload so the
//! check is wire-surface-only.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

use crate::capability_slot::CapabilitySlot;
use crate::engine::ExtensionKey;
use crate::engine::inline_stash;
use crate::environment::{EnvPackBinding, Environment, ExtensionBinding};
use greentic_types::EnvId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a binding verb refused to mutate the environment. Display strings
/// are verbatim what `LocalFsStore` raised before the move (PR-4.2d), so
/// operator-facing CLI errors are unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BindingError {
    // --- pack family ---
    #[error("slot `{slot}` already bound on env `{env_id}`; use update")]
    SlotAlreadyBound { slot: CapabilitySlot, env_id: EnvId },
    #[error("slot `{slot}` not bound on env `{env_id}`")]
    SlotNotBound { slot: CapabilitySlot, env_id: EnvId },
    #[error("binding slot `{binding_slot}` does not match target slot `{target_slot}`")]
    SlotMismatch {
        binding_slot: CapabilitySlot,
        target_slot: CapabilitySlot,
    },
    /// N-per-env slots (`messaging` / `extension`) never bind in `packs`
    /// — see the module doc's "stricter than the moved local code" note.
    #[error("slot `{slot}` is N-per-env and does not bind in `packs`")]
    NotPackSlot { slot: CapabilitySlot },
    #[error("slot `{slot}` on env `{env_id}` has no previous binding to roll back to")]
    SlotNoPrevious { slot: CapabilitySlot, env_id: EnvId },
    #[error("previous binding payload `{}` missing for slot `{slot}`", prev_ref.display())]
    SlotSnapshotMissing {
        prev_ref: PathBuf,
        slot: CapabilitySlot,
    },
    #[error("slot `{slot}` on env `{env_id}`: generation overflow ({generation})")]
    SlotGenerationOverflow {
        slot: CapabilitySlot,
        env_id: EnvId,
        generation: u64,
    },

    // --- extension family ---
    #[error("extension `{key}` is already bound on env `{env_id}`; use update")]
    ExtensionAlreadyBound { key: ExtensionKey, env_id: EnvId },
    #[error("extension `{key}` not bound on env `{env_id}`")]
    ExtensionNotBound { key: ExtensionKey, env_id: EnvId },
    #[error("binding key `{binding_key}` does not match target key `{target_key}`")]
    ExtensionKeyMismatch {
        binding_key: ExtensionKey,
        target_key: ExtensionKey,
    },
    #[error("extension `{key}` on env `{env_id}` has no previous binding to roll back to")]
    ExtensionNoPrevious { key: ExtensionKey, env_id: EnvId },
    #[error("previous binding payload `{}` missing for extension `{key}`", prev_ref.display())]
    ExtensionSnapshotMissing {
        prev_ref: PathBuf,
        key: ExtensionKey,
    },
    #[error("extension `{key}` on env `{env_id}`: generation overflow ({generation})")]
    ExtensionGenerationOverflow {
        key: ExtensionKey,
        env_id: EnvId,
        generation: u64,
    },

    // --- both families ---
    #[error("snapshot prior binding: {detail}")]
    SnapshotEncode { detail: String },
    #[error("deserialise previous binding: {detail}")]
    SnapshotDecode { detail: String },
}

// ---------------------------------------------------------------------------
// Wire payloads / outcomes (shared client ⇄ server shapes)
// ---------------------------------------------------------------------------

/// Request body for `add_pack_binding` (POST `…/packs`) and
/// `update_pack_binding` (PATCH `…/packs/{slot}` — the target slot rides
/// the URL). Encoding pinned by the PR-3b client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackBindingPayload {
    pub binding: EnvPackBinding,
}

/// Request body for `add_extension_binding` (POST `…/extensions`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionBindingPayload {
    pub binding: ExtensionBinding,
}

/// Request body for the keyed extension verbs: `update` (PATCH,
/// `binding: Some(_)` required), `remove` (DELETE) and `rollback` (POST)
/// send the key only. One struct, three routes — the verbs diverge by
/// method/URL, exactly as the PR-3b client serializes them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionKeyedPayload {
    pub key: ExtensionKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<ExtensionBinding>,
}

/// Response body for the binding verbs that return `(binding,
/// new_generation)` — pack/extension `update`, `remove` and `rollback`
/// (`add` returns the bare binding). The generation is surfaced
/// explicitly for downstream observability even though the binding
/// carries it, pinning the PR-3b client's decode shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingGenerationOutcome<T> {
    pub binding: T,
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// Pure transforms — pack family
// ---------------------------------------------------------------------------

/// Bind a new env-pack slot. Rejects [`BindingError::SlotAlreadyBound`]
/// when the slot is already bound (callers should `update` instead) and
/// [`BindingError::NotPackSlot`] for N-per-env slots.
pub fn add_pack_binding(
    env: &mut Environment,
    binding: EnvPackBinding,
) -> Result<EnvPackBinding, BindingError> {
    if !binding.slot.binds_in_packs() {
        return Err(BindingError::NotPackSlot { slot: binding.slot });
    }
    if env.pack_for_slot(binding.slot).is_some() {
        return Err(BindingError::SlotAlreadyBound {
            slot: binding.slot,
            env_id: env.environment_id.clone(),
        });
    }
    env.packs.push(binding.clone());
    Ok(binding)
}

/// Replace the binding on an existing slot. Bumps `generation` to
/// `previous + 1` and stashes the prior binding inline (with its own
/// `previous_binding_ref` cleared — see the module doc's stash-bounding
/// note) so one-step [`rollback_pack_binding`] works.
///
/// Returns `(new_binding, new_generation)`.
pub fn update_pack_binding(
    env: &mut Environment,
    slot: CapabilitySlot,
    binding: EnvPackBinding,
) -> Result<(EnvPackBinding, u64), BindingError> {
    if !slot.binds_in_packs() {
        return Err(BindingError::NotPackSlot { slot });
    }
    let idx = find_pack_slot(env, slot)?;
    if binding.slot != slot {
        return Err(BindingError::SlotMismatch {
            binding_slot: binding.slot,
            target_slot: slot,
        });
    }
    let prev_generation = env.packs[idx].generation;
    let new_generation =
        prev_generation
            .checked_add(1)
            .ok_or_else(|| BindingError::SlotGenerationOverflow {
                slot,
                env_id: env.environment_id.clone(),
                generation: prev_generation,
            })?;
    // Snapshot a clone with the nested ref cleared — one-step rollback
    // can never reach deeper history, and stashing it would nest every
    // prior stash inside the next.
    let mut snapshot_source = env.packs[idx].clone();
    snapshot_source.previous_binding_ref = None;
    let prev_snapshot =
        serde_json::to_value(&snapshot_source).map_err(|e| BindingError::SnapshotEncode {
            detail: e.to_string(),
        })?;
    let mut new_binding = EnvPackBinding {
        generation: new_generation,
        ..binding
    };
    new_binding.previous_binding_ref = Some(inline_stash::stash_inline(prev_snapshot));
    env.packs[idx] = new_binding;
    Ok((env.packs[idx].clone(), new_generation))
}

/// Remove a pack-binding slot. Returns `(removed_binding,
/// removed_generation)`.
pub fn remove_pack_binding(
    env: &mut Environment,
    slot: CapabilitySlot,
) -> Result<(EnvPackBinding, u64), BindingError> {
    let idx = find_pack_slot(env, slot)?;
    let removed = env.packs.remove(idx);
    let generation = removed.generation;
    Ok((removed, generation))
}

/// Roll a pack-binding slot back to its one-step-previous snapshot.
/// Bumps generation past the current one and clears the restored ref so
/// a second rollback fails (single-step only).
///
/// Returns `(restored_binding, new_generation)`.
pub fn rollback_pack_binding(
    env: &mut Environment,
    slot: CapabilitySlot,
) -> Result<(EnvPackBinding, u64), BindingError> {
    let idx = find_pack_slot(env, slot)?;
    let prev_generation = env.packs[idx].generation;
    let new_generation =
        prev_generation
            .checked_add(1)
            .ok_or_else(|| BindingError::SlotGenerationOverflow {
                slot,
                env_id: env.environment_id.clone(),
                generation: prev_generation,
            })?;
    let prev_ref = env.packs[idx].previous_binding_ref.clone().ok_or_else(|| {
        BindingError::SlotNoPrevious {
            slot,
            env_id: env.environment_id.clone(),
        }
    })?;
    let prev_value = inline_stash::load_inline(&prev_ref)
        .ok_or(BindingError::SlotSnapshotMissing { prev_ref, slot })?;
    let mut restored: EnvPackBinding =
        serde_json::from_value(prev_value).map_err(|e| BindingError::SnapshotDecode {
            detail: e.to_string(),
        })?;
    restored.generation = new_generation;
    restored.previous_binding_ref = None;
    env.packs[idx] = restored;
    Ok((env.packs[idx].clone(), new_generation))
}

// ---------------------------------------------------------------------------
// Pure transforms — extension family
// ---------------------------------------------------------------------------

/// Add a new extension binding. Rejects
/// [`BindingError::ExtensionAlreadyBound`] when a binding with the same
/// `(kind.path(), instance_id)` key exists — a `None` instance and a
/// `Some(_)` instance on the same path are distinct and coexist.
pub fn add_extension_binding(
    env: &mut Environment,
    binding: ExtensionBinding,
) -> Result<ExtensionBinding, BindingError> {
    let key = ExtensionKey::from_binding(&binding);
    if env.extensions.iter().any(|b| key.matches(b)) {
        return Err(BindingError::ExtensionAlreadyBound {
            key,
            env_id: env.environment_id.clone(),
        });
    }
    env.extensions.push(binding.clone());
    Ok(binding)
}

/// Replace an existing extension binding identified by `key`. Bumps
/// `generation` to `previous + 1` and stashes the prior binding inline
/// (nested ref cleared — see the module doc) so one-step
/// [`rollback_extension_binding`] works.
///
/// Returns `(new_binding, new_generation)`.
pub fn update_extension_binding(
    env: &mut Environment,
    key: &ExtensionKey,
    binding: ExtensionBinding,
) -> Result<(ExtensionBinding, u64), BindingError> {
    let idx = find_extension(env, key)?;
    let binding_key = ExtensionKey::from_binding(&binding);
    if binding_key != *key {
        return Err(BindingError::ExtensionKeyMismatch {
            binding_key,
            target_key: key.clone(),
        });
    }
    let prev_generation = env.extensions[idx].generation;
    let new_generation = prev_generation.checked_add(1).ok_or_else(|| {
        BindingError::ExtensionGenerationOverflow {
            key: key.clone(),
            env_id: env.environment_id.clone(),
            generation: prev_generation,
        }
    })?;
    let mut snapshot_source = env.extensions[idx].clone();
    snapshot_source.previous_binding_ref = None;
    let prev_snapshot =
        serde_json::to_value(&snapshot_source).map_err(|e| BindingError::SnapshotEncode {
            detail: e.to_string(),
        })?;
    let mut new_binding = binding;
    new_binding.generation = new_generation;
    new_binding.previous_binding_ref = Some(inline_stash::stash_inline(prev_snapshot));
    env.extensions[idx] = new_binding;
    Ok((env.extensions[idx].clone(), new_generation))
}

/// Remove an extension binding identified by `key`. Returns the removed
/// binding and its generation at the time of removal.
pub fn remove_extension_binding(
    env: &mut Environment,
    key: &ExtensionKey,
) -> Result<(ExtensionBinding, u64), BindingError> {
    let idx = find_extension(env, key)?;
    let removed = env.extensions.remove(idx);
    let generation = removed.generation;
    Ok((removed, generation))
}

/// Roll an extension binding back to its one-step-previous snapshot.
/// Bumps generation past the current one and clears the restored ref so
/// a second rollback fails (single-step only).
///
/// Returns `(restored_binding, new_generation)`.
pub fn rollback_extension_binding(
    env: &mut Environment,
    key: &ExtensionKey,
) -> Result<(ExtensionBinding, u64), BindingError> {
    let idx = find_extension(env, key)?;
    let prev_generation = env.extensions[idx].generation;
    let new_generation = prev_generation.checked_add(1).ok_or_else(|| {
        BindingError::ExtensionGenerationOverflow {
            key: key.clone(),
            env_id: env.environment_id.clone(),
            generation: prev_generation,
        }
    })?;
    let prev_ref = env.extensions[idx]
        .previous_binding_ref
        .clone()
        .ok_or_else(|| BindingError::ExtensionNoPrevious {
            key: key.clone(),
            env_id: env.environment_id.clone(),
        })?;
    let prev_value = inline_stash::load_inline(&prev_ref).ok_or_else(|| {
        BindingError::ExtensionSnapshotMissing {
            prev_ref,
            key: key.clone(),
        }
    })?;
    let mut restored: ExtensionBinding =
        serde_json::from_value(prev_value).map_err(|e| BindingError::SnapshotDecode {
            detail: e.to_string(),
        })?;
    restored.generation = new_generation;
    restored.previous_binding_ref = None;
    env.extensions[idx] = restored;
    Ok((env.extensions[idx].clone(), new_generation))
}

/// Locate the pack binding for `slot`, mirroring [`find_extension`] for
/// the pack family.
fn find_pack_slot(env: &Environment, slot: CapabilitySlot) -> Result<usize, BindingError> {
    env.packs
        .iter()
        .position(|b| b.slot == slot)
        .ok_or_else(|| BindingError::SlotNotBound {
            slot,
            env_id: env.environment_id.clone(),
        })
}

fn find_extension(env: &Environment, key: &ExtensionKey) -> Result<usize, BindingError> {
    env.extensions
        .iter()
        .position(|b| key.matches(b))
        .ok_or_else(|| BindingError::ExtensionNotBound {
            key: key.clone(),
            env_id: env.environment_id.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_slot::PackDescriptor;
    use crate::engine::fresh_environment;
    use crate::environment::EnvironmentHostConfig;
    use crate::ids::PackId;
    use crate::retention::{HealthStatus, RetentionPolicy, RevocationConfig};

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn minimal_env() -> Environment {
        fresh_environment(
            &env_id(),
            "Local".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            },
            RevocationConfig::default(),
            RetentionPolicy::default(),
            HealthStatus::default(),
        )
    }

    fn pack(slot: CapabilitySlot, kind: &str) -> EnvPackBinding {
        EnvPackBinding {
            slot,
            kind: PackDescriptor::try_new(format!("{kind}@1.0.0")).unwrap(),
            pack_ref: PackId::new(kind),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        }
    }

    fn ext(kind: &str, instance: Option<&str>) -> ExtensionBinding {
        ExtensionBinding {
            kind: PackDescriptor::try_new(format!("{kind}@0.1.0")).unwrap(),
            pack_ref: PackId::new(kind),
            instance_id: instance.map(str::to_string),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        }
    }

    // --- pack family ---

    #[test]
    fn add_pack_binding_appends_and_returns_binding() {
        let mut env = minimal_env();
        let added = add_pack_binding(&mut env, pack(CapabilitySlot::Secrets, "greentic.secrets"))
            .expect("fresh slot binds");
        assert_eq!(added.slot, CapabilitySlot::Secrets);
        assert_eq!(env.packs.len(), 1);
    }

    #[test]
    fn add_pack_binding_rejects_bound_slot() {
        let mut env = minimal_env();
        env.packs
            .push(pack(CapabilitySlot::Secrets, "greentic.secrets"));
        let err = add_pack_binding(&mut env, pack(CapabilitySlot::Secrets, "greentic.other"))
            .unwrap_err();
        assert!(matches!(err, BindingError::SlotAlreadyBound { .. }));
        assert_eq!(
            err.to_string(),
            "slot `secrets` already bound on env `local`; use update"
        );
        assert_eq!(env.packs.len(), 1, "env untouched on Err");
    }

    #[test]
    fn add_pack_binding_rejects_n_per_env_slots() {
        let mut env = minimal_env();
        for slot in [CapabilitySlot::Messaging, CapabilitySlot::Extension] {
            let err = add_pack_binding(&mut env, pack(slot, "greentic.thing")).unwrap_err();
            assert!(matches!(err, BindingError::NotPackSlot { .. }), "{slot}");
        }
        assert!(env.packs.is_empty());
    }

    #[test]
    fn update_pack_binding_bumps_generation_and_stashes_previous() {
        let mut env = minimal_env();
        env.packs
            .push(pack(CapabilitySlot::Secrets, "greentic.secrets"));
        let (updated, generation) = update_pack_binding(
            &mut env,
            CapabilitySlot::Secrets,
            pack(CapabilitySlot::Secrets, "greentic.vault"),
        )
        .expect("bound slot updates");
        assert_eq!(generation, 1);
        assert_eq!(updated.generation, 1);
        assert_eq!(updated.kind.as_str(), "greentic.vault@1.0.0");
        let stash = updated.previous_binding_ref.expect("prior binding stashed");
        let prev = inline_stash::load_inline(&stash).expect("stash decodes");
        assert_eq!(prev["kind"], "greentic.secrets@1.0.0");
    }

    #[test]
    fn update_pack_binding_rejects_unbound_slot_and_slot_mismatch() {
        let mut env = minimal_env();
        let err = update_pack_binding(
            &mut env,
            CapabilitySlot::Secrets,
            pack(CapabilitySlot::Secrets, "greentic.vault"),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "slot `secrets` not bound on env `local`");

        env.packs
            .push(pack(CapabilitySlot::Secrets, "greentic.secrets"));
        let err = update_pack_binding(
            &mut env,
            CapabilitySlot::Secrets,
            pack(CapabilitySlot::State, "greentic.state"),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "binding slot `state` does not match target slot `secrets`"
        );
        assert_eq!(env.packs[0].generation, 0, "env untouched on Err");
    }

    #[test]
    fn update_pack_binding_rejects_n_per_env_slots() {
        let mut env = minimal_env();
        let err = update_pack_binding(
            &mut env,
            CapabilitySlot::Messaging,
            pack(CapabilitySlot::Messaging, "greentic.slack"),
        )
        .unwrap_err();
        assert!(matches!(err, BindingError::NotPackSlot { .. }));
    }

    #[test]
    fn remove_pack_binding_returns_removed_binding() {
        let mut env = minimal_env();
        env.packs.push(EnvPackBinding {
            generation: 3,
            ..pack(CapabilitySlot::Secrets, "greentic.secrets")
        });
        let (removed, generation) =
            remove_pack_binding(&mut env, CapabilitySlot::Secrets).expect("bound slot removes");
        assert_eq!(generation, 3);
        assert_eq!(removed.kind.as_str(), "greentic.secrets@1.0.0");
        assert!(env.packs.is_empty());

        let err = remove_pack_binding(&mut env, CapabilitySlot::Secrets).unwrap_err();
        assert!(matches!(err, BindingError::SlotNotBound { .. }));
    }

    #[test]
    fn rollback_pack_binding_restores_previous_once() {
        let mut env = minimal_env();
        env.packs
            .push(pack(CapabilitySlot::Secrets, "greentic.secrets"));
        update_pack_binding(
            &mut env,
            CapabilitySlot::Secrets,
            pack(CapabilitySlot::Secrets, "greentic.vault"),
        )
        .unwrap();

        let (restored, generation) =
            rollback_pack_binding(&mut env, CapabilitySlot::Secrets).expect("stash restores");
        assert_eq!(generation, 2, "rollback advances generation");
        assert_eq!(restored.kind.as_str(), "greentic.secrets@1.0.0");
        assert!(
            restored.previous_binding_ref.is_none(),
            "restored ref cleared — single-step only"
        );

        let err = rollback_pack_binding(&mut env, CapabilitySlot::Secrets).unwrap_err();
        assert_eq!(
            err.to_string(),
            "slot `secrets` on env `local` has no previous binding to roll back to"
        );
    }

    #[test]
    fn pack_stash_is_bounded_to_one_level_across_multiple_updates() {
        let mut env = minimal_env();
        env.packs.push(pack(CapabilitySlot::Secrets, "greentic.a"));
        update_pack_binding(
            &mut env,
            CapabilitySlot::Secrets,
            pack(CapabilitySlot::Secrets, "greentic.b"),
        )
        .unwrap();
        let after_second = env.packs[0]
            .previous_binding_ref
            .clone()
            .expect("stash present");
        update_pack_binding(
            &mut env,
            CapabilitySlot::Secrets,
            pack(CapabilitySlot::Secrets, "greentic.c"),
        )
        .unwrap();
        let after_third = env.packs[0]
            .previous_binding_ref
            .clone()
            .expect("stash present");

        let decoded = inline_stash::load_inline(&after_third).expect("stash decodes");
        assert!(
            decoded.get("previous_binding_ref").is_none(),
            "stashed snapshot must not nest the prior stash"
        );
        // Token length stays flat (identical payload sizes) rather than
        // growing by the previous token's length.
        let len = |p: &std::path::Path| p.as_os_str().len();
        assert!(
            len(&after_third) <= len(&after_second) + 8,
            "stash grew: {} -> {}",
            len(&after_second),
            len(&after_third)
        );
    }

    // --- extension family ---

    #[test]
    fn add_extension_binding_distinguishes_instances() {
        let mut env = minimal_env();
        add_extension_binding(&mut env, ext("greentic.memory", None)).expect("default instance");
        add_extension_binding(&mut env, ext("greentic.memory", Some("alt")))
            .expect("named instance coexists with default");
        assert_eq!(env.extensions.len(), 2);

        let err = add_extension_binding(&mut env, ext("greentic.memory", None)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "extension `greentic.memory` is already bound on env `local`; use update"
        );
        assert_eq!(env.extensions.len(), 2, "env untouched on Err");
    }

    #[test]
    fn update_extension_binding_bumps_generation_and_stashes_previous() {
        let mut env = minimal_env();
        env.extensions.push(ext("greentic.memory", Some("alt")));
        let key = ExtensionKey::new("greentic.memory", Some("alt".to_string()));
        let (updated, generation) = update_extension_binding(
            &mut env,
            &key,
            ExtensionBinding {
                pack_ref: PackId::new("greentic.memory-v2"),
                ..ext("greentic.memory", Some("alt"))
            },
        )
        .expect("bound key updates");
        assert_eq!(generation, 1);
        assert_eq!(updated.pack_ref.as_str(), "greentic.memory-v2");
        let stash = updated.previous_binding_ref.expect("prior binding stashed");
        let prev = inline_stash::load_inline(&stash).expect("stash decodes");
        assert_eq!(prev["pack_ref"], "greentic.memory");
    }

    #[test]
    fn update_extension_binding_rejects_unbound_key() {
        let mut env = minimal_env();
        let key = ExtensionKey::new("greentic.memory", None);
        let err =
            update_extension_binding(&mut env, &key, ext("greentic.memory", None)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "extension `greentic.memory` not bound on env `local`"
        );
    }

    #[test]
    fn update_extension_binding_rejects_key_mismatch() {
        let mut env = minimal_env();
        env.extensions.push(ext("greentic.memory", None));
        let key = ExtensionKey::new("greentic.memory", None);
        // The replacement binding carries a different instance_id.
        let err = update_extension_binding(&mut env, &key, ext("greentic.memory", Some("alt")))
            .unwrap_err();
        assert!(
            matches!(err, BindingError::ExtensionKeyMismatch { .. }),
            "expected ExtensionKeyMismatch, got: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "binding key `greentic.memory/alt` does not match target key `greentic.memory`"
        );
        assert_eq!(env.extensions.len(), 1, "env untouched on Err");
        assert_eq!(env.extensions[0].generation, 0, "generation untouched");
    }

    #[test]
    fn remove_extension_binding_returns_removed_binding() {
        let mut env = minimal_env();
        env.extensions.push(ExtensionBinding {
            generation: 2,
            ..ext("greentic.memory", None)
        });
        let key = ExtensionKey::new("greentic.memory", None);
        let (removed, generation) =
            remove_extension_binding(&mut env, &key).expect("bound key removes");
        assert_eq!(generation, 2);
        assert_eq!(removed.pack_ref.as_str(), "greentic.memory");
        assert!(env.extensions.is_empty());
    }

    #[test]
    fn rollback_extension_binding_restores_previous_once() {
        let mut env = minimal_env();
        env.extensions.push(ext("greentic.memory", None));
        let key = ExtensionKey::new("greentic.memory", None);
        update_extension_binding(
            &mut env,
            &key,
            ExtensionBinding {
                pack_ref: PackId::new("greentic.memory-v2"),
                ..ext("greentic.memory", None)
            },
        )
        .unwrap();

        let (restored, generation) =
            rollback_extension_binding(&mut env, &key).expect("stash restores");
        assert_eq!(generation, 2);
        assert_eq!(restored.pack_ref.as_str(), "greentic.memory");
        assert!(restored.previous_binding_ref.is_none());

        let err = rollback_extension_binding(&mut env, &key).unwrap_err();
        assert_eq!(
            err.to_string(),
            "extension `greentic.memory` on env `local` has no previous binding to roll back to"
        );
    }

    #[test]
    fn extension_stash_is_bounded_to_one_level_across_multiple_updates() {
        let mut env = minimal_env();
        env.extensions.push(ext("greentic.memory", None));
        let key = ExtensionKey::new("greentic.memory", None);
        for _ in 0..3 {
            update_extension_binding(&mut env, &key, ext("greentic.memory", None)).unwrap();
        }
        let stash = env.extensions[0]
            .previous_binding_ref
            .clone()
            .expect("stash present");
        let decoded = inline_stash::load_inline(&stash).expect("stash decodes");
        assert!(
            decoded.get("previous_binding_ref").is_none(),
            "stashed snapshot must not nest the prior stash"
        );
    }

    // --- wire-format pinning (PR-3b client encoding) ---

    #[test]
    fn pack_binding_payload_wire_format() {
        let payload = PackBindingPayload {
            binding: pack(CapabilitySlot::Secrets, "greentic.secrets"),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["binding"]["slot"], "secrets");
        assert_eq!(json["binding"]["kind"], "greentic.secrets@1.0.0");
        let back: PackBindingPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back.binding, payload.binding);
    }

    #[test]
    fn extension_keyed_payload_wire_format() {
        // Keyed verbs without a binding: the field is absent, the
        // (explicitly null) instance_id is present — exactly what the
        // PR-3b client's `WireExtensionKey` emitted.
        let keyed = ExtensionKeyedPayload {
            key: ExtensionKey::new("greentic.memory", None),
            binding: None,
        };
        let json = serde_json::to_value(&keyed).unwrap();
        assert_eq!(json["key"]["kind_path"], "greentic.memory");
        assert!(json["key"]["instance_id"].is_null());
        assert!(json.get("binding").is_none(), "absent when None");

        let back: ExtensionKeyedPayload =
            serde_json::from_value(serde_json::json!({"key": {"kind_path": "greentic.memory"}}))
                .unwrap();
        assert_eq!(back.key.instance_id, None, "absent instance_id decodes");
        assert!(back.binding.is_none());
    }

    #[test]
    fn binding_generation_outcome_wire_format() {
        let outcome = BindingGenerationOutcome {
            binding: ext("greentic.memory", Some("alt")),
            generation: 4,
        };
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["generation"], 4);
        assert_eq!(json["binding"]["instance_id"], "alt");
        let back: BindingGenerationOutcome<ExtensionBinding> =
            serde_json::from_value(json).unwrap();
        assert_eq!(back.binding, outcome.binding);
        assert_eq!(back.generation, 4);
    }
}
