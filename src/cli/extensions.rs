//! `gtc op extensions {add,update,remove,rollback,list}` (`Path 3`).
//!
//! Manages `Environment.extensions: Vec<ExtensionBinding>` — the env's
//! open-namespace capability bindings. Unlike `op env-packs` (which manages the
//! closed, 1-per-slot core `packs`), extensions are **N-per-env**: their slot is
//! always [`CapabilitySlot::Extension`](greentic_deploy_spec::CapabilitySlot),
//! and identity is `(kind.path(), instance_id)` — the descriptor path plus an
//! optional instance selector for N instances of the same extension type.
//!
//! A workload resolves a binding by name at runtime via
//! `ext://<path>[/<instance>]`; no typed host interface is wired. Mutations bump
//! [`ExtensionBinding::generation`](greentic_deploy_spec::ExtensionBinding) and
//! stash the prior binding inline so `rollback` can restore it, reusing the same
//! one-step machinery as `env-packs`.

use std::path::PathBuf;

use greentic_deploy_spec::{EnvId, ExtensionBinding, PackDescriptor, PackId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::env_packs::{load_previous, stash_previous};
use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "extensions";

/// Payload for `op extensions add` / `op extensions update`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionBindingPayload {
    pub environment_id: String,
    pub kind: String,
    pub pack_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers_ref: Option<PathBuf>,
}

/// Payload for `op extensions remove` / `op extensions rollback`. Identifies a
/// binding by `(kind.path(), instance_id)` — the descriptor `@<version>` is
/// ignored for matching (the path is the version-independent key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionRemovePayload {
    pub environment_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

/// Returned by every mutating call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSummary {
    pub environment_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    pub pack_ref: String,
    pub generation: u64,
    pub has_previous: bool,
}

impl ExtensionSummary {
    fn from_binding(env_id: &EnvId, b: &ExtensionBinding) -> Self {
        Self {
            environment_id: env_id.as_str().to_string(),
            kind: b.kind.to_string(),
            instance_id: b.instance_id.clone(),
            pack_ref: b.pack_ref.as_str().to_string(),
            generation: b.generation,
            has_previous: b.previous_binding_ref.is_some(),
        }
    }
}

pub fn add(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<ExtensionBindingPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "add", payload_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let binding = build_binding(&payload, 0, None)?;
    let key = ExtensionKey::from_binding(&binding);
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({"kind": payload.kind, "instance_id": payload.instance_id}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let summary = store.transact(&env_id, |locked| -> Result<ExtensionSummary, OpError> {
            let mut env = locked.load()?;
            if env
                .extensions
                .iter()
                .any(|b| ExtensionKey::from_binding(b) == key)
            {
                return Err(OpError::Conflict(format!(
                    "extension `{}` is already bound on env `{}`; use update",
                    key, env_id
                )));
            }
            env.extensions.push(binding.clone());
            locked.save(&env)?;
            Ok(ExtensionSummary::from_binding(
                &env_id,
                env.extensions.last().expect("just pushed"),
            ))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "add",
            serde_json::to_value(summary).expect("ExtensionSummary is json-safe"),
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
    payload: Option<ExtensionBindingPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "update", payload_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let key = build_key(&payload.kind, &payload.instance_id)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "update",
        target: json!({"kind": payload.kind, "instance_id": payload.instance_id}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let (summary, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let idx = find_idx(&env.extensions, &key)
                .ok_or_else(|| OpError::NotFound(not_found_msg(&key, &env_id)))?;
            let prev_generation = env.extensions[idx].generation;
            let prev_snapshot = serde_json::to_value(&env.extensions[idx])
                .map_err(|e| OpError::InvalidArgument(format!("snapshot prior binding: {e}")))?;
            let mut new_binding = build_binding(&payload, prev_generation + 1, None)?;
            new_binding.previous_binding_ref = Some(stash_previous(prev_snapshot));
            env.extensions[idx] = new_binding;
            locked.save(&env)?;
            let gens = super::AuditGens {
                previous: Some(prev_generation),
                new: Some(prev_generation + 1),
            };
            Ok::<_, OpError>((
                ExtensionSummary::from_binding(&env_id, &env.extensions[idx]),
                gens,
            ))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "update",
            serde_json::to_value(summary).expect("ExtensionSummary is json-safe"),
        );
        Ok((outcome, gens))
    })
}

pub fn remove(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<ExtensionRemovePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "remove", remove_schema()));
    }
    let payload = resolve_payload::<ExtensionRemovePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let key = build_key(&payload.kind, &payload.instance_id)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({"kind": payload.kind, "instance_id": payload.instance_id}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let (summary, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let idx = find_idx(&env.extensions, &key)
                .ok_or_else(|| OpError::NotFound(not_found_msg(&key, &env_id)))?;
            let removed = env.extensions.remove(idx);
            locked.save(&env)?;
            let gens = super::AuditGens {
                previous: Some(removed.generation),
                new: None,
            };
            Ok::<_, OpError>((ExtensionSummary::from_binding(&env_id, &removed), gens))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "remove",
            serde_json::to_value(summary).expect("ExtensionSummary is json-safe"),
        );
        Ok((outcome, gens))
    })
}

pub fn rollback(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<ExtensionRemovePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "rollback", remove_schema()));
    }
    let payload = resolve_payload::<ExtensionRemovePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let key = build_key(&payload.kind, &payload.instance_id)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rollback",
        target: json!({"kind": payload.kind, "instance_id": payload.instance_id}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let (summary, gens) = store.transact(&env_id, |locked| {
            let mut env = locked.load()?;
            let idx = find_idx(&env.extensions, &key)
                .ok_or_else(|| OpError::NotFound(not_found_msg(&key, &env_id)))?;
            let prev_generation = env.extensions[idx].generation;
            let prev_ref = env.extensions[idx]
                .previous_binding_ref
                .clone()
                .ok_or_else(|| {
                    OpError::Conflict(format!(
                        "extension `{}` on env `{}` has no previous binding to roll back to",
                        key, env_id
                    ))
                })?;
            let prev_value = load_previous(&prev_ref).ok_or_else(|| {
                OpError::NotFound(format!(
                    "previous binding payload `{}` missing for extension `{}`",
                    prev_ref.display(),
                    key
                ))
            })?;
            let mut restored: ExtensionBinding =
                serde_json::from_value(prev_value).map_err(|e| {
                    OpError::InvalidArgument(format!("deserialise previous binding: {e}"))
                })?;
            restored.generation = prev_generation + 1;
            restored.previous_binding_ref = None;
            env.extensions[idx] = restored;
            locked.save(&env)?;
            let gens = super::AuditGens {
                previous: Some(prev_generation),
                new: Some(prev_generation + 1),
            };
            Ok::<_, OpError>((
                ExtensionSummary::from_binding(&env_id, &env.extensions[idx]),
                gens,
            ))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "rollback",
            serde_json::to_value(summary).expect("ExtensionSummary is json-safe"),
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
    let bindings: Vec<ExtensionSummary> = env
        .extensions
        .iter()
        .map(|b| ExtensionSummary::from_binding(&env_id, b))
        .collect();
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({"environment_id": env_id.as_str(), "extensions": bindings}),
    ))
}

// --- internals -----------------------------------------------------------

/// `(descriptor-path, instance_id)` — the uniqueness key for an extension
/// binding, version-independent by design.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExtensionKey {
    path: String,
    instance_id: Option<String>,
}

impl ExtensionKey {
    fn from_binding(b: &ExtensionBinding) -> Self {
        Self {
            path: b.kind.path().to_string(),
            instance_id: b.instance_id.clone(),
        }
    }
}

impl std::fmt::Display for ExtensionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.instance_id {
            Some(inst) => write!(f, "{}/{}", self.path, inst),
            None => f.write_str(&self.path),
        }
    }
}

fn find_idx(extensions: &[ExtensionBinding], key: &ExtensionKey) -> Option<usize> {
    extensions
        .iter()
        .position(|b| &ExtensionKey::from_binding(b) == key)
}

fn not_found_msg(key: &ExtensionKey, env_id: &EnvId) -> String {
    format!("extension `{key}` not bound on env `{env_id}`")
}

/// Build the lookup key from a remove/rollback payload's `kind` (path is the
/// version-independent key) and `instance_id`.
fn build_key(kind: &str, instance_id: &Option<String>) -> Result<ExtensionKey, OpError> {
    let descriptor = PackDescriptor::try_new(kind)
        .map_err(|e| OpError::InvalidArgument(format!("kind: {e}")))?;
    Ok(ExtensionKey {
        path: descriptor.path().to_string(),
        instance_id: instance_id.clone(),
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
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn build_binding(
    payload: &ExtensionBindingPayload,
    generation: u64,
    previous_binding_ref: Option<PathBuf>,
) -> Result<ExtensionBinding, OpError> {
    let kind = PackDescriptor::try_new(payload.kind.clone())
        .map_err(|e| OpError::InvalidArgument(format!("kind: {e}")))?;
    Ok(ExtensionBinding {
        kind,
        pack_ref: PackId::new(payload.pack_ref.clone()),
        instance_id: payload.instance_id.clone(),
        answers_ref: payload.answers_ref.clone(),
        generation,
        previous_binding_ref,
    })
}

fn payload_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ExtensionBindingPayload",
        "type": "object",
        "required": ["environment_id", "kind", "pack_ref"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "kind": {"type": "string", "description": "PackDescriptor — `<namespace>.<id>@<semver>`."},
            "pack_ref": {"type": "string"},
            "instance_id": {"type": ["string", "null"], "description": "Distinguishes N instances of the same extension; omit for the single default instance."},
            "answers_ref": {"type": ["string", "null"]}
        }
    })
}

fn remove_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ExtensionRemovePayload",
        "type": "object",
        "required": ["environment_id", "kind"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "kind": {"type": "string", "description": "PackDescriptor — `@<version>` is ignored; the path is the key."},
            "instance_id": {"type": ["string", "null"]}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::LocalFsStore;
    use tempfile::tempdir;

    fn payload(kind: &str, instance: Option<&str>) -> ExtensionBindingPayload {
        ExtensionBindingPayload {
            environment_id: "local".to_string(),
            kind: kind.to_string(),
            pack_ref: kind.split('@').next().unwrap_or(kind).to_string(),
            instance_id: instance.map(str::to_string),
            answers_ref: None,
        }
    }

    fn extensions(outcome: &OpOutcome) -> Vec<Value> {
        outcome
            .result
            .get("extensions")
            .and_then(|v| v.as_array())
            .expect("extensions array")
            .clone()
    }

    #[test]
    fn add_then_list_returns_binding() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", None)),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let bindings = extensions(&listed);
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].get("kind").and_then(|v| v.as_str()),
            Some("acme.oauth.auth0@1.0.0")
        );
    }

    #[test]
    fn add_allows_multiple_instances_same_path() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        // default (unnamed) + two named instances on the SAME path all coexist.
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", None)),
        )
        .unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", Some("primary"))),
        )
        .unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", Some("secondary"))),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(extensions(&listed).len(), 3);
    }

    #[test]
    fn add_rejects_duplicate_key() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let p = payload("acme.oauth.auth0@1.0.0", Some("primary"));
        add(&store, &OpFlags::default(), Some(p.clone())).unwrap();
        let err = add(&store, &OpFlags::default(), Some(p)).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn update_then_rollback_restores_previous() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", Some("primary"))),
        )
        .unwrap();
        let updated = update(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@2.0.0", Some("primary"))),
        )
        .unwrap();
        assert_eq!(
            updated.result.get("kind").and_then(|v| v.as_str()),
            Some("acme.oauth.auth0@2.0.0")
        );
        assert_eq!(
            updated.result.get("generation").and_then(|v| v.as_u64()),
            Some(1)
        );
        let rolled = rollback(
            &store,
            &OpFlags::default(),
            Some(ExtensionRemovePayload {
                environment_id: "local".to_string(),
                kind: "acme.oauth.auth0@2.0.0".to_string(),
                instance_id: Some("primary".to_string()),
            }),
        )
        .unwrap();
        assert_eq!(
            rolled.result.get("kind").and_then(|v| v.as_str()),
            Some("acme.oauth.auth0@1.0.0"),
            "rollback restores the pre-update version"
        );
        assert_eq!(
            rolled.result.get("generation").and_then(|v| v.as_u64()),
            Some(2)
        );
    }

    #[test]
    fn remove_targets_the_right_instance() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", Some("primary"))),
        )
        .unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", Some("secondary"))),
        )
        .unwrap();
        remove(
            &store,
            &OpFlags::default(),
            Some(ExtensionRemovePayload {
                environment_id: "local".to_string(),
                kind: "acme.oauth.auth0@9.9.9".to_string(), // version ignored
                instance_id: Some("primary".to_string()),
            }),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let bindings = extensions(&listed);
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].get("instance_id").and_then(|v| v.as_str()),
            Some("secondary")
        );
    }

    #[test]
    fn remove_absent_extension_errors_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = remove(
            &store,
            &OpFlags::default(),
            Some(ExtensionRemovePayload {
                environment_id: "local".to_string(),
                kind: "acme.oauth.auth0@1.0.0".to_string(),
                instance_id: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn rollback_after_remove_errors_not_found() {
        // Contract (parity with `env-packs`): `rollback` reverts the previous
        // `update`; `remove` is terminal. After a remove there is no binding to
        // roll back to — restore by re-adding, not by rollback.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", Some("primary"))),
        )
        .unwrap();
        remove(
            &store,
            &OpFlags::default(),
            Some(ExtensionRemovePayload {
                environment_id: "local".to_string(),
                kind: "acme.oauth.auth0@1.0.0".to_string(),
                instance_id: Some("primary".to_string()),
            }),
        )
        .unwrap();
        let err = rollback(
            &store,
            &OpFlags::default(),
            Some(ExtensionRemovePayload {
                environment_id: "local".to_string(),
                kind: "acme.oauth.auth0@1.0.0".to_string(),
                instance_id: Some("primary".to_string()),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn add_rejects_invalid_instance_id_at_save() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        // Uppercase is outside the instance-id charset; validate() at save
        // rejects it.
        let err = add(
            &store,
            &OpFlags::default(),
            Some(payload("acme.oauth.auth0@1.0.0", Some("Bad_Instance"))),
        )
        .unwrap_err();
        assert!(
            !matches!(err, OpError::Conflict(_)),
            "expected a validation error, got {err:?}"
        );
    }
}
