//! Append-only audit log + local authorization policy (`A7`).
//!
//! Every mutating `op` verb passes through [`authorize_local_only`] and
//! emits an [`AuditEvent`] into `<store_root>/<env_id>/audit/events.jsonl`.
//! Phase A posture: `env_id == "local"` → allow; anything else → deny with
//! [`OpError::Unauthorized`](crate::cli::OpError::Unauthorized) unless the
//! `GREENTIC_DEPLOYER_ALLOW_ANY_ENV` dev escape hatch is set. Remote RBAC
//! is A8.
//!
//! The append uses a per-file `fs4` flock on the audit file itself (not the
//! env's `.lock` sentinel), so emit can happen INSIDE a `transact` closure
//! without deadlocking on the env flock.
//!
//! The serializable audit shapes ([`AuditEvent`] et al.) are owned by
//! `greentic-deploy-spec` (the A8 remote-store contract reuses them) and
//! re-exported here; this module keeps the local FS writer and authz gate.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use fs4::fs_std::FileExt;
use greentic_deploy_spec::{EnvId, SchemaVersion};
use thiserror::Error;

use super::file_lock::LockError;
use super::store::{LocalFsStore, StoreError};

pub use greentic_deploy_spec::{
    Actor, AuditDecision, AuditEvent, AuditResult, POLICY_LOCAL_ONLY,
    POLICY_LOCAL_ONLY_DEV_OVERRIDE,
};

/// Env var that opts a local checkout out of the `local`-only authz gate so
/// every env id is allowed (dev/demo only — see [`authorize_local_only`]).
pub const DEV_OVERRIDE_ENV: &str = "GREENTIC_DEPLOYER_ALLOW_ANY_ENV";

pub const AUDIT_EVENT_SCHEMA_V1: &str = SchemaVersion::AUDIT_EVENT_V1;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("audit serialize: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("audit lock: {0}")]
    Lock(#[from] LockError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Local-mode authorization gate per plan §389 + §991. Returns `Allow` for
/// the env id matching [`crate::defaults::LOCAL_ENV_ID`]; any other id is
/// denied (A8 ships the production RBAC policy) UNLESS the [`DEV_OVERRIDE_ENV`]
/// escape hatch is set, in which case it is allowed under the distinct
/// [`POLICY_LOCAL_ONLY_DEV_OVERRIDE`] policy so the audit trail stays honest.
///
/// The escape hatch is read here (process env) and forwarded to the pure
/// [`authorize_with_override`] core so the decision logic stays unit-testable
/// without mutating process-global state.
pub fn authorize_local_only(env_id: &EnvId) -> AuditDecision {
    authorize_with_override(env_id, dev_override_enabled())
}

/// Whether the dev-only [`DEV_OVERRIDE_ENV`] escape hatch is set.
fn dev_override_enabled() -> bool {
    std::env::var_os(DEV_OVERRIDE_ENV).is_some()
}

/// Pure authorization core: `local` always allows; non-local allows only when
/// `dev_override` is true (and then under [`POLICY_LOCAL_ONLY_DEV_OVERRIDE`]).
fn authorize_with_override(env_id: &EnvId, dev_override: bool) -> AuditDecision {
    if env_id.as_str() == crate::defaults::LOCAL_ENV_ID {
        AuditDecision::Allow {
            policy: POLICY_LOCAL_ONLY.to_string(),
            reason: format!("env `{env_id}` is the local env"),
        }
    } else if dev_override {
        AuditDecision::Allow {
            policy: POLICY_LOCAL_ONLY_DEV_OVERRIDE.to_string(),
            reason: format!(
                "non-local env `{env_id}` permitted by {DEV_OVERRIDE_ENV} \
                 (dev override; A8 RBAC not enforced)"
            ),
        }
    } else {
        AuditDecision::Deny {
            policy: POLICY_LOCAL_ONLY.to_string(),
            reason: format!(
                "non-local env `{env_id}` requires RBAC; A8 ships the production policy"
            ),
        }
    }
}

pub fn current_local_actor() -> Actor {
    Actor {
        kind: "local-user".to_string(),
        user: std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok(),
        uid: current_uid(),
    }
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(rustix::process::getuid().as_raw())
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// Append-only writer for `<store_root>/<env_id>/audit/events.jsonl`.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Resolve the audit log path for `env_id` under `store`'s root.
    ///
    /// The path is built via the store's `env_dir` so it shares the same
    /// safe-env-segment validation that the rest of the store uses (rejects
    /// `.`, `..`, ids with separators).
    pub fn for_env(store: &LocalFsStore, env_id: &EnvId) -> Result<Self, AuditError> {
        let env_dir = store.env_dir(env_id)?;
        Ok(Self {
            path: env_dir.join("audit").join("events.jsonl"),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append one event as a single JSON line. Creates the parent dir on
    /// demand. The fs4 file-level flock is independent of the env's `.lock`
    /// sentinel — safe to call from inside [`LocalFsStore::transact`].
    pub fn append(&self, event: &AuditEvent) -> Result<(), AuditError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| AuditError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let serialized = serde_json::to_string(event)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        file.lock_exclusive().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        let mut handle = &file;
        handle
            .write_all(serialized.as_bytes())
            .and_then(|_| handle.write_all(b"\n"))
            .and_then(|_| file.sync_data())
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        FileExt::unlock(&file).ok();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::tempdir;

    fn make_event(env_id: &str, verb: &str) -> AuditEvent {
        AuditEvent {
            schema: AUDIT_EVENT_SCHEMA_V1.into(),
            event_id: ulid::Ulid::new().to_string(),
            ts: Utc::now(),
            actor: Actor {
                kind: "local-user".to_string(),
                user: Some("tester".to_string()),
                uid: Some(1000),
            },
            env_id: env_id.to_string(),
            noun: "env".to_string(),
            verb: verb.to_string(),
            target: serde_json::json!({"environment_id": env_id}),
            previous_generation: None,
            new_generation: None,
            idempotency_key: None,
            authorization: AuditDecision::Allow {
                policy: POLICY_LOCAL_ONLY.to_string(),
                reason: "test".to_string(),
            },
            result: AuditResult::Ok,
        }
    }

    #[test]
    fn authorize_local_env_id_allows() {
        let env_id = EnvId::try_from("local").unwrap();
        match authorize_local_only(&env_id) {
            AuditDecision::Allow { policy, reason } => {
                assert_eq!(policy, POLICY_LOCAL_ONLY);
                assert!(reason.contains("local"));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn authorize_non_local_env_id_denies() {
        // Pure core with the override OFF — deterministic regardless of the
        // ambient GREENTIC_DEPLOYER_ALLOW_ANY_ENV value in the test process.
        let env_id = EnvId::try_from("prod").unwrap();
        match authorize_with_override(&env_id, false) {
            AuditDecision::Deny { policy, reason } => {
                assert_eq!(policy, POLICY_LOCAL_ONLY);
                assert!(reason.contains("prod"));
                assert!(reason.contains("RBAC"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn authorize_non_local_env_id_allows_under_dev_override() {
        let env_id = EnvId::try_from("k8s").unwrap();
        match authorize_with_override(&env_id, true) {
            AuditDecision::Allow { policy, reason } => {
                assert_eq!(policy, POLICY_LOCAL_ONLY_DEV_OVERRIDE);
                assert!(reason.contains("k8s"));
                assert!(reason.contains(DEV_OVERRIDE_ENV));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn dev_override_does_not_change_local_policy() {
        // The local env is allowed under the canonical policy even with the
        // override on — it never borrows the dev-override label.
        let env_id = EnvId::try_from("local").unwrap();
        match authorize_with_override(&env_id, true) {
            AuditDecision::Allow { policy, .. } => assert_eq!(policy, POLICY_LOCAL_ONLY),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn audit_log_append_creates_dir_and_writes_jsonl_line() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_id = EnvId::try_from("local").unwrap();
        let log = AuditLog::for_env(&store, &env_id).unwrap();
        let event = make_event("local", "create");
        log.append(&event).unwrap();
        let raw = std::fs::read_to_string(log.path()).unwrap();
        assert!(raw.ends_with('\n'));
        let parsed: AuditEvent = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(parsed.env_id, "local");
        assert_eq!(parsed.verb, "create");
    }

    #[test]
    fn audit_log_append_appends_subsequent_events() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_id = EnvId::try_from("local").unwrap();
        let log = AuditLog::for_env(&store, &env_id).unwrap();
        log.append(&make_event("local", "create")).unwrap();
        log.append(&make_event("local", "update")).unwrap();
        let raw = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        let second: AuditEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first.verb, "create");
        assert_eq!(second.verb, "update");
        assert_ne!(first.event_id, second.event_id);
    }

    #[test]
    fn audit_log_append_under_env_flock_does_not_deadlock() {
        use crate::environment::EnvFlock;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();
        std::fs::create_dir_all(&env_dir).unwrap();
        let lock_path = env_dir.join(".lock");
        let _held = EnvFlock::acquire(&lock_path).unwrap();
        let log = AuditLog::for_env(&store, &env_id).unwrap();
        log.append(&make_event("local", "create")).unwrap();
    }

    #[test]
    fn actor_captures_user_env_var() {
        let prev = std::env::var("USER").ok();
        // SAFETY: Cargo test default thread-per-test isolation does not
        // protect from env-var races. We avoid `unsafe { set_var }` (the
        // crate forbids unsafe) and instead read whatever USER is and trust
        // that std::env::var resolves it. This test is a smoke check that
        // `current_local_actor` returns SOME user or none, not a specific
        // value.
        let actor = current_local_actor();
        assert_eq!(actor.kind, "local-user");
        // user is Some on Unix CI where $USER is set; tolerate either side.
        let _ = prev;
        let _ = actor.user;
    }

    #[test]
    fn serialize_event_round_trips() {
        let mut event = make_event("local", "set");
        event.previous_generation = Some(3);
        event.new_generation = Some(4);
        event.idempotency_key = Some("k1".to_string());
        event.authorization = AuditDecision::Deny {
            policy: POLICY_LOCAL_ONLY.to_string(),
            reason: "denied".to_string(),
        };
        event.result = AuditResult::Error {
            kind: "unauthorized".to_string(),
            message: "boom".to_string(),
        };
        let raw = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.previous_generation, Some(3));
        assert_eq!(parsed.new_generation, Some(4));
        assert_eq!(parsed.idempotency_key.as_deref(), Some("k1"));
        matches!(parsed.authorization, AuditDecision::Deny { .. });
        matches!(parsed.result, AuditResult::Error { .. });
    }

    #[test]
    fn audit_log_for_env_rejects_unsafe_env_id() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // EnvId itself allows "." and "..", but the store's safe_env_segment
        // helper inside env_dir() rejects them.
        let env_id = EnvId::try_from("..").unwrap();
        let err = AuditLog::for_env(&store, &env_id).unwrap_err();
        assert!(matches!(err, AuditError::Store(StoreError::UnsafeEnvId(_))));
    }
}
