//! Cross-verb integration tests for the A7 audit log.

use greentic_deploy_spec::{CapabilitySlot, EnvId};
use greentic_deployer::cli::env::{EnvCreatePayload, create};
use greentic_deployer::cli::env_packs::{EnvPackBindingPayload, add as env_packs_add};
use greentic_deployer::cli::{OpError, OpFlags};
use greentic_deployer::environment::{AuditDecision, AuditEvent, AuditResult, LocalFsStore};
use tempfile::tempdir;

fn read_events(store_root: &std::path::Path, env_id: &str) -> Vec<AuditEvent> {
    let log = store_root.join(env_id).join("audit").join("events.jsonl");
    let raw = std::fs::read_to_string(&log).unwrap_or_default();
    raw.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("audit event line is well-formed JSON"))
        .collect()
}

#[test]
fn audit_log_records_distinct_verbs_in_order() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let flags = OpFlags::default();

    create(
        &store,
        &flags,
        Some(EnvCreatePayload {
            environment_id: "local".to_string(),
            name: "local".to_string(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }),
    )
    .unwrap();

    env_packs_add(
        &store,
        &flags,
        Some(EnvPackBindingPayload {
            environment_id: "local".to_string(),
            slot: CapabilitySlot::Secrets,
            kind: "greentic.secrets.dev-store@1.0.0".to_string(),
            pack_ref: "greentic.secrets.dev-store".to_string(),
            answers_ref: None,
        }),
    )
    .unwrap();

    env_packs_add(
        &store,
        &flags,
        Some(EnvPackBindingPayload {
            environment_id: "local".to_string(),
            slot: CapabilitySlot::Telemetry,
            kind: "greentic.telemetry.stdout@1.0.0".to_string(),
            pack_ref: "greentic.telemetry.stdout".to_string(),
            answers_ref: None,
        }),
    )
    .unwrap();

    let events = read_events(dir.path(), "local");
    assert_eq!(events.len(), 3, "3 mutating verbs → 3 audit events");

    assert_eq!(events[0].noun, "env");
    assert_eq!(events[0].verb, "create");
    assert_eq!(events[1].noun, "env-packs");
    assert_eq!(events[1].verb, "add");
    assert_eq!(events[2].noun, "env-packs");
    assert_eq!(events[2].verb, "add");

    // Distinct event ids.
    let ids: std::collections::HashSet<_> = events.iter().map(|e| &e.event_id).collect();
    assert_eq!(ids.len(), 3, "event ids must be unique");

    // All three are Allow / Ok.
    for event in &events {
        assert!(
            matches!(&event.authorization, AuditDecision::Allow { .. }),
            "expected Allow, got {:?}",
            event.authorization
        );
        assert!(
            matches!(&event.result, AuditResult::Ok),
            "expected Ok, got {:?}",
            event.result
        );
    }
}

#[test]
fn non_local_env_create_denies_and_audits() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let err = create(
        &store,
        &OpFlags::default(),
        Some(EnvCreatePayload {
            environment_id: "prod".to_string(),
            name: "prod".to_string(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Unauthorized { .. }));

    // No environment.json under prod/.
    let env_json = dir.path().join("prod").join("environment.json");
    assert!(!env_json.exists(), "deny must not create env state");

    // But audit/events.jsonl carries the denied attempt.
    let events = read_events(dir.path(), "prod");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].env_id, "prod");
    assert_eq!(events[0].noun, "env");
    assert_eq!(events[0].verb, "create");
    match &events[0].authorization {
        AuditDecision::Deny { policy, reason } => {
            assert_eq!(policy, "local-only");
            assert!(reason.contains("prod"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
    match &events[0].result {
        AuditResult::Error { kind, .. } => assert_eq!(kind, "unauthorized"),
        other => panic!("expected Error, got {other:?}"),
    }

    // The schema field round-trips.
    assert_eq!(
        events[0].schema.as_str(),
        greentic_deployer::environment::AUDIT_EVENT_SCHEMA_V1
    );

    // Subsequent attempts append, don't replace.
    let _ = create(
        &store,
        &OpFlags::default(),
        Some(EnvCreatePayload {
            environment_id: "prod".to_string(),
            name: "prod".to_string(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }),
    );
    let events = read_events(dir.path(), "prod");
    assert_eq!(events.len(), 2);
    assert_ne!(events[0].event_id, events[1].event_id);
}

#[test]
fn env_packs_update_audit_records_generation_transition() {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let flags = OpFlags::default();
    create(
        &store,
        &flags,
        Some(EnvCreatePayload {
            environment_id: "local".to_string(),
            name: "local".to_string(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }),
    )
    .unwrap();
    env_packs_add(
        &store,
        &flags,
        Some(EnvPackBindingPayload {
            environment_id: "local".to_string(),
            slot: CapabilitySlot::Secrets,
            kind: "greentic.secrets.dev-store@1.0.0".to_string(),
            pack_ref: "greentic.secrets.dev-store".to_string(),
            answers_ref: None,
        }),
    )
    .unwrap();
    greentic_deployer::cli::env_packs::update(
        &store,
        &flags,
        Some(EnvPackBindingPayload {
            environment_id: "local".to_string(),
            slot: CapabilitySlot::Secrets,
            kind: "greentic.secrets.aws-sm@1.0.0".to_string(),
            pack_ref: "greentic.secrets.aws-sm".to_string(),
            answers_ref: None,
        }),
    )
    .unwrap();
    let events = read_events(dir.path(), "local");
    assert_eq!(events.len(), 3);
    let update_event = events
        .iter()
        .find(|e| e.verb == "update")
        .expect("update event present");
    assert_eq!(update_event.previous_generation, Some(0));
    assert_eq!(update_event.new_generation, Some(1));
}

#[test]
fn audit_log_uses_safe_env_segment_rejecting_dotdot() {
    // Defense-in-depth: even if a caller somehow constructs an env_id of
    // "..", the audit path should not escape the store root.
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    // EnvId::try_from accepts ".." but LocalFsStore::env_dir rejects it.
    let env_id = EnvId::try_from("..").unwrap();
    let result = greentic_deployer::environment::AuditLog::for_env(&store, &env_id);
    assert!(result.is_err(), "audit log must reject unsafe env segments");
}

#[test]
fn committed_mutation_with_unwritable_audit_dir_fails_closed() {
    // Codex finding [high]: a committed mutation must not report success when
    // the audit event cannot be persisted. Inject failure by occupying the
    // audit dir path with a regular file so `create_dir_all` fails.
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    std::fs::create_dir_all(dir.path().join("local")).unwrap();
    std::fs::write(dir.path().join("local").join("audit"), b"not a dir").unwrap();

    let err = create(
        &store,
        &OpFlags::default(),
        Some(EnvCreatePayload {
            environment_id: "local".to_string(),
            name: "local".to_string(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::Audit(_)),
        "committed mutation with broken audit dir must surface OpError::Audit, got {err:?}"
    );
    // The state did commit (we cannot un-commit a flushed transact); the point
    // is that the call does NOT report success without a durable audit record.
    assert!(
        dir.path().join("local").join("environment.json").exists(),
        "the mutation itself committed before the audit append was attempted"
    );
}

#[test]
fn denied_mutation_with_unwritable_audit_dir_still_returns_unauthorized() {
    // Counterpart to the fail-closed test: a DENIED op commits no state, so an
    // unwritable audit dir must not upgrade the error to OpError::Audit — the
    // caller still sees the authorization denial.
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    std::fs::create_dir_all(dir.path().join("prod")).unwrap();
    std::fs::write(dir.path().join("prod").join("audit"), b"not a dir").unwrap();

    let err = create(
        &store,
        &OpFlags::default(),
        Some(EnvCreatePayload {
            environment_id: "prod".to_string(),
            name: "prod".to_string(),
            region: None,
            tenant_org_id: None,
            listen_addr: None,
            public_base_url: None,
        }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::Unauthorized { .. }),
        "denied op must surface Unauthorized even when audit append fails, got {err:?}"
    );
    assert!(
        !dir.path().join("prod").join("environment.json").exists(),
        "deny must not commit state"
    );
}
