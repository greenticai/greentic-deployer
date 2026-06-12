-- PR-4.3: idempotency replay ledger + durable audit log.
--
-- `idempotency_ledger` is the server-side store behind the A8 §2 replay
-- contract (`greentic_deploy_spec::remote::IdempotencyRecord`): one row per
-- committed mutation, keyed by `(env_id, idempotency_key)`, holding the
-- canonical request fingerprint plus the FULL original response so a
-- same-key retry is replied to verbatim without re-applying state. Rows are
-- written in the SAME transaction as the mutation they record (the
-- revenue-policy precedent) — a committed mutation can never lack its
-- ledger entry, and a rolled-back mutation never leaves one.
--
-- `audit_log` is the durable append-only home of every audit record the
-- server emits (previously the record only rode the response envelope).
-- `id` is the append order; `event` is the full AuditEvent JSON.
--
-- Both tables grow without bound by design: the store is human-paced
-- control-plane state, the audit log must never forget a committed
-- mutation, and retention/backup is the PR-4.4 story.

CREATE TABLE idempotency_ledger (
    env_id              TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL,
    operation           TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    response_status     INTEGER NOT NULL,
    response_body       TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (env_id, idempotency_key)
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    env_id      TEXT NOT NULL,
    event_id    TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    event       TEXT NOT NULL
);

CREATE INDEX audit_log_env ON audit_log (env_id, id);
