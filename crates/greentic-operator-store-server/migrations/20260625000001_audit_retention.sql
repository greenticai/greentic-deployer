-- Audit-log retention watermark (opt-in).
--
-- The `audit_log` is append-only WITHOUT bound by default — it must never
-- forget a committed mutation (see `audit_log` in
-- `20260612000003_idempotency_audit.sql`). When an operator opts in to a
-- per-environment row cap (`--audit-max-rows-per-env`), the oldest audit
-- rows beyond the cap are pruned in the same transaction that appends a
-- new one — but, UNLIKE the silent idempotency-ledger eviction, the act of
-- forgetting is itself recorded here.
--
-- One monotonic row per environment:
--   `pruned_through_id` — the highest `audit_log.id` that retention has
--                         removed (everything <= this id is gone). Because
--                         pruning always removes the oldest rows under a
--                         single-writer store, this only ever increases.
--   `pruned_total`      — cumulative count of audit rows removed.
--   `policy_max_rows`   — the cap in force at the last prune (forensics: a
--                         later, looser cap explains a stalled watermark).
--   `last_pruned_at`    — wall-clock of the last prune.
--
-- A dedicated watermark beats an in-band `audit_log` marker event: a marker
-- is itself an audit row subject to the cap, so keeping it forces either
-- unbounded marker growth or a batch-prune heuristic. This row never churns,
-- is exact to the cap, and answers "how far back has history been trimmed?"
-- in one read.

CREATE TABLE audit_retention (
    env_id            TEXT PRIMARY KEY,
    pruned_through_id INTEGER NOT NULL,
    pruned_total      INTEGER NOT NULL,
    policy_max_rows   INTEGER NOT NULL,
    last_pruned_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
