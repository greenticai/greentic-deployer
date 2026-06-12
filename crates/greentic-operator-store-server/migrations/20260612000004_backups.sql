-- PR-4.4: environment backups (A8 #5).
--
-- One row per backup: the contract's `BackupManifest` metadata plus the
-- FULL canonical-JSON snapshot of the environment row at backup time
-- (`state`). `integrity` is the SHA-256 of the canonical snapshot; restore
-- recomputes and compares it before applying (contract #6 applied to the
-- backup itself), so silent at-rest corruption of a backup can never be
-- restored.
--
-- Backups are bounded per-environment (`MAX_BACKUPS_PER_ENV`, enforced in
-- the inserting transaction). Unlike the idempotency ledger the cap does
-- NOT evict: a backup is a recovery point an operator created on purpose,
-- so the insert is refused (409) until old backups are deleted explicitly.

CREATE TABLE backups (
    env_id      TEXT NOT NULL,
    backup_id   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    generation  INTEGER NOT NULL,
    integrity   TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    state       TEXT NOT NULL,
    PRIMARY KEY (env_id, backup_id)
);
