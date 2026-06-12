-- Trust-root documents (Phase D PR-4.2f) — the server-side analogue of the
-- LocalFS backend's `<env_dir>/trust-root.json`. One row per environment,
-- storing the `greentic.trust-root.v1` envelope verbatim; row absence is
-- load-bearing (it is how `seed_trust_root_if_absent` detects "never
-- bootstrapped"), so the trust-root verbs never delete rows — `remove`
-- only edits the key list inside the document.
--
-- IMMUTABLE AFTER FIRST MERGE: sqlx tracks applied migrations by checksum
-- in `_sqlx_migrations`. All subsequent schema changes must land as new
-- `*.sql` files with later timestamps.
--
-- Same column shape as environment_runtimes: optimistic CAS on
-- generation/etag, integrity_digest recomputed on load. No tombstone
-- column — rows are never deleted (see above).

CREATE TABLE trust_roots (
    env_id           TEXT    PRIMARY KEY REFERENCES environments(env_id) ON DELETE CASCADE,
    generation       INTEGER NOT NULL CHECK (generation > 0),
    etag             TEXT    NOT NULL,
    data             TEXT    NOT NULL,
    integrity_digest TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);
