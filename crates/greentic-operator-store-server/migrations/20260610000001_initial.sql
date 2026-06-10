-- Greentic operator store server (SQLite backend) initial schema.
-- Phase D PR-4.1 — see ../../../plans/next-gen-deployment.md. SQLite port
-- of the parked Postgres prototype schema
-- (crates/greentic-environment-store-postgres/migrations/20260609000001_initial.sql).
--
-- IMMUTABLE AFTER FIRST MERGE: sqlx tracks applied migrations by
-- checksum in `_sqlx_migrations`. Editing this file after the PR
-- merges will desync deployed databases. All subsequent schema
-- changes must land as new `*.sql` files with later timestamps.
--
-- Shared schema with env_id columns; optimistic CAS rides on the
-- generation column — every UPDATE checks the prior generation inside a
-- transaction (the pool is capped at one connection, so transactions are
-- fully serialized in-process; SQLite has no `FOR UPDATE`).
--
-- Each row stores its content twice — the strong validator (etag, hex
-- digest of canonical JSON) for cheap `If-Match` checks, and the full
-- digest (integrity_digest) so a corruption check can recompute against
-- the same canonical form on load. They are the same digest today but
-- live in separate columns to leave room for the contract's
-- `IntegrityMismatch` flow when load-time verification escalates.

CREATE TABLE environments (
    env_id            TEXT    PRIMARY KEY,
    generation        INTEGER NOT NULL CHECK (generation > 0),
    etag              TEXT    NOT NULL,
    data              TEXT    NOT NULL,
    integrity_digest  TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX environments_updated_at_idx ON environments (updated_at);

CREATE TABLE environment_runtimes (
    env_id           TEXT    PRIMARY KEY REFERENCES environments(env_id) ON DELETE CASCADE,
    generation       INTEGER NOT NULL CHECK (generation > 0),
    etag             TEXT    NOT NULL,
    data             TEXT    NOT NULL,
    integrity_digest TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE pack_answers (
    env_id           TEXT    NOT NULL REFERENCES environments(env_id) ON DELETE CASCADE,
    slot             TEXT    NOT NULL,
    generation       INTEGER NOT NULL CHECK (generation > 0),
    etag             TEXT    NOT NULL,
    data             TEXT    NOT NULL,
    integrity_digest TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (env_id, slot)
);
