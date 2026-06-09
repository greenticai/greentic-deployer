-- Greentic EnvironmentStore (Postgres prototype) initial schema.
-- Phase D §13.5 prereq #2 — see ../../../plans/next-gen-deployment.md.
--
-- Shared schema with env_id columns (NOT per-env Postgres schemas) so a
-- migration is one DDL, not O(envs) DDL. Optimistic CAS rides on the
-- generation column; every UPDATE checks the prior generation explicitly.
--
-- Each row stores its content twice — the strong validator (etag, hex
-- digest of canonical JSON) for cheap `If-Match` checks, and the full
-- digest (integrity_digest) so a corruption check can recompute against
-- the same canonical form on load. They are the same digest today but
-- live in separate columns to leave room for the contract's
-- `IntegrityMismatch` flow when load-time verification escalates.

CREATE TABLE environments (
    env_id            TEXT        PRIMARY KEY,
    generation        BIGINT      NOT NULL,
    etag              TEXT        NOT NULL,
    data              JSONB       NOT NULL,
    integrity_digest  TEXT        NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT environments_generation_positive CHECK (generation > 0)
);

CREATE INDEX environments_updated_at_idx ON environments (updated_at);

CREATE TABLE environment_runtimes (
    env_id           TEXT        PRIMARY KEY REFERENCES environments(env_id) ON DELETE CASCADE,
    generation       BIGINT      NOT NULL,
    etag             TEXT        NOT NULL,
    data             JSONB       NOT NULL,
    integrity_digest TEXT        NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT environment_runtimes_generation_positive CHECK (generation > 0)
);

CREATE TABLE pack_answers (
    env_id           TEXT        NOT NULL REFERENCES environments(env_id) ON DELETE CASCADE,
    slot             TEXT        NOT NULL,
    generation       BIGINT      NOT NULL,
    etag             TEXT        NOT NULL,
    data             JSONB       NOT NULL,
    integrity_digest TEXT        NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (env_id, slot),
    CONSTRAINT pack_answers_generation_positive CHECK (generation > 0)
);
