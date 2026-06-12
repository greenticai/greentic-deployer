-- Revenue-policy artifact versions (B10, Phase D PR-4.2g) — the server-side
-- analogue of the LocalFS backend's
-- `<env_dir>/billing-policies/<bundle>/<customer>/vN.json{,.sig}` files.
-- One row per signed policy version, holding the exact document bytes and
-- the DSSE envelope the shared builder
-- (`greentic_operator_trust::revenue_policy`) produced.
--
-- No CAS columns: rows commit in the SAME transaction as the environment
-- CAS update that pins their ref (`update_env_with_revenue_policy`), so a
-- conflicting env write rolls the artifact back too and committed env
-- state never references (or is shadowed by) a losing mutation's
-- artifact. Version numbers derive from the COMMITTED
-- `BundleDeployment.revenue_policy_ref`; a same-version rebuild (same-key
-- retry, PR-4.3) overwrites via INSERT OR REPLACE. Rows are never
-- deleted.
--
-- IMMUTABLE AFTER FIRST MERGE: sqlx tracks applied migrations by checksum
-- in `_sqlx_migrations`. All subsequent schema changes must land as new
-- `*.sql` files with later timestamps.

CREATE TABLE revenue_policies (
    env_id      TEXT    NOT NULL REFERENCES environments(env_id) ON DELETE CASCADE,
    bundle_id   TEXT    NOT NULL,
    customer_id TEXT    NOT NULL,
    version     INTEGER NOT NULL CHECK (version > 0),
    -- Canonical storage-relative sidecar ref, exactly the value pinned on
    -- `BundleDeployment.revenue_policy_ref`
    -- (`billing-policies/<bundle>/<customer>/vN.json.sig`).
    policy_ref  TEXT    NOT NULL,
    doc         BLOB    NOT NULL,
    envelope    BLOB    NOT NULL,
    doc_sha256  TEXT    NOT NULL,
    key_id      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (env_id, bundle_id, customer_id, version)
);
