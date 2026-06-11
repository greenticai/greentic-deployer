//! Operator store server — the HTTP front for the Greentic environment
//! store (Phase D PR-4).
//!
//! This is the server half of the A8 remote-store contract
//! (`greentic-deploy-spec::remote`,
//! `greentic-operator/docs/remote-environment-store-contract.md`). The
//! deployer CLI's `HttpEnvironmentStore` (PR-3b/3c) is the client; this
//! crate serves it.
//!
//! What ships so far:
//!
//! - [`storage::EnvironmentStorage`] — backend-agnostic async storage
//!   trait mirroring the parked Postgres prototype's surface (PR-4.1).
//! - [`sqlite::SqliteEnvironmentStore`] — the v1 backend: embedded
//!   SQLite, single-connection pool, optimistic CAS, at-rest integrity
//!   digests. Tests run as plain `cargo test` (no Docker). (PR-4.1)
//! - [`http::router`] — `/healthz` + `/readyz` (PR-4.1) plus the first A8
//!   verb group from [`api`]: environment lifecycle (`POST /environments`,
//!   `PATCH /environments/{env_id}`,
//!   `POST /environments/{env_id}/migrate-bindings`) and the two reads
//!   (`GET /environments`, `GET /environments/{env_id}`). Handlers apply
//!   the shared `greentic_deploy_spec::engine` transforms — the same code
//!   `LocalFsStore` runs — and reply with the A8 mutation envelope.
//!   (PR-4.2a)
//! - `greentic-operator-store-server` binary: clap config (bind address
//!   + database path), graceful shutdown.
//!
//! Out of scope, intentional follow-ups (PR-4.2b+):
//!
//! - The remaining A8 verb groups (route table pinned in the deployer's
//!   `environment::http_store` module doc), each landing with its engine
//!   extraction from `mutations_local.rs`. FS-coupled steps
//!   (revenue-policy signing, operator key, trust-root files) need
//!   injected server-side seams.
//! - Idempotency replay (A8 #2 — keys are currently echoed into the audit
//!   record, not cached) and the audit log's durable append (PR-4.3).
//! - RBAC (A8 #3, denials = 403 + A8 `unauthorized` body; today every
//!   decision is an honest `Allow{policy: "open-dev"}`) and
//!   backup/restore (A8 #5) (PR-4.4).
//! - Postgres backend adapter (the parked
//!   `greentic-environment-store-postgres` crate implements this trait
//!   when a managed-DB deployment mandates it).

pub mod api;
pub mod http;
pub mod sqlite;
pub mod storage;
