//! Operator store server — the HTTP front for the Greentic environment
//! store (Phase D PR-4).
//!
//! This is the server half of the A8 remote-store contract
//! (`greentic-deploy-spec::remote`,
//! `greentic-operator/docs/remote-environment-store-contract.md`). The
//! deployer CLI's `HttpEnvironmentStore` (PR-3b/3c) is the client; this
//! crate serves it.
//!
//! Scope of PR-4.1 (scaffold):
//!
//! - [`storage::EnvironmentStorage`] — backend-agnostic async storage
//!   trait mirroring the parked Postgres prototype's surface.
//! - [`sqlite::SqliteEnvironmentStore`] — the v1 backend: embedded
//!   SQLite, single-connection pool, optimistic CAS, at-rest integrity
//!   digests. Tests run as plain `cargo test` (no Docker).
//! - [`http::router`] — Axum scaffold with `/healthz` + `/readyz`.
//! - `greentic-operator-store-server` binary: clap config (bind address
//!   + database path), graceful shutdown.
//!
//! Out of scope, intentional follow-ups (PR-4.2+):
//!
//! - The 28 A8 mutation/read routes (route table pinned in the deployer's
//!   `environment::http_store` module doc) and the domain engine they
//!   call (extracted from `mutations_local.rs`).
//! - Audit log (A8 #4) — every 2xx mutation response MUST embed an audit
//!   record matching the request's env and idempotency key (the PR-4.0
//!   client rejects anything else).
//! - Idempotency replay (A8 #2), RBAC (A8 #3, denials = 403 + A8
//!   `unauthorized` body), backup/restore (A8 #5).
//! - Postgres backend adapter (the parked
//!   `greentic-environment-store-postgres` crate implements this trait
//!   when a managed-DB deployment mandates it).

pub mod http;
pub mod sqlite;
pub mod storage;
