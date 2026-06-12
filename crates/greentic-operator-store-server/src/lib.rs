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
//! - The revision-lifecycle verb group (PR-4.2b):
//!   `POST /environments/{env_id}/revisions` (stage) and
//!   `POST /environments/{env_id}/revisions/{rid}/{warm|drain|archive}`.
//!   The warm health gate is evaluated client-side and shipped as data; a
//!   gate failure persists the `Failed` flip BEFORE the typed 422
//!   (`health-gate-failed`) is returned — committed-on-error, mirroring
//!   `LocalFsStore`.
//! - The traffic verb group (PR-4.2c):
//!   `POST /environments/{env_id}/traffic` (set) and
//!   `POST /environments/{env_id}/traffic/rollback`. The idempotent
//!   same-key-same-entries replay is a 200 with `new_generation: null` and
//!   nothing persisted; key reuse with different entries is the typed 409
//!   `idempotency-conflict`. `runtime-config.json` materialization stays a
//!   `LocalFsStore` projection, and `TrafficSplitApplied` telemetry is
//!   emitted by the operator CLI from the outcome's env snapshot — not
//!   here.
//! - The pack/extension-binding verb group (PR-4.2d):
//!   `POST /environments/{env_id}/packs`,
//!   `PATCH|DELETE /environments/{env_id}/packs/{slot}`,
//!   `POST /environments/{env_id}/packs/{slot}/rollback`, and
//!   `POST|PATCH|DELETE /environments/{env_id}/extensions` +
//!   `POST /environments/{env_id}/extensions/rollback` (keyed extension
//!   verbs carry the `(kind_path, instance_id)` key in the body —
//!   `kind_path` contains `/`). Every `Ok` persists, every error leaves
//!   the env untouched; N-per-env slots are a typed 400 at the wire (the
//!   CLI rejects them upstream, the server can't rely on that).
//! - `greentic-operator-store-server` binary: clap config (bind address
//!   + database path), graceful shutdown.
//! - The A8 §2 idempotency replay ledger + the audit log's durable append
//!   (PR-4.3): every committed mutation writes its ledger row (canonical
//!   request fingerprint + the full original response) and its audit-log
//!   row in the SAME transaction as the mutation; a same-key retry replays
//!   the original response verbatim (`idempotency: replayed`), any other
//!   key reuse is a typed `409 idempotency-conflict`, and failed requests
//!   consume nothing. The ledger is bounded per-environment
//!   (`MAX_LEDGER_ROWS_PER_ENV` = 4096 rows, clock-free eviction in the
//!   inserting transaction); the audit log is deliberately append-only
//!   without bound — archival is the backup story below.
//! - RBAC (A8 #3, PR-4.4): [`rbac::RbacEngine`] — static bearer-token
//!   authentication with coarse roles (`admin` / `operator` /
//!   `read-only`), evaluated BEFORE the replay gate on every route.
//!   Without a token file the engine is the honest `open-dev` allow-all
//!   (loopback dev posture, unchanged wire shapes); with one, requests
//!   fail closed (`403 unauthorized`) and denied mutations still append
//!   a durable audit row (contract: "the rejected attempt is still
//!   audited").
//! - Backup/restore (A8 #5, PR-4.4): `POST/GET
//!   /environments/{env_id}/backups`, `DELETE .../backups/{backup_id}`,
//!   and `POST /environments/{env_id}/restore`. Backups snapshot the
//!   environment row (full canonical JSON + integrity digest, the
//!   contract's `BackupManifest`); restore is a guarded mutation whose
//!   `RestoreRequest.precondition` must pin prior state, verifies the
//!   snapshot's digest before applying (contract #6 on the backup
//!   itself), and commits through the same journaled CAS write as any
//!   other mutation. Backups are bounded per-environment
//!   (`MAX_BACKUPS_PER_ENV`): the cap REFUSES new backups (409) instead
//!   of silently evicting recovery points.
//!
//! Out of scope, intentional follow-ups:
//!
//! - Read-verb dispatch from the deployer CLI (GET endpoints exist; the
//!   CLI wiring is tracked as the read-verbs follow-up).
//! - The Phase D server-side secrets sink (lifts the two messaging 501s).
//! - Postgres backend adapter (the parked
//!   `greentic-environment-store-postgres` crate implements this trait
//!   when a managed-DB deployment mandates it).

pub mod api;
pub mod http;
pub mod rbac;
pub mod sqlite;
pub mod storage;
