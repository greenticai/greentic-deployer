//! Shared support for the integration-test suites.

use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;

/// A store on a fresh per-test SQLite file. Keep the `TempDir` alive for
/// the test's duration — dropping it deletes the database.
pub async fn fresh_store() -> (tempfile::TempDir, SqliteEnvironmentStore) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let store = SqliteEnvironmentStore::open(&dir.path().join("store.sqlite"))
        .await
        .expect("open sqlite store");
    (dir, store)
}

/// Like [`fresh_store`] but with opt-in audit-log retention enabled at
/// `max_rows` rows per environment.
#[allow(dead_code)] // used by the sqlite_storage suite, not every test binary
pub async fn fresh_store_with_audit_cap(
    max_rows: u32,
) -> (tempfile::TempDir, SqliteEnvironmentStore) {
    let (dir, store) = fresh_store().await;
    (dir, store.with_audit_max_rows_per_env(Some(max_rows)))
}
