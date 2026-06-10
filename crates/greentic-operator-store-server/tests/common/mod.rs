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
