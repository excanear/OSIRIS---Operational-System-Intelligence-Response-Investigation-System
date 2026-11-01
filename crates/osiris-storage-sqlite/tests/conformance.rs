//! Runs the backend-neutral `Storage` conformance suite against SQLite.

use std::ops::Deref;

use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;

/// Keeps the tempdir alive for as long as the storage is in use.
struct Guard {
    storage: SqliteStorage,
    _dir: tempfile::TempDir,
}

impl Deref for Guard {
    type Target = dyn Storage;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

fn fresh() -> Guard {
    let dir = tempfile::tempdir().unwrap();
    let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
    Guard { storage, _dir: dir }
}

osiris_storage::conformance_tests!(fresh);
