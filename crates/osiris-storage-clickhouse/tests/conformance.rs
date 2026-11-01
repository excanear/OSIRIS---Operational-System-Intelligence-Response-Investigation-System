//! Runs the backend-neutral `Storage` conformance suite against ClickHouse.
//!
//! Every test here is `#[ignore]`d: it needs a running server named by
//! `OSIRIS_CLICKHOUSE_URL` (see `tools/clickhouse/dev-server.sh`) and runs
//! only with `--include-ignored`. Each test opens its own uniquely named
//! database and drops it when done.

use std::ops::Deref;
use std::time::Duration;

use osiris_storage::Storage;
use osiris_storage_clickhouse::{ClickHouseOptions, ClickHouseStorage};

/// A storage on a fresh database, dropped again when the guard goes.
struct TestDb {
    storage: ClickHouseStorage,
}

impl Deref for TestDb {
    type Target = dyn Storage;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if let Err(e) = self.storage.drop_database() {
            eprintln!("warning: could not drop test database: {e}");
        }
    }
}

fn options(database: &str) -> ClickHouseOptions {
    let url = std::env::var("OSIRIS_CLICKHOUSE_URL")
        .expect("OSIRIS_CLICKHOUSE_URL must be set to run the ClickHouse tests");
    ClickHouseOptions {
        url,
        database: database.to_string(),
        timeout: Duration::from_secs(30),
        ..ClickHouseOptions::default()
    }
}

fn fresh_name() -> String {
    format!("osiris_t_{}", uuid::Uuid::new_v4().simple())
}

#[allow(dead_code)] // Invoked by the conformance groups from Task 3 on.
fn fresh() -> TestDb {
    let storage = ClickHouseStorage::open(options(&fresh_name())).expect("open fresh database");
    TestDb { storage }
}

#[test]
#[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
fn open_creates_schema_and_is_idempotent() {
    let name = fresh_name();
    let first = TestDb {
        storage: ClickHouseStorage::open(options(&name)).expect("first open"),
    };
    let second = ClickHouseStorage::open(options(&name)).expect("second open");
    assert!(first.health().healthy, "{:?}", first.health().detail);
    assert!(second.health().healthy, "{:?}", second.health().detail);
}
