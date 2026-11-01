//! ClickHouse implementation of `osiris_storage::Storage` (Phase 11c,
//! ARCHITECTURE.md §10.2).
//!
//! Talks to ClickHouse over its HTTP interface with the workspace's
//! blocking `reqwest`, from a dedicated worker thread (see `transport`), so
//! it is safe to call from async code. Values never enter SQL text; only
//! the validated database name does.
//!
//! Writes are documented as **single-writer**: ClickHouse has no unique
//! constraint, so write-once semantics on ids are enforced under a
//! process-local writer mutex (design §5.4).

mod schema;
mod transport;

use std::sync::Mutex;
use std::time::Duration;

use osiris_schema::{Alert, CanonicalEvent, EntityRelationship, RiskScoreRecord};
use osiris_storage::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RelationshipQueryPlan, RetentionPolicy,
    RetentionReport, RiskQueryPlan, Storage, StorageError, StorageHealth, WriteReport,
};
use uuid::Uuid;

use crate::transport::Transport;

/// The schema version this build writes and understands. `open` refuses a
/// database whose recorded version is newer.
pub const SCHEMA_VERSION: u32 = 1;

/// Connection settings for [`ClickHouseStorage::open`].
#[derive(Clone)]
pub struct ClickHouseOptions {
    /// `http(s)://host:port`, without credentials.
    pub url: String,
    /// Database name; must match `^[A-Za-z_][A-Za-z0-9_]{0,63}$`.
    pub database: String,
    /// Sent as `X-ClickHouse-User`.
    pub user: String,
    /// Sent as `X-ClickHouse-Key`. The server config reads it from a
    /// password file, never inline.
    pub password: Option<String>,
    /// Per-request timeout (connect and total).
    pub timeout: Duration,
}

impl Default for ClickHouseOptions {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8123".to_string(),
            database: "osiris".to_string(),
            user: "default".to_string(),
            password: None,
            timeout: Duration::from_secs(30),
        }
    }
}

impl std::fmt::Debug for ClickHouseOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClickHouseOptions")
            .field("url", &self.url)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// `^[A-Za-z_][A-Za-z0-9_]{0,63}$`, by hand (no regex crate).
pub(crate) fn is_valid_identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    match bytes.first() {
        Some(b) if b.is_ascii_alphabetic() || *b == b'_' => {}
        _ => return false,
    }
    bytes.len() <= 64
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

pub struct ClickHouseStorage {
    transport: Transport,
    database: String,
    /// Serialises the dedupe-then-insert write path (design §5.4). Used by
    /// the write methods from Task 3 on.
    #[allow(dead_code)]
    writer: Mutex<()>,
}

impl std::fmt::Debug for ClickHouseStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClickHouseStorage")
            .field("transport", &self.transport)
            .finish()
    }
}

impl ClickHouseStorage {
    /// Connects, creates the database and tables if absent, and checks the
    /// recorded schema version.
    pub fn open(opts: ClickHouseOptions) -> Result<Self, StorageError> {
        let storage = Self::connect(opts)?;
        schema::ensure(&storage.transport, &storage.database)?;
        tracing::info!(
            database = %storage.database,
            schema_version = SCHEMA_VERSION,
            "clickhouse storage opened"
        );
        Ok(storage)
    }

    /// Validates the options and starts the transport, without touching
    /// the server.
    fn connect(opts: ClickHouseOptions) -> Result<Self, StorageError> {
        if !is_valid_identifier(&opts.database) {
            return Err(StorageError::Backend(format!(
                "clickhouse: invalid database name {:?}: a database name must match \
                 ^[A-Za-z_][A-Za-z0-9_]{{0,63}}$",
                opts.database
            )));
        }
        let transport = Transport::start(
            &opts.url,
            &opts.database,
            &opts.user,
            opts.password,
            opts.timeout,
        )?;
        Ok(Self {
            transport,
            database: opts.database,
            writer: Mutex::new(()),
        })
    }

    /// Test-only: a storage whose transport is up but whose schema step was
    /// skipped, so it can point at an unreachable server.
    #[cfg(test)]
    fn open_without_schema(opts: ClickHouseOptions) -> Result<Self, StorageError> {
        Self::connect(opts)
    }

    /// Drops the whole database. For test and benchmark cleanup.
    pub fn drop_database(&self) -> Result<(), StorageError> {
        self.transport
            .execute_server(&format!("DROP DATABASE IF EXISTS {} SYNC", self.database))?;
        Ok(())
    }

    /// Bytes on disk of the database's active parts.
    pub fn disk_bytes(&self) -> Result<u64, StorageError> {
        let text = self.transport.execute(
            "SELECT sum(bytes_on_disk) FROM system.parts \
             WHERE database = {db:String} AND active FORMAT TSV",
            &[("db", self.database.clone())],
            &[],
            None,
        )?;
        text.trim().parse::<u64>().map_err(|e| {
            StorageError::Backend(format!(
                "clickhouse: unexpected disk_bytes value {:?}: {e}",
                text.trim()
            ))
        })
    }
}

fn not_implemented() -> StorageError {
    StorageError::Backend("not implemented".into())
}

impl Storage for ClickHouseStorage {
    fn write(&self, _event: &CanonicalEvent) -> Result<(), StorageError> {
        Err(not_implemented())
    }

    fn batch_write(&self, _events: &[CanonicalEvent]) -> Result<WriteReport, StorageError> {
        Err(not_implemented())
    }

    fn event_owner(&self, _event_id: Uuid) -> Result<Option<Uuid>, StorageError> {
        Err(not_implemented())
    }

    fn query(&self, _plan: &QueryPlan) -> Result<Vec<CanonicalEvent>, StorageError> {
        Err(not_implemented())
    }

    fn query_events(
        &self,
        _plan: &osiris_query::EventQueryPlan,
    ) -> Result<Vec<CanonicalEvent>, StorageError> {
        Err(not_implemented())
    }

    fn get_event(&self, _event_id: Uuid) -> Result<Option<CanonicalEvent>, StorageError> {
        Err(not_implemented())
    }

    fn delete(&self, _criteria: &DeleteCriteria) -> Result<u64, StorageError> {
        Err(not_implemented())
    }

    fn retention_apply(&self, _policy: &RetentionPolicy) -> Result<RetentionReport, StorageError> {
        Err(not_implemented())
    }

    fn health(&self) -> StorageHealth {
        // Bounded by the transport timeout; never panics. `event_count` and
        // `last_write_at` are filled in with the events table (Task 3).
        match self.transport.execute("SELECT 1", &[], &[], None) {
            Ok(_) => StorageHealth {
                healthy: true,
                event_count: 0,
                last_write_at: None,
                detail: None,
            },
            Err(e) => StorageHealth {
                healthy: false,
                event_count: 0,
                last_write_at: None,
                detail: Some(e.to_string()),
            },
        }
    }

    fn write_alerts(&self, _alerts: &[Alert]) -> Result<WriteReport, StorageError> {
        Err(not_implemented())
    }

    fn query_alerts(&self, _plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError> {
        Err(not_implemented())
    }

    fn write_relationships(
        &self,
        _edges: &[EntityRelationship],
    ) -> Result<WriteReport, StorageError> {
        Err(not_implemented())
    }

    fn query_relationships(
        &self,
        _plan: &RelationshipQueryPlan,
    ) -> Result<Vec<EntityRelationship>, StorageError> {
        Err(not_implemented())
    }

    fn write_risk_scores(&self, _scores: &[RiskScoreRecord]) -> Result<WriteReport, StorageError> {
        Err(not_implemented())
    }

    fn query_risk_scores(
        &self,
        _plan: &RiskQueryPlan,
    ) -> Result<Vec<RiskScoreRecord>, StorageError> {
        Err(not_implemented())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use osiris_storage::Storage;

    use super::*;

    fn opts(url: &str, database: &str) -> ClickHouseOptions {
        ClickHouseOptions {
            url: url.to_string(),
            database: database.to_string(),
            user: "default".to_string(),
            password: None,
            timeout: Duration::from_secs(2),
        }
    }

    fn open_err(opts: ClickHouseOptions) -> String {
        match ClickHouseStorage::open(opts) {
            Ok(_) => panic!("open unexpectedly succeeded"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn invalid_database_name_is_rejected() {
        let err = open_err(opts("http://127.0.0.1:1", "x; DROP"));
        assert!(err.contains("database name"), "{err}");
        let err = open_err(opts("http://127.0.0.1:1", "osiris_1"));
        assert!(!err.contains("database name"), "{err}");
        assert!(err.contains("clickhouse"), "{err}");
    }

    #[test]
    fn unreachable_server_fails_open_quickly() {
        let start = Instant::now();
        let _ = open_err(opts("http://127.0.0.1:1", "osiris_1"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn error_text_never_contains_the_password() {
        let mut o = opts("http://127.0.0.1:1", "osiris_1");
        o.password = Some("s3cr3t-pw".to_string());
        let err = open_err(o);
        assert!(!err.contains("s3cr3t-pw"), "{err}");
    }

    #[test]
    fn tsv_escaping_round_trips_control_characters() {
        assert_eq!(transport::tsv_escape("a\tb\nc\\d"), "a\\tb\\nc\\\\d");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn called_from_inside_a_tokio_runtime_does_not_panic() {
        let storage =
            ClickHouseStorage::open_without_schema(opts("http://127.0.0.1:1", "osiris_1"))
                .expect("transport starts without a server");
        let health = storage.health();
        assert!(!health.healthy);
        assert!(health.detail.is_some());
        drop(storage);
    }

    #[test]
    fn identifier_rule_matches_the_documented_pattern() {
        for ok in ["a", "_", "osiris_1", "A_b9", &"x".repeat(64)] {
            assert!(is_valid_identifier(ok), "{ok}");
        }
        for bad in ["", "1a", "a-b", "a b", "a;", "é", "a.b", &"x".repeat(65)] {
            assert!(!is_valid_identifier(bad), "{bad}");
        }
    }

    /// Needs a server: an exception raised after the first blocks have
    /// been streamed must surface as `Err`, never as a partial result.
    #[test]
    #[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
    fn mid_stream_exception_is_an_error_not_a_partial_result() {
        let url = std::env::var("OSIRIS_CLICKHOUSE_URL")
            .expect("OSIRIS_CLICKHOUSE_URL must be set to run the ClickHouse tests");
        let mut o = opts(&url, "default");
        o.timeout = Duration::from_secs(30);
        let storage = ClickHouseStorage::open_without_schema(o).unwrap();
        for format in ["TSV", "JSONEachRow"] {
            let sql = format!(
                "SELECT toString(number) AS s, throwIf(number = 100000) FROM numbers(200000) \
                 SETTINGS max_block_size = 1000 FORMAT {format}"
            );
            let result = storage.transport.execute(&sql, &[], &[], None);
            let err = match result {
                Ok(body) => panic!("{format}: got Ok with {} bytes", body.len()),
                Err(e) => e.to_string(),
            };
            assert!(
                err.contains("FUNCTION_THROW_IF_VALUE_IS_NON_ZERO"),
                "{format}: {err}"
            );
        }
    }

    /// Needs a server: a recorded version above `SCHEMA_VERSION` must make
    /// `open` fail.
    #[test]
    #[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
    fn newer_schema_version_fails_open() {
        let url = std::env::var("OSIRIS_CLICKHOUSE_URL")
            .expect("OSIRIS_CLICKHOUSE_URL must be set to run the ClickHouse tests");
        let mut o = opts(&url, &format!("osiris_t_{}", uuid::Uuid::new_v4().simple()));
        o.timeout = Duration::from_secs(30);
        let storage = ClickHouseStorage::open(o.clone()).unwrap();
        storage
            .transport
            .execute(
                &format!(
                    "INSERT INTO {}.osiris_schema_version FORMAT JSONEachRow",
                    o.database
                ),
                &[],
                &[],
                Some("{\"version\":2}\n".to_string()),
            )
            .unwrap();
        let err = open_err(o);
        storage.drop_database().unwrap();
        assert!(
            err.contains("clickhouse schema version 2 is newer than supported 1"),
            "{err}"
        );
    }

    /// Needs a server: parameters, external tables (multipart) and insert
    /// bodies all reach ClickHouse intact, including control characters.
    #[test]
    #[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
    fn transport_round_trips_params_external_tables_and_insert_bodies() {
        let url = std::env::var("OSIRIS_CLICKHOUSE_URL")
            .expect("OSIRIS_CLICKHOUSE_URL must be set to run the ClickHouse tests");
        let mut o = opts(&url, &format!("osiris_t_{}", uuid::Uuid::new_v4().simple()));
        o.timeout = Duration::from_secs(30);
        let storage = ClickHouseStorage::open(o).unwrap();
        let t = &storage.transport;
        let db = storage.database.clone();

        let tricky = "it's\t\"q\"\n\\ ' OR 1=1 --";
        let out = t
            .execute(
                "SELECT {v:String} FORMAT JSONEachRow",
                &[("v", tricky.to_string())],
                &[],
                None,
            )
            .unwrap();
        let row: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(row.as_object().unwrap().values().next().unwrap(), tricky);

        let ids = transport::ExternalTable {
            name: "ids",
            structure: "id String",
            rows: vec!["b".to_string(), tricky.to_string(), "a".to_string()],
        };
        let out = t
            .execute(
                "SELECT id FROM ids WHERE id != {skip:String} ORDER BY id FORMAT JSONEachRow",
                &[("skip", "a".to_string())],
                &[ids],
                None,
            )
            .unwrap();
        let got: Vec<String> = out
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let mut want = vec!["b".to_string(), tricky.to_string()];
        want.sort();
        assert_eq!(got, want);

        t.execute(
            &format!("INSERT INTO {db}.alert_evidence FORMAT JSONEachRow"),
            &[],
            &[],
            Some(format!(
                "{}\n{}\n",
                serde_json::json!({"alert_id": "x", "event_id": tricky}),
                serde_json::json!({"alert_id": "x", "event_id": "plain"})
            )),
        )
        .unwrap();
        let out = t
            .execute(
                &format!("SELECT count() FROM {db}.alert_evidence WHERE event_id = {{e:String}} FORMAT TSV"),
                &[("e", tricky.to_string())],
                &[],
                None,
            )
            .unwrap();
        assert_eq!(out.trim(), "1");

        let err = t
            .execute("SELECT nope FROM nowhere", &[], &[], None)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("storage backend error: clickhouse: 404 Not Found: Code: "),
            "{err}"
        );
        assert!(storage.disk_bytes().unwrap() > 0);

        // A server-side auth failure must not echo the password either.
        let mut bad = opts(&url, &db);
        bad.password = Some("s3cr3t-pw".to_string());
        bad.user = "osiris_no_such_user".to_string();
        let err = open_err(bad);
        assert!(err.contains("clickhouse: "), "{err}");
        assert!(!err.contains("s3cr3t-pw"), "{err}");
        storage.drop_database().unwrap();
    }
}
