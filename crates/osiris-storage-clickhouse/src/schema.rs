//! Database and table DDL, plus the schema-version check.
//!
//! The tables mirror `SqliteStorage`'s (`events`, `alerts`,
//! `alert_evidence`, `relationships`, `risk_scores`, `risk_score_reasons`)
//! column for column, with these rules (design §5.3):
//! - optional columns are `Nullable`, so "absent" stays distinct from a
//!   zero/empty value, as SQLite's `NULL`;
//! - timestamps are `UInt64` nanoseconds, the same value SQLite stores;
//! - ids are `String`, not `UUID`: ClickHouse orders `UUID` by its two
//!   64-bit halves, which differs from the textual order SQLite's `TEXT`
//!   columns sort by;
//! - `event_id` (and every other id used for point lookups) has a
//!   `bloom_filter` skip index, so lookups by id skip granules instead of
//!   scanning the table.
//!
//! The database name is the only thing ever placed in SQL text, and only
//! after `is_valid_identifier` accepted it.

use osiris_storage::StorageError;

use crate::transport::Transport;
use crate::SCHEMA_VERSION;

/// The table DDL, in creation order. `{db}` is replaced by the validated
/// database name.
const TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS {db}.events (
        event_id String,
        host_id String,
        timestamp UInt64,
        event_type LowCardinality(String),
        category LowCardinality(Nullable(String)),
        process_key Nullable(String),
        parent_process_key Nullable(String),
        file_path Nullable(String),
        file_inode Nullable(UInt64),
        file_device_id Nullable(UInt64),
        network_src_ip Nullable(String),
        network_dst_ip Nullable(String),
        dns_domain Nullable(String),
        session_id Nullable(String),
        user_uid Nullable(UInt32),
        unit_name Nullable(String),
        container_id Nullable(String),
        raw_json String CODEC(ZSTD(3)),
        INDEX idx_event_id event_id TYPE bloom_filter(0.001) GRANULARITY 1,
        INDEX idx_process_key process_key TYPE bloom_filter(0.01) GRANULARITY 1,
        INDEX idx_event_type event_type TYPE set(512) GRANULARITY 1,
        INDEX idx_file_path file_path TYPE bloom_filter(0.01) GRANULARITY 1,
        INDEX idx_network_src_ip network_src_ip TYPE bloom_filter(0.01) GRANULARITY 1,
        INDEX idx_network_dst_ip network_dst_ip TYPE bloom_filter(0.01) GRANULARITY 1,
        INDEX idx_dns_domain dns_domain TYPE bloom_filter(0.01) GRANULARITY 1,
        INDEX idx_session_id session_id TYPE bloom_filter(0.01) GRANULARITY 1,
        INDEX idx_container_id container_id TYPE bloom_filter(0.01) GRANULARITY 1
    ) ENGINE = MergeTree
    PARTITION BY intDiv(timestamp, 2592000000000000)
    ORDER BY (host_id, timestamp, event_id)",
    "CREATE TABLE IF NOT EXISTS {db}.alerts (
        alert_id String,
        rule_id String,
        rule_version UInt32,
        timestamp UInt64,
        host_id String,
        raw_json String CODEC(ZSTD(3)),
        INDEX idx_alert_id alert_id TYPE bloom_filter(0.001) GRANULARITY 1,
        INDEX idx_host_id host_id TYPE bloom_filter(0.01) GRANULARITY 1
    ) ENGINE = MergeTree
    ORDER BY (rule_id, timestamp, alert_id)",
    "CREATE TABLE IF NOT EXISTS {db}.alert_evidence (
        alert_id String,
        event_id String,
        INDEX idx_event_id event_id TYPE bloom_filter(0.001) GRANULARITY 1
    ) ENGINE = MergeTree
    ORDER BY (alert_id, event_id)",
    "CREATE TABLE IF NOT EXISTS {db}.relationships (
        from_key String,
        to_key String,
        relation LowCardinality(String),
        event_id String,
        timestamp UInt64,
        INDEX idx_to_key to_key TYPE bloom_filter(0.01) GRANULARITY 1,
        INDEX idx_event_id event_id TYPE bloom_filter(0.001) GRANULARITY 1
    ) ENGINE = MergeTree
    ORDER BY (from_key, timestamp)",
    "CREATE TABLE IF NOT EXISTS {db}.risk_scores (
        event_id String,
        process_key Nullable(String),
        host_id String,
        timestamp UInt64,
        score UInt8,
        severity LowCardinality(String),
        related_events String,
        INDEX idx_event_id event_id TYPE bloom_filter(0.001) GRANULARITY 1,
        INDEX idx_process_key process_key TYPE bloom_filter(0.01) GRANULARITY 1
    ) ENGINE = MergeTree
    ORDER BY (timestamp, event_id)",
    "CREATE TABLE IF NOT EXISTS {db}.risk_score_reasons (
        event_id String,
        seq UInt32,
        label String,
        weight Int16,
        evidence String
    ) ENGINE = MergeTree
    ORDER BY (event_id, seq)",
    "CREATE TABLE IF NOT EXISTS {db}.osiris_schema_version (
        version UInt32
    ) ENGINE = MergeTree
    ORDER BY version",
];

/// Creates the database and every table if absent, then records or checks
/// the schema version. Idempotent.
pub(crate) fn ensure(transport: &Transport, database: &str) -> Result<(), StorageError> {
    debug_assert!(crate::is_valid_identifier(database));
    transport.execute_server(&format!("CREATE DATABASE IF NOT EXISTS {database}"))?;
    for ddl in TABLES {
        transport.execute(&ddl.replace("{db}", database), &[], &[], None)?;
    }

    let stored = stored_version(transport, database)?;
    match stored {
        0 => {
            transport.execute(
                &format!("INSERT INTO {database}.osiris_schema_version FORMAT JSONEachRow"),
                &[],
                &[],
                Some(format!("{{\"version\":{SCHEMA_VERSION}}}\n")),
            )?;
        }
        v if v > SCHEMA_VERSION => {
            return Err(StorageError::Backend(format!(
                "clickhouse schema version {v} is newer than supported {SCHEMA_VERSION}"
            )));
        }
        // Equal (or an older version a future migration would upgrade).
        _ => {}
    }
    Ok(())
}

/// The highest recorded schema version, or 0 when none is recorded.
fn stored_version(transport: &Transport, database: &str) -> Result<u32, StorageError> {
    let text = transport.execute(
        &format!("SELECT max(version) FROM {database}.osiris_schema_version FORMAT TSV"),
        &[],
        &[],
        None,
    )?;
    text.trim().parse::<u32>().map_err(|e| {
        StorageError::Backend(format!(
            "clickhouse: unexpected schema version value {:?}: {e}",
            text.trim()
        ))
    })
}
