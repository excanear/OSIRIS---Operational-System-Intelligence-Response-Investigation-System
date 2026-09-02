use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_schema::CanonicalEvent;
use osiris_storage::{
    DeleteCriteria, QueryPlan, RetentionPolicy, RetentionReport, Storage, StorageError,
    StorageHealth, WriteReport,
};
use rusqlite::{params, Connection, OptionalExtension};

/// SQLite-backed Storage (ARCHITECTURE.md §10.2, MVP tier). One table
/// (`events`) with a few indexed columns for filtering plus the full
/// event as a JSON blob for round-trip fidelity — proportionate to
/// Phase 1's single event type, not the "small number of wide tables"
/// full design (which grows one column-family per category as later
/// phases add event types).
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StorageError> {
        let conn = Connection::open(path).map_err(|e| StorageError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                process_key TEXT,
                parent_process_key TEXT,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_host_timestamp ON events(host_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_process_key ON events(process_key);",
        )
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl Storage for SqliteStorage {
    fn write(&self, event: &CanonicalEvent) -> Result<(), StorageError> {
        let report = self.batch_write(std::slice::from_ref(event))?;
        if report.failed_count > 0 {
            return Err(StorageError::Backend(
                "write failed (duplicate event_id?)".to_string(),
            ));
        }
        Ok(())
    }

    fn batch_write(&self, events: &[CanonicalEvent]) -> Result<WriteReport, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut report = WriteReport::default();
        for event in events {
            let raw_json =
                serde_json::to_string(event).map_err(|e| StorageError::Serialize(e.to_string()))?;
            let process_key = event.process.as_ref().map(|p| p.process_key.as_hex());
            let parent_process_key = event
                .parent_process
                .as_ref()
                .map(|p| p.process_key.as_hex());
            let event_type = serde_json::to_string(&event.event_type)
                .map_err(|e| StorageError::Serialize(e.to_string()))?
                .trim_matches('"')
                .to_string();
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        event.event_id.to_string(),
                        event.host_id.to_string(),
                        event.timestamp as i64,
                        event_type,
                        process_key,
                        parent_process_key,
                        raw_json,
                    ],
                )
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            if changed == 1 {
                report.written_count += 1;
            } else {
                report.failed_count += 1;
            }
        }
        tx.commit()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(report)
    }

    fn query(&self, plan: &QueryPlan) -> Result<Vec<CanonicalEvent>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let mut sql = "SELECT raw_json FROM events WHERE 1=1".to_string();
        let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if let Some(event_type) = &plan.event_type {
            sql.push_str(" AND event_type = ?");
            let s = serde_json::to_string(event_type)
                .map_err(|e| StorageError::Serialize(e.to_string()))?
                .trim_matches('"')
                .to_string();
            sql_params.push(Box::new(s));
        }
        if let Some(process_key) = &plan.process_key {
            sql.push_str(" AND process_key = ?");
            sql_params.push(Box::new(process_key.as_hex()));
        }
        if let Some(since) = plan.since {
            sql.push_str(" AND timestamp >= ?");
            sql_params.push(Box::new(since as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND timestamp <= ?");
            sql_params.push(Box::new(until as i64));
        }
        sql.push_str(" ORDER BY timestamp ASC LIMIT ?");
        let limit = if plan.limit == 0 { 100 } else { plan.limit };
        sql_params.push(Box::new(limit as i64));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| StorageError::Backend(e.to_string()))?;
            let event: CanonicalEvent = serde_json::from_str(&raw_json)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }

    fn delete(&self, criteria: &DeleteCriteria) -> Result<u64, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let changed = conn
            .execute(
                "DELETE FROM events WHERE timestamp < ?1",
                params![criteria.before_timestamp as i64],
            )
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(changed as u64)
    }

    fn retention_apply(&self, policy: &RetentionPolicy) -> Result<RetentionReport, StorageError> {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .as_nanos() as u64;
        let cutoff = now_ns.saturating_sub(policy.max_age_secs.saturating_mul(1_000_000_000));
        let deleted = self.delete(&DeleteCriteria {
            before_timestamp: cutoff,
        })?;
        Ok(RetentionReport {
            deleted_count: deleted,
        })
    }

    fn health(&self) -> StorageHealth {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                return StorageHealth {
                    healthy: false,
                    event_count: 0,
                    last_write_at: None,
                    detail: Some("poisoned lock".to_string()),
                }
            }
        };
        let event_count: i64 = match conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        {
            Ok(count) => count,
            Err(e) => {
                return StorageHealth {
                    healthy: false,
                    event_count: 0,
                    last_write_at: None,
                    detail: Some(format!("event count query failed: {e}")),
                }
            }
        };
        let last_write_at: Option<i64> = match conn
            .query_row("SELECT MAX(timestamp) FROM events", [], |r| r.get(0))
            .optional()
        {
            Ok(v) => v.flatten(),
            Err(e) => {
                return StorageHealth {
                    healthy: false,
                    event_count: event_count as u64,
                    last_write_at: None,
                    detail: Some(format!("last write query failed: {e}")),
                }
            }
        };
        StorageHealth {
            healthy: true,
            event_count: event_count as u64,
            last_write_at: last_write_at.map(|v| v as u64),
            detail: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
    };
    use uuid::Uuid;

    fn sample_event(pid: u32, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", pid, timestamp),
                pid,
                exe_path: "/bin/x".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: timestamp,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn write_and_query_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let event = sample_event(100, 1000);
        storage.write(&event).unwrap();

        let results = storage.query(&QueryPlan::new()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, event.event_id);
    }

    #[test]
    fn batch_write_reports_counts() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let events = vec![sample_event(100, 1000), sample_event(200, 2000)];
        let report = storage.batch_write(&events).unwrap();
        assert_eq!(report.written_count, 2);
        assert_eq!(report.failed_count, 0);
    }

    #[test]
    fn query_filters_by_time_range() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .batch_write(&[
                sample_event(100, 1000),
                sample_event(200, 5000),
                sample_event(300, 9000),
            ])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.since = Some(2000);
        plan.until = Some(6000);
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].process.as_ref().unwrap().pid, 200);
    }

    #[test]
    fn query_filters_by_process_key() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let event = sample_event(100, 1000);
        let key = event.process.as_ref().unwrap().process_key;
        storage.write(&event).unwrap();
        storage.write(&sample_event(200, 2000)).unwrap();

        let mut plan = QueryPlan::new();
        plan.process_key = Some(key);
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn delete_removes_events_before_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .batch_write(&[sample_event(100, 1000), sample_event(200, 9000)])
            .unwrap();

        let deleted = storage
            .delete(&DeleteCriteria {
                before_timestamp: 5000,
            })
            .unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(storage.query(&QueryPlan::new()).unwrap().len(), 1);
    }

    #[test]
    fn health_reports_event_count_and_last_write() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage.write(&sample_event(100, 1000)).unwrap();
        let health = storage.health();
        assert!(health.healthy);
        assert_eq!(health.event_count, 1);
        assert_eq!(health.last_write_at, Some(1000));
    }

    #[test]
    fn duplicate_event_id_is_ignored_and_reported_as_failed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let event = sample_event(100, 1000);
        storage.write(&event).unwrap();

        // Second write of an event with the same event_id must be ignored by the
        // INSERT OR IGNORE and reported as failed, not silently duplicated.
        let report = storage.batch_write(std::slice::from_ref(&event)).unwrap();
        assert_eq!(report.written_count, 0);
        assert_eq!(report.failed_count, 1);

        let results = storage.query(&QueryPlan::new()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(storage.health().event_count, 1);
    }
}
