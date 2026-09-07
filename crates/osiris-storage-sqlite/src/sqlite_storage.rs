use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_schema::{Alert, CanonicalEvent, FileIdentity};
use osiris_storage::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RetentionPolicy, RetentionReport, Storage,
    StorageError, StorageHealth, WriteReport,
};
use rusqlite::{params, Connection, OptionalExtension};

/// SQLite-backed Storage (ARCHITECTURE.md §10.2, MVP tier). One table
/// (`events`) with a few indexed columns for filtering plus the full
/// event as a JSON blob for round-trip fidelity — proportionate to this
/// phase's five event types, with three indexed file columns added for
/// the File Story's two lookups plus an `alerts` table and its
/// `alert_evidence` join table, not the "small number of wide tables"
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
                file_path TEXT,
                file_inode INTEGER,
                file_device_id INTEGER,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_host_timestamp ON events(host_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_process_key ON events(process_key);

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                rule_version INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                host_id TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_timestamp ON alerts(rule_id, timestamp);

            -- One row per (alert, cited event). A join table rather than a
            -- JSON array column so the File Story's 'alerts citing these
            -- events' lookup is an indexed join, not a scan-and-parse.
            CREATE TABLE IF NOT EXISTS alert_evidence (
                alert_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (alert_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_alert_evidence_event ON alert_evidence(event_id);",
        )
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        // Migrate a database created by Phase 1, whose `events` table
        // predates the three file columns. `CREATE TABLE IF NOT EXISTS`
        // above is a no-op on such a database, so the columns must be added
        // explicitly. Adding a nullable column to SQLite is an O(1)
        // metadata-only operation, and existing rows read back as NULL —
        // correct, since no Phase 1 event ever populated `file`.
        for (column, ddl) in [
            ("file_path", "ALTER TABLE events ADD COLUMN file_path TEXT"),
            ("file_inode", "ALTER TABLE events ADD COLUMN file_inode INTEGER"),
            (
                "file_device_id",
                "ALTER TABLE events ADD COLUMN file_device_id INTEGER",
            ),
        ] {
            if !column_exists(&conn, "events", column)? {
                conn.execute(ddl, [])
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_events_file_path ON events(file_path);
             CREATE INDEX IF NOT EXISTS idx_events_file_identity ON events(file_device_id, file_inode);",
        )
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, StorageError> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| StorageError::Backend(e.to_string()))?;
    let mut rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| StorageError::Backend(e.to_string()))?;
    while let Some(name) = rows.next() {
        if name.map_err(|e| StorageError::Backend(e.to_string()))? == column {
            return Ok(true);
        }
    }
    Ok(false)
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
            let file_path = event.file.as_ref().map(|f| f.path.clone());
            let file_identity = event.file.as_ref().and_then(FileIdentity::from_file_ref);
            let file_inode = file_identity.map(|i| i.inode as i64);
            let file_device_id = file_identity.map(|i| i.device_id as i64);
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, file_path, file_inode, file_device_id, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        event.event_id.to_string(),
                        event.host_id.to_string(),
                        event.timestamp as i64,
                        event_type,
                        process_key,
                        parent_process_key,
                        file_path,
                        file_inode,
                        file_device_id,
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
        if let Some(file_path) = &plan.file_path {
            sql.push_str(" AND file_path = ?");
            sql_params.push(Box::new(file_path.clone()));
        }
        if let Some(identity) = &plan.file_identity {
            sql.push_str(" AND file_inode = ? AND file_device_id = ?");
            sql_params.push(Box::new(identity.inode as i64));
            sql_params.push(Box::new(identity.device_id as i64));
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

    fn write_alerts(&self, alerts: &[Alert]) -> Result<WriteReport, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut report = WriteReport::default();
        for alert in alerts {
            let raw_json =
                serde_json::to_string(alert).map_err(|e| StorageError::Serialize(e.to_string()))?;
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO alerts (alert_id, rule_id, rule_version, timestamp, host_id, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        alert.alert_id().to_string(),
                        alert.rule_id(),
                        alert.rule_version() as i64,
                        alert.timestamp() as i64,
                        alert.host_id().to_string(),
                        raw_json,
                    ],
                )
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            if changed == 1 {
                report.written_count += 1;
                for event_id in alert.evidence() {
                    tx.execute(
                        "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id) VALUES (?1, ?2)",
                        params![alert.alert_id().to_string(), event_id.to_string()],
                    )
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                }
            } else {
                report.failed_count += 1;
            }
        }
        tx.commit()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(report)
    }

    fn query_alerts(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        // DISTINCT because an alert citing several of the requested events
        // must come back once, not once per citation.
        let mut sql = "SELECT DISTINCT a.raw_json FROM alerts a".to_string();
        let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if !plan.evidence_event_ids.is_empty() {
            let placeholders = vec!["?"; plan.evidence_event_ids.len()].join(",");
            sql.push_str(&format!(
                " JOIN alert_evidence e ON e.alert_id = a.alert_id WHERE e.event_id IN ({placeholders})"
            ));
            for event_id in &plan.evidence_event_ids {
                sql_params.push(Box::new(event_id.to_string()));
            }
        } else {
            sql.push_str(" WHERE 1=1");
        }
        if let Some(rule_id) = &plan.rule_id {
            sql.push_str(" AND a.rule_id = ?");
            sql_params.push(Box::new(rule_id.clone()));
        }
        if let Some(since) = plan.since {
            sql.push_str(" AND a.timestamp >= ?");
            sql_params.push(Box::new(since as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND a.timestamp <= ?");
            sql_params.push(Box::new(until as i64));
        }
        sql.push_str(" ORDER BY a.timestamp ASC LIMIT ?");
        let limit = if plan.limit == 0 { 100 } else { plan.limit };
        sql_params.push(Box::new(limit as i64));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let mut alerts = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| StorageError::Backend(e.to_string()))?;
            let alert: Alert = serde_json::from_str(&raw_json)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            alerts.push(alert);
        }
        Ok(alerts)
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

    fn file_event(path: &str, inode: u64, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(300, timestamp);
        event.event_type = EventType::FileWrite;
        event.category = Category::File;
        event.file = Some(osiris_schema::FileRef {
            path: path.to_string(),
            previous_path: None,
            inode: Some(inode),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        event
    }

    fn sample_alert(evidence: Vec<Uuid>, rule_id: &str, timestamp: u64) -> osiris_schema::Alert {
        osiris_schema::Alert::new(
            rule_id,
            1,
            "deadbeef",
            osiris_schema::Severity::High,
            timestamp,
            Uuid::new_v4(),
            vec!["The file was written inside /var/www/".to_string()],
            evidence,
        )
        .expect("valid alert")
    }

    #[test]
    fn query_filters_by_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .batch_write(&[
                file_event("/var/www/html/shell.php", 200001, 1000),
                file_event("/home/user/notes.txt", 300777, 2000),
            ])
            .unwrap();

        let plan = QueryPlan {
            file_path: Some("/var/www/html/shell.php".to_string()),
            ..QueryPlan::new()
        };
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].file.as_ref().unwrap().path,
            "/var/www/html/shell.php"
        );
    }

    /// The point of identity-based lookup: one inode, two names. A query by
    /// identity must return both events, which is how a File Story follows
    /// a file across a rename.
    #[test]
    fn query_by_file_identity_spans_both_names_of_a_renamed_file() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .batch_write(&[
                file_event("/var/www/html/.shell.php.tmp", 200001, 1000),
                file_event("/var/www/html/shell.php", 200001, 2000),
                file_event("/home/user/notes.txt", 300777, 3000),
            ])
            .unwrap();

        let plan = QueryPlan {
            file_identity: Some(osiris_schema::FileIdentity::new(
                200001,
                osiris_schema::encode_device_id(8, 1),
            )),
            ..QueryPlan::new()
        };
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].timestamp, 1000, "results stay time-ordered");
        assert_eq!(results[1].timestamp, 2000);
    }

    #[test]
    fn a_process_event_with_no_file_ref_never_matches_a_file_filter() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage.write(&sample_event(100, 1000)).unwrap();
        let plan = QueryPlan {
            file_path: Some("/var/www/html/shell.php".to_string()),
            ..QueryPlan::new()
        };
        assert!(storage.query(&plan).unwrap().is_empty());
    }

    #[test]
    fn write_and_query_alerts_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let event_id = Uuid::now_v7();
        let alert = sample_alert(vec![event_id], "shell_wrote_file_to_web_root", 5000);

        let report = storage.write_alerts(std::slice::from_ref(&alert)).unwrap();
        assert_eq!(report.written_count, 1);

        let results = storage.query_alerts(&AlertQueryPlan::new()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].alert_id(), alert.alert_id());
        assert_eq!(results[0].rule_id(), "shell_wrote_file_to_web_root");
        assert_eq!(results[0].reasons().len(), 1);
        assert_eq!(results[0].evidence(), &[event_id]);
    }

    #[test]
    fn query_alerts_filters_by_rule_id_and_time_range() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .write_alerts(&[
                sample_alert(vec![Uuid::now_v7()], "rule_a", 1000),
                sample_alert(vec![Uuid::now_v7()], "rule_b", 5000),
                sample_alert(vec![Uuid::now_v7()], "rule_a", 9000),
            ])
            .unwrap();

        let by_rule = storage
            .query_alerts(&AlertQueryPlan {
                rule_id: Some("rule_a".to_string()),
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_rule.len(), 2);

        let by_time = storage
            .query_alerts(&AlertQueryPlan {
                since: Some(2000),
                until: Some(6000),
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_time.len(), 1);
        assert_eq!(by_time[0].rule_id(), "rule_b");
    }

    /// The File Story's "alerts citing these events" join, in one query.
    #[test]
    fn query_alerts_filters_by_the_events_they_cite() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let wanted = Uuid::now_v7();
        let other = Uuid::now_v7();
        storage
            .write_alerts(&[
                sample_alert(vec![wanted], "rule_a", 1000),
                sample_alert(vec![other], "rule_b", 2000),
            ])
            .unwrap();

        let results = storage
            .query_alerts(&AlertQueryPlan {
                evidence_event_ids: vec![wanted],
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id(), "rule_a");
    }

    /// One alert citing two events must be returned once, not twice, when
    /// both of its events are in the filter set.
    #[test]
    fn an_alert_citing_several_matching_events_is_returned_once() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        storage
            .write_alerts(&[sample_alert(vec![a, b], "rule_a", 1000)])
            .unwrap();

        let results = storage
            .query_alerts(&AlertQueryPlan {
                evidence_event_ids: vec![a, b],
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn rewriting_an_alert_id_is_ignored_and_reported_as_failed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let alert = sample_alert(vec![Uuid::now_v7()], "rule_a", 1000);
        storage.write_alerts(std::slice::from_ref(&alert)).unwrap();

        let report = storage.write_alerts(std::slice::from_ref(&alert)).unwrap();
        assert_eq!(report.written_count, 0);
        assert_eq!(report.failed_count, 1);
        assert_eq!(storage.query_alerts(&AlertQueryPlan::new()).unwrap().len(), 1);
    }

    /// A database created by Phase 1 has an `events` table with no file
    /// columns and no `alerts` table at all. Opening it with this build
    /// must migrate it in place — not fail, and not silently ignore the
    /// pre-existing rows.
    #[test]
    fn opens_and_migrates_a_phase_1_database_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        // Recreate Phase 1's exact schema and insert one row through it.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                    event_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    process_key TEXT,
                    parent_process_key TEXT,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            let legacy = sample_event(100, 1000);
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, raw_json)
                 VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
                rusqlite::params![
                    legacy.event_id.to_string(),
                    legacy.host_id.to_string(),
                    legacy.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&legacy).unwrap(),
                ],
            )
            .unwrap();
        }

        let storage = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(
            storage.query(&QueryPlan::new()).unwrap().len(),
            1,
            "the pre-existing row must survive migration"
        );
        // The new columns and the new tables now exist and work.
        storage
            .write(&file_event("/var/www/html/shell.php", 200001, 2000))
            .unwrap();
        let plan = QueryPlan {
            file_path: Some("/var/www/html/shell.php".to_string()),
            ..QueryPlan::new()
        };
        assert_eq!(storage.query(&plan).unwrap().len(), 1);
        storage
            .write_alerts(&[sample_alert(vec![Uuid::now_v7()], "rule_a", 3000)])
            .unwrap();
        assert_eq!(storage.query_alerts(&AlertQueryPlan::new()).unwrap().len(), 1);
    }
}
