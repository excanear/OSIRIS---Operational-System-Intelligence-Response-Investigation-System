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
                network_src_ip TEXT,
                network_dst_ip TEXT,
                dns_domain TEXT,
                session_id TEXT,
                user_uid INTEGER,
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
        //
        // The same loop also adds Phase 3's three network/DNS columns
        // (`network_src_ip`, `network_dst_ip`, `dns_domain`) for a database
        // created before this phase. As with the file columns above, these
        // are not backfilled on pre-existing rows — they read back as NULL
        // even if a pre-Phase-3 row's `raw_json` happened to contain
        // relevant data. This has no practical impact today since no
        // pre-Phase-3 database can actually contain network/DNS events.
        //
        // Phase 4a adds `session_id` and `user_uid` the same way. As with
        // every earlier phase's columns, pre-existing rows are not
        // backfilled — they read back NULL. That has no practical impact:
        // no database created before Phase 4a can contain an event with a
        // populated `session` or `user`, because nothing populated either
        // field until this phase's pipeline changes.
        for (column, ddl) in [
            ("file_path", "ALTER TABLE events ADD COLUMN file_path TEXT"),
            ("file_inode", "ALTER TABLE events ADD COLUMN file_inode INTEGER"),
            (
                "file_device_id",
                "ALTER TABLE events ADD COLUMN file_device_id INTEGER",
            ),
            (
                "network_src_ip",
                "ALTER TABLE events ADD COLUMN network_src_ip TEXT",
            ),
            (
                "network_dst_ip",
                "ALTER TABLE events ADD COLUMN network_dst_ip TEXT",
            ),
            ("dns_domain", "ALTER TABLE events ADD COLUMN dns_domain TEXT"),
            ("session_id", "ALTER TABLE events ADD COLUMN session_id TEXT"),
            ("user_uid", "ALTER TABLE events ADD COLUMN user_uid INTEGER"),
        ] {
            if !column_exists(&conn, "events", column)? {
                conn.execute(ddl, [])
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_events_file_path ON events(file_path);
             CREATE INDEX IF NOT EXISTS idx_events_file_identity ON events(file_device_id, file_inode);
             CREATE INDEX IF NOT EXISTS idx_events_network_src_ip ON events(network_src_ip);
             CREATE INDEX IF NOT EXISTS idx_events_network_dst_ip ON events(network_dst_ip);
             CREATE INDEX IF NOT EXISTS idx_events_dns_domain ON events(dns_domain);
             CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
             CREATE INDEX IF NOT EXISTS idx_events_user_uid ON events(user_uid);",
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
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| StorageError::Backend(e.to_string()))?;
    for name in rows {
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
            let network_src_ip = event.network.as_ref().map(|n| n.src_ip.clone());
            let network_dst_ip = event.network.as_ref().map(|n| n.dst_ip.clone());
            let dns_domain = event.dns.as_ref().map(|d| d.query.clone());
            let session_id = event.session.as_ref().map(|s| s.session_id.clone());
            // i64 because SQLite has no unsigned integer type; a uid is at
            // most u32::MAX, so this widening is always lossless — the same
            // cast the file inode/device columns already use.
            let user_uid = event.user.as_ref().map(|u| u.uid as i64);
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, file_path, file_inode, file_device_id, network_src_ip, network_dst_ip, dns_domain, session_id, user_uid, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
                        network_src_ip,
                        network_dst_ip,
                        dns_domain,
                        session_id,
                        user_uid,
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
        if let Some(addr) = &plan.network_addr {
            sql.push_str(" AND (network_src_ip = ? OR network_dst_ip = ?)");
            sql_params.push(Box::new(addr.clone()));
            sql_params.push(Box::new(addr.clone()));
        }
        if let Some(domain) = &plan.dns_domain {
            sql.push_str(" AND dns_domain = ?");
            sql_params.push(Box::new(domain.clone()));
        }
        if let Some(session_id) = &plan.session_id {
            sql.push_str(" AND session_id = ?");
            sql_params.push(Box::new(session_id.clone()));
        }
        if let Some(uid) = plan.user_uid {
            sql.push_str(" AND user_uid = ?");
            sql_params.push(Box::new(uid as i64));
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

    fn network_event(src_ip: &str, dst_ip: &str, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(300, timestamp);
        event.event_type = osiris_schema::EventType::NetworkConnect;
        event.category = osiris_schema::Category::Network;
        event.network = Some(osiris_schema::NetworkRef {
            src_ip: src_ip.to_string(),
            src_port: 51000,
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        event
    }

    fn dns_event(query: &str, response_ips: Vec<String>, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(300, timestamp);
        event.event_type = osiris_schema::EventType::DnsQuery;
        event.category = osiris_schema::Category::Dns;
        event.dns = Some(osiris_schema::DnsRef {
            query: query.to_string(),
            qtype: "A".to_string(),
            response_ips,
            ttl: Some(300),
        });
        event
    }

    fn open_test_storage() -> SqliteStorage {
        let dir = tempfile::tempdir().unwrap();
        SqliteStorage::open(dir.path().join("events.db")).unwrap()
    }

    #[test]
    fn query_filters_by_network_addr_matching_either_src_or_dst() {
        let storage = open_test_storage();
        let as_dst = network_event("10.0.0.5", "203.0.113.50", 1000);
        let as_src = network_event("203.0.113.50", "10.0.0.6", 2000);
        let unrelated = network_event("10.0.0.7", "198.51.100.1", 3000);
        storage
            .batch_write(&[as_dst.clone(), as_src.clone(), unrelated])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.network_addr = Some("203.0.113.50".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 2);
        let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&as_dst.event_id));
        assert!(ids.contains(&as_src.event_id));
    }

    #[test]
    fn query_filters_by_dns_domain() {
        let storage = open_test_storage();
        let matching = dns_event("cdn-assets.xyz", vec!["203.0.113.50".to_string()], 1000);
        let other = dns_event("example.com", vec!["93.184.216.34".to_string()], 2000);
        storage.batch_write(&[matching.clone(), other]).unwrap();

        let mut plan = QueryPlan::new();
        plan.dns_domain = Some("cdn-assets.xyz".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, matching.event_id);
    }

    /// Non-destructive/idempotent migration proof, matching Phase 2 Task
    /// 6's precedent exactly: open a database shaped like it predates this
    /// phase's three new columns, then re-open it through the current
    /// `SqliteStorage::open` and confirm existing data survives and the new
    /// columns' guarded ADD COLUMN migration runs, and new filtering works.
    #[test]
    fn migrates_a_pre_phase_3_database_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        // Recreate a Phase 2 schema (has file columns but not network/DNS).
        let pre_phase_3_network_event = network_event("10.0.0.5", "203.0.113.50", 1000);
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
                    file_path TEXT,
                    file_inode INTEGER,
                    file_device_id INTEGER,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, file_path, file_inode, file_device_id, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    pre_phase_3_network_event.event_id.to_string(),
                    pre_phase_3_network_event.host_id.to_string(),
                    pre_phase_3_network_event.timestamp as i64,
                    "NETWORK_CONNECT",
                    pre_phase_3_network_event.process.as_ref().map(|p| p.process_key.as_hex()),
                    pre_phase_3_network_event.parent_process.as_ref().map(|p| p.process_key.as_hex()),
                    None::<String>,
                    None::<i64>,
                    None::<i64>,
                    serde_json::to_string(&pre_phase_3_network_event).unwrap(),
                ],
            )
            .unwrap();
        }

        // Re-open via SqliteStorage::open, which must run the guarded
        // ALTER TABLE ADD COLUMN migrations for network_src_ip, network_dst_ip, dns_domain.
        let reopened = SqliteStorage::open(&db_path).unwrap();

        // Pre-existing row must survive (proves no data loss during migration).
        let all_events = reopened.query(&QueryPlan::new()).unwrap();
        assert_eq!(all_events.len(), 1, "the pre-existing row must survive migration");

        // The new columns must now exist and work: the guarded
        // ALTER TABLE ADD COLUMN path must have run. Prove this by writing a
        // new event after migration and verifying the new filter works on it.
        let new_event = network_event("192.168.1.1", "8.8.8.8", 2000);
        reopened.write(&new_event).unwrap();

        // Query the new event by its network address (proves columns exist).
        let mut plan = QueryPlan::new();
        plan.network_addr = Some("8.8.8.8".to_string());
        let network_results = reopened.query(&plan).unwrap();
        assert_eq!(
            network_results.len(),
            1,
            "the migrated network_src_ip/network_dst_ip columns must exist and filter correctly"
        );
        assert_eq!(network_results[0].event_id, new_event.event_id);

        // Also verify idempotency: re-open the same database and confirm
        // the second open doesn't error or duplicate columns.
        let reopened_again = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(
            reopened_again.query(&QueryPlan::new()).unwrap().len(),
            2,
            "all events (pre- and post-migration) must survive a second open"
        );
        let mut plan = QueryPlan::new();
        plan.network_addr = Some("8.8.8.8".to_string());
        assert_eq!(
            reopened_again.query(&plan).unwrap().len(),
            1,
            "filtering must still work after idempotent re-open"
        );
    }

    fn identity_event(
        event_type: osiris_schema::EventType,
        session_id: &str,
        uid: u32,
        remote_addr: Option<&str>,
        timestamp: u64,
    ) -> CanonicalEvent {
        let mut event = sample_event(300, timestamp);
        event.event_type = event_type;
        event.category = event_type.category();
        event.session = Some(osiris_schema::SessionRef {
            session_id: session_id.to_string(),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: remote_addr.map(str::to_string),
            auth_method: Some("sshd".to_string()),
        });
        event.user = Some(osiris_schema::UserRef {
            uid,
            gid: uid,
            euid: uid,
            egid: uid,
            username: Some("alice".to_string()),
            loginuid: Some(1000),
        });
        event
    }

    #[test]
    fn query_filters_by_session_id_across_every_category() {
        let storage = open_test_storage();
        // The point of the session filter: one id returns the whole
        // multi-category chain, not just the identity events.
        let login = identity_event(
            osiris_schema::EventType::SessionLogin,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let escalation = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            2000,
        );
        let mut exec = identity_event(
            osiris_schema::EventType::ProcessExec,
            "3",
            1000,
            Some("198.51.100.10"),
            3000,
        );
        exec.category = osiris_schema::Category::Process;
        let other_session = identity_event(
            osiris_schema::EventType::SessionLogin,
            "4",
            0,
            None,
            4000,
        );
        // An event that predates any session attribution at all.
        let unattributed = sample_event(900, 5000);
        storage
            .batch_write(&[
                login.clone(),
                escalation.clone(),
                exec.clone(),
                other_session,
                unattributed,
            ])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 3);
        let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&login.event_id));
        assert!(ids.contains(&escalation.event_id));
        assert!(ids.contains(&exec.event_id));
        // Storage returns rows time-ordered (ORDER BY timestamp ASC).
        assert_eq!(results[0].event_id, login.event_id);
        assert_eq!(results[2].event_id, exec.event_id);
    }

    #[test]
    fn query_filters_by_user_uid() {
        let storage = open_test_storage();
        let root = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let alice = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            2000,
        );
        storage.batch_write(&[root.clone(), alice.clone()]).unwrap();

        let mut plan = QueryPlan::new();
        plan.user_uid = Some(0);
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, root.event_id);

        // uid 0 must not be confused with "no user at all": an event whose
        // `user` is None writes NULL, and NULL never equals 0 in SQL.
        storage.write(&sample_event(901, 3000)).unwrap();
        assert_eq!(storage.query(&plan).unwrap().len(), 1);
    }

    /// The two filters compose (the Identity Story never needs this today,
    /// but the SQL builder must not special-case one over the other).
    #[test]
    fn the_session_and_uid_filters_compose() {
        let storage = open_test_storage();
        let alice_in_3 = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            1000,
            None,
            1000,
        );
        let root_in_3 = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            0,
            None,
            2000,
        );
        let alice_in_4 = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "4",
            1000,
            None,
            3000,
        );
        storage
            .batch_write(&[alice_in_3.clone(), root_in_3, alice_in_4])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        plan.user_uid = Some(1000);
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, alice_in_3.event_id);
    }

    /// Non-destructive/idempotent migration proof, matching Phase 2 Task 6's
    /// and Phase 3 Task 4's precedent exactly: open a database shaped like it
    /// predates this phase's two new columns, re-open it through the current
    /// `SqliteStorage::open`, and confirm existing data survives, the guarded
    /// ADD COLUMN migration runs, and the new filters work afterwards.
    #[test]
    fn migrates_a_pre_phase_4_database_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let pre_phase_4_event = sample_event(300, 1000);
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            // A Phase 3 schema: file and network/DNS columns, no identity
            // columns.
            conn.execute_batch(
                "CREATE TABLE events (
                    event_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    process_key TEXT,
                    parent_process_key TEXT,
                    file_path TEXT,
                    file_inode INTEGER,
                    file_device_id INTEGER,
                    network_src_ip TEXT,
                    network_dst_ip TEXT,
                    dns_domain TEXT,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    pre_phase_4_event.event_id.to_string(),
                    pre_phase_4_event.host_id.to_string(),
                    pre_phase_4_event.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&pre_phase_4_event).unwrap(),
                ],
            )
            .unwrap();
        }

        let reopened = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(
            reopened.query(&QueryPlan::new()).unwrap().len(),
            1,
            "the pre-existing row must survive migration"
        );

        let login = identity_event(
            osiris_schema::EventType::SessionLogin,
            "3",
            0,
            Some("198.51.100.10"),
            2000,
        );
        reopened.write(&login).unwrap();

        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        assert_eq!(
            reopened.query(&plan).unwrap().len(),
            1,
            "the migrated session_id column must exist and filter correctly"
        );
        let mut plan = QueryPlan::new();
        plan.user_uid = Some(0);
        assert_eq!(
            reopened.query(&plan).unwrap().len(),
            1,
            "the migrated user_uid column must exist and filter correctly"
        );

        // Idempotency: a second open must neither error nor duplicate a
        // column, and everything must still be there and still filterable.
        let reopened_again = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(reopened_again.query(&QueryPlan::new()).unwrap().len(), 2);
        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        assert_eq!(reopened_again.query(&plan).unwrap().len(), 1);
    }
}
