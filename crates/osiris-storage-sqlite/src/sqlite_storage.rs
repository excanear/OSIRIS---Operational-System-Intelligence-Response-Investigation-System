use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_schema::{
    Alert, CanonicalEvent, EntityRef, EntityRelationship, FileIdentity, Relation, RiskScoreRecord,
    Severity, WeightedReason,
};
use osiris_storage::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RelationshipQueryPlan, RetentionPolicy,
    RetentionReport, RiskQueryPlan, Storage, StorageError, StorageHealth, WriteReport,
};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

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
                category TEXT,
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
                unit_name TEXT,
                container_id TEXT,
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
            CREATE INDEX IF NOT EXISTS idx_alert_evidence_event ON alert_evidence(event_id);

            -- Phase 6: relationships as a first-class, queryable edge table
            -- (ARCHITECTURE.md §9.4), keyed on the stable EntityRef string
            -- encoding (`EntityRef::storage_key()`) rather than a typed
            -- per-variant column, so one index serves every entity kind.
            CREATE TABLE IF NOT EXISTS relationships (
                from_key TEXT NOT NULL,
                to_key TEXT NOT NULL,
                relation TEXT NOT NULL,
                event_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_relationships_from ON relationships(from_key);
            CREATE INDEX IF NOT EXISTS idx_relationships_to ON relationships(to_key);
            CREATE INDEX IF NOT EXISTS idx_relationships_timestamp ON relationships(timestamp);

            -- Phase 6: Risk Engine output (ARCHITECTURE.md §11.4), mirroring
            -- the alerts/alert_evidence split above exactly.
            CREATE TABLE IF NOT EXISTS risk_scores (
                event_id TEXT PRIMARY KEY,
                process_key TEXT,
                host_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                related_events TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_risk_scores_process_key ON risk_scores(process_key);
            CREATE INDEX IF NOT EXISTS idx_risk_scores_timestamp ON risk_scores(timestamp);

            CREATE TABLE IF NOT EXISTS risk_score_reasons (
                event_id TEXT NOT NULL,
                label TEXT NOT NULL,
                weight INTEGER NOT NULL,
                evidence TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_risk_score_reasons_event ON risk_score_reasons(event_id);",
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
        //
        // Phase 4b adds `unit_name` the same way. As with every earlier
        // phase's columns, pre-existing rows are not backfilled — they
        // read back NULL. No database created before Phase 4b can contain
        // an event with a populated `service`, so this has no practical
        // impact.
        //
        // Phase 5 adds `container_id` the same way. No database created
        // before Phase 5 can contain an event with a populated
        // `container`, so pre-existing rows reading back NULL has no
        // practical impact either.
        //
        // Phase 7b-6 adds `category`, added the same guarded way — but
        // unlike every column above, `category` is NOT a new fact: it has
        // always existed on every event (`CanonicalEvent::category` is
        // mandatory, never `Option`), just never had its own column. So a
        // pre-existing row's `category` IS already present in its own
        // stored `raw_json`, and leaving the column NULL would be wrong
        // (not merely uninformative) — it's backfilled explicitly below,
        // by reading `raw_json`'s own `category` field via `json_extract`,
        // instead of following the read-back-NULL precedent every earlier
        // column here uses.
        // Phase 9a: agent redelivery is at-least-once, so `relationships` must be
        // idempotent. Guarded: dedupe pre-existing rows, then add the unique
        // index (IF NOT EXISTS keeps re-opens no-ops; the DELETE is a no-op once unique).
        conn.execute_batch(
            "DELETE FROM relationships WHERE rowid NOT IN (
                 SELECT MIN(rowid) FROM relationships
                 GROUP BY from_key, to_key, relation, event_id);
             CREATE UNIQUE INDEX IF NOT EXISTS idx_relationships_unique
                 ON relationships(from_key, to_key, relation, event_id);",
        )
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        for (column, ddl) in [
            ("file_path", "ALTER TABLE events ADD COLUMN file_path TEXT"),
            (
                "file_inode",
                "ALTER TABLE events ADD COLUMN file_inode INTEGER",
            ),
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
            (
                "dns_domain",
                "ALTER TABLE events ADD COLUMN dns_domain TEXT",
            ),
            (
                "session_id",
                "ALTER TABLE events ADD COLUMN session_id TEXT",
            ),
            ("user_uid", "ALTER TABLE events ADD COLUMN user_uid INTEGER"),
            ("unit_name", "ALTER TABLE events ADD COLUMN unit_name TEXT"),
            (
                "container_id",
                "ALTER TABLE events ADD COLUMN container_id TEXT",
            ),
            ("category", "ALTER TABLE events ADD COLUMN category TEXT"),
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
             CREATE INDEX IF NOT EXISTS idx_events_user_uid ON events(user_uid);
             CREATE INDEX IF NOT EXISTS idx_events_unit_name ON events(unit_name);
             CREATE INDEX IF NOT EXISTS idx_events_container_id ON events(container_id);
             CREATE INDEX IF NOT EXISTS idx_events_category_timestamp ON events(category, timestamp);",
        )
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        // Backfill `category` for any row that predates this column. Every
        // row's `raw_json` already carries the authoritative, already-computed
        // `category` field (`CanonicalEvent::category`) regardless of whether
        // its `event_type` string is one this binary's `EventType` enum still
        // recognizes — so this reads it straight out of the stored JSON via
        // SQLite's `json_extract`, rather than re-deriving it from `event_type`
        // through `EventType::category()`. That avoids needing a hand-maintained
        // SQL CASE/WHEN mirroring `EventType::category()`'s ~49 branches (so the
        // two can never drift apart), and it means a row with an unrecognized
        // `event_type` (a renamed/removed variant, hand-edited data) still gets
        // correctly backfilled instead of being permanently skipped.
        conn.execute(
            "UPDATE events SET category = json_extract(raw_json, '$.category') \
             WHERE category IS NULL",
            [],
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

/// `Some(leaves)` when `ast` is a pure `AND`-chain of `Compare` leaves (no
/// `OR`/`NOT` anywhere) — the only shape this MVP's pushdown handles.
/// `None` for anything else, telling the caller to skip pushdown for this
/// filter and rely on `eval_ast` alone (still bounded by `since`/`until`
/// and `SqliteStorage::MAX_SCAN_ROWS`).
fn conjunction_leaves(
    ast: &osiris_query::Ast,
) -> Option<Vec<(&str, osiris_query::Op, &osiris_query::Value)>> {
    use osiris_query::Ast;
    match ast {
        Ast::Compare { field, op, value } => Some(vec![(field.as_str(), *op, value)]),
        Ast::And(l, r) => {
            let mut left = conjunction_leaves(l)?;
            let right = conjunction_leaves(r)?;
            left.extend(right);
            Some(left)
        }
        Ast::Or(_, _) | Ast::Not(_) => None,
    }
}

/// Appends the tenant host restriction to a WHERE clause already in progress:
/// ` AND <column> IN (?,..)`, or ` AND 1=0` for an empty list (an empty host
/// set must match nothing, never everything).
const MAX_TENANT_HOSTS: usize = 30_000;

fn host_set_too_large() -> StorageError {
    StorageError::Backend("tenant host set too large (limit 30000)".to_string())
}

fn push_host_filter(
    sql: &mut String,
    params: &mut Vec<Box<dyn rusqlite::ToSql>>,
    column: &str,
    host_ids: &Option<Vec<String>>,
) -> Result<(), StorageError> {
    let Some(ids) = host_ids else { return Ok(()) };
    if ids.len() > MAX_TENANT_HOSTS {
        return Err(host_set_too_large());
    }
    if ids.is_empty() {
        sql.push_str(" AND 1=0");
        return Ok(());
    }
    sql.push_str(&format!(
        " AND {column} IN ({})",
        vec!["?"; ids.len()].join(",")
    ));
    for id in ids {
        params.push(Box::new(id.clone()));
    }
    Ok(())
}

impl SqliteStorage {
    /// How many rows one SQL round-trip of `query_events`' scan pulls back
    /// before the residual `eval_ast` pass filters them. This is a *batch*
    /// size, not a result ceiling: `query_events_batched` keeps paginating
    /// with a `(timestamp, event_id)` cursor until it has collected
    /// `plan.effective_limit()` matches or the time range is exhausted.
    const SCAN_BATCH_SIZE: i64 = 20_000;

    /// Worst-case bound on how many rows a single `query_events` call will
    /// scan when pushdown covers little or none of the filter (e.g. an
    /// `OR`, a `!=`, or a field with no indexed column such as `process_name`).
    /// A query matching nothing over a huge table stops here rather than
    /// scanning unboundedly; the result is then bounded-incomplete, which
    /// is the same class of behavior the old fixed 20k prefetch had, only
    /// with a far more realistic ceiling.
    const MAX_SCAN_ROWS: i64 = 1_000_000;

    /// `query_events` with an explicit scan batch size so tests can prove
    /// the cursor pagination actually paginates without writing millions
    /// of rows.
    fn query_events_batched(
        &self,
        plan: &osiris_query::EventQueryPlan,
        batch_size: i64,
    ) -> Result<Vec<CanonicalEvent>, StorageError> {
        use osiris_query::{eval_ast, Op, Value};

        let effective_limit = plan.effective_limit();
        if effective_limit == 0 {
            return Ok(Vec::new());
        }

        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;

        // Pushdown: when the filter is a pure AND-conjunction (no OR/NOT),
        // push every leaf this MVP has an indexed column for into SQL — the
        // same 8 columns `query()` already filters on above, plus `category`
        // (Phase 7b-6), which `query()`/`QueryPlan` has no field for since
        // no caller of the older API needs it yet. Any leaf without a
        // matching column, and the whole filter when it
        // contains OR/NOT, is left to the residual `eval_ast` pass below —
        // pushdown here is a pure performance optimization: every returned
        // row is re-checked against the *entire* original filter before
        // being included, so a pushdown bug can only over-fetch, never
        // return a wrong result.
        let mut base_sql = "SELECT raw_json, timestamp, event_id FROM events WHERE 1=1".to_string();
        let mut base_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if let Some(filter) = &plan.filter {
            if let Some(leaves) = conjunction_leaves(filter) {
                for (field, op, value) in leaves {
                    if op != Op::Eq {
                        continue;
                    }
                    let column = match field {
                        "event_type" => "event_type",
                        "category" => "category",
                        "process.process_key" => "process_key",
                        "file.path" => "file_path",
                        "dns.query" => "dns_domain",
                        "session.session_id" => "session_id",
                        "user.uid" => "user_uid",
                        "service.unit_name" => "unit_name",
                        "container.container_id" => "container_id",
                        _ => continue,
                    };
                    match value {
                        Value::Str(s) => {
                            base_sql.push_str(&format!(" AND {} = ?", column));
                            base_params.push(Box::new(s.clone()));
                        }
                        Value::Num(n) => {
                            base_sql.push_str(&format!(" AND {} = ?", column));
                            base_params.push(Box::new(*n as i64));
                        }
                        Value::List(_) => continue,
                    }
                }
            }
        }
        push_host_filter(&mut base_sql, &mut base_params, "host_id", &plan.host_ids)?;
        if let Some(since) = plan.since {
            base_sql.push_str(" AND timestamp >= ?");
            base_params.push(Box::new(since.min(i64::MAX as u64) as i64));
        }
        if let Some(until) = plan.until {
            base_sql.push_str(" AND timestamp <= ?");
            base_params.push(Box::new(until.min(i64::MAX as u64) as i64));
        }

        // Cursor-paginated scan. `event_id` is a TEXT PRIMARY KEY (a UUID
        // string); it is only ever used here as a stable tiebreaker to make
        // `(timestamp, event_id)` a total order, never as a meaningful
        // ordering of its own.
        let mut events = Vec::new();
        let mut cursor: Option<(i64, String)> = None;
        let mut scanned: i64 = 0;

        loop {
            let mut sql = base_sql.clone();
            let mut extra_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
            if let Some((last_ts, last_id)) = &cursor {
                sql.push_str(" AND (timestamp > ? OR (timestamp = ? AND event_id > ?))");
                extra_params.push(Box::new(*last_ts));
                extra_params.push(Box::new(*last_ts));
                extra_params.push(Box::new(last_id.clone()));
            }
            sql.push_str(" ORDER BY timestamp ASC, event_id ASC LIMIT ?");
            extra_params.push(Box::new(batch_size));

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let param_refs: Vec<&dyn rusqlite::ToSql> = base_params
                .iter()
                .chain(extra_params.iter())
                .map(|p| p.as_ref())
                .collect();
            let rows = stmt
                .query_map(param_refs.as_slice(), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| StorageError::Backend(e.to_string()))?;

            let mut batch_rows: i64 = 0;
            let mut last_seen: Option<(i64, String)> = None;
            let mut reached_limit = false;
            for row in rows {
                let (raw_json, timestamp, event_id) =
                    row.map_err(|e| StorageError::Backend(e.to_string()))?;
                batch_rows += 1;
                last_seen = Some((timestamp, event_id));
                let event: CanonicalEvent = serde_json::from_str(&raw_json)
                    .map_err(|e| StorageError::Serialize(e.to_string()))?;
                if plan.filter.as_ref().is_none_or(|f| eval_ast(&event, f)) {
                    events.push(event);
                    if events.len() >= effective_limit {
                        reached_limit = true;
                        break;
                    }
                }
            }

            if reached_limit {
                break;
            }
            scanned += batch_rows;
            // A short batch means the time range is exhausted: there is no
            // more data to scan, so no match can be hiding past it.
            if batch_rows < batch_size {
                break;
            }
            if scanned >= Self::MAX_SCAN_ROWS {
                break;
            }
            match last_seen {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        Ok(events)
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
            let category = serde_json::to_string(&event.category)
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
            let unit_name = event.service.as_ref().map(|s| s.unit_name.clone());
            let container_id = event.container.as_ref().map(|c| c.container_id.clone());
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO events (event_id, host_id, timestamp, event_type, category, process_key, parent_process_key, file_path, file_inode, file_device_id, network_src_ip, network_dst_ip, dns_domain, session_id, user_uid, unit_name, container_id, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                    params![
                        event.event_id.to_string(),
                        event.host_id.to_string(),
                        event.timestamp as i64,
                        event_type,
                        category,
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
                        unit_name,
                        container_id,
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
        if let Some(unit_name) = &plan.unit_name {
            sql.push_str(" AND unit_name = ?");
            sql_params.push(Box::new(unit_name.clone()));
        }
        if let Some(container_id) = &plan.container_id {
            sql.push_str(" AND container_id = ?");
            sql_params.push(Box::new(container_id.clone()));
        }
        push_host_filter(&mut sql, &mut sql_params, "host_id", &plan.host_ids)?;
        if let Some(since) = plan.since {
            sql.push_str(" AND timestamp >= ?");
            // Clamp rather than cast directly: a caller-supplied window can
            // legitimately be `u64::MAX`/near it (e.g. the Correlation
            // Engine's "effectively unbounded" test configuration), and
            // SQLite has no unsigned column type — an un-clamped cast would
            // silently wrap into a negative i64, making a wide-open time
            // range filter out every real (small, positive) timestamp.
            sql_params.push(Box::new(since.min(i64::MAX as u64) as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND timestamp <= ?");
            sql_params.push(Box::new(until.min(i64::MAX as u64) as i64));
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

    fn query_events(
        &self,
        plan: &osiris_query::EventQueryPlan,
    ) -> Result<Vec<CanonicalEvent>, StorageError> {
        self.query_events_batched(plan, Self::SCAN_BATCH_SIZE)
    }

    fn get_event(&self, event_id: Uuid) -> Result<Option<CanonicalEvent>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let raw_json: Option<String> = conn
            .query_row(
                "SELECT raw_json FROM events WHERE event_id = ?",
                rusqlite::params![event_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        match raw_json {
            Some(json) => {
                let event = serde_json::from_str(&json)
                    .map_err(|e| StorageError::Serialize(e.to_string()))?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
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
        push_host_filter(&mut sql, &mut sql_params, "a.host_id", &plan.host_ids)?;
        if let Some(since) = plan.since {
            sql.push_str(" AND a.timestamp >= ?");
            // Clamp rather than cast directly: a caller-supplied window can
            // legitimately be `u64::MAX`/near it (e.g. the Correlation
            // Engine's "effectively unbounded" test configuration), and
            // SQLite has no unsigned column type — an un-clamped cast would
            // silently wrap into a negative i64, making a wide-open time
            // range filter out every real (small, positive) timestamp.
            sql_params.push(Box::new(since.min(i64::MAX as u64) as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND a.timestamp <= ?");
            sql_params.push(Box::new(until.min(i64::MAX as u64) as i64));
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

    fn write_relationships(
        &self,
        edges: &[EntityRelationship],
    ) -> Result<WriteReport, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut report = WriteReport::default();
        for edge in edges {
            let relation = serde_json::to_string(&edge.relation)
                .map_err(|e| StorageError::Serialize(e.to_string()))?
                .trim_matches('"')
                .to_string();
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO relationships (from_key, to_key, relation, event_id, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    edge.from.storage_key(),
                    edge.to.storage_key(),
                    relation,
                    edge.event_id.to_string(),
                    edge.timestamp as i64,
                ],
            )
            .map_err(|e| StorageError::Backend(e.to_string()))?;
            report.written_count += inserted as u64;
        }
        tx.commit()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(report)
    }

    fn query_relationships(
        &self,
        plan: &RelationshipQueryPlan,
    ) -> Result<Vec<EntityRelationship>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let mut sql =
            "SELECT from_key, to_key, relation, event_id, timestamp FROM relationships WHERE 1=1"
                .to_string();
        let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if let Some(entity) = &plan.entity {
            sql.push_str(" AND (from_key = ? OR to_key = ?)");
            let key = entity.storage_key();
            sql_params.push(Box::new(key.clone()));
            sql_params.push(Box::new(key));
        }
        if let Some(ids) = &plan.host_ids {
            if ids.len() > MAX_TENANT_HOSTS {
                return Err(host_set_too_large());
            }
            if ids.is_empty() {
                sql.push_str(" AND 1=0");
            } else {
                sql.push_str(&format!(
                    " AND event_id IN (SELECT event_id FROM events WHERE host_id IN ({}))",
                    vec!["?"; ids.len()].join(",")
                ));
                for id in ids {
                    sql_params.push(Box::new(id.clone()));
                }
            }
        }
        if let Some(since) = plan.since {
            sql.push_str(" AND timestamp >= ?");
            // Clamp rather than cast directly: a caller-supplied window can
            // legitimately be `u64::MAX`/near it (e.g. the Correlation
            // Engine's "effectively unbounded" test configuration), and
            // SQLite has no unsigned column type — an un-clamped cast would
            // silently wrap into a negative i64, making a wide-open time
            // range filter out every real (small, positive) timestamp.
            sql_params.push(Box::new(since.min(i64::MAX as u64) as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND timestamp <= ?");
            sql_params.push(Box::new(until.min(i64::MAX as u64) as i64));
        }
        sql.push_str(" ORDER BY timestamp ASC LIMIT ?");
        let limit = if plan.limit == 0 { 1000 } else { plan.limit };
        sql_params.push(Box::new(limit as i64));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let mut edges = Vec::new();
        for row in rows {
            let (from_key, to_key, relation, event_id, timestamp) =
                row.map_err(|e| StorageError::Backend(e.to_string()))?;
            let from = EntityRef::parse_storage_key(&from_key)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let to = EntityRef::parse_storage_key(&to_key)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let relation: Relation = serde_json::from_value(serde_json::Value::String(relation))
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            edges.push(EntityRelationship {
                from,
                to,
                relation,
                event_id: event_id
                    .parse()
                    .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?,
                timestamp: timestamp as u64,
            });
        }
        Ok(edges)
    }

    fn write_risk_scores(&self, scores: &[RiskScoreRecord]) -> Result<WriteReport, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut report = WriteReport::default();
        for record in scores {
            let severity = serde_json::to_string(&record.severity)
                .map_err(|e| StorageError::Serialize(e.to_string()))?
                .trim_matches('"')
                .to_string();
            let related_events = serde_json::to_string(&record.related_events)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO risk_scores (event_id, process_key, host_id, timestamp, score, severity, related_events)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        record.event_id.to_string(),
                        record.process_key.map(|k| k.as_hex()),
                        record.host_id.to_string(),
                        record.timestamp as i64,
                        record.score as i64,
                        severity,
                        related_events,
                    ],
                )
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            if changed == 1 {
                report.written_count += 1;
                for reason in &record.reasons {
                    tx.execute(
                        "INSERT INTO risk_score_reasons (event_id, label, weight, evidence) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            record.event_id.to_string(),
                            reason.label,
                            reason.weight as i64,
                            reason.evidence.to_string(),
                        ],
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

    fn query_risk_scores(
        &self,
        plan: &RiskQueryPlan,
    ) -> Result<Vec<RiskScoreRecord>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let mut sql = "SELECT event_id, process_key, host_id, timestamp, score, severity, related_events FROM risk_scores WHERE 1=1".to_string();
        let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if let Some(process_key) = &plan.process_key {
            sql.push_str(" AND process_key = ?");
            sql_params.push(Box::new(process_key.as_hex()));
        }
        if let Some(event_id) = &plan.event_id {
            sql.push_str(" AND event_id = ?");
            sql_params.push(Box::new(event_id.to_string()));
        }
        push_host_filter(&mut sql, &mut sql_params, "host_id", &plan.host_ids)?;
        if let Some(since) = plan.since {
            sql.push_str(" AND timestamp >= ?");
            // Clamp rather than cast directly: a caller-supplied window can
            // legitimately be `u64::MAX`/near it (e.g. the Correlation
            // Engine's "effectively unbounded" test configuration), and
            // SQLite has no unsigned column type — an un-clamped cast would
            // silently wrap into a negative i64, making a wide-open time
            // range filter out every real (small, positive) timestamp.
            sql_params.push(Box::new(since.min(i64::MAX as u64) as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND timestamp <= ?");
            sql_params.push(Box::new(until.min(i64::MAX as u64) as i64));
        }
        sql.push_str(" ORDER BY timestamp ASC LIMIT ?");
        let limit = if plan.limit == 0 { 100 } else { plan.limit };
        sql_params.push(Box::new(limit as i64));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let mut records = Vec::new();
        for row in rows {
            let (event_id, process_key, host_id, timestamp, score, severity, related_events) =
                row.map_err(|e| StorageError::Backend(e.to_string()))?;
            let event_id: Uuid = event_id
                .parse()
                .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?;
            let severity: Severity = serde_json::from_value(serde_json::Value::String(severity))
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            let related_events: Vec<Uuid> = serde_json::from_str(&related_events)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;

            let mut reason_stmt = conn
                .prepare(
                    "SELECT label, weight, evidence FROM risk_score_reasons WHERE event_id = ?1",
                )
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let reason_rows = reason_stmt
                .query_map(params![event_id.to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut reasons = Vec::new();
            for reason_row in reason_rows {
                let (label, weight, evidence) =
                    reason_row.map_err(|e| StorageError::Backend(e.to_string()))?;
                reasons.push(WeightedReason {
                    label,
                    weight: weight as i16,
                    evidence: evidence
                        .parse()
                        .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?,
                });
            }

            records.push(RiskScoreRecord {
                event_id,
                process_key: match process_key {
                    Some(hex) => Some(
                        serde_json::from_value(serde_json::Value::String(hex))
                            .map_err(|e| StorageError::Serialize(e.to_string()))?,
                    ),
                    None => None,
                },
                host_id: host_id
                    .parse()
                    .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?,
                timestamp: timestamp as u64,
                score: score as u8,
                severity,
                reasons,
                related_events,
            });
        }
        Ok(records)
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
    fn query_events_with_no_filter_returns_everything_within_the_default_cap() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        for i in 0..3 {
            storage
                .write(&sample_event(100 + i, 1000 + i as u64))
                .unwrap();
        }
        let plan = osiris_query::EventQueryPlan::new();
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn query_events_pushes_down_an_exact_match_event_type_filter() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(1, 100)).unwrap();
        let plan =
            osiris_query::EventQueryPlan::with_filter("event_type = \"PROCESS_EXEC\"").unwrap();
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 1);
        let plan_miss =
            osiris_query::EventQueryPlan::with_filter("event_type = \"PROCESS_FORK\"").unwrap();
        assert_eq!(storage.query_events(&plan_miss).unwrap().len(), 0);
    }

    /// `query_events`'s residual `eval_ast` pass parses `raw_json` for
    /// *any* field, so a round-trip test through `query_events` alone would
    /// pass correctly even with no `category` column and no pushdown at
    /// all — it would prove nothing about this phase's actual change. This
    /// test instead inspects the stored SQL row directly, which can only
    /// pass once `batch_write` actually populates a real `category` column.
    #[test]
    fn batch_write_populates_the_category_column_directly() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut file_event = sample_event(1, 100);
        file_event.event_type = EventType::FileWrite;
        file_event.category = Category::File;
        storage.write(&file_event).unwrap();

        let conn = storage.conn.lock().unwrap();
        let category: String = conn
            .query_row(
                "SELECT category FROM events WHERE event_id = ?1",
                [file_event.event_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(category, "FILE");
    }

    /// Phase 7b-6: `category` gets its own indexed column (Global
    /// Constraint: same pushdown treatment as `event_type`), so a
    /// `category = "..."` filter must be an exact-match SQL pushdown, not a
    /// full-scan residual evaluation.
    #[test]
    fn query_events_pushes_down_an_exact_match_category_filter() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut file_event = sample_event(1, 100);
        file_event.event_type = EventType::FileWrite;
        file_event.category = Category::File;
        storage.write(&file_event).unwrap();

        let plan = osiris_query::EventQueryPlan::with_filter("category = \"FILE\"").unwrap();
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 1);

        let plan_miss =
            osiris_query::EventQueryPlan::with_filter("category = \"NETWORK\"").unwrap();
        assert_eq!(storage.query_events(&plan_miss).unwrap().len(), 0);
    }

    #[test]
    fn query_events_residual_filters_a_field_with_no_sql_pushdown() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(42, 100)).unwrap();
        storage.write(&sample_event(43, 200)).unwrap();
        // process.pid has no dedicated indexed column, so this exercises
        // the in-memory eval_ast fallback, not SQL pushdown.
        let plan = osiris_query::EventQueryPlan::with_filter("process.pid = 42").unwrap();
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.as_ref().unwrap().pid, 42);
    }

    #[test]
    fn query_events_supports_or_and_not_via_residual_evaluation() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(1, 100)).unwrap();
        storage.write(&sample_event(2, 200)).unwrap();
        let plan = osiris_query::EventQueryPlan::with_filter("process.pid = 1 OR process.pid = 2")
            .unwrap();
        assert_eq!(storage.query_events(&plan).unwrap().len(), 2);

        let plan_not = osiris_query::EventQueryPlan::with_filter("NOT process.pid = 1").unwrap();
        assert_eq!(storage.query_events(&plan_not).unwrap().len(), 1);
    }

    #[test]
    fn query_events_respects_since_and_until() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(1, 100)).unwrap();
        storage.write(&sample_event(2, 500)).unwrap();
        storage.write(&sample_event(3, 900)).unwrap();
        let mut plan = osiris_query::EventQueryPlan::new();
        plan.since = Some(200);
        plan.until = Some(600);
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp, 500);
    }

    #[test]
    fn query_events_clamps_to_the_effective_limit() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        for i in 0..5 {
            storage.write(&sample_event(i, i as u64)).unwrap();
        }
        let mut plan = osiris_query::EventQueryPlan::new();
        plan.limit = 2;
        assert_eq!(storage.query_events(&plan).unwrap().len(), 2);
    }

    #[test]
    fn query_events_paginates_past_the_first_scan_batch_to_find_a_residual_match() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        // 12 events, only the last of which matches. With a scan batch of 5
        // the match sits in the *third* batch, so a single fixed-LIMIT
        // prefetch of one batch would silently return nothing.
        const BATCH: i64 = 5;
        for i in 1..=12u32 {
            storage.write(&sample_event(i, i as u64)).unwrap();
        }
        const { assert!(12 > BATCH, "the match must lie past the first batch") };

        // `process.pid` has no pushdown column, so this is pure residual
        // evaluation over the paginated scan.
        let plan = osiris_query::EventQueryPlan::with_filter("process.pid = 12").unwrap();
        let events = storage.query_events_batched(&plan, BATCH).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.as_ref().unwrap().pid, 12);

        // Same story for an OR, which disables pushdown entirely.
        let or_plan =
            osiris_query::EventQueryPlan::with_filter("process.pid = 11 OR process.pid = 12")
                .unwrap();
        let or_events = storage.query_events_batched(&or_plan, BATCH).unwrap();
        assert_eq!(or_events.len(), 2);
    }

    #[test]
    fn query_events_pagination_cursor_does_not_skip_rows_sharing_a_timestamp() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        // Every row has the same timestamp, so the `event_id` tiebreaker is
        // the only thing keeping `(timestamp, event_id)` a total order.
        for i in 1..=12u32 {
            storage.write(&sample_event(i, 1000)).unwrap();
        }
        let plan = osiris_query::EventQueryPlan::new();
        let events = storage.query_events_batched(&plan, 5).unwrap();
        assert_eq!(events.len(), 12);
        let mut ids: Vec<_> = events.iter().map(|e| e.event_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 12, "pagination must not duplicate rows");
    }

    #[test]
    fn query_events_stops_paginating_once_the_effective_limit_is_reached() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        for i in 1..=12u32 {
            storage.write(&sample_event(i, i as u64)).unwrap();
        }
        let mut plan = osiris_query::EventQueryPlan::new();
        plan.limit = 7;
        assert_eq!(storage.query_events_batched(&plan, 5).unwrap().len(), 7);
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
        assert_eq!(
            storage.query_alerts(&AlertQueryPlan::new()).unwrap().len(),
            1
        );
    }

    #[test]
    fn writing_the_same_relationship_batch_twice_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let edge = EntityRelationship {
            from: EntityRef::Process {
                process_key: ProcessKey::new(Uuid::new_v4(), "b", 1, 1),
            },
            to: EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            },
            relation: Relation::ConnectedTo,
            event_id: Uuid::now_v7(),
            timestamp: 5000,
        };
        storage
            .write_relationships(std::slice::from_ref(&edge))
            .unwrap();
        storage
            .write_relationships(std::slice::from_ref(&edge))
            .unwrap();
        let rows = storage
            .query_relationships(&RelationshipQueryPlan::new())
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn opening_dedupes_pre_existing_duplicate_relationships() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.db");
        {
            let s = SqliteStorage::open(&path).unwrap();
            drop(s);
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("DROP INDEX idx_relationships_unique;")
                .unwrap();
            for _ in 0..3 {
                conn.execute(
                    "INSERT INTO relationships VALUES ('a','b','connected_to','e',1)",
                    [],
                )
                .unwrap();
            }
        }
        SqliteStorage::open(&path).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        SqliteStorage::open(&path).unwrap(); // idempotent re-open
    }

    #[test]
    fn write_and_query_relationships_round_trips_by_either_side_of_the_edge() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 300, 1);
        let event_id = Uuid::now_v7();
        let edge = EntityRelationship {
            from: EntityRef::Process { process_key },
            to: EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            },
            relation: Relation::ConnectedTo,
            event_id,
            timestamp: 5000,
        };

        let report = storage
            .write_relationships(std::slice::from_ref(&edge))
            .unwrap();
        assert_eq!(report.written_count, 1);

        // Found by the `from` side.
        let by_from = storage
            .query_relationships(&RelationshipQueryPlan {
                entity: Some(EntityRef::Process { process_key }),
                ..RelationshipQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_from.len(), 1);
        assert_eq!(by_from[0].event_id, event_id);
        assert_eq!(by_from[0].relation, Relation::ConnectedTo);

        // Found by the `to` side too — a caller need not know which side
        // an entity was recorded on.
        let by_to = storage
            .query_relationships(&RelationshipQueryPlan {
                entity: Some(EntityRef::Ip {
                    addr: "203.0.113.10".to_string(),
                }),
                ..RelationshipQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_to.len(), 1);
    }

    #[test]
    fn query_relationships_filters_by_time_range_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let entity = EntityRef::Domain {
            name: "evil.example".to_string(),
        };
        let edges: Vec<EntityRelationship> = (0..3)
            .map(|i| EntityRelationship {
                from: entity.clone(),
                to: EntityRef::Session {
                    session_id: i.to_string(),
                },
                relation: Relation::ResolvedTo,
                event_id: Uuid::now_v7(),
                timestamp: 1000 * (i + 1) as u64,
            })
            .collect();
        storage.write_relationships(&edges).unwrap();

        let by_time = storage
            .query_relationships(&RelationshipQueryPlan {
                entity: Some(entity.clone()),
                since: Some(1500),
                until: Some(2500),
                ..RelationshipQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_time.len(), 1);
        assert_eq!(by_time[0].timestamp, 2000);

        let limited = storage
            .query_relationships(&RelationshipQueryPlan {
                entity: Some(entity),
                limit: 1,
                ..RelationshipQueryPlan::new()
            })
            .unwrap();
        assert_eq!(limited.len(), 1);
    }

    fn sample_risk_record(process_key: Option<ProcessKey>, timestamp: u64) -> RiskScoreRecord {
        let event_id = Uuid::now_v7();
        RiskScoreRecord {
            event_id,
            process_key,
            host_id: Uuid::new_v4(),
            timestamp,
            score: 42,
            severity: Severity::High,
            reasons: vec![WeightedReason {
                label: "Rare executable path".to_string(),
                weight: 10,
                evidence: event_id,
            }],
            related_events: vec![event_id],
        }
    }

    #[test]
    fn write_and_query_risk_scores_round_trips_reasons_intact() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let process_key = ProcessKey::new(Uuid::new_v4(), "b", 300, 1);
        let record = sample_risk_record(Some(process_key), 5000);

        let report = storage
            .write_risk_scores(std::slice::from_ref(&record))
            .unwrap();
        assert_eq!(report.written_count, 1);

        let by_process = storage
            .query_risk_scores(&RiskQueryPlan {
                process_key: Some(process_key),
                ..RiskQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_process.len(), 1);
        assert_eq!(by_process[0].score, 42);
        assert_eq!(by_process[0].severity, Severity::High);
        assert_eq!(by_process[0].reasons.len(), 1);
        assert_eq!(by_process[0].reasons[0].label, "Rare executable path");
        assert_eq!(by_process[0].reasons[0].weight, 10);

        let by_event = storage
            .query_risk_scores(&RiskQueryPlan {
                event_id: Some(record.event_id),
                ..RiskQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_event.len(), 1);
        assert_eq!(by_event[0].event_id, record.event_id);
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
        assert_eq!(
            storage.query_alerts(&AlertQueryPlan::new()).unwrap().len(),
            1
        );
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

    fn systemd_event(unit_name: &str, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(500, timestamp);
        event.event_type = osiris_schema::EventType::ServiceStart;
        event.category = osiris_schema::Category::Systemd;
        event.service = Some(osiris_schema::ServiceRef {
            unit_name: unit_name.to_string(),
            unit_type: "service".to_string(),
            action: "start".to_string(),
        });
        event
    }

    #[test]
    fn query_filters_by_unit_name() {
        let storage = open_test_storage();
        let backdoor = systemd_event("backdoor.service", 1000);
        let mut backdoor_stop = systemd_event("backdoor.service", 2000);
        backdoor_stop.event_type = osiris_schema::EventType::ServiceStop;
        let sshd = systemd_event("sshd.service", 3000);
        // An event with no service at all must never match any unit_name
        // filter — NULL never equals a string in SQL, same discipline as
        // Phase 4a's uid-0-vs-NULL distinction.
        let unrelated = sample_event(900, 4000);
        storage
            .batch_write(&[
                backdoor.clone(),
                backdoor_stop.clone(),
                sshd.clone(),
                unrelated,
            ])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.unit_name = Some("backdoor.service".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 2);
        let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&backdoor.event_id));
        assert!(ids.contains(&backdoor_stop.event_id));
        assert!(!ids.contains(&sshd.event_id));
    }

    /// Non-destructive/idempotent migration proof, matching every prior
    /// phase's precedent exactly.
    #[test]
    fn migrates_a_pre_phase_4b_database_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let pre_phase_4b_event = sample_event(300, 1000);
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
                    network_src_ip TEXT,
                    network_dst_ip TEXT,
                    dns_domain TEXT,
                    session_id TEXT,
                    user_uid INTEGER,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    pre_phase_4b_event.event_id.to_string(),
                    pre_phase_4b_event.host_id.to_string(),
                    pre_phase_4b_event.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&pre_phase_4b_event).unwrap(),
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

        reopened
            .write(&systemd_event("backdoor.service", 2000))
            .unwrap();
        let mut plan = QueryPlan::new();
        plan.unit_name = Some("backdoor.service".to_string());
        assert_eq!(
            reopened.query(&plan).unwrap().len(),
            1,
            "the migrated unit_name column must exist and filter correctly"
        );

        let reopened_again = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(reopened_again.query(&QueryPlan::new()).unwrap().len(), 2);
        assert_eq!(reopened_again.query(&plan).unwrap().len(), 1);
    }

    fn container_event(
        container_id: &str,
        event_type: osiris_schema::EventType,
        timestamp: u64,
    ) -> CanonicalEvent {
        let mut event = sample_event(600, timestamp);
        event.event_type = event_type;
        event.category = osiris_schema::Category::Container;
        event.container = Some(osiris_schema::ContainerRef {
            container_id: container_id.to_string(),
            image: String::new(),
            runtime: "cgroup".to_string(),
            pod_ref: None,
        });
        event
    }

    #[test]
    fn query_filters_by_container_id() {
        let storage = open_test_storage();
        let id_a = "a".repeat(64);
        let id_b = "b".repeat(64);
        let create = container_event(&id_a, osiris_schema::EventType::ContainerCreate, 1000);
        let start = container_event(&id_a, osiris_schema::EventType::ContainerStart, 2000);
        let other = container_event(&id_b, osiris_schema::EventType::ContainerStart, 3000);
        // An event with no container at all must never match any
        // container_id filter — NULL never equals a string in SQL, same
        // discipline as `query_filters_by_unit_name`.
        let unrelated = sample_event(900, 4000);
        storage
            .batch_write(&[create.clone(), start.clone(), other.clone(), unrelated])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.container_id = Some(id_a);
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 2);
        let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&create.event_id));
        assert!(ids.contains(&start.event_id));
        assert!(!ids.contains(&other.event_id));
    }

    /// Non-destructive/idempotent migration proof, matching every prior
    /// phase's precedent exactly.
    #[test]
    fn migrates_a_pre_phase_5_database_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let pre_phase_5_event = sample_event(300, 1000);
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
                    network_src_ip TEXT,
                    network_dst_ip TEXT,
                    dns_domain TEXT,
                    session_id TEXT,
                    user_uid INTEGER,
                    unit_name TEXT,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    pre_phase_5_event.event_id.to_string(),
                    pre_phase_5_event.host_id.to_string(),
                    pre_phase_5_event.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&pre_phase_5_event).unwrap(),
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

        let id = "c".repeat(64);
        reopened
            .write(&container_event(
                &id,
                osiris_schema::EventType::ContainerStart,
                2000,
            ))
            .unwrap();
        let mut plan = QueryPlan::new();
        plan.container_id = Some(id.clone());
        assert_eq!(
            reopened.query(&plan).unwrap().len(),
            1,
            "the migrated container_id column must exist and filter correctly"
        );

        let reopened_again = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(reopened_again.query(&QueryPlan::new()).unwrap().len(), 2);
        assert_eq!(reopened_again.query(&plan).unwrap().len(), 1);
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
        assert_eq!(
            all_events.len(),
            1,
            "the pre-existing row must survive migration"
        );

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
        let other_session =
            identity_event(osiris_schema::EventType::SessionLogin, "4", 0, None, 4000);
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

    #[test]
    fn get_event_returns_the_matching_event_by_id() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let event = sample_event(1, 100);
        let event_id = event.event_id;
        storage.write(&event).unwrap();
        let found = storage.get_event(event_id).unwrap();
        assert_eq!(found.unwrap().event_id, event_id);
    }

    #[test]
    fn get_event_returns_none_for_an_unknown_id() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        assert!(storage.get_event(Uuid::new_v4()).unwrap().is_none());
    }

    /// Non-destructive/idempotent migration proof for Phase 7b-6's new
    /// `category` column — unlike every earlier phase's added columns
    /// (which read back NULL on pre-existing rows because the source data
    /// genuinely didn't exist yet), `category` is already present as a
    /// top-level field of every row's stored `raw_json` (`CanonicalEvent`
    /// has always carried `category`), so this migration must backfill
    /// existing rows via `json_extract`, not just add the column — and must
    /// do so correctly for more than one row/event shape, proving the
    /// single bulk `UPDATE ... json_extract(...)` isn't hardcoded to a
    /// single case.
    #[test]
    fn migrates_a_pre_phase_7b6_database_by_backfilling_category_from_raw_json() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let pre_migration_process_event = sample_event(300, 1000);
        let mut pre_migration_container_event = sample_event(301, 2000);
        // The raw SQL row below sets its `event_type` COLUMN to
        // "CONTAINER_START" directly, but `query_events`'s residual
        // `eval_ast` pass re-checks every match against the actual parsed
        // `raw_json` — so the serialized event itself must agree, or a
        // correct backfill would still (rightly) get filtered out here.
        pre_migration_container_event.event_type = EventType::ContainerStart;
        pre_migration_container_event.category = Category::Container;
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            // The full current schema, minus `category` — exactly what a
            // database created before this phase looks like.
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
                    session_id TEXT,
                    user_uid INTEGER,
                    unit_name TEXT,
                    container_id TEXT,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            for (event, event_type) in [
                (&pre_migration_process_event, "PROCESS_EXEC"),
                (&pre_migration_container_event, "CONTAINER_START"),
            ] {
                conn.execute(
                    "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        event.event_id.to_string(),
                        event.host_id.to_string(),
                        event.timestamp as i64,
                        event_type,
                        serde_json::to_string(event).unwrap(),
                    ],
                )
                .unwrap();
            }
        }

        let reopened = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(
            reopened.query(&QueryPlan::new()).unwrap().len(),
            2,
            "both pre-existing rows must survive migration"
        );

        // Direct column inspection, not a `query_events` round-trip: the
        // residual `eval_ast` pass would derive the right answer from
        // `raw_json` regardless of whether backfill ever ran, so only
        // reading the raw SQL column proves the backfill itself happened.
        let read_category = |conn: &rusqlite::Connection, event_id: Uuid| -> Option<String> {
            conn.query_row(
                "SELECT category FROM events WHERE event_id = ?1",
                [event_id.to_string()],
                |row| row.get(0),
            )
            .unwrap()
        };
        {
            let conn = reopened.conn.lock().unwrap();
            assert_eq!(
                read_category(&conn, pre_migration_process_event.event_id),
                Some("PROCESS".to_string()),
                "the PROCESS_EXEC row's category column must be backfilled to PROCESS"
            );
            assert_eq!(
                read_category(&conn, pre_migration_container_event.event_id),
                Some("CONTAINER".to_string()),
                "the CONTAINER_START row's category column must be backfilled to CONTAINER, \
                 proving the backfill loop handles more than one distinct event_type"
            );
        }

        // The backfilled column must also be usable for pushdown filtering.
        let process_plan =
            osiris_query::EventQueryPlan::with_filter("category = \"PROCESS\"").unwrap();
        assert_eq!(reopened.query_events(&process_plan).unwrap().len(), 1);
        let container_plan =
            osiris_query::EventQueryPlan::with_filter("category = \"CONTAINER\"").unwrap();
        assert_eq!(reopened.query_events(&container_plan).unwrap().len(), 1);

        // Idempotency: a second open must neither error nor re-run the
        // backfill destructively, and everything must still be filterable.
        let reopened_again = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(reopened_again.query(&QueryPlan::new()).unwrap().len(), 2);
        {
            let conn = reopened_again.conn.lock().unwrap();
            assert_eq!(
                read_category(&conn, pre_migration_process_event.event_id),
                Some("PROCESS".to_string())
            );
            assert_eq!(
                read_category(&conn, pre_migration_container_event.event_id),
                Some("CONTAINER".to_string())
            );
        }
        assert_eq!(reopened_again.query_events(&process_plan).unwrap().len(), 1);
        assert_eq!(
            reopened_again.query_events(&container_plan).unwrap().len(),
            1
        );
    }

    /// A row whose `event_type` COLUMN string no longer deserializes to a
    /// known `EventType` variant (a renamed/removed variant, hand-edited
    /// data, mild corruption) must not make the whole database permanently
    /// unopenable, and — because the backfill reads `category` straight out
    /// of `raw_json` via `json_extract` rather than re-deriving it from the
    /// `event_type` column — that row still gets correctly backfilled, since
    /// its `raw_json` carries a perfectly valid, already-computed `category`
    /// regardless of what the `event_type` column says.
    #[test]
    fn migration_backfills_from_raw_json_even_when_the_event_type_column_is_unrecognized() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let event = sample_event(300, 1000);
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
            // The event_type COLUMN is a string this binary's EventType enum
            // does not recognize, but raw_json (serialized from a real,
            // valid CanonicalEvent) still has a correct top-level `category`.
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    event.event_id.to_string(),
                    event.host_id.to_string(),
                    event.timestamp as i64,
                    "SOME_FUTURE_EVENT_TYPE_THIS_BINARY_DOES_NOT_KNOW",
                    serde_json::to_string(&event).unwrap(),
                ],
            )
            .unwrap();
        }

        // Must not error, and must not lose the row.
        let reopened = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(reopened.query(&QueryPlan::new()).unwrap().len(), 1);

        let conn = reopened.conn.lock().unwrap();
        let category: Option<String> = conn
            .query_row(
                "SELECT category FROM events WHERE event_id = ?1",
                [event.event_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            category,
            Some("PROCESS".to_string()),
            "category must be backfilled from raw_json's own field, independent of whether \
             the event_type column is recognized"
        );
    }

    /// If `raw_json` itself is missing a `category` field entirely (deeper
    /// corruption than an unrecognized `event_type`), `json_extract` returns
    /// SQL NULL and the row's `category` simply stays NULL — falling back to
    /// residual `eval_ast` evaluation, exactly like every earlier column's
    /// pre-existing-row behavior in this file — rather than erroring.
    #[test]
    fn migration_leaves_category_null_when_raw_json_has_no_category_field() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let event = sample_event(300, 1000);
        // A real, otherwise-valid event whose raw_json has had its
        // `category` key removed (`residual eval_ast` re-parses raw_json
        // for any field on every query anyway, so this doesn't need to stay
        // a parseable CanonicalEvent for query() to still see the row —
        // it only needs the object shape for json_extract's target key to
        // genuinely be absent).
        let mut raw_json = serde_json::to_value(&event).unwrap();
        raw_json.as_object_mut().unwrap().remove("category");

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
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    event.event_id.to_string(),
                    event.host_id.to_string(),
                    event.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&raw_json).unwrap(),
                ],
            )
            .unwrap();
        }

        // Must not error opening the database (json_extract on a missing
        // key returns SQL NULL, not an error).
        let reopened = SqliteStorage::open(&db_path).unwrap();

        let conn = reopened.conn.lock().unwrap();
        let category: Option<String> = conn
            .query_row(
                "SELECT category FROM events WHERE event_id = ?1",
                [event.event_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(category, None);
    }

    /// The backfill's `WHERE category IS NULL` guard is load-bearing: it's
    /// what makes the backfill idempotent and what stops it from ever
    /// clobbering a value written by a normal `batch_write`. This locks
    /// that guard in by pre-populating a row's category with a value that
    /// disagrees with what the (correct) backfill would compute from its
    /// `event_type`, and asserting it survives untouched.
    #[test]
    fn migration_never_overwrites_an_already_populated_category() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let event = sample_event(300, 1000);
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
                    category TEXT,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            // event_type says PROCESS_EXEC (category would backfill to
            // PROCESS), but category is already populated with a
            // deliberately different value — the guard must leave it alone.
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, category, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    event.event_id.to_string(),
                    event.host_id.to_string(),
                    event.timestamp as i64,
                    "PROCESS_EXEC",
                    "SOME_PREEXISTING_VALUE",
                    serde_json::to_string(&event).unwrap(),
                ],
            )
            .unwrap();
        }

        let reopened = SqliteStorage::open(&db_path).unwrap();
        let conn = reopened.conn.lock().unwrap();
        let category: Option<String> = conn
            .query_row(
                "SELECT category FROM events WHERE event_id = ?1",
                [event.event_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(category, Some("SOME_PREEXISTING_VALUE".to_string()));
    }

    /// The whole point of Phase 7b-6 is that `category = "..."` becomes an
    /// indexed SQL seek instead of a full-table scan. Every other assertion
    /// in this file only proves *results are correct* — which was already
    /// true before this phase via the residual `eval_ast` fallback, so it
    /// can't catch a regression that silently drops the pushdown mapping or
    /// the index. This inspects `EXPLAIN QUERY PLAN` directly to prove the
    /// index is actually used.
    #[test]
    fn query_events_category_filter_actually_uses_the_index() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let conn = storage.conn.lock().unwrap();
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT raw_json, timestamp, event_id FROM events \
                 WHERE 1=1 AND category = ? ORDER BY timestamp ASC, event_id ASC LIMIT 100",
                ["FILE"],
                |row| row.get(3),
            )
            .unwrap();
        assert!(
            plan.contains("idx_events_category_timestamp"),
            "expected the category filter to use idx_events_category_timestamp, got: {plan}"
        );
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

    fn event_on(host: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
        let mut e = sample_event(pid, timestamp);
        e.host_id = host;
        e.host.host_id = host;
        e
    }

    #[test]
    fn host_ids_restricts_query_and_query_events_and_empty_matches_nothing() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        storage
            .batch_write(&[
                event_on(a, 1, 100),
                event_on(b, 2, 200),
                event_on(a, 3, 300),
            ])
            .unwrap();

        let only_a = storage
            .query(&QueryPlan {
                host_ids: Some(vec![a.to_string()]),
                ..QueryPlan::new()
            })
            .unwrap();
        assert_eq!(only_a.len(), 2);
        assert!(only_a.iter().all(|e| e.host_id == a));

        let none = storage
            .query(&QueryPlan {
                host_ids: Some(vec![]),
                ..QueryPlan::new()
            })
            .unwrap();
        assert!(
            none.is_empty(),
            "an empty host set must match nothing, not everything"
        );

        let both = storage
            .query(&QueryPlan {
                host_ids: Some(vec![a.to_string(), b.to_string()]),
                ..QueryPlan::new()
            })
            .unwrap();
        assert_eq!(both.len(), 3);

        let ev_a = storage
            .query_events(&osiris_query::EventQueryPlan {
                host_ids: Some(vec![a.to_string()]),
                ..osiris_query::EventQueryPlan::new()
            })
            .unwrap();
        assert_eq!(ev_a.len(), 2);
        assert!(ev_a.iter().all(|e| e.host_id == a));
        let ev_none = storage
            .query_events(&osiris_query::EventQueryPlan {
                host_ids: Some(vec![]),
                ..osiris_query::EventQueryPlan::new()
            })
            .unwrap();
        assert!(ev_none.is_empty());
    }

    #[test]
    fn host_ids_combines_with_an_or_filter_that_defeats_other_pushdown() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        storage
            .batch_write(&[event_on(a, 1, 100), event_on(b, 2, 200)])
            .unwrap();
        let plan = osiris_query::EventQueryPlan {
            host_ids: Some(vec![a.to_string()]),
            ..osiris_query::EventQueryPlan::with_filter(
                "event_type = \"PROCESS_EXEC\" OR event_type = \"FILE_WRITE\"",
            )
            .unwrap()
        };
        let got = storage.query_events(&plan).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id, a);
    }

    #[test]
    fn host_ids_restricts_alerts_and_risk_scores() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let alert = |host: Uuid| {
            osiris_schema::Alert::new(
                "r1",
                1,
                "deadbeef",
                osiris_schema::Severity::High,
                10,
                host,
                vec!["x".to_string()],
                vec![Uuid::now_v7()],
            )
            .unwrap()
        };
        storage.write_alerts(&[alert(a), alert(b)]).unwrap();
        let got = storage
            .query_alerts(&AlertQueryPlan {
                host_ids: Some(vec![a.to_string()]),
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id(), a);
        assert!(storage
            .query_alerts(&AlertQueryPlan {
                host_ids: Some(vec![]),
                ..AlertQueryPlan::new()
            })
            .unwrap()
            .is_empty());

        let mut ra = sample_risk_record(None, 10);
        ra.host_id = a;
        let mut rb = sample_risk_record(None, 20);
        rb.host_id = b;
        storage.write_risk_scores(&[ra, rb]).unwrap();
        let got = storage
            .query_risk_scores(&RiskQueryPlan {
                host_ids: Some(vec![b.to_string()]),
                ..RiskQueryPlan::new()
            })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id, b);
    }

    #[test]
    fn host_ids_restricts_relationships_through_the_source_event() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let ev_a = event_on(a, 1, 100);
        let ev_b = event_on(b, 2, 200);
        storage.batch_write(&[ev_a.clone(), ev_b.clone()]).unwrap();
        let edge = |event: &CanonicalEvent| EntityRelationship {
            from: EntityRef::Ip {
                addr: "10.0.0.1".to_string(),
            },
            to: EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            },
            relation: Relation::ConnectedTo,
            event_id: event.event_id,
            timestamp: event.timestamp,
        };
        storage
            .write_relationships(&[edge(&ev_a), edge(&ev_b)])
            .unwrap();
        let got = storage
            .query_relationships(&RelationshipQueryPlan {
                host_ids: Some(vec![a.to_string()]),
                ..RelationshipQueryPlan::new()
            })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].event_id, ev_a.event_id);
        assert!(storage
            .query_relationships(&RelationshipQueryPlan {
                host_ids: Some(vec![]),
                ..RelationshipQueryPlan::new()
            })
            .unwrap()
            .is_empty());
    }

    fn too_many_hosts() -> Vec<String> {
        (0..30_001).map(|_| Uuid::new_v4().to_string()).collect()
    }

    fn assert_too_large<T: std::fmt::Debug>(result: Result<T, StorageError>) {
        match result {
            Err(StorageError::Backend(msg)) => {
                assert!(msg.contains("tenant host set too large"), "{msg}")
            }
            other => panic!("expected the host-set-too-large error, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_host_set_is_a_clear_error_on_the_events_path() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        assert_too_large(storage.query(&QueryPlan {
            host_ids: Some(too_many_hosts()),
            ..QueryPlan::new()
        }));
    }

    #[test]
    fn an_oversized_host_set_is_a_clear_error_on_the_relationships_path() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        assert_too_large(storage.query_relationships(&RelationshipQueryPlan {
            host_ids: Some(too_many_hosts()),
            ..RelationshipQueryPlan::new()
        }));
    }
}
