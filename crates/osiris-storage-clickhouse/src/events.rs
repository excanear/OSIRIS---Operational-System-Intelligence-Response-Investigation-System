//! The `events` table: write path, point lookups, delete, retention and
//! health counts (design §5.4–5.6).
//!
//! Column values are derived exactly as `SqliteStorage::batch_write` does.
//! ClickHouse has no unique constraint, so write-once on `event_id` is the
//! writer mutex plus an existence check before the insert.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_schema::{CanonicalEvent, FileIdentity};
use osiris_storage::{
    DeleteCriteria, RetentionPolicy, RetentionReport, StorageError, StorageHealth, WriteReport,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::transport::{ExternalTable, Transport};
use crate::ClickHouseStorage;

pub(crate) fn backend(msg: impl Into<String>) -> StorageError {
    StorageError::Backend(msg.into())
}

pub(crate) fn serde_str(value: Result<Value, serde_json::Error>) -> Result<String, StorageError> {
    let value = value.map_err(|e| StorageError::Serialize(e.to_string()))?;
    Ok(match value {
        Value::String(s) => s,
        other => other.to_string().trim_matches('"').to_string(),
    })
}

/// One `JSONEachRow` object for `event`.
fn event_row(event: &CanonicalEvent) -> Result<Value, StorageError> {
    let raw_json =
        serde_json::to_string(event).map_err(|e| StorageError::Serialize(e.to_string()))?;
    let file_identity = event.file.as_ref().and_then(FileIdentity::from_file_ref);
    Ok(json!({
        "event_id": event.event_id.to_string(),
        "host_id": event.host_id.to_string(),
        "timestamp": event.timestamp,
        "event_type": serde_str(serde_json::to_value(event.event_type))?,
        "category": serde_str(serde_json::to_value(event.category))?,
        "process_key": event.process.as_ref().map(|p| p.process_key.as_hex()),
        "parent_process_key": event.parent_process.as_ref().map(|p| p.process_key.as_hex()),
        "file_path": event.file.as_ref().map(|f| f.path.clone()),
        "file_inode": file_identity.map(|i| i.inode),
        "file_device_id": file_identity.map(|i| i.device_id),
        "network_src_ip": event.network.as_ref().map(|n| n.src_ip.clone()),
        "network_dst_ip": event.network.as_ref().map(|n| n.dst_ip.clone()),
        "dns_domain": event.dns.as_ref().map(|d| d.query.clone()),
        "session_id": event.session.as_ref().map(|s| s.session_id.clone()),
        "user_uid": event.user.as_ref().map(|u| u.uid),
        "unit_name": event.service.as_ref().map(|s| s.unit_name.clone()),
        "container_id": event.container.as_ref().map(|c| c.container_id.clone()),
        "raw_json": raw_json,
    }))
}

/// Runs a `FORMAT TSV` query that selects one id column filtered by the
/// external table `ids`, and returns the ids found.
pub(crate) fn id_set(
    transport: &Transport,
    sql: &str,
    ids: Vec<String>,
) -> Result<HashSet<String>, StorageError> {
    let text = transport.execute(
        sql,
        &[],
        &[ExternalTable {
            name: "ids",
            structure: "id String",
            rows: ids,
        }],
        None,
    )?;
    Ok(text.lines().map(str::to_string).collect())
}

fn parse_u64(text: &str, what: &str) -> Result<u64, StorageError> {
    text.trim().parse::<u64>().map_err(|e| {
        backend(format!(
            "clickhouse: unexpected {what} {:?}: {e}",
            text.trim()
        ))
    })
}

impl ClickHouseStorage {
    pub(crate) fn lock_writer(&self) -> Result<std::sync::MutexGuard<'_, ()>, StorageError> {
        self.writer.lock().map_err(|_| backend("poisoned lock"))
    }

    pub(crate) fn events_write(&self, event: &CanonicalEvent) -> Result<(), StorageError> {
        let report = self.events_batch_write(std::slice::from_ref(event))?;
        if report.failed_count > 0 {
            return Err(backend("write failed (duplicate event_id?)"));
        }
        Ok(())
    }

    pub(crate) fn events_batch_write(
        &self,
        events: &[CanonicalEvent],
    ) -> Result<WriteReport, StorageError> {
        let _guard = self.lock_writer()?;

        // 1. Dedupe inside the batch, first occurrence wins.
        let mut seen = HashSet::with_capacity(events.len());
        let unique: Vec<&CanonicalEvent> =
            events.iter().filter(|e| seen.insert(e.event_id)).collect();
        if unique.is_empty() {
            return Ok(WriteReport::default());
        }

        // 2. Which of those ids are already stored?
        let ids = ExternalTable {
            name: "ids",
            structure: "id String",
            rows: unique.iter().map(|e| e.event_id.to_string()).collect(),
        };
        let existing = self.transport.execute(
            "SELECT event_id FROM events WHERE event_id IN (SELECT id FROM ids) FORMAT TSV",
            &[],
            &[ids],
            None,
        )?;
        let existing: HashSet<&str> = existing.lines().collect();

        // 3. One insert for the new rows.
        let mut body = String::new();
        let mut inserted = 0usize;
        for event in unique {
            if existing.contains(event.event_id.to_string().as_str()) {
                continue;
            }
            body.push_str(&event_row(event)?.to_string());
            body.push('\n');
            inserted += 1;
        }
        if inserted > 0 {
            self.transport.execute(
                &format!("INSERT INTO {}.events FORMAT JSONEachRow", self.database),
                &[],
                &[],
                Some(body),
            )?;
        }

        Ok(WriteReport {
            written_count: inserted as u64,
            failed_count: (events.len() - inserted) as u64,
        })
    }

    pub(crate) fn events_owner(&self, event_id: Uuid) -> Result<Option<Uuid>, StorageError> {
        let text = self.transport.execute(
            "SELECT host_id FROM events WHERE event_id = {id:String} LIMIT 1 FORMAT TSV",
            &[("id", event_id.to_string())],
            &[],
            None,
        )?;
        match text.trim() {
            "" => Ok(None),
            host => Uuid::parse_str(host)
                .map(Some)
                .map_err(|e| backend(e.to_string())),
        }
    }

    pub(crate) fn events_get(
        &self,
        event_id: Uuid,
    ) -> Result<Option<CanonicalEvent>, StorageError> {
        let text = self.transport.execute(
            "SELECT raw_json FROM events WHERE event_id = {id:String} LIMIT 1 FORMAT JSONEachRow",
            &[("id", event_id.to_string())],
            &[],
            None,
        )?;
        let Some(line) = text.lines().next() else {
            return Ok(None);
        };
        let row: Value =
            serde_json::from_str(line).map_err(|e| StorageError::Serialize(e.to_string()))?;
        let raw = row["raw_json"]
            .as_str()
            .ok_or_else(|| backend("clickhouse: raw_json missing from row"))?;
        serde_json::from_str(raw)
            .map(Some)
            .map_err(|e| StorageError::Serialize(e.to_string()))
    }

    pub(crate) fn events_delete(&self, criteria: &DeleteCriteria) -> Result<u64, StorageError> {
        let _guard = self.lock_writer()?;
        let before = criteria.before_timestamp.to_string();
        // A lightweight DELETE does not report the rows it removed, so count
        // first; the writer mutex keeps the count consistent with this
        // process's own writes.
        let text = self.transport.execute(
            "SELECT count() FROM events WHERE timestamp < {before:UInt64} FORMAT TSV",
            &[("before", before.clone())],
            &[],
            None,
        )?;
        let count = parse_u64(&text, "delete count")?;
        if count > 0 {
            self.transport.execute(
                "DELETE FROM events WHERE timestamp < {before:UInt64} \
                 SETTINGS lightweight_deletes_sync = 2",
                &[("before", before)],
                &[],
                None,
            )?;
        }
        Ok(count)
    }

    pub(crate) fn events_retention_apply(
        &self,
        policy: &RetentionPolicy,
    ) -> Result<RetentionReport, StorageError> {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| backend(e.to_string()))?
            .as_nanos() as u64;
        let cutoff = now_ns.saturating_sub(policy.max_age_secs.saturating_mul(1_000_000_000));
        let deleted_count = self.events_delete(&DeleteCriteria {
            before_timestamp: cutoff,
        })?;
        Ok(RetentionReport { deleted_count })
    }

    pub(crate) fn events_health(&self) -> StorageHealth {
        let result = self
            .transport
            .execute(
                "SELECT count(), max(timestamp) FROM events FORMAT TSV",
                &[],
                &[],
                None,
            )
            .and_then(|text| {
                let mut cols = text.trim().split('\t');
                let count = parse_u64(cols.next().unwrap_or(""), "event count")?;
                let max = parse_u64(cols.next().unwrap_or(""), "last write")?;
                Ok((count, max))
            });
        match result {
            Ok((count, max)) => StorageHealth {
                healthy: true,
                event_count: count,
                last_write_at: (count > 0).then_some(max),
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
}
