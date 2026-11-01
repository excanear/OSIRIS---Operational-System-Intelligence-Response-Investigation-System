//! The `risk_scores` and `risk_score_reasons` tables (design §5.8).
//!
//! Dedupe is on `event_id` (a repeat is `failed`); reasons are written with
//! `seq` = their index and only for records actually written, then read
//! back for every returned record in one query ordered by `(event_id, seq)`.

use std::collections::{HashMap, HashSet};

use osiris_schema::{RiskScoreRecord, Severity, WeightedReason};
use osiris_storage::{RiskQueryPlan, StorageError, WriteReport};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::events::{backend, id_set, serde_str};
use crate::query::Filter;
use crate::transport::ExternalTable;
use crate::ClickHouseStorage;

/// A numeric column of a `JSONEachRow` row; 64-bit integers arrive quoted.
fn number(row: &Value, name: &str) -> Result<u64, StorageError> {
    match &row[name] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .ok_or_else(|| backend(format!("clickhouse: bad {name} in row")))
}

fn text<'a>(row: &'a Value, name: &str) -> Result<&'a str, StorageError> {
    row[name]
        .as_str()
        .ok_or_else(|| backend(format!("clickhouse: {name} missing from row")))
}

impl ClickHouseStorage {
    pub(crate) fn risk_write(
        &self,
        scores: &[RiskScoreRecord],
    ) -> Result<WriteReport, StorageError> {
        let _guard = self.lock_writer()?;

        // 1. Dedupe inside the batch, first occurrence wins.
        let mut seen = HashSet::with_capacity(scores.len());
        let unique: Vec<&RiskScoreRecord> =
            scores.iter().filter(|r| seen.insert(r.event_id)).collect();
        if unique.is_empty() {
            return Ok(WriteReport::default());
        }

        // 2. Which of those ids are already stored?
        let existing = id_set(
            &self.transport,
            "SELECT event_id FROM risk_scores WHERE event_id IN (SELECT id FROM ids) FORMAT TSV",
            unique.iter().map(|r| r.event_id.to_string()).collect(),
        )?;

        // 3. Reasons first, then the scores (see `alerts_write`).
        let mut score_rows = String::new();
        let mut reason_rows = String::new();
        let mut inserted = 0usize;
        for record in unique {
            let event_id = record.event_id.to_string();
            if existing.contains(&event_id) {
                continue;
            }
            let related_events = serde_json::to_string(&record.related_events)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            score_rows.push_str(
                &json!({
                    "event_id": event_id,
                    "process_key": record.process_key.map(|k| k.as_hex()),
                    "host_id": record.host_id.to_string(),
                    "timestamp": record.timestamp,
                    "score": record.score,
                    "severity": serde_str(serde_json::to_value(record.severity))?,
                    "related_events": related_events,
                })
                .to_string(),
            );
            score_rows.push('\n');
            for (seq, reason) in record.reasons.iter().enumerate() {
                reason_rows.push_str(
                    &json!({
                        "event_id": event_id,
                        "seq": seq,
                        "label": reason.label,
                        "weight": reason.weight,
                        "evidence": reason.evidence.to_string(),
                    })
                    .to_string(),
                );
                reason_rows.push('\n');
            }
            inserted += 1;
        }
        if inserted > 0 {
            if !reason_rows.is_empty() {
                self.transport.execute(
                    &format!(
                        "INSERT INTO {}.risk_score_reasons FORMAT JSONEachRow",
                        self.database
                    ),
                    &[],
                    &[],
                    Some(reason_rows),
                )?;
            }
            self.transport.execute(
                &format!(
                    "INSERT INTO {}.risk_scores FORMAT JSONEachRow",
                    self.database
                ),
                &[],
                &[],
                Some(score_rows),
            )?;
        }
        Ok(WriteReport {
            written_count: inserted as u64,
            failed_count: (scores.len() - inserted) as u64,
        })
    }

    pub(crate) fn risk_query(
        &self,
        plan: &RiskQueryPlan,
    ) -> Result<Vec<RiskScoreRecord>, StorageError> {
        let mut f = Filter::new();
        if let Some(process_key) = &plan.process_key {
            f.eq_str("process_key", &process_key.as_hex());
        }
        if let Some(event_id) = &plan.event_id {
            f.eq_str("event_id", &event_id.to_string());
        }
        if !f.host_ids(&plan.host_ids)? {
            return Ok(Vec::new());
        }
        f.window(plan.since, plan.until);
        let limit = if plan.limit == 0 { 100 } else { plan.limit };
        let l = f.bind("UInt64", limit.to_string());
        let body = self.select_from(
            "risk_scores",
            "event_id, process_key, host_id, timestamp, score, severity, related_events",
            &f,
            &format!("ORDER BY timestamp ASC, event_id ASC LIMIT {l}"),
        )?;

        let hosts: Option<HashSet<&str>> = plan
            .host_ids
            .as_ref()
            .map(|ids| ids.iter().map(String::as_str).collect());
        let mut records = Vec::new();
        for line in body.lines() {
            let row: Value =
                serde_json::from_str(line).map_err(|e| StorageError::Serialize(e.to_string()))?;
            let host_id = text(&row, "host_id")?;
            if !hosts.as_ref().is_none_or(|h| h.contains(host_id)) {
                continue;
            }
            let severity: Severity =
                serde_json::from_value(Value::String(text(&row, "severity")?.to_string()))
                    .map_err(|e| StorageError::Serialize(e.to_string()))?;
            let process_key = match row["process_key"].as_str() {
                Some(hex) => Some(
                    serde_json::from_value(Value::String(hex.to_string()))
                        .map_err(|e| StorageError::Serialize(e.to_string()))?,
                ),
                None => None,
            };
            let related_events: Vec<Uuid> = serde_json::from_str(text(&row, "related_events")?)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            records.push(RiskScoreRecord {
                event_id: text(&row, "event_id")?
                    .parse()
                    .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?,
                process_key,
                host_id: host_id
                    .parse()
                    .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?,
                timestamp: number(&row, "timestamp")?,
                score: u8::try_from(number(&row, "score")?)
                    .map_err(|e| backend(format!("clickhouse: bad score: {e}")))?,
                severity,
                reasons: Vec::new(),
                related_events,
            });
        }
        if records.is_empty() {
            return Ok(records);
        }

        // Every returned record's reasons in one query, in written order.
        let ids: Vec<String> = records.iter().map(|r| r.event_id.to_string()).collect();
        let reasons = self.transport.execute(
            "SELECT event_id, label, weight, evidence FROM risk_score_reasons \
             WHERE event_id IN (SELECT id FROM ids) ORDER BY event_id, seq FORMAT JSONEachRow",
            &[],
            &[ExternalTable {
                name: "ids",
                structure: "id String",
                rows: ids,
            }],
            None,
        )?;
        let mut by_event: HashMap<String, Vec<WeightedReason>> = HashMap::new();
        for line in reasons.lines() {
            let row: Value =
                serde_json::from_str(line).map_err(|e| StorageError::Serialize(e.to_string()))?;
            let weight = row["weight"]
                .as_i64()
                .and_then(|w| i16::try_from(w).ok())
                .ok_or_else(|| backend("clickhouse: bad weight in row"))?;
            by_event
                .entry(text(&row, "event_id")?.to_string())
                .or_default()
                .push(WeightedReason {
                    label: text(&row, "label")?.to_string(),
                    weight,
                    evidence: text(&row, "evidence")?
                        .parse()
                        .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?,
                });
        }
        for record in &mut records {
            if let Some(found) = by_event.remove(&record.event_id.to_string()) {
                record.reasons = found;
            }
        }
        Ok(records)
    }
}
