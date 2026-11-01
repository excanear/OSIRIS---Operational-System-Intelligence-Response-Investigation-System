//! The `alerts` and `alert_evidence` tables (design §5.8).
//!
//! Semantics are `SqliteStorage`'s: an alert id is write-once (a repeat is
//! a `failed` row), evidence rows exist only for alerts actually written,
//! and an alert citing several requested events comes back once.

use std::collections::HashSet;

use osiris_schema::Alert;
use osiris_storage::{AlertQueryPlan, StorageError, WriteReport};
use serde_json::json;

use crate::events::{backend, id_set};
use crate::query::Filter;
use crate::ClickHouseStorage;

impl ClickHouseStorage {
    pub(crate) fn alerts_write(&self, alerts: &[Alert]) -> Result<WriteReport, StorageError> {
        let _guard = self.lock_writer()?;

        // 1. Dedupe inside the batch, first occurrence wins.
        let mut seen = HashSet::with_capacity(alerts.len());
        let unique: Vec<&Alert> = alerts
            .iter()
            .filter(|a| seen.insert(a.alert_id()))
            .collect();
        if unique.is_empty() {
            return Ok(WriteReport::default());
        }

        // 2. Which of those ids are already stored?
        let existing = id_set(
            &self.transport,
            "SELECT alert_id FROM alerts WHERE alert_id IN (SELECT id FROM ids) FORMAT TSV",
            unique.iter().map(|a| a.alert_id().to_string()).collect(),
        )?;

        // 3. Evidence first, then the alerts: a failure between the two
        // inserts leaves only invisible evidence rows, and a retry still
        // sees the alert as new.
        let mut alert_rows = String::new();
        let mut evidence_rows = String::new();
        let mut inserted = 0usize;
        for alert in unique {
            let alert_id = alert.alert_id().to_string();
            if existing.contains(&alert_id) {
                continue;
            }
            let raw_json =
                serde_json::to_string(alert).map_err(|e| StorageError::Serialize(e.to_string()))?;
            alert_rows.push_str(
                &json!({
                    "alert_id": alert_id,
                    "rule_id": alert.rule_id(),
                    "rule_version": alert.rule_version(),
                    "timestamp": alert.timestamp(),
                    "host_id": alert.host_id().to_string(),
                    "raw_json": raw_json,
                })
                .to_string(),
            );
            alert_rows.push('\n');
            let mut cited = HashSet::new();
            for event_id in alert.evidence() {
                if cited.insert(*event_id) {
                    evidence_rows.push_str(
                        &json!({"alert_id": alert_id, "event_id": event_id.to_string()})
                            .to_string(),
                    );
                    evidence_rows.push('\n');
                }
            }
            inserted += 1;
        }
        if inserted > 0 {
            if !evidence_rows.is_empty() {
                self.transport.execute(
                    &format!(
                        "INSERT INTO {}.alert_evidence FORMAT JSONEachRow",
                        self.database
                    ),
                    &[],
                    &[],
                    Some(evidence_rows),
                )?;
            }
            self.transport.execute(
                &format!("INSERT INTO {}.alerts FORMAT JSONEachRow", self.database),
                &[],
                &[],
                Some(alert_rows),
            )?;
        }
        Ok(WriteReport {
            written_count: inserted as u64,
            failed_count: (alerts.len() - inserted) as u64,
        })
    }

    pub(crate) fn alerts_query(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError> {
        let mut f = Filter::new();
        if !plan.evidence_event_ids.is_empty() {
            f.add_table(
                "evidence",
                "e String",
                plan.evidence_event_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect(),
            );
            // A subquery, not a join: each alert comes back once however
            // many of the requested events it cites.
            f.and(
                "alert_id IN (SELECT alert_id FROM alert_evidence \
                 WHERE event_id IN (SELECT e FROM evidence))",
            );
        }
        if let Some(rule_id) = &plan.rule_id {
            f.eq_str("rule_id", rule_id);
        }
        if !f.host_ids(&plan.host_ids)? {
            return Ok(Vec::new());
        }
        f.window(plan.since, plan.until);
        let limit = if plan.limit == 0 { 100 } else { plan.limit };
        let l = f.bind("UInt64", limit.to_string());
        let text = self.select_from(
            "alerts",
            "raw_json",
            &f,
            &format!("ORDER BY timestamp ASC, alert_id ASC LIMIT {l}"),
        )?;

        let hosts: Option<HashSet<&str>> = plan
            .host_ids
            .as_ref()
            .map(|ids| ids.iter().map(String::as_str).collect());
        let mut alerts = Vec::new();
        for line in text.lines() {
            let row: serde_json::Value =
                serde_json::from_str(line).map_err(|e| StorageError::Serialize(e.to_string()))?;
            let raw = row["raw_json"]
                .as_str()
                .ok_or_else(|| backend("clickhouse: raw_json missing from row"))?;
            let alert: Alert =
                serde_json::from_str(raw).map_err(|e| StorageError::Serialize(e.to_string()))?;
            if hosts
                .as_ref()
                .is_none_or(|h| h.contains(alert.host_id().to_string().as_str()))
            {
                alerts.push(alert);
            }
        }
        Ok(alerts)
    }
}
