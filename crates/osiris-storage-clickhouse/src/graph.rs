//! The `relationships` table (design §5.8).
//!
//! The unique key is `(from_key, to_key, relation, event_id)`. A repeat of
//! an edge is skipped silently: `written_count` counts inserted edges and
//! `failed_count` stays 0, exactly as `SqliteStorage` does.

use std::collections::HashSet;

use osiris_schema::{EntityRef, EntityRelationship, Relation};
use osiris_storage::{RelationshipQueryPlan, StorageError, WriteReport};
use serde_json::{json, Value};

use crate::events::{backend, serde_str};
use crate::query::Filter;
use crate::transport::ExternalTable;
use crate::ClickHouseStorage;

type EdgeKey = (String, String, String, String);

fn edge_key(edge: &EntityRelationship) -> Result<EdgeKey, StorageError> {
    Ok((
        edge.from.storage_key(),
        edge.to.storage_key(),
        serde_str(serde_json::to_value(edge.relation))?,
        edge.event_id.to_string(),
    ))
}

fn str_col<'a>(row: &'a Value, name: &str) -> Result<&'a str, StorageError> {
    row[name]
        .as_str()
        .ok_or_else(|| backend(format!("clickhouse: {name} missing from row")))
}

impl ClickHouseStorage {
    pub(crate) fn relationships_write(
        &self,
        edges: &[EntityRelationship],
    ) -> Result<WriteReport, StorageError> {
        let _guard = self.lock_writer()?;

        // 1. Dedupe inside the batch, first occurrence wins.
        let mut seen: HashSet<EdgeKey> = HashSet::with_capacity(edges.len());
        let mut unique: Vec<(EdgeKey, &EntityRelationship)> = Vec::new();
        for edge in edges {
            let key = edge_key(edge)?;
            if seen.insert(key.clone()) {
                unique.push((key, edge));
            }
        }
        if unique.is_empty() {
            return Ok(WriteReport::default());
        }

        // 2. Stored edges that share an event id with the batch; the key
        // is compared in full here, not in SQL.
        let event_ids: Vec<String> = unique
            .iter()
            .map(|(k, _)| k.3.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let text = self.transport.execute(
            "SELECT from_key, to_key, relation, event_id FROM relationships \
             WHERE event_id IN (SELECT id FROM ids) FORMAT JSONEachRow",
            &[],
            &[ExternalTable {
                name: "ids",
                structure: "id String",
                rows: event_ids,
            }],
            None,
        )?;
        let mut existing: HashSet<EdgeKey> = HashSet::new();
        for line in text.lines() {
            let row: Value =
                serde_json::from_str(line).map_err(|e| StorageError::Serialize(e.to_string()))?;
            existing.insert((
                str_col(&row, "from_key")?.to_string(),
                str_col(&row, "to_key")?.to_string(),
                str_col(&row, "relation")?.to_string(),
                str_col(&row, "event_id")?.to_string(),
            ));
        }

        // 3. One insert for the new edges.
        let mut body = String::new();
        let mut inserted = 0u64;
        for (key, edge) in unique {
            if existing.contains(&key) {
                continue;
            }
            body.push_str(
                &json!({
                    "from_key": key.0,
                    "to_key": key.1,
                    "relation": key.2,
                    "event_id": key.3,
                    "timestamp": edge.timestamp,
                })
                .to_string(),
            );
            body.push('\n');
            inserted += 1;
        }
        if inserted > 0 {
            self.transport.execute(
                &format!(
                    "INSERT INTO {}.relationships FORMAT JSONEachRow",
                    self.database
                ),
                &[],
                &[],
                Some(body),
            )?;
        }
        Ok(WriteReport {
            written_count: inserted,
            failed_count: 0,
        })
    }

    pub(crate) fn relationships_query(
        &self,
        plan: &RelationshipQueryPlan,
    ) -> Result<Vec<EntityRelationship>, StorageError> {
        let mut f = Filter::new();
        if let Some(entity) = &plan.entity {
            let p = f.bind("String", entity.storage_key());
            f.and(&format!("(from_key = {p} OR to_key = {p})"));
        }
        // The tenant of an edge is the tenant of the event that produced it.
        if !f.host_ids_on(
            "event_id IN (SELECT event_id FROM events WHERE host_id IN (SELECT h FROM hosts))",
            &plan.host_ids,
        )? {
            return Ok(Vec::new());
        }
        f.window(plan.since, plan.until);
        let limit = if plan.limit == 0 { 1000 } else { plan.limit };
        let l = f.bind("UInt64", limit.to_string());
        let text = self.select_from(
            "relationships",
            "from_key, to_key, relation, event_id, timestamp",
            &f,
            &format!(
                "ORDER BY timestamp ASC, from_key ASC, to_key ASC, relation ASC, event_id ASC \
                 LIMIT {l}"
            ),
        )?;

        let mut edges = Vec::new();
        for line in text.lines() {
            let row: Value =
                serde_json::from_str(line).map_err(|e| StorageError::Serialize(e.to_string()))?;
            let from = EntityRef::parse_storage_key(str_col(&row, "from_key")?)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let to = EntityRef::parse_storage_key(str_col(&row, "to_key")?)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let relation: Relation =
                serde_json::from_value(Value::String(str_col(&row, "relation")?.to_string()))
                    .map_err(|e| StorageError::Serialize(e.to_string()))?;
            let event_id = str_col(&row, "event_id")?
                .parse()
                .map_err(|e: uuid::Error| StorageError::Backend(e.to_string()))?;
            // 64-bit integers are quoted by default in JSONEachRow.
            let timestamp = match &row["timestamp"] {
                Value::Number(n) => n.as_u64(),
                Value::String(s) => s.parse().ok(),
                _ => None,
            }
            .ok_or_else(|| backend("clickhouse: bad timestamp in row"))?;
            edges.push(EntityRelationship {
                from,
                to,
                relation,
                event_id,
                timestamp,
            });
        }
        Ok(edges)
    }
}
