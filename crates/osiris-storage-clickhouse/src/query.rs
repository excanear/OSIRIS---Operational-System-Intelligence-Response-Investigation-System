//! `query` and `query_events` over the `events` table (design §5.7).
//!
//! The algorithm is `SqliteStorage`'s: push a pure AND-chain of `Op::Eq`
//! leaves on the nine mapped columns into SQL, scan with a
//! `(timestamp, event_id)` cursor, and re-check **every** decoded row with
//! `osiris_query::eval_ast`, so a pushdown shortfall can only over-fetch.
//! Values never enter SQL text: scalars are typed parameters and the tenant
//! host list is an external table.

use std::collections::HashSet;

use osiris_query::{eval_ast, Ast, EventQueryPlan, Op, Value};
use osiris_schema::CanonicalEvent;
use osiris_storage::{QueryPlan, StorageError, MAX_TENANT_HOSTS};
use serde_json::Value as Json;

use crate::events::{backend, serde_str};
use crate::transport::ExternalTable;
use crate::ClickHouseStorage;

/// Rows pulled back per round-trip of the `query_events` scan.
pub(crate) const SCAN_BATCH_SIZE: u64 = 20_000;

/// Worst-case rows one `query_events` call scans when pushdown covers
/// little of the filter.
pub(crate) const MAX_SCAN_ROWS: u64 = 1_000_000;

pub(crate) fn host_set_too_large() -> StorageError {
    backend(format!(
        "tenant host set too large (limit {MAX_TENANT_HOSTS})"
    ))
}

/// A WHERE clause under construction: typed parameter placeholders plus
/// the tenant host table.
#[derive(Default)]
pub(crate) struct Filter {
    pub(crate) sql: String,
    params: Vec<(String, String)>,
    tables: Vec<ExternalTable<'static>>,
}

impl Filter {
    pub(crate) fn new() -> Self {
        Self {
            sql: "WHERE 1=1".to_string(),
            ..Self::default()
        }
    }

    /// Attaches a one-column external table.
    pub(crate) fn add_table(
        &mut self,
        name: &'static str,
        structure: &'static str,
        rows: Vec<String>,
    ) {
        self.tables.push(ExternalTable {
            name,
            structure,
            rows,
        });
    }

    /// Registers a parameter and returns its `{pN:Type}` placeholder.
    pub(crate) fn bind(&mut self, ty: &str, value: String) -> String {
        let name = format!("p{}", self.params.len());
        let placeholder = format!("{{{name}:{ty}}}");
        self.params.push((name, value));
        placeholder
    }

    pub(crate) fn and(&mut self, condition: &str) {
        self.sql.push_str(" AND ");
        self.sql.push_str(condition);
    }

    pub(crate) fn eq_str(&mut self, column: &str, value: &str) {
        let p = self.bind("String", value.to_string());
        self.and(&format!("{column} = {p}"));
    }

    fn eq_u64(&mut self, column: &str, ty: &str, value: u64) {
        let p = self.bind(ty, value.to_string());
        self.and(&format!("{column} = {p}"));
    }

    /// Tenant restriction. `Ok(false)` means the set is empty and the
    /// query must return nothing without any I/O.
    pub(crate) fn host_ids(
        &mut self,
        host_ids: &Option<Vec<String>>,
    ) -> Result<bool, StorageError> {
        self.host_ids_on("host_id IN (SELECT h FROM hosts)", host_ids)
    }

    /// Like [`Filter::host_ids`], with the membership test spelled by
    /// `condition` (it reads the external table `hosts`).
    pub(crate) fn host_ids_on(
        &mut self,
        condition: &str,
        host_ids: &Option<Vec<String>>,
    ) -> Result<bool, StorageError> {
        let Some(ids) = host_ids else { return Ok(true) };
        if ids.len() > MAX_TENANT_HOSTS {
            return Err(host_set_too_large());
        }
        if ids.is_empty() {
            return Ok(false);
        }
        self.and(condition);
        self.add_table("hosts", "h String", ids.clone());
        Ok(true)
    }

    pub(crate) fn window(&mut self, since: Option<u64>, until: Option<u64>) {
        if let Some(since) = since {
            let p = self.bind("UInt64", since.to_string());
            self.and(&format!("timestamp >= {p}"));
        }
        if let Some(until) = until {
            let p = self.bind("UInt64", until.to_string());
            self.and(&format!("timestamp <= {p}"));
        }
    }
}

/// `Some(leaves)` when `ast` is a pure AND-chain of comparison leaves.
fn conjunction_leaves(ast: &Ast) -> Option<Vec<(&str, Op, &Value)>> {
    match ast {
        Ast::Compare { field, op, value } => Some(vec![(field.as_str(), *op, value)]),
        Ast::And(l, r) => {
            let mut left = conjunction_leaves(l)?;
            left.extend(conjunction_leaves(r)?);
            Some(left)
        }
        Ast::Or(_, _) | Ast::Not(_) => None,
    }
}

/// An integral, in-range number as a `u32` value, else `None` (no pushdown).
fn exact_u32(n: f64) -> Option<u64> {
    (n.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&n)).then_some(n as u64)
}

/// Decodes the `raw_json` column of one `JSONEachRow` line.
fn decode_row(line: &str) -> Result<(CanonicalEvent, Json), StorageError> {
    let row: Json =
        serde_json::from_str(line).map_err(|e| StorageError::Serialize(e.to_string()))?;
    let raw = row["raw_json"]
        .as_str()
        .ok_or_else(|| backend("clickhouse: raw_json missing from row"))?;
    let event = serde_json::from_str(raw).map_err(|e| StorageError::Serialize(e.to_string()))?;
    Ok((event, row))
}

fn in_hosts(event: &CanonicalEvent, hosts: &Option<HashSet<&str>>) -> bool {
    hosts
        .as_ref()
        .is_none_or(|h| h.contains(event.host_id.to_string().as_str()))
}

impl ClickHouseStorage {
    /// Runs `SELECT <select> FROM <table> <filter> <tail> FORMAT JSONEachRow`.
    /// `table` is a fixed table name, never caller input.
    pub(crate) fn select_from(
        &self,
        table: &str,
        select: &str,
        filter: &Filter,
        tail: &str,
    ) -> Result<String, StorageError> {
        let sql = format!(
            "SELECT {select} FROM {table} {} {tail} FORMAT JSONEachRow",
            filter.sql
        );
        let params: Vec<(&str, String)> = filter
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let tables: Vec<ExternalTable> = filter
            .tables
            .iter()
            .map(|t| ExternalTable {
                name: t.name,
                structure: t.structure,
                rows: t.rows.clone(),
            })
            .collect();
        self.transport.execute(&sql, &params, &tables, None)
    }

    fn select_events(
        &self,
        select: &str,
        filter: &Filter,
        tail: &str,
    ) -> Result<String, StorageError> {
        self.select_from("events", select, filter, tail)
    }

    pub(crate) fn events_query(
        &self,
        plan: &QueryPlan,
    ) -> Result<Vec<CanonicalEvent>, StorageError> {
        let mut f = Filter::new();
        if let Some(event_type) = &plan.event_type {
            f.eq_str("event_type", &serde_str(serde_json::to_value(event_type))?);
        }
        if let Some(process_key) = &plan.process_key {
            f.eq_str("process_key", &process_key.as_hex());
        }
        if let Some(file_path) = &plan.file_path {
            f.eq_str("file_path", file_path);
        }
        if let Some(identity) = &plan.file_identity {
            f.eq_u64("file_inode", "UInt64", identity.inode);
            f.eq_u64("file_device_id", "UInt64", identity.device_id);
        }
        if let Some(addr) = &plan.network_addr {
            let a = f.bind("String", addr.clone());
            f.and(&format!("(network_src_ip = {a} OR network_dst_ip = {a})"));
        }
        if let Some(domain) = &plan.dns_domain {
            f.eq_str("dns_domain", domain);
        }
        if let Some(session_id) = &plan.session_id {
            f.eq_str("session_id", session_id);
        }
        if let Some(uid) = plan.user_uid {
            f.eq_u64("user_uid", "UInt32", u64::from(uid));
        }
        if let Some(unit_name) = &plan.unit_name {
            f.eq_str("unit_name", unit_name);
        }
        if let Some(container_id) = &plan.container_id {
            f.eq_str("container_id", container_id);
        }
        if !f.host_ids(&plan.host_ids)? {
            return Ok(Vec::new());
        }
        f.window(plan.since, plan.until);
        let limit = if plan.limit == 0 { 100 } else { plan.limit };
        let l = f.bind("UInt64", limit.to_string());
        let text = self.select_events(
            "raw_json",
            &f,
            &format!("ORDER BY timestamp ASC, event_id ASC LIMIT {l}"),
        )?;

        let hosts: Option<HashSet<&str>> = plan
            .host_ids
            .as_ref()
            .map(|ids| ids.iter().map(String::as_str).collect());
        let mut events = Vec::new();
        for line in text.lines() {
            let (event, _) = decode_row(line)?;
            if in_hosts(&event, &hosts) {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub(crate) fn events_query_events(
        &self,
        plan: &EventQueryPlan,
    ) -> Result<Vec<CanonicalEvent>, StorageError> {
        self.query_events_batched(plan, SCAN_BATCH_SIZE)
    }

    /// `query_events` with an explicit scan batch size, so tests can prove
    /// the cursor pagination without writing millions of rows.
    pub(crate) fn query_events_batched(
        &self,
        plan: &EventQueryPlan,
        batch_size: u64,
    ) -> Result<Vec<CanonicalEvent>, StorageError> {
        let effective_limit = plan.effective_limit();
        if effective_limit == 0 {
            return Ok(Vec::new());
        }

        let mut f = Filter::new();
        if let Some(leaves) = plan.filter.as_ref().and_then(conjunction_leaves) {
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
                // A leaf whose value type does not fit the column is left to
                // the residual pass: pushdown may only ever over-fetch.
                match (column, value) {
                    ("user_uid", Value::Num(n)) => {
                        if let Some(uid) = exact_u32(*n) {
                            f.eq_u64("user_uid", "UInt32", uid);
                        }
                    }
                    ("user_uid", _) | (_, Value::Num(_)) | (_, Value::List(_)) => {}
                    (_, Value::Str(s)) => f.eq_str(column, s),
                }
            }
        }
        if !f.host_ids(&plan.host_ids)? {
            return Ok(Vec::new());
        }
        f.window(plan.since, plan.until);

        let hosts: Option<HashSet<&str>> = plan
            .host_ids
            .as_ref()
            .map(|ids| ids.iter().map(String::as_str).collect());
        let base_len = f.sql.len();
        let base_params = f.params.len();

        let mut events = Vec::new();
        let mut cursor: Option<(u64, String)> = None;
        let mut scanned: u64 = 0;
        loop {
            f.sql.truncate(base_len);
            f.params.truncate(base_params);
            if let Some((ts, id)) = &cursor {
                let t = f.bind("UInt64", ts.to_string());
                let i = f.bind("String", id.clone());
                f.and(&format!(
                    "(timestamp > {t} OR (timestamp = {t} AND event_id > {i}))"
                ));
            }
            let l = f.bind("UInt64", batch_size.to_string());
            let text = self.select_events(
                "raw_json, timestamp, event_id",
                &f,
                &format!("ORDER BY timestamp ASC, event_id ASC LIMIT {l}"),
            )?;

            let mut batch_rows: u64 = 0;
            let mut last_seen: Option<(u64, String)> = None;
            let mut reached_limit = false;
            for line in text.lines() {
                let (event, row) = decode_row(line)?;
                batch_rows += 1;
                let timestamp = match &row["timestamp"] {
                    Json::String(s) => s.parse::<u64>().ok(),
                    other => other.as_u64(),
                }
                .ok_or_else(|| backend("clickhouse: timestamp missing from row"))?;
                let event_id = row["event_id"]
                    .as_str()
                    .ok_or_else(|| backend("clickhouse: event_id missing from row"))?
                    .to_string();
                last_seen = Some((timestamp, event_id));
                if in_hosts(&event, &hosts)
                    && plan.filter.as_ref().is_none_or(|ast| eval_ast(&event, ast))
                {
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
            if batch_rows < batch_size || scanned >= MAX_SCAN_ROWS {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use osiris_query::EventQueryPlan;
    use osiris_storage::conformance::sample_event;
    use osiris_storage::Storage;

    use crate::{ClickHouseOptions, ClickHouseStorage};

    /// Drops the test database when the test ends.
    struct DropGuard(ClickHouseStorage);

    impl Drop for DropGuard {
        fn drop(&mut self) {
            let _ = self.0.drop_database();
        }
    }

    impl std::ops::Deref for DropGuard {
        type Target = ClickHouseStorage;
        fn deref(&self) -> &ClickHouseStorage {
            &self.0
        }
    }

    fn test_storage() -> DropGuard {
        let url = std::env::var("OSIRIS_CLICKHOUSE_URL")
            .expect("OSIRIS_CLICKHOUSE_URL must be set to run the ClickHouse tests");
        let storage = ClickHouseStorage::open(ClickHouseOptions {
            url,
            database: format!("osiris_t_{}", uuid::Uuid::new_v4().simple()),
            timeout: Duration::from_secs(30),
            ..ClickHouseOptions::default()
        })
        .expect("open fresh database");
        DropGuard(storage)
    }

    #[test]
    #[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
    fn paginates_past_the_first_scan_batch_to_find_a_residual_match() {
        let storage = test_storage();
        for i in 1..=12u32 {
            storage.write(&sample_event(i, u64::from(i))).unwrap();
        }
        let plan = EventQueryPlan::with_filter("process.pid = 12").unwrap();
        let events = storage.query_events_batched(&plan, 5).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.as_ref().unwrap().pid, 12);

        let or_plan = EventQueryPlan::with_filter("process.pid = 11 OR process.pid = 12").unwrap();
        assert_eq!(storage.query_events_batched(&or_plan, 5).unwrap().len(), 2);
    }

    #[test]
    #[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
    fn pagination_cursor_does_not_skip_rows_sharing_a_timestamp() {
        let storage = test_storage();
        for i in 1..=12u32 {
            storage.write(&sample_event(i, 1000)).unwrap();
        }
        let events = storage
            .query_events_batched(&EventQueryPlan::new(), 5)
            .unwrap();
        assert_eq!(events.len(), 12);
        let mut ids: Vec<_> = events.iter().map(|e| e.event_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 12, "pagination must not duplicate rows");
    }

    #[test]
    #[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
    fn stops_paginating_once_the_effective_limit_is_reached() {
        let storage = test_storage();
        for i in 1..=12u32 {
            storage.write(&sample_event(i, u64::from(i))).unwrap();
        }
        let mut plan = EventQueryPlan::new();
        plan.limit = 7;
        assert_eq!(storage.query_events_batched(&plan, 5).unwrap().len(), 7);
    }
}
