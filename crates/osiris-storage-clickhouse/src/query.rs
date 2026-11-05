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
use uuid::Uuid;

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

/// One `Op::Eq` leaf as it is pushed into SQL.
enum Pushed<'a> {
    Str(&'static str, &'a str),
    Uid(u64),
}

/// How a leaf is pushed down, or `None` when only the residual
/// `eval_ast` pass checks it. A leaf whose value type does not fit the
/// column stays residual: pushdown may only ever over-fetch.
fn pushed_leaf<'a>(field: &str, op: Op, value: &'a Value) -> Option<Pushed<'a>> {
    if op != Op::Eq {
        return None;
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
        _ => return None,
    };
    match (column, value) {
        ("user_uid", Value::Num(n)) => exact_u32(*n).map(Pushed::Uid),
        ("user_uid", _) | (_, Value::Num(_)) | (_, Value::List(_)) => None,
        (_, Value::Str(s)) => Some(Pushed::Str(column, s)),
    }
}

/// `true` when SQL already applies the whole filter, so (barring a
/// pushdown over-fetch, which the scan detects) every fetched row is
/// returned.
fn pushdown_is_exact(filter: Option<&Ast>) -> bool {
    filter.is_none_or(|ast| {
        conjunction_leaves(ast).is_some_and(|leaves| {
            leaves
                .iter()
                .all(|(field, op, value)| pushed_leaf(field, *op, value).is_some())
        })
    })
}

/// Rows the next `query_events` scan batch asks for.
///
/// - `exact` (no residual filter): only the `remaining` rows still wanted.
/// - otherwise: `remaining` for the first batch, then four times the
///   previous batch, never less than `remaining`.
///
/// Always capped by `cap` (one round-trip) and by `scan_left`, the rows
/// left before `MAX_SCAN_ROWS`, so the scan stops on exactly the same row
/// as with fixed-size batches. Never `0`.
fn next_batch_limit(
    exact: bool,
    remaining: u64,
    previous: Option<u64>,
    cap: u64,
    scan_left: u64,
) -> u64 {
    let want = match (exact, previous) {
        (false, Some(prev)) => prev.saturating_mul(4).max(remaining),
        _ => remaining,
    };
    want.min(cap).min(scan_left).max(1)
}

/// The tenant host set, parsed once per call. Only an id in its canonical
/// (lowercase hyphenated) spelling is kept: the old string comparison
/// against `host_id.to_string()` matched nothing else either.
fn host_set(host_ids: &Option<Vec<String>>) -> Option<HashSet<Uuid>> {
    host_ids.as_ref().map(|ids| {
        ids.iter()
            .filter_map(|s| Uuid::parse_str(s).ok().filter(|u| u.to_string() == *s))
            .collect()
    })
}

fn in_hosts(host_id: Uuid, hosts: &Option<HashSet<Uuid>>) -> bool {
    hosts.as_ref().is_none_or(|h| h.contains(&host_id))
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

        let hosts = host_set(&plan.host_ids);
        let mut events = Vec::new();
        for line in text.lines() {
            let (event, _) = decode_row(line)?;
            if in_hosts(event.host_id, &hosts) {
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
                match pushed_leaf(field, op, value) {
                    Some(Pushed::Str(column, s)) => f.eq_str(column, s),
                    Some(Pushed::Uid(uid)) => f.eq_u64("user_uid", "UInt32", uid),
                    None => {}
                }
            }
        }
        if !f.host_ids(&plan.host_ids)? {
            return Ok(Vec::new());
        }
        f.window(plan.since, plan.until);

        let hosts = host_set(&plan.host_ids);
        let base_len = f.sql.len();
        let base_params = f.params.len();
        // Batch sizing only changes how many rows each request asks for;
        // the rows scanned, in order, and the rows returned are the same as
        // with fixed `batch_size` batches.
        let mut exact = pushdown_is_exact(plan.filter.as_ref());
        let mut previous: Option<u64> = None;

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
            let remaining = (effective_limit - events.len()) as u64;
            let limit = next_batch_limit(
                exact,
                remaining,
                previous,
                batch_size,
                MAX_SCAN_ROWS - scanned,
            );
            previous = Some(limit);
            let l = f.bind("UInt64", limit.to_string());
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
                if in_hosts(event.host_id, &hosts)
                    && plan.filter.as_ref().is_none_or(|ast| eval_ast(&event, ast))
                {
                    events.push(event);
                    if events.len() >= effective_limit {
                        reached_limit = true;
                        break;
                    }
                } else {
                    // Defensive: should pushdown ever over-fetch, stop
                    // assuming every row is kept and grow the batches from
                    // here on rather than paging a few rows at a time.
                    exact = false;
                }
            }
            if reached_limit {
                break;
            }
            scanned += batch_rows;
            // A short batch means the range is exhausted.
            if batch_rows < limit || scanned >= MAX_SCAN_ROWS {
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

    use super::{host_set, in_hosts, next_batch_limit, pushdown_is_exact};

    const CAP: u64 = super::SCAN_BATCH_SIZE;
    const BUDGET: u64 = super::MAX_SCAN_ROWS;

    #[test]
    fn exact_pushdown_fetches_only_what_is_still_wanted() {
        assert_eq!(next_batch_limit(true, 500, None, CAP, BUDGET), 500);
        // Later batches still ask only for the remainder.
        assert_eq!(next_batch_limit(true, 120, Some(500), CAP, BUDGET), 120);
        // The cap still bounds one round-trip.
        assert_eq!(next_batch_limit(true, 1_000_000, None, CAP, BUDGET), CAP);
    }

    #[test]
    fn residual_scan_starts_at_the_limit_and_grows_fourfold_to_the_cap() {
        assert_eq!(next_batch_limit(false, 500, None, CAP, BUDGET), 500);
        assert_eq!(next_batch_limit(false, 499, Some(500), CAP, BUDGET), 2_000);
        assert_eq!(
            next_batch_limit(false, 499, Some(2_000), CAP, BUDGET),
            8_000
        );
        assert_eq!(next_batch_limit(false, 499, Some(8_000), CAP, BUDGET), CAP);
        assert_eq!(next_batch_limit(false, 499, Some(CAP), CAP, BUDGET), CAP);
        // Growth never asks for fewer rows than are still wanted.
        assert_eq!(next_batch_limit(false, 400, Some(3), CAP, BUDGET), 400);
        // A tiny test cap is honoured from the first batch.
        assert_eq!(next_batch_limit(false, 500, None, 5, BUDGET), 5);
    }

    #[test]
    fn batch_never_scans_past_the_row_budget() {
        // Same rows scanned in total as fixed-size batches: the cut-off
        // lands exactly on MAX_SCAN_ROWS.
        assert_eq!(next_batch_limit(false, 500, Some(CAP), CAP, 1_234), 1_234);
        assert_eq!(next_batch_limit(true, 500, None, CAP, 7), 7);
    }

    #[test]
    fn pushdown_is_exact_only_when_every_leaf_is_pushed() {
        let exact =
            |q: &str| pushdown_is_exact(EventQueryPlan::with_filter(q).unwrap().filter.as_ref());
        assert!(pushdown_is_exact(None));
        assert!(exact("event_type = \"process_start\""));
        assert!(exact("category = \"process\" AND user.uid = 0"));
        assert!(!exact("process.pid = 12"));
        assert!(!exact("user.uid = \"0\""));
        assert!(!exact("user.uid = 1.5"));
        assert!(!exact("event_type = \"a\" OR event_type = \"b\""));
        assert!(!exact("NOT event_type = \"a\""));
        assert!(!exact("file.path CONTAINS \"tmp\""));
        assert!(!exact("event_type = \"a\" AND process.pid = 1"));
    }

    #[test]
    fn host_set_matches_only_canonical_ids() {
        let id = uuid::Uuid::new_v4();
        let canonical = id.to_string();
        let upper = canonical.to_uppercase();
        let set = host_set(&Some(vec![canonical.clone(), "not-a-uuid".to_string()]));
        assert!(in_hosts(id, &set));
        assert!(!in_hosts(uuid::Uuid::new_v4(), &set));
        // A non-canonical spelling never matched a `to_string()` host id,
        // and still does not.
        assert!(!in_hosts(id, &host_set(&Some(vec![upper]))));
        assert!(!in_hosts(id, &host_set(&Some(vec![]))));
        assert!(in_hosts(id, &host_set(&None)));
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
