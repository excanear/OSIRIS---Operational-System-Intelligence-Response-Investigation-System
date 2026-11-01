# Phase 11c — ClickHouse telemetry storage backend (design)

Status: draft for planning. Date: 2026-11-01. Predecessor: Phase 11b (eBPF sensors), closed at master
`9535bee`.

The user asked to proceed with the recommended option and skipped the brainstorming questions. Every
choice below is therefore **the controller's call**, made from ARCHITECTURE.md §10.2, ADR-005, the
roadmap entry, and the current code. Each one is marked *(call)* where it is not already fixed by the
architecture.

## 1. Intent and why

ARCHITECTURE.md §10.2 picks SQLite for the MVP/edge and ClickHouse for fleet scale. The `Storage`
trait (`crates/osiris-storage/src/storage.rs`) exists so the swap is additive: Detection,
Correlation, Query, API and CLI code does not change. §10.2 and §79 also say the ClickHouse numbers
must be **measured before** ClickHouse is adopted, not assumed. ROADMAP-REMAINING lists the open
item as "implementação do trait `Storage`, migração/benchmark vs. SQLite".

Phase 11c delivers three things:
1. a second, complete `Storage` implementation on ClickHouse;
2. proof that it behaves exactly like the SQLite one through the trait;
3. the measured comparison that §79 requires.

**SQLite stays the default.** ClickHouse is opt-in by server config.

## 2. Goals

1. **New crate `osiris-storage-clickhouse`**, implementing every method of `Storage`:
   - `write`, `batch_write`, `event_owner`, `query`, `query_events`, `get_event`, `delete`,
     `retention_apply` and `health`;
   - `write_alerts` and `query_alerts`;
   - `write_relationships` and `query_relationships`;
   - `write_risk_scores` and `query_risk_scores`.
2. **Behavioural parity with `SqliteStorage`**, defined by a shared conformance test suite (§5). Any
   difference observable through the trait is a bug. That covers the result sets and their order,
   limits, `WriteReport` counts, duplicate handling, `host_ids` tenancy filtering, and delete and
   retention counts.
3. **Server wiring.** `osiris-server` config gains a backend choice. When ClickHouse is chosen, the
   server builds a `ClickHouseStorage` in place of `SqliteStorage` and everything else is
   unchanged. Startup fails clearly when ClickHouse is configured but unreachable or the schema
   cannot be created. It does **not** silently fall back to SQLite *(call: a silent fallback would
   split one deployment's data across two stores)*.
4. **Benchmark, SQLite vs ClickHouse, on a GitHub runner**, recorded in PERFORMANCE.md and
   VALIDATION.md. It measures ingest throughput, and query latency for the trait's main query
   shapes, at a size large enough to show the trend (§6).
5. **Docs:**
   - an operator doc for running the server on ClickHouse;
   - ADR-005 updated, or a new ADR, for the decisions here;
   - ARCHITECTURE §10.2 status;
   - ROADMAP update.

## 3. Non-goals

- ClickHouse clustering, replication, sharding or `ON CLUSTER` DDL. One server talks to one
  ClickHouse database.
- **Multiple OSIRIS servers writing the same ClickHouse database.** The duplicate-id guarantee (§4.4)
  relies on one writer process. Making it multi-writer-safe is debt.
- Migrating existing SQLite data into ClickHouse. A one-shot copy tool is debt *(call)*.
- Moving the control-plane stores to ClickHouse: baseline, incidents, evidence, links, users,
  tenants and audit stay on SQLite (ADR-005 "two-store split").
- Parquet cold storage or DataFusion.
- Streaming query results. The trait returns `Vec`, and it stays that way.
- Changing the `Storage` trait, `QueryPlan`/`EventQueryPlan`, OQL or the event schema. Adding
  backend-neutral test helpers to `osiris-storage` is allowed.
- Making ClickHouse the default, or changing any SQLite behaviour.

## 4. Anti-goals (failure even if it "works")

- ClickHouse becomes a hard dependency of the build, the default tests or a default deployment. The
  workspace must still build and test on Windows with no ClickHouse present.
- Any row from a host outside `host_ids` is returned. A tenancy leak is the worst possible bug here.
- Any value is interpolated into SQL text. All values travel as ClickHouse query parameters
  (`{name:Type}`), or as row data in the insert body.
- The ClickHouse backend passes its own tests but not the shared conformance suite.

## 5. The how: decided parts

### 5.1 Client and transport *(call)*
- The ClickHouse **HTTP interface**, through the workspace's existing `reqwest` with the
  `blocking` feature. The trait is synchronous, and every current backend is blocking.
  **No new third-party crate.** In particular, not the async `clickhouse` crate. If the builder
  finds a real need for another crate, that is a stop-and-ask.
- Writes are `INSERT ... FORMAT JSONEachRow` with the rows in the body. Reads use
  `FORMAT JSONEachRow`. The builder may switch to `RowBinary` for speed if the conformance suite
  stays green; the decision and the measured gain go in the docs.
- Auth: user and password from config. The password comes from a **file path** in config, never
  inline. `https://` URLs use reqwest's rustls. Timeouts must be configurable, with sane defaults.

### 5.2 Configuration
- New server config keys *(call; exact names are the builder's)*:
  - `storage_backend`: `sqlite` (default) or `clickhouse`;
  - `clickhouse.url`, `clickhouse.database`, `clickhouse.user`, `clickhouse.password_file`,
    `clickhouse.timeout_secs`.
- `db_path` is still used for SQLite. With `clickhouse` selected it is ignored for events, and the
  control-plane SQLite paths are unchanged.
- The server creates the database and tables if they are absent, with `CREATE ... IF NOT EXISTS`.
  A schema version is recorded so later phases can migrate.

### 5.3 Schema
These mirror SQLite's tables: `events`, `alerts`, `alert_evidence`, `relationships`,
`risk_scores` and `risk_score_reasons`. They keep the same indexed columns plus a `raw_json`
column, so a query result is the decoded `raw_json`, exactly as in SQLite. Engine choice, `ORDER BY`
keys, partitioning, skip indexes (for example a bloom filter on `event_id`/`process_key`) and codecs
are **the builder's**, under these rules:
- timestamps are stored as `UInt64` nanoseconds, the same as SQLite, with no lossy conversion;
- `event_id` lookups (`get_event`, `event_owner`, the duplicate check) must not be full scans at
  benchmark scale;
- the result order must match SQLite's for every query method. Read the SQLite `ORDER BY` clauses
  and reproduce them explicitly in SQL. Do not rely on storage order.

### 5.4 Duplicate ids (write-once semantics)
SQLite uses `INSERT OR IGNORE` on primary keys, and reports the ignored rows as `failed_count`.
`event_owner` lets ingest refuse an event whose `event_id` another host already used. ClickHouse
has no unique constraint, so *(call)*:
- Writes take a process-local writer mutex.
- Under it, the backend:
  1. removes duplicates inside the batch;
  2. queries which ids already exist;
  3. inserts only the new rows;
  4. reports the rest as failed.
  The same applies to alerts (`alert_id`), relationships (the SQLite unique key) and risk scores.
- One insert of one block per table per batch, so a batch is atomic per table as ClickHouse allows.
- The rule is documented as **single-writer**; a non-goal above covers multi-writer.

### 5.5 Queries
- `query_events` copies SQLite's design: push the indexable conjunction leaves into SQL, then
  re-check **every** returned row against the whole filter with `osiris_query::eval_ast`. A pushdown
  bug can then only over-fetch, never return a wrong row. Limits and batching must match SQLite's
  results, including when the residual filter rejects rows (SQLite's `query_events_batched` loop).
- `host_ids` filtering is pushed into SQL, and also re-checked on the decoded rows
  (defence in depth).

### 5.6 Delete and retention
- `delete(before)` must return the number of events deleted, as SQLite does. The mechanism is the
  builder's choice: lightweight `DELETE`, a mutation with `mutations_sync`, or dropping partitions
  plus a delete for the boundary. The count must be exact, and the rows must be gone from
  subsequent queries when the call returns.
- `delete` affects only `events`, as SQLite's does. If SQLite's retention touches other tables
  (check), mirror that exactly.

### 5.7 Health
`health()` reports `healthy: false` with `detail` when ClickHouse is unreachable. It never panics,
and it is bounded by the timeout. `event_count` and `last_write_at` mean the same as in SQLite.

### 5.8 Conformance suite (the parity proof)
- A backend-neutral suite, for example in `osiris-storage` behind a `conformance` feature or as a
  test-support module, of `fn(&dyn Storage)` tests. It covers every trait method, including:
  - duplicates (within a batch and across batches);
  - ordering;
  - limits;
  - `host_ids`;
  - OQL pushdown with residual rejects;
  - delete and retention counts;
  - empty plans.
  Move or copy SQLite's existing trait-level unit tests (58 in `sqlite_storage.rs`) into it where
  they are about trait behaviour. SQLite-internal tests (migrations, pragmas) stay where they are.
- `SqliteStorage` runs the suite in the normal `cargo test`.
- `ClickHouseStorage` runs it only when `OSIRIS_CLICKHOUSE_URL` is set. Otherwise the tests are
  skipped with a visible message, not silently passed. Each test uses a fresh, uniquely named
  database and drops it afterwards.
- CI: a new job in `.github/workflows/ci.yml`, Linux only, with a `clickhouse/clickhouse-server`
  service container pinned to an exact LTS version (the builder picks it and records it). It sets
  `OSIRIS_CLICKHOUSE_URL` and runs the conformance suite plus the crate's own tests. The existing
  jobs are unchanged.
- Add one e2e-style test: the server is started with `storage_backend: clickhouse`, ingests events,
  and serves them through the API. It also runs only when the env var is set.

## 6. Benchmark (§79 evidence)
- Extend `osiris-bench` with a storage comparison, run on a GitHub runner with the same pinned
  ClickHouse in a service container. It measures:
  - **ingest:** events per second for `batch_write` at realistic batch sizes, for example 1 000;
  - **queries:** median and p95 latency for `query_events` with:
    - a host and time range;
    - an `event_type` filter;
    - a `process_key` lookup;
    - an OQL filter with a residual predicate;
    - `get_event` by id.
  - query latency at, for example, 10⁵ and 10⁶ stored events, so the trend is visible;
  - disk footprint per event.
- Use repeated rounds and medians. Noise lessons from 11b-4: run several rounds, report the noise
  envelope, and never claim a pass that sits within noise.
- The result is **recorded, not acted on**. This phase does not change the default backend. The docs
  state what the numbers mean for the §10.2 decision.

## 7. Constraints
- No new third-party crate (see §5.1).
- `cargo build` / `cargo test --workspace` on Windows, with no ClickHouse, must stay green. The
  dependency-graph check (`tools/check-dep-graph.sh`) must pass. Update its allow-list if a new
  crate edge needs it, and justify the edge.
- Existing gates: fmt, clippy `-D warnings`, the workspace tests and the console tests where touched.
- The SQLite backend must not change behaviour. Its tests can move into the shared suite, but must
  not be weakened.
- All SQL values go through parameters (anti-goal).

## 8. Left to the builder
- The engine, keys, partitioning, skip indexes and codecs (within §5.3).
- JSONEachRow vs RowBinary.
- The exact config key names, defaults and timeouts.
- The delete mechanism (within §5.6).
- The conformance suite's location and shape.
- The bench's sizes and batch sizes (within §6).
- The pinned ClickHouse version.
- Task breakdown and ordering.
