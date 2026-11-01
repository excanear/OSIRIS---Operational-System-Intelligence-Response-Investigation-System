# Phase 11c — ClickHouse Storage Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A second, complete `Storage` implementation on ClickHouse, proven equal to `SqliteStorage` by a
shared conformance suite, wired into `osiris-server` as an opt-in backend, and benchmarked against SQLite.

**Architecture:** New crate `osiris-storage-clickhouse` talks to ClickHouse over its HTTP interface with
the workspace's `reqwest` (blocking), run on a dedicated worker thread owned by the storage. A
backend-neutral conformance suite lives in `osiris-storage` behind a `conformance` feature, as macros that
expand into named `#[test]` functions. SQLite runs it in the normal `cargo test`. ClickHouse runs it as
`#[ignore]` tests that a new CI job runs against a pinned ClickHouse service container.

**Tech Stack:** Rust, reqwest 0.12 blocking + rustls (already in the workspace), serde_json, ClickHouse
HTTP interface (`FORMAT JSONEachRow`, query parameters `{name:Type}`, external data tables), GitHub
Actions service containers.

**Spec:** `docs/superpowers/specs/2026-11-01-phase-11c-clickhouse-storage-design.md`

## Global Constraints

- No new third-party crate anywhere in the workspace (`Cargo.lock` gains only `osiris-storage-clickhouse`). Not the async `clickhouse` crate. A real need for one is a stop-and-ask.
- `cargo build`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check` stay green on Windows with **no ClickHouse present**.
- `bash tools/check-dep-graph.sh` passes; `osiris-storage-clickhouse` may depend OSIRIS-internally only on `osiris-storage`, `osiris-schema`, `osiris-query`.
- No value is ever interpolated into SQL text. Values travel as `param_<name>` query parameters (`{name:Type}` in SQL), as external-data tables, or as `JSONEachRow` row bodies. The only identifier in SQL text is the database name, and it is validated against `^[A-Za-z_][A-Za-z0-9_]{0,63}$` before use.
- A row from a host outside `host_ids` is never returned (worst possible bug). `Some(vec![])` matches nothing. More than `MAX_TENANT_HOSTS` (30 000) hosts is `StorageError::Backend("tenant host set too large (limit 30000)")` on both backends.
- SQLite behaviour does not change. Its trait-level tests move into the conformance suite; they are not weakened.
- SQLite stays the default backend. ClickHouse configured but unreachable, or schema creation failing, is a startup failure; never a silent fallback to SQLite.
- Single writer: one OSIRIS server per ClickHouse database (documented, not enforced).
- Timestamps are `UInt64` nanoseconds in ClickHouse; no lossy conversion.
- Every result order equals SQLite's: `query`/`query_alerts`/`query_relationships`/`query_risk_scores` order by `timestamp ASC` (ties are unspecified by the trait; ClickHouse adds a deterministic tiebreak), `query_events` orders by `(timestamp ASC, event_id ASC)` where `event_id` compares as its lowercase hyphenated **string** (so ids are stored as `String`/`FixedString(36)`, not ClickHouse `UUID`, whose sort order differs).
- Default limits when `limit == 0`: `query` 100, `query_alerts` 100, `query_risk_scores` 100, `query_relationships` 1000. `query_events` uses `plan.effective_limit()`; `0` returns empty.
- Pinned ClickHouse image: one exact LTS tag (for example `clickhouse/clickhouse-server:25.8.x.y`), chosen in Task 2, used identically by CI, the bench workflow and the dev script, and recorded in the ADR.

## Review Focus

1. **Storage called from an async context.** Some call sites may invoke `Storage` on a tokio worker thread without `spawn_blocking`. `reqwest::blocking` panics there. Expected: no panic, ever. Pinned by `called_from_inside_a_tokio_runtime_does_not_panic` (Task 2).
2. **`health()` on an empty table.** ClickHouse `max(timestamp)` on zero rows is `0`, not NULL. Expected: `last_write_at == None`, `event_count == 0`. Pinned by conformance `health_on_an_empty_store_has_no_last_write` (Task 1, run for ClickHouse in Task 3).
3. **Empty-string filters in `query()`, which has no residual re-check.** `QueryPlan { file_path: Some("") }` must not match events that have no file. Expected: optional columns are `Nullable`, matching SQLite's NULL semantics. Pinned by conformance `empty_string_filter_does_not_match_absent_fields` (Task 1, run in Task 4).
4. **Large id/host lists.** A 30 000-host tenant set, or a big batch's duplicate check, overflows ClickHouse's 1 MiB URI limit if sent as URL parameters. Expected: it works. Pinned by conformance `max_size_host_set_is_accepted` (Task 1, run in Task 4), `max_size_host_set_on_side_tables` (run in Task 5) and `large_batch_write_dedupes_correctly` (Task 1, run in Task 3).
5. **Hostile strings.** Quotes, backslashes, newlines and non-ASCII in event fields and filter values. Expected: exact round-trip and exact match, no SQL error. Pinned by conformance `hostile_strings_round_trip_and_match_exactly` (Task 1, run in Task 4).

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/osiris-storage/src/conformance/mod.rs` (new, feature `conformance`) | fixtures + group macros + `conformance_tests!` umbrella |
| `crates/osiris-storage/src/conformance/{events,query,alerts,graph,risk}.rs` (new) | `pub fn <name>(s: &dyn Storage)` test bodies, one file per group |
| `crates/osiris-storage/src/plan.rs` | add `pub const MAX_TENANT_HOSTS: usize = 30_000;` (re-exported) |
| `crates/osiris-storage-sqlite/src/sqlite_storage.rs` | use shared const; trait-level tests removed (moved); internal tests stay |
| `crates/osiris-storage-sqlite/tests/conformance.rs` (new) | invokes `conformance_tests!` for SQLite |
| `crates/osiris-storage-clickhouse/src/lib.rs` (new) | `ClickHouseStorage`, `ClickHouseOptions`, re-exports |
| `crates/osiris-storage-clickhouse/src/transport.rs` (new) | worker thread, HTTP, auth, params, external tables, error mapping |
| `crates/osiris-storage-clickhouse/src/schema.rs` (new) | DDL, schema version |
| `crates/osiris-storage-clickhouse/src/events.rs` (new) | event write/dedupe, owner, get, delete, retention, health |
| `crates/osiris-storage-clickhouse/src/query.rs` (new) | `query`, `query_events` (pushdown + residual + pagination) |
| `crates/osiris-storage-clickhouse/src/{alerts,graph,risk}.rs` (new) | the three side tables |
| `crates/osiris-storage-clickhouse/tests/conformance.rs` (new) | group macros for ClickHouse, `#[ignore]`, fresh database per test |
| `tools/clickhouse/dev-server.sh` (new) | downloads the pinned ClickHouse binary and runs it locally (WSL/Linux) |
| `.github/workflows/ci.yml` | `clickhouse` job; `ci/**` push trigger |
| `tools/check-dep-graph.sh` | allow-list line for the new crate |
| `crates/osiris-server/src/config.rs` | `storage_backend`, `clickhouse` section |
| `crates/osiris-server/src/storage_backend.rs` (new) | `open_storage(&ServerConfig)` |
| `crates/osiris-server/src/main.rs` | uses `open_storage` |
| `crates/osiris-e2e-tests/tests/clickhouse_backend.rs` (new) | server-on-ClickHouse e2e, `#[ignore]` |
| `crates/osiris-bench/src/storage_compare.rs` (new) | SQLite vs ClickHouse bench |
| `.github/workflows/storage-bench.yml` (new) | runs the bench with the pinned ClickHouse |
| `docs/operators-clickhouse.md`, `docs/adr/ADR-011-clickhouse-storage-backend.md` (new); `ARCHITECTURE.md` §10.2, `PERFORMANCE.md`, `docs/VALIDATION.md`, `docs/ROADMAP-REMAINING.md` | docs |

---

### Task 1: Backend-neutral conformance suite, run by SQLite

**Files:**
- Create: `crates/osiris-storage/src/conformance/mod.rs`, `events.rs`, `query.rs`, `alerts.rs`, `graph.rs`, `risk.rs`
- Modify: `crates/osiris-storage/Cargo.toml` (feature `conformance = ["dep:serde_json"]`, optional `serde_json`), `crates/osiris-storage/src/lib.rs`, `crates/osiris-storage/src/plan.rs`
- Modify: `crates/osiris-storage-sqlite/Cargo.toml` (dev-dep `osiris-storage` with `features = ["conformance"]`), `crates/osiris-storage-sqlite/src/sqlite_storage.rs`
- Create: `crates/osiris-storage-sqlite/tests/conformance.rs`

**Interfaces:**
- Produces (in `osiris_storage`): `pub const MAX_TENANT_HOSTS: usize = 30_000;`
- Produces (in `osiris_storage::conformance`, feature-gated):
  - fixtures `pub fn sample_event(pid: u32, timestamp: u64) -> CanonicalEvent` (fresh random host), `pub fn event_on(host: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent`, plus the file/network/dns/systemd/container/identity/alert/risk builders the moved SQLite tests use (copy them from `sqlite_storage.rs` tests);
  - group macros `conformance_events_tests!`, `conformance_query_tests!`, `conformance_alerts_tests!`, `conformance_graph_tests!`, `conformance_risk_tests!` and umbrella `conformance_tests!` (invokes all five). Each has the form
    `osiris_storage::conformance_query_tests!(make_fn);` or `osiris_storage::conformance_query_tests!(make_fn, ignore = "reason");`
    where `make_fn: fn() -> G` and `G: std::ops::Deref<Target = dyn Storage>` (a guard that keeps the tempdir or test database alive until drop). Each expansion emits one `#[test] fn <name>()` per body: `let g = make_fn(); $crate::conformance::<group>::<name>(&*g);`, with `#[ignore = reason]` when given.

**Group contents.** Move every trait-observable test from `sqlite_storage.rs` into the group that owns the method. Rewrite each as `pub fn name(s: &dyn Storage)` with the same assertions. Stay in SQLite: the WAL/pragma test, every `migrates_*`/`migration_*`/`opening_dedupes_*` test, the EXPLAIN index-usage tests (`query_events_category_filter_actually_uses_the_index`, `a_windowed_host_scoped_edge_lookup_is_bounded_by_its_indexes`), and the three `query_events_batched` pagination tests (they need the internal batch size). Add these new bodies:

| group | new test | assertion |
|---|---|---|
| events | `health_on_an_empty_store_has_no_last_write` | fresh store: `healthy`, `event_count == 0`, `last_write_at == None` |
| events | `health_last_write_is_max_event_timestamp` | write ts 300, 100 → `last_write_at == Some(300)`, `event_count == 2` |
| events | `duplicate_within_one_batch_counts_once` | batch `[e, e.clone()]` → `written 1, failed 1`; `get_event` returns it |
| events | `large_batch_write_dedupes_correctly` | batch of 20 000 new events written; re-write the same 20 000 plus 10 new → `written 10, failed 20 000` |
| events | `write_of_a_duplicate_is_an_error` | `write(e)` twice → second is `Err` |
| events | `event_owner_reports_the_host_and_none_after_delete` | owner is `Some(host)`; after `delete(before = ts+1)` it is `None`, and re-writing the same id then succeeds |
| events | `delete_counts_exactly_and_rows_vanish` | ts 10,20,30; `delete(before 25)` returns 2; `query_events` returns only ts 30; `delete(before 25)` again returns 0 |
| events | `retention_apply_deletes_only_older_than_max_age` | events at now−2 h and now; `max_age_secs 3600` → `deleted_count 1` |
| query | `query_events_ties_order_by_event_id_string` | 12 events same ts → result ids equal their `to_string()` sorted ascending |
| query | `full_u64_time_window_returns_everything` | `since Some(0)`, `until Some(u64::MAX)` on `query` and `query_events` → all rows |
| query | `empty_string_filter_does_not_match_absent_fields` | process-only events; `QueryPlan{file_path: Some("")}`, `dns_domain: Some("")`, `unit_name: Some("")` → empty |
| query | `max_size_host_set_is_accepted` | host set of exactly 30 000 ids (one real) → its rows returned on `query` and `query_events`; 30 001 → the "too large" error on each |
| risk | `delete_leaves_alerts_relationships_and_risk_intact` | write one of each citing an event, delete the event, all three still queryable |
| risk | `full_u64_time_window_on_side_tables` | as above for `query_alerts`, `query_relationships`, `query_risk_scores` |
| risk | `max_size_host_set_on_side_tables` | as above (30 000 accepted, 30 001 error) for `query_alerts`, `query_relationships`, `query_risk_scores` |
| query | `hostile_strings_round_trip_and_match_exactly` | file path `a'b"c\d` + `\n` + `✓ ü`; `get_event` equals the written event; `query(file_path = it)` and OQL `file.path = "<escaped>"` both return exactly it; a path differing by one char matches nothing |
| query | `query_events_residual_rejects_never_leak` | 50 events, filter `process.pid = 7 AND event_type = "PROCESS_EXEC"` → exactly the pid-7 event |
| alerts | `alert_rewrite_does_not_duplicate_evidence` | re-writing an alert id is `failed 1` and `query_alerts(evidence=[id])` still returns it once |
| risk | `risk_reasons_keep_their_written_order` | record with reasons `c, a, b` → returned in `c, a, b` order |

`sqlite_storage.rs` uses `osiris_storage::MAX_TENANT_HOSTS` in place of its private const.

- [ ] **Step 1:** Add `MAX_TENANT_HOSTS` and the feature, then write the conformance module with the fixtures and macros. Move the tests and add the new bodies from the table.
- [ ] **Step 2:** Create `crates/osiris-storage-sqlite/tests/conformance.rs`. It has a guard struct that holds a `tempfile::TempDir` and a `SqliteStorage` and implements `Deref<Target = dyn Storage>`, a `fn fresh() -> Guard`, and `osiris_storage::conformance_tests!(fresh);`.
- [ ] **Step 3:** Run `cargo test -p osiris-storage-sqlite`. Expected: PASS. The conformance count must equal the moved count plus the 19 new tests. (Rule for any test you add: it lives in the group of the latest-implemented table it touches, in order events → query → alerts → graph → risk, so each ClickHouse task can run its groups green.) If a new test fails on SQLite, SQLite defines the truth: fix the *test* to describe SQLite's behaviour, and record it in the commit message. The only exception is `max_size_host_set_is_accepted`, where SQLite must already accept 30 000.
- [ ] **Step 4:** `cargo test --workspace`, clippy, fmt. Expected: green. The test total must not drop (moved tests are counted in the new file).
- [ ] **Step 5:** Commit `test(11c): backend-neutral Storage conformance suite, run by SQLite`.

### Task 2: ClickHouse crate, transport, schema, CI job

**Files:**
- Create: `crates/osiris-storage-clickhouse/Cargo.toml`, `src/lib.rs`, `src/transport.rs`, `src/schema.rs`, `tests/conformance.rs` (helper only for now), `tools/clickhouse/dev-server.sh`
- Modify: `.github/workflows/ci.yml`, `tools/check-dep-graph.sh`

**Interfaces:**
- Produces:
  ```rust
  pub struct ClickHouseOptions {
      pub url: String,              // http(s)://host:port
      pub database: String,         // validated identifier
      pub user: String,             // default "default"
      pub password: Option<String>, // the server reads it from password_file
      pub timeout: std::time::Duration, // per request, default 30 s
  }
  pub struct ClickHouseStorage { /* transport, writer: Mutex<()> */ }
  impl ClickHouseStorage {
      pub fn open(opts: ClickHouseOptions) -> Result<Self, StorageError>; // creates DB + tables, checks version
      pub fn drop_database(&self) -> Result<(), StorageError>;              // test/bench cleanup
      pub fn disk_bytes(&self) -> Result<u64, StorageError>;               // sum(bytes_on_disk) of active parts in the DB
  }
  pub const SCHEMA_VERSION: u32 = 1;
  ```
  The `Storage` impl exists in this task, with every method returning `Err(StorageError::Backend("not implemented"))` except `health`. Tasks 3–5 fill them in.
- Produces (crate-internal, `transport.rs`): `Transport::execute(&self, sql: &str, params: &[(&str, String)], tables: &[ExternalTable], body: Option<String>) -> Result<String, StorageError>` with `ExternalTable { name: &str, structure: "id String", rows: Vec<String> }`. Every list value (host ids, event ids) goes through `tables`, never through `params`.
- Produces (test helper in `tests/conformance.rs`): `fn fresh() -> TestDb`. It reads `OSIRIS_CLICKHOUSE_URL` and **panics** with `"OSIRIS_CLICKHOUSE_URL must be set to run the ClickHouse tests"` when the variable is unset; the tests are `#[ignore]`, so this only fires on an explicit `--include-ignored`. It opens database `osiris_t_<uuid simple>`. `TestDb` derefs to `dyn Storage` and calls `drop_database` on `Drop`.

Design rules (implementer writes the bodies):
- **Worker thread.** `open` spawns one thread that owns the `reqwest::blocking::Client` and serves requests from a `std::sync::mpsc` channel, replying on a per-request channel. Callers only block on `recv`. This is what makes calls from async contexts safe (Review Focus 1). Dropping the storage closes the channel and the thread exits.
- **HTTP.** `POST {url}/?database=<db>&param_x=...`, with the query text in the body. When there are external tables, it is a hand-built `multipart/form-data` body: the query goes in a `query` part, each table is a part named after the table, and `<name>_structure` / `<name>_format=TSV` are URL parameters. TSV-escape the rows (`\t`, `\n`, `\\`). An insert body uses `query=INSERT ... FORMAT JSONEachRow` in the URL and the rows in the body. Auth uses the `X-ClickHouse-User` / `X-ClickHouse-Key` headers, never URL credentials. A non-2xx response becomes `StorageError::Backend("clickhouse: <status>: <first 512 bytes of body>")`, and the password must never appear in it. Verify the multipart form against the pinned version.
- **Schema.** `CREATE DATABASE IF NOT EXISTS`, then tables mirroring SQLite's `events`, `alerts`, `alert_evidence`, `relationships`, `risk_scores` and `risk_score_reasons`, plus `seq UInt32` on reasons and `osiris_schema_version(version UInt32)`. Optional columns are `Nullable` (Review Focus 3). `raw_json String`. Timestamps are `UInt64`. Ids are `String`. Engine, `ORDER BY`, partitions, codecs and skip indexes are your choice. `event_id` must have a skip index (bloom_filter or set) so id lookups are not full scans. A version row greater than `SCHEMA_VERSION` makes `open` fail with `"clickhouse schema version N is newer than supported 1"`.
- **`health`.** It runs `SELECT 1` within the timeout. On failure it returns `healthy: false` with `detail`, and never panics. The counts are filled in by Task 3.
- **Pinned version.** Pick the newest ClickHouse LTS image tag that exists, as an exact `x.y.z.w`. Use it in `ci.yml`, in `dev-server.sh` (download the matching static binary and run `clickhouse server` on `127.0.0.1:8123` with a temp data dir) and later in the bench workflow.
- **CI.** In `ci.yml`, add `ci/**` to `on.push.branches`, and add a job `clickhouse` (`ubuntu-latest`). It has a `services.clickhouse` entry with the pinned image, port `8123:8123` and env `CLICKHOUSE_SKIP_USER_SETUP=1`, and a health-check wait loop on `curl -sf http://127.0.0.1:8123/ping`. It runs `cargo test -p osiris-storage-clickhouse -- --include-ignored` with `OSIRIS_CLICKHOUSE_URL=http://127.0.0.1:8123`. The existing jobs stay unchanged. From Task 6 on it also runs the e2e test.
- **Dep graph.** Add `check_only_internal_deps osiris-storage-clickhouse osiris-storage osiris-schema osiris-query`.

- [ ] **Step 1: Write the failing tests** (in `src/lib.rs` `#[cfg(test)]`; they need no server):
  - `invalid_database_name_is_rejected`: `open` with database `"x; DROP"` → `Err` whose message mentions the database name rule; with `"osiris_1"` the error is about connectivity, not the name.
  - `unreachable_server_fails_open_quickly`: url `http://127.0.0.1:1`, timeout 2 s → `Err` within 5 s.
  - `error_text_never_contains_the_password`: the same unreachable open with password `"s3cr3t-pw"` → the error string does not contain it.
  - `tsv_escaping_round_trips_control_characters`: the escaper maps `a\tb\nc\\d` to `a\\tb\\nc\\\\d`.
  - `called_from_inside_a_tokio_runtime_does_not_panic`: a `#[tokio::test(flavor = "multi_thread")]` that calls `health()` on a storage built by a test-only constructor that skips the schema step and points at `http://127.0.0.1:1`, directly in the async body, not via `spawn_blocking`. It returns `healthy: false` and does not panic. (Add `tokio` as a dev-dependency from the workspace.)
  And in `tests/conformance.rs`: `#[ignore] open_creates_schema_and_is_idempotent`. It opens a fresh database twice; both succeed; `health().healthy`.
- [ ] **Step 2:** `cargo test -p osiris-storage-clickhouse`. Expected: FAIL (does not compile / not implemented).
- [ ] **Step 3:** Implement the crate per the rules above. Add `tools/clickhouse/dev-server.sh`.
- [ ] **Step 4:** Run `cargo test -p osiris-storage-clickhouse`. Expected: the unit tests PASS and the integration test is listed as ignored. Then start the dev server, in WSL: `wsl -d Ubuntu-24.04 -- bash tools/clickhouse/dev-server.sh` (drive WSL through a script file). Run with `OSIRIS_CLICKHOUSE_URL=http://127.0.0.1:8123 cargo test -p osiris-storage-clickhouse -- --include-ignored`. Expected: PASS.
- [ ] **Step 5:** Workspace test, clippy, fmt, `bash tools/check-dep-graph.sh` (via WSL). Expected: green, and `Cargo.lock` gained no third-party package.
- [ ] **Step 6:** Commit `feat(11c): ClickHouse storage crate — transport, schema, CI job`. Push the branch as `ci/t11c-1` and confirm the `clickhouse` job is green.

### Task 3: Event write path, lookups, delete, retention, health

**Files:**
- Create: `crates/osiris-storage-clickhouse/src/events.rs`
- Modify: `src/lib.rs` (trait methods delegate), `tests/conformance.rs` (add `osiris_storage::conformance_events_tests!(fresh, ignore = "needs OSIRIS_CLICKHOUSE_URL");`)

**Interfaces:**
- Consumes: `Transport::execute`, `ExternalTable`, the `writer` mutex (Task 2).
- Produces: `write`, `batch_write`, `event_owner`, `get_event`, `delete`, `retention_apply`, and `health` with counts.

Rules:
- **`batch_write`.** It holds the `writer` mutex for the whole call. It:
  1. dedupes in the batch (first occurrence wins);
  2. asks which ids already exist (`SELECT event_id FROM events WHERE event_id IN ids`, with `ids` as an external table);
  3. inserts the new rows in one `JSONEachRow` insert;
  4. returns `written = inserted`, `failed = batch.len() - inserted`.

  The column values are derived exactly as `SqliteStorage::batch_write` derives them: `event_type`/`category` are the serde string without quotes, `process_key` is `as_hex()`, the file identity comes from `FileIdentity::from_file_ref`, and so on. `write` returns `StorageError::Backend("write failed (duplicate event_id?)")` on a duplicate.
- **`delete`.** Under the `writer` mutex, `count()` the rows with `timestamp < before`, then `DELETE FROM events WHERE timestamp < {before:UInt64}` (lightweight delete; make sure it is synchronous for the pinned version, for example with `SETTINGS lightweight_deletes_sync = 2` or the version's equivalent). Return the count. Only `events` is touched.
- **`retention_apply`.** It uses the same cutoff arithmetic as SQLite (`now_ns - max_age_secs*1e9`, saturating).
- **`health`.** `event_count = count()`. `last_write_at` is `None` when the count is 0, otherwise `max(timestamp)`.

- [ ] **Step 1:** Add the events group macro to `tests/conformance.rs`.
- [ ] **Step 2:** Run against the dev server with `--include-ignored`. Expected: FAIL ("not implemented").
- [ ] **Step 3:** Implement `events.rs`.
- [ ] **Step 4:** Run with `--include-ignored`. Expected: every events-group test PASSES, including `large_batch_write_dedupes_correctly` and `health_on_an_empty_store_has_no_last_write`. Also `cargo test -p osiris-storage-sqlite`: unchanged, PASS.
- [ ] **Step 5:** Gates, then commit `feat(11c): ClickHouse event writes, lookups, delete, retention, health`.

### Task 4: `query` and `query_events`

**Files:**
- Create: `crates/osiris-storage-clickhouse/src/query.rs`
- Modify: `src/lib.rs`, `tests/conformance.rs` (add `conformance_query_tests!`)

**Interfaces:**
- Consumes: Task 2 transport, Task 3 schema columns.
- Produces: `query`, `query_events`, and `pub(crate) fn query_events_batched(&self, plan: &EventQueryPlan, batch_size: u64) -> Result<Vec<CanonicalEvent>, StorageError>` with `SCAN_BATCH_SIZE = 20_000` and `MAX_SCAN_ROWS = 1_000_000`.

Rules:
- **`query`.** The same filters as `SqliteStorage::query`: `network_addr` is `src OR dst`, and the file identity is inode AND device. The result is `ORDER BY timestamp ASC, event_id ASC LIMIT n`.
- **`query_events`.** It copies SQLite's algorithm. Pushdown applies only when the filter is a pure AND-chain, and only for `Op::Eq` leaves on the nine fields SQLite maps (`event_type`, `category`, `process.process_key`, `file.path`, `dns.query`, `session.session_id`, `user.uid`, `service.unit_name`, `container.container_id`). The scan uses a `(timestamp, event_id)` cursor, `ORDER BY timestamp ASC, event_id ASC`. **Every** row is re-checked with `osiris_query::eval_ast`. The scan stops at the effective limit, on a short batch, or at `MAX_SCAN_ROWS`.
- **Host restriction.** `host_id IN hosts` (external table) is in SQL, and `host_ids` is re-checked on each decoded row before it is accepted (defence in depth). An empty set short-circuits to an empty result without a query. More than 30 000 hosts is the shared error, raised before any I/O.

- [ ] **Step 1: Write the failing tests.** Add the query group macro. In `src/query.rs` `#[cfg(test)]`, add three `#[ignore]` tests that use `query_events_batched` with batch 5, mirroring SQLite's pagination tests:
  - `paginates_past_the_first_scan_batch_to_find_a_residual_match`: 12 events, `process.pid = 12` → 1 result; `process.pid = 11 OR process.pid = 12` → 2.
  - `pagination_cursor_does_not_skip_rows_sharing_a_timestamp`: 12 events at ts 1000 → 12 distinct ids.
  - `stops_paginating_once_the_effective_limit_is_reached`: limit 7 → 7.

  These need a connection helper inside the crate; reuse the `fresh` logic through a `#[cfg(test)] pub(crate) fn test_storage() -> (ClickHouseStorage, DropGuard)`.
- [ ] **Step 2:** Run with `--include-ignored`. Expected: FAIL.
- [ ] **Step 3:** Implement `query.rs`.
- [ ] **Step 4:** Run with `--include-ignored`. Expected: PASS for the events and query groups and the three pagination tests, including `max_size_host_set_is_accepted`, `hostile_strings_round_trip_and_match_exactly`, `empty_string_filter_does_not_match_absent_fields` and `query_events_ties_order_by_event_id_string`.
- [ ] **Step 5:** Gates, then commit `feat(11c): ClickHouse query and OQL query_events with residual re-check`.

### Task 5: Alerts, relationships, risk scores

**Files:**
- Create: `crates/osiris-storage-clickhouse/src/alerts.rs`, `graph.rs`, `risk.rs`
- Modify: `src/lib.rs`, `tests/conformance.rs` (replace the group invocations with the umbrella `osiris_storage::conformance_tests!(fresh, ignore = "needs OSIRIS_CLICKHOUSE_URL");`)

**Interfaces:**
- Produces: `write_alerts`, `query_alerts`, `write_relationships`, `query_relationships`, `write_risk_scores` and `query_risk_scores`. The `Storage` impl is now complete; no `"not implemented"` remains.

Rules (parity with `SqliteStorage`, under the `writer` mutex for writes):
- **Alerts.** Dedupe on `alert_id` (in the batch, then against existing rows). Duplicates are `failed`. Evidence rows are inserted only for the alerts actually written. `query_alerts` with evidence ids uses `alert_id IN (SELECT alert_id FROM alert_evidence WHERE event_id IN ids)`, so each alert comes back once. `rule_id`, host and time filters as in SQLite.
- **Relationships.** The unique key is `(from_key, to_key, relation, event_id)`. Already-present or in-batch duplicate edges are skipped silently: `written_count` counts the inserted edges and `failed_count` stays 0, exactly as in SQLite. `entity` matches `from_key = k OR to_key = k`. The host restriction is `event_id IN (SELECT event_id FROM events WHERE host_id IN hosts)`.
- **Risk scores.** Dedupe on `event_id`; duplicates are `failed`. Reasons are inserted with `seq` = their index, only for the records actually written. `query_risk_scores` fetches reasons for all returned ids in **one** query, `ORDER BY event_id, seq`. Not one query per record.

- [ ] **Step 1:** Switch `tests/conformance.rs` to the umbrella macro.
- [ ] **Step 2:** Run with `--include-ignored`. Expected: the alerts, graph and risk groups FAIL.
- [ ] **Step 3:** Implement the three modules.
- [ ] **Step 4:** Run with `--include-ignored`. Expected: the **whole** conformance suite PASSES for ClickHouse, and still for SQLite. `grep -rn "not implemented" crates/osiris-storage-clickhouse/src` finds nothing.
- [ ] **Step 5:** Gates. Commit `feat(11c): ClickHouse alerts, relationships, risk scores — full Storage parity`. Push `ci/t11c-2`; the `clickhouse` job must be green.

### Task 6: Server wiring, e2e test, operator doc

**Files:**
- Modify: `crates/osiris-server/Cargo.toml` (dep `osiris-storage-clickhouse`), `src/config.rs`, `src/lib.rs`, `src/main.rs`
- Create: `crates/osiris-server/src/storage_backend.rs`, `crates/osiris-e2e-tests/tests/clickhouse_backend.rs`, `docs/operators-clickhouse.md`
- Modify: `.github/workflows/ci.yml` (the `clickhouse` job also runs `cargo test -p osiris-e2e-tests --test clickhouse_backend -- --include-ignored`)

**Interfaces:**
- Produces in `config.rs`:
  ```rust
  #[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
  #[serde(rename_all = "lowercase")]
  pub enum StorageBackend { #[default] Sqlite, Clickhouse }
  #[derive(Debug, Clone, Deserialize)]
  pub struct ClickHouseConfig {
      pub url: String,
      #[serde(default = "default_ch_database")] pub database: String,   // "osiris"
      #[serde(default = "default_ch_user")] pub user: String,           // "default"
      #[serde(default)] pub password_file: Option<String>,
      #[serde(default = "default_ch_timeout_secs")] pub timeout_secs: u64, // 30, valid 1..=600
  }
  // on ServerConfig:
  #[serde(default)] pub storage_backend: StorageBackend,
  #[serde(default)] pub clickhouse: Option<ClickHouseConfig>,
  ```
- Produces in `storage_backend.rs`: `pub fn open_storage(config: &ServerConfig) -> Result<Arc<dyn Storage>, String>`. For `Sqlite` it is today's `SqliteStorage::open(&config.db_path)`. For `Clickhouse` it reads the password file (trailing `\r\n`/`\n` trimmed; an unreadable file is an error naming the path), builds `ClickHouseOptions`, and calls `ClickHouseStorage::open`. The error text names the backend and the URL, never the password.
- Validation (`ServerConfig::validate`): `storage_backend: clickhouse` without a `clickhouse:` section → `ConfigError::Invalid("storage_backend clickhouse requires a clickhouse section")`. `timeout_secs` outside 1..=600 is invalid. A `clickhouse:` section with `sqlite` is allowed and ignored.

- [ ] **Step 1: Write the failing tests** (`config.rs` tests):
  - `storage_backend_defaults_to_sqlite`: today's minimal YAML → `Sqlite`, `clickhouse.is_none()`.
  - `clickhouse_backend_parses_with_defaults`: YAML with `storage_backend: clickhouse` and `clickhouse: {url: http://ch:8123}` → database `"osiris"`, user `"default"`, timeout 30.
  - `clickhouse_backend_without_section_is_invalid`.
  - `clickhouse_timeout_out_of_range_is_invalid` (0 and 601).

  And in `storage_backend.rs`:
  - `sqlite_backend_opens_db_path` (a tempdir path → `Ok`);
  - `clickhouse_backend_unreachable_is_an_error_not_a_fallback` (url `http://127.0.0.1:1`, timeout 1 → `Err`, mentions `clickhouse`);
  - `missing_password_file_is_an_error_naming_the_path`.

  In `clickhouse_backend.rs`, add an `#[ignore]` `#[tokio::test]` `server_on_clickhouse_ingests_and_serves_events_through_the_api`. It builds a `ServerConfig` from YAML with `storage_backend: clickhouse` and a unique database. It gets storage from `open_storage`, then follows `end_to_end.rs`'s first test pattern for spool ingestion (`run_ingestion_loop`) and the API router. It writes synthetic events to the spool, waits until `GET /api/v1/events` (with an admin session) returns them, asserts their ids, and drops the database at the end through a `reqwest` `DROP DATABASE` call.
- [ ] **Step 2:** Run `cargo test -p osiris-server`. Expected: FAIL.
- [ ] **Step 3:** Implement the config, `open_storage` and `main.rs` (replace the inline `SqliteStorage::open` match with `open_storage`; same `eprintln!` + `exit(1)` on error). Write `docs/operators-clickhouse.md`. It covers enabling the backend, a config example, the password file, the single-writer rule, the pinned and tested ClickHouse version, what stays on SQLite (the control-plane stores), that there is no SQLite→ClickHouse migration tool, and running `tools/clickhouse/dev-server.sh`.
- [ ] **Step 4:** `cargo test -p osiris-server` → PASS. Against the dev server: `cargo test -p osiris-e2e-tests --test clickhouse_backend -- --include-ignored` → PASS. `cargo test --workspace` (no env) → green, with the e2e test ignored.
- [ ] **Step 5:** Gates (+ dep graph). Commit `feat(11c): opt-in ClickHouse backend in osiris-server`. Push `ci/t11c-3`; the `clickhouse` job with e2e must be green.

### Task 7: SQLite vs ClickHouse benchmark and decision docs

**Files:**
- Create: `crates/osiris-bench/src/storage_compare.rs`, `.github/workflows/storage-bench.yml`, `docs/adr/ADR-011-clickhouse-storage-backend.md`
- Modify: `crates/osiris-bench/Cargo.toml` (dep `osiris-storage-clickhouse`, `osiris-query`), `crates/osiris-bench/src/main.rs`, `PERFORMANCE.md`, `docs/VALIDATION.md`, `ARCHITECTURE.md` (§10.2 status line + ADR-005 pointer to ADR-011), `docs/ROADMAP-REMAINING.md` (mark the ClickHouse item done; add the debts)

**Interfaces:**
- Produces: subcommand `osiris-bench storage-compare --events <n> --rounds <r> --batch <b> [--clickhouse-url <url>]` (defaults: events 100 000, rounds 5, batch 1 000). It emits one `stats::Record` per backend per size, with `bench: "storage_compare"` and `params {backend, events, batch, rounds}`. The metrics are:
  - `ingest_eps` (median across rounds);
  - for each query shape, `{p50_ms, p95_ms}` over all samples;
  - `bytes_per_event`;
  - `noise_pct` (max−min over median, for `ingest_eps` and each query p50).

  It is not part of `Cmd::All`. Without `--clickhouse-url` it runs SQLite only and says so on stderr.

Workload. Each round has a fresh store. Fill it with `events` pipeline events (reuse `pipeline::scenario` as `query.rs` does), spread over 8 host ids, with `batch_write` in chunks of `batch`; ingest time covers the fill. Then run each shape 20 times:
1. `query_events` host + 10 % time window;
2. `query_events` `event_type = "PROCESS_EXEC"`;
3. `query` `process_key` lookup of a known key;
4. `query_events` with the residual `event_type = "PROCESS_EXEC" AND process.pid = <known pid>`;
5. `get_event` by a known id.

The footprint is the SQLite file size (+ `-wal`) / count, versus `disk_bytes()` / count after `OPTIMIZE TABLE events FINAL`. The ClickHouse database is dropped after each round.

Workflow `storage-bench.yml`: `workflow_dispatch` + push to `storage-bench/**`, `ubuntu-24.04`, the pinned ClickHouse service container. It runs `cargo run --release -p osiris-bench -- storage-compare --clickhouse-url http://127.0.0.1:8123` with `--events 100000` and again with `--events 1000000`, records the runner facts like `real-linux-bench.yml` does, and uploads the jsonl as an artifact.

- [ ] **Step 1: Write the failing test** in `storage_compare.rs` `#[cfg(test)]`: `sqlite_only_run_emits_all_metrics` → `run(Args{events: 2_000, rounds: 2, batch: 500, clickhouse_url: None})` returns 1 record with `backend: "sqlite"`, `ingest_eps > 0`, all five shapes present with `p50_ms <= p95_ms`, and `bytes_per_event > 0`.
- [ ] **Step 2:** `cargo test -p osiris-bench storage_compare`. Expected: FAIL.
- [ ] **Step 3:** Implement the module, the subcommand and the workflow.
- [ ] **Step 4:** `cargo test -p osiris-bench` → PASS. Gates + dep graph (`osiris-server` must still not reach `osiris-bench`).
- [ ] **Step 5:** Commit `bench(11c): SQLite vs ClickHouse storage comparison`. Push `storage-bench/t11c-1` and wait for the run (poll the GitHub API as in earlier phases). Download the artifact.
- [ ] **Step 6: Write the docs from the measured numbers.**
  - `PERFORMANCE.md`: a table per size (ingest eps, p50/p95 per shape, bytes/event) with the noise envelope, the runner facts, the ClickHouse version, and the run id. Any difference within noise is reported as "no measurable difference".
  - `docs/VALIDATION.md`: the CI runs (`ci/t11c-*`) and the bench run.
  - `ADR-011`: the decisions and their reasons:
    - HTTP + reqwest worker thread;
    - external tables for lists;
    - String ids for order parity;
    - single-writer dedupe;
    - synchronous lightweight delete;
    - Nullable optional columns;
    - no fallback;
    - the pinned version.

    It ends with what the numbers mean for §10.2. The numbers are recorded, not acted on: the default stays SQLite.
  - `ARCHITECTURE.md` §10.2: a status line. `docs/ROADMAP-REMAINING.md`: the item done, plus the debts: multi-writer safety, a SQLite→ClickHouse copy tool, clustering/replication, RowBinary if JSONEachRow shows up as the ingest bottleneck, and streaming results.
- [ ] **Step 7:** Commit `docs(11c): storage benchmark evidence and ClickHouse ADR`.
