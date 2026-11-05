# ADR-011: ClickHouse is an opt-in telemetry backend over HTTP; SQLite stays the default

Status: accepted, 2026-11-05 (Phase 11c). Implements the "Fleet/scale deployments" tier of
ARCHITECTURE.md §10.2 and refines ADR-005 (SQLite MVP, ClickHouse fleet-scale, two-store split).
Spec: `docs/superpowers/specs/2026-11-01-phase-11c-clickhouse-storage-design.md`. Operator guide:
`docs/operators-clickhouse.md`. Measurements: `PERFORMANCE.md`, "Storage comparison".

## Context

ARCHITECTURE §10.2 and §79 name ClickHouse as the storage backend for fleet scale and require
that its numbers are measured before it is adopted. The `Storage` trait exists so the swap is
additive. Phase 11c adds the second implementation, `crates/osiris-storage-clickhouse`, proves it
equal to the SQLite one through a shared conformance suite, wires it into `osiris-server` behind
config, and measures both backends on a GitHub runner. The workspace must still build and test on
Windows with no ClickHouse present, and no third-party crate may be added.

## Decision

1. **HTTP interface through the existing `reqwest` (blocking), one worker thread.** The trait is
   synchronous, and the server calls it from async handlers, where `reqwest::blocking` panics if
   it is used or dropped on a runtime thread. One worker thread owns the client, and callers send
   a job over a channel and wait on a plain `std::sync::mpsc` reply. No new crate (the async
   `clickhouse` crate is not used). The single thread serialises requests, the same model as
   SQLite's `Mutex<Connection>`. Inserts are `INSERT ... FORMAT JSONEachRow` and reads use
   `FORMAT JSONEachRow`. Every request sets `wait_end_of_query=1`, so an exception raised after
   the first blocks were flushed becomes a real error status instead of an HTTP 200 with a partial
   body (verified on 26.3). A check for the `__exception__` trailer remains as a backstop.
2. **Lists travel as external tables.** A set of ids or hosts is sent as a `multipart/form-data`
   external data table, referenced by `IN <table>`. Scalars are `param_<name>` query parameters
   (`{name:Type}`). Nothing is interpolated into SQL text; the one identifier, the database name,
   is validated against `^[A-Za-z_][A-Za-z0-9_]{0,63}$`. A list as an `Array` parameter was not
   used.
3. **`event_id` and `host_id` are `String`, not `UUID`, for order parity.** SQLite orders and
   compares these ids as text. The spec requires the same result order on every query method, so
   the ids keep their text form and the SQL `ORDER BY` clauses reproduce SQLite's explicitly
   instead of relying on storage order.
4. **Single-writer dedupe.** ClickHouse has no unique constraint, while SQLite uses
   `INSERT OR IGNORE`. Under a process-local writer mutex a batch is deduplicated inside itself,
   the existing ids are looked up, only new rows are inserted and the rest are reported as failed.
   This holds only with one server process per database. Two servers writing one database can store
   duplicates (documented in `docs/operators-clickhouse.md`).
5. **Synchronous lightweight `DELETE`.** `delete(before)` counts the matching events, then runs
   `DELETE FROM events WHERE timestamp < ... SETTINGS lightweight_deletes_sync = 2`. The count is
   needed because a lightweight delete does not report the rows it removed; the writer mutex keeps
   it consistent with this process's own writes. The `2` makes the call return only when the rows
   are gone, as the trait requires.
6. **Optional columns are `Nullable`.** `process_key`, `file_path`, the network and DNS columns
   and the others map one-to-one to SQLite's NULL columns, so "absent" and "empty" stay distinct
   and the filters behave the same.
7. **No fallback.** If ClickHouse is configured but unreachable, the credentials are wrong or the
   schema step fails, the server exits with an error. It never falls back to SQLite, because that
   would split one deployment's data across two stores. The default `storage_backend` is `sqlite`.
8. **The pinned version is ClickHouse 26.3.60.2 (LTS), not 26.8.** The 26.8 binary raises SIGILL
   on the pre-AVX2 CPU of the development host, so it could not be tested locally. CI and the bench
   use `clickhouse/clickhouse-server:26.3.60.2`. Other versions are untested. Bumping the pin needs a
   re-run of the conformance suite and the bench.
9. **Query design copied from SQLite.** `query_events` pushes the indexable conjunction leaves
   into SQL, then re-checks every returned row against the whole filter with
   `osiris_query::eval_ast`, so a pushdown bug can only over-fetch. `host_ids` is pushed into SQL
   and checked again on the decoded rows. The schema is `MergeTree`, partitioned by 30-day buckets
   of the nanosecond timestamp and ordered by `(host_id, timestamp, event_id)`, with `bloom_filter`
   and `set` skip indexes on `event_id`, `process_key`, `event_type` and the entity columns, and
   `raw_json` compressed with ZSTD(3).

## What the numbers mean for §10.2

Measured on GitHub Actions run 42066442818 (branch `storage-bench/t11c-3` @ `b237563`, after the
`query_events` fetch fix `17b488e`; ubuntu-24.04, kernel 7.0.0-1017-azure, 4 vCPU AMD EPYC 9V74,
15 GiB, ClickHouse 26.3.60.2 as a local service container, 5 rounds per backend and size,
`noise_pct` = (max - min) / median). Details and caveats are in `PERFORMANCE.md`.

| Metric | 100 000 events | 1 000 000 events |
|---|---|---|
| Footprint, SQLite / ClickHouse (bytes/event) | 2 077.19 / 126.83 (16.38x smaller) | 2 004.32 / 139.53 (14.37x smaller) |
| Ingest, SQLite / ClickHouse (events/s) | 11 492.28 / 12 345.59: no measurable difference (7.4 %, noise 27.27 % and 0.36 %) | 6 759.50 / 11 882.25: ClickHouse 75.8 % higher (noise 23.40 % and 1.07 %) |
| `get_event` p50 (ms) | 0.007 / 4.30 | 0.007 / 3.67 |
| `process_key` p50 (ms) | 0.020 / 8.76 | 0.011 / 4.78 |
| `host_window` p50 (ms) | 2.43 / 11.88 | 2.42 / 11.10 |
| `event_type` p50 (ms) | 4.48 / 22.91 | 4.43 / 24.94 |
| `residual` p50 (ms) | 6.45 / 24.99 | 6.38 / 26.55 |

An earlier run (41362219110 @ `ade5a60`, Intel Xeon Platinum 8573C) showed ClickHouse at 133.18,
294.23 and 298.38 ms for `host_window`, `event_type` and `residual` at 1 000 000 events. A review
then found that `query_events` over-fetched on ClickHouse (each scan batch asked for 20 000 rows
when 500 were needed). After the fix (17b488e) the same shapes measure 11.10, 24.94 and 26.55 ms,
about 11 to 12 times lower. The runs are on different CPUs, so this is not a controlled
before/after. The earlier attribution of the query latency gap to HTTP round trips and MergeTree
granule reads did not hold: most of that run's scan-shape latency was the over-fetch.

- **ClickHouse wins on space and, at the larger size, on ingest.** It stores an event in about
  one fourteenth to one sixteenth of the space. At 100 000 events the ingest difference is inside
  the noise. At 1 000 000 events ClickHouse is 75.8 % higher, but SQLite's ingest envelope is wide
  in this run (27.27 % and 23.40 %), so that figure is the least stable one.
- **SQLite still wins every query shape measured**, by 3.9x to 615x at 100 000 events and by 4.2x
  to 514x at 1 000 000 (p50 ratios), far outside the noise. The scan-filtered shapes
  (`host_window`, `event_type`, `residual`) are 3.9x to 5.6x slower on ClickHouse; the point and
  key lookups (`get_event`, `process_key`) are two to three orders of magnitude slower in ratio
  because SQLite answers them in microseconds.
- **Scan shapes grow little with table size.** On ClickHouse `host_window` went from 11.88 ms to
  11.10 ms (inside the envelopes), `event_type` from 22.91 ms to 24.94 ms (inside the 1 000 000
  event envelope of 6.52 %) and `residual` from 24.99 ms to 26.55 ms (above both envelopes).
  This is stated as observed; the cause of the small growth was not isolated.
- **The per-request floor.** `get_event` on ClickHouse takes 4.30 ms and 3.67 ms (p50) at the two
  sizes. That is consistent with a per-request HTTP overhead on loopback, but it is a reading: no
  profile of the ClickHouse path was taken and the bench did not isolate it.
- **Caveats that bound the claim.** `host_window` and `event_type` go through `query_events`,
  which is capped by the plan limit (`DEFAULT_EVENT_LIMIT`, 500), so they measure limit-capped
  scans, not full scans. When every filter is pushed down, both backends fetch only what
  `query_events` can return. The footprints are measured differently: SQLite is the main file plus
  `-wal` without a checkpoint, ClickHouse is `disk_bytes()` after `OPTIMIZE TABLE events FINAL`.
  It is one runner and one run of 5 rounds, with ClickHouse on loopback, and the two runs used
  different CPUs. The bench does not test concurrent readers, large aggregations or retention
  volumes, which are the workloads ClickHouse is chosen for.
- **Conclusion.** For the Console's interactive lookups at single-host scale, SQLite is still the
  faster backend by these numbers, though the scan-filtered gap is a factor of about 4 to 6 rather
  than the one to two orders of magnitude the first run suggested. ClickHouse is justified by
  retention volume, footprint and analytical workloads, which this bench does not measure. The
  numbers are recorded, not acted on: **the default stays SQLite**, ClickHouse stays opt-in, and
  §10.2's two-tier split stands as written.

## Consequences

- `osiris-server` has `storage_backend: sqlite | clickhouse` (default `sqlite`) and a
  `clickhouse:` section (`url`, `database`, `user`, `password_file`, `timeout_secs`). The password
  comes from a file, never inline, and error text never contains it. The `url` may not carry
  userinfo, a query string or a fragment (startup rejects it), and errors show only its
  `scheme://host:port`. Only the telemetry tables
  (events, alerts, relationships, risk scores) move; the control-plane stores stay on SQLite.
- The backend runs the shared conformance suite and a server end-to-end test, but only when
  `OSIRIS_CLICKHOUSE_URL` is set. CI has a Linux job with the pinned service container. Default
  `cargo test` on Windows does not need ClickHouse.
- A server on ClickHouse should run as one process per database (decision 4). There is no
  SQLite-to-ClickHouse copy tool; switching starts empty.
- Operators who need low interactive latency at moderate volume should stay on SQLite.

## Known weaknesses (deferred, found in review)

- **Orphan risk reasons are nondeterministic on retry.** If a risk-score insert fails after its
  reasons were written, a retry with the same reasons is deduplicated on read. A retry with
  different reasons can leave extra `seq` rows or let the orphaned ones win. Fixing it needs an
  attempt discriminator or a pre-delete.
- **30-day partitions and bad clocks.** `PARTITION BY` 30-day buckets means a batch whose
  timestamps span more than `max_partitions_per_insert_block` partitions (100 by default, about 100
  months) is rejected with an error and nothing is written. An agent with a wrong clock could make
  a batch fail.
- **Large batches split into blocks.** A batch larger than `max_insert_block_size` (about 1 000 000
  rows) is split into several blocks, so a failure part-way can leave a partial write. A retry
  repairs it, because event writes deduplicate on id. The server's batches are far smaller (the
  bench uses 1 000).
- **Relationship tenant filter builds the tenant's whole event-id set.** `query_relationships`
  restricts a tenant with `event_id IN (SELECT event_id FROM events WHERE host_id IN hosts)`, which
  materialises every event id of the tenant's hosts on each call — the same class as Phase 10's
  F2. Fix: bound the subquery by the query's time window, or use a semi-join.
- **Alert evidence orphans.** If the same `alert_id` were retried with different evidence after a
  failed insert, orphaned `alert_evidence` rows could be attributed to it. Alert ids are per-alert
  UUIDs and retries resend the same alert, so this is not expected in practice.
- **Existing-edge check fan-out.** The relationship duplicate check reads all stored edges for the
  batch's event ids, which costs more on hub entities.
- **The single worker queues everything**, including `health()`, so under load health waits behind
  other requests. Idle it is bounded by the timeout.
- **`wait_end_of_query=1` buffers whole results server-side.** The bench did not isolate the
  cost of this.

## Cost if wrong, and revisit triggers

| Decision | Cost if wrong | Revisit when |
|---|---|---|
| HTTP + `reqwest` worker thread | Moderate: the transport is one module (`transport.rs`); the SQL stays. A native-protocol client replaces it. | Per-request latency (`get_event` at 3.67 ms to 4.30 ms) or the single worker is shown to dominate (see follow-ups), or `reqwest` blocking cannot meet a needed feature. |
| External tables for lists | Low: a parameter-passing detail inside `transport.rs`. | A ClickHouse version changes multipart behaviour, or list sizes make the body a cost. |
| `String` ids | Low: a column type; ordering parity depends on it. | Never expected to change while SQLite stays the reference order. |
| Single-writer dedupe | High if multiple servers are deployed: duplicate rows. | Multiple servers write one database (multi-writer safety, roadmap). Use `ReplacingMergeTree` or insert-time dedupe tokens. |
| Synchronous lightweight delete | Low to moderate: exact counts cost a count query first. | Retention volume makes the count slow: drop whole partitions instead. |
| `Nullable` optional columns | Low: some storage and speed cost. | A column proves to be hot in scans. |
| No fallback | Low: a visible startup error. | Never, unless a stand-by store is designed deliberately. |
| Pin 26.3.60.2 | Low: a re-run of CI and bench. | The dev host gets an AVX2 CPU, or 26.3 leaves support. |
| Default stays SQLite | Low. | A bench of the workloads ClickHouse is chosen for (full scans, aggregations, retention volume) is run and favours it. |

## Follow-ups the numbers suggest (not done)

- Check connection reuse (keep-alive) on the worker's client: `get_event` at 3.67 ms to 4.30 ms
  on loopback is consistent with a fixed per-request cost (a reading, not measured).
- Skip indexes or a projection for `event_type` and for the process key, if those filters need to
  get closer to SQLite (the scan-filtered shapes are about 4x to 6x slower).
- A bench that is not limit-capped (full-scan and aggregate shapes) and one with concurrent
  readers, to test what ClickHouse is chosen for.
- Re-run on a second runner or a second run to get a run-to-run envelope; the two runs so far used
  different CPUs.
