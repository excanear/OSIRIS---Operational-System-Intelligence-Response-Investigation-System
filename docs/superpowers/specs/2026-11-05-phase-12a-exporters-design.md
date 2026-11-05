# Phase 12a — Server-side exporters (design)

Status: draft for planning. Date: 2026-11-05. Predecessor: Phase 11c (ClickHouse storage), closed at
master `f4cd936`.

The user said "Prossiga" to the brainstorming opener, i.e. proceed with the recommended option and
skip the questions (same as Phases 11a–11c). Every choice below is therefore **the controller's
call**, made from ARCHITECTURE.md §20.1/§20.3, the roadmap entry (ROADMAP-REMAINING "Fase 12"), and
the current code. Each one not already fixed by the architecture is marked *(call)*.

## 0. Phase split *(call)*

ROADMAP "Fase 12" holds two independent projects. They are split:

- **12a (this document): exporters.**
- **12b: WASM detection/enrichment plugins** — its own brainstorm → spec → plan cycle after 12a
  merges. Nothing in 12a may assume 12b exists.

## 1. Intent and why

OSIRIS today keeps everything it sees inside its own storage, API and console. Real deployments
already run a SIEM, a log pipeline or an OpenTelemetry collector, and they want OSIRIS events and
alerts *there* too. ARCHITECTURE.md §20.3 defines an `Exporter` as a Server-side consumer of the same
post-ingestion stream Detection consumes, and names the v1 set: file sinks (JSON/NDJSON/CSV),
Syslog/CEF over UDP/TCP/TLS, and OpenTelemetry (OTLP) logs. Kafka, webhook and object storage are
"structurally identical, deferred implementations".

12a delivers that v1 set plus the webhook (cheap, HTTP-only, and the most-asked-for generic
integration), behind one trait, configured in the server YAML, observable, and unable to hurt
ingestion.

## 2. Goals

1. **New crate `osiris-export`** (server-side only; the Agent never links it) containing:
   - the `Exporter` trait and the `ExportRecord` type (`Event(CanonicalEvent)` | `Alert(Alert)`);
   - the formatters (pure functions, golden-tested): NDJSON, CSV, RFC 5424 syslog, CEF, OTLP/JSON
     logs;
   - the transports: rotating file, UDP, TCP, TCP+TLS, HTTP(S) POST;
   - the per-exporter worker (queue, batching, retry, counters);
   - the `ExportHub` that fans one ingest batch out to every configured exporter.
2. **Exporter kinds shipped:** `file` (format `ndjson` | `csv`), `syslog` (format `rfc5424` | `cef`;
   transport `udp` | `tcp` | `tls`), `otlp` (OTLP/HTTP logs, JSON encoding), `webhook` (HTTP(S) POST
   of an NDJSON batch).
3. **Server wiring:** the hub is fed from `IngestContext::ingest` after all of the batch's storage
   writes succeed (the same point the live broadcast fires), with only the **new** events of the
   batch and their alerts — see §5.4 "Resends".
4. **Filters per exporter:** streams (`events`, `alerts`, or both), minimum severity, optional
   `event_types` allow-list, optional `tenant_id`.
5. **Observability:** per-exporter counters and state, exposed at `GET /api/v1/exporters`
   (platform admin only) and `osiris exporters status` in the CLI.
6. **Docs:** `docs/operators-exporters.md` (config reference, formats, delivery guarantees, CEF field
   map) and `docs/adr/ADR-012-exporters.md`.

## 3. Non-goals

- **Kafka and object storage.** Kafka needs librdkafka (C toolchain, a large new dependency) or an
  immature pure-Rust client; object storage needs an S3 client and credentials story. The trait is
  shaped so either is a new `impl Exporter` later. *(call)*
- **OTLP metrics and traces, OTLP/gRPC, OTLP protobuf.** Logs over OTLP/HTTP with the JSON encoding
  only — every collector accepts it and it needs no protobuf/gRPC dependencies. *(call)*
- **Durable (disk-backed) delivery.** Delivery is best-effort with bounded memory (§5.4). A
  disk spool with replay is a later phase if anyone needs at-least-once. *(call)*
- **Exporting risk scores, incidents, audit log, relationships.** Events and alerts only. *(call)*
- **Runtime reconfiguration.** Exporters are read from the server config at startup; changing them
  needs a restart. No API or console editing. *(call)*
- **Console screen.** The status endpoint and CLI are enough; a console panel can come with Phase
  13's UX items. *(call)*
- Sigma import/export (ARCHITECTURE.md mentions it as a possible future exporter) — out.
- A separate single-document `JSON` file format (§20.3 lists it): NDJSON covers the use case and is
  streamable; a JSON array file cannot be appended to safely. *(call)*

## 4. Anti-goals (failure even if it "works")

1. **An exporter slows or fails ingestion.** A dead SIEM, a full disk under the file sink, a slow
   webhook, or a panicking formatter must never delay, fail or drop a storage write, detection, or
   the live stream. Ingest only does a non-blocking enqueue.
2. **Unbounded memory.** Every queue and every retry buffer is bounded; overflow drops and counts.
3. **Silent loss.** Every dropped record is counted, per exporter and per reason, and a rate-limited
   warning is logged. Loss is visible in `/api/v1/exporters`.
4. **Secret leakage.** Tokens, passwords, HMAC keys and TLS keys come from files, are never logged,
   never returned by the status endpoint, and URLs carrying userinfo or fragment are rejected
   at config load (the same rule 11c applies to `clickhouse.url`, though 11c checks it when the
   storage opens; exporters check at config load). Query strings are allowed for `otlp`/`webhook`
   URLs only if the operator accepts they appear in config, but `last_error` and logs never print
   them. *(call)*
5. **Cross-tenant leakage.** An exporter with `tenant_id` set must never emit a record from a host
   that was not in that tenant within the last refresh interval (§5.5). A host that has never
   belonged to the tenant is never exported; a host *moved out* may leak for at most one refresh
   interval (10 s), which is documented. *(call — a push notification from the tenant store would
   close the window but needs a new `TenantStore` hook; deferred)*
6. **Plaintext where the operator asked for TLS.** `tls`/`https` never silently falls back to
   plaintext; certificate verification is on and cannot be turned off by config. *(call)*

## 5. The how: decided parts

### 5.1 Trait and record *(call)*

```rust
pub enum ExportRecord { Event(CanonicalEvent), Alert(Alert) }

#[async_trait]
pub trait Exporter: Send + Sync {
    fn name(&self) -> &str;
    /// Deliver one batch. Err = transient, the worker may retry the same batch.
    async fn export(&self, batch: &[ExportRecord]) -> Result<(), ExportError>;
}
```

`ExportError` distinguishes `Transient` (retry) from `Permanent` (drop the batch, count it, do not
retry — e.g. a 4xx from a webhook other than 408/429, a record the formatter cannot render).
Records are shared as `Arc<ExportRecord>` between exporters so fan-out does not deep-clone a batch
per exporter (builder may choose the exact sharing type).

### 5.2 Configuration

New optional `exporters:` list in the server YAML. Unknown keys inside an exporter entry are rejected
(`deny_unknown_fields` on the new exporter types only; `ServerConfig` itself is unchanged), names
must be unique, and any invalid exporter fails startup with a
message naming it. A destination that is unreachable at startup does **not** fail startup — the
exporter starts in `DEGRADED` and keeps retrying. *(call)*

Common fields (every kind):

| field | default | meaning |
|---|---|---|
| `name` | required | unique, `[a-z0-9_-]{1,64}` |
| `kind` | required | `file` \| `syslog` \| `otlp` \| `webhook` |
| `streams` | `[events, alerts]` | which record kinds |
| `min_severity` | `info` | drop records below it |
| `event_types` | all | allow-list (events only; ignored for alerts) |
| `tenant_id` | none (all) | restrict to hosts of one tenant |
| `include_raw` | `false` | include `raw_event` bytes (base64) in event output |
| `queue_capacity` | 10 000 records | bounded queue |
| `batch_max` | 500 records | flush when reached |
| `flush_interval_ms` | 1 000 | flush at least this often |
| `max_retries` | 5 | per batch, exponential backoff 0.5 s → 30 s cap, with jitter |

Kind-specific fields:

- **file:** `path`, `format: ndjson|csv`, `max_bytes` (default 100 MiB), `max_files` (default 5).
  Rotation renames `path` → `path.1` … `path.N`, oldest deleted. Files are created mode 0600 on
  Unix. `csv` requires `streams` to hold exactly one stream (columns differ). Write errors (disk
  full) are transient.
- **syslog:** `address` (`host:port`), `transport: udp|tcp|tls`, `format: rfc5424|cef`,
  `facility` (default `local0`), `app_name` (default `osiris`), `ca_file` (optional extra roots for
  `tls`), `client_cert`/`client_key` (optional mTLS), `server_name` (optional TLS name to verify
  when `address` is an IP or differs from the certificate name; verification itself stays on). TCP/TLS framing is RFC 6587 octet-counting.
  UDP messages longer than 8 KiB are truncated at a UTF-8 boundary and counted as `truncated`.
- **otlp:** `endpoint` (e.g. `https://collector:4318/v1/logs`), `headers_file` (optional; one
  `Name: value` per line, for auth headers), `ca_file`, `client_cert`/`client_key`, `timeout_secs`
  (default 10).
- **webhook:** `url`, `hmac_key_file` (optional; adds
  `X-Osiris-Signature: sha256=<hex HMAC-SHA256 of the body>`), `headers_file`, `ca_file`,
  `timeout_secs` (default 10). Body is NDJSON (`application/x-ndjson`), one record per line.

`http://` (not https) is accepted for `otlp`/`webhook` only to a loopback address; any other plain
http URL fails config load. *(call)*

### 5.3 Formats

All formats render one `ExportRecord` deterministically (golden-file tests). Every record carries a
`record_type` (`event` | `alert`).

- **NDJSON:** the record's own serde JSON (the same shape the API returns), plus
  `"record_type"`, with one deliberate difference: `raw_event` is removed unless `include_raw`, and
  when included it is a **base64 string** (standard alphabet, padded), not the API's array of
  numbers. This NDJSON object is the one embedded in the RFC 5424 MSG, the OTLP `body` and the
  webhook lines, so `include_raw` and the base64 rule apply there too; CEF and CSV never carry
  `raw_event`. *(call)*
- **CSV:** RFC 4180, header row written at the start of each file. Event columns: `timestamp`
  (RFC 3339 ns), `event_id`, `host_id`, `hostname`, `event_type`, `category`, `severity`, `pid`,
  `exe_path`, `user`, `file_path`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `dns_query`,
  `tags`. Alert columns: `timestamp`, `alert_id`, `host_id`, `rule_id`, `rule_version`, `severity`,
  `status`, `reasons` (joined by ` | `), `evidence` (joined by space). Cells starting with `=`,
  `+`, `-`, `@`, tab or CR are prefixed with `'` (spreadsheet formula injection). *(call)*
- **RFC 5424 syslog:** PRI from facility + severity map (critical→2, high→3, medium→4, low→5,
  info→6), `HOSTNAME` = the event's host name (alert: host_id), `APP-NAME`, `MSGID` = event_type or
  `ALERT`, structured data `[osiris@32473 record_type=… id=… host_id=…]`, MSG = the NDJSON line.
  (32473 is the IANA documentation PEN; noted in the doc as replaceable.) *(call)*
- **CEF:** `CEF:0|OSIRIS|OSIRIS|<server version>|<signature id>|<name>|<severity 0-10>|<ext>` inside
  an RFC 5424 envelope. Signature id = `rule_id` for alerts, `event_type` for events. Severity map
  info 1, low 3, medium 5, high 8, critical 10. Extension keys use the standard CEF dictionary
  (`rt`, `dvchost`, `src`, `spt`, `dst`, `dpt`, `suser`, `sproc`, `spid`, `fname`, `filePath`,
  `msg`, `cs1`/`cs1Label` for host_id, etc.); the full map is a table in the operator doc. Header
  and extension escaping follow the CEF spec (`|`, `\`, `=` and newlines).
- **OTLP logs (JSON):** one `ResourceLogs` per host in the batch, resource attributes
  `host.id`, `host.name`, `service.name = osiris`; one `LogRecord` per record with
  `timeUnixNano`, `observedTimeUnixNano` (server time), `severityNumber` (info 9, low 10, medium 13,
  high 17, critical 21) and `severityText`, `body` = the NDJSON object as a string, attributes
  `osiris.record_type`, `osiris.event_type` / `osiris.rule_id`, `osiris.event_id` / `osiris.alert_id`.
  Partial-success responses count the rejected records as dropped.

### 5.4 Delivery semantics *(call)*

- **Best effort, at most once per successful send, bounded memory.** No disk spool.
- Ingest calls `hub.offer(&kept_events, &alerts)` after the storage write succeeds (same place the
  live broadcast happens). `offer` filters per exporter and `try_send`s into each exporter's bounded
  queue; when full, the record is dropped and `dropped_queue_full` is incremented. `offer` never
  awaits and never takes a lock that an exporter worker can hold across I/O.
- Each exporter has one worker task: drain up to `batch_max` or until `flush_interval_ms`, call
  `export`, retry `Transient` errors up to `max_retries` with backoff, then drop and count
  `dropped_after_retries`. While a batch is retrying the queue keeps filling (and overflowing,
  counted), so a dead destination costs at most `queue_capacity + batch_max` records of memory.
- Order is preserved within one exporter; there is no ordering across exporters.
- A panic inside an exporter's worker is caught (task join), counted, logged, and the worker is
  restarted; it never propagates to ingest. *(call)*
- Shutdown: on cancellation each worker gets up to 5 s to flush what it holds, then exits.

**Resends *(call)*.** The Agent transport resends a batch until the Server acknowledges it, so the
same events can reach `ingest` twice; storage skips them, but detection runs again and creates new
alerts with new ids. The ingest loop already tells new from resent: `event_owner` → `None` means
new, `Some(same host)` means resent. Exporters receive:
- events: only the new ones;
- alerts: only those whose evidence contains at least one new event of this batch.
So a pure resend exports nothing. (Detection still writes the duplicate alerts to storage, as it
does today; fixing that is out of scope and noted as debt.)

**Partial failure.** Ingest is several separate writes (`batch_write`, `write_alerts`,
`write_relationships`, `write_risk_scores`). If a later one fails, the earlier data is stored but
nothing is exported for that batch, exactly like the live broadcast; on the spool path that batch is
not retried. Documented in the ADR as a known gap of best-effort delivery.

The live-stream fan-out today publishes the batch as it arrived, including events dropped for an
event-id owner collision. The exporter path must use the kept set; whether to also fix the
broadcaster to use the kept set is left to the builder (a one-line change; do it if trivially safe
and cover it with a test).

### 5.5 Tenant filter

`tenant_id` is resolved to its host set through the existing `osiris-tenancy` registry. The set is
cached and refreshed at most every 10 s *(call)*; a host not in the cached set is not exported. If
the registry read fails, the previous set is kept and an error is logged (same policy as the WS
stream, see roadmap debt). A host moved out of the tenant may therefore still be exported for up to
one refresh interval — documented, accepted. *(call)*

### 5.6 Status and counters

Per exporter: `name`, `kind`, `state` (`OK` | `DEGRADED` — last send failed — | `STOPPED`),
`queued` (current depth), `sent_records`, `sent_batches`, `send_errors`, `dropped_queue_full`,
`dropped_after_retries`, `dropped_permanent`, `truncated`, `last_success_at`, `last_error` (message
with destination host only; never a URL query, header, or key). `GET /api/v1/exporters` returns
this list, platform `admin` role only (exporters see all tenants unless filtered, so tenant admins
must not see them). `osiris exporters status` prints it as a table, `--json` raw.

### 5.7 TLS

All TLS uses the workspace `rustls` stack (ring) with native roots plus optional `ca_file`, and
optional client cert/key for mTLS. Hostname verification always on. For HTTP exporters use the
workspace `reqwest` (already pinned with `rustls-tls-native-roots`); the async client, not
`blocking`. *(call)*

## 6. Tests and evidence

- **Formatters:** golden tests per format for an exec event, a network event, a DNS event, an alert;
  CEF/CSV escaping edge cases; syslog UDP truncation at a UTF-8 boundary.
- **Transports:** in-process listeners — UDP socket, TCP socket (octet-counting parse), TLS server
  with an `rcgen` CA (also: wrong CA fails, no plaintext fallback), axum HTTP server for OTLP and
  webhook (HMAC verified on the receiving side; 500 → retried; 400 → permanent; 429 → retried).
- **Worker:** queue overflow counts, retry/backoff (paused tokio time), panic restart, shutdown
  flush, order preservation.
- **Isolation:** an exporter pointed at a black-hole destination does not change ingest latency
  beyond noise (a test with a deliberately stuck exporter proving `ingest` returns).
- **Tenant filter:** records from a host of another tenant are never exported; a host moved out
  stops being exported after the next refresh.
- **Resends:** ingesting the same batch twice exports its events and alerts once.
- **Config:** every rejection rule (dup names, csv with two streams, plain http to non-loopback,
  URL userinfo, unknown key).
- **Server e2e:** real server binary with a `file` NDJSON exporter and a `webhook` exporter to a
  test receiver; ingest a spool line that triggers a rule; assert both the event and the alert
  arrive at both, and `/api/v1/exporters` shows the counts.
- **Bench *(call)*:** an `osiris-bench` case measuring ingest throughput with 0 vs 3 exporters (file
  ndjson, syslog tcp to a local sink, webhook to a local sink). The existing ingest bench drives the
  real server via `osiris_real_linux_tests::stack::Stack`, whose server YAML has no exporter section
  yet — extending it is part of this task. Recorded in PERFORMANCE.md; no
  target number is promised up front, but the result is reported honestly.
- Real-linux CI is not required for this phase (no kernel-dependent code). The standard CI gates
  apply: fmt, clippy `-D warnings`, workspace tests, console lint/test/build.

## 7. Constraints

- Rust workspace conventions: workspace dependencies, `thiserror`, `tracing`, no `unwrap` on I/O
  paths. New dependencies must be justified in the plan; expected: `csv` (or hand-rolled RFC 4180),
  `hmac` (sha2 already present), `base64`. No protobuf, no gRPC, no Kafka client.
- The Agent binary must not gain any dependency from this phase.
- Windows dev host: everything must build and test on Windows too (no Unix-only code without
  `cfg`); the 0600 file mode is `cfg(unix)`.
- Follow the per-phase definition of done (ROADMAP-REMAINING): tests, errors, metrics, logs, docs,
  security review, performance consideration, CLI/API integration.

## 8. Left to the builder

- Exact module layout inside `osiris-export`, and whether `ExportHub` lives there or in
  `osiris-server`.
- Exact sharing type for records across exporters (`Arc<ExportRecord>` or `Arc<[ExportRecord]>`).
- How the alert list leaves the `spawn_blocking` closure in `IngestContext::ingest`.
- The full CEF extension map and CSV column details beyond §5.3, as long as they are documented.
- Jitter formula; rate-limit interval for drop warnings (suggest ≤ 1 per exporter per 60 s).
