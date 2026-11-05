# Phase 12a — Server-side exporters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship file (NDJSON/CSV), Syslog (RFC 5424/CEF over UDP/TCP/TLS), OTLP/HTTP-JSON logs and webhook exporters fed from server ingest, observable, and unable to hurt ingestion.

**Architecture:** New server-side crate `osiris-export` holds the record type, `Exporter` trait, config + validation, pure formatters, transports, and an `ExportHub` (per-exporter bounded queue + worker task). `IngestContext::ingest` hands the hub only *new* events and the alerts they produced, after every storage write of the batch succeeded, via a non-blocking `offer`. Status is served at `GET /api/v1/exporters` (platform admin) and `osiris exporters status`.

**Tech Stack:** Rust (workspace crates), tokio, async-trait, reqwest 0.12 async (rustls), rustls 0.23 + tokio-rustls 0.26 + rustls-native-certs 0.8, hmac 0.12 + sha2 0.10, base64 0.22, time 0.3, axum 0.7.

**Spec:** `docs/superpowers/specs/2026-11-05-phase-12a-exporters-design.md` (read it first; section numbers below refer to it).

## Global Constraints

- `osiris-export` is server-side only: `osiris-agent` must not gain any dependency (enforced in `tools/check-dep-graph.sh`, Task 1).
- `osiris-export` may depend OSIRIS-internally on `osiris-schema` and `osiris-tenancy` only.
- New external deps allowed: `hmac = "0.12"`, `base64 = "0.22"`, `rustls-native-certs = "0.8"` (both latter already in Cargo.lock), added to `[workspace.dependencies]`. No protobuf, gRPC, Kafka, or `csv` crate (CSV is hand-rolled RFC 4180).
- Everything builds and tests on Windows; Unix-only code (file mode 0600) is `#[cfg(unix)]`.
- Ingest must never await an exporter, never block on a lock an exporter worker holds across I/O, and never fail because of an exporter.
- Secrets (token/header files, HMAC keys, TLS keys) never appear in logs, `Debug` output, `last_error`, or the status endpoint. URLs with userinfo or fragment are rejected at config load; a URL query string is never printed.
- TLS verification is always on; no config knob disables it; `tls`/`https` never falls back to plaintext. Plain `http://` is accepted only for loopback hosts (`127.0.0.0/8`, `::1`, `localhost`).
- Defaults (verbatim from spec §5.2): `streams [events, alerts]`, `min_severity info`, `include_raw false`, `queue_capacity 10000`, `batch_max 500`, `flush_interval_ms 1000`, `max_retries 5`, backoff 0.5 s → 30 s cap with jitter; file `max_bytes` 100 MiB, `max_files` 5; syslog `facility local0`, `app_name osiris`; otlp/webhook `timeout_secs 10`; UDP payload cap 8192 bytes; tenant cache refresh 10 s; shutdown flush 5 s.
- Name rule: `[a-z0-9_-]{1,64}`, unique.
- CI gates before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `bash tools/check-dep-graph.sh`, console lint/test/build unchanged.
- Commit messages: `feat(12a): …` / `test(12a): …` / `docs(12a): …`, ending with the `Co-Authored-By` line the controller provides.

## Review Focus

1. **A destination that accepts the TCP/TLS connection but never reads** (stuck SIEM): the worker must time out the write (use the same `timeout_secs`, default 10, for syslog TCP/TLS writes) and treat it as transient; ingest stays fast. Test in Task 4 (`tcp_write_to_a_reader_that_never_reads_times_out_as_transient`).
2. **Destination comes back after being down**: TCP/TLS syslog must reconnect on the next batch after a broken connection (no permanently dead socket). Test in Task 4 (`tcp_reconnects_after_the_listener_restarts`).
3. **Same event id twice inside one batch** (not a resend across batches): exported once. Test in Task 6 (`an_event_id_repeated_inside_one_batch_is_exported_once`).
4. **Non-ASCII / control characters in fields** (paths with newlines, UTF-8 hostnames): CEF/CSV/RFC 5424 output stays one record per line/frame and valid UTF-8. Golden cases in Task 2 (`newline_in_a_path_does_not_split_the_record`).
5. **Server with zero exporters configured**: no hub, no worker tasks, ingest path unchanged, `/api/v1/exporters` returns `{"exporters": []}`. Tests in Task 6 (`ingest_without_exporters_is_unchanged`) and Task 7 (`exporters_endpoint_returns_empty_list_when_none_configured`).

---

## File Structure

```
crates/osiris-export/
  Cargo.toml
  src/lib.rs             re-exports
  src/record.rs          ExportRecord, Stream
  src/error.rs           ExportError, ConfigError
  src/exporter.rs        Exporter trait, ExportOutcome
  src/config.rs          ExporterConfig (+ per-kind specs), validate_exporters, Filter
  src/format/mod.rs      shared helpers (severity maps, RFC 3339 ns)
  src/format/ndjson.rs   src/format/csv.rs   src/format/syslog.rs (RFC 5424 + CEF)   src/format/otlp.rs
  src/hub.rs             ExportHub, worker loop, tenant cache, ExporterStatus
  src/transport/file.rs  src/transport/syslog.rs  src/transport/http.rs (otlp + webhook)  src/transport/tls.rs
  src/build.rs           build_exporters(config) -> Vec<(WorkerSettings, Arc<dyn Exporter>)>
  tests/golden/*.txt     golden outputs
crates/osiris-server/src/{config.rs,ingest.rs,main.rs}   wiring
crates/osiris-api/src/exporters.rs, auth_middleware.rs, lib.rs
crates/osiris-cli/src/{main.rs,client.rs}
crates/osiris-e2e-tests/tests/exporters.rs
crates/osiris-real-linux-tests/src/{stack.rs,render.rs}, tests/exporters_binary.rs
crates/osiris-bench/src/ingest.rs (+ main.rs flag)
docs/operators-exporters.md, docs/adr/ADR-012-exporters.md, PERFORMANCE.md, docs/ROADMAP-REMAINING.md
```

---

### Task 1: Crate skeleton, record, trait, config and validation

**Files:**
- Create: `crates/osiris-export/{Cargo.toml,src/lib.rs,src/record.rs,src/error.rs,src/exporter.rs,src/config.rs}`
- Modify: `Cargo.toml` (workspace deps `hmac`, `base64`, `rustls-native-certs`), `tools/check-dep-graph.sh`

**Interfaces:**
- Produces:
  - `pub enum ExportRecord { Event(CanonicalEvent), Alert(Alert) }` with `fn stream(&self) -> Stream`, `fn severity(&self) -> Severity`, `fn host_id(&self) -> Uuid`, `fn timestamp(&self) -> u64`, `fn id(&self) -> Uuid` (event_id / alert_id).
  - `#[serde(rename_all = "lowercase")] pub enum Stream { Events, Alerts }`.
  - `pub enum ExportError { Transient(String), Permanent(String) }` (thiserror).
  - `#[derive(Default)] pub struct ExportOutcome { pub dropped: u64, pub truncated: u64 }` — records the destination rejected (OTLP partial success) or truncated (UDP).
  - `#[async_trait] pub trait Exporter: Send + Sync { fn name(&self) -> &str; async fn export(&self, batch: &[Arc<ExportRecord>]) -> Result<ExportOutcome, ExportError>; }` *(plan call: returns `ExportOutcome` instead of `()` so partial success and truncation are countable, §5.6)*.
  - `pub struct ExporterConfig { pub name: String, pub common: CommonOptions, pub kind: KindConfig }` deserializable from one flat YAML mapping (`name`, `kind`, common fields, kind fields side by side); `pub enum KindConfig { File(FileConfig), Syslog(SyslogConfig), Otlp(OtlpConfig), Webhook(WebhookConfig) }`; field names and defaults exactly as spec §5.2. Unknown keys must be rejected — `#[serde(flatten)]` disables `deny_unknown_fields`, so the builder picks a working mechanism (e.g. deserialize to a raw map, check keys against the kind's allow-list, then convert).
  - `pub fn validate_exporters(cfgs: &[ExporterConfig]) -> Result<(), ConfigError>`; `ConfigError` messages name the exporter.
  - `pub struct Filter` built by `Filter::from_config(&CommonOptions)`, `fn accepts(&self, rec: &ExportRecord) -> bool` (streams, min_severity, event_types for events only; tenant is *not* here — the hub applies it).

- [ ] **Step 1: Write failing tests in `config.rs`** — `parses_a_file_exporter_with_defaults` (assert every §5.2 default), `parses_each_kind`, and one rejection test each: `rejects_duplicate_names`, `rejects_bad_name` (`"Bad Name"`), `rejects_unknown_key` (`colour: red`), `rejects_csv_with_two_streams`, `rejects_plain_http_to_non_loopback` (`http://10.0.0.5/x`), `accepts_plain_http_to_loopback` (`http://127.0.0.1:4318/v1/logs`), `rejects_url_with_userinfo` (`https://u:p@h/x`), `rejects_url_with_fragment`, `rejects_zero_queue_capacity`, `rejects_zero_batch_max`, `rejects_syslog_address_without_port`, `rejects_client_cert_without_key`. Each asserts `Err` and that the message contains the exporter name.
- [ ] **Step 2: Write failing tests in `config.rs` for `Filter`** — `filter_drops_below_min_severity`, `filter_respects_streams`, `event_types_allow_list_ignored_for_alerts`.
- [ ] **Step 3: Run** `cargo test -p osiris-export` — expect compile failure / FAIL.
- [ ] **Step 4: Implement** the types above. `Debug` for config types must not print file *contents* (they hold only paths, so derive is fine — no secrets are read in this task).
- [ ] **Step 5: Run** `cargo test -p osiris-export` — PASS.
- [ ] **Step 6: Add dep-graph rule** in `tools/check-dep-graph.sh`: `check_only_internal_deps osiris-export osiris-schema osiris-tenancy`, and add `osiris-export` to the list of crates `osiris-agent` must never reach (follow the script's existing `check_forbidden` pattern). Run `bash tools/check-dep-graph.sh` — exit 0.
- [ ] **Step 7: Commit** `feat(12a): osiris-export crate, record, trait and config validation`.

### Task 2: Formatters (pure, golden-tested)

**Files:**
- Create: `crates/osiris-export/src/format/{mod.rs,ndjson.rs,csv.rs,syslog.rs,otlp.rs}`, `crates/osiris-export/tests/golden/*.txt`, `crates/osiris-export/tests/formats.rs`

**Interfaces:**
- Consumes: `ExportRecord`, `Stream` (Task 1).
- Produces:
  - `pub fn ndjson_value(rec: &ExportRecord, include_raw: bool) -> serde_json::Value` and `pub fn ndjson_line(rec: &ExportRecord, include_raw: bool) -> String` (no trailing newline).
  - `pub fn csv_header(stream: Stream) -> &'static str` (with trailing `\r\n`), `pub fn csv_row(rec: &ExportRecord) -> String` (with trailing `\r\n`).
  - `pub enum Facility` (serde lowercase: `kern`…`local7`, numeric codes per RFC 5424), `pub fn rfc5424(rec: &ExportRecord, facility: Facility, app_name: &str, include_raw: bool) -> String`.
  - `pub fn cef(rec: &ExportRecord, facility: Facility, app_name: &str, product_version: &str) -> String` (RFC 5424 envelope, CEF in MSG).
  - `pub fn otlp_logs_body(batch: &[Arc<ExportRecord>], include_raw: bool, observed_ns: u64) -> serde_json::Value`.
  - `pub fn severity_number_otlp(Severity) -> u8`, `pub fn cef_severity(Severity) -> u8`, `pub fn syslog_severity(Severity) -> u8` (maps verbatim from spec §5.3).

- [ ] **Step 1: Write fixture builders** in `tests/formats.rs`: `exec_event()`, `network_event()`, `dns_event()`, `alert()` with fixed UUIDs/timestamps (`timestamp = 1_762_300_800_123_456_789`) so output is deterministic.
- [ ] **Step 2: Write failing golden tests** — for each of the 4 fixtures × {ndjson, csv row, rfc5424, cef}, plus `otlp_body_groups_records_by_host` (2 hosts → 2 `resourceLogs`): compare to `tests/golden/<fixture>.<format>.txt`. Generate goldens once by hand-checking the first output against spec §5.3, then commit them.
- [ ] **Step 3: Write failing edge tests**:
  - `ndjson_omits_raw_event_by_default`, `ndjson_includes_raw_event_as_base64_when_enabled` (bytes `[0,1,2,255]` → `"AAEC/w=="`), `ndjson_has_record_type`.
  - `csv_escapes_quotes_commas_and_newlines`, `csv_prefixes_formula_cells` (`=cmd|' /C calc'!A0` → `'=cmd…`; also `+`, `-`, `@`, `\t`, `\r`).
  - `cef_escapes_header_pipes_and_backslashes`, `cef_escapes_extension_equals_and_newlines` (newline → `\n` literal).
  - `newline_in_a_path_does_not_split_the_record` (Review Focus 4): an exec event whose `exe_path` contains `"\n"` and a UTF-8 name renders to exactly one line in ndjson, csv (quoted), rfc5424 and cef.
  - `rfc5424_pri_combines_facility_and_severity` (local0 + high → `<131>`), `rfc5424_hostname_is_nilvalue_when_empty` (`-`).
  - `otlp_severity_numbers_match_spec` (info 9, low 10, medium 13, high 17, critical 21).
- [ ] **Step 4: Run** `cargo test -p osiris-export --test formats` — FAIL.
- [ ] **Step 5: Implement** the formatters. RFC 3339 timestamps with nanoseconds via `time` (`OffsetDateTime::from_unix_timestamp_nanos`). Structured data param values escape `"`, `\`, `]` per RFC 5424 §6.3.3. SD-ID `osiris@32473`.
- [ ] **Step 6: Run** — PASS. Then `cargo clippy -p osiris-export --all-targets -- -D warnings` — clean.
- [ ] **Step 7: Commit** `feat(12a): ndjson, csv, rfc5424, cef and otlp formatters`.

### Task 3: ExportHub and worker

**Files:**
- Create: `crates/osiris-export/src/hub.rs`

**Interfaces:**
- Consumes: `Exporter`, `ExportRecord`, `Filter`, `CommonOptions` (Task 1); `osiris_tenancy::TenantStore::hosts_of(&self, Uuid) -> Result<HashSet<Uuid>, TenantStoreError>`.
- Produces:
  - `pub struct WorkerSettings { pub name: String, pub kind: &'static str, pub filter: Filter, pub tenant_id: Option<Uuid>, pub queue_capacity: usize, pub batch_max: usize, pub flush_interval: Duration, pub max_retries: u32 }` with `WorkerSettings::from_config(&ExporterConfig) -> WorkerSettings`.
  - `pub struct ExportHub`; `ExportHub::start(exporters: Vec<(WorkerSettings, Arc<dyn Exporter>)>, tenants: Option<Arc<dyn TenantStore>>, cancel: CancellationToken) -> Arc<ExportHub>` (must be called inside a tokio runtime).
  - `pub fn offer(&self, events: &[CanonicalEvent], alerts: &[Alert])` — sync, non-blocking: per exporter apply filter + tenant set, `try_send` into a bounded `tokio::sync::mpsc` of `Arc<ExportRecord>`; full → `dropped_queue_full += 1`. Records are wrapped in `Arc` once per offer call and shared across exporters.
  - `pub fn status(&self) -> Vec<ExporterStatus>`; `#[derive(Serialize, Clone)] pub struct ExporterStatus { name, kind, state: ExporterState, queued, sent_records, sent_batches, send_errors, dropped_queue_full, dropped_after_retries, dropped_permanent, truncated, panics, last_success_at: Option<u64> /* unix ns */, last_error: Option<String> }`; `#[serde(rename_all = "SCREAMING_SNAKE_CASE")] pub enum ExporterState { Ok, Degraded, Stopped }`.
  - `pub async fn shutdown(&self)` — after `cancel` fires, waits for workers to flush, max 5 s total, then marks `STOPPED`.
- Worker loop: collect up to `batch_max` or until `flush_interval` elapsed since the first record of the batch; call `export` inside `tokio::spawn` and await the `JoinHandle` (a panic → `panics += 1`, `dropped_permanent += batch.len()`, continue). `Transient` → `send_errors += 1`, state `DEGRADED`, sleep backoff (0.5 s × 2^attempt, cap 30 s, ±20 % jitter), retry same batch up to `max_retries`, then `dropped_after_retries += len`. `Permanent` → `dropped_permanent += len`. `Ok(outcome)` → `sent_records += len - outcome.dropped`, `dropped_permanent += outcome.dropped`, `truncated += outcome.truncated`, `sent_batches += 1`, state `OK`, `last_success_at = now`. On cancel: stop retry sleeps, try one final export of what is held + drained, respecting the 5 s overall deadline.
- Tenant cache: if any worker has `tenant_id`, spawn one refresher task that calls `hosts_of` in `spawn_blocking` for each distinct tenant every 10 s and swaps the result into a `std::sync::RwLock<HashMap<Uuid, HashSet<Uuid>>>` (writer holds the lock only for the swap). Before the first successful load the set is empty (nothing leaks). On error keep the previous set and `tracing::error!`.
- Drop warnings: `tracing::warn!` at most once per exporter per 60 s, carrying the running counters.

- [ ] **Step 1: Write failing tests** (in `hub.rs`, using a `FakeExporter` that records batches and can be scripted to return Ok / Transient / Permanent / panic / sleep), with `#[tokio::test(start_paused = true)]` where timing matters:
  - `delivers_records_in_order_in_batches_of_batch_max` (batch_max 3, 7 records → batches 3,3,1).
  - `flushes_a_partial_batch_after_flush_interval`.
  - `queue_overflow_is_counted_not_blocking` (exporter blocked; capacity 4; offer 10 → `dropped_queue_full == 10 - 4 - <in-flight batch>`; assert `offer` returns without awaiting).
  - `transient_errors_retry_with_backoff_then_drop` (always Transient, max_retries 2 → 3 attempts, then `dropped_after_retries == len`, state `DEGRADED`).
  - `permanent_error_drops_without_retry`.
  - `panic_in_export_is_contained` (next batch still delivered, `panics == 1`).
  - `outcome_dropped_and_truncated_are_counted`.
  - `filter_is_applied_per_exporter` (two exporters, one alerts-only).
  - `tenant_filter_never_exports_foreign_hosts` (fake `TenantStore`: tenant A = {h1}; records from h1 and h2 → only h1).
  - `tenant_filter_exports_nothing_before_first_load` (store blocks first call).
  - `host_moved_out_stops_after_refresh` (advance 10 s).
  - `tenant_store_error_keeps_previous_set`.
  - `shutdown_flushes_held_records_within_5s`.
- [ ] **Step 2: Run** `cargo test -p osiris-export hub` — FAIL.
- [ ] **Step 3: Implement** `hub.rs` per the interface above.
- [ ] **Step 4: Run** — PASS (run 5× in a loop to check for timing flakiness: `for i in 1 2 3 4 5; do cargo test -p osiris-export hub -q || break; done`).
- [ ] **Step 5: Commit** `feat(12a): export hub with bounded queues, retry and tenant filter`.

### Task 4: File and syslog transports

**Files:**
- Create: `crates/osiris-export/src/transport/{mod.rs,file.rs,syslog.rs,tls.rs}`

**Interfaces:**
- Consumes: formatters (Task 2), `Exporter` (Task 1), `FileConfig`, `SyslogConfig`.
- Produces:
  - `pub struct FileExporter`; `FileExporter::new(name, &FileConfig, include_raw: bool, stream_for_csv: Option<Stream>) -> Result<Self, ConfigError>`. One `std::fs::File` behind a `tokio::sync::Mutex`; writes via `spawn_blocking`. CSV header written whenever a new file is created. Rotation before a write that would push size past `max_bytes`: `path.(N-1)` → `path.N` … `path` → `path.1`, oldest beyond `max_files` deleted. Created with mode 0600 (`#[cfg(unix)]`). I/O error → `Transient`.
  - `pub fn client_tls_config(ca_file: Option<&Path>, client_cert: Option<&Path>, client_key: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, ConfigError>` in `tls.rs` (native roots via `rustls-native-certs` + `ca_file` PEMs; ring provider). Used by Task 5 too.
  - `pub struct SyslogExporter`; `SyslogExporter::new(name, &SyslogConfig, include_raw, product_version: &str) -> Result<Self, ConfigError>`. UDP: one datagram per record, payload capped at 8192 bytes, cut at a UTF-8 char boundary, `truncated += 1`. TCP/TLS: lazily connected stream held in a `tokio::sync::Mutex<Option<…>>`; each record framed `"<len> <msg>"` (RFC 6587 octet counting); each connect and each batch write wrapped in `tokio::time::timeout(10 s)`; any error or timeout drops the connection (reconnect next attempt) and returns `Transient`. TLS server name = `server_name` if set, else the host part of `address`.
- `address` resolution happens at connect time (DNS names allowed).

- [ ] **Step 1: Write failing tests** (`#[tokio::test]`, temp dirs, in-process listeners):
  - file: `file_ndjson_appends_one_line_per_record`, `file_csv_writes_header_once_per_file`, `file_rotates_at_max_bytes_and_keeps_max_files` (max_bytes 200, max_files 2 → `path`, `path.1`, `path.2` exist, `path.3` does not), `#[cfg(unix)] file_is_created_0600`.
  - syslog: `udp_sends_one_datagram_per_record`, `udp_truncates_oversized_payload_at_char_boundary` (record with 9000 × `é` in a path → datagram ≤ 8192 bytes, valid UTF-8, `outcome.truncated == 1`), `tcp_uses_octet_counting_framing` (parse frames on the server side), `tls_delivers_with_a_trusted_ca` (rcgen CA + server cert for `localhost`, `ca_file` set), `tls_with_wrong_ca_fails_and_never_sends_plaintext` (listener records any bytes; assert Transient and that no syslog payload bytes were received), `tls_server_name_override_allows_ip_address` (address `127.0.0.1:port`, cert for `syslog.test`, `server_name: syslog.test`), `tcp_reconnects_after_the_listener_restarts` (Review Focus 2), `tcp_write_to_a_reader_that_never_reads_times_out_as_transient` (Review Focus 1; listener accepts and never reads; send > socket buffer, use paused time or a 1 s test-only timeout via a `#[cfg(test)]` constructor parameter).
- [ ] **Step 2: Run** `cargo test -p osiris-export transport` — FAIL.
- [ ] **Step 3: Implement** per interfaces. `rcgen` goes in `[dev-dependencies]` (workspace dep exists).
- [ ] **Step 4: Run** — PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(12a): file and syslog (udp/tcp/tls) transports`.

### Task 5: OTLP and webhook transports, and `build_exporters`

**Files:**
- Create: `crates/osiris-export/src/transport/http.rs`, `crates/osiris-export/src/build.rs`

**Interfaces:**
- Consumes: `client_tls_config` (Task 4), `otlp_logs_body`, `ndjson_line` (Task 2), `WorkerSettings::from_config` (Task 3).
- Produces:
  - `pub struct OtlpExporter`, `pub struct WebhookExporter`, each `::new(name, &cfg, include_raw) -> Result<Self, ConfigError>`; one `reqwest::Client` per exporter built with `use_preconfigured_tls(client_tls_config(..))` and `timeout(timeout_secs)`.
  - `headers_file`: read once at construction; lines `Name: value`, blank lines and `#` comments skipped; invalid header name/value → `ConfigError` naming the exporter and the line number, never the value. `hmac_key_file`: raw bytes of the file, trailing `\r?\n` stripped; empty → `ConfigError`.
  - Webhook body: records joined as NDJSON lines each ending `\n`, `Content-Type: application/x-ndjson`; with HMAC: `X-Osiris-Signature: sha256=<lowercase hex HMAC-SHA256(key, body)>`.
  - OTLP: `POST` `Content-Type: application/json` with `otlp_logs_body`. Response `partialSuccess.rejectedLogRecords` (string or number) → `ExportOutcome.dropped`.
  - Status mapping (both): 2xx → Ok; 408, 429, 5xx, connect/timeout errors → `Transient`; other 4xx → `Permanent`. Error text = `"<status> from <host>"` or the reqwest error kind plus host — never the full URL.
  - `pub fn build_exporters(cfgs: &[ExporterConfig], product_version: &str) -> Result<Vec<(WorkerSettings, Arc<dyn Exporter>)>, ConfigError>` — calls `validate_exporters` first.

- [ ] **Step 1: Write failing tests** with an axum test receiver on `127.0.0.1:0` (plain http is allowed to loopback; one TLS test uses `axum-server`-free `tokio-rustls` acceptor + `hyper-util` if needed — builder's choice — or asserts TLS behaviour already covered by Task 4 and only checks `https` client building with `ca_file`):
  - `webhook_posts_ndjson_with_valid_hmac` (receiver recomputes HMAC with the same key and compares).
  - `webhook_without_hmac_has_no_signature_header`.
  - `webhook_sends_headers_from_headers_file`.
  - `status_500_and_429_are_transient_400_is_permanent`.
  - `otlp_posts_json_logs_and_counts_partial_success` (receiver returns `{"partialSuccess":{"rejectedLogRecords":"2"}}` → `outcome.dropped == 2`).
  - `error_messages_never_contain_url_query_or_header_values` (URL `http://127.0.0.1:1/x?token=SECRET`, header file with `Authorization: Bearer SECRET`; assert the error string does not contain `SECRET`).
  - `headers_file_with_bad_line_names_the_line_not_the_value`.
  - `build_exporters_builds_every_kind` and `build_exporters_rejects_invalid_config`.
- [ ] **Step 2: Run** `cargo test -p osiris-export http build` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p osiris-export` — all PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(12a): otlp and webhook transports`.

### Task 6: Server wiring (config, ingest, shutdown)

**Files:**
- Modify: `crates/osiris-server/Cargo.toml`, `crates/osiris-server/src/config.rs` (field + validate call), `crates/osiris-server/src/ingest.rs:115-300`, `crates/osiris-server/src/main.rs:122-170` and shutdown path, every `IngestContext { … }` literal (≈15 across server tests, e2e tests, bench).

**Interfaces:**
- Consumes: `ExporterConfig`, `validate_exporters`, `build_exporters`, `ExportHub` (Tasks 1–5).
- Produces:
  - `ServerConfig.exporters: Vec<osiris_export::ExporterConfig>` with `#[serde(default)]`; `ServerConfig::load` calls `validate_exporters` and maps errors into `ConfigError`.
  - `IngestContext.exporters: Option<Arc<osiris_export::ExportHub>>` (all existing literals get `exporters: None`).
  - In `ingest`: the blocking closure classifies each event — `event_owner(id)` `None` and first occurrence of that id in this batch → *new*; `Some(owner) == host` or repeated id → *resent* (still kept for storage as today). It returns `(report, new_events: Vec<CanonicalEvent>, export_alerts: Vec<Alert>)` where `export_alerts` = alerts whose `evidence()` contains at least one new event id. After the whole closure succeeds: `if let Some(hub) = &self.exporters { hub.offer(&new_events, &export_alerts) }` — next to the broadcaster publish.
  - Broadcaster: publish the **kept** set instead of the arrived batch (spec §5.4 last paragraph). Test it.
  - `main.rs`: when `config.exporters` is non-empty, `build_exporters(&config.exporters, env!("CARGO_PKG_VERSION"))` (error → `eprintln!` + exit 1, like other config errors), `ExportHub::start(.., Some(tenant_store.clone()), cancellation.clone())`, put it in `IngestContext` and keep a clone for the API (Task 7). On shutdown, `hub.shutdown().await` after ingestion loops stop. Log one `info!` per exporter at startup (name, kind, destination host only).

- [ ] **Step 1: Write failing tests** in `ingest.rs` tests (fake exporter registered through `ExportHub::start`; reuse `test_engines`):
  - `ingest_offers_new_events_and_their_alerts_to_the_hub` (rule-matching event → hub receives 1 event + 1 alert).
  - `a_resent_batch_exports_nothing` (ingest same batch twice → second time 0 records offered; storage alert count is whatever detection does today — do not assert it changed).
  - `an_event_id_repeated_inside_one_batch_is_exported_once` (Review Focus 3).
  - `owner_collision_events_are_neither_exported_nor_broadcast`.
  - `a_stuck_exporter_does_not_slow_ingest` (fake exporter sleeps forever; 20 ingests each complete in < 500 ms wall — use real time, generous bound).
  - `ingest_without_exporters_is_unchanged` (Review Focus 5; `exporters: None` path passes the existing assertions).
  - `config.rs`: `loads_a_config_with_exporters`, `rejects_an_invalid_exporter_at_load`.
- [ ] **Step 2: Run** `cargo test -p osiris-server` — FAIL.
- [ ] **Step 3: Implement**, then update every `IngestContext` literal (`grep -rn "IngestContext {" crates`).
- [ ] **Step 4: Run** `cargo test --workspace` — PASS; `cargo clippy --workspace --all-targets -- -D warnings` — clean; `bash tools/check-dep-graph.sh` — exit 0.
- [ ] **Step 5: Commit** `feat(12a): feed exporters from ingest with only new events`.

### Task 7: Status API, CLI and in-process end-to-end test

**Files:**
- Create: `crates/osiris-api/src/exporters.rs`, `crates/osiris-e2e-tests/tests/exporters.rs`
- Modify: `crates/osiris-api/src/{lib.rs,auth_middleware.rs}`, `crates/osiris-api/Cargo.toml`, `crates/osiris-server/src/main.rs` (router merge), `crates/osiris-cli/src/{main.rs,client.rs}`

**Interfaces:**
- Consumes: `ExportHub::status() -> Vec<ExporterStatus>` (Task 3), `IngestContext.exporters` (Task 6).
- Produces:
  - `pub struct ExportersState { pub hub: Option<Arc<osiris_export::ExportHub>> }`, `pub fn build_exporters_router(state: ExportersState) -> Router` serving `GET /api/v1/exporters` → `200 {"exporters": [ExporterStatus…]}` (empty array when `hub` is `None`).
  - `min_role_for`: `/api/v1/exporters` → `Role::Admin`. `tenant_route_allowed` already denies by default — add a test, not an allow-list entry.
  - CLI: `osiris exporters status [--json]` → `GET {server}/api/v1/exporters` with the cached token; `pub fn format_exporters_table(body: &serde_json::Value) -> String` in `client.rs`, columns `NAME KIND STATE QUEUED SENT DROPPED LAST_ERROR` where `DROPPED = dropped_queue_full + dropped_after_retries + dropped_permanent`; `--json` prints the body pretty-printed.

- [ ] **Step 1: Write failing tests**:
  - `osiris-api`: `exporters_endpoint_returns_empty_list_when_none_configured` (Review Focus 5), `exporters_endpoint_requires_platform_admin` (Viewer → 403, Analyst → 403, Admin → 200), `tenant_admin_cannot_read_exporters` (tenant-bound Admin → 403), `exporters_endpoint_never_returns_secrets` (hub built with a webhook whose headers file holds `SECRET`; body does not contain `SECRET`).
  - `osiris-cli`: `format_exporters_table_sums_drops`, CLI parse test like the existing `Command::Hosts` one.
  - `osiris-e2e-tests/tests/exporters.rs`: `event_and_alert_reach_file_and_webhook_exporters` — in-process server pieces wired like the existing end-to-end tests (real `IngestContext`, real rules from `rules/`, real auth router + `build_exporters_router`), a `file` NDJSON exporter in a tempdir and a `webhook` exporter to an axum receiver on loopback with HMAC; ingest an event that fires a shipped rule; within 5 s assert both sinks hold the event (by `event_id`) and the alert (by `rule_id`), the receiver's HMAC check passed, and `GET /api/v1/exporters` (admin token) shows `sent_records >= 2` for both.
- [ ] **Step 2: Run** the new tests — FAIL.
- [ ] **Step 3: Implement**; merge the router in `main.rs` next to `build_fleet_router`.
- [ ] **Step 4: Run** `cargo test --workspace` — PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(12a): exporters status endpoint and cli`.

### Task 8: Real-binary test, bench, docs, ADR

**Files:**
- Modify: `crates/osiris-real-linux-tests/src/{stack.rs,render.rs}`, `crates/osiris-bench/src/{main.rs,ingest.rs}`, `PERFORMANCE.md`, `docs/ROADMAP-REMAINING.md`
- Create: `crates/osiris-real-linux-tests/tests/exporters_binary.rs`, `docs/operators-exporters.md`, `docs/adr/ADR-012-exporters.md`

**Interfaces:**
- Consumes: everything above.
- Produces: `StackOptions.exporters_yaml: Option<String>` — appended verbatim under an `exporters:` key in the rendered `server.yaml` (`ServerYaml` gains the same field); `osiris-bench ingest --exporters` flag that starts three local sinks (a file exporter, a TCP listener that drains and discards for syslog-tcp, an axum webhook receiver returning 200) and configures the stack with them.

- [ ] **Step 1: Write the binary test** `exporters_binary.rs` (not `cfg(linux)`; server-only stack; `#[ignore]` like the crate's other tests because it needs built binaries): start the stack with a file NDJSON exporter, append an event line to the stack's server spool (`stack.spool_path()`), wait (≤ 10 s) for the line to appear in the export file, then `stack.api_get("/api/v1/exporters")` shows `sent_records >= 1` and `state == "OK"`.
- [ ] **Step 2: Run** `cargo build -p osiris-server -p osiris-cli && cargo test -p osiris-real-linux-tests --test exporters_binary -- --ignored` — PASS (after implementing the `StackOptions` field).
- [ ] **Step 3: Implement the bench flag**, run `osiris-bench ingest` with and without `--exporters` at the same rate/duration the existing ingest bench documents in PERFORMANCE.md (on this Windows host; label the host); record both results and the delta in a new "Phase 12a — exporter overhead" section of PERFORMANCE.md. No target; report honestly.
- [ ] **Step 4: Write `docs/operators-exporters.md`**: config reference (every field, default, kind), the four formats with one example output each, the full CEF extension map and CSV columns, delivery guarantees (best effort; at most once per successful send; bounded memory; resends export nothing; partial-failure gap; tenant 10 s window; no disk spool), TLS rules (verification always on, `server_name`, loopback-only http), secrets handling, the status endpoint/CLI and what each counter means, troubleshooting (DEGRADED, drops).
- [ ] **Step 5: Write `docs/adr/ADR-012-exporters.md`** (follow ADR-011's layout): context, decision (in-server hub, best-effort bounded queues, OTLP JSON over HTTP, no Kafka), consequences incl. known gaps (partial-failure batch not exported; duplicate alerts on resend still stored; tenant move window), alternatives rejected (disk spool, OTLP protobuf/gRPC, Kafka via librdkafka).
- [ ] **Step 6: Update `docs/ROADMAP-REMAINING.md`**: mark the exporter part of Fase 12 done (12a), keep WASM plugins as 12b, add debts: duplicate alerts on resend; push notification from tenant store; Kafka/object storage; OTLP metrics.
- [ ] **Step 7: Full gates**: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `bash tools/check-dep-graph.sh`, `cd console && npm run lint && npm test && npm run build`. All green.
- [ ] **Step 8: Commit** `docs(12a): exporters operator guide, ADR-012, bench results`.
