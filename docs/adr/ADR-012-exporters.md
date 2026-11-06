# ADR-012: Exporters run in the server, deliver best effort from bounded queues, and speak OTLP JSON over HTTP

Status: accepted, 2026-11-06 (Phase 12a). Implements ARCHITECTURE.md §20.1/§20.3 (the `Exporter`
consumer of the post-ingestion stream). Spec: `docs/superpowers/specs/2026-11-05-phase-12a-exporters-design.md`.
Operator guide: `docs/operators-exporters.md`. Measurements: `PERFORMANCE.md`, "Phase 12a - exporter overhead".

## Context

OSIRIS keeps everything inside its own storage, API and console. Real deployments already run a
SIEM, a log pipeline or an OpenTelemetry collector and want events and alerts there too.
ARCHITECTURE §20.3 names the v1 set: file sinks, Syslog/CEF over UDP/TCP/TLS and OTLP logs, with
Kafka, webhook and object storage as structurally identical, deferred implementations. The
constraints that shape the design:

- Ingestion is the product's hot path. An exporter must never slow it, fail it or hold a lock it
  needs.
- The Agent must not gain code or dependencies; exporting is a Server concern.
- The workspace builds and tests on Windows, with no extra toolchain (no C compiler for a Kafka
  client, no protobuf compiler).
- Destinations are often down, slow or stuck. Memory must stay bounded when they are.

## Decision

1. **A new server-side crate, `osiris-export`, with an in-process `ExportHub`.** The hub is built by
   `osiris-server` only when `exporters:` is non-empty and is fed from `IngestContext::ingest` right
   after the batch's storage writes succeed (the point where the live broadcast fires). It depends
   on `osiris-schema` and `osiris-tenancy` only; `tools/check-dep-graph.sh` fails the build if the
   Agent ever depends on it. No hub means no worker tasks and an unchanged ingest path.
2. **Best-effort delivery from bounded in-memory queues.** Each exporter has one bounded queue and
   one worker task. `offer` filters, wraps each kept record in an `Arc` once, and `try_send`s it; a
   full queue drops the record and counts it. The worker batches (`batch_max`, `flush_interval_ms`),
   retries transient errors with jittered exponential backoff (0.5 s to 30 s), then drops and counts.
   Every loss has a counter and a rate-limited warning. Memory per exporter is bounded by
   `queue_capacity + batch_max` records. A panic in an exporter is caught by the task join, counted,
   and does not reach ingest.
3. **Exporters get only new data.** The Agent resends a batch until acknowledged, so ingest sees the
   same events twice. Exporters receive only events that are new in the batch (`event_owner` was
   `None`) and only alerts whose evidence includes a new event, so a pure resend exports nothing.
4. **OTLP as JSON over HTTP, logs only.** Every collector accepts OTLP/HTTP JSON. It needs no
   protobuf compiler, no `prost`, no gRPC stack. The NDJSON object rides as the log body.
5. **Hand-rolled formats and transports on the workspace stack.** NDJSON, RFC 4180 CSV, RFC 5424
   and CEF are pure, golden-tested functions (no `csv` crate). HTTP uses the workspace `reqwest`
   (rustls); syslog TLS uses the workspace `tokio-rustls`. New dependencies are `hmac`, `base64` and
   `rustls-native-certs` (the first two were already in `Cargo.lock`).
6. **TLS cannot be weakened.** Verification is always on, there is no knob to disable it, `tls` and
   `https` never fall back to plaintext, and plain `http://` is accepted only for loopback hosts.
   Credentials come from files; URLs with userinfo or a fragment are rejected at config load; no
   secret reaches logs, `Debug`, `last_error` or the status endpoint.
7. **The hub is shut down after ingestion stops.** It has its own cancellation token. On shutdown
   the server cancels and joins the ingestion loops first (so nothing is offered afterwards), then
   gives the exporters a 5 s flush: one attempt per remaining batch, losses counted.
8. **No Kafka.** Not in 12a (see alternatives).
9. **Status is an API and a CLI, not a console screen.** `GET /api/v1/exporters` (platform admin
   only, because an unscoped exporter sees every tenant) and `osiris exporters status [--json]`.

Webhook and OTLP also accept `client_cert`/`client_key` (mutual TLS), beyond the original spec, so
the HTTP exporters have the same TLS options as syslog.

## Consequences

- With no `exporters:` configured nothing changes: no hub, no tasks, `/api/v1/exporters` returns
  `{"exporters": []}`.
- Delivery is **at most once per successful send**, with a bounded exception: a retried batch that
  was partly written can be delivered twice (file lines, UDP datagrams). Receivers de-duplicate on
  the event or alert id.
- A restart or crash loses whatever is queued. This is the price of having no disk spool, and it is
  documented for operators.
- An unreachable destination at startup does not stop the server; the exporter reports `DEGRADED`
  and retries. A malformed exporter entry does stop it.
- Operators get one stable shape per format, a documented CEF map, and per-exporter counters.
- The exporter overhead on ingest was measured (PERFORMANCE.md) rather than assumed.

## Known gaps (deferred)

- **Partial-failure batch is not exported.** Ingest is several separate storage writes. If a later
  one fails, the earlier data is stored, nothing is exported for the batch, and the spool path does
  not retry it. The live broadcast has the same behaviour.
- **Duplicate alerts on resend are still stored.** A resend exports nothing, but detection runs again
  and writes new alerts with new ids. Exporters are shielded; storage is not. Fixing it belongs in
  the ingest/detection path.
- **Tenant move window.** A host moved out of a tenant can be exported by that tenant's exporter for
  up to 10 s (the host-set refresh interval). A push notification from the tenant store would close
  it but needs a new `TenantStore` hook.
- **Records offered during a failed startup can be lost uncounted.** Spool ingestion starts before
  later fallible startup steps (API TLS setup, port binds, which end in `exit(1)`). Records offered
  to exporters in that window are lost with the process and are not counted, and on restart the
  Agent resends them, where they read as resends. The fix is to start ingestion after those checks.
- **Offers after shutdown are counted as `dropped_queue_full`.** The closed channel reuses that
  counter; the name is misleading for that case.
- **A hung tenant store accumulates blocking loads.** Each 10 s round starts a new load while an
  earlier one may still be outstanding (the blocking call cannot be cancelled).
- **Partly written batch plus retry duplicates.** See Consequences; a transactional file or UDP
  sender is not possible, so this is accepted.
- **Syslog TCP/TLS timeout is fixed at 10 s**, not configurable (the HTTP exporters use `timeout_secs`).
- **reqwest honours `HTTP(S)_PROXY`.** Exporter traffic follows the proxy environment of the server
  process; it is documented but not switched off.
- **A `Content-Type` line in a `headers_file`** produces a duplicate header.
- **Serialization failures render empty values** (an unserializable enum as `""`, a bad timestamp as
  the epoch) instead of failing the record; unreachable with the current schema.
- Not exported: risk scores, incidents, the audit log, relationships. No runtime reconfiguration.

## Alternatives rejected

- **A disk-backed spool with replay.** Would give at-least-once across restarts. It needs a format,
  a replay and compaction policy, disk-full behaviour and an ordering story across a restart, and it
  moves the failure from "dropped and counted" to "disk filled". A later phase can add it behind the
  same queue if someone needs the guarantee; the trait already allows it.
- **OTLP protobuf or gRPC.** Needs `prost`/`tonic` (a protobuf toolchain and a large dependency
  tree) for no gain at this scale; OTLP/HTTP JSON is accepted by every collector.
- **Kafka through librdkafka.** Requires a C toolchain on every build host including Windows, and
  the pure-Rust clients are immature. Deferred; it is a new `impl Exporter` when needed.
- **Exporting from the Agent.** Would multiply connections and credentials by the fleet size, put
  SIEM secrets on every host, and bypass the server's tenant and resend handling.
- **Blocking ingest on a full queue (backpressure).** Would let a dead SIEM stall detection and
  storage, the failure the design exists to prevent.
- **A single-document JSON array file.** Cannot be appended to safely; NDJSON covers it.

## Cost if wrong, and revisit triggers

| Decision | Cost if wrong | Revisit when |
|---|---|---|
| In-memory queues, no spool | Moderate: a restart or outage longer than the retries loses data. A spool slots in behind the same worker. | An operator needs at-least-once or compliance-grade delivery. |
| Hub inside the server | Low: the hub is one object behind `offer`. | Exporter load needs its own process or CPU isolation. |
| OTLP JSON only | Low: a second encoding is a new formatter. | A collector refuses JSON, or payload size matters. |
| Resend filtering via `event_owner` | Low. | Ingest changes how it tells new from resent. |
| Fixed 10 s syslog timeout | Low: one constant. | A slow link needs a longer value. |
| Tenant refresh polling | Low: a 10 s window. | Tenant moves must take effect at once (add the store hook). |
