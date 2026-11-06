# Exporters: sending events and alerts to a SIEM, a log pipeline or a collector

Phase 12a. The server can forward every event and alert it ingests to outside systems. This guide
covers the configuration, the output formats, what delivery does and does not guarantee, TLS and
secrets, and how to see what is happening. Design: `docs/superpowers/specs/2026-11-05-phase-12a-exporters-design.md`.
Decision record: `docs/adr/ADR-012-exporters.md`. Overhead measurement: `PERFORMANCE.md`,
"Phase 12a - exporter overhead".

Exporters run **inside `osiris-server`** only. The Agent does not link them and needs no change.

## Quick start

Add an `exporters:` list to the server YAML. With no `exporters:` key (or an empty list) the server
starts no exporter code at all and ingestion is unchanged.

```yaml
exporters:
  - name: siem-syslog
    kind: syslog
    address: 'siem.example.com:6514'
    transport: tls
    format: cef
    ca_file: /etc/osiris/siem-ca.pem
    min_severity: medium

  - name: archive
    kind: file
    path: /var/log/osiris/export.ndjson
    format: ndjson
```

Then restart the server. Exporters are read at startup; there is no runtime reconfiguration. A
bad entry (unknown key, bad value, duplicate name) stops the server at startup with a message that
names the exporter. A destination that is merely unreachable does **not** stop startup: that
exporter starts as `OK` and reports `DEGRADED` only after its first send fails (see
"Troubleshooting").

Check it:

```
osiris exporters status
curl -H "Authorization: Bearer $TOKEN" https://server:8080/api/v1/exporters
```

## Configuration reference

An exporter entry is one flat YAML mapping: `name`, `kind`, the common fields and the fields of its
kind side by side. Unknown keys are rejected. Names are unique and match `[a-z0-9_-]{1,64}`.

### Common fields (every kind)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | Unique name, `[a-z0-9_-]{1,64}`. Shown in status and logs. |
| `kind` | string | required | `file`, `syslog`, `otlp` or `webhook`. |
| `streams` | list | `[events, alerts]` | Which record kinds to send. May not be empty. |
| `min_severity` | string | `info` | Drop records below this: `info`, `low`, `medium`, `high`, `critical` (any case). Applies to events and alerts. |
| `event_types` | list | all | Allow-list of event types (for example `PROCESS_EXEC`). Applies to events only; alerts ignore it. |
| `tenant_id` | UUID | none (all hosts) | Send only records of hosts that belong to this tenant (see "Tenant filter"). |
| `include_raw` | bool | `false` | Include the event's `raw_event` bytes, base64-encoded, in NDJSON-based output. An event that has no raw event yields `"raw_event": null`. |
| `queue_capacity` | integer | `10000` | Records the exporter's in-memory queue holds. Must be greater than 0 and at most `1000000`. |
| `batch_max` | integer | `500` | Records per send. Must be greater than 0 and not larger than `queue_capacity`. |
| `flush_interval_ms` | integer | `1000` | Send a partial batch after this long. Must be greater than 0. |
| `max_retries` | integer | `5` | Retries of one batch after a transient failure. Backoff is 0.5 s doubling to a 30 s cap, with about 20 % jitter. |

### `kind: file`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `path` | path | required | The active file. Created if missing, appended to if present. |
| `format` | string | `ndjson` | `ndjson` or `csv`. |
| `max_bytes` | integer | 104857600 (100 MiB) | Rotate when the next record would pass this size. Must be greater than 0. |
| `max_files` | integer | `5` | Rotated files kept. Must be greater than 0. |

Rotation renames `path` to `path.1`, `path.1` to `path.2` and so on up to `path.<max_files>`; the
oldest is deleted. On Unix the files are created with mode 0600. `csv` needs `streams` to hold
exactly one stream, because events and alerts have different columns. The CSV header row is written
whenever a file starts empty, including after each rotation. A write error (disk full, permission)
is transient: the exporter goes `DEGRADED` and retries.

### `kind: syslog`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `address` | string | required | `host:port` (IPv6 in brackets: `[::1]:514`). Port 1-65535. |
| `transport` | string | required | `udp`, `tcp` or `tls`. |
| `format` | string | `rfc5424` | `rfc5424` or `cef`. |
| `facility` | string | `local0` | `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0` to `local7`. |
| `app_name` | string | `osiris` | RFC 5424 APP-NAME: 1-48 printable ASCII characters, no spaces. |
| `ca_file` | path | none | `tls` only. PEM file with extra trusted roots (added to the OS roots). |
| `client_cert`, `client_key` | path | none | `tls` only. PEM pair for mutual TLS. Both or neither. |
| `server_name` | string | host of `address` | `tls` only. Name to verify the server certificate against, for when `address` is an IP or differs from the certificate name. Verification stays on. |

TCP and TLS use RFC 6587 octet-counting framing (`<length> <message>`). UDP sends one message per
datagram, cut at 8192 bytes (at a UTF-8 boundary); each cut message is sent anyway and counted in
`truncated`. TCP and TLS connect and write with a fixed 10 s timeout (not configurable); a
destination that accepts the connection but never reads is treated as a transient failure. The
connection is re-opened on the next batch after any failure.

`ca_file`, `client_cert`, `client_key` and `server_name` are only used with `transport: tls`.
(They are not rejected on `udp`/`tcp`; they are ignored there.)

### `kind: otlp`

OpenTelemetry logs over OTLP/HTTP with the JSON encoding (`POST`, `Content-Type: application/json`).

| Field | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | URL | required | For example `https://collector:4318/v1/logs`. |
| `headers_file` | path | none | One `Name: value` per line (blank lines and `#` comments skipped). For auth headers. |
| `ca_file` | path | none | PEM file with extra trusted roots. |
| `client_cert`, `client_key` | path | none | PEM pair for mutual TLS. Both or neither. |
| `timeout_secs` | integer | `10` | Whole-request timeout. Must be greater than 0. |

### `kind: webhook`

`POST` of an NDJSON batch (`Content-Type: application/x-ndjson`), one record per line.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `url` | URL | required | Destination. |
| `hmac_key_file` | path | none | If set, each request carries `X-Osiris-Signature: sha256=<hex>`, the HMAC-SHA256 of the request body. One trailing newline in the key file is ignored. The file must not be empty. |
| `headers_file` | path | none | As for `otlp`. |
| `ca_file` | path | none | PEM file with extra trusted roots. |
| `client_cert`, `client_key` | path | none | PEM pair for mutual TLS. Both or neither. (An addition to the original design, also available on `otlp`.) |
| `timeout_secs` | integer | `10` | Whole-request timeout. Must be greater than 0. |

HTTP status handling for `otlp` and `webhook`: 2xx is success; 408, 429 and 5xx are transient
(retried); any other status is permanent (the batch is dropped and counted). Redirects are not
followed. For `otlp`, a 2xx reply with `partialSuccess.rejectedLogRecords` counts those records as
`dropped_permanent` and the rest as sent.

## Output formats

All formats are deterministic. The same record always renders the same bytes (golden-tested in
`crates/osiris-export/tests/golden/`). Every NDJSON object carries `record_type` (`event` or
`alert`).

### NDJSON

One JSON object per line: the record's own JSON (the same shape the API returns) plus
`record_type`. The object is also the message of RFC 5424 output, the body string of OTLP records
and the line of webhook bodies. `raw_event` is removed unless `include_raw` is true; when included
it is a standard, padded base64 string, not the API's array of numbers; an event that has no raw event
keeps `"raw_event": null` (the field is present, not omitted). CEF and CSV never carry
`raw_event`.

```
{"boot_id":"boot-1","category":"PROCESS",...,"event_id":"aaaaaaaa-0000-4000-8000-000000000001","event_type":"PROCESS_EXEC",...,"record_type":"event","severity":"HIGH","source":"EBPF","tags":["suspicious","net"],"timestamp":1762300800123456789,"user":{...}}
```

### CSV

RFC 4180: CRLF line ends, cells with a comma, quote, CR or LF are double-quoted with `"` doubled.
A cell that starts with `=`, `+`, `-`, `@`, tab or CR gets a leading `'` (spreadsheet formula
injection guard).

Event columns:

```
timestamp,event_id,host_id,hostname,event_type,category,severity,pid,exe_path,user,file_path,src_ip,src_port,dst_ip,dst_port,dns_query,tags
2025-11-05T00:00:00.123456789Z,aaaaaaaa-0000-4000-8000-000000000001,11111111-1111-4111-8111-111111111111,web-01,PROCESS_EXEC,PROCESS,HIGH,4242,/usr/bin/curl,alice,,,,,,,suspicious net
```

`timestamp` is RFC 3339 UTC with nine fractional digits. `user` is the username, else the numeric
uid. `tags` are joined by a space. Fields an event does not have are empty.

Alert columns:

```
timestamp,alert_id,host_id,rule_id,rule_version,severity,status,reasons,evidence
```

`reasons` are joined by ` | `, `evidence` (event ids) by a space.

### RFC 5424 syslog

```
<131>1 2025-11-05T00:00:00.123456789Z web-01 osiris - PROCESS_EXEC [osiris@32473 record_type="event" id="aaaaaaaa-0000-4000-8000-000000000001" host_id="11111111-1111-4111-8111-111111111111"] {"boot_id":"boot-1",...}
```

- PRI = facility x 8 + severity. Severity map: critical 2, high 3, medium 4, low 5, info 6.
- HOSTNAME is the event's host name; an alert carries only a host id, so alerts use the host id.
- MSGID is the event type, or `ALERT`.
- Structured data is `[osiris@32473 record_type=... id=... host_id=...]`. 32473 is the IANA
  documentation enterprise number; if you need your own, it is a constant in
  `crates/osiris-export/src/format/syslog.rs`.
- MSG is the NDJSON object.
- Spaces and control characters in HOSTNAME, APP-NAME and MSGID are replaced with `_`, so one
  record is always one frame. A non-ASCII (UTF-8) host name passes through unchanged, which is
  outside the strict RFC 5424 HOSTNAME grammar; most collectors accept it. If yours does not, use
  ASCII host names or the NDJSON/file path.

### CEF

CEF inside an RFC 5424 envelope (same PRI, HOSTNAME, MSGID and structured data as above):

```
<131>1 2025-11-05T00:00:00.123456789Z web-01 osiris - PROCESS_EXEC [osiris@32473 ...] CEF:0|OSIRIS|OSIRIS|0.12.0|PROCESS_EXEC|PROCESS_EXEC|8|rt=1762300800123 dvchost=web-01 cs1Label=hostId cs1=11111111-1111-4111-8111-111111111111 cs2Label=eventId cs2=aaaaaaaa-0000-4000-8000-000000000001 cat=PROCESS spid=4242 sproc=/usr/bin/curl suser=alice cs3Label=tags cs3=suspicious net
```

Header: `CEF:0|OSIRIS|OSIRIS|<server version>|<signature>|<name>|<severity>|<extension>`.

| Header field | Event | Alert |
|---|---|---|
| signature | `event_type` | `rule_id` |
| name | `event_type` | first reason (the `rule_id` if there is none) |
| severity | info 1, low 3, medium 5, high 8, critical 10 | same |

Extension keys:

| CEF key | Source | Records |
|---|---|---|
| `rt` | record timestamp, epoch milliseconds | all |
| `dvchost` | event host name (alert: host id) | all |
| `cs1` / `cs1Label=hostId` | host id | all |
| `cs2` / `cs2Label=eventId` or `alertId` | event id / alert id | all |
| `cat` | event category | events |
| `spid` | process pid | events with a process |
| `sproc` | process executable path | events with a process |
| `suser` | username, else numeric uid | events with a user |
| `filePath` | file path | file events |
| `fname` | file base name | file events |
| `src` / `spt` | source IP / port | network events |
| `dst` / `dpt` | destination IP / port | network events |
| `proto` | network protocol | network events |
| `msg` | `DNS query <name>` for DNS events; the reasons joined by ` \| ` for alerts | DNS events, alerts |
| `cs3` / `cs3Label=tags` | tags joined by a space | events with tags |
| `cs3` / `cs3Label=evidence` | evidence event ids joined by a space | alerts |
| `cs4` / `cs4Label=alertStatus` | alert status | alerts |
| `cn1` / `cn1Label=ruleVersion` | rule version | alerts |

Escaping follows the CEF rules: in the header `\`, `|`, newline and carriage return are escaped; in
extension values `\`, `=`, newline and carriage return are escaped. The product version is the
`osiris-server` version.

### OTLP logs (JSON)

An `ExportLogsServiceRequest` per batch, one `ResourceLogs` per host in the batch (first-seen
order). Resource attributes: `host.id`, `host.name`, `service.name = osiris`. Scope name:
`osiris-export`. One `LogRecord` per record:

| LogRecord field | Value |
|---|---|
| `timeUnixNano` | record timestamp (string) |
| `observedTimeUnixNano` | server time at send (string) |
| `severityNumber` | info 9, low 10, medium 13, high 17, critical 21 |
| `severityText` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `body.stringValue` | the NDJSON object |
| attributes | `osiris.record_type`; `osiris.event_type` and `osiris.event_id` (events) or `osiris.rule_id` and `osiris.alert_id` (alerts) |

Only logs, only the JSON encoding. There is no protobuf, no gRPC and no OTLP metrics or traces.

## Delivery guarantees

Read this before relying on exporters for compliance.

- **Best effort, at most once per successful send, bounded memory.** Each exporter has an in-memory
  queue of `queue_capacity` records and one worker. There is **no disk spool**: a server restart or
  crash loses what is queued.
- **Ingestion is never affected.** Ingest does a non-blocking enqueue only. A dead SIEM, a full
  disk, a slow webhook or a panicking exporter cannot delay or fail a storage write, detection or
  the live stream.
- **Every loss is counted.** A full queue drops the new record and counts `dropped_queue_full`. A
  batch that fails more than `max_retries` times counts `dropped_after_retries`. A permanent
  failure counts `dropped_permanent`. A rate-limited warning (at most one per exporter per minute)
  is logged with the counters. While one batch is retrying the queue keeps filling, so a dead
  destination holds at most about `queue_capacity + batch_max` records per exporter.
- **Order** is preserved within one exporter. There is no ordering across exporters.
- **Resends export nothing.** The Agent resends a batch until the server acknowledges it. Storage
  skips the duplicates; exporters also receive only the events that are new in the batch, and only
  the alerts whose evidence includes at least one new event of the batch. A pure resend exports
  nothing. (The duplicate alerts that detection creates for a resend are still stored; see the
  ADR's known gaps.)
- **Partial failure gap.** Ingest does several storage writes. If a later write fails, the earlier
  ones stay stored but nothing is exported for that batch, and the spool path does not retry it.
  Those records are never exported.
- **At-least-once within a batch.** If a send fails after part of a batch was already written, the
  retry sends the whole batch again. For `file` (some lines already written) and `udp` (some
  datagrams already sent) that can duplicate lines on the receiving side. Receivers that need
  exactness should de-duplicate on `event_id` / `alert_id`, which every format carries.
- **Panics.** A panic in an exporter is caught and counted (`panics`); the batch is counted
  `dropped_permanent` and the exporter keeps working.
- **Shutdown.** On shutdown the server first stops its ingestion loops (so nothing new is offered),
  then gives the exporters up to 5 s to flush what they hold and what is queued, with one attempt
  per batch and no retries. Whatever is not delivered in that time is counted
  `dropped_after_retries` and the exporter ends `STOPPED`. Records offered after the hub has shut
  down are counted as `dropped_queue_full` (the name is a little off for that case).
- **Failed startup.** Ingestion starts before the server's later startup checks (API TLS, port
  binds). If one of them fails and the process exits, records offered in that window can be lost
  without being counted, and on the next start the Agent resends them (see the ADR).

### Tenant filter

With `tenant_id` set, an exporter sends only records of hosts that belong to that tenant. The
host set is loaded at startup and refreshed every 10 s. A host that has never been in the tenant is
never exported. A host moved **out** of the tenant can still be exported for up to 10 s after the
move. A host moved in is exported from the next refresh on. If the tenant store cannot be read the
previous set is kept and an error is logged. Until the first load completes, a tenant-scoped
exporter exports nothing.

An exporter without `tenant_id` sees every tenant's records. This is why the status endpoint is
for platform admins only.

## TLS rules

- Certificate verification is **always on**. No setting turns it off.
- `transport: tls` (syslog) and `https://` (otlp, webhook) never fall back to plaintext.
- Trust is the OS root store plus every certificate in `ca_file`. Use `ca_file` for a private CA.
- The name verified is the host of `address`/`url`. If you connect by IP or the certificate carries
  a different name, set `server_name` (syslog). The HTTP exporters verify the host of the URL.
- Plain `http://` is accepted for `otlp` and `webhook` **only** for loopback hosts (`127.0.0.0/8`,
  `::1`, `localhost`), for example a local collector. Any other `http://` URL fails config load.
  `udp` and `tcp` syslog are plaintext by nature: use `tls` across networks.
- `client_cert` and `client_key` enable mutual TLS and must be given together.
- The HTTP exporters never use a proxy: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are ignored, so
  exporter headers are never sent to a proxy. The destination must be reachable directly.

## Secrets

- Tokens and credentials come from **files**, never inline: `headers_file` (for example
  `Authorization: Bearer ...`), `hmac_key_file`, `client_key`. Restrict them to the user that runs
  the server (mode 0600).
- URLs with userinfo (`https://user:pass@host/`) or a fragment are rejected at config load. Use
  `headers_file` for credentials. A query string is allowed, but it is a secret in your config file
  if you put one there: it is never printed in logs, errors or the status endpoint.
- Secrets never appear in logs, `Debug` output, `last_error` or the status endpoint. `last_error`
  names the destination host at most.
- Do not set `Content-Type` in a `headers_file`. The exporter always sets its own
  (`application/json` or `application/x-ndjson`); a second line from the file results in a
  duplicate `Content-Type` header, which some servers reject.
- A header or HMAC file that cannot be read, or has an invalid line, fails startup (the message
  names the line number, never its content).

## Status endpoint and CLI

`GET /api/v1/exporters` (platform `admin` role only) returns:

```json
{ "exporters": [ {
  "name": "siem-syslog", "kind": "syslog", "state": "OK", "queued": 0,
  "sent_records": 1520, "sent_batches": 4, "send_errors": 0,
  "dropped_queue_full": 0, "dropped_after_retries": 0, "dropped_permanent": 0,
  "truncated": 0, "panics": 0,
  "last_success_at": 1762300801123456789, "last_error": null
} ] }
```

With no exporters configured the body is `{"exporters": []}`.

`osiris exporters status` prints a table (`NAME KIND STATE QUEUED SENT DROPPED LAST_ERROR`, tab
separated; `DROPPED` is the sum of the three drop counters); `--json` prints the API body. It
uses the cached login token (or `OSIRIS_TOKEN`) and `--server`.

| Field | Meaning |
|---|---|
| `state` | `OK`: the last send worked (or none has been tried yet). `DEGRADED`: the last send failed. `STOPPED`: shut down. |
| `queued` | Records waiting in the queue now. |
| `sent_records` | Records the destination accepted. |
| `sent_batches` | Successful sends. |
| `send_errors` | Failed send attempts. Every failed attempt counts, including each retry of one batch and including permanent failures. |
| `dropped_queue_full` | Records dropped because the queue was full (also: offers after shutdown). |
| `dropped_after_retries` | Records dropped after `max_retries` failures, or not flushed at shutdown. |
| `dropped_permanent` | Records dropped without retry: a permanent error (such as HTTP 400), a panic, or records an OTLP collector reported as rejected. |
| `truncated` | UDP messages cut at 8192 bytes (they were still sent). |
| `panics` | Exporter panics caught. |
| `last_success_at` | Unix time in nanoseconds of the last successful send. |
| `last_error` | Last failure message, destination host only; `null` if none. It is kept after recovery. |

Counters reset when the server restarts.

## Troubleshooting

- **`DEGRADED`, `last_error` set.** The last send failed. Read `last_error`: `connect error`,
  `timeout`, `tls handshake ... failed`, `503 from host`. The exporter keeps retrying each new
  batch and returns to `OK` on the first success; `last_error` stays as history. `send_errors`
  rising while `sent_records` stands still means the destination is down or unreachable.
- **`tls handshake` failures.** Unknown issuer: add the CA to `ca_file`. Name mismatch: set
  `server_name` (syslog) or use the hostname the certificate was issued for. Check the server's
  clock.
- **`queued` stays high, `dropped_queue_full` rising.** The destination is slower than ingest. Raise
  `queue_capacity` (memory: roughly the record size times the capacity), raise `batch_max`, narrow
  the exporter with `min_severity`, `event_types` or `streams`, or fix the destination.
- **`dropped_after_retries` rising.** A destination was down longer than the retries last
  (about 0.5 + 1 + 2 + 4 + 8 seconds with the defaults, roughly 15 s). Raise `max_retries`. Dropped
  records are not replayed. Note that while a batch retries, new records queue behind it and may
  overflow (`dropped_queue_full`).
- **`dropped_permanent` rising.** The destination rejects the data: a 4xx from a webhook/collector
  (bad token in `headers_file`, wrong path, payload too large) or rejected OTLP records. The
  `last_error` carries the status.
- **`truncated` rising.** UDP messages over 8192 bytes. Use `tcp`/`tls`, or drop `include_raw`.
- **Nothing arrives and no errors.** Check the filters (`min_severity`, `event_types`, `streams`,
  `tenant_id`). A tenant-scoped exporter exports nothing until the tenant's host set has loaded
  (a few seconds after start) and for hosts outside the tenant.
- **Duplicates at the receiver.** See "At-least-once within a batch". De-duplicate on the id.
- **Server will not start.** The log names the exporter and the field. URLs are never echoed.
