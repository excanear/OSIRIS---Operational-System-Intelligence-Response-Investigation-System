# Operating OSIRIS on ClickHouse

SQLite remains the default storage backend. ClickHouse is opt-in and holds
the telemetry tables: events, alerts, entity relationships and risk scores.

## Tested version

The backend is developed and tested against ClickHouse **26.3.60.2** (LTS).
CI runs the full `Storage` conformance suite and a server end-to-end test
against exactly that image. Other versions are untested.

## Enabling it

Add to the Server config (`server.yaml`):

```yaml
storage_backend: clickhouse
clickhouse:
  url: http://clickhouse.internal:8123   # HTTP interface, no credentials in the URL
  database: osiris                       # default; must match ^[A-Za-z_][A-Za-z0-9_]{0,63}$
  user: osiris                           # default: "default"
  password_file: /etc/osiris/clickhouse.pass   # optional
  timeout_secs: 30                       # default 30, valid 1..=600
```

- `storage_backend` defaults to `sqlite`. A `clickhouse:` section is ignored
  unless `storage_backend: clickhouse`.
- `storage_backend: clickhouse` without a `clickhouse:` section is a config
  error.
- On startup the Server creates the database and tables if absent and
  checks the recorded schema version. If ClickHouse is unreachable, the
  credentials are wrong, or the schema step fails, the Server **exits with an
  error**. It never falls back to SQLite.

## Password

The password is read from the file named by `password_file`, never from the
config inline. A trailing newline in the file is trimmed. Restrict the file
(for example `chmod 600`, owned by the Server user). An unreadable file is a
startup error that names the path; error messages never contain the password.

## Single writer

Run **one** Server process per ClickHouse database. ClickHouse has no unique
constraints, so write-once semantics on ids are enforced under a
process-local writer lock. Two Servers writing the same database can store
duplicate rows.

## What stays on SQLite

Only the telemetry tables move. The control-plane stores keep their own
SQLite files regardless of the backend: baseline, incidents, evidence,
evidence-incident links, users and sessions, tenants, and the host registry
(`baseline_db_path`, `incidents_db_path`, `evidence_db_path`, `links_db_path`,
`users_db_path`, `tenants_db_path`, `hosts_db_path`).

## Migration

There is no SQLite to ClickHouse migration tool. Switching the backend starts
with an empty ClickHouse database; existing SQLite telemetry is not copied.

## Development server

`tools/clickhouse/dev-server.sh` runs the pinned ClickHouse version locally
(for WSL: `wsl -d Ubuntu-24.04 -- bash tools/clickhouse/dev-server.sh`). Then:

```sh
export OSIRIS_CLICKHOUSE_URL=http://127.0.0.1:8123
cargo test -p osiris-storage-clickhouse -- --include-ignored
cargo test -p osiris-e2e-tests --test clickhouse_backend -- --include-ignored
```

These tests are `#[ignore]`d and panic with a clear message if run without
`OSIRIS_CLICKHOUSE_URL`. Each test uses its own uniquely named database and
drops it afterwards.
