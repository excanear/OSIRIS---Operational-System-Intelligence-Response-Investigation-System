# Phase 9d-1 Fleet Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `GET /api/v1/hosts`'s "any event in the last 24h" heuristic with a real agent registry backed by a genuine `AGENT_HEALTH` heartbeat, so "which hosts are in my fleet, and are they alive" is a real question with a real, reliable answer.

**Architecture:** New crate `osiris-fleet` (`HostRegistry` trait + `SqliteHostRegistry`, `hosts.db`, one-crate-per-subsystem pattern). Agent gains a periodic health task that aggregates already-collected `SensorHealth` via the already-existing (currently unused) `osiris_health::HealthAggregator`, wraps it in a new `RawEvent::AgentHealth` variant, and pushes it through the pipeline like any sensor event. Server's single ingestion choke point (`IngestContext::ingest`) upserts the registry whenever a batch contains an `AGENT_HEALTH` event. `GET /api/v1/hosts` moves to a new `build_fleet_router`/`FleetState` (mirroring `ResponseState`'s shape) reading the registry directly instead of querying `Storage`.

**Tech Stack:** Rust workspace, `rusqlite` (existing), `tokio` (existing), no new external dependencies.

**Spec:** `docs/superpowers/specs/2026-09-22-phase-9d1-fleet-manager-design.md` (read it first).

## Plan clarification (fills in what the spec left to plan-time)

The spec's §2.1 says the agent "builds one `CanonicalEvent` directly" and "pushes it into the same pipeline every sensor event already goes through." Investigating `osiris-pipeline`/`osiris-sensor-api` at plan time found there is no public entry point for pushing a pre-built `CanonicalEvent` in — every event enters via `Pipeline::process(raw: RawEvent) -> PrioritizedEvent`, where `RawEvent` is a closed 9-variant enum each normalized by its own `normalize_*` function in `crates/osiris-pipeline/src/normalize.rs`. Rather than inventing a bypass around that (which every other event type in this codebase goes through, including validation and prioritization), this plan adds `RawEvent::AgentHealth(AgentHealthRaw)` as a 10th variant and a matching `normalize_agent_health` function — the same integration shape every sensor already uses, not a special case. This does not change the spec's actual intent (no `CanonicalEvent` struct field addition, `event_data` still carries `agent_version`/`health`) — it's a plan-level detail about *how* the event reaches the pipeline, not *what* it contains.

`Source` (`osiris-schema`'s 7-variant enum: `Ebpf, Audit, Fanotify, Procfs, Dbus, ContainerApi, Synthetic`) has no variant that honestly describes "the agent's own internal state, not sensed from anything external." `Synthetic` is reserved for the demo/scenario generator (`osiris_generator`) and using it here would make a real health signal indistinguishable from generated demo data in `source`-filtered queries. This plan adds one new variant, `Source::AgentInternal`, exhaustively handled everywhere `Source` is matched (checked at plan time: only display/serialization sites, no logic branches on it — Task 4 verifies this with `cargo build` before touching call sites, since a missing match arm is a compile error, not a silent gap).

## Global Constraints

* Health interval config key: `fleet.health_interval_secs: u64`, default `60`, under a new `#[serde(default)] pub fleet: FleetConfig` field on `AgentConfig` (matching `cloud_metadata`/`k8s_context`'s existing `#[serde(default)]`-struct pattern, not `control`/`forward`'s `Option<...>` pattern, since fleet heartbeat is always-on, not opt-in).
* Server-side staleness threshold is a hardcoded constant, NOT read from any agent's config: `const EXPECTED_HEARTBEAT_INTERVAL_NS: u64 = 60 * 1_000_000_000` (matches the agent's own default), `status = ONLINE` if `now_ns() - last_seen <= 3 * EXPECTED_HEARTBEAT_INTERVAL_NS` else `STALE`. This is spec §5's explicitly documented limitation, not an oversight — do not make it configurable in this phase.
* `event_data` wire shape for `AGENT_HEALTH` events (the contract between Task 2's producer and Task 3's consumer — both sides implement independently against this, do not renegotiate mid-task):
  ```json
  { "agent_version": "0.1.0", "health": { "state": {"state": "HEALTHY"}, "sensors": [ {"sensor_name": "process_exec", "state": {"state": "HEALTHY"}, "events_processed": 42, "last_event_at": 1700000000000000000 } ] } }
  ```
  (`health` is exactly `serde_json::to_value(&osiris_health::AgentHealth)` — its `Serialize` impl already produces this shape via `#[serde(tag = "state", ...)]` on `HealthState`; do not hand-roll a different shape.)
* Every existing call site constructing `IngestContext` or calling `run_ingestion_loop` must be updated in the same task that changes their signature — the compiler enforces completeness, but each site's `Arc<dyn HostRegistry>` argument must be a real, opened `SqliteHostRegistry` in `main.rs` and a fresh in-memory-backed one per test in `end_to_end.rs` (never a shared/leaked one across tests).
* Before any commit: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (rebuild `osiris-cli osiris-server osiris-agent` first: `cargo build -p osiris-cli -p osiris-server -p osiris-agent`).
* Commit messages end with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.
* Model for subagents: `sonnet` (haiku is org-blocked on this account).
* This is tenant-scoping-adjacent code (Task 4 touches `GET /api/v1/hosts`, an existing tenant-scoped route) — its review should be opus, per this project's standing practice for anything touching the tenant boundary.

## Review Focus

* A batch with two `AGENT_HEALTH` events for the same `host_id` arriving out of timestamp order (e.g. redelivered/retried) — the registry's `last_seen` must reflect the newer timestamp, never regress to an older one just because it was upserted more recently in wall-clock time. (Task 1)
* `enrolled_at` must never change after the first upsert for a `host_id`, even across many subsequent heartbeats, a server restart, or a batch where that host's *first-ever* event isn't literally the first one processed. (Task 1)
* A batch containing one malformed `AGENT_HEALTH` event (missing/unparseable `event_data`) alongside otherwise-valid events must not fail the whole batch — that one event's registry upsert is skipped (logged), every other event (including its own underlying `CanonicalEvent`, which still has valid `host`/`timestamp` fields) is still written to `Storage` normally. (Task 3)
* A tenant user's `GET /api/v1/hosts` must never return another tenant's or a platform host's row, and a platform (non-tenant) caller sees everyone — reusing `hosts_of_tenant` incorrectly (e.g. applying it after building the response instead of before, or forgetting the `None` = unscoped case) is an easy way to leak or over-restrict. (Task 4)
* The ONLINE/STALE boundary is exact: a host whose `last_seen` is precisely `3 * EXPECTED_HEARTBEAT_INTERVAL_NS` old is STALE (the spec's `<=` for ONLINE means the boundary itself is the last ONLINE instant, one nanosecond older is STALE) — off-by-one here silently misreports fleet health. (Task 4)

---

### Task 1: `osiris-fleet` crate — `HostRegistry` trait + `SqliteHostRegistry`

**Files:**
- Create: `crates/osiris-fleet/Cargo.toml`, `crates/osiris-fleet/src/lib.rs`
- Modify: `Cargo.toml` (add `"crates/osiris-fleet"` to workspace `members`)

**Interfaces:**
- Produces (all `pub`, used by Task 3 and Task 4):
  - `pub struct HostRow { pub host_id: Uuid, pub hostname: String, pub distro: String, pub kernel_version: String, pub agent_version: String, pub enrolled_at: u64, pub last_seen: u64, pub health_state: osiris_health::HealthState }` (derive `Debug, Clone, PartialEq`)
  - `pub trait HostRegistry: Send + Sync { fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError>; fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError>; fn list(&self) -> Result<Vec<HostRow>, FleetError>; }`
  - `pub struct SqliteHostRegistry { /* private: Mutex<Connection> */ }` with `pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FleetError>`, implementing `HostRegistry`.
  - `pub enum FleetError { Io(String), Sqlite(String), Serde(String) }` (derive `Debug`, `thiserror::Error` with `#[error(...)]` per variant, `Display`).

- [ ] **Step 1: Cargo.toml**

```toml
[package]
name = "osiris-fleet"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
rusqlite = { workspace = true }
thiserror = { workspace = true }
osiris-health = { path = "../osiris-health" }

[dev-dependencies]
tempfile = { workspace = true }
```

Add `"crates/osiris-fleet",` to the root `Cargo.toml`'s `[workspace] members` list, alphabetically next to `"crates/osiris-evidence"`/`"crates/osiris-generator"` (check the existing list's ordering convention and match it).

- [ ] **Step 2: Failing tests** in `crates/osiris-fleet/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_health::HealthState;
    use uuid::Uuid;

    fn row(host_id: Uuid, last_seen: u64) -> HostRow {
        HostRow {
            host_id,
            hostname: "h1".into(),
            distro: "ubuntu-24.04".into(),
            kernel_version: "6.8.0".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: last_seen,
            last_seen,
            health_state: HealthState::Healthy,
        }
    }

    #[test]
    fn list_on_an_empty_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        assert_eq!(reg.list().unwrap(), vec![]);
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(row(host_id, 1_000)).unwrap();
        let got = reg.get(host_id).unwrap().unwrap();
        assert_eq!(got.host_id, host_id);
        assert_eq!(got.last_seen, 1_000);
        assert_eq!(got.enrolled_at, 1_000);
    }

    #[test]
    fn a_second_upsert_bumps_last_seen_but_never_enrolled_at() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(row(host_id, 1_000)).unwrap();
        let mut second = row(host_id, 5_000);
        second.enrolled_at = 5_000; // a buggy caller passing the wrong enrolled_at must still be ignored
        second.hostname = "h1-renamed".into();
        reg.upsert_heartbeat(second).unwrap();
        let got = reg.get(host_id).unwrap().unwrap();
        assert_eq!(got.last_seen, 5_000);
        assert_eq!(got.enrolled_at, 1_000, "enrolled_at must never move after the first upsert");
        assert_eq!(got.hostname, "h1-renamed", "other fields do update on every heartbeat");
    }

    #[test]
    fn an_out_of_order_older_heartbeat_never_regresses_last_seen() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(row(host_id, 5_000)).unwrap();
        reg.upsert_heartbeat(row(host_id, 1_000)).unwrap(); // arrives later, but is an OLDER event
        let got = reg.get(host_id).unwrap().unwrap();
        assert_eq!(got.last_seen, 5_000, "last_seen is the max timestamp ever seen, not the most recently upserted");
    }

    #[test]
    fn list_returns_every_distinct_host() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        reg.upsert_heartbeat(row(a, 1_000)).unwrap();
        reg.upsert_heartbeat(row(b, 2_000)).unwrap();
        let mut ids: Vec<Uuid> = reg.list().unwrap().into_iter().map(|r| r.host_id).collect();
        ids.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn get_of_an_unknown_host_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        assert_eq!(reg.get(Uuid::new_v4()).unwrap(), None);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-fleet` (from repo root)
Expected: FAIL to compile — `HostRow`/`HostRegistry`/`SqliteHostRegistry`/`FleetError` don't exist yet.

- [ ] **Step 4: Implementation** in `crates/osiris-fleet/src/lib.rs` (above the test module):

```rust
use std::sync::Mutex;

use osiris_health::HealthState;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("io: {0}")]
    Io(String),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("serde: {0}")]
    Serde(String),
}

impl From<rusqlite::Error> for FleetError {
    fn from(e: rusqlite::Error) -> Self {
        FleetError::Sqlite(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostRow {
    pub host_id: Uuid,
    pub hostname: String,
    pub distro: String,
    pub kernel_version: String,
    pub agent_version: String,
    pub enrolled_at: u64,
    pub last_seen: u64,
    pub health_state: HealthState,
}

pub trait HostRegistry: Send + Sync {
    fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError>;
    fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError>;
    fn list(&self) -> Result<Vec<HostRow>, FleetError>;
}

pub struct SqliteHostRegistry {
    conn: Mutex<Connection>,
}

impl SqliteHostRegistry {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FleetError> {
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hosts (
                host_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                distro TEXT NOT NULL,
                kernel_version TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                enrolled_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                health_state TEXT NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn row_from(r: &rusqlite::Row) -> rusqlite::Result<HostRow> {
        let host_id: String = r.get(0)?;
        let health_json: String = r.get(7)?;
        Ok(HostRow {
            host_id: Uuid::parse_str(&host_id).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
            hostname: r.get(1)?,
            distro: r.get(2)?,
            kernel_version: r.get(3)?,
            agent_version: r.get(4)?,
            enrolled_at: r.get::<_, i64>(5)? as u64,
            last_seen: r.get::<_, i64>(6)? as u64,
            health_state: serde_json::from_str(&health_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        })
    }
}

impl HostRegistry for SqliteHostRegistry {
    fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let health_json = serde_json::to_string(&row.health_state)
            .map_err(|e| FleetError::Serde(e.to_string()))?;
        conn.execute(
            "INSERT INTO hosts (host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
             ON CONFLICT(host_id) DO UPDATE SET
                hostname = excluded.hostname,
                distro = excluded.distro,
                kernel_version = excluded.kernel_version,
                agent_version = excluded.agent_version,
                last_seen = MAX(hosts.last_seen, excluded.last_seen),
                health_state = excluded.health_state",
            params![
                row.host_id.to_string(),
                row.hostname,
                row.distro,
                row.kernel_version,
                row.agent_version,
                row.last_seen as i64,
                health_json,
            ],
        )?;
        Ok(())
    }

    fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        Ok(conn
            .query_row(
                "SELECT host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state
                 FROM hosts WHERE host_id = ?1",
                params![host_id.to_string()],
                Self::row_from,
            )
            .optional()?)
    }

    fn list(&self) -> Result<Vec<HostRow>, FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(
            "SELECT host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state FROM hosts",
        )?;
        let rows = stmt
            .query_map([], Self::row_from)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}
```

Note the `INSERT`'s `VALUES (..., ?6, ?6, ...)` — the same bound parameter (`row.last_seen`) fills both `enrolled_at` and `last_seen` on first insert, and the `ON CONFLICT` clause's `SET` list deliberately omits `enrolled_at` (never touched again) and computes `last_seen = MAX(hosts.last_seen, excluded.last_seen)` (never regresses on an out-of-order older heartbeat) — this single statement is what makes both Review Focus items structural, not something a caller can get wrong.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-fleet`
Expected: PASS, all 6 tests.

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt -p osiris-fleet
cargo clippy -p osiris-fleet --all-targets -- -D warnings
git add Cargo.toml crates/osiris-fleet
git commit -m "feat(fleet): osiris-fleet crate — HostRegistry + SqliteHostRegistry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Agent — `AGENT_HEALTH` event emission

**Files:**
- Modify: `crates/osiris-sensor-api/src/raw_event.rs` (new `RawEvent::AgentHealth` variant + `AgentHealthRaw` struct + `timestamp_ns()` match arm)
- Modify: `crates/osiris-schema/src/event_type.rs` (new `Source::AgentInternal` variant)
- Modify: `crates/osiris-pipeline/src/normalize.rs` (new `normalize_agent_health` function + match arm)
- Modify: `crates/osiris-agent/src/config.rs` (new `FleetConfig` struct + `AgentConfig.fleet` field)
- Modify: `crates/osiris-agent/src/agent.rs` (new periodic health task in `Agent::start`)
- Test: inline `#[cfg(test)]` in `normalize.rs` and `agent.rs`

**Interfaces:**
- Consumes: `osiris_health::{AgentHealth, HealthAggregator}` (existing, Task 1 doesn't touch this crate), `osiris_sensor_api::SensorHealth::to_agent_health()` (existing).
- Produces (used by Task 3 only as the wire contract, not as Rust types — Task 3 is a different crate reading the JSON `event_data` this task writes):
  - `pub struct AgentHealthRaw { pub agent_version: String, pub health: osiris_health::AgentHealth, pub timestamp_ns: u64 }` (in `osiris-sensor-api`)
  - `RawEvent::AgentHealth(AgentHealthRaw)`
  - `Source::AgentInternal` (in `osiris-schema`)
  - `EventType::AgentHealth`'s normalized `event_data` shape — exactly the Global Constraints JSON contract above.

- [ ] **Step 1: `Source::AgentInternal`**

In `crates/osiris-schema/src/event_type.rs`, add the variant:

```rust
pub enum Source {
    Ebpf,
    Audit,
    Fanotify,
    Procfs,
    Dbus,
    ContainerApi,
    Synthetic,
    /// The Agent's own internal state (health, lifecycle) — not sensed
    /// from any external backend, so none of the above apply.
    AgentInternal,
}
```

Run `cargo build --workspace` immediately — the compiler will point at every non-exhaustive match on `Source` (expected: none outside `normalize.rs`, which Step 4 below handles; if any other match site is found, add a straightforward arm there matching the sibling arms' style, do not use `_ =>`).

- [ ] **Step 2: `AgentHealthRaw` + `RawEvent::AgentHealth`**

In `crates/osiris-sensor-api/src/raw_event.rs`, near the other `*Raw` structs:

```rust
/// The Agent's periodic aggregated health report (Phase 9d-1). Built by
/// the Agent's own supervisor loop, not sensed from any raw source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthRaw {
    pub agent_version: String,
    pub health: osiris_health::AgentHealth,
    pub timestamp_ns: u64,
}
```

`crates/osiris-sensor-api/Cargo.toml` already depends on `osiris-health` (confirmed at plan time — it's what `SensorHealth::to_agent_health()` already uses) — no `Cargo.toml` change needed for this step.

Add the enum variant to `RawEvent` (in the same file, near the existing 9 variants):

```rust
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
    File(FileEventRaw),
    Network(NetworkEventRaw),
    Dns(DnsEventRaw),
    Identity(IdentityEventRaw),
    Privilege(PrivilegeEventRaw),
    Systemd(SystemdEventRaw),
    Persistence(PersistenceEventRaw),
    Container(ContainerEventRaw),
    AgentHealth(AgentHealthRaw),
}
```

Add the `timestamp_ns()` match arm (find the existing `impl RawEvent { pub fn timestamp_ns(&self) -> u64 { match self { ... } } }` block):

```rust
RawEvent::AgentHealth(a) => a.timestamp_ns,
```

- [ ] **Step 3: Failing test for `normalize_agent_health`**

In `crates/osiris-pipeline/src/normalize.rs`'s existing `#[cfg(test)]` module:

```rust
#[test]
fn agent_health_normalizes_with_event_data_and_severity_from_worst_state() {
    use osiris_health::{AgentHealth, HealthState};
    use osiris_sensor_api::AgentHealthRaw;

    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "h1".into(),
        distro: "ubuntu-24.04".into(),
        kernel_version: "6.8.0".into(),
        cloud: None,
    };
    let raw = RawEvent::AgentHealth(AgentHealthRaw {
        agent_version: "0.1.0".into(),
        health: AgentHealth {
            state: HealthState::Degraded {
                last_error: "sensor stopped".into(),
            },
            sensors: vec![],
        },
        timestamp_ns: 1_700_000_000_000_000_000,
    });

    let event = normalize(raw, &host, "boot-1");

    assert_eq!(event.event_type, EventType::AgentHealth);
    assert_eq!(event.category, Category::System);
    assert_eq!(event.severity, Severity::Medium);
    assert_eq!(event.source, Source::AgentInternal);
    assert_eq!(event.timestamp, 1_700_000_000_000_000_000);
    assert_eq!(
        event.event_data["agent_version"].as_str().unwrap(),
        "0.1.0"
    );
    assert_eq!(
        event.event_data["health"]["state"]["state"].as_str().unwrap(),
        "DEGRADED"
    );
}

#[test]
fn agent_health_severity_is_info_for_healthy_and_high_for_failed() {
    use osiris_health::{AgentHealth, HealthState};
    use osiris_sensor_api::AgentHealthRaw;

    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "h1".into(),
        distro: "ubuntu-24.04".into(),
        kernel_version: "6.8.0".into(),
        cloud: None,
    };
    let healthy = normalize(
        RawEvent::AgentHealth(AgentHealthRaw {
            agent_version: "0.1.0".into(),
            health: AgentHealth {
                state: HealthState::Healthy,
                sensors: vec![],
            },
            timestamp_ns: 1,
        }),
        &host,
        "boot-1",
    );
    assert_eq!(healthy.severity, Severity::Info);

    let failed = normalize(
        RawEvent::AgentHealth(AgentHealthRaw {
            agent_version: "0.1.0".into(),
            health: AgentHealth {
                state: HealthState::Failed {
                    last_error: "x".into(),
                },
                sensors: vec![],
            },
            timestamp_ns: 1,
        }),
        &host,
        "boot-1",
    );
    assert_eq!(failed.severity, Severity::High);
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p osiris-pipeline normalize::tests::agent_health`
Expected: FAIL to compile (`normalize_agent_health` not wired, `RawEvent::AgentHealth` match arm missing in `normalize`'s dispatcher — the compiler will also flag `normalize`'s existing `match raw { ... }` as non-exhaustive once Step 2 lands, which is the signal to do Step 5).

- [ ] **Step 5: Implement `normalize_agent_health`**

Add the match arm to `normalize`'s dispatcher (`crates/osiris-pipeline/src/normalize.rs`):

```rust
RawEvent::AgentHealth(a) => normalize_agent_health(a, host, boot_id),
```

Add the function itself, near the other `normalize_*` functions:

```rust
fn normalize_agent_health(raw: AgentHealthRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let severity = match &raw.health.state {
        HealthState::Healthy => Severity::Info,
        HealthState::Degraded { .. } => Severity::Medium,
        HealthState::Failed { .. } => Severity::High,
    };
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type: EventType::AgentHealth,
        category: EventType::AgentHealth.category(),
        severity,
        host: host.clone(),
        user: None,
        session: None,
        process: None,
        parent_process: None,
        thread: None,
        file: None,
        network: None,
        dns: None,
        device: None,
        service: None,
        container: None,
        namespace: None,
        cgroup: None,
        kernel: None,
        source: Source::AgentInternal,
        provider: "agent/health".to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({
            "agent_version": raw.agent_version,
            "health": raw.health,
        }),
    }
}
```

(Cross-check this struct literal's field list against `normalize_process_exec`'s in the same file — if `CanonicalEvent` has gained or lost a field since this plan was written, match the current struct exactly; the compiler will refuse to build otherwise.)

`crates/osiris-pipeline/Cargo.toml` does not currently depend on `osiris-health` directly (confirmed at plan time — it only depends on `osiris-sensor-api`, which does not re-export `osiris_health::HealthState`), so naming `HealthState` in the match above requires adding `osiris-health = { path = "../osiris-health" }` to its `[dependencies]`. Import `osiris_health::HealthState` and `osiris_sensor_api::AgentHealthRaw` at the top of `normalize.rs` alongside its existing imports.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p osiris-pipeline normalize::tests::agent_health`
Expected: PASS, both tests.

- [ ] **Step 7: `FleetConfig` on `AgentConfig`**

In `crates/osiris-agent/src/config.rs`, near `CloudMetadataConfig`:

```rust
/// Phase 9d-1: how often the Agent emits an AGENT_HEALTH event. Always
/// on (unlike `control`/`forward`, which are opt-in features) — the
/// Fleet Manager registry depends on every agent heartbeating.
#[derive(Debug, Clone, Deserialize)]
pub struct FleetConfig {
    #[serde(default = "default_health_interval_secs")]
    pub health_interval_secs: u64,
}

fn default_health_interval_secs() -> u64 {
    60
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            health_interval_secs: default_health_interval_secs(),
        }
    }
}
```

Add to `AgentConfig`:

```rust
/// AGENT_HEALTH heartbeat cadence (Phase 9d-1). Defaults to enabled at
/// 60s, so every pre-9d-1 agent.yaml still loads.
#[serde(default)]
pub fleet: FleetConfig,
```

`agent.rs`'s test module builds `AgentConfig` as an exhaustive struct literal in a `base_config(dir: &tempfile::TempDir) -> AgentConfig` helper (`agent.rs:329-358`, no `..Default::default()` at the top level) — this field addition makes that literal stop compiling until it also sets `fleet: crate::config::FleetConfig::default(),` (add it right after the existing `cloud_metadata`/`k8s_context` fields, same style). Fix `base_config` in this same step, not later — Step 9's `cargo test -p osiris-agent` run will fail to compile otherwise, for every test in this file, not just the new one.

Also add `FleetConfig` to `crates/osiris-agent/src/lib.rs`'s existing re-export list (`pub use config::{AgentConfig, CloudMetadataConfig, ControlConfig, ForwardConfig, K8sContextConfig};` becomes `pub use config::{AgentConfig, CloudMetadataConfig, ControlConfig, FleetConfig, ForwardConfig, K8sContextConfig};`) — the next sub-step needs it importable as `osiris_agent::FleetConfig` from outside the crate.

`crates/osiris-e2e-tests/tests/end_to_end.rs` independently builds 8 of its own exhaustive `AgentConfig { .. }` literals (one per scenario, e.g. line 81 — grep the file for `AgentConfig {` to find all 8; they do NOT go through `base_config`, since that helper is private to `agent.rs`'s own test module). Every one of them also stops compiling the moment `AgentConfig` gains the `fleet` field. Fix all 8 in this same step (not deferred to Task 3, even though Task 3 separately touches this file for `run_ingestion_loop`'s new argument — Task 2 is what breaks these literals, so Task 2's own "cargo test --workspace" gate must include fixing them): add `fleet: osiris_agent::FleetConfig::default(),` to each, matching the existing style of that struct literal's other fields (see the `cloud_metadata`/`k8s_context` fields immediately above where it should go, in the same literal).

- [ ] **Step 8: Failing test for the periodic health task**

In `crates/osiris-agent/src/agent.rs`'s existing `#[cfg(test)]` module, find a test that already asserts on `status_snapshot()`'s sensors (e.g. the one asserting `status.sensors[0].name == "synthetic_generator"`) for the exact `Agent::start` call shape to reuse, then add:

```rust
#[tokio::test]
async fn agent_health_event_is_emitted_within_two_intervals() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.ndjson");
    let mut config = base_config(&dir); // this test module's existing config builder (agent.rs's other tests, e.g. line ~388, all use it)
    config.fleet.health_interval_secs = 1; // the task's own `.max(1)` floors below this anyway; keep the test's wait proportionate
    let agent = Agent::start(config, test_host(), "boot-1".to_string())
        .await
        .unwrap();

    // health_interval_secs=1: one full interval plus slack for the tokio scheduler.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let spooled = std::fs::read_to_string(&spool_path).unwrap();
    assert!(
        spooled.contains("\"event_type\":\"AGENT_HEALTH\""),
        "expected an AGENT_HEALTH line in the spool, got: {spooled}"
    );
    agent.shutdown().await;
}
```

`base_config(&dir)` and `test_host()` are this test module's existing helpers (used by every other `Agent::start(...)` test in this file, e.g. `agent.rs:388-398`) — reuse them verbatim, do not invent new ones. `spool_path` comes from `base_config`'s own `config.spool_path` (check its body if unclear where the returned config points its spool file, rather than assuming `dir.path().join("spool.ndjson")` matches — some existing tests set `spool_path` explicitly after calling `base_config`, follow whichever this file's own tests actually do).

- [ ] **Step 9: Run test to verify it fails**

Run: `cargo test -p osiris-agent agent_health_event_is_emitted_within_two_intervals`
Expected: FAIL — no `AGENT_HEALTH` line ever appears (no task emits it yet).

- [ ] **Step 10: Implement the periodic health task**

Two real constraints in the current `agent.rs` shape this code around, both confirmed by reading the file (not guessed):

1. `raw_tx` (the sender half feeding `pipeline_handle`'s `raw_rx`) is explicitly `drop(raw_tx)`'d right after every sensor gets its own `raw_tx.clone()` (`agent.rs:169`, in the `for mut sensor in candidate_sensors` loop's setup) — this is deliberate: once every sensor's clone is also dropped, `raw_rx` closes and the pipeline task exits cleanly. So the health task's own `raw_tx.clone()` must happen **before** that `drop(raw_tx)` line, not after.
2. `running_sensors` is moved into `Self.sensors` only inside the final `Arc::new(Self { sensors: tokio::sync::Mutex::new(running_sensors), ... })` — there is no live handle to poll sensor health from until `Self` (i.e. `Arc<Agent>`) exists. Rather than duplicate sensor polling, spawn the health task **after** `Agent` is constructed and reuse its own already-existing `status_snapshot()` method (`agent.rs:267-277`), which already returns `AgentStatus { sensors: Vec<SensorHealth>, .. }` — exactly the input `HealthAggregator` needs. `background_tasks` (`agent.rs:58`, `tokio::sync::Mutex<Vec<JoinHandle<()>>>`) can have a handle pushed into it after construction, so this doesn't require restructuring the return type.

First, near the other `let ..._cancellation = cancellation.clone();` lines already in this function (by the `forward`/`control` blocks), add one more, and clone `raw_tx` right before its `drop(raw_tx)` call:

```rust
// Immediately before `drop(raw_tx);` (agent.rs:169 today):
let health_raw_tx = raw_tx.clone();
```

```rust
// Alongside the existing `forwarder_cancellation`/`control` cancellation.clone() calls, before Self is constructed:
let health_cancellation = cancellation.clone();
```

Then, after `let agent = Arc::new(Self { ... });` — change the function's final `Ok(Arc::new(Self { ... }))` into a bound variable first, so the health task can be spawned against it:

```rust
let agent = Arc::new(Self {
    lifecycle: Mutex::new(AgentLifecycle::Running),
    sensors: tokio::sync::Mutex::new(running_sensors),
    skipped_sensors: Mutex::new(skipped),
    cancellation,
    background_tasks: tokio::sync::Mutex::new(tasks),
});

// Phase 9d-1: periodic AGENT_HEALTH heartbeat. Spawned after `agent`
// exists so it can reuse status_snapshot()'s existing sensor-health
// readout instead of re-polling sensors directly.
{
    let health_interval = Duration::from_secs(config.fleet.health_interval_secs.max(1));
    let health_agent = agent.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(health_interval) => {}
                _ = health_cancellation.cancelled() => break,
            }
            let status = health_agent.status_snapshot().await;
            let mut aggregator = osiris_health::HealthAggregator::new();
            for s in &status.sensors {
                aggregator.record_sensor(s.to_agent_health());
            }
            let raw = osiris_sensor_api::RawEvent::AgentHealth(osiris_sensor_api::AgentHealthRaw {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                health: aggregator.aggregate(),
                timestamp_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
            });
            if health_raw_tx.send(raw).await.is_err() {
                break; // pipeline task gone; agent is shutting down
            }
        }
    });
    agent.background_tasks.lock().await.push(handle);
}

Ok(agent)
```

`SystemTime`/`UNIX_EPOCH` are already imported at the top of this file (used identically for `base_ts` in the synthetic-scenario setup a few dozen lines above) — reuse that same expression shape, don't add a new timestamp helper. `s.to_agent_health()` is `SensorHealth::to_agent_health()` from `osiris-sensor-api` (already used nowhere else in `agent.rs` but already `pub`, no new import needed beyond what `use osiris_sensor_api::{Sensor, SensorContext, SensorHealth};` at the top already brings in scope).

- [ ] **Step 11: Run test to verify it passes**

Run: `cargo test -p osiris-agent agent_health_event_is_emitted_within_two_intervals`
Expected: PASS.

- [ ] **Step 12: Full workspace check + commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add crates/osiris-schema crates/osiris-sensor-api crates/osiris-pipeline crates/osiris-agent
git commit -m "feat(agent): emit AGENT_HEALTH events periodically (Phase 9d-1)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Server — ingest hook + `main.rs` wiring

**Files:**
- Modify: `crates/osiris-server/Cargo.toml` (add `osiris-fleet` dependency)
- Modify: `crates/osiris-server/src/ingest.rs` (`IngestContext` gains `fleet_registry`, `ingest()` upserts on `AGENT_HEALTH`, `run_ingestion_loop` gains a parameter)
- Modify: `crates/osiris-server/src/main.rs` (open `hosts.db`, thread the registry into both `IngestContext` construction sites)
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs` (8 call sites, mechanical)
- Test: extend `ingest.rs`'s existing `#[cfg(test)]` module

**Interfaces:**
- Consumes: `osiris_fleet::{HostRegistry, HostRow, SqliteHostRegistry}` (Task 1), the `event_data` JSON shape from Task 2 (Global Constraints).
- Produces: `IngestContext.fleet_registry: Arc<dyn HostRegistry>` (used unchanged by Task 4's router wiring — same `Arc` instance passed to both `IngestContext` and the new `FleetState`).

- [ ] **Step 1: Add the dependencies**

In `crates/osiris-server/Cargo.toml`'s `[dependencies]`, add both (confirmed at plan time neither is present yet, unlike `serde_json` which already is): `osiris-fleet = { path = "../osiris-fleet" }` and `osiris-health = { path = "../osiris-health" }` (needed for `osiris_health::AgentHealth` in Step 4's upsert code).

- [ ] **Step 2: Failing test for the upsert hook**

In `crates/osiris-server/src/ingest.rs`'s existing test module, near the other `IngestContext`/`run_ingestion_loop` tests:

```rust
fn agent_health_event(host_id: uuid::Uuid, timestamp: u64) -> CanonicalEvent {
    let host = osiris_schema::HostRef {
        host_id,
        hostname: "h1".into(),
        distro: "ubuntu-24.04".into(),
        kernel_version: "6.8.0".into(),
        cloud: None,
    };
    CanonicalEvent {
        event_id: uuid::Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id,
        boot_id: "boot-1".into(),
        timestamp,
        monotonic_timestamp: timestamp,
        event_type: EventType::AgentHealth,
        category: EventType::AgentHealth.category(),
        severity: Severity::Info,
        host,
        user: None, session: None, process: None, parent_process: None, thread: None,
        file: None, network: None, dns: None, device: None, service: None,
        container: None, namespace: None, cgroup: None, kernel: None,
        source: Source::AgentInternal,
        provider: "agent/health".into(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({
            "agent_version": "0.1.0",
            "health": {"state": {"state": "HEALTHY"}, "sensors": []}
        }),
    }
}

#[tokio::test]
async fn ingesting_an_agent_health_event_upserts_the_fleet_registry() {
    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
    let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
        Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
    let detection_engine = Arc::new(DetectionEngine::new(vec![]));
    let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
    let context = IngestContext {
        storage: storage.clone(),
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
        broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
        fleet_registry: fleet_registry.clone(),
    };
    let host_id = uuid::Uuid::new_v4();

    context.ingest(vec![agent_health_event(host_id, 1_000)]).await.unwrap();

    let row = fleet_registry.get(host_id).unwrap().unwrap();
    assert_eq!(row.agent_version, "0.1.0");
    assert_eq!(row.last_seen, 1_000);
    // The underlying event is still written to Storage unchanged — the
    // registry is an additive side effect, not a replacement path.
    let stored = storage.query(&osiris_storage::QueryPlan::default()).unwrap();
    assert_eq!(stored.len(), 1);
}

#[tokio::test]
async fn a_malformed_agent_health_event_data_does_not_fail_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
    let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
        Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
    let detection_engine = Arc::new(DetectionEngine::new(vec![]));
    let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
    let context = IngestContext {
        storage: storage.clone(),
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
        broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
        fleet_registry: fleet_registry.clone(),
    };
    let host_id = uuid::Uuid::new_v4();
    let mut bad = agent_health_event(host_id, 1_000);
    bad.event_data = serde_json::json!({"nonsense": true}); // no "agent_version"/"health"

    let result = context.ingest(vec![bad]).await;

    assert!(result.is_ok(), "a bad AGENT_HEALTH payload must not fail the batch");
    assert_eq!(fleet_registry.get(host_id).unwrap(), None, "no row is created for the unparseable event");
    let stored = storage.query(&osiris_storage::QueryPlan::default()).unwrap();
    assert_eq!(stored.len(), 1, "the underlying event is still stored even though its registry upsert was skipped");
}

#[tokio::test]
async fn an_ordinary_event_batch_does_not_touch_the_fleet_registry() {
    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
    let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
        Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
    let detection_engine = Arc::new(DetectionEngine::new(vec![]));
    let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
    let context = IngestContext {
        storage,
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
        broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
        fleet_registry: fleet_registry.clone(),
    };
    // `sample_event()` (this file's existing test-only helper, defined
    // above at the top of this test module) builds a plain ProcessExec
    // CanonicalEvent with its own freshly-generated host_id — reuse it
    // rather than inventing a new builder.
    let plain = sample_event();
    let host_id = plain.host_id;

    context.ingest(vec![plain]).await.unwrap();

    assert_eq!(fleet_registry.get(host_id).unwrap(), None);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-server ingest::tests::ingesting_an_agent_health_event`
Expected: FAIL to compile — `IngestContext` has no `fleet_registry` field yet.

- [ ] **Step 4: Implement the hook**

In `crates/osiris-server/src/ingest.rs`:

Add the field to `IngestContext`:

```rust
pub struct IngestContext {
    pub storage: Arc<dyn Storage>,
    pub detection_engine: Arc<DetectionEngine>,
    pub baseline_engine: Arc<BaselineEngine>,
    pub risk_engine: Arc<RiskEngine>,
    pub correlation_engine: Arc<CorrelationEngine>,
    pub broadcaster: Arc<osiris_api::LiveEventBroadcaster>,
    pub fleet_registry: Arc<dyn osiris_fleet::HostRegistry>,
}
```

**Read `ingest()`'s current body first** (`ingest.rs:106-185`) — its outer `events: Vec<CanonicalEvent>` parameter is itself `move`d into the `spawn_blocking(move || ...)` closure at line 120 and is gone (consumed) by the time `.await` at line 174 returns. The existing `events_for_broadcast` variable (lines 115-119) is the *only* thing that survives past that move, and only conditionally (`Some` only when `self.broadcaster.has_subscribers()`). The fleet-registry hook needs `AGENT_HEALTH` events regardless of whether anyone is subscribed to the broadcaster, so it needs its own extraction at that same point, unconditionally — inserting a read of `events` any later (e.g. "after the storage write, before broadcast," which is where a first instinct might place it) will not compile, because `events` no longer exists there.

Add this immediately after the existing `let events_for_broadcast = ...;` block (still lines 115-119) and before `let outcome = tokio::task::spawn_blocking(move || {` (line 120) — i.e., while `events` is still owned by this function, before the storage closure's `move` takes it:

```rust
let health_events: Vec<CanonicalEvent> = events
    .iter()
    .filter(|e| e.event_type == osiris_schema::EventType::AgentHealth)
    .cloned()
    .collect();
```

Then, after the existing `match outcome { Ok(Ok(_report)) => { ... } ... }` block's `Ok(Ok(_report))` arm runs the broadcast (so a storage failure still short-circuits the registry upsert too, matching the broadcast step's own existing ordering), add the registry upsert inside that same arm, using `health_events` (not `events`):

```rust
Ok(Ok(_report)) => {
    if let Some(events) = events_for_broadcast {
        self.broadcaster.publish(&events);
    }
    if !health_events.is_empty() {
        let fleet_registry = self.fleet_registry.clone();
        let _ = tokio::task::spawn_blocking(move || {
            for event in health_events {
                let agent_version =
                    event.event_data.get("agent_version").and_then(|v| v.as_str());
                let health: Option<osiris_health::AgentHealth> = event
                    .event_data
                    .get("health")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                let (Some(agent_version), Some(health)) = (agent_version, health) else {
                    tracing::warn!(host_id = %event.host_id, "AGENT_HEALTH event has malformed event_data; skipping fleet registry upsert");
                    continue;
                };
                let row = osiris_fleet::HostRow {
                    host_id: event.host_id,
                    hostname: event.host.hostname.clone(),
                    distro: event.host.distro.clone(),
                    kernel_version: event.host.kernel_version.clone(),
                    agent_version: agent_version.to_string(),
                    enrolled_at: event.timestamp, // ignored by upsert_heartbeat after the first insert
                    last_seen: event.timestamp,
                    health_state: health.state,
                };
                if let Err(e) = fleet_registry.upsert_heartbeat(row) {
                    tracing::warn!(host_id = %event.host_id, error = %e, "fleet registry upsert failed");
                }
            }
        })
        .await;
    }
    Ok(())
}
```

This changes the `Ok(Ok(_report)) => { ... }` arm from its current single-expression `if let Some(events) = events_for_broadcast { self.broadcaster.publish(&events); } Ok(())` body to the block above — replace that whole arm, not just insert alongside it. The registry upsert is intentionally `.await`ed here (making `ingest()`'s own return wait for it) rather than fire-and-forget, so the Review Focus test in Step 2 (`ingesting_an_agent_health_event_upserts_the_fleet_registry`) can assert on the registry immediately after `context.ingest(...).await` returns, without a race.

Add the parameter to `run_ingestion_loop`'s signature and its internal `IngestContext { ... }` construction:

```rust
#[allow(clippy::too_many_arguments)]
pub async fn run_ingestion_loop(
    spool_path: impl Into<std::path::PathBuf>,
    storage: Arc<dyn Storage>,
    detection_engine: Arc<DetectionEngine>,
    baseline_engine: Arc<BaselineEngine>,
    risk_engine: Arc<RiskEngine>,
    correlation_engine: Arc<CorrelationEngine>,
    broadcaster: Arc<osiris_api::LiveEventBroadcaster>,
    fleet_registry: Arc<dyn osiris_fleet::HostRegistry>,
    poll_interval: Duration,
    cancellation: CancellationToken,
) {
    let context = IngestContext {
        storage,
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
        broadcaster,
        fleet_registry,
    };
    // ... rest unchanged
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-server ingest::`
Expected: PASS, including every pre-existing test in this file (each one's `IngestContext`/`run_ingestion_loop` call site now needs a `fleet_registry` argument — add `Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap())` to each, matching how each test already opens its own `events.db`/`baseline.db` in a per-test tempdir).

- [ ] **Step 6: Wire `main.rs`**

Near where `tenant_store`/`incident_evidence_state` are opened in `crates/osiris-server/src/main.rs`, add:

```rust
let hosts_db_path = config
    .hosts_db_path
    .clone()
    .unwrap_or_else(|| "/var/lib/osiris/hosts.db".to_string());
let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> = Arc::new(open_or_exit(
    osiris_fleet::SqliteHostRegistry::open(&hosts_db_path),
    &hosts_db_path,
    "hosts_db_path",
));
```

(Add `hosts_db_path: Option<String>` to `ServerConfig` in `crates/osiris-server/src/config.rs`, `#[serde(default)]`, matching `tenants_db_path`'s existing shape exactly — check that struct for the precise field style before adding.)

Update the existing `let ingest_context = osiris_server::IngestContext { ... }` literal to add `fleet_registry: fleet_registry.clone(),`.

Update the existing `run_ingestion_loop(...)` call to add `fleet_registry.clone(),` as a new positional argument in the same position as the struct field list above (right after `live_event_broadcaster.clone()`, before `Duration::from_millis(200)`).

- [ ] **Step 7: Update the 8 e2e call sites**

In `crates/osiris-e2e-tests/tests/end_to_end.rs`, each of the 8 `tokio::spawn(run_ingestion_loop(...))` call sites needs one new argument. For each: add, right before its existing `Duration::from_millis(...)`/poll-interval argument, a fresh registry:

```rust
Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()),
```

(`dir` is each scenario's existing per-test tempdir — check each call site's surrounding code for its exact tempdir variable name, which may differ between scenarios, and use that same one; do not introduce a new tempdir just for this.) Add `osiris-fleet = { path = "../osiris-fleet" }` to `crates/osiris-e2e-tests/Cargo.toml` if not already present.

- [ ] **Step 8: Full workspace check + commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p osiris-cli -p osiris-server -p osiris-agent
cargo test --workspace
git add crates/osiris-server crates/osiris-e2e-tests
git commit -m "feat(server): upsert the fleet registry on AGENT_HEALTH ingest (Phase 9d-1)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: API — `GET /api/v1/hosts` on the fleet registry

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (remove old `hosts_handler`/`HostSummary`/`build_host_rows` and their tests; `build_router` drops the `/api/v1/hosts` route)
- Create: `crates/osiris-api/src/fleet.rs` (new `FleetState`, `build_fleet_router`, rewritten `hosts_handler`/`HostSummary`)
- Modify: `crates/osiris-api/Cargo.toml` (add `osiris-fleet` and `osiris-health` dependencies — confirmed at plan time neither is currently present; `osiris-auth`/`osiris-tenancy` already are)
- Modify: `crates/osiris-server/src/main.rs` (merge `build_fleet_router`, remove `/api/v1/hosts` from wherever `build_router`'s old route lived)
- Test: `crates/osiris-api/src/fleet.rs`'s own `#[cfg(test)]` module

**Interfaces:**
- Consumes: `osiris_fleet::{HostRegistry, HostRow}` (Task 1), `osiris_fleet::SqliteHostRegistry` via the `Arc<dyn HostRegistry>` Task 3 already opened in `main.rs` (same instance, passed to both).
- Consumes: `hosts_of_tenant`/`tenant_hosts` (`crates/osiris-api/src/tenant_scope.rs`, existing, `pub(crate)` — this task lives in the same crate so visibility is already sufficient).
- Produces: `pub fn build_fleet_router(state: FleetState) -> Router`, `pub struct FleetState { pub registry: Arc<dyn HostRegistry>, pub tenants: Arc<dyn TenantStore> }`.

- [ ] **Step 1: Delete the old handler**

In `crates/osiris-api/src/lib.rs`: delete `struct HostSummary`, the `hosts_handler` function and its doc comment, `build_host_rows`, `const HOST_REGISTRY_DEFAULT_WINDOW_NS` (or equivalent — check the exact constant name near `hosts_handler`), `struct HostsQuery`, and every test in this file whose name starts with `hosts_endpoint_` (there are at least 4, per the earlier grep: `hosts_endpoint_returns_one_row_per_host_most_recent_first`, `hosts_endpoint_excludes_events_outside_the_since_until_window`, `hosts_endpoint_marks_status_online_within_five_minutes_and_stale_beyond_it`, `hosts_endpoint_orders_last_seen_ties_deterministically_by_host_id` — search the file for all of them, do not assume this list is exhaustive). Remove `.route("/api/v1/hosts", get(hosts_handler))` from `build_router`.

- [ ] **Step 2: Failing tests** in a new `crates/osiris-api/src/fleet.rs`

This codebase's established convention for handler-level tests (see `response.rs`'s `response_handler` tests, e.g. `response.rs:906-916`, and Phase 8c's own `hosts_handler` tests before this task deletes them) is to call the `async fn` handler directly with hand-built extractor values — no `Router`/`oneshot`/`tower::ServiceExt`, no HTTP layer at all. Follow that exact pattern, not axum's router-level testing style:

```rust
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use uuid::Uuid;

use crate::auth_middleware::AuthContext;
use osiris_fleet::{HostRegistry, HostRow};
use osiris_tenancy::TenantStore;

const EXPECTED_HEARTBEAT_INTERVAL_NS: u64 = 60 * 1_000_000_000;

#[derive(Clone)]
pub struct FleetState {
    pub registry: Arc<dyn HostRegistry>,
    pub tenants: Arc<dyn TenantStore>,
}

pub fn build_fleet_router(state: FleetState) -> Router {
    Router::new()
        .route("/api/v1/hosts", get(hosts_handler))
        .with_state(state)
}

#[derive(Serialize)]
struct HostSummary {
    host_id: String,
    hostname: String,
    distro: String,
    kernel_version: String,
    agent_version: String,
    enrolled_at: u64,
    last_seen: u64,
    status: String,
}

fn to_summary(row: HostRow, now_ns: u64) -> HostSummary {
    let status = if now_ns.saturating_sub(row.last_seen) <= 3 * EXPECTED_HEARTBEAT_INTERVAL_NS {
        "ONLINE"
    } else {
        "STALE"
    };
    HostSummary {
        host_id: row.host_id.to_string(),
        hostname: row.hostname,
        distro: row.distro,
        kernel_version: row.kernel_version,
        agent_version: row.agent_version,
        enrolled_at: row.enrolled_at,
        last_seen: row.last_seen,
        status: status.to_string(),
    }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

async fn hosts_handler(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<FleetState>,
) -> Result<Json<Vec<HostSummary>>, (StatusCode, String)> {
    let scope =
        crate::tenant_scope::hosts_of_tenant(ctx.tenant_id, Some(state.tenants.clone())).await?;
    let mut rows = state
        .registry
        .list()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(allowed) = scope {
        rows.retain(|r| allowed.contains(&r.host_id));
    }
    let now = now_ns();
    let mut summaries: Vec<HostSummary> = rows.into_iter().map(|r| to_summary(r, now)).collect();
    summaries.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.host_id.cmp(&b.host_id)));
    Ok(Json(summaries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_tenancy::SqliteTenantStore;

    fn row(host_id: Uuid, last_seen: u64) -> HostRow {
        HostRow {
            host_id,
            hostname: "h1".into(),
            distro: "ubuntu-24.04".into(),
            kernel_version: "6.8.0".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: last_seen,
            last_seen,
            health_state: osiris_health::HealthState::Healthy,
        }
    }

    fn state(dir: &std::path::Path) -> FleetState {
        FleetState {
            registry: Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.join("hosts.db")).unwrap()),
            tenants: Arc::new(SqliteTenantStore::open(dir.join("tenants.db")).unwrap()),
        }
    }

    fn platform_ctx() -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::Admin,
            token: "t".to_string(),
            tenant_id: None,
        }
    }

    fn tenant_ctx(tenant_id: Uuid) -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::Viewer,
            token: "t".to_string(),
            tenant_id: Some(tenant_id),
        }
    }

    #[test]
    fn online_exactly_at_the_boundary_stale_one_ns_past_it() {
        let now = 10 * EXPECTED_HEARTBEAT_INTERVAL_NS;
        let at_boundary = row(Uuid::new_v4(), now - 3 * EXPECTED_HEARTBEAT_INTERVAL_NS);
        let past_boundary = row(Uuid::new_v4(), now - 3 * EXPECTED_HEARTBEAT_INTERVAL_NS - 1);
        assert_eq!(to_summary(at_boundary, now).status, "ONLINE");
        assert_eq!(to_summary(past_boundary, now).status, "STALE");
    }

    #[tokio::test]
    async fn an_empty_registry_returns_an_empty_array() {
        let dir = tempfile::tempdir().unwrap();
        let Json(rows) = hosts_handler(Extension(platform_ctx()), State(state(dir.path())))
            .await
            .unwrap();
        assert_eq!(rows.len(), 0);
    }

    #[tokio::test]
    async fn a_tenant_user_only_sees_its_own_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let tenant_id = s.tenants.create_tenant("acme").unwrap().tenant_id;
        let mine = Uuid::new_v4();
        let theirs = Uuid::new_v4();
        s.registry.upsert_heartbeat(row(mine, 1_000)).unwrap();
        s.registry.upsert_heartbeat(row(theirs, 1_000)).unwrap();
        s.tenants.assign_host(mine, tenant_id).unwrap();
        // `theirs` stays unassigned (platform-owned), which per
        // `hosts_of_tenant`'s existing contract must also be invisible
        // to a tenant-scoped caller.

        let Json(rows) = hosts_handler(Extension(tenant_ctx(tenant_id)), State(s))
            .await
            .unwrap();

        let ids: Vec<String> = rows.iter().map(|r| r.host_id.clone()).collect();
        assert!(ids.contains(&mine.to_string()));
        assert!(!ids.contains(&theirs.to_string()));
    }
}
```

Check `osiris_auth::Role`'s exact variant names (`Admin`, `Viewer`, etc.) against `crates/osiris-auth/src/lib.rs` before using them if this doesn't compile as written — this plan uses the same variant names Phase 8a's design established and every later phase's tests have used unchanged since.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-api fleet::`
Expected: FAIL to compile initially (module not registered in `lib.rs`) — add `mod fleet; pub use fleet::{build_fleet_router, FleetState};` to `crates/osiris-api/src/lib.rs`, then re-run.
Expected after that: PASS or FAIL per test — `online_exactly_at_the_boundary_stale_one_ns_past_it` may already pass (pure function, no dependency on the deleted old handler), the other two should FAIL only if `hosts_handler`/`FleetState`/wiring have a mistake; if they instead fail to compile, fix the compile error before treating this as the TDD RED step (a compile failure is not the same as a legitimate failing assertion — resolve type/import errors first, then re-run to confirm a genuine RED before moving to Step 4).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p osiris-api fleet::`
Expected: PASS, all 3 tests.

- [ ] **Step 5: Wire into `main.rs`**

In `crates/osiris-server/src/main.rs`, add `.merge(build_fleet_router(osiris_api::FleetState { registry: fleet_registry.clone(), tenants: tenant_store.clone() }))` to the existing router-building chain (`build_router(storage).merge(...)`), using the same `fleet_registry` Task 3 Step 6 already opened and the same `tenant_store` already in scope.

- [ ] **Step 6: Full workspace check + commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p osiris-cli -p osiris-server -p osiris-agent
cargo test --workspace
git add crates/osiris-api crates/osiris-server
git commit -m "feat(api): GET /api/v1/hosts reads the real fleet registry (Phase 9d-1)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Console — `HostList` gains `agent_version`/`enrolled_at`, drops time-range filter

**Files:**
- Modify: `console/src/api/types.ts` (`HostSummary` type)
- Modify: `console/src/screens/hosts/HostList.tsx`
- Modify: `console/src/api/client.ts` / `hooks.ts` if `fetchHosts`/`useHosts` currently pass `since`/`until` query params (check both files first)
- Test: `console/src/screens/hosts/HostList.test.tsx`

**Interfaces:**
- Consumes: the API's new `HostSummary` JSON shape (Task 4): `{ host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, status }`.

- [ ] **Step 1: Read the current files**

Read `console/src/api/types.ts`'s `HostSummary` type, `console/src/screens/hosts/HostList.tsx`, `console/src/screens/hosts/HostList.test.tsx`, and whatever `fetchHosts`/`useHosts` look like in `client.ts`/`hooks.ts` in full before changing anything — this plan does not re-derive their current exact shape, since Task 4 already establishes the wire contract they must match.

- [ ] **Step 2: Failing test**

In `HostList.test.tsx`, extend the existing row-rendering test (or add one) asserting the table renders an "Agent version" column with the value from a mocked `agent_version` field and an "Enrolled" column with `enrolled_at` formatted as a date (reuse whatever date-formatting utility this codebase's other screens already use for a Unix-nanosecond timestamp — check `Timeline.tsx`/`HostList.tsx`'s existing `last_seen` formatting for the established helper and reuse it, do not add a new one). If the existing test file mocks `fetchHosts`/`useHosts` with a fixture object, add `agent_version: "0.1.0"` and `enrolled_at: <some ns value>` to that fixture.

- [ ] **Step 3: Run test to verify it fails**

Run: `npm test -- HostList` (from `console/`)
Expected: FAIL — no such column exists yet.

- [ ] **Step 4: Implement**

Add `agent_version: string;` and `enrolled_at: number;` to `HostSummary` in `types.ts`. Add two `<th>`/`<td>` pairs to `HostList.tsx`'s table, following its existing column pattern exactly (same cell styling/structure as the `hostname`/`distro` columns already there). If `fetchHosts`/`useHosts` currently build a query string with `since`/`until`, remove that — the new endpoint doesn't accept them (per Task 4, `hosts_handler` takes no query params at all).

- [ ] **Step 5: Run test to verify it passes**

Run: `npm test -- HostList`
Expected: PASS.

- [ ] **Step 6: Full console check + commit**

```bash
cd console
npm run build
npm test
cd ..
git add console
git commit -m "feat(console): show agent_version/enrolled_at on the Hosts screen (Phase 9d-1)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: e2e — a real end-to-end scenario

**Files:**
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs` (one new scenario; existing scenarios already compile from Task 3's mechanical fix, but check whether any of them assert on `/api/v1/hosts` output and, if so, whether they now need to also ingest an `AGENT_HEALTH` event to keep passing — per spec §5's migration note)

**Interfaces:**
- Consumes: everything from Tasks 1–4 (the full stack, real components, no mocks — matching this file's existing scenario style).

- [ ] **Step 1: Check for existing `/api/v1/hosts` assertions**

Search `end_to_end.rs` for `/api/v1/hosts` or `hosts_handler`. For each hit, check whether that scenario's fixture data included an `AGENT_HEALTH` event (it won't have, since this event type didn't exist as agent output before this phase). If a scenario currently asserts a host appears in that endpoint's response, it needs one `AGENT_HEALTH` event added to its fixture stream (matching Task 3's `agent_health_event`-shaped test builder, or wherever this file's own event-construction helpers live) — fix in place, same task, since it's a direct consequence of this phase's change to that endpoint's data source (spec §5).

- [ ] **Step 2: Failing test for the new scenario**

Add a new scenario function to `end_to_end.rs`, following this file's existing scenario shape (spin up a real `run_ingestion_loop` + real HTTP router, feed events through the spool file, assert on the API response) — read the file's most recent existing scenario in full first and copy its harness-setup shape exactly (tempdir, storage, engines, router, spool-file writer):

```rust
#[tokio::test]
async fn an_agent_health_event_makes_the_host_appear_online_in_the_fleet_registry() {
    // 1. Set up the same way this file's existing scenarios do: tempdir,
    //    SqliteStorage, engines, a fresh SqliteHostRegistry (Task 1),
    //    run_ingestion_loop spawned with the new fleet_registry argument
    //    (Task 3), and a router built with build_router(...).merge(build_fleet_router(...))
    //    (Task 4) — mirror an existing scenario's setup block verbatim,
    //    adjusted only to add the fleet registry and fleet router.
    // 2. Write one AGENT_HEALTH line to the spool file (JSON matching
    //    Task 2/3's event_data contract) for a fresh host_id.
    // 3. Poll GET /api/v1/hosts (same polling-for-ingestion-to-land
    //    pattern this file's other scenarios already use, since
    //    run_ingestion_loop is async and polls the spool on an interval)
    //    until that host_id appears or a timeout — copy the existing
    //    poll-retry helper this file already has for analogous
    //    eventually-consistent assertions rather than writing a new one.
    // 4. Assert: status == "ONLINE", agent_version == the value the
    //    fixture event carried, enrolled_at == last_seen (first-ever
    //    heartbeat for this host_id).
}
```

Write the real, complete test body — the numbered comments above describe what each part must do; replace them with actual code copied from this file's nearest existing scenario's real setup, adapted to this scenario's assertions, not left as comments.

- [ ] **Step 3: Run test to verify it fails, then implement until it passes**

Run: `cargo test -p osiris-e2e-tests an_agent_health_event_makes_the_host_appear_online`
Expected: FAIL first (if the scenario harness has any gap versus Tasks 1–4's real wiring, fix the harness, not the production code — everything it needs already exists by this point in the plan), then PASS once correctly wired.

- [ ] **Step 4: Full workspace verification + commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p osiris-cli -p osiris-server -p osiris-agent
cargo test --workspace
git add crates/osiris-e2e-tests
git commit -m "test(e2e): AGENT_HEALTH ingest -> fleet registry -> GET /api/v1/hosts (Phase 9d-1)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## After all tasks: whole-branch review and merge

Follow this project's standing workflow (see project memory `feedback-osiris-workflow`): final opus review of the whole branch (base = `master` at the point the worktree branched, head = the last task's commit), fix any findings in one or more waves with scoped re-review after each, then `superpowers:finishing-a-development-branch` — full `cargo test --workspace` on the exact final commit (rebuilding `osiris-cli`/`osiris-server`/`osiris-agent` first), fast-forward merge into `master`, push, clean up the worktree/branch with user confirmation for the destructive steps.
