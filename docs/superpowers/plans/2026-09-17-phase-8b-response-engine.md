# Phase 8b — Response Engine (v1 scaffolding) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the Response Engine's v1 scaffolding: a `ResponseAction` type system, the full `AuthCheck → Confirmation → Audit(pre) → Dispatch → Result → Audit(post)` pipeline from `ARCHITECTURE.md` §13, `CollectEvidence` executing for real, and every destructive action rejected (never silently) behind a `501` until the separately-versioned "Response — Active Actions" milestone builds the Agent command channel.

**Architecture:** New crate `osiris-response` holds pure domain logic (`ResponseActionKind`, `ResponseRequest`, `ResponseOutcome`, `dispatch()`) with no HTTP dependency, testable standalone against a real `SqliteStorage`/`SqliteEvidenceStore`. `osiris-api` gets a new `response.rs` handler module (mirroring `incidents.rs`/`evidence.rs`) that owns the audit-writing responsibility around `dispatch()`, gated by one new `min_role_for` entry (`ResponseOperator`). `osiris-server`'s `main.rs` wires a new `ResponseState` alongside the existing `IncidentEvidenceState`/`AuthState`.

**Tech Stack:** Rust workspace, axum, rusqlite (via `osiris-storage-sqlite`), `sha2`/`hex` for evidence hashing, `osiris-query`'s `EventQueryPlan`/`Ast` for entity-scoped event lookup (reused, not reinvented).

**Spec:** `docs/superpowers/specs/2026-09-17-phase-8b-response-engine-design.md`

## Global Constraints

- Every destructive `ResponseActionKind` (`TerminateProcess`, `StopService`, `QuarantineFile`, `BlockIndicator`, `IsolateNetwork`, `DisablePersistence`) must be rejected with `501` and a two-phase audit trail (pre `Success`, post `Failure`) when requested outside dry-run — never a silent no-op.
- `CollectEvidence` is the only action that executes for real in this phase.
- `min_role: ResponseOperator` applies uniformly to `/api/v1/response/*` — dry-run and real, every action kind, no per-action carve-out.
- Dry-run writes exactly **one** audit entry (pre only); non-dry-run writes exactly **two** (pre + post) — this asymmetry is deliberate (see spec §4) and must be asserted by tests, not just implemented.
- `osiris-response` has no `AuditLog`/HTTP dependency — audit writing stays in `osiris-api`'s handler, bracketing the `dispatch()` call.
- No Console/CLI/response-history-endpoint work this phase (spec §6 Non-Goals).

---

### Task 1: `osiris-response` crate skeleton — action types

**Files:**
- Create: `crates/osiris-response/Cargo.toml`
- Create: `crates/osiris-response/src/lib.rs`

**Interfaces:**
- Produces: `pub enum ResponseActionKind { TerminateProcess, StopService, QuarantineFile, BlockIndicator, IsolateNetwork, DisablePersistence, CollectEvidence }` with `pub fn destructive(&self) -> bool` and `pub fn supports_dry_run(&self) -> bool`; `pub struct ResponseRequest { pub action: ResponseActionKind, pub target: osiris_schema::EntityRef, pub reason: String, pub dry_run: bool, pub since: Option<u64>, pub until: Option<u64>, pub incident_id: Option<uuid::Uuid> }`; `pub enum ResponseOutcome { DryRunPreview { description: String }, EvidenceCollected { evidence_id: uuid::Uuid }, Rejected { reason: String } }`; `pub enum ResponseError` (populated fully in Task 3, declared here as an empty-variant placeholder is NOT acceptable — see Task 3, which adds its variants in the same file this task creates).

- [ ] **Step 1: Add the crate to the workspace and write its `Cargo.toml`**

Create `crates/osiris-response/Cargo.toml`:

```toml
[package]
name = "osiris-response"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
uuid = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
osiris-schema = { path = "../osiris-schema" }
osiris-storage = { path = "../osiris-storage" }
osiris-query = { path = "../osiris-query" }
osiris-evidence = { path = "../osiris-evidence" }

[dev-dependencies]
tempfile = { workspace = true }
osiris-storage-sqlite = { path = "../osiris-storage-sqlite" }
```

The workspace `Cargo.toml`'s `members = ["crates/*", ...]` glob already picks this up — no edit needed there.

- [ ] **Step 2: Write the failing test for `ResponseActionKind::destructive()`/`supports_dry_run()`**

Create `crates/osiris-response/src/lib.rs`:

```rust
use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseActionKind {
    TerminateProcess,
    StopService,
    QuarantineFile,
    BlockIndicator,
    IsolateNetwork,
    DisablePersistence,
    CollectEvidence,
}

#[derive(Debug, Clone)]
pub struct ResponseRequest {
    pub action: ResponseActionKind,
    pub target: EntityRef,
    pub reason: String,
    pub dry_run: bool,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub incident_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseOutcome {
    DryRunPreview { description: String },
    EvidenceCollected { evidence_id: Uuid },
    Rejected { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_collect_evidence_is_non_destructive() {
        assert!(!ResponseActionKind::CollectEvidence.destructive());
        for action in [
            ResponseActionKind::TerminateProcess,
            ResponseActionKind::StopService,
            ResponseActionKind::QuarantineFile,
            ResponseActionKind::BlockIndicator,
            ResponseActionKind::IsolateNetwork,
            ResponseActionKind::DisablePersistence,
        ] {
            assert!(action.destructive(), "{action:?} must be destructive");
        }
    }

    #[test]
    fn every_action_supports_dry_run_in_v1() {
        for action in [
            ResponseActionKind::TerminateProcess,
            ResponseActionKind::StopService,
            ResponseActionKind::QuarantineFile,
            ResponseActionKind::BlockIndicator,
            ResponseActionKind::IsolateNetwork,
            ResponseActionKind::DisablePersistence,
            ResponseActionKind::CollectEvidence,
        ] {
            assert!(action.supports_dry_run(), "{action:?} must support dry_run");
        }
    }

    #[test]
    fn action_kind_wire_form_is_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&ResponseActionKind::CollectEvidence).unwrap(),
            "\"COLLECT_EVIDENCE\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseActionKind::TerminateProcess).unwrap(),
            "\"TERMINATE_PROCESS\""
        );
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p osiris-response`
Expected: FAIL — `destructive`/`supports_dry_run` methods don't exist yet (compile error).

- [ ] **Step 4: Implement `destructive()`/`supports_dry_run()`**

Add to `crates/osiris-response/src/lib.rs`, directly below the `ResponseActionKind` enum definition:

```rust
impl ResponseActionKind {
    /// Every kind except `CollectEvidence` is destructive per
    /// ARCHITECTURE.md §13's typed split.
    pub fn destructive(&self) -> bool {
        !matches!(self, ResponseActionKind::CollectEvidence)
    }

    /// Every kind supports dry-run in v1 — it is the one mode every
    /// action, destructive or not, can honor without the Agent command
    /// channel this phase does not build.
    pub fn supports_dry_run(&self) -> bool {
        true
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p osiris-response`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-response/Cargo.toml crates/osiris-response/src/lib.rs
git commit -m "feat(response): add osiris-response crate with ResponseActionKind"
```

---

### Task 2: entity-scoped event lookup helpers

**Files:**
- Create: `crates/osiris-response/src/query.rs`
- Modify: `crates/osiris-response/src/lib.rs` (add `mod query;`)

**Interfaces:**
- Consumes: `osiris_schema::EntityRef` (7 variants: `Process{process_key}`, `File{host_id,inode,device_id}`, `Ip{addr}`, `Domain{name}`, `User{host_id,uid}`, `Container{container_id}`, `Session{session_id}`); `osiris_storage::Storage::query_events(&EventQueryPlan) -> Result<Vec<CanonicalEvent>, StorageError>`; `osiris_query::EventQueryPlan{filter,since,until,limit,export}`; `osiris_query::ast::{Ast,Op,Value}`.
- Produces: `pub(crate) fn entity_query_ast(entity: &EntityRef) -> osiris_query::ast::Ast` and `pub(crate) fn events_for_entity(storage: &dyn Storage, entity: &EntityRef, since: u64, until: u64, limit: usize, export: bool) -> Result<Vec<CanonicalEvent>, StorageError>` — both consumed by Task 3's `dispatch()`.

- [ ] **Step 1: Write the failing tests**

Create `crates/osiris-response/src/query.rs`:

```rust
use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::{CanonicalEvent, EntityRef};
use osiris_storage::{Storage, StorageError};

/// Builds the OQL comparison that matches every event touching `entity`,
/// mirroring the field-per-kind approach `osiris-investigate`'s
/// `network_story`/`process_story` already use (ARCHITECTURE.md §12.1) —
/// one query primitive reused across every `EntityRef` kind rather than a
/// new one invented for the Response Engine.
pub(crate) fn entity_query_ast(entity: &EntityRef) -> Ast {
    match entity {
        EntityRef::Process { process_key } => Ast::Compare {
            field: "process.process_key".to_string(),
            op: Op::Eq,
            value: Value::Str(process_key.as_hex()),
        },
        EntityRef::File { inode, device_id, .. } => Ast::And(
            Box::new(Ast::Compare {
                field: "file.inode".to_string(),
                op: Op::Eq,
                value: Value::Num(*inode as f64),
            }),
            Box::new(Ast::Compare {
                field: "file.device_id".to_string(),
                op: Op::Eq,
                value: Value::Num(*device_id as f64),
            }),
        ),
        EntityRef::Ip { addr } => Ast::Or(
            Box::new(Ast::Compare {
                field: "network.src_ip".to_string(),
                op: Op::Eq,
                value: Value::Str(addr.clone()),
            }),
            Box::new(Ast::Compare {
                field: "network.dst_ip".to_string(),
                op: Op::Eq,
                value: Value::Str(addr.clone()),
            }),
        ),
        EntityRef::Domain { name } => Ast::Compare {
            field: "dns.query".to_string(),
            op: Op::Eq,
            value: Value::Str(name.clone()),
        },
        EntityRef::User { uid, .. } => Ast::Compare {
            field: "user.uid".to_string(),
            op: Op::Eq,
            value: Value::Num(*uid as f64),
        },
        EntityRef::Container { container_id } => Ast::Compare {
            field: "container.container_id".to_string(),
            op: Op::Eq,
            value: Value::Str(container_id.clone()),
        },
        EntityRef::Session { session_id } => Ast::Compare {
            field: "session.session_id".to_string(),
            op: Op::Eq,
            value: Value::Str(session_id.clone()),
        },
    }
}

/// Every event touching `entity` within `[since, until]`, bounded by
/// `limit` (clamped further to `osiris_query::MAX_EVENT_LIMIT` when
/// `export` is true — see `EventQueryPlan::effective_limit`).
pub(crate) fn events_for_entity(
    storage: &dyn Storage,
    entity: &EntityRef,
    since: u64,
    until: u64,
    limit: usize,
    export: bool,
) -> Result<Vec<CanonicalEvent>, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(entity_query_ast(entity)),
        since: Some(since),
        until: Some(until),
        limit,
        export,
    };
    storage.query_events(&plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, ContainerRef, DnsRef, EventType, FileRef, HostRef, NetworkDirection, NetworkRef,
        ProcessKey, ProcessRef, Severity, SessionRef, Source, UserRef, SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(host_id: Uuid, timestamp: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
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
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn entity_query_ast_matches_a_process_event_by_process_key() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let process_key = ProcessKey::new(host_id, "b", 42, 1000);
        let mut e = base_event(host_id, 1000);
        e.process = Some(ProcessRef {
            process_key,
            pid: 42,
            exe_path: "/bin/x".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1000,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Process { process_key },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].event_id, e.event_id);
    }

    #[test]
    fn entity_query_ast_matches_a_file_event_by_inode_and_device_id() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::FileWrite;
        e.category = Category::File;
        e.file = Some(FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(9),
            device_id: Some(1),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        storage.write(&e).unwrap();

        let target = EntityRef::File { host_id, inode: 9, device_id: 1 };
        let found = events_for_entity(&storage, &target, 0, u64::MAX, 10, false).unwrap();
        assert_eq!(found.len(), 1);

        let miss = EntityRef::File { host_id, inode: 999, device_id: 1 };
        assert!(events_for_entity(&storage, &miss, 0, u64::MAX, 10, false).unwrap().is_empty());
    }

    #[test]
    fn entity_query_ast_matches_an_ip_event_on_either_side_of_the_connection() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::NetworkConnect;
        e.category = Category::Network;
        e.network = Some(NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 5555,
            dst_ip: "203.0.113.10".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            bytes: None,
        });
        storage.write(&e).unwrap();

        let by_dst = events_for_entity(
            &storage,
            &EntityRef::Ip { addr: "203.0.113.10".to_string() },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(by_dst.len(), 1);
        let by_src = events_for_entity(
            &storage,
            &EntityRef::Ip { addr: "10.0.0.5".to_string() },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(by_src.len(), 1);
    }

    #[test]
    fn entity_query_ast_matches_a_domain_event_by_dns_query() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::DnsQuery;
        e.category = Category::Dns;
        e.dns = Some(DnsRef {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: None,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Domain { name: "cdn-assets.xyz".to_string() },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn entity_query_ast_matches_a_user_event_by_uid() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::SessionLogin;
        e.category = Category::Identity;
        e.user = Some(UserRef { uid: 0, gid: 0, euid: 0, egid: 0, username: Some("root".to_string()), loginuid: Some(0) });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::User { host_id, uid: 0 },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn entity_query_ast_matches_a_container_event_by_container_id() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::ContainerStart;
        e.category = Category::Container;
        e.container = Some(ContainerRef {
            container_id: "abc123".to_string(),
            image: "nginx".to_string(),
            runtime: "docker".to_string(),
            pod_ref: None,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Container { container_id: "abc123".to_string() },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn entity_query_ast_matches_a_session_event_by_session_id() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.session = Some(SessionRef {
            session_id: "3".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Session { session_id: "3".to_string() },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn events_for_entity_respects_the_since_until_window() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 5000);
        e.dns = Some(DnsRef { query: "x.example".to_string(), qtype: "A".to_string(), response_ips: vec![], ttl: None });
        e.event_type = EventType::DnsQuery;
        e.category = Category::Dns;
        storage.write(&e).unwrap();

        let target = EntityRef::Domain { name: "x.example".to_string() };
        assert_eq!(events_for_entity(&storage, &target, 0, 4000, 10, false).unwrap().len(), 0);
        assert_eq!(events_for_entity(&storage, &target, 0, u64::MAX, 10, false).unwrap().len(), 1);
    }
}
```

Note: all `EventType`/`Category` names used above (`ProcessExec`, `FileWrite`/`Category::File`, `NetworkConnect`/`Category::Network`, `DnsQuery`/`Category::Dns`, `SessionLogin`/`Category::Identity`, `ContainerStart`/`Category::Container`) were confirmed directly against `crates/osiris-schema/src/event_type.rs` while writing this plan — no further verification needed before running Step 3.

- [ ] **Step 2: Wire the new module into the crate**

Add to the top of `crates/osiris-response/src/lib.rs` (before the `ResponseActionKind` definition):

```rust
mod query;
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p osiris-response`
Expected: FAIL — `query` module referenced but not yet compiling cleanly against real field names until Step 1's names are verified against the schema (fix any mismatches found), then re-run until it's a clean compile with failing/passing assertions as expected for a fresh helper (it should actually pass immediately once compiling, since `events_for_entity` has no separate "unimplemented" stub — if it compiles, these tests already exercise real logic). If it compiles and passes on the first try, that is expected here (this task has no separate red/green code split — the helper's only failure mode is a schema-name mismatch, not missing behavior).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p osiris-response`
Expected: PASS (11 tests total: 3 from Task 1 + 8 new)

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-response/src/lib.rs crates/osiris-response/src/query.rs
git commit -m "feat(response): add entity-scoped event query helpers"
```

---

### Task 3: `dispatch()` — the full pipeline

**Files:**
- Create: `crates/osiris-response/src/dispatch.rs`
- Modify: `crates/osiris-response/src/lib.rs` (add `mod dispatch; pub use dispatch::dispatch;`, add `ResponseError` enum)

**Interfaces:**
- Consumes: Task 2's `query::{entity_query_ast, events_for_entity}` (crate-private, same crate); `osiris_evidence::{Evidence, EvidenceSource, Integrity, EvidenceStore, EvidenceIncidentLinks}`; `osiris_storage::Storage`.
- Produces: `pub fn dispatch(request: &ResponseRequest, storage: &dyn Storage, evidence_store: &dyn EvidenceStore, links: &dyn EvidenceIncidentLinks) -> Result<ResponseOutcome, ResponseError>` — consumed by Task 5's `osiris-api` handler.

- [ ] **Step 1: Write the failing tests**

Create `crates/osiris-response/src/dispatch.rs`:

```rust
use osiris_evidence::{Evidence, EvidenceIncidentLinks, EvidenceSource, Integrity};
use osiris_schema::{CanonicalEvent, EntityRef};
use osiris_storage::Storage;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::query::events_for_entity;
use crate::{ResponseActionKind, ResponseOutcome, ResponseRequest};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Builds the human-readable dry-run preview for `action` against
/// `target`, using one already-matched `sample` event for the
/// entity-specific detail a bare `EntityRef` cannot carry alone (a
/// process's pid, a file's path).
fn describe_target(action: ResponseActionKind, target: &EntityRef, sample: &CanonicalEvent) -> String {
    let verb = match action {
        ResponseActionKind::TerminateProcess => "terminate process",
        ResponseActionKind::StopService => "stop service",
        ResponseActionKind::QuarantineFile => "quarantine file",
        ResponseActionKind::BlockIndicator => "block indicator",
        ResponseActionKind::IsolateNetwork => "isolate network for",
        ResponseActionKind::DisablePersistence => "disable persistence for",
        ResponseActionKind::CollectEvidence => "collect evidence for",
    };
    let target_desc = match target {
        EntityRef::Process { process_key } => format!(
            "process {} (pid {}, host {})",
            process_key.as_hex(),
            sample.process.as_ref().map(|p| p.pid).unwrap_or(0),
            sample.host_id,
        ),
        EntityRef::File { inode, device_id, .. } => format!(
            "file at inode {} device {} (path {})",
            inode,
            device_id,
            sample.file.as_ref().map(|f| f.path.clone()).unwrap_or_default(),
        ),
        EntityRef::Ip { addr } => format!("network address {addr}"),
        EntityRef::Domain { name } => format!("domain {name}"),
        EntityRef::User { uid, .. } => format!("user uid {uid}"),
        EntityRef::Container { container_id } => format!("container {container_id}"),
        EntityRef::Session { session_id } => format!("session {session_id}"),
    };
    format!("would {verb} {target_desc} — no action taken, dry run")
}

/// Runs `request` through ARCHITECTURE.md §13's pipeline. Audit writing is
/// the caller's responsibility (`osiris-api`'s handler), not this
/// function's — `dispatch` is pure domain logic, deliberately free of any
/// `AuditLog` dependency (spec §2).
pub fn dispatch(
    request: &ResponseRequest,
    storage: &dyn Storage,
    evidence_store: &dyn osiris_evidence::EvidenceStore,
    links: &dyn EvidenceIncidentLinks,
) -> Result<ResponseOutcome, crate::ResponseError> {
    if request.dry_run {
        let sample = events_for_entity(storage, &request.target, 0, u64::MAX, 1, false)?;
        let Some(sample_event) = sample.into_iter().next() else {
            return Err(crate::ResponseError::UnknownTarget(request.target.clone()));
        };
        let description = describe_target(request.action, &request.target, &sample_event);
        return Ok(ResponseOutcome::DryRunPreview { description });
    }

    if !request.action.destructive() {
        let since = request.since.unwrap_or(0);
        let until = request.until.unwrap_or(u64::MAX);
        let events = events_for_entity(storage, &request.target, since, until, 10_000, true)?;
        let serialized = serde_json::to_vec(&events).expect("CanonicalEvent always serializes");
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let hash = hex::encode(hasher.finalize());
        let integrity = Integrity { hash, immutable_since: now_secs() };
        let evidence = Evidence::new(
            EvidenceSource::EventCapture,
            now_secs(),
            integrity,
            vec![request.target.clone()],
            None,
        )?;
        let inserted = evidence_store.insert(evidence)?;
        if let Some(incident_id) = request.incident_id {
            links.link(incident_id, inserted.evidence_id())?;
        }
        return Ok(ResponseOutcome::EvidenceCollected { evidence_id: inserted.evidence_id() });
    }

    Ok(ResponseOutcome::Rejected {
        reason: "Active Actions milestone not yet shipped — see ARCHITECTURE.md §13/§29".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore};
    use osiris_schema::{Category, DnsRef, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(host_id: Uuid, timestamp: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
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
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        storage: SqliteStorage,
        evidence: SqliteEvidenceStore,
        links: SqliteEvidenceIncidentLinks,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        Harness {
            storage: SqliteStorage::open(dir.path().join("events.db")).unwrap(),
            evidence: SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap(),
            links: SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap()).unwrap(),
            _dir: dir,
        }
    }

    fn process_request(action: ResponseActionKind, process_key: ProcessKey, dry_run: bool) -> ResponseRequest {
        ResponseRequest {
            action,
            target: EntityRef::Process { process_key },
            reason: "investigating".to_string(),
            dry_run,
            since: None,
            until: None,
            incident_id: None,
        }
    }

    #[test]
    fn dry_run_on_a_destructive_action_returns_a_preview_and_touches_nothing() {
        let h = harness();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 42, 1000);
        let mut e = base_event(host_id, 1000);
        e.process = Some(ProcessRef { process_key, pid: 42, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: 1000 });
        h.storage.write(&e).unwrap();

        let req = process_request(ResponseActionKind::TerminateProcess, process_key, true);
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        match outcome {
            ResponseOutcome::DryRunPreview { description } => {
                assert!(description.contains("terminate process"));
                assert!(description.contains("pid 42"));
                assert!(description.contains("dry run"));
            }
            other => panic!("expected DryRunPreview, got {other:?}"),
        }
        assert!(h.evidence.list().unwrap().is_empty(), "dry run must not create evidence");
    }

    #[test]
    fn dry_run_against_an_unresolvable_target_is_an_error() {
        let h = harness();
        let process_key = ProcessKey::new(Uuid::new_v4(), "b", 999, 1);
        let req = process_request(ResponseActionKind::TerminateProcess, process_key, true);
        let err = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap_err();
        assert!(matches!(err, crate::ResponseError::UnknownTarget(_)));
    }

    #[test]
    fn collect_evidence_executes_and_persists_a_record() {
        let h = harness();
        let host_id = Uuid::new_v4();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::DnsQuery;
        e.category = Category::Dns;
        e.dns = Some(DnsRef { query: "evil.example".to_string(), qtype: "A".to_string(), response_ips: vec![], ttl: None });
        h.storage.write(&e).unwrap();

        let req = ResponseRequest {
            action: ResponseActionKind::CollectEvidence,
            target: EntityRef::Domain { name: "evil.example".to_string() },
            reason: "collecting for incident review".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        let ResponseOutcome::EvidenceCollected { evidence_id } = outcome else {
            panic!("expected EvidenceCollected, got {outcome:?}");
        };
        let stored = h.evidence.get(evidence_id).unwrap().expect("evidence must be persisted");
        assert_eq!(stored.source(), EvidenceSource::EventCapture);
        assert!(!stored.integrity().hash.is_empty());
    }

    #[test]
    fn collect_evidence_with_zero_matching_events_still_succeeds() {
        let h = harness();
        let req = ResponseRequest {
            action: ResponseActionKind::CollectEvidence,
            target: EntityRef::Domain { name: "never-seen.example".to_string() },
            reason: "confirming absence".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        assert!(matches!(outcome, ResponseOutcome::EvidenceCollected { .. }));
    }

    #[test]
    fn collect_evidence_links_to_an_incident_when_one_is_given() {
        let h = harness();
        let incident_id = Uuid::now_v7();
        let req = ResponseRequest {
            action: ResponseActionKind::CollectEvidence,
            target: EntityRef::Domain { name: "linked.example".to_string() },
            reason: "linking test".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: Some(incident_id),
        };
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        let ResponseOutcome::EvidenceCollected { evidence_id } = outcome else { panic!("expected EvidenceCollected") };
        assert_eq!(h.links.evidence_ids_for_incident(incident_id).unwrap(), vec![evidence_id]);
    }

    #[test]
    fn every_destructive_action_is_rejected_when_not_a_dry_run() {
        let h = harness();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 42, 1000);
        let mut e = base_event(host_id, 1000);
        e.process = Some(ProcessRef { process_key, pid: 42, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: 1000 });
        h.storage.write(&e).unwrap();

        for action in [
            ResponseActionKind::TerminateProcess,
            ResponseActionKind::StopService,
            ResponseActionKind::QuarantineFile,
            ResponseActionKind::BlockIndicator,
            ResponseActionKind::IsolateNetwork,
            ResponseActionKind::DisablePersistence,
        ] {
            let req = process_request(action, process_key, false);
            let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
            match outcome {
                ResponseOutcome::Rejected { reason } => {
                    assert!(reason.contains("Active Actions"), "{action:?}: {reason}");
                }
                other => panic!("{action:?}: expected Rejected, got {other:?}"),
            }
        }
        assert!(h.evidence.list().unwrap().is_empty(), "no destructive action may create evidence");
    }
}
```

- [ ] **Step 2: Add `ResponseError` to `lib.rs` and wire the new module**

Add to `crates/osiris-response/src/lib.rs`, near the top (after the `mod query;` line):

```rust
mod dispatch;
pub use dispatch::dispatch;

#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    #[error("storage error: {0}")]
    Storage(#[from] osiris_storage::StorageError),
    #[error("evidence store error: {0}")]
    Evidence(#[from] osiris_evidence::EvidenceStoreError),
    #[error("evidence/incident link error: {0}")]
    Link(#[from] osiris_evidence::LinkStoreError),
    #[error("evidence construction error: {0}")]
    EvidenceBuild(#[from] osiris_evidence::EvidenceError),
    #[error("target entity does not resolve to any known data: {0:?}")]
    UnknownTarget(EntityRef),
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p osiris-response`
Expected: FAIL until `ResponseError`'s variants and `#[from]` conversions compile cleanly against the real `EvidenceStoreError`/`LinkStoreError`/`EvidenceError`/`StorageError` types (all four already exist and derive `thiserror::Error` — confirmed during planning). If a `?` conversion doesn't compile, it means one of these error types doesn't actually implement `std::error::Error` the way assumed; re-check with `grep -n "derive.*Error" crates/osiris-evidence/src/*.rs crates/osiris-storage/src/storage.rs` and adjust the `#[from]` wrapping accordingly.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p osiris-response`
Expected: PASS (17 tests total: 11 from Tasks 1-2 + 6 new)

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-response/src/lib.rs crates/osiris-response/src/dispatch.rs
git commit -m "feat(response): implement the dispatch() pipeline (dry-run, CollectEvidence, destructive rejection)"
```

---

### Task 4: RBAC — `/api/v1/response/*` requires `ResponseOperator`

**Files:**
- Modify: `crates/osiris-api/src/auth_middleware.rs`

**Interfaces:**
- Consumes: existing `fn min_role_for(method: &axum::http::Method, path: &str) -> Role` (in this file); existing `protected_app(state: AuthState) -> Router` test harness (in this file's `#[cfg(test)] mod tests`).
- Produces: `min_role_for` now returns `Role::ResponseOperator` for any method on a path starting with `/api/v1/response/` — consumed by Task 5's real router once merged into `main.rs` (Task 6).

- [ ] **Step 1: Write the failing tests**

In `crates/osiris-api/src/auth_middleware.rs`'s `#[cfg(test)] mod tests`, add a stub route to `protected_app` and new assertions. Find the existing `protected_app` function and add one more `.route(...)` call before `.route_layer(...)`:

```rust
            .route(
                "/api/v1/response/:action",
                axum::routing::post(|| async { "response-ok" }),
            )
```

Then add these two test functions (place them near `min_role_for_is_method_aware_on_the_mutating_investigation_routes`):

```rust
    #[test]
    fn min_role_for_requires_response_operator_on_every_response_route() {
        use axum::http::Method;
        assert_eq!(
            min_role_for(&Method::POST, "/api/v1/response/terminate_process"),
            Role::ResponseOperator
        );
        assert_eq!(
            min_role_for(&Method::POST, "/api/v1/response/collect_evidence"),
            Role::ResponseOperator
        );
        assert_eq!(
            min_role_for(&Method::GET, "/api/v1/response/collect_evidence"),
            Role::ResponseOperator
        );
    }

    #[tokio::test]
    async fn an_analyst_is_forbidden_from_the_response_route_but_a_response_operator_is_not() {
        let (_d1, _d2, state) = test_state();
        let analyst_token = session_for_role(&state, "analyst1", Role::Analyst);
        let operator_token = session_for_role(&state, "operator1", Role::ResponseOperator);
        let app = protected_app(state);

        let forbidden = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/response/terminate_process")
                    .header("Authorization", format!("Bearer {}", analyst_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/response/terminate_process")
                    .header("Authorization", format!("Bearer {}", operator_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p osiris-api min_role_for_requires_response_operator -- --nocapture` and `cargo test -p osiris-api an_analyst_is_forbidden_from_the_response_route`
Expected: FAIL — `min_role_for` still falls through to `Role::Viewer` for `/api/v1/response/*`, so the operator-should-be-403-for-Analyst assertion... actually the Analyst call will currently succeed with `200` (Viewer-level), not `403` — confirm the failure is exactly that (Analyst reaching `200` instead of `403`).

- [ ] **Step 3: Add the `min_role_for` rule**

In `crates/osiris-api/src/auth_middleware.rs`'s `min_role_for` function, add one more check before the final `Role::Viewer`:

```rust
    if path.starts_with("/api/v1/response/") {
        return Role::ResponseOperator;
    }
```

(Insert it after the existing `POST /api/v1/evidence` check and before `Role::Viewer` at the function's end — order among the `if` blocks doesn't matter here since the path prefixes don't overlap with the earlier ones, but keeping new rules appended preserves the file's existing chronological-by-phase layout.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p osiris-api`
Expected: PASS — full `osiris-api` suite green, including the 2 new tests.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-api/src/auth_middleware.rs
git commit -m "feat(api): require ResponseOperator on /api/v1/response/*"
```

---

### Task 5: `osiris-api` response handler

**Files:**
- Create: `crates/osiris-api/src/response.rs`
- Modify: `crates/osiris-api/src/lib.rs` (add `pub mod response; pub use response::{build_response_router, ResponseState};`)
- Modify: `crates/osiris-api/Cargo.toml` (add `osiris-response` dependency)

**Interfaces:**
- Consumes: `osiris_response::{ResponseActionKind, ResponseRequest, ResponseOutcome, ResponseError, dispatch}`; `osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry}`; `crate::auth_middleware::AuthContext` (from `Extension<AuthContext>`, populated by `auth_gate`); `osiris_evidence::{EvidenceStore, EvidenceIncidentLinks}`; `osiris_storage::Storage`.
- Produces: `pub struct ResponseState { pub storage: Arc<dyn Storage>, pub evidence: Arc<dyn EvidenceStore>, pub links: Arc<dyn EvidenceIncidentLinks>, pub audit_log: Arc<dyn AuditLog + Send + Sync> }`, `pub fn build_response_router(state: ResponseState) -> Router` — consumed by Task 6's `main.rs`.

- [ ] **Step 1: Add the `osiris-response` dependency**

In `crates/osiris-api/Cargo.toml`, add to `[dependencies]` (alongside the existing `osiris-evidence`/`osiris-audit`/`osiris-auth` lines):

```toml
osiris-response = { path = "../osiris-response" }
```

- [ ] **Step 2: Write the failing tests**

Create `crates/osiris-api/src/response.rs`:

```rust
use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_evidence::{EvidenceIncidentLinks, EvidenceStore};
use osiris_response::{dispatch, ResponseActionKind, ResponseError, ResponseOutcome, ResponseRequest};
use osiris_schema::EntityRef;
use osiris_storage::Storage;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth_middleware::AuthContext;

#[derive(Clone)]
pub struct ResponseState {
    pub storage: Arc<dyn Storage>,
    pub evidence: Arc<dyn EvidenceStore>,
    pub links: Arc<dyn EvidenceIncidentLinks>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
}

pub fn build_response_router(state: ResponseState) -> Router {
    Router::new()
        .route("/api/v1/response/:action", post(response_handler))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct ResponseRequestBody {
    target: EntityRef,
    reason: String,
    dry_run: bool,
    since: Option<u64>,
    until: Option<u64>,
    incident_id: Option<Uuid>,
}

fn parse_action(raw: &str) -> Option<ResponseActionKind> {
    serde_json::from_value(serde_json::Value::String(raw.to_string())).ok()
}

async fn response_handler(
    State(state): State<ResponseState>,
    Extension(ctx): Extension<AuthContext>,
    Path(action_raw): Path<String>,
    Json(body): Json<ResponseRequestBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(action) = parse_action(&action_raw) else {
        return Err((StatusCode::NOT_FOUND, format!("unknown response action: {action_raw}")));
    };
    if body.reason.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "reason must not be empty".to_string()));
    }

    let request = ResponseRequest {
        action,
        target: body.target,
        reason: body.reason.clone(),
        dry_run: body.dry_run,
        since: body.since,
        until: body.until,
        incident_id: body.incident_id,
    };

    let what = if request.dry_run {
        format!("response.{action_raw}.dry_run")
    } else {
        format!("response.{action_raw}.execute")
    };
    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User { user_id: ctx.user_id },
        what: what.clone(),
        target: request.target.clone(),
        why: Some(request.reason.clone()),
        result: AuditResult::Success,
    });

    let storage = state.storage.clone();
    let evidence = state.evidence.clone();
    let links = state.links.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        dispatch(&request, storage.as_ref(), evidence.as_ref(), links.as_ref())
    })
    .await
    .unwrap();

    match outcome {
        Ok(ResponseOutcome::DryRunPreview { description }) => {
            // Dry-run's single pre-execution entry above already records
            // this preview's full text via `why` — no second entry (see
            // spec §4's deliberate one-vs-two-entry asymmetry).
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({ "dry_run": true, "preview": description })),
            ))
        }
        Ok(ResponseOutcome::EvidenceCollected { evidence_id }) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: body_target_placeholder(&action_raw),
                why: Some(format!("{} (evidence_id={evidence_id})", "collected")),
                result: AuditResult::Success,
            });
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({ "dry_run": false, "evidence_id": evidence_id })),
            ))
        }
        Ok(ResponseOutcome::Rejected { reason }) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: body_target_placeholder(&action_raw),
                why: Some(reason.clone()),
                result: AuditResult::Failure,
            });
            Ok((
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({ "error": "not_implemented", "message": reason })),
            ))
        }
        Err(ResponseError::UnknownTarget(_)) => Err((
            StatusCode::BAD_REQUEST,
            "target does not resolve to any known data".to_string(),
        )),
        Err(e) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: EntityRef::Domain { name: "response-engine-internal-error".to_string() },
                why: Some(e.to_string()),
                result: AuditResult::Failure,
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
```

This first draft has a placeholder `body_target_placeholder(&action_raw)` that does not exist — that is deliberate: Step 2's job is to get the module compiling with real logic except for the one detail the tests below will pin down (what `target` the post-execution entry actually carries). Replace `body_target_placeholder(&action_raw)` in both call sites with the original request's target, which must be captured before `request` is moved into the `spawn_blocking` closure. Fix this now, in this same step, before writing the tests below — do not leave the placeholder in the file you save:

```rust
    let original_target = request.target.clone();
```

placed right after `let request = ResponseRequest { ... };` and above the pre-execution audit write, then replace both `body_target_placeholder(&action_raw)` calls with `original_target.clone()`.

Now append the test module at the bottom of `crates/osiris-api/src/response.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::FileAuditLog;
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore};
    use osiris_schema::{Category, DnsRef, EventType, HostRef, Severity, Source, CanonicalEvent, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;

    fn test_state() -> (tempfile::TempDir, ResponseState) {
        let dir = tempfile::tempdir().unwrap();
        let state = ResponseState {
            storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            evidence: Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap()),
            links: Arc::new(SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap()).unwrap()),
            audit_log: Arc::new(FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
        };
        (dir, state)
    }

    fn dns_event(host_id: Uuid, query: &str) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1000,
            monotonic_timestamp: 1000,
            event_type: EventType::DnsQuery,
            category: Category::Dns,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: Some(DnsRef { query: query.to_string(), qtype: "A".to_string(), response_ips: vec![], ttl: None }),
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    fn ctx() -> AuthContext {
        AuthContext { user_id: Uuid::now_v7(), role: osiris_auth::Role::ResponseOperator, token: "t".to_string() }
    }

    fn count_audit_entries(dir: &std::path::Path) -> usize {
        let log = FileAuditLog::open(dir.join("audit.jsonl")).unwrap();
        log.read_all().unwrap().len()
    }

    #[tokio::test]
    async fn dry_run_writes_exactly_one_audit_entry() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "audit-dry-run.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "audit-dry-run.example".to_string() },
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            Path("collect_evidence".to_string()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["dry_run"], serde_json::json!(true));
        assert_eq!(count_audit_entries(dir.path()), 1);
    }

    #[tokio::test]
    async fn collect_evidence_execute_writes_exactly_two_audit_entries() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "audit-execute.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "audit-execute.example".to_string() },
            reason: "collecting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            Path("collect_evidence".to_string()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(resp["evidence_id"].is_string());
        assert_eq!(count_audit_entries(dir.path()), 2);
    }

    #[tokio::test]
    async fn a_destructive_execute_request_returns_501_and_writes_two_audit_entries() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "audit-destructive.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "audit-destructive.example".to_string() },
            reason: "attempting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            Path("block_indicator".to_string()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(resp["error"], serde_json::json!("not_implemented"));
        assert_eq!(count_audit_entries(dir.path()), 2);
    }

    #[tokio::test]
    async fn an_empty_reason_is_rejected_before_any_audit_write() {
        let (dir, state) = test_state();
        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "x.example".to_string() },
            reason: "   ".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        let err = response_handler(State(state), Extension(ctx()), Path("collect_evidence".to_string()), Json(body))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(count_audit_entries(dir.path()), 0);
    }

    #[tokio::test]
    async fn an_unknown_action_segment_is_a_404() {
        let (_dir, state) = test_state();
        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "x.example".to_string() },
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        let err = response_handler(State(state), Extension(ctx()), Path("not_a_real_action".to_string()), Json(body))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_response_router_merges_without_a_route_collision() {
        let (_dir, state) = test_state();
        let storage_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(storage_dir.path().join("events.db")).unwrap());
        let merged: Router = crate::build_router(storage).merge(crate::build_response_router(state));
        let _ = std::hint::black_box(merged);
    }
}
```

This assumes `osiris_audit::AuditLog` has a `read_all()` method for tests to assert entry counts — verify this before running (`grep -n "fn read_all\|trait AuditLog" crates/osiris-audit/src/file_log.rs`). If the real method has a different name (e.g. `read_page`/`list`), use that name instead everywhere `count_audit_entries` calls it; check the existing `audit_handler` in `crates/osiris-api/src/auth.rs` for the exact method this codebase already uses to read the log back, and match it.

- [ ] **Step 3: Wire the module into `lib.rs`**

Add near the other `pub mod .../pub use ...` lines in `crates/osiris-api/src/lib.rs` (after the `stream` block):

```rust
pub mod response;
pub use response::{build_response_router, ResponseState};
```

- [ ] **Step 4: Run the tests to verify they fail, then pass**

Run: `cargo build -p osiris-api` first to shake out the placeholder/compile issues from Step 2 (fix `body_target_placeholder`, confirm the audit-log read-back method name, confirm `EventType::DnsQuery`/`Category::Dns` names). Then:

Run: `cargo test -p osiris-api`
Expected: PASS — full `osiris-api` suite green, including this task's 6 new tests and Task 4's RBAC tests.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-api/Cargo.toml crates/osiris-api/src/lib.rs crates/osiris-api/src/response.rs
git commit -m "feat(api): add POST /api/v1/response/:action handler with the two-phase audit pipeline"
```

---

### Task 6: Wire into `osiris-server`, full verification, commit

**Files:**
- Modify: `crates/osiris-server/src/main.rs`

**Interfaces:**
- Consumes: `osiris_api::{build_response_router, ResponseState}` (Task 5); existing `storage`, `incident_evidence_state.evidence`/`.links`, `audit_log` locals already present in `main()`.
- Produces: the composed router now also serves `/api/v1/response/:action`, gated by the same global `auth_gate` layer every other route already goes through.

- [ ] **Step 1: Add the import**

In `crates/osiris-server/src/main.rs`, extend the existing `osiris_api` imports (near the top, alongside the `build_incident_evidence_router`/`build_auth_router` lines):

```rust
use osiris_api::{build_response_router, ResponseState};
```

- [ ] **Step 2: Build `ResponseState` before `incident_evidence_state` is moved**

In `crates/osiris-server/src/main.rs`, immediately after the existing `let incident_evidence_state = IncidentEvidenceState { ... };` block (before it is consumed later by `.merge(build_incident_evidence_router(incident_evidence_state))`), insert:

```rust
    let response_state = ResponseState {
        storage: storage.clone(),
        evidence: incident_evidence_state.evidence.clone(),
        links: incident_evidence_state.links.clone(),
        audit_log: audit_log.clone(),
    };
```

- [ ] **Step 3: Merge the new router**

In the existing router-assembly expression:

```rust
    let app = osiris_server::apply_dev_cors(
        build_router(storage)
            .merge(build_incident_evidence_router(incident_evidence_state))
            .merge(build_stream_router(live_event_broadcaster))
            .merge(build_auth_router(auth_state.clone()))
            .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate)),
        config.dev_cors,
    );
```

add one more `.merge(...)` call for the response router, placed after the incident/evidence merge (order among merges doesn't matter to axum, but grouping it near its sibling investigation-surface routers keeps the composition readable):

```rust
    let app = osiris_server::apply_dev_cors(
        build_router(storage)
            .merge(build_incident_evidence_router(incident_evidence_state))
            .merge(build_response_router(response_state))
            .merge(build_stream_router(live_event_broadcaster))
            .merge(build_auth_router(auth_state.clone()))
            .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate)),
        config.dev_cors,
    );
```

- [ ] **Step 4: Build the whole workspace**

Run: `cargo build --workspace`
Expected: clean build, no errors. If `storage` was already moved by this point in the function by some earlier line not shown above, the compiler will report a use-after-move on `storage.clone()` in Step 2 — if so, move Step 2's block earlier, right after `incident_evidence_state` is constructed and before any line that consumes `storage` by value.

- [ ] **Step 5: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: every crate's tests pass, including the new `osiris-response` crate and `osiris-api`'s new tests. Grep the output for `FAILED` or `error\[` to confirm zero matches, the same way Phase 8a's own verification did.

- [ ] **Step 6: Rebuild the CLI/server/agent binaries and re-run `osiris-e2e-tests`**

Phase 8a's own session-note (recorded in project memory) flags that `cargo test --workspace` alone does not rebuild `osiris-cli`/`osiris-server`/`osiris-agent` binaries that `osiris-e2e-tests` invokes as real subprocesses — a stale binary from before this change would not exercise the new route at all (though this phase adds no new *required* auth wiring to those existing e2e tests, since `/api/v1/response/*` isn't called by any of them, this step is still cheap insurance against a stale binary masking an unrelated regression). Run:

```bash
cargo build -p osiris-cli -p osiris-server -p osiris-agent
cargo test -p osiris-e2e-tests
```

Expected: all pass.

- [ ] **Step 7: Final commit**

```bash
git add crates/osiris-server/src/main.rs
git commit -m "feat(server): wire the Response Engine into the composed router"
```

---

## Self-Review Notes (already applied above, recorded here for the executor's awareness)

- **Spec coverage:** §2 (types + dispatch) → Tasks 1-3. §3 (API, RBAC, request/response shapes, audit sequencing) → Tasks 4-5. §4 (error/audit-count table) → Task 5's tests assert the 1-vs-2 entry counts directly. §5 (testing) → covered per-task. §6 (Non-Goals) → deliberately no tasks for Console/CLI/history-endpoint/per-action-RBAC.
- **The `body_target_placeholder` step in Task 5** is intentionally called out as a fix-before-you-save instruction, not a real placeholder left in committed code — the plan's own no-placeholder rule applies to what ends up in the repository, and Task 5's steps explicitly say to replace it before writing the tests.
- **Audit-log read-back method name** (Task 5) and **exact `EventType` variant names** (Task 2) are flagged as "verify against the real source" rather than asserted outright, because they're read, not designed, in this plan — confirm-not-guess is safer than a name that turns out wrong across a dozen test call sites.
