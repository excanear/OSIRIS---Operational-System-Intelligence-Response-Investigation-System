# Phase 0 — Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the OSIRIS Cargo workspace and the five Phase 0 foundation crates (`osiris-schema`, `osiris-config`, `osiris-audit`, `osiris-health`, `osiris-selftelemetry`) plus workspace CI and the dependency-graph privilege-boundary check, with no sensors and no network-facing code — exactly the scope ARCHITECTURE.md §29 assigns to Phase 0.

**Architecture:** One Cargo workspace (`crates/*` members) with zero external service dependencies (no DB, no network daemon) — every crate here is a library used by both the future Agent and Server binaries. `osiris-schema` depends on nothing OSIRIS-internal (§27's hard rule) and defines the canonical event envelope; the other four crates are independent of each other and of `osiris-schema` except where noted below.

**Tech Stack:** Rust (edition 2021, stable toolchain), `serde`/`serde_json` for the schema, `sha2`+`hex` for hash chains, `uuid` (v4 + v7) for identifiers, `thiserror` for error types, `tracing`/`tracing-subscriber` for logging, `tempfile` for filesystem tests. No async runtime yet — nothing in Phase 0 does I/O that needs one.

**Spec:** `ARCHITECTURE.md` (project root) — primarily §9 (Event Schema v1), §20 (Plugin Architecture / CapabilityProbe), §22 (Audit System), §23 (Health/Self-Observability), §24 (Repository Structure), §25 (Technology Decisions), §27 (Dependency Graph / privilege boundary), §29 Phase 0 scope line.

## Global Constraints

- Zero external service dependencies in Phase 0 — no database, no network listener, no daemon (§10.2, §95/§96 ordering: correctness before operational complexity).
- `osiris-schema` must depend on nothing OSIRIS-internal; it is the base of the dependency graph (§27).
- `event_type`/`category`/`severity`/`source` are persisted as string enums (`SCREAMING_SNAKE_CASE`), never bare ints (§9.3).
- `ProcessRef.process_key = hash(host_id, boot_id, pid, start_time_monotonic)` — PIDs alone are never identity (§9.2/§29 of the master prompt, quoted in ARCHITECTURE.md §9.2).
- `schema_version` is a field on every event; schema evolves additively within a major version (§9.1).
- Health `DEGRADED`/`FAILED` states must structurally carry a `last_error` — "generic unhealthy" is not an allowed terminal state (§23).
- Audit entries are append-only and hash-chained (`prev_entry_hash`/`entry_hash`), never deleted by retention (§22/§10.5).
- No AI/LLM component anywhere in scope (project decision, 2026-08-30: Phase 9 removed from the roadmap entirely).
- `cargo tree`-based CI must fail the build if the §27 privilege-boundary dependency rules are violated, as workspace crates are added.

---

### Task 1: Workspace skeleton, git init, and `osiris-schema`

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `.gitignore`
- Create: `rust-toolchain.toml`
- Create: `crates/osiris-schema/Cargo.toml`
- Create: `crates/osiris-schema/src/lib.rs`
- Create: `crates/osiris-schema/src/process_key.rs`
- Create: `crates/osiris-schema/src/event_type.rs`
- Create: `crates/osiris-schema/src/entities.rs`
- Create: `crates/osiris-schema/src/relationships.rs`
- Create: `crates/osiris-schema/src/envelope.rs`

**Interfaces:**
- Produces: `osiris_schema::{CanonicalEvent, SCHEMA_VERSION, ProcessKey, EventType, Category, Severity, Source, EntityRef, EntityRelationship, Relation}` plus all `*Ref` entity types (`HostRef`, `UserRef`, `SessionRef`, `ProcessRef`, `ThreadRef`, `FileRef`, `NetworkRef`, `DnsRef`, `DeviceRef`, `ServiceRef`, `ContainerRef`, `PodRef`, `NamespaceRef`, `CgroupRef`, `KernelRef`, `RiskAnnotation`, `CloudContext`) — every later crate and every future sensor/pipeline/storage crate builds on these.

- [ ] **Step 1: Initialize git repository**

```bash
git init
```

- [ ] **Step 2: Create workspace root files**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "UNLICENSED"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
uuid = { version = "1.10", features = ["v4", "v7", "serde"] }
sha2 = "0.10"
hex = "0.4"
thiserror = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tempfile = "3"
```

`.gitignore`:
```text
/target
**/*.rs.bk
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 3: Create `osiris-schema` crate manifest**

`crates/osiris-schema/Cargo.toml`:
```toml
[package]
name = "osiris-schema"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
sha2 = { workspace = true }
```

- [ ] **Step 4: Write `process_key.rs` (with tests)**

`crates/osiris-schema/src/process_key.rs`:
```rust
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Composite process identity: hash(host_id, boot_id, pid, start_time_monotonic).
/// Solves PID reuse — two processes reusing the same PID within the same boot
/// get different keys because start_time_monotonic differs (ARCHITECTURE.md §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey([u8; 16]);

impl ProcessKey {
    pub fn new(host_id: Uuid, boot_id: &str, pid: u32, start_time_mono: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update(boot_id.as_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(start_time_mono.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        ProcessKey(bytes)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl Serialize for ProcessKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for ProcessKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom("process_key must decode to 16 bytes"));
        }
        let mut array = [0u8; 16];
        array.copy_from_slice(&bytes);
        Ok(ProcessKey(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_start_time_yields_different_key_for_same_pid() {
        let host_id = Uuid::new_v4();
        let key_a = ProcessKey::new(host_id, "boot-1", 1234, 1_000_000);
        let key_b = ProcessKey::new(host_id, "boot-1", 1234, 2_000_000);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn same_inputs_yield_same_key() {
        let host_id = Uuid::new_v4();
        let key_a = ProcessKey::new(host_id, "boot-1", 1234, 1_000_000);
        let key_b = ProcessKey::new(host_id, "boot-1", 1234, 1_000_000);
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn hex_round_trip_via_json() {
        let key = ProcessKey::new(Uuid::new_v4(), "boot-1", 42, 99);
        let json = serde_json::to_string(&key).unwrap();
        let back: ProcessKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }
}
```

Add `hex` to the crate's `Cargo.toml` dependencies (used above):
```toml
hex = { workspace = true }
```

- [ ] **Step 5: Write `event_type.rs` (with tests)**

`crates/osiris-schema/src/event_type.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    Process, File, Network, Dns, Identity, Privilege,
    Systemd, Persistence, KernelModule, Container, Security, System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Source { Ebpf, Audit, Fanotify, Procfs, Dbus, ContainerApi, Synthetic }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    ProcessExec, ProcessFork, ProcessExit,
    FileCreate, FileDelete, FileRename, FileMove, FileModify, FileWrite,
    FileExecute, FilePermissionChange, FileOwnerChange, FileAttributeChange,
    SocketCreate, SocketBind, SocketListen, NetworkConnect, NetworkAccept, NetworkClose,
    DnsQuery,
    SessionLogin, SessionLogout, SessionCreate, SessionTerminate,
    PrivilegeUidChange, PrivilegeGidChange, PrivilegeCapabilityChange, PrivilegeSudo, PrivilegeSetuid,
    ServiceCreate, ServiceModify, ServiceStart, ServiceStop, ServiceDelete, TimerCreate, TimerModify,
    PersistenceCreated, PersistenceModified, PersistenceRemoved,
    ModuleLoad, ModuleUnload,
    ContainerCreate, ContainerStart, ContainerStop, ContainerDestroy,
    LsmDenial, CapabilityUse,
    AgentHealth, SensorHealth, AgentStart, AgentStop,
}

impl EventType {
    /// Maps each event_type to its category, per ARCHITECTURE.md §9.3.
    pub fn category(self) -> Category {
        use EventType::*;
        match self {
            ProcessExec | ProcessFork | ProcessExit => Category::Process,
            FileCreate | FileDelete | FileRename | FileMove | FileModify | FileWrite
            | FileExecute | FilePermissionChange | FileOwnerChange | FileAttributeChange => Category::File,
            SocketCreate | SocketBind | SocketListen | NetworkConnect | NetworkAccept | NetworkClose => Category::Network,
            DnsQuery => Category::Dns,
            SessionLogin | SessionLogout | SessionCreate | SessionTerminate => Category::Identity,
            PrivilegeUidChange | PrivilegeGidChange | PrivilegeCapabilityChange | PrivilegeSudo | PrivilegeSetuid => Category::Privilege,
            ServiceCreate | ServiceModify | ServiceStart | ServiceStop | ServiceDelete | TimerCreate | TimerModify => Category::Systemd,
            PersistenceCreated | PersistenceModified | PersistenceRemoved => Category::Persistence,
            ModuleLoad | ModuleUnload => Category::KernelModule,
            ContainerCreate | ContainerStart | ContainerStop | ContainerDestroy => Category::Container,
            LsmDenial | CapabilityUse => Category::Security,
            AgentHealth | SensorHealth | AgentStart | AgentStop => Category::System,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_screaming_snake_case() {
        let json = serde_json::to_string(&EventType::ProcessExec).unwrap();
        assert_eq!(json, "\"PROCESS_EXEC\"");
    }

    #[test]
    fn category_mapping_matches_spec() {
        assert_eq!(EventType::NetworkConnect.category(), Category::Network);
        assert_eq!(EventType::FileCreate.category(), Category::File);
        assert_eq!(EventType::AgentHealth.category(), Category::System);
    }
}
```

- [ ] **Step 6: Write `entities.rs`**

`crates/osiris-schema/src/entities.rs`:
```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::event_type::Severity;
use crate::process_key::ProcessKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudContext {
    pub provider: String,
    pub instance_id: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRef {
    pub host_id: Uuid,
    pub hostname: String,
    pub distro: String,
    pub kernel_version: String,
    pub cloud: Option<CloudContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRef {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub username: Option<String>,
    pub loginuid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRef {
    pub session_id: String,
    pub tty: Option<String>,
    pub remote_addr: Option<String>,
    pub auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRef {
    pub process_key: ProcessKey,
    pub pid: u32,
    pub exe_path: String,
    pub cmdline: Vec<String>,
    pub exe_hash: Option<String>,
    pub start_time_mono: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRef {
    pub tid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRef {
    pub path: String,
    pub previous_path: Option<String>,
    pub inode: Option<u64>,
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkDirection { Inbound, Outbound }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRef {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub direction: NetworkDirection,
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRef {
    pub query: String,
    pub qtype: String,
    pub response_ips: Vec<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRef {
    pub device_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRef {
    pub unit_name: String,
    pub unit_type: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodRef {
    pub pod_name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRef {
    pub container_id: String,
    pub image: String,
    pub runtime: String,
    pub pod_ref: Option<PodRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceRef {
    pub pid_ns: u64,
    pub net_ns: u64,
    pub mnt_ns: u64,
    pub user_ns: u64,
    pub ipc_ns: u64,
    pub uts_ns: u64,
    pub cgroup_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CgroupVersion { V1, V2 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupRef {
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub version: CgroupVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRef {
    pub module_name: Option<String>,
    pub syscall_nr: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAnnotation {
    pub score: i32,
    pub severity: Severity,
    pub reasons: Vec<String>,
    pub rule_ids: Vec<String>,
}
```

- [ ] **Step 7: Write `relationships.rs`**

`crates/osiris-schema/src/relationships.rs`:
```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::process_key::ProcessKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityRef {
    Process { process_key: ProcessKey },
    File { host_id: Uuid, inode: u64, device_id: u64 },
    Ip { addr: String },
    Domain { name: String },
    User { host_id: Uuid, uid: u32 },
    Container { container_id: String },
    Session { session_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Relation {
    Spawned, ExecutedAs, Wrote, Read, ConnectedTo, ResolvedTo,
    BelongsToContainer, BelongsToPod, RunsInCgroup, TriggeredBySession,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationship {
    pub from: EntityRef,
    pub to: EntityRef,
    pub relation: Relation,
    pub event_id: Uuid,
    pub timestamp: u64,
}
```

- [ ] **Step 8: Write `envelope.rs` (with round-trip tests)**

`crates/osiris-schema/src/envelope.rs`:
```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::*;
use crate::event_type::{Category, EventType, Severity, Source};
use crate::relationships::EntityRelationship;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    pub event_id: Uuid,
    pub schema_version: String,
    pub host_id: Uuid,
    pub boot_id: String,

    pub timestamp: u64,
    pub monotonic_timestamp: u64,

    pub event_type: EventType,
    pub category: Category,
    pub severity: Severity,

    pub host: HostRef,
    pub user: Option<UserRef>,
    pub session: Option<SessionRef>,
    pub process: Option<ProcessRef>,
    pub parent_process: Option<ProcessRef>,
    pub thread: Option<ThreadRef>,
    pub file: Option<FileRef>,
    pub network: Option<NetworkRef>,
    pub dns: Option<DnsRef>,
    pub device: Option<DeviceRef>,
    pub service: Option<ServiceRef>,
    pub container: Option<ContainerRef>,
    pub namespace: Option<NamespaceRef>,
    pub cgroup: Option<CgroupRef>,
    pub kernel: Option<KernelRef>,

    pub source: Source,
    pub provider: String,
    pub raw_event: Option<Vec<u8>>,

    pub relationships: Vec<EntityRelationship>,
    pub tags: Vec<String>,
    pub risk: Option<RiskAnnotation>,

    /// Typed per event_type by the sensor that emits it — no sensor exists
    /// yet in Phase 0 (§29), so the concrete payload shapes arrive with the
    /// Phase 1 Process+Exec sensor. Kept untyped here deliberately.
    pub event_data: serde_json::Value,
}

impl CanonicalEvent {
    pub fn schema_version_matches(&self, expected: &str) -> bool {
        self.schema_version == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_key::ProcessKey;

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "boot-1".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 123_456_789,
            event_type: EventType::ProcessExec,
            category: EventType::ProcessExec.category(),
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "test-host".to_string(),
                distro: "ubuntu-24.04".to_string(),
                kernel_version: "6.8.0".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "boot-1", 4242, 123_456_789),
                pid: 4242,
                exe_path: "/usr/bin/curl".to_string(),
                cmdline: vec!["curl".to_string(), "https://example.com".to_string()],
                exe_hash: None,
                start_time_mono: 123_456_789,
            }),
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
            source: Source::Ebpf,
            provider: "exec_sensor/ebpf".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn round_trips_through_json() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: CanonicalEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.event_id, back.event_id);
        assert_eq!(
            event.process.as_ref().unwrap().process_key,
            back.process.as_ref().unwrap().process_key
        );
    }

    #[test]
    fn schema_version_check() {
        let event = sample_event();
        assert!(event.schema_version_matches(SCHEMA_VERSION));
        assert!(!event.schema_version_matches("2.0"));
    }
}
```

- [ ] **Step 9: Write `lib.rs`**

`crates/osiris-schema/src/lib.rs`:
```rust
pub mod entities;
pub mod envelope;
pub mod event_type;
pub mod process_key;
pub mod relationships;

pub use entities::*;
pub use envelope::{CanonicalEvent, SCHEMA_VERSION};
pub use event_type::{Category, EventType, Severity, Source};
pub use process_key::ProcessKey;
pub use relationships::{EntityRef, EntityRelationship, Relation};
```

- [ ] **Step 10: Run tests**

Run: `cargo test -p osiris-schema`
Expected: all tests pass (process_key: 3, event_type: 2, envelope: 2 = 7 tests).

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml .gitignore rust-toolchain.toml crates/osiris-schema
git commit -m "feat: workspace skeleton and osiris-schema (Event Schema v1)"
```

---

### Task 2: `osiris-config` — host identity and capability probe

**Files:**
- Create: `crates/osiris-config/Cargo.toml`
- Create: `crates/osiris-config/src/lib.rs`
- Create: `crates/osiris-config/src/host_identity.rs`
- Create: `crates/osiris-config/src/capability.rs`

**Interfaces:**
- Consumes: nothing from Task 1 (independent of `osiris-schema`).
- Produces: `osiris_config::{HostIdentity, HostIdentityError, CapabilityProbe, LinuxCapabilityProbe, FakeCapabilityProbe, SystemCapabilities, CgroupVersion}`. `CapabilityProbe` is the trait Phase 1 sensors will consume via `SensorContext` (ARCHITECTURE.md §4.1) to pick eBPF vs. fallback backends. `HostIdentity::load_or_create` produces the `host_id: Uuid` that `osiris-schema`'s `HostRef.host_id`/`CanonicalEvent.host_id` are populated from in Phase 1's pipeline.

- [ ] **Step 1: Create crate manifest**

`crates/osiris-config/Cargo.toml`:
```toml
[package]
name = "osiris-config"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
uuid = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 2: Write `host_identity.rs` (with tests)**

`crates/osiris-config/src/host_identity.rs`:
```rust
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum HostIdentityError {
    #[error("failed to read host_id file at {path}: {source}")]
    Read { path: PathBuf, #[source] source: std::io::Error },
    #[error("failed to write host_id file at {path}: {source}")]
    Write { path: PathBuf, #[source] source: std::io::Error },
    #[error("host_id file at {path} does not contain a valid UUID: {source}")]
    Parse { path: PathBuf, #[source] source: uuid::Error },
}

/// Loads the stable per-installation host_id from disk, generating and
/// persisting a new one on first run. ARCHITECTURE.md §9.2: "persisted in
/// /etc/osiris/host_id" (path is caller-supplied here, not hardcoded, so
/// tests and non-default installs can point elsewhere).
pub struct HostIdentity;

impl HostIdentity {
    pub fn load_or_create(path: &Path) -> Result<Uuid, HostIdentityError> {
        if path.exists() {
            let contents = fs::read_to_string(path)
                .map_err(|source| HostIdentityError::Read { path: path.to_path_buf(), source })?;
            Uuid::parse_str(contents.trim())
                .map_err(|source| HostIdentityError::Parse { path: path.to_path_buf(), source })
        } else {
            let id = Uuid::new_v4();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|source| HostIdentityError::Write { path: path.to_path_buf(), source })?;
            }
            fs::write(path, id.to_string())
                .map_err(|source| HostIdentityError::Write { path: path.to_path_buf(), source })?;
            Ok(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_persists_host_id_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host_id");
        let first = HostIdentity::load_or_create(&path).unwrap();
        let second = HostIdentity::load_or_create(&path).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_corrupted_host_id_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host_id");
        std::fs::write(&path, "not-a-uuid").unwrap();
        let result = HostIdentity::load_or_create(&path);
        assert!(matches!(result, Err(HostIdentityError::Parse { .. })));
    }
}
```

- [ ] **Step 3: Run tests for this module**

Run: `cargo test -p osiris-config host_identity`
Expected: 2 tests pass.

- [ ] **Step 4: Write `capability.rs` (with tests)**

`crates/osiris-config/src/capability.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CgroupVersion { V1, V2, Unknown }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemCapabilities {
    pub kernel_version: String,
    pub btf_available: bool,
    pub cgroup_version: CgroupVersion,
    pub lsms: Vec<String>,
}

/// Design surface for kernel/distro capability probing (ARCHITECTURE.md
/// §20/§4.1's `SensorContext.CapabilityProbe`): each sensor's backend
/// choice (eBPF vs. fallback) is decided against this, not assumed.
/// Phase 0 defines the trait and a Linux implementation; sensors consume
/// it starting Phase 1 (ARCHITECTURE.md §29).
pub trait CapabilityProbe: Send + Sync {
    fn probe(&self) -> SystemCapabilities;
}

/// Reads real system state. Only meaningful on Linux; the paths it reads
/// do not exist on other platforms, so probing there degrades to
/// conservative "unavailable" values rather than erroring — this keeps the
/// crate buildable and testable from any dev machine.
pub struct LinuxCapabilityProbe;

impl CapabilityProbe for LinuxCapabilityProbe {
    fn probe(&self) -> SystemCapabilities {
        SystemCapabilities {
            kernel_version: read_kernel_version(),
            btf_available: std::path::Path::new("/sys/kernel/btf/vmlinux").exists(),
            cgroup_version: detect_cgroup_version(),
            lsms: read_lsm_list(),
        }
    }
}

fn read_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn detect_cgroup_version() -> CgroupVersion {
    if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        CgroupVersion::V2
    } else if std::path::Path::new("/sys/fs/cgroup").exists() {
        CgroupVersion::V1
    } else {
        CgroupVersion::Unknown
    }
}

fn read_lsm_list() -> Vec<String> {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.trim().split(',').map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// Fixed-response probe for tests and any non-Linux dev environment.
pub struct FakeCapabilityProbe(pub SystemCapabilities);

impl CapabilityProbe for FakeCapabilityProbe {
    fn probe(&self) -> SystemCapabilities {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_probe_returns_configured_capabilities() {
        let caps = SystemCapabilities {
            kernel_version: "6.8.0-generic".to_string(),
            btf_available: true,
            cgroup_version: CgroupVersion::V2,
            lsms: vec!["apparmor".to_string()],
        };
        let probe = FakeCapabilityProbe(caps.clone());
        assert_eq!(probe.probe(), caps);
    }

    #[test]
    fn linux_probe_does_not_panic_when_paths_are_absent() {
        // On any OS/CI runner without these paths (including this dev
        // machine), probing must degrade gracefully, not panic.
        let probe = LinuxCapabilityProbe;
        let caps = probe.probe();
        assert!(caps.kernel_version == "unknown" || !caps.kernel_version.is_empty());
    }
}
```

- [ ] **Step 5: Write `lib.rs`**

`crates/osiris-config/src/lib.rs`:
```rust
pub mod capability;
pub mod host_identity;

pub use capability::{CapabilityProbe, CgroupVersion, FakeCapabilityProbe, LinuxCapabilityProbe, SystemCapabilities};
pub use host_identity::{HostIdentity, HostIdentityError};
```

- [ ] **Step 6: Run full crate test suite**

Run: `cargo test -p osiris-config`
Expected: 4 tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-config
git commit -m "feat: osiris-config host identity and capability probe"
```

---

### Task 3: `osiris-audit` — hash-chained audit log

**Files:**
- Create: `crates/osiris-audit/Cargo.toml`
- Create: `crates/osiris-audit/src/lib.rs`
- Create: `crates/osiris-audit/src/entry.rs`
- Create: `crates/osiris-audit/src/file_log.rs`

**Interfaces:**
- Consumes: nothing from Tasks 1–2.
- Produces: `osiris_audit::{ActorRef, AuditEntry, AuditResult, NewAuditEntry, AuditLog, AuditLogError, FileAuditLog}`. `AuditLog` is the trait the Agent and Server will both call into (ARCHITECTURE.md §22) whenever a security-relevant action occurs; `FileAuditLog` is the Phase 0/1 backend, replaced by the control-plane store's audit table behind the same trait once `osiris-storage` exists (Phase 1+).

- [ ] **Step 1: Create crate manifest**

`crates/osiris-audit/Cargo.toml`:
```toml
[package]
name = "osiris-audit"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 2: Write `entry.rs`**

`crates/osiris-audit/src/entry.rs`:
```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActorRef {
    User { user_id: Uuid },
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditResult { Success, Failure, Denied }

/// Caller-supplied fields for a new entry; the log fills in audit_id,
/// timestamp, and the hash chain fields on append (ARCHITECTURE.md §22).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuditEntry {
    pub who: ActorRef,
    pub what: String,
    pub target: String,
    pub why: Option<String>,
    pub result: AuditResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id: Uuid,
    pub timestamp: u64,
    pub who: ActorRef,
    pub what: String,
    pub target: String,
    pub why: Option<String>,
    pub result: AuditResult,
    pub prev_entry_hash: String,
    pub entry_hash: String,
}
```

- [ ] **Step 3: Write `file_log.rs` (with tests)**

`crates/osiris-audit/src/file_log.rs`:
```rust
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entry::{ActorRef, AuditEntry, AuditResult, NewAuditEntry};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000"; // 64 hex chars, matches SHA-256 output width

#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    #[error("failed to open audit log at {path}: {source}")]
    Open { path: PathBuf, #[source] source: std::io::Error },
    #[error("failed to write audit entry: {0}")]
    Write(#[from] std::io::Error),
    #[error("failed to serialize/deserialize audit entry: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("audit chain broken at entry {audit_id}: expected hash {expected}, found {found}")]
    ChainBroken { audit_id: Uuid, expected: String, found: String },
}

pub trait AuditLog {
    fn append(&self, entry: NewAuditEntry) -> Result<AuditEntry, AuditLogError>;
    fn read_all(&self) -> Result<Vec<AuditEntry>, AuditLogError>;
    fn verify_chain(&self) -> Result<(), AuditLogError>;
}

/// Append-only JSONL-backed audit log with a SHA-256 hash chain
/// (ARCHITECTURE.md §22/§17.2). Stands in for the control-plane store's
/// audit table until osiris-storage exists (Phase 1); the `AuditLog` trait
/// is the seam that migration happens behind.
pub struct FileAuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileAuditLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditLogError> {
        let path = path.into();
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| AuditLogError::Open { path: path.clone(), source })?;
        Ok(Self { path, lock: Mutex::new(()) })
    }

    fn last_hash(&self) -> Result<String, AuditLogError> {
        let entries = self.read_all()?;
        Ok(entries.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        prev_entry_hash: &str,
        audit_id: Uuid,
        timestamp: u64,
        who: &ActorRef,
        what: &str,
        target: &str,
        why: &Option<String>,
        result: AuditResult,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_entry_hash.as_bytes());
        hasher.update(audit_id.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(serde_json::to_vec(who).unwrap_or_default());
        hasher.update(what.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(why.clone().unwrap_or_default().as_bytes());
        hasher.update(serde_json::to_vec(&result).unwrap_or_default());
        hex::encode(hasher.finalize())
    }
}

impl AuditLog for FileAuditLog {
    fn append(&self, new_entry: NewAuditEntry) -> Result<AuditEntry, AuditLogError> {
        let _guard = self.lock.lock().unwrap();
        let prev_entry_hash = self.last_hash()?;
        let audit_id = Uuid::now_v7();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        let entry_hash = Self::compute_hash(
            &prev_entry_hash, audit_id, timestamp, &new_entry.who, &new_entry.what,
            &new_entry.target, &new_entry.why, new_entry.result,
        );
        let entry = AuditEntry {
            audit_id,
            timestamp,
            who: new_entry.who,
            what: new_entry.what,
            target: new_entry.target,
            why: new_entry.why,
            result: new_entry.result,
            prev_entry_hash,
            entry_hash,
        };
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| AuditLogError::Open { path: self.path.clone(), source })?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(entry)
    }

    fn read_all(&self) -> Result<Vec<AuditEntry>, AuditLogError> {
        let file = File::open(&self.path)
            .map_err(|source| AuditLogError::Open { path: self.path.clone(), source })?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str(&line)?);
        }
        Ok(entries)
    }

    fn verify_chain(&self) -> Result<(), AuditLogError> {
        let entries = self.read_all()?;
        let mut expected_prev = GENESIS_HASH.to_string();
        for entry in &entries {
            if entry.prev_entry_hash != expected_prev {
                return Err(AuditLogError::ChainBroken {
                    audit_id: entry.audit_id,
                    expected: expected_prev,
                    found: entry.prev_entry_hash.clone(),
                });
            }
            let recomputed = Self::compute_hash(
                &entry.prev_entry_hash, entry.audit_id, entry.timestamp, &entry.who,
                &entry.what, &entry.target, &entry.why, entry.result,
            );
            if recomputed != entry.entry_hash {
                return Err(AuditLogError::ChainBroken {
                    audit_id: entry.audit_id,
                    expected: recomputed,
                    found: entry.entry_hash.clone(),
                });
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> (tempfile::TempDir, FileAuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = FileAuditLog::open(&path).unwrap();
        (dir, log)
    }

    #[test]
    fn appended_entries_form_a_valid_chain() {
        let (_dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: "agent.yaml".to_string(),
            why: None,
            result: AuditResult::Success,
        }).unwrap();
        log.append(NewAuditEntry {
            who: ActorRef::User { user_id: Uuid::new_v4() },
            what: "rule_disable".to_string(),
            target: "rule:suspicious_execution_chain".to_string(),
            why: Some("false positive under investigation".to_string()),
            result: AuditResult::Success,
        }).unwrap();

        assert!(log.verify_chain().is_ok());
        assert_eq!(log.read_all().unwrap().len(), 2);
    }

    #[test]
    fn tampered_entry_breaks_verification() {
        let (dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: "agent.yaml".to_string(),
            why: None,
            result: AuditResult::Success,
        }).unwrap();

        let path = dir.path().join("audit.jsonl");
        let contents = std::fs::read_to_string(&path).unwrap();
        let tampered = contents.replace("config_reload", "config_wipe");
        std::fs::write(&path, tampered).unwrap();

        assert!(matches!(log.verify_chain(), Err(AuditLogError::ChainBroken { .. })));
    }

    #[test]
    fn empty_log_verifies_trivially() {
        let (_dir, log) = temp_log();
        assert!(log.verify_chain().is_ok());
    }
}
```

- [ ] **Step 4: Write `lib.rs`**

`crates/osiris-audit/src/lib.rs`:
```rust
pub mod entry;
pub mod file_log;

pub use entry::{ActorRef, AuditEntry, AuditResult, NewAuditEntry};
pub use file_log::{AuditLog, AuditLogError, FileAuditLog, GENESIS_HASH};
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p osiris-audit`
Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-audit
git commit -m "feat: osiris-audit hash-chained append-only audit log"
```

---

### Task 4: `osiris-health` — health state and aggregation

**Files:**
- Create: `crates/osiris-health/Cargo.toml`
- Create: `crates/osiris-health/src/lib.rs`
- Create: `crates/osiris-health/src/state.rs`
- Create: `crates/osiris-health/src/aggregate.rs`

**Interfaces:**
- Consumes: nothing from Tasks 1–3.
- Produces: `osiris_health::{HealthState, SensorHealth, AgentHealth, HealthAggregator}`. Phase 1's Agent Supervisor calls `HealthAggregator::record_sensor` per sensor and forwards `HealthAggregator::aggregate()` as `AGENT_HEALTH`/`SENSOR_HEALTH` events into the pipeline (ARCHITECTURE.md §23), using `osiris_schema::EventType::{AgentHealth, SensorHealth}` from Task 1 as the `event_type`.

- [ ] **Step 1: Create crate manifest**

`crates/osiris-health/Cargo.toml`:
```toml
[package]
name = "osiris-health"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
```

- [ ] **Step 2: Write `state.rs` (with tests)**

`crates/osiris-health/src/state.rs`:
```rust
use serde::{Deserialize, Serialize};

/// ARCHITECTURE.md §23: "generic unhealthy" is not an allowed terminal
/// state — Degraded/Failed must carry a reason. Enforced structurally: it
/// is impossible to construct either variant without a `last_error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthState {
    Healthy,
    Degraded { last_error: String },
    Failed { last_error: String },
}

impl HealthState {
    /// Ordering for aggregation: Failed worst, then Degraded, then Healthy.
    pub fn severity_rank(&self) -> u8 {
        match self {
            HealthState::Healthy => 0,
            HealthState::Degraded { .. } => 1,
            HealthState::Failed { .. } => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorHealth {
    pub sensor_name: String,
    pub state: HealthState,
    pub events_processed: u64,
    pub last_event_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_outranks_degraded_outranks_healthy() {
        assert!(
            HealthState::Failed { last_error: "x".into() }.severity_rank()
                > HealthState::Degraded { last_error: "x".into() }.severity_rank()
        );
        assert!(
            HealthState::Degraded { last_error: "x".into() }.severity_rank()
                > HealthState::Healthy.severity_rank()
        );
    }
}
```

- [ ] **Step 3: Write `aggregate.rs` (with tests)**

`crates/osiris-health/src/aggregate.rs`:
```rust
use serde::{Deserialize, Serialize};

use crate::state::{HealthState, SensorHealth};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub state: HealthState,
    pub sensors: Vec<SensorHealth>,
}

/// Aggregates per-sensor health into Agent-level health (ARCHITECTURE.md
/// §23): overall state is the worst state among all sensors.
#[derive(Default)]
pub struct HealthAggregator {
    sensors: Vec<SensorHealth>,
}

impl HealthAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sensor(&mut self, health: SensorHealth) {
        self.sensors.retain(|s| s.sensor_name != health.sensor_name);
        self.sensors.push(health);
    }

    pub fn aggregate(&self) -> AgentHealth {
        let worst = self.sensors.iter()
            .map(|s| &s.state)
            .max_by_key(|state| state.severity_rank())
            .cloned()
            .unwrap_or(HealthState::Healthy);
        AgentHealth { state: worst, sensors: self.sensors.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sensors_is_healthy() {
        let agg = HealthAggregator::new();
        assert_eq!(agg.aggregate().state, HealthState::Healthy);
    }

    #[test]
    fn one_failed_sensor_makes_agent_failed() {
        let mut agg = HealthAggregator::new();
        agg.record_sensor(SensorHealth {
            sensor_name: "exec".into(),
            state: HealthState::Healthy,
            events_processed: 10,
            last_event_at: Some(1),
        });
        agg.record_sensor(SensorHealth {
            sensor_name: "network".into(),
            state: HealthState::Failed { last_error: "eBPF load failure: verifier rejected program".into() },
            events_processed: 0,
            last_event_at: None,
        });
        let health = agg.aggregate();
        assert!(matches!(health.state, HealthState::Failed { .. }));
        assert_eq!(health.sensors.len(), 2);
    }

    #[test]
    fn re_recording_a_sensor_replaces_its_entry() {
        let mut agg = HealthAggregator::new();
        agg.record_sensor(SensorHealth {
            sensor_name: "exec".into(), state: HealthState::Healthy,
            events_processed: 1, last_event_at: Some(1),
        });
        agg.record_sensor(SensorHealth {
            sensor_name: "exec".into(),
            state: HealthState::Degraded { last_error: "queue overflow: dropped 12 events".into() },
            events_processed: 2, last_event_at: Some(2),
        });
        let health = agg.aggregate();
        assert_eq!(health.sensors.len(), 1);
        assert!(matches!(health.sensors[0].state, HealthState::Degraded { .. }));
    }
}
```

- [ ] **Step 4: Write `lib.rs`**

`crates/osiris-health/src/lib.rs`:
```rust
pub mod aggregate;
pub mod state;

pub use aggregate::{AgentHealth, HealthAggregator};
pub use state::{HealthState, SensorHealth};
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p osiris-health`
Expected: 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-health
git commit -m "feat: osiris-health state model and aggregation"
```

---

### Task 5: `osiris-selftelemetry` — logging and metrics glue

**Files:**
- Create: `crates/osiris-selftelemetry/Cargo.toml`
- Create: `crates/osiris-selftelemetry/src/lib.rs`
- Create: `crates/osiris-selftelemetry/src/logging.rs`
- Create: `crates/osiris-selftelemetry/src/metrics.rs`

**Interfaces:**
- Consumes: nothing from Tasks 1–4.
- Produces: `osiris_selftelemetry::{init_logging, Counter, MetricsRegistry}`. Phase 1's Agent/Server binaries call `init_logging` at startup; the Event Bus (§8.2, per-lane counters) and sensors (§3.3) will register counters through `MetricsRegistry`.

- [ ] **Step 1: Create crate manifest**

`crates/osiris-selftelemetry/Cargo.toml`:
```toml
[package]
name = "osiris-selftelemetry"
version.workspace = true
edition.workspace = true

[dependencies]
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
```

- [ ] **Step 2: Write `logging.rs`**

`crates/osiris-selftelemetry/src/logging.rs`:
```rust
use tracing_subscriber::{fmt, EnvFilter};

/// Initializes structured logging shared by Agent and Server binaries.
/// Level defaults to `default_level`, overridable via `RUST_LOG`.
pub fn init_logging(default_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level.to_string()));
    let _ = fmt().with_env_filter(filter).with_target(true).try_init();
}
```

- [ ] **Step 3: Write `metrics.rs` (with tests)**

`crates/osiris-selftelemetry/src/metrics.rs`:
```rust
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Minimal in-process metrics registry (per-lane bus counters, sensor
/// event counts — ARCHITECTURE.md §8.2/§23). Kept dependency-free rather
/// than pulling in a full metrics facade for Phase 0's needs.
#[derive(Default)]
pub struct MetricsRegistry {
    counters: RwLock<HashMap<String, Counter>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn counter(&self, name: &str) -> Counter {
        if let Some(c) = self.counters.read().unwrap().get(name) {
            return c.clone();
        }
        let mut counters = self.counters.write().unwrap();
        counters.entry(name.to_string()).or_insert_with(Counter::default).clone()
    }

    pub fn snapshot(&self) -> HashMap<String, u64> {
        self.counters.read().unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.get()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments_are_visible_via_snapshot() {
        let registry = MetricsRegistry::new();
        registry.counter("bus.high.enqueued").increment();
        registry.counter("bus.high.enqueued").add(4);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.get("bus.high.enqueued"), Some(&5));
    }

    #[test]
    fn same_name_returns_the_same_shared_counter() {
        let registry = MetricsRegistry::new();
        let a = registry.counter("sensor.exec.events");
        let b = registry.counter("sensor.exec.events");
        a.increment();
        assert_eq!(b.get(), 1);
    }
}
```

- [ ] **Step 4: Write `lib.rs`**

`crates/osiris-selftelemetry/src/lib.rs`:
```rust
pub mod logging;
pub mod metrics;

pub use logging::init_logging;
pub use metrics::{Counter, MetricsRegistry};
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p osiris-selftelemetry`
Expected: 2 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-selftelemetry
git commit -m "feat: osiris-selftelemetry logging and metrics glue"
```

---

### Task 6: Dependency-graph CI enforcement and workspace CI

**Files:**
- Create: `tools/check-dep-graph.sh`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the crate names introduced in Tasks 1–5, plus the not-yet-existing crate names from §27's rule (`osiris-server`, `osiris-api`, `osiris-agent`, `osiris-sensors`, `osiris-ebpf`, `osiris-kernel`, `osiris-storage*`, `osiris-detect`, `osiris-correlate`, `osiris-risk`) — the script tolerates crates that don't exist yet so it keeps working unmodified as Phase 1+ adds them.
- Produces: a `bash tools/check-dep-graph.sh` command any later task/CI run can call; a GitHub Actions workflow gating `fmt`/`clippy`/`test`/dep-graph on every push and PR.

- [ ] **Step 1: Write the dependency-graph check script**

`tools/check-dep-graph.sh`:
```bash
#!/usr/bin/env bash
# Enforces ARCHITECTURE.md §27's privilege-boundary dependency rules:
# osiris-sensors/*, osiris-ebpf, osiris-kernel must never reach osiris-server
# or osiris-api; osiris-storage-*, osiris-detect, osiris-correlate,
# osiris-risk must never reach osiris-agent; osiris-schema must not depend
# on any other OSIRIS-internal crate. Crates that don't exist yet in the
# workspace are skipped so this script keeps working unmodified as later
# phases add them.
set -euo pipefail

fail=0

crate_exists() {
  cargo tree -p "$1" >/dev/null 2>&1
}

check_no_internal_deps() {
  local crate="$1"
  if ! crate_exists "$crate"; then
    echo "skip: $crate not in workspace yet"
    return
  fi
  local deps
  deps=$(cargo tree -p "$crate" --prefix none | tail -n +2 | grep -E "^osiris-" || true)
  if [ -n "$deps" ]; then
    echo "FAIL: $crate must depend on nothing OSIRIS-internal, found:"
    echo "$deps"
    fail=1
  fi
}

check_forbidden() {
  local crate="$1"
  shift
  if ! crate_exists "$crate"; then
    echo "skip: $crate not in workspace yet"
    return
  fi
  local tree
  tree=$(cargo tree -p "$crate" --prefix none)
  for forbidden in "$@"; do
    if echo "$tree" | grep -qE "^${forbidden}[[:space:]-]"; then
      echo "FAIL: $crate depends on forbidden crate matching '$forbidden' (ARCHITECTURE.md §27)"
      fail=1
    fi
  done
}

check_no_internal_deps osiris-schema
check_forbidden osiris-server osiris-sensors osiris-ebpf osiris-kernel
check_forbidden osiris-api osiris-sensors osiris-ebpf osiris-kernel
check_forbidden osiris-agent osiris-storage osiris-detect osiris-correlate osiris-risk

if [ "$fail" -ne 0 ]; then
  echo "Dependency-graph check FAILED"
  exit 1
fi
echo "Dependency-graph check PASSED"
```

- [ ] **Step 2: Make it executable and run it locally**

```bash
chmod +x tools/check-dep-graph.sh
bash tools/check-dep-graph.sh
```

Expected output ends with `Dependency-graph check PASSED` (all Phase-1+ crates print `skip: ... not in workspace yet`; `osiris-schema` is actually checked and passes since it has no OSIRIS-internal dependencies).

- [ ] **Step 3: Write the CI workflow**

`.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Format check
        run: cargo fmt --all -- --check
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Test
        run: cargo test --workspace
      - name: Dependency-graph enforcement
        run: bash tools/check-dep-graph.sh
```

- [ ] **Step 4: Verify the whole workspace builds, formats, lints, and tests clean**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: format check passes (or run `cargo fmt --all` first to fix and re-check), clippy reports no warnings, all 20 tests across the five crates pass (7 + 4 + 3 + 4 + 2).

- [ ] **Step 5: Commit**

```bash
git add tools/check-dep-graph.sh .github/workflows/ci.yml
git commit -m "chore: dependency-graph CI enforcement and workspace CI workflow"
```

---

## Exit Criterion

`cargo test --workspace` passes with zero warnings under `cargo clippy --workspace --all-targets -- -D warnings`, `bash tools/check-dep-graph.sh` passes, and the five Phase 0 crates listed in ARCHITECTURE.md §29 exist with no sensor code and no external service dependency anywhere in the workspace. This matches Phase 0's scope exactly; Phase 1 (Agent skeleton, Process+Exec Sensor, Event Pipeline, SQLite storage, minimal API/CLI) is a separate plan that consumes these five crates.
