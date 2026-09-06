# Phase 2 — Filesystem Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Phase 1's working Process/Exec vertical slice to filesystem telemetry — a real Filesystem Sensor (auditd `SYSCALL`+`PATH` record correlation), file events flowing through the existing Pipeline/Bus/Storage/API path, a File Story query endpoint, Timeline coverage for the file category, and a first stateless Detection rule that fires on file events and persists a structurally-explained `Alert`.

**Architecture:** A new `osiris-sensors-fs` sensor tails an auditd-format log file and assembles each audit event's correlated `type=SYSCALL` + `type=PATH` (+ `type=CWD`) records — which share one `msg=audit(<ts>:<serial>)` id — into `RawEvent::File(FileEventRaw)` records. Those flow through the *existing* Phase 1 Pipeline (Normalize/Enrich/Validate/Prioritize), Event Bus, spool file, and Server ingestion, unchanged in shape. Storage gains file-path and file-identity filters plus an alerts table; the Server's ingest path additionally runs a new `osiris-detect` single-event rule matcher after each successful `batch_write` and persists the resulting `Alert`s. The API gains `GET /api/v1/files/story` (path → file identities → identity-joined events → citing alerts) and `GET /api/v1/alerts`. Phase 1's two near-duplicate file tailers are collapsed into one shared `osiris-fileutil` crate before a third copy can be written.

**Tech Stack:** Rust (edition 2021), Tokio, `async-trait`, `axum`, `rusqlite` (`bundled`), `clap`, `reqwest` (blocking, CLI), `serde_yaml` (rule files), `sha2`/`hex` (rule content hashing) — all already present in `[workspace.dependencies]`. No new third-party crates are introduced by this phase.

**Spec:** `ARCHITECTURE.md` (project root) — primarily §2.1 (layering rule), §4.1/§4.3 (Sensor trait + the Filesystem row's fallback backend), §6 (telemetry levels, Filesystem STANDARD row), §7.1 (Event Pipeline stages), §8 (Event Bus), §9.2/§9.3/§9.4 (Event Schema v1 envelope, `FILE_*` taxonomy, `EntityRef::File` identity), §10.1 (Storage trait), §11.1/§11.2 (Detection Engine + the structural explanation requirement), §12.1 (`file_story`), §12.4 (Timeline Engine), §14.2 (endpoint surface), §15 (CLI), §24 (repo structure), §26 (worked trace), §27 (dependency graph / privilege boundary), §29's Phase 2 line. Phase 1's plan (`docs/superpowers/plans/2026-08-31-phase-1-core-v0.1.md`) is the immediate prior art this plan builds on and, in two places, deliberately reverses.

## Global Constraints — scope decisions made for this plan (read before dispatching any task)

The development environment is unchanged from Phase 1: Windows, no Linux kernel, no clang/libbpf toolchain, no root, no `auditd`, no fanotify. Phase 1's response was not to fake a sensor but to implement §4.3's *documented fallback backend* as portable Rust. Phase 2 applies the same strategy to the Filesystem sensor. The following decisions are disclosed and reversible; every task's requirements implicitly include this section.

1. **No eBPF LSM hooks, no fanotify, no inotify.** The Filesystem sensor's only backend in this phase is the Linux Audit fallback from ARCHITECTURE.md §4.3's Filesystem row ("Audit (`watch` rules), inotify"), consumed by tailing an auditd-format log file. `SensorCapabilities.ebpf` stays `false`. Real fanotify/eBPF-LSM backends are deferred to whenever a Linux development machine exists; because they are additional `Sensor` implementations behind the same unchanged trait, retrofitting them is not a rewrite (§4.3's explicit design justification).

2. **Audit correlation is implemented for real, not simplified to one-line-per-event.** Unlike `execve` (which Phase 1 could read from a single `type=SYSCALL` line), a file syscall emits **multiple records sharing one audit event id**: one `type=SYSCALL`, an optional `type=CWD`, and one `type=PATH` per path operand, e.g. `type=PATH ... item=1 name="/tmp/foo" inode=131075 dev=08:01 mode=0100644 ouid=1000 ogid=1000 nametype=DELETE`. This plan implements a real assembler that groups records by the `msg=audit(<secs>.<millis>:<serial>)` header, joins them, resolves relative `name=` values against the group's `CWD` record, and derives file operations from the `nametype` field (`PARENT`/`NORMAL`/`CREATE`/`DELETE`) plus the syscall number. Anything less would silently mis-report file operations.

3. **A shared `osiris-fileutil` crate is extracted — this deliberately reverses Phase 1's Global Constraint #7.** Phase 1 deferred a shared crate and shipped two near-identical tailers (`crates/osiris-server/src/tailer.rs`, `crates/osiris-sensors/process/src/audit_tailer.rs`); Phase 1's own final review found one read-race bug that had to be fixed twice as a direct result. Phase 2 needs a third consumer, so the shared crate is created *first* (Task 2) and all three consumers use it. It holds exactly two things — `line_tailer::LineTailer` (poll a growing file for complete new lines, buffer partial trailing lines, restart on truncation/rotation) and `audit_kv` (auditd `key="value"` tokenizing and `msg=audit(...)` header parsing) — and depends on nothing OSIRIS-internal.

4. **The shared crate is named `osiris-fileutil`, not `osiris-kernel`.** ARCHITECTURE.md §24 reserves `osiris-kernel` for shared *non-eBPF kernel-telemetry backend* code, and `tools/check-dep-graph.sh` mechanically forbids `osiris-server` from depending on anything matching `osiris-kernel` (§27's privilege boundary). Since `osiris-server` is one of the three consumers, reusing that name would break the boundary check. `osiris-fileutil` is unprivileged, pure-Rust, zero-internal-dependency host-file parsing, which the Server may legitimately share; Task 2 adds `check_no_internal_deps osiris-fileutil` to the boundary script so it stays a leaf.

5. **Telemetry scope is §6's Filesystem STANDARD row only:** create / delete / rename / write on watched paths. No read events, no hash-on-write, no permission/owner/attribute-change events — those are §6's DETAILED and FORENSIC rows and belong to a later phase. Concretely, this phase emits exactly four event types: `FILE_CREATE`, `FILE_WRITE`, `FILE_DELETE`, `FILE_RENAME`.

6. **File identity is `(host_id, inode, device_id)`, per §9.4 — path is the lookup key, identity is the join key.** `device_id` is OSIRIS's own lossless encoding `((major as u64) << 32) | (minor as u64)` of the audit `PATH` record's `dev=MAJ:MIN` (hex) field — deliberately **not** the kernel's `dev_t` bit layout, whose glibc encoding scatters major bits and is not what auditd prints. This choice is what makes a File Story survive a rename: the renamed file keeps its inode, so an identity-joined query finds events under both names.

7. **`osiris-schema` gains two new types and one new optional field; Event Schema v1's envelope is not changed.** New: `FileIdentity` and `Alert` (plus `AlertStatus`/`AlertError`). Changed: `FileRef` gains `device_id: Option<u64>` with `#[serde(default)]`. This is additive and safe — §9.4 *already* defines file identity as `(host_id, inode, device_id)`, so `FileRef` lacking a device field was an internal inconsistency in the frozen schema, and no event ever persisted by Phase 1 populates `file` at all (every construction site sets `file: None`), so no stored JSON can fail to deserialize. The `EventType` taxonomy is **not** extended: every `FILE_*` variant this phase emits already exists from Phase 0 and already maps to `Category::File`.

8. **`Alert` lives in `osiris-schema`, not in `osiris-detect`.** `osiris-storage` must persist alerts; if `Alert` lived in `osiris-detect`, `osiris-storage` would have to depend on a detection crate, inverting §2.1's layering rule (data contracts below engines). `Alert` is a persisted control-plane record per §12.7, i.e. a data contract, so `osiris-schema` — which both `osiris-storage` and `osiris-detect` already depend on, and which depends on nothing internal — is its correct home.

9. **§11.2's explanation requirement is enforced at the type level, including across the wire.** `Alert`'s fields are private; the only ways to obtain one are `Alert::new(...) -> Result<Alert, AlertError>` (which rejects an empty `rule_id`, empty/blank `reasons`, or empty `evidence`) and a hand-written `Deserialize` that runs the same validation. There is no struct-literal path and no "deserialize a bare `Threat detected`" path.

10. **Detection is single-event and stateless. No `sequence`, no `window`, no state tables, no hot-reload** — those are Phase 6 (§11.1/§29). The rule file format is a strict subset of §11.1's YAML: `id`, `version`, `severity`, and a `match:` list of `{field, op, value, reason}` conditions, all ANDed, evaluated against the event's own JSON projection by dotted field path. **One deliberate deviation from §11.1's sketch:** the explanation `reason` is attached *per condition* rather than as a free-floating `explain.reasons:` list, which makes §11.2's "one per matched condition, not a generic template" structural rather than a convention a rule author can violate. A positional `explain.reasons` list remains trivially derivable from this shape if a later phase wants it.

11. **File Story is a composed query, not the Investigation Engine.** §12.1's `file_story(file_identity) -> FileStory` is implemented as: resolve the requested path (or file id) to the set of file identities seen there → union the events matching the path with the events matching each identity → time-order them → attach every `Alert` whose evidence cites one of those events. Full multi-edge graph traversal, `process_story`/`network_story`/`system_story`, and `reconstruct_incident` remain Phase 7. This mirrors Phase 1's Global Constraint #9 precedent, where "Timeline (basic)" and "Process Tree" were API endpoints rather than engine crates.

12. **The File Story route is `GET /api/v1/files/story?path=…` (or `?file_id=…`), not §14.2's `/api/v1/files/{id}/story`.** The path-param shape presupposes a minted, stable file id resource that does not exist until Phase 7's Investigation Engine; the query-param shape matches the convention `osiris-api` already uses for `/api/v1/events`, and `path` is what an analyst actually has in hand. `file_id` accepts the canonical `"<device_id>:<inode>"` form for identity-first lookups.

13. **"Timeline integration" is a verification task, not new engine code.** §12.4's Timeline is "a specific, canonical `QueryPlan` shape", already served generically by `GET /api/v1/events?since=&until=` from Phase 1. Task 9 proves with content-level assertions that file events appear there correctly interleaved with process events, in `(timestamp, event_id)` order. No gap was found in the category mapping (`EventType::category()` already maps all ten `FILE_*` variants to `Category::File`, with an existing test), so no change is needed there.

14. **`Relation::Wrote` is used for every mutating file edge** (create / write / delete / rename). §9.4's relation set has no `DELETED`/`RENAMED` member, and this phase does not extend that frozen enum; the precise operation is always recoverable from the cited event's `event_type`, so no information is lost.

15. **Detection runs on the Server's ingest path, after `batch_write`, inside the same `spawn_blocking` call.** This preserves §27's privilege boundary exactly: the Agent never links `osiris-detect` or `osiris-storage`. `tools/check-dep-graph.sh`'s `check_forbidden osiris-agent … osiris-detect` check, which has printed `skip: osiris-detect not in workspace yet` since Phase 0, now runs for real.

16. **No alert deduplication or suppression.** If the same event were ingested twice, its rule would fire twice. This is bounded in practice (the spool tailer tracks a byte offset and never re-reads), and real dedup/suppression state belongs with Phase 6's stateful engine.

None of these decisions touch the `CanonicalEvent` envelope's existing fields, the `EventType`/`Category`/`Severity`/`Source`/`Relation` enums, or the dependency-graph privilege boundary (§27), which this plan extends with one new check but never relaxes.

**New workspace-wide facts this phase establishes** (binding on every task):
- Workspace `members` gains `"crates/osiris-sensors/fs"` (matching the explicit-path convention the root `Cargo.toml` already uses for `crates/osiris-sensors/process`, since `crates/osiris-sensors` is in `exclude`).
- New crates: `osiris-fileutil`, `osiris-sensors-fs`, `osiris-detect`. No new `[workspace.dependencies]` entries — `serde_yaml`, `sha2`, `hex`, `tracing`, `uuid` are all already declared.
- `osiris-storage` gains a `uuid` dependency (needed for `AlertQueryPlan.evidence_event_ids`).
- The four event types produced or consumed in this phase are `FILE_CREATE`, `FILE_WRITE`, `FILE_DELETE`, `FILE_RENAME`, alongside Phase 1's `PROCESS_EXEC`. No other `EventType` variant is produced anywhere.
- Every new **library** crate keeps Phase 0/1's discipline: zero `unwrap()`/`expect()` on I/O, lock, or parse results outside test code; return `Result` with a `thiserror` error type; recover poisoned mutexes via `unwrap_or_else(|p| p.into_inner())` rather than panicking.
- Rule files live at `config/rules/*.yaml` in the repo root and are loaded by directory path.

---

### Task 1: `osiris-schema` — file identity and the `Alert` data contract

**Files:**
- Modify: `crates/osiris-schema/Cargo.toml` (add `thiserror`)
- Modify: `crates/osiris-schema/src/entities.rs` (`FileRef` gains `device_id`)
- Create: `crates/osiris-schema/src/file_identity.rs`
- Create: `crates/osiris-schema/src/alert.rs`
- Modify: `crates/osiris-schema/src/lib.rs` (module declarations + re-exports)

**Interfaces:**
- Consumes: Phase 0's `osiris_schema::{FileRef, EntityRef, Severity}` — unchanged except for the one added `FileRef` field.
- Produces:
  - `osiris_schema::FileIdentity { inode: u64, device_id: u64 }` with `FileIdentity::new(inode: u64, device_id: u64) -> Self`, `FileIdentity::from_file_ref(file: &FileRef) -> Option<FileIdentity>`, `fn as_key(&self) -> String` (`"<device_id>:<inode>"`), `FileIdentity::parse_key(s: &str) -> Option<FileIdentity>`, `fn to_entity_ref(self, host_id: Uuid) -> EntityRef`.
  - `osiris_schema::encode_device_id(major: u32, minor: u32) -> u64`.
  - `osiris_schema::FileRef.device_id: Option<u64>` — every `FileRef` construction site must now supply it (there are none outside tests as of Phase 1).
  - `osiris_schema::{Alert, AlertStatus, AlertError}` with `Alert::new(rule_id: impl Into<String>, rule_version: u32, rule_content_hash: impl Into<String>, severity: Severity, timestamp: u64, host_id: Uuid, reasons: Vec<String>, evidence: Vec<Uuid>) -> Result<Alert, AlertError>` and read accessors `alert_id() -> Uuid`, `rule_id() -> &str`, `rule_version() -> u32`, `rule_content_hash() -> &str`, `severity() -> Severity`, `status() -> AlertStatus`, `timestamp() -> u64`, `host_id() -> Uuid`, `reasons() -> &[String]`, `evidence() -> &[Uuid]`, plus `set_status(&mut self, status: AlertStatus)`.
  - Task 4 uses `encode_device_id`; Task 3 uses `FileIdentity`; Tasks 6/7/8 use `Alert`.

- [ ] **Step 1: Add `thiserror` to `osiris-schema`**

Edit `crates/osiris-schema/Cargo.toml`, adding one line to `[dependencies]` (keep the existing five entries unchanged):
```toml
thiserror = { workspace = true }
```

`thiserror` is external, so `tools/check-dep-graph.sh`'s `check_no_internal_deps osiris-schema` (which only rejects `osiris-`-prefixed dependencies) still passes.

- [ ] **Step 2: Write the failing test for `FileIdentity`**

Create `crates/osiris-schema/src/file_identity.rs` containing **only** the test module for now:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::FileRef;
    use uuid::Uuid;

    fn file_ref(inode: Option<u64>, device_id: Option<u64>) -> FileRef {
        FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode,
            device_id,
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        }
    }

    #[test]
    fn encodes_major_minor_losslessly_and_reversibly() {
        // auditd prints `dev=08:01` (hex major:minor) for the usual root
        // block device; 8:1 must round-trip through the encoding.
        let device_id = encode_device_id(8, 1);
        assert_eq!(device_id, (8u64 << 32) | 1u64);
        assert_eq!((device_id >> 32) as u32, 8);
        assert_eq!((device_id & 0xFFFF_FFFF) as u32, 1);
    }

    #[test]
    fn builds_from_a_file_ref_only_when_both_halves_are_known() {
        assert_eq!(
            FileIdentity::from_file_ref(&file_ref(Some(131075), Some(encode_device_id(8, 1)))),
            Some(FileIdentity::new(131075, encode_device_id(8, 1)))
        );
        assert_eq!(FileIdentity::from_file_ref(&file_ref(Some(131075), None)), None);
        assert_eq!(FileIdentity::from_file_ref(&file_ref(None, Some(1))), None);
    }

    #[test]
    fn key_round_trips() {
        let identity = FileIdentity::new(131075, encode_device_id(8, 1));
        let key = identity.as_key();
        assert_eq!(key, format!("{}:{}", encode_device_id(8, 1), 131075));
        assert_eq!(FileIdentity::parse_key(&key), Some(identity));
    }

    #[test]
    fn parse_key_rejects_malformed_input() {
        assert_eq!(FileIdentity::parse_key("not-a-key"), None);
        assert_eq!(FileIdentity::parse_key("12:"), None);
        assert_eq!(FileIdentity::parse_key(":34"), None);
    }

    #[test]
    fn converts_to_the_schema_entity_ref_for_files() {
        let host_id = Uuid::new_v4();
        let identity = FileIdentity::new(131075, encode_device_id(8, 1));
        match identity.to_entity_ref(host_id) {
            crate::relationships::EntityRef::File {
                host_id: got_host,
                inode,
                device_id,
            } => {
                assert_eq!(got_host, host_id);
                assert_eq!(inode, 131075);
                assert_eq!(device_id, encode_device_id(8, 1));
            }
            other => panic!("expected EntityRef::File, got {other:?}"),
        }
    }
}
```

Add `pub mod file_identity;` to `crates/osiris-schema/src/lib.rs` (module list only for now — the re-export comes in Step 8).

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p osiris-schema file_identity`
Expected: FAIL — compile errors for `encode_device_id`, `FileIdentity`, and `FileRef` having no field named `device_id`.

- [ ] **Step 4: Add `device_id` to `FileRef`**

In `crates/osiris-schema/src/entities.rs`, replace the `FileRef` struct with:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRef {
    pub path: String,
    pub previous_path: Option<String>,
    pub inode: Option<u64>,
    /// The filesystem holding this file, as OSIRIS's own lossless encoding
    /// `((major as u64) << 32) | (minor as u64)` of the device's major:minor
    /// pair (see `crate::file_identity::encode_device_id`). Deliberately NOT
    /// the kernel's `dev_t` bit layout — the audit `PATH` record prints
    /// `dev=MAJ:MIN` in hex, and re-deriving glibc's scattered `dev_t`
    /// packing from it would add a lossy step for no gain. Together with
    /// `inode` and the event's `host_id` this forms the file identity
    /// ARCHITECTURE.md §9.4 already requires of `EntityRef::File`; the field
    /// is `#[serde(default)]` so JSON written before this field existed
    /// still deserializes (no Phase 1 event ever populated `file`).
    #[serde(default)]
    pub device_id: Option<u64>,
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    pub hash: Option<String>,
}
```

- [ ] **Step 5: Write the `FileIdentity` implementation**

Insert above the test module in `crates/osiris-schema/src/file_identity.rs`:
```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::FileRef;
use crate::relationships::EntityRef;

/// Stable filesystem-level identity for a file on one host, per
/// ARCHITECTURE.md §9.4's `file = (host_id, inode, device_id)` composite.
/// The `host_id` half lives on the owning `CanonicalEvent`, so this type
/// carries the host-independent pair and gains `host_id` at the moment it
/// becomes an `EntityRef` (see `to_entity_ref`).
///
/// Why identity and not path: a rename keeps the inode and changes the
/// path, so a path-only model loses the file across `FILE_RENAME`. Path is
/// the lookup key an analyst types; identity is the join key the File Story
/// query (Task 8) uses to follow the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    pub inode: u64,
    pub device_id: u64,
}

impl FileIdentity {
    pub fn new(inode: u64, device_id: u64) -> Self {
        Self { inode, device_id }
    }

    /// Builds an identity from a `FileRef`, returning `None` when the
    /// originating backend could not report both halves (the audit `PATH`
    /// record prints `inode=` and `dev=` for real paths but omits or nulls
    /// them for e.g. `nametype=UNKNOWN` items).
    pub fn from_file_ref(file: &FileRef) -> Option<Self> {
        Some(Self::new(file.inode?, file.device_id?))
    }

    /// The canonical wire/URL form: `"<device_id>:<inode>"`, both decimal.
    pub fn as_key(&self) -> String {
        format!("{}:{}", self.device_id, self.inode)
    }

    pub fn parse_key(s: &str) -> Option<Self> {
        let (device_id, inode) = s.split_once(':')?;
        Some(Self::new(inode.parse().ok()?, device_id.parse().ok()?))
    }

    pub fn to_entity_ref(self, host_id: Uuid) -> EntityRef {
        EntityRef::File {
            host_id,
            inode: self.inode,
            device_id: self.device_id,
        }
    }
}

/// Encodes a device's major:minor pair (as printed by an audit `PATH`
/// record's `dev=MAJ:MIN` field, in hex) into `FileRef::device_id`.
pub fn encode_device_id(major: u32, minor: u32) -> u64 {
    ((major as u64) << 32) | (minor as u64)
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p osiris-schema file_identity`
Expected: PASS — 5 tests.

- [ ] **Step 7: Write the failing test for `Alert`**

Create `crates/osiris-schema/src/alert.rs` containing **only** the test module for now:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn ok_alert() -> Alert {
        Alert::new(
            "shell_wrote_file_to_web_root",
            1,
            "abc123",
            Severity::High,
            1_700_000_000_000_000_000,
            Uuid::new_v4(),
            vec!["The file was written inside /var/www/".to_string()],
            vec![Uuid::now_v7()],
        )
        .expect("valid alert")
    }

    #[test]
    fn a_valid_alert_carries_every_required_explanation_field() {
        let alert = ok_alert();
        assert_eq!(alert.rule_id(), "shell_wrote_file_to_web_root");
        assert_eq!(alert.rule_version(), 1);
        assert_eq!(alert.rule_content_hash(), "abc123");
        assert_eq!(alert.status(), AlertStatus::Open);
        assert_eq!(alert.reasons().len(), 1);
        assert_eq!(alert.evidence().len(), 1);
    }

    #[test]
    fn rejects_an_alert_with_no_reasons() {
        let err = Alert::new(
            "r",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec![],
            vec![Uuid::now_v7()],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoReasons);
    }

    #[test]
    fn rejects_an_alert_whose_reasons_are_all_blank() {
        let err = Alert::new(
            "r",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec!["   ".to_string()],
            vec![Uuid::now_v7()],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoReasons);
    }

    #[test]
    fn rejects_an_alert_with_no_evidence() {
        let err = Alert::new(
            "r",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec!["because".to_string()],
            vec![],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoEvidence);
    }

    #[test]
    fn rejects_an_alert_with_a_blank_rule_id() {
        let err = Alert::new(
            "  ",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec!["because".to_string()],
            vec![Uuid::now_v7()],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoRuleId);
    }

    #[test]
    fn round_trips_through_json_preserving_identity_and_status() {
        let mut alert = ok_alert();
        alert.set_status(AlertStatus::Acknowledged);
        let json = serde_json::to_string(&alert).unwrap();
        let back: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(back.alert_id(), alert.alert_id());
        assert_eq!(back.status(), AlertStatus::Acknowledged);
        assert_eq!(back.reasons(), alert.reasons());
        assert_eq!(back.evidence(), alert.evidence());
    }

    /// ARCHITECTURE.md §11.2 says an Alert is *never allowed to exist*
    /// without reasons/evidence/rule identity. A validating constructor
    /// alone would leave a hole: anything could hand-write JSON with empty
    /// arrays and deserialize a bare "Threat detected". Deserialization
    /// must run the same validation.
    #[test]
    fn deserializing_an_alert_with_empty_reasons_is_rejected() {
        let json = serde_json::to_string(&ok_alert()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["reasons"] = serde_json::json!([]);
        let result: Result<Alert, _> = serde_json::from_value(value);
        assert!(result.is_err(), "empty reasons must not deserialize");
    }

    #[test]
    fn deserializing_an_alert_with_empty_evidence_is_rejected() {
        let json = serde_json::to_string(&ok_alert()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["evidence"] = serde_json::json!([]);
        let result: Result<Alert, _> = serde_json::from_value(value);
        assert!(result.is_err(), "empty evidence must not deserialize");
    }
}
```

Add `pub mod alert;` to `crates/osiris-schema/src/lib.rs`.

- [ ] **Step 8: Run the test to verify it fails**

Run: `cargo test -p osiris-schema alert`
Expected: FAIL — compile errors for `Alert`, `AlertStatus`, `AlertError`.

- [ ] **Step 9: Write the `Alert` implementation**

Insert above the test module in `crates/osiris-schema/src/alert.rs`:
```rust
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::event_type::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AlertError {
    #[error("alert must cite a non-empty rule_id (ARCHITECTURE.md §11.2)")]
    NoRuleId,
    #[error("alert must cite at least one non-blank reason (ARCHITECTURE.md §11.2)")]
    NoReasons,
    #[error("alert must cite at least one evidence event_id (ARCHITECTURE.md §11.2)")]
    NoEvidence,
}

/// A detection result (ARCHITECTURE.md §11.2/§12.7). Fields are private on
/// purpose: §11.2 requires that an Alert is *never allowed to exist*
/// without `reasons`, `evidence`, and `rule_id`+`rule_version`, and that
/// this is "enforced at the type level". Public fields would leave a
/// struct-literal escape hatch, and a derived `Deserialize` would leave a
/// wire escape hatch — so construction goes through `new()` and
/// deserialization goes through the same validation (see the hand-written
/// `Deserialize` below).
///
/// Everything is immutable after construction except `status`, which
/// §12.7 explicitly allows to transition (`OPEN` -> `ACKNOWLEDGED` /
/// `SUPPRESSED`).
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    alert_id: Uuid,
    rule_id: String,
    rule_version: u32,
    /// SHA-256 hex of the rule file's exact text, so an alert always cites
    /// the precise rule version that fired (§11.1's auditability point).
    rule_content_hash: String,
    severity: Severity,
    status: AlertStatus,
    /// Wall-clock nanoseconds of the event that triggered this alert.
    timestamp: u64,
    host_id: Uuid,
    /// One human-readable reason per matched condition — never a generic
    /// template (§11.2).
    reasons: Vec<String>,
    /// The exact `event_id`s that matched.
    evidence: Vec<Uuid>,
}

impl Alert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: impl Into<String>,
        rule_version: u32,
        rule_content_hash: impl Into<String>,
        severity: Severity,
        timestamp: u64,
        host_id: Uuid,
        reasons: Vec<String>,
        evidence: Vec<Uuid>,
    ) -> Result<Self, AlertError> {
        let rule_id = rule_id.into();
        Self::validate(&rule_id, &reasons, &evidence)?;
        Ok(Self {
            alert_id: Uuid::now_v7(),
            rule_id,
            rule_version,
            rule_content_hash: rule_content_hash.into(),
            severity,
            status: AlertStatus::Open,
            timestamp,
            host_id,
            reasons,
            evidence,
        })
    }

    fn validate(rule_id: &str, reasons: &[String], evidence: &[Uuid]) -> Result<(), AlertError> {
        if rule_id.trim().is_empty() {
            return Err(AlertError::NoRuleId);
        }
        if reasons.iter().all(|r| r.trim().is_empty()) {
            return Err(AlertError::NoReasons);
        }
        if evidence.is_empty() {
            return Err(AlertError::NoEvidence);
        }
        Ok(())
    }

    pub fn alert_id(&self) -> Uuid {
        self.alert_id
    }
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }
    pub fn rule_version(&self) -> u32 {
        self.rule_version
    }
    pub fn rule_content_hash(&self) -> &str {
        &self.rule_content_hash
    }
    pub fn severity(&self) -> Severity {
        self.severity
    }
    pub fn status(&self) -> AlertStatus {
        self.status
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn host_id(&self) -> Uuid {
        self.host_id
    }
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
    pub fn evidence(&self) -> &[Uuid] {
        &self.evidence
    }

    pub fn set_status(&mut self, status: AlertStatus) {
        self.status = status;
    }
}

/// The on-the-wire shape. Kept private so the only public path back from
/// JSON is the validating `Deserialize` below.
#[derive(Deserialize)]
struct AlertWire {
    alert_id: Uuid,
    rule_id: String,
    rule_version: u32,
    rule_content_hash: String,
    severity: Severity,
    status: AlertStatus,
    timestamp: u64,
    host_id: Uuid,
    reasons: Vec<String>,
    evidence: Vec<Uuid>,
}

impl<'de> Deserialize<'de> for Alert {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AlertWire::deserialize(deserializer)?;
        Alert::validate(&wire.rule_id, &wire.reasons, &wire.evidence)
            .map_err(serde::de::Error::custom)?;
        Ok(Alert {
            alert_id: wire.alert_id,
            rule_id: wire.rule_id,
            rule_version: wire.rule_version,
            rule_content_hash: wire.rule_content_hash,
            severity: wire.severity,
            status: wire.status,
            timestamp: wire.timestamp,
            host_id: wire.host_id,
            reasons: wire.reasons,
            evidence: wire.evidence,
        })
    }
}
```

- [ ] **Step 10: Update `lib.rs` re-exports**

Replace `crates/osiris-schema/src/lib.rs` with:
```rust
pub mod alert;
pub mod entities;
pub mod envelope;
pub mod event_type;
pub mod file_identity;
pub mod process_key;
pub mod relationships;

pub use alert::{Alert, AlertError, AlertStatus};
pub use entities::*;
pub use envelope::{CanonicalEvent, SCHEMA_VERSION};
pub use event_type::{Category, EventType, Severity, Source};
pub use file_identity::{encode_device_id, FileIdentity};
pub use process_key::ProcessKey;
pub use relationships::{EntityRef, EntityRelationship, Relation};
```

- [ ] **Step 11: Run the full crate test suite**

Run: `cargo test -p osiris-schema`
Expected: PASS — Phase 0's existing tests plus 5 `file_identity` tests and 8 `alert` tests. No other crate constructs a `FileRef`, so nothing else needs updating; if `cargo build --workspace` reports a missing `device_id` field anywhere, add `device_id: None` at that site.

- [ ] **Step 12: Verify the workspace still builds and the boundary check still passes**

Run: `cargo build --workspace` then `bash tools/check-dep-graph.sh`
Expected: build succeeds; the script prints `Dependency-graph check PASSED` and `osiris-schema`'s `check_no_internal_deps` still passes (the new `thiserror` dependency is external).

- [ ] **Step 13: Commit**

```bash
git add crates/osiris-schema
git commit -m "feat(schema): file identity (inode+device_id) and a type-enforced Alert contract

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0192TqfN5oKsNzSDGYCo7aTt"
```

---

### Task 2: `osiris-fileutil` — extract the shared line tailer and audit tokenizer

This task reverses Phase 1's Global Constraint #7 before a third copy of the tailer can be written (see this plan's Global Constraint #3 for why). It is pure refactoring plus one boundary-check addition: no behavior changes, and every existing test — including both copies of the concurrent-writer regression test — must survive the move.

**Files:**
- Modify: `Cargo.toml` (workspace root — nothing to add for this task; `crates/*` already matches the new crate)
- Create: `crates/osiris-fileutil/Cargo.toml`
- Create: `crates/osiris-fileutil/src/lib.rs`
- Create: `crates/osiris-fileutil/src/line_tailer.rs`
- Create: `crates/osiris-fileutil/src/audit_kv.rs`
- Delete: `crates/osiris-server/src/tailer.rs`
- Modify: `crates/osiris-server/src/lib.rs`, `crates/osiris-server/src/ingest.rs`, `crates/osiris-server/Cargo.toml`
- Delete: `crates/osiris-sensors/process/src/audit_tailer.rs`
- Modify: `crates/osiris-sensors/process/src/lib.rs`, `crates/osiris-sensors/process/src/sensor.rs`, `crates/osiris-sensors/process/src/audit_line.rs`, `crates/osiris-sensors/process/Cargo.toml`
- Modify: `tools/check-dep-graph.sh`

**Interfaces:**
- Produces:
  - `osiris_fileutil::LineTailer` with `LineTailer::new(path: impl Into<PathBuf>) -> Self` and `fn poll(&mut self) -> std::io::Result<Vec<String>>`. Replaces both `osiris_server::SpoolTailer` and `osiris_sensors_process::AuditLogTailer`, which cease to exist. Task 4's Filesystem sensor is its third consumer.
  - `osiris_fileutil::audit_kv::tokenize(line: &str) -> HashMap<String, String>`.
  - `osiris_fileutil::audit_kv::AuditMsgId { timestamp_ns: u64, serial: u64 }` (derives `Debug, Clone, Copy, PartialEq, Eq, Hash`) and `osiris_fileutil::audit_kv::parse_audit_msg_id(msg: &str) -> Option<AuditMsgId>`. Task 4 groups audit records by `AuditMsgId`.

- [ ] **Step 1: Create the crate manifest**

`crates/osiris-fileutil/Cargo.toml`:
```toml
[package]
name = "osiris-fileutil"
version.workspace = true
edition.workspace = true

[dependencies]

[dev-dependencies]
tempfile = { workspace = true }
```

Zero dependencies (not even `serde`) is deliberate: this crate sits below every consumer including `osiris-server`, and Step 9 adds a boundary check asserting it stays a leaf.

- [ ] **Step 2: Write `line_tailer.rs` by moving the existing implementation and both test suites**

Create `crates/osiris-fileutil/src/line_tailer.rs`. The implementation is byte-for-byte the body of `crates/osiris-server/src/tailer.rs` / `crates/osiris-sensors/process/src/audit_tailer.rs` (they are identical after Phase 1's double bug fix), renamed and re-documented:
```rust
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// Tails a growing text file by tracking a byte offset, returning any
/// complete new lines since the last poll and buffering a trailing partial
/// line for the next call. Pure `std::fs` — no OS-specific API — so this
/// behaves identically tailing a real `/var/log/audit/audit.log` on Linux
/// and a fixture file in a test on any platform.
///
/// This is the single shared implementation behind the Server's spool
/// ingestion, the Process/Exec sensor's audit backend, and the Filesystem
/// sensor's audit backend. Phase 1 shipped two copies of it and had to fix
/// the same read-race bug in both; this crate exists so that cannot recur
/// (Phase 2 plan Global Constraints #3).
pub struct LineTailer {
    path: PathBuf,
    offset: u64,
    partial: String,
}

impl LineTailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
            partial: String::new(),
        }
    }

    /// Returns any complete new lines appended since the last call. Returns
    /// an empty `Vec` (not an error) if the file doesn't exist yet or hasn't
    /// grown — callers treat "no new lines" as normal.
    pub fn poll(&mut self) -> std::io::Result<Vec<String>> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        if len < self.offset {
            // File was truncated/rotated — restart from the beginning.
            self.offset = 0;
            self.partial.clear();
        }
        if len == self.offset {
            return Ok(vec![]);
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut buf = String::new();
        // Bound the read to exactly the measured length: read_to_string
        // reads to the *current* EOF, which can have grown past `len` if
        // the writer appended concurrently. Reading past `len` in one poll
        // risks capturing a mid-write partial line while still advancing
        // `self.offset` only to `len`, causing that event to be re-read
        // and corrupted (prefixed with stale partial data) on next poll.
        (&mut file)
            .take(len - self.offset)
            .read_to_string(&mut buf)?;
        self.offset = len;

        buf.insert_str(0, &self.partial);
        self.partial.clear();

        let mut lines: Vec<String> = buf.split('\n').map(|s| s.to_string()).collect();
        if !buf.ends_with('\n') {
            self.partial = lines.pop().unwrap_or_default();
        } else {
            lines.pop(); // trailing empty string after the last '\n'
        }
        Ok(lines.into_iter().filter(|l| !l.is_empty()).collect())
    }
}
```

Then append the test module: take **all six** existing tests — the four from `crates/osiris-sensors/process/src/audit_tailer.rs` (`returns_empty_when_file_does_not_exist`, `returns_new_complete_lines_across_multiple_polls`, `buffers_a_partial_trailing_line_until_it_completes`, `restarts_from_zero_after_the_file_is_truncated_by_rotation`, plus its `survives_concurrent_writer_without_corrupting_lines`) and the NDJSON-flavoured `returns_new_lines_across_polls` from `crates/osiris-server/src/tailer.rs` — copy them verbatim into a single `#[cfg(test)] mod tests` block, replacing every `AuditLogTailer::new` / `SpoolTailer::new` with `LineTailer::new`. Keep every doc comment on the regression tests: they explain *which* bug they pin. Rename the server-flavoured one to `returns_new_ndjson_lines_across_polls` to avoid a name collision with `returns_new_complete_lines_across_multiple_polls`.

- [ ] **Step 3: Write the failing test for `audit_kv`**

Create `crates/osiris-fileutil/src/audit_kv.rs` containing **only** the test module for now:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL_LINE: &str = r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 uid=1000 comm="curl" exe="/usr/bin/curl" key=(null)"#;

    #[test]
    fn tokenizes_key_value_pairs_honouring_quoted_values() {
        let fields = tokenize(SYSCALL_LINE);
        assert_eq!(fields.get("type").map(String::as_str), Some("SYSCALL"));
        assert_eq!(fields.get("syscall").map(String::as_str), Some("59"));
        assert_eq!(fields.get("comm").map(String::as_str), Some("curl"));
        assert_eq!(fields.get("exe").map(String::as_str), Some("/usr/bin/curl"));
    }

    #[test]
    fn tokenizes_a_quoted_value_containing_spaces_as_one_token() {
        let fields = tokenize(r#"type=PATH name="/tmp/two words.txt" nametype=CREATE"#);
        assert_eq!(
            fields.get("name").map(String::as_str),
            Some("/tmp/two words.txt")
        );
        assert_eq!(fields.get("nametype").map(String::as_str), Some("CREATE"));
    }

    #[test]
    fn a_truncated_key_yields_an_empty_value_rather_than_panicking() {
        let fields = tokenize("type=SYSCALL pid=");
        assert_eq!(fields.get("pid").map(String::as_str), Some(""));
    }

    #[test]
    fn parses_the_shared_audit_event_header() {
        let fields = tokenize(SYSCALL_LINE);
        let id = parse_audit_msg_id(fields.get("msg").unwrap()).expect("must parse");
        assert_eq!(id.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(id.serial, 456);
    }

    /// Every record belonging to one audit event repeats the same
    /// `msg=audit(<secs>.<millis>:<serial>)` header — that shared id is
    /// exactly what the Filesystem sensor's assembler groups on.
    #[test]
    fn records_of_the_same_event_share_one_id() {
        let path_line = r#"type=PATH msg=audit(1690000000.123:456): item=1 name="/tmp/foo" nametype=DELETE"#;
        let syscall_id = parse_audit_msg_id(tokenize(SYSCALL_LINE).get("msg").unwrap()).unwrap();
        let path_id = parse_audit_msg_id(tokenize(path_line).get("msg").unwrap()).unwrap();
        assert_eq!(syscall_id, path_id);
    }

    #[test]
    fn rejects_a_malformed_header() {
        assert_eq!(parse_audit_msg_id("not-an-audit-header"), None);
        assert_eq!(parse_audit_msg_id("audit(1690000000.123)"), None);
        assert_eq!(parse_audit_msg_id("audit(nope.123:456):"), None);
    }
}
```

Create `crates/osiris-fileutil/src/lib.rs`:
```rust
pub mod audit_kv;
pub mod line_tailer;

pub use audit_kv::{parse_audit_msg_id, tokenize, AuditMsgId};
pub use line_tailer::LineTailer;
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p osiris-fileutil audit_kv`
Expected: FAIL — compile errors for `tokenize`, `parse_audit_msg_id`, `AuditMsgId`.

- [ ] **Step 5: Write the `audit_kv` implementation**

Insert above the test module in `crates/osiris-fileutil/src/audit_kv.rs`. `tokenize` is moved verbatim from `crates/osiris-sensors/process/src/audit_line.rs` (made `pub`); `parse_audit_msg_id` generalizes that file's private `parse_audit_timestamp_ns` to also return the serial, which the Filesystem sensor needs for grouping:
```rust
use std::collections::HashMap;

/// The header every record of one audit event repeats:
/// `msg=audit(<secs>.<millis>:<serial>)`. Records sharing a `serial` (and
/// timestamp) belong to the same kernel audit event — for a file syscall
/// that means one `type=SYSCALL` record plus one `type=PATH` record per
/// path operand, plus an optional `type=CWD` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditMsgId {
    /// Nanoseconds since the epoch, derived from the header's
    /// `<secs>.<millis>` pair (auditd's own resolution is milliseconds).
    pub timestamp_ns: u64,
    pub serial: u64,
}

/// Tokenizes one auditd record line into `key=value` pairs, honoring
/// auditd's double-quoting convention for values that may contain spaces
/// (`comm="curl"`, `name="/tmp/two words.txt"`).
///
/// Malformed input is handled by producing something a caller can reject,
/// never by panicking: a truncated `pid=` yields an empty value (which
/// fails the caller's `parse()`), and an unterminated quote swallows the
/// rest of the line into that one value (so the caller's required fields
/// come back missing).
pub fn tokenize(line: &str) -> HashMap<String, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
            current.push(c);
        } else if c.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
        .into_iter()
        .filter_map(|t| {
            let mut parts = t.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").trim_matches('"').to_string();
            Some((key, value))
        })
        .collect()
}

/// Parses a `msg` field's `audit(1690000000.123:456)` payload. Accepts the
/// value with or without auditd's trailing `:` (the tokenizer strips the
/// record's trailing colon into the value in some layouts).
pub fn parse_audit_msg_id(msg: &str) -> Option<AuditMsgId> {
    let inner = msg.strip_prefix("audit(")?;
    let inner = inner.split(')').next()?;
    let (ts_part, serial_part) = inner.split_once(':')?;
    let (secs, millis) = ts_part.split_once('.')?;
    let secs: u64 = secs.parse().ok()?;
    let millis: u64 = millis.parse().ok()?;
    let serial: u64 = serial_part.parse().ok()?;
    Some(AuditMsgId {
        timestamp_ns: secs * 1_000_000_000 + millis * 1_000_000,
        serial,
    })
}
```

- [ ] **Step 6: Run the new crate's tests**

Run: `cargo test -p osiris-fileutil`
Expected: PASS — 6 `line_tailer` tests and 6 `audit_kv` tests.

- [ ] **Step 7: Rewire `osiris-server` onto the shared tailer**

Delete `crates/osiris-server/src/tailer.rs`.

Add to `crates/osiris-server/Cargo.toml`'s `[dependencies]`:
```toml
osiris-fileutil = { path = "../osiris-fileutil" }
```

Replace `crates/osiris-server/src/lib.rs` with:
```rust
pub mod config;
pub mod ingest;

pub use config::{ConfigError, ServerConfig};
pub use ingest::run_ingestion_loop;
```

In `crates/osiris-server/src/ingest.rs`, replace `use crate::tailer::SpoolTailer;` with `use osiris_fileutil::LineTailer;`, and replace `let mut tailer = SpoolTailer::new(spool_path);` with `let mut tailer = LineTailer::new(spool_path);`. Nothing else in that file changes.

- [ ] **Step 8: Rewire `osiris-sensors-process` onto the shared tailer and tokenizer**

Delete `crates/osiris-sensors/process/src/audit_tailer.rs`.

Add to `crates/osiris-sensors/process/Cargo.toml`'s `[dependencies]`:
```toml
osiris-fileutil = { path = "../../osiris-fileutil" }
```

Replace `crates/osiris-sensors/process/src/lib.rs` with:
```rust
pub mod audit_line;
pub mod proc_stat;
pub mod sensor;

pub use audit_line::parse_audit_line;
pub use proc_stat::{parse_proc_stat_starttime, read_process_start_time};
pub use sensor::ProcessExecSensor;
```

In `crates/osiris-sensors/process/src/sensor.rs`, replace `use crate::audit_tailer::AuditLogTailer;` with `use osiris_fileutil::LineTailer;`, and replace `let mut tailer = AuditLogTailer::new(path);` with `let mut tailer = LineTailer::new(path);`.

In `crates/osiris-sensors/process/src/audit_line.rs`, delete the private `tokenize` and `parse_audit_timestamp_ns` functions and their `use std::collections::HashMap;`, add `use osiris_fileutil::{parse_audit_msg_id, tokenize};` at the top, and change the timestamp line inside `parse_audit_line` from:
```rust
    let timestamp_ns = fields
        .get("msg")
        .and_then(|m| parse_audit_timestamp_ns(m))
        .unwrap_or(0);
```
to:
```rust
    let timestamp_ns = fields
        .get("msg")
        .and_then(|m| parse_audit_msg_id(m))
        .map(|id| id.timestamp_ns)
        .unwrap_or(0);
```
Leave `audit_line.rs`'s six existing tests exactly as they are — they are the proof that this refactor changed no behavior, including the two that pin truncated-key and unterminated-quote handling.

- [ ] **Step 9: Add the leaf-crate boundary check**

In `tools/check-dep-graph.sh`, add one line immediately after `check_no_internal_deps osiris-schema`:
```bash
check_no_internal_deps osiris-fileutil
```
And extend the header comment's first sentence so the file documents its own new rule — change:
```
# osiris-schema must not depend on any other OSIRIS-internal crate.
```
to:
```
# osiris-schema and osiris-fileutil must not depend on any other
# OSIRIS-internal crate (osiris-fileutil sits below both the privileged
# Agent side and the unprivileged Server side, so it must stay a leaf).
```

- [ ] **Step 10: Run every affected crate's tests**

Run: `cargo test -p osiris-fileutil -p osiris-server -p osiris-sensors-process`
Expected: PASS, with no test *count* regression versus before the refactor — the six tailer tests now live in `osiris-fileutil` instead of being split across the other two crates, and `osiris-sensors-process`'s six `audit_line` tests plus two sensor tests, and `osiris-server`'s two ingest tests plus one config test, all still pass unchanged.

- [ ] **Step 11: Verify the boundary check**

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`, and the output no longer prints `skip:` for `osiris-fileutil` (it now exists) — confirming the new leaf check actually ran.

- [ ] **Step 12: Commit**

```bash
git add crates/osiris-fileutil crates/osiris-server crates/osiris-sensors tools/check-dep-graph.sh
git commit -m "refactor: extract osiris-fileutil shared line tailer and audit tokenizer

Collapses Phase 1's two near-duplicate tailers (osiris-server::SpoolTailer,
osiris-sensors-process::AuditLogTailer) into one shared implementation
before the Filesystem sensor adds a third copy. Reverses Phase 1 plan
Global Constraint #7, which the phase's own review found had already
carried one read-race bug into both copies.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0192TqfN5oKsNzSDGYCo7aTt"
```

---

### Task 3: `osiris-sensor-api` + `osiris-pipeline` — the raw→canonical path for file events

This task takes a file event all the way from a sensor's output shape to a validated, prioritized `CanonicalEvent` with a real entity-graph edge. It touches both crates in one task because adding a `RawEvent` variant breaks the pipeline's exhaustive `match`, so splitting them would leave the workspace red between tasks.

**Files:**
- Modify: `crates/osiris-sensor-api/src/raw_event.rs`
- Modify: `crates/osiris-sensor-api/src/lib.rs`
- Modify: `crates/osiris-sensor-api/Cargo.toml` (add `serde_json` as a dev-dependency)
- Modify: `crates/osiris-pipeline/src/normalize.rs`
- Modify: `crates/osiris-pipeline/src/process_resolver.rs`
- Modify: `crates/osiris-pipeline/src/enrich.rs`
- Modify: `crates/osiris-pipeline/src/validate.rs`
- Modify: `crates/osiris-pipeline/src/prioritize.rs`
- Modify: `crates/osiris-pipeline/src/pipeline.rs` (one new integration test)
- Modify: `crates/osiris-sensors/process/src/sensor.rs` (one non-exhaustive `match` in a test)
- Modify: `generator/src/sensor.rs` (one non-exhaustive `match` in a test)

**Interfaces:**
- Consumes: `osiris_schema::{FileIdentity, encode_device_id, FileRef}` from Task 1.
- Produces:
  - `osiris_sensor_api::FileOperation` — `enum { Create, Write, Delete, Rename }` (derives `Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize`).
  - `osiris_sensor_api::FileEventRaw` — the struct defined in Step 3 below. Task 4's sensor and Task 5's generator both construct it.
  - `osiris_sensor_api::RawEvent::File(FileEventRaw)` — a second variant alongside `ProcessExec`.
  - `osiris_sensor_api::RawEvent::timestamp_ns(&self) -> u64`.
  - `osiris_pipeline::ProcessResolver::resolve(&self, pid: u32) -> Option<ProcessKey>` and `ProcessResolver::parent_of(&self, pid: u32) -> Option<(ProcessKey, u32)>`.
  - The tag string `"PROCESS_KEY_PROVISIONAL"`, pushed onto `CanonicalEvent.tags` by the Enrich stage when a non-process event's pid was never observed executing. Task 9's end-to-end test asserts on its absence for the synthetic scenario.
  - `PriorityTable::default()` now maps `FILE_CREATE`/`FILE_DELETE`/`FILE_RENAME` to `PriorityLane::Normal` and `FILE_WRITE` to `PriorityLane::Low`.

- [ ] **Step 1: Write the failing test for the new raw event shape**

Append to `crates/osiris-sensor-api/src/raw_event.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn file_raw() -> FileEventRaw {
        FileEventRaw {
            operation: FileOperation::Create,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some((8u64 << 32) | 1),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn file_raw_round_trips_through_json() {
        let raw = RawEvent::File(file_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::File(f) => {
                assert_eq!(f.path, "/var/www/html/shell.php");
                assert_eq!(f.operation, FileOperation::Create);
                assert_eq!(f.inode, Some(131075));
            }
            other => panic!("expected RawEvent::File, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_both_variants() {
        assert_eq!(
            RawEvent::File(file_raw()).timestamp_ns(),
            1_690_000_000_123_000_000
        );
        let exec = RawEvent::ProcessExec(ProcessExecRaw {
            pid: 1,
            ppid: 0,
            uid: 0,
            exe_path: "/bin/init".to_string(),
            comm: "init".to_string(),
            timestamp_ns: 42,
            start_time_mono: 42,
            source: RawEventSource::Synthetic,
        });
        assert_eq!(exec.timestamp_ns(), 42);
    }
}
```

- [ ] **Step 2: Add the dev-dependency the test needs**

`crates/osiris-sensor-api/Cargo.toml` currently has no `[dev-dependencies]` section. Add one at the end of the file:
```toml
[dev-dependencies]
serde_json = { workspace = true }
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p osiris-sensor-api raw_event`
Expected: FAIL — `FileEventRaw`, `FileOperation`, `RawEvent::File`, and `timestamp_ns` are undefined.

- [ ] **Step 4: Implement the new raw event shape**

In `crates/osiris-sensor-api/src/raw_event.rs`, insert immediately before the `RawEvent` enum:
```rust
/// The four filesystem operations this phase emits — ARCHITECTURE.md §6's
/// Filesystem STANDARD row ("create/delete/rename on watched paths") plus
/// write, which the audit backend yields from the same PATH records. No
/// read, permission, owner, or attribute operations: those are §6's
/// DETAILED/FORENSIC rungs (Phase 2 plan Global Constraints #5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Write,
    Delete,
    Rename,
}

/// A filesystem operation record. Unlike `ProcessExecRaw` this is assembled
/// from *several* correlated audit records (one `type=SYSCALL` supplying the
/// acting process fields, one `type=PATH` supplying the file fields, and
/// optionally one `type=CWD` used to absolutize a relative path), so every
/// field here is already joined and absolute by the time a sensor emits it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventRaw {
    pub operation: FileOperation,
    /// Absolute path. For `Rename` this is the *destination* path.
    pub path: String,
    /// Only set for `Rename`: the source path the file moved from.
    pub previous_path: Option<String>,
    /// Inode and device of the file itself. `None` when the backend could
    /// not report them (an audit PATH record omits them for some
    /// `nametype=UNKNOWN` items) — the pipeline then emits no entity-graph
    /// edge rather than inventing an identity.
    pub inode: Option<u64>,
    /// See `osiris_schema::encode_device_id` for the encoding.
    pub device_id: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    /// The acting process, from the group's `type=SYSCALL` record.
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the audit event header.
    pub timestamp_ns: u64,
    /// The originating audit event's serial, retained for provenance so an
    /// operator can find the exact record group in the source log.
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}
```

Then replace the `RawEvent` enum with:
```rust
/// The shape sensors emit onto their output channel (ARCHITECTURE.md §7.1
/// step 1, "Collect"). Phase 1 scoped this to Process/Exec; Phase 2 adds
/// File. Later phases add Network/Dns/... variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
    File(FileEventRaw),
}

impl RawEvent {
    /// The originating backend's wall-clock timestamp, regardless of
    /// variant — used by sensors for their `last_event_at` health field
    /// without matching on the variant at every call site.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            RawEvent::ProcessExec(p) => p.timestamp_ns,
            RawEvent::File(f) => f.timestamp_ns,
        }
    }
}
```

Update `crates/osiris-sensor-api/src/lib.rs`'s re-export line from:
```rust
pub use raw_event::{ProcessExecRaw, RawEvent, RawEventSource};
```
to:
```rust
pub use raw_event::{FileEventRaw, FileOperation, ProcessExecRaw, RawEvent, RawEventSource};
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p osiris-sensor-api`
Expected: PASS — the crate's 6 existing tests plus the 2 new `raw_event` tests.

- [ ] **Step 6: Fix the two now-non-exhaustive `match`es in existing tests**

`cargo build --workspace --all-targets` now fails in two test modules. Fix both.

In `crates/osiris-sensors/process/src/sensor.rs`, inside `sensor_emits_a_canonical_raw_event_for_an_appended_execve_line`, change:
```rust
        match received {
            RawEvent::ProcessExec(raw) => {
                assert_eq!(raw.pid, 5678);
                assert_eq!(raw.exe_path, "/usr/bin/curl");
            }
        }
```
to:
```rust
        match received {
            RawEvent::ProcessExec(raw) => {
                assert_eq!(raw.pid, 5678);
                assert_eq!(raw.exe_path, "/usr/bin/curl");
            }
            other => panic!(
                "the Process/Exec sensor must only emit ProcessExec events, got {other:?}"
            ),
        }
```

In `generator/src/sensor.rs`, inside `emits_every_event_in_the_scenario_in_order`, change:
```rust
            match raw_event {
                RawEvent::ProcessExec(raw) => pids.push(raw.pid),
            }
```
to:
```rust
            match raw_event {
                RawEvent::ProcessExec(raw) => pids.push(raw.pid),
                other => panic!(
                    "exec_chain_scenario must only produce ProcessExec events, got {other:?}"
                ),
            }
```

- [ ] **Step 7: Write the failing test for normalizing a file event**

Append these to the existing `mod tests` in `crates/osiris-pipeline/src/normalize.rs`:
```rust
    fn file_raw(operation: osiris_sensor_api::FileOperation) -> osiris_sensor_api::FileEventRaw {
        osiris_sensor_api::FileEventRaw {
            operation,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn file_operations_map_to_the_matching_event_type_and_file_category() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        for (operation, expected) in [
            (FileOperation::Create, EventType::FileCreate),
            (FileOperation::Write, EventType::FileWrite),
            (FileOperation::Delete, EventType::FileDelete),
            (FileOperation::Rename, EventType::FileRename),
        ] {
            let event = normalize(RawEvent::File(file_raw(operation)), &host, "boot-1");
            assert_eq!(event.event_type, expected);
            assert_eq!(event.category, Category::File);
        }
    }

    #[test]
    fn file_event_carries_a_complete_file_ref() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::File(file_raw(FileOperation::Create)),
            &host,
            "boot-1",
        );
        let file = event.file.expect("file events must carry a FileRef");
        assert_eq!(file.path, "/var/www/html/shell.php");
        assert_eq!(file.inode, Some(131075));
        assert_eq!(file.device_id, Some(osiris_schema::encode_device_id(8, 1)));
        assert_eq!(file.owner_uid, Some(33));
        assert_eq!(event.provider, "filesystem_sensor/audit");
        assert_eq!(event.source, Source::Audit);
    }

    #[test]
    fn rename_carries_the_previous_path() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let mut raw = file_raw(FileOperation::Rename);
        raw.previous_path = Some("/var/www/html/.shell.php.tmp".to_string());
        let event = normalize(RawEvent::File(raw), &host, "boot-1");
        assert_eq!(
            event.file.unwrap().previous_path.as_deref(),
            Some("/var/www/html/.shell.php.tmp")
        );
    }

    /// The acting process's identity is minted by its PROCESS_EXEC event,
    /// the only record carrying the real start time that `process_key`
    /// hashes. A file event has no access to that, so normalize
    /// deliberately mints a *provisional* key (start_time 0) which the
    /// Enrich stage replaces with the authoritative one. Hashing the file
    /// event's own timestamp in here instead would silently produce a
    /// different key for the same process.
    #[test]
    fn file_event_process_key_is_provisional_with_a_zero_start_time() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::File(file_raw(FileOperation::Write)),
            &host,
            "boot-1",
        );
        let process = event
            .process
            .expect("file events must name the acting process");
        assert_eq!(process.pid, 300);
        assert_eq!(process.exe_path, "/usr/bin/curl");
        assert_eq!(process.start_time_mono, 0);
        assert_eq!(
            process.process_key,
            ProcessKey::new(host.host_id, "boot-1", 300, 0)
        );
    }

    /// §9.4 says relationships are computed once, at *enrichment* time —
    /// normalize must not pre-populate an edge whose `from` cites the
    /// provisional key it is about to have overwritten.
    #[test]
    fn normalize_does_not_yet_attach_relationships() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::File(file_raw(FileOperation::Create)),
            &host,
            "boot-1",
        );
        assert!(event.relationships.is_empty());
    }
```

- [ ] **Step 8: Run to verify it fails**

Run: `cargo test -p osiris-pipeline normalize`
Expected: FAIL — the `match raw` in `normalize` is non-exhaustive (`RawEvent::File` not covered).

- [ ] **Step 9: Implement file normalization**

In `crates/osiris-pipeline/src/normalize.rs`, replace the two `use` statements at the top with:
```rust
use osiris_schema::{
    CanonicalEvent, Category, EventType, FileRef, HostRef, ProcessKey, ProcessRef, Severity,
    Source, SCHEMA_VERSION,
};
use osiris_sensor_api::{FileEventRaw, FileOperation, ProcessExecRaw, RawEvent, RawEventSource};
```

Extend the dispatcher:
```rust
pub fn normalize(raw: RawEvent, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    match raw {
        RawEvent::ProcessExec(p) => normalize_process_exec(p, host, boot_id),
        RawEvent::File(f) => normalize_file_event(f, host, boot_id),
    }
}
```

And append, after `normalize_process_exec`:
```rust
fn normalize_file_event(raw: FileEventRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let source = match raw.source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
    };
    let provider = match raw.source {
        RawEventSource::Audit => "filesystem_sensor/audit",
        RawEventSource::Synthetic => "filesystem_sensor/synthetic",
    };
    let event_type = match raw.operation {
        FileOperation::Create => EventType::FileCreate,
        FileOperation::Write => EventType::FileWrite,
        FileOperation::Delete => EventType::FileDelete,
        FileOperation::Rename => EventType::FileRename,
    };
    // Provisional identity, replaced by the Enrich stage's ProcessResolver
    // lookup whenever this pid's PROCESS_EXEC has been seen. `0` is used
    // rather than the event timestamp so the placeholder is obviously not a
    // real start time, and so two file events from the same process hash to
    // one provisional key instead of one key per event.
    let process_key = ProcessKey::new(host.host_id, boot_id, raw.pid, 0);
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category: Category::File,
        severity: Severity::Info,
        host: host.clone(),
        user: None,
        session: None,
        process: Some(ProcessRef {
            process_key,
            pid: raw.pid,
            exe_path: raw.exe_path,
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        }),
        parent_process: None,
        thread: None,
        file: Some(FileRef {
            path: raw.path,
            previous_path: raw.previous_path,
            inode: raw.inode,
            device_id: raw.device_id,
            size: None,
            mode: raw.mode,
            owner_uid: raw.owner_uid,
            owner_gid: raw.owner_gid,
            hash: None,
        }),
        network: None,
        dns: None,
        device: None,
        service: None,
        container: None,
        namespace: None,
        cgroup: None,
        kernel: None,
        source,
        provider: provider.to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({
            "comm": raw.comm,
            "ppid": raw.ppid,
            "uid": raw.uid,
            "audit_serial": raw.audit_serial,
        }),
    }
}
```

- [ ] **Step 10: Run to verify it passes**

Run: `cargo test -p osiris-pipeline normalize`
Expected: PASS — 2 existing normalize tests plus 5 new ones.

- [ ] **Step 11: Write the failing test for the resolver's two new lookups**

Append to `crates/osiris-pipeline/src/process_resolver.rs`'s `mod tests`:
```rust
    #[test]
    fn resolves_a_pids_own_key() {
        let mut resolver = ProcessResolver::new();
        let host_id = Uuid::new_v4();
        let curl_key = ProcessKey::new(host_id, "boot-1", 300, 3);
        resolver.record(300, 200, curl_key);
        assert_eq!(resolver.resolve(300), Some(curl_key));
        assert_eq!(resolver.resolve(999), None);
    }

    #[test]
    fn parent_of_returns_both_the_parents_key_and_its_pid() {
        let mut resolver = ProcessResolver::new();
        let host_id = Uuid::new_v4();
        let bash_key = ProcessKey::new(host_id, "boot-1", 200, 2);
        let curl_key = ProcessKey::new(host_id, "boot-1", 300, 3);
        resolver.record(200, 100, bash_key);
        resolver.record(300, 200, curl_key);
        assert_eq!(resolver.parent_of(300), Some((bash_key, 200)));
    }

    #[test]
    fn parent_of_returns_none_when_the_parent_was_never_observed() {
        let mut resolver = ProcessResolver::new();
        let host_id = Uuid::new_v4();
        let curl_key = ProcessKey::new(host_id, "boot-1", 300, 3);
        resolver.record(300, 200, curl_key);
        assert_eq!(resolver.parent_of(300), None);
    }
```

- [ ] **Step 12: Run to verify it fails**

Run: `cargo test -p osiris-pipeline process_resolver`
Expected: FAIL — no method `resolve`, no method `parent_of`.

- [ ] **Step 13: Implement the two lookups**

Append to `impl ProcessResolver` in `crates/osiris-pipeline/src/process_resolver.rs`:
```rust
    /// Resolves a pid to the `process_key` minted by its own PROCESS_EXEC
    /// event. Non-process events (file now, network/dns later) use this to
    /// replace the provisional key their Normalize stage assigned, so every
    /// event attributed to one process shares one identity.
    pub fn resolve(&self, pid: u32) -> Option<ProcessKey> {
        self.by_pid.get(&pid).map(|(key, _)| *key)
    }

    /// Resolves a pid's parent, returning both the parent's `process_key`
    /// and the parent's own pid. Returns `None` unless *both* the process
    /// and its parent were observed — the caller leaves `parent_process`
    /// unset rather than guessing.
    pub fn parent_of(&self, pid: u32) -> Option<(ProcessKey, u32)> {
        let (_, ppid) = self.by_pid.get(&pid)?;
        let (parent_key, _) = self.by_pid.get(ppid)?;
        Some((*parent_key, *ppid))
    }
```

- [ ] **Step 14: Run to verify it passes**

Run: `cargo test -p osiris-pipeline process_resolver`
Expected: PASS — 2 existing tests plus 3 new ones.

- [ ] **Step 15: Write the failing test for enriching a file event**

Append to `crates/osiris-pipeline/src/enrich.rs`'s `mod tests` (and add `Category` and `Relation` to that module's `use osiris_schema::{...}` list):
```rust
    fn bare_file_event(host_id: uuid::Uuid, pid: u32, ppid: u32, inode: u64) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid, ppid);
        event.event_type = EventType::FileWrite;
        event.category = Category::File;
        event.process = Some(ProcessRef {
            // The provisional key the Normalize stage mints for file events.
            process_key: ProcessKey::new(host_id, "boot-1", pid, 0),
            pid,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
        event.file = Some(osiris_schema::FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(inode),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        event
    }

    #[test]
    fn file_event_adopts_the_authoritative_process_key_from_the_exec_event() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
        );
        assert_eq!(
            file_event.process.unwrap().process_key,
            authoritative,
            "a file event's process must be the same entity as its exec event"
        );
        assert!(!file_event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }

    #[test]
    fn file_event_for_an_unseen_pid_is_tagged_provisional_rather_than_guessing() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let file_event = enrich(
            bare_file_event(host_id, 777, 1, 131075),
            "boot-1",
            &mut resolver,
        );
        assert!(file_event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }

    #[test]
    fn file_event_resolves_its_parent_process_from_the_resolver() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver);
        let _curl = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
        );
        let parent = file_event.parent_process.expect("parent must resolve");
        assert_eq!(parent.process_key, bash.process.unwrap().process_key);
        assert_eq!(parent.pid, 200);
    }

    /// ARCHITECTURE.md §9.4: relationships are computed once, at enrichment
    /// time, and stored as first-class edges — and the edge must cite the
    /// *authoritative* process key, which only exists after the lookup above.
    #[test]
    fn file_event_gains_a_process_wrote_file_entity_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
        );
        assert_eq!(file_event.relationships.len(), 1);
        let edge = &file_event.relationships[0];
        assert_eq!(edge.relation, Relation::Wrote);
        assert_eq!(edge.event_id, file_event.event_id);
        match (&edge.from, &edge.to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::File {
                    host_id: edge_host,
                    inode,
                    device_id,
                },
            ) => {
                assert_eq!(*process_key, authoritative);
                assert_eq!(*edge_host, host_id);
                assert_eq!(*inode, 131075);
                assert_eq!(*device_id, osiris_schema::encode_device_id(8, 1));
            }
            other => panic!("expected a Process -> File edge, got {other:?}"),
        }
    }

    #[test]
    fn file_event_without_a_usable_identity_gets_no_edge_rather_than_a_fabricated_one() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut event = bare_file_event(host_id, 300, 200, 131075);
        if let Some(file) = event.file.as_mut() {
            file.inode = None;
        }
        let enriched = enrich(event, "boot-1", &mut resolver);
        assert!(enriched.relationships.is_empty());
    }

    /// Regression guard: the Process branch's behaviour (record, then
    /// resolve the parent by the ppid carried in event_data) must be
    /// untouched by the new non-process path.
    #[test]
    fn process_events_still_record_and_resolve_exactly_as_before() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let bash = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver);
        let curl = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver);
        assert_eq!(
            curl.parent_process.unwrap().process_key,
            bash.process.unwrap().process_key
        );
    }
```

- [ ] **Step 16: Run to verify it fails**

Run: `cargo test -p osiris-pipeline enrich`
Expected: FAIL — the provisional key is not replaced, no `PROCESS_KEY_PROVISIONAL` tag exists, `parent_process` is `None` for file events, and `relationships` is empty.

- [ ] **Step 17: Implement category-aware enrichment**

Replace everything above `mod tests` in `crates/osiris-pipeline/src/enrich.rs` with:
```rust
use osiris_schema::{
    CanonicalEvent, Category, EntityRef, EntityRelationship, FileIdentity, ProcessRef, Relation,
};

use crate::process_resolver::ProcessResolver;

/// Enrich (local) stage (ARCHITECTURE.md §7.1 step 3): attach host/boot
/// identity, resolve process identity via the Process Resolver, and compute
/// the entity-graph edges §9.4 requires be written once here rather than
/// re-derived by every consumer. Cheap, always-available context only —
/// expensive enrichment is server-side (§7.2's split is preserved by simply
/// not doing that work yet, not by doing it here).
pub fn enrich(
    mut event: CanonicalEvent,
    boot_id: &str,
    resolver: &mut ProcessResolver,
) -> CanonicalEvent {
    event.boot_id = boot_id.to_string();

    match event.category {
        // Process events are the *source* of process identity: Normalize
        // hashed the real start time into their process_key, and they
        // populate the resolver for everyone else.
        Category::Process => enrich_process_event(&mut event, resolver),
        // Every other category *consumes* identity: the pid is known but
        // the start time isn't, so Normalize could only mint a provisional
        // key. Replace it with the authoritative one where we have it.
        _ => enrich_non_process_event(&mut event, resolver),
    }

    if event.category == Category::File {
        attach_file_relationship(&mut event);
    }

    event
}

fn enrich_process_event(event: &mut CanonicalEvent, resolver: &mut ProcessResolver) {
    let Some(process) = &event.process else {
        return;
    };
    let (pid, process_key) = (process.pid, process.process_key);
    let ppid = current_ppid(event);
    resolver.record(pid, ppid, process_key);
    event.parent_process = resolver.resolve_parent(pid).map(|parent_key| ProcessRef {
        process_key: parent_key,
        // The real ppid (Phase 1 finding 5) — not the placeholder 0 that was
        // indistinguishable from a genuine pid 0 once persisted and served
        // over /api/v1/events.
        pid: ppid,
        // ProcessResolver's cache only stores (ProcessKey, ppid), not
        // exe_path, so there is no cheap cached value to populate this
        // from — leave it empty, an honest "unknown" rather than paired
        // with a wrong pid.
        exe_path: String::new(),
        cmdline: vec![],
        exe_hash: None,
        start_time_mono: 0,
    });
}

fn enrich_non_process_event(event: &mut CanonicalEvent, resolver: &ProcessResolver) {
    let Some(pid) = event.process.as_ref().map(|p| p.pid) else {
        return;
    };
    match resolver.resolve(pid) {
        Some(authoritative) => {
            if let Some(process) = event.process.as_mut() {
                process.process_key = authoritative;
            }
        }
        // The process exec'd before the Agent started, or its sensor is
        // disabled. The provisional key stays, but it is tagged so nothing
        // downstream mistakes it for a real, joinable process identity.
        None => event.tags.push("PROCESS_KEY_PROVISIONAL".to_string()),
    }
    event.parent_process = resolver
        .parent_of(pid)
        .map(|(parent_key, parent_pid)| ProcessRef {
            process_key: parent_key,
            pid: parent_pid,
            exe_path: String::new(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
}

/// Writes the §9.4 `Process -WROTE-> File` edge. `WROTE` covers create,
/// write, delete and rename alike: §9.4's relation set has no
/// DELETED/RENAMED member and this phase does not extend it — the precise
/// operation is always recoverable from the cited event's `event_type`
/// (Phase 2 plan Global Constraints #14). No edge is written when the
/// backend could not report a full file identity: an edge citing a
/// fabricated identity is worse than no edge at all.
fn attach_file_relationship(event: &mut CanonicalEvent) {
    let (Some(process), Some(file)) = (event.process.as_ref(), event.file.as_ref()) else {
        return;
    };
    let Some(identity) = FileIdentity::from_file_ref(file) else {
        return;
    };
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: identity.to_entity_ref(event.host_id),
        relation: Relation::Wrote,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}

fn current_ppid(event: &CanonicalEvent) -> u32 {
    event
        .event_data
        .get("ppid")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0)
}
```

The existing test helper `bare_event` already sets `category: Category::Process`, so the three pre-existing enrich tests continue to exercise the process branch unchanged.

- [ ] **Step 18: Run to verify it passes**

Run: `cargo test -p osiris-pipeline enrich`
Expected: PASS — 3 existing enrich tests plus 6 new ones.

- [ ] **Step 19: Write the failing validate and prioritize tests**

Append to `crates/osiris-pipeline/src/validate.rs`'s `mod tests` (add `Category` to that module's `use osiris_schema::{...}` list):
```rust
    fn valid_file_event(event_type: EventType) -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = event_type;
        event.category = Category::File;
        event.file = Some(osiris_schema::FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: if event_type == EventType::FileRename {
                Some("/var/www/html/.shell.php.tmp".to_string())
            } else {
                None
            },
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        event
    }

    #[test]
    fn well_formed_file_events_of_every_type_validate() {
        for event_type in [
            EventType::FileCreate,
            EventType::FileWrite,
            EventType::FileDelete,
            EventType::FileRename,
        ] {
            let mut event = valid_file_event(event_type);
            assert!(validate(&mut event), "{event_type:?} should be valid");
            assert!(!event.tags.contains(&"INVALID".to_string()));
        }
    }

    #[test]
    fn file_event_without_a_file_ref_is_invalid_but_still_forwarded() {
        let mut event = valid_file_event(EventType::FileCreate);
        event.file = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn file_event_with_an_empty_path_is_invalid() {
        let mut event = valid_file_event(EventType::FileWrite);
        if let Some(file) = event.file.as_mut() {
            file.path = "   ".to_string();
        }
        assert!(!validate(&mut event));
    }

    /// A FILE_RENAME with no `previous_path` carries no information about
    /// where the file moved from, which is the entire point of the type.
    #[test]
    fn file_rename_without_a_previous_path_is_invalid() {
        let mut event = valid_file_event(EventType::FileRename);
        if let Some(file) = event.file.as_mut() {
            file.previous_path = None;
        }
        assert!(!validate(&mut event));
    }
```

In `crates/osiris-pipeline/src/prioritize.rs`'s `mod tests`, **replace** the existing `unmapped_event_type_falls_back_to_default_lane` test (its subject, `FileCreate`, is now mapped) with these two:
```rust
    #[test]
    fn file_event_types_map_to_their_configured_lanes() {
        let table = PriorityTable::default();
        for (event_type, expected) in [
            (EventType::FileCreate, PriorityLane::Normal),
            (EventType::FileDelete, PriorityLane::Normal),
            (EventType::FileRename, PriorityLane::Normal),
            // FILE_WRITE is the highest-volume file event by a wide margin
            // (every write to a watched path), so it gets a lane that can be
            // shed first under pressure — §8.1's whole reason for lanes.
            (EventType::FileWrite, PriorityLane::Low),
        ] {
            let mut event = exec_event();
            event.event_type = event_type;
            assert_eq!(prioritize(&event, &table), expected, "{event_type:?}");
        }
    }

    #[test]
    fn unmapped_event_type_falls_back_to_default_lane() {
        let mut event = exec_event();
        // NETWORK_CONNECT arrives in Phase 3; until then it is unmapped.
        event.event_type = EventType::NetworkConnect;
        let table = PriorityTable::default();
        assert_eq!(prioritize(&event, &table), PriorityLane::Normal);
    }
```

- [ ] **Step 20: Run to verify they fail**

Run: `cargo test -p osiris-pipeline validate prioritize`
Expected: FAIL — the three negative file-validation tests fail (validate has no file rules yet), and `file_event_types_map_to_their_configured_lanes` fails on `FileWrite` expecting `Low` but getting `Normal`.

- [ ] **Step 21: Implement the validate and prioritize changes**

In `crates/osiris-pipeline/src/validate.rs`, replace the whole `validate` function with:
```rust
pub fn validate(event: &mut CanonicalEvent) -> bool {
    use osiris_schema::EventType::{FileCreate, FileDelete, FileRename, FileWrite};
    let mut valid = true;
    if event.host_id.is_nil() {
        valid = false;
    }
    if event.timestamp == 0 {
        valid = false;
    }
    if event.event_type == osiris_schema::EventType::ProcessExec && event.process.is_none() {
        valid = false;
    }
    if matches!(
        event.event_type,
        FileCreate | FileWrite | FileDelete | FileRename
    ) {
        // A file event with no path names nothing — it cannot be stored,
        // queried by a File Story, or explained in an alert.
        let has_path = event
            .file
            .as_ref()
            .map(|f| !f.path.trim().is_empty())
            .unwrap_or(false);
        if !has_path {
            valid = false;
        }
        if event.event_type == FileRename
            && event
                .file
                .as_ref()
                .and_then(|f| f.previous_path.as_deref())
                .map(|p| p.trim().is_empty())
                .unwrap_or(true)
        {
            valid = false;
        }
    }
    if !valid {
        event.tags.push("INVALID".to_string());
    }
    valid
}
```

In `crates/osiris-pipeline/src/prioritize.rs`, replace `PriorityTable`'s `Default` impl with:
```rust
impl Default for PriorityTable {
    fn default() -> Self {
        Self {
            table: vec![
                (EventType::ProcessExec, PriorityLane::Normal),
                (EventType::FileCreate, PriorityLane::Normal),
                (EventType::FileDelete, PriorityLane::Normal),
                (EventType::FileRename, PriorityLane::Normal),
                // See the lane rationale in the tests: FILE_WRITE is the one
                // high-volume type this phase emits.
                (EventType::FileWrite, PriorityLane::Low),
            ],
            default_lane: PriorityLane::Normal,
        }
    }
}
```

Also update the `PriorityTable` doc comment: replace the clause "and Phase 1 only ever populates one entry (PROCESS_EXEC) here anyway, so a small `Vec` scan is both sufficient and simpler than a map" with "and this table holds five entries as of Phase 2, so a small `Vec` scan is still both sufficient and simpler than a map".

- [ ] **Step 22: Add the pipeline-level integration test**

Append to `crates/osiris-pipeline/src/pipeline.rs`'s `mod tests`:
```rust
    /// The whole Normalize -> Enrich -> Validate -> Prioritize path for a
    /// file event that follows its own process's exec — the shape every
    /// real trace has.
    #[test]
    fn file_event_following_its_process_exec_is_fully_resolved_and_valid() {
        use osiris_sensor_api::{FileEventRaw, FileOperation};
        let host = test_host();
        let mut pipeline = Pipeline::new(host.clone(), "boot-1".to_string());

        let curl = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_000,
            start_time_mono: 1_000,
            source: RawEventSource::Synthetic,
        }));

        let write = pipeline.process(RawEvent::File(FileEventRaw {
            operation: FileOperation::Write,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 2_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }));

        assert_eq!(write.lane, PriorityLane::Low);
        assert!(!write.event.tags.contains(&"INVALID".to_string()));
        assert!(!write
            .event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
        assert_eq!(
            write.event.process.as_ref().unwrap().process_key,
            curl.event.process.as_ref().unwrap().process_key,
            "the file event must be attributed to the same process entity as its exec"
        );
        assert_eq!(write.event.relationships.len(), 1);
        assert_eq!(
            write.event.file.as_ref().unwrap().path,
            "/var/www/html/shell.php"
        );
    }
```

- [ ] **Step 23: Run the full pipeline and sensor-api suites**

Run: `cargo test -p osiris-sensor-api -p osiris-pipeline`
Expected: PASS — every pre-existing test plus the new normalize (5), process_resolver (3), enrich (6), validate (4), prioritize (2, one replacing one) and pipeline (1) tests.

- [ ] **Step 24: Verify the whole workspace still builds and passes**

Run: `cargo test --workspace`
Expected: PASS across every crate. A compile failure in `osiris-agent` or the e2e tests would be one of the two `match` arms from Step 6 — recheck those.

- [ ] **Step 25: Commit**

```bash
git add crates/osiris-sensor-api crates/osiris-pipeline crates/osiris-sensors generator
git commit -m "feat(pipeline): normalize, enrich, validate and prioritize file events

Adds RawEvent::File(FileEventRaw), maps the four file operations onto the
existing FILE_* taxonomy, resolves a file event's acting process to the
same process_key its PROCESS_EXEC minted, and writes the §9.4
Process -WROTE-> File entity edge at enrichment time.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0192TqfN5oKsNzSDGYCo7aTt"
```

---

### Task 4: `osiris-sensors-fs` — the real Filesystem sensor (audit-log backend)

This is the phase's centrepiece. Unlike Phase 1's Process/Exec sensor, a file operation is **not** one audit line: the kernel emits a record *group* sharing one `msg=audit(<secs>.<millis>:<serial>)` header. A real `unlink("/tmp/foo")` under an audit watch rule looks like this in `/var/log/audit/audit.log`:

```
type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=87 success=yes exit=0 items=2 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=1000 tty=pts0 ses=1 comm="rm" exe="/usr/bin/rm" key="osiris_fs"
type=CWD msg=audit(1690000000.123:456): cwd="/home/user"
type=PATH msg=audit(1690000000.123:456): item=0 name="/tmp" inode=131074 dev=08:01 mode=040777 ouid=0 ogid=0 rdev=00:00 nametype=PARENT
type=PATH msg=audit(1690000000.123:456): item=1 name="/tmp/foo" inode=131075 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=DELETE
type=PROCTITLE msg=audit(1690000000.123:456): proctitle=726D002F746D702F666F6F
```

The `nametype` field is the operation signal (`PARENT` for a containing directory — never itself an event; `NORMAL` for a path merely touched; `CREATE` and `DELETE` for the dentry actually created/removed). `dev=08:01` is **hex** major:minor. `mode=0100644` is **octal**. A `rename(a, b)` where `b` already exists produces `PARENT, PARENT, DELETE(a), DELETE(b), CREATE(b)` — and the renamed file keeps the *source's* inode, which is what lets a File Story follow it across the rename.

**Files:**
- Modify: `Cargo.toml` (workspace root — add `"crates/osiris-sensors/fs"` to `members`)
- Create: `crates/osiris-sensors/fs/Cargo.toml`
- Create: `crates/osiris-sensors/fs/src/lib.rs`
- Create: `crates/osiris-sensors/fs/src/audit_record.rs`
- Create: `crates/osiris-sensors/fs/src/assembler.rs`
- Create: `crates/osiris-sensors/fs/src/sensor.rs`

**Interfaces:**
- Consumes: `osiris_fileutil::{LineTailer, tokenize, parse_audit_msg_id, AuditMsgId}` (Task 2); `osiris_schema::encode_device_id` (Task 1); `osiris_sensor_api::{Sensor, SensorContext, SensorCapabilities, SensorHealth, SensorState, SensorMetrics, SensorError, RawEvent, FileEventRaw, FileOperation, RawEventSource}` (Tasks 1/3, unchanged trait).
- Produces:
  - `osiris_sensors_fs::audit_record::{AuditRecord, PathRecord, SyscallRecord, NameType, parse_record}` where `parse_record(line: &str) -> Option<(AuditMsgId, AuditRecord)>`.
  - `osiris_sensors_fs::audit_record::{is_file_syscall, syscall_class, SyscallClass}` where `syscall_class(nr: u32) -> Option<SyscallClass>`.
  - `osiris_sensors_fs::assembler::{AuditEventAssembler, group_to_file_events}` where `group_to_file_events(id: AuditMsgId, syscall: &SyscallRecord, cwd: Option<&str>, paths: &[PathRecord]) -> Vec<FileEventRaw>` and `AuditEventAssembler::new(completion_timeout: Duration)`, `fn offer(&mut self, line: &str, now: Instant) -> Vec<FileEventRaw>`, `fn tick(&mut self, now: Instant) -> Vec<FileEventRaw>`, `fn flush(&mut self) -> Vec<FileEventRaw>`.
  - `osiris_sensors_fs::FilesystemSensor` with `FilesystemSensor::new(audit_log_path: impl Into<PathBuf>) -> Self`, `with_poll_interval(Duration) -> Self`, `with_completion_timeout(Duration) -> Self`, `with_audit_key(impl Into<String>) -> Self`. `Sensor::name()` returns `"filesystem"`. Task 5 registers it on the Agent.

- [ ] **Step 1: Register the crate in the workspace and write its manifest**

In the root `Cargo.toml`, change:
```toml
members = ["crates/*", "crates/osiris-sensors/process", "generator"]
```
to:
```toml
members = ["crates/*", "crates/osiris-sensors/process", "crates/osiris-sensors/fs", "generator"]
```
(`crates/osiris-sensors` stays in `exclude`, unchanged.)

Create `crates/osiris-sensors/fs/Cargo.toml`:
```toml
[package]
name = "osiris-sensors-fs"
version.workspace = true
edition.workspace = true

[dependencies]
tokio = { workspace = true }
tokio-util = { workspace = true }
async-trait = { workspace = true }
osiris-sensor-api = { path = "../../osiris-sensor-api" }
osiris-schema = { path = "../../osiris-schema" }
osiris-fileutil = { path = "../../osiris-fileutil" }

[dev-dependencies]
tempfile = { workspace = true }
```

Create `crates/osiris-sensors/fs/src/lib.rs`:
```rust
pub mod assembler;
pub mod audit_record;
pub mod sensor;

pub use assembler::{group_to_file_events, AuditEventAssembler};
pub use audit_record::{parse_record, AuditRecord, NameType, PathRecord, SyscallClass, SyscallRecord};
pub use sensor::FilesystemSensor;
```

Run: `cargo metadata --no-deps --format-version 1 | grep osiris-sensors-fs`
Expected: the package appears (it will not build yet — the modules are empty; that's Step 2's job).

- [ ] **Step 2: Write the failing test for `audit_record`**

Create `crates/osiris-sensors/fs/src/audit_record.rs` containing **only** the test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL_UNLINK: &str = r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=87 success=yes exit=0 a0=7ffd items=2 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="rm" exe="/usr/bin/rm" subj=unconfined key="osiris_fs""#;
    const CWD_LINE: &str = r#"type=CWD msg=audit(1690000000.123:456): cwd="/home/user""#;
    const PATH_PARENT: &str = r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/tmp" inode=131074 dev=08:01 mode=040777 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0"#;
    const PATH_DELETE: &str = r#"type=PATH msg=audit(1690000000.123:456): item=1 name="/tmp/foo" inode=131075 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0"#;

    #[test]
    fn parses_a_syscall_record_with_the_acting_process() {
        let (id, record) = parse_record(SYSCALL_UNLINK).expect("must parse");
        assert_eq!(id.serial, 456);
        assert_eq!(id.timestamp_ns, 1_690_000_000_123_000_000);
        match record {
            AuditRecord::Syscall(s) => {
                assert_eq!(s.syscall, 87);
                assert!(s.success);
                assert_eq!(s.pid, 300);
                assert_eq!(s.ppid, 200);
                assert_eq!(s.uid, 1000);
                assert_eq!(s.comm, "rm");
                assert_eq!(s.exe_path, "/usr/bin/rm");
                assert_eq!(s.key.as_deref(), Some("osiris_fs"));
            }
            other => panic!("expected Syscall, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_path_record_decoding_hex_dev_and_octal_mode() {
        let (_, record) = parse_record(PATH_DELETE).expect("must parse");
        match record {
            AuditRecord::Path(p) => {
                assert_eq!(p.item, 1);
                assert_eq!(p.name, "/tmp/foo");
                assert_eq!(p.inode, Some(131075));
                // dev=08:01 is HEX major:minor -> major 8, minor 1.
                assert_eq!(p.device_id, Some(osiris_schema::encode_device_id(8, 1)));
                // mode=0100644 is OCTAL: regular file, rw-r--r--.
                assert_eq!(p.mode, Some(0o100644));
                assert_eq!(p.owner_uid, Some(1000));
                assert_eq!(p.owner_gid, Some(1000));
                assert_eq!(p.nametype, NameType::Delete);
            }
            other => panic!("expected Path, got {other:?}"),
        }
    }

    /// A hex dev field with letters must not be read as decimal: `dev=fd:00`
    /// is major 253 (an LVM device), not a parse failure and not 65,536.
    #[test]
    fn decodes_a_hex_dev_field_containing_letters() {
        let line = PATH_DELETE.replace("dev=08:01", "dev=fd:00");
        let (_, record) = parse_record(&line).expect("must parse");
        match record {
            AuditRecord::Path(p) => {
                assert_eq!(p.device_id, Some(osiris_schema::encode_device_id(253, 0)))
            }
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn parses_every_nametype_the_kernel_emits() {
        for (raw, expected) in [
            ("PARENT", NameType::Parent),
            ("NORMAL", NameType::Normal),
            ("CREATE", NameType::Create),
            ("DELETE", NameType::Delete),
            ("UNKNOWN", NameType::Unknown),
            ("SOMETHING_NEW", NameType::Unknown),
        ] {
            let line = PATH_DELETE.replace("nametype=DELETE", &format!("nametype={raw}"));
            match parse_record(&line).expect("must parse").1 {
                AuditRecord::Path(p) => assert_eq!(p.nametype, expected, "{raw}"),
                other => panic!("expected Path, got {other:?}"),
            }
        }
    }

    #[test]
    fn parses_a_cwd_record() {
        match parse_record(CWD_LINE).expect("must parse").1 {
            AuditRecord::Cwd(cwd) => assert_eq!(cwd, "/home/user"),
            other => panic!("expected Cwd, got {other:?}"),
        }
    }

    #[test]
    fn classifies_unrelated_record_types_as_other_rather_than_dropping_them() {
        // PROCTITLE shares the event's id, so it must still parse (the
        // assembler needs the id to know the group hasn't ended) but carry
        // no payload.
        let line = r#"type=PROCTITLE msg=audit(1690000000.123:456): proctitle=726D"#;
        let (id, record) = parse_record(line).expect("must parse");
        assert_eq!(id.serial, 456);
        assert!(matches!(record, AuditRecord::Other));
    }

    #[test]
    fn rejects_a_line_with_no_audit_header() {
        assert!(parse_record("this is not an audit record").is_none());
    }

    #[test]
    fn a_path_record_with_a_null_name_is_rejected() {
        let line = PATH_DELETE.replace(r#"name="/tmp/foo""#, "name=(null)");
        assert!(parse_record(&line).is_none());
    }

    #[test]
    fn a_parent_path_record_still_parses_so_the_assembler_can_ignore_it_by_nametype() {
        match parse_record(PATH_PARENT).expect("must parse").1 {
            AuditRecord::Path(p) => {
                assert_eq!(p.item, 0);
                assert_eq!(p.nametype, NameType::Parent);
            }
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn classifies_the_file_syscalls_this_phase_handles() {
        assert_eq!(syscall_class(87), Some(SyscallClass::Delete)); // unlink
        assert_eq!(syscall_class(263), Some(SyscallClass::Delete)); // unlinkat
        assert_eq!(syscall_class(84), Some(SyscallClass::Delete)); // rmdir
        assert_eq!(syscall_class(82), Some(SyscallClass::Rename)); // rename
        assert_eq!(syscall_class(264), Some(SyscallClass::Rename)); // renameat
        assert_eq!(syscall_class(316), Some(SyscallClass::Rename)); // renameat2
        assert_eq!(syscall_class(83), Some(SyscallClass::Create)); // mkdir
        assert_eq!(syscall_class(258), Some(SyscallClass::Create)); // mkdirat
        assert_eq!(syscall_class(2), Some(SyscallClass::Write)); // open
        assert_eq!(syscall_class(257), Some(SyscallClass::Write)); // openat
        assert_eq!(syscall_class(437), Some(SyscallClass::Write)); // openat2
        assert_eq!(syscall_class(85), Some(SyscallClass::Write)); // creat
        assert_eq!(syscall_class(76), Some(SyscallClass::Write)); // truncate
        assert_eq!(syscall_class(77), Some(SyscallClass::Write)); // ftruncate
        // execve is a Process/Exec concern, not a filesystem one, and
        // write(2) operates on an fd so it emits no PATH records at all.
        assert_eq!(syscall_class(59), None);
        assert_eq!(syscall_class(1), None);
        assert!(is_file_syscall(87));
        assert!(!is_file_syscall(59));
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p osiris-sensors-fs audit_record`
Expected: FAIL — every name in the test module is undefined.

- [ ] **Step 4: Implement `audit_record.rs`**

Insert above the test module:
```rust
use osiris_fileutil::{parse_audit_msg_id, tokenize, AuditMsgId};
use osiris_schema::encode_device_id;

/// The `nametype` field of a `type=PATH` record — the kernel's own
/// statement of what role the path played in the syscall. This, not the
/// syscall number alone, is what tells create from delete from touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameType {
    /// A containing directory, resolved on the way to the real operand.
    /// Never an event in its own right.
    Parent,
    /// A path the syscall touched without creating or removing its dentry.
    Normal,
    Create,
    Delete,
    /// The kernel could not classify it, or emitted a value this build does
    /// not know. Treated as "not an event" rather than guessed at.
    Unknown,
}

/// The classes of file syscall this phase handles, keyed by x86_64 syscall
/// number. `write(2)` is deliberately absent: it operates on a file
/// descriptor and emits no `type=PATH` records, so there is nothing to
/// correlate — the `open`/`openat` that produced the descriptor is what
/// audit reports, and that is what this sensor keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallClass {
    /// open/openat/openat2/creat/truncate/ftruncate — a NORMAL path operand
    /// here means the file's contents were opened for modification.
    Write,
    /// mkdir/mkdirat.
    Create,
    /// unlink/unlinkat/rmdir.
    Delete,
    /// rename/renameat/renameat2 — the one class producing a paired
    /// DELETE + CREATE that must be joined into a single event.
    Rename,
}

pub fn syscall_class(nr: u32) -> Option<SyscallClass> {
    match nr {
        2 | 257 | 437 | 85 | 76 | 77 => Some(SyscallClass::Write),
        83 | 258 => Some(SyscallClass::Create),
        87 | 263 | 84 => Some(SyscallClass::Delete),
        82 | 264 | 316 => Some(SyscallClass::Rename),
        _ => None,
    }
}

pub fn is_file_syscall(nr: u32) -> bool {
    syscall_class(nr).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallRecord {
    pub syscall: u32,
    pub success: bool,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe_path: String,
    /// The audit rule's `-F key=` tag, when the rule set one. Lets the
    /// sensor consume only the records its own watch rules produced.
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRecord {
    pub item: u32,
    /// As printed by the kernel — may be relative, in which case the
    /// group's `type=CWD` record absolutizes it (see `assembler`).
    pub name: String,
    pub inode: Option<u64>,
    pub device_id: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    pub nametype: NameType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRecord {
    Syscall(SyscallRecord),
    Path(PathRecord),
    Cwd(String),
    /// Any other record type sharing the event id (PROCTITLE, EXECVE, ...).
    /// Kept rather than dropped so the assembler can see that the group is
    /// still open.
    Other,
}

/// Parses one auditd log line into its shared event id plus its payload.
/// Returns `None` only for lines with no parseable `msg=audit(...)` header
/// or a PATH record with no usable name — never panics on malformed input.
pub fn parse_record(line: &str) -> Option<(AuditMsgId, AuditRecord)> {
    let fields = tokenize(line);
    let id = parse_audit_msg_id(fields.get("msg")?)?;
    let record = match fields.get("type").map(String::as_str) {
        Some("SYSCALL") => AuditRecord::Syscall(SyscallRecord {
            syscall: fields.get("syscall")?.parse().ok()?,
            success: fields.get("success").map(String::as_str) == Some("yes"),
            pid: fields.get("pid")?.parse().ok()?,
            ppid: fields.get("ppid")?.parse().ok()?,
            uid: fields.get("uid")?.parse().ok()?,
            comm: fields.get("comm").cloned().unwrap_or_default(),
            exe_path: fields.get("exe").cloned().unwrap_or_default(),
            key: fields
                .get("key")
                .filter(|k| k.as_str() != "(null)")
                .cloned(),
        }),
        Some("PATH") => {
            let name = fields.get("name")?;
            if name.is_empty() || name == "(null)" {
                return None;
            }
            AuditRecord::Path(PathRecord {
                item: fields.get("item").and_then(|v| v.parse().ok()).unwrap_or(0),
                name: name.clone(),
                inode: fields.get("inode").and_then(|v| v.parse().ok()),
                device_id: fields.get("dev").and_then(|v| parse_dev(v)),
                mode: fields
                    .get("mode")
                    .and_then(|v| u32::from_str_radix(v, 8).ok()),
                owner_uid: fields.get("ouid").and_then(|v| v.parse().ok()),
                owner_gid: fields.get("ogid").and_then(|v| v.parse().ok()),
                nametype: parse_nametype(fields.get("nametype").map(String::as_str)),
            })
        }
        Some("CWD") => AuditRecord::Cwd(fields.get("cwd")?.clone()),
        _ => AuditRecord::Other,
    };
    Some((id, record))
}

fn parse_nametype(raw: Option<&str>) -> NameType {
    match raw {
        Some("PARENT") => NameType::Parent,
        Some("NORMAL") => NameType::Normal,
        Some("CREATE") => NameType::Create,
        Some("DELETE") => NameType::Delete,
        // Includes the kernel's literal "UNKNOWN" and any value a future
        // kernel adds: unrecognised is never guessed at.
        _ => NameType::Unknown,
    }
}

/// Decodes an audit PATH record's `dev=MAJ:MIN` field. Both halves are
/// **hexadecimal** (`dev=08:01` is major 8 minor 1; `dev=fd:00` is major
/// 253) — reading them as decimal silently mis-identifies every LVM and
/// device-mapper volume.
fn parse_dev(raw: &str) -> Option<u64> {
    let (major, minor) = raw.split_once(':')?;
    let major = u32::from_str_radix(major, 16).ok()?;
    let minor = u32::from_str_radix(minor, 16).ok()?;
    Some(encode_device_id(major, minor))
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p osiris-sensors-fs audit_record`
Expected: PASS — 10 tests. (`assembler.rs` and `sensor.rs` are still empty files at this point; create them as empty modules so `lib.rs` compiles, or comment out their `pub mod` lines and restore them in Steps 6 and 10 — either way `cargo test -p osiris-sensors-fs audit_record` must run green before moving on.)

- [ ] **Step 6: Write the failing test for the record assembler**

Create `crates/osiris-sensors/fs/src/assembler.rs` containing **only** the test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::FileOperation;

    fn syscall_line(serial: u64, nr: u32, comm: &str, exe: &str) -> String {
        format!(
            r#"type=SYSCALL msg=audit(1690000000.123:{serial}): arch=c000003e syscall={nr} success=yes exit=0 items=2 ppid=200 pid=300 auid=1000 uid=1000 tty=pts0 ses=1 comm="{comm}" exe="{exe}" key="osiris_fs""#
        )
    }

    fn path_line(serial: u64, item: u32, name: &str, inode: u64, nametype: &str) -> String {
        format!(
            r#"type=PATH msg=audit(1690000000.123:{serial}): item={item} name="{name}" inode={inode} dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype={nametype}"#
        )
    }

    fn cwd_line(serial: u64, cwd: &str) -> String {
        format!(r#"type=CWD msg=audit(1690000000.123:{serial}): cwd="{cwd}""#)
    }

    /// The pure joiner, tested without any clock at all.
    fn events_for(lines: &[String]) -> Vec<osiris_sensor_api::FileEventRaw> {
        let mut assembler = AuditEventAssembler::new(Duration::from_millis(0));
        let start = Instant::now();
        let mut out = vec![];
        for line in lines {
            out.extend(assembler.offer(line, start));
        }
        out.extend(assembler.flush());
        out
    }

    #[test]
    fn unlink_produces_one_delete_event_and_ignores_the_parent_item() {
        let lines = vec![
            syscall_line(456, 87, "rm", "/usr/bin/rm"),
            cwd_line(456, "/home/user"),
            path_line(456, 0, "/tmp", 131074, "PARENT"),
            path_line(456, 1, "/tmp/foo", 131075, "DELETE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1, "PARENT items must never become events");
        let event = &events[0];
        assert_eq!(event.operation, FileOperation::Delete);
        assert_eq!(event.path, "/tmp/foo");
        assert_eq!(event.inode, Some(131075));
        assert_eq!(event.device_id, Some(osiris_schema::encode_device_id(8, 1)));
        assert_eq!(event.pid, 300);
        assert_eq!(event.ppid, 200);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.exe_path, "/usr/bin/rm");
        assert_eq!(event.comm, "rm");
        assert_eq!(event.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(event.audit_serial, Some(456));
    }

    #[test]
    fn open_with_o_creat_produces_a_create_event() {
        let lines = vec![
            syscall_line(457, 257, "curl", "/usr/bin/curl"),
            path_line(457, 0, "/var/www/html", 200000, "PARENT"),
            path_line(457, 1, "/var/www/html/shell.php", 200001, "CREATE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, FileOperation::Create);
        assert_eq!(events[0].path, "/var/www/html/shell.php");
    }

    #[test]
    fn opening_an_existing_file_for_write_produces_a_write_event() {
        let lines = vec![
            syscall_line(458, 257, "curl", "/usr/bin/curl"),
            path_line(458, 0, "/var/www/html/shell.php", 200001, "NORMAL"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, FileOperation::Write);
    }

    /// A NORMAL path operand on a syscall that cannot modify contents is
    /// not a write. This phase emits no read events at all (§6's Filesystem
    /// STANDARD row), so such a group must produce nothing.
    #[test]
    fn a_normal_path_on_a_non_write_syscall_produces_nothing() {
        let lines = vec![
            // stat(2) = 4, not in any file-syscall class.
            syscall_line(459, 4, "ls", "/usr/bin/ls"),
            path_line(459, 0, "/var/www/html/shell.php", 200001, "NORMAL"),
        ];
        assert!(events_for(&lines).is_empty());
    }

    /// rename() emits PARENT, PARENT, DELETE(src), CREATE(dst). The two
    /// must join into exactly ONE FILE_RENAME, never a delete plus a create
    /// — and the identity must be the SOURCE's inode, because that is the
    /// inode the file keeps, and following it is the whole reason File
    /// Story joins on identity rather than path.
    #[test]
    fn rename_joins_the_delete_and_create_items_into_one_event() {
        let lines = vec![
            syscall_line(460, 82, "curl", "/usr/bin/curl"),
            path_line(460, 0, "/var/www/html", 200000, "PARENT"),
            path_line(460, 1, "/var/www/html", 200000, "PARENT"),
            path_line(460, 2, "/var/www/html/.shell.php.tmp", 200001, "DELETE"),
            path_line(460, 3, "/var/www/html/shell.php", 200001, "CREATE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.operation, FileOperation::Rename);
        assert_eq!(event.path, "/var/www/html/shell.php");
        assert_eq!(
            event.previous_path.as_deref(),
            Some("/var/www/html/.shell.php.tmp")
        );
        assert_eq!(event.inode, Some(200001));
    }

    /// Renaming *over* an existing file emits a second DELETE for the
    /// destination. The event is still one rename, and its identity is
    /// still the source's (the first DELETE item's) inode — not the
    /// clobbered destination's.
    #[test]
    fn rename_over_an_existing_destination_is_still_one_event_with_the_source_inode() {
        let lines = vec![
            syscall_line(461, 82, "curl", "/usr/bin/curl"),
            path_line(461, 0, "/var/www/html", 200000, "PARENT"),
            path_line(461, 1, "/var/www/html", 200000, "PARENT"),
            path_line(461, 2, "/var/www/html/.shell.php.tmp", 200001, "DELETE"),
            path_line(461, 3, "/var/www/html/shell.php", 199999, "DELETE"),
            path_line(461, 4, "/var/www/html/shell.php", 200001, "CREATE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, FileOperation::Rename);
        assert_eq!(events[0].path, "/var/www/html/shell.php");
        assert_eq!(
            events[0].previous_path.as_deref(),
            Some("/var/www/html/.shell.php.tmp")
        );
        assert_eq!(events[0].inode, Some(200001));
    }

    #[test]
    fn a_relative_path_is_absolutized_against_the_groups_cwd_record() {
        let lines = vec![
            syscall_line(462, 87, "rm", "/usr/bin/rm"),
            cwd_line(462, "/var/www/html"),
            path_line(462, 0, "shell.php", 200001, "DELETE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events[0].path, "/var/www/html/shell.php");
    }

    #[test]
    fn a_failed_syscall_produces_no_events() {
        let failed = syscall_line(463, 87, "rm", "/usr/bin/rm").replace("success=yes", "success=no");
        let lines = vec![failed, path_line(463, 0, "/tmp/foo", 131075, "DELETE")];
        assert!(events_for(&lines).is_empty());
    }

    #[test]
    fn a_group_with_no_syscall_record_produces_no_events() {
        let lines = vec![path_line(464, 0, "/tmp/foo", 131075, "DELETE")];
        assert!(events_for(&lines).is_empty());
    }

    /// Two consecutive audit events must not bleed into each other: the
    /// arrival of a record with a new id closes the previous group.
    #[test]
    fn a_new_event_id_closes_the_previous_group() {
        let mut assembler = AuditEventAssembler::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(assembler
            .offer(&syscall_line(470, 87, "rm", "/usr/bin/rm"), now)
            .is_empty());
        assert!(assembler
            .offer(&path_line(470, 0, "/tmp/a", 1, "DELETE"), now)
            .is_empty());
        // The first record of event 471 closes event 470.
        let emitted = assembler.offer(&syscall_line(471, 87, "rm", "/usr/bin/rm"), now);
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].path, "/tmp/a");
        assert_eq!(emitted[0].audit_serial, Some(470));
    }

    /// The final event in a log file has no following record to close it,
    /// so a pending group must be released once it has sat untouched for
    /// the completion timeout. Without this the last file operation before
    /// the system goes quiet is never reported.
    #[test]
    fn a_pending_group_is_released_by_tick_after_the_completion_timeout() {
        let mut assembler = AuditEventAssembler::new(Duration::from_millis(100));
        let start = Instant::now();
        assembler.offer(&syscall_line(480, 87, "rm", "/usr/bin/rm"), start);
        assembler.offer(&path_line(480, 0, "/tmp/last", 1, "DELETE"), start);

        assert!(
            assembler.tick(start + Duration::from_millis(50)).is_empty(),
            "must not release a group that could still be receiving records"
        );
        let emitted = assembler.tick(start + Duration::from_millis(150));
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].path, "/tmp/last");
        // Released once and once only.
        assert!(assembler.tick(start + Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn unparseable_lines_are_skipped_without_disturbing_the_open_group() {
        let mut assembler = AuditEventAssembler::new(Duration::from_secs(60));
        let now = Instant::now();
        assembler.offer(&syscall_line(490, 87, "rm", "/usr/bin/rm"), now);
        assert!(assembler.offer("garbage with no audit header", now).is_empty());
        assembler.offer(&path_line(490, 0, "/tmp/foo", 1, "DELETE"), now);
        let emitted = assembler.flush();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].path, "/tmp/foo");
    }
}
```

- [ ] **Step 7: Run to verify it fails**

Run: `cargo test -p osiris-sensors-fs assembler`
Expected: FAIL — `AuditEventAssembler` and `group_to_file_events` are undefined.

- [ ] **Step 8: Implement `assembler.rs`**

Insert above the test module:
```rust
use std::time::{Duration, Instant};

use osiris_fileutil::AuditMsgId;
use osiris_sensor_api::{FileEventRaw, FileOperation, RawEventSource};

use crate::audit_record::{
    parse_record, syscall_class, AuditRecord, NameType, PathRecord, SyscallClass, SyscallRecord,
};

/// One kernel audit event's records, accumulated until the group closes.
struct PendingGroup {
    id: AuditMsgId,
    syscall: Option<SyscallRecord>,
    cwd: Option<String>,
    paths: Vec<PathRecord>,
    first_seen: Instant,
}

/// Groups an auditd log's records into complete kernel audit events and
/// turns each into zero or more `FileEventRaw`s.
///
/// auditd writes every record of one event contiguously, so exactly one
/// group is ever open: a record bearing a new `AuditMsgId` proves the
/// previous group is complete. The one case that rule cannot cover is the
/// *last* event in the file, which has no successor — that is what
/// `completion_timeout` and `tick` are for.
pub struct AuditEventAssembler {
    pending: Option<PendingGroup>,
    completion_timeout: Duration,
    /// Guards against a pathological log (a single event with an unbounded
    /// number of PATH records) growing this buffer without limit.
    max_paths_per_group: usize,
}

impl AuditEventAssembler {
    pub fn new(completion_timeout: Duration) -> Self {
        Self {
            pending: None,
            completion_timeout,
            max_paths_per_group: 64,
        }
    }

    /// Feeds one raw audit log line. Returns the file events of the
    /// *previous* group if this line closed it. Lines that don't parse are
    /// skipped without disturbing the open group.
    pub fn offer(&mut self, line: &str, now: Instant) -> Vec<FileEventRaw> {
        let Some((id, record)) = parse_record(line) else {
            return vec![];
        };
        let mut emitted = vec![];
        match &self.pending {
            Some(group) if group.id == id => {}
            Some(_) => emitted = self.take_pending(),
            None => {}
        }
        let group = self.pending.get_or_insert_with(|| PendingGroup {
            id,
            syscall: None,
            cwd: None,
            paths: Vec::new(),
            first_seen: now,
        });
        match record {
            AuditRecord::Syscall(s) => group.syscall = Some(s),
            AuditRecord::Cwd(cwd) => group.cwd = Some(cwd),
            AuditRecord::Path(p) => {
                if group.paths.len() < self.max_paths_per_group {
                    group.paths.push(p);
                }
            }
            AuditRecord::Other => {}
        }
        emitted
    }

    /// Releases the open group once it has gone `completion_timeout`
    /// without a new record — the only way the final event in a quiet log
    /// ever gets reported.
    pub fn tick(&mut self, now: Instant) -> Vec<FileEventRaw> {
        let expired = self
            .pending
            .as_ref()
            .map(|g| now.duration_since(g.first_seen) >= self.completion_timeout)
            .unwrap_or(false);
        if expired {
            self.take_pending()
        } else {
            vec![]
        }
    }

    /// Releases the open group unconditionally (shutdown, and tests).
    pub fn flush(&mut self) -> Vec<FileEventRaw> {
        self.take_pending()
    }

    fn take_pending(&mut self) -> Vec<FileEventRaw> {
        let Some(group) = self.pending.take() else {
            return vec![];
        };
        let Some(syscall) = &group.syscall else {
            // PATH records with no SYSCALL record describe nothing
            // attributable — no acting process, no syscall class.
            return vec![];
        };
        group_to_file_events(group.id, syscall, group.cwd.as_deref(), &group.paths)
    }
}

/// The pure joiner: one completed audit event group in, file events out.
/// Free-standing and clock-free so every correlation rule below is
/// testable without an `Instant`.
pub fn group_to_file_events(
    id: AuditMsgId,
    syscall: &SyscallRecord,
    cwd: Option<&str>,
    paths: &[PathRecord],
) -> Vec<FileEventRaw> {
    // A syscall that failed changed nothing on disk.
    if !syscall.success {
        return vec![];
    }
    let Some(class) = syscall_class(syscall.syscall) else {
        return vec![];
    };
    // PARENT items are directories resolved on the way to the operand, not
    // operations in their own right; UNKNOWN items are unclassifiable.
    let operands: Vec<&PathRecord> = paths
        .iter()
        .filter(|p| !matches!(p.nametype, NameType::Parent | NameType::Unknown))
        .collect();
    if operands.is_empty() {
        return vec![];
    }

    if class == SyscallClass::Rename {
        return rename_event(id, syscall, cwd, &operands).into_iter().collect();
    }

    operands
        .iter()
        .filter_map(|path| {
            let operation = match path.nametype {
                NameType::Create => FileOperation::Create,
                NameType::Delete => FileOperation::Delete,
                // A merely-touched path counts as a write only when the
                // syscall could modify contents. Read-only opens produce
                // NORMAL items too, and this phase emits no read events
                // (§6's Filesystem STANDARD row).
                NameType::Normal if class == SyscallClass::Write => FileOperation::Write,
                _ => return None,
            };
            Some(build_event(id, syscall, operation, absolutize(&path.name, cwd), None, path))
        })
        .collect()
}

/// rename/renameat/renameat2 emit a DELETE for the source and a CREATE for
/// the destination (plus a second DELETE when the destination already
/// existed and was clobbered). That is ONE move, not a delete and a
/// create — and the moved file keeps the SOURCE's inode, so the source
/// item is what supplies the identity a File Story follows across the
/// rename.
fn rename_event(
    id: AuditMsgId,
    syscall: &SyscallRecord,
    cwd: Option<&str>,
    operands: &[&PathRecord],
) -> Option<FileEventRaw> {
    let source = operands
        .iter()
        .find(|p| p.nametype == NameType::Delete)
        .copied()?;
    let destination = operands
        .iter()
        .find(|p| p.nametype == NameType::Create)
        .copied()
        // renameat2 with RENAME_EXCHANGE reports no CREATE item; fall back
        // to the last DELETE so the event still names both ends.
        .or_else(|| {
            operands
                .iter()
                .rev()
                .find(|p| p.nametype == NameType::Delete && !std::ptr::eq(**p, source))
                .copied()
        })?;
    Some(build_event(
        id,
        syscall,
        FileOperation::Rename,
        absolutize(&destination.name, cwd),
        Some(absolutize(&source.name, cwd)),
        source,
    ))
}

/// `identity_source` is the PATH record whose inode/device/mode describe
/// the file this event is *about* — the same record as the path for every
/// operation except rename, where it is the source item.
fn build_event(
    id: AuditMsgId,
    syscall: &SyscallRecord,
    operation: FileOperation,
    path: String,
    previous_path: Option<String>,
    identity_source: &PathRecord,
) -> FileEventRaw {
    FileEventRaw {
        operation,
        path,
        previous_path,
        inode: identity_source.inode,
        device_id: identity_source.device_id,
        mode: identity_source.mode,
        owner_uid: identity_source.owner_uid,
        owner_gid: identity_source.owner_gid,
        pid: syscall.pid,
        ppid: syscall.ppid,
        uid: syscall.uid,
        exe_path: syscall.exe_path.clone(),
        comm: syscall.comm.clone(),
        timestamp_ns: id.timestamp_ns,
        audit_serial: Some(id.serial),
        source: RawEventSource::Audit,
    }
}

/// The kernel prints `name=` exactly as the syscall received it, so a
/// relative path must be joined to the group's `type=CWD` record. A
/// relative path with no CWD record is returned unchanged rather than
/// guessed at — downstream it is still a real, if less useful, observation.
fn absolutize(name: &str, cwd: Option<&str>) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    match cwd {
        Some(cwd) => format!("{}/{}", cwd.trim_end_matches('/'), name),
        None => name.to_string(),
    }
}
```

- [ ] **Step 9: Run to verify it passes**

Run: `cargo test -p osiris-sensors-fs assembler`
Expected: PASS — 12 tests.

- [ ] **Step 10: Write the failing test for the sensor**

Create `crates/osiris-sensors/fs/src/sensor.rs` containing **only** the test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{FileOperation, RawEvent};
    use std::io::Write;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn reports_unsupported_when_the_audit_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = FilesystemSensor::new(dir.path().join("missing.log"));
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        assert!(caps
            .unsupported_reason
            .as_deref()
            .unwrap_or_default()
            .contains("audit log not found"));

        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn emits_a_create_event_for_an_appended_audit_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor = FilesystemSensor::new(&path)
            .with_poll_interval(Duration::from_millis(20))
            .with_completion_timeout(Duration::from_millis(40));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=257 success=yes exit=3 items=2 ppid=200 pid=300 uid=1000 comm="curl" exe="/usr/bin/curl" key="osiris_fs""#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/var/www/html" inode=200000 dev=08:01 mode=040755 ouid=0 ogid=0 nametype=PARENT"#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=1 name="/var/www/html/shell.php" inode=200001 dev=08:01 mode=0100644 ouid=33 ogid=33 nametype=CREATE"#).unwrap();
        file.flush().unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for a file event")
            .expect("channel closed unexpectedly");
        match received {
            RawEvent::File(raw) => {
                assert_eq!(raw.operation, FileOperation::Create);
                assert_eq!(raw.path, "/var/www/html/shell.php");
                assert_eq!(raw.inode, Some(200001));
                assert_eq!(raw.exe_path, "/usr/bin/curl");
            }
            other => panic!("the Filesystem sensor must only emit File events, got {other:?}"),
        }

        sensor.stop().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.events_emitted_total, 1);
        assert_eq!(health.state, SensorState::Stopped);
    }

    /// The sensor must consume only what its own audit watch rules
    /// produced when a key filter is configured — a busy host's audit log
    /// carries every other subsystem's records too.
    #[tokio::test]
    async fn an_audit_key_filter_excludes_records_from_other_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor = FilesystemSensor::new(&path)
            .with_poll_interval(Duration::from_millis(20))
            .with_completion_timeout(Duration::from_millis(40))
            .with_audit_key("osiris_fs");
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        // Someone else's rule fired first.
        writeln!(file, r#"type=SYSCALL msg=audit(1690000000.100:400): arch=c000003e syscall=87 success=yes exit=0 items=1 ppid=1 pid=99 uid=0 comm="logrotate" exe="/usr/sbin/logrotate" key="other_rule""#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.100:400): item=0 name="/var/log/old.log" inode=111 dev=08:01 mode=0100644 ouid=0 ogid=0 nametype=DELETE"#).unwrap();
        // Then ours.
        writeln!(file, r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=87 success=yes exit=0 items=1 ppid=200 pid=300 uid=1000 comm="rm" exe="/usr/bin/rm" key="osiris_fs""#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/var/www/html/shell.php" inode=200001 dev=08:01 mode=0100644 ouid=33 ogid=33 nametype=DELETE"#).unwrap();
        file.flush().unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        match received {
            RawEvent::File(raw) => assert_eq!(
                raw.path, "/var/www/html/shell.php",
                "the other rule's event must have been filtered out"
            ),
            other => panic!("expected a File event, got {other:?}"),
        }
        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 1);
    }
}
```

- [ ] **Step 11: Run to verify it fails**

Run: `cargo test -p osiris-sensors-fs sensor`
Expected: FAIL — `FilesystemSensor` is undefined.

- [ ] **Step 12: Implement `sensor.rs`**

Insert above the test module. The lifecycle shape deliberately mirrors `ProcessExecSensor` exactly (spawn on `initialize`, poison-recovering health lock, cancel-and-await on `stop`) so the two sensors stay reviewable side by side:
```rust
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use osiris_fileutil::LineTailer;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::assembler::AuditEventAssembler;
use crate::audit_record::{parse_record, AuditRecord};

struct HealthState {
    state: SensorState,
    events_emitted_total: u64,
    events_dropped_total: u64,
    last_error: Option<String>,
    last_event_at: Option<u64>,
    capability_flags: Vec<String>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            state: SensorState::Starting,
            events_emitted_total: 0,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: None,
            capability_flags: vec![],
        }
    }
}

/// Locks a health mutex, recovering rather than panicking if a prior holder
/// panicked while holding it — matches the discipline established by
/// `osiris-sensors-process` and `osiris-generator`.
fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Filesystem sensor (ARCHITECTURE.md §4.3's Filesystem row), Phase 2
/// scope: the Audit fallback backend only, consumed by tailing an
/// auditd-format log file (plan Global Constraints #1/#2). eBPF LSM hooks
/// and fanotify are additional `Sensor` implementations behind this same
/// unchanged trait, not a rewrite of this one.
///
/// Expected audit rules on a real host (the sensor does not install them;
/// that is an operator/packaging concern):
/// ```text
/// -a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate \
///    -F dir=/var/www -F perm=wa -F key=osiris_fs
/// -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir \
///    -F dir=/var/www -F key=osiris_fs
/// ```
pub struct FilesystemSensor {
    audit_log_path: PathBuf,
    poll_interval: Duration,
    completion_timeout: Duration,
    audit_key: Option<String>,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl FilesystemSensor {
    pub fn new(audit_log_path: impl Into<PathBuf>) -> Self {
        Self {
            audit_log_path: audit_log_path.into(),
            poll_interval: Duration::from_millis(200),
            // Comfortably longer than one poll, so a group split across two
            // polls is never released mid-way, but short enough that the
            // last operation before a quiet period still surfaces promptly.
            completion_timeout: Duration::from_millis(500),
            audit_key: None,
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn with_completion_timeout(mut self, timeout: Duration) -> Self {
        self.completion_timeout = timeout;
        self
    }

    /// Consume only records tagged with this audit rule `key=`. Without it
    /// the sensor consumes every file syscall record in the log, which on a
    /// busy host means other subsystems' rules too.
    pub fn with_audit_key(mut self, key: impl Into<String>) -> Self {
        self.audit_key = Some(key.into());
        self
    }
}

/// True when this line should be fed to the assembler. A key filter can
/// only be applied to `SYSCALL` records (they are the only records carrying
/// `key=`), so PATH/CWD/other records always pass through — the assembler
/// discards any group whose SYSCALL record never arrived, which is exactly
/// what happens to a filtered-out group.
fn passes_key_filter(line: &str, audit_key: Option<&str>) -> bool {
    let Some(wanted) = audit_key else {
        return true;
    };
    match parse_record(line) {
        Some((_, AuditRecord::Syscall(s))) => s.key.as_deref() == Some(wanted),
        _ => true,
    }
}

#[async_trait]
impl Sensor for FilesystemSensor {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn capabilities(&self) -> SensorCapabilities {
        if self.audit_log_path.exists() {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: true,
                always_available: false,
                unsupported_reason: None,
            }
        } else {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: false,
                unsupported_reason: Some(format!(
                    "audit log not found at {}",
                    self.audit_log_path.display()
                )),
            }
        }
    }

    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError> {
        self.cancellation = Some(ctx.cancellation.clone());
        lock_health(&self.health).state = SensorState::Starting;

        let caps = self.capabilities();
        if !caps.supported() {
            let reason = caps.unsupported_reason.clone().unwrap_or_default();
            lock_health(&self.health).last_error = Some(reason.clone());
            return Err(SensorError::Unsupported(reason));
        }
        lock_health(&self.health).capability_flags = vec!["audit_fallback".to_string()];

        let path = self.audit_log_path.clone();
        let poll_interval = self.poll_interval;
        let completion_timeout = self.completion_timeout;
        let audit_key = self.audit_key.clone();
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut tailer = LineTailer::new(path);
            let mut assembler = AuditEventAssembler::new(completion_timeout);
            loop {
                if cancellation.is_cancelled() {
                    // Release whatever group was still open so the last
                    // observed operation isn't silently dropped on shutdown.
                    for raw in assembler.flush() {
                        emit(&output, raw, &health).await;
                    }
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                match tailer.poll() {
                    Ok(lines) => {
                        for line in lines {
                            if !passes_key_filter(&line, audit_key.as_deref()) {
                                continue;
                            }
                            for raw in assembler.offer(&line, Instant::now()) {
                                emit(&output, raw, &health).await;
                            }
                        }
                        for raw in assembler.tick(Instant::now()) {
                            emit(&output, raw, &health).await;
                        }
                    }
                    Err(e) => {
                        let mut h = lock_health(&health);
                        h.state = SensorState::Degraded;
                        h.last_error = Some(e.to_string());
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancellation.cancelled() => {
                        for raw in assembler.flush() {
                            emit(&output, raw, &health).await;
                        }
                        lock_health(&health).state = SensorState::Stopped;
                        return;
                    }
                }
            }
        });
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
        // The polling task is already spawned in initialize(); this sensor
        // has no separate "armed but not running" state, same as
        // ProcessExecSensor.
        lock_health(&self.health).state = SensorState::Healthy;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), SensorError> {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        lock_health(&self.health).state = SensorState::Stopped;
        Ok(())
    }

    fn health(&self) -> SensorHealth {
        let h = lock_health(&self.health);
        SensorHealth {
            name: self.name().to_string(),
            state: h.state,
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
            last_error: h.last_error.clone(),
            last_event_at: h.last_event_at,
            capability_flags: h.capability_flags.clone(),
            p99_emit_latency_us: 0,
        }
    }

    fn metrics(&self) -> SensorMetrics {
        let h = lock_health(&self.health);
        SensorMetrics {
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
        }
    }
}

async fn emit(
    output: &tokio::sync::mpsc::Sender<RawEvent>,
    raw: osiris_sensor_api::FileEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::File(raw)).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(timestamp);
        h.state = SensorState::Healthy;
    } else {
        lock_health(health).events_dropped_total += 1;
    }
}
```

- [ ] **Step 13: Run the whole crate's tests**

Run: `cargo test -p osiris-sensors-fs`
Expected: PASS — 10 `audit_record` + 12 `assembler` + 3 `sensor` tests.

- [ ] **Step 14: Verify the privilege boundary**

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`. `osiris-sensors-fs` matches `check_forbidden osiris-server osiris-sensors …` and `check_forbidden osiris-api osiris-sensors …`, so this confirms neither the Server nor the API reaches the new sensor crate.

- [ ] **Step 15: Commit**

```bash
git add Cargo.toml crates/osiris-sensors/fs
git commit -m "feat(sensors): Filesystem sensor with real auditd SYSCALL+PATH correlation

Groups audit records by their shared msg=audit(<ts>:<serial>) header,
resolves relative names against the group's CWD record, derives operations
from nametype plus syscall class, and joins rename's DELETE+CREATE pair
into one FILE_RENAME carrying the source inode.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0192TqfN5oKsNzSDGYCo7aTt"
```

---

### Task 5: `osiris-generator` file scenario and Agent wiring

The generator is how this phase exercises the file path end-to-end without Linux hardware (§15's requirement that it push real events through the *real* pipeline, not a parallel simulation). `SyntheticSensor` currently only knows how to emit `ProcessExecRaw`, so it is generalized to `RawEvent` and given a second scenario.

**Files:**
- Modify: `generator/src/scenarios.rs`
- Modify: `generator/src/sensor.rs`
- Modify: `generator/src/lib.rs`
- Modify: `generator/src/main.rs`
- Modify: `crates/osiris-agent/src/config.rs`
- Modify: `crates/osiris-agent/src/agent.rs`
- Modify: `crates/osiris-agent/Cargo.toml`

**Interfaces:**
- Consumes: `osiris_sensor_api::{RawEvent, FileEventRaw, FileOperation, ProcessExecRaw, RawEventSource}` (Task 3); `osiris_schema::encode_device_id` (Task 1); `osiris_sensors_fs::FilesystemSensor` (Task 4).
- Produces:
  - `osiris_generator::exec_chain_scenario(base_ts_ns: u64) -> Vec<RawEvent>` — **return type changed** from `Vec<ProcessExecRaw>`.
  - `osiris_generator::web_shell_drop_scenario(base_ts_ns: u64) -> Vec<RawEvent>` — 7 events: sshd→bash→curl execs, then curl creates, writes and renames a file under `/var/www/html/`, then bash writes a benign file under `/home/user/`.
  - `osiris_generator::SyntheticSensor::new(scenario: Vec<RawEvent>)` — **parameter type changed**.
  - `osiris_generator::scenarios::{WEB_SHELL_INODE, WEB_SHELL_DEVICE_ID, WEB_SHELL_FINAL_PATH, WEB_SHELL_TEMP_PATH, BENIGN_NOTES_PATH}` — `pub const`s so Tasks 7 and 9 assert against the same literals the scenario emits instead of re-typing them.
  - `osiris_agent::AgentConfig` gains `fs_audit_log_path: Option<String>` and `synthetic_scenario: Option<String>` (both `#[serde(default)]`).

- [ ] **Step 1: Write the failing test for the file scenario**

Replace `generator/src/scenarios.rs`'s `mod tests` with:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::FileOperation;

    fn exec_events(scenario: &[RawEvent]) -> Vec<&ProcessExecRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::ProcessExec(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    fn file_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::FileEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::File(f) => Some(f),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn exec_chain_scenario_has_three_execs_with_the_correct_parent_chain() {
        let scenario = exec_chain_scenario(1000);
        let execs = exec_events(&scenario);
        assert_eq!(scenario.len(), 3);
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[0].pid, 100);
        assert_eq!(execs[1].ppid, execs[0].pid);
        assert_eq!(execs[2].ppid, execs[1].pid);
    }

    #[test]
    fn every_scenario_is_strictly_time_ordered() {
        for scenario in [exec_chain_scenario(1000), web_shell_drop_scenario(1000)] {
            for pair in scenario.windows(2) {
                assert!(
                    pair[0].timestamp_ns() < pair[1].timestamp_ns(),
                    "scenario events must be strictly increasing in time"
                );
            }
        }
    }

    /// The scenario mirrors ARCHITECTURE.md §26's sshd -> bash -> curl trace
    /// and extends it into the filesystem: curl stages a payload under a
    /// temp name, writes it, then renames it into place — the classic
    /// atomic web-shell drop, and the exact shape Task 7's detection rule
    /// is written against.
    #[test]
    fn web_shell_drop_scenario_has_the_full_exec_then_file_chain() {
        let scenario = web_shell_drop_scenario(1000);
        assert_eq!(scenario.len(), 7);

        let execs = exec_events(&scenario);
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[2].exe_path, "/usr/bin/curl");
        assert_eq!(execs[2].pid, 300);

        let files = file_events(&scenario);
        assert_eq!(files.len(), 4);

        assert_eq!(files[0].operation, FileOperation::Create);
        assert_eq!(files[0].path, WEB_SHELL_TEMP_PATH);
        assert_eq!(files[0].pid, 300);

        assert_eq!(files[1].operation, FileOperation::Write);
        assert_eq!(files[1].path, WEB_SHELL_TEMP_PATH);

        assert_eq!(files[2].operation, FileOperation::Rename);
        assert_eq!(files[2].path, WEB_SHELL_FINAL_PATH);
        assert_eq!(files[2].previous_path.as_deref(), Some(WEB_SHELL_TEMP_PATH));

        // The benign control: a shell writing to a user's home directory
        // must NOT match the web-root rule, which is what makes the
        // detection test in Task 7 meaningful rather than vacuous.
        assert_eq!(files[3].operation, FileOperation::Write);
        assert_eq!(files[3].path, BENIGN_NOTES_PATH);
        assert_eq!(files[3].pid, 200);
    }

    /// The staged file keeps one inode across create, write and rename —
    /// this is precisely what lets Task 8's File Story follow the file from
    /// its temp name to its final name.
    #[test]
    fn the_staged_file_keeps_one_identity_across_create_write_and_rename() {
        let scenario = web_shell_drop_scenario(1000);
        let files = file_events(&scenario);
        for file in files.iter().take(3) {
            assert_eq!(file.inode, Some(WEB_SHELL_INODE));
            assert_eq!(file.device_id, Some(WEB_SHELL_DEVICE_ID));
        }
        assert_ne!(files[3].inode, Some(WEB_SHELL_INODE));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p osiris-generator scenarios`
Expected: FAIL — `web_shell_drop_scenario`, the five constants, and `RawEvent::timestamp_ns` on a `Vec<ProcessExecRaw>` are all undefined/mismatched.

- [ ] **Step 3: Implement the scenarios**

Replace everything above `mod tests` in `generator/src/scenarios.rs` with:
```rust
use osiris_schema::encode_device_id;
use osiris_sensor_api::{FileEventRaw, FileOperation, ProcessExecRaw, RawEvent, RawEventSource};

/// The identity the staged payload keeps across create -> write -> rename.
pub const WEB_SHELL_INODE: u64 = 200_001;
/// Major 8, minor 1 — the usual root block device, as `dev=08:01` in audit.
pub const WEB_SHELL_DEVICE_ID: u64 = encode_device_id(8, 1);
pub const WEB_SHELL_TEMP_PATH: &str = "/var/www/html/.shell.php.tmp";
pub const WEB_SHELL_FINAL_PATH: &str = "/var/www/html/shell.php";
/// The benign control file: same actor family, ordinary destination.
pub const BENIGN_NOTES_PATH: &str = "/home/user/notes.txt";
const BENIGN_NOTES_INODE: u64 = 300_777;

/// A minimal process/exec scenario mirroring ARCHITECTURE.md §26's worked
/// trace (sshd -> bash -> curl). Timestamps are relative nanoseconds
/// starting at `base_ts_ns`, spaced 1ms apart.
pub fn exec_chain_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 1_000_000),
        exec(300, 200, "/usr/bin/curl", "curl", base_ts_ns + 2_000_000),
    ]
}

/// §26's exec chain continued into the filesystem: curl stages a payload
/// under a dot-prefixed temp name, writes it, then renames it into place
/// (the atomic-drop pattern real tooling uses), followed by a benign write
/// to a home directory that must NOT trigger the web-root detection rule.
///
/// Every file event carries a real inode/device pair, and the staged file
/// keeps ONE inode across all three of its events — so this scenario
/// exercises identity-based File Story assembly, not just path matching.
pub fn web_shell_drop_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 1_000_000),
        exec(300, 200, "/usr/bin/curl", "curl", base_ts_ns + 2_000_000),
        file_event(
            FileOperation::Create,
            WEB_SHELL_TEMP_PATH,
            None,
            WEB_SHELL_INODE,
            300,
            200,
            "/usr/bin/curl",
            "curl",
            base_ts_ns + 3_000_000,
        ),
        file_event(
            FileOperation::Write,
            WEB_SHELL_TEMP_PATH,
            None,
            WEB_SHELL_INODE,
            300,
            200,
            "/usr/bin/curl",
            "curl",
            base_ts_ns + 4_000_000,
        ),
        file_event(
            FileOperation::Rename,
            WEB_SHELL_FINAL_PATH,
            Some(WEB_SHELL_TEMP_PATH),
            WEB_SHELL_INODE,
            300,
            200,
            "/usr/bin/curl",
            "curl",
            base_ts_ns + 5_000_000,
        ),
        file_event(
            FileOperation::Write,
            BENIGN_NOTES_PATH,
            None,
            BENIGN_NOTES_INODE,
            200,
            100,
            "/bin/bash",
            "bash",
            base_ts_ns + 6_000_000,
        ),
    ]
}

fn exec(pid: u32, ppid: u32, exe_path: &str, comm: &str, timestamp_ns: u64) -> RawEvent {
    RawEvent::ProcessExec(ProcessExecRaw {
        pid,
        ppid,
        uid: 1000,
        exe_path: exe_path.to_string(),
        comm: comm.to_string(),
        timestamp_ns,
        start_time_mono: timestamp_ns,
        source: RawEventSource::Synthetic,
    })
}

#[allow(clippy::too_many_arguments)]
fn file_event(
    operation: FileOperation,
    path: &str,
    previous_path: Option<&str>,
    inode: u64,
    pid: u32,
    ppid: u32,
    exe_path: &str,
    comm: &str,
    timestamp_ns: u64,
) -> RawEvent {
    RawEvent::File(FileEventRaw {
        operation,
        path: path.to_string(),
        previous_path: previous_path.map(|p| p.to_string()),
        inode: Some(inode),
        device_id: Some(WEB_SHELL_DEVICE_ID),
        mode: Some(0o100644),
        owner_uid: Some(33),
        owner_gid: Some(33),
        pid,
        ppid,
        uid: 1000,
        exe_path: exe_path.to_string(),
        comm: comm.to_string(),
        timestamp_ns,
        audit_serial: None,
        source: RawEventSource::Synthetic,
    })
}
```

Add `osiris-schema` to `generator/Cargo.toml`'s `[dependencies]` if it isn't already listed (it is), and note the test module needs `use osiris_sensor_api::ProcessExecRaw;` in scope — it comes from the `use super::*;` re-export of the file's own imports.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p osiris-generator scenarios`
Expected: FAIL to *compile* the sensor module, because `SyntheticSensor::new` still takes `Vec<ProcessExecRaw>`. That is Step 5. The `scenarios` tests themselves are complete.

- [ ] **Step 5: Generalize `SyntheticSensor` to any `RawEvent`**

In `generator/src/sensor.rs`:

Change the import line from:
```rust
use osiris_sensor_api::{
    ProcessExecRaw, RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
```
to:
```rust
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
```

Change the struct field and constructor:
```rust
pub struct SyntheticSensor {
    scenario: Vec<RawEvent>,
    ...
}

impl SyntheticSensor {
    pub fn new(scenario: Vec<RawEvent>) -> Self {
```

And in the spawned loop, replace:
```rust
                let ts = raw.timestamp_ns;
                if output.send(RawEvent::ProcessExec(raw)).await.is_ok() {
```
with:
```rust
                let ts = raw.timestamp_ns();
                if output.send(raw).await.is_ok() {
```

Update the type doc comment: replace "Emits a fixed, deterministic scenario of ProcessExecRaw events" with "Emits a fixed, deterministic scenario of `RawEvent`s (process and file alike)".

In its `mod tests`, `emits_every_event_in_the_scenario_in_order` already has the catch-all arm added in Task 3 Step 6 and still passes unchanged. Add one more test:
```rust
    #[tokio::test]
    async fn emits_file_events_from_a_mixed_scenario() {
        use crate::scenarios::{web_shell_drop_scenario, WEB_SHELL_TEMP_PATH};
        let mut sensor = SyntheticSensor::new(web_shell_drop_scenario(1000))
            .with_emit_interval(Duration::from_millis(1));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let mut file_paths = vec![];
        for _ in 0..7 {
            let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timed out")
                .expect("channel closed");
            if let RawEvent::File(f) = event {
                file_paths.push(f.path);
            }
        }
        assert_eq!(file_paths.len(), 4);
        assert_eq!(file_paths[0], WEB_SHELL_TEMP_PATH);

        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 7);
    }
```

- [ ] **Step 6: Update `lib.rs` and `main.rs` for the new shapes**

`generator/src/lib.rs`:
```rust
pub mod scenarios;
pub mod sensor;

pub use scenarios::{
    exec_chain_scenario, web_shell_drop_scenario, BENIGN_NOTES_PATH, WEB_SHELL_DEVICE_ID,
    WEB_SHELL_FINAL_PATH, WEB_SHELL_INODE, WEB_SHELL_TEMP_PATH,
};
pub use sensor::SyntheticSensor;
```

In `generator/src/main.rs`, replace the `use osiris_generator::exec_chain_scenario;` line with:
```rust
use osiris_generator::{exec_chain_scenario, web_shell_drop_scenario};
```
replace `use osiris_sensor_api::RawEvent;` with nothing (the scenarios already yield `RawEvent`s), and replace the emit loop:
```rust
    for raw in exec_chain_scenario(base_ts_ns) {
        let result = pipeline.process(RawEvent::ProcessExec(raw));
```
with a scenario selected by an optional argv argument, so the binary can produce either dataset:
```rust
    // `osiris-generator [exec_chain|web_shell_drop]`, defaulting to the
    // Phase 1 exec chain so existing usage is unchanged.
    let scenario_name = std::env::args().nth(1).unwrap_or_else(|| "exec_chain".to_string());
    let scenario = match scenario_name.as_str() {
        "web_shell_drop" => web_shell_drop_scenario(base_ts_ns),
        "exec_chain" => exec_chain_scenario(base_ts_ns),
        other => {
            eprintln!("unknown scenario '{other}'; expected exec_chain or web_shell_drop");
            std::process::exit(1);
        }
    };

    for raw in scenario {
        let result = pipeline.process(raw);
```
(the `match serde_json::to_string(&result.event)` block that follows is unchanged).

- [ ] **Step 7: Run the generator's tests**

Run: `cargo test -p osiris-generator`
Expected: PASS — 4 `scenarios` tests and 3 `sensor` tests.

- [ ] **Step 8: Write the failing test for Agent wiring**

Append to `crates/osiris-agent/src/agent.rs`'s `mod tests`:
```rust
    fn base_config(dir: &tempfile::TempDir) -> AgentConfig {
        AgentConfig {
            audit_log_path: None,
            fs_audit_log_path: None,
            enable_synthetic: false,
            synthetic_scenario: None,
            spool_path: dir
                .path()
                .join("spool.ndjson")
                .to_string_lossy()
                .to_string(),
            status_addr: "127.0.0.1:0".to_string(),
        }
    }

    #[tokio::test]
    async fn starts_the_filesystem_sensor_when_an_fs_audit_log_exists() {
        let dir = tempfile::tempdir().unwrap();
        let fs_log = dir.path().join("fs-audit.log");
        std::fs::write(&fs_log, "").unwrap();
        let mut config = base_config(&dir);
        config.fs_audit_log_path = Some(fs_log.to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "filesystem");
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn skips_the_filesystem_sensor_with_a_visible_reason_when_its_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.fs_audit_log_path =
            Some(dir.path().join("missing.log").to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 0);
        assert_eq!(status.skipped_sensors.len(), 1);
        assert_eq!(status.skipped_sensors[0].name, "filesystem");
        assert!(status.skipped_sensors[0]
            .reason
            .contains("audit log not found"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn the_web_shell_drop_scenario_reaches_the_spool_file_with_file_events() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("web_shell_drop".to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 7);
        assert!(contents.contains("\"PROCESS_EXEC\""));
        assert!(contents.contains("\"FILE_CREATE\""));
        assert!(contents.contains("\"FILE_WRITE\""));
        assert!(contents.contains("\"FILE_RENAME\""));
        assert!(contents.contains("/var/www/html/shell.php"));
    }

    #[tokio::test]
    async fn an_unknown_scenario_name_falls_back_to_the_exec_chain_rather_than_starting_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("nonsense".to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 3);
    }
```

Also rewrite the three **existing** agent tests to build their config through `base_config(&dir)` and then set only the fields they care about, so the two new `AgentConfig` fields don't have to be repeated at every literal.

- [ ] **Step 9: Run to verify it fails**

Run: `cargo test -p osiris-agent`
Expected: FAIL — `AgentConfig` has no fields `fs_audit_log_path` or `synthetic_scenario`.

- [ ] **Step 10: Implement the config and supervisor changes**

In `crates/osiris-agent/src/config.rs`, add two fields to `AgentConfig` (after `audit_log_path`):
```rust
    /// Path to a Linux auditd-style log file for the Filesystem sensor's
    /// audit backend (a separate file from `audit_log_path` so an operator
    /// can point the two sensors at different, rule-scoped logs; pointing
    /// both at the same file is also valid — each sensor ignores the
    /// records the other consumes). Skipped, never silently, if absent.
    #[serde(default)]
    pub fs_audit_log_path: Option<String>,
```
and (after `enable_synthetic`):
```rust
    /// Which canned scenario the synthetic sensor emits: `"exec_chain"`
    /// (default, Phase 1's sshd->bash->curl) or `"web_shell_drop"` (that
    /// chain continued into the filesystem). Ignored unless
    /// `enable_synthetic` is true.
    #[serde(default)]
    pub synthetic_scenario: Option<String>,
```

Add a config test proving the defaults hold:
```rust
    #[test]
    fn the_new_phase_2_fields_default_to_none_so_phase_1_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: true\nspool_path: /tmp/spool.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.fs_audit_log_path.is_none());
        assert!(config.synthetic_scenario.is_none());
    }
```

In `crates/osiris-agent/Cargo.toml`, add to `[dependencies]`:
```toml
osiris-sensors-fs = { path = "../osiris-sensors/fs" }
```

In `crates/osiris-agent/src/agent.rs`, change the imports:
```rust
use osiris_generator::{exec_chain_scenario, web_shell_drop_scenario, SyntheticSensor};
use osiris_sensors_fs::FilesystemSensor;
use osiris_sensors_process::ProcessExecSensor;
```
and replace the candidate-sensor construction block with:
```rust
        let mut candidate_sensors: Vec<Box<dyn Sensor>> = vec![];
        if let Some(path) = &config.audit_log_path {
            candidate_sensors.push(Box::new(ProcessExecSensor::new(path.clone())));
        }
        if let Some(path) = &config.fs_audit_log_path {
            candidate_sensors.push(Box::new(FilesystemSensor::new(path.clone())));
        }
        if config.enable_synthetic {
            let base_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let scenario = match config.synthetic_scenario.as_deref() {
                Some("web_shell_drop") => web_shell_drop_scenario(base_ts),
                Some("exec_chain") | None => exec_chain_scenario(base_ts),
                Some(other) => {
                    tracing::warn!(
                        scenario = other,
                        "unknown synthetic_scenario; falling back to exec_chain"
                    );
                    exec_chain_scenario(base_ts)
                }
            };
            candidate_sensors.push(Box::new(SyntheticSensor::new(scenario)));
        }
```
(Note the `.unwrap()` on `duration_since` becomes `.unwrap_or_default()` — this crate's no-unwrap discipline applies to the library path, and a pre-epoch clock should degrade, not abort.)

Update the `Agent` type's doc comment's Phase reference: replace "Phase 1 scope: starts every registered sensor" with "Phase 1/2 scope: starts every registered sensor".

- [ ] **Step 11: Run to verify it passes**

Run: `cargo test -p osiris-agent`
Expected: PASS — 3 updated existing agent tests, 4 new agent tests, and 3 config tests.

- [ ] **Step 12: Verify the privilege boundary still holds**

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`. The Agent now links a second sensor crate but still links no storage/detection crate — `check_forbidden osiris-agent osiris-storage osiris-detect osiris-correlate osiris-risk` must pass.

- [ ] **Step 13: Commit**

```bash
git add generator crates/osiris-agent
git commit -m "feat(generator,agent): web-shell-drop file scenario and Filesystem sensor wiring

SyntheticSensor now emits any RawEvent, so the generator can push a mixed
exec+file scenario through the real pipeline. The Agent registers the
Filesystem sensor from a new fs_audit_log_path config field, skipping it
with a health-visible reason when the log is absent.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0192TqfN5oKsNzSDGYCo7aTt"
```

---

### Task 6: `osiris-storage` + `osiris-storage-sqlite` — file filters, alert persistence, and schema migration

**Files:**
- Modify: `crates/osiris-storage/Cargo.toml` (add `uuid`)
- Modify: `crates/osiris-storage/src/plan.rs`
- Modify: `crates/osiris-storage/src/storage.rs`
- Modify: `crates/osiris-storage/src/lib.rs`
- Modify: `crates/osiris-storage-sqlite/src/sqlite_storage.rs`

**Interfaces:**
- Consumes: `osiris_schema::{Alert, FileIdentity, Severity}` (Task 1).
- Produces:
  - `osiris_storage::QueryPlan` gains `file_path: Option<String>` and `file_identity: Option<FileIdentity>`. All other fields and `QueryPlan::new()`'s `limit: 100` default are unchanged.
  - `osiris_storage::AlertQueryPlan { rule_id: Option<String>, evidence_event_ids: Vec<Uuid>, since: Option<u64>, until: Option<u64>, limit: usize }` with `AlertQueryPlan::new() -> Self` (limit 100).
  - `osiris_storage::Storage` gains `fn write_alerts(&self, alerts: &[Alert]) -> Result<WriteReport, StorageError>` and `fn query_alerts(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError>`.
  - `osiris_storage_sqlite::SqliteStorage` implements both, and `SqliteStorage::open` migrates a Phase 1 database in place.
  - Task 7's engine produces the `Alert`s; Task 8's ingest loop calls `write_alerts` and its API calls `query_alerts`.

- [ ] **Step 1: Write the failing test for the widened plans**

Replace `crates/osiris-storage/src/plan.rs`'s `mod tests` with:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_query_plan_defaults_to_limit_100_and_no_filters() {
        let plan = QueryPlan::new();
        assert_eq!(plan.limit, 100);
        assert!(plan.event_type.is_none());
        assert!(plan.file_path.is_none());
        assert!(plan.file_identity.is_none());
    }

    #[test]
    fn new_alert_query_plan_defaults_to_limit_100_and_no_filters() {
        let plan = AlertQueryPlan::new();
        assert_eq!(plan.limit, 100);
        assert!(plan.rule_id.is_none());
        assert!(plan.evidence_event_ids.is_empty());
        assert!(plan.since.is_none());
        assert!(plan.until.is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p osiris-storage`
Expected: FAIL — `QueryPlan` has no `file_path`/`file_identity` fields; `AlertQueryPlan` is undefined.

- [ ] **Step 3: Widen the plans and the `Storage` trait**

Add to `crates/osiris-storage/Cargo.toml`'s `[dependencies]`:
```toml
uuid = { workspace = true }
```

In `crates/osiris-storage/src/plan.rs`, replace the `use` line and `QueryPlan` with:
```rust
use osiris_schema::{EventType, FileIdentity, ProcessKey};
use uuid::Uuid;

/// This phase's minimal query surface (plan Global Constraints #11) — what
/// the API needs and no more: event_type/time-range filtering, a
/// process_key lookup, and the two file lookups the File Story composes.
/// The full OQL planner is Phase 7 scope (ARCHITECTURE.md §12.3).
#[derive(Debug, Clone, Default)]
pub struct QueryPlan {
    pub event_type: Option<EventType>,
    pub process_key: Option<ProcessKey>,
    /// Exact-match on `file.path`. The lookup key an analyst types.
    pub file_path: Option<String>,
    /// Exact-match on `(file.inode, file.device_id)`. The join key that
    /// follows a file across a rename (§9.4, plan Global Constraints #6).
    pub file_identity: Option<FileIdentity>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: usize,
}
```
(the `impl QueryPlan { pub fn new() ... }` block below it is unchanged — `..Default::default()` picks up the new fields automatically).

Add, after `QueryPlan`'s impl:
```rust
/// The alert-query surface. `evidence_event_ids` is what makes a File
/// Story able to attach "every Alert whose evidence references one of these
/// events" (ARCHITECTURE.md §12.1) in one query rather than one per event.
#[derive(Debug, Clone, Default)]
pub struct AlertQueryPlan {
    pub rule_id: Option<String>,
    pub evidence_event_ids: Vec<Uuid>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: usize,
}

impl AlertQueryPlan {
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }
}
```

In `crates/osiris-storage/src/storage.rs`, add `Alert` to the schema import and two methods to the trait:
```rust
use osiris_schema::{Alert, CanonicalEvent};
```
```rust
    /// Persists detection results. Alerts are append-only apart from their
    /// `status` field (ARCHITECTURE.md §12.7); a re-written `alert_id` is
    /// ignored and counted as failed, matching `batch_write`'s semantics.
    fn write_alerts(&self, alerts: &[Alert]) -> Result<WriteReport, StorageError>;
    fn query_alerts(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError>;
```
and add `AlertQueryPlan` to that file's `use crate::plan::{...}` list.

In `crates/osiris-storage/src/lib.rs`, extend the re-export:
```rust
pub use plan::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RetentionPolicy, RetentionReport, WriteReport,
};
```

- [ ] **Step 4: Run to verify the trait crate passes**

Run: `cargo test -p osiris-storage`
Expected: PASS — 2 tests. `osiris-storage-sqlite` will not compile yet (it doesn't implement the two new methods); that is Step 5.

- [ ] **Step 5: Write the failing tests for the SQLite backend**

Append to `crates/osiris-storage-sqlite/src/sqlite_storage.rs`'s `mod tests`:
```rust
    fn file_event(path: &str, inode: u64, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(300, timestamp);
        event.event_type = EventType::FileWrite;
        event.category = Category::File;
        event.file = Some(osiris_schema::FileRef {
            path: path.to_string(),
            previous_path: None,
            inode: Some(inode),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        event
    }

    fn sample_alert(evidence: Vec<Uuid>, rule_id: &str, timestamp: u64) -> osiris_schema::Alert {
        osiris_schema::Alert::new(
            rule_id,
            1,
            "deadbeef",
            osiris_schema::Severity::High,
            timestamp,
            Uuid::new_v4(),
            vec!["The file was written inside /var/www/".to_string()],
            evidence,
        )
        .expect("valid alert")
    }

    #[test]
    fn query_filters_by_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .batch_write(&[
                file_event("/var/www/html/shell.php", 200001, 1000),
                file_event("/home/user/notes.txt", 300777, 2000),
            ])
            .unwrap();

        let plan = QueryPlan {
            file_path: Some("/var/www/html/shell.php".to_string()),
            ..QueryPlan::new()
        };
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].file.as_ref().unwrap().path,
            "/var/www/html/shell.php"
        );
    }

    /// The point of identity-based lookup: one inode, two names. A query by
    /// identity must return both events, which is how a File Story follows
    /// a file across a rename.
    #[test]
    fn query_by_file_identity_spans_both_names_of_a_renamed_file() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .batch_write(&[
                file_event("/var/www/html/.shell.php.tmp", 200001, 1000),
                file_event("/var/www/html/shell.php", 200001, 2000),
                file_event("/home/user/notes.txt", 300777, 3000),
            ])
            .unwrap();

        let plan = QueryPlan {
            file_identity: Some(osiris_schema::FileIdentity::new(
                200001,
                osiris_schema::encode_device_id(8, 1),
            )),
            ..QueryPlan::new()
        };
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].timestamp, 1000, "results stay time-ordered");
        assert_eq!(results[1].timestamp, 2000);
    }

    #[test]
    fn a_process_event_with_no_file_ref_never_matches_a_file_filter() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage.write(&sample_event(100, 1000)).unwrap();
        let plan = QueryPlan {
            file_path: Some("/var/www/html/shell.php".to_string()),
            ..QueryPlan::new()
        };
        assert!(storage.query(&plan).unwrap().is_empty());
    }

    #[test]
    fn write_and_query_alerts_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let event_id = Uuid::now_v7();
        let alert = sample_alert(vec![event_id], "shell_wrote_file_to_web_root", 5000);

        let report = storage.write_alerts(std::slice::from_ref(&alert)).unwrap();
        assert_eq!(report.written_count, 1);

        let results = storage.query_alerts(&AlertQueryPlan::new()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].alert_id(), alert.alert_id());
        assert_eq!(results[0].rule_id(), "shell_wrote_file_to_web_root");
        assert_eq!(results[0].reasons().len(), 1);
        assert_eq!(results[0].evidence(), &[event_id]);
    }

    #[test]
    fn query_alerts_filters_by_rule_id_and_time_range() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        storage
            .write_alerts(&[
                sample_alert(vec![Uuid::now_v7()], "rule_a", 1000),
                sample_alert(vec![Uuid::now_v7()], "rule_b", 5000),
                sample_alert(vec![Uuid::now_v7()], "rule_a", 9000),
            ])
            .unwrap();

        let by_rule = storage
            .query_alerts(&AlertQueryPlan {
                rule_id: Some("rule_a".to_string()),
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_rule.len(), 2);

        let by_time = storage
            .query_alerts(&AlertQueryPlan {
                since: Some(2000),
                until: Some(6000),
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(by_time.len(), 1);
        assert_eq!(by_time[0].rule_id(), "rule_b");
    }

    /// The File Story's "alerts citing these events" join, in one query.
    #[test]
    fn query_alerts_filters_by_the_events_they_cite() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let wanted = Uuid::now_v7();
        let other = Uuid::now_v7();
        storage
            .write_alerts(&[
                sample_alert(vec![wanted], "rule_a", 1000),
                sample_alert(vec![other], "rule_b", 2000),
            ])
            .unwrap();

        let results = storage
            .query_alerts(&AlertQueryPlan {
                evidence_event_ids: vec![wanted],
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id(), "rule_a");
    }

    /// One alert citing two events must be returned once, not twice, when
    /// both of its events are in the filter set.
    #[test]
    fn an_alert_citing_several_matching_events_is_returned_once() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        storage
            .write_alerts(&[sample_alert(vec![a, b], "rule_a", 1000)])
            .unwrap();

        let results = storage
            .query_alerts(&AlertQueryPlan {
                evidence_event_ids: vec![a, b],
                ..AlertQueryPlan::new()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn rewriting_an_alert_id_is_ignored_and_reported_as_failed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let alert = sample_alert(vec![Uuid::now_v7()], "rule_a", 1000);
        storage.write_alerts(std::slice::from_ref(&alert)).unwrap();

        let report = storage.write_alerts(std::slice::from_ref(&alert)).unwrap();
        assert_eq!(report.written_count, 0);
        assert_eq!(report.failed_count, 1);
        assert_eq!(storage.query_alerts(&AlertQueryPlan::new()).unwrap().len(), 1);
    }

    /// A database created by Phase 1 has an `events` table with no file
    /// columns and no `alerts` table at all. Opening it with this build
    /// must migrate it in place — not fail, and not silently ignore the
    /// pre-existing rows.
    #[test]
    fn opens_and_migrates_a_phase_1_database_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        // Recreate Phase 1's exact schema and insert one row through it.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                    event_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    process_key TEXT,
                    parent_process_key TEXT,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            let legacy = sample_event(100, 1000);
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, raw_json)
                 VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
                rusqlite::params![
                    legacy.event_id.to_string(),
                    legacy.host_id.to_string(),
                    legacy.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&legacy).unwrap(),
                ],
            )
            .unwrap();
        }

        let storage = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(
            storage.query(&QueryPlan::new()).unwrap().len(),
            1,
            "the pre-existing row must survive migration"
        );
        // The new columns and the new tables now exist and work.
        storage
            .write(&file_event("/var/www/html/shell.php", 200001, 2000))
            .unwrap();
        let plan = QueryPlan {
            file_path: Some("/var/www/html/shell.php".to_string()),
            ..QueryPlan::new()
        };
        assert_eq!(storage.query(&plan).unwrap().len(), 1);
        storage
            .write_alerts(&[sample_alert(vec![Uuid::now_v7()], "rule_a", 3000)])
            .unwrap();
        assert_eq!(storage.query_alerts(&AlertQueryPlan::new()).unwrap().len(), 1);
    }
```

Add to that test module's imports: `Category` and `EventType` are already imported; add `AlertQueryPlan` to the `use osiris_storage::{...}` list at the top of the file (see Step 6).

- [ ] **Step 6: Run to verify it fails**

Run: `cargo test -p osiris-storage-sqlite`
Expected: FAIL — `SqliteStorage` does not implement `write_alerts`/`query_alerts`, and `QueryPlan` has no file fields being used by `query`.

- [ ] **Step 7: Implement the SQLite changes**

In `crates/osiris-storage-sqlite/src/sqlite_storage.rs`:

Change the imports at the top:
```rust
use osiris_schema::{Alert, CanonicalEvent, FileIdentity};
use osiris_storage::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RetentionPolicy, RetentionReport, Storage,
    StorageError, StorageHealth, WriteReport,
};
```

Replace `SqliteStorage::open` with:
```rust
impl SqliteStorage {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StorageError> {
        let conn = Connection::open(path).map_err(|e| StorageError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                process_key TEXT,
                parent_process_key TEXT,
                file_path TEXT,
                file_inode INTEGER,
                file_device_id INTEGER,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_host_timestamp ON events(host_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_process_key ON events(process_key);

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                rule_version INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                host_id TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_timestamp ON alerts(rule_id, timestamp);

            -- One row per (alert, cited event). A join table rather than a
            -- JSON array column so the File Story's 'alerts citing these
            -- events' lookup is an indexed join, not a scan-and-parse.
            CREATE TABLE IF NOT EXISTS alert_evidence (
                alert_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (alert_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_alert_evidence_event ON alert_evidence(event_id);",
        )
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        // Migrate a database created by Phase 1, whose `events` table
        // predates the three file columns. `CREATE TABLE IF NOT EXISTS`
        // above is a no-op on such a database, so the columns must be added
        // explicitly. Adding a nullable column to SQLite is an O(1)
        // metadata-only operation, and existing rows read back as NULL —
        // correct, since no Phase 1 event ever populated `file`.
        for (column, ddl) in [
            ("file_path", "ALTER TABLE events ADD COLUMN file_path TEXT"),
            ("file_inode", "ALTER TABLE events ADD COLUMN file_inode INTEGER"),
            (
                "file_device_id",
                "ALTER TABLE events ADD COLUMN file_device_id INTEGER",
            ),
        ] {
            if !column_exists(&conn, "events", column)? {
                conn.execute(ddl, [])
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_events_file_path ON events(file_path);
             CREATE INDEX IF NOT EXISTS idx_events_file_identity ON events(file_device_id, file_inode);",
        )
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, StorageError> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| StorageError::Backend(e.to_string()))?;
    let mut rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| StorageError::Backend(e.to_string()))?;
    while let Some(name) = rows.next() {
        if name.map_err(|e| StorageError::Backend(e.to_string()))? == column {
            return Ok(true);
        }
    }
    Ok(false)
}
```

In `batch_write`, add the three file bindings. Immediately after the existing `let event_type = ...;` line, add:
```rust
            let file_path = event.file.as_ref().map(|f| f.path.clone());
            let file_identity = event.file.as_ref().and_then(FileIdentity::from_file_ref);
            let file_inode = file_identity.map(|i| i.inode as i64);
            let file_device_id = file_identity.map(|i| i.device_id as i64);
```
and replace the `INSERT` statement and its `params!` with:
```rust
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, file_path, file_inode, file_device_id, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        event.event_id.to_string(),
                        event.host_id.to_string(),
                        event.timestamp as i64,
                        event_type,
                        process_key,
                        parent_process_key,
                        file_path,
                        file_inode,
                        file_device_id,
                        raw_json,
                    ],
                )
                .map_err(|e| StorageError::Backend(e.to_string()))?;
```

In `query`, add the two new filters immediately after the existing `process_key` block:
```rust
        if let Some(file_path) = &plan.file_path {
            sql.push_str(" AND file_path = ?");
            sql_params.push(Box::new(file_path.clone()));
        }
        if let Some(identity) = &plan.file_identity {
            sql.push_str(" AND file_inode = ? AND file_device_id = ?");
            sql_params.push(Box::new(identity.inode as i64));
            sql_params.push(Box::new(identity.device_id as i64));
        }
```

Add the two new trait methods to `impl Storage for SqliteStorage` (place them after `query`):
```rust
    fn write_alerts(&self, alerts: &[Alert]) -> Result<WriteReport, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut report = WriteReport::default();
        for alert in alerts {
            let raw_json =
                serde_json::to_string(alert).map_err(|e| StorageError::Serialize(e.to_string()))?;
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO alerts (alert_id, rule_id, rule_version, timestamp, host_id, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        alert.alert_id().to_string(),
                        alert.rule_id(),
                        alert.rule_version() as i64,
                        alert.timestamp() as i64,
                        alert.host_id().to_string(),
                        raw_json,
                    ],
                )
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            if changed == 1 {
                report.written_count += 1;
                for event_id in alert.evidence() {
                    tx.execute(
                        "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id) VALUES (?1, ?2)",
                        params![alert.alert_id().to_string(), event_id.to_string()],
                    )
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                }
            } else {
                report.failed_count += 1;
            }
        }
        tx.commit()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(report)
    }

    fn query_alerts(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        // DISTINCT because an alert citing several of the requested events
        // must come back once, not once per citation.
        let mut sql = "SELECT DISTINCT a.raw_json FROM alerts a".to_string();
        let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if !plan.evidence_event_ids.is_empty() {
            let placeholders = vec!["?"; plan.evidence_event_ids.len()].join(",");
            sql.push_str(&format!(
                " JOIN alert_evidence e ON e.alert_id = a.alert_id WHERE e.event_id IN ({placeholders})"
            ));
            for event_id in &plan.evidence_event_ids {
                sql_params.push(Box::new(event_id.to_string()));
            }
        } else {
            sql.push_str(" WHERE 1=1");
        }
        if let Some(rule_id) = &plan.rule_id {
            sql.push_str(" AND a.rule_id = ?");
            sql_params.push(Box::new(rule_id.clone()));
        }
        if let Some(since) = plan.since {
            sql.push_str(" AND a.timestamp >= ?");
            sql_params.push(Box::new(since as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND a.timestamp <= ?");
            sql_params.push(Box::new(until as i64));
        }
        sql.push_str(" ORDER BY a.timestamp ASC LIMIT ?");
        let limit = if plan.limit == 0 { 100 } else { plan.limit };
        sql_params.push(Box::new(limit as i64));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let mut alerts = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| StorageError::Backend(e.to_string()))?;
            let alert: Alert = serde_json::from_str(&raw_json)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            alerts.push(alert);
        }
        Ok(alerts)
    }
```

Also update `SqliteStorage`'s doc comment: replace "proportionate to Phase 1's single event type" with "proportionate to this phase's five event types, with three indexed file columns added for the File Story's two lookups plus an `alerts` table and its `alert_evidence` join table".

- [ ] **Step 8: Run to verify it passes**

Run: `cargo test -p osiris-storage -p osiris-storage-sqlite`
Expected: PASS — `osiris-storage`'s 2 tests plus `osiris-storage-sqlite`'s 6 pre-existing tests and 9 new ones.

- [ ] **Step 9: Confirm no other `Storage` implementor broke**

Run: `cargo build --workspace --all-targets`
Expected: succeeds. `SqliteStorage` is the only implementor of `Storage` in the workspace, so adding trait methods breaks nothing else; if a test module anywhere defines a stub implementor, add the two methods there too.

- [ ] **Step 10: Commit**

```bash
git add crates/osiris-storage crates/osiris-storage-sqlite
git commit -m "feat(storage): file-path and file-identity query filters, alert persistence

Adds three indexed file columns to the events table (with an in-place
migration for Phase 1 databases), an alerts table plus an alert_evidence
join table, and QueryPlan/AlertQueryPlan filters covering exactly what the
File Story and alerts endpoints need.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0192TqfN5oKsNzSDGYCo7aTt"
```

---

### Task 7: `osiris-detect` — single-event rule engine and the first file-event rule

Scope reminder (plan Global Constraints #10): single-event, stateless matching only. No `sequence`, no `window`, no per-entity state table, no hot-reload — those are Phase 6. What *is* real here is §11.2's structural explanation requirement and §11.1's per-rule content hash, both carried into every `Alert`.

**Files:**
- Create: `crates/osiris-detect/Cargo.toml`
- Create: `crates/osiris-detect/src/lib.rs`
- Create: `crates/osiris-detect/src/rule.rs`
- Create: `crates/osiris-detect/src/eval.rs`
- Create: `crates/osiris-detect/src/engine.rs`
- Create: `config/rules/shell_wrote_file_to_web_root.yaml`
- Modify: `tools/check-dep-graph.sh` (one added check)

**Interfaces:**
- Consumes: `osiris_schema::{Alert, AlertError, CanonicalEvent, Severity}` (Task 1).
- Produces:
  - `osiris_detect::{Operator, Condition, Rule, RuleError}` with `Rule::from_yaml_str(yaml: &str, origin: &str) -> Result<Rule, RuleError>` and fields `id: String`, `version: u32`, `severity: Severity`, `match_conditions: Vec<Condition>`, `content_hash: String`.
  - `osiris_detect::eval::{field_value, matches}` with `field_value<'a>(event_json: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value>` and `matches(op: Operator, actual: &serde_json::Value, expected: &serde_json::Value) -> bool`.
  - `osiris_detect::DetectionEngine` with `DetectionEngine::new(rules: Vec<Rule>) -> Self`, `DetectionEngine::load_from_dir(dir: &Path) -> Result<Self, RuleError>`, `fn rule_count(&self) -> usize`, `fn evaluate(&self, event: &CanonicalEvent) -> Vec<Alert>`, `fn evaluate_batch(&self, events: &[CanonicalEvent]) -> Vec<Alert>`.
  - The rule file `config/rules/shell_wrote_file_to_web_root.yaml`, which Task 8's server config points at and Task 9's end-to-end test loads.

- [ ] **Step 1: Create the crate manifest and module skeleton**

`crates/osiris-detect/Cargo.toml`:
```toml
[package]
name = "osiris-detect"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
osiris-schema = { path = "../osiris-schema" }

[dev-dependencies]
tempfile = { workspace = true }
uuid = { workspace = true }
```

`crates/osiris-detect/src/lib.rs`:
```rust
pub mod engine;
pub mod eval;
pub mod rule;

pub use engine::DetectionEngine;
pub use eval::{field_value, matches};
pub use rule::{Condition, Operator, Rule, RuleError};
```

`osiris-detect` depends only on `osiris-schema`, so it stays below the Server in §2.1's layering and cannot reach a sensor or storage crate.

- [ ] **Step 2: Write the failing test for rule parsing**

Create `crates/osiris-detect/src/rule.rs` containing **only** the test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RULE: &str = r#"
id: shell_wrote_file_to_web_root
version: 1
severity: HIGH
match:
  - field: event_type
    op: in
    value: ["FILE_CREATE", "FILE_WRITE"]
    reason: "A file was created or written on disk"
  - field: file.path
    op: starts_with
    value: "/var/www/"
    reason: "The file was written inside the web-served directory /var/www/"
"#;

    #[test]
    fn parses_a_valid_rule() {
        let rule = Rule::from_yaml_str(VALID_RULE, "test.yaml").expect("must parse");
        assert_eq!(rule.id, "shell_wrote_file_to_web_root");
        assert_eq!(rule.version, 1);
        assert_eq!(rule.severity, osiris_schema::Severity::High);
        assert_eq!(rule.match_conditions.len(), 2);
        assert_eq!(rule.match_conditions[0].op, Operator::In);
        assert_eq!(rule.match_conditions[1].op, Operator::StartsWith);
        assert_eq!(rule.match_conditions[1].field, "file.path");
    }

    /// §11.1 requires an alert to cite the exact rule version that fired,
    /// which means hashing the rule's own text — a version number alone
    /// cannot distinguish an edited rule from its predecessor.
    #[test]
    fn content_hash_is_a_stable_sha256_of_the_rule_text() {
        let a = Rule::from_yaml_str(VALID_RULE, "test.yaml").unwrap();
        let b = Rule::from_yaml_str(VALID_RULE, "other-name.yaml").unwrap();
        assert_eq!(a.content_hash, b.content_hash, "the file name is not content");
        assert_eq!(a.content_hash.len(), 64);

        let edited = VALID_RULE.replace("/var/www/", "/srv/www/");
        let c = Rule::from_yaml_str(&edited, "test.yaml").unwrap();
        assert_ne!(a.content_hash, c.content_hash);
    }

    #[test]
    fn rejects_a_rule_with_no_match_conditions() {
        let yaml = "id: empty\nversion: 1\nseverity: LOW\nmatch: []\n";
        let err = Rule::from_yaml_str(yaml, "empty.yaml").unwrap_err();
        assert!(matches!(err, RuleError::NoConditions { .. }));
    }

    /// The structural half of §11.2: a rule that cannot explain a match is
    /// rejected at load time, so no alert can ever carry a blank reason.
    #[test]
    fn rejects_a_condition_with_a_blank_reason() {
        let yaml = r#"
id: unexplained
version: 1
severity: LOW
match:
  - field: file.path
    op: starts_with
    value: "/var/www/"
    reason: "   "
"#;
        let err = Rule::from_yaml_str(yaml, "unexplained.yaml").unwrap_err();
        assert!(matches!(err, RuleError::EmptyReason { index: 0, .. }));
    }

    #[test]
    fn rejects_a_rule_with_a_blank_id() {
        let yaml = r#"
id: "  "
version: 1
severity: LOW
match:
  - field: file.path
    op: eq
    value: "/x"
    reason: "because"
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "blank.yaml").unwrap_err(),
            RuleError::BlankId { .. }
        ));
    }

    #[test]
    fn rejects_malformed_yaml_naming_the_origin() {
        let err = Rule::from_yaml_str("id: [unclosed", "broken.yaml").unwrap_err();
        assert!(err.to_string().contains("broken.yaml"));
    }

    #[test]
    fn rejects_an_unknown_operator_rather_than_silently_never_matching() {
        let yaml = r#"
id: bad_op
version: 1
severity: LOW
match:
  - field: file.path
    op: regex_matches
    value: ".*"
    reason: "because"
"#;
        assert!(Rule::from_yaml_str(yaml, "bad_op.yaml").is_err());
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p osiris-detect rule`
Expected: FAIL — every name is undefined. (Create `eval.rs` and `engine.rs` as empty files, or comment out their `pub mod` lines, so `lib.rs` compiles far enough to report these errors.)

- [ ] **Step 4: Implement `rule.rs`**

Insert above the test module:
```rust
use serde::Deserialize;
use sha2::{Digest, Sha256};

use osiris_schema::Severity;

/// The comparison operators this phase supports — a subset of §12.3's OQL
/// operator set, restricted to what single-event matching needs. No regex:
/// an unbounded-backtracking matcher on the ingestion hot path is a
/// denial-of-service surface, and nothing in this phase's rules needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
    In,
}

/// One matchable condition. `reason` is **required**, not optional: it is
/// the explanation that lands in the resulting `Alert.reasons`, one per
/// matched condition, which is how ARCHITECTURE.md §11.2's "not a generic
/// template" requirement is made structural rather than a convention
/// (Phase 2 plan Global Constraints #10).
#[derive(Debug, Clone, Deserialize)]
pub struct Condition {
    /// Dotted path into the event's JSON projection, e.g. `file.path`,
    /// `process.exe_path`, `event_type`.
    pub field: String,
    pub op: Operator,
    pub value: serde_json::Value,
    pub reason: String,
}

/// A compiled detection rule. `content_hash` is the SHA-256 of the exact
/// rule text, stored on every `Alert` this rule produces so an alert always
/// cites the precise rule revision that fired (§11.1).
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub version: u32,
    pub severity: Severity,
    pub match_conditions: Vec<Condition>,
    pub content_hash: String,
}

/// The on-disk YAML shape. A strict subset of §11.1's rule structure:
/// `window`, `sequence`, `scope` and `mitre` are Phase 6 and are rejected
/// rather than silently ignored (serde's default deny-unknown behaviour is
/// off by default, so `deny_unknown_fields` makes that explicit).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    id: String,
    version: u32,
    severity: Severity,
    #[serde(rename = "match")]
    match_conditions: Vec<Condition>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("failed to read rule file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse rule {origin}: {source}")]
    Parse {
        origin: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("rule {origin} has a blank id")]
    BlankId { origin: String },
    #[error("rule {id} has no match conditions — it would fire on everything")]
    NoConditions { id: String },
    #[error("rule {id} condition {index} has a blank reason (ARCHITECTURE.md §11.2 requires one explanation per matched condition)")]
    EmptyReason { id: String, index: usize },
}

impl Rule {
    /// Parses and validates one rule. `origin` is only used in error
    /// messages — it deliberately does not feed the content hash, so
    /// renaming a rule file does not invalidate the alerts citing it.
    pub fn from_yaml_str(yaml: &str, origin: &str) -> Result<Self, RuleError> {
        let parsed: RuleFile =
            serde_yaml::from_str(yaml).map_err(|source| RuleError::Parse {
                origin: origin.to_string(),
                source,
            })?;
        if parsed.id.trim().is_empty() {
            return Err(RuleError::BlankId {
                origin: origin.to_string(),
            });
        }
        if parsed.match_conditions.is_empty() {
            return Err(RuleError::NoConditions { id: parsed.id });
        }
        for (index, condition) in parsed.match_conditions.iter().enumerate() {
            if condition.reason.trim().is_empty() {
                return Err(RuleError::EmptyReason {
                    id: parsed.id.clone(),
                    index,
                });
            }
        }
        let mut hasher = Sha256::new();
        hasher.update(yaml.as_bytes());
        Ok(Self {
            id: parsed.id,
            version: parsed.version,
            severity: parsed.severity,
            match_conditions: parsed.match_conditions,
            content_hash: hex::encode(hasher.finalize()),
        })
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p osiris-detect rule`
Expected: PASS — 7 tests.

- [ ] **Step 6: Write the failing test for field extraction and matching**

Create `crates/osiris-detect/src/eval.rs` containing **only** the test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Operator;
    use serde_json::json;

    fn event_json() -> serde_json::Value {
        json!({
            "event_type": "FILE_CREATE",
            "file": { "path": "/var/www/html/shell.php", "inode": 200001 },
            "process": { "exe_path": "/usr/bin/curl", "pid": 300 },
            "network": null,
            "tags": ["A", "B"]
        })
    }

    #[test]
    fn reads_a_top_level_field() {
        assert_eq!(
            field_value(&event_json(), "event_type"),
            Some(&json!("FILE_CREATE"))
        );
    }

    #[test]
    fn reads_a_nested_field_by_dotted_path() {
        assert_eq!(
            field_value(&event_json(), "file.path"),
            Some(&json!("/var/www/html/shell.php"))
        );
        assert_eq!(
            field_value(&event_json(), "process.exe_path"),
            Some(&json!("/usr/bin/curl"))
        );
    }

    #[test]
    fn returns_none_for_a_missing_or_null_field() {
        assert_eq!(field_value(&event_json(), "file.hash"), None);
        assert_eq!(field_value(&event_json(), "nope.at.all"), None);
        // An explicit JSON null is "not present" for matching purposes —
        // otherwise every `network.*` condition would match every process
        // event, where `network` is null.
        assert_eq!(field_value(&event_json(), "network"), None);
        assert_eq!(field_value(&event_json(), "network.dst_ip"), None);
    }

    #[test]
    fn string_operators_compare_strings() {
        let path = json!("/var/www/html/shell.php");
        assert!(matches(Operator::Eq, &path, &json!("/var/www/html/shell.php")));
        assert!(!matches(Operator::Eq, &path, &json!("/etc/passwd")));
        assert!(matches(Operator::Ne, &path, &json!("/etc/passwd")));
        assert!(matches(Operator::StartsWith, &path, &json!("/var/www/")));
        assert!(!matches(Operator::StartsWith, &path, &json!("/home/")));
        assert!(matches(Operator::EndsWith, &path, &json!(".php")));
        assert!(matches(Operator::Contains, &path, &json!("/html/")));
        assert!(!matches(Operator::Contains, &path, &json!("/etc/")));
    }

    #[test]
    fn in_matches_any_member_of_the_expected_array() {
        let exe = json!("/usr/bin/curl");
        assert!(matches(
            Operator::In,
            &exe,
            &json!(["/bin/bash", "/usr/bin/curl"])
        ));
        assert!(!matches(Operator::In, &exe, &json!(["/bin/bash"])));
        // A non-array `value` for `in` is a rule authoring mistake; it must
        // not match rather than being coerced into an equality test.
        assert!(!matches(Operator::In, &exe, &json!("/usr/bin/curl")));
    }

    /// A string operator against a non-string actual value (an integer
    /// inode, say) must be false, never a panic and never a coercion that
    /// makes a rule match something its author did not intend.
    #[test]
    fn string_operators_are_false_against_non_string_values() {
        let inode = json!(200001);
        assert!(!matches(Operator::StartsWith, &inode, &json!("2")));
        assert!(!matches(Operator::Contains, &inode, &json!("0")));
        assert!(!matches(Operator::EndsWith, &inode, &json!("1")));
    }

    #[test]
    fn eq_and_ne_work_on_non_string_values_too() {
        assert!(matches(Operator::Eq, &json!(300), &json!(300)));
        assert!(matches(Operator::Ne, &json!(300), &json!(301)));
    }
}
```

- [ ] **Step 7: Run to verify it fails**

Run: `cargo test -p osiris-detect eval`
Expected: FAIL — `field_value` and `matches` are undefined.

- [ ] **Step 8: Implement `eval.rs`**

Insert above the test module:
```rust
use crate::rule::Operator;

/// Resolves a dotted field path against an event's JSON projection.
/// Matching against the serialized event rather than against
/// `CanonicalEvent`'s Rust fields is what lets a rule name any field in the
/// schema (`file.path`, `process.exe_path`, `event_type`) without this
/// crate hard-coding an accessor per field — and it means rule field names
/// are literally the schema's own JSON names, so §12.3's "field reference
/// generated from the Event Schema so it never drifts" stays achievable.
///
/// An explicit JSON `null` resolves to `None`, not to `Some(null)`: the
/// envelope sets every unused entity ref to `null`, so treating null as
/// present would make `network.dst_ip`-style conditions match on events
/// that have no network context at all.
pub fn field_value<'a>(
    event_json: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = event_json;
    for segment in path.split('.') {
        current = current.get(segment)?;
        if current.is_null() {
            return None;
        }
    }
    Some(current)
}

/// Applies one operator. Every comparison is total: a type mismatch is
/// `false`, never a panic and never a silent coercion that would make a
/// rule match something its author did not write.
pub fn matches(op: Operator, actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match op {
        Operator::Eq => actual == expected,
        Operator::Ne => actual != expected,
        Operator::In => expected
            .as_array()
            .map(|values| values.iter().any(|v| v == actual))
            .unwrap_or(false),
        Operator::Contains | Operator::StartsWith | Operator::EndsWith => {
            let (Some(actual), Some(expected)) = (actual.as_str(), expected.as_str()) else {
                return false;
            };
            match op {
                Operator::Contains => actual.contains(expected),
                Operator::StartsWith => actual.starts_with(expected),
                Operator::EndsWith => actual.ends_with(expected),
                _ => unreachable!("outer match already narrowed to the string operators"),
            }
        }
    }
}
```

- [ ] **Step 9: Run to verify it passes**

Run: `cargo test -p osiris-detect eval`
Expected: PASS — 7 tests.

- [ ] **Step 10: Write the real rule file**

Create `config/rules/shell_wrote_file_to_web_root.yaml`:
```yaml
# Detects the classic web-shell drop: a shell or download tool writing a
# file into a web-served directory. The web server itself writes there
# constantly (uploads, caches, sessions), so the actor condition is what
# makes this specific rather than noisy — matching ARCHITECTURE.md §11.2's
# requirement that every reason be specific, not a generic template.
#
# MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell).
id: shell_wrote_file_to_web_root
version: 1
severity: HIGH
match:
  - field: event_type
    op: in
    value: ["FILE_CREATE", "FILE_WRITE"]
    reason: "A file was created or written on disk"
  - field: file.path
    op: starts_with
    value: "/var/www/"
    reason: "The file was written inside the web-served directory /var/www/"
  - field: process.exe_path
    op: in
    value: ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget"]
    reason: "The writing process is an interactive shell or download tool, not the web server"
```

- [ ] **Step 11: Write the failing test for the engine**

Create `crates/osiris-detect/src/engine.rs` containing **only** the test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, FileRef, HostRef, ProcessKey, ProcessRef, Severity, Source,
        SCHEMA_VERSION,
    };
    use uuid::Uuid;

    const WEB_ROOT_RULE: &str = r#"
id: shell_wrote_file_to_web_root
version: 1
severity: HIGH
match:
  - field: event_type
    op: in
    value: ["FILE_CREATE", "FILE_WRITE"]
    reason: "A file was created or written on disk"
  - field: file.path
    op: starts_with
    value: "/var/www/"
    reason: "The file was written inside the web-served directory /var/www/"
  - field: process.exe_path
    op: in
    value: ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget"]
    reason: "The writing process is an interactive shell or download tool, not the web server"
"#;

    fn event(event_type: EventType, path: &str, exe_path: &str) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 1,
            event_type,
            category: event_type.category(),
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
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", 300, 1),
                pid: 300,
                exe_path: exe_path.to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
            parent_process: None,
            thread: None,
            file: Some(FileRef {
                path: path.to_string(),
                previous_path: None,
                inode: Some(200001),
                device_id: Some(osiris_schema::encode_device_id(8, 1)),
                size: None,
                mode: None,
                owner_uid: None,
                owner_gid: None,
                hash: None,
            }),
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

    fn engine() -> DetectionEngine {
        DetectionEngine::new(vec![
            crate::rule::Rule::from_yaml_str(WEB_ROOT_RULE, "test.yaml").unwrap()
        ])
    }

    #[test]
    fn fires_on_a_shell_writing_into_the_web_root() {
        let event = event(
            EventType::FileCreate,
            "/var/www/html/shell.php",
            "/usr/bin/curl",
        );
        let alerts = engine().evaluate(&event);
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.rule_id(), "shell_wrote_file_to_web_root");
        assert_eq!(alert.rule_version(), 1);
        assert_eq!(alert.severity(), Severity::High);
        assert_eq!(alert.timestamp(), event.timestamp);
        assert_eq!(alert.host_id(), event.host_id);
        assert_eq!(alert.evidence(), &[event.event_id]);
        assert_eq!(alert.rule_content_hash().len(), 64);
    }

    /// §11.2: one reason per matched condition, each specific enough to be
    /// actionable — never "Threat detected".
    #[test]
    fn the_alert_explains_every_matched_condition_specifically() {
        let alerts = engine().evaluate(&event(
            EventType::FileWrite,
            "/var/www/html/shell.php",
            "/bin/bash",
        ));
        let reasons = alerts[0].reasons();
        assert_eq!(reasons.len(), 3);
        assert!(reasons[1].contains("/var/www/"));
        assert!(reasons[2].contains("shell or download tool"));
        assert!(reasons.iter().all(|r| !r.trim().is_empty()));
    }

    #[test]
    fn does_not_fire_when_the_path_is_outside_the_web_root() {
        let alerts = engine().evaluate(&event(
            EventType::FileWrite,
            "/home/user/notes.txt",
            "/bin/bash",
        ));
        assert!(alerts.is_empty());
    }

    #[test]
    fn does_not_fire_when_the_writer_is_the_web_server_itself() {
        let alerts = engine().evaluate(&event(
            EventType::FileWrite,
            "/var/www/html/cache/page.html",
            "/usr/sbin/nginx",
        ));
        assert!(alerts.is_empty());
    }

    #[test]
    fn does_not_fire_on_a_rename_because_the_rule_names_only_create_and_write() {
        let alerts = engine().evaluate(&event(
            EventType::FileRename,
            "/var/www/html/shell.php",
            "/usr/bin/curl",
        ));
        assert!(alerts.is_empty());
    }

    /// A condition naming a field the event doesn't carry must not match —
    /// a process event has no `file`, so a file rule must never fire on it.
    #[test]
    fn does_not_fire_on_an_event_missing_the_referenced_field() {
        let mut process_event = event(EventType::ProcessExec, "/ignored", "/usr/bin/curl");
        process_event.file = None;
        assert!(engine().evaluate(&process_event).is_empty());
    }

    #[test]
    fn evaluate_batch_returns_one_alert_per_matching_event() {
        let events = vec![
            event(EventType::FileCreate, "/var/www/html/a.php", "/usr/bin/curl"),
            event(EventType::FileWrite, "/home/user/notes.txt", "/bin/bash"),
            event(EventType::FileWrite, "/var/www/html/b.php", "/bin/bash"),
        ];
        let alerts = engine().evaluate_batch(&events);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].evidence(), &[events[0].event_id]);
        assert_eq!(alerts[1].evidence(), &[events[2].event_id]);
    }

    #[test]
    fn an_engine_with_no_rules_produces_no_alerts() {
        let engine = DetectionEngine::new(vec![]);
        assert_eq!(engine.rule_count(), 0);
        assert!(engine
            .evaluate(&event(
                EventType::FileCreate,
                "/var/www/html/shell.php",
                "/usr/bin/curl"
            ))
            .is_empty());
    }

    #[test]
    fn loads_every_yaml_rule_in_a_directory_in_a_deterministic_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b_rule.yaml"), WEB_ROOT_RULE).unwrap();
        std::fs::write(
            dir.path().join("a_rule.yml"),
            WEB_ROOT_RULE.replace("id: shell_wrote_file_to_web_root", "id: a_rule"),
        )
        .unwrap();
        // Non-rule files in the directory are ignored, not parsed.
        std::fs::write(dir.path().join("README.md"), "not a rule").unwrap();

        let engine = DetectionEngine::load_from_dir(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 2);
        let alerts = engine.evaluate(&event(
            EventType::FileCreate,
            "/var/www/html/shell.php",
            "/usr/bin/curl",
        ));
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].rule_id(), "a_rule", "rules load in file-name order");
        assert_eq!(alerts[1].rule_id(), "shell_wrote_file_to_web_root");
    }

    #[test]
    fn load_from_dir_reports_the_offending_file_when_a_rule_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.yaml"), "id: [unclosed").unwrap();
        let err = DetectionEngine::load_from_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("broken.yaml"));
    }

    #[test]
    fn load_from_dir_on_a_missing_directory_is_an_error_not_a_silent_empty_engine() {
        let dir = tempfile::tempdir().unwrap();
        assert!(DetectionEngine::load_from_dir(&dir.path().join("nope")).is_err());
    }

    /// The repository's own shipped rule must load and behave — this is the
    /// CI-enforced half of §11.1's "every rule ships with a fixture that
    /// must trigger it, and a negative fixture that must not".
    #[test]
    fn the_shipped_web_root_rule_loads_and_fires_on_its_positive_fixture_only() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/shell_wrote_file_to_web_root.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("shipped rule must exist at {}: {e}", path.display()));
        let engine = DetectionEngine::new(vec![
            crate::rule::Rule::from_yaml_str(&yaml, "shell_wrote_file_to_web_root.yaml").unwrap()
        ]);
        assert_eq!(
            engine
                .evaluate(&event(
                    EventType::FileCreate,
                    "/var/www/html/shell.php",
                    "/usr/bin/curl"
                ))
                .len(),
            1
        );
        assert!(engine
            .evaluate(&event(
                EventType::FileWrite,
                "/home/user/notes.txt",
                "/bin/bash"
            ))
            .is_empty());
    }
}
```

- [ ] **Step 12: Run to verify it fails**

Run: `cargo test -p osiris-detect engine`
Expected: FAIL — `DetectionEngine` is undefined.

- [ ] **Step 13: Implement `engine.rs`**

Insert above the test module:
```rust
use std::path::Path;

use osiris_schema::{Alert, CanonicalEvent};

use crate::eval::{field_value, matches};
use crate::rule::{Rule, RuleError};

/// The Phase 2 Detection Engine: stateless, single-event matching over the
/// rules loaded at startup (plan Global Constraints #10). Stateful
/// `sequence`/`window` evaluation and rule hot-reload are Phase 6
/// (ARCHITECTURE.md §11.1/§29). Runs on the Server's ingestion path, after
/// each successful `batch_write` — never on the Agent, which must not link
/// this crate at all (§27's privilege boundary).
pub struct DetectionEngine {
    rules: Vec<Rule>,
}

impl DetectionEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Loads every `*.yaml`/`*.yml` file in `dir`, sorted by file name so
    /// rule order — and therefore alert order — is deterministic across
    /// runs and platforms (directory iteration order is not).
    pub fn load_from_dir(dir: &Path) -> Result<Self, RuleError> {
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .map_err(|source| RuleError::Read {
                path: dir.display().to_string(),
                source,
            })?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        paths.sort();

        let mut rules = Vec::with_capacity(paths.len());
        for path in paths {
            let origin = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unnamed>")
                .to_string();
            let yaml = std::fs::read_to_string(&path).map_err(|source| RuleError::Read {
                path: path.display().to_string(),
                source,
            })?;
            rules.push(Rule::from_yaml_str(&yaml, &origin)?);
        }
        tracing::info!(rule_count = rules.len(), dir = %dir.display(), "loaded detection rules");
        Ok(Self::new(rules))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluates one event against every rule, returning one `Alert` per
    /// rule whose conditions all matched.
    pub fn evaluate(&self, event: &CanonicalEvent) -> Vec<Alert> {
        if self.rules.is_empty() {
            return vec![];
        }
        // Serialize once per event, not once per rule.
        let Ok(event_json) = serde_json::to_value(event) else {
            tracing::error!(
                event_id = %event.event_id,
                "could not project event to JSON for rule evaluation; skipping it"
            );
            return vec![];
        };

        self.rules
            .iter()
            .filter_map(|rule| self.evaluate_rule(rule, event, &event_json))
            .collect()
    }

    pub fn evaluate_batch(&self, events: &[CanonicalEvent]) -> Vec<Alert> {
        events.iter().flat_map(|e| self.evaluate(e)).collect()
    }

    fn evaluate_rule(
        &self,
        rule: &Rule,
        event: &CanonicalEvent,
        event_json: &serde_json::Value,
    ) -> Option<Alert> {
        let mut reasons = Vec::with_capacity(rule.match_conditions.len());
        for condition in &rule.match_conditions {
            // A missing (or null) field never matches — a file rule must
            // not fire on a process event that carries no `file` at all.
            let actual = field_value(event_json, &condition.field)?;
            if !matches(condition.op, actual, &condition.value) {
                return None;
            }
            reasons.push(condition.reason.clone());
        }
        match Alert::new(
            rule.id.clone(),
            rule.version,
            rule.content_hash.clone(),
            rule.severity,
            event.timestamp,
            event.host_id,
            reasons,
            vec![event.event_id],
        ) {
            Ok(alert) => Some(alert),
            // Unreachable in practice: `Rule::from_yaml_str` rejects a blank
            // id, zero conditions, and blank reasons, and evidence is always
            // exactly one event_id. Logged rather than unwrapped so a future
            // rule-format change surfaces as a visible error, not a panic on
            // the Server's ingestion path.
            Err(e) => {
                tracing::error!(rule_id = %rule.id, error = %e, "rule matched but produced an invalid alert; dropping it");
                None
            }
        }
    }
}
```

- [ ] **Step 14: Run the whole crate's tests**

Run: `cargo test -p osiris-detect`
Expected: PASS — 7 `rule` + 7 `eval` + 12 `engine` tests, including the shipped-rule fixture test.

- [ ] **Step 15: Confirm the privilege boundary check now runs for real**

Add nothing to `tools/check-dep-graph.sh`'s rules (`check_forbidden osiris-agent … osiris-detect …` already covers it), but add one line after `check_no_internal_deps osiris-fileutil` so the *new* crate's own dependency surface is pinned too:
```bash
check_forbidden osiris-detect osiris-storage osiris-sensors osiris-agent osiris-server osiris-api
```
This encodes §2.1's layering: the Detection Engine consumes the schema and nothing above it, so it can never be pulled into the Agent by a transitive edge and can never grow a direct storage dependency (which would put `Alert` persistence back inside the engine — the thing Global Constraint #8 avoids).

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`, and the `osiris-agent` line's `osiris-detect` check now runs for real instead of printing `skip: osiris-detect not in workspace yet`.

- [ ] **Step 16: Commit**

```bash
git add crates/osiris-detect config/rules tools/check-dep-graph.sh
git commit -m "feat(detect): stateless single-event rule engine and the first file-event rule

YAML rules with a required per-condition reason, so §11.2's 'one
explanation per matched condition' is structural rather than convention.
Every alert cites the rule's SHA-256 content hash. Ships
shell_wrote_file_to_web_root with positive and negative fixtures.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0192TqfN5oKsNzSDGYCo7aTt"
```

---
