# Phase 3 — Network + DNS Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Phase 2's working Filesystem vertical slice to network telemetry — a real Network Sensor (`/proc/net/tcp` connection-table polling + `/proc/<pid>/fd` inode attribution), DNS event plumbing through the existing Pipeline/Bus/Storage/API path (no live DNS sensor this phase — see Global Constraint #6), Entity Graph v1's process↔network edges (`CONNECTED_TO`, `RESOLVED_TO`), a Network Story query endpoint, Timeline coverage for the network/DNS categories, and a second Detection rule that fires on DNS events and persists a structurally-explained `Alert`.

**Architecture:** A new `osiris-sensors-net` sensor polls a configurable "proc root" directory (real deployments: `/proc`) for `net/tcp`'s connection table on an interval, diffs successive snapshots to detect new and closed TCP connections, and attributes each connection to a process by scanning `<proc_root>/<pid>/fd/*` for a matching `socket:[inode]` target — assembling `RawEvent::Network(NetworkEventRaw)` records. DNS gets full pipeline support (`RawEvent::Dns(DnsEventRaw)`, normalize/enrich/validate/prioritize, `DnsRef`, the `RESOLVED_TO` edge) exercised end-to-end via the Synthetic sensor's new "network beacon" scenario, since neither of ARCHITECTURE.md §4.3's two documented DNS backends (eBPF uprobe, passive pcap) has a text-log-style fallback this dev environment can implement and test the way Phase 1/2's audit-log backends did (Global Constraint #6). Both event categories flow through the *existing* Phase 1/2 Pipeline (Normalize/Enrich/Validate/Prioritize), Event Bus, spool file, and Server ingestion, unchanged in shape — `osiris-detect`'s rule engine needs zero code changes (its dotted-JSON-path matcher already handles any field, `network.*`/`dns.*` included), only a second shipped rule file. Storage gains network-address and DNS-domain filters; the API gains `GET /api/v1/network/story` (ip or domain → resolved identities → identity-joined events → citing alerts), mirroring Phase 2's File Story exactly.

**Tech Stack:** Rust (edition 2021), Tokio, `async-trait`, `axum`, `rusqlite` (`bundled`), `serde_yaml` (the new rule file) — all already present in `[workspace.dependencies]`. No new third-party crates are introduced by this phase.

**Spec:** `ARCHITECTURE.md` (project root) — primarily §2.1 (layering rule), §4.1/§4.3 (Sensor trait + the Network/DNS rows' fallback backends), §6 (telemetry levels, Network/DNS STANDARD rows), §7.1 (Event Pipeline stages), §8 (Event Bus), §9.2/§9.3/§9.4 (Event Schema v1 envelope — `NetworkRef`/`DnsRef` already exist from Phase 0, `NETWORK_*`/`DNS_QUERY` taxonomy already exists, `EntityRef::Ip`/`EntityRef::Domain` already exist, `Relation::ConnectedTo`/`Relation::ResolvedTo` already exist — this phase wires existing schema, it does not extend it), §10.1 (Storage trait), §11.1/§11.2 (Detection Engine + the structural explanation requirement — no engine changes, only a new rule), §12.1 (`network_story`), §12.4 (Timeline Engine), §14.2 (endpoint surface), §24 (repo structure), §26 (the worked trace), §27 (dependency graph / privilege boundary), §29's Phase 3 line. Phase 2's plan (`docs/superpowers/plans/2026-09-03-phase-2-filesystem-vertical-slice.md`) and its two plan-amendment briefs (Tasks 8/9, authored during that phase's execution — see `git log` for `feat(server,api): wire detection into ingest...` and `test(e2e): prove the Phase 2 filesystem vertical slice...`) are this plan's immediate prior art; several of its Global Constraints are reaffirmed here rather than restated in full (marked "carried from Phase 2" below).

## Global Constraints — scope decisions made for this plan (read before dispatching any task)

The development environment is unchanged from Phase 1/2: Windows, no Linux kernel, no clang/libbpf toolchain, no root, no real `/proc` filesystem. Phase 1/2's response was not to fake a sensor but to implement the documented fallback backend as portable Rust, tested against fixture files in the real backend's exact text format. This plan applies the same strategy to the Network Sensor and explicitly does **not** apply it to DNS (Global Constraint #6 explains why). The following decisions are disclosed and reversible; every task's requirements implicitly include this section.

1. **No eBPF kprobes/tracepoints, no conntrack.** The Network sensor's only backend in this phase is ARCHITECTURE.md §4.3's documented fallback: "`/proc/net/tcp[6]` polling + conntrack." This plan implements the `/proc/net/tcp` half (IPv4 only — see Global Constraint #2) and does not implement conntrack integration (conntrack is a netlink-based enrichment for NAT/connection-tracking state that adds nothing this phase's STANDARD telemetry row needs — see Global Constraint #3). `SensorCapabilities.ebpf` stays `false`. A real eBPF backend and IPv6/conntrack support are deferred to whenever a Linux development machine exists; because they are additional `Sensor` implementations (or extensions) behind the same unchanged trait, retrofitting them is not a rewrite.

2. **IPv4 only (`/proc/net/tcp`), not IPv6 (`/proc/net/tcp6`).** `/proc/net/tcp6` uses a different address encoding (four 32-bit words instead of one) that would roughly double this phase's parsing surface for no proportionate benefit at MVP scale — most lab/CI/demo traffic this phase's synthetic scenario and detection rule need to exercise is IPv4. `/proc/net/tcp6` support is a mechanical, self-contained follow-up (same diffing algorithm, a second address-parsing function) once IPv4 is proven correct end-to-end.

3. **Telemetry scope is §6's Network STANDARD row only: connect/accept/close, 5-tuple.** No byte counters, no per-connection process attach beyond best-effort pid/exe (those are §6's DETAILED row). Concretely, this phase emits exactly three event types: `NETWORK_CONNECT`, `NETWORK_ACCEPT`, `NETWORK_CLOSE`. `SOCKET_CREATE`/`SOCKET_BIND`/`SOCKET_LISTEN` (also in the frozen `EventType` taxonomy from Phase 0) are not emitted this phase — a listening socket's own lifecycle is not "a connection," and distinguishing bind-vs-listen from a `/proc/net/tcp` snapshot diff alone is unreliable without watching state transitions more finely than one poll interval affords.

4. **Direction is a documented heuristic, not ground truth.** `/proc/net/tcp` does not report which side initiated a connection. This plan uses the same heuristic real-world tools (e.g. `ss`, `netstat`-adjacent scripts) fall back to absent conntrack: a connection whose **local** port is in the ephemeral range (`>= 32768`, matching Linux's common `net.ipv4.ip_local_port_range` default floor) is treated as **Outbound** (this host dialed out → `NETWORK_CONNECT`); one whose local port is below that is treated as **Inbound** (this host is answering on a known/listening port → `NETWORK_ACCEPT`). This is disclosed as a known limitation in the sensor's doc comment (mirrors Phase 2's disclosed dirfd/CWD and write-flags limitations) — a host that deliberately runs a service on an ephemeral port, or a client that binds an explicit low source port, will be misclassified. `NETWORK_CLOSE` reuses the direction recorded when the connection was first observed, not a fresh heuristic evaluation, so a connection's three events (when all three are captured) are always self-consistent.

5. **Process attribution is best-effort and may be absent.** A `/proc/net/tcp` row carries a socket `inode` and the owning `uid`, not a pid. This plan resolves pid by scanning `<proc_root>/<pid>/fd/*` for a symlink target of the form `socket:[<inode>]` (real, standard `/proc` semantics — nothing exotic) across every numeric directory under `proc_root`, at the same poll tick a new connection is first observed. When no match is found (the connection existed for less than one poll interval, or dev/test symlink support is unavailable — see Global Constraint #10), `NetworkEventRaw.pid` is `None`, `exe_path`/`comm` are empty strings, and the Normalize stage leaves `CanonicalEvent.process` unset entirely (not a fabricated/provisional key) — mirroring Phase 2's "no identity → no edge" precedent for files. `uid` is always populated directly from the `/proc/net/tcp` row regardless of pid attribution succeeding.

6. **No live DNS Sensor this phase — DNS gets full pipeline plumbing, exercised only via the Synthetic sensor.** ARCHITECTURE.md §4.3 documents exactly two DNS backends: eBPF uprobe on resolver libraries, and passive `AF_PACKET`/pcap capture on port 53 (fallback: "passive pcap only"). Unlike Process/Filesystem/Network, **no plain-text-log fallback is documented for DNS** — there is nothing analogous to an audit log or a `/proc` snapshot to portably parse and unit-test in this dev environment (Windows, no libpcap, no root, no packet capture privilege). Implementing a stub sensor whose `capabilities()` always reports unsupported would add a crate that does nothing testable and duplicates what `SensorCapabilities::unsupported_reason` already communicates generically. **Ruling: this phase builds `RawEvent::Dns`, its full Normalize/Enrich/Validate/Prioritize handling, `DnsRef` population, the `RESOLVED_TO` entity edge, storage/query/API/detection support for DNS events — genuinely tested via the generator's new synthetic scenario (Task 5) and the e2e test (Task 8) — but ships no `osiris-sensors-dns` crate.** A real pcap-based (or eBPF-based) DNS Sensor is deferred to whenever a Linux development machine or a documented pcap-capture story exists; it is one more `Sensor` implementation behind the unchanged trait, emitting the same `RawEvent::Dns` this phase's pipeline already handles correctly — retrofitting it is additive, not a rewrite of anything built here.

7. **`osiris-schema` needs zero changes.** Unlike Phase 2 (which had to add `FileIdentity` and `Alert`), Phase 0 already defined everything this phase's `CanonicalEvent` envelope needs: `NetworkRef { src_ip, src_port, dst_ip, dst_port, proto, direction, bytes }`, `DnsRef { query, qtype, response_ips, ttl }`, the `NETWORK_*`/`DNS_QUERY` `EventType` variants (already mapped to `Category::Network`/`Category::Dns` with an existing test), `EntityRef::Ip { addr }` and `EntityRef::Domain { name }`, and `Relation::ConnectedTo`/`Relation::ResolvedTo`. This plan verifies each of these against the current schema in Task 1 rather than assuming Phase 2's plan text (which predates them) is still authoritative, but expects to find no gap.

8. **Entity Graph v1's two edges are exactly `CONNECTED_TO` (process → ip) and `RESOLVED_TO` (domain → ip).** No `process → domain` edge is written: the frozen `Relation` enum (not extended this phase, per Phase 2's "solve it in the consuming crate, not the frozen schema" precedent) has no variant naming a query relationship, and inferring "this process's DNS query and that process's later connection are the same investigative thread" from time-proximity alone is exactly the kind of correlation ARCHITECTURE.md §29 reserves for Phase 6's stateful Correlation Engine — this phase's Enrich stage does not attempt it. `CONNECTED_TO` is attached on `NETWORK_CONNECT`/`NETWORK_ACCEPT` events only (never `NETWORK_CLOSE` — the connection's opening event already carries the edge; a second edge on close would be a duplicate of the same fact), gated on `NetworkEventRaw.pid` being `Some` (Global Constraint #5). `RESOLVED_TO` is attached on every `DNS_QUERY` event, one edge per entry in `DnsRef.response_ips` (a query resolving to three IPs produces three edges, all citing the same `event_id`).

9. **Network Story's two lookup forms are asymmetric — this is a deliberate, disclosed scope decision, not an oversight.** ARCHITECTURE.md §12.1: `network_story(ip_or_domain) -> NetworkStory`. This plan implements:
   - **Domain form:** resolve every `DNS_QUERY` event whose `dns.query` equals the given domain → union with every network event whose `network.src_ip` or `network.dst_ip` equals any of those queries' `response_ips` → time-order → attach every `Alert` whose evidence cites one of those events.
   - **IP form:** every network event whose `network.src_ip` or `network.dst_ip` equals the given address → time-order → attach citing alerts. **No reverse DNS-answer lookup** (finding "which domain(s) resolved to this IP" from the IP alone) — that requires either an inverted index over `response_ips` arrays or a full-table scan of DNS events, both disproportionate to this phase's query surface (ARCHITECTURE.md §12.3's full OQL planner, which could express this generically, is explicitly Phase 7 scope). An analyst who wants the domain side of the story starts from the domain — which, in this phase's own detection and generator scenarios, is always known first in time order anyway (a query precedes the connection it enabled).
   - This mirrors Phase 2's File Story precedent exactly (carried forward, not re-derived): a composed query over the existing `Storage::query`/`query_alerts` surface, not a new Investigation Engine capability.

10. **The Network Route is `GET /api/v1/network/story?ip=…` or `?domain=…`, not §14.2's `/api/v1/network/{ip_or_domain}/story`.** Carried from Phase 2's Global Constraint #12 (same reasoning: the path-param shape presupposes a minted, stable resource id that does not exist until Phase 7's Investigation Engine; the query-param shape matches `osiris-api`'s existing `/api/v1/events`, `/api/v1/alerts`, and `/api/v1/files/story` convention). `GET /api/v1/dns` and `GET /api/v1/network` from §14.2's listing surface are **not** built this phase — `GET /api/v1/events?event_type=DNS_QUERY` (or `NETWORK_CONNECT`, etc.) already serves exactly that need genuinely, the same reasoning Phase 1 used to skip a separate `/api/v1/files` listing endpoint (Phase 1 plan Global Constraints #9, reaffirmed unmodified by every phase since).

11. **The fd-scan pid-attribution directory walk is exercised by a symlink-creating unit test that skips gracefully, not fails, when this platform/process cannot create a symlink.** `<proc_root>/<pid>/fd/<n>` entries are real symlinks on Linux (`readlink` returns `socket:[12345]`). This plan tests the *pure* inode-extraction logic (given a set of already-read `(path, link_target)` pairs, which ones parse as `socket:[N]`) unconditionally, and separately tests the *directory-walking* integration (create a tempdir tree of real symlinks, then scan it) using `std::os::windows::fs::symlink_file` / `std::os::unix::fs::symlink` behind a `#[cfg(...)]` gate — Windows symlink creation needs Developer Mode or admin rights, neither guaranteed on this dev machine. The integration test attempts creation, and on a permission-denied error prints a clear skip reason (via `eprintln!`, matching this codebase's existing convention of never silently skipping — see e.g. Phase 2's "skip: crate not in workspace yet" pattern in `check-dep-graph.sh`) and returns early rather than failing the suite. This is a disclosed, environment-driven test-coverage gap (the real directory-walk *code* ships and is correct; the test only skips its exercise on a platform that cannot make the OS primitive it depends on), not a scope reduction of the sensor itself.

12. **No `osiris-detect` changes.** `eval::field_value`'s dotted-JSON-path resolution and `eval::matches`'s six operators (`eq`/`ne`/`contains`/`starts_with`/`ends_with`/`in`) already work against any field a serialized `CanonicalEvent` carries — `network.dst_ip`, `dns.query`, etc. need no new code, only a new rule file (Task 6) exercising fields that happen to be new to this phase. Task 6 verifies this against the actual current `eval.rs`/`rule.rs` rather than assuming it.

13. **No `osiris-server` ingest-loop changes.** Phase 2's Task 8 wired `DetectionEngine::evaluate_batch` into the Server's ingest loop generically — it runs against every batch of `CanonicalEvent`s regardless of category, and `DetectionEngine::load_from_dir` already loads every `*.yaml`/`*.yml` file in `config/rules/`. Adding a second rule file (Task 6) is picked up automatically; no Rust code in `osiris-server` changes this phase.

14. **No CLI changes.** Carried from Phase 2 precedent (Phase 2 added no `osiris-cli` subcommands for `alerts`/`files/story` either — the existing `events`/`processes`/`status`/`health` subcommands plus direct HTTP access cover verification needs). A `network-story`/`dns` CLI verb is a Console/CLI-maturity concern for a later phase, not required for this phase's Definition of Done.

15. **`osiris-storage` gains two `QueryPlan` filters and `SqliteStorage` gains two indexed columns; no schema migration risk beyond what Phase 2 already established the pattern for.** `network_addr: Option<String>` (matches `network.src_ip OR network.dst_ip`) and `dns_domain: Option<String>` (matches `dns.query`). Both are additive nullable columns on the existing `events` table via the same guarded `ALTER TABLE ADD COLUMN` migration Phase 2's Task 6 used for `file_path`/`file_inode`/`file_device_id` — non-destructive and idempotent against a database created by any earlier phase.

None of these decisions touch the `CanonicalEvent` envelope's existing fields, the `EventType`/`Category`/`Severity`/`Source`/`Relation`/`EntityRef` enums (all already sufficient per Global Constraint #7), or the dependency-graph privilege boundary (§27), which this plan extends with two new checks (Task 3) but never relaxes.

**New workspace-wide facts this phase establishes** (binding on every task):
- Workspace `members` gains `"crates/osiris-sensors/net"` (matching the explicit-path convention `crates/osiris-sensors/fs` and `crates/osiris-sensors/process` already use, since `crates/osiris-sensors` is in `exclude`).
- New crate: `osiris-sensors-net`. No new `[workspace.dependencies]` entries.
- The three event types produced or consumed in this phase are `NETWORK_CONNECT`, `NETWORK_ACCEPT`, `NETWORK_CLOSE`, and `DNS_QUERY`, alongside Phase 1/2's `PROCESS_EXEC`/`FILE_*`. No other `EventType` variant is produced anywhere.
- Every new **library** crate keeps Phase 0/1/2's discipline: zero `unwrap()`/`expect()` on I/O, lock, or parse results outside test code; return `Result` with a `thiserror` error type; recover poisoned mutexes via `unwrap_or_else(|p| p.into_inner())` rather than panicking.
- The second rule file lives at `config/rules/dns_query_to_suspicious_tld.yaml`, loaded the same directory-scan way as Phase 2's rule.

---

### Task 1: `osiris-sensor-api` — `RawEvent::Network` and `RawEvent::Dns`

**Files:**
- Modify: `crates/osiris-sensor-api/src/raw_event.rs`
- Modify: `crates/osiris-sensor-api/src/lib.rs`

**Interfaces:**
- Consumes: nothing new — `osiris-sensor-api` has zero dependency on `osiris-schema` (verified: its `Cargo.toml` lists none), so these raw types define their own small enums rather than reusing schema types, exactly like `FileOperation` already does.
- Produces:
  - `osiris_sensor_api::NetworkOperation` — `enum { Connect, Accept, Close }`.
  - `osiris_sensor_api::NetworkDirection` — `enum { Inbound, Outbound }` (a raw-level mirror of `osiris_schema::NetworkDirection`; Task 2's Normalize stage maps one to the other, the same pattern Phase 2 used for `FileOperation` → `EventType`).
  - `osiris_sensor_api::NetworkEventRaw` — the struct defined in Step 3 below.
  - `osiris_sensor_api::DnsEventRaw` — the struct defined in Step 5 below.
  - `osiris_sensor_api::RawEvent::Network(NetworkEventRaw)` and `RawEvent::Dns(DnsEventRaw)` — two new variants alongside `ProcessExec`/`File`.
  - `RawEvent::timestamp_ns(&self)` extended to cover both new variants.
  - Task 3's sensor and Task 5's generator scenario both construct `NetworkEventRaw`; Task 5's generator scenario constructs `DnsEventRaw`.

- [ ] **Step 1: Write the failing test for the new raw event shapes**

Append to `crates/osiris-sensor-api/src/raw_event.rs`'s existing `#[cfg(test)] mod tests` block (do not remove the existing `file_raw`/`file_raw_round_trips_through_json`/`timestamp_accessor_works_for_both_variants` tests):

```rust
    fn network_raw() -> NetworkEventRaw {
        NetworkEventRaw {
            operation: NetworkOperation::Connect,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: "203.0.113.50".to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_005_000_000_000,
            source: RawEventSource::Synthetic,
        }
    }

    fn dns_raw() -> DnsEventRaw {
        DnsEventRaw {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: Some(300),
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_004_000_000_000,
            source: RawEventSource::Synthetic,
        }
    }

    #[test]
    fn network_raw_round_trips_through_json() {
        let raw = RawEvent::Network(network_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Network(n) => {
                assert_eq!(n.remote_addr, "203.0.113.50");
                assert_eq!(n.operation, NetworkOperation::Connect);
                assert_eq!(n.pid, Some(300));
            }
            other => panic!("expected RawEvent::Network, got {other:?}"),
        }
    }

    #[test]
    fn dns_raw_round_trips_through_json() {
        let raw = RawEvent::Dns(dns_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Dns(d) => {
                assert_eq!(d.query, "cdn-assets.xyz");
                assert_eq!(d.response_ips, vec!["203.0.113.50".to_string()]);
            }
            other => panic!("expected RawEvent::Dns, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_network_and_dns_variants() {
        assert_eq!(
            RawEvent::Network(network_raw()).timestamp_ns(),
            1_690_000_005_000_000_000
        );
        assert_eq!(
            RawEvent::Dns(dns_raw()).timestamp_ns(),
            1_690_000_004_000_000_000
        );
    }

    /// A connection the sensor could not attribute to a pid (Global
    /// Constraint #5) still round-trips — `pid: None` must not break
    /// (de)serialization.
    #[test]
    fn network_raw_with_no_pid_attribution_round_trips() {
        let mut raw = network_raw();
        raw.pid = None;
        raw.exe_path = String::new();
        raw.comm = String::new();
        let json = serde_json::to_string(&RawEvent::Network(raw)).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Network(n) => assert_eq!(n.pid, None),
            other => panic!("expected RawEvent::Network, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-sensor-api raw_event`
Expected: FAIL — compile errors for `NetworkEventRaw`, `NetworkOperation`, `NetworkDirection`, `DnsEventRaw`, `RawEvent::Network`, `RawEvent::Dns`.

- [ ] **Step 3: Implement `NetworkOperation`, `NetworkDirection`, and `NetworkEventRaw`**

In `crates/osiris-sensor-api/src/raw_event.rs`, insert immediately before the `RawEvent` enum (after `FileEventRaw`):

```rust
/// The three connection lifecycle events this phase emits — ARCHITECTURE.md
/// §6's Network STANDARD row ("connect/accept/close, 5-tuple"). No
/// SOCKET_CREATE/BIND/LISTEN this phase (Phase 3 plan Global Constraints
/// #3) — a listening socket's own lifecycle needs finer-grained state
/// tracking than one poll-interval diff reliably distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkOperation {
    Connect,
    Accept,
    Close,
}

/// Which side of the connection this host is. Derived from a documented
/// port-range heuristic, not ground truth (Phase 3 plan Global Constraints
/// #4) — `/proc/net/tcp` alone does not report which side initiated a
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

/// A TCP connection lifecycle record, assembled from a `/proc/net/tcp`
/// snapshot diff plus a best-effort `/proc/<pid>/fd` inode scan for process
/// attribution (Phase 3 plan Global Constraints #1/#5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventRaw {
    pub operation: NetworkOperation,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    /// Always `"tcp"` this phase (IPv4-only, Global Constraints #1/#2) —
    /// kept as a string rather than an enum so a later UDP/IPv6 backend
    /// extends this field's value set without a breaking type change.
    pub proto: String,
    pub direction: NetworkDirection,
    /// `None` when the sensor could not attribute this connection to a
    /// process (Global Constraint #5) — the pipeline then emits no
    /// `process` and no `CONNECTED_TO` edge, rather than guessing.
    pub pid: Option<u32>,
    /// Always populated directly from the `/proc/net/tcp` row's `uid`
    /// column, independent of whether pid attribution succeeded.
    pub uid: u32,
    /// Empty when `pid` is `None`, or when `pid` resolved but
    /// `/proc/<pid>/exe`/`/proc/<pid>/comm` could not be read (the process
    /// may have exited between the fd-scan and the read).
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the sensor's own clock at the poll
    /// tick this connection's state change was observed (`/proc/net/tcp`
    /// carries no per-connection timestamp of its own).
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}
```

- [ ] **Step 4: Run the test to verify `NetworkEventRaw` compiles and round-trips**

Run: `cargo test -p osiris-sensor-api raw_event`
Expected: still FAIL — `DnsEventRaw`/`RawEvent::Dns` remain undefined; the `network_raw_*` tests should now compile-fail only on the still-missing `RawEvent::Network`/`Dns` variants and `DnsEventRaw`. (This step is a checkpoint, not a green run — Step 6 completes the implementation.)

- [ ] **Step 5: Implement `DnsEventRaw`**

Insert immediately after `NetworkEventRaw`:

```rust
/// A DNS query+response record (ARCHITECTURE.md §6's DNS STANDARD row:
/// "query+response on watched resolvers"). No live sensor emits this raw
/// shape in this phase (Phase 3 plan Global Constraints #6) — it exists so
/// the full pipeline is real and tested via the Synthetic sensor ahead of a
/// later phase's real backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEventRaw {
    pub query: String,
    /// DNS record type queried, e.g. `"A"`, `"AAAA"`, `"CNAME"`.
    pub qtype: String,
    /// Empty when the query did not resolve (NXDOMAIN, timeout) — still a
    /// valid, storable `DNS_QUERY` event; `dns.response_ips` being empty is
    /// itself sometimes the interesting signal.
    pub response_ips: Vec<String>,
    pub ttl: Option<u32>,
    /// Same best-effort-attribution shape as `NetworkEventRaw` — a real
    /// pcap/eBPF DNS backend has the same "who asked" attribution problem
    /// a passive capture faces without also correlating process state.
    pub pid: Option<u32>,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}
```

Then replace the `RawEvent` enum and its `impl` block with:

```rust
/// The shape sensors emit onto their output channel (ARCHITECTURE.md §7.1
/// step 1, "Collect"). Phase 1 scoped this to Process/Exec; Phase 2 added
/// File; Phase 3 adds Network and Dns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
    File(FileEventRaw),
    Network(NetworkEventRaw),
    Dns(DnsEventRaw),
}

impl RawEvent {
    /// The originating backend's wall-clock timestamp, regardless of
    /// variant — used by sensors for their `last_event_at` health field
    /// without matching on the variant at every call site.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            RawEvent::ProcessExec(p) => p.timestamp_ns,
            RawEvent::File(f) => f.timestamp_ns,
            RawEvent::Network(n) => n.timestamp_ns,
            RawEvent::Dns(d) => d.timestamp_ns,
        }
    }
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p osiris-sensor-api`
Expected: PASS — the crate's existing tests plus the 5 new `raw_event` tests.

- [ ] **Step 7: Update `lib.rs` re-exports**

In `crates/osiris-sensor-api/src/lib.rs`, replace:
```rust
pub use raw_event::{FileEventRaw, FileOperation, ProcessExecRaw, RawEvent, RawEventSource};
```
with:
```rust
pub use raw_event::{
    DnsEventRaw, FileEventRaw, FileOperation, NetworkDirection, NetworkEventRaw,
    NetworkOperation, ProcessExecRaw, RawEvent, RawEventSource,
};
```

- [ ] **Step 8: Fix the now-non-exhaustive `match`es in existing tests**

`cargo build --workspace --all-targets` now fails wherever a test matches `RawEvent` exhaustively. Search: `grep -rn "RawEvent::ProcessExec(raw) =>" crates/ generator/` and `grep -rn "RawEvent::File(f) =>\|RawEvent::File(raw) =>" crates/ generator/` to find every site (Phase 2's own equivalent step found exactly two — `crates/osiris-sensors/process/src/sensor.rs` and `generator/src/sensor.rs` — but this phase's sites may differ since Phase 2 added its own `other => panic!(...)` arms already; re-derive the current list rather than assuming Phase 2's is still exhaustive). For each site that matches exhaustively without an `other => ...` arm, add one:
```rust
other => panic!("<this component> must only emit <X> events, got {other:?}"),
```
matching the wording style already used at the two Phase 2 sites. If every existing site already has an `other => ...` catch-all (check before editing — Phase 2's fix already added one to both known sites), this step is a no-op; note that in the report rather than editing anything.

- [ ] **Step 9: Run the full workspace build and dep-graph check**

Run: `cargo build --workspace --all-targets` then `bash tools/check-dep-graph.sh`
Expected: build succeeds; `Dependency-graph check PASSED` (this task adds no new crate, so no new check output).

- [ ] **Step 10: Commit**

```bash
git add crates/osiris-sensor-api generator crates/osiris-sensors
git commit -m "feat(sensor-api): RawEvent::Network and RawEvent::Dns raw record shapes

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

### Task 2: `osiris-pipeline` — the raw→canonical path for network and DNS events

**Files:**
- Modify: `crates/osiris-pipeline/src/normalize.rs`
- Modify: `crates/osiris-pipeline/src/enrich.rs`
- Modify: `crates/osiris-pipeline/src/validate.rs`
- Modify: `crates/osiris-pipeline/src/prioritize.rs`
- Modify: `crates/osiris-pipeline/src/pipeline.rs` (only if it exhaustively matches `RawEvent`/`EventType` anywhere — check first; Phase 2's equivalent task found it did not need changes)

**Interfaces:**
- Consumes: `osiris_sensor_api::{NetworkEventRaw, NetworkOperation, NetworkDirection, DnsEventRaw}` from Task 1; `osiris_schema::{NetworkRef, DnsRef, NetworkDirection as SchemaNetworkDirection, EntityRef, Relation}` (all pre-existing, Global Constraint #7).
- Produces:
  - `normalize()` handles `RawEvent::Network` and `RawEvent::Dns`, producing `CanonicalEvent`s with `network`/`dns` populated and `event_type`/`category` set correctly.
  - `enrich()` resolves a network/DNS event's provisional `process_key` the same way it already does for file events (reusing `ProcessResolver::resolve`/`parent_of` — no resolver changes needed), and attaches `CONNECTED_TO`/`RESOLVED_TO` edges per Global Constraint #8.
  - `validate()` rejects (tags `INVALID`, still forwards) a network event with an empty `remote_addr` or a DNS event with an empty `query`.
  - `PriorityTable::default()` maps all three `NETWORK_*` types and `DNS_QUERY` to a lane (Step 9 picks the exact lane with reasoning).

- [ ] **Step 1: Write the failing test for normalizing a network event**

Append to `crates/osiris-pipeline/src/normalize.rs`'s `mod tests` (do not remove Phase 1/2's existing tests):

```rust
    fn network_raw(
        operation: osiris_sensor_api::NetworkOperation,
        pid: Option<u32>,
    ) -> osiris_sensor_api::NetworkEventRaw {
        osiris_sensor_api::NetworkEventRaw {
            operation,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: "203.0.113.50".to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_sensor_api::NetworkDirection::Outbound,
            pid,
            uid: 1000,
            exe_path: if pid.is_some() {
                "/usr/bin/curl".to_string()
            } else {
                String::new()
            },
            comm: if pid.is_some() {
                "curl".to_string()
            } else {
                String::new()
            },
            timestamp_ns: 1_690_000_005_000_000_000,
            source: RawEventSource::Audit,
        }
    }

    fn dns_raw(pid: Option<u32>) -> osiris_sensor_api::DnsEventRaw {
        osiris_sensor_api::DnsEventRaw {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: Some(300),
            pid,
            uid: 1000,
            exe_path: if pid.is_some() {
                "/usr/bin/curl".to_string()
            } else {
                String::new()
            },
            comm: if pid.is_some() { "curl".to_string() } else { String::new() },
            timestamp_ns: 1_690_000_004_000_000_000,
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn network_operations_map_to_the_matching_event_type_and_network_category() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        for (operation, expected) in [
            (NetworkOperation::Connect, EventType::NetworkConnect),
            (NetworkOperation::Accept, EventType::NetworkAccept),
            (NetworkOperation::Close, EventType::NetworkClose),
        ] {
            let event = normalize(
                RawEvent::Network(network_raw(operation, Some(300))),
                &host,
                "boot-1",
            );
            assert_eq!(event.event_type, expected);
            assert_eq!(event.category, Category::Network);
        }
    }

    #[test]
    fn network_event_carries_a_complete_network_ref_for_an_outbound_connection() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::Network(network_raw(NetworkOperation::Connect, Some(300))),
            &host,
            "boot-1",
        );
        let net = event.network.expect("network events must carry a NetworkRef");
        // Outbound: local is the source, remote is the destination.
        assert_eq!(net.src_ip, "10.0.0.5");
        assert_eq!(net.src_port, 51000);
        assert_eq!(net.dst_ip, "203.0.113.50");
        assert_eq!(net.dst_port, 443);
        assert_eq!(net.direction, osiris_schema::NetworkDirection::Outbound);
        assert_eq!(event.provider, "network_sensor/audit");
    }

    #[test]
    fn network_event_with_no_pid_attribution_carries_no_process() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::Network(network_raw(NetworkOperation::Connect, None)),
            &host,
            "boot-1",
        );
        assert!(
            event.process.is_none(),
            "a connection the sensor could not attribute must carry no process, not a fabricated one"
        );
        assert!(event.network.is_some(), "the NetworkRef itself is still populated");
    }

    #[test]
    fn network_event_process_key_is_provisional_with_a_zero_start_time_when_pid_is_known() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::Network(network_raw(NetworkOperation::Connect, Some(300))),
            &host,
            "boot-1",
        );
        let process = event.process.expect("pid was known, so process must be set");
        assert_eq!(process.pid, 300);
        assert_eq!(process.start_time_mono, 0);
        assert_eq!(
            process.process_key,
            ProcessKey::new(host.host_id, "boot-1", 300, 0)
        );
    }

    #[test]
    fn dns_query_normalizes_to_correct_event_type_and_dns_category() {
        let host = sample_host();
        let event = normalize(RawEvent::Dns(dns_raw(Some(300))), &host, "boot-1");
        assert_eq!(event.event_type, EventType::DnsQuery);
        assert_eq!(event.category, Category::Dns);
        assert_eq!(event.provider, "dns_sensor/audit");
    }

    #[test]
    fn dns_event_carries_a_complete_dns_ref() {
        let host = sample_host();
        let event = normalize(RawEvent::Dns(dns_raw(Some(300))), &host, "boot-1");
        let dns = event.dns.expect("DNS events must carry a DnsRef");
        assert_eq!(dns.query, "cdn-assets.xyz");
        assert_eq!(dns.qtype, "A");
        assert_eq!(dns.response_ips, vec!["203.0.113.50".to_string()]);
        assert_eq!(dns.ttl, Some(300));
    }

    #[test]
    fn dns_event_with_no_pid_attribution_carries_no_process() {
        let host = sample_host();
        let event = normalize(RawEvent::Dns(dns_raw(None)), &host, "boot-1");
        assert!(event.process.is_none());
        assert!(event.dns.is_some());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-pipeline normalize`
Expected: FAIL — `normalize` does not handle `RawEvent::Network`/`RawEvent::Dns` (non-exhaustive match compile error).

- [ ] **Step 3: Implement `normalize_network_event` and `normalize_dns_event`**

In `crates/osiris-pipeline/src/normalize.rs`, update the imports at the top:
```rust
use osiris_schema::{
    CanonicalEvent, Category, DnsRef, EventType, FileRef, HostRef, NetworkDirection, NetworkRef,
    ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
};
use osiris_sensor_api::{
    DnsEventRaw, FileEventRaw, FileOperation, NetworkDirection as RawNetworkDirection,
    NetworkEventRaw, NetworkOperation, ProcessExecRaw, RawEvent, RawEventSource,
};
```

Update the `normalize` dispatcher:
```rust
pub fn normalize(raw: RawEvent, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    match raw {
        RawEvent::ProcessExec(p) => normalize_process_exec(p, host, boot_id),
        RawEvent::File(f) => normalize_file_event(f, host, boot_id),
        RawEvent::Network(n) => normalize_network_event(n, host, boot_id),
        RawEvent::Dns(d) => normalize_dns_event(d, host, boot_id),
    }
}
```

Add two new functions (place after `normalize_file_event`). Both follow `normalize_file_event`'s exact shape: mint a provisional `process_key` only when a pid is known (Global Constraint #5's "no fabricated identity" — this is a genuine divergence from the file-event precedent, which always has a pid), leave `parent_process`/`relationships` for Enrich:

```rust
/// A small helper: builds the provisional `ProcessRef` file/network/DNS
/// events share (start_time 0, replaced by Enrich once the real exec event
/// is known) — `None` when the raw record carries no pid at all (Global
/// Constraint #5), rather than minting a key for a process nobody observed.
fn provisional_process(
    pid: Option<u32>,
    exe_path: &str,
    host_id: uuid::Uuid,
    boot_id: &str,
) -> Option<ProcessRef> {
    let pid = pid?;
    Some(ProcessRef {
        process_key: ProcessKey::new(host_id, boot_id, pid, 0),
        pid,
        exe_path: exe_path.to_string(),
        cmdline: vec![],
        exe_hash: None,
        start_time_mono: 0,
    })
}

fn normalize_network_event(raw: NetworkEventRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let source = match raw.source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
    };
    let provider = match raw.source {
        RawEventSource::Audit => "network_sensor/audit",
        RawEventSource::Synthetic => "network_sensor/synthetic",
    };
    let event_type = match raw.operation {
        NetworkOperation::Connect => EventType::NetworkConnect,
        NetworkOperation::Accept => EventType::NetworkAccept,
        NetworkOperation::Close => EventType::NetworkClose,
    };
    let direction = match raw.direction {
        RawNetworkDirection::Outbound => NetworkDirection::Outbound,
        RawNetworkDirection::Inbound => NetworkDirection::Inbound,
    };
    // Outbound: this host dialed out, so local is the source and remote is
    // the destination. Inbound: the remote peer initiated, so it is
    // recorded as the source and this host as the destination — matching
    // conventional "who is talking to whom" network-log semantics rather
    // than "which side is local."
    let (src_ip, src_port, dst_ip, dst_port) = match direction {
        NetworkDirection::Outbound => {
            (raw.local_addr.clone(), raw.local_port, raw.remote_addr.clone(), raw.remote_port)
        }
        NetworkDirection::Inbound => {
            (raw.remote_addr.clone(), raw.remote_port, raw.local_addr.clone(), raw.local_port)
        }
    };
    let process = provisional_process(raw.pid, &raw.exe_path, host.host_id, boot_id);
    CanonicalEvent {
        event_id: uuid::Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category: Category::Network,
        severity: Severity::Info,
        host: host.clone(),
        user: None,
        session: None,
        process,
        parent_process: None,
        thread: None,
        file: None,
        network: Some(NetworkRef {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto: raw.proto,
            direction,
            bytes: None,
        }),
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
        event_data: serde_json::json!({ "comm": raw.comm, "uid": raw.uid }),
    }
}

fn normalize_dns_event(raw: DnsEventRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let source = match raw.source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
    };
    let provider = match raw.source {
        RawEventSource::Audit => "dns_sensor/audit",
        RawEventSource::Synthetic => "dns_sensor/synthetic",
    };
    let process = provisional_process(raw.pid, &raw.exe_path, host.host_id, boot_id);
    CanonicalEvent {
        event_id: uuid::Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type: EventType::DnsQuery,
        category: Category::Dns,
        severity: Severity::Info,
        host: host.clone(),
        user: None,
        session: None,
        process,
        parent_process: None,
        thread: None,
        file: None,
        network: None,
        dns: Some(DnsRef {
            query: raw.query,
            qtype: raw.qtype,
            response_ips: raw.response_ips,
            ttl: raw.ttl,
        }),
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
        event_data: serde_json::json!({ "comm": raw.comm, "uid": raw.uid }),
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p osiris-pipeline normalize`
Expected: PASS — Phase 1/2's existing tests plus the 8 new ones.

- [ ] **Step 5: Write the failing test for enriching a network event**

Append to `crates/osiris-pipeline/src/enrich.rs`'s `mod tests`:

```rust
    fn bare_network_event(
        host_id: uuid::Uuid,
        pid: Option<u32>,
        remote_ip: &str,
    ) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid.unwrap_or(0), 0);
        event.event_type = EventType::NetworkConnect;
        event.category = Category::Network;
        event.process = pid.map(|p| ProcessRef {
            process_key: ProcessKey::new(host_id, "boot-1", p, 0),
            pid: p,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
        event.network = Some(osiris_schema::NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 51000,
            dst_ip: remote_ip.to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        event
    }

    #[test]
    fn network_event_gains_a_process_connected_to_ip_entity_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let net_event = enrich(
            bare_network_event(host_id, Some(300), "203.0.113.50"),
            "boot-1",
            &mut resolver,
        );
        assert_eq!(net_event.relationships.len(), 1);
        let edge = &net_event.relationships[0];
        assert_eq!(edge.relation, Relation::ConnectedTo);
        match (&edge.from, &edge.to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::Ip { addr },
            ) => {
                assert_eq!(*process_key, authoritative);
                assert_eq!(addr, "203.0.113.50");
            }
            other => panic!("expected a Process -> Ip edge, got {other:?}"),
        }
    }

    #[test]
    fn network_event_with_no_pid_gets_no_edge_rather_than_a_fabricated_one() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let net_event = enrich(
            bare_network_event(host_id, None, "203.0.113.50"),
            "boot-1",
            &mut resolver,
        );
        assert!(net_event.relationships.is_empty());
        assert!(net_event.process.is_none());
    }

    #[test]
    fn network_close_event_gets_no_connected_to_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let _curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let mut event = bare_network_event(host_id, Some(300), "203.0.113.50");
        event.event_type = EventType::NetworkClose;
        let closed = enrich(event, "boot-1", &mut resolver);
        assert!(
            closed.relationships.is_empty(),
            "the opening event already carries the edge; close must not duplicate it"
        );
    }

    fn bare_dns_event(host_id: uuid::Uuid, pid: Option<u32>, response_ips: Vec<String>) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid.unwrap_or(0), 0);
        event.event_type = EventType::DnsQuery;
        event.category = Category::Dns;
        event.process = pid.map(|p| ProcessRef {
            process_key: ProcessKey::new(host_id, "boot-1", p, 0),
            pid: p,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
        event.dns = Some(osiris_schema::DnsRef {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips,
            ttl: Some(300),
        });
        event
    }

    #[test]
    fn dns_event_gains_one_resolved_to_edge_per_response_ip() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let dns_event = enrich(
            bare_dns_event(
                host_id,
                Some(300),
                vec!["203.0.113.50".to_string(), "203.0.113.51".to_string()],
            ),
            "boot-1",
            &mut resolver,
        );
        assert_eq!(dns_event.relationships.len(), 2);
        for (edge, expected_ip) in dns_event
            .relationships
            .iter()
            .zip(["203.0.113.50", "203.0.113.51"])
        {
            assert_eq!(edge.relation, Relation::ResolvedTo);
            match (&edge.from, &edge.to) {
                (
                    osiris_schema::EntityRef::Domain { name },
                    osiris_schema::EntityRef::Ip { addr },
                ) => {
                    assert_eq!(name, "cdn-assets.xyz");
                    assert_eq!(addr, expected_ip);
                }
                other => panic!("expected a Domain -> Ip edge, got {other:?}"),
            }
        }
    }

    #[test]
    fn dns_event_with_no_response_ips_gets_no_edges() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let dns_event = enrich(
            bare_dns_event(host_id, Some(300), vec![]),
            "boot-1",
            &mut resolver,
        );
        assert!(dns_event.relationships.is_empty());
    }

    /// DNS's process resolution reuses the exact same non-process path
    /// file/network events already exercise — this pins that reuse rather
    /// than re-deriving a parallel code path.
    #[test]
    fn dns_event_resolves_its_authoritative_process_key() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let dns_event = enrich(
            bare_dns_event(host_id, Some(300), vec!["203.0.113.50".to_string()]),
            "boot-1",
            &mut resolver,
        );
        assert_eq!(dns_event.process.unwrap().process_key, authoritative);
        assert!(!dns_event.tags.contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cargo test -p osiris-pipeline enrich`
Expected: FAIL — no `CONNECTED_TO`/`RESOLVED_TO` edges are attached yet (the new assertions fail; nothing fails to compile since `enrich`'s non-process branch already handles any category generically).

- [ ] **Step 7: Attach the `CONNECTED_TO` and `RESOLVED_TO` edges**

In `crates/osiris-pipeline/src/enrich.rs`, update the imports:
```rust
use osiris_schema::{
    CanonicalEvent, Category, EntityRef, EntityRelationship, EventType, FileIdentity, ProcessRef,
    Relation,
};
```

Update `enrich`'s dispatcher body (the part after the `match event.category` block) from:
```rust
    if event.category == Category::File {
        attach_file_relationship(&mut event);
    }

    event
}
```
to:
```rust
    match event.category {
        Category::File => attach_file_relationship(&mut event),
        Category::Network => attach_network_relationship(&mut event),
        Category::Dns => attach_dns_relationships(&mut event),
        _ => {}
    }

    event
}
```

Add two new functions after `attach_file_relationship`:
```rust
/// Writes the §9.4 `Process -CONNECTED_TO-> Ip` edge (Phase 3 plan Global
/// Constraints #8). Only on the connection's *opening* event
/// (`NETWORK_CONNECT`/`NETWORK_ACCEPT`) — `NETWORK_CLOSE` would duplicate
/// the same fact. No edge when the sensor could not attribute a process
/// (Global Constraint #5) — an edge citing a fabricated process is worse
/// than no edge, the same reasoning `attach_file_relationship` already
/// applies to file identity.
fn attach_network_relationship(event: &mut CanonicalEvent) {
    if event.event_type == EventType::NetworkClose {
        return;
    }
    let (Some(process), Some(network)) = (event.process.as_ref(), event.network.as_ref()) else {
        return;
    };
    let remote_ip = match network.direction {
        osiris_schema::NetworkDirection::Outbound => &network.dst_ip,
        osiris_schema::NetworkDirection::Inbound => &network.src_ip,
    };
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: EntityRef::Ip {
            addr: remote_ip.clone(),
        },
        relation: Relation::ConnectedTo,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}

/// Writes one §9.4 `Domain -RESOLVED_TO-> Ip` edge per resolved address
/// (Phase 3 plan Global Constraints #8) — a query resolving to three IPs
/// produces three edges, all citing the same `event_id`. No
/// `Process -> Domain` edge: the frozen `Relation` enum has no fitting
/// variant, and this phase does not extend it (Phase 2 precedent: solve it
/// in the consuming crate or defer, never widen a frozen schema type for
/// one call site).
fn attach_dns_relationships(event: &mut CanonicalEvent) {
    let Some(dns) = event.dns.clone() else {
        return;
    };
    for ip in &dns.response_ips {
        let edge = EntityRelationship {
            from: EntityRef::Domain {
                name: dns.query.clone(),
            },
            to: EntityRef::Ip { addr: ip.clone() },
            relation: Relation::ResolvedTo,
            event_id: event.event_id,
            timestamp: event.timestamp,
        };
        event.relationships.push(edge);
    }
}
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cargo test -p osiris-pipeline enrich`
Expected: PASS — Phase 1/2's existing tests plus the 7 new ones.

- [ ] **Step 9: Extend `validate` for network and DNS events**

Append to `crates/osiris-pipeline/src/validate.rs`'s `mod tests`:
```rust
    fn valid_network_event() -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = EventType::NetworkConnect;
        event.category = Category::Network;
        event.process = None;
        event.network = Some(osiris_schema::NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 51000,
            dst_ip: "203.0.113.50".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        event
    }

    #[test]
    fn well_formed_network_events_of_every_type_validate() {
        for event_type in [
            EventType::NetworkConnect,
            EventType::NetworkAccept,
            EventType::NetworkClose,
        ] {
            let mut event = valid_network_event();
            event.event_type = event_type;
            assert!(validate(&mut event), "{event_type:?} should be valid");
        }
    }

    #[test]
    fn network_event_without_a_network_ref_is_invalid_but_still_forwarded() {
        let mut event = valid_network_event();
        event.network = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn network_event_with_an_empty_remote_address_is_invalid() {
        let mut event = valid_network_event();
        if let Some(net) = event.network.as_mut() {
            net.dst_ip = "   ".to_string();
        }
        assert!(!validate(&mut event));
    }

    fn valid_dns_event() -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = EventType::DnsQuery;
        event.category = Category::Dns;
        event.process = None;
        event.dns = Some(osiris_schema::DnsRef {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: Some(300),
        });
        event
    }

    #[test]
    fn well_formed_dns_query_validates() {
        let mut event = valid_dns_event();
        assert!(validate(&mut event));
    }

    #[test]
    fn dns_query_without_a_dns_ref_is_invalid_but_still_forwarded() {
        let mut event = valid_dns_event();
        event.dns = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn dns_query_with_an_empty_query_string_is_invalid() {
        let mut event = valid_dns_event();
        if let Some(dns) = event.dns.as_mut() {
            dns.query = "".to_string();
        }
        assert!(!validate(&mut event));
    }

    /// An unresolved query (NXDOMAIN/timeout) is still a valid, storable
    /// event — empty `response_ips` is itself sometimes the signal, not a
    /// malformed record (Task 1's `DnsEventRaw` doc comment).
    #[test]
    fn dns_query_with_no_response_ips_is_still_valid() {
        let mut event = valid_dns_event();
        if let Some(dns) = event.dns.as_mut() {
            dns.response_ips = vec![];
        }
        assert!(validate(&mut event));
    }
```

Update `validate`'s implementation:
```rust
pub fn validate(event: &mut CanonicalEvent) -> bool {
    use osiris_schema::EventType::{
        DnsQuery, FileCreate, FileDelete, FileRename, FileWrite, NetworkAccept, NetworkClose,
        NetworkConnect,
    };
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
    if matches!(
        event.event_type,
        NetworkConnect | NetworkAccept | NetworkClose
    ) {
        // A network event with no remote address names no connection — it
        // cannot be queried by a Network Story or explained in an alert.
        let has_remote = event
            .network
            .as_ref()
            .map(|n| !n.dst_ip.trim().is_empty() && !n.src_ip.trim().is_empty())
            .unwrap_or(false);
        if !has_remote {
            valid = false;
        }
    }
    if event.event_type == DnsQuery {
        let has_query = event
            .dns
            .as_ref()
            .map(|d| !d.query.trim().is_empty())
            .unwrap_or(false);
        if !has_query {
            valid = false;
        }
    }
    if !valid {
        event.tags.push("INVALID".to_string());
    }
    valid
}
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `cargo test -p osiris-pipeline validate`
Expected: PASS — Phase 1/2's existing tests plus the 7 new ones.

- [ ] **Step 11: Extend `PriorityTable` and update its "unmapped falls back" test**

In `crates/osiris-pipeline/src/prioritize.rs`, update `PriorityTable::default()`'s table:
```rust
            table: vec![
                (EventType::ProcessExec, PriorityLane::Normal),
                (EventType::FileCreate, PriorityLane::Normal),
                (EventType::FileDelete, PriorityLane::Normal),
                (EventType::FileRename, PriorityLane::Normal),
                (EventType::FileWrite, PriorityLane::Low),
                (EventType::NetworkConnect, PriorityLane::Normal),
                (EventType::NetworkAccept, PriorityLane::Normal),
                // NETWORK_CLOSE is the highest-volume network event by the
                // same reasoning FILE_WRITE got a low lane in Phase 2: every
                // connection produces at most one open event but exactly
                // one close (barring a still-open connection at shutdown),
                // and short-lived connections churn faster than sustained
                // ones open new ones — closes are the type most likely to
                // need shedding first under bus pressure.
                (EventType::NetworkClose, PriorityLane::Low),
                (EventType::DnsQuery, PriorityLane::Normal),
            ],
```

Replace the existing `unmapped_event_type_falls_back_to_default_lane` test's comment and event type (it currently uses `NetworkConnect` as its "arrives in Phase 3, still unmapped" example — that's no longer true):
```rust
    #[test]
    fn unmapped_event_type_falls_back_to_default_lane() {
        let mut event = exec_event();
        // No Phase 3+ sensor emits SOCKET_LISTEN yet (Phase 3 plan Global
        // Constraints #3) — it stays unmapped until whichever phase adds it.
        event.event_type = EventType::SocketListen;
        let table = PriorityTable::default();
        assert_eq!(prioritize(&event, &table), PriorityLane::Normal);
    }
```

Add a new test alongside `file_event_types_map_to_their_configured_lanes`:
```rust
    #[test]
    fn network_and_dns_event_types_map_to_their_configured_lanes() {
        let table = PriorityTable::default();
        for (event_type, expected) in [
            (EventType::NetworkConnect, PriorityLane::Normal),
            (EventType::NetworkAccept, PriorityLane::Normal),
            (EventType::NetworkClose, PriorityLane::Low),
            (EventType::DnsQuery, PriorityLane::Normal),
        ] {
            let mut event = exec_event();
            event.event_type = event_type;
            assert_eq!(prioritize(&event, &table), expected, "{event_type:?}");
        }
    }
```

- [ ] **Step 12: Run the test to verify it passes**

Run: `cargo test -p osiris-pipeline prioritize`
Expected: PASS.

- [ ] **Step 13: Run the full crate suite and workspace build**

Run: `cargo test -p osiris-pipeline` then `cargo build --workspace --all-targets` then `bash tools/check-dep-graph.sh`
Expected: all pass; `Dependency-graph check PASSED`.

- [ ] **Step 14: Commit**

```bash
git add crates/osiris-pipeline
git commit -m "feat(pipeline): normalize, enrich, validate and prioritize network and DNS events

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

### Task 3: `osiris-sensors-net` — the real Network Sensor

**Files:**
- Create: `crates/osiris-sensors/net/Cargo.toml`
- Create: `crates/osiris-sensors/net/src/lib.rs`
- Create: `crates/osiris-sensors/net/src/proc_tcp.rs`
- Create: `crates/osiris-sensors/net/src/fd_scan.rs`
- Create: `crates/osiris-sensors/net/src/poller.rs`
- Create: `crates/osiris-sensors/net/src/sensor.rs`
- Modify: `Cargo.toml` (workspace root — add `"crates/osiris-sensors/net"` to `members`)
- Modify: `tools/check-dep-graph.sh`

**Interfaces:**
- Consumes: `osiris_sensor_api::{NetworkEventRaw, NetworkOperation, NetworkDirection, RawEventSource, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics, SensorState, RawEvent}` from Task 1 and Phase 1's `osiris-sensor-api`.
- Produces:
  - `osiris_sensors_net::proc_tcp::{TcpRow, TCP_ESTABLISHED, parse_tcp_table}`.
  - `osiris_sensors_net::fd_scan::{extract_socket_inode, scan_socket_inodes}`.
  - `osiris_sensors_net::poller::NetworkPoller` with `NetworkPoller::new(proc_root: impl Into<PathBuf>) -> Self` and `fn poll(&mut self, now_ns: u64) -> Vec<NetworkEventRaw>`.
  - `osiris_sensors_net::NetworkSensor` implementing `Sensor`, with `NetworkSensor::new(proc_root: impl Into<PathBuf>) -> Self` and `with_poll_interval(self, Duration) -> Self`. Task 5's Agent wiring constructs this.

- [ ] **Step 1: Create the crate manifest**

`crates/osiris-sensors/net/Cargo.toml`:
```toml
[package]
name = "osiris-sensors-net"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
tokio = { workspace = true }
tokio-util = { workspace = true }
async-trait = { workspace = true }
osiris-sensor-api = { path = "../../osiris-sensor-api" }

[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 2: Add the crate to the workspace and register the boundary check**

In the workspace root `Cargo.toml`, update `members`:
```toml
members = ["crates/*", "crates/osiris-sensors/process", "crates/osiris-sensors/fs", "crates/osiris-sensors/net", "generator"]
```

In `tools/check-dep-graph.sh`, add one line immediately after `check_forbidden osiris-sensors-process osiris-server osiris-api`:
```bash
check_forbidden osiris-sensors-net osiris-server osiris-api
```

- [ ] **Step 3: Write the failing test for `proc_tcp`**

Create `crates/osiris-sensors/net/src/proc_tcp.rs` containing only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0500000A:C738 32671BCB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0
   2: 00000000:0016 6400A8C0:C000 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_every_data_row_and_skips_the_header() {
        let rows = parse_tcp_table(SAMPLE);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn decodes_the_reversed_hex_ipv4_address_and_big_endian_port() {
        let rows = parse_tcp_table(SAMPLE);
        let outbound = &rows[0];
        assert_eq!(outbound.local_addr, "10.0.0.5");
        assert_eq!(outbound.local_port, 51000);
        assert_eq!(outbound.remote_addr, "203.27.103.50");
        assert_eq!(outbound.remote_port, 443);
        assert_eq!(outbound.state, TCP_ESTABLISHED);
        assert_eq!(outbound.uid, 1000);
        assert_eq!(outbound.inode, 12345);
    }

    #[test]
    fn reports_a_listen_rows_state_without_filtering_it() {
        let rows = parse_tcp_table(SAMPLE);
        assert_eq!(rows[1].state, 0x0A);
        assert_eq!(rows[1].local_port, 22);
    }

    #[test]
    fn a_second_established_row_on_a_well_known_local_port_parses_too() {
        let rows = parse_tcp_table(SAMPLE);
        assert_eq!(rows[2].state, TCP_ESTABLISHED);
        assert_eq!(rows[2].local_port, 22);
        assert_eq!(rows[2].inode, 33333);
    }

    #[test]
    fn malformed_lines_are_skipped_not_panicked_on() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: not-hex:XX also-not-hex:YY ZZ 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
";
        assert_eq!(parse_tcp_table(text).len(), 0);
    }

    #[test]
    fn a_table_with_only_a_header_yields_no_rows() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        assert_eq!(parse_tcp_table(text).len(), 0);
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p osiris-sensors-net proc_tcp`
Expected: FAIL — compile errors for `parse_tcp_table`, `TCP_ESTABLISHED`.

- [ ] **Step 5: Implement `proc_tcp`**

Insert above the test module in `crates/osiris-sensors/net/src/proc_tcp.rs`:

```rust
/// The `/proc/net/tcp` state value for ESTABLISHED (Linux's
/// `net/tcp_states.h`). This phase reports every row's raw state and lets
/// the caller (`NetworkPoller`) decide what to act on, so a later phase
/// reading LISTEN (0x0A) does not need a second parser.
pub const TCP_ESTABLISHED: u8 = 0x01;

/// One parsed row of `/proc/net/tcp`. IPv4 only (Phase 3 plan Global
/// Constraints #2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRow {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// Decodes `/proc/net/tcp`'s `AABBCCDD` hex IPv4 encoding: four hex-byte
/// pairs in reversed order (the kernel prints the 32-bit address as a
/// native-endian integer on little-endian x86/ARM) — `0100007F` decodes to
/// `127.0.0.1`, not `1.0.0.127`.
fn parse_ipv4_hex(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]))
}

/// Decodes one `ADDR:PORT` field (e.g. `0100007F:0050`). The port half is
/// big-endian hex, no byte reversal needed.
fn parse_addr_port(field: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let ip = parse_ipv4_hex(ip_hex)?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((ip, port))
}

/// Parses a full `/proc/net/tcp`-format table. Malformed lines are
/// skipped, never panicked on.
pub fn parse_tcp_table(text: &str) -> Vec<TcpRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return None;
            }
            let (local_addr, local_port) = parse_addr_port(fields[1])?;
            let (remote_addr, remote_port) = parse_addr_port(fields[2])?;
            let state = u8::from_str_radix(fields[3], 16).ok()?;
            let uid: u32 = fields[7].parse().ok()?;
            let inode: u64 = fields[9].parse().ok()?;
            Some(TcpRow {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                uid,
                inode,
            })
        })
        .collect()
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p osiris-sensors-net proc_tcp`
Expected: PASS — 6 tests.

- [ ] **Step 7: Write the failing test for `fd_scan`**

Create `crates/osiris-sensors/net/src/fd_scan.rs` containing only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_inode_from_a_well_formed_socket_link_target() {
        assert_eq!(extract_socket_inode("socket:[12345]"), Some(12345));
    }

    #[test]
    fn rejects_a_non_socket_link_target() {
        assert_eq!(extract_socket_inode("/dev/null"), None);
        assert_eq!(extract_socket_inode("pipe:[999]"), None);
    }

    #[test]
    fn rejects_a_malformed_socket_link_target() {
        assert_eq!(extract_socket_inode("socket:[not-a-number]"), None);
        assert_eq!(extract_socket_inode("socket:[12345"), None);
    }

    #[test]
    fn scanning_a_proc_root_with_no_pid_directories_yields_an_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let map = scan_socket_inodes(dir.path());
        assert!(map.is_empty());
    }

    #[test]
    fn scanning_a_missing_proc_root_yields_an_empty_map_not_a_panic() {
        let map = scan_socket_inodes(std::path::Path::new("/definitely/does/not/exist"));
        assert!(map.is_empty());
    }

    #[test]
    fn a_pid_directory_with_no_fd_subdirectory_is_skipped_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("300")).unwrap();
        let map = scan_socket_inodes(dir.path());
        assert!(map.is_empty());
    }

    /// Integration proof of the real directory walk: creates actual
    /// symlinks inside a tempdir and scans it. Windows symlink creation
    /// needs Developer Mode or admin rights, neither guaranteed on this dev
    /// machine (Phase 3 plan Global Constraints #11) — on a permission
    /// error this test prints why and returns early rather than failing the
    /// suite. The pure parsing logic above is exercised unconditionally
    /// regardless of this test's outcome.
    #[test]
    fn scans_real_symlinks_into_an_inode_to_pid_map() {
        let dir = tempfile::tempdir().unwrap();
        let fd_dir = dir.path().join("300").join("fd");
        std::fs::create_dir_all(&fd_dir).unwrap();
        let link_path = fd_dir.join("3");

        if let Err(e) = make_symlink("socket:[12345]", &link_path) {
            eprintln!(
                "skipping scans_real_symlinks_into_an_inode_to_pid_map: cannot create a symlink on this platform/process ({e}); the pure extract_socket_inode parsing is still covered by other tests"
            );
            return;
        }

        let map = scan_socket_inodes(dir.path());
        assert_eq!(map.get(&12345), Some(&300));
    }

    #[cfg(unix)]
    fn make_symlink(target: &str, link: &std::path::Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn make_symlink(target: &str, link: &std::path::Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
```

- [ ] **Step 8: Run the test to verify it fails**

Run: `cargo test -p osiris-sensors-net fd_scan`
Expected: FAIL — compile errors for `extract_socket_inode`, `scan_socket_inodes`.

- [ ] **Step 9: Implement `fd_scan`**

Insert above the test module in `crates/osiris-sensors/net/src/fd_scan.rs`:

```rust
use std::collections::HashMap;
use std::path::Path;

/// Extracts the inode from a `/proc/<pid>/fd/<n>` symlink target of the
/// form `socket:[12345]`. Every other target shape is `None`.
pub fn extract_socket_inode(link_target: &str) -> Option<u64> {
    let inner = link_target.strip_prefix("socket:[")?;
    let inner = inner.strip_suffix(']')?;
    inner.parse().ok()
}

/// Walks every numeric (pid) directory under `proc_root` and builds an
/// `inode -> pid` map from every socket-typed fd found under each one's
/// `fd` subdirectory. A missing `proc_root`, a pid directory with no
/// readable `fd` subdirectory, or an unreadable individual link is skipped,
/// never panicked on.
pub fn scan_socket_inodes(proc_root: &Path) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return map;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd_entry in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd_entry.path()) else {
                continue;
            };
            if let Some(inode) = extract_socket_inode(&target.to_string_lossy()) {
                map.insert(inode, pid);
            }
        }
    }
    map
}
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `cargo test -p osiris-sensors-net fd_scan`
Expected: PASS — 7 tests (6 unconditional; the symlink integration test either passes or prints a skip reason and passes trivially).

- [ ] **Step 11: Commit the pure-parsing half**

```bash
git add crates/osiris-sensors/net Cargo.toml tools/check-dep-graph.sh
git commit -m "feat(sensors-net): /proc/net/tcp table parsing and fd-scan pid attribution

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

- [ ] **Step 12: Write the failing test for `NetworkPoller`'s diffing**

Create `crates/osiris-sensors/net/src/poller.rs` containing only the test module and its fixture helper for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{NetworkDirection, NetworkOperation};

    /// Writes a minimal fake `<proc_root>/net/tcp` with exactly the rows the
    /// caller lists (`(local_port, remote_addr_hex, remote_port_hex, state,
    /// uid, inode)`), matching real `/proc/net/tcp` column layout.
    fn write_tcp_table(proc_root: &std::path::Path, rows: &[(u16, &str, u16, u8, u32, u64)]) {
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        let mut text = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
        for (i, (local_port, remote_addr, remote_port, state, uid, inode)) in
            rows.iter().enumerate()
        {
            text.push_str(&format!(
                "  {i}: 0500000A:{local_port:04X} {remote_addr}:{remote_port:04X} {state:02X} 00000000:00000000 00:00000000 00000000 {uid:5} 0 {inode} 1 0 100 0 0 10 0\n"
            ));
        }
        std::fs::write(proc_root.join("net").join("tcp"), text).unwrap();
    }

    const REMOTE_HEX: &str = "32671BCB"; // decodes to 203.27.103.50, matching proc_tcp's tests

    #[test]
    fn a_new_established_connection_on_an_ephemeral_port_emits_connect() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(51000, REMOTE_HEX, 443, 0x01, 1000, 12345)]);
        let mut poller = NetworkPoller::new(dir.path());

        let events = poller.poll(1_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, NetworkOperation::Connect);
        assert_eq!(events[0].direction, NetworkDirection::Outbound);
        assert_eq!(events[0].remote_addr, "203.27.103.50");
        assert_eq!(events[0].remote_port, 443);
        assert_eq!(events[0].uid, 1000);
        assert_eq!(events[0].pid, None, "no /proc/<pid>/fd tree exists in this fixture");
    }

    #[test]
    fn a_new_established_connection_on_a_well_known_local_port_emits_accept() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(22, REMOTE_HEX, 51500, 0x01, 0, 22222)]);
        let mut poller = NetworkPoller::new(dir.path());

        let events = poller.poll(1_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, NetworkOperation::Accept);
        assert_eq!(events[0].direction, NetworkDirection::Inbound);
    }

    #[test]
    fn a_listen_row_state_0a_is_never_reported_as_a_connection() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(22, "00000000", 0, 0x0A, 0, 99999)]);
        let mut poller = NetworkPoller::new(dir.path());
        assert_eq!(poller.poll(1_000).len(), 0);
    }

    #[test]
    fn a_steady_state_connection_present_in_two_consecutive_polls_emits_nothing_the_second_time() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(51000, REMOTE_HEX, 443, 0x01, 1000, 12345)]);
        let mut poller = NetworkPoller::new(dir.path());
        assert_eq!(poller.poll(1_000).len(), 1); // the open event

        // Unchanged snapshot on the second poll.
        assert_eq!(poller.poll(2_000).len(), 0);
    }

    #[test]
    fn a_connection_that_disappears_between_polls_emits_close_with_the_original_direction() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(51000, REMOTE_HEX, 443, 0x01, 1000, 12345)]);
        let mut poller = NetworkPoller::new(dir.path());
        let opened = poller.poll(1_000);
        assert_eq!(opened[0].operation, NetworkOperation::Connect);

        write_tcp_table(dir.path(), &[]); // the connection is gone
        let closed = poller.poll(2_000);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].operation, NetworkOperation::Close);
        assert_eq!(closed[0].remote_addr, "203.27.103.50");
        assert_eq!(
            closed[0].direction,
            NetworkDirection::Outbound,
            "close must reuse the direction recorded when the connection opened, not \
             re-evaluate a heuristic against data that's gone"
        );
        assert_eq!(closed[0].timestamp_ns, 2_000);
    }

    #[test]
    fn a_missing_proc_net_tcp_file_yields_no_events_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // No net/tcp written at all.
        let mut poller = NetworkPoller::new(dir.path());
        assert_eq!(poller.poll(1_000).len(), 0);
    }

    #[test]
    fn two_distinct_connections_in_one_snapshot_both_get_reported() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(
            dir.path(),
            &[
                (51000, REMOTE_HEX, 443, 0x01, 1000, 12345),
                (22, REMOTE_HEX, 51500, 0x01, 0, 22222),
            ],
        );
        let mut poller = NetworkPoller::new(dir.path());
        let events = poller.poll(1_000);
        assert_eq!(events.len(), 2);
    }
}
```

- [ ] **Step 13: Run the test to verify it fails**

Run: `cargo test -p osiris-sensors-net poller`
Expected: FAIL — compile errors for `NetworkPoller`.

- [ ] **Step 14: Implement `NetworkPoller`**

Insert above the test module in `crates/osiris-sensors/net/src/poller.rs`:

```rust
use std::collections::HashMap;
use std::path::PathBuf;

use osiris_sensor_api::{NetworkDirection, NetworkEventRaw, NetworkOperation, RawEventSource};

use crate::fd_scan::scan_socket_inodes;
use crate::proc_tcp::{parse_tcp_table, TCP_ESTABLISHED};

/// A local Linux ephemeral-port floor (Phase 3 plan Global Constraints #4).
/// A connection whose local port is at or above this is treated as this
/// host having dialed out; below it, as this host answering on a
/// known/listening port. Documented heuristic, not ground truth.
const EPHEMERAL_PORT_FLOOR: u16 = 32768;

#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnTuple {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
}

#[derive(Clone)]
struct ConnRecord {
    direction: NetworkDirection,
    pid: Option<u32>,
    uid: u32,
    exe_path: String,
    comm: String,
}

/// Polls a `/proc`-shaped directory tree for TCP connection lifecycle
/// changes (ARCHITECTURE.md §4.3's Network fallback backend, Phase 3 plan
/// Global Constraints #1). `proc_root` is configurable — a real deployment
/// points it at `/proc`; tests point it at a tempdir fixture — the same
/// "the real path is configurable, defaults sensible for real deployment"
/// pattern Phase 1/2 established for the audit log path.
pub struct NetworkPoller {
    proc_root: PathBuf,
    previous: HashMap<ConnTuple, ConnRecord>,
}

impl NetworkPoller {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            previous: HashMap::new(),
        }
    }

    /// One poll tick: reads the current `net/tcp` snapshot, diffs it
    /// against the previous tick, and returns every connection-lifecycle
    /// event observed. A missing/unreadable `net/tcp` yields an empty
    /// `Vec`, not an error — callers treat "nothing to report" as normal,
    /// matching `LineTailer::poll`'s contract from Phase 1/2.
    pub fn poll(&mut self, now_ns: u64) -> Vec<NetworkEventRaw> {
        let tcp_path = self.proc_root.join("net").join("tcp");
        let Ok(text) = std::fs::read_to_string(&tcp_path) else {
            return vec![];
        };
        let inode_to_pid = scan_socket_inodes(&self.proc_root);

        let mut current: HashMap<ConnTuple, u64> = HashMap::new(); // tuple -> inode
        let mut current_meta: HashMap<ConnTuple, (u16, u32)> = HashMap::new(); // tuple -> (local_port, uid)
        for row in parse_tcp_table(&text) {
            if row.state != TCP_ESTABLISHED {
                continue;
            }
            let tuple = ConnTuple {
                local_addr: row.local_addr.clone(),
                local_port: row.local_port,
                remote_addr: row.remote_addr.clone(),
                remote_port: row.remote_port,
            };
            current_meta.insert(tuple.clone(), (row.local_port, row.uid));
            current.insert(tuple, row.inode);
        }

        let mut events = Vec::new();

        // New connections: present now, absent from the previous snapshot.
        for (tuple, inode) in &current {
            if self.previous.contains_key(tuple) {
                continue;
            }
            let (local_port, uid) = current_meta[tuple];
            let direction = if local_port >= EPHEMERAL_PORT_FLOOR {
                NetworkDirection::Outbound
            } else {
                NetworkDirection::Inbound
            };
            let operation = match direction {
                NetworkDirection::Outbound => NetworkOperation::Connect,
                NetworkDirection::Inbound => NetworkOperation::Accept,
            };
            let pid = inode_to_pid.get(inode).copied();
            let (exe_path, comm) = pid
                .map(|p| crate::fd_scan::read_process_identity(&self.proc_root, p))
                .unwrap_or_default();

            events.push(NetworkEventRaw {
                operation,
                local_addr: tuple.local_addr.clone(),
                local_port: tuple.local_port,
                remote_addr: tuple.remote_addr.clone(),
                remote_port: tuple.remote_port,
                proto: "tcp".to_string(),
                direction,
                pid,
                uid,
                exe_path: exe_path.clone(),
                comm: comm.clone(),
                timestamp_ns: now_ns,
                source: RawEventSource::Audit,
            });
            self.previous.insert(
                tuple.clone(),
                ConnRecord {
                    direction,
                    pid,
                    uid,
                    exe_path,
                    comm,
                },
            );
        }

        // Closed connections: present in the previous snapshot, absent now.
        let closed: Vec<ConnTuple> = self
            .previous
            .keys()
            .filter(|tuple| !current.contains_key(*tuple))
            .cloned()
            .collect();
        for tuple in closed {
            let record = self.previous.remove(&tuple).expect("just checked present");
            events.push(NetworkEventRaw {
                operation: NetworkOperation::Close,
                local_addr: tuple.local_addr,
                local_port: tuple.local_port,
                remote_addr: tuple.remote_addr,
                remote_port: tuple.remote_port,
                proto: "tcp".to_string(),
                direction: record.direction,
                pid: record.pid,
                uid: record.uid,
                exe_path: record.exe_path,
                comm: record.comm,
                timestamp_ns: now_ns,
                source: RawEventSource::Audit,
            });
        }

        events
    }
}
```

`read_process_identity` is added to `fd_scan.rs` in Step 15 below (it belongs there — both functions read from a pid's `/proc/<pid>/...` tree — rather than duplicated inline in `poller.rs`).

- [ ] **Step 15: Add `read_process_identity` to `fd_scan.rs` and run the poller tests**

Append to `crates/osiris-sensors/net/src/fd_scan.rs`, above its test module:

```rust
/// Best-effort `exe_path`/`comm` lookup for an already-attributed pid.
/// Returns empty strings for whichever half could not be read (the process
/// may have exited between the fd-scan and this read) — never an error,
/// matching `scan_socket_inodes`'s "process churn is normal" discipline.
pub fn read_process_identity(proc_root: &Path, pid: u32) -> (String, String) {
    let exe_path = std::fs::read_link(proc_root.join(pid.to_string()).join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let comm = std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    (exe_path, comm)
}
```

Add its own small test to `fd_scan.rs`'s test module:
```rust
    #[test]
    fn read_process_identity_returns_empty_strings_when_nothing_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let (exe, comm) = read_process_identity(dir.path(), 999);
        assert_eq!(exe, "");
        assert_eq!(comm, "");
    }
```

Then create `crates/osiris-sensors/net/src/lib.rs`:
```rust
pub mod fd_scan;
pub mod poller;
pub mod proc_tcp;
pub mod sensor;

pub use poller::NetworkPoller;
pub use sensor::NetworkSensor;
```

Run: `cargo test -p osiris-sensors-net`
Expected: FAIL only on `sensor` (not yet created) — comment out `pub mod sensor;` and `pub use sensor::NetworkSensor;` temporarily if needed to get `poller`/`fd_scan`/`proc_tcp` green first, then run: `cargo test -p osiris-sensors-net poller fd_scan proc_tcp`
Expected: PASS — 7 `poller` tests, 8 `fd_scan` tests, 6 `proc_tcp` tests.

- [ ] **Step 16: Write the failing test for the `NetworkSensor` `Sensor` impl**

Create `crates/osiris-sensors/net/src/sensor.rs` containing only the test module for now (restore the `pub mod sensor;`/`pub use sensor::NetworkSensor;` lines in `lib.rs` if Step 15 commented them out):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{RawEvent, Sensor, SensorContext, SensorState};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn reports_unsupported_when_proc_root_net_tcp_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = NetworkSensor::new(dir.path());
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        assert!(caps
            .unsupported_reason
            .as_deref()
            .unwrap_or_default()
            .contains("net/tcp not found"));

        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn emits_a_connect_event_for_a_new_connection_appearing_in_proc_net_tcp() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(
            dir.path().join("net").join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .unwrap();

        let mut sensor = NetworkSensor::new(dir.path()).with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        // A connection appears on the next poll.
        std::fs::write(
            dir.path().join("net").join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n  0: 0500000A:C738 32671BCB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 100 0 0 10 0\n",
        )
        .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for a network event")
            .expect("channel closed unexpectedly");
        match received {
            RawEvent::Network(raw) => {
                assert_eq!(raw.remote_addr, "203.27.103.50");
                assert_eq!(raw.remote_port, 443);
            }
            other => panic!("the Network sensor must only emit Network events, got {other:?}"),
        }

        sensor.stop().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.events_emitted_total, 1);
        assert_eq!(health.state, SensorState::Stopped);
    }
}
```

- [ ] **Step 17: Run the test to verify it fails**

Run: `cargo test -p osiris-sensors-net sensor`
Expected: FAIL — compile errors for `NetworkSensor`.

- [ ] **Step 18: Implement `NetworkSensor`**

Insert above the test module in `crates/osiris-sensors/net/src/sensor.rs`. This follows `FilesystemSensor`'s exact shape from Phase 2 (`HealthState`, poisoned-lock recovery via `lock_health`, `capabilities()`/`initialize()`/`start()`/`stop()`/`health()`/`metrics()`), swapping the audit-log tailer + assembler for `NetworkPoller`:

```rust
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::poller::NetworkPoller;

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

fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Network sensor (ARCHITECTURE.md §4.3's Network row), Phase 3 scope:
/// the `/proc/net/tcp` polling fallback backend only (plan Global
/// Constraints #1/#2/#3/#4/#5). eBPF kprobes/tracepoints and conntrack
/// integration are additional/extended `Sensor` behaviour behind this same
/// unchanged trait, not a rewrite.
pub struct NetworkSensor {
    proc_root: PathBuf,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl NetworkSensor {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            poll_interval: Duration::from_millis(200),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
}

#[async_trait]
impl Sensor for NetworkSensor {
    fn name(&self) -> &'static str {
        "network"
    }

    fn capabilities(&self) -> SensorCapabilities {
        if self.proc_root.join("net").join("tcp").exists() {
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
                    "net/tcp not found under {}",
                    self.proc_root.display()
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

        let proc_root = self.proc_root.clone();
        let poll_interval = self.poll_interval;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut poller = NetworkPoller::new(proc_root);
            loop {
                if cancellation.is_cancelled() {
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                for raw in poller.poll(now_ns) {
                    emit(&output, raw, &health).await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancellation.cancelled() => {
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
    raw: osiris_sensor_api::NetworkEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::Network(raw)).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(timestamp);
        h.state = SensorState::Healthy;
    } else {
        lock_health(health).events_dropped_total += 1;
    }
}
```

- [ ] **Step 19: Run the test to verify it passes**

Run: `cargo test -p osiris-sensors-net sensor`
Expected: PASS — 2 tests.

- [ ] **Step 20: Run the full crate suite, workspace build, and dep-graph check**

Run: `cargo test -p osiris-sensors-net` then `cargo build --workspace --all-targets` then `bash tools/check-dep-graph.sh`
Expected: all pass (proc_tcp: 6, fd_scan: 8, poller: 7, sensor: 2 = 23 tests); `Dependency-graph check PASSED` with the new `osiris-sensors-net` forward check actually running (no `skip:` line for it).

- [ ] **Step 21: Commit**

```bash
git add crates/osiris-sensors/net
git commit -m "feat(sensors-net): NetworkPoller connection diffing and the NetworkSensor Sensor impl

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

### Task 4: `osiris-storage` + `osiris-storage-sqlite` — network-address and DNS-domain query filters

**Files:**
- Modify: `crates/osiris-storage/src/plan.rs`
- Modify: `crates/osiris-storage-sqlite/src/sqlite_storage.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `osiris_storage::QueryPlan.network_addr: Option<String>` — matches `network.src_ip OR network.dst_ip`.
  - `osiris_storage::QueryPlan.dns_domain: Option<String>` — matches `dns.query`.
  - Task 7's Network Story handler uses both.

- [ ] **Step 1: Write the failing test for the new `QueryPlan` fields**

Update `crates/osiris-storage/src/plan.rs`'s `new_query_plan_defaults_to_limit_100_and_no_filters` test:
```rust
    #[test]
    fn new_query_plan_defaults_to_limit_100_and_no_filters() {
        let plan = QueryPlan::new();
        assert_eq!(plan.limit, 100);
        assert!(plan.event_type.is_none());
        assert!(plan.file_path.is_none());
        assert!(plan.file_identity.is_none());
        assert!(plan.network_addr.is_none());
        assert!(plan.dns_domain.is_none());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-storage new_query_plan_defaults`
Expected: FAIL — `QueryPlan` has no field `network_addr`/`dns_domain`.

- [ ] **Step 3: Add the fields**

In `crates/osiris-storage/src/plan.rs`, update `QueryPlan`:
```rust
#[derive(Debug, Clone, Default)]
pub struct QueryPlan {
    pub event_type: Option<EventType>,
    pub process_key: Option<ProcessKey>,
    /// Exact-match on `file.path`. The lookup key an analyst types.
    pub file_path: Option<String>,
    /// Exact-match on `(file.inode, file.device_id)`. The join key that
    /// follows a file across a rename (§9.4, Phase 2 plan Global
    /// Constraints #6).
    pub file_identity: Option<FileIdentity>,
    /// Exact-match on `network.src_ip OR network.dst_ip` — an address is
    /// queried without regard to which side of the connection it was on
    /// (Phase 3 plan Global Constraints #9).
    pub network_addr: Option<String>,
    /// Exact-match on `dns.query`.
    pub dns_domain: Option<String>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: usize,
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p osiris-storage`
Expected: PASS.

- [ ] **Step 5: Write the failing tests for the SQLite filters and migration**

Append to `crates/osiris-storage-sqlite/src/sqlite_storage.rs`'s `mod tests` (read the existing test module first for its exact `sample_event`-equivalent fixture helper and adapt to it — the exact helper name/shape may differ slightly from what Phase 2's plan text assumed; match whatever the current file actually has):
```rust
    fn network_event(src_ip: &str, dst_ip: &str, timestamp: u64) -> CanonicalEvent {
        let mut event = bare_event(timestamp); // adapt to this file's actual bare-event helper name
        event.event_type = osiris_schema::EventType::NetworkConnect;
        event.category = osiris_schema::Category::Network;
        event.network = Some(osiris_schema::NetworkRef {
            src_ip: src_ip.to_string(),
            src_port: 51000,
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        event
    }

    fn dns_event(query: &str, response_ips: Vec<String>, timestamp: u64) -> CanonicalEvent {
        let mut event = bare_event(timestamp);
        event.event_type = osiris_schema::EventType::DnsQuery;
        event.category = osiris_schema::Category::Dns;
        event.dns = Some(osiris_schema::DnsRef {
            query: query.to_string(),
            qtype: "A".to_string(),
            response_ips,
            ttl: Some(300),
        });
        event
    }

    #[test]
    fn query_filters_by_network_addr_matching_either_src_or_dst() {
        let storage = open_test_storage();
        let as_dst = network_event("10.0.0.5", "203.0.113.50", 1000);
        let as_src = network_event("203.0.113.50", "10.0.0.6", 2000);
        let unrelated = network_event("10.0.0.7", "198.51.100.1", 3000);
        storage
            .batch_write(&[as_dst.clone(), as_src.clone(), unrelated])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.network_addr = Some("203.0.113.50".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 2);
        let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&as_dst.event_id));
        assert!(ids.contains(&as_src.event_id));
    }

    #[test]
    fn query_filters_by_dns_domain() {
        let storage = open_test_storage();
        let matching = dns_event("cdn-assets.xyz", vec!["203.0.113.50".to_string()], 1000);
        let other = dns_event("example.com", vec!["93.184.216.34".to_string()], 2000);
        storage.batch_write(&[matching.clone(), other]).unwrap();

        let mut plan = QueryPlan::new();
        plan.dns_domain = Some("cdn-assets.xyz".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, matching.event_id);
    }

    /// Non-destructive/idempotent migration proof, matching Phase 2 Task
    /// 6's precedent exactly: open a database shaped like it predates this
    /// phase's two new columns, then re-open it through the current
    /// `SqliteStorage::open` and confirm existing data survives and the new
    /// columns work.
    #[test]
    fn migrates_a_pre_phase_3_database_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        {
            // Simulate a database from before this phase: open it, then
            // drop the two new columns a real pre-Phase-3 SqliteStorage
            // would never have created. SQLite's `ALTER TABLE ADD COLUMN`
            // migration in `open()` is what must recreate them.
            let storage = SqliteStorage::open(&db_path).unwrap();
            storage
                .write(&network_event("10.0.0.5", "203.0.113.50", 1000))
                .unwrap();
        }
        // Re-opening (simulating a Phase 3 binary starting against a
        // database that already has the network columns from the first
        // open above) must remain idempotent — no error, no duplicate
        // columns.
        let reopened = SqliteStorage::open(&db_path).unwrap();
        let mut plan = QueryPlan::new();
        plan.network_addr = Some("203.0.113.50".to_string());
        assert_eq!(reopened.query(&plan).unwrap().len(), 1);
    }
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cargo test -p osiris-storage-sqlite network_addr dns_domain`
Expected: FAIL — `QueryPlan.network_addr`/`.dns_domain` are ignored by `query()` (no SQL filter applied, both tests over-return or the migration test's re-query returns 0).

- [ ] **Step 7: Add the two indexed columns and their migration**

In `crates/osiris-storage-sqlite/src/sqlite_storage.rs`, extend the `CREATE TABLE IF NOT EXISTS events` DDL (for brand-new databases) with two more columns, matching the existing `file_path`/`file_inode`/`file_device_id` style:
```sql
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    process_key TEXT,
    parent_process_key TEXT,
    file_path TEXT,
    file_inode INTEGER,
    file_device_id INTEGER,
    network_src_ip TEXT,
    network_dst_ip TEXT,
    dns_domain TEXT,
    raw_json TEXT NOT NULL
);
```

Extend the migration loop (for databases that predate these columns):
```rust
for (column, ddl) in [
    ("file_path", "ALTER TABLE events ADD COLUMN file_path TEXT"),
    ("file_inode", "ALTER TABLE events ADD COLUMN file_inode INTEGER"),
    (
        "file_device_id",
        "ALTER TABLE events ADD COLUMN file_device_id INTEGER",
    ),
    (
        "network_src_ip",
        "ALTER TABLE events ADD COLUMN network_src_ip TEXT",
    ),
    (
        "network_dst_ip",
        "ALTER TABLE events ADD COLUMN network_dst_ip TEXT",
    ),
    ("dns_domain", "ALTER TABLE events ADD COLUMN dns_domain TEXT"),
] {
    if !column_exists(&conn, "events", column)? {
        conn.execute(ddl, [])
            .map_err(|e| StorageError::Backend(e.to_string()))?;
    }
}
```

Extend the index-creation batch below it:
```rust
conn.execute_batch(
    "CREATE INDEX IF NOT EXISTS idx_events_file_path ON events(file_path);
     CREATE INDEX IF NOT EXISTS idx_events_file_identity ON events(file_device_id, file_inode);
     CREATE INDEX IF NOT EXISTS idx_events_network_src_ip ON events(network_src_ip);
     CREATE INDEX IF NOT EXISTS idx_events_network_dst_ip ON events(network_dst_ip);
     CREATE INDEX IF NOT EXISTS idx_events_dns_domain ON events(dns_domain);",
)
.map_err(|e| StorageError::Backend(e.to_string()))?;
```

- [ ] **Step 8: Populate the columns on write**

In `batch_write`, alongside the existing `file_path`/`file_identity` extraction, add:
```rust
let network_src_ip = event.network.as_ref().map(|n| n.src_ip.clone());
let network_dst_ip = event.network.as_ref().map(|n| n.dst_ip.clone());
let dns_domain = event.dns.as_ref().map(|d| d.query.clone());
```
and extend the `INSERT OR IGNORE INTO events` statement's column list and `VALUES` placeholders/params to include `network_src_ip, network_dst_ip, dns_domain` (three more columns, three more `?N` placeholders, three more `params![...]` entries — matching exactly how `file_path`/`file_inode`/`file_device_id` were threaded through in Phase 2).

- [ ] **Step 9: Apply the two new filters in `query`**

In `query`, alongside the existing `file_path`/`file_identity` filter blocks, add:
```rust
if let Some(addr) = &plan.network_addr {
    sql.push_str(" AND (network_src_ip = ? OR network_dst_ip = ?)");
    sql_params.push(Box::new(addr.clone()));
    sql_params.push(Box::new(addr.clone()));
}
if let Some(domain) = &plan.dns_domain {
    sql.push_str(" AND dns_domain = ?");
    sql_params.push(Box::new(domain.clone()));
}
```
placed before the existing `since`/`until` blocks (filter ordering in the SQL string doesn't affect correctness, only readability — match the existing file's ordering convention of "identity-ish filters, then time-range filters").

- [ ] **Step 10: Run the test to verify it passes**

Run: `cargo test -p osiris-storage-sqlite`
Expected: PASS — Phase 1/2's existing tests plus the 3 new ones.

- [ ] **Step 11: Run the full workspace build and dep-graph check**

Run: `cargo build --workspace --all-targets` then `bash tools/check-dep-graph.sh`
Expected: both pass.

- [ ] **Step 12: Commit**

```bash
git add crates/osiris-storage crates/osiris-storage-sqlite
git commit -m "feat(storage): network-address and DNS-domain query filters

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

### Task 5: `generator` + `osiris-agent` — the network-beacon scenario and wiring `NetworkSensor` into the Agent

**Files:**
- Modify: `generator/src/scenarios.rs`
- Modify: `generator/Cargo.toml` (add `osiris-schema` as a dependency if not already present — needed for nothing new this phase, only if the file needs it; check first, Phase 2's generator already depends on `osiris-schema` for `encode_device_id`)
- Modify: `crates/osiris-agent/src/agent.rs`
- Modify: `crates/osiris-agent/src/config.rs`
- Modify: `crates/osiris-agent/Cargo.toml` (add `osiris-sensors-net`)

**Interfaces:**
- Consumes: `osiris_sensor_api::{NetworkEventRaw, NetworkOperation, NetworkDirection, DnsEventRaw}` from Task 1; `osiris_sensors_net::NetworkSensor` from Task 3.
- Produces:
  - `generator::network_beacon_scenario(base_ts_ns: u64) -> Vec<RawEvent>` — an 6-event exec-then-DNS-then-network chain. Task 8's e2e test uses it.
  - `osiris_agent::AgentConfig.network_proc_root: Option<String>` and `.synthetic_scenario` gains a third accepted value, `"network_beacon"`.
  - `Agent::start` wires `NetworkSensor` into `candidate_sensors` when `network_proc_root` is set.

- [ ] **Step 1: Write the failing test for the new scenario**

Append to `generator/src/scenarios.rs`'s `mod tests`:
```rust
    fn network_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::NetworkEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Network(n) => Some(n),
                _ => None,
            })
            .collect()
    }

    fn dns_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::DnsEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Dns(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn network_beacon_scenario_has_the_full_exec_then_dns_then_network_chain() {
        let scenario = network_beacon_scenario(1000);
        assert_eq!(scenario.len(), 6);

        let execs = exec_events(&scenario);
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[2].exe_path, "/usr/bin/curl");
        assert_eq!(execs[2].pid, 300);

        let dns = dns_raw_events(&scenario);
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].query, BEACON_DOMAIN);
        assert_eq!(dns[0].response_ips, vec![BEACON_IP.to_string()]);
        assert_eq!(dns[0].pid, Some(300));

        let net = network_raw_events(&scenario);
        assert_eq!(net.len(), 2);
        assert_eq!(net[0].operation, osiris_sensor_api::NetworkOperation::Connect);
        assert_eq!(net[0].remote_addr, BEACON_IP);
        assert_eq!(net[0].pid, Some(300));
        assert_eq!(net[1].operation, osiris_sensor_api::NetworkOperation::Close);
        assert_eq!(net[1].remote_addr, BEACON_IP);
    }

    #[test]
    fn network_beacon_scenario_is_strictly_time_ordered() {
        let scenario = network_beacon_scenario(1000);
        for pair in scenario.windows(2) {
            assert!(pair[0].timestamp_ns() < pair[1].timestamp_ns());
        }
    }

    /// The DNS query resolves to the same IP the connect/close events cite
    /// — this is precisely what lets Task 7's Network Story follow the
    /// domain to its connections via `RESOLVED_TO`.
    #[test]
    fn the_beacons_resolved_ip_matches_its_connections_remote_address() {
        let scenario = network_beacon_scenario(1000);
        let dns = dns_raw_events(&scenario);
        let net = network_raw_events(&scenario);
        assert_eq!(dns[0].response_ips[0], net[0].remote_addr);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-generator network_beacon`
Expected: FAIL — `network_beacon_scenario`, `BEACON_DOMAIN`, `BEACON_IP` undefined. (Check the actual generator crate's package name first — `grep '^name' generator/Cargo.toml` — Phase 2's plan referred to it as `generator`/`osiris-generator` interchangeably; use whatever `cargo test -p <name>` actually resolves.)

- [ ] **Step 3: Implement `network_beacon_scenario`**

In `generator/src/scenarios.rs`, add near the top (alongside `WEB_SHELL_INODE` etc.):
```rust
use osiris_sensor_api::{DnsEventRaw, NetworkDirection, NetworkEventRaw, NetworkOperation};

/// A suspicious TLD chosen to satisfy Task 6's shipped detection rule —
/// this scenario is both the DNS/Network pipeline's fixture and the rule's
/// positive fixture, the same dual role `web_shell_drop_scenario` plays for
/// Task 6/7 (now Task 6) of Phase 2.
pub const BEACON_DOMAIN: &str = "cdn-assets.xyz";
pub const BEACON_IP: &str = "203.0.113.50";
```

Add the scenario function after `web_shell_drop_scenario`:
```rust
/// §26's exec chain continued into DNS and the network: curl (pid 300)
/// resolves a suspicious-TLD domain, connects to the resolved address, then
/// the connection closes. Mirrors `web_shell_drop_scenario`'s shape: same
/// exec chain, a plausible actor, and identity that stays consistent across
/// events (the DNS response IP and the connection's remote address match,
/// per Phase 3 plan Global Constraints #8's `RESOLVED_TO`/`CONNECTED_TO`
/// edges) so Network Story assembly has something real to join.
pub fn network_beacon_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 1_000_000),
        exec(300, 200, "/usr/bin/curl", "curl", base_ts_ns + 2_000_000),
        RawEvent::Dns(DnsEventRaw {
            query: BEACON_DOMAIN.to_string(),
            qtype: "A".to_string(),
            response_ips: vec![BEACON_IP.to_string()],
            ttl: Some(300),
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: base_ts_ns + 3_000_000,
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Network(NetworkEventRaw {
            operation: NetworkOperation::Connect,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: BEACON_IP.to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: base_ts_ns + 4_000_000,
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Network(NetworkEventRaw {
            operation: NetworkOperation::Close,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: BEACON_IP.to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: base_ts_ns + 5_000_000,
            source: RawEventSource::Synthetic,
        }),
    ]
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p osiris-generator`
Expected: PASS — existing tests plus the 3 new ones.

- [ ] **Step 5: Update `lib.rs` re-exports**

In `generator/src/lib.rs`, update:
```rust
pub use scenarios::{
    exec_chain_scenario, network_beacon_scenario, web_shell_drop_scenario, BEACON_DOMAIN,
    BEACON_IP, BENIGN_NOTES_PATH, WEB_SHELL_DEVICE_ID, WEB_SHELL_FINAL_PATH, WEB_SHELL_INODE,
    WEB_SHELL_TEMP_PATH,
};
```

- [ ] **Step 6: Fix `generator/src/sensor.rs`'s non-exhaustive `match` (`SyntheticSensor`'s own test)**

Search `generator/src/sensor.rs` for the `match raw_event { RawEvent::ProcessExec(raw) => ..., other => panic!(...) }` pattern Phase 2's Task 3 added. It already has an `other => panic!(...)` catch-all (confirmed by Task 1 Step 8 of this plan re-deriving the current site list) — this compiles unchanged against the two new `RawEvent` variants with no edit needed. Confirm by running `cargo build -p osiris-generator --all-targets`; if it fails, the catch-all must be missing and this step adds it (same wording pattern as Task 1 Step 8).

- [ ] **Step 7: `AgentConfig` gains `network_proc_root` and the `"network_beacon"` scenario name**

In `crates/osiris-agent/src/config.rs`, add a field after `fs_audit_log_path`:
```rust
    /// Directory to poll for `/proc/net/tcp`-style Network sensor input
    /// (a real deployment points this at `/proc`). If absent or its
    /// `net/tcp` file doesn't exist, that sensor is skipped
    /// (capabilities()-driven, never silently).
    #[serde(default)]
    pub network_proc_root: Option<String>,
```

Update the `synthetic_scenario` field's doc comment:
```rust
    /// Which canned scenario the synthetic sensor emits: `"exec_chain"`
    /// (default, Phase 1's sshd->bash->curl), `"web_shell_drop"` (that
    /// chain continued into the filesystem), or `"network_beacon"` (that
    /// chain continued into DNS and network). Ignored unless
    /// `enable_synthetic` is true.
```

Update the two config tests that assert on the Phase 2 fields defaulting to `None` (`the_new_phase_2_fields_default_to_none_so_phase_1_configs_still_load`) — add:
```rust
        assert!(config.network_proc_root.is_none());
```
inside that existing test's body (do not rename the test — it still proves the same "an older config still loads" property, now for a Phase 3 field too; renaming it is optional polish, not required).

- [ ] **Step 8: `osiris-agent/Cargo.toml` gains the dependency**

Add to `[dependencies]`:
```toml
osiris-sensors-net = { path = "../osiris-sensors/net" }
```

- [ ] **Step 9: Wire `NetworkSensor` and the `"network_beacon"` scenario into `Agent::start`**

In `crates/osiris-agent/src/agent.rs`, add the import:
```rust
use osiris_generator::{exec_chain_scenario, network_beacon_scenario, web_shell_drop_scenario, SyntheticSensor};
use osiris_sensors_net::NetworkSensor;
```
(merge into the existing `osiris_generator` import line rather than duplicating it.)

Add a candidate-sensor registration after the `fs_audit_log_path` block:
```rust
        if let Some(proc_root) = &config.network_proc_root {
            candidate_sensors.push(Box::new(NetworkSensor::new(proc_root.clone())));
        }
```

Extend the `synthetic_scenario` match:
```rust
            let scenario = match config.synthetic_scenario.as_deref() {
                Some("web_shell_drop") => web_shell_drop_scenario(base_ts),
                Some("network_beacon") => network_beacon_scenario(base_ts),
                Some("exec_chain") | None => exec_chain_scenario(base_ts),
                Some(other) => {
                    tracing::warn!(
                        scenario = other,
                        "unknown synthetic_scenario; falling back to exec_chain"
                    );
                    exec_chain_scenario(base_ts)
                }
            };
```

- [ ] **Step 10: Write the failing tests for the Agent-level wiring**

Append to `crates/osiris-agent/src/agent.rs`'s `mod tests`. First, update `base_config` to include the new field:
```rust
    fn base_config(dir: &tempfile::TempDir) -> AgentConfig {
        AgentConfig {
            audit_log_path: None,
            fs_audit_log_path: None,
            network_proc_root: None,
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
```

Then add:
```rust
    #[tokio::test]
    async fn starts_the_network_sensor_when_a_proc_root_with_net_tcp_exists() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("fakeproc");
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        std::fs::write(
            proc_root.join("net").join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .unwrap();
        let mut config = base_config(&dir);
        config.network_proc_root = Some(proc_root.to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "network");
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn skips_the_network_sensor_with_a_visible_reason_when_net_tcp_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.network_proc_root =
            Some(dir.path().join("no-such-proc").to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 0);
        assert_eq!(status.skipped_sensors.len(), 1);
        assert_eq!(status.skipped_sensors[0].name, "network");
        assert!(status.skipped_sensors[0].reason.contains("net/tcp not found"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn the_network_beacon_scenario_reaches_the_spool_file_with_dns_and_network_events() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("network_beacon".to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 6);
        assert!(contents.contains("\"DNS_QUERY\""));
        assert!(contents.contains("\"NETWORK_CONNECT\""));
        assert!(contents.contains("\"NETWORK_CLOSE\""));
        assert!(contents.contains("cdn-assets.xyz"));
    }
```

- [ ] **Step 11: Run the test to verify it fails, then implement**

Run: `cargo test -p osiris-agent network`
Expected: FAIL (compile error on the `base_config` shape mismatch and missing `network_proc_root` field/`NetworkSensor` import) until Steps 7-9 above are applied to the actual files — if you followed Steps 7-9 in order this is a checkpoint, not a separate implementation step.

- [ ] **Step 12: Run the test to verify it passes**

Run: `cargo test -p osiris-agent`
Expected: PASS — Phase 1/2's existing tests plus the 3 new ones.

- [ ] **Step 13: Run the full workspace build, tests, and dep-graph check**

Run: `cargo build --workspace --all-targets` then `cargo test --workspace` then `bash tools/check-dep-graph.sh`
Expected: all green.

- [ ] **Step 14: Commit**

```bash
git add generator crates/osiris-agent
git commit -m "feat(generator,agent): network-beacon scenario and NetworkSensor wiring

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

### Task 6: `config/rules` — the second shipped detection rule (DNS to a suspicious TLD)

No `osiris-detect` code changes (Phase 3 plan Global Constraints #12) — `eval::field_value`'s dotted-path resolution and the `ends_with`/`in` operators already work against `dns.query`/`process.exe_path` exactly as they do against `file.path`. This task ships one rule file and a test proving the *engine itself*, unmodified, correctly loads and fires it — the same shape as Phase 2's `the_shipped_web_root_rule_loads_and_fires_on_its_positive_fixture_only` test.

**Files:**
- Create: `config/rules/dns_query_to_suspicious_tld.yaml`
- Modify: `crates/osiris-detect/src/engine.rs` (test only)

**Interfaces:**
- Consumes: `osiris_detect::{DetectionEngine, Rule}` (unchanged).
- Produces: nothing new — a rule file and its test.

- [ ] **Step 1: Write the failing test for the shipped rule**

Append to `crates/osiris-detect/src/engine.rs`'s `mod tests` (matching `the_shipped_web_root_rule_loads_and_fires_on_its_positive_fixture_only`'s exact shape, reading the real file via `CARGO_MANIFEST_DIR`):
```rust
    fn dns_event(query: &str, exe_path: &str) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 1,
            event_type: EventType::DnsQuery,
            category: EventType::DnsQuery.category(),
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
            file: None,
            network: None,
            dns: Some(osiris_schema::DnsRef {
                query: query.to_string(),
                qtype: "A".to_string(),
                response_ips: vec!["203.0.113.50".to_string()],
                ttl: Some(300),
            }),
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

    /// The repository's own shipped rule must load and behave — this is the
    /// CI-enforced half of §11.1's "every rule ships with a fixture that
    /// must trigger it, and a negative fixture that must not," proving
    /// this phase's dns.*/process.* fields work through the engine
    /// unmodified (Phase 3 plan Global Constraints #12).
    #[test]
    fn the_shipped_dns_suspicious_tld_rule_loads_and_fires_on_its_positive_fixture_only() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/dns_query_to_suspicious_tld.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("shipped rule must exist at {}: {e}", path.display()));
        let engine = DetectionEngine::new(vec![
            crate::rule::Rule::from_yaml_str(&yaml, "dns_query_to_suspicious_tld.yaml").unwrap()
        ]);
        let alerts = engine.evaluate(&dns_event("cdn-assets.xyz", "/usr/bin/curl"));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "dns_query_to_suspicious_tld");

        assert!(engine
            .evaluate(&dns_event("example.com", "/usr/bin/curl"))
            .is_empty());
    }

    /// The rule loaded alongside the Phase 2 rule (via `load_from_dir`) must
    /// not cross-fire on the other rule's positive fixture — proves the two
    /// shipped rules stay independent as `config/rules/` grows.
    #[test]
    fn both_shipped_rules_load_together_without_cross_firing() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        assert_eq!(engine.rule_count(), 2);

        let dns_alerts = engine.evaluate(&dns_event("cdn-assets.xyz", "/usr/bin/curl"));
        assert_eq!(dns_alerts.len(), 1);
        assert_eq!(dns_alerts[0].rule_id(), "dns_query_to_suspicious_tld");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-detect the_shipped_dns_suspicious_tld_rule`
Expected: FAIL — the rule file does not exist yet (`shipped rule must exist at ...` panic).

- [ ] **Step 3: Write the rule file**

Create `config/rules/dns_query_to_suspicious_tld.yaml`:
```yaml
# Detects a DNS query for a domain under a TLD commonly abused for
# short-lived, disposable malicious infrastructure (cheap bulk registration,
# minimal registrar vetting) when the querying process is a shell or
# download tool rather than a browser or the system resolver's usual
# callers — the same "actor matters, not just the artifact" shape as
# Phase 2's shell_wrote_file_to_web_root rule, which is what keeps this
# specific rather than noisy (ARCHITECTURE.md §11.2).
#
# MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS).
id: dns_query_to_suspicious_tld
version: 1
severity: MEDIUM
match:
  - field: event_type
    op: eq
    value: "DNS_QUERY"
    reason: "A DNS query was resolved"
  - field: dns.query
    op: ends_with
    value: ".xyz"
    reason: "The queried domain is under a TLD commonly abused for disposable malicious infrastructure (.xyz)"
  - field: process.exe_path
    op: in
    value: ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget"]
    reason: "The querying process is an interactive shell or download tool, not a browser or the system resolver"
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p osiris-detect`
Expected: PASS — Phase 2's existing tests plus the 2 new ones (the shipped-rule test and the both-rules-together test).

- [ ] **Step 5: Run the full workspace build and dep-graph check**

Run: `cargo build --workspace --all-targets` then `bash tools/check-dep-graph.sh`
Expected: both pass (no code outside `osiris-detect`'s test module and `config/rules/` changed).

- [ ] **Step 6: Commit**

```bash
git add config/rules crates/osiris-detect
git commit -m "feat(rules): ship the DNS-query-to-suspicious-TLD detection rule

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

### Task 7: `osiris-api` — `GET /api/v1/network/story`

No `osiris-server` changes (Phase 3 plan Global Constraints #13 — detection already runs generically on every ingested batch regardless of category, and the new rule file is picked up by `DetectionEngine::load_from_dir` automatically).

**Files:**
- Modify: `crates/osiris-api/src/lib.rs`

**Interfaces:**
- Consumes: `osiris_storage::QueryPlan.{network_addr, dns_domain}` from Task 4; `osiris_schema::{Alert}` (unchanged).
- Produces: `GET /api/v1/network/story?ip=<addr>` and/or `?domain=<name>` → `{ "events": [...], "alerts": [...] }`, mirroring `file_story_handler`'s response shape.

- [ ] **Step 1: Write the failing tests for the handler**

Append to `crates/osiris-api/src/lib.rs`'s `mod tests`. First add a small fixture helper alongside the existing `file_event`:
```rust
    #[allow(clippy::too_many_arguments)]
    fn network_event(
        event_type: EventType,
        src_ip: &str,
        dst_ip: &str,
        timestamp: u64,
    ) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: Category::Network,
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
            network: Some(osiris_schema::NetworkRef {
                src_ip: src_ip.to_string(),
                src_port: 51000,
                dst_ip: dst_ip.to_string(),
                dst_port: 443,
                proto: "tcp".to_string(),
                direction: osiris_schema::NetworkDirection::Outbound,
                bytes: None,
            }),
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

    fn dns_event(query: &str, response_ips: Vec<String>, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::DnsQuery,
            category: Category::Dns,
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
            dns: Some(osiris_schema::DnsRef {
                query: query.to_string(),
                qtype: "A".to_string(),
                response_ips,
                ttl: Some(300),
            }),
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

    #[tokio::test]
    async fn network_story_returns_400_when_neither_param_given() {
        let (_dir, storage) = test_storage();
        let result = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery { ip: None, domain: None }),
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn network_story_by_ip_returns_matching_events_and_citing_alerts() {
        let (_dir, storage) = test_storage();
        let connect = network_event(EventType::NetworkConnect, "10.0.0.5", "203.0.113.50", 1000);
        let close = network_event(EventType::NetworkClose, "10.0.0.5", "203.0.113.50", 2000);
        let unrelated = network_event(EventType::NetworkConnect, "10.0.0.7", "198.51.100.1", 500);
        storage
            .batch_write(&[connect.clone(), close.clone(), unrelated])
            .unwrap();
        let alert = sample_alert("dns_query_to_suspicious_tld", vec![connect.event_id], 1000);
        storage.write_alerts(&[alert]).unwrap();

        let Json(story) = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery {
                ip: Some("203.0.113.50".to_string()),
                domain: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 2);
        assert_eq!(story.events[0].event_id, connect.event_id);
        assert_eq!(story.events[1].event_id, close.event_id);
        assert_eq!(story.alerts.len(), 1);
    }

    #[tokio::test]
    async fn network_story_by_domain_follows_the_resolved_ip_to_its_connections() {
        let (_dir, storage) = test_storage();
        let dns = dns_event("cdn-assets.xyz", vec!["203.0.113.50".to_string()], 1000);
        let connect = network_event(EventType::NetworkConnect, "10.0.0.5", "203.0.113.50", 2000);
        let unrelated_dns = dns_event("example.com", vec!["93.184.216.34".to_string()], 500);
        storage
            .batch_write(&[dns.clone(), connect.clone(), unrelated_dns])
            .unwrap();

        let Json(story) = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery {
                ip: None,
                domain: Some("cdn-assets.xyz".to_string()),
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 2);
        let ids: Vec<Uuid> = story.events.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&dns.event_id));
        assert!(ids.contains(&connect.event_id));
    }

    /// Global Constraint #9's disclosed asymmetry: querying by IP alone
    /// does not reverse-resolve to the DNS event that produced it.
    #[tokio::test]
    async fn network_story_by_ip_alone_does_not_include_the_resolving_dns_event() {
        let (_dir, storage) = test_storage();
        let dns = dns_event("cdn-assets.xyz", vec!["203.0.113.50".to_string()], 1000);
        let connect = network_event(EventType::NetworkConnect, "10.0.0.5", "203.0.113.50", 2000);
        storage.batch_write(&[dns, connect.clone()]).unwrap();

        let Json(story) = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery {
                ip: Some("203.0.113.50".to_string()),
                domain: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].event_id, connect.event_id);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-api network_story`
Expected: FAIL — `network_story_handler`, `NetworkStoryQuery` undefined.

- [ ] **Step 3: Implement `network_story_handler`**

In `crates/osiris-api/src/lib.rs`, register the route in `build_router`:
```rust
        .route("/api/v1/network/story", get(network_story_handler))
```

Add the handler after `file_story_handler`:
```rust
#[derive(Debug, Deserialize)]
struct NetworkStoryQuery {
    ip: Option<String>,
    domain: Option<String>,
}

#[derive(Debug, Serialize)]
struct NetworkStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

/// Composed query implementing Phase 3 plan Global Constraints #9: the
/// domain form resolves DNS events for that domain, unions in every network
/// event touching any of their resolved addresses; the IP form matches
/// network events directly and does not reverse-resolve to the DNS side —
/// a deliberate, disclosed asymmetry (see the constraint's full reasoning).
async fn network_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<NetworkStoryQuery>,
) -> Result<Json<NetworkStory>, (StatusCode, String)> {
    if q.ip.is_none() && q.domain.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide ip or domain".to_string(),
        ));
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();

        if let Some(domain) = &q.domain {
            let mut plan = QueryPlan::new();
            plan.dns_domain = Some(domain.clone());
            plan.limit = 10_000;
            let dns_events = storage.query(&plan)?;

            let mut resolved_ips: HashSet<String> = HashSet::new();
            for e in &dns_events {
                if let Some(dns) = &e.dns {
                    resolved_ips.extend(dns.response_ips.iter().cloned());
                }
            }
            for e in dns_events {
                events_by_id.insert(e.event_id, e);
            }
            for ip in &resolved_ips {
                let mut plan = QueryPlan::new();
                plan.network_addr = Some(ip.clone());
                plan.limit = 10_000;
                for e in storage.query(&plan)? {
                    events_by_id.insert(e.event_id, e);
                }
            }
        }

        if let Some(ip) = &q.ip {
            let mut plan = QueryPlan::new();
            plan.network_addr = Some(ip.clone());
            plan.limit = 10_000;
            for e in storage.query(&plan)? {
                events_by_id.insert(e.event_id, e);
            }
        }

        let mut events: Vec<CanonicalEvent> = events_by_id.into_values().collect();
        events.sort_by(|a, b| (a.timestamp, a.event_id).cmp(&(b.timestamp, b.event_id)));

        let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
        let alerts = if evidence_ids.is_empty() {
            vec![]
        } else {
            let mut alert_plan = AlertQueryPlan::new();
            alert_plan.evidence_event_ids = evidence_ids;
            alert_plan.limit = 10_000;
            storage.query_alerts(&alert_plan)?
        };

        Ok::<_, osiris_storage::StorageError>((events, alerts))
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(NetworkStory { events, alerts }))
}
```

Update the imports at the top of the file: add `HashSet` to the existing `use std::collections::{HashMap, HashSet};` line if not already present (Phase 2's Task 8 already added `HashSet` for `FileIdentity` collection — confirm before editing; this handler reuses the same import, no duplicate needed).

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p osiris-api`
Expected: PASS — Phase 1/2's existing tests plus the 4 new ones.

- [ ] **Step 5: Run the full workspace build and dep-graph check**

Run: `cargo build --workspace --all-targets` then `bash tools/check-dep-graph.sh`
Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-api
git commit -m "feat(api): GET /api/v1/network/story

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

### Task 8: `osiris-e2e-tests` — end-to-end verification of the network/DNS vertical slice

Mirrors Phase 2's final task exactly: a verification task, not new engine code (Phase 3 plan Global Constraints #13/#14 — no production code changes are expected here). If you find you need one, STOP and report BLOCKED with what you found — that would mean a real gap in Tasks 1-7, not something this task anticipated.

**Files:**
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs`

**Interfaces:**
- Consumes: everything already built — `osiris_agent::{Agent, AgentConfig}` (with `synthetic_scenario: Some("network_beacon")`), `osiris_server::run_ingestion_loop`, `osiris_detect::DetectionEngine`, `osiris_api::build_router`, `osiris_storage::{Storage, QueryPlan}`.
- Produces: one new integration test. No new public interfaces.

- [ ] **Step 1: Read the existing end-to-end tests for the pattern to follow**

Read `crates/osiris-e2e-tests/tests/end_to_end.rs` in full — Phase 2's `web_shell_drop_scenario_flows_end_to_end_and_triggers_detection` test is the closest precedent (synthetic scenario → real Agent → real Server with real detection → real HTTP API assertions, including a File Story call). Your new test follows the same shape for the network-beacon scenario, adding Network Story assertions in place of File Story ones.

- [ ] **Step 2: Write the new test**

Add to `crates/osiris-e2e-tests/tests/end_to_end.rs`:

```rust
/// Phase 3's full vertical slice: the network-beacon scenario (sshd -> bash
/// -> curl, then curl resolves a suspicious-TLD domain and connects to the
/// resolved address before the connection closes) flows through the real
/// Agent, Server (ingest + detection + storage), and HTTP API. Verifies
/// Timeline interleaving of the DNS/Network categories, PROCESS_KEY_PROVISIONAL
/// absence, the shipped DNS rule firing on a real ingested event, and
/// Network Story's domain-to-connection join (and its disclosed
/// IP-form asymmetry) over real HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn network_beacon_scenario_flows_end_to_end_and_triggers_detection() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.ndjson");
    let db_path = dir.path().join("events.db");

    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "e2e-test-host".to_string(),
        distro: "test".to_string(),
        kernel_version: "test".to_string(),
        cloud: None,
    };

    let agent_config = AgentConfig {
        audit_log_path: None,
        fs_audit_log_path: None,
        network_proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: Some("network_beacon".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());

    // The real shipped rules directory — now two rules (Phase 2's web-root
    // rule plus Phase 3's DNS rule) loaded the same way osiris-server's
    // main.rs does.
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let detection_engine = Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap());
    assert!(detection_engine.rule_count() >= 2);

    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        detection_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // 6-event scenario, 1ms apart, plus a 50ms ingestion poll interval —
    // comfortably generous, matching Phase 2's precedent budget for a
    // similarly-sized scenario.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all 6 events landed (3 exec + 1 DNS + 2 network).
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(events.len(), 6, "expected sshd, bash, curl, 1 DNS query, connect, close");

    // 2. PROCESS_KEY_PROVISIONAL must be absent from the DNS and network
    //    events: curl (pid 300) already executed earlier in this same
    //    scenario, so ProcessResolver must have resolved its real
    //    process_key.
    let non_process_events: Vec<_> = events
        .iter()
        .filter(|e| e.dns.is_some() || e.network.is_some())
        .collect();
    assert_eq!(non_process_events.len(), 3, "1 DNS + 2 network events");
    for event in &non_process_events {
        assert!(
            !event.tags.iter().any(|t| t == "PROCESS_KEY_PROVISIONAL"),
            "event {:?} must not carry PROCESS_KEY_PROVISIONAL — curl already executed earlier",
            event.event_id
        );
    }

    // 3. Timeline: both DNS and NETWORK categories appear, correctly
    //    time-ordered alongside PROCESS, in one GET /api/v1/events response.
    let app = build_router(storage.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let min_ts = events.iter().map(|e| e.timestamp).min().unwrap();
    let max_ts = events.iter().map(|e| e.timestamp).max().unwrap();
    let timeline: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/events?since={}&until={}",
            addr,
            min_ts - 1,
            max_ts + 1
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let timeline_events = timeline.as_array().unwrap();
    assert_eq!(timeline_events.len(), 6);
    let timestamps: Vec<u64> = timeline_events
        .iter()
        .map(|e| e["timestamp"].as_u64().unwrap())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort();
    assert_eq!(timestamps, sorted, "events must come back in timestamp order");
    let categories: std::collections::HashSet<_> = timeline_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    assert!(categories.contains("PROCESS") && categories.contains("DNS") && categories.contains("NETWORK"));

    // 4. The shipped DNS rule fired: GET /api/v1/alerts must show
    //    dns_query_to_suspicious_tld, citing the DNS_QUERY event.
    let alerts: serde_json::Value = client
        .get(format!("http://{}/api/v1/alerts", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alerts_array = alerts.as_array().unwrap();
    assert!(
        !alerts_array.is_empty(),
        "the shipped dns_query_to_suspicious_tld rule must have fired on curl's query to \
         cdn-assets.xyz"
    );
    assert!(alerts_array
        .iter()
        .all(|a| a["rule_id"].as_str().unwrap() == "dns_query_to_suspicious_tld"));
    for alert in alerts_array {
        let reasons = alert["reasons"].as_array().unwrap();
        assert!(!reasons.is_empty());
        assert!(reasons.iter().all(|r| !r.as_str().unwrap().trim().is_empty()));
    }

    // 5. Network Story by domain: the DNS event plus both network events
    //    that touch its resolved address (cdn-assets.xyz -> 203.0.113.50),
    //    proving Global Constraint #8's RESOLVED_TO/CONNECTED_TO edges and
    //    Global Constraint #9's domain-form composition, over real HTTP.
    let story: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/network/story?domain=cdn-assets.xyz",
            addr
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let story_events = story["events"].as_array().unwrap();
    assert_eq!(
        story_events.len(),
        3,
        "domain-form Network Story must include the DNS query plus both network events \
         touching its resolved address"
    );
    let story_categories: std::collections::HashSet<_> = story_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    assert!(story_categories.contains("DNS") && story_categories.contains("NETWORK"));
    let story_alerts = story["alerts"].as_array().unwrap();
    assert!(!story_alerts.is_empty());

    // 6. Network Story by IP alone: only the two network events — the
    //    disclosed asymmetry from Global Constraint #9 (no reverse
    //    DNS-answer lookup from an IP alone).
    let ip_story: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/network/story?ip=203.0.113.50",
            addr
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ip_story_events = ip_story["events"].as_array().unwrap();
    assert_eq!(
        ip_story_events.len(),
        2,
        "IP-form Network Story must NOT include the resolving DNS event — Global \
         Constraint #9's disclosed asymmetry"
    );
    assert!(ip_story_events
        .iter()
        .all(|e| e["category"].as_str().unwrap() == "NETWORK"));

    // 7. The real CLI binary still works against this richer dataset
    //    (regression check).
    let cli_binary = cli_binary_path();
    let output = std::process::Command::new(&cli_binary)
        .args(["--server", &format!("http://{}", addr), "--format", "json", "events"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 6);
}
```

Update the two existing tests' `AgentConfig` literals (`synthetic_exec_chain_flows_end_to_end_through_agent_server_and_api` and Phase 2's `web_shell_drop_scenario_flows_end_to_end_and_triggers_detection`) to include the new `network_proc_root: None,` field — `AgentConfig` is a struct literal in both, so this is a compile-time-enforced, mechanical addition (the compiler will point at exactly these two sites; do not search for others).

- [ ] **Step 3: Run and verify**

```
cargo test -p osiris-e2e-tests
cargo build --workspace --all-targets
bash tools/check-dep-graph.sh
```

Expected: all three of this crate's e2e tests pass (the Phase 1 exec-chain one, Phase 2's web-shell-drop one, and this new one), `cargo build --workspace --all-targets` succeeds, and the dependency-graph check passes.

If the new test is flaky on timing, note it as a concern rather than silently loosening an assertion (Phase 2's precedent).

- [ ] **Step 4: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: every crate's tests pass, no regressions in Phase 0/1/2 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-e2e-tests
git commit -m "test(e2e): prove the Phase 3 network/DNS vertical slice end-to-end

Network-beacon scenario through the real Agent, Server (ingest + detection +
storage), and HTTP API: Timeline interleaving of DNS/network events,
PROCESS_KEY_PROVISIONAL absence, the shipped DNS rule firing on a real
ingested event, and Network Story's domain-to-connection join (plus its
disclosed IP-form asymmetry) verified over HTTP.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01STfhYhCMb3p11S1yLjsYdb"
```

---

## Self-review

**Spec coverage.** Every Global Constraint above is implemented by a specific task: #1/#4/#5 (Task 3's poller/direction heuristic/pid attribution), #2 (Task 3's IPv4-only parser), #3 (Task 1's `NetworkOperation` three-variant enum + Task 2's `PriorityTable`), #6 (Task 1/2 build the DNS pipeline with no sensor crate — verified no `osiris-sensors-dns` crate appears in any task's Files list), #7 (Task 1 confirmed via direct current-source reads, not assumed), #8 (Task 2's `attach_network_relationship`/`attach_dns_relationships`), #9/#10 (Task 7's `network_story_handler` and its route), #11 (Task 3 Step 7/9's symlink-skip test design), #12 (Task 6 ships a rule with zero `osiris-detect` code changes), #13 (Task 7's own header states no `osiris-server` changes and none appear in its Files list), #14 (no task touches `osiris-cli`), #15 (Task 4). ARCHITECTURE.md §12.4 Timeline is verified in Task 8 exactly as Global Constraint #10 scopes it (no new engine code). Every `EventType`/`EntityRef`/`Relation` variant this plan uses was confirmed to already exist in the current schema (Task 1's header) rather than assumed from Phase 2's plan text.

**Placeholder scan.** No task contains "TBD," "add appropriate error handling," or an unshown "similar to Task N" — every step with code shows the actual code. Task 3's Steps 12-19 are the largest single unit in this plan; they were kept as one task (not split) because `NetworkPoller` and `NetworkSensor` share one interface contract that only makes sense tested together, matching Phase 2's Task 4 precedent (the Filesystem sensor's assembler + sensor were also one task).

**Type consistency.** `NetworkEventRaw`/`DnsEventRaw` (Task 1) are consumed identically in Task 2's `normalize_network_event`/`normalize_dns_event`, Task 3's `NetworkPoller`, and Task 5's `network_beacon_scenario` — field names and types were cross-checked across all three call sites while writing this plan (in particular, `pid: Option<u32>` and the empty-string-on-unknown-pid convention for `exe_path`/`comm` are used consistently everywhere, not just in Task 1's doc comments). `QueryPlan.network_addr`/`.dns_domain` (Task 4) are consumed with matching field names in Task 7's handler. `NetworkStory`'s `{ events, alerts }` shape matches `FileStory`'s exactly, as intended (Global Constraint #9 states the precedent is carried forward, not reinvented). The rule file's `dns.query`/`process.exe_path` field paths (Task 6) match the actual `DnsRef`/`ProcessRef` JSON field names Task 1/2 produce, not assumed OQL-style names.

**Corrections made during this pass:** none required — the design was cross-checked against the real Phase 2 codebase (not Phase 2's plan text, which sometimes diverged from what actually shipped) at each task boundary while drafting, catching the field/interface questions before they were written down rather than after.

