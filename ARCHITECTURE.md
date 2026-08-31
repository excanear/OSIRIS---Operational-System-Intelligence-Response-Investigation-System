# OSIRIS — ARCHITECTURE.md

**Operational System Intelligence & Response Investigation System**
Status: v1.0 (definitive, pre-implementation) · Scope: Linux-native, server/cloud-first · Companion to `MASTER ENGINEERING PROMPT.md`

This document is the single technical source of truth for building OSIRIS. It is written so that a fresh engineering session can open this file alone and begin implementation without re-reading or re-deriving anything from the master prompt. Where the master prompt states an aspiration, this document states the concrete mechanism, the interface, the technology, and the justification.

No code is included. This is architecture only.

---

## 0. How to read this document

- Sections 1–2: system-level architecture and layering rules.
- Sections 3–7: the Agent, sensors, eBPF, kernel telemetry — the collection plane.
- Sections 8–11: pipeline, bus, schema — the data plane.
- Sections 12–15: storage, detection/correlation/risk, investigation/DFIR — the analysis plane.
- Sections 16–19: API, CLI, Console — the interaction plane.
- Sections 20–24: security, privilege boundaries, performance, plugins, multi-host future.
- Sections 25–29: repo structure, technology decisions, data flow trace, dependency graph, roadmap.
- Section 30: architecture self-review (risks found and corrected).

---

## 1. System Architecture (High Level)

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                              OSIRIS CONSOLE                              │
│              (TypeScript/React SPA — SOC / DFIR / Hunting UI)           │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ HTTPS / REST + WebSocket (query, stream)
┌───────────────────────────────▼───────────────────────────────────────┐
│                               OSIRIS API                                 │
│        (Rust, axum — authn/authz, query surface, alert/incident CRUD)   │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ in-process calls / gRPC (if split later)
┌───────────────────────────────▼───────────────────────────────────────┐
│                              OSIRIS CORE                                  │
│  Detection Engine · Correlation Engine · Risk Engine · Baseline Engine   │
│  Investigation Engine · Evidence Engine · Response Engine · Query Engine │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ query / write
┌───────────────────────────────▼───────────────────────────────────────┐
│                          STORAGE (Hot/Warm/Cold)                         │
│                 SQLite (edge/MVP) → ClickHouse (fleet/scale)             │
└───────────────────────────────▲───────────────────────────────────────┘
                                 │ normalized, enriched events (batched)
┌───────────────────────────────┴───────────────────────────────────────┐
│                            EVENT PIPELINE                                │
│      Collect → Normalize → Enrich → Validate → Prioritize → Queue       │
└───────────────────────────────▲───────────────────────────────────────┘
                                 │ raw sensor events
┌───────────────────────────────┴───────────────────────────────────────┐
│                              EVENT BUS                                   │
│        (in-process, priority-lane, bounded MPSC — see §9)               │
└──────────┬───────────────────────┬───────────────────────┬────────────┘
           │                       │                        │
   ┌───────▼───────┐      ┌────────▼────────┐      ┌────────▼────────┐
   │  eBPF Sensors │      │  Kernel Sensors  │      │  User Sensors   │
   │ (exec, net,   │      │ (audit, fanotify,│      │ (systemd, cron, │
   │  file, sock)  │      │  procfs, /sys)   │      │  container API) │
   └───────┬───────┘      └────────┬────────┘      └────────┬────────┘
           └───────────────────────┼────────────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │     LINUX HOST     │
                          └────────────────────┘
```

**Deviation from the master prompt's sketch, justified:** the master prompt places `OSIRIS Agent` as a peer of Console/Core. In this architecture, the **Agent is the process that hosts the entire left-hand collection stack (sensors → pipeline → bus) on each monitored host**, while **Core, Storage, API run inside a separate process, the OSIRIS Server** (see §2.1). This split exists from day one — even on a single-host MVP where Agent and Server run on the same machine — because the privilege boundary between "thing that touches the kernel" and "thing that answers queries over the network" is a security requirement, not a scaling nicety (§21). Bolting this split on later means rewriting IPC, config and lifecycle; building it in from v0.1 costs one Unix domain socket and one supervisor process.

### 1.1 Process topology (MVP, single host)

```text
Host
 ├── osirisd (Agent)        — root or CAP_* capabilities, no network listener
 │     runs: sensors, eBPF loader, event pipeline, local bounded bus
 │     ships normalized events over a local Unix socket (UDS) to the Server
 │
 └── osiris-server           — unprivileged user, binds loopback/mTLS port
       runs: ingestion endpoint, Core (detection/correlation/risk),
             storage engine, API, static Console assets
```

Both binaries are started by systemd as separate units (`osirisd.service`, `osiris-server.service`) with `Requires=`/`After=` ordering. This is the same topology that scales to multi-host (§24): the Agent talks the same wire protocol to a local server or a remote one.

---

## 2. Module Architecture

### 2.1 Layering rule

Every layer depends only downward, never sideways or upward, and never reaches through a layer:

```text
Console  →  API  →  Core  →  Storage
                      ↑
             Query Engine (used by API, Core, CLI)

Agent:  Sensors → Event Pipeline → Event Bus → Transport (to Server)
```

- Sensors never call Storage, Detection, or the API directly. They only emit onto the local Event Bus.
- Core never talks to sensors. It only consumes normalized events from Storage/ingestion and writes back detections/risk/evidence.
- The Console never talks to Storage or sensors directly. It only talks to the API.
- The CLI is a thin client of the same API (§17) — it does not duplicate query or business logic.

This is enforced structurally by Cargo workspace crate boundaries (§25): a crate that must not depend on another simply does not declare the dependency, and CI runs `cargo deny`/`cargo machete` style dependency-graph checks to catch violations.

### 2.2 Conceptual layer list → concrete crate/package mapping

| Conceptual layer (master prompt §6) | Concrete component | Process |
|---|---|---|
| OSIRIS Agent | `osiris-agent` (binary) | Agent |
| OSIRIS Sensors | `osiris-sensors-*` (crates per sensor) | Agent |
| Kernel Telemetry | `osiris-kernel` (audit/fanotify/procfs backends) | Agent |
| eBPF Layer | `osiris-ebpf` (loader + skeletons) | Agent |
| Event Pipeline | `osiris-pipeline` | Agent |
| Event Bus | `osiris-bus` | Agent (local) + wire protocol (Agent↔Server) |
| Normalization | `osiris-pipeline::normalize` | Agent |
| Enrichment | `osiris-enrich` | Agent (local/cheap) + Server (contextual/expensive) |
| Storage | `osiris-storage` (trait) + `osiris-storage-sqlite`, `osiris-storage-clickhouse` | Server |
| Query Engine | `osiris-query` (OQL parser/planner) | Server |
| Detection Engine | `osiris-detect` | Server |
| Correlation Engine | `osiris-correlate` | Server |
| Risk Engine | `osiris-risk` | Server |
| Baseline Engine | `osiris-baseline` | Server |
| Investigation Engine | `osiris-investigate` | Server |
| Evidence Engine | `osiris-evidence` | Server |
| Threat Hunting Engine | reuses `osiris-query` + `osiris-investigate` | Server |
| Response Engine | `osiris-response` | Server (dispatches back to Agent for local actions) |
| API | `osiris-api` | Server |
| CLI | `osiris-cli` (binary) | Client |
| Console | `osiris-console` (TS/React) | Client |
| Configuration | `osiris-config` | shared crate, both processes |
| Audit | `osiris-audit` | shared crate, both processes |
| Health | `osiris-health` | shared crate, both processes |
| Telemetry (self) | `osiris-selftelemetry` (metrics/tracing glue) | shared crate |

`osiris-schema` (the Event Schema, §10) is the one crate every other Rust crate is allowed to depend on without restriction, since it is pure data definitions with no behavior.

---

## 3. OSIRIS Agent Architecture

### 3.1 Responsibilities (from master prompt §7, made concrete)

The Agent is a **supervisor**, not a monolith. It owns:

1. **Sensor supervision** — a `SensorSupervisor` that starts each enabled sensor as an isolated async task (Tokio), restarts it on panic with exponential backoff, and demotes a sensor to `DEGRADED` (not killed) after N consecutive failures rather than silently disabling it.
2. **Configuration loading and hot-reload** — reads `/etc/osiris/agent.yaml`, validates against a schema, watches the file (inotify) for changes, and applies non-disruptive changes (e.g., telemetry level, filters) without restart; disruptive changes (e.g., enabling a new eBPF program) trigger a controlled sensor restart, never a full agent restart.
3. **Lifecycle** — `Initializing → Running → Degraded → Draining → Stopped`, with `Draining` flushing the local bus and in-flight batches before exit (SIGTERM handling with a bounded grace period; SIGKILL is a failure to design against, not a control path).
4. **Health reporting** — aggregates per-sensor `Health` (§3.3) into an agent-level health document, exposed locally over the UDS control endpoint and forwarded to the Server as `AGENT_HEALTH` events.
5. **Buffer control** — owns the bounded Event Bus (§9) and enforces backpressure policy per priority lane.
6. **Policy application** — telemetry level (§6), sensor enable/disable, filter rules (e.g., exclude noisy paths) are all agent-local policy, applied before events ever reach the pipeline's expensive stages.
7. **Event transmission** — batches normalized events and pushes them to the Server over the local/remote transport (§3.2), with local disk spooling when the Server is unreachable (bounded, with the same priority-aware drop policy as the in-memory bus).
8. **Shutdown control, failure detection, metrics** — covered by health/lifecycle above; metrics are exported via the shared `osiris-selftelemetry` crate (Prometheus text format on a loopback-only endpoint).

### 3.2 Agent internal architecture

```text
osirisd
│
├── Supervisor
│    ├── ConfigManager        (load, validate, watch, diff)
│    ├── SensorRegistry       (enable/disable, capability negotiation)
│    ├── SensorSupervisor     (spawn, restart, backoff, health rollup)
│    └── ShutdownCoordinator  (signal handling, drain sequencing)
│
├── Sensors (§4)               — each an isolated Tokio task implementing
│                                  the Sensor trait (§4.1)
│
├── Event Pipeline (§8)        — Collect/Normalize/Enrich(local)/Validate/
│                                  Prioritize stages, single pipeline shared
│                                  by all sensors (fan-in)
│
├── Event Bus (§9, local half) — bounded, priority-lane, in-process
│
├── Transport
│    ├── LocalUDS client      — Agent→Server on same host (MVP default)
│    ├── mTLS/gRPC client     — Agent→remote Server (multi-host future, §24)
│    └── DiskSpool            — bounded on-disk queue for outage buffering
│
└── Control Plane
     ├── Health/Metrics endpoint (UDS, loopback-only)
     └── Self-audit log (osiris-audit, local append-only file, §22)
```

**Why one shared pipeline instance, not one per sensor:** normalization, enrichment ordering, prioritization, and batching must be globally consistent (e.g., a `CRITICAL` file event from the filesystem sensor must not queue behind a burst of `VERBOSE` network events from another sensor). A single fan-in pipeline with per-sensor input channels feeding one prioritized bus gives that guarantee; N independent pipelines would each need their own backpressure and priority logic, duplicating complexity and losing cross-sensor prioritization.

### 3.3 Sensor health/metrics contract

Every sensor reports, at minimum every 5s or on state change:

```text
SensorHealth {
  name, state: {STARTING, HEALTHY, DEGRADED, FAILED, STOPPED},
  events_emitted_total,
  events_dropped_total,
  last_error: Option<String>,
  last_event_at: Option<timestamp>,
  capability_flags: [...],     // what this sensor is actually using
  p99_emit_latency_us,
}
```

`DEGRADED` means "producing events but with reduced fidelity or partial coverage" (e.g., eBPF program failed to load, fell back to audit). `FAILED` means "not producing events" but the sensor task is still alive and retrying. The Agent never hides a `FAILED` sensor — it always surfaces in `osiris health` and `AGENT_HEALTH` events (master prompt §57, "never hide telemetry loss").

---

## 4. Sensor Architecture

### 4.1 Sensor trait (interface, not implementation)

Every sensor, regardless of backend (eBPF, audit, fanotify, procfs polling, systemd D-Bus, container runtime API), implements one uniform lifecycle contract:

```text
trait Sensor {
    fn name(&self) -> &'static str
    fn initialize(&mut self, ctx: &SensorContext) -> Result<(), SensorError>
    fn start(&mut self) -> Result<(), SensorError>
    fn stop(&mut self) -> Result<(), SensorError>
    fn health(&self) -> SensorHealth
    fn capabilities(&self) -> SensorCapabilities
    fn metrics(&self) -> SensorMetrics
}
```

`SensorContext` carries: the output channel to the Event Pipeline (bounded `mpsc`), the effective `TelemetryLevel`, sensor-specific config, a `CapabilityProbe` handle (§20), and a `CancellationToken` for cooperative shutdown.

`capabilities()` is called **before** `start()`, at registration time, and answers "what can this sensor actually do on this host" (e.g., `NetworkSensor` on a 4.14 kernel without BTF reports `capabilities = {ebpf: false, audit_fallback: true}`). The Supervisor uses this to decide whether to start the sensor at all, start it in a degraded mode, or skip it with a logged, health-visible reason — never a silent no-op.

### 4.2 Sensor independence

Sensors do not import each other. Cross-sensor relationships (e.g., "this network connection belongs to this process") are **not** resolved inside sensors — they are resolved by the Enrichment stage (§8.3) using an in-memory **Process/Entity Resolver** that all sensors populate by emitting identity-bearing events, but no sensor queries another sensor's internal state directly. This keeps sensors independently testable and replaceable (e.g., swapping the eBPF-based exec sensor for an audit-based one changes nothing downstream).

### 4.3 Sensor catalog and backend per sensor (MVP → later)

| Sensor | Primary backend | Fallback backend | Telemetry level introduced |
|---|---|---|---|
| Process/Exec | eBPF (tracepoint `sched_process_exec`, `sched_process_fork`, `sched_process_exit`) | Linux Audit (`execve` rules) | MINIMAL |
| Filesystem | eBPF (LSM hooks `path_mknod`, `path_rename`, `inode_permission` where available) + fanotify | Audit (`watch` rules), inotify | STANDARD |
| Network | eBPF (kprobes/tracepoints on `tcp_connect`, `tcp_close`, `udp_sendmsg`, cgroup skb hooks) | `/proc/net/tcp[6]` polling + conntrack | STANDARD |
| DNS | eBPF uprobe on resolver libs (best-effort) + AF_PACKET/pcap on port 53 | passive pcap only | DETAILED |
| Identity/Session | Linux Audit (`PAM`, `login`), `/var/run/utmp`, `/proc/<pid>/loginuid` | utmp/wtmp polling | MINIMAL |
| Systemd | D-Bus (`org.freedesktop.systemd1`) subscription | polling `systemctl list-units` | STANDARD |
| Persistence | File watch (fanotify) on known persistence paths + periodic scan | periodic scan only | STANDARD |
| Kernel module | eBPF tracepoint (`module_load`/`module_free`) | `/proc/modules` diff polling | STANDARD |
| Container | containerd/CRI-O/Docker API (unix socket) + cgroup/namespace correlation | cgroup-only correlation (no container metadata) | STANDARD |
| Namespace | procfs (`/proc/<pid>/ns/*`) resolved at exec time, cached | — | STANDARD |
| Cgroup | procfs (`/proc/<pid>/cgroup`) + cgroup v2 `cgroup.events`/pressure files | cgroup v1 hierarchy walk | STANDARD |
| Security (LSM/capabilities) | eBPF LSM hooks where kernel supports `CONFIG_BPF_LSM`; audit for capability use | audit only | DETAILED |
| Module/generic Security | see above | — | DETAILED |

Justification for the fallback design, not an afterthought: RHEL 8 (kernel 4.18 backported), Amazon Linux 2 (kernel 4.14/5.10), Ubuntu 22.04 (5.15), Debian 12 (6.1) span a real spread of eBPF/BTF/LSM support (§20). A sensor that only works on the newest kernel is not "Linux-first," it is "Ubuntu-24.04-first." Every sensor above is designed with a non-eBPF path from day one, even if the MVP implements only the eBPF path first and stubs the fallback as a tracked follow-up — the **interface** must accommodate it so retrofitting isn't a rewrite.

---

## 5. eBPF / Kernel Telemetry Architecture

### 5.1 OSIRIS eBPF Engine — position in the stack

eBPF is a **sensor backend technology**, not the sensor itself and not the only telemetry source (master prompt §9 explicitly requires this framing). The eBPF Engine is a shared service used by multiple sensors:

```text
osiris-ebpf (crate)
│
├── Loader             — libbpf-rs based; loads compiled BPF object (CO-RE),
│                          verifies, attaches, manages program lifecycle
├── Skeleton Registry   — one .bpf.c source + generated skeleton per program,
│                          versioned (§5.4)
├── Ring Buffer Reader  — BPF_MAP_TYPE_RINGBUF consumer, per-program,
│                          feeds directly into Sensor output channels
├── Map Manager         — BPF_MAP_TYPE_HASH/LRU_HASH for kernel-side state
│                          (e.g., PID→context correlation maps)
└── Capability Probe    — at startup: kernel version, BTF presence,
                           BPF_LSM availability, JIT status, program-type
                           support (bpf_probe via a minimal load-and-unload
                           test per feature)
```

### 5.2 Technology choice: CO-RE + libbpf, Aya considered and rejected for v1

Two realistic Rust-ecosystem paths exist: **Aya** (pure-Rust eBPF, no libbpf/clang dependency at runtime) and **libbpf-rs + C-based BPF programs compiled with clang, loaded CO-RE style**.

**Decision: libbpf-rs + CO-RE for kernel-space programs; Rust for all user-space loader/consumer code.**

Justification:
- CO-RE (Compile Once – Run Everywhere) via libbpf + BTF is the de-facto portability mechanism the kernel community and every major Linux eBPF-based security product (Falco's modern eBPF driver, Tetragon, Tracee) has converged on. It directly solves the "different kernel versions/distros" requirement (master prompt §4, §82): one compiled `.bpf.o` object adapts its struct offsets at load time using the target kernel's BTF, instead of needing per-kernel-version recompilation (the old "BCC" approach) or a Rust-only reimplementation of every kernel struct layout (Aya's approach, which is improving but still has narrower verifier/helper coverage as of this writing and a smaller track record for LSM-hook and complex ring-buffer patterns).
- Aya is reconsidered as a **future** option once its LSM/CO-RE coverage matures (tracked as an ADR follow-up, §28), because it would remove the clang/libbpf C toolchain dependency entirely. Not choosing it for v1 is a pragmatic, revisitable decision, not a permanent one — this is exactly the kind of "adapt if a better decision is found" case the master prompt invites (§5), documented here instead of silently deviating.
- All BPF **kernel-space** code is still written in the minimal, restricted-C subset the verifier accepts (unavoidable regardless of loader choice) — user-space loading, ring buffer consumption, map management, and all business logic are Rust.

### 5.3 What runs in kernel-space vs. user-space (master prompt §9's "minimum in kernel")

**Kernel-space (BPF programs) do only:**
- Capture the syscall/tracepoint/LSM-hook arguments already resident in kernel context (pid, uid, comm, args, return codes, socket tuples).
- Minimal filtering that is only possible in-kernel (e.g., skip events for the OSIRIS Agent's own PID to prevent feedback loops; a pid-cgroup allow/deny map for scoping).
- Push a fixed-shape raw record into a `BPF_MAP_TYPE_RINGBUF`.
- Maintain small correlation maps (e.g., in-flight `execve` argument accumulation across multiple tracepoint hits) — bounded size, LRU eviction, never unbounded growth.

**User-space does everything else:** path resolution beyond what's cheaply available in-kernel, hashing, string formatting, cross-referencing the Process/Entity Resolver, container/namespace context lookups, MITRE mapping, risk scoring, and all business logic. This is a direct, load-bearing consequence of §9's instruction and also a stability requirement: a bug in kernel-space code can panic the host; a bug in user-space code can only crash a sensor task, which the Supervisor restarts.

### 5.4 Program versioning and safety

Each `.bpf.c` program carries a `SCHEMA_VERSION` constant compiled into its ring-buffer record struct, mirrored in the corresponding Rust struct via a shared `#[repr(C)]` definition generated from one canonical source (build-time codegen, not hand-duplicated structs — a hand-sync mismatch here is a memory-safety bug, not a logic bug). The Loader refuses to attach a program whose compiled record version doesn't match the Rust consumer's expected version, failing sensor `initialize()` with a clear `SensorError::SchemaMismatch` rather than silently misreading kernel memory.

Every program is validated pre-merge in CI against a matrix of representative kernels (see §26, CI section) using the verifier in a VM/container with the target BTF, not just "compiles."

### 5.5 Explicit non-goal

OSIRIS does not attempt full syscall-level capture of "every syscall, always." Per master prompt §10/§61, kernel-space telemetry is scoped to what each `TelemetryLevel` (§6 below) declares, and FORENSIC-level deep capture is explicitly a **temporary, operator-triggered** mode (time-boxed, auto-reverting), never a default.

---

## 6. Telemetry Levels — concrete mechanism

```text
enum TelemetryLevel { Minimal, Standard, Detailed, Forensic }
```

This is not a single global knob with vague meaning — it is a **per-sensor capability matrix** resolved at config-load time:

| Sensor | MINIMAL | STANDARD | DETAILED | FORENSIC |
|---|---|---|---|---|
| Process/Exec | create/exit, pid/ppid/uid/exe | + full argv, env allowlist keys | + interpreter detection, hash-on-exec | + full env capture, per-syscall args on flagged PIDs |
| Filesystem | none | create/delete/rename on watched paths | + modify/permission/owner-change, broader path set | + hash on every write, full path set, read events |
| Network | none | connect/accept/close, 5-tuple | + byte counters, per-connection process attach | + packet-level metadata capture window |
| DNS | none | query+response on watched resolvers | all queries | + raw payload capture (bounded window) |

The key architectural point: **raising the level is a targeted, reversible config change scoped to specific sensors or specific entities (e.g., "FORENSIC for PID tree rooted at 4821, for 30 minutes")**, never a global "log everything" switch — this is what makes §61's "never capture/store/process everything without measuring cost" and §11's "increasing telemetry cannot compromise stability" both enforceable: the Agent computes an estimated additional events/sec for the requested scope before applying it, and rejects/warns if it would exceed a configured budget (see Performance Model, §22).

---

## 7. Event Pipeline

### 7.1 Stages (in order, per event)

```text
Collect → Normalize → Enrich(local) → Validate → Prioritize → Queue(Bus)
```

1. **Collect** — sensor emits a `RawEvent` (backend-specific shape) onto its bounded output channel. This is the only stage sensors participate in.
2. **Normalize** — maps `RawEvent` → `CanonicalEvent` (Event Schema v1, §10) via a per-source-type `Normalizer`. The original raw payload is retained in `raw_event` (bounded size, truncated with a flag if oversized) so nothing is thrown away silently (master prompt §31).
3. **Enrich (local)** — cheap, always-available context only: resolve PID→process identity via the in-memory Process Resolver, attach cgroup/namespace/container IDs already cached from the Container/Namespace sensors, attach host identity (`host_id`, `boot_id`). Expensive/optional enrichment (hash computation for large files, MITRE mapping, baseline comparison) happens **server-side** post-ingestion, not on the Agent's hot path — this keeps Agent CPU bounded regardless of Server-side analytical load.
4. **Validate** — schema conformance check (required fields present, enums valid) against the versioned schema. A failing event is not dropped silently: it is tagged `INVALID`, counted in a metric, and still forwarded (best-effort) so an operator can see what's malformed rather than have a silent gap.
5. **Prioritize** — assigns one of the five bus lanes (§9) based on `event_type`/`severity` from a configurable priority table (e.g., `PRIVILEGE_CHANGE` → CRITICAL, `FILE_READ` → VERBOSE).
6. **Queue** — pushed onto the Event Bus.

### 7.2 Why local enrichment is capped

This is the answer to a real tension in the master prompt: §32 wants rich enrichment, §61 wants low CPU/RAM and bounded resource use, and §64 wants the privileged Agent kept minimal. Splitting enrichment into a **cheap/local** phase (Agent, privileged, hot path) and an **expensive/contextual** phase (Server, unprivileged, off the hot path) satisfies all three: the Agent stays small and fast, and the Server — which can be scaled/tuned independently and holds the historical data needed for baseline/rarity comparisons anyway — does the heavy lifting.

---

## 8. Event Bus

### 8.1 Local bus (inside the Agent)

An in-process, `tokio::sync::mpsc`-based bounded multi-producer/single-consumer structure, one bounded channel per priority lane:

```text
CRITICAL  — capacity: small, never dropped (blocks producer with timeout,
            then spills to DiskSpool rather than drop — see policy below)
HIGH      — capacity: medium, drop-oldest under sustained overflow
NORMAL    — capacity: large, drop-oldest under sustained overflow
LOW       — capacity: large, drop-oldest aggressively
VERBOSE   — capacity: largest, drop-newest immediately under any pressure
            (verbose events are, by definition, the least individually
            valuable — cheapest to lose first)
```

A single consumer task drains lanes in strict priority order with a starvation guard (a lane below CRITICAL is guaranteed at least one drain slot per N cycles even under sustained CRITICAL load, so HIGH/NORMAL don't starve completely during a burst).

**Never-silently-drop-CRITICAL, made concrete:** CRITICAL events (privilege escalation, persistence change, detected process-injection indicators) that cannot be enqueued within a bounded wait are written to the `DiskSpool` (append-only, bounded-size ring file) rather than discarded, and a `bus.critical_spilled_total` metric fires — this satisfies §33's "critical events never silently discarded" without allowing an unbounded queue to OOM the Agent.

### 8.2 Bus metrics (mandatory, per lane)

`enqueued_total`, `dequeued_total`, `dropped_total`, `spilled_total`, `queue_depth_current`, `queue_depth_max`, `time_in_queue_p50/p99`.

### 8.3 Agent↔Server transport (the "distributed" half of the bus)

Batches of normalized events cross the Agent→Server boundary over a length-prefixed, compressed (zstd) protobuf/Cap'n Proto stream (§27 justifies the serialization choice) on a Unix domain socket (same host, MVP) or mTLS-authenticated TCP (remote, §24). This transport carries the same five-lane priority semantics: batches are tagged with the highest-priority lane they contain and the Server's ingestion endpoint applies analogous backpressure back toward the Agent (a slow Server causes the Agent's DiskSpool to grow, not an unbounded memory queue).

---

## 9. Event Schema v1

### 9.1 Design principles

- **Versioned and additive.** `schema_version` is a field on every event; the schema evolves by adding optional fields, never by repurposing or removing a field within a major version. A breaking change bumps the major version and requires an explicit migration path in storage (§12.4).
- **Canonical envelope + typed payload.** Every event has a common envelope (identity, timing, entities, relationships) plus one `event_data` payload whose shape is determined by `event_type`. This avoids one giant flat struct with hundreds of mostly-null columns while keeping a single queryable, storable unit.
- **Nothing is a permanent identity except what actually is one** (§29): PIDs are never used alone as identity.

### 9.2 Canonical envelope (fields from master prompt §28, made concrete with types/semantics)

```text
CanonicalEvent {
  // Identity
  event_id: UUIDv7                     // time-sortable, globally unique
  schema_version: string                // e.g. "1.0"
  host_id: UUIDv4                       // stable per installation, persisted in /etc/osiris/host_id
  boot_id: string                       // from /proc/sys/kernel/random/boot_id — scopes PID reuse

  // Timing
  timestamp: uint64 (ns, UTC, wall-clock, from CLOCK_REALTIME)
  monotonic_timestamp: uint64 (ns, from CLOCK_MONOTONIC, boot-scoped)
                                         // wall clock can jump (NTP); ordering
                                         // and duration math use monotonic

  // Classification
  event_type: enum (e.g. PROCESS_EXEC, FILE_CREATE, NETWORK_CONNECT, ...)
  category: enum (PROCESS, FILE, NETWORK, DNS, IDENTITY, PRIVILEGE,
                   SYSTEMD, PERSISTENCE, KERNEL_MODULE, CONTAINER, SECURITY)
  severity: enum (INFO, LOW, MEDIUM, HIGH, CRITICAL)   // sensor-assigned,
                                         // distinct from Risk Engine's score

  // Actors / context (each Optional<T> — "when applicable" per master prompt)
  host: HostRef { host_id, hostname, distro, kernel_version, cloud: Optional<CloudContext> }
  user: Optional<UserRef>       { uid, gid, euid, egid, username, loginuid }
  session: Optional<SessionRef> { session_id, tty, remote_addr, auth_method }
  process: Optional<ProcessRef> { process_key, pid, exe_path, cmdline,
                                   exe_hash: Optional<string>, start_time_mono }
  parent_process: Optional<ProcessRef>
  thread: Optional<ThreadRef>   { tid }
  file: Optional<FileRef>       { path, previous_path, inode, size, mode,
                                   owner_uid, owner_gid, hash: Optional<string> }
  network: Optional<NetworkRef> { src_ip, src_port, dst_ip, dst_port, proto,
                                   direction, bytes: Optional<u64> }
  dns: Optional<DnsRef>         { query, qtype, response_ips, ttl }
  device: Optional<DeviceRef>
  service: Optional<ServiceRef> { unit_name, unit_type, action }
  container: Optional<ContainerRef> { container_id, image, runtime, pod_ref: Optional<PodRef> }
  namespace: Optional<NamespaceRef> { pid_ns, net_ns, mnt_ns, user_ns, ipc_ns, uts_ns, cgroup_ns }
  cgroup: Optional<CgroupRef>   { cgroup_path, cgroup_id, version }
  kernel: Optional<KernelRef>   { module_name, syscall_nr: Optional<u32> }

  // Provenance
  source: enum (EBPF, AUDIT, FANOTIFY, PROCFS, DBUS, CONTAINER_API, SYNTHETIC)
  provider: string              // specific sensor name + backend, e.g. "exec_sensor/ebpf"
  raw_event: Optional<bytes>    // bounded, original payload for forensic replay
  normalized_event: CanonicalEvent (self — the record itself IS this)

  // Derived (populated post-ingestion, not by sensors)
  relationships: [EntityRelationship]   // see §9.4
  tags: [string]
  risk: Optional<RiskAnnotation> { score, severity, reasons: [string], rule_ids: [string] }
}
```

`ProcessRef.process_key` is the composite identity that solves §29's PID-reuse problem: `process_key = hash(host_id, boot_id, pid, start_time_monotonic)`. Two different processes that happen to reuse the same PID across the same boot get different `process_key`s because `start_time_monotonic` differs (this is the same technique the Linux audit subsystem and `/proc/<pid>/stat`'s `starttime` field make possible, and what tools like `auditd` rely on for correlation).

### 9.3 event_type taxonomy (initial, extensible)

Grouped by `category`, each a stable string enum persisted as text (not a bare int) so schema evolution and storage-level filtering stay human-debuggable:

```text
PROCESS:     PROCESS_EXEC, PROCESS_FORK, PROCESS_EXIT
FILE:        FILE_CREATE, FILE_DELETE, FILE_RENAME, FILE_MOVE, FILE_MODIFY,
             FILE_WRITE, FILE_EXECUTE, FILE_PERMISSION_CHANGE,
             FILE_OWNER_CHANGE, FILE_ATTRIBUTE_CHANGE
NETWORK:     SOCKET_CREATE, SOCKET_BIND, SOCKET_LISTEN, NETWORK_CONNECT,
             NETWORK_ACCEPT, NETWORK_CLOSE
DNS:         DNS_QUERY
IDENTITY:    SESSION_LOGIN, SESSION_LOGOUT, SESSION_CREATE, SESSION_TERMINATE
PRIVILEGE:   PRIVILEGE_UID_CHANGE, PRIVILEGE_GID_CHANGE,
             PRIVILEGE_CAPABILITY_CHANGE, PRIVILEGE_SUDO, PRIVILEGE_SETUID
SYSTEMD:     SERVICE_CREATE, SERVICE_MODIFY, SERVICE_START, SERVICE_STOP,
             SERVICE_DELETE, TIMER_CREATE, TIMER_MODIFY
PERSISTENCE: PERSISTENCE_CREATED, PERSISTENCE_MODIFIED, PERSISTENCE_REMOVED
KERNEL_MODULE: MODULE_LOAD, MODULE_UNLOAD
CONTAINER:   CONTAINER_CREATE, CONTAINER_START, CONTAINER_STOP, CONTAINER_DESTROY
SECURITY:    LSM_DENIAL, CAPABILITY_USE
SYSTEM:      AGENT_HEALTH, SENSOR_HEALTH, AGENT_START, AGENT_STOP
```

### 9.4 Relationships (feeding the Entity Graph, §14.5)

Relationships are **not** re-derived by every consumer; they are computed once, at enrichment time, and stored as first-class edges:

```text
EntityRelationship { from: EntityRef, to: EntityRef, relation: enum, event_id, timestamp }

relation examples: SPAWNED, EXECUTED_AS, WROTE, READ, CONNECTED_TO,
                    RESOLVED_TO, BELONGS_TO_CONTAINER, BELONGS_TO_POD,
                    RUNS_IN_CGROUP, TRIGGERED_BY_SESSION
```

`EntityRef` is a tagged union over the stable identity types (`process_key`, `file` = `(host_id, inode, device_id)` composite or path+hash, `ip`, `domain`, `user` = `(host_id, uid)`, `container_id`, `session_id`). Storing edges explicitly (rather than re-joining raw events at query time for every graph traversal) is what makes the Entity Graph (§14.5) and Incident Reconstruction (§14.4) tractable at scale — this is the one deliberate denormalization in the schema, justified because graph traversal over raw event joins does not scale past a modest event volume.

---

## 10. Storage Architecture

### 10.1 Abstract interface

```text
trait Storage {
    fn write(&self, event: CanonicalEvent) -> Result<()>
    fn batch_write(&self, events: &[CanonicalEvent]) -> Result<WriteReport>
    fn query(&self, plan: QueryPlan) -> Result<QueryResultStream>
    fn delete(&self, criteria: DeleteCriteria) -> Result<u64>
    fn retention_apply(&self, policy: RetentionPolicy) -> Result<RetentionReport>
    fn health(&self) -> StorageHealth
}
```

All of Core, API, and CLI query through this trait — never through a database-specific client directly — so the backend can change without touching detection/correlation/query logic.

### 10.2 Backend decision: SQLite for MVP/edge, ClickHouse for scale — not chosen by popularity (§79)

**MVP / single-host / edge deployments: SQLite**, WAL mode, one file per hot-storage window, with:
- A schema of a small number of wide tables mirroring the envelope + payload-per-category, plus the `relationships` edge table, all indexed on `(host_id, timestamp)`, `(process_key)`, `(event_type, timestamp)`.
- Justification: zero operational overhead (no server process, no cluster), durable, transactional, trivially backed up (file copy), and — critically — this is exactly the workload SQLite is good at below roughly single-digit-thousands of writes/sec sustained with periodic batch commits (which the Event Bus's batching already produces, §8). It also means OSIRIS Core v0.1 has **zero external service dependencies**, directly satisfying §96's ordering (correctness/security/observability before adding operational complexity) and §95's "no premature distributed infrastructure."

**Fleet/scale deployments (post-MVP, §24): ClickHouse**, because:
- The workload is fundamentally time-series/append-mostly, high-cardinality, read-pattern-is-analytical-aggregation-and-filter — ClickHouse's column-store, sparse-indexing, and native compression (LZ4/ZSTD codecs, per-column) directly target this shape, and it is the backend multiple existing security-telemetry systems (e.g., Elastic's underlying design goals, Uptycs-style architectures) converge on for the same reason.
- The `Storage` trait means this migration is additive (`osiris-storage-clickhouse` implements the same trait) — Detection/Correlation/Query code does not change.

**Explicitly deferred, not chosen for either tier initially: PostgreSQL, Parquet.** PostgreSQL is a reasonable metadata/control-plane store (incidents, rules, users, audit log — see §10.5) but is not the event-telemetry store: row-store OLTP engines don't compress or scan at the density this workload needs at fleet scale. Parquet is the right **cold-tier archival format** (§10.4) but is not a query-serving engine on its own — it is written to, and queried via, a lightweight embedded query engine (evaluated: DataFusion, given it's Rust-native and integrates cleanly with the rest of the stack) only when cold data is explicitly rehydrated for an investigation.

Per master prompt §34/§79: this decision is made on documented workload reasoning here, but the actual benchmark numbers (§23) must be produced before the ClickHouse migration is executed, not assumed.

### 10.3 Two-database split: telemetry store vs. control-plane store

```text
Event/Telemetry Store   (SQLite → ClickHouse)   — CanonicalEvent, relationships
Control-Plane Store     (SQLite → PostgreSQL)   — users, RBAC, rules, incidents,
                                                    alerts, evidence records,
                                                    audit log, agent registry
```

Justification: these have opposite workload shapes (high-volume append-only time-series vs. low-volume transactional CRUD with foreign keys and multi-row transactions) and opposite consistency needs (an incident update must be transactionally consistent; an event write can be eventually-consistent/batched). Forcing both into one engine optimizes neither. SQLite serves both in the MVP (two separate `.db` files, still zero operational overhead) and they diverge independently as each is scaled.

### 10.4 Hot / Warm / Cold

```text
HOT  (0–7 days, default):   full-fidelity, fully indexed, on local NVMe/SSD.
WARM (7–90 days, default):  compacted/compressed, indexed on (host_id, timestamp,
                             event_type) only, may live on cheaper storage.
COLD (90+ days, default):   exported as partitioned, ZSTD-compressed Parquet
                             files (partitioned by host_id/date), object-storage
                             ready (local disk in MVP, S3-compatible later),
                             queried only on-demand via DataFusion when an
                             investigation explicitly requests a rehydration.
```

A background `RetentionCompactor` (part of `osiris-storage`) runs on a schedule, moves data hot→warm→cold per the configured `RetentionPolicy`, and always operates non-destructively-first (cold export completes and is verified before hot/warm data referencing that window is deleted).

### 10.5 What is never deleted by retention

Audit log entries (§22) and Evidence Engine records (§14.6) attached to an open Incident are exempt from automatic retention deletion — they follow the Incident's lifecycle instead, since deleting evidence for an active investigation is a correctness/legal problem, not a storage-optimization opportunity.

---

## 11. Detection / Correlation / Risk Architecture

### 11.1 Detection Engine

- **Rule format:** YAML, declarative, versioned by filename+semver and a content hash stored alongside each generated `Alert` (so an alert always cites the exact rule version that fired — auditable and reproducible per §36).
- **Rule structure** (elaborating the master prompt's sketch into something evaluable):

```text
id: suspicious_execution_chain
version: 1
severity: high
mitre: { tactic: "TA0002", technique: "T1059.004" }   # optional, §17
scope: { telemetry_level_min: standard }
window: 30s                      # correlation window, if the rule spans events
conditions:
  match:
    - field: process.parent.exe_path
      op: ends_with
      value: "/sshd"
    - field: process.exe_path
      op: ends_with
      value: "/bash"
  sequence:                       # ordered sub-conditions within `window`
    - field: child_process.exe_path
      op: in
      value: ["/usr/bin/curl", "/usr/bin/wget"]
    - field: event_type
      op: eq
      value: "FILE_CREATE"
explain:
  reasons:
    - "Shell spawned directly from an SSH session"
    - "Shell spawned a network download tool"
    - "Download tool created a new file"
```

- **Execution model:** rules compile to a matcher tree evaluated incrementally as events arrive at the Server's ingestion path (stateless single-event conditions evaluated inline; stateful `sequence`/`window` conditions tracked in a bounded per-entity state table keyed by `process_key`/`session_id`, expired on window timeout). This is the same general architecture as Sigma-style detection-as-code engines, adapted to OSIRIS's own schema rather than adopting Sigma wholesale (Sigma's field taxonomy targets log sources OSIRIS doesn't have — a translation layer is a plausible **future** exporter/importer, not the native rule format).
- **Testability:** every rule ships with a fixture — a small sequence of synthetic `CanonicalEvent`s (reusable via the Event Replay/Synthetic Generator, §29 in the master prompt) that must trigger the rule, and a negative fixture that must not. CI runs the full rule set against all fixtures on every change (§26).

### 11.2 Detection explanation (§37, made structural not aspirational)

`Alert` is never allowed to exist without: `reasons: [string]` (human-readable, one per matched condition, not a generic template), `evidence: [event_id]` (the exact events that matched), and `rule_id`+`rule_version`. This is enforced at the type level — `Alert::new()` requires these fields; there is no constructor that produces a bare "Threat detected."

### 11.3 Correlation Engine

Builds `BehavioralChain`s: an ordered sequence of related events connected via the `relationships` edges (§9.4) and shared entity identity (same `process_key`, same `session_id`, same descendant-process lineage), scoped to a configurable time window. A chain is not itself an alert — it's the structural unit that both the Detection Engine's `sequence` conditions and the Investigation Engine's reconstruction (§14.4) consume. Concretely, it's implemented as a graph walk over the entity graph (§9.4/§14.5) seeded from a trigger event, bounded by depth and time window, not a separate parallel data structure duplicating the graph.

### 11.4 Risk Engine

- **Never a bare number** (§39): `RiskAnnotation { score: u8, severity: enum, reasons: [WeightedReason], related_events: [event_id] }` where `WeightedReason { label: string, weight: i16, evidence: event_id }`.
- **Scoring model for v1: transparent, additive, rule-weighted** — a configurable table (YAML, hot-reloadable, same governance as detection rules) mapping observed conditions to weights, summed and clamped, exactly as sketched in the master prompt §39. This is deliberately **not** a black-box model for v1: every score must be explainable by listing which weighted reasons fired, satisfying §37/§39 together. A statistical/ML-based scoring refinement is an explicit **future** phase (§17/§74 of the master prompt), never the v1 mechanism.
- Risk annotations attach to events, processes, and later-computed incidents; the Baseline Engine (§11.5) is one of several inputs a weighted reason can reference (e.g., `"Rare executable path" +10` sourced from a baseline rarity lookup).

### 11.5 Baseline Engine

- **v1 approach: frequency-based statistics, not ML** (§40 is explicit about this ordering). Maintains rolling per-host (and later per-fleet) frequency tables for: `(parent_exe, child_exe)` pairs, `(process_exe, dst_ip/dst_port)` pairs, `(process_exe, dns_query_domain)` pairs, `(user, exe_path)` pairs, each with a first-seen/last-seen/count and a rarity classification (`NEW` = first-seen within a configurable recent window, `RARE` = count below a percentile threshold over the observation period, `UNUSUAL`/`DEVIATING` reserved for the future statistical-deviation work).
- Implemented as its own storage-backed component (`osiris-baseline`), not recomputed from raw events on every query — baselines are updated incrementally as events are ingested (a consumer of the same event stream Detection subscribes to), and queried by Detection/Risk as an O(1) lookup, not a scan.

---

## 12. Investigation / DFIR Architecture

### 12.1 Investigation Engine

Provides the query/reconstruction primitives that the "Story" and "Incident Reconstruction" features (master prompt §44–48) are built from. It is not a separate data store — it is a set of composed queries and graph traversals over the Query Engine (§16) and the entity graph (§9.4), packaged as named, reusable operations:

```text
process_story(process_key) -> ProcessStory
file_story(file_identity)  -> FileStory
network_story(ip_or_domain) -> NetworkStory
system_story(host_id, time_range) -> SystemStory
reconstruct_incident(seed_entity, time_range) -> IncidentReconstruction
```

Each `*Story` is a pre-defined graph-traversal-plus-timeline-assembly template (not free-form per feature) so behavior is consistent and testable: e.g., `ProcessStory` = the process's own lineage edges (ancestors/descendants via `SPAWNED`), all `WROTE`/`READ`/`CONNECTED_TO`/`EXECUTED_AS` edges from that `process_key`, plus every `Alert` whose evidence references an event tied to that `process_key`, assembled and returned as a time-ordered structure the Console renders as a timeline+tree.

`IncidentReconstruction` composes `Correlation Engine` chains seeded from the given entity, walked forward and backward in time up to the given range, producing the staged view the master prompt sketches (`INITIAL EVENT → EXECUTION → FILESYSTEM → NETWORK → PRIVILEGE → PERSISTENCE → IMPACT`) by bucketing the chain's events by `category` in temporal order — every bucket entry cites its source `event_id`(s), so §44's "every conclusion must have evidence" is structural, not a UI convention.

### 12.2 Threat Hunting workspace

Not a separate engine — it is the **Query Engine** (§16) exposed through a dedicated Console workspace and CLI verb (`osiris hunt`), pre-loaded with saved-query templates for the example patterns in the master prompt (§41). Hunting differs from the general query surface only in UX (result pivoting into Stories/Entity Graph is one click away), not in underlying mechanism — this avoids building two query implementations.

### 12.3 Query Language (OQL — OSIRIS Query Language)

- Grammar: field-comparison expressions combined with `AND`/`OR`/`NOT`, operators `= != > < >= <= CONTAINS STARTS_WITH ENDS_WITH IN`, exactly the operator set in master prompt §42, plus parentheses for grouping (needed the moment two `AND`s and one `OR` combine — this is a correction to keep §42's grammar actually usable, not an addition of scope).
- Implementation: a hand-written recursive-descent parser (`osiris-query::oql`) producing an AST, compiled into a `QueryPlan` — a backend-agnostic filter/aggregation tree — which each `Storage` backend's query implementation translates into its native query (SQL for SQLite/ClickHouse). Because AST→plan is backend-agnostic, switching storage backends does not require changing OQL or the parser.
- Documented formally in `QUERY_LANGUAGE.md` (§25) including full grammar (EBNF), field reference (generated from the Event Schema so it never drifts out of sync), and worked examples.

### 12.4 Timeline Engine

A specific, canonical `QueryPlan` shape (time-range filter + multi-category projection + stable sort by `(timestamp, event_id)`) exposed as its own API/CLI surface because it's the single most common investigative operation — not a distinct data pipeline from Query.

### 12.5 Entity Graph

Rendered from the `relationships` edge table (§9.4) plus entity metadata lookups; the Console's graph view (§18.7) requests a bounded-depth, bounded-node-count subgraph from a `/api/graph` endpoint (never the full graph — always scoped to a seed entity + depth + time range) to keep response size and render cost bounded regardless of fleet history size.

### 12.6 Evidence Engine

`Evidence { evidence_id, source: enum, timestamp, integrity: { sha256_or_content_hash, immutable_since }, relationships: [EntityRef], incident_id: Optional<UUID> }`. Evidence records are **append-only** (no `UPDATE`, only new evidence records superseding old ones, with the supersession link recorded) — this is what makes them usable as investigation output the master prompt's DFIR framing requires. Grouping evidence into an `Incident` is a many-to-many join table, not a foreign key on the evidence record, since one piece of evidence can be relevant to more than one incident.

### 12.7 Alert Center and Incident Management

- `Alert` (§11.2) is generated by Detection and is otherwise immutable except for a `status` field (`OPEN`, `ACKNOWLEDGED`, `SUPPRESSED`) and an optional `incident_id` link.
- `Incident { incident_id, status: {NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE}, entities: [EntityRef], alerts: [alert_id], evidence: [evidence_id], notes: [Note], actions: [ResponseAction], timeline_cache: Optional<...> }` — a control-plane record (§10.3), CRUD'd through the API with full audit logging (§22) on every state transition, since incident status changes are exactly the kind of security-relevant action the self-audit system must capture.

---

## 13. Response Engine Architecture

- **Split by risk, not by convenience:** `ResponseAction` is typed per operation (`TerminateProcess`, `StopService`, `QuarantineFile`, `BlockIndicator`, `IsolateNetwork`, `CollectEvidence`, `DisablePersistence`), each with a declared `destructive: bool` and a declared `supports_dry_run: bool`.
- **Authorization gate:** every destructive `ResponseAction` request flows through: `AuthCheck (RBAC) → Confirmation (explicit reason string required) → Audit log entry (pre-execution, with WHO/WHAT/WHEN/WHY/TARGET) → Dispatch → Result recorded (including failure) → Audit log entry (post-execution)`. This two-phase (pre+post) audit write means even a crash mid-execution leaves a record that an action was *attempted*, not just successes.
- **Execution path:** the API/Core never executes a response action directly on the host — it dispatches a signed command to the relevant host's **Agent** over the same transport events flow up on (§8.3), and the Agent (which already holds the necessary privileges) performs the action locally. This keeps the privilege boundary (§21) consistent: the Server process, reachable over the network, never needs privileges to kill processes or touch files — only the Agent does, and it only acts on authenticated commands from the Server it's paired with.
- **v1 scope:** per master prompt §53/§95 ("no destructive response silently"), the MVP implements the **audit/authorization/dry-run scaffolding and evidence collection actions** (non-destructive) fully; process/service/network destructive actions are architected (types, authz path, audit path all exist) but gated behind an explicit, separately-versioned "Response — Active Actions" milestone (§29) so that shipping investigation capability doesn't implicitly ship live destructive control before it's had focused security review.

---

## 14. API Architecture

### 14.1 Style and framework

REST over HTTPS (TLS terminated by the API itself or a reverse proxy — both supported), JSON bodies, using **axum** (Tokio-native, tower-middleware-based) — chosen over Actix-web because it shares the async runtime and middleware ecosystem the rest of the Rust stack (Agent transport, Storage) already uses, minimizing dependency surface, and because tower's middleware composition maps directly onto the layered authn→authz→audit→handler pipeline every mutating endpoint needs.

### 14.2 Endpoint surface (from master prompt §68, grouped by resource)

```text
GET  /api/v1/events                 (filtered, paginated; OQL via ?q=)
GET  /api/v1/events/{id}
GET  /api/v1/processes              /api/v1/processes/{process_key}/story
GET  /api/v1/files                  /api/v1/files/{id}/story
GET  /api/v1/network                /api/v1/network/{ip_or_domain}/story
GET  /api/v1/dns
GET  /api/v1/users
GET  /api/v1/containers
GET  /api/v1/services
GET  /api/v1/hosts
GET  /api/v1/alerts                 PATCH /api/v1/alerts/{id}
GET  /api/v1/incidents              POST/PATCH /api/v1/incidents
GET  /api/v1/timeline
POST /api/v1/hunt                   (OQL query body, for complex queries)
GET  /api/v1/query?q=...
GET  /api/v1/rules                  POST/PUT for rule management (RBAC-gated)
GET  /api/v1/evidence
GET  /api/v1/graph                  (bounded subgraph query, §12.5)
POST /api/v1/response/{action}      (RBAC-gated, audited, §13)
GET  /api/v1/health
GET  /api/v1/metrics                (Prometheus exposition format)
WS   /api/v1/stream/events          (live event stream for the Console)
```

### 14.3 AuthN/AuthZ

- **Authentication:** local users (Argon2id password hashing) issuing short-lived signed session tokens (JWT or opaque+server-side session — opaque tokens chosen for v1 to allow immediate revocation, which signed JWTs complicate) for MVP; pluggable OIDC/SAML for enterprise deployments is an explicit later-phase addition behind the same auth middleware interface, not a v1 requirement.
- **Authorization:** RBAC with a small fixed set of v1 roles (`Viewer`, `Analyst`, `ResponseOperator`, `Admin`) enforced in middleware before any handler runs — the frontend is never trusted for authorization decisions (§63 explicit requirement), and every RBAC decision is itself evaluable independent of any handler logic (a `tower::Layer` that inspects the route's declared required-role and the session's role).
- **Machine-to-machine (Agent→Server ingestion):** separate from user auth — mTLS client certificates (or a pre-shared token for same-host UDS in MVP where mTLS overhead isn't warranted) issued per-Agent at enrollment, so a compromised Console session can never masquerade as an Agent submitting events.

### 14.4 Streaming

Live event stream (Console's "Live Events" screen, §18.3) is a WebSocket fed by a server-side broadcast channel that taps the same post-ingestion event stream Detection consumes — not a polling loop — so latency from ingestion to Console display is bounded by the same backpressure-aware pipeline already in place, and a slow WebSocket client (a laggy browser tab) cannot exert backpressure on ingestion (its channel is independently bounded with drop-oldest for VERBOSE-lane events, matching the Bus's own policy, §9.1).

---

## 15. CLI Architecture

- **Framework:** `clap` (derive API), the de facto standard for professional Rust CLIs, giving free `--help`, shell completion generation, and subcommand structure.
- **Structural rule (§17 requirement to avoid duplicated logic):** the CLI is a thin HTTP client of the same API every other client uses (§14) for anything data-related (`osiris events`, `osiris processes`, `osiris alerts`, `osiris query`, `osiris hunt`) — it does not embed a second copy of Storage/Query/Detection logic. The **only** things the CLI talks to locally (not via the Server API) are Agent-local operations that make no sense remotely: `osiris status` (local agent process state), `osiris sensors` (local sensor health) when run on the host itself, and `osiris config` (local config validation/reload trigger) — these go over the local UDS control endpoint (§3.2) directly.
- **Interactive vs. non-interactive:** subcommands work identically in both scriptable (`osiris events --format json`) and human (colorized table, paged) output modes, selected by TTY detection with an explicit `--format` override — this is what makes `osiris query "risk.score > 70"` composable in scripts per §58.
- **Event Replay and Synthetic Generator (§59–60):** `osiris replay <dataset>` and a separate `osiris-generator` binary are **development/testing tools**, architecturally part of the same `osiris-schema`/`osiris-pipeline` crates (they construct real `CanonicalEvent`s and push them through the real pipeline/detection/storage path) so that replay/synthetic testing exercises the actual production code paths, not a parallel simulation — this is what makes them trustworthy for benchmarking and regression testing (§62/§81).

---

## 16. Web Console Architecture

### 16.1 Stack

- **React + TypeScript**, Vite build, no framework-provided backend (pure SPA against the REST/WebSocket API, §14). Justification: TypeScript for the type-safe consumption of the (OpenAPI-generated, §26) API client, React for the componentized, data-dense views this tool needs (tables, graphs, timelines) with the largest available ecosystem of mature primitives for exactly those (virtualized tables, graph rendering).
- **State/data-fetching:** a query-cache library (React Query/TanStack Query pattern) for REST resources, a dedicated store (lightweight, e.g. Zustand-style) for cross-cutting UI state (active filters, selected entity, time range) that many screens (§18) need to share — e.g., selecting a process in Process Explorer should be reflected if the user pivots to Timeline or Entity Graph.
- **Visualization:** a virtualized table component for event/alert lists (must handle tens of thousands of rows without degrading), a graph-rendering library for the Entity Graph (force-directed or hierarchical layout, chosen for interactive zoom/pan/filter per §49), and a custom timeline component (swim-lane style, category-colored) since off-the-shelf timeline libraries rarely fit a multi-category security timeline's density needs.

### 16.2 Design direction (§69 requirement)

Dark-first, information-dense, monospace/technical typography for data fields, a fixed left-nav matching the screen list (§70), and explicitly **not** a general admin-dashboard template — card-heavy, decorative dashboards are the wrong metaphor; the reference class is SOC/DFIR tooling (dense tables, inline evidence, one-click pivot between views) over BI dashboards. (Concrete component-level design decisions belong in an implementation-time design pass, not this architecture document — flagged here as the governing direction.)

### 16.3 Screen ↔ API/Engine mapping

| Screen (§70) | Backed by |
|---|---|
| Overview | `/api/v1/health`, aggregate counts from `/events`, `/alerts`, `/incidents` |
| Live Events | `WS /stream/events` |
| Process Explorer | `/processes/{key}/story` (§12.1) |
| Filesystem | `/files` + `/files/{id}/story` |
| Network | `/network` + `/network/{x}/story` + `/graph` |
| Containers | `/containers`, filtered `/events?category=CONTAINER` |
| Timeline | `/timeline` (§12.4) |
| Alerts | `/alerts` |
| Incidents | `/incidents` |
| Threat Hunting | `/hunt`, `/query` |
| Entity Graph | `/graph` (§12.5) |
| Evidence | `/evidence` |
| Sensors | `/health` (agent/sensor rollup, §3.3) |

No screen introduces a data shape the API doesn't already serve — this constraint (data model before UI, §95's explicit prohibition on "UI before data is defined") is enforced by this table existing before any Console implementation begins.

---

## 17. Security Model

### 17.1 Threat model summary

OSIRIS is itself a high-value target: it runs with elevated privileges and holds a complete behavioral record of the host. The security model treats OSIRIS as **software that must defend itself** (§55), not just software that defends the host.

### 17.2 Controls, mapped to master prompt §55/§63

| Requirement | Mechanism |
|---|---|
| Integrity verification | Agent and eBPF object binaries are shipped with detached signatures (minisign/cosign-style); the Agent verifies its own eBPF object's hash against a manifest before loading |
| Tamper detection | Self-audit log (§22) is append-only and hash-chained (each entry includes the hash of the previous entry) so truncation/edit is detectable, not preventable at the OS level alone — paired with recommending immutable/append-only filesystem attributes where the OS supports it |
| Secure configuration | Config schema validation rejects unknown/malformed keys rather than ignoring them; secrets (API auth secrets, mTLS keys) are never stored in the YAML config directly — referenced by path with required restrictive file permissions, checked at load time |
| Least privilege | See §21 (Privilege Boundary Model) — the core architectural mechanism, not a policy statement |
| Secure IPC | Agent↔Server UDS socket created with restrictive permissions (root:osiris, 0660) validated at bind time; remote transport is mTLS-only, no plaintext option |
| Authenticated API | §14.3 |
| Authorization | §14.3, enforced server-side only |
| Audit logging | §22 |

### 17.3 Explicit prohibitions carried into the architecture (§63/§95)

No component invents kernel behavior or undocumented APIs (eBPF program design in §5 is scoped to documented, stable-enough hook points, with the Capability Probe, §20, as the mechanism for "don't assume it exists"). No destructive Response action executes without the full authz+audit path (§13). No component trusts client-supplied authorization claims. No sensor or Agent process runs as root when a narrower Linux capability set suffices — the Agent process drops to the minimal `CAP_*` set required per enabled sensor at startup (e.g., `CAP_SYS_PTRACE`/`CAP_BPF`/`CAP_PERFMON`/`CAP_NET_ADMIN` as applicable to enabled sensors, verified against the kernel's actual capability model rather than assumed) rather than running unconstrained as UID 0.

---

## 18. Privilege Boundary Model

This is the concrete architecture behind §21/§64's "isolate privileged components."

```text
┌─────────────────────────────────────────────────────────────┐
│  osirisd (Agent)                                              │
│  Runs as: root at start, then drops to minimal CAP_* set      │
│           required by enabled sensors (never stays full-root  │
│           if the enabled sensor set doesn't need it)          │
│  Touches: eBPF programs, audit netlink, fanotify, procfs,      │
│           container runtime sockets                            │
│  Never:  binds a network-reachable port, serves the API,       │
│           holds user credentials                                │
└─────────────────────────────┬─────────────────────────────────┘
                               │ UDS (0660, root:osiris group) or mTLS
┌─────────────────────────────▼─────────────────────────────────┐
│  osiris-server                                                 │
│  Runs as: dedicated unprivileged system user (e.g. `osiris`)   │
│  Touches: Storage (files owned by that user), binds the API    │
│           port (loopback by default; reverse proxy for TLS/    │
│           external exposure recommended, not embedded root      │
│           needed for privileged ports — bind >1024 and let a    │
│           reverse proxy or systemd socket-activation handle 443)│
│  Never:  loads eBPF, reads other users' process memory,         │
│           needs any elevated Linux capability                    │
└─────────────────────────────────────────────────────────────────┘
```

**Why the Agent drops capabilities instead of staying root, and why this is enforceable:** Linux capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH` as needed for specific sensors) are well-documented, kernel-enforced, and independently toggleable — the Agent computes the minimal required set from its `SensorRegistry`'s enabled sensors at startup (each sensor declares `required_capabilities()` as part of its `capabilities()` contract, §4.1) and calls into `libcap`-equivalent Rust bindings to drop everything else immediately after initialization, before entering its steady-state event loop. This means a vulnerability in, say, the DNS sensor's packet parsing cannot be leveraged into arbitrary kernel module loading — the process literally does not hold that capability by the time untrusted input (packets, file paths, exec arguments) is being parsed.

**Systemd hardening** as a second, OS-enforced layer (not a substitute for the above, a complement): both units run with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, explicit `ReadWritePaths=` scoped to only the Agent's spool/socket directories and the Server's storage directory, and `CapabilityBoundingSet=` set to exactly the capability list the Agent computes (kept in sync via a generated systemd drop-in, not hand-maintained).

---

## 19. Performance Model

### 19.1 Governing principle (§61)

No stage is allowed to be "capture/store/process everything" as a default. Every stage has an explicit bound:

| Stage | Bound mechanism |
|---|---|
| eBPF kernel-space | Fixed-size ring buffer per program; in-kernel pid/cgroup filtering before emission when scoped (§6) |
| Agent local enrichment | Only cheap, cache-hit lookups (Process Resolver is a bounded LRU keyed by `process_key`, evicting on process exit) |
| Event Bus | Bounded per-lane channels + explicit, documented drop/spill policy (§9.1) — never unbounded |
| Agent→Server transport | Batched + compressed; DiskSpool is a bounded ring file, not an unbounded queue |
| Server ingestion | Backpressure signaled to Agent transport under sustained overload rather than unbounded buffering server-side |
| Storage writes | Batched writes (the pipeline already batches for transport; Storage batches again for commit efficiency) |
| Query Engine | Every query plan has an enforced row/time-range cap unless explicitly run in an "export" mode with streaming pagination |

### 19.2 Budgets (targets to benchmark against, not invented final numbers — §62)

Concrete numeric SLOs are **not asserted here** as fact; they are the benchmark program's job to establish (§23) and record in `PERFORMANCE.md` once measured on real representative hardware/kernels. This document fixes the **methodology**: Agent idle CPU/RSS, sustained-load CPU/RSS at 1K/10K/100K events/sec synthetic load (via the Synthetic Generator + Replay tooling, §15), end-to-end p50/p99 latency from kernel event to queryable-in-storage, and detection/query latency at increasing stored-event-volume, all captured automatically as CI-adjacent benchmark jobs (§26) so regressions are caught, not just measured once.

### 19.3 Degradation ladder

Under sustained resource pressure, the Agent degrades in a defined order rather than failing unpredictably: 1) drop VERBOSE-lane events, 2) drop LOW-lane events, 3) reduce local enrichment (skip optional lookups, keep required identity fields only), 4) shed NORMAL-lane events, 5) alert via `AGENT_HEALTH` at `DEGRADED`/`CRITICAL` — HIGH/CRITICAL lanes and the health-reporting path itself are the last things ever shed, since observability-of-observability (§57) must survive longer than any individual data lane.

---

## 20. Plugin Architecture

### 20.1 Extension points (§66)

```text
Sensor Plugin      — implements the Sensor trait (§4.1), loaded via a
                       registered plugin directory + manifest, NOT via
                       dynamic loading of arbitrary shared objects into the
                       privileged Agent process (see below)
Detection Plugin    — a rule pack (YAML) or, for logic beyond declarative
                       rules, a WASM module (sandboxed, no ambient authority)
                       evaluated by the Detection Engine with a bounded
                       execution budget per event
Enrichment Plugin   — same WASM sandboxing approach as Detection, since
                       enrichment logic runs on the Server, not the
                       privileged Agent, third-party code here is safer by
                       construction than in the Agent
Storage Plugin      — implements the Storage trait (§10.1)
Exporter Plugin     — implements a simple `export(events) -> Result<()>`
                       trait (§20.2)
Response Plugin     — implements a `ResponseAction` handler; because these
                       run on the privileged Agent side, response plugins
                       are restricted to first-party/signed plugins only in
                       v1 — no third-party response plugin execution until
                       a stronger sandboxing story (WASM+capability-scoped)
                       exists for the Agent process specifically
```

### 20.2 Why not arbitrary dynamic loading into the Agent

Loading third-party native code (`dlopen`-style) into the same process that holds `CAP_BPF`/`CAP_SYS_PTRACE` defeats the entire privilege-boundary model in §18/§21 — a malicious or buggy plugin would inherit the Agent's capabilities directly. Sensor plugins therefore run either (a) as first-party, compiled-in-tree crates selected at build time (the only option for v1), or (b) in a **future** phase, as separate subprocesses speaking the same wire protocol the Agent already uses for its own sensor-to-pipeline boundary, sandboxed independently (seccomp + their own minimal capability set) — never as code loaded directly into `osirisd`'s address space. Detection/Enrichment plugins, running Server-side and without privileged OS access already, are far lower risk and get the more permissive WASM-sandbox treatment described above, closer to v1-feasible.

### 20.3 Exporters (§67)

`Exporter` is a Server-side trait consuming the same post-ingestion, post-enrichment event stream Detection consumes: `JSON`/`NDJSON`/`CSV` (file-sink), `Syslog`/`CEF` (structured text over UDP/TCP/TLS to a SIEM), `OpenTelemetry` (OTLP log/metric export) are the v1-architected set given they require no new infrastructure; `Kafka`/`Webhook`/object-storage exporters are structurally identical (same trait) and are explicitly deferred implementations, not deferred design.

---

## 21. Future Multi-Host / Cloud / Kubernetes Architecture

### 21.1 Multi-host, without inventing new architecture

Because Agent and Server are already separate processes speaking a defined wire protocol (§1.1, §8.3) authenticated by mTLS, "multi-host" is: point N Agents at one Server instead of one Agent at its co-located Server. No new component is required for this step — only configuration (Agent enrollment, per-agent mTLS cert issuance) and Server-side scaling (the storage backend swap to ClickHouse from §10.2 is what actually enables this at volume, not a re-architecture).

### 21.2 Fleet management (§76, later phase)

A `Fleet Manager` concern is added to the control-plane store (§10.3): agent registry (enrollment status, last-seen, version, health), policy distribution (push telemetry-level/sensor-config changes to a group of Agents rather than one at a time), and a corresponding API/Console surface. This is additive to the existing config/health mechanisms (§3.1) — Agents already report health and accept config; Fleet Management is a Server-side aggregation and distribution layer over that existing contract, not a new Agent capability.

### 21.3 Kubernetes context (§26 of the master prompt)

`osiris-k8s-context` is an **optional** enrichment source (never a hard dependency, per the master prompt's explicit instruction) that, when the Agent detects it's running on a Kubernetes node (kubelet API/CRI socket reachable), subscribes to the Kubernetes API (via the node's kubelet read-only API and/or a watched service account) to resolve `container_id → pod → namespace → deployment/service` and attaches this as `ContainerRef.pod_ref` (§9.2) during local enrichment. Its absence degrades gracefully to container-level (not pod-level) context — the schema already models this as `Optional<PodRef>` nested inside `Optional<ContainerRef>`, so no schema change is needed when this ships.

### 21.4 Cloud context (§27 of the master prompt)

Similarly optional: a small `CloudMetadataProbe` queries the instance metadata service (IMDSv2 for AWS, Azure IMDS, GCP metadata server — each behind a common `CloudMetadataProvider` trait, auto-detected by probing well-known link-local addresses/endpoints, never assumed) once at Agent startup and populates `HostRef.cloud` (§9.2). Failure to reach any metadata endpoint (on-prem/bare-metal) simply leaves this field `None` — never a startup failure.

### 21.5 Centralized SOC (§75/§76, later phase)

The `OSIRIS Server` described throughout this document already *is* "Central OSIRIS" in the master prompt's diagram — the multi-host future is this same Server ingesting from many Agents, with the fleet/RBAC/multi-tenant additions layered on the existing control-plane store and API authz model (§14.3's RBAC roles extend with a `tenant_id`/`host_group` scoping dimension when multi-tenancy is needed, not a new authz system).

---

## 22. Audit System

`osiris-audit` is a shared crate used identically by both Agent and Server whenever a security-relevant action occurs (not only Response actions, §13 — also: config changes, RBAC/user management, rule changes, auth failures, sensor enable/disable). Each entry:

```text
AuditEntry {
  audit_id: UUIDv7, timestamp, who: ActorRef (user_id or "system"),
  what: string (action taken), target: EntityRef,
  why: Optional<string> (required for destructive actions, §13),
  result: enum (SUCCESS, FAILURE, DENIED),
  prev_entry_hash: string, entry_hash: string   // hash chain, §17.2
}
```

Stored append-only in the control-plane store (§10.3), never subject to retention deletion (§10.5), exposed read-only via `/api/v1/audit` (Admin-role-gated).

---

## 23. Health / Self-Observability Architecture

`osiris-health` aggregates: per-sensor `SensorHealth` (§3.3) → Agent-level health → forwarded as `AGENT_HEALTH`/`SENSOR_HEALTH` events into the normal event pipeline (so health history is itself queryable/timeline-able, not a side-channel) → Server-side health rollup across all connected Agents for the Console's Overview/Sensors screens (§18.3's table). Detected failure conditions (§57: sensor failure, event loss, queue overflow, eBPF load failure, storage failure, permission errors, resource exhaustion) each map to a specific `HealthState` transition with a specific, non-generic reason string — "generic unhealthy" is not an allowed terminal state; every `DEGRADED`/`FAILED` state must carry a `last_error` explaining which of the above it is.

---

## 24. Repository / Module Structure

```text
osiris/
├── Cargo.toml                     # workspace root
├── ARCHITECTURE.md                # this file
├── EVENT_MODEL.md
├── ROADMAP.md
├── SECURITY.md
├── DEVELOPMENT.md
├── crates/
│   ├── osiris-schema/             # Event Schema v1 — canonical types, no logic
│   ├── osiris-config/             # config loading/validation, shared
│   ├── osiris-audit/              # audit log, shared
│   ├── osiris-health/             # health aggregation, shared
│   ├── osiris-selftelemetry/      # metrics/tracing glue, shared
│   │
│   ├── osiris-agent/              # binary: osirisd
│   ├── osiris-sensor-api/         # Sensor trait + SensorContext (interface only)
│   ├── osiris-sensors/
│   │   ├── process/  exec/  filesystem/  network/  dns/
│   │   ├── identity/  systemd/  persistence/  kernel-module/
│   │   ├── container/  namespace/  cgroup/  security/
│   ├── osiris-ebpf/                # loader, ring buffer reader, capability probe
│   │   └── bpf/                    # .bpf.c sources, per-program, versioned
│   ├── osiris-kernel/              # audit/fanotify/procfs backends (non-eBPF)
│   ├── osiris-pipeline/            # collect/normalize/enrich(local)/validate/prioritize
│   ├── osiris-bus/                 # local bounded bus + Agent<->Server transport
│   │
│   ├── osiris-server/              # binary: osiris-server (hosts everything below)
│   ├── osiris-storage/             # Storage trait
│   ├── osiris-storage-sqlite/
│   ├── osiris-storage-clickhouse/  # added when §10.2's later tier is implemented
│   ├── osiris-enrich/              # server-side contextual enrichment
│   ├── osiris-query/               # OQL parser + QueryPlan + planner
│   ├── osiris-detect/
│   ├── osiris-correlate/
│   ├── osiris-risk/
│   ├── osiris-baseline/
│   ├── osiris-investigate/         # Story/Reconstruction composed queries
│   ├── osiris-evidence/
│   ├── osiris-response/
│   ├── osiris-api/                 # axum HTTP/WS surface
│   │
│   └── osiris-cli/                 # binary: osiris
│
├── console/                        # osiris-console — TypeScript/React SPA
├── generator/                      # osiris-generator — synthetic event tool
├── rules/                          # default detection rule packs (YAML)
├── schemas/                        # JSON Schema exports of osiris-schema, for
│                                    # docs/validation/OQL field reference generation
├── docs/
│   ├── EBPF.md  KERNEL.md  SENSORS.md  DETECTION.md  CORRELATION.md
│   ├── RISK_ENGINE.md  QUERY_LANGUAGE.md  INVESTIGATION.md  EVIDENCE.md
│   ├── RESPONSE.md  STORAGE.md  PERFORMANCE.md  LINUX_COMPATIBILITY.md
│   ├── CONTAINERS.md  KUBERNETES.md  CLOUD.md  TESTING.md
│   └── adr/  ADR-001-event-schema.md  ADR-002-rust.md  ADR-003-ebpf.md ...
├── tests/                           # integration/system tests spanning crates
├── benchmarks/                      # criterion + synthetic-load benchmark harness
└── tools/                           # dev tooling (BTF fetch scripts, kernel matrix CI helpers)
```

**Deviation from the master prompt's flat suggestion:** the master prompt's sketch (§77) puts every conceptual layer as a top-level directory. This document nests sensors/storage-backends/etc. under a `crates/` Cargo workspace and groups multi-crate concerns (`osiris-sensors/*`, `osiris-storage-*`) — functionally identical set of components, restructured only so `cargo` workspace tooling (shared lockfile, per-crate test/build, dependency-graph enforcement, §2.1) works idiomatically. This is exactly the kind of "you may alter structure if there's a better solution, document it" case §77 invites.

---

## 25. Technology Decisions and Justifications (summary table)

| Decision | Choice | Alternatives considered | Why |
|---|---|---|---|
| Systems language | Rust | C/C++, Go | Memory safety without GC pauses (relevant for Agent hot path), strong async ecosystem (Tokio), one language across Agent/Core/CLI reduces cross-language FFI risk. Mandated by master prompt §78 as well. |
| eBPF toolchain | libbpf-rs + CO-RE (C kernel-space) | Aya (pure Rust) | CO-RE is the portability mechanism the ecosystem converged on for multi-kernel support (§5.2); Aya reconsidered once its LSM/complex-map coverage matures — tracked as ADR follow-up. |
| Web API framework | axum | actix-web, warp | Shares Tokio runtime/tower middleware with the rest of the stack; tower layering matches the authn→authz→audit pipeline needed. |
| Console framework | React + TypeScript | Svelte, Vue | Largest ecosystem of mature data-table/graph/timeline primitives for a data-dense DFIR UI; TypeScript for type-safe API consumption. |
| MVP telemetry store | SQLite (WAL) | PostgreSQL, ClickHouse from day one | Zero operational dependency for v1 (§96 ordering: correctness before scale); matches expected MVP write volume; swappable via `Storage` trait. |
| Fleet-scale telemetry store | ClickHouse (planned, benchmarked before commit) | PostgreSQL+TimescaleDB, Elasticsearch | Column-store/compression/sparse-index shape matches append-heavy, filter-and-aggregate telemetry workload; benchmark required before final commit (§79). |
| Control-plane store | SQLite → PostgreSQL | Same as telemetry store | Opposite workload (transactional, relational) from telemetry; kept logically and physically separate from day one (§10.3) so each can scale independently. |
| Cold storage format | Parquet (+ DataFusion for on-demand query) | Keep everything in ClickHouse indefinitely | Compression/cost-efficient long-term archival; DataFusion is Rust-native, avoiding a second query-engine ecosystem. |
| Agent↔Server transport | UDS (local) / mTLS+TCP (remote), compressed protobuf/Cap'n Proto batches | gRPC end-to-end, plain JSON | Binary compact framing minimizes overhead on the hot ingestion path; mTLS is non-optional for any network-crossing transport (§17). |
| Detection rule format | Custom YAML (OSIRIS-native fields) | Adopt Sigma directly | Sigma's field taxonomy targets syslog-era sources OSIRIS's schema doesn't map 1:1 to; a Sigma import/export bridge is a plausible future exporter, not the native format. |
| CLI framework | clap (derive) | structopt (superseded by clap), custom parsing | De facto standard, free completions/help, well-maintained. |
| Risk/Baseline v1 | Weighted rules + frequency statistics | ML/anomaly detection from day one | Explainability is a hard requirement (§37/§39); master prompt explicitly orders ML after the explainable core (§40/§74). |

---

## 26. Complete Data Flow of One Event (worked trace)

Trace: an SSH session runs `curl` which writes a file — the master prompt's own running example (§12, §37).

```text
1.  sshd accepts a connection → PAM/audit records session start.
    → Identity Sensor (audit backend) emits RawEvent{session_login}.

2.  User runs `bash`; bash execs `curl https://x/y -o /tmp/payload`.
    → Kernel: sched_process_exec tracepoint fires.
    → eBPF exec program captures pid, ppid, uid, comm, argv (bounded),
      pushes fixed-shape record to its BPF_RINGBUF.
    → osiris-ebpf's ring buffer reader (Agent, user-space) reads the record,
      hands it to the Exec Sensor's output channel as a RawEvent.

3.  Event Pipeline (Agent):
    Collect:    RawEvent{exec} received from Exec Sensor channel.
    Normalize:  mapped to CanonicalEvent{event_type: PROCESS_EXEC,
                process: {process_key: hash(host,boot,pid,start_mono),
                          exe_path: "/usr/bin/curl", cmdline: [...]},
                parent_process: {process_key of bash's process_key}}.
                process_key for bash was already resolved and cached by
                the in-memory Process Resolver from its own earlier
                PROCESS_EXEC event.
    Enrich(local): attach host_id/boot_id; attach session_id from the
                Identity Sensor's earlier SESSION_LOGIN (looked up via
                the Process Resolver's session-to-process linkage,
                populated at login/exec time); attach cgroup/namespace
                refs (cached from Namespace/Cgroup sensors).
    Validate:   required fields present → OK.
    Prioritize: PROCESS_EXEC with a network-tool exe_path → HIGH lane
                (priority table match on exe_path pattern).
    Queue:      pushed to Event Bus HIGH lane.

4.  Event Bus (Agent): dequeued in priority order, batched with other
    pending events (batch window: small, bounded, e.g. 50ms or N events),
    compressed, sent over local UDS to osiris-server.

5.  Server ingestion endpoint: receives batch, decompresses, validates
    schema version, writes to Storage (batch_write), and simultaneously
    fans the batch out to: Detection Engine, Correlation Engine,
    Baseline Engine (update frequency tables), WebSocket broadcast
    (Live Events), Exporters (if configured).

6.  Baseline Engine: looks up (bash_exe, curl_exe) pair — if first-seen
    for this host, marks NEW; updates the frequency table.

7.  curl opens a socket, connects → tcp_connect kprobe fires.
    → Network Sensor (eBPF) emits RawEvent{connect}, same pipeline path
      as step 3, producing CanonicalEvent{event_type: NETWORK_CONNECT,
      process: {process_key: curl's}, network: {dst_ip, dst_port: 443}}.

8.  curl writes /tmp/payload → path_mknod/write LSM hook or fanotify
    fires. Filesystem Sensor emits RawEvent{create}, pipeline produces
    CanonicalEvent{event_type: FILE_CREATE, process: {curl's process_key},
    file: {path: "/tmp/payload"}}.

9.  Server-side, at ingestion of each of steps 7/8's events:
    - Enrichment (server-side, contextual): computes file hash for
      /tmp/payload (deferred, async, not blocking ingestion — hash
      attached as a follow-up enrichment event/update once computed).
    - Correlation Engine: recognizes NETWORK_CONNECT and FILE_CREATE
      both share curl's process_key within the correlation window as
      bash's descendant → extends the BehavioralChain rooted at the
      SESSION_LOGIN from step 1.
    - Relationships persisted: SESSION→SPAWNED→bash, bash→SPAWNED→curl,
      curl→CONNECTED_TO→dst_ip, curl→WROTE→/tmp/payload.

10. Detection Engine evaluates the `suspicious_execution_chain`-style
    rule (§11.1) against the chain: parent=sshd-descended bash, child=
    curl, followed by FILE_CREATE within the window → conditions match.
    → Alert{severity: high, reasons: ["Shell spawned directly from an
      SSH session", "Shell spawned a network download tool", "Download
      tool created a new file"], evidence: [event_id x4], rule_id,
      rule_version} is created, written to the control-plane store.

11. Risk Engine annotates the curl process_key: "Rare executable path
    for this session" (+10, from Baseline NEW) + "Network connection
    followed by file write" (+20) → RiskAnnotation{score, reasons}
    attached to the relevant events/process.

12. API/Console: the WebSocket stream had already shown steps 2/7/8 in
    Live Events in near-real-time; the new Alert appears in Alert
    Center; opening the Incident from that alert triggers
    reconstruct_incident(seed=alert.evidence[0], time_range=...),
    which walks the same persisted relationship edges to render the
    staged INITIAL EVENT → EXECUTION → NETWORK → FILESYSTEM view,
    each stage citing its source event_id.

13. Every step above that touched a security-relevant boundary (none in
    this trace required authz/response) would, in a Response scenario,
    additionally write to osiris-audit (§22) before/after execution.
```

This trace exercises every architectural layer in this document at least once and is the intended basis for the first end-to-end integration test (§29).

---

## 27. Dependency Graph Between Modules

```text
osiris-schema  (depended on by everything; depends on nothing OSIRIS-internal)
     ▲
     │
osiris-config, osiris-audit, osiris-health, osiris-selftelemetry
     ▲                    ▲
     │                    │
osiris-sensor-api    osiris-storage (trait)
     ▲                    ▲
     │                    │
osiris-sensors/*     osiris-storage-sqlite, osiris-storage-clickhouse
     ▲                    ▲
     │                    │
osiris-ebpf, osiris-kernel│
     ▲                    │
     │                    │
osiris-pipeline ──────────┤
     ▲                    │
     │                    │
osiris-bus                │
     ▲                    │
     │                    │
osiris-agent (bin)   osiris-query ── osiris-detect, osiris-correlate,
                          │              osiris-risk, osiris-baseline
                          │                    ▲
                          │                    │
                     osiris-investigate ───────┘
                          │
                     osiris-evidence, osiris-response
                          │
                     osiris-api
                          │
                    osiris-server (bin)
                          │
              ┌───────────┴───────────┐
        osiris-cli (bin)        osiris-console (TS, separate build)
```

Hard rule enforced in CI (§26): `osiris-sensors/*` and `osiris-ebpf`/`osiris-kernel` must never appear in `osiris-server`'s or `osiris-api`'s dependency tree, and `osiris-storage-*`/`osiris-detect`/`osiris-correlate`/`osiris-risk` must never appear in `osiris-agent`'s dependency tree. This is what makes the Privilege Boundary Model (§21/§18) a build-time-checkable fact, not just a design intention — a `cargo tree`-based CI check fails the build if either boundary is crossed.

---

## 28. Architectural Decision Records (index — to be filed individually under docs/adr/)

```text
ADR-001  Event Schema v1 design (envelope+payload split, process_key identity)
ADR-002  Rust as the systems language across Agent/Core/CLI
ADR-003  eBPF via libbpf-rs+CO-RE, not Aya, for v1 (revisit trigger documented)
ADR-004  Event Bus: bounded, priority-lane, in-process design; spill-not-drop
         policy for CRITICAL
ADR-005  Storage: SQLite MVP → ClickHouse fleet-scale, two-store split
         (telemetry vs. control-plane)
ADR-006  Detection Engine: custom OQL-native YAML rules over adopting Sigma
ADR-007  Query Language (OQL) grammar and planner design
ADR-008  Agent/Server process split and privilege boundary enforcement
ADR-009  Response Engine: dispatch-to-agent execution model, v1 scope limited
         to non-destructive actions
```

Each ADR follows the master prompt's required structure: Context, Decision, Alternatives, Consequences. These are written at implementation time for each area as it is built, using this ARCHITECTURE.md as the pre-agreed context — they should not re-litigate decisions already justified here, only record any refinement made during implementation.

---

## 29. Technical Roadmap by Phase

Phases mirror the master prompt's vertical-slice ordering (§85–93), made concrete against the crates/components defined above. Each phase is gated by the Definition of Done (§94: implementation + tests + error handling + metrics + logging + docs + security review + performance consideration + CLI/API integration).

### Phase 0 — Foundation (pre-slice)
`osiris-schema`, `osiris-config`, `osiris-audit`, `osiris-health`, `osiris-selftelemetry`, workspace/CI skeleton, kernel/distro capability-probe design (§20/§82), dependency-graph CI enforcement (§27). No sensors yet.

### Phase 1 — OSIRIS Core v0.1 (master prompt §85–86)
Agent skeleton (Supervisor, lifecycle, local bus), Process+Exec Sensor (eBPF primary, audit fallback stubbed), Event Pipeline, local Event Bus, Agent→Server transport (UDS), SQLite storage, Server skeleton, minimal API (`/events`, `/processes`, `/health`), CLI (`status`, `events`, `processes`, `health`), Timeline (basic), Process Tree, unit+integration tests, first benchmark pass (events/sec, latency), `osiris-generator` minimal scenario for exec events. **Exit criterion:** the full trace in §26 works end-to-end for process/exec events specifically (network/file portions come in later phases).

### Phase 2 — Filesystem vertical slice (§87)
Filesystem Sensor (fanotify + eBPF LSM hooks where available), File Story, Timeline integration, first Detection rules referencing file events.

### Phase 3 — Network + DNS vertical slice (§88)
Network Sensor, DNS Sensor, Network Story, Entity Graph v1 (process↔network edges).

### Phase 4 — Identity/Privilege/Persistence (§89)
Identity Sensor, Privilege telemetry, SSH/sudo correlation, Systemd Sensor, Persistence Monitor — this phase is where the Correlation Engine's `BehavioralChain` first becomes genuinely multi-category (identity→process→file→network, matching §26's worked trace in full).

### Phase 5 — Containers/Namespaces/Cgroups (§90)
Container Sensor (Docker/containerd/CRI-O), Namespace/Cgroup context resolution, container-aware Entity Graph and Stories.

### Phase 6 — Detection/Correlation/Risk/Baseline maturity (§91)
Full Detection Engine (rule compiler, stateful sequence/window evaluation), Correlation Engine graph-walk implementation, Risk Engine weighted scoring, Baseline Engine frequency tables — this is also the phase where the ClickHouse storage backend benchmark/migration decision (§10.2) is executed if MVP volume has outgrown SQLite.

### Phase 7 — Investigation/Evidence/Hunting (§92)
Investigation Engine (`*_story`/`reconstruct_incident`), Evidence Engine, full OQL, Threat Hunting workspace, Entity Graph v2 (bounded subgraph API), Console screens for all of the above.

### Phase 8 — Kubernetes/Cloud/Multi-host (§93)
`osiris-k8s-context`, `CloudMetadataProvider` implementations, Fleet Manager, multi-tenant RBAC extension, Response Engine's destructive-action milestone (explicitly gated separately per §13's v1 scope decision).

---

## 30. Architecture Self-Review (issues found and corrected before finalizing)

This section documents the review pass required before this document was considered final, per the task's explicit instruction to check for inconsistencies, coupling, bottlenecks, security risks, scalability issues, Linux-compatibility problems, premature decisions, and unnecessary components.

1. **Inconsistency found:** the master prompt's high-level diagram (§5) shows Agent as a peer of Core/Console, but its per-layer requirements (privileged sensors, unprivileged API, separate CLI/Console) only make sense with a process split. **Correction:** explicitly split Agent and Server into two processes from §1.1 onward, and called out as a deliberate, justified deviation rather than leaving it ambiguous.

2. **Excessive coupling risk found:** an earlier draft of this design had sensors perform their own cross-referencing (e.g., the Network Sensor directly querying the Process Sensor for PID context). **Correction:** introduced the Process/Entity Resolver as a pipeline-level, not sensor-level, concern (§4.2/§7.1) — sensors emit identity-bearing events only, resolution happens once in Enrichment.

3. **Bottleneck risk found:** a single global bounded Event Bus with one lane per priority could let one noisy sensor (e.g., filesystem under heavy write load) starve others within the same lane. **Correction:** documented the starvation guard in §8.1 (bounded drain slots per lower-priority lane even under sustained higher-priority load) rather than leaving strict-priority draining unqualified.

4. **Security risk found:** an initial version of the Response Engine let the Server execute actions locally "for simplicity" in early deployments. **Correction:** removed that option entirely — §13 now mandates all response execution dispatches to the Agent, preserving the privilege boundary even in a single-host deployment, since "simplicity" here directly undermines §18's entire model.

5. **Scalability issue found:** storing only raw events and re-deriving relationships at query time (originally simpler) does not scale to graph/Story queries over large histories. **Correction:** made `relationships` a first-class, persisted edge table computed once at enrichment time (§9.4), explicitly noted as the one deliberate denormalization and why.

6. **Linux-compatibility problem found:** treating eBPF as mandatory for any sensor would fail outright on older enterprise kernels (RHEL 8 backports, older Amazon Linux) with partial or absent BTF/LSM support. **Correction:** every sensor in the catalog (§4.3) has a documented non-eBPF fallback backend and a `CapabilityProbe`-driven degrade path, not an eBPF-or-nothing design; also corrected an implicit assumption that cgroup v2 is universal — cgroup v1 hierarchy walk is retained as a fallback (§4.3).

7. **Premature decision found and reversed:** an early pass defaulted to ClickHouse from v0.1 "to avoid a migration later." **Correction:** reversed to SQLite-first per §10.2's reasoning — a distributed/clustered analytical database as a hard dependency for a single-host MVP directly violates the master prompt's explicit prohibition (§95) on premature infrastructure, and the `Storage` trait makes the later migration a bounded, planned cost rather than a rewrite.

8. **Unnecessary component found and removed:** a draft included a separate "Message Broker" component between Agent and Server distinct from the Event Bus's transport half. **Correction:** removed it — §8.3 clarifies the same bus/priority/backpressure model extends across the Agent→Server boundary via a defined wire protocol, with no separate broker process required until the genuinely distributed multi-host phase (§21), where the *existing* Server simply accepts connections from more Agents rather than introducing new middleware.

9. **Gap found:** the OQL grammar sketch in the master prompt (§42) has no grouping/parentheses, which makes any query mixing `AND`/`OR` ambiguous or inexpressible. **Correction:** added parentheses to the grammar in §12.3 as a necessary correction, not scope creep — without it the example queries in the master prompt itself (§41) can't reliably compose.

10. **Risk found:** allowing arbitrary third-party plugins to load into the privileged Agent process (a literal reading of §66) would reintroduce the exact privilege-boundary problem §18 solves. **Correction:** §20.2 restricts Agent-side (Sensor/Response) plugins to first-party/in-tree or future sandboxed-subprocess models only; only Server-side plugins (Detection/Enrichment), which never hold elevated OS privileges, get the more permissive WASM-sandbox treatment.

No further inconsistencies, unresolved bottlenecks, or unjustified premature complexity were identified in this pass. Any future deviation from this document during implementation should be recorded as an ADR update (§28) and reflected back into this file, keeping it authoritative.
