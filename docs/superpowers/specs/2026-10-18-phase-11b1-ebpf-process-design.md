# Phase 11b-1 — eBPF engine and eBPF process exec/exit backend

Status: design, 2026-10-18. Phase 11b (eBPF/CO-RE, `docs/ROADMAP-REMAINING.md` "Fase 11") is too
large for one plan, so it is split into independent sub-projects run in this order:
**11b-1 eBPF engine + process exec/exit** (this document), 11b-2 network (connect/accept/close),
11b-3 filesystem, 11b-4 DNS uprobe on resolver libraries. 11c (ClickHouse) follows 11b. The user
asked to proceed with the recommended option for every choice; every decision below that is not
dictated by `ARCHITECTURE.md` or existing code is the designer's call and is marked *(call)*.

## 1. Intent

OSIRIS has no eBPF code today. The Process/Exec sensor (`crates/osiris-sensors/process`, sensor
name `process_exec`) reads only the Linux audit log file, which needs auditd plus `execve` rules,
loses events when auditd is not configured, and never reports process exit. Nothing in the
codebase emits `PROCESS_EXIT` (`crates/osiris-pipeline/src/session_resolver.rs` notes this), so the
session resolver cannot forget dead processes.

ARCHITECTURE.md §4 (table, row "Process/Exec") names eBPF tracepoints `sched_process_exec` /
`sched_process_exit` as the primary backend with audit as the fallback, and §5 describes a shared
eBPF engine (loader, ring-buffer reader, capability probe). 11b-1 builds that engine and the first
sensor backend on it, so later sub-projects (network, filesystem, DNS uprobe) only add programs.

Success: on a real Ubuntu host (GitHub Actions runners, as in Phases 10/11a), with the eBPF object
present, the agent's process sensor reports provider `process_exec_sensor/ebpf`, a marker command
produces a stored `PROCESS_EXEC` with the right exe, argv, ppid and uid **without auditd rules
being needed**, its exit produces a stored `PROCESS_EXIT`, and the existing real-Linux process
scenarios still pass. With the object absent or the kernel unsupported, behaviour is exactly
today's audit backend.

## 2. Goals

1. **Toolchain** *(call — deviates from ARCHITECTURE §5.2's loader choice, keeps its program
   choice)*: kernel-space programs are restricted C compiled by clang to a CO-RE BPF object
   (`-target bpf -g -O2`, BTF included), exactly as §5.2 says. The **user-space loader** is the
   pure-Rust `aya` crate (it loads clang/libbpf-style CO-RE objects and applies BTF relocations)
   instead of `libbpf-rs`. Reason: `libbpf-rs` pulls `libbpf-sys`, a C build (libbpf + libelf +
   zlib) that cannot be built or even type-checked from this Windows dev host and adds a C
   toolchain to every Linux build; `aya` keeps all cargo builds pure Rust and lets the Linux-only
   code be cross-checked here with `--target x86_64-unknown-linux-gnu`. This is the "revisit via
   ADR" path §5.2 itself allows: record it as `docs/adr/0001-ebpf-loader-aya.md` (ARCHITECTURE §28
   ADR location) and update §5.1/§5.2 to point at it. `aya` (and its dependencies) is the only new
   third-party crate, and only under `[target.'cfg(target_os = "linux")'.dependencies]`.
2. **The BPF object is not built by cargo** *(call)*: sources live in `bpf/` (e.g.
   `bpf/process.bpf.c` plus a shared header), and `tools/ebpf/build.sh` compiles them with clang on
   Linux into `<out>/process.bpf.o` and writes `<out>/process.bpf.o.sha256`. Cargo builds, Windows
   tests and the existing CI never need clang. The agent loads the object at run time from a
   configured directory. No compiled object is committed to git. CO-RE struct access uses minimal
   hand-declared kernel structs with `__attribute__((preserve_access_index))` rather than a
   generated multi-megabyte `vmlinux.h` *(call)*; BPF helper headers come from the distro's
   `libbpf-dev` package at build time.
3. **New crate `crates/osiris-ebpf`** (package `osiris-ebpf`), ARCHITECTURE §5.1's engine, scoped
   to what 11b-1 needs:
   - **Capability probe** (OS-neutral API, Linux implementation): kernel release, BTF present
     (`/sys/kernel/btf/vmlinux`), ring buffer map support (kernel ≥ 5.8), and whether the process
     can load programs (effective `CAP_BPF`+`CAP_PERFMON`, or `CAP_SYS_ADMIN`). Returns a list of
     human-readable reasons when unsupported. Off Linux it always reports unsupported with a
     reason that mentions Linux.
   - **Object loader**: reads the object file from the configured directory, verifies its SHA-256
     against the sidecar `.sha256` file (ARCHITECTURE "Integrity verification" row), verifies the
     object's record **schema version** constant matches the Rust consumer's (§5.4), then loads
     and attaches the named programs through `aya`. Every failure is a typed error with a clear
     message (missing file, hash mismatch, schema mismatch, verifier rejection, attach failure).
   - **Ring buffer reader**: consumes a `BPF_MAP_TYPE_RINGBUF` on a dedicated `std::thread` (never
     an async worker thread), with a poll timeout of at most **500 ms** so cancellation is
     observed, decoding each record into a typed Rust value and handing it to a callback/channel.
   - A per-CPU **drop counter** map incremented by the BPF program when ring-buffer reservation
     fails; the reader exposes it so the sensor can report `events_dropped_total`.
4. **BPF program `process`** (in `bpf/process.bpf.c`):
   - `tp/sched/sched_process_exec`: emits an exec record with tgid, ppid (real parent's tgid),
     uid, gid, comm, the exec'd filename from the tracepoint, argv read from the new mm's
     `arg_start..arg_end` (bounded to **4096** bytes, NUL-separated; truncated flag set when cut)
     *(call: 4096)*, the task's boot-time start time, and a kernel timestamp.
   - `tp/sched/sched_process_exit`: emits an exit record **only for thread-group leaders**
     (pid == tgid), with tgid, ppid, uid, comm, exit code and start time.
   - In-kernel self-filter: a one-entry array map holds the agent's own tgid, written by the
     loader before attach; events from that tgid are not emitted (ARCHITECTURE §5.3 feedback-loop
     guard).
   - Every record starts with a fixed header `{ schema_version: u32, kind: u32 }`; the record
     layout is one C header mirrored by a `#[repr(C)]` Rust struct whose size and field offsets
     are pinned by unit tests *(call — §5.4 asks for build-time codegen from one source; a
     layout test catches the same mismatch with no codegen toolchain. Record this in the ADR)*.
   - Ring buffer size **1 MiB** *(call: exec records are fixed-size, ~4.5 KiB, so this holds
     ~230 in-flight execs)*.
5. **Process sensor gains an eBPF backend.** The sensor keeps its name `process_exec` and its
   audit backend. Backend selection at `initialize`:
   - Agent config has no `ebpf` section → audit backend, exactly as today (no behaviour change
     for existing installs).
   - `ebpf` configured, probe OK and load OK → eBPF backend; health `Healthy`, capability flag
     `ebpf`; raw events carry `RawEventSource::Ebpf`, normalized provider
     `process_exec_sensor/ebpf`, canonical `Source::Ebpf` (serde wire `EBPF`, already in the
     ARCHITECTURE §9.2 enum).
   - `ebpf` configured but probe or load fails → falls back to the audit backend, health
     `Degraded` with the failure reason in `last_error` and capability flag `audit_fallback`
     (ARCHITECTURE §4.2: DEGRADED = "eBPF program failed to load, fell back to audit"). Never a
     silent no-op.
6. **Exec events** from eBPF become the existing `RawEvent::ProcessExec(ProcessExecRaw)`:
   `exe_path` is the `/proc/<pid>/exe` link target when readable, else the exec'd filename
   from the tracepoint (parity with the audit backend's resolved `exe=`), `cmdline` from the
   argv bytes split on NUL (same bounds and truncation rules as the audit backend's `execve.rs`,
   so downstream sees identical shapes), `comm`, `uid`, `ppid`, `pid`, `timestamp_ns` (wall clock).
   `start_time_mono` must equal what the audit backend computes for the same process
   (`/proc/<pid>/stat` field 22, clock ticks) so `process_key` hashing is identical across
   backends; derive it from the kernel boot-time start time converted to clock ticks, and pin the
   conversion with a test *(call: conversion over a /proc read, which races with short-lived
   processes)*.
7. **Exit events — new raw type.** Add `RawEvent::ProcessExit(ProcessExitRaw)` to
   `osiris-sensor-api` (`pid`, `ppid`, `uid`, `comm`, `exe_path` (best-effort, may be empty),
   `exit_code: Option<i32>`, `signal: Option<u32>` — decoded from the kernel wait status: normal
   exit sets `exit_code`, death by signal sets `signal` — `timestamp_ns`, `start_time_mono`,
   `source`), normalize it to the existing `EventType::ProcessExit` with the same `process_key`
   derivation as exec and `event_data` carrying at least `exit_code` and `signal` (each `<n|null>`), plus `comm`,
   `ppid` and `uid` (enrichment needs `ppid`; no schema struct change) *(call)*, and make the session
   resolver forget the exiting process (the "no sensor emits PROCESS_EXIT yet" comment goes away).
   The audit backend does not emit exits (unchanged). `PROCESS_EXIT`'s telemetry level stays as
   `crates/osiris-policy` already defines it.
8. **Agent wiring.** New optional config key `ebpf: Option<EbpfConfig>` with
   `#[serde(default)]`; `EbpfConfig { object_dir: PathBuf }` *(call: default path when the key is
   present but empty is `/usr/lib/osiris/bpf`)*. Old YAML without the key must load. The agent
   passes its own pid to the loader for the self-filter. No new sensor name, so `KNOWN_SENSORS`
   and fleet policies are unchanged.
9. **Dependency graph**: `osiris-ebpf` may depend on `osiris-sensor-api`-free basics only (it knows
   nothing about events beyond its own record types); `osiris-sensors-process` depends on
   `osiris-ebpf`; add the matching forbidden lines to `tools/check-dep-graph.sh`
   (`osiris-ebpf` must not depend on storage/pipeline/detect/api crates).
10. **Real-Linux validation** on GitHub Actions (`.github/workflows/real-linux.yml`, pushed to
    `real-linux/t11b1-*`): setup installs clang and libbpf-dev and runs `tools/ebpf/build.sh`;
    the rendered agent config sets `ebpf.object_dir` to the build output. New `#[ignore]` test(s):
    the process sensor reports provider `process_exec_sensor/ebpf` and Healthy; a marker command
    (e.g. `/bin/sh -c 'exit 7'` with a unique argv marker) yields a stored `PROCESS_EXEC` with
    the marker in `cmdline`, correct `ppid`/`uid`, and a `PROCESS_EXIT` with `exit_code` 7 for the
    same `process_key`. All existing real-Linux tests (which today run on the audit backend)
    must pass with the eBPF backend active. One extra test proves the fallback: with a corrupted
    object (hash mismatch) the sensor is `Degraded` and audit-backed exec events still arrive.
    Run on ubuntu-22.04 (kernel 5.15) and ubuntu-24.04 (6.x).
11. **Docs**: the ADR; ARCHITECTURE §5.1/§5.2 pointer to the ADR and a §4 status note for the
    Process row; `docs/VALIDATION.md` eBPF section with the GH run id; `docs/ROADMAP-REMAINING.md`
    11b-1 done and 11b-2..4 listed; operator note (`docs/operators-ebpf.md`) on building the
    object, the `ebpf` key, required privileges and the fallback.

## 3. Non-goals

- Network, filesystem, LSM, kernel-module and DNS-uprobe programs (11b-2..4 and later).
- `sched_process_fork` events (`PROCESS_FORK` stays unemitted; exec + exit cover the session
  resolver's needs) *(call)*.
- Capturing environment variables, interpreter detection, hash-on-exec (DETAILED/FORENSIC rows).
- Per-entity telemetry-level maps in kernel (ARCHITECTURE §6 scoping) — later.
- A kernel-version CI matrix with VMs (§5.4 / §26): validation is the two GH runner kernels.
- Packaging the object (`.deb`/`.rpm`, systemd units) — Phase 13.
- Privilege dropping to a minimal capability set (ARCHITECTURE §15) — later.
- Removing or changing the audit backend.

## 4. Anti-goals (would be a failure even if it "works")

- A BPF program that can hang, crash or noticeably slow the host: no unbounded loops (verifier
  enforces), bounded reads only, no blocking helpers.
- Silent telemetry loss: ring-buffer drops are counted and visible in sensor metrics; a failed
  load is visible as `Degraded` with a reason.
- Misreading kernel memory because Rust and C disagree on the record layout (schema version check
  plus layout tests).
- Making `cargo build`/`cargo test --workspace` on Windows or Linux CI need clang, root, BTF or a
  loaded program.
- Changing behaviour for installs without the `ebpf` key.
- Feedback loops: the agent's own processes generating exec/exit events about itself.

## 5. Known behaviour to document (not fix)

- `exe_path` is the `/proc/<pid>/exe` target when readable, else the `execve` filename; for
  scripts it is the script path, the interpreter appears in argv — same as the audit backend.
- argv is read after exec from the new process's memory; a process that rewrites its argv before
  the read (rare, racy) shows the rewritten text.
- Exit events for very short-lived processes may have an empty `exe_path` when user space cannot
  resolve it anymore; `comm` is always present.
- Event volume roughly doubles versus audit-only (exits are new).

## 6. Constraints carried from earlier phases

- Configs are YAML; binaries take the config path as `argv[1]`.
- Before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `bash tools/check-dep-graph.sh`, console
  `npm run lint && npm test && npm run build`.
- No new CI gates (the real-Linux workflow stays push-triggered on `real-linux/**`).
- Linux-only code is cross-checked on this Windows host with
  `cargo check`/`cargo clippy -D warnings --target x86_64-unknown-linux-gnu`; behaviour is proven
  on GH Actions. Claude can push `real-linux/*` branches; artifacts need GitHub auth (the user
  downloads them when needed).
- Real-Linux tests: `#[ignore]`, `#[cfg(target_os = "linux")]`, serial, root, bounded waits with
  logs on timeout, unique markers.
- Untrusted input (ring-buffer bytes are kernel-produced but still parsed defensively, `/proc`
  text) never panics and is bounded.

## 7. Left to the builder

Module split inside `osiris-ebpf` and the process sensor, the exact C, map names, error enum
names, backoff on ring-buffer errors, the shape of the reader callback, and doc wording — within
the constraints above. The `aya` version is the latest stable release at implementation time,
pinned exactly in `Cargo.toml`.
