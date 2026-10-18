# Phase 11b-1 eBPF Engine and Process Exec/Exit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a shared eBPF engine crate and an eBPF backend (exec + exit tracepoints) to the existing `process_exec` sensor, with the audit backend kept as fallback, validated on real Linux.

**Architecture:** Restricted-C CO-RE programs in `bpf/` are compiled by clang outside cargo (`tools/ebpf/build.sh`); the agent loads the object at run time through the pure-Rust `aya` loader in a new `osiris-ebpf` crate (probe, integrity + schema check, ring-buffer reader thread). The process sensor picks eBPF when configured and working, else audit; exits become a new `RawEvent::ProcessExit`.

**Tech Stack:** Rust 1.99 workspace, `aya` (Linux-only), clang + libbpf-dev headers (Linux build host / GH Actions only), GH Actions real-Linux workflow.

**Spec:** `docs/superpowers/specs/2026-10-18-phase-11b1-ebpf-process-design.md`

## Global Constraints

1. Only new third-party crate: `aya` (exact version pinned, latest stable at implementation), only under `[target.'cfg(target_os = "linux")'.dependencies]`. `sha2` is already in the workspace and may be reused.
2. Cargo never builds BPF C. No compiled `.bpf.o` committed. `cargo build`/`cargo test --workspace` on Windows and Linux CI need no clang, root, BTF or loaded program.
3. Record ABI (C header ↔ `#[repr(C)]` Rust) is exactly the layout in Task 2; `SCHEMA_VERSION = 1`; kinds `EXEC = 1`, `EXIT = 2`.
4. argv capture bounded to **4096** bytes; filename **256** bytes; comm **16** bytes; ring buffer **1 MiB** (`1 << 20`).
5. Ring-buffer reader runs on a dedicated `std::thread`, poll timeout ≤ **500 ms**, exits on cancellation; never on async worker threads.
6. Provider strings: `process_exec_sensor/ebpf` (exec and exit); raw source `RawEventSource::Ebpf`; canonical `Source::Ebpf` (wire `EBPF`).
7. Config: `ebpf: Option<EbpfConfig>` with `#[serde(default)]`; `EbpfConfig { object_dir: PathBuf }`, `object_dir` defaults to `/usr/lib/osiris/bpf` when the key is present but empty. YAML without `ebpf` loads and behaves exactly as today.
8. Object integrity: `<dir>/process.bpf.o` must match the lowercase hex SHA-256 in `<dir>/process.bpf.o.sha256` (first whitespace-separated token).
9. Fallback: `ebpf` configured but probe/load fails → audit backend if `audit_log_path` is configured, health `Degraded`, `last_error` = reason, capability flag `audit_fallback`; with no audit path → sensor `Failed` with the reason. eBPF working → `Healthy`, capability flag `ebpf`.
10. `start_time_mono` from eBPF = `start_boottime_ns / 10_000_000` (clock ticks at USER_HZ 100, matching `/proc/<pid>/stat` field 22).
11. Sensor name stays `process_exec`; `KNOWN_SENSORS` unchanged.
12. Real-Linux tests: `#[ignore]`, `#[cfg(target_os = "linux")]`, serial, root, bounded waits, unique markers; run by pushing to `real-linux/t11b1-<n>`; poll `https://api.github.com/repos/excanear/OSIRIS---Operational-System-Intelligence-Response-Investigation-System/actions/runs`. Artifacts need GitHub auth (the user downloads them).
13. Linux-only code is cross-checked on Windows: `cargo check` and `cargo clippy -D warnings` with `--target x86_64-unknown-linux-gnu` for every touched crate.
14. Before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `bash tools/check-dep-graph.sh`, console `npm run lint && npm test && npm run build`. No new CI gates.

## Review Focus

1. **Truncated or short ring-buffer record** (kernel/user layout drift, partial read) → decode returns an error and the record is counted as dropped; never a panic or misread. Task 2 test `decode_rejects_short_and_wrong_version`.
2. **argv with no trailing NUL / truncated at 4096 / empty argv** → `cmdline` split like the audit backend, last fragment kept, no empty trailing element. Task 5 test `argv_bytes_split_like_audit`.
3. **Process killed by a signal** (wait status low 7 bits non-zero) → `signal: Some(n)`, `exit_code: None`. Task 2 test `wait_status_decoding`.
4. **eBPF configured on a host without BTF / without CAP_BPF / object missing** → audit fallback with `Degraded` and a reason naming the cause. Task 5 test `falls_back_to_audit_when_ebpf_unavailable`.
5. **Hash sidecar with trailing filename/newline or uppercase hex** → accepted when the digest matches; a different digest is rejected. Task 2 test `sidecar_digest_parsing`.

---

### Task 1: ProcessExit raw event, Ebpf source, normalization, resolver eviction

**Files:** Modify `crates/osiris-sensor-api/src/raw_event.rs` (add `RawEventSource::Ebpf`, `ProcessExitRaw`, `RawEvent::ProcessExit`, `timestamp_ns` arm); `crates/osiris-pipeline/src/normalize.rs` (provider `process_exec_sensor/ebpf` for `Ebpf`; `normalize_process_exit`; every `match` on `RawEventSource`/`RawEvent` across the workspace gets its arm); `crates/osiris-pipeline/src/session_resolver.rs` (`forget_pid`); `crates/osiris-pipeline/src/process_resolver.rs` (evict pid on exit if it has a per-pid map); `crates/osiris-pipeline/src/enrich.rs` (call eviction for `PROCESS_EXIT` **after** attaching session/process to the exit event).

**Interfaces — Produces:**
```rust
pub struct ProcessExitRaw { pub pid: u32, pub ppid: u32, pub uid: u32, pub comm: String,
  pub exe_path: String, pub exit_code: Option<i32>, pub signal: Option<u32>,
  pub timestamp_ns: u64, pub start_time_mono: u64, pub source: RawEventSource }
impl SessionResolver { pub fn forget_pid(&mut self, pid: u32) }
```
Exit canonical event: `EventType::ProcessExit`, `process` = `ProcessRef` with the same `process_key` derivation as exec (pid + start_time_mono + boot_id), `event_data` = `{"exit_code": <n|null>, "signal": <n|null>}`.

- [ ] **Step 1: Failing tests:** `normalize_process_exit_carries_key_and_exit_data` (exec and exit raws with equal pid/start_time_mono/boot normalize to equal `process_key`; exit's `event_data["exit_code"] == 7`, `["signal"]` null; provider `process_exec_sensor/ebpf`, source `Source::Ebpf`); `ebpf_exec_provider` (exec raw with `Ebpf` source → `process_exec_sensor/ebpf`); `forget_pid_drops_only_that_pid` (session keeps other members); `exit_event_keeps_session_then_evicts` (enrich: exit event of a session member carries the session, a later exec of the same pid with a new parent outside the session does not inherit it).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement; remove the "no sensor emits PROCESS_EXIT yet" limitation text, describing per-pid eviction instead.
- [ ] **Step 4:** `cargo test --workspace` PASS; clippy clean.
- [ ] **Step 5:** Commit `feat(11b-1): PROCESS_EXIT raw event and eBPF source`.

### Task 2: `osiris-ebpf` crate — record ABI, decoding, integrity

**Files:** Create `crates/osiris-ebpf/{Cargo.toml,src/lib.rs,src/record.rs,src/integrity.rs}`; add to workspace members; `tools/check-dep-graph.sh` forbidden lines (`osiris-ebpf` must not depend on `osiris-storage`, `osiris-pipeline`, `osiris-detect`, `osiris-api`, `osiris-server`, `osiris-sensor-api`).

**Interfaces — Produces** (OS-neutral, `pub`):
```rust
pub const SCHEMA_VERSION: u32 = 1;
pub const KIND_EXEC: u32 = 1; pub const KIND_EXIT: u32 = 2;
pub const ARGS_MAX: usize = 4096; pub const FILENAME_MAX: usize = 256; pub const COMM_LEN: usize = 16;
#[repr(C)] pub struct RecordHeader { pub schema_version: u32, pub kind: u32 }
#[repr(C)] pub struct ExecRecord { pub hdr: RecordHeader, pub pid: u32, pub ppid: u32, pub uid: u32,
  pub gid: u32, pub ktime_ns: u64, pub start_boottime_ns: u64, pub comm: [u8; 16],
  pub filename_len: u32, pub args_len: u32, pub args_truncated: u8, pub _pad: [u8; 7],
  pub filename: [u8; 256], pub args: [u8; 4096] }
#[repr(C)] pub struct ExitRecord { pub hdr: RecordHeader, pub pid: u32, pub ppid: u32, pub uid: u32,
  pub exit_status: u32, pub ktime_ns: u64, pub start_boottime_ns: u64, pub comm: [u8; 16] }
pub enum Record { Exec(ExecEvent), Exit(ExitEvent) }   // owned, decoded: Strings/Vec<u8>, lens clamped
pub fn decode(bytes: &[u8]) -> Result<Record, DecodeError>;
pub fn decode_wait_status(status: u32) -> (Option<i32>, Option<u32>);  // (exit_code, signal)
pub fn verify_object(object: &[u8], sidecar_text: &str) -> Result<(), IntegrityError>;
```
`ExecEvent { pid, ppid, uid, ktime_ns, start_boottime_ns, comm: String, filename: String, args: Vec<u8>, args_truncated: bool }`; `ExitEvent { pid, ppid, uid, exit_status, ktime_ns, start_boottime_ns, comm }`. Lengths are clamped to the array size; comm/filename stop at the first NUL; invalid UTF-8 is lossily converted.

- [ ] **Step 1: Failing tests:** `layout_is_pinned` (`size_of::<ExecRecord>() == 4424`, `size_of::<ExitRecord>() == 56`, `offset_of!(ExecRecord, comm) == 40`, `offset_of!(ExecRecord, filename) == 72`, `offset_of!(ExecRecord, args) == 328`, `offset_of!(ExitRecord, comm) == 40`); `decode_round_trips_exec_and_exit`; `decode_rejects_short_and_wrong_version` (shorter than header, shorter than the kind's struct, version 2, unknown kind 9 → distinct errors); `lengths_are_clamped` (`filename_len = 9999` → 256 bytes max); `wait_status_decoding` (`7 << 8` → `(Some(7), None)`; `9` → `(None, Some(9))`; `0` → `(Some(0), None)`); `sidecar_digest_parsing` (`"<hex>  process.bpf.o\n"` and uppercase hex accepted; other digest → `IntegrityError::Mismatch`; empty → `IntegrityError::Malformed`).
- [ ] **Step 2:** FAIL. **Step 3:** implement (decode by `read_unaligned` from a length-checked slice; no `transmute` of unchecked lengths).
- [ ] **Step 4:** `cargo test -p osiris-ebpf`, workspace clippy, `bash tools/check-dep-graph.sh` PASS.
- [ ] **Step 5:** Commit `feat(11b-1): osiris-ebpf record ABI and object integrity`.

### Task 3: BPF program and build script

**Files:** Create `bpf/process.h` (C mirror of Task 2's structs and constants, with `_Static_assert` on `sizeof` 4424 / 56), `bpf/process.bpf.c`, `bpf/vmlinux_min.h` (hand-declared `task_struct`, `mm_struct`, tracepoint ctx structs with `preserve_access_index`), `tools/ebpf/build.sh` (`build.sh <out_dir>`: `clang -target bpf -D__TARGET_ARCH_x86 -g -O2 -c bpf/process.bpf.c -o <out>/process.bpf.o`, then `sha256sum` sidecar; fails loudly if clang or `/usr/include/bpf/bpf_helpers.h` is missing).

**Interfaces — Produces** (names the loader in Task 4 uses): programs `handle_exec` (`SEC("tp/sched/sched_process_exec")`) and `handle_exit` (`SEC("tp/sched/sched_process_exit")`); maps `EVENTS` (`BPF_MAP_TYPE_RINGBUF`, `max_entries = 1 << 20`), `DROPS` (`BPF_MAP_TYPE_PERCPU_ARRAY`, 1 × u64), `SELF_TGID` (`BPF_MAP_TYPE_ARRAY`, 1 × u32); global `const volatile u32 schema_version = 1` readable from the object (`.rodata`) for the loader's check. Exec: pid = tgid, ppid = `real_parent->tgid`, filename from the tracepoint's `__data_loc` field, args via `bpf_probe_read_user` of `mm->arg_start..min(arg_end, arg_start+4096)`. Exit: only when `pid == tgid`; `exit_status = task->exit_code`. Both skip when tgid equals `SELF_TGID[0]`; reservation failure increments `DROPS[0]`. License `"Dual BSD/GPL"`.

- [ ] **Step 1:** Write the sources and script. (No local compile is possible; Task 7's GH run builds and loads it. `bash -n tools/ebpf/build.sh` must pass here.)
- [ ] **Step 2:** Add a Rust test in `osiris-ebpf` `c_header_matches_rust_constants` that reads `bpf/process.h` as text and asserts it contains `#define SCHEMA_VERSION 1`, `ARGS_MAX 4096`, `FILENAME_MAX 256` and the two `_Static_assert` sizes.
- [ ] **Step 3:** Commit `feat(11b-1): process BPF program and build script`.

### Task 4: Linux loader, capability probe and ring-buffer reader

**Files:** Create `crates/osiris-ebpf/src/{probe.rs,loader.rs,reader.rs}`; `Cargo.toml` (Linux-only `aya`).

**Interfaces — Produces:**
```rust
pub struct ProbeReport { pub supported: bool, pub reasons: Vec<String>, pub kernel_release: String }
pub fn probe() -> ProbeReport;                                    // off Linux: unsupported, reason mentions Linux
pub fn parse_kernel_release(s: &str) -> Option<(u32, u32)>;      // OS-neutral, "5.15.0-1057-azure" → (5,15)
pub fn caps_allow_bpf(cap_eff_hex: &str) -> bool;                // OS-neutral: CAP_SYS_ADMIN(21) or CAP_BPF(39)+CAP_PERFMON(38)
pub struct ProcessProgram { /* Linux: aya::Ebpf + ring buffer */ }
impl ProcessProgram {
  pub fn load(object_dir: &Path, self_tgid: u32) -> Result<Self, LoadError>; // verify_object, schema check, set SELF_TGID, attach both
  pub fn drops(&self) -> u64;                                                // sum of DROPS per CPU
}
pub fn spawn_reader(prog: ProcessProgram, cancel: CancellationToken,
                    on_record: impl FnMut(Result<Record, DecodeError>) + Send + 'static)
    -> std::thread::JoinHandle<Result<(), ReaderError>>;
```
Probe reasons: kernel < 5.8 ("ring buffer needs kernel ≥ 5.8"), missing `/sys/kernel/btf/vmlinux` ("kernel BTF not available"), capability check from `/proc/self/status` `CapEff`. `LoadError` variants: `MissingObject`, `Integrity`, `SchemaMismatch { object: u32, expected: u32 }`, `Load(String)`, `Attach(String)`. Reader polls the ring buffer fd with ≤ 500 ms timeout, drains all available records per wake, stops when `cancel` is cancelled.

- [ ] **Step 1: Failing tests (OS-neutral):** `kernel_release_parsing` (`"6.8.0-1015-azure"` → `(6,8)`, `"5.4"` → `(5,4)`, `"garbage"` → None); `cap_eff_parsing` (`"000001ffffffffff"` → true; `"00000000a80425fb"` (Docker default set: no CAP_SYS_ADMIN, no CAP_BPF) → false; `"0000000000200000"` (only CAP_SYS_ADMIN) → true; `"000000c000000000"` (CAP_PERFMON+CAP_BPF only) → true; `"0000000000000000"` → false); `#[cfg(not(target_os = "linux"))] probe_unsupported_off_linux`; `load_reports_missing_object` (empty temp dir → `LoadError::MissingObject`, on all OSes — the Linux path must check the file before touching aya; off Linux `load` returns `MissingObject` too when the file is absent, otherwise `Load("eBPF requires Linux")`).
- [ ] **Step 2:** FAIL. **Step 3:** implement; the schema check reads the object's `schema_version` global via aya's object inspection before load.
- [ ] **Step 4:** `cargo test -p osiris-ebpf`; Linux cross-check (Global Constraint #13) clean.
- [ ] **Step 5:** Commit `feat(11b-1): eBPF capability probe, loader and ring-buffer reader`.

### Task 5: Process sensor eBPF backend with audit fallback

**Files:** Modify `crates/osiris-sensors/process/{Cargo.toml,src/sensor.rs,src/lib.rs}`; create `src/ebpf_backend.rs` (record → raw event conversion, OS-neutral).

**Interfaces — Consumes:** Task 2 `Record`/`decode_wait_status`, Task 4 `probe`/`ProcessProgram`/`spawn_reader`, Task 1 `ProcessExitRaw`. **Produces:**
```rust
pub struct EbpfSettings { pub object_dir: PathBuf, pub self_tgid: u32 }
impl ProcessExecSensor { pub fn new(audit_log_path: Option<PathBuf>, ebpf: Option<EbpfSettings>) -> Self }
pub fn exec_to_raw(e: &ExecEvent, boot_wall_offset_ns: i128) -> ProcessExecRaw;
pub fn exit_to_raw(e: &ExitEvent, boot_wall_offset_ns: i128) -> ProcessExitRaw;
pub fn split_argv(bytes: &[u8]) -> Vec<String>;
```
`timestamp_ns = ktime_ns + boot_wall_offset_ns` (offset = realtime − monotonic sampled once at reader start); `start_time_mono = start_boottime_ns / 10_000_000`; `exe_path` = filename if absolute, else `/proc/<pid>/exe` target when readable, else the filename as given; exit `exe_path` = `/proc/<pid>/exe` if readable else `""`. `split_argv` applies the same per-arg and count bounds as `execve.rs` (reuse its constants).

- [ ] **Step 1: Failing tests:** `argv_bytes_split_like_audit` (`b"ls\0-la\0/tmp\0"` → 3 args; no trailing NUL keeps last; empty → `vec![]`; consecutive NULs keep an empty arg in the middle like audit does — check `execve.rs` behaviour and match it); `exec_conversion` (start_boottime 12_340_000_000 → start_time_mono 1234; offset applied; source `Ebpf`); `exit_conversion_signal` (status 9 → `signal Some(9)`); `falls_back_to_audit_when_ebpf_unavailable` (sensor with audit path + `EbpfSettings` pointing at an empty dir: after `initialize`/`start`, health `Degraded`, `last_error` contains "process.bpf.o", capability flags contain `audit_fallback`, and an audit line written to the log still yields an exec event); `no_ebpf_settings_is_todays_behaviour` (health Healthy, no `audit_fallback` flag); `ebpf_unavailable_without_audit_fails` (`Failed` with the reason).
- [ ] **Step 2:** FAIL. **Step 3:** implement; mirror the existing sensor's health/locking/cancellation; on the eBPF path add `ProcessProgram::drops()` to `events_dropped_total` each health read; a reader error after start moves health to `Failed` with the error (no silent stop).
- [ ] **Step 4:** `cargo test -p osiris-sensors-process`; Linux cross-check clean.
- [ ] **Step 5:** Commit `feat(11b-1): eBPF backend for the process sensor`.

### Task 6: Agent wiring

**Files:** Modify `crates/osiris-agent/{Cargo.toml,src/config.rs,src/agent.rs}`; e2e test `AgentConfig` literals.

**Interfaces — Produces:** `AgentConfig.ebpf: Option<EbpfConfig>`, `pub struct EbpfConfig { #[serde(default = "default_object_dir")] pub object_dir: PathBuf }`. `build_sensor("process_exec")` returns a sensor when `audit_log_path` **or** `ebpf` is configured, passing `EbpfSettings { object_dir, self_tgid: std::process::id() }`.

- [ ] **Step 1: Failing tests:** `config_without_ebpf_loads` (existing fixture → `ebpf.is_none()`); `config_with_empty_ebpf_defaults_dir` (`ebpf: {}` → `/usr/lib/osiris/bpf`); `build_sensor_process_with_ebpf_only` (no audit path, `ebpf` set → `Some`); existing `build_sensor` "not configured" tests unchanged.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `cargo test --workspace`, dep-graph PASS. **Step 5:** Commit `feat(11b-1): agent ebpf config`.

### Task 7: Real-Linux validation

**Files:** Modify `tools/real-linux/setup.sh` (install `clang libbpf-dev`; run `tools/ebpf/build.sh "$OSIRIS_BPF_DIR"`), `.github/workflows/real-linux.yml` (export `OSIRIS_BPF_DIR`; upload the build log), `crates/osiris-real-linux-tests/src/render.rs` (`ebpf: { object_dir: <dir> }` when `OSIRIS_BPF_DIR` is set), `tests/real_linux.rs`.

- [ ] **Step 1: Tests (`#[ignore]`):** `process_sensor_uses_ebpf` (AGENT_HEALTH lists `process_exec` HEALTHY with capability `ebpf`); `exec_and_exit_are_observed_via_ebpf` (`m = marker()`; run `/bin/sh -c 'exit 7' <m>`-style command carrying `m` in argv; wait for `PROCESS_EXEC` with provider `process_exec_sensor/ebpf`, `m` in `cmdline`, `ppid` = the test's spawning shell pid when known, uid 0; then `PROCESS_EXIT` with the same `process_key` and `event_data.exit_code == 7`); `corrupted_object_falls_back_to_audit` (stack with a copy of the object dir whose sidecar digest is altered → `process_exec` DEGRADED with `audit_fallback`, and an audit-backed exec event for a marker arrives). Existing tests must stay green with eBPF active.
- [ ] **Step 2:** Cross-check compile; commit; push `real-linux/t11b1-1`; poll the run. If red: diagnose from the job log summary/artifacts (ask the user to download when needed), fix with a regression test in the owning crate, re-run as `t11b1-2`, …
- [ ] **Step 3:** Commit `test(11b-1): real-Linux eBPF process scenarios`.

### Task 8: Docs and final gates

**Files:** Create `docs/adr/0001-ebpf-loader-aya.md` (context, decision: aya loader + clang C CO-RE programs, layout-test instead of codegen, consequences, revisit triggers); `docs/operators-ebpf.md` (build the object, `ebpf` key, privileges, fallback, drop counter). Modify `ARCHITECTURE.md` §5.1/§5.2 (point to the ADR, loader = aya) and §4 Process row status note; `docs/VALIDATION.md` (eBPF section with the GH run id and kernels); `docs/ROADMAP-REMAINING.md` (11b-1 done; 11b-2 network, 11b-3 filesystem, 11b-4 DNS uprobe pending; debts found).

- [ ] **Step 1:** Write docs. **Step 2:** Run every gate in Global Constraint #14 → PASS. **Step 3:** Commit `docs(11b-1): eBPF engine and process backend validated`.
