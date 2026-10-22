# Phase 11b-2 eBPF Network Backend and Process Schema v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `network` sensor an eBPF backend (TCP connect/accept/close, IPv4 and IPv6), with the procfs poller as fallback. In the same change, move the process BPF record to schema v2: the exe identity is captured in the kernel, and exit is reported when the thread group dies.

**Architecture:** The 11b-1 `ProcessProgram` loader is generalised into a spec-driven `LoadedObject`. That object handles one `.bpf.o` per sensor with its own schema version, and it is shared by a new `net.bpf.o` (tracepoints `sock/inet_sock_set_state` + `syscalls/sys_exit_accept{,4}`, LRU socket-owner map). The `exe_path` resolver and the wall-clock offset move into `osiris-ebpf` so both sensors share them. The network sensor gains the same eBPF/fallback selection as the process sensor.

**Tech Stack:** Rust 1.99 workspace, `aya` (pinned at the 11b-1 version, Linux-only), clang + libbpf-dev (Linux build host / GH Actions only), GH Actions real-Linux workflow.

**Spec:** `docs/superpowers/specs/2026-10-22-phase-11b2-ebpf-network-design.md` (and the 11b-1 spec it builds on: `docs/superpowers/specs/2026-10-18-phase-11b1-ebpf-process-design.md`)

## Global Constraints

1. No new third-party crate. `aya` stays at the version pinned in `crates/osiris-ebpf/Cargo.toml` unless a needed feature forces a bump; a bump is recorded in the task report and in ADR-010.
2. Cargo never builds BPF C, and no `.bpf.o` is committed. `cargo build`/`cargo test --workspace` on Windows and Linux CI need no clang, root, BTF or loaded program.
3. One object per sensor: `process.bpf.o` and `net.bpf.o`, each with a `<file>.sha256` sidecar (lowercase hex, first token), both in the configured `ebpf.object_dir`. Each exports a `.rodata` global `schema_version`. Process expects **2**, net expects **1**.
4. Record ABIs are exactly those in Tasks 2 and 4. Kinds: `EXEC = 1`, `EXIT = 2`, `NET_CONNECT = 3`, `NET_ACCEPT = 4`, `NET_CLOSE = 5`.
5. Net ring buffer **256 KiB** (`1 << 18`). The process ring buffer stays **1 MiB**. The socket-owner map is `BPF_MAP_TYPE_LRU_HASH`, key u64 sock pointer, **65 536** entries. The exit `exe_path` cache holds **65 536** entries and evicts the oldest first.
6. Ring-buffer readers run on dedicated `std::thread`s with a poll timeout ≤ **500 ms**, and exit on cancellation.
7. Provider `network_sensor/ebpf` (already mapped), raw source `RawEventSource::Ebpf`, `proto` `"tcp"`. Direction: CONNECT → Outbound, ACCEPT → Inbound, CLOSE → the direction stored at open time. The eBPF path never guesses direction from ports.
8. Network fallback: if `ebpf` is configured but probe or load fails, the sensor falls back to the procfs poller when `network_proc_root` is set, with health `Degraded`, `last_error` = the reason naming `net.bpf.o`, and flag `procfs_fallback`. Without `network_proc_root`, `initialize` returns `SensorError::Unsupported(reason)`. When eBPF works the health is `Healthy` with flag `ebpf`. With no `ebpf` key, behaviour is exactly today's.
9. The `exe_path` fallback chain (exec and net), in order: (1) `stat(/proc/<pid>/exe)` `(st_dev, st_ino)` equals the kernel identity → the link target; (2) else the link target if `/proc/<pid>/comm`, read after the link, equals the record's comm (first 15 bytes, the 11b-1 rule); (3) else the exec filename (exec records) or `""` (net records). Exit `exe_path` comes from the `(tgid, start_time)` cache and is `""` on a miss.
10. Sensor names, `KNOWN_SENSORS` and agent config keys are unchanged (no new keys).
11. Real-Linux tests: `#[ignore]`, `#[cfg(target_os = "linux")]`, serial, root, bounded waits, unique markers. They run when pushed to `real-linux/t11b2-<n>` and are polled via `https://api.github.com/repos/excanear/OSIRIS---Operational-System-Intelligence-Response-Investigation-System/actions/runs`. Failures surface as `::error::`/`::warning::` annotations (the 11b-1 R4b pattern).
12. Linux-only code is cross-checked on Windows with `cargo check` and `cargo clippy -D warnings --target x86_64-unknown-linux-gnu` for every touched crate. Stubs for C-building deps go only in the session scratchpad.
13. Before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `bash tools/check-dep-graph.sh`, and the console's `npm run lint && npm test && npm run build`. No new CI gates.
14. Untrusted bytes (ring-buffer records, `/proc` text) never panic and are bounded.

## Review Focus

1. **A net record with an unknown family (neither 2 nor 10), a short buffer, or an unknown kind** → `DecodeError`, counted as dropped, no panic. Task 4 test `net_decode_rejects_bad_family_short_and_unknown_kind`.
2. **IPv4-mapped IPv6 (`::ffff:1.2.3.4`), loopback `::1`, IPv4 in the first 4 bytes** → `"1.2.3.4"`, `"::1"`, dotted quad. Task 5 test `render_addr_cases`.
3. **An exit for a process the agent never saw exec, and a full cache** → `exe_path` `""` without a panic, and the oldest entry is evicted at 65 536. Task 3 test `exit_cache_miss_and_eviction`.
4. **Identity mismatch with a matching comm, a zero identity, and an unreadable link** → the link via the comm rule, the comm rule, and `None`. Task 2 test `resolve_exe_fallback_chain`.
5. **`ebpf` configured with `process.bpf.o` valid but `net.bpf.o` missing** → network `Degraded`/`procfs_fallback` while the process sensor's eBPF path is unaffected. Task 5 test `falls_back_to_procfs_when_net_object_missing`.

---

### Task 1: Generalise the engine loader, reader and clock (behaviour-preserving)

**Files:** Modify `crates/osiris-ebpf/src/{lib.rs,loader.rs,reader.rs}`; create `crates/osiris-ebpf/src/clock.rs`; modify `crates/osiris-sensors/process/src/{sensor.rs,ebpf_backend.rs,lib.rs}` to use the new API. `EbpfSettings` moves to `osiris-ebpf`, and `osiris-sensors-process` re-exports it so `osiris-agent` compiles unchanged.

**Interfaces — Produces:**
```rust
pub struct ObjectSpec { pub object_file: &'static str, pub expected_schema: u32,
  /// (program name, tracepoint category, tracepoint name)
  pub tracepoints: &'static [(&'static str, &'static str, &'static str)] }
pub const PROCESS_OBJECT: ObjectSpec; // "process.bpf.o", schema = record::PROCESS_SCHEMA_VERSION (still 1 in this task), handle_exec/handle_exit
pub struct LoadedObject { .. } // owns aya Ebpf + EVENTS ring + DROPS; Drop detaches
impl LoadedObject {
  pub fn load(object_dir: &Path, spec: &ObjectSpec, self_tgid: u32) -> Result<Self, LoadError>;
  pub fn drop_counter(&self) -> DropCounter; }
pub fn spawn_reader<T: Send + 'static>(obj: LoadedObject, decode: fn(&[u8]) -> Result<T, DecodeError>,
  cancel: CancellationToken, on_record: impl FnMut(Result<T, DecodeError>) + Send + 'static)
  -> Result<JoinHandle<Result<(), ReaderError>>, ReaderError>;
pub fn sidecar_name(object_file: &str) -> String; // "<object_file>.sha256"
#[derive(Clone, Debug)] pub struct EbpfSettings { pub object_dir: PathBuf, pub self_tgid: u32 }
pub fn boot_wall_offset_ns() -> i128; // in clock.rs, moved from the process sensor (same semantics and Once-guarded warn)
```
`record::SCHEMA_VERSION` is renamed `PROCESS_SCHEMA_VERSION`. `ProcessProgram`, `OBJECT_FILE` and `SIDECAR_FILE` are removed. Every `LoadError` message names the object file it concerns (e.g. `MissingObject` shows the full path).

- [ ] **Step 1: Failing tests** in `loader.rs`: `sidecar_name_appends_sha256` (`sidecar_name("net.bpf.o") == "net.bpf.o.sha256"`); `load_reports_missing_object_with_its_file_name` (empty tempdir + a test `ObjectSpec { object_file: "x.bpf.o", .. }` → `LoadError::MissingObject(p)` with `p.ends_with("x.bpf.o")`); `load_rejects_schema_mismatch_against_spec` (the existing schema-mismatch fixture checked against `expected_schema: 99` → `SchemaMismatch { expected: 99, .. }`, on Linux; on other OSes the existing off-Linux error path is kept).
- [ ] **Step 2:** Run `cargo test -p osiris-ebpf` → FAIL (the items do not exist).
- [ ] **Step 3:** Implement. Map names stay `EVENTS`, `DROPS` and `SELF_TGID` in every object. Attach every tracepoint in `spec.tracepoints` in order, and fail with `Attach("<prog>: <err>")` on the first error. Port the existing process loader and reader tests to the new API without weakening their assertions.
- [ ] **Step 4:** `cargo test --workspace` PASS (process sensor tests unchanged in behaviour); Linux-target clippy on `osiris-ebpf`, `osiris-sensors-process` and `osiris-agent` clean.
- [ ] **Step 5:** Commit `refactor(11b-2): spec-driven eBPF object loader and shared clock`.

### Task 2: Process record v2 ABI, exe identity and shared resolver

**Files:** Modify `bpf/process.h`, `bpf/process.bpf.c`, `bpf/vmlinux_min.h`; `crates/osiris-ebpf/src/record.rs`; create `crates/osiris-ebpf/src/exe.rs` (moving `choose_exe_path`/`resolve_exe_path`/the comm logic out of `crates/osiris-sensors/process/src/ebpf_backend.rs`, which then calls it).

**Interfaces — Produces:**
```rust
pub const PROCESS_SCHEMA_VERSION: u32 = 2;
// ExecRecord v2 (size 4432): hdr@0 pid@8 ppid@12 uid@16 gid@20 ktime_ns@24 start_boottime_ns@32
// comm[16]@40 filename_len@56 args_len@60 args_truncated:u8@64 _pad:[u8;3]@65 exe_dev:u32@68
// exe_ino:u64@72 filename[256]@80 args[4096]@336.  ExitRecord unchanged (56 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct ExeIdentity { pub dev: u64, pub ino: u64 } // dev in user st_dev encoding
pub fn dev_to_user(kernel_dev: u32) -> u64; // MAJOR = d >> 20, MINOR = d & 0xfffff, glibc makedev encoding
// ExecEvent gains `pub exe: Option<ExeIdentity>` (None when exe_ino == 0)
pub fn resolve_exe(proc_root: &Path, pid: u32, exe: Option<ExeIdentity>, record_comm: &str) -> Option<String>; // steps 1-2 of GC 9
```
C side: at `sched_process_exec`, read `current->mm->exe_file->f_inode` (`i_ino`, `i_sb->s_dev`) with CO-RE. At `sched_process_exit`, emit when `BPF_CORE_READ(task, signal, live.counter) == 0` instead of `pid == tgid`. The record carries the tgid and `group_leader->start_boottime`. `exit_status` is `signal->group_exit_code` when the group-exit flag (`SIGNAL_GROUP_EXIT` in `signal->flags`) is set, else `task->exit_code`. The C comment cites the 5.15 and 6.x `do_exit` ordering (`signal->live` decremented and `exit_mm()` called before `trace_sched_process_exit`).

- [ ] **Step 1: Failing tests:** update `layout_is_pinned` and `c_header_matches_rust_constants` to the v2 offsets above (size 4432); `dev_to_user_encodes_like_glibc` (`dev_to_user((8 << 20) | 1) == 2049`; `dev_to_user((259 << 20) | 0x12345) == 0x1231_0345`); `decode_exec_v2_carries_exe_identity` (exe_ino 0 → `None`; dev `(8<<20)|1`, ino 42 → `Some(ExeIdentity{dev:2049, ino:42})`); `decode_rejects_v1_records`; `resolve_exe_fallback_chain` in `exe.rs` (fixture `/proc` tree: identity match → link; identity mismatch + matching comm → link; `None` identity + matching comm → link; mismatching comm and identity → `None`; missing link → `None`). Symlink-based cases skip on hosts without symlink privilege, as in 11b-1.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Identity comparison uses `std::os::unix::fs::MetadataExt::{dev, ino}` on `/proc/<pid>/exe` behind `#[cfg(unix)]`; elsewhere step 1 is skipped. Bump `SCHEMA_VERSION` in `process.h` to 2 with matching `_Static_assert`s. The process sensor keeps compiling: `exec_to_raw` passes `e.exe` into `resolve_exe` and then falls back to the filename.
- [ ] **Step 4:** `cargo test --workspace` PASS; Linux-target clippy clean.
- [ ] **Step 5:** Commit `feat(11b-2): process record v2 with kernel exe identity and group exit`.

### Task 3: Exit `exe_path` cache in the process sensor

**Files:** Create `crates/osiris-sensors/process/src/exe_cache.rs`; modify `ebpf_backend.rs` (`exit_to_raw` no longer reads `/proc`) and `sensor.rs` (the reader callback owns the cache).

**Interfaces — Produces:**
```rust
pub const EXE_CACHE_CAPACITY: usize = 65_536;
pub struct ExeCache { .. }
impl ExeCache { pub fn new(capacity: usize) -> Self;
  pub fn insert(&mut self, tgid: u32, start_boottime_ns: u64, exe_path: String); // evicts oldest insert when full
  pub fn take(&mut self, tgid: u32, start_boottime_ns: u64) -> Option<String>; }
pub fn exit_to_raw(e: &ExitEvent, boot_wall_offset_ns: i128, exe_path: String) -> ProcessExitRaw;
```
- [ ] **Step 1: Failing tests:** `exit_cache_miss_and_eviction` (a miss → `None`; with capacity 2, inserting a, b, c → `take(a)` is `None` and `take(c)` is `Some`; `take` removes the entry); `exit_takes_exe_path_from_exec` (the `on_record` path: exec then exit for the same tgid/start → the exit raw's `exe_path` equals the exec's; an exit with a different start → `""`).
- [ ] **Step 2:** Run `cargo test -p osiris-sensors-process` → FAIL.
- [ ] **Step 3:** Implement with a `HashMap` plus an insertion-order `VecDeque`. Re-inserting a key updates the value without a duplicate queue entry, or with stale queue entries skipped on eviction.
- [ ] **Step 4:** PASS; workspace tests and Linux-target clippy clean.
- [ ] **Step 5:** Commit `feat(11b-2): exit exe_path from an exec-fed cache`.

### Task 4: Net BPF program and net record ABI

**Files:** Create `bpf/net.h`, `bpf/net.bpf.c`; modify `bpf/vmlinux_min.h` (sock_common/inet_sock/socket/file/fdtable/files_struct and the tracepoint context structs, with `preserve_access_index`), `tools/ebpf/build.sh` (build both objects and both sidecars), `crates/osiris-ebpf/src/record.rs` (or a sibling `net_record.rs`) and `lib.rs` (`NET_OBJECT`).

**Interfaces — Produces:**
```rust
pub const NET_SCHEMA_VERSION: u32 = 1;
pub const KIND_NET_CONNECT: u32 = 3; pub const KIND_NET_ACCEPT: u32 = 4; pub const KIND_NET_CLOSE: u32 = 5;
pub const AF_INET: u16 = 2; pub const AF_INET6: u16 = 10;
pub const DIR_OUTBOUND: u8 = 1; pub const DIR_INBOUND: u8 = 2;
// NetRecord (size 96): hdr@0 pid@8 uid@12 ktime_ns:u64@16 comm[16]@24 family:u16@40 lport:u16@42
// rport:u16@44 direction:u8@46 _pad:u8@47 laddr[16]@48 raddr[16]@64 exe_dev:u32@80 _pad2:u32@84 exe_ino:u64@88
// Ports in host byte order; IPv4 address in the first 4 bytes, rest zero.
pub enum NetKind { Connect, Accept, Close }
pub struct NetEvent { pub kind: NetKind, pub pid: u32, pub uid: u32, pub ktime_ns: u64, pub comm: String,
  pub family: u16, pub lport: u16, pub rport: u16, pub direction: u8, pub laddr: [u8; 16], pub raddr: [u8; 16],
  pub exe: Option<ExeIdentity> }
pub fn decode_net(bytes: &[u8]) -> Result<NetEvent, DecodeError>;
pub const NET_OBJECT: ObjectSpec; // "net.bpf.o", schema 1, tracepoints:
//   ("handle_state", "sock", "inet_sock_set_state"),
//   ("handle_accept4_exit", "syscalls", "sys_exit_accept4"),
//   ("handle_accept_exit", "syscalls", "sys_exit_accept")
```
C maps: `EVENTS` ringbuf `1 << 18`, `DROPS` per-CPU array[1], `SELF_TGID` array[1], `SOCKS` LRU_HASH u64 → owner {pid, uid, comm, direction, exe_dev, exe_ino} of 65 536 entries. State logic follows spec goal 2 exactly: track on `CLOSE→SYN_SENT` (process context; skip self tgid); emit CONNECT on `SYN_SENT→ESTABLISHED` for tracked sockets; drop the entry on `SYN_SENT→CLOSE`; never track or emit for the self tgid (connect or accept); emit CLOSE on any other `→CLOSE` of a tracked socket, then delete it. Accept: when ret ≥ 0 and `< fdt->max_fds`, `fd[ret]->private_data` → `struct socket` → `sk`; if TCP (`sk_protocol == IPPROTO_TCP`), emit ACCEPT and track. Owner and tuple are never taken from `current` in softirq paths.

- [ ] **Step 1: Failing tests:** `net_layout_is_pinned` (size 96 plus every offset above); `net_c_header_matches_rust_constants` (text of `bpf/net.h`: `SCHEMA_VERSION 1`, kinds, `_Static_assert` size 96); `decode_net_v4_and_v6` (a hand-built v4 connect and a v6 accept decode to the right fields); `net_decode_rejects_bad_family_short_and_unknown_kind` (family 7 → error; 95 bytes → error; kind 9 → error; process kinds 1/2 → error; a 10 000-iteration pseudo-random byte loop never panics); `net_object_spec_names` (`NET_OBJECT.object_file == "net.bpf.o"`, `expected_schema == 1`, the three tracepoint tuples above).
- [ ] **Step 2:** Run `cargo test -p osiris-ebpf` → FAIL.
- [ ] **Step 3:** Implement the Rust decode and the C program. The C cannot be compiled here; Task 7's GH run proves it. Note in the report every kernel field read and the reason it is CO-RE-safe on 5.15 and 6.x.
- [ ] **Step 4:** PASS; Linux-target clippy on `osiris-ebpf` clean; `bash -n tools/ebpf/build.sh` OK.
- [ ] **Step 5:** Commit `feat(11b-2): net BPF program and record ABI`.

### Task 5: Network sensor eBPF backend

**Files:** Create `crates/osiris-sensors/net/src/ebpf_backend.rs`; modify `crates/osiris-sensors/net/{Cargo.toml,src/lib.rs,src/sensor.rs}`; `crates/osiris-sensor-api/src/raw_event.rs` (update the `NetworkEventRaw` doc comments that say IPv4-only and that uid always comes from `/proc/net/tcp`); `tools/check-dep-graph.sh` if an allow-list needs the new edge.

**Interfaces — Consumes:** `LoadedObject`, `NET_OBJECT`, `spawn_reader`, `decode_net`, `NetEvent`, `resolve_exe`, `boot_wall_offset_ns`, `EbpfSettings` (Tasks 1, 2 and 4). **Produces:**
```rust
pub fn render_addr(family: u16, addr: &[u8; 16]) -> String; // v4 dotted; v6 via std::net::Ipv6Addr, mapped → v4
pub fn net_to_raw(e: &NetEvent, boot_wall_offset_ns: i128, proc_root: &Path) -> NetworkEventRaw;
impl NetworkSensor { pub fn new(proc_root: Option<PathBuf>, ebpf: Option<EbpfSettings>) -> Self; }
```
`net_to_raw`: `operation` comes from the kind; direction follows GC 7 (`DIR_*` from the record); `pid: Some(e.pid)`; `uid`/`comm` come from the record; `exe_path` is `resolve_exe(..).unwrap_or_default()`; `proto` is `"tcp"`; `source` is `Ebpf`; `timestamp_ns` is `(ktime_ns as i128 + offset)` clamped to ≥ 0, with the offset resampled per record as in the process sensor.

- [ ] **Step 1: Failing tests:** `render_addr_cases` (v4 `[127,0,0,1,0..]` → `"127.0.0.1"`; v6 `::1` → `"::1"`; `::ffff:1.2.3.4` → `"1.2.3.4"`; v6 `2001:db8::1` → `"2001:db8::1"`); `net_to_raw_maps_kinds_and_direction` (connect → Connect/Outbound, accept → Accept/Inbound, close with `DIR_INBOUND` → Close/Inbound; pid, uid, comm and ports copied; exe_path `""` with a fixture proc root lacking the pid); `ebpf_on_record_resamples_offset` (same shape as the process sensor's per-record offset test); `falls_back_to_procfs_when_net_object_missing` (sensor with proc_root fixture + `EbpfSettings` pointing at a dir holding only process objects → `Degraded`, flag `procfs_fallback`, `last_error` contains `net.bpf.o`, and a fixture `net/tcp` row still produces an event); `unsupported_without_proc_root_when_ebpf_fails` (`new(None, Some(bad))` → `initialize` returns `SensorError::Unsupported` and the message names `net.bpf.o`); `no_ebpf_key_behaves_as_before` (`new(Some(root), None)` → flag `always_available`, as today).
- [ ] **Step 2:** Run `cargo test -p osiris-sensors-net` → FAIL.
- [ ] **Step 3:** Implement, mirroring the process sensor's backend selection, `running_state`, drop counter → `events_dropped_total`, and reader supervision. Keep the poller untouched.
- [ ] **Step 4:** Workspace tests PASS; Linux-target clippy for `osiris-sensors-net` clean.
- [ ] **Step 5:** Commit `feat(11b-2): eBPF backend for the network sensor`.

### Task 6: Agent wiring

**Files:** Modify `crates/osiris-agent/src/agent.rs` (`build_sensor`).

- [ ] **Step 1: Failing tests:** `network_sensor_built_from_ebpf_only` (config with `ebpf` and no `network_proc_root` → `Some`, name `"network"`); `network_sensor_absent_without_either_key` (neither key → `None`); the existing test with only `network_proc_root` still builds the sensor.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Build `NetworkSensor::new(proc_root, ebpf)` when either key is present, passing the same `EbpfSettings { object_dir, self_tgid: std::process::id() }` as the process sensor.
- [ ] **Step 4:** PASS; clippy clean.
- [ ] **Step 5:** Commit `feat(11b-2): agent builds the network sensor with eBPF`.

### Task 7: Real-Linux validation

**Files:** Modify `crates/osiris-real-linux-tests/tests/real_linux.rs`, `.github/workflows/real-linux.yml` (build both objects; extend the eBPF status annotation to the network sensor; run `osiris-sensors-net` unit tests on Linux alongside the process/eBPF ones), and `tools/real-linux/annotate.sh` if needed.

- [ ] **Step 1: New `#[ignore]` tests:**
  - `network_sensor_uses_ebpf`: Healthy, flag `ebpf`, provider `network_sensor/ebpf` on stored network events.
  - `short_tcp_connection_is_observed_via_ebpf_v4` and `_v6`: the test listens on `127.0.0.1:0` / `[::1]:0`; a thread accepts one connection and immediately drops it; the child is `bash -c 'exec 3<>/dev/tcp/<host>/<port>; : <marker>'`. Assert, within bounded waits:
    - a `NETWORK_CONNECT` and a `NETWORK_CLOSE` with the child's pid (from the spawned `Child::id()`), comm `bash`, direction `OUTBOUND`, and `dst_port` = the listener port;
    - a `NETWORK_ACCEPT` and a `NETWORK_CLOSE` with the test's pid, direction `INBOUND`;
    - for v6, the address `::1`.
  - `group_exit_reports_once_with_code`: `python3 -c` whose worker thread calls `os._exit(7)` while the main thread sleeps → exactly one `PROCESS_EXIT` for that pid, with `exit_code` 7 and a non-empty `exe_path`.
  - Extend `corrupted_object_falls_back_to_audit` (or add `corrupted_net_object_falls_back_to_procfs`): corrupt `net.bpf.o` only → network `Degraded` + `procfs_fallback`, process eBPF still `Healthy`.
  - Existing tests: adjust any network assertion that depends on procfs-only behaviour, such as the provider or the direction-by-port heuristic, and list each adjustment in the report.
- [ ] **Step 2:** `cargo check --tests --target x86_64-unknown-linux-gnu -p osiris-real-linux-tests` clean.
- [ ] **Step 3:** Push to `real-linux/t11b2-1`; poll the run; fix and push `-2`, `-3`… until green on ubuntu-22.04 and 24.04. Record each run id and its outcome in the report.
- [ ] **Step 4:** Commit `test(11b-2): real-Linux eBPF network and group-exit scenarios` (amend nothing; fix-up commits are fine).

### Task 8: Docs

**Files:** `ARCHITECTURE.md` (§4 Network row status note; §5 mention of the per-sensor objects), `docs/operators-ebpf.md` (the net object, hooks, fallback, spec §5 known behaviour, both objects in `object_dir`), `docs/VALIDATION.md` (11b-2 section with the GH run id), `docs/ROADMAP-REMAINING.md` (11b-2 done; remove the two 11b-1 debts it fixed: the non-leader `execve`/`pthread_exit` exits and the late `/proc` exe read; add the new debts: UDP, failed connects, io_uring accepts, pre-existing connections, LRU-evicted closes, identity mismatch on btrfs/overlay), `docs/adr/ADR-010-ebpf-loader-aya.md` (one paragraph: one object per sensor, layouts still hand-mirrored).

- [ ] **Step 1:** Write the docs. **Step 2:** Run all GC 13 gates and get green results. **Step 3:** Commit `docs(11b-2): eBPF network backend validated`.
