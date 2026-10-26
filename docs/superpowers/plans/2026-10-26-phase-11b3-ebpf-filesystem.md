# Phase 11b-3 eBPF Filesystem Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `filesystem` sensor an eBPF backend that reports successful create, write, delete and rename operations under watched directories. Keep the audit tailer as the fallback. Settle the `process_exec` eBPF health debt with real-Linux evidence.

**Architecture:**
- A new `fs.bpf.o` stages one operation per thread at the LSM path kprobes (`security_path_*`, `security_file_open`, truncate hooks). The hook builds the absolute path with a bounded dentry/mount walk and filters it against an in-kernel `WATCH` map of `(dev, ino)` keys.
- Per-syscall `sys_enter_*` tracepoints clear the staged operation. Per-syscall `sys_exit_*` tracepoints emit it into a 4 MiB ring buffer when `ret >= 0`.
- The engine loader learns kprobes, optional attach points and watch-map population.
- The fs sensor gains the same eBPF/fallback selection as the process sensor.

**Tech Stack:**
- Rust 1.99 workspace, using `aya` at the pinned version (Linux-only).
- clang + libbpf-dev, on GH Actions only.
- The GH Actions real-Linux workflow.

**Spec:** `docs/superpowers/specs/2026-10-26-phase-11b3-ebpf-filesystem-design.md`. It builds on the 11b-2 spec `docs/superpowers/specs/2026-10-22-phase-11b2-ebpf-network-design.md`.

## Global Constraints

1. No new third-party crate. `aya` stays pinned. If a bump is unavoidable, record it in the task report and in ADR-010.
2. Cargo never builds BPF C, and no `.bpf.o` is committed. `cargo build` and `cargo test --workspace` on Windows need no clang, root, BTF or loaded program.
3. Objects: `process.bpf.o` (schema 2), `net.bpf.o` (schema 1) and the new `fs.bpf.o` (schema **1**), each with a `<file>.sha256` sidecar, all in `ebpf.object_dir`. The process and net objects' load behaviour and record ABIs do not change.
4. Kinds: `EXEC = 1`, `EXIT = 2`, `NET_CONNECT = 3`, `NET_ACCEPT = 4`, `NET_CLOSE = 5`, `FS_CREATE = 6`, `FS_WRITE = 7`, `FS_DELETE = 8`, `FS_RENAME = 9`.
5. fs maps:
   - `EVENTS`: ringbuf **4 MiB** (`1 << 22`).
   - `DROPS`: per-CPU array[1].
   - `SELF_TGID`: array[1].
   - `PENDING`: `BPF_MAP_TYPE_HASH` with `BPF_F_NO_PREALLOC`, key u64 `pid_tgid`, **10 240** entries. A failed insert counts in `DROPS`.
   - `WATCH`: hash of **64** entries, key `{u32 dev; u32 _pad; u64 ino}`, value u8.
   - `WATCH_FLAGS`: array[1] of u32; bit 0 means "an inode-only key exists".
   - `PATH_CAP` = **1024** bytes per path; the ancestor walk is limited to **32** components.
6. fs is **x86_64-only**. On other arches the probe reason is exactly `fs eBPF object is x86_64-only`, and the sensor falls back.
7. Only successful operations are emitted. `sys_enter_*` clears the thread's `PENDING` entry, and the first hook in a syscall wins. `security_file_open` may fill the inode fields of a staged CREATE. `sys_exit_*` emits when `ret >= 0` and always deletes. `sched/sched_process_exit` deletes the exiting thread's entry.
8. Covered syscalls, each with an enter and an exit program: `open openat openat2 creat truncate ftruncate mknod mknodat mkdir mkdirat unlink unlinkat rmdir rename renameat renameat2`.
9. Required kprobes: `security_path_mknod`, `security_path_mkdir`, `security_path_unlink`, `security_path_rmdir`, `security_path_rename`, `security_file_open`, `security_path_truncate`. Optional kprobe: `security_file_truncate`. All syscall tracepoints are required except `open creat mknod mkdir unlink rmdir rename` and `openat2`, which are optional.
10. Provider `filesystem_sensor/ebpf` is already mapped in `normalize.rs`. The raw source is `RawEventSource::Ebpf` and `audit_serial` is `None`.
11. A truncated path is rendered as `…/` followed by the bytes kept, and is never absolute.
12. fs health:
    - eBPF working: `Healthy`, flag `ebpf`.
    - eBPF configured but unusable, with an audit log present: `Degraded`, flag `audit_fallback`, and `last_error` naming the reason (it must contain `fs.bpf.o` when the object is the problem).
    - Neither backend usable: `SensorError::Unsupported` with every reason.
    - No `ebpf` key: exactly today's behaviour.
13. Default `fs_watch_paths` when the key is empty: `/etc /usr/bin /usr/sbin /usr/local/bin /usr/lib/systemd /var/spool/cron /var/www /root /tmp /var/tmp /dev/shm`. A path that is missing or is not a directory is skipped and named in `last_error`, and the sensor stays `Healthy`. If no path resolves, eBPF is unusable.
14. Watch keys:
    - Kernel `dev_t` = `MAJOR << 20 | MINOR`, derived from `st_dev`.
    - On btrfs (`f_type 0x9123683E`) or overlayfs (`0x794C7630`), insert `(0, ino)` and set `WATCH_FLAGS` bit 0.
15. Real-Linux tests:
    - Mark them `#[ignore]` and `#[cfg(target_os = "linux")]`. They run serially, as root, with bounded waits and unique markers.
    - Push to `real-linux/t11b3-<n>`. Poll `https://api.github.com/repos/excanear/OSIRIS---Operational-System-Intelligence-Response-Investigation-System/actions/runs`.
    - This host's clock is about 3 h ahead of GitHub. Judge run age by GitHub timestamps.
    - No `gh` CLI is available; use curl.
16. Cross-check Linux-only code on Windows with `cargo check` and `cargo clippy --target x86_64-unknown-linux-gnu -- -D warnings` for every touched crate.
17. Gates before merge:
    - `cargo fmt --all -- --check`
    - `cargo clippy --workspace --all-targets -- -D warnings`
    - `cargo test --workspace`, after rebuilding `osiris-cli`/`osiris-server`/`osiris-agent`
    - `bash tools/check-dep-graph.sh`
    - console `npm run lint && npm test && npm run build`
18. Untrusted ring-buffer bytes never panic and are bounded. No `unwrap`/`expect` outside tests. Recover poisoned locks. Reader threads use `blocking_send`.

## Review Focus

1. **An fs record with `path_len > PATH_CAP`, an unknown kind, or a short buffer** → `DecodeError`, counted as dropped, no panic. Owner: Task 2, test `fs_decode_rejects_bad_lengths_and_kinds`.
2. **A truncated path, invalid UTF-8 in a path, or a RENAME with an empty old path** → `…/tail`, lossy text, and `previous_path: Some("")` respectively. None of these is ever rendered as an absolute path when truncated. Owner: Task 4, test `fs_to_raw_truncation_and_lossy_paths`.
3. **A watch list mixing a missing path, a regular file and one good dir** → the good dir is inserted, the other two are named in `last_error`, and the sensor stays `Healthy`. With all three bad, the sensor falls back. Owner: Task 4, test `watch_resolution_skips_bad_paths`.
4. **`ebpf` configured with `process.bpf.o`/`net.bpf.o` valid but `fs.bpf.o` missing** → filesystem `Degraded`/`audit_fallback`, while the other sensors are unaffected. Owner: Task 4, test `falls_back_to_audit_when_fs_object_missing`, and Task 6 test (h).
5. **An optional attach point whose symbol or tracepoint does not exist** → it is skipped and listed. A missing *required* one fails the load with a reason naming it. Owner: Task 1, test `optional_attach_points_are_skipped_required_fail`.

---

### Task 1: Engine: attach-point specs, kprobes, symbol probe, watch map

**Files:**
- Modify `crates/osiris-ebpf/src/{loader.rs,probe.rs,exe.rs,lib.rs}`.
- Modify `crates/osiris-sensors/process/src/sensor.rs` and `crates/osiris-sensors/net/src/sensor.rs`, only where they name `ObjectSpec.tracepoints`.

**Interfaces — Produces:**
```rust
pub enum AttachKind { TracePoint { category: &'static str, name: &'static str }, KProbe { symbol: &'static str } }
pub struct AttachPoint { pub program: &'static str, pub kind: AttachKind, pub required: bool }
pub struct ObjectSpec { pub object_file: &'static str, pub expected_schema: u32, pub attach: &'static [AttachPoint] }
// PROCESS_OBJECT / NET_OBJECT: same programs as today, all required: true.
impl LoadedObject {
  pub fn skipped_attach_points(&self) -> &[String];            // "<program>: <target>: <reason>" per optional skip
  pub fn insert_watch(&mut self, dev: u32, ino: u64) -> Result<(), LoadError>;  // WATCH; Err if the object has no WATCH map
  pub fn set_watch_flags(&mut self, flags: u32) -> Result<(), LoadError>;      // WATCH_FLAGS[0]
}
pub fn dev_from_user(st_dev: u64) -> u32;          // inverse of dev_to_user (exe.rs)
pub fn missing_kernel_symbols(available: &str, wanted: &[&str]) -> Vec<String>; // probe.rs; `available` = text of available_filter_functions or /proc/kallsyms (both formats)
pub fn kernel_symbols_text() -> Option<String>;    // Linux: /sys/kernel/tracing/available_filter_functions, else /sys/kernel/debug/tracing/..., else /proc/kallsyms; None off Linux
```
Keep the `WATCH`/`WATCH_FLAGS` maps in `Inner` as `Option` (taken with `ebpf.take_map` only if present), so the process and net objects keep loading unchanged. Each optional attach failure, whether the program or target is missing or the attach is rejected, is collected into `skipped_attach_points`. A required attach failure returns `LoadError::Attach` naming the program and target.

- [ ] **Step 1: Failing tests.**
  - `object_specs_keep_their_programs`: `PROCESS_OBJECT`/`NET_OBJECT` contain exactly today's program/tracepoint triples, all `required`.
  - `dev_from_user_round_trips`: for `(8,1)`, `(259,3)`, `(0,47)` and `(4095,1048575)`, `dev_from_user(dev_to_user(k)) == k`.
  - `missing_kernel_symbols_parses_both_formats`:
    - `"security_path_mknod\nsecurity_file_open [kernel]\n"` against the wanted list `["security_path_mknod","security_file_open","security_path_rename"]` → `["security_path_rename"]`.
    - The kallsyms line `"ffffffff81234560 T security_path_mknod\n"` matches `security_path_mknod`.
    - A `security_path_mknod.cold` entry does not count.
  - `optional_attach_points_are_skipped_required_fail`: a pure helper `plan_attach(points, exists: impl Fn(&AttachPoint) -> bool) -> Result<Vec<&AttachPoint>, String>`, tested off Linux. A missing optional point is skipped and reported; a missing required one returns `Err` containing the program name.
- [ ] **Step 2:** `cargo test -p osiris-ebpf` → FAIL.
- [ ] **Step 3:** Implement. Use the aya `KProbe` program type for `AttachKind::KProbe` (attach offset 0). Check tracepoint existence via `/sys/kernel/tracing/events/<category>/<name>` before attaching an optional one.
- [ ] **Step 4:** `cargo test --workspace` passes. Linux-target clippy on `osiris-ebpf`, `osiris-sensors-process` and `osiris-sensors-net` is clean.
- [ ] **Step 5:** Commit `feat(11b-3): engine kprobes, optional attach points, watch map`.

### Task 2: fs record ABI and `FS_OBJECT`

**Files:**
- Create `bpf/fs.h` and `crates/osiris-ebpf/src/fs_record.rs`.
- Modify `crates/osiris-ebpf/src/{lib.rs,loader.rs,record.rs}`. `DecodeError` gains `PathTooLong { field: &'static str, len: u16 }`.
- Modify `crates/osiris-ebpf/tests/c_header.rs`.

**Interfaces — Produces:**
```rust
pub const FS_SCHEMA_VERSION: u32 = 1;
pub const KIND_FS_CREATE: u32 = 6; pub const KIND_FS_WRITE: u32 = 7; pub const KIND_FS_DELETE: u32 = 8; pub const KIND_FS_RENAME: u32 = 9;
pub const PATH_CAP: usize = 1024;
// FsRecord (size 2144): hdr@0 pid@8 ppid@12 uid@16 ret:i32@20 ktime_ns:u64@24 comm[16]@32
// exe_dev:u32@48 dev:u32@52 exe_ino:u64@56 ino:u64@64 mode:u32@72 owner_uid:u32@76 owner_gid:u32@80
// has_inode:u8@84 path_truncated:u8@85 old_path_truncated:u8@86 _pad:u8@87 path_len:u16@88 old_path_len:u16@90
// _pad2:u32@92 path[1024]@96 old_path[1024]@1120 ; end 2144 (8-aligned, no tail padding)
pub enum FsKind { Create, Write, Delete, Rename }
pub struct FsEvent { pub kind: FsKind, pub pid: u32, pub ppid: u32, pub uid: u32, pub ret: i32, pub ktime_ns: u64,
  pub comm: String, pub exe: Option<ExeIdentity>, pub inode: Option<FsInode>,
  pub path: Vec<u8>, pub path_truncated: bool, pub old_path: Option<Vec<u8>>, pub old_path_truncated: bool }
pub struct FsInode { pub dev: u32, pub ino: u64, pub mode: u32, pub owner_uid: u32, pub owner_gid: u32 }
pub fn decode_fs(bytes: &[u8]) -> Result<FsEvent, DecodeError>;
pub const FS_OBJECT: ObjectSpec; // "fs.bpf.o", schema 1, attach points per GC 8/9:
//   kprobes  kp_path_mknod, kp_path_mkdir, kp_path_unlink, kp_path_rmdir, kp_path_rename, kp_file_open, kp_path_truncate, kp_file_truncate(optional)
//   tracepoints  tp_enter_<sc> / tp_exit_<sc> on syscalls/sys_{enter,exit}_<sc> for each GC 8 syscall; tp_task_exit on sched/sched_process_exit
```
`old_path` is `Some` only for `Rename`. A zero `ino`, or `has_inode == 0`, gives `inode: None`. `exe` follows the net rule (a zero identity gives `None`).

- [ ] **Step 1: Failing tests.**
  - `fs_layout_is_pinned`: the size plus every offset above.
  - `fs_c_header_matches_rust_constants`: the text of `bpf/fs.h` contains `SCHEMA_VERSION 1`, the four kinds, `PATH_CAP 1024`, and `_Static_assert(sizeof(struct fs_record) == <size>`.
  - `decode_fs_rename_and_create`: a hand-built RENAME yields both paths. A CREATE with `has_inode 0` yields `inode: None` and `old_path: None`.
  - `fs_decode_rejects_bad_lengths_and_kinds`:
    - `path_len 1025` → `PathTooLong`.
    - A record one byte short → `Truncated`.
    - Kind 5 → `UnknownKind`.
    - Schema 2 → `UnsupportedVersion`.
    - A 10 000-iteration pseudo-random byte loop never panics.
  - `fs_object_spec_names`: file name, schema, and every program in GC 8/9, with the required flags exactly as in GC 9.
- [ ] **Step 2:** `cargo test -p osiris-ebpf` → FAIL.
- [ ] **Step 3:** Implement `fs_record.rs` and `bpf/fs.h`, with `_Static_assert` for the size and every offset.
- [ ] **Step 4:** PASS. Linux-target clippy is clean.
- [ ] **Step 5:** Commit `feat(11b-3): fs record ABI and object spec`.

### Task 3: fs BPF program, build, and a first real-Linux load

**Files:**
- Create `bpf/fs.bpf.c` and `crates/osiris-ebpf/tests/load_fs.rs`.
- Modify `bpf/vmlinux_min.h`: add `path`, `vfsmount`, `mount`, `dentry`, `qstr`, `inode`, `super_block`, `file` (`f_mode`, `f_inode`, `f_path`), `fs_struct` and `task_struct` fields (`fs`, `real_parent`, `group_leader`, `mm`, `cred`), plus `pt_regs`. Use `preserve_access_index` throughout.
- Modify `tools/ebpf/build.sh`: loop over `process net fs`.
- Modify `.github/workflows/real-linux.yml`: add `-p osiris-sensors-fs` to the line-100 unit-test step once Task 4 exists; for now add `-p osiris-ebpf --test load_fs`.

**Interfaces — Consumes:** `FS_OBJECT` and the record layout (Task 2); `LoadedObject::{load, insert_watch, set_watch_flags, skipped_attach_points}` (Task 1).

Program behaviour is GC 5–9 plus spec §2.1 items 3–5, exactly:
- Kprobe bodies use `BPF_KPROBE`.
- `security_file_open` returns before any map access unless `f_mode & FMODE_WRITE` (0x2) is set and `S_ISREG(i_mode)` holds.
- Non-regular `mknod` modes are ignored.
- The self tgid is never staged.
- The ancestor walk checks `WATCH` at each dentry, including mount roots, and crosses mounts via `container_of(vfsmount, struct mount, mnt)->mnt_parent` / `mnt_mountpoint`. It stops at `current->fs->root`.
- RENAME matches if the source *or* the destination parent is watched.
- Emission copies the `PENDING` value into a ringbuf reservation of constant size, sets `ret` and `ktime_ns`, then submits.

`tests/load_fs.rs::fs_object_loads_and_attaches`:
- `#[ignore]`, Linux-only, and requires root and `$OSIRIS_BPF_DIR`.
- Loads `FS_OBJECT`, inserts a watch on a fresh temp dir, and starts `spawn_reader`.
- Creates `<dir>/probe.txt` with `std::fs::File::create`.
- Asserts that within 5 s one `FsKind::Create` with path `<dir>/probe.txt` and this test's pid is decoded.
- Prints `skipped_attach_points()`.

- [ ] **Step 1:** Write `load_fs.rs`. Check it with `cargo check --tests --target x86_64-unknown-linux-gnu -p osiris-ebpf`.
- [ ] **Step 2:** Write `fs.bpf.c`, the header additions and `build.sh`. `bash -n tools/ebpf/build.sh` must pass.
- [ ] **Step 3:** Commit `feat(11b-3): fs BPF program`. Push to `real-linux/t11b3-1` and poll.
  - Expected: setup builds `fs.bpf.o`, and `fs_object_loads_and_attaches` passes on ubuntu-22.04 and 24.04.
  - On a verifier rejection, fix and push `-2`, `-3`, and so on. If `PATH_CAP` 1024 cannot pass, shrink it and change Task 2's constants and tests in the same commit. Record the value and the reason for ADR-010 in the report.
  - Record each run id and its outcome in the report.
- [ ] **Step 4:** Report every kernel field read and why it is CO-RE-safe on 5.15 and 6.x.

### Task 4: Filesystem sensor eBPF backend

**Files:**
- Create `crates/osiris-sensors/fs/src/{ebpf_backend.rs,watch.rs}`.
- Modify `crates/osiris-sensors/fs/{Cargo.toml (add osiris-ebpf),src/lib.rs,src/sensor.rs}`.
- Modify `crates/osiris-sensor-api/src/raw_event.rs`: the `FileEventRaw` docs gain the eBPF path semantics (truncation marker, no audit serial, real dirfd resolution).
- Modify `tools/check-dep-graph.sh` if needed.

**Interfaces — Consumes:** Tasks 1–3. **Produces:**
```rust
pub fn fs_to_raw(e: &FsEvent, boot_wall_offset_ns: i128, proc_root: &Path) -> FileEventRaw;
pub struct WatchKey { pub dev: u32, pub ino: u64 }          // dev 0 = inode-only
pub struct WatchResolution { pub keys: Vec<WatchKey>, pub inode_only: bool, pub skipped: Vec<String> }
pub fn resolve_watch_paths(paths: &[PathBuf]) -> WatchResolution; // stat (follow symlinks) + statfs on Linux; off Linux every path is skipped with "watch paths need Linux"
pub fn watch_key(st_dev: u64, ino: u64, fs_magic: i64) -> WatchKey;   // pure: GC 14
pub const DEFAULT_WATCH_PATHS: &[&str];                    // GC 13, in that order
impl FilesystemSensor {
  pub fn new(audit_log_path: Option<PathBuf>, ebpf: Option<EbpfSettings>, watch_paths: Vec<PathBuf>) -> Self;
}
```
`fs_to_raw` behaviour:
- `operation` comes from the kind.
- `path` is the lossy UTF-8 of `path`, with the `…/` prefix when truncated.
- `previous_path` is `Some(old)` for Rename only.
- `inode`/`device_id`/`mode`/`owner_*` are `None` without an inode. Otherwise `device_id = osiris_schema::encode_device_id(major, minor)`, where `major = dev >> 20` and `minor = dev & 0xfffff`.
- `exe_path` is `resolve_exe(..).unwrap_or_default()`.
- `timestamp_ns` is `ktime + offset`, clamped to ≥ 0, with the offset resampled per record.
- `audit_serial: None`, `source: Ebpf`.

Backend selection mirrors `ProcessExecSensor` (`running_state`, `fallback_reason`, the drop counter added to `events_dropped_total`, reader supervision). Watch-resolution skips go into `last_error` while the sensor stays Healthy (GC 13). The existing audit tests keep passing through `new(Some(path), None, vec![])`.

- [ ] **Step 1: Failing tests.**
  - `fs_to_raw_maps_kinds`: each kind maps to its `FileOperation`. Pid, ppid, uid and comm are copied. `exe_path` is `""` under a fixture proc root. `source` is `Ebpf`. The timestamp is `ktime + offset`. The `device_id` for dev `(8 << 20) | 1` equals `encode_device_id(8, 1)`.
  - `fs_to_raw_truncation_and_lossy_paths`: truncated `b"a/b"` → `"…/a/b"`; `b"/x/\xff"` → `"/x/\u{FFFD}"`; a Rename with an empty old path → `previous_path == Some("")`.
  - `watch_key_rules`: ext4 magic `0xEF53` with `st_dev` `makedev(8,1)` → `(8 << 20 | 1, ino)`. The btrfs and overlay magics → `(0, ino)`.
  - `watch_resolution_skips_bad_paths` (Linux-only, with tempfiles): a missing path, a regular file and a good dir → 1 key and 2 skips, each naming its path.
  - `falls_back_to_audit_when_fs_object_missing`: `EbpfSettings` pointing at an empty dir plus an audit log fixture → `Degraded`, flag `audit_fallback`, `last_error` contains `fs.bpf.o`, and an appended audit group still yields an event.
  - `unsupported_without_audit_when_ebpf_fails`: `initialize` → `SensorError::Unsupported`, and the message names `fs.bpf.o`.
  - `no_ebpf_key_behaves_as_before`: `new(Some(log), None, vec![])` → `Healthy`, flag `audit_fallback`, no `ebpf`.
  - `ebpf_on_record_counts_and_resamples`: the same shape as the net sensor's per-record offset and closed-channel tests.
- [ ] **Step 2:** `cargo test -p osiris-sensors-fs` → FAIL.
- [ ] **Step 3:** Implement. `load_ebpf` collects every reason before loading: the object problem, `probe().reasons`, the GC 6 arch check, and `missing_kernel_symbols(kernel_symbols_text(), <GC 9 required kprobes>)`, rendered as `required kernel symbol missing: <name>`. If none is found, it loads `FS_OBJECT`. Then, before `spawn_reader`, insert the watch keys (zero resolved keys counts as unusable, as in GC 13), and set `WATCH_FLAGS` bit 0 when `inode_only` is true. On a non-x86_64 Linux target, the load reason is GC 6's string.
- [ ] **Step 4:** Workspace tests PASS. Linux-target clippy for `osiris-sensors-fs` is clean. Add `-p osiris-sensors-fs` to the workflow's line-100 unit-test step.
- [ ] **Step 5:** Commit `feat(11b-3): eBPF backend for the filesystem sensor`.

### Task 5: Agent config and wiring

**Files:**
- Modify `crates/osiris-agent/src/{config.rs,agent.rs}`.
- Update every exhaustive `AgentConfig` literal: `crates/osiris-e2e-tests/tests/end_to_end.rs`, `base_config()`, and any other place `cargo build --workspace --tests` finds.

**Interfaces — Produces:** `AgentConfig.fs_watch_paths: Vec<String>` (serde default empty). `build_sensor("filesystem")` returns `Some` when `fs_audit_log_path` or `ebpf` is set, passing `watch_paths` = the config list, or `DEFAULT_WATCH_PATHS` when it is empty.

- [ ] **Step 1: Failing tests.**
  - `filesystem_sensor_built_from_ebpf_only`: `ebpf` set and no `fs_audit_log_path` → `Some`, with name `"filesystem"`.
  - `filesystem_sensor_absent_without_either_key`.
  - `fs_watch_paths_parse_and_default`: YAML with `fs_watch_paths: ['/srv']` → `["/srv"]`; the key absent → empty.
  - The existing audit-only test still builds the sensor.
- [ ] **Step 2:** Run the tests → FAIL. **Step 3:** Implement. **Step 4:** Workspace tests PASS; clippy is clean.
- [ ] **Step 5:** Commit `feat(11b-3): agent builds the filesystem sensor with eBPF`.

### Task 6: Real-Linux validation and the `process_exec` health debt

**Files:**
- Modify `crates/osiris-real-linux-tests/src/render.rs`: `AgentYaml.fs_watch_paths: Vec<PathBuf>`, rendered as `fs_watch_paths:`. Update the render test.
- Modify `crates/osiris-real-linux-tests/tests/real_linux.rs`. Every `stack*` renders `fs_watch_paths` = `/tmp/osiris-p10`, `/var/www`, `/etc/systemd/system` plus the test's own dirs; create these before start.
- Modify `.github/workflows/real-linux.yml` and `tools/real-linux/annotate.sh`: extend the eBPF status annotation to `filesystem`.

- [ ] **Step 1: Make existing tests backend-neutral.** In `file_lifecycle_is_observed` and `web_root_drop_raises_an_alert`, drop any assertion on `audit_serial` or on the audit provider. List each change in the report.
- [ ] **Step 2: Add the new `#[ignore]` tests** (spec §2.7, item 14). Each scenario's actor is one `python3 -c` child; take its pid from `Child::id()` and its exe from `realpath $(command -v python3)`.
  - `filesystem_sensor_uses_ebpf` (a).
  - `fs_lifecycle_is_observed_via_ebpf` (b): `/tmp/osiris-p10/fs-ebpf-<marker>` sees CREATE, then WRITE (`O_WRONLY|O_APPEND` on a pre-created file), then RENAME, then DELETE. Each produces exactly one event, with source `EBPF`, the child's pid, the python exe, the exact paths and a non-null inode.
  - `fs_mkdir_rmdir_via_ebpf` (c).
  - `fs_unwatched_dir_is_silent` (d): ops in `/var/tmp/osiris-unwatched-<marker>`, then a watched marker create. After the marker is stored, there must be zero events whose path starts with the unwatched dir.
  - `fs_failed_ops_after_hook_are_silent` (e): `rmdir` of a non-empty watched dir, and `unlink` of a `chattr +i` file (cleanup runs `chattr -i`). A marker create bounds the wait. There must be zero DELETE events for those two paths.
  - `fs_dirfd_relative_open_reports_true_path` (f): `os.open("rel.txt", O_CREAT|O_WRONLY, dir_fd=<watched subdir>)` with the CWD elsewhere gives path `<watched subdir>/rel.txt`.
  - `fs_tmpfs_mount_crossing` (g): `/dev/shm/osiris-<marker>` is in the watch list, and the event path starts with that prefix.
  - `fs_missing_object_falls_back_to_audit` (h): use the broken-copy pattern with every object except `fs.bpf.o` → `Degraded`, flag `audit_fallback`, and a python write under `/tmp/osiris-p10` arrives with source `AUDIT`.
  - `sensor_health_counts_events` (i): after (b)'s events and after an exec observed via eBPF are stored, `/status` shows `events_emitted_total > 0` and a non-null `last_event_at` for both `process_exec` and `filesystem`.
- [ ] **Step 3:** `cargo check --tests --target x86_64-unknown-linux-gnu -p osiris-real-linux-tests` is clean.
- [ ] **Step 4:** Push to `real-linux/t11b3-<n>` and poll. Fix and re-push until all tests are green on both runners.
  - If (i) fails for `process_exec`, stop feature work and use superpowers:systematic-debugging. Fix the root cause with a unit test that reproduces it.
  - Record each run id, outcome and runner kernel.
- [ ] **Step 5:** Commit `test(11b-3): real-Linux eBPF filesystem scenarios`. Fix-up commits are fine.

### Task 7: Benchmark and docs

**Files:**
- `osiris-bench`, or `.github/workflows/real-linux-bench.yml` plus its script, whichever already hosts agent benches: a create/write/delete loop, 10 000 iterations, in a watched dir and in an unwatched dir, with and without the agent running.
- `PERFORMANCE.md`.
- `docs/operators-ebpf.md`: the fs section, the watch list and default, `CONFIG_SECURITY_PATH`, x86_64-only, the fallback, the same-host server data-dir warning, the upgrade note that `ebpf:` now enables the fs sensor, and spec §5 verbatim in substance.
- `docs/adr/ADR-010-ebpf-loader-aya.md`: kprobes, optional attach points, the layout re-evaluation (hand-mirrored layouts kept, with the reason), and the final `PATH_CAP`.
- `docs/VALIDATION.md`: the 11b-3 section with run ids and kernels; note that the optional-attach path is not exercised on the runners; the outcome of the health debt; and the fix to the parked `VALIDATION.md:215` line, which says 22.04 reported 5.15 although the runner kernel is 6.8.
- `docs/ROADMAP-REMAINING.md`: 11b-3 done, the health-debt outcome, the layout debt resolved as kept, and the new debts (io_uring and compat file ops, no link/symlink/chmod/chown, no watch re-resolution, container mount namespaces, inode-only matching on btrfs/overlay, x86_64-only fs object, `PENDING` overflow).
- `ARCHITECTURE.md` §4.3 Filesystem row: a status note.

- [ ] **Step 1:** Run the bench on GH and record the numbers. If the unwatched-dir overhead is above 10 %, add a warning to `PERFORMANCE.md`.
- [ ] **Step 2:** Write the docs.
- [ ] **Step 3:** All GC 17 gates are green.
- [ ] **Step 4:** Commit `docs(11b-3): eBPF filesystem backend validated`.
