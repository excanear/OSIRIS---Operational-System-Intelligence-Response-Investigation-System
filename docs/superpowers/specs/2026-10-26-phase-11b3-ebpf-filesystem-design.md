# Phase 11b-3: eBPF filesystem backend (create/write/delete/rename)

Status: design, 2026-10-26. This is the third sub-project of Phase 11b. The order is: 11b-1 engine
plus process exec/exit (done, @ 06bfbc6); 11b-2 network plus process schema v2 (done, @ 88ee9bc);
**11b-3 filesystem**, which is this document; 11b-4 DNS uprobe; then 11c ClickHouse. The user's
standing instruction is to proceed with the recommended option for every choice. Every decision
below that `ARCHITECTURE.md`, the 11b-1/11b-2 designs
(`docs/superpowers/specs/2026-10-18-phase-11b1-ebpf-process-design.md`,
`docs/superpowers/specs/2026-10-22-phase-11b2-ebpf-network-design.md`) or the existing code does
not already dictate is the designer's call, and is marked *(call)*.

## 1. Intent

The Filesystem sensor (`crates/osiris-sensors/fs`, sensor name `filesystem`) has only one backend
today: it tails an auditd log. That backend has three problems:

- It sees nothing unless an operator has installed matching `-a always,exit ... dir=` audit rules.
  The sensor cannot install them. On WSL and in many containers auditd cannot run at all.
- It resolves a relative `name=` from an `*at()` syscall with a real dirfd against the process CWD.
  That can produce a path that is absolute but wrong (documented on `FileEventRaw::path`).
- It shares the audit log, and its parse cost, with every other audit-based sensor.

ARCHITECTURE §4.3 (row "Filesystem") names eBPF as the primary backend, with audit as the
fallback. 11b-3 adds that eBPF backend on the 11b-1 engine and keeps the audit tailer as the
fallback, in the same shape as the process and network sensors.

11b-3 also takes on two debts that `docs/ROADMAP-REMAINING.md` lists:

- **Health reporting of `process_exec` under eBPF.** `/status` reportedly shows
  `events_emitted_total: 0` and `last_event_at: null`. Reading the code
  (`crates/osiris-sensors/process/src/sensor.rs`, `on_record`) suggests the counters are updated
  correctly. The observation may come from the real-Linux test reading `/status` right after start
  (`process_sensor_uses_ebpf`), before any exec happened. 11b-3 settles this with evidence (§2.5)
  and does not assume a fix.
- **Hand-mirrored record layouts.** These are to be re-evaluated now that there are three of them
  (§2.6).

Success means the following on the GitHub real-Linux runners (ubuntu-22.04 and ubuntu-24.04), with
the objects present:

- The filesystem sensor is `Healthy` with capability flag `ebpf`, with no audit rules installed.
- A shell writing in a watched directory produces stored `FILE_CREATE`, `FILE_WRITE`, `FILE_RENAME`
  and `FILE_DELETE` events. Each one has the right absolute path, the right inode/device, the right
  pid and the right kernel-verified `exe_path`, and has `source = EBPF`.
- The same operations in an unwatched directory produce nothing.
- The agent's own writes produce nothing.

With the object absent or the kernel unsupported, the sensor falls back to the audit tailer and
reports `Degraded` with the reason, exactly as the process sensor does.

## 2. Goals

### 2.1 Filesystem BPF program

1. **New BPF program `fs`** in `bpf/fs.bpf.c` plus `bpf/fs.h`. `tools/ebpf/build.sh` builds it into
   its own `fs.bpf.o` + `fs.bpf.o.sha256`. It is one object per sensor, as in 11b-2. It uses the
   same toolchain, the same integrity sidecar, the same `schema_version` `.rodata` global (its own
   schema, starting at 1), the same `SELF_TGID` exclusion, the same `DROPS` per-CPU counter and the
   same fixed-size record reservations.

2. **Hooks.** These are kprobes on the LSM path hooks, which ARCHITECTURE §4.3 names. BPF-LSM
   programs themselves are rejected (§3).
   *(call: kprobes rather than `BPF_PROG_TYPE_LSM`. BPF-LSM requires `lsm=...,bpf` on the kernel
   command line, which stock Ubuntu/Debian/RHEL do not set, so the runners could never exercise it.
   Kprobes rather than fentry: fentry on arm64 needs kernel 6.0+, and aya's kprobe support needs no
   BTF trampoline. The `security_path_*` signatures have been stable since well before 5.15.)*

   | Hook (kprobe) | Operation | Notes |
   |---|---|---|
   | `security_path_mknod` | CREATE | Creation of a regular file by `open(O_CREAT)`, `creat`, `mknod`. Non-regular modes (fifo, socket, device) are ignored *(call)*. |
   | `security_path_mkdir` | CREATE | Directory creation (the audit backend also maps `mkdir` to Create). |
   | `security_path_unlink` | DELETE | |
   | `security_path_rmdir` | DELETE | |
   | `security_path_rename` | RENAME | Records the source and destination. `RENAME_EXCHANGE` is reported as one RENAME (src → dst) *(call)*. |
   | `security_file_open` | WRITE | Only when `f_mode & FMODE_WRITE` and the inode is a regular file. The program checks this first, so the very hot open path exits after two loads. |
   | `security_path_truncate`, `security_file_truncate` | WRITE | `truncate`/`ftruncate`/`O_TRUNC`. `security_file_truncate` exists only on 6.2+. Its attach is optional (§2.2). |

   All of these require `CONFIG_SECURITY_PATH=y` (Ubuntu, Debian and RHEL set it). The capability
   probe checks that each mandatory symbol is attachable (listed in
   `/sys/kernel/tracing/available_filter_functions`, else `/sys/kernel/debug/tracing/...`, else
   `/proc/kallsyms`). If one is missing, the sensor falls back to audit and the reason names the
   symbol.

3. **Only successful operations are reported** (the audit backend has the same semantics). An LSM
   hook fires before the operation, so the hook only *stages* the event, and the event is emitted
   at syscall exit if the return value is ≥ 0. This works as follows:
   - `PENDING` is a hash keyed by `pid_tgid` (thread), created with `BPF_F_NO_PREALLOC` and up
     to 10,240 entries. Each value holds one staged operation: the kind, the process fields, the
     file fields and the path(s). The paths are built at hook time because a dentry can become
     negative before exit (unlink). Memory is used only by in-flight operations, never preallocated
     *(call: a preallocated LRU with roughly 2 KiB values would pin more than 20 MiB of kernel
     memory)*.
   - If an insert fails because the map is full, the operation is lost and counted in `DROPS`.
   - A `sched/sched_process_exit` tracepoint deletes the entry of a thread that exits, so entries
     left by a thread that died mid-syscall, or by an io_uring submission, never accumulate.
   - `sys_enter_<syscall>` tracepoints **clear** the thread's `PENDING` entry. Therefore an entry
     present at exit was staged during this same syscall. Without this, a stale entry, for example
     one left by an io_uring submission that never passes a syscall exit tracepoint, could be
     emitted at an unrelated later exit.
   - A hook stages only when the thread has no entry yet, so the first hook in a syscall wins.
     `open(O_CREAT)` on a new file therefore reports CREATE, not CREATE + WRITE. The exception is
     that `security_file_open` may *fill in* the inode fields of a staged CREATE, because the inode
     does not exist yet at `security_path_mknod` time.
   - `sys_exit_<syscall>` tracepoints emit the staged entry when `ret >= 0` and delete it in every
     case.
   - Covered syscalls: `open`, `openat`, `openat2`, `creat`, `truncate`, `ftruncate`, `mknod`,
     `mknodat`, `mkdir`, `mkdirat`, `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat`,
     `renameat2`. Each gets an enter program and an exit program sharing one inline body. These are
     per-syscall tracepoints, not `raw_syscalls`, so unrelated syscalls pay nothing *(call)*.

4. **Watched-path filtering happens in the kernel.** `WATCH` is a hash map of up to 64 entries
   keyed by `(dev, ino)` of a watched directory, filled by the agent at load (§2.2).
   - The program walks from the operand's dentry up through its ancestors. It crosses mount points
     via `struct mount` (`mnt_parent` / `mnt_mountpoint`) and stops at the task's root
     (`current->fs->root`) or after **32 components** *(call)*.
   - It emits only if some ancestor, or the operand itself for a directory, is in `WATCH`.
   - A rename matches if either its source or its destination parent is watched.
   - The same walk builds the path. Components are written right to left into a per-CPU scratch
     buffer.
   - The key is the inode's `i_sb->s_dev` (kernel `dev_t`) plus `i_ino`. When the agent marks a
     watched directory as "inode only" (`dev = 0`, see §2.2), the lookup tries `(dev, ino)` first
     and then `(0, ino)`. The second lookup happens only when a one-entry `WATCH_FLAGS` array says
     at least one inode-only entry exists, so the common case pays one lookup per ancestor.

   **Architecture: x86_64 only** *(call)*. Kprobe argument access (`BPF_KPROBE` /
   `PT_REGS_PARMn`) depends on the architecture, and `tools/ebpf/build.sh` builds with
   `-D__TARGET_ARCH_x86`. The fs object is therefore x86_64-only, while the process and net objects
   use only tracepoints and do not depend on the architecture. On other architectures the probe
   reports "fs eBPF object is x86_64-only" and the sensor falls back to audit. Building per-arch
   objects is debt for packaging (Phase 13). The optional attach points in §2.2 exist for kernel
   version differences (`security_file_truncate` before 6.2), not for other architectures.

5. **The record** (`struct fs_record`, `bpf/fs.h`) has a fixed size and is pinned with
   `_Static_assert`s on the C side and layout tests on the Rust side, as in `net.h`. Its fields:
   - header: `schema_version`, `kind`; kinds `KIND_FS_CREATE 6`, `KIND_FS_WRITE 7`,
     `KIND_FS_DELETE 8`, `KIND_FS_RENAME 9`, continuing after net's 3–5;
   - acting process: `pid` (tgid), `ppid` (real parent tgid), `uid`, `comm[16]` (group leader's,
     as in net), `exe_dev`, `exe_ino` (identity as in process v2 / net);
   - `ktime_ns` (at syscall exit), `ret`;
   - file: `ino`, `dev` (kernel `dev_t`, 0 = unknown), `mode`, `owner_uid`, `owner_gid` (from the
     inode, `i_uid`/`i_gid` as kernel-global ids), `has_inode` flag;
   - paths: `path[PATH_CAP]` with `path_len` and a `path_truncated` flag, plus, for RENAME only,
     `old_path[PATH_CAP]` / `old_path_len` / `old_path_truncated`.

   `PATH_CAP = 1024` bytes *(call)*. The ring buffer is 4 MiB *(call: about 1,900 records in
   flight, up from net's 256 KiB, because records are about 2 KiB)*. The builder may shrink
   `PATH_CAP` if the verifier rejects the program at 1024, recording the value it uses and the
   reason in ADR-010.

   For DELETE and RENAME, the file fields describe the operand (the source for RENAME) as read at
   hook time. For CREATE they come from `security_file_open` when that hook ran in the same
   syscall. Otherwise `has_inode = 0`, for example with `mkdir`, `mknod(2)`, or a CREATE whose
   inode the open hook never filled.

### 2.2 Engine (`crates/osiris-ebpf`)

6. **`FS_OBJECT` spec and the loader extensions it needs.**
   - `ObjectSpec` gains a kprobe list. The loader learns to attach kprobes (aya `KProbe`).
   - Each tracepoint/kprobe entry also gets a `required: bool`. A missing optional attach point is
     skipped and listed in the load report. This covers `security_file_truncate` before 6.2 and
     legacy syscall tracepoints that don't exist on some arches. A missing required attach point
     fails the load, and the sensor falls back.
   - The existing `PROCESS_OBJECT`/`NET_OBJECT` keep their current behaviour, with all entries
     required.

7. **`fs_record.rs`** holds `FsEvent`, `FsKind` and `decode_fs`. The tests mirror `net_record.rs`:
   layout pinned, C header text checked against the Rust constants (`tests/c_header.rs`), and every
   malformed input (bad kind, `path_len > PATH_CAP`, wrong size) rejected with a `DecodeError`.
   Nothing panics.

8. **Watch map population.** `LoadedObject` gets a way to insert `(dev, ino)` keys into `WATCH`
   before the reader starts.
   - The fs sensor resolves each configured watch path with `stat` (following symlinks). It
     converts `st_dev` (userspace encoding) to the kernel `dev_t` encoding (`MAJOR << 20 | MINOR`)
     and inserts it.
   - When `statfs` reports btrfs or overlayfs, it inserts `(0, ino)` instead ("inode only"). On
     those filesystems `stat`'s `st_dev` does not equal the `s_dev` the kernel sees (the same root
     cause as the 11b-2 exe-identity debt). Inode-only matching can over-report: an unrelated file
     whose ancestor has the same inode number on another filesystem would match. It can never
     silently miss. Over-reporting is the safer failure *(call)*.
   - A watch path that doesn't exist or isn't a directory is skipped. It is named in `last_error`
     while the sensor stays `Healthy` *(call: an operator typo should not disable the sensor)*.
   - If no watch path resolves, eBPF counts as unusable and the sensor falls back.

### 2.3 Filesystem sensor (`crates/osiris-sensors/fs`)

9. **Two backends chosen at `initialize`**, mirroring `ProcessExecSensor`. The constructor
   becomes `FilesystemSensor::new(audit_log_path: Option<PathBuf>, ebpf: Option<EbpfSettings>,
   watch_paths: Vec<PathBuf>)`, with existing builder methods kept.
   - **eBPF**: `Healthy`, flag `ebpf`, records read on the `spawn_reader` thread, `on_record`
     using `blocking_send`. Health counters are updated as in the process/net `on_record`. Ring
     buffer drops are added to `events_dropped_total`. A supervisor task turns a reader error into
     `Failed`.
   - **audit fallback** (eBPF configured but unusable): `Degraded`, flag `audit_fallback`, reason
     in `last_error`, with a later tail error appended next to it and never instead of it.
   - **audit only** (no eBPF configured): today's exact behaviour, `Healthy` with
     `audit_fallback`.
   - Neither usable: `Unsupported`/`Failed` with every reason.

10. **`ebpf_backend.rs`: `fs_to_raw(&FsEvent, boot_wall_offset_ns, proc_root) -> FileEventRaw`**
    is a pure function, tested on every OS.
    - `operation` comes from kind.
    - `path`: on `path_truncated`, the rendered path is prefixed with `…/` so it can never pass as
      an absolute path. The struct doc is updated to say so.
    - `previous_path` is set for RENAME only.
    - `inode`/`device_id` are `None` when `has_inode = 0`. Otherwise `device_id` uses
      `osiris_schema::encode_device_id` on the kernel `dev_t` split into major/minor.
    - `exe_path` comes from `osiris_ebpf::resolve_exe` (the same identity check and `comm` fallback
      as net).
    - `timestamp_ns` is ktime plus the offset resampled per record.
    - `audit_serial: None`, `source: RawEventSource::Ebpf`.
    - Invalid UTF-8 in a path is converted lossily *(call: the same as the audit parser's
      treatment of hex-encoded names)*.

### 2.4 Configuration and wiring

11. **Agent config** gains `fs_watch_paths: Vec<String>`. When it is empty and eBPF is configured,
    the default is `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/lib/systemd`,
    `/var/spool/cron`, `/var/www`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm` *(call: persistence,
    binary and web-shell locations plus the usual staging dirs; `/home` is excluded because browser
    and editor churn there would dominate volume, and operators can add it)*.
    - `build_sensor("filesystem")` builds the sensor when `fs_audit_log_path` or `ebpf` is set,
      not only for audit as today. As a result, an existing eBPF deployment starts watching the
      default list after upgrading. This is intended, and `docs/operators-ebpf.md` states it.
    - Only the agent's own tgid is excluded (`SELF_TGID`, unchanged). The docs warn not to put a
      same-host server's data directory inside a watched tree, because its database writes would
      become events and those events more writes (a feedback loop). The default list contains none
      of the documented server data paths *(call: a multi-tgid or exe-based exclusion would change
      the map contract every object shares, for a misconfiguration the operator controls)*.
    - The policy telemetry-level filter from 9d-3 still applies downstream, unchanged.
    - The real-Linux config, `docs/operators-ebpf.md` and the sample `agent.yaml` document the key.
    - Every exhaustive `AgentConfig` literal in the tests is updated.

### 2.5 `process_exec` health debt

12. **Evidence before fix.** A real-Linux assertion is added. After `exec_and_exit_are_observed_via_ebpf`
    has seen its events stored, `/status` for `process_exec` must show `events_emitted_total > 0`
    and a non-null `last_event_at`. The same assertion is added for `filesystem` after its
    scenario. Then:
    - If the assertion passes on both runners, the roadmap debt is closed as a misreading of a
      status read before any event, and VALIDATION.md records that.
    - If it fails, the cause is debugged with superpowers:systematic-debugging and fixed within
      11b-3, with a unit test reproducing it.

### 2.6 Record-layout debt

13. **Keep hand-mirrored layouts** (C header + `_Static_assert` + Rust layout test + header-text
    test) for the third record. Do not introduce codegen (bindgen / aya-tool) *(call: the
    four-way pinning has caught every drift so far, and codegen would add a Linux-only build step
    to a pure-Rust cargo build, which is exactly what ADR-010 avoided)*. ADR-010 records this
    re-evaluation.

### 2.7 Validation and docs

14. **Real-Linux tests** (`crates/osiris-real-linux-tests`, run on the GH workflow via
    `real-linux/t11b3-*` branches).

    **Harness split** *(call)*:
    - The global audit rules in `tools/real-linux/osiris.rules` stay as they are. The eBPF backend
      does not read them, and the fallback test needs them.
    - `render.rs` gains `fs_watch_paths`, and every stack renders an explicit list:
      `/tmp/osiris-p10`, `/var/www`, `/etc/systemd/system` (the trees the audit rules already
      watch), plus the per-test dirs below. The server's `/tmp/osiris-p10-*` data dirs are
      siblings of `/tmp/osiris-p10`, not inside it.
    - The workflow always sets `OSIRIS_BPF_DIR`, so the existing `file_lifecycle_is_observed` and
      `web_root_drop_raises_an_alert` now run on the eBPF backend. They must keep passing unchanged
      except where they assert audit-specific fields (`audit_serial`, source). Those assertions
      become backend-neutral.

    **Actor** *(call)*: every scenario's operations are done by a single `python3` child (`os.open`,
    `os.write`, `os.rename`, `os.unlink`, `os.mkdir`, `os.rmdir`, `os.open(..., dir_fd=)`). Pid and
    `exe_path` are then one known process. Bash builtins cannot rename or delete without spawning
    `mv`/`rm`. The expected `exe_path` is the realpath of the `python3` used.

    - (a) `filesystem` is `Healthy` with flag `ebpf` and without `audit_fallback`. The global fs
      audit rules are present but unused.
    - (b) In a fresh watched dir `/tmp/osiris-p10/fs-ebpf-<n>`, the python child does create
      (`O_CREAT`) → write (`O_WRONLY|O_APPEND` on an existing file) → rename → delete. Each yields
      exactly one stored event with source `EBPF`, the child's pid, the python `exe_path`, the
      exact absolute path (old and new path for rename) and a non-null inode.
    - (c) `mkdir` + `rmdir` yields CREATE and DELETE.
    - (d) The same operations in an unwatched dir (`/var/tmp/osiris-unwatched-<n>`, which is not in
      the list) yield nothing. This is checked after a later watched marker event has arrived, so
      "nothing" is not just "not yet".
    - (e) **Failures after the hook fired** yield nothing:
      - `rmdir` of a non-empty dir (ENOTEMPTY after `security_path_rmdir`);
      - `unlink` of a `chattr +i` file (EPERM after the hook; the runner is root on ext4; the test
        removes the flag in cleanup).
      A watched marker event afterwards bounds the wait. *(call: failures that happen before the
      hook, such as ENOENT or permission denials in `may_open`, prove nothing about the
      stage-at-hook / emit-at-exit logic.)*
    - (f) `openat(dirfd, "rel.txt", O_CREAT|O_WRONLY)` with `dirfd` on a watched subdir different
      from the CWD reports the subdir's true absolute path. This is the case the audit backend gets
      wrong.
    - (g) An operation in a watched `/dev/shm/osiris-<n>` (tmpfs, a mount crossing) yields a path
      starting with `/dev/shm/osiris-<n>/`.
    - (h) A stack whose object dir is a copy without `fs.bpf.o` (the existing broken-copy pattern)
      has the sensor `Degraded` with `audit_fallback`. A python write under `/tmp/osiris-p10`
      still arrives with source `AUDIT`.
    - (i) The `process_exec`/`filesystem` health assertion of §2.5.
    - The optional-attach-point path (`security_file_truncate` absent before 6.2) is not exercised
      on the runners, which are both 6.2 or later. It is covered by a loader unit test with a spec
      that names a nonexistent symbol as optional. VALIDATION.md records this gap.

    Every test runs on both ubuntu-22.04 and ubuntu-24.04. The run IDs and runner kernels are
    recorded in `docs/VALIDATION.md`.

15. **Benchmark.** `osiris-bench` (or the existing real-Linux bench workflow) measures one
    create/write/delete loop, 10,000 iterations, in (i) a watched dir and (ii) an unwatched dir,
    with and without the agent running. The result is recorded in `PERFORMANCE.md`. It is
    informative and is not a gate *(call)*. A warning in `PERFORMANCE.md` is required if the
    unwatched-dir overhead exceeds 10 %.

16. **Docs.**
    - `docs/operators-ebpf.md`: the fs section, covering the watch list, the kernel config
      requirement, the fallback, and the known behaviour in §5.
    - ADR-010: kprobe attach support, optional attach points, the layout re-evaluation.
    - `FileEventRaw` doc comments for the eBPF backend (path truncation marker, no audit serial).
    - `docs/ROADMAP-REMAINING.md`: 11b-3 done, its debts, and the outcome for the `process_exec`
      health debt.
    - `docs/VALIDATION.md`.

## 3. Non-goals

- BPF-LSM (`BPF_PROG_TYPE_LSM`) programs, and any *blocking* or deny decision. The sensor observes
  only.
- fanotify or inotify backends (ARCHITECTURE lists them; they belong to a later phase).
- Read events, `chmod`/`chown`/xattr changes, hard links (`link`/`linkat`), symlink creation,
  `mmap` writes, `splice`/`sendfile`, and `copy_file_range` without an open-for-write. The
  `FileOperation` enum stays at its four variants.
- io_uring file operations and 32-bit compat syscalls, which never pass the per-syscall
  tracepoints (the same blind spot as 11b-2's accepts).
- Hashing written files (the DETAILED telemetry level), and per-entity telemetry levels in kernel
  maps.
- Re-resolving the watch list when a watched directory is removed and recreated after start.
- Container mount-namespace path translation (§5).
- Changes to the audit backend's behaviour.

## 4. Anti-goals

These would count as failure even if the tests passed.

- A wrong path presented as fact. A truncated path must carry the `…/` marker, and a path built
  from the walk must be the operand's real location, never a CWD guess.
- Reporting a failed operation as if it changed the disk.
- Events from the agent's own writes (spool, DBs) feeding back into itself.
- A noticeable slowdown on unwatched paths. The `security_file_open` program must return before
  any map lookup for read-only opens.
- A verifier rejection, a missing kernel symbol or a missing object leaving the sensor silently
  dead. Each must surface as fallback or `Failed` with the reason.
- Regressing the process or network objects. Their load behaviour and record schemas are
  untouched.

## 5. Known behaviour to document (not fix)

- Paths are relative to the acting task's root and mount namespace. A process inside a container
  reports container-relative paths, and a watch dir resolved in the host namespace will not match
  inodes a container sees under a different overlay.
- On btrfs/overlayfs, watched dirs match by inode only and can over-report (§2.2).
- The ancestor walk stops after 32 components. A file nested deeper than 32 levels below its
  watched ancestor is not matched, and a path longer than 32 components or `PATH_CAP` bytes
  carries the `…/` marker.
- A `rename` within one watched dir is one RENAME. A rename *into* a watched dir from an unwatched
  one is also reported (the destination matched), with the true source path.
- `security_file_open` with write intent counts as WRITE even if the process never writes a byte
  (the audit backend has the same semantics: `perm=wa`).
- `PENDING` holds at most 10,240 in-flight operations *(call)*. Past that, the staged operation
  is lost and counted in `DROPS`, so it appears in `events_dropped_total`.
- Every `open`/`openat`/`openat2` system-wide pays one hash delete on enter and one lookup on exit,
  whatever the path. Only write-opens pay the ancestor walk. The benchmark in §2.7 quantifies this.
- The fs object is x86_64-only (§2.1).
- The kernel-floor claim (5.15) is reasoned, as in 11b-2. The runners run 6.8 and 6.17.

## 6. Constraints carried from earlier phases

- Rust stays OS-neutral and compiles on the Windows dev host. Linux-only code is `cfg(target_os =
  "linux")`. BPF objects are built only by `tools/ebpf/build.sh`, never by cargo.
- Use `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt` on touched files and
  `cargo test --workspace` before every merge. Rebuild `osiris-cli`/`osiris-server`/`osiris-agent`
  before trusting e2e results.
- Real-Linux validation runs only on GitHub Actions. To trigger it, push to `real-linux/<name>`.
  This host's clock runs about 3 h ahead of GitHub's.
- Ship no `unwrap`/`expect` outside tests, recover poisoned locks, and send backpressure from
  reader threads with `blocking_send`.
- Fetch before merging (the user sometimes commits on GitHub). Leave remote test branches until the
  user OKs deleting them.

## 7. Left to the builder

- Splitting the per-syscall programs across C macros or inline functions, and the exact verifier
  strategy for the dentry walk (bounded loop vs. unrolled, scratch-buffer layout). It must pass on
  5.15+ verifiers.
- How the agent detects btrfs/overlayfs (`statfs` `f_type` magic values).
- The precise optional/required flag per attach point beyond those named above.
- Rust module layout inside `osiris-ebpf` and the fs sensor, following the net precedent.
- The shape of the benchmark harness.
