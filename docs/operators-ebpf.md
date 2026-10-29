# Operator guide — eBPF process, network and filesystem backends (agent.yaml)

The `process_exec` sensor can use an eBPF backend (tracepoints `sched_process_exec` and
`sched_process_exit`) instead of the Linux audit log. It reports provider
`process_exec_sensor/ebpf`, source `EBPF`, and also emits `PROCESS_EXIT` events. Decision record:
`docs/adr/ADR-010-ebpf-loader-aya.md`.

The `network_sensor` can use a second eBPF backend (TCP connect, accept and close) instead of
procfs polling; it is described in "Network backend" below. The `filesystem` sensor can use a third
eBPF backend instead of the audit log ("Filesystem backend" below). All backends share the `ebpf` key
and the object directory.

## Building the object

The BPF object is not built by cargo. On a Linux build host with `clang` and `libbpf-dev`:

```sh
tools/ebpf/build.sh /usr/lib/osiris/bpf
```

This writes `process.bpf.o`, `net.bpf.o` and `fs.bpf.o`, each with a `.sha256` sidecar, into the directory.
There is one object per sensor, and `object_dir` must hold all three. The agent verifies each digest at
load time and refuses an object whose `schema_version` differs from what it expects (process 2,
net 1, fs 1). Nothing compiled is committed to git. Packaging (.deb/.rpm) is Phase 13.

## Configuration

```yaml
ebpf:
  object_dir: /usr/lib/osiris/bpf
```

- `ebpf` absent: the process sensor uses the audit backend only and the network sensor the procfs
  poller only, exactly as before.
- `ebpf` present: the process, network and filesystem sensors try eBPF, so `object_dir` must
  hold `process.bpf.o`, `net.bpf.o` and `fs.bpf.o` with their sidecars.
- `ebpf: {}`: `object_dir` defaults to `/usr/lib/osiris/bpf`.
- Backend choice at start: probe OK and load OK gives the eBPF backend (health `HEALTHY`,
  capability flag `ebpf`). Otherwise, if `audit_log_path` is configured, the sensor falls back to
  the audit backend with health `DEGRADED`, capability flag `audit_fallback` and the reason in
  `last_error` (for example "eBPF unavailable: bpf object integrity check failed: ..."). With
  `ebpf` configured but no `audit_log_path`, an eBPF failure makes the sensor `FAILED` (no
  fallback).
- Capability flags and `last_error` are visible through the agent's local `GET /status`, not in
  `AGENT_HEALTH`.

### Upgrading from 11b-1

Rebuild both objects on upgrade (`tools/ebpf/build.sh <object_dir>`). Two things change for an
install that already has an `ebpf` key:

- A `process.bpf.o` built for 11b-1 (record schema 1) is now refused, because the agent expects
  schema 2. The process sensor then falls back to the audit backend (`DEGRADED`,
  `audit_fallback`), or is `FAILED` without `audit_log_path`.
- The `ebpf` key now also starts the network sensor's eBPF backend, which needs `net.bpf.o` in
  `object_dir`. Without it the network sensor is `DEGRADED` on the procfs poller (when
  `network_proc_root` is set) or is skipped as unsupported.

## Requirements

- Validated on the ubuntu-22.04 and ubuntu-24.04 GitHub runners. Run 40043542332 recorded their kernels: `6.8.0-1064-azure` (ubuntu-22.04) and `6.17.0-1022-azure` (ubuntu-24.04). No 5.15 kernel was exercised. The 5.15 floor is reasoned (CO-RE relocations and ring buffers, >= 5.8, with BTF at `/sys/kernel/btf/vmlinux`), not run. Other kernels are untested.
- The net program also needs `CONFIG_FTRACE_SYSCALLS` (syscall tracepoints), which mainstream distro kernels enable.
- Privileges: `CAP_BPF` and `CAP_PERFMON`, or `CAP_SYS_ADMIN` (root).
- The build host needs clang and libbpf-dev. The run host needs neither.
- The agent must run in the host (initial) pid namespace and the root time namespace, as a
  systemd service or a `hostPID` DaemonSet does. The kernel reports root-namespace pids: the
  self-filter compares them with the agent's own pid, and `/proc/<pid>/...` lookups use them. The
  audit backend's `/proc/<pid>/stat` starttime is time-namespace-adjusted, so only in the root
  time namespace do both backends derive the same `process_key` for one process.

## Behaviour and limitations

- The agent's own pid is filtered in the kernel, so it does not report itself.
- Drops: if the ring buffer (1 MiB) cannot take a record, a per-CPU counter is incremented and
  reported as `events_dropped_total` in the sensor metrics. Loss is counted, not silent.
- Exec events carry exe path, argv (bounded to 4096 bytes, truncated flag), ppid, uid, comm.
  `exe_path` is the `/proc/<pid>/exe` target when readable and `/proc/<pid>/comm` (read after
  the link) still equals the comm captured in the kernel at exec time; otherwise it is the
  `execve` filename. Since 11b-2 (process record v2) the kernel also captures the exec'd image's
  identity (`st_dev`, `st_ino`), and the order is: (1) `stat(/proc/<pid>/exe)` has the same
  identity, so the link target; (2) else the link target if `/proc/<pid>/comm` equals the record's
  comm; (3) else the `execve` filename.
- `/proc/<pid>/exe` is still read when user space consumes the record, not at exec time. By then
  the pid may have exec'd again (`sh -c 'cmd'`, `system()`, `popen()`, wrapper scripts) or been
  reused; the identity check catches this and the event keeps its `execve` filename instead of
  naming the later image. The identity cannot match on btrfs subvolumes or overlayfs; those hosts
  get the `comm`-checked result of step 2. Residual: on such hosts a later image with the same
  15-byte comm is not detected.
- argv is read in the kernel at exec time from the new process memory. It is empty when that read
  fails or when the process has no argv area (`arg_end <= arg_start`). A process that rewrites its
  argv first shows the new text.
- Event timestamps are the kernel's monotonic clock plus a realtime − monotonic offset that is
  resampled for every record, so a wall-clock step or a resume from suspend is followed from the
  next event on.
- Exit events are emitted once per process, when the thread group dies (`signal->live` reaches 0).
  `event_data` has `exit_code`, `signal`, plus `comm`, `ppid` and `uid`. `exe_path` comes from a
  cache keyed by `(tgid, start_time)` filled at exec time (65 536 entries, oldest evicted first)
  and is empty on a miss. A leader calling `pthread_exit`, or a non-leader `execve`, no longer
  produces an exit for a live process.
- Two threads that both see `signal->live == 0` emit one exit: a kernel-side LRU dedup map
  (4096 entries, key `{start_boottime, tgid}`) suppresses the second. When all threads call
  `pthread_exit`, the reported exit status is that of the first thread to observe `live == 0`,
  not necessarily the leader's.
- `PROCESS_FORK` is not emitted. Event volume is expected to be roughly double audit-only because exits are new (an unmeasured estimate).
- Benchmarks: `osiris-bench` runs the agent on the eBPF backend when `OSIRIS_BPF_DIR` is set to a
  built object directory.

## Network backend

With `ebpf` configured, the `network_sensor` uses the eBPF backend instead of the procfs poller.
It reports provider `network_sensor/ebpf`, source `EBPF`, `proto` `tcp`, for IPv4 and IPv6, and
the event types `NETWORK_CONNECT`, `NETWORK_ACCEPT` and `NETWORK_CLOSE`.

Hooks (object `net.bpf.o`): the `sock/inet_sock_set_state` tracepoint (connect, accept
completion and close of TCP sockets), and the `syscalls/sys_exit_accept` and
`syscalls/sys_exit_accept4` tracepoints (the accepting process). A kernel LRU map of 65 536
sockets stores the owner (tgid, uid, comm, exe identity, direction) at open time. The ring buffer
is 256 KiB; a record that does not fit increments a per-CPU counter reported as
`events_dropped_total`. Direction comes from the hook, never from ports: CONNECT is outbound,
ACCEPT inbound, CLOSE the direction stored at open time.

Backend choice at start:

- Probe and load OK: health `HEALTHY`, capability flag `ebpf`.
- Probe or load fails and `network_proc_root` is set: the sensor falls back to the procfs poller,
  health `DEGRADED`, flag `procfs_fallback`, `last_error` naming `net.bpf.o` (for example a
  corrupted object).
- Probe or load fails and `network_proc_root` is not set: `initialize` returns `Unsupported` with
  the reason.
- No `ebpf` key: procfs only, exactly as before.

The net program needs `CONFIG_FTRACE_SYSCALLS`; without it, it fails to attach and the sensor
falls back as above.

### Network known behaviour

- Connections that already existed when the agent started are not reported, and neither is their
  CLOSE (they are untracked). The procfs backend's startup burst does not occur.
- A passive connection that the peer closes before the server calls `accept()` still produces an ACCEPT when `accept()` returns, but its CLOSE may be missing (the socket was already closed when the owner entry was inserted).
- After LRU eviction (more than 65 536 tracked sockets) an evicted connection's CLOSE is lost. The
  map is an LRU whose per-CPU free lists can evict before it is full. The race between the
  accept-time insert and a peer close is not fenced, so a stale entry can remain. It is replaced
  only when the next socket at the same kernel address goes through `connect()` or `accept()`.
  A socket that reaches CLOSE without either (a passive child reset before `accept()`, an
  io_uring or in-kernel accept) is reported under the stale owner: at worst one later CLOSE at a
  reused socket address may be attributed to the wrong pid. The window is tiny (the address must
  be reused while the entry survives), but such a CLOSE's owner is not proof.
- A CLOSE can arrive without a prior CONNECT (simultaneous open, or a ring-buffer drop).
  Consumers must not assume CONNECT/CLOSE pairing.
- The owner is the process that called `connect()` or `accept()`. CLOSE reports that tgid even if
  the process has since exec'd or exited; a socket passed to another process (fork, `SCM_RIGHTS`)
  keeps its original owner.
- Connects made by kernel threads (NFS, CIFS, iSCSI, MPTCP extra subflows) are attributed to the
  kernel worker, with an unknown exe.
- Accepts through io_uring, or any path that bypasses `accept`/`accept4`, are not reported.
- Accepts by 32-bit (ia32 compat) processes on x86_64 are not reported: syscall tracepoints do
  not fire for compat syscalls, so their `accept`/`accept4`/`socketcall` produces no ACCEPT, and
  the socket is untracked (no CLOSE either). Their outbound connects are still seen, because
  CONNECT comes from the socket-state tracepoint.
- `comm` is the owner process's comm (the thread-group leader's, as `/proc/<pid>/comm` and the
  procfs backend report it), not the name of the thread that called `connect()` or `accept()`.
- Only TCP is covered: no UDP, and failed connects (no established connection) are not reported.
- `exe_path` follows the same chain as exec, ending in `""` for network events. It is resolved
  against `network_proc_root` when set, else `/proc`, and is usually `""` when the process exits
  before user space reads the record; enrichment from the exec event supplies the identity.
- The agent must run in the host pid, network and root time namespaces. A connection in another
  network namespace is reported with that namespace's addresses, without namespace context.
- Event volume is higher than with procfs, because every short-lived connection is seen.

## Filesystem backend

With `ebpf` configured, the `filesystem` sensor uses a third eBPF backend instead of the Linux
audit log. It reports source `EBPF` and the event types `FILE_CREATE`, `FILE_WRITE`, `FILE_DELETE`
and `FILE_RENAME`. Object: `fs.bpf.o`, built by `tools/ebpf/build.sh` next to the other two
(record schema 1). `object_dir` must now hold `process.bpf.o`, `net.bpf.o` and `fs.bpf.o`.

Hooks are kprobes on the LSM path hooks (not BPF-LSM programs, which need `lsm=...,bpf` on the
kernel command line): `security_path_mknod` and `security_path_mkdir` (CREATE),
`security_path_unlink` and `security_path_rmdir` (DELETE), `security_path_rename` (RENAME),
`security_file_open` with write intent (WRITE), and `security_path_truncate` and
`security_file_truncate` (WRITE). `security_file_truncate` exists only on kernels 6.2 and later;
it is an optional attach point, so its absence is skipped and listed in the load report. A missing
required attach point fails the load.

Only successful operations are reported. The hook stages the operation and a per-syscall exit
tracepoint emits it when the return value is not negative, so a failed `unlink` or `rmdir`
produces no event.

### Requirements and platform

- `CONFIG_SECURITY_PATH=y`. Ubuntu, Debian and RHEL kernels set it. The probe checks that each
  required symbol is attachable; if one is missing the sensor falls back to audit and the reason
  names the symbol.
- **x86_64 only.** Kprobe argument access depends on the architecture and the object is built with
  `-D__TARGET_ARCH_x86`. On other architectures the probe reports "fs eBPF object is x86_64-only"
  and the sensor falls back to audit. The process and network objects use only tracepoints and are
  not affected.
- The kernel statements under "Requirements" above apply. The fs object was validated on the
  runner kernels only (see `docs/VALIDATION.md`).

### Watch list and default

The sensor only reports operations under a watched directory. The list is the agent config key
`fs_watch_paths`. When it is empty and `ebpf` is configured, the default is:

```
/etc /usr/bin /usr/sbin /usr/local/bin /usr/lib/systemd /var/spool/cron /var/www /root /tmp /var/tmp /dev/shm
```

These are persistence, binary and web-shell locations plus the usual staging dirs. `/home` is
excluded because browser and editor churn would dominate the volume; add it if you want it.

```yaml
fs_watch_paths:
  - /etc
  - /var/www
```

Each path is resolved at start with `stat` (symlinks followed). A path that does not exist or is
not a directory is skipped and named in `last_error`, and the sensor stays `HEALTHY`. If no path
resolves, eBPF counts as unusable and the sensor falls back. The kernel map holds at most 64
watched directories; more than that makes the insert fail and the whole filesystem sensor falls
back to audit.

On btrfs and overlayfs a watched directory is matched by inode number only (`stat`'s device does
not equal the kernel's there). This can over-report, never silently miss.

### Warning: do not watch a same-host server's data directory

Only the agent's own process is excluded in the kernel. If the OSIRIS server runs on the same host
as the agent and its data directory (SQLite databases, spool) is inside a watched tree, each
database write becomes an event, and storing those events causes more writes: a feedback loop.
The default list contains none of the documented server data paths. If you move the server data
under `/tmp`, `/var/tmp` or another watched tree, remove that tree from `fs_watch_paths`.

### Backend choice at start

- Probe and load OK: health `HEALTHY`, capability flag `ebpf`.
- Probe or load fails (missing or corrupted `fs.bpf.o`, missing symbol, non-x86_64, no watch path
  resolved) and an audit log is configured: the sensor falls back to the audit backend, health
  `DEGRADED`, flag `audit_fallback`, reason in `last_error`. The process and network sensors are
  not affected.
- Neither backend usable: `FAILED` or unsupported, with every reason.
- No `ebpf` key: audit only, exactly as before.

### Upgrading from 11b-2

- Rebuild all three objects (`tools/ebpf/build.sh <object_dir>`).
- **The `ebpf` key now also enables the filesystem sensor's eBPF backend**, and the sensor is
  built even when no `fs_audit_log_path` is set. An existing eBPF deployment therefore starts
  watching the default list above after upgrading. This is intended. Set `fs_watch_paths`
  explicitly to change it. Without `fs.bpf.o` in `object_dir` the sensor is `DEGRADED` on audit
  (or skipped as unsupported when no audit log is configured).
- Expect more events than before on busy `/tmp` and `/var/tmp`.

### Known behaviour of the filesystem backend

- Paths are relative to the acting task's root and mount namespace. A process inside a container
  reports container-relative paths, and a watch dir resolved in the host namespace will not match
  the inodes a container sees under a different overlay.
- On btrfs and overlayfs, watched dirs match by inode only and can over-report.
- The ancestor walk stops after 32 components (mount crossings count). A file nested deeper than 32
  levels below its watched ancestor is **not matched**: this is a known evasion, a consequence of
  the verifier's instruction budget. A path longer than `PATH_CAP` (1024 bytes) is rendered as a
  truncated tail with a `…/` prefix, as is a path of more than 32 components, so it can never be
  mistaken for an absolute path; the walk
  keeps checking ancestors against the watch list after the buffer is full.
- A `rename` within one watched dir is one RENAME. A rename *into* a watched dir from an
  unwatched one is also reported (the destination matched), with the true source path.
  `RENAME_EXCHANGE` is one RENAME.
- `open` with write intent counts as WRITE even if the process never writes a byte (the audit
  backend has the same semantics, `perm=wa`). The first hook in a syscall wins: `open(O_CREAT)` on
  a new file reports CREATE, not CREATE + WRITE.
- Non-regular files (fifo, socket, device) are not reported as CREATE.
- `PENDING` holds at most 10 240 in-flight operations. Past that the operation is lost and counted
  in `events_dropped_total`.
- Every `open`/`openat`/`openat2` on the host pays one hash delete on enter and one lookup on
  exit, whatever the path; only write-opens pay the ancestor walk. Measured cost: see
  `PERFORMANCE.md`. In a tight create/write/delete loop the unwatched-dir slowdown is above 10 %,
  and that file carries a warning.
- Not reported: io_uring file operations (`IORING_OP_OPENAT`, `UNLINKAT`, `RENAMEAT`),
  `open_by_handle_at`, 32-bit compat syscalls, hard links, symlink creation, `chmod`/`chown`/xattr
  changes, `mmap` writes, `splice`/`sendfile`, and reads. For a kernel thread or an io_uring
  submission the hook fires but no covered syscall exit follows, so nothing is reported and the
  staged entry stays until that thread's next covered syscall or exit.
- A watched directory that is removed and recreated after start is not re-resolved.
- `exe_path` is the `/proc/<pid>/exe` target (identity-checked, `comm` fallback) when the actor is
  still alive. Otherwise the agent looks the kernel's executable identity (`st_dev`, `st_ino`) up
  in an index of the standard binary directories (`/usr/local/sbin`, `/usr/local/bin`,
  `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`; canonicalised, first wins). Every hit is re-verified
  against the identity, the index is rescanned at most once per 60 s, and its capacity is 65 536.
  An unknown binary gives `""`. The index does not work on btrfs subvolumes or overlayfs, and a
  binary outside those directories gives `""` when the actor has already gone.
- The agent must run in the host pid and root time namespaces.
