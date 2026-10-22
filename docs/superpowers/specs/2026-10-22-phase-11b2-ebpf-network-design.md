# Phase 11b-2 — eBPF network backend (TCP connect/accept/close) and process schema v2

Status: design, 2026-10-22. Second sub-project of Phase 11b (order: 11b-1 engine + process
exec/exit — done, merged @ 06bfbc6; **11b-2 network** — this document; 11b-3 filesystem; 11b-4 DNS
uprobe; then 11c ClickHouse). The user asked to proceed with the recommended option for every
choice; every decision below that is not dictated by `ARCHITECTURE.md`, the 11b-1 design
(`docs/superpowers/specs/2026-10-18-phase-11b1-ebpf-process-design.md`) or existing code is the
designer's call and is marked *(call)*.

## 1. Intent

The Network sensor (`crates/osiris-sensors/net`, sensor name `network`) only polls
`/proc/net/tcp` every 200 ms. That backend:

- misses every TCP connection that opens and closes between two polls (short-lived C2 beacons,
  port probes, `curl` one-shots);
- guesses direction from the local port (≥ 32768 → outbound), which is wrong for services on high
  ports and for clients bound to low ports;
- attributes the pid by scanning every `/proc/<pid>/fd`, which is racy and costly;
- reads IPv4 only (`/proc/net/tcp`, not `tcp6`);
- emits a burst of fake "new" connections at every agent start.

ARCHITECTURE §4 (row "Network") names eBPF as the primary backend with `/proc/net/tcp[6]` polling
as the fallback. 11b-2 adds that eBPF backend on the 11b-1 engine, keeping the poller as the
fallback.

11b-2 also closes the two 11b-1 debts that `docs/ROADMAP-REMAINING.md` assigned to it, because both
change the process BPF record and share the "who owns this exe" problem with networking:

- `exe_path` is resolved from `/proc/<pid>/exe` in user space, late and racy (mitigated only by a
  `comm` check);
- the exit record is gated on the thread-group leader, so `pthread_exit` of a leader with live
  threads reports a live process as exited, and its real end is never reported.

Success: on the GitHub real-Linux runners (ubuntu-22.04 / kernel 5.15 and ubuntu-24.04 / 6.x), with
the objects present, the network sensor reports provider `network_sensor/ebpf` and `Healthy`. A
short-lived TCP connection that lives far less than one poll interval produces a stored
`NETWORK_CONNECT` and `NETWORK_CLOSE` for the connecting process, and a `NETWORK_ACCEPT` and
`NETWORK_CLOSE` for the accepting process. Those events carry the right pid, the right direction
and the right addresses, for both IPv4 and IPv6. Process exec/exit events carry
kernel-verified `exe_path`s. With the objects absent or the kernel unsupported, behaviour is
exactly today's.

## 2. Goals

### Network program

1. **New BPF program `net`** in `bpf/net.bpf.c` (plus `bpf/net.h`), built by `tools/ebpf/build.sh`
   into its own `net.bpf.o` + `net.bpf.o.sha256` next to `process.bpf.o` *(call: one object per
   sensor, so a verifier rejection in one does not disable the other)*. Same toolchain, the same
   minimal hand-declared CO-RE structs in `bpf/vmlinux_min.h` (extended), and the same integrity
   and schema-version checks as 11b-1.
2. **Hooks** *(call)*. TCP only, IPv4 and IPv6:
   - `tp/sock/inet_sock_set_state` (stable since 4.16; carries `family`, `protocol`, ports,
     `saddr`/`daddr`, `saddr_v6`/`daddr_v6`, `skaddr`, `oldstate` and `newstate`). Only
     `protocol == IPPROTO_TCP` is handled:
     - `CLOSE → SYN_SENT` runs in the connecting task's context, inside `connect()`. It records
       the owner in the tracking map: tgid, uid, comm, the exe identity (goal 8) and
       direction = outbound. No event is emitted yet, because the source port may not be assigned.
     - `SYN_SENT → ESTABLISHED` runs in softirq context. If `skaddr` is tracked, it emits
       **CONNECT** with the tuple from the tracepoint and the owner from the map.
     - `SYN_SENT → CLOSE` is a failed connect. It removes the entry and emits nothing (goal 14).
     - Any `→ CLOSE` transition of a tracked socket that reached ESTABLISHED emits **CLOSE** with
       the owner stored at open time, then removes the entry. This includes the TIME_WAIT
       hand-off, where the full socket moves to CLOSE.
   - `tp/syscalls/sys_exit_accept4` and `tp/syscalls/sys_exit_accept` run in the accepting
     task's context, so `current` is the acceptor. When the return value is a valid fd, the
     program resolves it to the socket with bounded CO-RE reads
     (`current->files->fdt->fd[fd]->private_data` → `struct socket` → `sk`, with the fd checked
     against `fdt->max_fds`). If that sock is TCP, it emits **ACCEPT** with the tuple read from
     `sock_common` and direction = inbound, and records the owner in the tracking map.
     *(call, revised after the builder check: a kretprobe on `inet_csk_accept` silently loses
     returns once blocked acceptors exhaust its `maxactive` slots; fexit's return-value slot
     moves with the 6.10 change to the argument lists of `inet_csk_accept`/`inet_accept`, and
     `bpf_get_func_ret` needs 5.17+. Syscall-exit tracepoints are stable ABI, have no slot
     limit, and run in the right context.)* Accepts through io_uring are not seen (§5).
   - Direction comes from which hook fired. It is never guessed from port numbers.
3. **Tracking map**: `BPF_MAP_TYPE_LRU_HASH`, key = socket pointer (u64), value = owner record,
   **65 536** entries *(call)*. LRU eviction of a long-lived connection loses only its CLOSE
   (documented in §5).
4. **Self-filter**: sockets owned by the agent's tgid, which is written by the loader into a
   one-entry array map as in 11b-1, are neither tracked nor emitted *(call: consistent with the
   process program and ARCHITECTURE §5.3; the agent's own transport connection is visible in the
   agent's self-telemetry instead)*.
5. **Record**: the fixed header `{schema_version, kind}`, then kind ∈ {CONNECT, ACCEPT, CLOSE},
   tgid, uid, comm[16], family, local/remote port, local/remote address as 16 bytes (IPv4 in the
   first 4), exe identity (goal 8), and a kernel `bpf_ktime_get_ns` timestamp. The layout is
   mirrored by a `#[repr(C)]` Rust struct with size/offset-pinning tests and a C header text test,
   as in 11b-1. The net object exports its own `schema_version` global, starting at **1**. Ring
   buffer: **256 KiB** *(call: records are ~100 bytes)*. Drops go to a per-CPU drop counter,
   reported as `events_dropped_total`.
6. **Engine generalisation** (`crates/osiris-ebpf`): factor what `ProcessProgram` does into a
   reusable loader. That means the object path, digest and schema check against an expected
   version per object, the self-tgid map write, attaching a list of named programs of mixed
   tracepoints across categories (`sched`, `sock`, `syscalls`), the drop counter and the ring-buffer reader. `ProcessProgram`
   becomes a thin wrapper, and `NetProgram` is a second wrapper. The public API used by the
   process sensor may change. The decoders for the net record live beside the process ones in
   `record` (or a sibling module), and stay panic-free on arbitrary bytes. *(The builder chooses
   the shape.)*

### Network sensor

7. **The `network` sensor gains an eBPF backend**, selected at `initialize` exactly like the
   process sensor's:
   - No `ebpf` key in the agent config → the procfs poller, exactly as today.
   - `ebpf` configured, probe and load OK → the eBPF backend. Health is `Healthy` with capability
     flag `ebpf`, raw events carry `RawEventSource::Ebpf`, and the provider becomes
     `network_sensor/ebpf` (already mapped in `normalize.rs`).
   - `ebpf` configured but probe or load fails → the procfs poller. Health is `Degraded`,
     `last_error` holds the reason (naming `net.bpf.o` and the probe reasons), and the capability
     flag is `procfs_fallback`.
   - The agent builds the `network` sensor when `network_proc_root` **or** `ebpf` is configured
     *(call, mirrors `process_exec`)*. With `ebpf` configured, no `network_proc_root` and a failed
     load, `initialize` fails with `Unsupported` and the reason. It is never a silent no-op.
   - Events become the existing `RawEvent::Network(NetworkEventRaw)`. `operation` comes from the
     record kind. `direction` is Outbound for CONNECT, and Inbound for ACCEPT. CLOSE uses the
     direction stored at open time. `proto` is `"tcp"`. Addresses are rendered as text with
     `std::net`, and IPv4-mapped IPv6 addresses are rendered as IPv4 *(call)*. `pid` is
     `Some(tgid)`. `uid` and `comm` come from the record. `exe_path` is resolved as in goal 8.
     `timestamp_ns` is wall clock, converted from the kernel timestamp with the same per-record
     offset resampling as the process backend. The doc comments on `NetworkEventRaw` that say
     "IPv4-only" and "always from the `/proc/net/tcp` uid column" are updated.
   - There is no change to normalization, enrichment, graph edges or detection rules.
     Downstream must see the same shapes it sees today. The only difference is that direction is
     now exact.

### Process schema v2 (11b-1 debts)

8. **Kernel-side exe identity.** At exec, and on net records at connect/accept, the BPF program
   reads `current->mm->exe_file->f_inode`: `i_ino`, plus `i_sb->s_dev` converted to the user-space
   `st_dev` encoding (kernel `MAJOR = dev >> 20`, `MINOR = dev & 0xfffff`). All of these hooks run
   in process context, where `current->mm` is valid. The conversion is done in Rust, with a unit
   test. Exit records do **not** carry the identity, because `exit_mm()` runs before
   `trace_sched_process_exit` and `current->mm` is NULL there.
   - **Exec and net `exe_path`** use one shared resolver: a function in `osiris-ebpf` that takes an
     injectable `/proc` root. It tries these in order *(call)*:
     1. If `stat(/proc/<pid>/exe)` gives the same `(st_dev, st_ino)` as the kernel identity, use
        the `readlink(/proc/<pid>/exe)` target.
     2. Otherwise apply the 11b-1 rule: use the link target if `/proc/<pid>/comm`, read after the
        link, equals the record's comm. This step covers an identity of zero, a failed `stat`, and
        a mismatch. Mismatches are common on btrfs subvolumes, where `stat` reports an anonymous
        dev, and on overlayfs, where `stat` reports the real underlying inode.
     3. Otherwise use the exec'd filename for exec records, or `""` for net records.

     The identity check therefore only ever strengthens the 11b-1 result. It never makes it worse.
   - **Exit `exe_path`** comes from a bounded user-space cache inside the process sensor:
     - The key is `(tgid, start_time)`. Exec records fill it with their resolved `exe_path`, and
       the exit removes the entry.
     - It holds up to 65 536 entries and evicts the oldest first *(call)*.
     - A miss gives `""`, as today. That happens when the process started before the agent or was
       evicted.

     This closes the 11b-1 parked item "`exit_to_raw` reads `/proc/<pid>/exe` unverified": the
     `/proc` read on exit goes away.
   - **Net `exe_path`** is best-effort. A short-lived connector has usually exited before user
     space reads the record, which gives `""`. That matches today's procfs semantics, where
     `exe_path` is empty when it cannot be resolved. Enrichment replaces the pipeline's
     provisional `ProcessRef` from the process's exec event anyway, so no cross-sensor cache is
     added *(call)*.
9. **Exit when the thread group dies.** `sched_process_exit` emits the exit record when
   `task->signal->live` has reached 0, which `do_exit` decrements before the tracepoint fires,
   instead of when `pid == tgid`. The record reports the tgid, and the group leader's start time,
   so `process_key` matches the exec. The exit status is taken from `signal->group_exit_code`
   when the group exit flag is set (any `exit_group` or fatal signal), else from the last
   exiting thread's `exit_code` (every thread ended by `pthread_exit`). That is the same value a
   waiting parent's `wait()` sees *(builder confirms the flag name and field location against
   the kernel source for 5.15 and 6.x, and writes the reasoning in the C)*. This removes both
   documented wrong-exit cases: the non-leader `execve` "exit signal 9", and the leader
   `pthread_exit`.
10. **Process record schema version 1 → 2.** Rust and C change together, the layout tests are
    updated, and a v1 object is rejected with the existing schema-mismatch error, which falls
    back to audit.

### Wiring, validation, docs

11. **Agent config**: no new keys. The existing `ebpf.object_dir` holds both objects. The agent
    passes `EbpfSettings`, or a shared equivalent, to the network sensor too. Old YAML still
    loads.
12. **Dependency graph**: `osiris-sensors-net` may depend on `osiris-ebpf`. The `osiris-ebpf`
    forbidden lines in `tools/check-dep-graph.sh` stay the same.
13. **Real-Linux validation** (`.github/workflows/real-linux.yml`, branches
    `real-linux/t11b2-*`). The build step produces both objects. New `#[ignore]` tests:
    - The `network` sensor is `Healthy` with flag `ebpf`.
    - The test process opens a listener on `127.0.0.1:<random>`. A thread in it accepts, then
      **immediately closes** the accepted socket. A child process (a unique marker command, e.g.
      `bash -c 'exec 3<>/dev/tcp/127.0.0.1/<port>'`) connects and exits immediately, so both
      ends reach `TCP_CLOSE` promptly. The connection lives far less than 200 ms. That is a
      property of the connection, not a promise about how fast events are delivered: waits use
      the existing real-Linux bounded timeouts. The test asserts:
      - a stored `NETWORK_CONNECT` and `NETWORK_CLOSE` with the child's pid and comm `bash`,
        direction Outbound, with the dst port equal to the listener port;
      - a stored `NETWORK_ACCEPT` and `NETWORK_CLOSE` with the test process's pid, direction
        Inbound;
      - no assertion on the network events' `exe_path`, which is best-effort (goal 8).
    - The same scenario over `[::1]` asserts the IPv6 rendering.
    - A multi-threaded process ends and yields exactly one `PROCESS_EXIT`, with `exit_code` 7, for
      its `process_key`, and with a non-empty `exe_path` from the exec cache. For example, a
      `python3` process whose non-leader thread calls `os._exit(7)` while the main thread sleeps.
    - The existing exec scenario's `exe_path` assertion now runs through the identity check.
    - The fallback test from 11b-1 is extended: with a corrupted `net.bpf.o`, the network sensor
      is `Degraded` with `procfs_fallback`, and procfs network events still arrive.

    All existing real-Linux tests must pass with both eBPF backends active. A test that asserts
    procfs-only behaviour, such as the provider string or the startup burst, is adjusted, and the
    change is noted in the report. The workflow annotations from 11b-1 (R4b) are extended to the
    network status.
14. **Docs**: an ARCHITECTURE §4 status note for the Network row; `docs/operators-ebpf.md`
    (the net object, its hooks, the fallback, the known behaviour in §5); `docs/VALIDATION.md`
    with the GH run id; and `docs/ROADMAP-REMAINING.md`, with 11b-2 done, the two 11b-1 debts
    removed, and the new debts listed. No new ADR is needed. ADR-010 covers the loader. If the
    builder changes the hand-mirrored layout approach, the change is recorded in ADR-010.

## 3. Non-goals

- UDP (`udp_sendmsg`), raw sockets, UNIX sockets, and listening sockets (bind/listen events).
- Failed outbound connects (`SYN_SENT → CLOSE`) as events. They are a detection signal for port
  scans, but adding them needs a new event type or operation, so this is deferred.
- Byte/packet counters, cgroup skb hooks, conntrack and NAT resolution (DETAILED/FORENSIC rows of
  §6).
- Reporting connections that existed before the agent started (the eBPF backend has no startup
  snapshot; see §5).
- `PROCESS_FORK`, per-entity telemetry levels in kernel maps, a VM kernel matrix, privilege
  dropping, packaging — still later phases, as in 11b-1.
- Removing or changing the procfs poller or the audit process backend.
- Codegen of the C/Rust record layouts. The approach stays hand-mirrored with pinning tests
  *(call: two small records do not justify a codegen toolchain; revisit in 11b-3)*.

## 4. Anti-goals

- Any BPF program that can hang, crash or noticeably slow the host: bounded reads only, no loops
  the verifier cannot bound, no blocking helpers.
- Silent loss: drops are counted; load failures surface as `Degraded` with a reason; LRU
  evictions are documented.
- Wrong attribution presented as fact: a CLOSE or CONNECT emitted in softirq context must take its
  owner from the tracking map, never from `current`.
- Guessed direction on the eBPF path.
- Making `cargo build`/`cargo test --workspace` need clang, root, BTF or a loaded program.
- Changing behaviour for installs without the `ebpf` key.

## 5. Known behaviour to document (not fix)

- Connections that already existed when the agent started are not reported. Their CLOSE is not
  reported either, because they are untracked. The procfs backend's startup burst goes away on
  the eBPF path.
- A passive connection that the peer closes before the server calls `accept()` produces no
  events.
- After LRU eviction (more than 65 536 tracked sockets), an evicted connection's CLOSE is lost.
- The owner is the process that called `connect()`/`accept()`. The tracking-map value is a full
  copy of the owner (tgid, uid, comm, exe identity, direction). CLOSE reports that tgid even if
  the process has since exec'd or exited. A socket passed to another process (fork,
  `SCM_RIGHTS`) keeps its original owner on CLOSE.
- Accepts done through io_uring, or through any path that bypasses the `accept`/`accept4`
  syscalls, are not reported. The syscall tracepoints need `CONFIG_FTRACE_SYSCALLS`, which
  mainstream distro kernels enable. Without it the net program fails to attach, and the sensor
  falls back to procfs as `Degraded`.
- The identity check in goal 8 cannot match on btrfs subvolumes or overlayfs. Those hosts get the
  11b-1 `comm`-checked result, never a worse one.
- A network event's `exe_path` is usually `""` when the process exits before user space reads
  the record. Downstream, enrichment from the exec event supplies the process identity.
- The agent must run in the host pid, network and root time namespaces. A connection made inside
  another network namespace is reported with that namespace's addresses, without namespace
  context, so container/K8s enrichment provides it, as today.
- Event volume rises versus the procfs backend, because every short-lived connection is now seen.

## 6. Constraints carried from earlier phases

The same as the 11b-1 design §6: YAML configs and `argv[1]` config path; the pre-merge gates
(fmt, clippy `-D warnings`, workspace tests, `tools/check-dep-graph.sh`, the console's
lint/test/build); no new CI gates; Linux-only code cross-checked here with
`--target x86_64-unknown-linux-gnu` and proven on GH Actions via `real-linux/*` pushes, diagnosed
via public check-run annotations; real-Linux tests `#[ignore]`, Linux-only, serial, root, bounded
waits, unique markers; untrusted bytes never panic and are bounded; `aya` stays pinned at the
11b-1 version unless a needed feature forces a bump, which the builder records.

## 7. Left to the builder

The engine refactor's shape, module split, map and program names, the exact C, the error enum
names, how the network sensor shares the process sensor's timestamp-offset helper, and the
wording of the docs, within the constraints above.
