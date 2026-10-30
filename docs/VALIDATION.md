# Real-Linux validation (Phase 10)

The Phase 10 suite (`crates/osiris-real-linux-tests/tests/real_linux.rs`) runs the production
`osirisd` agent and `osiris-server` binaries on a real Linux host, performs real actions
(exec, file writes, sudo, systemd units, TCP connects) and asserts that the matching canonical
events and alerts appear through the server API. Every test filters on a unique per-test marker,
never on counts of host activity, and every wait is bounded.

Each result section states the code it ran against: GitHub Actions results are from `ef7171d`
(the Task 8 WAL and batched-ingest changes landed later; the final re-run, GitHub Actions run
38999490611 on branch `real-linux/t12-1` at `964e894`, 2026-10-17, was green on `ubuntu-22.04` and
`ubuntu-24.04` and covers them),
the Debian WSL run is from `564f50a` (`ef7171d` plus the `setup.sh` libssl-dev fix), and the Ubuntu
WSL data is from Task 3 (older code, before the Task 4 fixes). Authoritative audit-backed results
come from GitHub Actions, because auditd cannot run under WSL2 (see "Deferred").

## How to reproduce

### GitHub Actions (audit-backed, Ubuntu 22.04 and 24.04)

Push the commit to a `real-linux/**` branch, or dispatch the workflow manually:

```
git push origin HEAD:refs/heads/real-linux/<name>
```

`.github/workflows/real-linux.yml` runs on `ubuntu-22.04` and `ubuntu-24.04`: it calls
`sudo tools/real-linux/setup.sh`, then `tools/real-linux/run.sh` as root, and uploads
`audit.log`, the test output and any kept stack dirs as the `real-linux-<os>` artifact.
It is not a merge gate (CI keeps only `perf_smoke`). Delete the `real-linux/*` branches after use.

### A VM or host with a working auditd

As root:

```
tools/real-linux/setup.sh     # installs auditd, build tools, libssl-dev, and rust if cargo is absent; loads tools/real-linux/osiris.rules
tools/real-linux/run.sh       # release build into $CARGO_TARGET_DIR (default /root/osiris-target), then the suite
tools/real-linux/run.sh exec  # optional: test-name filter
```

The suite is `#[ignore]` and `#[cfg(target_os = "linux")]`, runs serially
(`--test-threads=1`) and needs root. On failure each test panics with the last API body and the
tail of both process logs, and keeps its stack dir (`/tmp/osiris-p10-*`) for post-mortem.

### WSL2 (no auditd)

Run these inside the distro as root (`wsl -d Debian -u root -- bash -lc "..."`; for Ubuntu use
`wsl -d Ubuntu-24.04 -- bash -lc "..."`), from the worktree (WSL path under `/mnt/f/...`, quoted):

```
tools/real-linux/setup.sh
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
tools/real-linux/run.sh
```

1. `setup.sh` installs the packages (auditd, curl, sudo, build-essential, pkg-config, libssl-dev)
   and creates `/tmp/osiris-p10`, `/var/www` and `/etc/osiris`, then stops with exit code 1 at
   `systemctl enable --now auditd` and prints a message. On WSL2 this stop is expected: the distro
   lives in a child PID namespace and the kernel refuses audit control (`auditctl -s`: Operation
   not permitted; auditd logs `DAEMON_ABORT`).
2. Because `setup.sh` exits before its rustup step, install rust yourself (the one remaining manual
   step; `run.sh` sources `~/.cargo/env`).
3. `run.sh` builds into the Linux-side `/root/osiris-target` (never the Windows `target/`) and runs
   the suite. Only the non-audit scenarios can pass; pass a name filter (for example
   `run.sh persistence`) to run a subset.

The Windows host clock can drift from real UTC; do not use it for timing.

## Ubuntu 22.04 (GitHub Actions, audit-backed)

| Item | Value |
|---|---|
| Distro | Ubuntu 22.04 (GitHub-hosted runner image `ubuntu-22.04`) |
| Kernel | 6.8.0-1064-azure |
| auditd | 3.0.7 (from the `DAEMON_START` record) |
| systemd | n/a (not captured; the runner image's stock package) |
| Code | `ef7171d` |
| Date / run | 2026-10-10, runs 38074649377 and 38075037549 (both at `ef7171d`) |

| Scenario | Result |
|---|---|
| agent_reports_real_host_facts_and_healthy_sensors | pass |
| exec_is_observed | pass |
| file_lifecycle_is_observed | pass |
| network_connect_is_observed | pass |
| sudo_is_observed | pass |
| systemd_unit_start_is_observed | pass |
| persistence_write_is_observed | pass |
| web_root_drop_raises_an_alert | pass |

8/8 in both runs (suite about 80 s).

## Ubuntu 24.04 (GitHub Actions, audit-backed)

| Item | Value |
|---|---|
| Distro | Ubuntu 24.04 (GitHub-hosted runner image `ubuntu-24.04`) |
| Kernel | 6.17.0-1022-azure |
| auditd | 3.1.2 (from the `DAEMON_START` record) |
| systemd | n/a (not captured; the runner image's stock package) |
| Code | `ef7171d` |
| Date / run | 2026-10-10, runs 38074649377 and 38075037549 (both at `ef7171d`) |

| Scenario | Result |
|---|---|
| agent_reports_real_host_facts_and_healthy_sensors | pass |
| exec_is_observed | pass |
| file_lifecycle_is_observed | pass |
| network_connect_is_observed | pass |
| sudo_is_observed | pass |
| systemd_unit_start_is_observed | pass |
| persistence_write_is_observed | pass |
| web_root_drop_raises_an_alert | pass |

8/8 in both runs (suite about 79 s).

Kernel and auditd versions come from the run artifacts (agent `kernel_version` in the spool,
`DAEMON_START` in `audit.log`); the runner image can change between runs.

## Ubuntu 24.04 (WSL2, non-audit scenarios only)

| Item | Value |
|---|---|
| Distro | Ubuntu 24.04 under WSL2 |
| Kernel | 6.18.40.1-microsoft-standard-WSL2 |
| auditd | installed, cannot run (EPERM on audit netlink) |
| systemd | PID 1 |
| Code | Task 3-era code (before the Task 4 fixes); only persistence was re-run later (574fec3) |
| Date | 2026-10-09/10 (Task 3; host clock about 3 h ahead of real UTC) |

Task 3's full run was 2/8 (host facts, network). `persistence_write_is_observed` was fixed
afterwards (574fec3) and passes alone in WSL (1 passed in about 32 s). The audit-dependent
scenarios cannot pass without auditd and were not weakened to make them pass.

| Scenario | Result |
|---|---|
| agent_reports_real_host_facts_and_healthy_sensors | pass (audit.log existed, all six sensors started) |
| network_connect_is_observed | pass |
| persistence_write_is_observed | pass |
| exec_is_observed | expected fail, not re-run at HEAD: environmental (audit) |
| file_lifecycle_is_observed | expected fail, not re-run at HEAD: environmental (audit) |
| sudo_is_observed | expected fail, not re-run at HEAD: environmental (audit) |
| systemd_unit_start_is_observed | expected fail, not re-run at HEAD: environmental (the systemd sensor tails the audit log) |
| web_root_drop_raises_an_alert | expected fail, not re-run at HEAD: environmental (needs audit exec and file events) |

## Debian 13 "trixie" (WSL2, non-audit scenarios only)

| Item | Value |
|---|---|
| Distro | Debian GNU/Linux 13 (trixie) under WSL2 (`wsl --install -d Debian --no-launch`) |
| Kernel | 6.18.40.1-microsoft-standard-WSL2 |
| auditd | 4.0.2 package installed, cannot run (same WSL2 limitation) |
| systemd | 257 (PID 1) |
| Code | `564f50a` |
| Date | 2026-10-10 (host clock about 3 h ahead of real UTC) |

All eight tests were run (`tools/real-linux/run.sh`, `--test-threads=1`, root): 2 passed, 6 failed,
303 s (the raw output was not committed). The six failures are environmental (no audit data), not product defects.

| Scenario | Result |
|---|---|
| network_connect_is_observed | pass |
| persistence_write_is_observed | pass |
| agent_reports_real_host_facts_and_healthy_sensors | fail, environmental. The distro and kernel assertions pass (`Debian GNU/Linux 13 (trixie)`, real kernel). The test then fails because `/var/log/audit/audit.log` does not exist: the agent correctly skips `process_exec`, `filesystem`, `identity` and `systemd` ("unsupported on this host"), so AGENT_HEALTH lists only `network` and `persistence` |
| exec_is_observed | fail, environmental: no PROCESS_EXEC within 45 s |
| file_lifecycle_is_observed | fail, environmental: no FILE_CREATE within 45 s |
| sudo_is_observed | fail, environmental: no PRIVILEGE_SUDO within 45 s |
| systemd_unit_start_is_observed | fail, environmental: no SERVICE_START within 45 s (`systemd-run` itself succeeded) |
| web_root_drop_raises_an_alert | fail, environmental: no FILE_CREATE within 45 s, so no alert |

Debian-specific finding: a bare Debian needs `libssl-dev` for `openssl-sys`, and `setup.sh` did
not install it (the GitHub runner images ship it). Fixed in the `setup.sh` apt line. No product
code change was needed for Debian. Debian with a working auditd is not covered (it needs a VM; the
workflow matrix has only Ubuntu runners).

## DNS sensor (Phase 11a)

The passive AF_PACKET DNS sensor (`crates/osiris-sensors/dns`) was validated on GitHub Actions
run 39087535939 (commit `bf85f37`, branch `real-linux/t11a-1`), green on `ubuntu-22.04` and
`ubuntu-24.04`. The scenario `dns_query_is_observed_and_alerts` passed: a real `curl` lookup of
`<marker>.xyz` produced a `DNS_QUERY` event attributed to curl and a
`dns_query_to_suspicious_tld` alert citing it. The DNS crate's unit tests, including the
Linux-only cBPF, loopback and symlink attribution tests, also passed on the runner (65 unit tests
plus the replay test on 24.04). That run's replay test covered only the synthetic fixtures. A real
capture from the same run (24.04, SLL2 header stripped) was added afterwards, in commit `d7566b5`,
as the replay fixture `crates/osiris-sensors/dns/tests/fixtures/ubuntu2404-curl-xyz.hex`. It is
replayed by the host test suite (`cargo test` on Windows and in CI), not in run 39087535939.

### Observed behaviour (documented, not fixed)

- On `lo` the kernel delivers every packet twice (outgoing and incoming). The sensor skips the
  outgoing loopback copy, so no duplicate event is produced.
- On the Azure runner systemd-resolved sends each upstream query on two interfaces. The copies are
  merged into one transaction (no duplicate event), but the engine's internal `duplicates` counter
  rises by one per upstream query. This was seen by replaying the fixture: the engine counters are
  not exported yet (see the Phase 11 debts in `ROADMAP-REMAINING.md`). Health is unaffected (only parse errors and overflow evictions degrade it).
- One `curl` lookup of a `.xyz` name yields 4 `DNS_QUERY` events: A and AAAA from curl through the
  127.0.0.53 stub (these alert), and A and AAAA from systemd-resolved upstream (no alert, its exe
  is not in the rule). glibc search-domain variants add more events that do not end in `.xyz`.
- Attribution is racy for clients that close the socket before the query packet is processed;
  such events carry no process and do not feed the `(exe, domain)` baseline.

### Known limitations

- If the AF_PACKET socket cannot be opened at initialize (no `CAP_NET_RAW`, unknown interface),
  the sensor is reported unsupported or failed and is not retried. Socket errors after start are
  retried with backoff.
- DNS over TCP, DoT, DoH and mDNS are not captured. The eBPF resolver uprobe is Phase 11b-4.

## eBPF process backend (Phase 11b-1)

The eBPF engine (`crates/osiris-ebpf`) and the eBPF exec/exit backend of `process_exec` were
validated on GitHub Actions run 39139529617 (commit `e5becff`, branch `real-linux/t11b1-1`),
green on `ubuntu-22.04` and `ubuntu-24.04` on the first run (that run did not record `uname -r`. The ubuntu-22.04 runner kernel is 6.8 (`6.8.0-1064-azure` in run 40043542332), not 5.15, so no 5.15 kernel has been run). The object was
built on the runner by `tools/ebpf/build.sh` (clang, libbpf-dev).

- `process_exec` reported `HEALTHY` with capability flag `ebpf`.
- `exec_and_exit_are_observed_via_ebpf` passed: provider `process_exec_sensor/ebpf`, the argv
  marker, ppid and uid 0 on the `PROCESS_EXEC`, and a `PROCESS_EXIT` with the same `process_key`
  and `exit_code` 7.
- `corrupted_object_falls_back_to_audit` passed: with a corrupted object the sensor was
  `DEGRADED`, flag `audit_fallback`, `last_error` "eBPF unavailable: bpf object integrity check
  failed: bpf object digest mismatch ...".
- All pre-existing real-Linux scenarios stayed green with the eBPF backend active.
- The process and osiris-ebpf crates' unit tests ran on the runner.

### Known limitations

- Not covered: kernels other than the runners' (versions not recorded), RHEL-like distributions, a kernel-version VM
  matrix (ARCHITECTURE §26).
- When a non-leader thread calls `execve`, the old thread-group leader's exit is reported as a
  `PROCESS_EXIT` with signal 9 for a process that keeps running, then an `EXEC` under the same pid.
- When the thread-group leader calls `pthread_exit` while other threads run, a `PROCESS_EXIT` is
  reported for a live process and its real end is never reported. Not provoked in validation.
- Exec `exe_path` comes from `/proc/<pid>/exe` read in user space, accepted only while
  `/proc/<pid>/comm` matches the record's comm; otherwise the `execve` filename. The comm check
  (against a later exec or pid reuse) is unit-tested; on a real kernel only the plain
  `/bin/sh` case is asserted, from the next `real-linux/*` run on.
- Exit `exe_path` is often empty (the process is already gone). argv is empty when the kernel read
  fails or when `arg_end <= arg_start`.
- A ring-buffer reservation failure increments the drop counter, reported as
  `events_dropped_total`. Not provoked in validation.
- With `ebpf` configured but no `audit_log_path`, an eBPF failure makes the sensor `FAILED`.
- `PROCESS_FORK` is not emitted. See `docs/operators-ebpf.md`.

## eBPF network backend and process record v2 (Phase 11b-2)

The eBPF TCP backend of `network_sensor` (`bpf/net.bpf.c`, `crates/osiris-sensors/net`) and
process record v2 (exe identity captured in the kernel, one exit per thread group) were validated
on GitHub Actions run 40039969622 (commit `8e4d8d6`, branch `real-linux/t11b2-1`), green on
`ubuntu-22.04` (job 120708485081) and `ubuntu-24.04` (job 120708485394) on the first push. Both
objects were built on the runner by `tools/ebpf/build.sh`.

After the final review, the net owner `comm` was changed to the thread-group leader's, and the
inbound check now asserts it. The suite was re-run as GitHub Actions run 40043542332 (commit
`6140b74`, branch `real-linux/t11b2-2`), green on `ubuntu-22.04` (job 120719901813, kernel
`6.8.0-1064-azure`) and `ubuntu-24.04` (job 120719901404, kernel `6.17.0-1022-azure`). The
workflow now records `uname -r` per job as a notice annotation.

Scenarios that passed on both runners:

- `network_sensor_uses_ebpf`: `network_sensor` `HEALTHY` with capability flag `ebpf`.
- `short_tcp_connection_is_observed_via_ebpf_v4` and `_v6`: a short-lived `bash` connection to a
  listener in the test process produced CONNECT and CLOSE (OUTBOUND, owner the child pid, comm
  `bash`) and ACCEPT and CLOSE (INBOUND, owner the test process, comm its `/proc/self/comm`,
  not the name of the accepting thread; asserted since run 40043542332), provider `network_sensor/ebpf`;
  the v6 run also checked the `::1` addresses.
- `group_exit_reports_once_with_code`: a worker thread calls `os._exit(7)` while the main
  thread sleeps; exactly one `PROCESS_EXIT` arrived for the pid, exit code 7, non-empty `exe_path`
  (from the exec cache).
- `corrupted_net_object_falls_back_to_procfs`: with a corrupted `net.bpf.o` the sensor was
  `DEGRADED`, flag `procfs_fallback`, `last_error` naming `net.bpf.o`.

Kernel coverage: run 40043542332 recorded `6.8.0-1064-azure` (ubuntu-22.04) and
`6.17.0-1022-azure` (ubuntu-24.04). Run 40039969622 did not record `uname -r`. No 5.15 kernel was
exercised: the 5.15 floor is reasoned from CO-RE and ring-buffer support, not run.

### Known limitations

- Not covered: kernels other than the two runner kernels, RHEL-like distributions, a kernel-version
  VM matrix (ARCHITECTURE §26).
- Network: TCP only; connections open at agent start, failed connects, io_uring accepts,
  accepts by 32-bit compat processes and LRU-evicted closes are not reported; a CLOSE can arrive without a CONNECT; connects by kernel
  threads (NFS/CIFS/iSCSI, MPTCP extra subflows) are attributed to the kernel worker; the exe
  identity check cannot match on btrfs or overlayfs. See `docs/operators-ebpf.md`.
- Ring-buffer drops and LRU eviction were not provoked in validation.
- On a real kernel only the worker-thread group exit is asserted; the leader `pthread_exit` and
  non-leader `execve` cases were not provoked.

## eBPF filesystem backend (Phase 11b-3)

The eBPF filesystem backend (`bpf/fs.bpf.c`, `crates/osiris-sensors/fs`, `crates/osiris-ebpf`
kprobe support) was built up over a series of `real-linux/t11b3-<n>` runs, each on
`ubuntu-22.04` and `ubuntu-24.04`. The logs of run 40786985456 (t11b3-9) show the runner kernels
`6.8.0-1070-azure` (ubuntu-22.04) and `7.0.0-1017-azure` (ubuntu-24.04); the 24.04 image moved
from 6.17.0-1022-azure (the 11b-2 runs) to 7.0 since. Bench run 40789871234 also ran on
`7.0.0-1017-azure`. Exact strings per run: `gh run view <id> --log | grep -o "[0-9.]*-[0-9]*-azure"`.

| Run | Branch / commit | Outcome |
|---|---|---|
| 40432835805 | t11b3-1 @ `f82cdc8` | `fs.bpf.o` compiled; load failed on both: verifier "BPF program is too large" (1M instructions) from the 32-step unrolled ancestor walk. |
| 40768725486 | t11b3-2 @ `3e916cf` | Bounded non-unrolled walk, loop state in a per-CPU scratch map: object loads and attaches on both. (24.04 first attempt: DNS flake, rerun green.) |
| 40771969598 | t11b3-3 @ `1992de3` | Ancestors keep being checked against `WATCH` after a full path buffer; green on both. |
| 40775169390 | t11b3-4 @ `c721fdc` | Filesystem sensor eBPF backend; green. (22.04 first attempt: `corrupted_object_falls_back_to_audit` flake, rerun green.) |
| 40779488463 | t11b3-5 @ `6e54396` | Agent wiring. 22.04 `web_root_drop_raises_an_alert` failed: the eBPF `FILE_CREATE` had `exe_path` `""` (the short-lived `bash -c` was gone from `/proc`). Real bug, fixed. |
| 40781865893 | t11b3-6 @ `e1792b4` | Kernel exe-identity index for `exe_path`; green on both. |
| 40783256483 | t11b3-7 @ `e7976d1` | Index entries verified against the identity; green on both. |
| 40785524078 | t11b3-8 @ `4e8f90a` | Scenarios (a)-(i): `real_linux` 26/26 on both kernels. |
| 40786985456 | t11b3-9 @ `b57b492` | Positive control for failed-operation silence. 24.04 green on every attempt. 22.04 attempt 1: `dns_query_is_observed_and_alerts` and `process_sensor_uses_ebpf` flakes (below); attempt 2: `dns_query_is_observed_and_alerts` again; **attempt 3 green on both 22.04 and 24.04**. `b57b492` therefore passed, after two flaky 22.04 attempts. |
| 40989019470 | t11b3-10 @ `9a8331e` | Final-review fixes. Verifier accepts the objects on both kernels (kprobe programs about 20.3k instructions, rename 40 151; no attach point skipped). Self-filter and detached-mount tests green. The chroot test failed on both kernels from a test-matcher bug (it matched the jail `mkdir`, not the payload create); 22.04 also had the known DNS flake. |
| 40999372578 | t11b3-11 @ `8e814ac` | Chroot test matcher fixed (BPF unchanged). **Green on both 22.04 (6.8.0-1070-azure) and 24.04 (7.0.0-1017-azure) on the first attempt**; `real_linux` 26/26, the chroot create reported as `/payload`. |

Scenarios that passed on both runners (run 40785524078):

- (a) `filesystem` `HEALTHY` with flag `ebpf`, without `audit_fallback`.
- (b) create, write, rename and delete in a fresh watched dir by one `python3` child: one stored
  event each, source `EBPF`, the child's pid, the `python3` `exe_path`, the exact absolute path
  (old and new for rename) and a non-null inode.
- (c) `mkdir` and `rmdir` give CREATE and DELETE.
- (d) the same operations in an unwatched dir give nothing, checked after a later watched marker.
- (e) failed operations give nothing: `rmdir` of a non-empty dir and `unlink` of a `chattr +i`
  file. Run 40786985456 adds a positive control (the same operation succeeds once the obstacle is
  removed and is then reported), so the silence is not a missed hook.
- (f) `openat(dirfd, "rel.txt", O_CREAT)` with a `dirfd` outside the CWD reports the true absolute
  path, which the audit backend gets wrong.
- (g) an operation in a watched tmpfs `/dev/shm/osiris-<n>` (a mount crossing) reports a path
  starting `/dev/shm/osiris-<n>/`.
- (h) with `fs.bpf.o` missing from the object dir, `filesystem` is `DEGRADED` with
  `audit_fallback` and a write still arrives with source `AUDIT`, while the process sensor stays
  `HEALTHY` on eBPF (the network sensor is not checked by this scenario).
- (i) the health assertion below.
- The existing `file_lifecycle_is_observed` and `web_root_drop_raises_an_alert` now run on the
  eBPF backend.

### Bench run

Run 40789871234 (`real-linux-bench/t11b3-1` @ `91eb93c`, ubuntu-24.04, kernel 7.0.0-1017-azure)
ran the create/write/delete loop. The agent had the process, network and filesystem sensors
`HEALTHY` on eBPF, and the filesystem sensor emitted 20 000 events (create + delete for each of
10 000 watched iterations) with 0 dropped. The numbers and the unwatched-dir overhead warning are
in `PERFORMANCE.md`.

### Optional attach points are not exercised on the runners

`security_file_truncate` exists only on kernels 6.2 and later and is the only optional attach point
(every syscall tracepoint is required since the final review). Both
runner kernels are 6.2 or later, so the skip-and-list path never runs there. It is covered by a
loader unit test with a spec that names a nonexistent symbol as optional, not by a real kernel
that lacks the symbol.

### Outcome of the process_exec health debt

The 11b-1 debt said `process_exec` showed `events_emitted_total` 0 and `last_event_at` null in
`/status` with the eBPF backend. It was a test misreading, not a code bug. Once the tests wait for
the events to be stored first, `/status` shows `events_emitted_total` > 0 and a non-null
`last_event_at` for both `process_exec` and `filesystem` (runs 40785524078 onward; the bench run
shows `process_exec` at 36 and 38 events and `filesystem` at 0 then 20 000). The evidence is
ordering after storage plus eventual consistency, not an instantaneous read: the check polls until
counts appear, and `process_exec` counts from agent start. Debt closed.

### Observed flakes (not fixed this phase)

None of these touch code changed in this phase except as noted.

- `dns_query_is_observed_and_alerts`: the 45 s matcher timed out with DNS events present. Three
  occurrences: run 40768725486 (t11b3-2, ubuntu-24.04, before the filesystem wiring existed) and
  run 40786985456 attempts 1 and 2 (ubuntu-22.04). In the last two every
  `DNS_QUERY` event in the stack had `process: null`, including `curl`'s and the system's, so
  attribution failed across the board. Cause (ruling): a pre-existing race in the DNS sensor's
  user-space attribution. It reads `/proc/net/udp` and `/proc/*/fd` when the agent processes a
  captured packet, but `curl`'s stub-resolver socket and systemd-resolved's upstream sockets close
  within milliseconds of the answer. When the agent's DNS thread lags, whole bursts are
  unattributed (uid 0, process null), which breaks the test's `exe_path` ends-with-`curl` matcher.
  The DNS sensor code is untouched by 11b-3 and the first occurrence (t11b3-2) predates the
  filesystem wiring. master `88ee9bc` ran green 2/2 on both kernels on the same runners
  (diagnostic run 40790007073), while this branch saw 3 DNS failures in about 20 job attempts, so
  11b-3's extra agent load may widen the race; that is not proven. The fix is Phase 11b-4 (the
  DNS uprobe captures the pid in the kernel at query time, removing the race by design); carried
  as a debt in `docs/ROADMAP-REMAINING.md`.
- `corrupted_object_falls_back_to_audit`: `PROCESS_EXEC` never matched in 45 s (1 occurrence,
  run 40775169390, ubuntu-22.04; rerun green).
- `process_sensor_uses_ebpf`: the server failed with "cannot bind control listener ...: Address
  already in use" because the test harness's `free_port()` released a port and handed it out
  twice within one stack (1 occurrence, run 40786985456 attempt 1). Harness issue: allocate all
  ports while holding the listeners, or retry.

### Known limitations

- Not covered: kernels other than the runners', a kernel-version VM matrix (ARCHITECTURE §26).
  The 5.15 floor is reasoned, not run.
- The fs object is x86_64 only; elsewhere the sensor falls back to audit.
- A file nested more than 32 path components below a watched dir is never matched (known evasion).
- io_uring file operations, `open_by_handle_at`, 32-bit compat syscalls and kernel threads are not
  reported. Hard links, symlink creation, `chmod`/`chown`/xattr changes and reads are never
  reported.
- Container mount namespaces are not translated; btrfs and overlayfs match by inode only and can
  over-report.
- The watch list is not re-resolved after start. More than 64 watch keys make the whole fs eBPF
  backend fall back to audit.
- `exe_path` is `""` for a short-lived actor on btrfs/overlayfs, or whose binary is outside the
  standard bin directories. `PENDING` overflow (10 240) and ring-buffer drops were not provoked in
  validation.
- See `docs/operators-ebpf.md` for the full list.

## Findings

| Finding | Distro | Fix commit |
|---|---|---|
| Agent reported distro and kernel as "unknown" instead of the real values | Ubuntu 24.04 (WSL) | 5e2d96a |
| Harness spawned the agent by the wrong binary name (`osiris-agent` instead of `osirisd`) | Ubuntu 24.04 (WSL) | e3463ca |
| Harness did not own the agent child before the readiness wait, so a timeout panic leaked the process | Ubuntu 24.04 (WSL) | 73995e1 |
| Agent could not create its quarantine vault when the harness pre-created it at 0755 (control connection refused) | Ubuntu 24.04 (WSL) | a213fc3 |
| Persistence scenario expected PERSISTENCE_CREATED, but a unit file normalises to SERVICE_CREATE and the scan interval is 30 s | Ubuntu 24.04 (WSL) | 574fec3 |
| `run.sh` / `setup.sh` were not executable in git | all | b015be2 |
| Shipped shell rules listed only `/bin/*` shell paths; merged-/usr hosts report `/usr/bin/bash`, so the web-root and DNS rules never fired | Ubuntu 22.04, 24.04 | 265d678 |
| Spool NDJSON lines interleaved (tokio `write_all` returned before the bytes were written, so one send's newline landed after the next line) | Ubuntu 22.04, 24.04 | 5a7f082 |
| `tokenize` did not treat auditd's ENRICHED `\x1d` separator as a field boundary (latent: the audit `key` carried the enrichment) | Ubuntu 24.04 | dd68664 |
| Process sensor never captured argv (execve arguments live in a separate EXECVE record) | Ubuntu 22.04, 24.04 | 0010a58 |
| Web-root scenario matched the alert on the marker, but alerts carry only evidence event ids | Ubuntu 22.04, 24.04 | e3741a2 |
| Scenario shell actions had no bound (`systemd-run --wait`, `sudo`) and the CI suite step had no timeout | Ubuntu 22.04, 24.04 | ef7171d |
| `setup.sh` omitted `libssl-dev`, so the release build failed on a bare Debian | Debian 13 (WSL) | 564f50a |
| F1: server ingest committed baseline frequencies (two commits per exec event) and risk scores (one per event) before the ack, with the default rollback journal and synchronous=FULL; about 100-140 eps stored at a 1000 eps target, most markers lost | Ubuntu 24.04 (WSL, ingest bench) | 3f4fe59, 5c73537, 3a22003 |
| F2: every correlation edge lookup materialised all of the host's stored event ids (tenant host filter) and read every edge an entity ever had (key-only indexes), so lookup cost grew with the database: 35 ms at 5k events, 2.8 s at 200k | any (storage) | 4b450e1 |

Each product fix has a fixture-based or unit regression test that runs in normal CI on any OS, for
example `the_shipped_web_root_rule_fires_on_merged_usr_shell_spellings`,
`a_batch_is_scored_with_one_risk_score_write`,
`a_batch_is_observed_in_one_commit_with_the_same_counts_as_one_by_one`,
`opens_in_wal_mode_with_normal_sync`, `a_windowed_host_scoped_edge_lookup_is_bounded_by_its_indexes`,
`send_returns_only_after_the_whole_line_is_written`,
`the_enriched_gs_separator_is_a_field_boundary`, `tests/real_audit_fixtures.rs` and
`ids_containing_ties_an_alert_back_to_its_marker_event`.

## Deferred

- M1 (Task 4 review): the process sensor's `ExecAssembler` holds one pending exec at a time. When
  audit records of another event interleave on a busy host, the exec is released early and its argv
  is silently lost (the event is still reported, with an empty `cmdline`).
- M3 (Task 4 review): on a host with no policy set the agent sends the full argv, and there is no
  secret redaction of argument values. Argv is stripped only below the STANDARD policy level.
- WSL auditd gap: auditd cannot run under WSL2, so audit-dependent scenarios can be validated only
  on GitHub Actions or a real VM. The WSL runs (Ubuntu and Debian) cover the non-audit scenarios.
- Debian with a working auditd is not validated.
- F2 remainder (correlation fan-out): `build_chain` walks up to depth 5 with up to 1000 edges per
  lookup and no other bound. When a hub entity (a domain, an IP, a shared file) links many entities
  inside one correlation window, every process event walks the whole connected component, so the
  per-event cost grows with the component. The ingest bench's 5-scenario mix shows it in the
  extreme (all synthetic timestamps fall in one 5 ms span, so one window covers the whole run):
  about 75 eps stored at 1000 eps, one server thread at 100 % CPU in `query_relationships`. Fixing it
  needs a design choice (degree cap, edge budget per chain, or hub exclusion). See PERFORMANCE.md
  "Known limits".

## Console

Visual pass over every screen at 1440x900 and 390x844 against `osiris-stack` (spool-only seed: the
seven generator scenarios, 46 events and 8 alerts, no agent) served by `vite preview`. Each
screen's primary interaction was exercised: the process filter, the process, file, network and
container detail views, Timeline "Last 1 hour" and a host deep link, the alerts rule filter, a
hunt-template run, a graph load with a node hover and click, and a group policy edit through its
confirm step (the saved values persist after a reload). No page errors or HTTP 4xx/5xx were
seen.

Provenance: the pass ran on binaries built on 2026-10-10, before the WAL and batched-baseline
ingest commits of the Task 8 performance work. The Console does not touch those paths, but the pass
was not repeated on the final binaries.

### Bugs (fixed)

| Finding | Fix commit | Regression test |
|---|---|---|
| The Vite dev/preview proxy forwarded the browser's Origin on WebSocket upgrades, so the API's CSWSH guard rejected Live Events with 403 | 5bb2999 | `console/proxyOrigin.test.ts`, the Live Events spec in `console/e2e/screens.spec.ts` |
| That fix rewrote Origin unconditionally, so any foreign page could get past the API's Origin check through the dev/preview proxy. Origin is now rewritten only when it is the Console's own origin. Also, a stale `tsc -b` emit (`proxyOrigin.js`) shadowed the TypeScript source | 977889f | `console/proxyOrigin.test.ts` (own origin rewritten; foreign and missing Origin left alone) |
| Entity Graph edges were invisible: react-force-graph-2d's default link colour (`rgba(0,0,0,0.2)`) does not show on the dark background, so a subgraph looked like disconnected dots | 73d78e4 | `EntityGraph.test.tsx` "draws edges in a colour that is visible on the dark background" |

### Empty states (seed has no agent, so Hosts, Incidents, Evidence and Sensors are empty)

- Hosts: "No hosts found." is clear, but it does not say that hosts appear once an agent enrols.
- Incidents: "No incidents found." under the New-incident form is clear.
- Timeline: the host picker only lists hosts that sent SENSOR_HEALTH in the last hour. With a
  spool-only seed the picker is empty while the page says "Select a host to load its timeline."
  This is a dead end: nothing explains why no host is offered, although the host has 46 events.
  `?host=<id>` works and renders all 46 events. "Last 1 hour" with no host only fills Since.
- Evidence ("No evidence recorded.") and Sensors ("No sensor health data reported yet.") are clear.

### Phase 13 UX debt

- No layout or styling beyond the base colours: the navigation is a plain bulleted list above
  every page, there is no sidebar or header, and forms run together inline (labels touch their
  inputs, and on Group policy "Heartbeat" wraps away from its input).
- Timestamps are raw nanoseconds everywhere (lists, Timeline, Alerts, Hunting), and time-range
  inputs take nanoseconds. Groups alone shows a local date, which is inconsistent.
- Detail screens (process, file, network, container) show "Events (N)" with no event list under it.
  This matches the 7b-2/7b-5 plans, but it reads as missing data.
- File detail is titled with `device:inode` only. The path is not shown.
- Alerts show the host id (UUID) where other lists show the hostname. Alert rows do not link to
  the evidence events or a detail view.
- Overview: "Alerts8" and "Incidents0" lack a separator.
- Containers: an empty image renders as a blank cell. Pod shows "—".
- Entity Graph: nodes have no labels (hover tooltip only), there is no legend for the kind colours,
  and a node click does nothing (no pivot to the entity's detail screen). The canvas is 600 px
  high, so the graph sits far below the form.
- Threat Hunting: the OQL textarea is tiny and shows about one line of the template query.
- Mobile (390 px): tables overflow horizontally (Files, Network, Containers and Alerts).
  Long ids in headings (process key, container id) overflow the viewport. The Alerts reasons
  column wraps to one or two words per line.
- Live Events shows a bare "Live" status word above the filter, with no explanation.

## Known gaps

- DNS over TCP, DoT, DoH and mDNS are not captured (see "DNS sensor (Phase 11a)").
- No container or Kubernetes scenarios.
- RHEL-like distributions (auditd paths, SELinux) are not covered.
- eBPF covers process exec/exit (11b-1) and TCP network (11b-2); filesystem and the DNS uprobe are pending (11b-3, 11b-4).
