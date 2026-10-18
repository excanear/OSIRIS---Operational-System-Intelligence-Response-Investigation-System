# Operator guide — eBPF process backend (agent.yaml)

The `process_exec` sensor can use an eBPF backend (tracepoints `sched_process_exec` and
`sched_process_exit`) instead of the Linux audit log. It reports provider
`process_exec_sensor/ebpf`, source `EBPF`, and also emits `PROCESS_EXIT` events. Decision record:
`docs/adr/ADR-010-ebpf-loader-aya.md`.

## Building the object

The BPF object is not built by cargo. On a Linux build host with `clang` and `libbpf-dev`:

```sh
tools/ebpf/build.sh /usr/lib/osiris/bpf
```

This writes `process.bpf.o` and `process.bpf.o.sha256` into the directory. The agent verifies
the digest at load time. Nothing compiled is committed to git. Packaging (.deb/.rpm) is Phase 13.

## Configuration

```yaml
ebpf:
  object_dir: /usr/lib/osiris/bpf
```

- `ebpf` absent: audit backend only, exactly as before.
- `ebpf: {}`: `object_dir` defaults to `/usr/lib/osiris/bpf`.
- Backend choice at start: probe OK and load OK gives the eBPF backend (health `HEALTHY`,
  capability flag `ebpf`). Otherwise, if `audit_log_path` is configured, the sensor falls back to
  the audit backend with health `DEGRADED`, capability flag `audit_fallback` and the reason in
  `last_error` (for example "eBPF unavailable: bpf object integrity check failed: ..."). With
  `ebpf` configured but no `audit_log_path`, an eBPF failure makes the sensor `FAILED` (no
  fallback).
- Capability flags and `last_error` are visible through the agent's local `GET /status`, not in
  `AGENT_HEALTH`.

## Requirements

- Validated kernels: 5.15 (Ubuntu 22.04) and 6.x (Ubuntu 24.04). Theoretical minimum: 5.8 (ring buffer maps) with BTF (`/sys/kernel/btf/vmlinux`); other kernels are untested.
- Privileges: `CAP_BPF` and `CAP_PERFMON`, or `CAP_SYS_ADMIN` (root).
- The build host needs clang and libbpf-dev. The run host needs neither.

## Behaviour and limitations

- The agent's own pid is filtered in the kernel, so it does not report itself.
- Drops: if the ring buffer (1 MiB) cannot take a record, a per-CPU counter is incremented and
  reported as `events_dropped_total` in the sensor metrics. Loss is counted, not silent.
- Exec events carry exe path, argv (bounded to 4096 bytes, truncated flag), ppid, uid, comm.
  `exe_path` is the `/proc/<pid>/exe` target when readable, else the `execve` filename.
- argv is read after exec from the new process memory. If the page is not resident the read can
  fail and the event has empty args. A process that rewrites its argv first shows the new text.
- Exit events are emitted for thread-group leaders. `event_data` has `exit_code`, `signal`, plus
  `comm`, `ppid` and `uid`. `exe_path` is often empty (the process is already gone).
- When a non-leader thread calls `execve`, the old thread-group leader's exit is reported as a
  `PROCESS_EXIT` with signal 9 for a process that keeps running, followed by an `EXEC` under the
  same pid.
- `PROCESS_FORK` is not emitted. Event volume is expected to be roughly double audit-only because exits are new (an unmeasured estimate).
- Benchmarks: `osiris-bench` runs the agent on the eBPF backend when `OSIRIS_BPF_DIR` is set to a
  built object directory.
