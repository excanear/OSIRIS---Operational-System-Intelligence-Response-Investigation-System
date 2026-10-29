# OSIRIS performance baseline

This is the first measured baseline for the benchmark program in ARCHITECTURE.md §19.2. It records
what the code at `4b450e1` does on two specific machines. These numbers are not SLOs. Every number
in the tables comes from the JSON lines that `osiris-bench` printed, rounded to two decimals.

## Methodology

All benches are in `crates/osiris-bench`, built in release mode (`cargo build --release`). Each
configuration ran once. Load phases last 30 s.

| Bench | What it measures |
|---|---|
| `pipeline` | In-process `Pipeline::process` (normalise + enrich) over 200 000 synthetic raw events from the 5-scenario generator mix. There is no I/O. |
| `query` | Fills a fresh SQLite `events.db` with N events from the same mix (chunks of 5 000 through `batch_write`), then writes N/100 alerts. It then reports the median of 5 runs each for: the default event list (`QueryPlan::new()`), a `PROCESS_EXEC` filter, and the default alert list. `fill_ms` covers **both** the event writes and the alert writes, so it is not comparable with the Task 6 `fill_ms`, which covered events only. |
| `ingest` | Starts the real `osiris-server` binary. The bench acts as the agent: it appends paced exec-chain events to a spool, and the real mTLS forwarder (`run_forwarder`) ships them to the server's agent listener. Every 100 ms one event is a marker, and the bench polls `events.db` until each marker becomes visible. After the 30 s load phase it drains for up to 30 s. `stored_eps_over_run` = events in `events.db` at the end ÷ (load + drain time), which is the server-side throughput. The latency percentiles cover delivered markers only. A lost marker (not visible when the drain ends) is excluded from them, so read them together with `markers_lost`. |
| `agent` | Starts the real `osirisd` on real auditd, spawns `/bin/true` at the target rate, and samples the agent's `/proc/<pid>/stat` and `status` on a fixed 1 s tick. CPU % is relative to one core. |
| `fs-loop` | Create, write 4 KiB, close and delete a file, 10 000 times, timing every iteration. Run in a watched and an unwatched dir, first without the agent, then with the real `osirisd` (eBPF backends). Single run, so the overheads below carry run-to-run noise that was not measured. |

`saturated` means the load generator itself fell more than one 100 ms slice behind its target at
some point. When `achieved` is far below `target`, the driver could not keep up, and the result
measures the driver's ceiling, not the system under test.

The ingest bench uses exec chains only. The 5-scenario mix reuses fixed pids, one inode and one
domain, and its synthetic timestamps all fall inside a few milliseconds. That builds a correlation
graph no real host would produce (see "Known limits").

## Environment

Two environments are used (ruling R9). auditd cannot run under WSL2, so the agent bench runs on
GitHub Actions. Every results table names the environment it came from.

**WSL**: pipeline, query, ingest

| Item | Value |
|---|---|
| Host CPU (Windows, `Get-CimInstance Win32_Processor`) | Intel Core i5-2400 @ 3.10 GHz, 4 cores / 4 threads |
| Host RAM | 16 GiB |
| Guest | Ubuntu 24.04.5 LTS under WSL2, kernel 6.18.40.1-microsoft-standard-WSL2 |
| Guest `lscpu` / `nproc` / `free -h` | Intel Core i5-2400 @ 3.10 GHz / 4 / 7.7 GiB RAM, 2 GiB swap |
| Disk | WSL ext4 virtual disk (`.vhdx`) on a Kingston SA400 SATA SSD. Bench data lives under `/tmp` on that disk. |
| Run | `tools/real-linux/bench.sh --skip-agent`, 2026-10-10 21:05-21:15 UTC (guest clock), code `4b450e1` |

**GitHub Actions**: agent

| Item | Value |
|---|---|
| Runner | `ubuntu-24.04` hosted runner, Ubuntu 24.04.5 LTS, kernel 6.17.0-1022-azure |
| CPU / RAM | AMD EPYC 7763, 4 vCPU / 15 GiB |
| Run | `.github/workflows/real-linux-bench.yml`, run 38085445024, 2026-10-10 20:52:26-20:57:55 UTC (GitHub timestamps), code `4b450e1` |

## Results

### Pipeline (WSL)

| Events | Elapsed | Events/s |
|---|---|---|
| 200 004 | 1 864.58 ms | 107 265.15 |

### Query (WSL)

| Stored events | `fill_ms` (events + alerts write) | Alerts rows | Default list median | `PROCESS_EXEC` median | Alerts median |
|---|---|---|---|---|---|
| 10 006 | 2 988.15 ms | 100 | 24.51 ms | 1.02 ms | 0.37 ms |
| 100 004 | 23 760.95 ms | 1 000 | 186.36 ms | 0.99 ms | 1.53 ms |
| 1 000 008 | 290 946.80 ms | 10 000 | 1 828.81 ms | 1.03 ms | 34.74 ms |

### Ingest (WSL)

| Target eps | Achieved (driver) eps | Driver saturated | Stored eps over run | Markers lost | Delivered p50 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| 1 000 | 999.82 | yes (max 311 behind) | 994.82 | 0 / 300 | 153.91 ms | 642.01 ms | 886.45 ms |
| 10 000 | 9 998.59 | no | 1 665.76 | 200 / 300 | 19 892.96 ms | 48 119.82 ms | 49 375.20 ms |
| 100 000 | 63 765.99 | yes (max 502 674 behind) | 804.12 | 262 / 268 | 6 831.68 ms | 61 808.04 ms | 61 808.04 ms |

At 10 000 and 100 000 eps the delivered-only percentiles cover 100 and 6 markers. Most markers
were lost, so those percentiles understate the real latency.

### Agent (GitHub Actions)

| Target exec/s | Achieved exec/s | Saturated | CPU % (one core) p50 / p95 / max | RSS MiB p50 / max | Samples |
|---|---|---|---|---|---|
| 0 (idle) | 0.00 | no | 5.97 / 6.96 / 6.97 | 50.63 / 50.63 | 29 |
| 1 000 | 999.94 | no | 32.50 / 35.81 / 36.64 | 56.38 / 72.05 | 29 |
| 10 000 | 2 342.88 | yes (spawner) | 92.17 / 102.93 / 107.77 | 50.70 / 68.93 | 30 |

At a target of 10 000 exec/s, the single-thread spawner reached only about 2 300 exec/s, so that
row shows the agent at about 2 300 exec/s, not at 10 000. `sample_read_failures` was 0 in every row.

### Filesystem sensor, eBPF backend (GitHub Actions)

One create + 4 KiB write + close + delete per iteration, 10 000 iterations, each iteration timed
on its own. The watched dir is passed to the agent as an `fs_watch_paths` entry. The unwatched dir
is not in the list. Neither dir is under the global audit rules, so the no-agent rows carry no
audit cost.

| Item | Value |
|---|---|
| Runner | `ubuntu-24.04` hosted runner, kernel 7.0.0-1017-azure (the agent table above ran on 6.17.0-1022-azure, a different image), AMD EPYC 9V45, 4 vCPU |
| Run | `.github/workflows/real-linux-bench.yml`, run 40789871234, branch `real-linux-bench/t11b3-1`, code `91eb93c` |
| Agent | process, network and filesystem sensors on eBPF, all `HEALTHY` |

| Agent | Dir | Total | Iterations/s | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| off | watched | 272.52 ms | 36 694.44 | 26.60 us | 27.70 us | 35.64 us | 132.46 us |
| off | unwatched | 274.46 ms | 36 435.28 | 26.69 us | 28.32 us | 35.81 us | 161.37 us |
| on | watched | 387.99 ms | 25 773.99 | 37.06 us | 46.86 us | 69.24 us | 157.79 us |
| on | unwatched | 325.51 ms | 30 721.07 | 31.05 us | 38.61 us | 48.05 us | 109.88 us |

Overhead of running the agent, computed from the table (total time, p50 in brackets):

| Dir | Overhead | Per iteration |
|---|---|---|
| unwatched | +18.6 % (+16.3 %) | +5.1 us |
| watched | +42.4 % (+39.3 %) | +11.5 us |

Over the three loops with the agent on, the agent used 0.73 s of CPU. Its status afterwards showed
`filesystem` `events_emitted_total` 20 000 and `events_dropped_total` 0. That is one CREATE and one
DELETE for each of the 10 000 watched iterations. The 4 KiB write is not a separate WRITE event:
the file was just created by `open(O_CREAT)`, and the first hook in a syscall wins (CREATE, not
CREATE + WRITE; see `docs/operators-ebpf.md`). Do not expect 30 000 events. The unwatched loops
produced no events.

> **Warning: the agent slows file operations in unwatched directories by more than 10 %.** In this
> create/write/delete loop the unwatched-dir loop took 18.6 % longer with the agent running
> (p50 per iteration 26.69 us to 31.05 us). The kernel hooks cannot know a directory is unwatched
> until they have looked at it: each `open`/`openat`/`creat` pays a map delete on syscall enter and
> a lookup on exit, and every create, unlink and rename walks the ancestors to test them against
> the watch list. The loop is a worst case (nothing else happens in it, so the hook cost is the
> whole difference). The absolute cost is about 5 us per iteration, not per byte, so
> file-metadata-heavy workloads (unpacking archives, builds, many small files) see it most.
> Watched dirs cost about 11.5 us per iteration on top of that (+42.4 %) because the event is also
> built and sent.

### Before/after F1 (WSL, ingest at 1 000 eps target, 30 s)

| Code | Stored eps over run | Markers lost | Delivered p50 |
|---|---|---|---|
| `2794ac9` + stored-eps metric (before) | 94.88-136.65 | 217-243 / 300 | 18 863.96-27 408.29 ms |
| + one risk-score write per batch (`3f4fe59`) | 69.97-136.30 | 217-258 / 300 | 19 953.00-22 327.13 ms |
| + one baseline transaction per batch (`5c73537`) | 976.64-996.46 | 0 / 300 | 92.63-103.38 ms |
| + WAL, synchronous=NORMAL (`3a22003`) | 994.80-999.44 | 0 / 300 | 109.41-122.36 ms |

Each row is two runs, shown as a range. At a 10 000 eps target, WAL raised stored eps from 1 132.72
to 1 591.01 (same tree, pragmas disabled versus enabled). The final matrix run above measured
1 665.76.

## Interpretation

- **F1, server ingest throughput (fixed).** Before the fixes, the ingest path committed SQLite once
  for each baseline frequency pair (two commits per exec event) and once for each risk score, and
  it did all of this before acknowledging the batch. It ran on the default rollback journal with
  `synchronous=FULL`. strace showed one blocking thread spending about 6.5 s of every 8 s in
  `fsync` (12.8 ms per call on the WSL virtual disk), while server CPU stayed around 2 %. Batching
  the risk scores alone changed nothing measurable. The per-event baseline commits were the
  dominant cost. With one transaction per batch for each store, the server keeps up with 1 000 eps
  with zero lost markers.
- **Durability trade-off.** `events.db` and `baseline.db` now open with `journal_mode=WAL` and
  `synchronous=NORMAL`. Commits are no longer fsynced one by one, so a power loss or OS crash can
  lose every transaction committed since the last WAL sync (checkpoint, by default up to about
  1 000 WAL pages, which is seconds of telemetry at these rates). The database is never corrupted,
  and an application crash loses nothing. Those lost batches were already acknowledged, so the
  forwarder does not resend them (it advances its offset on ack). The raw lines remain in the
  agent's spool and can only be replayed by hand. A file-copy backup must include the `-wal` file,
  or use SQLite's backup API or `VACUUM INTO`.
  The other SQLite stores (incidents, evidence, users, tenants, hosts) are not on the ingest hot
  path and keep their defaults.
- **Current ceiling.** On this WSL host the server stores about 1 600-1 700 eps (10 000 eps
  target). Above that, markers queue behind the forwarder's stop-and-wait batches of 500 events.
  At 100 000 eps the driver saturated at about 64 000 eps and wrote about 2 GB of spool to the same
  virtual disk. Stored throughput fell to about 800 eps because the driver, the forwarder and the
  server share 4 cores and one disk. This is a property of the rig as much as of the server.
- **WSL2 caveats.** The disk is a virtualised ext4 image (fsync latency is not that of bare metal).
  The guest shares the host's 4 cores with Windows. No CPU isolation or pinning was used, the load
  generator runs on the same machine as the server, and each configuration ran once.
- **Query.** Filtered queries (`PROCESS_EXEC`) stay around 1 ms up to 1 M events. The unfiltered
  default list grows roughly linearly with table size (1.83 s at 1 M). The alert list grows with
  the number of alerts (34.74 ms at 10 000).
- **Agent.** About 6 % of one core when idle and about 33 % at 1 000 exec/s. RSS is 50-57 MiB
  at p50 and at most 72 MiB. Thirty-second runs are too short to rule out slow growth.

## Known limits

- **F2, correlation fan-out (deferred).** Finding F2 had two parts. The first was a per-lookup cost
  that grew with the host's whole history: the tenant host filter materialised every stored event
  id of the host, and the key-only indexes read every edge an entity ever had. That part is fixed
  (`4b450e1`): with 10 % of edges on one hub key, one lookup took 35 ms at 5 000 host events and
  2.8 s at 200 000, and now takes 0.1-0.3 ms flat. The second part remains: `build_chain` walks up
  to depth 5, with up to 1 000 edges per lookup and no other bound. When a hub entity (a domain, an
  IP, a shared file) links many entities inside one correlation window, every process event walks
  the whole connected component. With the 5-scenario mix as ingest load (1 000 eps), the server
  stored about 75 eps, with one thread at 100 % CPU, and 5 of 6 gdb stack samples were in
  `query_relationships` under `build_chain`. The bench makes this extreme: all 1 036 edges fell in
  a 5 ms span, so one window held the whole run, and the generator reuses one domain and one inode.
  On a real host the component is bounded by the activity around hubs within ±30 s, but a busy hub
  can still be large. Bounding it needs a design choice (degree cap, edge budget per chain, or hub
  exclusion), so it is deferred (docs/VALIDATION.md "Deferred").
- The ingest bench drives exec chains only, so it barely exercises correlation. Its numbers are an
  upper bound for richer event mixes.
- The forwarder is stop-and-wait (one 500-event batch in flight), which caps throughput per agent
  connection at the server's per-batch latency.

## Reproduce

```
# WSL or any Linux host, as root (pipeline, query, ingest):
tools/real-linux/bench.sh --skip-agent /tmp/bench-ubuntu.jsonl
# Agent bench (needs real auditd): push to a real-linux-bench/** branch, or run on a VM:
git push origin HEAD:refs/heads/real-linux-bench/<name>   # .github/workflows/real-linux-bench.yml
tools/real-linux/bench.sh --agent-only /tmp/bench-agent.jsonl   # includes the fs loop
# The fs loop alone (OSIRIS_BPF_DIR must point at the built objects):
$CARGO_TARGET_DIR/release/osiris-bench fs-loop --iterations 10000
# Single configurations:
$CARGO_TARGET_DIR/release/osiris-bench ingest --rate 1000 --duration 30
```

`bench.sh` builds release binaries into `$CARGO_TARGET_DIR` (default `/root/osiris-target`) and
prints one JSON line per configuration.
