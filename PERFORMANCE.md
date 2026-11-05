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
| `dns-send` | 10 000 timed `sendto` calls of a well-formed DNS A query from one UDP socket to `127.0.0.1:5300`, then 10 000 to `127.0.0.1:53`, each port with a listener that drains and never answers. Four configurations (no agent; full agent; full agent without `dns.bpf.o`; full agent without `dns_capture`), 5 interleaved rounds, medians reported. After each agent run's port-53 flood the `dns` status is sampled every second for 10 s. |

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
> (p50 per iteration 26.69 us to 31.05 us). The likely cause is the hooks: they cannot know a
> directory is unwatched until they have looked at it. Each `open`/`openat`/`creat` pays a map
> delete on syscall enter and a lookup on exit, and every create, unlink and rename walks the
> ancestors to test them against the watch list. This attribution is not isolated by the bench.
> One confound: the unwatched loop ran after the watched loop, while the agent may still have been
> draining about 20 000 watched-dir events (a CREATE and a DELETE per watched iteration), which
> could inflate the unwatched figure. The loop is
> a worst case (nothing else happens in it, so the hook cost is the whole difference). The absolute
> cost is about 5 us per iteration, not per byte, so file-metadata-heavy workloads (unpacking
> archives, builds, many small files) see it most. The watched-dir overhead versus no agent is
> about 11.5 us per iteration (+42.4 %); that is about 6.4 us more than the unwatched dir, which is
> the added cost of building and sending the events. Known cost driver and future optimisation:
> a create in an unwatched dir walks the ancestors twice (`security_path_mknod` misses, then
> `security_file_open` walks again for the write-open); a per-thread "walked, no match" marker
> would skip the second walk.

### DNS send path, eBPF DNS attribution (GitHub Actions)

The 11b-4 kprobes on `udp_sendmsg`/`udpv6_sendmsg` run on every UDP send on the host. They return
after the destination-port check for every port other than 53, so the number that matters is the
slowdown of a send to a port other than 53. The bench sends to port 5300 for that, and to port 53
for the full DNS path. Each loop is 10 000 `sendto` calls of the same well-formed A query from one
socket, each call timed. The listeners drain and never answer, so the port-53 loop is an
unanswered 10 000-query flood.

| Item | Value |
|---|---|
| Runner | `ubuntu-24.04` hosted runner, kernel 7.0.0-1017-azure |
| Run | `.github/workflows/real-linux-bench.yml`, run 41326077476, branch `real-linux-bench/t11b4-2`, code `696698f` |
| Configurations | A: no agent. B: the full agent (process, network, filesystem on eBPF; `dns` on `ebpf_attribution`). C: B with `dns.bpf.o*` removed from a copy of the object dir, so `dns` runs AF_PACKET + `/proc` attribution and no kprobes. D: B without `dns_capture`, so no DNS sensor. |
| Rounds | 5 per configuration, interleaved (the order rotates every round), medians below |

Medians over the 5 rounds (send rate; p50 and p99 of one `sendto`):

| Config | Port 5300 sends/s | p50 | p99 | Port 53 sends/s | p50 | p99 |
|---|---|---|---|---|---|---|
| A no agent | 270 862 | 2.878 us | 6.606 us | 128 433 | 5.283 us | 23.313 us |
| B full agent | 237 988 | 3.313 us | 8.035 us | 110 679 | 7.301 us | 22.242 us |
| C no `dns.bpf.o` | 248 709 | 3.145 us | 7.221 us | 115 744 | 6.649 us | 20.789 us |
| D no DNS sensor | 201 624 | 3.280 us | 12.218 us | 127 992 | 5.295 us | 23.564 us |

Overhead pairs, computed from the median rates (time per send), with the p50 difference:

| Pair | What it isolates | Port 5300 | Port 53 |
|---|---|---|---|
| B vs C | **the 11b-4 kprobes** | **+4.50 %** (+0.168 us) | +4.58 % (+0.652 us) |
| C vs D | the 11a AF_PACKET capture (on port 53 also `/proc` attribution) | −18.9 % (−0.135 us), noise | +10.58 % (+1.354 us) |
| D vs A | the rest of the agent | +34.3 % (+0.402 us), noisy | +0.34 % (+0.012 us) |
| B vs A | the whole agent | +13.8 % (+0.435 us) | +16.0 % (+2.018 us) |

- **The 11b-4 cost on a send to a port other than 53 was +4.50 %, about 0.17 us per send, in this
  run.** The rerun below measured −15.4 % for the same pair. The kprobe cost is below what this
  runner can resolve. It is not a measured pass of the spec's 5 % threshold. A kprobe has a fixed
  entry cost even when the program returns at once, so some cost is certain; the bench only bounds
  it inside the noise.
- On port 53 the kprobes cost +4.58 % (+0.65 us per send): the program also reserves and submits a
  ring-buffer record.
- **Noise.** One loop of 10 000 sends lasts about 40-90 ms on a shared hosted runner. The C vs D
  port-5300 figure is negative, and D's port-5300 rate (201 624/s, p99 12.2 us) is below both C and
  A, which no agent configuration can explain. It is noise, and it also inflates D vs A on port
  5300. Read the pairs as about ±15 % (see the rerun below). B vs C is the cleanest pair, since B
  and C differ only in the kprobes and ran interleaved, but it is inside that band too.
- A first run (41324827608, `t11b4-1` @ `1748899`) had one round and no variants and showed
  +51.8 % on port 5300 for the whole agent. That figure is superseded: a single short loop with no
  variants could not attribute the cost to anything.
- The agent used 0.14-0.17 s of CPU over the three loops (warm-up, port 5300, port 53) in B, and
  0.17-0.19 s in C.

**Second measurement: the noise envelope.** Run 41331461832 (branch `real-linux-bench/t11b4-3`,
code `f1b557b`, same runner image and kernel, same 5 interleaved rounds) repeated the bench after
the final fix wave. Run 41326077476 above stays the reference for the overhead pairs; this run
shows how far the same bench moves between runs.

| Config | Port 5300 sends/s | p50 | p99 | Port 53 sends/s | p50 | p99 |
|---|---|---|---|---|---|---|
| A no agent | 175 958 | 4.958 us | 8.072 us | 85 613 | 10.315 us | 22.213 us |
| B full agent | 151 817 | 6.820 us | 9.353 us | 76 063 | 10.887 us | 25.938 us |
| C no `dns.bpf.o` | 128 392 | 6.709 us | 12.419 us | 71 662 | 13.920 us | 23.275 us |
| D no DNS sensor | 146 010 | 6.259 us | 11.947 us | 87 039 | 9.965 us | 21.982 us |

| Pair | Port 5300 | Port 53 |
|---|---|---|
| B vs C (the 11b-4 kprobes) | −15.4 % (+0.111 us) | −5.8 % (−3.033 us) |
| C vs D | +13.7 % (+0.450 us) | +21.5 % (+3.955 us) |
| D vs A | +20.5 % (+1.301 us) | −1.6 % (−0.350 us) |
| B vs A | +15.9 % (+1.862 us) | +12.6 % (+0.572 us) |

- The no-agent baseline A swung from 270 862 to 175 958 sends/s on port 5300 between the two runs,
  with nothing changed in A. The runner's own speed varies by more than a third.
- The kprobe pair B vs C on port 5300 ranged from −15.4 % to +4.50 % across the runs. A negative
  cost is impossible, so the spread is noise. **The 11b-4 kprobe cost is below what this runner can
  resolve. The bench does not show it under 5 %; it shows it is lost in a noise band of about
  ±15 %.**
- The whole agent (B vs A) cost +13.8 % then +15.9 % on port 5300: the most stable pair, since it
  sums every cost.

**The unanswered port-53 flood.** The `dns` status, sampled 1-10 s after each flood.

Pre-counter, run 41326077476 (before the sensor counted capture-socket drops):

| Config | State | `events_dropped_total` after the flood | `events_emitted_total` |
|---|---|---|---|
| B, 5/5 rounds | `HEALTHY` throughout | 5 317 / 4 574 / 5 056 / 4 672 / 5 368, final already at 1 s | 0 until about 5 s, then 3 245 / 2 843 / 3 320 / 2 894 / 3 193 |
| C, 5/5 rounds | `DEGRADED` before and after (the missing `dns.bpf.o` fallback, by design) | 0 | 0 until about 5 s, then 859 / 845 / 777 / 864 / 878 |

Post-counter, run 41331461832 (`PACKET_STATISTICS` drops counted):

| Config | State | `events_dropped_total` after the flood | `events_emitted_total` | Agent CPU |
|---|---|---|---|---|
| B, 5/5 rounds | `DEGRADED` already at t = 1 s in every round | 15 489 / 14 928 / 15 170 / 15 758 / 15 396 | 4 181 / 4 301 / 4 239 / 3 917 / 4 196 | 0.21-0.33 s |
| C, 5/5 rounds | `DEGRADED` | 17 238 / 17 363 / 17 244 / 17 550 / 17 440 | 1 259 / 1 176 / 1 261 / 1 111 / 1 157 | 0.19-0.21 s |

- **The loss is now counted, and a flood reports `DEGRADED` within 1 s.** Before the counter, B
  stayed `HEALTHY` and about 70 % of the queries vanished uncounted.
- `events_dropped_total` exceeds the 10 000 queries sent. That is the documented mix of units: on
  `lo` both copies of a packet are queued and either can be dropped, and in B the lost ring-buffer
  records count as well. Read it as "the flood lost a lot", not as a query count.
- C has no ring-buffer records, so its count is capture drops alone; it emits fewer events and
  drops more packets, because every query costs a `/proc` lookup.

- Emission waits about 5 s because an unanswered query is emitted when the 11a tracker times it
  out (`TX_TIMEOUT` 5 s).
- **The kernel ring buffer loses about half of a 10 000-send burst.** The `dns` object's ring
  buffer is 256 KiB, about 2 340 records of 112 bytes (104 + 8 header). The reader thread resolves
  the sender's exe through `/proc` for every record before it takes the next one, and 10 000 sends
  arrive in about 0.1 s. A record that does not fit increments the `DROPS` counter, which is part of
  `events_dropped_total`, so the loss is counted. A query whose record was lost is emitted
  unattributed. The bench sends from one socket, so every send also lands on one send-table key,
  whose queue holds 8 entries: the bench is a worst case for attribution, and only the drop count is
  read from it.
- **Far fewer than 10 000 query events come out.** B emitted about 3 000 and C about 850 in the
  pre-counter run, and about 4 200 and 1 200 in the rerun. The likely cause is the `AF_PACKET`
  socket's receive queue overflowing while the capture loop falls behind. This is pre-existing
  from 11a. It is worse in C, where every query costs a `/proc` lookup. In the pre-counter run the
  loss was silent. Since the 11b-4 final fix the sensor reads the kernel's `PACKET_STATISTICS`
  (`tp_drops`, accumulated, read at most once a second and before the socket is closed) and adds
  it to `events_dropped_total`.
- **`events_dropped_total` mixes units.** It now adds ring-buffer records (lost or undecodable),
  capture packets (on `lo` the socket queues both copies of each packet, so one lost query can
  count twice) and failed channel sends. It shows that something was lost, not how many queries.
- **A flood now degrades the sensor when the capture socket drops.** `DEGRADED` from the capture
  side is reported for 60 s after parse errors, tracker overflow evictions (more than 4 096
  pending transactions) or capture-socket drops. In run 41326077476, before capture drops counted,
  nothing was emitted before the 5 s timeout and an overflow eviction is emitted at once, so the
  tracker evicted nothing: the capture saw fewer than 4 096 queries, and B stayed `HEALTHY` in 5/5
  rounds. The first run (41324827608) ended `DEGRADED` after its flood.

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

## Storage comparison: SQLite vs ClickHouse (Phase 11c)

Evidence for the ARCHITECTURE.md §10.2 / §79 requirement that the ClickHouse numbers are measured
before the backend is adopted. It is recorded, not acted on: the default stays SQLite (ADR-011).
This section is a different environment from the baseline above (GitHub Actions only, code
`ade5a60`), so its numbers are not comparable with the WSL tables. Every number comes from the
JSON lines in the `storage-bench` artifact (`storage-100k.jsonl`, `storage-1m.jsonl`,
`runner-facts.txt`). Latencies are in ms and rounded to two decimals; values under 0.1 ms are shown
to three decimals so they do not collapse to 0.01.

### Method

`osiris-bench` `storage_compare` (`crates/osiris-bench/src/storage_compare.rs`). Per backend and
size it runs 5 rounds. Each round fills a fresh store through `batch_write` in batches of 1 000
events, then times five query shapes, 20 samples each. The same pre-generated events feed both
backends and every round, so generation cost is outside the ingest timing and both backends see
identical data. Reported values are medians across the rounds. A warm-up call of each shape before
sampling hard-fails the run if the shape returns no rows (commit `8da1742`, after the measured
run's code `ade5a60`), so the bench now guarantees that every latency is for a query that found
data. The run reported here predates that check.

| Shape | What it runs |
|---|---|
| `host_window` | `query_events` with one `host_id` and a `since`/`until` window |
| `event_type` | `query_events` with `event_type = "PROCESS_EXEC"` |
| `process_key` | `query` with a `process_key` |
| `residual` | `query_events` with `event_type = "PROCESS_EXEC" AND process.pid = <n>` (the pid part is a residual predicate, re-checked in Rust) |
| `get_event` | `get_event` by id |

`noise_pct` is (max - min) / median of the per-round values over the 5 rounds. It is the noise
envelope. A difference smaller than the envelope of either side is reported as "no measurable
difference".

### Environment

| Item | Value |
|---|---|
| Run | GitHub Actions run 41362219110, workflow `storage-bench.yml`, branch `storage-bench/t11c-1` @ `ade5a60` |
| Runner | `ubuntu-24.04` hosted runner, Ubuntu 24.04.5 LTS, kernel 7.0.0-1017-azure |
| CPU / RAM | INTEL(R) XEON(R) PLATINUM 8573C, 4 vCPU / 15 GiB |
| ClickHouse | `clickhouse/clickhouse-server:26.3.60.2`, version 26.3.60.2, a service container on the same runner (loopback only, no network hop) |

### Results, 100 000 events

| Metric | SQLite | ClickHouse | SQLite noise | ClickHouse noise |
|---|---|---|---|---|
| Ingest (events/s) | 12 203.53 | 12 079.05 | 3.51 % | 1.05 % |
| Footprint (bytes/event) | 2 076.41 | 126.35 | n/a | n/a |
| `host_window` p50 / p95 (ms) | 2.27 / 2.57 | 21.92 / 25.13 | 1.23 % | 5.12 % |
| `event_type` p50 / p95 (ms) | 4.46 / 4.61 | 202.30 / 238.93 | 1.84 % | 15.02 % |
| `process_key` p50 / p95 (ms) | 0.019 / 0.030 | 8.18 / 9.27 | 7.40 % | 8.60 % |
| `residual` p50 / p95 (ms) | 6.42 / 6.62 | 205.66 / 242.40 | 0.75 % | 12.64 % |
| `get_event` p50 / p95 (ms) | 0.006 / 0.009 | 5.35 / 5.89 | 3.24 % | 11.58 % |

The ingest difference is 1.0 % (12 203.53 vs 12 079.05), inside both noise envelopes: no
measurable difference at 100 000 events. Footprint has no noise figure (one value per size).

### Results, 1 000 000 events

| Metric | SQLite | ClickHouse | SQLite noise | ClickHouse noise |
|---|---|---|---|---|
| Ingest (events/s) | 8 781.99 | 10 968.06 | 1.94 % | 0.48 % |
| Footprint (bytes/event) | 2 004.45 | 138.98 | n/a | n/a |
| `host_window` p50 / p95 (ms) | 2.28 / 2.48 | 133.18 / 163.29 | 3.93 % | 6.57 % |
| `event_type` p50 / p95 (ms) | 4.46 / 4.65 | 294.23 / 320.10 | 2.00 % | 2.10 % |
| `process_key` p50 / p95 (ms) | 0.011 / 0.017 | 5.63 / 6.49 | 1.91 % | 7.04 % |
| `residual` p50 / p95 (ms) | 6.43 / 6.58 | 298.38 / 317.49 | 1.15 % | 1.06 % |
| `get_event` p50 / p95 (ms) | 0.006 / 0.012 | 4.44 / 5.08 | 2.81 % | 8.70 % |

### What the numbers say

- **Footprint.** ClickHouse stores an event in 126.35 bytes at 100 000 events and 138.98 bytes at
  1 000 000; SQLite needs 2 076.41 and 2 004.45. That is 16.43 times smaller at 100 000 events and
  14.42 times smaller at 1 000 000 (ratios computed from the table values).
- **Ingest.** At 100 000 events there is no measurable difference (above). At 1 000 000 events
  ClickHouse ingests 10 968.06 events/s against 8 781.99 for SQLite, 24.9 % more, which is far
  outside both envelopes (1.94 % and 0.48 %). SQLite's rate fell from 12 203.53 to 8 781.99 between
  the two sizes; ClickHouse's from 12 079.05 to 10 968.06.
- **Queries.** At both sizes every shape is slower on ClickHouse. ClickHouse p50 divided by SQLite
  p50 is 9.7 (`host_window`), 45.4 (`event_type`), 422 (`process_key`), 32.0 (`residual`) and 902
  (`get_event`) at 100 000 events, and 58.3, 66.0, 533, 46.4 and 730 at 1 000 000. Every gap is far
  larger than the noise envelopes. The two ClickHouse shapes that filter with a scan
  (`event_type`, `residual`) went from about 200 ms to about 300 ms between the sizes, and
  `host_window` from 21.92 ms to 133.18 ms. SQLite's `host_window`, `event_type` and `residual`
  p50 did not change between sizes (2.27 to 2.28, 4.46 to 4.46, 6.42 to 6.43 ms).

### Caveats

- **`host_window` and `event_type` measure limit-capped scans, not full scans.** Both go through
  `query_events`, which applies the plan limit (`DEFAULT_EVENT_LIMIT`, 500). On SQLite the query
  stops after 500 rows, so its cost does not grow with the table; that is why SQLite's
  `host_window` is flat from 2.27 ms to 2.28 ms between 100 000 and 1 000 000 events. The limit
  does not bound the scan cost on ClickHouse: its `host_window` grew from 21.92 ms to 133.18 ms
  and its `event_type` from 202.30 ms to 294.23 ms across the same sizes. This bench does not
  explain that growth (the cause was not isolated). These shapes say nothing about a query that
  has to read the whole table or a large part of it, which is where a column store is expected
  to do better.
- **Footprint is measured differently per backend.** SQLite's number is the main database file
  plus its `-wal` file, measured without a checkpoint, so it includes WAL pages not yet merged.
  ClickHouse's number is `disk_bytes()` after `OPTIMIZE TABLE events FINAL`, so parts are merged.
  Each is the bench's best number for that side, not an identical procedure.
- **One runner, one run of 5 rounds.** There is no run-to-run comparison, and the noise envelope
  covers only the rounds inside this run. ClickHouse ran as a local service container, so the
  figures contain no network latency beyond loopback.
- **Single worker thread.** The ClickHouse backend serialises all requests on one worker thread,
  the same model as SQLite's `Mutex<Connection>`. The bench issues one request at a time, so this
  run does not measure queueing under concurrent readers.
- **Shapes are checked for rows, not compared for equality.** Result equality between the two
  backends is proven by the conformance suite, not by the bench.
- SQLite's `process_key` p50 is 0.019 ms at 100 000 events and 0.011 ms at 1 000 000. That is
  outside its own noise envelopes (7.40 % and 1.91 %), and this run does not explain it.

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
tools/real-linux/bench.sh --agent-only /tmp/bench-agent.jsonl   # includes the fs loop and dns-send
# The fs loop alone (OSIRIS_BPF_DIR must point at the built objects):
$CARGO_TARGET_DIR/release/osiris-bench fs-loop --iterations 10000
# The DNS send bench alone (OSIRIS_BPF_DIR as above; binds 127.0.0.1:53 and :5300; starts 15 agents):
$CARGO_TARGET_DIR/release/osiris-bench dns-send --sends 10000
# Storage comparison, SQLite vs ClickHouse (push a storage-bench/** branch; the workflow starts ClickHouse):
git push origin HEAD:refs/heads/storage-bench/<name>   # .github/workflows/storage-bench.yml
# Single configurations:
$CARGO_TARGET_DIR/release/osiris-bench ingest --rate 1000 --duration 30
```

`bench.sh` builds release binaries into `$CARGO_TARGET_DIR` (default `/root/osiris-target`) and
prints one JSON line per configuration.
