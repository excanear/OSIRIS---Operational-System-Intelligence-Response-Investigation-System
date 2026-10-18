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
- DNS over TCP, DoT, DoH and mDNS are not captured. The eBPF resolver uprobe is Phase 11b.

## eBPF process backend (Phase 11b-1)

The eBPF engine (`crates/osiris-ebpf`) and the eBPF exec/exit backend of `process_exec` were
validated on GitHub Actions run 39139529617 (commit `e5becff`, branch `real-linux/t11b1-1`),
green on `ubuntu-22.04` (kernel 5.15) and `ubuntu-24.04` (6.x) on the first run. The object was
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

- Not covered: kernels other than 5.15 and 6.x, RHEL-like distributions, a kernel-version VM
  matrix (ARCHITECTURE §26).
- When a non-leader thread calls `execve`, the old thread-group leader's exit is reported as a
  `PROCESS_EXIT` with signal 9 for a process that keeps running, then an `EXEC` under the same pid.
- Exit `exe_path` is often empty (the process is already gone). argv can be empty when the page is
  not resident at read time.
- A ring-buffer reservation failure increments the drop counter, reported as
  `events_dropped_total`. Not provoked in validation.
- With `ebpf` configured but no `audit_log_path`, an eBPF failure makes the sensor `FAILED`.
- `PROCESS_FORK` is not emitted. See `docs/operators-ebpf.md`.

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
- eBPF covers only process exec/exit (Phase 11b-1); network, filesystem and the DNS uprobe are pending (11b-2..4).
