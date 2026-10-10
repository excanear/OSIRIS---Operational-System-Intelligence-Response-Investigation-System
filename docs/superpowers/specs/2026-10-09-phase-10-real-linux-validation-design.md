# Phase 10 — Real-Linux Validation, Benchmarks, Browser Check (design)

Status: approved in brainstorming 2026-10-09. Roadmap: `docs/ROADMAP-REMAINING.md` §"Fase 10".

## 1. Goal

Until now every OSIRIS test has run against synthetic inputs (canned audit lines, fake `/proc`
trees, in-process Agent/Server wiring) and the Console has never been opened in a browser.
Phase 10 closes that gap:

1. **Real-Linux validation harness** — the production `osiris-server` and `osiris-agent`
   binaries, configured by real YAML files, running against a real kernel + real `auditd`,
   driven by real user-space actions; assertions made through the real authenticated API.
2. **First benchmark pass** (ARCHITECTURE.md §19.2) — an `osiris-bench` binary that measures
   throughput, end-to-end latency, Agent CPU/RSS and query latency and writes `PERFORMANCE.md`.
3. **Browser check** — a persistent Playwright suite for the Console plus one manual visual pass.

Bugs found by (1) and (3) are fixed in this phase, each with a regression test.

## 2. Scope

In scope:

* Environments: WSL2 **Ubuntu-24.04** (already provisioned: systemd on, kernel 6.18 with
  `CONFIG_AUDIT`, rustup+gcc) and **Debian** imported into WSL (whatever release the WSL store
  ships — recorded in the validation report). Same WSL kernel, different user lands (auditd
  version, systemd version, paths, default shells).
* Scenarios: process exec, file create/write/rename/delete, network connect, sudo
  (identity/privilege), systemd unit start, persistence-path writes.
* Benchmarks at 1K and 10K events/s; a 100K events/s attempt whose result is recorded as-is.
* Playwright smoke for every Console screen.

Out of scope (recorded as debt in the roadmap):

* Container and Kubernetes scenarios (need Docker/kind — not installed; deferred).
* RHEL-like distributions.
* New CI gates. CI keeps `perf_smoke` as its only perf check; the real-Linux suite, the bench
  and Playwright run locally/WSL. A CI job for Playwright is a follow-up.
* eBPF (Phase 11).
* DNS: no real DNS sensor exists (DNS events are synthetic-only); real DNS capture needs
  eBPF/packet capture and is Phase 11 debt.

## 3. Real-Linux validation harness

### 3.1 Layout

```text
crates/osiris-real-linux-tests/       new crate, publish = false, no lib code shipped
  Cargo.toml                          deps: reqwest (blocking), serde_json, tempfile, uuid,
                                      osiris-auth, osiris-transport (pki), osiris-command
                                      (keys), osiris-config (HostIdentity), osiris-generator,
                                      osiris-pipeline, osiris-schema
  src/lib.rs                          the harness library (config rendering, PKI, users,
                                      process spawning, API polling) — dev tooling only
  src/bin/osiris-stack.rs             seeded server for the Console Playwright suite (§5.1)
  tests/real_linux.rs                 scenarios; every test #[ignore] + #[cfg(target_os="linux")]
tools/real-linux/
  setup.sh                            idempotent: apt install auditd (+ curl, sudo),
                                      enable/start auditd, load osiris.rules, sanity check
  osiris.rules                        audit rules the sensors depend on (execve, file syscalls
                                      on watched dirs, identity/USER_* is default, systemd)
  run.sh                              builds release binaries, runs
                                      `cargo test -p osiris-real-linux-tests -- --ignored
                                      --test-threads=1`, must run as root
```

The crate is a workspace member so clippy/fmt cover it; on non-Linux it compiles to an empty
test binary. `tools/check-dep-graph.sh` gets an entry allowing it to depend on the crates above.

### 3.2 Harness (`harness::Stack`)

`Stack::start(opts)`:

1. Creates a temp dir; writes PKI via `osiris_transport::pki` (CA, server cert for
   `127.0.0.1`/`localhost`, agent cert for the host id the Agent binary will use — it reads/creates
   `/etc/osiris/host_id`, so the harness calls `HostIdentity::load_or_create` on that path first) and a command signing key.
2. Pre-creates `users.db` with `SqliteUserStore::open`, takes the bootstrap admin and mints a
   session token (server opens the same file — this is how the harness authenticates without
   scraping stdout).
3. Writes `server.yaml` (API on `127.0.0.1:<free port>`, agent listener, control listener,
   rules dir = repo `config/rules`, risk weights = repo `config/risk/weights.yaml`, all DBs in
   the temp dir) and `agent.yaml` (forward + control to the server, `audit_log_path` /
   `fs_audit_log_path` / `identity_audit_log_path` / `systemd_audit_log_path` =
   `/var/log/audit/audit.log`, `proc_root=/proc`, persistence watch on a temp dir and on
   `/etc/systemd/system`, synthetic off).
4. Spawns `target/release/osiris-server` then `target/release/osiris-agent` with
   `Command`, stdout/stderr captured to files in the temp dir (dumped on test failure).
5. Waits (bounded, 30 s) for `GET /api/v1/health` and for the host to appear in
   `GET /api/v1/hosts`.

`Drop` kills both children (`Child::kill` + `wait`) and keeps the temp dir when the
test panicked (path printed) for post-mortem. The harness is synchronous (blocking reqwest);
server-only mode works on every OS (the Console stack uses it), Agent mode is Linux-only.

Helpers: `stack.api_get(path) -> serde_json::Value`, and
`stack.wait_for(path, deadline, predicate)` — bounded poll (250 ms) that panics with the last
body plus the tail of both process logs.

### 3.3 Scenarios (one `#[ignore]` test each)

Each action carries a unique marker (random token in a file name, argv or hostname) so a
test can find *its* event among everything else the real host is doing.

| Test | Real action | Asserted via API |
|---|---|---|
| `exec_is_observed` | spawn `/bin/sh -c "true <marker>"` | `/api/v1/processes` has the exe + argv containing marker, correct ppid chain |
| `file_lifecycle_is_observed` | create, write, rename, delete `<tmp>/<marker>` | `/api/v1/files` shows create/write/rename/delete for one file identity |
| `network_connect_is_observed` | test binds a listener on a random loopback port; a child `bash` opens `/dev/tcp/127.0.0.1/<port>` and holds it ~6 s (the sensor polls `/proc/net/tcp`, so the connection must outlive a poll) | a `NETWORK_CONNECT` event with `dst_port == <port>` |
| `sudo_is_observed` | `sudo -u nobody true` as root, `su` login of a throwaway user created by the test | identity/privilege events in `/api/v1/events` for the session |
| `systemd_unit_start_is_observed` | write + start a transient unit `osiris-<marker>.service` (`/bin/true`), then remove it | systemd service-start event for the unit |
| `persistence_write_is_observed` | write a file into the watched persistence dir | persistence event for that path |
| `web_root_drop_raises_an_alert` | `bash -c 'echo x > /var/www/osiris-<marker>.php'` (rule `shell_wrote_file_to_web_root` matches the fixed prefix `/var/www/`; `osiris.rules` watches `/var/www`; the test removes the file) | `/api/v1/alerts` has the rule's alert for the file |
| `agent_reports_healthy_sensors` | none | `/api/v1/hosts` row has real distro + kernel strings (today `main.rs` hard-codes `"unknown"` — a known finding fixed in this phase by reading `/etc/os-release` `PRETTY_NAME` and `/proc/sys/kernel/osrelease`); the latest `AGENT_HEALTH` event lists every configured sensor as healthy |

The alert test is the only detection-level check; the others validate sensors end to end.
Known suspect it is expected to surface: on merged-`/usr` distros the kernel reports the
resolved exe (`/usr/bin/bash`, `/usr/bin/dash`), not `/bin/sh`/`/bin/bash` as the rule lists —
exactly the synthetic-vs-real gap this phase exists to find.
Rules whose trigger needs a remote session (ssh) are not exercised (no sshd in scope).

### 3.4 Discover-and-fix loop

Running the suite on each distro is expected to fail in places the synthetic tests never
reached (audit record shapes, field encodings, timing, paths). For every failure:

1. Capture the real raw input (audit lines / `/proc` content) into a fixture under the owning
   sensor crate's tests.
2. Add a failing unit test against that fixture in the sensor crate (runs in normal CI on any
   OS).
3. Fix; re-run the real-Linux test.

A finding whose fix is larger than roughly one plan task is documented in
`docs/VALIDATION.md` and the roadmap as debt instead of being fixed here.

### 3.5 Report

`docs/VALIDATION.md`: per distro — distro/kernel/auditd/systemd versions, date, the pass/fail
table of §3.3, findings (fixed with commit refs / deferred), and how to reproduce
(`tools/real-linux/setup.sh && tools/real-linux/run.sh`).

## 4. Benchmarks

### 4.1 `osiris-bench`

New bin crate `crates/osiris-bench` (publish = false), subcommands:

* `pipeline --events N` — in-process `Pipeline::process` throughput (events/s), the
  `perf_smoke` measurement made larger and reported precisely.
* `ingest --rate R --duration S` — starts the real `osiris-server` binary (same config
  generation as the harness — the harness module is reused through a small shared config
  module, see §4.3) and a **load driver** that pushes `CanonicalEvent`s produced by the real
  `Pipeline` into a spool file at a paced rate, shipped by the real
  `osiris_transport::client::run_forwarder` over mTLS. Reports achieved rate, server-side
  backlog at the end, and **end-to-end latency p50/p95/p99**: one marker event per 100 ms
  is stamped with its send time; a sampler opens `events.db` read-only and records when each
  marker becomes queryable.
* `agent --rate R --duration S` — starts the real Agent against real auditd and generates real
  kernel load: an exec storm (`/bin/true` at the target rate from a pacing loop). Samples the
  Agent PID's CPU (utime+stime deltas from `/proc/<pid>/stat`) and RSS (`/proc/<pid>/status`
  `VmRSS`) once per second; reports idle (rate 0) and loaded mean/max. Linux-only.
* `query --events N` — fills a fresh SQLite store with N events (10K, 100K, 1M), then times
  representative API-backing queries (process list, event search with filter, graph subgraph)
  — median of 5 runs each.
* `all` — runs the standard matrix and emits a markdown table.

Each run prints JSON lines (machine-readable) and a markdown summary. `ingest`/`agent` at
100K events/s are run once; if the achieved rate falls short, the shortfall is the result.

### 4.2 PERFORMANCE.md

Repo-root `PERFORMANCE.md` (ARCHITECTURE.md §19.2 names it): methodology, hardware (CPU model,
cores, RAM), environment (WSL2 kernel, distro, build profile), the results table, and an
honest interpretation (WSL2 caveats: virtualised I/O, shared host). Numbers are measurements,
not SLOs.

### 4.3 Sharing between harness and bench

Config/PKI generation and process spawning live in `osiris-real-linux-tests`' `harness`
module as a library; `osiris-bench` depends on that crate. (Both are dev tooling; nothing in
the shipped binaries depends on either.)

## 5. Browser check

### 5.1 Playwright suite

* `console/e2e/` with `@playwright/test` (devDependency) and `console/playwright.config.ts`,
  Chromium only, `npm run e2e`.
* `console/e2e/global-setup.ts` spawns `osiris-stack` (the harness's server-only mode, any OS):
  it starts the real `osiris-server` on port 8080 (the port Vite's proxy targets), seeds data by
  pushing every generator scenario (exec chain, web shell drop, network beacon, download then
  write, ssh/sudo escalation, systemd persistence, container deploy) through the real
  `Pipeline` into the server's spool file so alerts and incidents exist, and writes
  `{base_url, username, password}` (the bootstrap admin) to a JSON file the specs read.
  Playwright's `webServer` starts `vite preview` (built console, `/api` proxied to the
  server). Teardown kills the stack.
* One spec per screen: login, overview, alerts, incidents, processes (+ process story), files,
  network, containers, graph, timeline, hunting, evidence, live events, hosts (+ host policy),
  groups (+ group policy editor), sensors. Each spec asserts: the screen's main heading and at
  least one seeded row/node render, no `console.error`, no failed request (status >= 400 or
  network error), and a full-page screenshot is attached to the report.
* Vitest stays as is; Playwright specs live outside `src/` so Vitest does not pick them up.

### 5.2 Visual pass

A manual pass (Playwright MCP) over every screen at desktop and a narrow width, recording
layout/UX defects in `docs/VALIDATION.md` §Console. Defects that are bugs (broken render,
wrong data, crash) are fixed with a Vitest or Playwright regression test; cosmetic items
become Phase 13 UX debt.

## 6. Error handling and robustness of the tooling

* Harness and bench never hang: every wait is bounded and failure output includes both
  process logs.
* `run.sh` and `setup.sh` refuse to run without root and say why; `setup.sh` is idempotent.
* Real-Linux tests are serial (`--test-threads=1`): they share the single system audit log.
* Tests tolerate unrelated host activity by filtering on markers, never on counts.

## 7. Testing of the new code

* Harness helpers with non-trivial logic (config rendering, marker matching, log tailing)
  get plain unit tests that run on every OS.
* `osiris-bench` statistics (percentiles, rate pacing math, `/proc` stat parsing) get unit
  tests with fixtures.
* The scenario tests are themselves the validation; they are `#[ignore]` so `cargo test
  --workspace` stays green on Windows and in CI.

## 8. Deliverables / done criteria

1. `osiris-real-linux-tests` + `tools/real-linux/` exist; the full suite passes on Ubuntu-24.04
   and Debian in WSL (or each remaining failure is a documented deferred finding).
2. Every fixed finding has a regression test that runs in normal CI.
3. `osiris-bench` exists; `PERFORMANCE.md` holds the first measured matrix.
4. `npm run e2e` passes against the seeded stack; visual-pass findings recorded and bugs fixed.
5. `docs/VALIDATION.md` written; `docs/ROADMAP-REMAINING.md` updated (Phase 10 done, debts
   listed: container/k8s scenarios, RHEL-like, CI jobs for real-Linux/Playwright).
6. `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`,
   `cargo test --workspace`, console lint/test/build all green.
