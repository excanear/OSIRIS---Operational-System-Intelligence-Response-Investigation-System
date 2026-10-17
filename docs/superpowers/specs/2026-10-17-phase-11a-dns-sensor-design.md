# Phase 11a — Real DNS sensor (passive AF_PACKET capture)

Status: design, 2026-10-17. Phase 11 is split into three independent sub-projects run in this
order: **11a real DNS sensor** (this document), 11b eBPF/CO-RE sensors, 11c ClickHouse storage.
The user asked to proceed with the recommended option for every choice; every decision below
that is not dictated by `ARCHITECTURE.md` or existing code is the designer's call and is marked
*(call)*.

## 1. Intent

Today OSIRIS has no real DNS telemetry: `RawEvent::Dns` is produced only by the synthetic
generator (`network_beacon` scenario), so `config/rules/dns_query_to_suspicious_tld.yaml`, the
`ResolvedTo` domain→IP graph edges, the `(exe, domain)` baseline and the network story
(`/network/{ip_or_domain}/story`) only ever work on fixtures. Phase 10 recorded this as debt
(`docs/ROADMAP-REMAINING.md`, "captura real de DNS"). 11a adds the fallback DNS backend that
`ARCHITECTURE.md` §4 table (row "DNS") names — passive packet capture on port 53 — so those
downstream features work on a real host. The eBPF uprobe backend for resolver libraries is
11b's business, not this one.

Success: on a real Ubuntu host (GitHub Actions runners, as in Phase 10), `curl http://<marker>.xyz/`
produces a stored `DNS_QUERY` event whose `dns.query` is `<marker>.xyz` and whose
`process.exe_path` is curl, and the existing TLD rule raises its alert — with no synthetic sensor.

## 2. Goals

1. New sensor crate `crates/osiris-sensors/dns` (package `osiris-sensors-dns`) implementing the
   existing `Sensor` trait, mirroring the layout of `osiris-sensors-net` (pure, OS-neutral parsing
   modules + a thin Linux-only capture module).
2. Passive capture of **UDP port 53** traffic (IPv4 and IPv6) on all interfaces including `lo`,
   via an `AF_PACKET` socket (`SOCK_DGRAM`, `ETH_P_ALL` — cooked L3 frames, so `lo`, Ethernet
   and tunnel links all look the same) *(call: `SOCK_DGRAM` over `SOCK_RAW` to avoid per-link
   header parsing)*, using `libc` directly (already in the lockfile; no new third-party crate
   for capture or DNS parsing) *(call)*.
3. A classic-BPF socket filter (`SO_ATTACH_FILTER`) that admits only IPv4/UDP and IPv6/UDP
   (next-header directly UDP) packets with source or destination port 53, so a busy host does
   not copy all traffic to user space. IPv6 packets with extension headers before UDP are not
   admitted (documented limit) *(call)*.
4. An own DNS wire-format parser (header, question, answer RRs, name compression with a loop
   guard and length limits). Hostile/malformed packets are counted and dropped, never panic.
5. Transaction pairing: a query (client port ≠ 53 → server port 53) opens a pending
   transaction keyed by `(client ip, client port, server ip, DNS id)`; the matching response
   closes it and emits **one** `RawEvent::Dns` with `query`, `qtype`, `response_ips` (A/AAAA
   answers), `ttl` (minimum TTL among A/AAAA answers). A transaction without a response after
   **5 s** emits with empty `response_ips` and `ttl: None` (the existing `DnsEventRaw` contract
   already says an empty list means NXDOMAIN or timeout). Pending table bounded at **4096**
   entries; on overflow the oldest is emitted as a timeout and a counter increments *(calls:
   5 s, 4096)*. A response with no pending query (e.g. the sensor started mid-flight) is
   counted and dropped.
6. `qtype` rendered as the standard mnemonic for common codes (A, AAAA, CNAME, MX, TXT, NS, PTR,
   SOA, SRV, HTTPS, SVCB, ANY), otherwise `TYPE<n>`. Only the first question of a message is
   used (real resolvers send exactly one).
7. Best-effort process attribution at **query** time: look up the client's local UDP port in
   `/proc/net/udp` and `/proc/net/udp6` (new parser, same column format as the existing
   `proc_tcp.rs`) → socket inode + uid; map inode → pid with the existing
   `osiris_sensors_net::fd_scan::scan_socket_inodes`, and pid → `(exe_path, comm)` with
   `read_process_identity`. The inode→pid map is cached and rescanned on a miss at most once
   per **250 ms** *(call)*. Attribution failure leaves `pid: None`, `exe_path`/`comm` empty and
   `uid` from the UDP table when known (else 0) — never blocks or drops the event. Queries whose
   client is not local (the host is a resolver for others) get no attribution, naturally.
8. Agent wiring: new config key `dns_capture: Option<DnsCaptureConfig>` (`#[serde(default)]`, so
   every existing YAML config still loads; absent = sensor not configured, consistent with the
   other `Option` keys); `DnsCaptureConfig { interface: Option<String> }` where `None` = all
   interfaces *(call)*. `build_sensor` arm + `STARTUP_ORDER` entry `"dns"` (last). Proc root
   reuses the agent's existing `proc_root`.
9. `capabilities()`: on Linux, probe by opening and closing the `AF_PACKET` socket — success →
   supported; `EPERM`/`EACCES` → `unsupported_reason: "AF_PACKET needs CAP_NET_RAW"`. On
   non-Linux → unsupported with a clear reason. So an unprivileged agent skips the sensor
   visibly (`SkippedSensor`), never silently.
10. Health/metrics: `Healthy` while capturing; `Degraded` if the parse-error rate or pending
    overflow is non-zero in the last minute *(call)*; `Failed` if the socket errors
    persistently (retry with backoff, as other sensors do). Metrics: packets seen, parse errors,
    transactions emitted, timeouts, unmatched responses, overflow evictions, attribution
    hits/misses.
11. Fleet policy: add `"dns"` to `osiris-policy` `KNOWN_SENSORS` so `sensors: {dns: false}` works
    at startup and at runtime like the other seven; update every test that today asserts
    `"dns"` is an unknown sensor (in `osiris-api`, `osiris-fleet`, `osiris-command`,
    `osiris-agent`). The policy hash golden vectors from 9d-3 must stay byte-identical for
    existing policies (adding a name to the allow-list must not change the encoding) — verify.
12. Schema provenance: add a raw source variant for packet capture (`RawEventSource::Packet`)
    and the matching canonical `Source` value (wire name `PACKET`) wherever the source enum is
    defined/serialised/displayed (schema, storage round-trip, console type union if it is a
    closed union); `normalize_dns_event` maps it to provider `dns_sensor/af_packet` and the
    "unreachable today" comment is updated.
13. Tests:
    - OS-neutral unit tests with byte fixtures: DNS parser (A, AAAA, CNAME chain, NXDOMAIN,
      compression, compression loop, truncated/oversized names, bogus counts), IPv4/IPv6/UDP
      frame decoding, transaction tracker (match, timeout, overflow, unmatched response,
      id reuse on a different port), `/proc/net/udp{,6}` parser, qtype mnemonics, config
      back-compat (old YAML without the key loads).
    - At least one fixture captured from a real Ubuntu run committed under
      `crates/osiris-sensors/dns/tests/fixtures/` and replayed through the packet→event path
      (Phase 10 Global Constraint #8 style: real findings get OS-neutral regression tests).
    - Real-Linux scenario in `crates/osiris-real-linux-tests/tests/real_linux.rs`
      (`#[ignore]`, Linux-only, root, marker-based): `curl` to `http://<marker>.xyz/` → wait for a
      `DNS_QUERY` with `dns.query` = `<marker>.xyz` and `process.exe_path` ending in `curl`, and
      for the `dns_query_to_suspicious_tld` alert. Harness renders `dns_capture: {}` into the agent
      config (`render.rs`, `AgentOptions`). Runs on `.github/workflows/real-linux.yml`
      (ubuntu-22.04 + 24.04), which already runs as root.
14. Docs: `ARCHITECTURE.md` DNS row/section status note (AF_PACKET backend implemented, uprobe
    pending 11b); `docs/VALIDATION.md` DNS entry with the GH run id; `docs/ROADMAP-REMAINING.md`
    marks the DNS debt done; operator note on `docs/operators-fleet-policy.md` about the `dns`
    sensor switch and the privilege (CAP_NET_RAW) requirement.

## 3. Non-goals

- DNS over TCP, DoT (853), DoH, mDNS/LLMNR (5353/5355) — later work; documented as blind spots.
- eBPF uprobes on libc/resolver libraries — Phase 11b.
- A `GET /api/v1/dns` route or a Console DNS screen (ARCHITECTURE lists the route; it stays
  unimplemented) — the events are already queryable via `/api/v1/events?event_type=DNS_QUERY`.
- FORENSIC raw-payload capture.
- Changing `DnsRef`/`DnsEventRaw` fields (no rcode, no resolver address, no CNAME chain in the
  schema) — keeps storage and console untouched beyond the source enum.
- Privilege dropping / capability-only agent operation.
- Changing the telemetry level at which `DNS_QUERY` is admitted (code says STANDARD; ARCHITECTURE
  says DETAILED). Code behaviour is kept; ARCHITECTURE gets a one-line note of the discrepancy
  *(call — changing it would silently drop DNS for existing STANDARD fleets)*.

## 4. Anti-goals (would be a failure even if it "works")

- Any panic, unbounded allocation or unbounded loop on attacker-controlled packet bytes.
- Blocking the async runtime: capture runs on a dedicated blocking thread
  (`spawn_blocking`/std thread) with a receive timeout (≤ 500 ms) so cancellation is observed;
  events go out through the existing `mpsc` sender.
- Capturing or storing payloads beyond the parsed fields.
- Making `cargo test --workspace` on Windows or CI depend on root, a network or Linux.
- A silent no-op: an unsupported/unprivileged sensor must appear as skipped/failed in health.

## 5. Known behaviour to document (not fix)

- On hosts using systemd-resolved (Ubuntu default) each lookup appears twice: app → 127.0.0.53
  on `lo` (attributed to the app) and systemd-resolved → upstream (attributed to
  systemd-resolved). Both events are emitted; they are both true. The TLD rule filters by exe,
  so it fires once.
- Attribution is racy for clients that close the socket before the sensor processes the query
  packet; such events carry no process.
- The baseline `(exe, domain)` key requires a process, so unattributed events do not feed it.

## 6. Constraints carried from earlier phases

- Configs are YAML; binaries take the config path as `argv[1]`.
- Before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `bash tools/check-dep-graph.sh` (add the `osiris-sensors-dns` forbidden
  line like its siblings), console `npm run lint && npm test && npm run build`.
- No new CI gates; real-Linux runs on GH Actions by pushing to `real-linux/<name>` (this host has
  no WSL/Docker; the user runs `git push`/branch deletes when the auto-mode classifier blocks them).
- Real-Linux tests: `#[ignore]`, `#[cfg(target_os = "linux")]`, serial, root, bounded waits with
  logs on timeout, unique markers.

## 7. Left to the builder

Module split inside the crate, exact cBPF program bytes, backoff constants, metric names,
how the pending table is ordered for eviction, and the exact wording of docs — within the
constraints above.
