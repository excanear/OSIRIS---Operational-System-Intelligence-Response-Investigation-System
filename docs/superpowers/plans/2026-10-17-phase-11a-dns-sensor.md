# Phase 11a — Real DNS Sensor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A real, passive DNS sensor (`osiris-sensors-dns`) that captures UDP/53 on Linux via AF_PACKET, pairs queries with responses, attributes them to local processes, and emits `RawEvent::Dns` so the existing DNS rule, graph edges, baseline and network story work on real hosts.

**Architecture:** OS-neutral modules (DNS wire parser, L3/UDP frame decoder, transaction tracker, `/proc/net/udp{,6}` attribution, a packet→event engine) are unit-tested on any OS with byte fixtures; a thin `#[cfg(target_os = "linux")]` capture module owns the AF_PACKET socket and runs on a blocking thread feeding the engine. The agent wires it through a new `dns_capture` config key and a new `"dns"` fleet-policy sensor name.

**Tech Stack:** Rust (workspace, tokio, async-trait), `libc` (Linux-only target dep, already in Cargo.lock), existing `osiris-sensor-api`, `osiris-sensors-net::fd_scan`. No new third-party crates.

**Spec:** `docs/superpowers/specs/2026-10-17-phase-11a-dns-sensor-design.md`

## Global Constraints

1. No new third-party crates. `libc = "0.2"` only under `[target.'cfg(target_os = "linux")'.dependencies]`.
2. All parsing of packet bytes is panic-free and bounded: name ≤ 255 bytes, label ≤ 63, ≤ 16 compression jumps, ≤ 64 answer RRs inspected, ≤ 4096 pending transactions.
3. Transaction timeout **5 s**; on timeout emit with `response_ips: []`, `ttl: None`.
4. Attribution rescan at most once per **250 ms**; failure → `pid: None`, empty `exe_path`/`comm`, `uid` from the UDP table or 0.
5. Capture thread receive timeout ≤ **500 ms**; capture never runs on the async runtime's worker threads.
6. Provider string `dns_sensor/af_packet`; raw source `RawEventSource::Packet`; canonical `Source::Packet` (serde wire `PACKET`).
7. Config: `dns_capture: Option<DnsCaptureConfig>` with `#[serde(default)]`; `DnsCaptureConfig { interface: Option<String> }` (`None` = all interfaces). Old YAML without the key must load.
8. Sensor name (`Sensor::name`, `STARTUP_ORDER`, `KNOWN_SENSORS`) is exactly `"dns"`.
9. Real-Linux tests: `#[ignore]`, `#[cfg(target_os = "linux")]`, serial, root, bounded waits, unique markers; run on GH Actions (`.github/workflows/real-linux.yml`) by pushing to `real-linux/<name>`. This Windows host has no WSL/Docker/gh CLI; poll runs via `https://api.github.com/repos/excanear/OSIRIS---Operational-System-Intelligence-Response-Investigation-System/actions/runs`. If the auto-mode classifier blocks a push, report it — the user runs it.
10. Before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `bash tools/check-dep-graph.sh`, console `npm run lint && npm test && npm run build`.
11. No new CI gates. `DNS_QUERY`'s telemetry level (STANDARD in code) is not changed.

## Review Focus

1. **Socket bound to `0.0.0.0`/`::` (most resolvers' clients)** — a query from `127.0.0.1:41000` must attribute to the row `00000000:A028`. Task 5 test `wildcard_bound_socket_matches`.
2. **Retransmitted query (same key twice before the answer)** — must yield one event, not two, and not a spurious timeout. Task 4 test `retransmit_keeps_single_transaction`.
3. **Response with only CNAME / zero A-AAAA answers, or NXDOMAIN** — emitted immediately with empty `response_ips`, never waits for the timeout. Task 4 test `cname_only_response_completes_immediately`.
4. **IPv4 fragments and IPv6 extension headers** — non-first fragments and non-UDP next-headers are ignored, not misparsed. Task 3 tests `ipv4_non_first_fragment_ignored`, `ipv6_extension_header_ignored`.
5. **Unprivileged or non-Linux agent** — the sensor is reported unsupported with a reason, never silently idle. Task 7 tests `eperm_maps_to_cap_net_raw_reason` and (non-Linux) `capabilities_unsupported_off_linux`.

---

### Task 1: Packet source plumbing

**Files:**
- Modify: `crates/osiris-sensor-api/src/raw_event.rs` (`RawEventSource`)
- Modify: `crates/osiris-schema/src/event_type.rs` (`Source`)
- Modify: `crates/osiris-pipeline/src/normalize.rs` (all six `RawEventSource` matches; DNS comment at ~:338)

**Interfaces:**
- Produces: `RawEventSource::Packet`, `Source::Packet` (serde `"PACKET"`).

- [ ] **Step 1: Failing tests** — in `normalize.rs` tests: `dns_packet_source_maps_to_packet_and_af_packet_provider` (a `RawEvent::Dns` with `source: RawEventSource::Packet` normalises to `source == Source::Packet` and provider `"dns_sensor/af_packet"`); in `event_type.rs` tests: `source_packet_serialises_as_packet` (`serde_json::to_string(&Source::Packet) == "\"PACKET\""` and round-trips).
- [ ] **Step 2:** `cargo test -p osiris-pipeline -p osiris-schema` → FAIL (variant missing).
- [ ] **Step 3:** Add the variants with doc comments (Packet = passive packet capture, no audit serial). Other sensors' provider arms for `Packet` use `"<sensor>_sensor/packet"`; DNS uses `"dns_sensor/af_packet"`. Replace the "unreachable today" comment with the real mapping description.
- [ ] **Step 4:** `cargo test --workspace` → PASS (fix any other exhaustive match the compiler reports).
- [ ] **Step 5:** Commit `feat(11a): packet-capture event source`.

### Task 2: DNS wire parser (new crate)

**Files:**
- Create: `crates/osiris-sensors/dns/Cargo.toml` (package `osiris-sensors-dns`; deps mirror `crates/osiris-sensors/net/Cargo.toml` plus `osiris-sensors-net = { path = "../net" }`; dev `tempfile`)
- Create: `crates/osiris-sensors/dns/src/lib.rs`, `src/wire.rs`
- Modify: root `Cargo.toml` workspace members; `tools/check-dep-graph.sh` (add the `osiris-sensors-dns` forbidden line like its siblings)

**Interfaces:**
- Produces (`wire.rs`):
  - `pub struct DnsMessage { pub id: u16, pub is_response: bool, pub rcode: u8, pub question: Option<Question>, pub answers: Vec<Answer> }`
  - `pub struct Question { pub name: String, pub qtype: u16 }` (name lower-cased, no trailing dot)
  - `pub struct Answer { pub rtype: u16, pub ttl: u32, pub addr: Option<std::net::IpAddr> }` (addr set for A/AAAA only)
  - `pub fn parse_message(buf: &[u8]) -> Result<DnsMessage, WireError>`
  - `pub fn qtype_mnemonic(qtype: u16) -> String` (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, SVCB=64, HTTPS=65, ANY=255; else `TYPE<n>`)
  - `pub enum WireError { Truncated, BadName, TooManyJumps, … }` (builder's naming beyond these three)

- [ ] **Step 1: Failing tests** (hand-built byte arrays in `wire.rs` tests): `parses_a_query`, `parses_a_response_with_two_a_records` (both IPs, ttls kept per answer), `parses_aaaa_answer`, `cname_chain_then_a` (answers include CNAME with `addr: None` and the A), `nxdomain_rcode_3_no_answers`, `compressed_name_pointer`, `compression_loop_is_error` (`TooManyJumps`), `name_over_255_is_error`, `label_over_63_is_error`, `truncated_header_is_error`, `answer_count_lies_is_error_or_partial` (ancount 50, one RR present → `Err(Truncated)`), `qtype_mnemonics` (1→"A", 28→"AAAA", 65→"HTTPS", 999→"TYPE999"), `uppercase_name_is_lowercased`.
- [ ] **Step 2:** `cargo test -p osiris-sensors-dns wire` → FAIL.
- [ ] **Step 3:** Implement per Global Constraint #2 (only the first question is parsed into `question`; skip remaining questions; inspect at most 64 answers).
- [ ] **Step 4:** Tests PASS; `bash tools/check-dep-graph.sh` PASS.
- [ ] **Step 5:** Commit `feat(11a): DNS wire-format parser`.

### Task 3: L3/UDP frame decoding

**Files:** Create `crates/osiris-sensors/dns/src/frame.rs`

**Interfaces:**
- Produces: `pub struct UdpDatagram<'a> { pub src: SocketAddr, pub dst: SocketAddr, pub payload: &'a [u8] }`; `pub fn decode_l3(buf: &[u8]) -> Option<UdpDatagram<'_>>` (input starts at the IP header, as AF_PACKET `SOCK_DGRAM` delivers); `pub enum Direction { Query, Response }`; `pub fn classify(d: &UdpDatagram) -> Option<Direction>` (dst 53 & src ≠ 53 → Query; src 53 → Response; else None).

- [ ] **Step 1: Failing tests:** `ipv4_udp_decodes` (IHL 5 and IHL 6 with options), `ipv6_udp_decodes`, `ipv4_non_first_fragment_ignored` (frag offset ≠ 0 → None), `ipv4_more_fragments_first_fragment_ignored` (MF set → None, *call: fragmented DNS is skipped*), `ipv6_extension_header_ignored` (next header 0 → None), `non_udp_ignored`, `udp_length_beyond_buffer_ignored`, `classify_query_and_response`, `classify_53_to_53_is_response` (server-to-server: src 53 wins).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(11a): IPv4/IPv6 UDP frame decoding`.

### Task 4: Transaction tracker

**Files:** Create `crates/osiris-sensors/dns/src/tracker.rs`

**Interfaces:**
- Consumes: `wire::DnsMessage`, `wire::qtype_mnemonic`.
- Produces:
  - `#[derive(Hash, Eq, PartialEq, Clone, Copy)] pub struct TxKey { pub client: SocketAddr, pub server: IpAddr, pub id: u16 }`
  - `pub struct Attribution { pub pid: Option<u32>, pub uid: u32, pub exe_path: String, pub comm: String }` (`Default` = unattributed)
  - `pub struct Tracker` with `pub fn new(timeout: Duration, capacity: usize) -> Self`, `pub fn on_query(&mut self, key: TxKey, msg: &DnsMessage, attribution: Attribution, timestamp_ns: u64, now: Instant)`, `pub fn on_response(&mut self, key: TxKey, msg: &DnsMessage) -> Option<DnsEventRaw>`, `pub fn expire(&mut self, now: Instant) -> Vec<DnsEventRaw>`, `pub fn counters(&self) -> TrackerCounters` (`timeouts`, `unmatched_responses`, `overflow_evictions`, `duplicates`).
  - Emitted `DnsEventRaw` has `source: RawEventSource::Packet`, `timestamp_ns` = query time, `ttl` = min TTL of A/AAAA answers.

- [ ] **Step 1: Failing tests:** `query_then_response_emits_one_event` (fields: query, qtype "A", response_ips, ttl = min, pid from attribution), `timeout_after_5s_emits_empty` (`expire(now + 5s)` → 1 event, `response_ips` empty, `ttl` None; `expire(now + 4s)` → 0), `unmatched_response_counted_and_dropped`, `retransmit_keeps_single_transaction` (same key twice, then response → 1 event, `duplicates == 1`, later expire → 0), `cname_only_response_completes_immediately`, `nxdomain_completes_immediately`, `same_id_different_port_are_distinct`, `overflow_evicts_oldest_as_timeout` (capacity 2, third query → oldest emitted from `expire`/eviction path with empty ips, `overflow_evictions == 1`), `query_without_question_ignored`.
- [ ] **Step 2:** FAIL. **Step 3:** implement (eviction order = insertion order; builder's structure). **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(11a): DNS transaction tracker`.

### Task 5: Process attribution

**Files:** Create `crates/osiris-sensors/dns/src/proc_udp.rs`, `src/attribution.rs`

**Interfaces:**
- Consumes: `osiris_sensors_net::fd_scan::{scan_socket_inodes, read_process_identity}`; `tracker::Attribution`.
- Produces: `pub struct UdpRow { pub local: SocketAddr, pub uid: u32, pub inode: u64 }`; `pub fn parse_udp_table(text: &str, v6: bool) -> Vec<UdpRow>` (v4 hex like `proc_tcp.rs`; v6 = 32 hex chars as four 32-bit native-endian words); `pub struct Attributor` with `pub fn new(proc_root: PathBuf) -> Self` and `pub fn lookup(&mut self, client: SocketAddr, now: Instant) -> Attribution` (reads `<proc_root>/net/udp` and `udp6` each call; inode→pid cache rescanned on miss at most every 250 ms).

- [ ] **Step 1: Failing tests** (tempdir proc root with fake `net/udp`, `net/udp6`, `<pid>/fd/N` symlinks via the same `#[cfg(unix)]/#[cfg(windows)]` helper pattern as `crates/osiris-sensors/net/src/fd_scan.rs` tests, `<pid>/exe`, `<pid>/comm`): `parses_udp_v4_row`, `parses_udp_v6_row` (`::1` and a mapped address), `malformed_lines_skipped`, `exact_bound_socket_matches`, `wildcard_bound_socket_matches` (row `00000000:A028` matches client `127.0.0.1:41000`), `unknown_port_is_unattributed` (pid None, uid 0), `inode_without_pid_keeps_uid`, `rescan_rate_limited` (second miss within 250 ms does not rescan — observe via a pid created between calls not being found until `now + 250ms`).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(11a): /proc/net/udp process attribution`.

### Task 6: Packet→event engine

**Files:** Create `crates/osiris-sensors/dns/src/engine.rs`; Create `crates/osiris-sensors/dns/tests/fixtures/` (synthetic hex fixtures now; Task 9 adds a real one)

**Interfaces:**
- Consumes: Tasks 2–5.
- Produces: `pub struct Engine` with `pub fn new(attributor: Attributor, timeout: Duration, capacity: usize) -> Self`, `pub fn on_packet(&mut self, l3: &[u8], timestamp_ns: u64, now: Instant) -> Vec<RawEvent>`, `pub fn tick(&mut self, now: Instant) -> Vec<RawEvent>`, `pub fn metrics(&self) -> EngineMetrics` (`packets`, `parse_errors`, `emitted`, plus tracker counters, `attributed`, `unattributed`). Parse errors increment a counter and return no events.

- [ ] **Step 1: Failing tests:** `query_response_packets_emit_dns_event` (L3 IPv4 fixture pair → one `RawEvent::Dns`), `ipv6_pair_emits`, `garbage_packet_counts_parse_error`, `non_dns_udp_ignored_without_error` (port 1234 ↔ 5678), `tick_emits_timeouts`, plus a `tests/replay.rs` integration test `replays_fixture_files` that reads every `tests/fixtures/*.hex` pair file (format: one hex-encoded L3 packet per line, `#` comments; companion `*.expected.json` with the expected `query`, `qtype`, `response_ips`) and asserts the events.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(11a): DNS packet engine with fixture replay`.

### Task 7: AF_PACKET capture and `DnsSensor`

**Files:** Create `crates/osiris-sensors/dns/src/capture.rs` (`#[cfg(target_os = "linux")]`), `src/sensor.rs`; Modify `Cargo.toml` (Linux-only `libc`)

**Interfaces:**
- Consumes: `Engine`; `osiris_sensor_api::{Sensor, SensorCapabilities, SensorContext, SensorHealth, SensorMetrics, SensorError}`.
- Produces: `pub struct DnsSensor` with `pub fn new(proc_root: PathBuf, interface: Option<String>) -> Self`; `Sensor::name() == "dns"`; `pub fn unsupported_reason_for(errno: i32) -> String` (OS-neutral; `EPERM`/`EACCES` (1/13) → `"AF_PACKET needs CAP_NET_RAW"`, other → `"AF_PACKET socket failed: errno <n>"`).
- Capture (Linux): `socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))`; cBPF filter via `SO_ATTACH_FILTER` admitting IPv4/UDP and IPv6/UDP (next header 17) with src or dst port 53 — on `SOCK_DGRAM` the data starts at L3, so read the protocol from the `SKF_AD_OFF + SKF_AD_PROTOCOL` ancillary load; `SO_RCVTIMEO` 500 ms; optional `bind` to `if_nametoindex(interface)`; read `sockaddr_ll` from `recvfrom` and, on the loopback ifindex only, skip packets with `sll_pkttype == PACKET_OUTGOING` (on `lo` every packet is seen twice, once outgoing and once incoming); keep all packets on other interfaces (*call; Task 9 confirms on a real run that each lookup yields exactly one event per hop*). Loop runs on `std::thread`/`spawn_blocking`, calls `Engine::on_packet` and `Engine::tick` (≥ every 500 ms), sends events via `SensorContext.output.blocking_send`, exits on cancellation.
- Health: Healthy while capturing; Degraded when `parse_errors` or `overflow_evictions` rose in the last 60 s; Failed after a socket error, retrying with backoff like `osiris-sensors-net`'s sensor.

- [ ] **Step 1: Failing tests:** `eperm_maps_to_cap_net_raw_reason`, `other_errno_reason`, `#[cfg(not(target_os = "linux"))] capabilities_unsupported_off_linux` (`!caps.supported()` and reason mentions Linux), `#[cfg(target_os = "linux")] cbpf_program_is_well_formed` (length ≤ 64, last instruction is a return), `name_is_dns`.
- [ ] **Step 2:** FAIL. **Step 3:** implement; mirror `crates/osiris-sensors/net/src/sensor.rs` for health/locking/cancellation.
- [ ] **Step 4:** `cargo test -p osiris-sensors-dns` and `cargo clippy -p osiris-sensors-dns --all-targets -- -D warnings` PASS (Windows). Linux compile is proven by Task 9's GH run.
- [ ] **Step 5:** Commit `feat(11a): AF_PACKET capture and DnsSensor`.

### Task 8: Agent wiring and fleet policy

**Files:** Modify `crates/osiris-agent/Cargo.toml`, `src/config.rs`, `src/agent.rs` (`build_sensor` ~:97, `STARTUP_ORDER` :76 → 8 entries, `"dns"` last); `crates/osiris-policy/src/lib.rs` (`KNOWN_SENSORS` → 8, sorted, `"dns"` after `"container"`); every test asserting `"unknown sensor: dns"` (`crates/osiris-api/src/policy.rs` ~:578/:811, `crates/osiris-fleet/src/policies.rs` ~:360, `crates/osiris-command/src/envelope.rs` ~:253, `crates/osiris-agent/src/policy.rs` ~:182) — switch them to another unknown name (e.g. `"bogus"`) and add positive `dns` cases; `docs/operators-fleet-policy.md` sensor list.

**Interfaces:** Consumes `DnsSensor::new(proc_root, interface)`. Produces `AgentConfig.dns_capture: Option<DnsCaptureConfig>`, `pub struct DnsCaptureConfig { pub interface: Option<String> }`.

- [ ] **Step 1: Failing tests:** `config_without_dns_capture_loads` (existing YAML fixture → `dns_capture.is_none()`), `config_with_empty_dns_capture_loads` (`dns_capture: {}` → `Some(DnsCaptureConfig { interface: None })`), `build_sensor_dns_not_configured` / `build_sensor_dns_configured`, `policy_accepts_dns_sensor` (`sensors: {dns: false}` validates), `policy_golden_hashes_unchanged` (re-run the 9d-3 golden vectors in `crates/osiris-policy` — they must pass unchanged, no vector edits).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** `cargo test --workspace` PASS; `bash tools/check-dep-graph.sh` PASS.
- [ ] **Step 5:** Commit `feat(11a): wire the DNS sensor into the agent and fleet policy`.

### Task 9: Real-Linux validation and real fixture

**Files:** Modify `crates/osiris-real-linux-tests/src/render.rs` (`dns_capture: {}`), `src/stack.rs` (`AgentOptions` if needed), `tests/real_linux.rs`; `tools/real-linux/setup.sh` (install `tcpdump`); `.github/workflows/real-linux.yml` (capture `tcpdump -i any -w dns.pcap udp port 53` around the suite, upload `dns.pcap` with the existing artifacts); Create `crates/osiris-sensors/dns/tests/fixtures/ubuntu2404-curl-xyz.hex` + `.expected.json` from that pcap (strip the SLL/SLL2 link header so lines start at L3).

- [ ] **Step 1: Test** `dns_query_is_observed_and_alerts` (`#[test] #[ignore]`): `m = marker()`; start stack; `sh("curl -s -m 5 http://<m>.xyz/ || true")`; wait for `DNS_QUERY` where `dns.query == "<m>.xyz"` and `process.exe_path` ends with `curl`; wait for an alert from rule `dns_query_to_suspicious_tld` whose event carries the marker. Follow the `network_connect_is_observed` / `web_root_drop_raises_an_alert` patterns.
- [ ] **Step 2:** Push to `real-linux/t11a-1`; poll the run. Expected: green on ubuntu-22.04 + 24.04 including the new test. If red: diagnose from artifacts, fix with a fixture-based regression test in `osiris-sensors-dns` (Phase 10 Constraint #8), re-run (`t11a-2`, …).
- [ ] **Step 3:** Build the real fixture from the artifact `dns.pcap`; `replays_fixture_files` PASS on Windows.
- [ ] **Step 4:** Commit `test(11a): real-Linux DNS scenario and captured fixture`.

### Task 10: Docs and final gates

**Files:** `ARCHITECTURE.md` (DNS row/§5 note: AF_PACKET backend implemented, uprobe pending 11b; level discrepancy note), `docs/VALIDATION.md` (DNS section with GH run id, known behaviour from spec §5), `docs/ROADMAP-REMAINING.md` (DNS debt done; 11a done; TCP-DNS/DoT/DoH/mDNS blind spots as debt)

- [ ] **Step 1:** Write the docs.
- [ ] **Step 2:** Run every gate in Global Constraint #10 → all PASS.
- [ ] **Step 3:** Commit `docs(11a): real DNS sensor validated`.
