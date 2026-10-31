# Phase 11b-4 eBPF DNS Attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attribute every captured DNS query to the process that sent it, using a kernel record of the send that is taken in the sender's context. This removes the `/proc` race behind the `dns_query_is_observed_and_alerts` flake. `/proc` attribution stays as the fallback.

**Architecture:**
- A new `dns.bpf.o` puts kprobes on `udp_sendmsg`/`udpv6_sendmsg`. It emits one fixed 104-byte record per send to port 53. The record carries the owner (tgid, uid, comm, exe identity), the 5-tuple, the netns inode and the ktime.
- The DNS sensor's reader thread resolves the exe right away and fills an OS-neutral `SendTable`.
- The `AF_PACKET` capture gains kernel receive timestamps (`SO_TIMESTAMPNS`). The engine joins each local query packet with the oldest matching send in a time window, and consumes that send. A query that misses is re-checked when its transaction closes, with a 250 ms hold on responses.

**Tech Stack:**
- Rust 1.99 workspace with `aya` at the pinned version (Linux-only).
- clang + libbpf-dev, built by `tools/ebpf/build.sh`.
- The GH Actions real-Linux workflow.
- The WSL2 `Ubuntu-24.04` distro, for local object builds and verifier loads only.

**Spec:** `docs/superpowers/specs/2026-10-31-phase-11b4-ebpf-dns-attribution-design.md`. It builds on the 11a DNS spec (`2026-10-17-phase-11a-dns-sensor-design.md`) and the 11b-3 spec (`2026-10-26-phase-11b3-ebpf-filesystem-design.md`).

## Global Constraints

1. No new third-party crate. `aya` stays pinned. Cargo never builds BPF C, and no `.bpf.o` is committed. `cargo build`/`cargo test --workspace` on Windows need no clang, root, BTF or loaded program.
2. Objects:
   - `process.bpf.o` schema 2, `net.bpf.o` schema 1 and `fs.bpf.o` schema 1 are unchanged.
   - The new `dns.bpf.o` has schema **1** and a `.sha256` sidecar. Every object lives in `ebpf.object_dir`.
3. Kinds 1–9 are unchanged. New kind: `KIND_DNS_SEND = 10`.
4. dns maps:
   - `EVENTS`: ringbuf 256 KiB (`1 << 18`).
   - `DROPS`: per-CPU array[1].
   - `SELF_TGID`: array[1]. The map is present and set by the loader, but **the program never reads it**, so the agent's own sends are emitted.
5. Required kprobes `udp_sendmsg` and `udpv6_sendmsg`; nothing is optional. The object is **x86_64-only**. On other arches the reason is exactly `dns eBPF object is x86_64-only`.
6. The program emits only when the destination port is 53, taken from `msg_name` when `msg_namelen != 0` and from the socket otherwise. `udpv6_sendmsg` skips IPv4-mapped destinations, and such a send is reported once, as AF_INET, by `udp_sendmsg`. Ports are in host order. Addresses are in network order, with IPv4 in the first 4 bytes.
7. `SendTable` values:
   - key `(lport, raddr canonical, rport)`;
   - queue of ≤ **8** sends per key, oldest first;
   - window `[packet_ts − 2 s, packet_ts + 5 ms]`, taking the **oldest** match and consuming it;
   - entries older than `packet_ts − 2 s` are discarded on lookup;
   - TTL **10 s**, capacity **16 384** entries, oldest evicted and counted;
   - the local address is compared only when both sides are non-wildcard.
8. Only sends whose `netns_ino` equals the agent's own netns inode (`stat("/proc/self/ns/net").st_ino`) enter the table. Others are counted as `foreign_netns`. If the agent's netns cannot be read, eBPF attribution is unusable (fallback).
9. A response that closes an unattributed transaction is held for at most **250 ms**, re-checked on each tick, and then emitted unattributed. Timeouts and evictions are re-checked once at close and emitted.
10. DNS health and flags:
    - eBPF working: `Healthy`, flag `ebpf_attribution`.
    - eBPF configured but unusable: `Degraded`, flag `procfs_attribution`, `last_error` with the reason (containing `dns.bpf.o` when the object is the problem).
    - No `ebpf` key: `Healthy`, flag `procfs_attribution`.
    - A reader failure mid-run is a **one-way latch** to `Degraded` + `procfs_attribution` until restart.
    - Reported state = worse of the backend state and the parse/eviction window. The capture loop never overwrites a backend `Degraded`.
    - Existing capture flags are kept.
11. No schema change: `source` stays `PACKET`, provider `dns_sensor/af_packet`. `DnsEventRaw`/`DnsRef` are untouched. No new agent config key: the DNS sensor gets `ebpf_settings(config)`.
12. In eBPF mode the engine **never** does the `/proc` lookup on the query path. After the latch, new queries use `/proc` and pending ones get a `/proc` lookup at close.
13. Real-Linux tests:
    - `#[ignore]`, `#[cfg(target_os = "linux")]`, serial, root, bounded waits, unique markers.
    - Push to `real-linux/t11b4-<n>`.
    - Poll with `gh run list/view` from the WSL distro, driven through script files (`wsl -d Ubuntu-24.04 -- bash /mnt/c/.../script.sh`); inline bash through PowerShell mangles `$`.
    - In WSL, pid assertions are invalid (child pid namespace), so the full suite runs only on GH.
14. Cross-check Linux-only code on Windows with `cargo check`/`cargo clippy --target x86_64-unknown-linux-gnu -- -D warnings` for touched crates, or natively in WSL (`~/osiris`, objects in `~/osiris-bpf`).
15. Gates before merge:
    - `cargo fmt --all -- --check`
    - `cargo clippy --workspace --all-targets -- -D warnings`
    - `cargo test --workspace`, after building `osiris-cli`/`osiris-server`/`osiris-agent`
    - `bash tools/check-dep-graph.sh`
    - console lint/test/build, only if touched
16. Untrusted ring-buffer bytes and packets never panic and are bounded. No `unwrap`/`expect` outside tests. Recover poisoned locks. Reader threads use `blocking_send`, and the capture thread never blocks on the reader. A held lock is never kept across I/O.

## Review Focus

1. **Port reuse between two processes:** A sends on port P, then B sends on P to the same resolver, and B's record is inserted before A's packet is looked up → A's packet gets A, B's packet gets B. With A's record missing, A's packet gets nothing (never B, because B's send is newer than A's packet + 5 ms). Owner: Task 3, test `port_reuse_never_misattributes`.
2. **A retransmission from the same socket** (two sends, two packets 1 s apart) → each packet consumes one entry, and both come out attributed to the same owner. Owner: Task 3, test `retransmission_consumes_one_entry_each`.
3. **A kernel record that arrives after the response packet** → the response is held, the late record attributes it within 250 ms, and `attribution_late` increments. With no record, the event is emitted unattributed after 250 ms. Owner: Task 4, tests `late_record_attributes_held_response` and `held_response_emits_unattributed_after_grace`.
4. **The reader dies while transactions are pending** → flag `procfs_attribution`, `Degraded`, a pending transaction gets a `/proc` lookup at close, and the state never flips back to `Healthy` even if the parse window is clean. Owner: Task 5, test `reader_failure_latches_procfs`.
5. **A malformed dns record** (unknown kind, wrong size, schema 2, family neither 2 nor 10) → `DecodeError`, counted as dropped, no panic, also under a 10 000-iteration random-bytes loop. Owner: Task 1, test `dns_decode_rejects_bad_input`.

---

### Task 1: dns record ABI and `DNS_OBJECT`

**Files:**
- Create `bpf/dns.h` and `crates/osiris-ebpf/src/dns_record.rs`.
- Modify `crates/osiris-ebpf/src/{lib.rs,loader.rs}` and `crates/osiris-ebpf/tests/c_header.rs`.

**Interfaces — Produces:**
```rust
pub const DNS_SCHEMA_VERSION: u32 = 1;
pub const KIND_DNS_SEND: u32 = 10;
// DnsRecord (size 104): hdr@0 pid@8 tid@12 uid@16 family:u16@20 lport:u16@22 ktime_ns:u64@24
// comm[16]@32 exe_dev:u32@48 netns_ino:u32@52 exe_ino:u64@56 rport:u16@64 _pad:u16@66 _pad2:u32@68
// laddr[16]@72 raddr[16]@88 ; end 104
pub struct DnsSendEvent { pub pid: u32, pub tid: u32, pub uid: u32, pub ktime_ns: u64, pub comm: String,
  pub exe: Option<ExeIdentity>, pub netns_ino: u32, pub local: SocketAddr, pub remote: SocketAddr }
pub fn decode_dns(bytes: &[u8]) -> Result<DnsSendEvent, DecodeError>;
pub const DNS_OBJECT: ObjectSpec; // "dns.bpf.o", schema 1, kprobes kp_udp_sendmsg -> udp_sendmsg, kp_udpv6_sendmsg -> udpv6_sendmsg, both required
pub const DNS_REQUIRED_KPROBES: &[&str] = &["udp_sendmsg", "udpv6_sendmsg"];
```
`exe` follows the net rule: a zero identity gives `None`. Addresses become `SocketAddr::V4`/`V6` according to `family`.

- [ ] **Step 1: Failing tests.**
  - `dns_layout_is_pinned`: the size and every offset above.
  - `dns_c_header_matches_rust_constants` (in `tests/c_header.rs`): `bpf/dns.h` contains `SCHEMA_VERSION 1`, `KIND_DNS_SEND 10` and `_Static_assert(sizeof(struct dns_record) == 104`.
  - `decode_dns_v4_and_v6`: a hand-built v4 record gives `remote == 127.0.0.53:53` and the right `local`; a v6 record gives `[::1]:53`.
  - `dns_decode_rejects_bad_input`:
    - 103 bytes → `Truncated`.
    - Kind 9 → `UnknownKind`.
    - Schema 2 → `UnsupportedVersion`.
    - Family 7 → a `DecodeError`. Add a variant if none fits, e.g. `BadFamily(u16)`.
    - A random 10 000-iteration loop never panics.
  - `dns_object_spec_names`: file, schema, the two programs/symbols, all required. Also extend `object_specs_keep_their_programs` so the other three specs are unchanged.
- [ ] **Step 2:** `cargo test -p osiris-ebpf` → FAIL.
- [ ] **Step 3:** Implement `dns_record.rs` and `bpf/dns.h`, with a `_Static_assert` for the size and every offset.
- [ ] **Step 4:** PASS. Linux-target clippy on `osiris-ebpf` is clean.
- [ ] **Step 5:** Commit `feat(11b-4): dns record ABI and object spec`.

### Task 2: dns BPF program, build, first load

**Files:**
- Create `bpf/dns.bpf.c` and `crates/osiris-ebpf/tests/load_dns.rs`.
- Modify `bpf/vmlinux_min.h`: add `msghdr` (`msg_name`, `msg_namelen`), `sockaddr_in`, `sockaddr_in6`, `sock_common` (`skc_daddr`, `skc_rcv_saddr`, `skc_dport`, `skc_num`, `skc_v6_daddr`, `skc_v6_rcv_saddr`, `skc_net`), `possible_net_t`/`net` (`ns.inum`), and `inet_sock` (`inet_sport`) as needed. Use `preserve_access_index` throughout.
- Modify `tools/ebpf/build.sh` (loop over `process net fs dns`) and `.github/workflows/real-linux.yml` (add `-p osiris-ebpf --test load_dns` to the unit-test step).

**Interfaces — Consumes:** Task 1's layout and `DNS_OBJECT`; `LoadedObject::load`, `verified_instruction_counts`, `spawn_reader`.

Program behaviour is GC 4–6 exactly:
- Use `BPF_KPROBE(kp_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)` and the v6 twin.
- Read the destination port first, and return for anything other than 53 before any map access or reservation.
- Detect an IPv4-mapped destination in the v6 program (`::ffff:a.b.c.d`) and return.
- comm comes from the group leader. exe identity comes from `mm->exe_file->f_inode`, as `net.bpf.c` does. uid is `bpf_get_current_uid_gid() & 0xffffffff`.
- Every reservation has a constant size and is submitted. A failed reserve increments `DROPS`.

`tests/load_dns.rs::dns_object_loads_and_reports_a_send`:
- `#[ignore]`, Linux-only; needs root and `$OSIRIS_BPF_DIR`.
- Load `DNS_OBJECT`, print `verified_instruction_counts()`, start `spawn_reader`.
- Bind a UDP socket on `127.0.0.1:0`, then `send_to` 12 bytes to `127.0.0.1:53`. Also send to `127.0.0.1:5353` (must not appear) and from an IPv6 socket to `[::1]:53`.
- Within 5 s, assert one record with `local.port()` equal to the socket's port and `remote == 127.0.0.1:53`, and one v6 record, and none with port 5353.
- Assert `pid == std::process::id()` **only when** `/proc/self/status`'s `NSpid:` line has one field. That keeps the test valid in WSL.

- [ ] **Step 1:** Write `load_dns.rs`. `cargo check --tests --target x86_64-unknown-linux-gnu -p osiris-ebpf` passes.
- [ ] **Step 2:** Write `dns.bpf.c`, the header additions and `build.sh`. `bash -n tools/ebpf/build.sh` passes.
- [ ] **Step 3:** Verify in WSL: build the objects into `~/osiris-bpf` and run `load_dns` as root. Expected: the load succeeds (verifier OK on 6.18) and the test passes. Record the instruction counts.
- [ ] **Step 4:** Commit `feat(11b-4): dns BPF program`. Push `real-linux/t11b4-1` and poll. Expected: `load_dns` passes on 22.04 and 24.04. On a rejection, fix and push `-2`, `-3`, and so on. Record the run ids and instruction counts.
- [ ] **Step 5:** Report every kernel field read and why it is CO-RE-safe on 5.15 and 6.x.

### Task 3: `SendTable`

**Files:**
- Create `crates/osiris-sensors/dns/src/send_table.rs`.
- Modify `crates/osiris-sensors/dns/src/lib.rs`.

**Interfaces — Produces:**
```rust
pub struct SendKey { pub lport: u16, pub raddr: IpAddr, pub rport: u16 }   // raddr = to_canonical()
impl SendKey { pub fn new(local: SocketAddr, remote: SocketAddr) -> Self; }
pub struct KernelSend { pub key: SendKey, pub laddr: IpAddr, pub sent_wall_ns: u64, pub owner: Attribution }
pub struct SendTableCounters { pub inserted: u64, pub consumed: u64, pub evicted: u64, pub expired: u64 }
pub struct SendTable { /* private */ }
impl SendTable {
  pub fn new() -> Self;                                   // GC 7 limits
  pub fn insert(&mut self, send: KernelSend);
  pub fn take(&mut self, key: &SendKey, laddr: IpAddr, packet_wall_ns: u64) -> Option<Attribution>;
  pub fn expire(&mut self, now_wall_ns: u64);             // drops entries older than now − 10 s
  pub fn counters(&self) -> SendTableCounters;
  pub fn len(&self) -> usize;
}
pub type SharedSendTable = Arc<Mutex<SendTable>>;
```
`Attribution` is the existing `tracker::Attribution`.

- [ ] **Step 1: Failing tests.** Times are in ns, with `S = 1_000_000_000`.
  - `exact_match_consumes_once`: insert at t, then `take` at t+1 ms → `Some`; a second `take` → `None`.
  - `window_bounds`: a send at t is matched by a packet at t+2 s, not at t+2 s+1. A send at t+6 ms is not matched by a packet at t (above the 5 ms slack); a send at t+5 ms is matched.
  - `port_reuse_never_misattributes`: the Review Focus #1 scenarios, all three orders.
  - `retransmission_consumes_one_entry_each`.
  - `wildcard_local_matches_any`: an entry with laddr `0.0.0.0` matches packet laddr `10.0.0.5`; an entry with laddr `10.0.0.6` does not.
  - `ipv4_mapped_normalised`: an entry with remote `[::ffff:127.0.0.53]:53` matches a key built from `127.0.0.53:53`.
  - `queue_and_capacity_limits`: a 9th send on a key drops that key's oldest. 16 385 inserts on distinct keys leave `len() == 16_384` and `evicted == 1`, with the globally oldest gone.
  - `expire_drops_old`: `expire(t + 10 s + 1)` removes an entry inserted at t.
- [ ] **Step 2:** `cargo test -p osiris-sensors-dns send_table` → FAIL.
- [ ] **Step 3:** Implement. Use `HashMap<SendKey, VecDeque<Entry>>` plus a global insertion-ordered `VecDeque<(u64 seq, SendKey)>` for capacity eviction. Stale order slots are skipped lazily.
- [ ] **Step 4:** PASS. Clippy is clean.
- [ ] **Step 5:** Commit `feat(11b-4): send table joining kernel sends with packets`.

### Task 4: Capture timestamps and engine attribution modes

**Files:**
- Modify `crates/osiris-sensors/dns/src/{capture.rs,engine.rs,tracker.rs,sensor.rs}` (the sensor only where it calls `recv`/`Engine::new`).

**Interfaces — Consumes:** Task 3. **Produces:**
```rust
// capture.rs: Recv's packet variant gains `ts_wall_ns: Option<u64>` from the SCM_TIMESTAMPNS cmsg (recvmsg instead of recvfrom,
// SO_TIMESTAMPNS enabled in open()); a None is counted by the sensor as `timestamp_fallbacks`.
pub enum AttributionMode { Kernel(SharedSendTable), Procfs }
impl Engine {
  pub fn new(attributor: Attributor, mode: AttributionMode, timeout: Duration, capacity: usize) -> Self;
  pub fn latch_procfs(&mut self);            // GC 10/12: one-way; later queries use /proc, pending ones get /proc at close
  // on_packet(l3, local_origin, timestamp_ns, now): timestamp_ns is the kernel ts when present, else wall_ns() as today
}
pub struct EngineMetrics { /* existing */ pub attributed_kernel: u64, pub attributed_procfs: u64,
  pub attribution_late: u64, pub unattributed: u64, pub held: u64 }
```
The engine's internal flow is spec §3.3 item 9, with GC 9:
- At query time in Kernel mode, call `take`. A miss marks the transaction pending with `(SendKey, laddr, packet_ts)`, so the tracker's per-transaction state gains an optional pending key.
- When the tracker closes a transaction, the engine tries `take` again for a pending one.
- A response close that still misses goes into a hold queue with a deadline of now + 250 ms. `tick` re-checks the queue and emits on a hit or at the deadline.
- Timeout and eviction closes are re-checked once and then emitted.
- The engine calls `SendTable::expire` on each tick.
- Keep `attributed` as the sum of the two attributed counters, so existing metrics consumers keep working.

- [ ] **Step 1: Failing tests** (the engine tests use the existing packet builders, plus a `SharedSendTable` filled by hand):
  - `kernel_mode_attributes_from_table`: send inserted, then query → response gives an event with the owner's pid/exe and `attributed_kernel == 1`. The procfs fixture has **no** row, which proves no `/proc` lookup is needed.
  - `kernel_mode_never_reads_proc`: the fixture proc root has a matching `/proc/net/udp` row and fd, but the table is empty → the event is unattributed after the grace period (`unattributed == 1`).
  - `late_record_attributes_held_response`: query, then response, then insert, then `tick(now + 100 ms)` → one attributed event, `attribution_late == 1`.
  - `held_response_emits_unattributed_after_grace`: no insert; `tick(now + 249 ms)` emits nothing, `tick(now + 251 ms)` emits one unattributed event.
  - `timeout_close_rechecks_table`: query, then insert, then `tick` past the 5 s timeout → an attributed timeout event.
  - `latch_switches_to_procfs`: Kernel mode with a pending query, then `latch_procfs()`, then response → attributed from the procfs fixture. A new query also uses the procfs fixture.
  - `procfs_mode_unchanged`: the existing engine tests pass with `AttributionMode::Procfs`.
  - `capture.rs`: `cmsg_timestamp_parsed` is a pure parser test for an `SCM_TIMESTAMPNS` control buffer, plus one with no cmsg → `None`. It is Linux-only if it needs libc types.
- [ ] **Step 2:** `cargo test -p osiris-sensors-dns` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS. Linux-target clippy on `osiris-sensors-dns` is clean.
- [ ] **Step 5:** Commit `feat(11b-4): engine joins packets with kernel sends`.

### Task 5: Sensor eBPF backend, health rule, agent wiring

**Files:**
- Create `crates/osiris-sensors/dns/src/ebpf_backend.rs`.
- Modify `crates/osiris-sensors/dns/{Cargo.toml (add osiris-ebpf),src/sensor.rs,src/lib.rs}`, `crates/osiris-agent/src/agent.rs` and `tools/check-dep-graph.sh` if needed.

**Interfaces — Consumes:** Tasks 1–4. **Produces:**
```rust
pub fn send_from_event(e: &DnsSendEvent, boot_wall_offset_ns: i128, proc_root: &Path) -> KernelSend; // exe via resolve_exe(..).unwrap_or_default(), pid Some, uid, comm; sent_wall_ns = ktime + offset clamped ≥ 0
pub fn agent_netns_ino() -> Option<u32>;    // Linux: stat("/proc/self/ns/net").st_ino as u32; None elsewhere
impl DnsSensor { pub fn new(proc_root: PathBuf, interface: Option<String>, ebpf: Option<EbpfSettings>) -> Self; }
fn reported_state(backend: SensorState, window: SensorState) -> SensorState; // worse of the two (Failed > Degraded > Healthy)
```
Backend selection mirrors the fs sensor's `load_ebpf`:
- First collect every reason: object problem, `probe().reasons`, the arch check (GC 5 string), `missing_kernel_symbols(.., DNS_REQUIRED_KPROBES)`, and `agent_netns_ino()` being `None` (reason `cannot read the agent's network namespace`).
- Then load. The reader's `on_record` drops `netns_ino != agent` (counter `foreign_netns`), converts each event with `send_from_event`, and inserts it under the table lock. Decode errors and ring-buffer drops count in `events_dropped_total`.
- The supervisor task calls the latch. The capture thread holds an `Arc<AtomicBool>` and calls `engine.latch_procfs()` when it sees the flag. Health then switches flags per GC 10.
- `build_sensor("dns")` passes `ebpf_settings(config)`.

- [ ] **Step 1: Failing tests.**
  - `send_from_event_maps_fields`: pid/uid/comm are copied, `exe_path` is `""` under a fixture proc root, the time is `ktime + offset`, and the key comes from local/remote.
  - `reported_state_is_worse_of_two`: every pair.
  - `falls_back_to_procfs_when_dns_object_missing`: `EbpfSettings` pointing at an empty dir → after `initialize`, `Degraded`, flag `procfs_attribution`, `last_error` contains `dns.bpf.o`. Off Linux, the existing unsupported path stays as it is today. Gate the test the way the fs sensor's equivalent is gated.
  - `no_ebpf_key_is_procfs_healthy`: `new(.., None)` → the flags contain `procfs_attribution` and not `ebpf_attribution`.
  - `reader_failure_latches_procfs`: Review Focus #4, using the same seam the net/fs sensors use for a supervised reader error.
  - `dns_sensor_gets_ebpf_settings` (agent): with `dns_capture` and `ebpf` both set, the built sensor is `"dns"`, and the existing agent tests pass.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** `cargo test --workspace` PASS; Linux-target clippy is clean for `osiris-sensors-dns` and `osiris-agent`; add `-p osiris-sensors-dns` to the workflow unit-test step if it is not already there.
- [ ] **Step 5:** Commit `feat(11b-4): DNS sensor kernel attribution backend`.

### Task 6: Real-Linux validation

**Files:**
- Modify `crates/osiris-real-linux-tests/tests/real_linux.rs`, plus helpers in `crates/osiris-real-linux-tests/src/` if a fake responder helper fits there.
- Modify `tools/real-linux/annotate.sh` and the workflow: extend the eBPF status annotation to `dns`.

Scenarios are spec §3.5 item 12, (a)–(f):
- The fake responder is a `python3 -c` process bound to `127.0.0.1:53`. It echoes each query back as a response with one A answer (`127.0.0.2`), after 300 ms.
- Clients are `python3 -c` children that use `socket.socket(AF_INET, SOCK_DGRAM)` + `sendto` to `127.0.0.1:53`, then `close()`.
- The expected pid is `Child::id()`, and the expected exe is `realpath $(command -v python3)`.

- [ ] **Step 1:** Add the tests:
  - `dns_sensor_uses_ebpf_attribution` (a);
  - the existing `dns_query_is_observed_and_alerts` unchanged (b);
  - `dns_closed_socket_client_is_attributed` (c): sleeps 2 s after close;
  - `dns_exited_client_keeps_its_pid` (d): exits right after the close; `exe_path` is the python path or `""`;
  - `dns_missing_object_falls_back_to_procfs` (e): the broken-copy pattern without `dns.bpf.o` → `Degraded`, `procfs_attribution`, and the curl query is stored;
  - `dns_burst_attribution_is_near_complete` (f): 20 clients × 10 queries, each query on its own socket with a unique name `<marker>-<i>-<j>.xyz`. ≥ 198 of 200 stored events carry the pid of the client that sent that name. If fewer than 200 are attributed, `/status` for `dns` must show `events_dropped_total > 0`. Any event attributed to the *wrong* client pid fails the test outright.
- [ ] **Step 2:** `cargo check --tests --target x86_64-unknown-linux-gnu -p osiris-real-linux-tests` is clean.
- [ ] **Step 3:** Push `real-linux/t11b4-<n>` and poll. Fix and re-push until the **whole** suite is green on both runners, with every earlier test still passing. Record the run ids, kernels and the dns instruction counts.
- [ ] **Step 4:** Commit `test(11b-4): real-Linux DNS kernel attribution scenarios`. Fix-ups are fine.

### Task 7: Benchmark and docs

**Files:**
- `.github/workflows/real-linux-bench.yml` and its script: 10 000 UDP sends on `lo` to port 5300 and 10 000 to port 53, with a listener on each, run with and without the agent.
- `PERFORMANCE.md`.
- `docs/operators-ebpf.md` (DNS section: the kprobes, x86_64-only, the fallback, the netns rule, the upgrade note that `dns_capture` + `ebpf` now switches attribution, and spec §6 in substance).
- `docs/operators-dns-sensor.md` (attribution section and the new flags).
- `docs/adr/ADR-010-ebpf-loader-aya.md` (fourth object; hand-mirrored layouts kept).
- `ARCHITECTURE.md` §4.3 DNS row and status note (kernel send attribution + packet capture, the uprobe ruling).
- `docs/VALIDATION.md`: an 11b-4 section with the pre-phase A/B result (run 41227648672, 60/60), the runs, kernels and instruction counts; and the `dns_query_is_observed_and_alerts` flake entry updated with the Task 6 evidence.
- `docs/ROADMAP-REMAINING.md`: 11b-4 done, Phase 11b closed. New debts: pid-namespace-aware pids for all 11b objects, foreign-netns DNS attribution, x86_64-only kprobe objects, uprobes as an optional future source, and `SO_REUSEPORT` 5 ms ambiguity.

- [ ] **Step 1:** Run the bench on GH and record the numbers. If the non-53 overhead is above 5 %, add a warning to `PERFORMANCE.md`.
- [ ] **Step 2:** Write the docs.
- [ ] **Step 3:** All GC 15 gates are green.
- [ ] **Step 4:** Commit `docs(11b-4): eBPF DNS attribution validated`.
