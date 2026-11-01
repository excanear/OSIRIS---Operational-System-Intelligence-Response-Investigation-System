# Phase 11b-4: eBPF DNS attribution (kernel-side owner of every port-53 send)

Status: design, 2026-10-31. This is the fourth and last sub-project of Phase 11b. The order is:
11b-1 engine plus process exec/exit (done); 11b-2 network (done); 11b-3 filesystem (done,
@ 88c4981); **11b-4 DNS**, which is this document; then 11c ClickHouse. The user's standing
instruction is to proceed with the recommended option for every choice. Every decision below that
`ARCHITECTURE.md`, the earlier 11b designs or the existing code does not already dictate is the
designer's call, and is marked *(call)*.

## 1. Intent

The DNS sensor (`crates/osiris-sensors/dns`, sensor name `dns`, Phase 11a) captures UDP port-53
packets with `AF_PACKET` and pairs queries with responses. That part works. Its weak point is
**process attribution**. When the agent processes a captured query packet, it looks the client's
local port up in `/proc/net/udp{,6}` and maps the socket inode to a pid through a `/proc/*/fd`
scan. A stub resolver socket (glibc, `curl`, systemd-resolved's upstream sockets) is closed within
milliseconds of the answer. When the agent's DNS thread lags behind, whole bursts of events come out
with `process: null`. This is the cause of the intermittent `dns_query_is_observed_and_alerts`
failure recorded in `docs/VALIDATION.md` ("Observed flakes") and carried to 11b-4 by
`docs/ROADMAP-REMAINING.md`.

11b-4 makes the kernel record the owner of every port-53 send **in the sending task's context, at
send time**. User space then joins that owner with the captured packet. The race goes away because
nothing has to exist on `/proc` any more when the packet is processed.

Success means the following on the GitHub real-Linux runners (ubuntu-22.04 and ubuntu-24.04), with
the objects present:

- The `dns` sensor is `Healthy` with capability flag `ebpf_attribution`.
- `curl http://<marker>.xyz/` yields a stored `DNS_QUERY` whose `process.exe_path` ends in `curl`,
  on every run.
- A client that sends one query and **closes its socket before the answer arrives** is still
  attributed to its pid and exe. The 11a backend cannot do this, so this test proves the race is
  gone.

With the object absent or the kernel unsupported, the sensor keeps today's `/proc` attribution and
reports `Degraded` with the reason, in the same shape as the other 11b sensors.

### 1.1 Pre-phase A/B (acceptance condition from the 11b-3 final review)

This was done before this design. Temporary branch `real-linux/t11b4-ab` @ b267cc6, run
41227648672: `dns_query_is_observed_and_alerts` ran alone 15 times with the filesystem sensor on and
15 times with it off, interleaved, on each runner. A marker file proved the fs sensor really was off.
**Result: 60/60 PASS** on 22.04 and 24.04. The filesystem sensor does not cause the flake by itself.
The flake appears only under full-suite load, which fits the attribution race already ruled
in 11b-3. VALIDATION.md records the run. The temporary branch is deleted once this spec is
committed.

## 2. Why not uprobes on the resolver libraries

ARCHITECTURE §4.3 (row "DNS") and the roadmap name "eBPF uprobe on resolver libs (best-effort)".
11b-4 deliberately does something else *(call; ARCHITECTURE is amended)*. Uprobes on
`getaddrinfo`/`res_*` would:

- miss every client that does not resolve through glibc: Go binaries (pure-Go resolver), musl
  (Alpine containers), static binaries, `dig`/`nslookup`/`host` (bind's own library), language
  runtimes with their own resolvers, and malware that sends raw UDP. Those are the clients a
  detection product cares about most;
- need the agent to find every libc on the host: per mount namespace, per container image, per
  architecture. A uprobe binds to an inode, so after `apt upgrade libc6` new processes use the new
  inode and are silently missed until the agent re-attaches;
- cost a trap on every `getaddrinfo` call system-wide, cache hits included;
- still not give the answers without walking user-space `addrinfo` lists. The packet capture already
  has the answers.

A kprobe on the kernel's UDP send path (`udp_sendmsg`, `udpv6_sendmsg`) sees every sender, whatever
library it uses, at the moment the query leaves. It also runs in the sender's task context, which
is exactly what attribution needs. The packet capture keeps providing the content (name, type,
answers, TTL).

**Ruling: kernel UDP send kprobes for attribution + AF_PACKET for content, instead of resolver
uprobes — costs: no visibility of lookups that never reach a socket (nscd over a Unix socket,
`/etc/hosts` hits, which 11a does not see either); no "intended name" for a lookup that is answered
from a resolver cache without a packet (systemd-resolved's cache answer to the app still crosses
`lo` and is seen); x86_64-only like the fs object.** Uprobes stay possible later as an *additional*
source and are a non-goal here.

## 3. Goals

### 3.1 DNS BPF program

1. **New BPF program `dns`** in `bpf/dns.bpf.c` + `bpf/dns.h`, built by `tools/ebpf/build.sh` into
   `dns.bpf.o` + sidecar, one object per sensor as in 11b-2/11b-3. It uses the same toolchain,
   integrity sidecar, `schema_version` `.rodata` global (its own schema, starting at 1), the same
   `SELF_TGID` exclusion and the same `DROPS` per-CPU counter. Its ring buffer is 256 KiB *(call:
   records are small, see 4)*.

2. **Hooks** *(call: kprobes, x86_64-only, same reasoning and same probe/fallback behaviour as the
   fs object in 11b-3 §2.1)*:

   | Hook (kprobe) | Required | Notes |
   |---|---|---|
   | `udp_sendmsg` | yes | IPv4 UDP, and IPv4-mapped destinations sent from IPv6 sockets (the kernel delegates them here) |
   | `udpv6_sendmsg` | yes | IPv6 UDP |

   These signatures (`struct sock *, struct msghdr *, size_t`) have been stable since well before
   5.15. The capability probe checks each symbol as in 11b-3 (`available_filter_functions`, then
   debugfs, then `/proc/kallsyms`). A missing one means fallback, with the symbol named in the
   reason.

3. **What the program emits.** On entry it works out the destination:
   - from `msg->msg_name` when `msg_namelen` is non-zero (an unconnected `sendto`/`sendmsg`);
   - otherwise from the socket (`sk_daddr`/`sk_dport` or `sk_v6_daddr` for a connected socket).

   It emits **only when the destination port is 53** *(call: the same port set as the 11a cBPF
   filter; other ports exit after the port check)*. The local port is the socket's `inet_sport`.
   It is already bound when `udp_sendmsg` runs, because `inet_sendmsg` autobinds first. The local
   address may be the wildcard. Nothing is staged and nothing waits for the syscall exit: this is
   side information that only attributes a packet. A failed send simply produces no packet to
   attribute *(call)*.
   - `udpv6_sendmsg` emits nothing for an IPv4-mapped destination, because the kernel hands that
     send to `udp_sendmsg`, which emits it. One send therefore gives one record.
   - **The agent's own sends are emitted** *(call)*. This object ignores `SELF_TGID`, so the
     agent's own lookups stay attributed as they are in 11a. There is no feedback loop to prevent:
     reading the ring buffer causes no UDP traffic. The loader still sets the map, because every
     object shares that contract.

4. **The record** (`struct dns_record`, `bpf/dns.h`) is fixed-size and pinned four ways
   (`_Static_assert`, Rust layout test, C-header text test, decode tests), as in `net.h`/`fs.h`:
   - header: `schema_version`, `kind`; one kind, `KIND_DNS_SEND 10`, continuing after fs's 6–9;
   - sender: `pid` (tgid), `tid`, `uid`, `comm[16]` (group leader's, as in net), `exe_dev`,
     `exe_ino` (the identity used by process v2 / net / fs);
   - `ktime_ns` at send;
   - `netns_ino`, the inode number of the socket's network namespace (`sk->__sk_common.skc_net->ns.inum`);
   - `family` (AF_INET / AF_INET6 of the destination as sent; an IPv4-mapped IPv6 destination is
     reported as AF_INET with the IPv4 address *(call: the captured packet is IPv4 too)*), `lport`,
     `rport` (host order), `laddr[16]`, `raddr[16]` (network order, IPv4 in the first 4 bytes).

   No payload bytes are read *(call: reading the DNS id would need walking an `iov_iter`, whose
   layout changed across 5.15–6.x; the 5-tuple, network namespace and kernel timestamps are enough,
   see 8)*.

### 3.2 Engine (`crates/osiris-ebpf`)

5. **`DNS_OBJECT` spec** with the two required kprobes, using the existing kprobe and
   required/optional support from 11b-3. `load_*` prints the verifier instruction counts as the
   other objects do.

6. **`dns_record.rs`**: `DnsSendEvent` + `decode_dns`, with tests mirroring `net_record.rs`
   (layout pinned, `tests/c_header.rs` extended, every malformed input rejected with a
   `DecodeError`, nothing panics).

### 3.3 DNS sensor (`crates/osiris-sensors/dns`)

7. **Two attribution backends chosen at `initialize`**, mirroring the 11b sensors. Capture changes
   in one way only: the `AF_PACKET` socket enables `SO_TIMESTAMPNS`, and each packet carries its
   kernel receive time from the control message (wall clock). If the control message is missing,
   the time falls back to today's `wall_ns()` at processing. That fallback is counted, and the join
   in 8 then widens to its slack bound.
   - **eBPF attribution**: `Healthy`, flags `ebpf_attribution` (plus the existing capture flags).
     The reader thread (`spawn_reader`) decodes each `DnsSendEvent`. It **resolves the exe
     immediately** with `osiris_ebpf::resolve_exe` while the sender is almost certainly still
     alive. It converts `ktime_ns` to wall time with the per-record boot offset (`clock.rs`), then
     inserts the resulting owner into a shared `SendTable`. Ring-buffer drops are added to
     `events_dropped_total`.
   - **Reader failure mid-run is a one-way latch** *(call)*. The sensor becomes `Degraded`, the
     reason goes into `last_error`, and the flag changes from `ebpf_attribution` to
     `procfs_attribution` for the rest of the run, until restart. The engine switches to `/proc`
     lookups for new queries. Transactions still pending attribution get a `/proc` lookup when they
     close (best-effort). Capture still works, so the sensor is not `Failed`.
   - **Health rule** *(call)*: the reported state is the worse of the backend state and the
     existing parse/eviction window. A backend `Degraded` (fallback at start or the latch) stays
     `Degraded` for the whole run. The capture loop must stop overwriting it, which it does today
     (`h.state = window.observe(..)`).
   - **procfs fallback** (eBPF configured but unusable): today's `Attributor`, `Degraded`, flag
     `procfs_attribution`, reason in `last_error`.
   - **procfs only** (no `ebpf` key): today's behaviour exactly, `Healthy`, flag
     `procfs_attribution` *(call: a new flag, so the backend is always visible in `/status`)*.
   - The constructor becomes `DnsSensor::new(proc_root, interface, ebpf: Option<EbpfSettings>)`.
     The agent passes the shared `ebpf_settings(config)` as it does for the other three sensors.

8. **`SendTable`** (pure, OS-neutral, unit-tested). It must never give a query to the wrong
   process when a port is reused. The rules:
   - **Key:** `(lport, raddr, rport)`, with IPv4 and IPv4-mapped forms normalised.
   - **Agent's namespace only.** Only sends from the agent's own network namespace are inserted.
     The agent reads that namespace's inode from `/proc/self/ns/net` at start. Sends from other
     namespaces (containers on a veth) are dropped and counted. Their packets were never
     attributable in 11a either: they arrive as `PACKET_HOST` or leave after SNAT. A host-netns
     entry can therefore never claim a SNAT'd container query by accident *(call)*.
   - **Small queue per key.** Each key holds the up to **8** most recent sends, oldest first, each
     with its wall-clock send time and owner *(call)*. A retransmission from the same socket is a
     second send and a second packet, so it gets its own entry.
   - **Matching a query packet:** take the **oldest** entry whose send time is within
     `[packet_ts − 2 s, packet_ts + 5 ms]`, and **remove it** (one entry per packet). Entries older
     than `packet_ts − 2 s` are discarded. The 5 ms slack covers the uncertainty of the
     ktime-to-wall conversion. When the packet has no kernel timestamp (7), the upper bound becomes
     the processing time *(calls: 2 s, 5 ms)*.
   - **Why this is safe under port reuse.** Process A closes port P. Process B binds P and sends to
     the same resolver. A's send happened before B's, so A's entry is older. Packet and record
     travel on separate paths, so A's packet may be processed before A's record is in the table,
     and B's packet may arrive after both records. Lookup by age alone would then hand A's entry
     to B. So a packet that misses registers a **claim** `(key, local address, packet_ts)`, kept in
     its pending transaction. **Older unresolved packets on a key have priority over newer ones**:
     claims older than the packet (earlier `packet_ts`, ties broken by claim order) first reserve,
     oldest claim first, the oldest entries inside their own windows with compatible local
     addresses; the packet takes the oldest entry left. A claimed packet's retry (at close and on
     each hold tick) applies the same rule against claims older than itself and drops its claim on
     a hit. Entries a claim could still take are not discarded by a newer lookup. When the engine
     gives up on a transaction (hold deadline, timeout or eviction miss, held overflow, drain miss,
     or a query the tracker did not keep) its claim becomes a **tombstone**: it keeps ranking and
     reserving like a live claim until the 10 s TTL, and when a record it reserves arrives late it
     consumes that entry silently (counted as `tombstone_consumed`), so a newer packet on the
     reused port cannot take it. A claim is released only when its owner was settled another way:
     a retry hit, a `/proc` resolve after the latch, or a retransmit that resolved the transaction
     (which also consumes the original send's entry, or tombstones the claim when that entry has not
     arrived). Retransmits make no claim of their own. Claims expire with the 10 s TTL and are
     capped at 16,384, oldest dropped. A claim whose own record was lost blocks only entries inside
     its window (`[packet_ts − 2 s, packet_ts + 5 ms]`), which B's later send normally is not.
     Unit tests cover these interleavings. **Known limits**, where a wrong owner is still possible:
     - two sockets sharing a port (`SO_REUSEPORT`), or two sends on one key within the 5 ms slack,
       can swap owners (§6);
     - a claim dropped at the cap no longer protects its entry, so a newer packet can take it;
     - when a captured packet is dropped, its sender's record has no claim, and a later packet on
       the key within the 2 s lookback can take it;
     - when a packet's own kernel record is lost (ring-buffer drop), its claim can take an entry
       sent on the key within the 5 ms slack after the packet;
     - a retransmit whose packet arrives before its own kernel record makes no claim, so its late
       record can be taken by a newer packet on a reused port within the 2 s lookback;
     - a tombstone can consume an older orphan entry in its lookback (an entry whose packet was
       dropped, the limit above), leaving its own late record unclaimed for a newer packet.
   - **Limits:** entries expire after **10 s** *(call: two 11a tracker timeouts)*. The table holds
     at most **16,384** entries; on overflow the oldest entry is evicted and counted *(call)*.
   - **Local address:** matched when both sides have one, ignored when the send came from a
     wildcard socket.

9. **When attribution is taken.** The kernel record and the captured packet travel on two
   different asynchronous paths, so either can arrive first.
   - At query-packet time the engine looks in the `SendTable`. On a hit it uses that owner.
   - On a miss it records the transaction as *pending attribution*. It does **not** run the
     `/proc` lookup in eBPF mode *(call: that lookup is the slow path that caused the lag)*.
   - When the transaction closes (response, timeout or eviction), a pending one looks in the
     `SendTable` again.
   - A response that closes a still-unattributed transaction holds it for at most **250 ms**
     *(call)*, re-checked on each tick, before it is emitted unattributed. Unattributed events keep
     11a's contract (`pid: None`, uid 0).
   - Metrics split `attributed` into `attributed_kernel` / `attributed_procfs`, plus
     `attribution_late` (hits found only at close) and `send_table_evictions`.
   - Only packets whose source is local are attributed, as today.

### 3.4 Schema, config and wiring

10. **No schema change.** `source` stays `PACKET` and the provider stays `dns_sensor/af_packet`: the
    event's content still comes from the packet *(call)*. Attribution origin is visible only in
    sensor health and metrics. `DnsRef`/`DnsEventRaw` are untouched.
11. **Config:** no new key. The DNS sensor uses kernel attribution whenever `dns_capture` and `ebpf`
    are both set. An existing deployment with both keys switches on upgrade, and
    `docs/operators-ebpf.md` says so.

### 3.5 Validation and docs

12. **Real-Linux tests** (`crates/osiris-real-linux-tests`, run on GH Actions via
    `real-linux/t11b4-*` branches, both runners). The WSL dev host can load and verify the object,
    but cannot run pid-matching tests (§5).
    - (a) `dns` is `Healthy` with `ebpf_attribution` and without `procfs_attribution`.
    - (b) The existing `dns_query_is_observed_and_alerts` passes unchanged.
    - (c) **Closed-socket client.** A `python3` child creates a UDP socket and sends one A query
      for `<marker>.xyz` to a local fake responder. The responder is a second python process bound
      to `127.0.0.1:53` *(call: answers after 300 ms, so the query and the answer are both seen on
      `lo` with no internet dependency)*. The client closes the socket right after `sendto`, sleeps
      2 s and exits. Expected: one stored `DNS_QUERY` with `dns.query = <marker>.xyz`, the client's
      pid and the python `exe_path`.
    - (d) **Exited client.** As (c), but the client exits right after `sendto`. Expected: the
      event carries the client's pid. `exe_path` is asserted only to be the python path or empty,
      never another process's path (the anti-goal of §4).
    - (c) and (d) send raw UDP from python's `socket` module, never through `getaddrinfo`, so they
      also prove that a non-glibc sender is covered *(call: no separate test)*.
    - (e) **Fallback.** A stack whose object dir lacks `dns.bpf.o` (the existing broken-copy
      pattern) has `dns` `Degraded` with `procfs_attribution`. The curl query is still stored
      (attribution there is best-effort and is not asserted).
    - (f) **Stress, the old flake's shape.** 200 closed-socket queries from 20 concurrent clients
      in a burst, with the full agent running (process, net and fs sensors on). At least **99 %**
      of the stored events are attributed to the right pid *(call: the missing 1 % is allowed for
      ring-buffer drops, which `events_dropped_total` must then show)*.
    - The verifier instruction counts are recorded in VALIDATION.md, as for the other objects.
13. **Benchmark** (informative, not a gate): 10,000 UDP sends to a non-53 port and 10,000 to
    port 53 on `lo`, with and without the agent, recorded in `PERFORMANCE.md`. A warning is
    required there if the non-53 overhead exceeds 5 %.
14. **Docs:** ARCHITECTURE §4.3 DNS row and status note (kernel send attribution + packet capture;
    the uprobe ruling); `docs/operators-ebpf.md` DNS section; `docs/operators-dns-sensor.md`
    attribution section; ADR-010 (fourth object, still hand-mirrored layouts); `docs/VALIDATION.md`
    (A/B result, runs, kernels, instruction counts; the flake entry closed or updated with
    evidence); `docs/ROADMAP-REMAINING.md` (11b-4 done, Phase 11b closed, debts below).

## 4. Anti-goals

These would count as failure even if the tests passed.

- **Attributing a query to the wrong process.** A wrong pid or exe is worse than none. A stale
  `SendTable` entry must not survive port reuse past its expiry. An exited sender's pid must never
  be turned into another process's exe; `resolve_exe`'s identity/comm checks already reject a
  recycled pid.
- Slowing down non-DNS UDP. The program must return after the destination port check for every
  port other than 53.
- Running the `/proc` scan on the hot path in eBPF mode.
- A missing object, a missing symbol or a verifier rejection leaving attribution silently dead. Each
  must surface as `Degraded` + `procfs_attribution` with the reason.
- Regressing the process, network or filesystem objects, or the 11a capture/pairing behaviour.

## 5. Non-goals

- Uprobes on glibc/libresolv/systemd-resolved (§2). Varlink/D-Bus resolver tracing.
- DNS over TCP, DoT, DoH, mDNS/LLMNR. These are the 11a blind spots, unchanged.
- Reading DNS payloads in the kernel.
- Special handling for io_uring sends. They reach `udp_sendmsg` either inline in the submitter or
  from an io-wq worker, and since 5.12 io-wq workers are threads of the submitting process. The
  tgid is therefore the submitter's on the supported kernels, and nothing extra is needed. This is
  reasoned, not tested.
- **PID-namespace-aware pids.** `bpf_get_current_pid_tgid()` returns init-namespace ids. An agent
  running in a child pid namespace (WSL2 distros, a container without `hostPID`) therefore sees pids
  that do not match its `/proc`. That affects every 11b object, not only DNS. It is recorded as a
  roadmap debt (candidate fix: `bpf_get_ns_current_pid_tgid` with the agent's pidns dev/ino, plus a
  per-namespace parent tgid). It is not part of this phase.
- arm64 builds of the kprobe objects (Phase 13 packaging debt, as for fs).

## 6. Known behaviour to document (not fix)

- With systemd-resolved, each lookup still yields two events: app → 127.0.0.53, attributed to the
  app, and resolved → upstream, attributed to `systemd-resolved`. Both are true.
- Two sockets sharing one local port at the same instant (`SO_REUSEPORT`) and sending to the same
  resolver within 5 ms of each other can swap attributions. Sequential port reuse is handled (8).
- Queries sent from other network namespaces (containers without host networking) are
  unattributed, as in 11a. Doing this per namespace is future work.
- A query sent before the agent started, or one whose record was dropped by the ring buffer, falls
  back to unattributed. In eBPF mode there is no `/proc` retry.
- Queries forwarded for other hosts (the host is itself a resolver) are not attributed, as in 11a.
- The DNS object is x86_64-only. On other architectures the sensor reports the reason and uses
  `/proc` attribution.

## 7. Constraints carried from earlier phases

- Rust stays OS-neutral and compiles on the Windows dev host. Linux-only code is
  `cfg(target_os = "linux")`. BPF objects are built only by `tools/ebpf/build.sh`.
- Gates before merge: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` (rebuild cli/server/agent first), `bash tools/check-dep-graph.sh`,
  console lint/test/build if touched.
- Real-Linux validation is the GH Actions matrix (push `real-linux/t11b4-<n>`). The WSL2
  Ubuntu-24.04 dev distro (kernel 6.18) may be used to build objects and check that they pass the
  verifier. Its pid namespace and missing auditd make it unsuitable for the suite.
- No `unwrap`/`expect` outside tests; recover poisoned locks; `blocking_send` from reader threads.
- Fetch before merging; push after every significant commit; remote test branches are deleted only
  with the user's OK.

## 8. Left to the builder

- The exact CO-RE reads for `msg_name` and the socket's address fields, and how IPv4-mapped
  destinations are detected. These must pass the 5.15+ verifier.
- Whether the `SendTable` lives behind a `Mutex` shared with the capture thread or is fed through a
  channel into the engine. Either is fine if the capture thread never blocks on the reader.
- Module layout inside the sensor crate, metric names and the exact shape of the fake responder and
  stress harness.
