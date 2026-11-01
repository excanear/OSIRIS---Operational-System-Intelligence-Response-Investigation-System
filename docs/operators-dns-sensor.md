# Operator guide — DNS sensor (agent.yaml)

The DNS sensor passively captures UDP port 53 traffic (IPv4 and IPv6) with an AF_PACKET socket
and emits `DNS_QUERY` events (source `PACKET`, provider `dns_sensor/af_packet`) attributed to the
querying process when possible.

## Configuration

```yaml
dns_capture:
  interface: eth0   # optional
```

- `dns_capture` absent: the sensor is off.
- `dns_capture: {}`: capture on all interfaces.
- `dns_capture: { interface: <name> }`: capture on one interface only.

Fleet policy can stop and restart the sensor by the name `dns`, but only if `dns_capture` is
configured (see `operators-fleet-policy.md`).

## Attribution: kernel or /proc

The content of every event (name, type, answers, TTL) always comes from the captured packet. What
changes is how the sensor finds the process that sent the query. There is no new config key.

- **Kernel attribution** (Phase 11b-4), when both `dns_capture` and `ebpf` are set. kprobes on
  `udp_sendmsg` and `udpv6_sendmsg` (object `dns.bpf.o`) record the owner (pid, uid, comm,
  executable identity) of every send to port 53, in the sender's own context, at send time. The
  sensor joins each captured query with that record. A client that closes its socket or exits
  right after sending is still attributed, which `/proc` attribution cannot do. Health `HEALTHY`,
  capability flag `ebpf_attribution`. Details, requirements and the upgrade note:
  `docs/operators-ebpf.md`, "DNS attribution".
- **`/proc` attribution** (Phase 11a): the client's local port is looked up in
  `/proc/net/udp{,6}` and mapped to a pid through `/proc/*/fd` when the packet is processed. A
  socket closed by then is not found, so short-lived clients often come out unattributed. Used:
  - with no `ebpf` key: health `HEALTHY`, flag `procfs_attribution`;
  - when `ebpf` is set but kernel attribution is unusable (missing or corrupted `dns.bpf.o`,
    non-x86_64, a missing kprobe symbol, the agent's network namespace unreadable): `DEGRADED`, flag
    `procfs_attribution`, the reason in `last_error`;
  - after the kernel reader fails mid-run: `DEGRADED` and `procfs_attribution` until the agent
    restarts (a one-way switch).

The capture flag `af_packet` is reported in every mode. Flags and `last_error` are visible in the
agent's local `GET /status`.

**Kernel attribution never assigns a query to the wrong process when a port is reused: a query
can come out unattributed, but not misattributed, except in the cases below. Most are rare; the
captured-packet drop is not, under load.**

- Two sockets sharing one local port (`SO_REUSEPORT`) and sending to the same resolver, or two
  sends on one port within 5 ms of each other, can swap owners.
- A query whose kernel record was lost (ring-buffer drop) can take the record of a send made on the
  same port within 5 ms after it.
- When the captured query packet itself is dropped, its record can go to a later query on the same
  port within 2 s. This is not rare under load: once the capture socket drops packets, for example
  under a flood, wrong owners become likely. An attacker can cause it on purpose by flooding port
  53 from a decoy process and then reusing the decoy's ports. The drops show in
  `events_dropped_total` and the sensor reports `DEGRADED` for 60 s after them, so treat owners
  seen while the DNS sensor is `DEGRADED` with suspicion. The same holds for a retransmitted query whose packet arrives before its own
  kernel record, and for a query the sensor gave up on: the reservation it leaves behind (a
  tombstone) can consume an older orphaned record instead of its own, and its own late record can
  then go to a newer query.
- More than 16 384 queries waiting at once for their kernel record: the oldest lose their
  protection.

Other behaviour with kernel attribution:

- Unattributed events keep the 11a contract (`process` null, uid 0). This happens for queries sent
  before the agent started, sends whose kernel record was lost, and sends from another network
  namespace (containers without host networking, counted as `foreign_netns`). In this mode no
  `/proc` lookup is attempted for them.
- A response that closes a still-unattributed query waits up to 250 ms for the kernel record before
  the event is emitted unattributed.
- The agent's own lookups are attributed to the agent.
- On systemd-resolved hosts each lookup still yields two events, both true: the app's query to
  127.0.0.53 (attributed to the app) and systemd-resolved's upstream query (attributed to
  `systemd-resolved`).
- Kernel ring-buffer drops count in `events_dropped_total`. A sudden burst of thousands of queries
  can overflow the 256 KiB ring buffer (`PERFORMANCE.md`, "DNS send path"); the affected queries
  are emitted unattributed.

## Requirements and limitations

- Needs `CAP_NET_RAW` (root or a granted capability).
- If the socket cannot be opened at initialize (no `CAP_NET_RAW`, unknown interface), the sensor
  is reported unsupported or failed and is not retried. Socket errors after start are retried with
  backoff.
- DNS over TCP, DoT, DoH and mDNS are not captured.
- On systemd-resolved hosts one lookup yields events for the app (via 127.0.0.53) and for
  systemd-resolved upstream; see `VALIDATION.md`, "DNS sensor (Phase 11a)".
- Forwarded and NATed traffic (Docker hosts, routers) is seen twice:
  - First on the veth or bridge as an incoming packet. It is not local, so it is not attributed.
  - Again on egress as `PACKET_OUTGOING`. The sensor treats that copy as sent by the host, so it
    yields a second `DNS_QUERY` event, attributed by its post-masquerade source port.

  With `/proc` attribution, if that port collides with a host socket on the same port (exact or
  wildcard-bound), the second event is attributed to an unrelated host process. With kernel
  attribution the container's send comes from another network namespace and never enters the send
  table, so the egress copy normally stays unattributed. Processes in other
  network namespaces are never attributed, in either mode.
- The engine counters (packets, parse errors, duplicates, timeouts and so on) and the kernel
  attribution counters (`foreign_netns`, `send_table_evictions`, `timestamp_fallbacks`) are not
  exported to `/status`.
- `events_dropped_total` adds up losses in different units:
  - kernel ring-buffer records that could not be reserved (one per lost send record), and records
    that did not decode;
  - packets the capture socket dropped because the sensor fell behind (the kernel's
    `PACKET_STATISTICS` counter, read at most once a second). On `lo` the socket queues both copies
    of every packet, so one lost query can count once or twice, and a dropped copy the sensor would
    have skipped counts too;
  - events whose send to the agent pipeline failed (at shutdown, every event not yet sent).

  It is a loss signal, not an exact count of lost queries. In a 10 000-query flood on `lo`, measured
  before capture-socket drops were counted, only about 3 000 queries (kernel attribution) or 850
  (`/proc` attribution) came out and the loss did not show (`PERFORMANCE.md`). It now does.
- Health under a flood: `DEGRADED` is reported for 60 s after parse errors, after more than 4 096
  queries are pending at once, or after the capture socket drops packets.
