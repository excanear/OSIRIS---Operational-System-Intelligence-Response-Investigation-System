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

  If that port collides with a host socket on the same port (exact or wildcard-bound), the second
  event is attributed to an unrelated host process. Processes in other network namespaces are
  never attributed, because the sensor reads the agent's own `/proc/net/udp`.
- The engine counters (packets, parse errors, duplicates, timeouts and so on) and the kernel's
  drop counter are not exported yet. Packet loss on a busy host is therefore silent.
