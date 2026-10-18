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
