# Agent → Server transport (mTLS)

By default the Server tails the Agent's spool file. Phase 9a adds a network
transport: the Agent's forwarder tails the spool, and the Server listens for
Agents over TLS 1.3 with mutual authentication. Frames are zstd-compressed JSON;
the forwarder persists its progress in `<spool>.offset`, so nothing is lost or
duplicated across restarts (delivery is at-least-once, acked by the Server).

## 1. Create the PKI (offline, on a trusted machine)

```sh
osiris pki init-ca --dir pki
osiris pki issue-server --dir pki osiris.example.com 10.0.0.5
osiris pki issue-agent  --dir pki <host-uuid>   # one per host
```

`ca.key` never leaves the trusted machine. Each Agent certificate carries the
SAN `urn:osiris:host:<uuid>`; the Server binds the connection to that host id
and refuses events claiming any other host.

## 2. Server (`agent_listener`)

```yaml
agent_listener:
  listen_addr: 0.0.0.0:9443
  cert: /etc/osiris/server.pem
  key: /etc/osiris/server.key
  client_ca: /etc/osiris/ca.pem
  revoked_hosts: []        # host UUIDs whose certificates must be refused
```

## 3. Agent (`forward`)

```yaml
forward:
  server_addr: osiris.example.com:9443
  server_name: osiris.example.com   # must match a server certificate SAN
  ca: /etc/osiris/ca.pem
  cert: /etc/osiris/agent.pem
  key: /etc/osiris/agent.key
```

Revoke a host by adding its UUID to `revoked_hosts` and restarting the Server.
Certificates are valid for 365 days (CA: 10 years); reissue before expiry.
