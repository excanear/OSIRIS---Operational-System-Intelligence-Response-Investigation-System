# Operator guide: TLS on the API and Console

By default `osiris-server` serves the API and the Console over plain HTTP, so
session tokens (and the WebSocket `token=` fallback) cross the network in
clear text. Enable native TLS to fix that without a reverse proxy.

## 1. Issue a certificate

Use a **separate CA directory for the API certificate**, not the Agent CA:

```
osiris pki init-ca --dir pki-api
osiris pki issue-server --dir pki-api --name api osiris.example.com 10.0.0.5
```

This writes `pki-api/api.pem` and `pki-api/api.key` (key mode 0600 on unix).
`--name` sets the file stem (default `server`). It must match
`[A-Za-z0-9_-][A-Za-z0-9._-]*` (no path separators, no `..`, no leading dot).
`issue-server` refuses to overwrite either the `.key` or the `.pem` (both are
checked before anything is written), so pick a new name when issuing from a CA
that already has a `server` certificate.

If you deliberately reuse the Agent CA from the agent-transport guide, run
`osiris pki issue-server --dir pki --name api ...` so the existing
`server.pem`/`server.key` used by the agent listener is left untouched.

**Why a separate CA.** The generated CA is unconstrained: anyone holding
`ca.key` can mint a certificate for any site that trusts the CA. Do not
install it into the operating system's root store. Keep `ca.key` offline or
tightly permissioned (it is not needed by the server at runtime), and never
copy it to the server host.

## 2. Configure the server

Add to `server.yaml`:

```yaml
listen_addr: 0.0.0.0:8443
api_tls:
  cert: /etc/osiris/pki-api/api.pem
  key: /etc/osiris/pki-api/api.key
  # Optional connection caps (defaults shown):
  # max_connections: 1024
  # max_connections_per_ip: 16
```

- TLS 1.3 only, ALPN `h2` and `http/1.1`, no client certificate required
  (session tokens remain the authentication).
- Every response carries `Strict-Transport-Security: max-age=31536000`.
- Limits: at most `max_connections` (default 1024) concurrent connections and
  `max_connections_per_ip` (default 16) per peer IP; further connections are
  closed immediately. Both must be between 1 and the runtime maximum
  (`Semaphore::MAX_PERMITS`); 0 or larger values are rejected at startup. An
  open WebSocket counts against both caps for its whole lifetime.
  **NAT / load balancers:** the per-IP cap sees the address of the nearest hop.
  Many users behind one NAT, or a proxy in front of the server, share one
  budget, so raise `max_connections_per_ip` (up to `max_connections`) there.
  Refusals are logged at debug, with at most one aggregate warning per 10 s.
- Timeouts: the TLS handshake must finish within 5 s; after it the client must
  send its first bytes, and each request's headers, within 30 s (a client that
  handshakes and then stays silent is dropped). HTTP/2 connections are pinged
  every 30 s and dropped after 20 s without an answer. Established idle
  WebSockets are not cut by these; they use their own ping/idle timeout.
- If the certificate or key is unreadable or invalid the server exits with
  status 1; it never falls back to HTTP.
- Without `api_tls` behaviour is unchanged (HTTP). Listening on a non-loopback
  address without `api_tls` logs a warning that tokens travel unencrypted.

## 3. Trust the CA

Trust it per site, not system-wide:

- **CLI:** `osiris --server https://osiris.example.com:8443 --ca-cert pki-api/ca.pem health`
  or set `OSIRIS_CA_CERT=pki-api/ca.pem`. The file may be a PEM bundle. The
  CA is trusted in addition to the system roots, and the option builds one
  shared HTTP client, so it also applies to `--agent` requests.
- **Browsers:** add a per-site certificate exception (or import the CA into
  the browser profile only, not the OS store). The Console and its WebSocket
  (`wss://`) then work same-origin; the WebSocket Origin check is unchanged.
- Development: the Vite dev server proxy talks to the API over plain HTTP by
  default; point its target at the `https://` URL only if the dev machine
  trusts the CA (for example via `NODE_EXTRA_CA_CERTS=pki-api/ca.pem`).

HSTS notes: the header is `max-age=31536000` only, with no `includeSubDomains`
and no `preload`. Browsers scope it to the exact host name (any port) they used,
not to its subdomains; a host that previously served HTTP will be upgraded to
HTTPS by browsers for a year.

## 4. Rotation

Certificates are read at startup. To rotate, issue a new certificate under a
new name (existing files are never overwritten):

```
osiris pki issue-server --dir pki-api --name api-2026 osiris.example.com 10.0.0.5
```

then point `api_tls.cert` / `api_tls.key` at the new files and restart
`osiris-server` (on SIGTERM the listener closes at once, open connections are drained for up
to about 10 seconds, and live WebSockets receive a Close frame).
Alternatively remove the old `api.pem`/`api.key` first and reissue with the
same name. There is no hot reload, automatic renewal, or HTTP to HTTPS
redirect listener.

## 5. Shutdown

On SIGTERM/SIGINT the HTTPS listener stops accepting immediately, in-flight
requests get up to 10 seconds to finish, and WebSocket streams are closed with
a Close frame. Without `api_tls` (plain HTTP) the graceful drain is also capped
at 10 seconds, after which the server exits. On plain HTTP, open WebSockets
are not closed cleanly: they are cut abruptly (no Close frame) when the
10-second cap expires.
