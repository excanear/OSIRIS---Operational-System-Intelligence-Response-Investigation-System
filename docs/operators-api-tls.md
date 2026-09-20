# Operator guide: TLS on the API and Console

By default `osiris-server` serves the API and the Console over plain HTTP, so
session tokens (and the WebSocket `token=` fallback) cross the network in
clear text. Enable native TLS to fix that without a reverse proxy.

## 1. Issue a certificate

Reuse the private CA from the agent-transport guide (or create one with
`osiris pki init-ca --dir pki`), then issue a server certificate for every
DNS name and IP address clients will use:

```
osiris pki issue-server --dir pki osiris.example.com 10.0.0.5
```

This writes a certificate and key (PEM; key mode 0600 on unix) into `pki/`.

## 2. Configure the server

Add to `server.yaml`:

```yaml
listen_addr: 0.0.0.0:8443
api_tls:
  cert: /etc/osiris/pki/server.pem
  key: /etc/osiris/pki/server.key
```

- TLS 1.3 only, ALPN `h2` and `http/1.1`, no client certificate required
  (session tokens remain the authentication).
- Every response carries `Strict-Transport-Security: max-age=31536000`.
- If the certificate or key is unreadable or invalid the server exits with
  status 1; it never falls back to HTTP.
- Without `api_tls` behaviour is unchanged (HTTP). Listening on a non-loopback
  address without `api_tls` logs a warning that tokens travel unencrypted.

## 3. Trust the CA

- **CLI:** `osiris --server https://osiris.example.com:8443 --ca-cert pki/ca.pem health`
  or set `OSIRIS_CA_CERT=pki/ca.pem`. The option builds one shared HTTP client,
  so it also applies to `--agent` requests. Without it, the system roots are used.
- **Browsers:** import `ca.pem` as a trusted root (OS certificate store, or
  Settings > Privacy > Certificates in Firefox). The Console and its
  WebSocket (`wss://`) then work same-origin; the WebSocket Origin check is
  unchanged.

## 4. Rotation

Certificates are read at startup. To rotate, replace the files and restart
`osiris-server`. There is no hot reload, automatic renewal, or HTTP to HTTPS
redirect listener.
