# Phase 9b — TLS on the API/Console (ARCHITECTURE §14.3, §17)

## Problem
`osiris-server` serves the API and Console over plain HTTP (`TcpListener` + `axum::serve`,
`crates/osiris-server/src/main.rs`). Session tokens, and the WebSocket `token=` query fallback,
cross the network in clear text unless an operator adds a reverse proxy.

## Decisions (approved 2026-09-19)
1. **Optional native TLS.** New optional config block `api_tls: { cert, key }` (PEM paths).
   When present the server terminates TLS 1.3 itself; when absent behaviour is unchanged (HTTP).
   Implementation: `tokio_rustls::TlsAcceptor` + `hyper_util` (`TokioIo`, `auto::Builder`,
   `TowerToHyperService`) over the existing `axum::Router`; no new server framework crate.
   Add direct deps `hyper-util` and `hyper` (already transitive via axum). A `serve_tls`
   function lives in a new `crates/osiris-server/src/api_tls.rs`; it reuses the cert/key loading
   helpers of `osiris-transport::tls` where possible (server-side, **no client auth**).
2. **ALPN** `h2` + `http/1.1`. Graceful shutdown on the server's existing cancellation token.
   TLS handshake timeout 5 s; a failed handshake never affects other connections.
3. **HSTS.** When TLS is active every response carries
   `Strict-Transport-Security: max-age=31536000` (middleware layered outermost; not sent on HTTP).
4. **Plaintext warning.** If `api_tls` is absent and `listen_addr` is not loopback, log a
   `tracing::warn!` at startup that tokens travel unencrypted.
5. **Fail closed.** Unreadable/invalid cert or key with `api_tls` set → exit(1) with a message
   naming the config key; never silently fall back to HTTP.
6. **CLI.** `--ca-cert <pem>` (env `OSIRIS_CA_CERT`) adds a trusted root to the blocking
   reqwest client used for `--server` requests. It is NOT applied to the `--agent` client path
   semantics beyond building one shared client (documented). `--server https://…` works otherwise.
7. **Console/WebSocket.** No code change: same-origin; `wss` derives from the page scheme. The
   Origin-vs-Host check in `stream.rs` is unchanged (must be covered by a test over TLS).
8. **PKI.** `osiris pki issue-server` already issues certificates for arbitrary DNS/IP names and
   is reused for the API certificate. Docs explain issuing one and trusting the CA in browsers.

## Out of scope
Client-certificate auth on the API (session tokens remain the auth), automatic cert renewal,
hot reload (cert change requires restart, same as 9a), HTTP→HTTPS redirect listener.

## Testing
- Unit: config parse (`api_tls` optional/present); HSTS layer present/absent; loopback detection.
- Integration (real sockets, rcgen certs from `osiris_transport::pki`): HTTPS request with the CA
  succeeds and carries HSTS; client without the CA is rejected; plain-HTTP request to the TLS port
  fails; bad cert path → `serve_tls` setup error; `/api/v1/stream/events` WebSocket over `wss`
  with a same-origin Origin works and a foreign Origin is 403.
- CLI: `--ca-cert` against a live TLS server returns success; without it fails.
- Docs: `docs/operators-api-tls.md`.
