# Phase 9a — Secure Agent→Server transport (mTLS)

## Problem
Today the Agent appends NDJSON to a spool file and the Server tails the same path
(`SpoolFileSink` / `run_ingestion_loop`). That only works on one host and has no
authentication. ARCHITECTURE.md §8.3/§21.1 call for an authenticated stream so N
Agents can feed one Server. Tenant isolation (8f) keys on `event.host_id`, so the
transport must also stop an enrolled Agent from writing events for another host.

## Decisions
1. **Keep the spool as the durable buffer.** The Agent still writes the spool
   (crash-safe, already tested). A new **Forwarder** task tails it, ships batches, and
   persists an acknowledged byte offset in `<spool>.offset`. A slow/absent Server makes
   the spool grow (matches §8.3), never memory. Delivery is at-least-once; the event
   store is `INSERT OR IGNORE` on `event_id`, so duplicates are harmless.
2. **New crate `osiris-transport`** (frame codec, PKI helpers, rustls config, client
   Forwarder, server Listener). Deps: `tokio-rustls`/`rustls` (ring), `rustls-pemfile`,
   `rcgen`, `x509-parser`, `zstd`.
3. **Wire format:** length-prefixed frames (u32 BE, max 16 MiB), each frame
   `zstd(JSON)`. Messages: `Batch{seq, events}` (Agent→Server), `Ack{seq}` /
   `Nack{seq, reason}` (Server→Agent). JSON+zstd instead of protobuf/Cap'n Proto: the
   canonical schema is already serde; recorded as a deviation from §27 (revisit if
   profiling demands it).
4. **mTLS, TLS 1.3 only.** The Server requires a client certificate signed by the
   configured CA. Enrollment = the operator issues an Agent certificate with
   `osiris pki issue-agent`; revocation = a `revoked_hosts` list in the Server config
   (checked per connection). No unenrolled connection reaches the parser.
5. **Host binding.** The Agent certificate carries its host id as a SAN URI
   `urn:osiris:host:<uuid>`. The Server drops (Nack) any batch containing an event whose
   `host_id` differs from the certificate's. This keeps 8f's isolation sound.
6. **Ack after durable processing.** The Server acks a batch only after
   `IngestContext::ingest` (batch_write + detection + correlation) completes; on error
   it Nacks and the Forwarder retries with backoff (1s→30s).
7. **Same-host UDS is out of scope**: same-host deployments keep using `spool_path`
   (file permissions are the trust boundary). UDS adds nothing testable on the Windows
   dev host; recorded in the backlog.
8. **Ingest refactor.** `run_ingestion_loop` keeps its signature; its per-batch body
   moves into `IngestContext::ingest`, shared by the tailer and the network listener.
9. **CLI PKI.** `osiris pki init-ca`, `issue-server`, `issue-agent` (rcgen; ECDSA P-256;
   keys written 0600 on unix). Private keys never leave the machine that generated them
   except as files the operator copies.

## Config
Server: `agent_listener: { listen_addr, cert, key, client_ca, revoked_hosts: [uuid] }`
(optional; absent = spool-only as today). Agent: `forward: { server_addr, server_name,
ca, cert, key }` (optional; absent = spool-only).

## Non-goals
Server→Agent commands (9c), TLS on the HTTP API (9b), certificate rotation automation,
spool rotation/compaction (documented follow-up).

## Testing
Frame round-trip/limits; PKI issue + verify; live mTLS loopback: accepted with a good
cert, refused with none/foreign-CA/revoked; host-binding Nack; Forwarder resumes from
the persisted offset and redelivers after a Nack; end-to-end Agent spool → Server storage.
