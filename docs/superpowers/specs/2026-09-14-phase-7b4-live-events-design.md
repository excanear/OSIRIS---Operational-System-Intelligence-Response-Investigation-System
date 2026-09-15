# Phase 7b-4: Live Events (WebSocket) — Design Spec

## Context

`ARCHITECTURE.md` has specified a Live Events WebSocket screen since the system diagram (L32: "HTTPS / REST + WebSocket (query, stream)") and route table (L702: `WS /api/v1/stream/events`) were written, but no `axum::extract::ws` usage exists anywhere in the codebase. Every prior phase (7a, 7b-1, 7b-2, 7b-3) deliberately deferred it — 7b-2's spec called it out explicitly as needing "new backend work (a WebSocket...)", and 7b-3's spec scoped it out as deserving "its own dedicated design pass." This spec is that pass.

## Documentation defect found during brainstorming (out of scope, filed here for a future small fix)

`ARCHITECTURE.md` §14.4 cites "§9.1" and "§18.3" for the Bus policy and the Live Events screen respectively. In the current document those sections are actually Event Schema design principles and Privilege Boundary Model — unrelated. The real content lives at §8.1 (Local bus) and §16.3 (Screen↔API mapping). Additionally, §8.1's prose (drop-oldest per lane, CRITICAL spills to a `DiskSpool` rather than being dropped) does not match `crates/osiris-bus/src/bus.rs`'s actual implementation, which uses `try_send` for every lane including CRITICAL (drop-**newest**-with-metric, no spill, no `DiskSpool` type exists). This is a pre-existing doc/code mismatch, unrelated to this phase's own work — noted here rather than silently worked around, not fixed as part of this phase.

## Ruling: which "Bus policy" the WS channel matches

§14.4 says the WS channel should be "independently bounded... matching the Bus's own policy." Given the mismatch above, this phase matches the **real Bus code's** behavior (bounded channel, `try_send`, drop-newest-with-counter under pressure) rather than the doc's inconsistent prose (drop-oldest, disk-spill). This is a deliberate, human-approved choice, not an oversight.

## Architecture overview

```
Agent spool → LineTailer → run_ingestion_loop (osiris-server/src/ingest.rs)
                              │
                              ├─ storage.batch_write(&events)      [existing]
                              ├─ detection_engine.evaluate_batch   [existing]
                              ├─ ... baseline/risk/correlation     [existing]
                              └─ NEW: broadcaster.publish(&events) — called only
                                 after a successful batch_write, on the same
                                 events Detection consumes; synchronous,
                                 non-blocking, cannot slow ingestion
                                       │
                              LiveEventBroadcaster (new osiris-api module)
                                 one bounded mpsc::Sender<CanonicalEvent> per
                                 open WS connection + that connection's
                                 optional parsed OQL filter (Ast)
                                       │
                    ┌──────────────────┼──────────────────┐
              Conn A (host_id=X)  Conn B (unfiltered)  Conn C (q=...)
                    │                  │                  │
              try_send → on Err(Full), drop the new event for that one
              connection and increment its dropped_total counter — mirrors
              osiris-bus's try_send semantics exactly; a slow browser tab
              can never block ingestion or any other connection
                    │
              GET/Upgrade /api/v1/stream/events → Console's Live Events screen
```

## Backend

### New module: `crates/osiris-api/src/stream.rs`

Follows the exact precedent `crates/osiris-api/src/incidents.rs` already set: its own state type, its own `build_*_router` function, merged into the app router in `main.rs` alongside `build_router` and `build_incident_evidence_router` — not folded into the existing `Arc<dyn Storage>`-only state.

```rust
pub struct LiveEventBroadcaster {
    connections: Mutex<Vec<Connection>>,
}

struct Connection {
    id: Uuid,
    filter: Option<osiris_query::Ast>,   // None = unfiltered (every event matches)
    sender: mpsc::Sender<CanonicalEvent>, // bounded, capacity 4096
    dropped_total: Arc<AtomicU64>,
}

impl LiveEventBroadcaster {
    pub fn new() -> Self;

    /// Registers a new connection. Returns its id (for unsubscribe), the
    /// receiver half the WS handler forwards to the socket, and a shared
    /// drop counter for observability.
    pub fn subscribe(&self, filter: Option<osiris_query::Ast>) -> (Uuid, mpsc::Receiver<CanonicalEvent>, Arc<AtomicU64>);

    /// Removes the connection. If its `dropped_total` is non-zero, emits one
    /// `tracing::warn!` summarizing the count for that connection's lifetime
    /// — not one log line per dropped event (which would itself add load
    /// under the same sustained-overflow condition it's reporting on). No
    /// metrics endpoint exists yet in this codebase to hang a live counter
    /// off of instead.
    pub fn unsubscribe(&self, id: Uuid);

    /// Called once per successfully-persisted batch from the ingestion loop.
    /// For each connection whose filter matches (or has no filter), calls
    /// `sender.try_send(event.clone())`. On `Err(TrySendError::Full)`,
    /// increments that connection's `dropped_total` and moves on — never
    /// blocks, never retries, never affects other connections.
    pub fn publish(&self, events: &[CanonicalEvent]);
}

pub fn build_stream_router(broadcaster: Arc<LiveEventBroadcaster>) -> Router;
```

**Channel capacity: 4096.** Matches `osiris-bus`'s VERBOSE lane (`crates/osiris-bus/src/bus.rs:21-29`) — the largest, most permissive capacity in that file. This stream is a single unified feed (not split into 5 priority lanes; a browser tab has no equivalent of the Agent's own drain-priority concept), so it takes the most generous existing capacity as its bound rather than inventing a new number.

**`publish()` is synchronous and cheap** (mutex lock, iterate, `osiris_query::eval::eval_ast` filter check, `try_send`) — called directly from the async ingestion task, no `spawn_blocking` needed. "Cheap" is relative to `spawn_blocking`, not free: each `eval_ast` field lookup does a full `serde_json::to_value(event)` serialization, so a connection whose filter compares multiple fields pays multiple full event serializations per event.

### Ingestion tap: `crates/osiris-server/src/ingest.rs`

`run_ingestion_loop` gains one new parameter, `broadcaster: Arc<LiveEventBroadcaster>`, constructed once in `main.rs` alongside `storage` and the engines. One addition in the existing success arm:

```rust
Ok(Ok(_report)) => broadcaster.publish(&events),
```

Tapping here (after `spawn_blocking` returns `Ok(Ok(_))`, i.e. after `batch_write` has already succeeded) means the live stream never shows an event that failed to persist — it only ever reflects events Detection also consumed, matching §14.4's "same post-ingestion event stream Detection consumes" literally.

### Route and query contract

```
GET /api/v1/stream/events                 — unfiltered, every event
GET /api/v1/stream/events?host_id=<uuid>  — shorthand: only that host's events
GET /api/v1/stream/events?q=<OQL string>  — full filter, same grammar as GET /events?q=
```

`host_id` and `q` are mutually exclusive — both present is a `400` before the upgrade, same status the REST `/events` endpoint already uses for a bad `q`. `host_id` desugars server-side to `Ast::Compare{field:"host.host_id", op:Eq, value:Str(...)}`. `q` is parsed with the existing `osiris_query::parser` — the identical code path `GET /events?q=` uses today, so any query valid there is valid here. A parse error returns `400` with the parser's error message, same as `/events`.

On successful upgrade: `broadcaster.subscribe(filter)` registers the connection. Two tasks per socket:
1. Forwards `mpsc::Receiver<CanonicalEvent>` → `Message::Text(serde_json::to_string(&event).unwrap())` on the WS sink.
2. Drains incoming WS frames solely to detect `Message::Close` (the client never sends application data on this socket).

Either task ending (send failure, receive `Close`, socket error) triggers `broadcaster.unsubscribe(id)` and the other task's cancellation.

**No authentication** on this endpoint, consistent with every other endpoint in the API today — `ARCHITECTURE.md` §14.3's session/RBAC model is unimplemented everywhere in this codebase, not selectively skipped here.

### Dev proxy

`console/vite.config.ts`'s existing `/api` proxy entry (proxying to `http://127.0.0.1:8080`) needs `ws: true` added. Vite's proxy does not upgrade WebSocket connections by default; without this flag `/api/v1/stream/events` would silently fail to upgrade through the dev server.

## Console

### `console/src/api/liveEvents.ts`

A hook wrapping the browser's native `WebSocket` — not TanStack Query, since this is a push stream rather than a request/response and none of the existing hooks fit that shape.

```ts
export function useLiveEvents(filter?: { hostId: string } | { q: string }): {
  events: CanonicalEvent[];       // newest-first, capped at 500 (ring buffer)
  connectionState: "connecting" | "live" | "reconnecting" | "disconnected";
  paused: boolean;
  setPaused: (paused: boolean) => void;
  clear: () => void;
};
```

Builds the WS URL from `filter` (`?host_id=...` or `?q=...`, or neither), opens a `WebSocket`. On each message: parse JSON as `CanonicalEvent`, prepend into a 500-capacity ring buffer (oldest silently dropped past the cap) — this happens regardless of `paused`, so the buffer never falls behind; `paused` only controls whether the *rendered* list updates, meaning Resume always shows the latest 500 events rather than replaying a frozen snapshot. `connectionState` starts `"connecting"`, becomes `"live"` on open. On `onclose`/`onerror`: reconnect with exponential backoff (1s, 2s, 4s, 8s, 16s, capped at 30s; resets to 1s after a successful reopen), `connectionState` becomes `"reconnecting"` during backoff. `"disconnected"` is not currently reachable (backoff retries indefinitely) — reserved for a future explicit-stop control if one is added later.

### `console/src/screens/live/LiveEvents.tsx`

Follows `ThreatHunting.tsx`'s existing inline-table style — no extracted shared table component, matching this codebase's established per-screen pattern (confirmed: `ThreatHunting.tsx` and `Timeline.tsx` both render their own inline `<table>` rather than sharing one).

- Filter inputs: a Host ID text field and a raw OQL query text field, mutually exclusive in the UI the same way the backend enforces (selecting one clears the other) — reopens the WebSocket with the new filter on submit.
- Connection-state indicator (`Live` / `Reconnecting…` / `Connecting…`) rendered near the top.
- Pause / Resume button; Clear button (empties the ring buffer immediately, independent of pause state).
- Table columns: Event type | Timestamp | Host — identical to `ThreatHunting.tsx`'s results table (`event.event_type`, `event.timestamp`, `event.host.hostname`), newest event first.

### Wiring

`Live Events` already exists as a `ComingSoon`-backed placeholder nav item from an earlier phase (per `navItems.ts`'s already-fixed declaration order, confirmed in the 7b-3 ledger's preflight scan) — this phase replaces that placeholder with the real screen. No nav-array reordering needed.

### Tests

`LiveEvents.test.tsx`: renders; connects (mocked `WebSocket`); receives and renders an event; Pause freezes the visible table while new messages keep arriving into the buffer; connection-state text transitions correctly through open → close → reconnecting.

`liveEvents.test.ts` (hook unit tests): ring buffer caps at 500; `paused` doesn't stop ingestion into the buffer, only rendering; backoff delay sequence; filter query-string construction (`host_id` vs `q`, never both).

Backend: `stream.rs` unit tests for `LiveEventBroadcaster` — `publish()` respects per-connection filters (`eval_ast` true/false cases reusing `osiris-query`'s existing test fixtures); a full connection channel drops the new event and increments `dropped_total` without affecting a second, non-full connection; `unsubscribe` stops further `try_send` calls to that connection. An integration-style test spinning up the WS route with `axum::extract::ws`'s test utilities (or a raw `tokio-tungstenite` client against a bound test server, whichever the implementer finds less brittle) covering: connect unfiltered → receive a published event; connect with `host_id` → only matching events arrive; connect with a malformed `q` → `400` before upgrade.

## Out of scope (explicitly deferred, not blocking this phase)

- **Pivot links into Live Events** from Process/Incident detail screens (e.g., "watch this host live"). Nothing in this design blocks adding one later; §16.3's mapping table doesn't require it, so it's left as a future small follow-up rather than pulled into this phase's scope.
- **Fixing the `ARCHITECTURE.md` §14.4 cross-reference / §8.1 doc-vs-code mismatch** noted above. Filed here for visibility; not part of this phase's diff.
- **Metrics/observability endpoint** for `dropped_total` counters — surfaced via `tracing` only in this phase, since no metrics infrastructure (Prometheus endpoint, etc.) exists yet in the codebase to extend.
