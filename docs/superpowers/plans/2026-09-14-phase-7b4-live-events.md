# Phase 7b-4: Live Events (WebSocket) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the Live Events WebSocket stream — `GET /api/v1/stream/events`
on the backend, and a real Console screen replacing the existing
`ComingSoon` placeholder — so an analyst can watch ingested events arrive
in near-real-time, optionally scoped to one host or an OQL query.

**Architecture:** A new `LiveEventBroadcaster` (in `osiris-api`, following
`IncidentEvidenceState`'s own-state-plus-own-router precedent exactly)
holds one bounded `tokio::sync::mpsc` channel per open WebSocket
connection. The existing ingestion loop calls `broadcaster.publish(&events)`
once per batch, immediately after a successful `storage.batch_write` — the
same events Detection consumes. `publish()` evaluates each connection's
optional OQL filter with `osiris_query::eval_ast` (already built for
SQL-pushdown fallback, reused here unchanged) and `try_send`s matching
events; a full connection's channel just drops the new event for that one
connection, mirroring `osiris-bus`'s real `try_send` semantics exactly —
never blocking ingestion or any other connection. The Console gets a small
`useLiveEvents` hook wrapping the native `WebSocket`, with a 500-event ring
buffer, a pause control, and reconnect-with-backoff.

**Tech Stack:** Same as 7b-1/7b-2/7b-3 — Rust/axum on the backend (touching
`osiris-api` and `osiris-server` only), Vite/React 18/TypeScript 5/TanStack
Query v5/Vitest on the console (this feature's own data path uses the
native browser `WebSocket` API directly, not TanStack Query, since it's a
push stream). Two new dev-only Rust dependencies for the backend's
integration test: `tokio-tungstenite` and `futures-util`.

**Spec:** `docs/superpowers/specs/2026-09-14-phase-7b4-live-events-design.md`

## Global Constraints

- `LiveEventBroadcaster` lives in `crates/osiris-api/src/stream.rs` — its
  own state type and its own `build_stream_router(state) -> Router`,
  merged into the app alongside `build_router` and
  `build_incident_evidence_router` in `main.rs`, never folded into the
  existing `Arc<dyn Storage>`-only state.
- Per-connection channel capacity is `4096`, matching `osiris-bus`'s
  VERBOSE lane (`crates/osiris-bus/src/bus.rs:21-29`) — the largest,
  most permissive capacity that file defines. A full connection's channel
  drops the *new* event for that one connection via `try_send` (never
  blocks, never affects other connections or ingestion), incrementing a
  per-connection `dropped_total: Arc<AtomicU64>`.
- Route: `GET /api/v1/stream/events`, with `host_id` (shorthand,
  `Ast::Compare{field:"host_id", op:Eq, value:Str(...)}`) and `q` (full
  OQL, parsed the same way `GET /events?q=` already does via
  `osiris_query::EventQueryPlan::with_filter`) as mutually exclusive
  optional query params. Both present is a `400` before the WebSocket
  upgrade. No new authentication — matches every existing endpoint.
- `run_ingestion_loop` (`crates/osiris-server/src/ingest.rs`) gains one new
  parameter, `broadcaster: Arc<LiveEventBroadcaster>`, inserted
  immediately after `correlation_engine` and before `poll_interval`.
  `broadcaster.publish(&events)` is called only in the existing
  `Ok(Ok(_report)) => {}` arm — i.e. only after a successful
  `batch_write` — never on a failed or malformed batch.
- Console: `console/src/api/liveEvents.ts`'s `useLiveEvents` hook uses the
  native `WebSocket`, not TanStack Query. Ring buffer capped at 500 events
  (newest first), independent of `paused` — pausing only freezes what's
  *rendered*; Resume always shows the latest 500. Reconnect on
  close/error with exponential backoff (1s → 2s → 4s → 8s → 16s → capped
  at 30s, reset to 1s on a successful reopen).
- `console/vite.config.ts`'s existing `/api` proxy entry gains `ws: true`
  — required for Vite's dev proxy to forward a WebSocket upgrade.
- `Live Events` already exists as a `ComingSoon`-backed placeholder nav
  item (`console/src/app/navItems.ts`, already `enabled: false` at its
  fixed array position, second after Overview) — this phase flips it to
  `enabled: true` and swaps the `ComingSoon` route for the real screen. No
  nav-array reordering.
- No Playwright/e2e — Vitest + React Testing Library only, plus one
  Rust-side integration test using a real bound `TcpListener` and a
  `tokio-tungstenite` client (no browser needed to test the WebSocket
  wire protocol itself).
- `cargo test --workspace` and `cargo clippy --workspace --all-targets --
  -D warnings` must pass after every backend task. `npm test`, `npm run
  build`, and `npm run lint` must pass in `console/` after every frontend
  task.
- Numeric timestamps are nanoseconds since the Unix epoch everywhere,
  matching every prior phase's convention.
- Dark-first, information-dense, monospace-for-data-fields visual
  direction continues unchanged.

---

### Task 1: Backend — `LiveEventBroadcaster` core

**Files:**
- Create: `crates/osiris-api/src/stream.rs` (`LiveEventBroadcaster`,
  `subscribe`/`unsubscribe`/`publish`)
- Modify: `crates/osiris-api/src/lib.rs` (add `pub mod stream;` and
  `pub use stream::LiveEventBroadcaster;`)
- Modify: `crates/osiris-api/Cargo.toml` (add `tracing` dependency)

**Interfaces:**
- Consumes: `osiris_query::{Ast, eval_ast}` (existing, unchanged);
  `osiris_schema::CanonicalEvent` (existing, unchanged).
- Produces: `osiris_api::LiveEventBroadcaster` with `pub fn new() -> Self`,
  `pub fn subscribe(&self, filter: Option<Ast>) -> (Uuid,
  mpsc::Receiver<CanonicalEvent>, Arc<AtomicU64>)`, `pub fn unsubscribe(&self,
  id: Uuid)`, `pub fn publish(&self, events: &[CanonicalEvent])`. Task 2
  consumes all four; Task 3 consumes `new`/`publish`.

- [ ] **Step 1: Write the failing tests**

Create `crates/osiris-api/src/stream.rs` with only this content (the
`LiveEventBroadcaster` it references doesn't exist yet — this is the
expected compile failure):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_query::{Ast, Op, Value};
    use osiris_schema::{
        Category, EventType, HostRef, Severity, Source, CanonicalEvent, SCHEMA_VERSION,
    };
    use tokio::sync::mpsc::error::TryRecvError;
    use uuid::Uuid;

    fn sample_event(host_id: Uuid, event_type: EventType) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1000,
            monotonic_timestamp: 1000,
            event_type,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn an_unfiltered_connection_receives_a_published_event() {
        let broadcaster = LiveEventBroadcaster::new();
        let (_id, mut receiver, _dropped) = broadcaster.subscribe(None);
        let host_id = Uuid::new_v4();
        let event = sample_event(host_id, EventType::ProcessExec);

        broadcaster.publish(&[event.clone()]);

        let received = receiver.try_recv().unwrap();
        assert_eq!(received.event_id, event.event_id);
    }

    #[tokio::test]
    async fn a_filtered_connection_only_receives_matching_events() {
        let broadcaster = LiveEventBroadcaster::new();
        let matching_host = Uuid::new_v4();
        let other_host = Uuid::new_v4();
        let filter = Ast::Compare {
            field: "host_id".to_string(),
            op: Op::Eq,
            value: Value::Str(matching_host.to_string()),
        };
        let (_id, mut receiver, _dropped) = broadcaster.subscribe(Some(filter));

        broadcaster.publish(&[
            sample_event(other_host, EventType::ProcessExec),
            sample_event(matching_host, EventType::ProcessExec),
        ]);

        let received = receiver.try_recv().unwrap();
        assert_eq!(received.host_id, matching_host);
        assert_eq!(receiver.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[tokio::test]
    async fn a_full_connection_channel_drops_the_newest_event_and_counts_it() {
        let broadcaster = LiveEventBroadcaster::new();
        let (_id, _receiver, dropped) = broadcaster.subscribe(None);
        let host_id = Uuid::new_v4();
        // Nobody drains `_receiver`, so after LIVE_EVENT_CHANNEL_CAPACITY
        // successful sends the channel is full; the next publish must drop.
        let events: Vec<CanonicalEvent> = (0..LIVE_EVENT_CHANNEL_CAPACITY + 1)
            .map(|_| sample_event(host_id, EventType::ProcessExec))
            .collect();

        broadcaster.publish(&events);

        assert_eq!(dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn unsubscribe_stops_further_delivery() {
        let broadcaster = LiveEventBroadcaster::new();
        let (id, mut receiver, _dropped) = broadcaster.subscribe(None);

        broadcaster.unsubscribe(id);
        broadcaster.publish(&[sample_event(Uuid::new_v4(), EventType::ProcessExec)]);

        assert_eq!(receiver.try_recv().unwrap_err(), TryRecvError::Disconnected);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p osiris-api stream::`
Expected: FAIL — compile error, `LiveEventBroadcaster` and
`LIVE_EVENT_CHANNEL_CAPACITY` don't exist yet.

- [ ] **Step 3: Add the `tracing` dependency**

In `crates/osiris-api/Cargo.toml`, add `tracing = { workspace = true }` to
the `[dependencies]` section (anywhere among the existing entries).

- [ ] **Step 4: Implement `LiveEventBroadcaster`**

At the top of `crates/osiris-api/src/stream.rs` (above the `#[cfg(test)]`
module), add:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use osiris_query::{eval_ast, Ast};
use osiris_schema::CanonicalEvent;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Matches `osiris-bus`'s VERBOSE lane capacity
/// (`crates/osiris-bus/src/bus.rs:21-29`) — the largest, most permissive
/// capacity that file defines. This stream is one unified feed (not split
/// into 5 priority lanes; a browser tab has no equivalent of the Agent's
/// own drain-priority concept), so it takes the most generous existing
/// capacity as its bound rather than inventing a new number.
const LIVE_EVENT_CHANNEL_CAPACITY: usize = 4096;

struct Connection {
    id: Uuid,
    filter: Option<Ast>,
    sender: mpsc::Sender<CanonicalEvent>,
    dropped_total: Arc<AtomicU64>,
}

/// Fans out ingested events to live WebSocket connections
/// (ARCHITECTURE.md §14.4). Each connection gets its own bounded channel;
/// `publish` uses `try_send` per connection, matching `osiris-bus`'s real
/// (not documented) backpressure behavior exactly — a full channel drops
/// the new event for that one connection, never blocking ingestion or any
/// other connection (`crates/osiris-bus/src/bus.rs:96-105`).
#[derive(Default)]
pub struct LiveEventBroadcaster {
    connections: Mutex<Vec<Connection>>,
}

impl LiveEventBroadcaster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a new connection. Returns its id (for `unsubscribe`), the
    /// receiver half a WebSocket handler forwards to the socket, and a
    /// shared drop counter for observability.
    pub fn subscribe(&self, filter: Option<Ast>) -> (Uuid, mpsc::Receiver<CanonicalEvent>, Arc<AtomicU64>) {
        let id = Uuid::new_v4();
        let (sender, receiver) = mpsc::channel(LIVE_EVENT_CHANNEL_CAPACITY);
        let dropped_total = Arc::new(AtomicU64::new(0));
        self.connections.lock().unwrap().push(Connection {
            id,
            filter,
            sender,
            dropped_total: dropped_total.clone(),
        });
        (id, receiver, dropped_total)
    }

    /// Removes the connection. If its `dropped_total` is non-zero, emits
    /// one `tracing::warn!` summarizing the count for that connection's
    /// lifetime — not one log line per dropped event (which would itself
    /// add load under the same sustained-overflow condition it reports).
    pub fn unsubscribe(&self, id: Uuid) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(pos) = connections.iter().position(|c| c.id == id) {
            let removed = connections.remove(pos);
            let dropped = removed.dropped_total.load(Ordering::Relaxed);
            if dropped > 0 {
                tracing::warn!(
                    connection_id = %id,
                    dropped_total = dropped,
                    "live event stream connection closed after dropping events under sustained overflow"
                );
            }
        }
    }

    /// Called once per successfully-persisted ingestion batch. For each
    /// connection whose filter matches (or has no filter), `try_send`s the
    /// event. On `Err` (channel full), increments that connection's
    /// `dropped_total` and moves on.
    pub fn publish(&self, events: &[CanonicalEvent]) {
        let connections = self.connections.lock().unwrap();
        for event in events {
            for conn in connections.iter() {
                let matches = match &conn.filter {
                    Some(ast) => eval_ast(event, ast),
                    None => true,
                };
                if matches && conn.sender.try_send(event.clone()).is_err() {
                    conn.dropped_total.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p osiris-api stream::`
Expected: PASS (all 4 tests).

- [ ] **Step 6: Register the module**

In `crates/osiris-api/src/lib.rs`, near the existing `pub mod evidence;` /
`pub mod incidents;` / `pub use incidents::{...};` lines, add:

```rust
pub mod stream;
pub use stream::LiveEventBroadcaster;
```

- [ ] **Step 7: Run the full workspace check**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: both pass.

- [ ] **Step 8: Commit**

```bash
git add crates/osiris-api/src/stream.rs crates/osiris-api/src/lib.rs crates/osiris-api/Cargo.toml Cargo.lock
git commit -m "feat(api): add the Live Events broadcaster core (subscribe/unsubscribe/publish)"
```

---

### Task 2: Backend — `GET /api/v1/stream/events` WebSocket route

**Files:**
- Modify: `crates/osiris-api/src/stream.rs` (add `StreamQuery`,
  `build_stream_router`, `stream_events_handler`, `handle_socket`)
- Modify: `crates/osiris-api/Cargo.toml` (`axum` gains the `ws` feature;
  add `tokio-tungstenite` and `futures-util` dev-dependencies)
- Modify: `Cargo.toml` (workspace root — add `tokio-tungstenite` and
  `futures-util` to `[workspace.dependencies]`)

**Interfaces:**
- Consumes: `LiveEventBroadcaster` (Task 1).
- Produces: `osiris_api::build_stream_router(broadcaster:
  Arc<LiveEventBroadcaster>) -> axum::Router`. Task 3's `main.rs` wiring
  and this task's own integration tests consume it.

- [ ] **Step 1: Add workspace dependencies**

In the repo root `Cargo.toml`, in `[workspace.dependencies]`, add two new
lines (anywhere among the existing entries):

```toml
tokio-tungstenite = "0.21"
futures-util = "0.3"
```

- [ ] **Step 2: Add the `ws` feature and dev-dependencies**

In `crates/osiris-api/Cargo.toml`, change:

```toml
axum = { workspace = true }
```

to:

```toml
axum = { workspace = true, features = ["ws"] }
```

Then add to `[dev-dependencies]`:

```toml
tokio-tungstenite = { workspace = true }
futures-util = { workspace = true }
```

- [ ] **Step 3: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `crates/osiris-api/src/stream.rs`
(after the existing 4 tests, before the closing `}`):

```rust
    async fn spawn_test_server(broadcaster: Arc<LiveEventBroadcaster>) -> std::net::SocketAddr {
        let app = build_stream_router(broadcaster);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn a_client_receives_a_published_event_over_the_socket() {
        use futures_util::StreamExt;

        let broadcaster = Arc::new(LiveEventBroadcaster::new());
        let addr = spawn_test_server(broadcaster.clone()).await;

        let (mut ws_stream, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/api/v1/stream/events"))
                .await
                .unwrap();

        let host_id = Uuid::new_v4();
        let event = sample_event(host_id, EventType::ProcessExec);
        broadcaster.publish(&[event.clone()]);

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let received: CanonicalEvent = match msg {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                serde_json::from_str(&text).unwrap()
            }
            other => panic!("expected a text message, got {:?}", other),
        };
        assert_eq!(received.event_id, event.event_id);
    }

    #[tokio::test]
    async fn a_host_id_filtered_client_only_receives_matching_events() {
        use futures_util::StreamExt;

        let broadcaster = Arc::new(LiveEventBroadcaster::new());
        let addr = spawn_test_server(broadcaster.clone()).await;

        let matching_host = Uuid::new_v4();
        let other_host = Uuid::new_v4();
        let (mut ws_stream, _) = tokio_tungstenite::connect_async(format!(
            "ws://{addr}/api/v1/stream/events?host_id={matching_host}"
        ))
        .await
        .unwrap();

        broadcaster.publish(&[
            sample_event(other_host, EventType::ProcessExec),
            sample_event(matching_host, EventType::ProcessExec),
        ]);

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let received: CanonicalEvent = match msg {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                serde_json::from_str(&text).unwrap()
            }
            other => panic!("expected a text message, got {:?}", other),
        };
        assert_eq!(received.host_id, matching_host);
    }

    #[tokio::test]
    async fn rejects_a_connection_with_both_host_id_and_q() {
        let broadcaster = Arc::new(LiveEventBroadcaster::new());
        let addr = spawn_test_server(broadcaster).await;

        let result = tokio_tungstenite::connect_async(format!(
            "ws://{addr}/api/v1/stream/events?host_id=abc&q=event_type%20%3D%20%22PROCESS_EXEC%22"
        ))
        .await;

        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 400);
            }
            other => panic!("expected an HTTP 400 rejection, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rejects_a_connection_with_a_malformed_q() {
        let broadcaster = Arc::new(LiveEventBroadcaster::new());
        let addr = spawn_test_server(broadcaster).await;

        let result = tokio_tungstenite::connect_async(format!(
            "ws://{addr}/api/v1/stream/events?q=event_type%20%3D"
        ))
        .await;

        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 400);
            }
            other => panic!("expected an HTTP 400 rejection, got {:?}", other),
        }
    }
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p osiris-api stream::`
Expected: FAIL — compile error, `build_stream_router` doesn't exist yet.

- [ ] **Step 5: Implement the route and handler**

In `crates/osiris-api/src/stream.rs`, add these imports to the top-of-file
`use` block (alongside the ones from Task 1):

```rust
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use osiris_query::{EventQueryPlan, Op, Value};
use serde::Deserialize;
```

Then add this code after the `impl LiveEventBroadcaster` block, still
before the `#[cfg(test)]` module:

```rust
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub host_id: Option<String>,
    pub q: Option<String>,
}

pub fn build_stream_router(broadcaster: Arc<LiveEventBroadcaster>) -> Router {
    Router::new()
        .route("/api/v1/stream/events", get(stream_events_handler))
        .with_state(broadcaster)
}

async fn stream_events_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<StreamQuery>,
    State(broadcaster): State<Arc<LiveEventBroadcaster>>,
) -> Result<Response, (StatusCode, String)> {
    if params.host_id.is_some() && params.q.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "host_id and q are mutually exclusive".to_string(),
        ));
    }

    let filter = if let Some(host_id) = params.host_id {
        Some(Ast::Compare {
            field: "host_id".to_string(),
            op: Op::Eq,
            value: Value::Str(host_id),
        })
    } else if let Some(q) = params.q {
        let plan = EventQueryPlan::with_filter(&q)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        plan.filter
    } else {
        None
    };

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, broadcaster, filter)))
}

async fn handle_socket(mut socket: WebSocket, broadcaster: Arc<LiveEventBroadcaster>, filter: Option<Ast>) {
    let (id, mut receiver, _dropped_total) = broadcaster.subscribe(filter);
    loop {
        tokio::select! {
            maybe_event = receiver.recv() => {
                let Some(event) = maybe_event else { break; };
                let Ok(payload) = serde_json::to_string(&event) else { continue; };
                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
    broadcaster.unsubscribe(id);
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p osiris-api stream::`
Expected: PASS (all 8 tests: the 4 from Task 1 plus these 4).

- [ ] **Step 7: Run the full workspace check**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: both pass.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock crates/osiris-api/src/stream.rs crates/osiris-api/Cargo.toml
git commit -m "feat(api): add the GET /api/v1/stream/events WebSocket route"
```

---

### Task 3: Backend — publish ingested events to the broadcaster

**Files:**
- Modify: `crates/osiris-server/src/ingest.rs` (`run_ingestion_loop` gains
  a `broadcaster` parameter; publishes after a successful batch write;
  update the 4 existing test call sites; add 1 new test)
- Modify: `crates/osiris-server/src/main.rs` (construct the broadcaster,
  thread it to `run_ingestion_loop` and into the merged router)

**Interfaces:**
- Consumes: `osiris_api::LiveEventBroadcaster` (Task 1 and 2).
- Produces: nothing new for later tasks — this is the last backend task.

- [ ] **Step 1: Write the failing test**

In `crates/osiris-server/src/ingest.rs`, add this test to the `mod tests`
block, after `ingests_spooled_events_into_storage`:

```rust
    #[tokio::test]
    async fn ingested_events_are_published_to_the_broadcaster() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        std::fs::write(&spool_path, "").unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let cancellation = CancellationToken::new();
        let detection_engine = Arc::new(DetectionEngine::new(vec![]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let broadcaster = Arc::new(osiris_api::LiveEventBroadcaster::new());
        let (_id, mut receiver, _dropped) = broadcaster.subscribe(None);

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster.clone(),
            Duration::from_millis(20),
            cancellation.clone(),
        ));

        let event = sample_event();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&spool_path)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.event_id, event.event_id);

        cancellation.cancel();
        handle.await.unwrap();
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-server ingested_events_are_published_to_the_broadcaster`
Expected: FAIL — compile error, `run_ingestion_loop` doesn't take a
`broadcaster` argument yet.

- [ ] **Step 3: Add the parameter and the publish call**

In `crates/osiris-server/src/ingest.rs`, change the function signature
from:

```rust
pub async fn run_ingestion_loop(
    spool_path: impl Into<std::path::PathBuf>,
    storage: Arc<dyn Storage>,
    detection_engine: Arc<DetectionEngine>,
    baseline_engine: Arc<BaselineEngine>,
    risk_engine: Arc<RiskEngine>,
    correlation_engine: Arc<CorrelationEngine>,
    poll_interval: Duration,
    cancellation: CancellationToken,
) {
```

to:

```rust
pub async fn run_ingestion_loop(
    spool_path: impl Into<std::path::PathBuf>,
    storage: Arc<dyn Storage>,
    detection_engine: Arc<DetectionEngine>,
    baseline_engine: Arc<BaselineEngine>,
    risk_engine: Arc<RiskEngine>,
    correlation_engine: Arc<CorrelationEngine>,
    broadcaster: Arc<osiris_api::LiveEventBroadcaster>,
    poll_interval: Duration,
    cancellation: CancellationToken,
) {
```

Then, still in `run_ingestion_loop`, change:

```rust
                    let event_count = events.len();
                    match tokio::task::spawn_blocking(move || {
```

to:

```rust
                    let event_count = events.len();
                    let events_for_broadcast = events.clone();
                    match tokio::task::spawn_blocking(move || {
```

And change:

```rust
                    {
                        Ok(Ok(_report)) => {}
                        Ok(Err(storage_err)) => {
```

to:

```rust
                    {
                        Ok(Ok(_report)) => broadcaster.publish(&events_for_broadcast),
                        Ok(Err(storage_err)) => {
```

- [ ] **Step 4: Update the 4 existing test call sites**

In `crates/osiris-server/src/ingest.rs`'s `mod tests` block, this exact
two-line sequence occurs 4 times (inside
`ingests_spooled_events_into_storage`,
`skips_malformed_lines_and_ingests_valid_ones`,
`alerts_are_evaluated_and_persisted_end_to_end_through_the_loop`, and
`the_full_detection_correlation_baseline_risk_trace_runs_end_to_end`):

```rust
            correlation_engine,
            Duration::from_millis(20),
```

Replace **all 4 occurrences** with:

```rust
            correlation_engine,
            Arc::new(osiris_api::LiveEventBroadcaster::new()),
            Duration::from_millis(20),
```

- [ ] **Step 5: Add the `osiris-api` dependency if missing, run the tests**

`crates/osiris-server/Cargo.toml` already depends on `osiris-api` (used by
`main.rs`), so no dependency change is needed.

Run: `cargo test -p osiris-server ingest::`
Expected: PASS (all 5 tests: the 4 pre-existing ones plus the new one).

- [ ] **Step 6: Wire the broadcaster into `main.rs`**

In `crates/osiris-server/src/main.rs`, change the import line:

```rust
use osiris_api::{build_incident_evidence_router, IncidentEvidenceState};
```

to:

```rust
use osiris_api::{build_incident_evidence_router, build_stream_router, IncidentEvidenceState, LiveEventBroadcaster};
```

Then change:

```rust
    let cancellation = CancellationToken::new();
    let ingest_storage = storage.clone();
    let spool_path = config.spool_path.clone();
    tokio::spawn(run_ingestion_loop(
        spool_path,
        ingest_storage,
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
        Duration::from_millis(200),
        cancellation.clone(),
    ));
```

to:

```rust
    let live_event_broadcaster = Arc::new(LiveEventBroadcaster::new());

    let cancellation = CancellationToken::new();
    let ingest_storage = storage.clone();
    let spool_path = config.spool_path.clone();
    tokio::spawn(run_ingestion_loop(
        spool_path,
        ingest_storage,
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
        live_event_broadcaster.clone(),
        Duration::from_millis(200),
        cancellation.clone(),
    ));
```

Then change:

```rust
    let app = osiris_server::apply_dev_cors(
        build_router(storage).merge(build_incident_evidence_router(incident_evidence_state)),
        config.dev_cors,
    );
```

to:

```rust
    let app = osiris_server::apply_dev_cors(
        build_router(storage)
            .merge(build_incident_evidence_router(incident_evidence_state))
            .merge(build_stream_router(live_event_broadcaster)),
        config.dev_cors,
    );
```

- [ ] **Step 7: Run the full workspace check**

Run: `cargo build -p osiris-server && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all pass. The explicit `cargo build -p osiris-server` first
confirms `main.rs` compiles (it has no `#[cfg(test)]` coverage of its own
wiring).

- [ ] **Step 8: Commit**

```bash
git add crates/osiris-server/src/ingest.rs crates/osiris-server/src/main.rs
git commit -m "feat(server): publish ingested events to the Live Events broadcaster"
```

---

### Task 4: Console — Live Events WebSocket client hook

**Files:**
- Create: `console/src/api/liveEvents.ts` (`useLiveEvents`,
  `ConnectionState`, `LiveEventsFilter`)
- Test: `console/src/api/liveEvents.test.ts` (new)

**Interfaces:**
- Consumes: `CanonicalEvent` type from `./types` (existing).
- Produces: `useLiveEvents(filter?: LiveEventsFilter):
  UseLiveEventsResult` — `{events: CanonicalEvent[]; connectionState:
  ConnectionState; paused: boolean; setPaused: (paused: boolean) => void;
  clear: () => void}`, where `LiveEventsFilter = {hostId?: string; q?:
  string}` and `ConnectionState = "connecting" | "live" | "reconnecting" |
  "disconnected"`. Task 5 (Live Events screen) consumes all of this.

- [ ] **Step 1: Write the failing tests**

Create `console/src/api/liveEvents.test.ts`:

```typescript
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useLiveEvents } from "./liveEvents";
import type { CanonicalEvent } from "./types";

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances: MockWebSocket[] = [];

  url: string;
  readyState = MockWebSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  simulateOpen() {
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.();
  }

  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
}

function makeEvent(eventId: string): CanonicalEvent {
  return {
    event_id: eventId,
    event_type: "PROCESS_EXEC",
    timestamp: 1000,
    host: { host_id: "h1", hostname: "host-one" },
    event_data: {},
  };
}

describe("useLiveEvents", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.stubGlobal("WebSocket", MockWebSocket);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("opens a socket and transitions to live on open", () => {
    const { result } = renderHook(() => useLiveEvents());
    expect(result.current.connectionState).toBe("connecting");

    act(() => MockWebSocket.instances[0].simulateOpen());

    expect(result.current.connectionState).toBe("live");
  });

  it("adds received events newest-first", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());

    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("a")));
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("b")));

    expect(result.current.events.map((e) => e.event_id)).toEqual(["b", "a"]);
  });

  it("caps the buffer at 500 events", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());

    act(() => {
      for (let i = 0; i < 501; i++) {
        MockWebSocket.instances[0].simulateMessage(makeEvent(String(i)));
      }
    });

    expect(result.current.events).toHaveLength(500);
    expect(result.current.events[0].event_id).toBe("500");
  });

  it("pause freezes the rendered list; resume flushes the latest buffer", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("a")));

    act(() => result.current.setPaused(true));
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("b")));

    expect(result.current.events.map((e) => e.event_id)).toEqual(["a"]);

    act(() => result.current.setPaused(false));

    expect(result.current.events.map((e) => e.event_id)).toEqual(["b", "a"]);
  });

  it("clear empties both the rendered list and the buffer", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("a")));

    act(() => result.current.clear());

    expect(result.current.events).toEqual([]);
  });

  it("reconnects with exponential backoff after the socket closes", () => {
    renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());

    act(() => MockWebSocket.instances[0].close());
    expect(MockWebSocket.instances).toHaveLength(1);

    act(() => vi.advanceTimersByTime(1000));
    expect(MockWebSocket.instances).toHaveLength(2);

    act(() => MockWebSocket.instances[1].close());
    act(() => vi.advanceTimersByTime(1999));
    expect(MockWebSocket.instances).toHaveLength(2);
    act(() => vi.advanceTimersByTime(1));
    expect(MockWebSocket.instances).toHaveLength(3);
  });

  it("builds the socket URL with a host_id filter, never both host_id and q", () => {
    renderHook(() => useLiveEvents({ hostId: "host-1" }));
    expect(MockWebSocket.instances[0].url).toContain("host_id=host-1");
    expect(MockWebSocket.instances[0].url).not.toContain("q=");
  });

  it("builds the socket URL with a q filter", () => {
    renderHook(() => useLiveEvents({ q: 'event_type = "PROCESS_EXEC"' }));
    expect(MockWebSocket.instances[0].url).toContain("q=");
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd console && npm test -- liveEvents`
Expected: FAIL — `./liveEvents` module doesn't exist yet.

- [ ] **Step 3: Implement `liveEvents.ts`**

Create `console/src/api/liveEvents.ts`:

```typescript
import { useCallback, useEffect, useRef, useState } from "react";
import type { CanonicalEvent } from "./types";

const RING_BUFFER_CAPACITY = 500;
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;

export type ConnectionState = "connecting" | "live" | "reconnecting" | "disconnected";

export interface LiveEventsFilter {
  hostId?: string;
  q?: string;
}

export interface UseLiveEventsResult {
  events: CanonicalEvent[];
  connectionState: ConnectionState;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  clear: () => void;
}

function buildStreamUrl(filter: LiveEventsFilter): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const search = new URLSearchParams();
  if (filter.hostId) {
    search.set("host_id", filter.hostId);
  } else if (filter.q) {
    search.set("q", filter.q);
  }
  const queryString = search.toString();
  return `${protocol}//${window.location.host}/api/v1/stream/events${queryString ? `?${queryString}` : ""}`;
}

export function useLiveEvents(filter: LiveEventsFilter = {}): UseLiveEventsResult {
  const [events, setEvents] = useState<CanonicalEvent[]>([]);
  const [connectionState, setConnectionState] = useState<ConnectionState>("connecting");
  const [paused, setPausedState] = useState(false);
  const pausedRef = useRef(paused);
  const bufferRef = useRef<CanonicalEvent[]>([]);
  const backoffRef = useRef(INITIAL_BACKOFF_MS);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;

    function connect() {
      if (cancelled) {
        return;
      }
      setConnectionState((current) => (current === "live" ? current : "connecting"));
      socket = new WebSocket(buildStreamUrl(filter));

      socket.onopen = () => {
        backoffRef.current = INITIAL_BACKOFF_MS;
        setConnectionState("live");
      };

      socket.onmessage = (messageEvent) => {
        const parsed = JSON.parse(messageEvent.data as string) as CanonicalEvent;
        bufferRef.current = [parsed, ...bufferRef.current].slice(0, RING_BUFFER_CAPACITY);
        if (!pausedRef.current) {
          setEvents(bufferRef.current);
        }
      };

      socket.onclose = () => {
        if (cancelled) {
          return;
        }
        setConnectionState("reconnecting");
        reconnectTimer = setTimeout(connect, backoffRef.current);
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
      };

      socket.onerror = () => {
        socket?.close();
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      socket?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter.hostId, filter.q]);

  const clear = useCallback(() => {
    bufferRef.current = [];
    setEvents([]);
  }, []);

  const setPaused = useCallback((next: boolean) => {
    setPausedState(next);
    if (!next) {
      setEvents(bufferRef.current);
    }
  }, []);

  return { events, connectionState, paused, setPaused, clear };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd console && npm test -- liveEvents`
Expected: PASS (all 8 tests).

- [ ] **Step 5: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add console/src/api/liveEvents.ts console/src/api/liveEvents.test.ts
git commit -m "feat(console): add the Live Events WebSocket client hook"
```

---

### Task 5: Console — Live Events screen

**Files:**
- Create: `console/src/screens/live/LiveEvents.tsx`
- Test: `console/src/screens/live/LiveEvents.test.tsx` (new)

**Interfaces:**
- Consumes: `useLiveEvents` from `../../api/liveEvents` (Task 4).
- Produces: `LiveEvents` component (default export not used anywhere in
  this codebase's convention — named export, matching every other
  screen). Task 6 wires it into `App.tsx`.

- [ ] **Step 1: Write the failing tests**

Create `console/src/screens/live/LiveEvents.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as liveEvents from "../../api/liveEvents";
import { LiveEvents } from "./LiveEvents";

vi.mock("../../api/liveEvents");

function mockResult(
  overrides: Partial<ReturnType<typeof liveEvents.useLiveEvents>> = {}
): ReturnType<typeof liveEvents.useLiveEvents> {
  return {
    events: [],
    connectionState: "connecting",
    paused: false,
    setPaused: vi.fn(),
    clear: vi.fn(),
    ...overrides,
  };
}

describe("LiveEvents", () => {
  it("shows the connection state", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ connectionState: "live" }));
    render(<LiveEvents />);
    expect(screen.getByRole("status")).toHaveTextContent("Live");
  });

  it("shows a message when there are no events yet", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult());
    render(<LiveEvents />);
    expect(screen.getByText("No events yet.")).toBeInTheDocument();
  });

  it("renders received events in a table", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(
      mockResult({
        events: [
          {
            event_id: "e1",
            event_type: "PROCESS_EXEC",
            timestamp: 1000,
            host: { host_id: "h1", hostname: "host-one" },
            event_data: {},
          },
        ],
      })
    );
    render(<LiveEvents />);
    expect(screen.getByText("PROCESS_EXEC")).toBeInTheDocument();
    expect(screen.getByText("host-one")).toBeInTheDocument();
  });

  it("calls setPaused(true) when Pause is clicked", () => {
    const setPaused = vi.fn();
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ setPaused }));
    render(<LiveEvents />);
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    expect(setPaused).toHaveBeenCalledWith(true);
  });

  it("shows Resume and calls setPaused(false) when already paused", () => {
    const setPaused = vi.fn();
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ paused: true, setPaused }));
    render(<LiveEvents />);
    fireEvent.click(screen.getByRole("button", { name: "Resume" }));
    expect(setPaused).toHaveBeenCalledWith(false);
  });

  it("calls clear when Clear is clicked", () => {
    const clear = vi.fn();
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ clear }));
    render(<LiveEvents />);
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(clear).toHaveBeenCalled();
  });

  it("applying a Host ID filter re-invokes useLiveEvents with that filter", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult());
    render(<LiveEvents />);
    fireEvent.change(screen.getByLabelText("Host ID"), { target: { value: "host-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filter" }));
    expect(liveEvents.useLiveEvents).toHaveBeenLastCalledWith({ hostId: "host-1" });
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd console && npm test -- LiveEvents`
Expected: FAIL — `./LiveEvents` module doesn't exist yet.

- [ ] **Step 3: Implement the screen**

Create `console/src/screens/live/LiveEvents.tsx`:

```tsx
import { useState, type FormEvent } from "react";
import { useLiveEvents } from "../../api/liveEvents";

export function LiveEvents() {
  const [hostIdInput, setHostIdInput] = useState("");
  const [qInput, setQInput] = useState("");
  const [filter, setFilter] = useState<{ hostId?: string; q?: string }>({});

  const { events, connectionState, paused, setPaused, clear } = useLiveEvents(filter);

  function handleApplyFilter(event: FormEvent) {
    event.preventDefault();
    if (hostIdInput.trim()) {
      setFilter({ hostId: hostIdInput.trim() });
    } else if (qInput.trim()) {
      setFilter({ q: qInput.trim() });
    } else {
      setFilter({});
    }
  }

  const connectionLabel =
    connectionState === "live"
      ? "Live"
      : connectionState === "reconnecting"
        ? "Reconnecting…"
        : connectionState === "connecting"
          ? "Connecting…"
          : "Disconnected";

  return (
    <div>
      <h1>Live Events</h1>
      <p role="status">{connectionLabel}</p>
      <form onSubmit={handleApplyFilter}>
        <input
          type="text"
          aria-label="Host ID"
          placeholder="Host ID"
          value={hostIdInput}
          onChange={(event) => {
            setHostIdInput(event.target.value);
            setQInput("");
          }}
        />
        <input
          type="text"
          aria-label="OQL query"
          placeholder="OQL query"
          value={qInput}
          onChange={(event) => {
            setQInput(event.target.value);
            setHostIdInput("");
          }}
        />
        <button type="submit">Apply filter</button>
      </form>
      <button type="button" onClick={() => setPaused(!paused)}>
        {paused ? "Resume" : "Pause"}
      </button>
      <button type="button" onClick={clear}>
        Clear
      </button>
      {events.length === 0 && <p>No events yet.</p>}
      {events.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Event type</th>
              <th>Timestamp</th>
              <th>Host</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.event_id}>
                <td>{event.event_type}</td>
                <td>{event.timestamp}</td>
                <td>{event.host.hostname}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd console && npm test -- LiveEvents`
Expected: PASS (all 7 tests).

- [ ] **Step 5: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add console/src/screens/live/
git commit -m "feat(console): add the Live Events screen"
```

---

### Task 6: Console — wire up the screen, enable the dev WS proxy

**Files:**
- Modify: `console/src/app/navItems.ts` (`Live Events` → `enabled: true`)
- Modify: `console/src/App.tsx` (swap the `ComingSoon` route for
  `LiveEvents`)
- Modify: `console/src/App.test.tsx` (update the nav-link-count test)
- Modify: `console/vite.config.ts` (add `ws: true` to the `/api` proxy
  entry)

**Interfaces:**
- Consumes: `LiveEvents` (Task 5).
- Produces: nothing for later tasks — this is the last frontend task.

- [ ] **Step 1: Write the failing test**

In `console/src/App.test.tsx`, change:

```tsx
  it("renders exactly nine nav links, for Overview, Process Explorer, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, Evidence, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(9);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Timeline",
      "Alerts",
      "Incidents",
      "Threat Hunting",
      "Entity Graph",
      "Evidence",
      "Sensors",
    ]);
  });
```

to:

```tsx
  it("renders exactly ten nav links, for Overview, Live Events, Process Explorer, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, Evidence, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(10);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Live Events",
      "Process Explorer",
      "Timeline",
      "Alerts",
      "Incidents",
      "Threat Hunting",
      "Entity Graph",
      "Evidence",
      "Sensors",
    ]);
  });
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- App.test`
Expected: FAIL — still 9 links (`Live Events` is `enabled: false`, so
`Shell`'s nav doesn't render it as a link).

- [ ] **Step 3: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Live Events", path: "/live-events", enabled: false },
```

to:

```typescript
  { label: "Live Events", path: "/live-events", enabled: true },
```

- [ ] **Step 4: Swap the route**

In `console/src/App.tsx`, the screen imports are alphabetized by imported
name (`Alerts`, `ComingSoon`, `EntityGraph`, `EvidenceList`,
`IncidentDetailScreen`, `IncidentList`, `Overview`, ...). Change:

```tsx
import { IncidentList } from "./screens/incidents/IncidentList";
import { Overview } from "./screens/overview/Overview";
```

to:

```tsx
import { IncidentList } from "./screens/incidents/IncidentList";
import { LiveEvents } from "./screens/live/LiveEvents";
import { Overview } from "./screens/overview/Overview";
```

Then change:

```tsx
              <Route path="/live-events" element={<ComingSoon label="Live Events" />} />
```

to:

```tsx
              <Route path="/live-events" element={<LiveEvents />} />
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd console && npm test -- App.test`
Expected: PASS (all 3 tests).

- [ ] **Step 6: Enable WebSocket proxying in the dev server**

In `console/vite.config.ts`, change:

```typescript
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
```

to:

```typescript
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
        // Live Events' WebSocket upgrade (GET /api/v1/stream/events)
        // needs this explicitly — Vite's dev proxy does not forward
        // WebSocket upgrades by default.
        ws: true,
      },
    },
```

- [ ] **Step 7: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add console/src/app/navItems.ts console/src/App.tsx console/src/App.test.tsx console/vite.config.ts
git commit -m "feat(console): wire up the Live Events screen and enable ws proxying"
```

---

### Task 7: Manual end-to-end smoke verification

**Files:** none (verification only, no code changes).

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: nothing — this is the last task in the plan.

- [ ] **Step 1: Build the server binary**

Run: `cargo build -p osiris-server`
Expected: succeeds.

- [ ] **Step 2: Start a scratch server**

Following prior phases' precedent, create a scratch config (writable
paths, `dev_cors: true`) and start `osiris-server` against it, e.g.:

```bash
mkdir -p /tmp/osiris-7b4-scratch
cat > /tmp/osiris-7b4-scratch/server.yaml <<'EOF'
listen_addr: "127.0.0.1:8080"
db_path: "/tmp/osiris-7b4-scratch/events.db"
spool_path: "/tmp/osiris-7b4-scratch/spool.ndjson"
rules_dir: "rules"
dev_cors: true
incidents_db_path: "/tmp/osiris-7b4-scratch/incidents.db"
evidence_db_path: "/tmp/osiris-7b4-scratch/evidence.db"
links_db_path: "/tmp/osiris-7b4-scratch/links.db"
investigate_audit_log_path: "/tmp/osiris-7b4-scratch/investigate-audit.jsonl"
EOF
touch /tmp/osiris-7b4-scratch/spool.ndjson
./target/debug/osiris-server /tmp/osiris-7b4-scratch/server.yaml &
```

(Adjust `rules_dir` to the repo's actual rules directory if the default
`"rules"` relative path doesn't resolve from the working directory used.)

- [ ] **Step 3: Connect a raw WebSocket client and verify delivery**

Using a small script (Node with the `ws` package, `websocat`, or any
available WebSocket CLI), connect to `ws://127.0.0.1:8080/api/v1/stream/events`
and leave it connected. In a second terminal, append one NDJSON event line
to `/tmp/osiris-7b4-scratch/spool.ndjson` (any valid `CanonicalEvent` JSON
— reuse a fixture from `crates/osiris-schema`'s tests if convenient, or
construct one by hand with the required fields per
`crates/osiris-schema/src/envelope.rs`). Confirm the connected client
receives that same event as a JSON text message within ~1 second (the
ingestion loop's 200ms poll interval).

- [ ] **Step 4: Verify host_id filtering**

Repeat Step 3, but connect two clients: one to
`ws://127.0.0.1:8080/api/v1/stream/events?host_id=<the event's host_id>`
and one to `?host_id=<a different, non-matching UUID>`. Append the same
event again. Confirm only the matching client receives it.

- [ ] **Step 5: Verify the Console screen through the dev proxy**

Start the console dev server (`cd console && npm run dev`) against the
same scratch backend. If the Chrome browser extension is connected this
session (check via `tabs_context_mcp`), navigate to `/live-events`,
confirm the connection indicator shows "Live", append another event to
the spool file, and confirm it appears in the table within about a
second. If the extension is not connected, this step's browser-rendering
check cannot be completed this session — note that explicitly rather than
skipping it silently; the WebSocket wire protocol itself is already
covered end-to-end by Task 2's automated integration tests and Steps 3-4
above.

- [ ] **Step 6: Clean up**

Stop the scratch `osiris-server` and `npm run dev` processes. Confirm no
orphaned processes remain (`ps` / Task Manager). Remove
`/tmp/osiris-7b4-scratch` if desired (it is outside the repo, so nothing
to `git status` here).
