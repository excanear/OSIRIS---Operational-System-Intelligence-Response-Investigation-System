use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::request::Parts;
use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use osiris_query::{eval_ast, Ast, EventQueryPlan, Op, Value};
use osiris_schema::CanonicalEvent;
use serde::Deserialize;
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
    /// Tenant host restriction, checked in O(1) before any AST evaluation.
    /// `Some(empty)` delivers nothing.
    hosts: Option<HashSet<Uuid>>,
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
        self.subscribe_scoped(filter, None)
    }

    /// Like `subscribe`, but restricted to `hosts` when `Some`.
    pub fn subscribe_scoped(
        &self,
        filter: Option<Ast>,
        hosts: Option<HashSet<Uuid>>,
    ) -> (Uuid, mpsc::Receiver<CanonicalEvent>, Arc<AtomicU64>) {
        let id = Uuid::new_v4();
        let (sender, receiver) = mpsc::channel(LIVE_EVENT_CHANNEL_CAPACITY);
        let dropped_total = Arc::new(AtomicU64::new(0));
        self.connections.lock().unwrap().push(Connection {
            id,
            filter,
            hosts,
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

    /// True if at least one connection is currently registered. Lets
    /// callers skip cloning an event batch when there is nobody to publish
    /// it to.
    pub fn has_subscribers(&self) -> bool {
        !self.connections.lock().unwrap().is_empty()
    }

    /// Called once per successfully-persisted ingestion batch. For each
    /// connection whose filter matches (or has no filter), `try_send`s the
    /// event. On `Err` (channel full), increments that connection's
    /// `dropped_total` and moves on.
    pub fn publish(&self, events: &[CanonicalEvent]) {
        let connections = self.connections.lock().unwrap();
        for event in events {
            for conn in connections.iter() {
                if let Some(hosts) = &conn.hosts {
                    if !hosts.contains(&event.host_id) {
                        continue;
                    }
                }
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

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub host_id: Option<String>,
    pub q: Option<String>,
}

/// WebSocket liveness policy: the server pings every `ping_every`, and closes a
/// connection that has sent nothing (a pong counts) for `idle_timeout`. Without
/// this a half-open TCP connection would hold its 4096-slot channel forever.
#[derive(Clone, Copy, Debug)]
pub struct KeepAlive {
    pub ping_every: std::time::Duration,
    pub idle_timeout: std::time::Duration,
}

impl Default for KeepAlive {
    fn default() -> Self {
        Self {
            ping_every: std::time::Duration::from_secs(30),
            idle_timeout: std::time::Duration::from_secs(90),
        }
    }
}

pub fn build_stream_router(broadcaster: Arc<LiveEventBroadcaster>) -> Router {
    build_stream_router_with_keepalive(broadcaster, KeepAlive::default())
}

pub fn build_stream_router_with_keepalive(
    broadcaster: Arc<LiveEventBroadcaster>,
    keepalive: KeepAlive,
) -> Router {
    Router::new()
        .route("/api/v1/stream/events", get(stream_events_handler))
        .with_state(broadcaster)
        .layer(axum::Extension(keepalive))
}

/// Cross-site WebSocket hijacking (CSWSH) guard: WebSocket handshakes are
/// not subject to Same-Origin Policy/CORS the way REST fetches are, so a
/// malicious page could otherwise open a WebSocket to this endpoint from a
/// victim's browser and read the live telemetry stream. If the request
/// carries an `Origin` header, it must match the request's own `Host`
/// header. Non-browser clients (tokio-tungstenite, websocat, Node `ws`,
/// ...) typically send no `Origin` header at all and are unaffected.
fn origin_is_same_site(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(axum::http::header::ORIGIN) else {
        // No Origin header: not a browser cross-origin request (e.g. a
        // native WebSocket client). Nothing to check.
        return true;
    };
    let Some(host) = headers.get(axum::http::header::HOST) else {
        return false;
    };
    let (Ok(origin_str), Ok(host_str)) = (origin.to_str(), host.to_str()) else {
        return false;
    };
    // Origin looks like "http://127.0.0.1:8080" or "https://example.com";
    // Host looks like "127.0.0.1:8080". Compare the host:port portion only.
    origin_str
        .rsplit("://")
        .next()
        .map(|origin_host| origin_host == host_str)
        .unwrap_or(false)
}

/// Canonical spelling of a requested `host_id` (None if not a UUID).
pub(crate) fn normalize_host(requested: &str) -> Option<String> {
    Uuid::parse_str(requested).ok().map(|id| id.to_string())
}

/// Whether a `host_id` the client asked for belongs to the tenant.
pub(crate) fn host_allowed(hosts: &HashSet<Uuid>, requested: &str) -> bool {
    Uuid::parse_str(requested)
        .map(|id| hosts.contains(&id))
        .unwrap_or(false)
}

async fn stream_events_handler(
    parts: Parts,
    ws: WebSocketUpgrade,
    Query(params): Query<StreamQuery>,
    State(broadcaster): State<Arc<LiveEventBroadcaster>>,
    keepalive: Option<axum::Extension<KeepAlive>>,
) -> Result<Response, (StatusCode, String)> {
    let headers = parts.headers.clone();
    if !origin_is_same_site(&headers) {
        return Err((
            StatusCode::FORBIDDEN,
            "cross-origin WebSocket connections are not allowed".to_string(),
        ));
    }

    if params.host_id.is_some() && params.q.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "host_id and q are mutually exclusive".to_string(),
        ));
    }

    if let Some(host_id) = &params.host_id {
        if normalize_host(host_id).is_none() {
            return Err((StatusCode::BAD_REQUEST, "host_id must be a UUID".to_string()));
        }
    }

    // Tenant users are restricted to their tenant's hosts. The host set is a
    // snapshot taken at connect time: a reassignment mid-connection only
    // applies at the next connect. Platform / no-auth requests get `None`.
    let tenant_hosts = crate::tenant_scope::tenant_hosts(&parts).await?;
    if let (Some(hosts), Some(requested)) = (&tenant_hosts, &params.host_id) {
        if !host_allowed(hosts, requested) {
            return Err((StatusCode::FORBIDDEN, "host not in your tenant".to_string()));
        }
    }

    let filter = if let Some(host_id) = params.host_id {
        Some(Ast::Compare {
            field: "host_id".to_string(),
            op: Op::Eq,
            value: Value::Str(normalize_host(&host_id).expect("validated above")),
        })
    } else if let Some(q) = params.q {
        let plan = EventQueryPlan::with_filter(&q)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        plan.filter
    } else {
        None
    };

    let keepalive = keepalive.map(|axum::Extension(k)| k).unwrap_or_default();
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, broadcaster, filter, tenant_hosts, keepalive)))
}

async fn handle_socket(
    mut socket: WebSocket,
    broadcaster: Arc<LiveEventBroadcaster>,
    filter: Option<Ast>,
    hosts: Option<HashSet<Uuid>>,
    keepalive: KeepAlive,
) {
    let (id, mut receiver, _dropped_total) = broadcaster.subscribe_scoped(filter, hosts);
    let mut ping = tokio::time::interval(keepalive.ping_every);
    ping.tick().await; // the first tick fires immediately
    let mut last_seen = tokio::time::Instant::now();
    loop {
        tokio::select! {
            maybe_event = receiver.recv() => {
                let Some(event) = maybe_event else { break; };
                let Ok(payload) = serde_json::to_string(&event) else { continue; };
                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            _ = ping.tick() => {
                if last_seen.elapsed() >= keepalive.idle_timeout {
                    break;
                }
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => last_seen = tokio::time::Instant::now(),
                    Some(Err(_)) => break,
                }
            }
        }
    }
    broadcaster.unsubscribe(id);
}

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

        broadcaster.publish(std::slice::from_ref(&event));

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

    #[test]
    fn origin_is_same_site_allows_a_matching_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
        headers.insert(axum::http::header::HOST, "127.0.0.1:8080".parse().unwrap());
        assert!(origin_is_same_site(&headers));
    }

    #[test]
    fn origin_is_same_site_rejects_a_cross_origin_request() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::ORIGIN, "https://evil.example".parse().unwrap());
        headers.insert(axum::http::header::HOST, "127.0.0.1:8080".parse().unwrap());
        assert!(!origin_is_same_site(&headers));
    }

    #[test]
    fn origin_is_same_site_allows_a_request_with_no_origin_header() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, "127.0.0.1:8080".parse().unwrap());
        assert!(origin_is_same_site(&headers));
    }

    #[test]
    fn origin_is_same_site_rejects_an_origin_with_no_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
        assert!(!origin_is_same_site(&headers));
    }

    #[test]
    fn has_subscribers_reflects_the_connection_list() {
        let broadcaster = LiveEventBroadcaster::new();
        assert!(!broadcaster.has_subscribers());

        let (id, _receiver, _dropped) = broadcaster.subscribe(None);
        assert!(broadcaster.has_subscribers());

        broadcaster.unsubscribe(id);
        assert!(!broadcaster.has_subscribers());
    }

    #[tokio::test]
    async fn a_scoped_connection_only_receives_its_hosts_events() {
        let broadcaster = LiveEventBroadcaster::new();
        let (mine, foreign) = (Uuid::new_v4(), Uuid::new_v4());
        let hosts: HashSet<Uuid> = [mine].into_iter().collect();
        let (_id, mut receiver, _d) = broadcaster.subscribe_scoped(None, Some(hosts));

        broadcaster.publish(&[
            sample_event(foreign, EventType::ProcessExec),
            sample_event(mine, EventType::ProcessExec),
        ]);

        assert_eq!(receiver.try_recv().unwrap().host_id, mine);
        assert_eq!(receiver.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[tokio::test]
    async fn a_scoped_connection_applies_the_callers_filter_after_the_host_check() {
        let broadcaster = LiveEventBroadcaster::new();
        let mine = Uuid::new_v4();
        let hosts: HashSet<Uuid> = [mine].into_iter().collect();
        let user = Ast::Compare {
            field: "event_type".to_string(),
            op: Op::Eq,
            value: Value::Str("PROCESS_EXEC".to_string()),
        };
        let (_id, mut receiver, _d) = broadcaster.subscribe_scoped(Some(user), Some(hosts));

        broadcaster.publish(&[
            sample_event(mine, EventType::FileWrite),
            sample_event(mine, EventType::ProcessExec),
        ]);

        assert_eq!(receiver.try_recv().unwrap().event_type, EventType::ProcessExec);
        assert_eq!(receiver.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[tokio::test]
    async fn an_empty_scoped_host_set_delivers_nothing() {
        let broadcaster = LiveEventBroadcaster::new();
        let (_id, mut receiver, _d) = broadcaster.subscribe_scoped(None, Some(HashSet::new()));
        broadcaster.publish(&[sample_event(Uuid::new_v4(), EventType::ProcessExec)]);
        assert_eq!(receiver.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[test]
    fn a_requested_host_is_normalized_through_the_parsed_uuid() {
        let a = Uuid::new_v4();
        let upper = a.to_string().to_uppercase();
        let braced = format!("{{{a}}}");
        assert_eq!(normalize_host(&upper), Some(a.to_string()));
        assert_eq!(normalize_host(&braced), Some(a.to_string()));
        assert_eq!(normalize_host("nope"), None);
    }

    #[test]
    fn a_requested_host_outside_the_tenant_is_rejected() {
        let a = Uuid::new_v4();
        let hosts: HashSet<Uuid> = [a].into_iter().collect();
        assert!(host_allowed(&hosts, &a.to_string()));
        assert!(!host_allowed(&hosts, &Uuid::new_v4().to_string()));
        assert!(!host_allowed(&hosts, "not-a-uuid"));
    }

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
        broadcaster.publish(std::slice::from_ref(&event));

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

    #[tokio::test]
    async fn rejects_a_cross_origin_websocket_upgrade() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let broadcaster = Arc::new(LiveEventBroadcaster::new());
        let addr = spawn_test_server(broadcaster).await;

        let mut request = format!("ws://{addr}/api/v1/stream/events")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            axum::http::header::ORIGIN,
            "https://evil.example".parse().unwrap(),
        );

        let result = tokio_tungstenite::connect_async(request).await;

        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 403);
            }
            other => panic!("expected an HTTP 403 rejection, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rejects_a_host_id_that_is_not_a_uuid() {
        let broadcaster = Arc::new(LiveEventBroadcaster::new());
        let addr = spawn_test_server(broadcaster).await;
        let err = tokio_tungstenite::connect_async(format!(
            "ws://{addr}/api/v1/stream/events?host_id=not-a-uuid"
        ))
        .await
        .unwrap_err();
        match err {
            tokio_tungstenite::tungstenite::Error::Http(resp) => assert_eq!(resp.status(), 400),
            other => panic!("expected an HTTP 400 rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed_and_unsubscribed() {
        let broadcaster = Arc::new(LiveEventBroadcaster::new());
        let app = build_stream_router_with_keepalive(
            broadcaster.clone(),
            KeepAlive {
                ping_every: std::time::Duration::from_millis(20),
                idle_timeout: std::time::Duration::from_millis(60),
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Connect, then never poll the client: it cannot answer pings.
        let (_ws_stream, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/api/v1/stream/events"))
                .await
                .unwrap();
        assert!(broadcaster.has_subscribers());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while broadcaster.has_subscribers() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(!broadcaster.has_subscribers(), "idle connection must be dropped");
    }
}
