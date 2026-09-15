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
}
