use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use osiris_pipeline::{PrioritizedEvent, PriorityLane};
use osiris_schema::CanonicalEvent;
use osiris_selftelemetry::MetricsRegistry;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::sync::CancellationToken;

use crate::sink::Sink;

const LANES: [PriorityLane; 5] = [
    PriorityLane::Critical,
    PriorityLane::High,
    PriorityLane::Normal,
    PriorityLane::Low,
    PriorityLane::Verbose,
];

fn capacity_for(lane: PriorityLane) -> usize {
    match lane {
        PriorityLane::Critical => 64,
        PriorityLane::High => 256,
        PriorityLane::Normal => 1024,
        PriorityLane::Low => 2048,
        PriorityLane::Verbose => 4096,
    }
}

/// How many events the drain loop takes from a lane per cycle before
/// moving to the next lane — the starvation guard from ARCHITECTURE.md
/// §8.1: CRITICAL drains fastest, but every lower lane still gets its
/// weight's worth of progress each cycle even under sustained CRITICAL
/// load, rather than strict priority starving them completely.
fn drain_weight(lane: PriorityLane) -> usize {
    match lane {
        PriorityLane::Critical => 8,
        PriorityLane::High => 4,
        PriorityLane::Normal => 2,
        PriorityLane::Low => 1,
        PriorityLane::Verbose => 1,
    }
}

/// The Agent's local, in-process, bounded, priority-lane bus (ARCHITECTURE.md
/// §8.1). `enqueue` is synchronous (non-blocking, `try_send`) per plan
/// Global Constraints #5: a full lane drops-with-metric rather than
/// spilling to a disk ring file.
///
/// Holds only the five `Sender` halves — never the `Receiver` halves, which
/// `new()` returns separately to the caller instead of storing them behind
/// an `Option` on this struct. This is deliberate: it keeps `EventBus`
/// unconditionally `Send + Sync` (safe to wrap in `Arc<EventBus>` and share
/// with the pipeline-consumer task) without depending on whether
/// `tokio::sync::mpsc::Receiver<CanonicalEvent>` happens to be `Sync` — the
/// receivers are moved, once, into `run_drain_loop`'s single consumer
/// (ARCHITECTURE.md §8.1's "single consumer task"), and the type system
/// enforces "exactly once" by making the receivers a value returned from
/// `new()`, not a re-takeable field.
pub struct EventBus {
    senders: HashMap<PriorityLane, Sender<CanonicalEvent>>,
    metrics: Arc<MetricsRegistry>,
}

impl EventBus {
    /// Returns the bus (for `enqueue`) together with the five lane
    /// receivers (for `run_drain_loop`) — see the struct doc comment for
    /// why these are returned separately rather than stored together.
    pub fn new(
        metrics: Arc<MetricsRegistry>,
    ) -> (Self, HashMap<PriorityLane, Receiver<CanonicalEvent>>) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for lane in LANES {
            let (tx, rx) = mpsc::channel(capacity_for(lane));
            senders.insert(lane, tx);
            receivers.insert(lane, rx);
        }
        (Self { senders, metrics }, receivers)
    }

    /// Enqueues one prioritized event onto its lane (ARCHITECTURE.md §8.2's
    /// mandatory per-lane metrics: increments `bus.<lane>.enqueued_total`
    /// on success, `bus.<lane>.dropped_total` when the lane is full).
    pub fn enqueue(&self, item: PrioritizedEvent) {
        let Some(sender) = self.senders.get(&item.lane) else {
            // All five lanes are always populated by `new()`; this branch
            // only guards against a future lane being added to
            // `PriorityLane` without a corresponding channel here.
            self.metrics
                .counter(&format!("bus.{:?}.dropped_total", item.lane))
                .increment();
            return;
        };
        match sender.try_send(item.event) {
            Ok(()) => self
                .metrics
                .counter(&format!("bus.{:?}.enqueued_total", item.lane))
                .increment(),
            Err(_) => self
                .metrics
                .counter(&format!("bus.{:?}.dropped_total", item.lane))
                .increment(),
        }
    }
}

/// Drains all five lanes in strict-priority order with the starvation
/// guard, forwarding each event to `sink`. Runs until `cancellation` fires.
pub async fn run_drain_loop(
    mut receivers: HashMap<PriorityLane, Receiver<CanonicalEvent>>,
    sink: Arc<dyn Sink>,
    metrics: Arc<MetricsRegistry>,
    cancellation: CancellationToken,
) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        let mut drained_any = false;
        for lane in LANES {
            let Some(receiver) = receivers.get_mut(&lane) else {
                continue;
            };
            for _ in 0..drain_weight(lane) {
                match receiver.try_recv() {
                    Ok(event) => {
                        drained_any = true;
                        metrics
                            .counter(&format!("bus.{:?}.dequeued_total", lane))
                            .increment();
                        let _ = sink.send(event).await;
                    }
                    Err(_) => break,
                }
            }
        }
        if !drained_any {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                _ = cancellation.cancelled() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::InMemorySink;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use uuid::Uuid;

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1,
            monotonic_timestamp: 1,
            event_type: EventType::ProcessExec,
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

    /// Like `sample_event`, but tagged so a test can tell, from
    /// `InMemorySink::events()`'s send-order recording, which lane an
    /// event came from.
    fn tagged_event(tag: &str) -> CanonicalEvent {
        let mut event = sample_event();
        event.tags = vec![tag.to_string()];
        event
    }

    #[tokio::test]
    async fn enqueued_events_reach_the_sink_via_drain_loop() {
        let metrics = Arc::new(MetricsRegistry::new());
        let (bus, receivers) = EventBus::new(metrics.clone());
        let sink = InMemorySink::new();
        let sink_dyn: Arc<dyn Sink> = Arc::new(sink.clone());
        let cancellation = CancellationToken::new();
        let drain_handle = tokio::spawn(run_drain_loop(
            receivers,
            sink_dyn,
            metrics.clone(),
            cancellation.clone(),
        ));

        bus.enqueue(PrioritizedEvent {
            event: sample_event(),
            lane: PriorityLane::Normal,
        });
        bus.enqueue(PrioritizedEvent {
            event: sample_event(),
            lane: PriorityLane::Critical,
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        cancellation.cancel();
        drain_handle.await.unwrap();

        assert_eq!(sink.events().len(), 2);
        assert_eq!(metrics.counter("bus.Normal.enqueued_total").get(), 1);
        assert_eq!(metrics.counter("bus.Critical.enqueued_total").get(), 1);
    }

    #[tokio::test]
    async fn full_lane_drops_with_metric_instead_of_blocking() {
        let metrics = Arc::new(MetricsRegistry::new());
        let (bus, _receivers) = EventBus::new(metrics.clone());
        // Verbose lane capacity is 4096 — instead of filling it for real,
        // this test verifies the drop path directly on a lane whose
        // channel we can fill cheaply: send one over Critical's smaller
        // capacity (64) worth of events with nothing draining them yet
        // (the receivers are held but never polled in this test).
        for _ in 0..64 {
            bus.enqueue(PrioritizedEvent {
                event: sample_event(),
                lane: PriorityLane::Critical,
            });
        }
        // The 65th send must be dropped, not block, since nothing is
        // draining the channel in this test.
        bus.enqueue(PrioritizedEvent {
            event: sample_event(),
            lane: PriorityLane::Critical,
        });

        assert_eq!(metrics.counter("bus.Critical.enqueued_total").get(), 64);
        assert_eq!(metrics.counter("bus.Critical.dropped_total").get(), 1);
    }

    /// Under sustained CRITICAL-lane load (far more queued than one drain
    /// cycle's weight of 8), the Verbose lane must still make progress each
    /// cycle (the starvation guard) rather than being starved outright by
    /// strict priority ordering.
    ///
    /// Final counts alone don't distinguish weighted/interleaved draining
    /// from naive strict-priority draining (drain all of Critical, then
    /// Verbose) — both reach the same totals once everything's flushed. So
    /// this test inspects `InMemorySink`'s *send order* (tagging each event
    /// by originating lane) and asserts the first Verbose event was
    /// forwarded before the last Critical event: with weight
    /// Critical=8/Verbose=1, cycle 1 drains 8 Critical then 1 Verbose, so
    /// Verbose event #1 lands at index 8 while Critical events keep
    /// arriving through index 21. A strict-priority-only implementation
    /// would instead forward all 20 Critical events (indices 0..19) before
    /// any Verbose event (indices 20..22), which fails this assertion.
    #[tokio::test]
    async fn lower_lanes_still_drain_under_sustained_critical_load() {
        let metrics = Arc::new(MetricsRegistry::new());
        let (bus, receivers) = EventBus::new(metrics.clone());
        let sink = InMemorySink::new();
        let sink_dyn: Arc<dyn Sink> = Arc::new(sink.clone());
        let cancellation = CancellationToken::new();
        let drain_handle = tokio::spawn(run_drain_loop(
            receivers,
            sink_dyn,
            metrics.clone(),
            cancellation.clone(),
        ));

        // 20 Critical events (more than one cycle's weight of 8) plus 3
        // Verbose events, all enqueued before the loop gets to run.
        for _ in 0..20 {
            bus.enqueue(PrioritizedEvent {
                event: tagged_event("critical"),
                lane: PriorityLane::Critical,
            });
        }
        for _ in 0..3 {
            bus.enqueue(PrioritizedEvent {
                event: tagged_event("verbose"),
                lane: PriorityLane::Verbose,
            });
        }

        tokio::time::sleep(Duration::from_millis(150)).await;
        cancellation.cancel();
        drain_handle.await.unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 23);
        assert_eq!(metrics.counter("bus.Verbose.dequeued_total").get(), 3);
        assert_eq!(metrics.counter("bus.Critical.dequeued_total").get(), 20);

        let has_tag = |e: &CanonicalEvent, tag: &str| e.tags.iter().any(|t| t == tag);
        let first_verbose_idx = events
            .iter()
            .position(|e| has_tag(e, "verbose"))
            .expect("a verbose event was sent and must appear in send order");
        let last_critical_idx = events
            .iter()
            .rposition(|e| has_tag(e, "critical"))
            .expect("a critical event was sent and must appear in send order");
        assert!(
            first_verbose_idx < last_critical_idx,
            "expected interleaved draining (first Verbose event before the last Critical event), \
             got first_verbose_idx={first_verbose_idx} last_critical_idx={last_critical_idx} — \
             this would fail under naive strict-priority draining"
        );
    }
}
