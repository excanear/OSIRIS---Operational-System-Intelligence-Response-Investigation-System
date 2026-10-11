use std::sync::Arc;
use std::time::Duration;

use osiris_baseline::BaselineEngine;
use osiris_correlate::{BehavioralChain, CorrelationEngine, EdgeSource};
use osiris_detect::DetectionEngine;
use osiris_risk::RiskEngine;
use osiris_schema::{Alert, CanonicalEvent, EntityRef, EntityRelationship, RiskScoreRecord};
use osiris_storage::{RelationshipQueryPlan, Storage};
use tokio_util::sync::CancellationToken;

use osiris_fileutil::LineTailer;

/// The server's own wall clock, nanoseconds since the Unix epoch — used to
/// clamp agent-supplied `event.timestamp` values before they reach the fleet
/// registry (see `IngestContext::ingest`'s AGENT_HEALTH handling below).
/// Panics if the system clock is set before the epoch, matching the existing
/// `now_ns` pattern used elsewhere in the workspace (e.g. `osiris-api`).
fn server_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Adapts `osiris_storage::Storage::query_relationships` to
/// `osiris_correlate::EdgeSource` — the one place `osiris-correlate` and
/// `osiris-storage` meet, keeping the Correlation Engine itself decoupled
/// from the storage layer (Phase 6 plan Task 10 / Global Constraint #3). A
/// query failure degrades to "no edges found" rather than panicking the
/// ingestion loop — correlation is best-effort enrichment, not a
/// correctness-critical path.
///
/// Edges are attributed to a host through their source event, and lookups are
/// restricted to the ingesting event's host so one host cannot inject edges
/// into another host's chains.
struct StorageEdgeSource<'s> {
    storage: &'s dyn Storage,
    host_id: String,
}

impl EdgeSource for StorageEdgeSource<'_> {
    fn edges_for(&self, entity: &EntityRef, since: u64, until: u64) -> Vec<EntityRelationship> {
        let plan = RelationshipQueryPlan {
            entity: Some(entity.clone()),
            since: Some(since),
            until: Some(until),
            host_ids: Some(vec![self.host_id.clone()]),
            ..RelationshipQueryPlan::new()
        };
        match self.storage.query_relationships(&plan) {
            Ok(edges) => edges,
            Err(e) => {
                tracing::warn!(error = %e, "query_relationships failed during correlation; treating as no edges");
                vec![]
            }
        }
    }
}

/// One event's worth of Correlation/Baseline/Risk processing (ARCHITECTURE.md
/// §26 step 5/9/11: "simultaneously fans the batch out to: Detection...
/// Correlation... Baseline", then Risk annotates from both). Runs after
/// `storage.write_relationships` for the whole batch, so a chain built for
/// an early event in the batch can already see relationships persisted by
/// this same batch. Returns the event's risk record instead of writing it:
/// the caller persists the whole batch's records in one transaction (one
/// commit per batch rather than per event — Phase 10 finding F1). Nothing in
/// this function reads risk scores back, so deferring the write is invisible.
/// `observations` are the event's Baseline observations, taken for the whole
/// batch up front in one transaction (`BaselineEngine::observe_batch`).
fn correlate_and_score(
    storage: &dyn Storage,
    risk_engine: &RiskEngine,
    correlation_engine: &CorrelationEngine,
    event: &CanonicalEvent,
    alerts_for_event: &[Alert],
    observations: &[osiris_baseline::Observation],
) -> Option<RiskScoreRecord> {
    let process = event.process.as_ref()?;
    let seed = EntityRef::Process {
        process_key: process.process_key,
    };
    let edge_source = StorageEdgeSource {
        storage,
        host_id: event.host_id.to_string(),
    };
    let chain: BehavioralChain =
        correlation_engine.build_chain(&edge_source, seed, event.timestamp);

    risk_engine.score(event, alerts_for_event, observations, Some(&chain))
}

/// The policy hash an agent reports in its heartbeat. An explicit `null`
/// means "no policy" (the empty-policy hash). A missing field means the agent
/// predates 9d-3 and cannot apply policy, so it is recorded as unknown
/// (`None`) and the reconciler sends it nothing; a 9d-3 agent always sends the
/// field. Anything that is not 64 lowercase hex characters is unusable and is
/// recorded as unknown too.
fn reported_policy_hash(event_data: &serde_json::Value) -> Option<String> {
    match event_data.get("policy_hash") {
        None => None,
        Some(serde_json::Value::Null) => Some(osiris_policy::empty_policy_hash_hex()),
        Some(v) => v
            .as_str()
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .map(str::to_string),
    }
}

/// Everything a batch of events flows through once it reaches the Server:
/// storage, detection, baseline, risk, correlation, and the live-stream fan-out.
/// Shared by the spool tailer and the mTLS Agent listener.
#[derive(Clone)]
pub struct IngestContext {
    pub storage: Arc<dyn Storage>,
    pub detection_engine: Arc<DetectionEngine>,
    pub baseline_engine: Arc<BaselineEngine>,
    pub risk_engine: Arc<RiskEngine>,
    pub correlation_engine: Arc<CorrelationEngine>,
    pub broadcaster: Arc<osiris_api::LiveEventBroadcaster>,
    pub fleet_registry: Arc<dyn osiris_fleet::HostRegistry>,
    /// Set once at startup when the command channel is configured; unset means
    /// heartbeats trigger no policy reconciliation.
    pub policy_reconciler: Arc<std::sync::OnceLock<Arc<crate::policy_reconcile::PolicyReconciler>>>,
}

impl IngestContext {
    /// Persists and analyses `events`, then publishes them to live-stream
    /// subscribers. `Err` carries a human-readable cause; nothing is published on error.
    pub async fn ingest(&self, events: Vec<CanonicalEvent>) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let storage = self.storage.clone();
        let detection_engine = self.detection_engine.clone();
        let baseline_engine = self.baseline_engine.clone();
        let risk_engine = self.risk_engine.clone();
        let correlation_engine = self.correlation_engine.clone();
        let events_for_broadcast = if self.broadcaster.has_subscribers() {
            Some(events.clone())
        } else {
            None
        };
        let health_events: Vec<CanonicalEvent> = events
            .iter()
            .filter(|e| e.event_type == osiris_schema::EventType::AgentHealth)
            .cloned()
            .collect();
        let outcome = tokio::task::spawn_blocking(move || {
            Ok::<_, osiris_storage::StorageError>({
                // An event id already owned by a different host must not be
                // ingested: the insert would be ignored but its edges, alerts
                // and risk would otherwise be attributed to the victim host.
                let total = events.len();
                let mut kept = Vec::with_capacity(total);
                for event in events {
                    match storage.event_owner(event.event_id)? {
                        Some(owner) if owner != event.host_id => {}
                        _ => kept.push(event),
                    }
                }
                let events = kept;
                if events.len() < total {
                    tracing::error!(
                        dropped = total - events.len(),
                        total,
                        "dropped events whose event_id is already owned by another host"
                    );
                }
                let report = storage.batch_write(&events)?;
                let alerts = detection_engine.evaluate_batch(&events);
                if !alerts.is_empty() {
                    storage.write_alerts(&alerts)?;
                }

                let edges: Vec<EntityRelationship> = events
                    .iter()
                    .flat_map(|e| e.relationships.clone())
                    .collect();
                if !edges.is_empty() {
                    storage.write_relationships(&edges)?;
                }

                // Baseline counts only process events (the ones that are scored).
                let process_events: Vec<&CanonicalEvent> =
                    events.iter().filter(|e| e.process.is_some()).collect();
                let mut observations = match baseline_engine
                    .observe_batch(process_events.iter().copied())
                {
                    Ok(obs) => obs,
                    Err(e) => {
                        tracing::warn!(error = %e, events = process_events.len(), "baseline observe failed; scoring the batch without baseline input");
                        vec![vec![]; process_events.len()]
                    }
                }
                .into_iter();
                let mut risk_records = Vec::new();
                for event in process_events {
                    let alerts_for_event: Vec<Alert> = alerts
                        .iter()
                        .filter(|a| a.evidence().contains(&event.event_id))
                        .cloned()
                        .collect();
                    let observations = observations.next().unwrap_or_default();
                    risk_records.extend(correlate_and_score(
                        storage.as_ref(),
                        &risk_engine,
                        &correlation_engine,
                        event,
                        &alerts_for_event,
                        &observations,
                    ));
                }
                if !risk_records.is_empty() {
                    storage.write_risk_scores(&risk_records)?;
                }

                report
            })
        })
        .await;
        match outcome {
            Ok(Ok(_report)) => {
                if let Some(events) = events_for_broadcast {
                    self.broadcaster.publish(&events);
                }
                if !health_events.is_empty() {
                    let fleet_registry = self.fleet_registry.clone();
                    let heartbeat_hosts: Vec<uuid::Uuid> = {
                        let mut seen = std::collections::HashSet::new();
                        health_events
                            .iter()
                            .map(|e| e.host_id)
                            .filter(|h| seen.insert(*h))
                            .collect()
                    };
                    // Computed once for the whole batch: an agent's clock is
                    // unbounded, so every timestamp that reaches the registry
                    // is capped at the server's own clock. Without this, a
                    // future-stamped heartbeat (bad RTC, manual clock set,
                    // compromised host) would freeze the row's last_seen
                    // ahead of real time — the freshness gate in
                    // `osiris-fleet` then rejects every correctly-stamped
                    // heartbeat that follows until real time catches up, so
                    // a dead host would keep showing ONLINE/healthy. A
                    // backward-skewed agent still reports its true (older)
                    // timestamp and shows STALE, which is honest.
                    let server_now = server_now_ns();
                    let join_result = tokio::task::spawn_blocking(move || {
                        for event in health_events {
                            let agent_version =
                                event.event_data.get("agent_version").and_then(|v| v.as_str());
                            let health: Option<osiris_health::AgentHealth> = event
                                .event_data
                                .get("health")
                                .and_then(|v| serde_json::from_value(v.clone()).ok());
                            let (Some(agent_version), Some(health)) = (agent_version, health) else {
                                tracing::warn!(host_id = %event.host_id, "AGENT_HEALTH event has malformed event_data; skipping fleet registry upsert");
                                continue;
                            };
                            let clamped_ts = event.timestamp.min(server_now);
                            let cloud = event.host.cloud.as_ref();
                            let row = osiris_fleet::HostRow {
                                host_id: event.host_id,
                                hostname: event.host.hostname.clone(),
                                distro: event.host.distro.clone(),
                                kernel_version: event.host.kernel_version.clone(),
                                agent_version: agent_version.to_string(),
                                enrolled_at: clamped_ts, // ignored by upsert_heartbeat after the first insert
                                last_seen: clamped_ts,
                                health_state: health.state,
                                cloud_provider: cloud.map(|c| c.provider.clone()),
                                cloud_instance_id: cloud.and_then(|c| c.instance_id.clone()),
                                cloud_region: cloud.and_then(|c| c.region.clone()),
                                applied_policy_hash: reported_policy_hash(&event.event_data),
                            };
                            if let Err(e) = fleet_registry.upsert_heartbeat(row) {
                                tracing::warn!(host_id = %event.host_id, error = %e, "fleet registry upsert failed");
                            }
                        }
                    })
                    .await;
                    if let Err(e) = join_result {
                        tracing::error!(error = %e, "fleet registry upsert task panicked or was cancelled");
                    } else if let Some(reconciler) = self.policy_reconciler.get() {
                        reconciler.spawn_reconcile(heartbeat_hosts);
                    }
                }
                Ok(())
            }
            Ok(Err(storage_err)) => Err(storage_err.to_string()),
            Err(join_err) => Err(format!("ingest task panicked or was cancelled: {join_err}")),
        }
    }
}

#[async_trait::async_trait]
impl osiris_transport::server::BatchHandler for IngestContext {
    async fn handle(
        &self,
        _host_id: uuid::Uuid,
        events: Vec<CanonicalEvent>,
    ) -> Result<(), String> {
        self.ingest(events).await
    }
}

/// Tails the Agent's spool file and ingests each new line - the same-host
/// path (a remote Agent uses the mTLS listener instead).
#[allow(clippy::too_many_arguments)]
pub async fn run_ingestion_loop(
    spool_path: impl Into<std::path::PathBuf>,
    storage: Arc<dyn Storage>,
    detection_engine: Arc<DetectionEngine>,
    baseline_engine: Arc<BaselineEngine>,
    risk_engine: Arc<RiskEngine>,
    correlation_engine: Arc<CorrelationEngine>,
    broadcaster: Arc<osiris_api::LiveEventBroadcaster>,
    fleet_registry: Arc<dyn osiris_fleet::HostRegistry>,
    poll_interval: Duration,
    cancellation: CancellationToken,
) {
    let context = IngestContext {
        storage,
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
        broadcaster,
        fleet_registry,
        policy_reconciler: Arc::new(std::sync::OnceLock::new()),
    };
    run_ingestion_context_loop(spool_path, context, poll_interval, cancellation).await;
}

/// `run_ingestion_loop` with a caller-built context (so the spool path shares
/// the server's policy reconciler slot).
pub async fn run_ingestion_context_loop(
    spool_path: impl Into<std::path::PathBuf>,
    context: IngestContext,
    poll_interval: Duration,
    cancellation: CancellationToken,
) {
    let mut tailer = LineTailer::new(spool_path);
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        match tailer.poll() {
            Ok(lines) => {
                let events: Vec<CanonicalEvent> = lines
                    .iter()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
                let event_count = events.len();
                if let Err(error) = context.ingest(events).await {
                    tracing::error!(
                        %error,
                        event_count,
                        "batch ingest failed; tailer offset already advanced past these events \
                         — they are permanently lost"
                    );
                }
            }
            Err(io_err) => {
                tracing::error!(error = %io_err, "spool tailer poll failed; events since last successful poll may be lost");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {}
            _ = cancellation.cancelled() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        encode_device_id, Category, EventType, FileRef, HostRef, ProcessKey, ProcessRef, Severity,
        Source, SCHEMA_VERSION,
    };
    use osiris_storage::{AlertQueryPlan, QueryPlan};
    use osiris_storage_sqlite::SqliteStorage;
    use std::io::Write;
    use uuid::Uuid;

    /// Fresh, empty Baseline/Risk/Correlation engines for a test —
    /// `baseline.db` lives under `dir` (a per-test tempdir), `risk_engine`
    /// uses every documented default weight, `correlation_engine` uses a
    /// generous depth/window since these tests operate on nanosecond-scale
    /// synthetic timestamps that may span more than a real-world 30s.
    fn test_engines(
        dir: &std::path::Path,
    ) -> (Arc<BaselineEngine>, Arc<RiskEngine>, Arc<CorrelationEngine>) {
        let baseline_engine = Arc::new(BaselineEngine::open(dir.join("baseline.db")).unwrap());
        let risk_engine = Arc::new(RiskEngine::new(Default::default()));
        let correlation_engine = Arc::new(CorrelationEngine::new(5, u64::MAX / 2));
        (baseline_engine, risk_engine, correlation_engine)
    }

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1000,
            monotonic_timestamp: 1000,
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

    fn agent_health_event(host_id: uuid::Uuid, timestamp: u64) -> CanonicalEvent {
        let host = osiris_schema::HostRef {
            host_id,
            hostname: "h1".into(),
            distro: "ubuntu-24.04".into(),
            kernel_version: "6.8.0".into(),
            cloud: None,
        };
        CanonicalEvent {
            event_id: uuid::Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "boot-1".into(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::AgentHealth,
            category: EventType::AgentHealth.category(),
            severity: Severity::Info,
            host,
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
            source: Source::AgentInternal,
            provider: "agent/health".into(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({
                "agent_version": "0.1.0",
                "health": {"state": {"state": "HEALTHY"}, "sensors": []}
            }),
        }
    }

    fn agent_health_event_with_health(
        host_id: uuid::Uuid,
        timestamp: u64,
        health_json: serde_json::Value,
    ) -> CanonicalEvent {
        let mut event = agent_health_event(host_id, timestamp);
        event.event_data = serde_json::json!({
            "agent_version": "0.1.0",
            "health": {"state": health_json, "sensors": []}
        });
        event
    }

    #[tokio::test]
    async fn a_future_stamped_heartbeat_does_not_freeze_the_row_as_online_and_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let detection_engine = Arc::new(DetectionEngine::new(vec![]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage: storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: fleet_registry.clone(),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let host_id = uuid::Uuid::new_v4();
        let server_now = server_now_ns();
        let one_hour_ns = 60 * 60 * 1_000_000_000u64;

        // A heartbeat stamped an hour in the future (bad RTC, manual clock
        // set, compromised host) must be clamped to server time on ingest,
        // not stored verbatim.
        context
            .ingest(vec![agent_health_event_with_health(
                host_id,
                server_now + one_hour_ns,
                serde_json::json!({"state": "HEALTHY"}),
            )])
            .await
            .unwrap();
        let after_future = fleet_registry.get(host_id).unwrap().unwrap();
        assert!(
            after_future.last_seen <= server_now_ns(),
            "a future-stamped heartbeat's last_seen must be clamped to server time"
        );

        // A correctly-stamped Failed heartbeat that follows must not be
        // rejected by the freshness gate (which it would be if the first
        // heartbeat's last_seen had been stored unclamped, ahead of real
        // time).
        context
            .ingest(vec![agent_health_event_with_health(
                host_id,
                server_now_ns(),
                serde_json::json!({"state": "FAILED", "last_error": "sensor crashed"}),
            )])
            .await
            .unwrap();
        let after_failed = fleet_registry.get(host_id).unwrap().unwrap();
        assert!(
            matches!(after_failed.health_state, osiris_health::HealthState::Failed { .. }),
            "a subsequent correctly-stamped Failed heartbeat must not be frozen out by a future last_seen: got {:?}",
            after_failed.health_state
        );
        assert!(
            after_failed.last_seen <= server_now_ns(),
            "last_seen must never exceed server time"
        );
    }

    #[tokio::test]
    async fn a_heartbeats_policy_hash_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage,
            detection_engine: Arc::new(DetectionEngine::new(vec![])),
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: fleet_registry.clone(),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let host_id = uuid::Uuid::new_v4();
        let base = server_now_ns() - 10_000_000_000;
        let empty = osiris_policy::empty_policy_hash_hex();
        let abab = "ab".repeat(32);
        let cases: Vec<(serde_json::Value, Option<String>)> = vec![
            (serde_json::json!(abab), Some(abab.clone())),
            (serde_json::Value::Null, Some(empty.clone())),
            (serde_json::json!("not-a-hash"), None),
            (serde_json::json!("AB".repeat(32)), None),
            (serde_json::json!(12345), None),
        ];
        let mut ts = base;
        for (value, expected) in cases {
            ts += 1_000_000_000;
            let mut event = agent_health_event(host_id, ts);
            event.event_data["policy_hash"] = value.clone();
            context.ingest(vec![event]).await.unwrap();
            assert_eq!(
                fleet_registry
                    .get(host_id)
                    .unwrap()
                    .unwrap()
                    .applied_policy_hash,
                expected,
                "policy_hash {value}"
            );
        }
        // Field absent entirely: a pre-9d-3 agent, recorded as unknown.
        ts += 1_000_000_000;
        context
            .ingest(vec![agent_health_event(host_id, ts)])
            .await
            .unwrap();
        assert_eq!(
            fleet_registry
                .get(host_id)
                .unwrap()
                .unwrap()
                .applied_policy_hash,
            None
        );
        // An explicit null after that is "no policy" again.
        ts += 1_000_000_000;
        let mut event = agent_health_event(host_id, ts);
        event.event_data["policy_hash"] = serde_json::Value::Null;
        context.ingest(vec![event]).await.unwrap();
        assert_eq!(
            fleet_registry
                .get(host_id)
                .unwrap()
                .unwrap()
                .applied_policy_hash,
            Some(empty)
        );
    }

    #[tokio::test]
    async fn ingesting_an_agent_health_event_upserts_the_fleet_registry() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let detection_engine = Arc::new(DetectionEngine::new(vec![]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage: storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: fleet_registry.clone(),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let host_id = uuid::Uuid::new_v4();

        context
            .ingest(vec![agent_health_event(host_id, 1_000)])
            .await
            .unwrap();

        let row = fleet_registry.get(host_id).unwrap().unwrap();
        assert_eq!(row.agent_version, "0.1.0");
        assert_eq!(row.last_seen, 1_000);
        // The underlying event is still written to Storage unchanged — the
        // registry is an additive side effect, not a replacement path.
        let stored = storage
            .query(&osiris_storage::QueryPlan::default())
            .unwrap();
        assert_eq!(stored.len(), 1);
    }

    #[tokio::test]
    async fn a_malformed_agent_health_event_data_does_not_fail_the_batch() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let detection_engine = Arc::new(DetectionEngine::new(vec![]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage: storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: fleet_registry.clone(),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let host_id = uuid::Uuid::new_v4();
        let mut bad = agent_health_event(host_id, 1_000);
        bad.event_data = serde_json::json!({"nonsense": true}); // no "agent_version"/"health"

        let result = context.ingest(vec![bad]).await;

        assert!(
            result.is_ok(),
            "a bad AGENT_HEALTH payload must not fail the batch"
        );
        assert_eq!(
            fleet_registry.get(host_id).unwrap(),
            None,
            "no row is created for the unparseable event"
        );
        let stored = storage
            .query(&osiris_storage::QueryPlan::default())
            .unwrap();
        assert_eq!(
            stored.len(),
            1,
            "the underlying event is still stored even though its registry upsert was skipped"
        );
    }

    #[tokio::test]
    async fn an_ordinary_event_batch_does_not_touch_the_fleet_registry() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let detection_engine = Arc::new(DetectionEngine::new(vec![]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage,
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: fleet_registry.clone(),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        // `sample_event()` (this file's existing test-only helper, defined
        // above at the top of this test module) builds a plain ProcessExec
        // CanonicalEvent with its own freshly-generated host_id — reuse it
        // rather than inventing a new builder.
        let plain = sample_event();
        let host_id = plain.host_id;

        context.ingest(vec![plain]).await.unwrap();

        assert_eq!(fleet_registry.get(host_id).unwrap(), None);
    }

    #[tokio::test]
    async fn ingests_spooled_events_into_storage() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        std::fs::write(&spool_path, "").unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let cancellation = CancellationToken::new();
        let detection_engine = Arc::new(DetectionEngine::new(vec![]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            Arc::new(osiris_api::LiveEventBroadcaster::new()),
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()),
            Duration::from_millis(20),
            cancellation.clone(),
        ));

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&spool_path)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(&sample_event()).unwrap()).unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        cancellation.cancel();
        handle.await.unwrap();

        let results = storage.query(&QueryPlan::new()).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn a_remote_agent_over_mtls_lands_in_storage_through_the_same_pipeline() {
        use osiris_transport::client::{run_forwarder, ForwarderConfig};
        use osiris_transport::pki::{generate_ca, issue_agent, issue_server, write_issued};
        use osiris_transport::server::Listener;

        let dir = tempfile::tempdir().unwrap();
        let ca = generate_ca("t").unwrap();
        write_issued(dir.path(), "ca", &ca).unwrap();
        let server = issue_server(&ca.cert_pem, &ca.key_pem, &["localhost".into()]).unwrap();
        write_issued(dir.path(), "server", &server).unwrap();
        let mut event = sample_event();
        let host = event.host_id;
        event.host.host_id = host;
        let agent = issue_agent(&ca.cert_pem, &ca.key_pem, host).unwrap();
        write_issued(dir.path(), "agent", &agent).unwrap();

        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage: storage.clone(),
            detection_engine: Arc::new(DetectionEngine::new(vec![])),
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: Arc::new(
                osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap(),
            ),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let tls = osiris_transport::tls::server_config(
            &dir.path().join("server.pem"),
            &dir.path().join("server.key"),
            &dir.path().join("ca.pem"),
        )
        .unwrap();
        let listener = Listener::bind("127.0.0.1:0", tls, Default::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let cancel = CancellationToken::new();
        tokio::spawn(listener.run(Arc::new(context), cancel.clone()));

        let spool = dir.path().join("spool.ndjson");
        std::fs::write(
            &spool,
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        let forwarder = tokio::spawn(run_forwarder(
            ForwarderConfig::new(
                addr,
                "localhost",
                dir.path().join("ca.pem"),
                dir.path().join("agent.pem"),
                dir.path().join("agent.key"),
                &spool,
            ),
            cancel.clone(),
        ));

        for _ in 0..100 {
            if storage.query(&QueryPlan::new()).unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(storage.query(&QueryPlan::new()).unwrap().len(), 1);
        cancel.cancel();
        forwarder.await.unwrap().unwrap();
    }

    #[test]
    fn edge_lookups_are_restricted_to_the_ingesting_host() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let (a, b) = (sample_event(), sample_event());
        storage.batch_write(&[a.clone(), b.clone()]).unwrap();
        let process = EntityRef::Process {
            process_key: ProcessKey::new(a.host_id, "b", 1, 1),
        };
        let edge = |ev: &CanonicalEvent, ip: &str| EntityRelationship {
            from: process.clone(),
            to: EntityRef::Ip {
                addr: ip.to_string(),
            },
            relation: osiris_schema::Relation::ConnectedTo,
            event_id: ev.event_id,
            timestamp: 10,
        };
        storage
            .write_relationships(&[edge(&a, "10.0.0.1"), edge(&b, "10.0.0.2")])
            .unwrap();
        let source = StorageEdgeSource {
            storage: &storage,
            host_id: a.host_id.to_string(),
        };
        let edges = source.edges_for(&process, 0, 100);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].event_id, a.event_id);
    }

    #[tokio::test]
    async fn foreign_event_id_reuse_is_dropped_and_own_redelivery_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage: storage.clone(),
            detection_engine: Arc::new(DetectionEngine::new(vec![])),
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: Arc::new(
                osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap(),
            ),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let a = sample_event();
        context.ingest(vec![a.clone()]).await.unwrap();
        context.ingest(vec![a.clone()]).await.unwrap();
        context.ingest(vec![a.clone()]).await.unwrap();

        let mut forged = sample_event();
        forged.event_id = a.event_id;
        forged.relationships.push(EntityRelationship {
            from: EntityRef::Process {
                process_key: ProcessKey::new(forged.host_id, "b", 1, 1),
            },
            to: EntityRef::Ip {
                addr: "6.6.6.6".to_string(),
            },
            relation: osiris_schema::Relation::ConnectedTo,
            event_id: a.event_id,
            timestamp: 10,
        });
        context.ingest(vec![forged.clone()]).await.unwrap();

        let all = storage.query(&QueryPlan::new()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].host_id, a.host_id);
        assert_eq!(storage.event_owner(a.event_id).unwrap(), Some(a.host_id));
        let mut plan = osiris_storage::RelationshipQueryPlan::new();
        plan.limit = 100;
        assert_eq!(storage.query_relationships(&plan).unwrap().len(), 0);
    }

    /// Delegates to SQLite and counts `write_risk_scores` calls: each call is
    /// one SQLite transaction (one fsync), so the count is the commit cost.
    struct CountingStorage {
        inner: SqliteStorage,
        risk_writes: std::sync::atomic::AtomicUsize,
    }

    impl Storage for CountingStorage {
        fn write(&self, event: &CanonicalEvent) -> Result<(), osiris_storage::StorageError> {
            self.inner.write(event)
        }
        fn batch_write(
            &self,
            events: &[CanonicalEvent],
        ) -> Result<osiris_storage::WriteReport, osiris_storage::StorageError> {
            self.inner.batch_write(events)
        }
        fn event_owner(&self, id: Uuid) -> Result<Option<Uuid>, osiris_storage::StorageError> {
            self.inner.event_owner(id)
        }
        fn query(
            &self,
            plan: &QueryPlan,
        ) -> Result<Vec<CanonicalEvent>, osiris_storage::StorageError> {
            self.inner.query(plan)
        }
        fn query_events(
            &self,
            plan: &osiris_query::EventQueryPlan,
        ) -> Result<Vec<CanonicalEvent>, osiris_storage::StorageError> {
            self.inner.query_events(plan)
        }
        fn get_event(
            &self,
            id: Uuid,
        ) -> Result<Option<CanonicalEvent>, osiris_storage::StorageError> {
            self.inner.get_event(id)
        }
        fn delete(
            &self,
            criteria: &osiris_storage::DeleteCriteria,
        ) -> Result<u64, osiris_storage::StorageError> {
            self.inner.delete(criteria)
        }
        fn retention_apply(
            &self,
            policy: &osiris_storage::RetentionPolicy,
        ) -> Result<osiris_storage::RetentionReport, osiris_storage::StorageError> {
            self.inner.retention_apply(policy)
        }
        fn health(&self) -> osiris_storage::StorageHealth {
            self.inner.health()
        }
        fn write_alerts(
            &self,
            alerts: &[Alert],
        ) -> Result<osiris_storage::WriteReport, osiris_storage::StorageError> {
            self.inner.write_alerts(alerts)
        }
        fn query_alerts(
            &self,
            plan: &AlertQueryPlan,
        ) -> Result<Vec<Alert>, osiris_storage::StorageError> {
            self.inner.query_alerts(plan)
        }
        fn write_relationships(
            &self,
            edges: &[EntityRelationship],
        ) -> Result<osiris_storage::WriteReport, osiris_storage::StorageError> {
            self.inner.write_relationships(edges)
        }
        fn query_relationships(
            &self,
            plan: &RelationshipQueryPlan,
        ) -> Result<Vec<EntityRelationship>, osiris_storage::StorageError> {
            self.inner.query_relationships(plan)
        }
        fn write_risk_scores(
            &self,
            scores: &[osiris_schema::RiskScoreRecord],
        ) -> Result<osiris_storage::WriteReport, osiris_storage::StorageError> {
            self.risk_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.write_risk_scores(scores)
        }
        fn query_risk_scores(
            &self,
            plan: &osiris_storage::RiskQueryPlan,
        ) -> Result<Vec<osiris_schema::RiskScoreRecord>, osiris_storage::StorageError> {
            self.inner.query_risk_scores(plan)
        }
    }

    /// Phase 10 finding F1: risk scores used to be written one transaction per
    /// event before the ack, which capped real-Linux ingest at ~100-140 eps.
    #[tokio::test]
    async fn a_batch_is_scored_with_one_risk_score_write() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingStorage {
            inner: SqliteStorage::open(dir.path().join("events.db")).unwrap(),
            risk_writes: std::sync::atomic::AtomicUsize::new(0),
        });
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let context = IngestContext {
            storage: counting.clone(),
            detection_engine: Arc::new(DetectionEngine::new(vec![])),
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: Arc::new(
                osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap(),
            ),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let host_id = Uuid::new_v4();
        let events: Vec<CanonicalEvent> = (0..20u32)
            .map(|i| {
                let mut e = network_connect_event(host_id, 1000 + i, 1_000_000 + i as u64);
                // A distinct destination per event: each is a NEW baseline pair, so each scores.
                e.network.as_mut().unwrap().dst_port = 1000 + i as u16;
                e
            })
            .collect();
        context.ingest(events).await.unwrap();

        let scores = counting
            .query_risk_scores(&osiris_storage::RiskQueryPlan {
                limit: 100,
                ..osiris_storage::RiskQueryPlan::new()
            })
            .unwrap();
        assert_eq!(scores.len(), 20, "every process event is scored");
        assert_eq!(
            counting
                .risk_writes
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the whole batch's scores are persisted in one write"
        );
    }

    /// Phase 10 finding F1: per-event baseline upserts (one autocommit each)
    /// were the dominant ingest cost. Ingest must observe a batch in one
    /// baseline transaction.
    #[tokio::test]
    async fn a_batch_is_baseline_observed_in_one_commit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());
        let commits = Arc::new(AtomicUsize::new(0));
        let counter = commits.clone();
        baseline_engine.set_commit_hook(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            false
        });
        let context = IngestContext {
            storage,
            detection_engine: Arc::new(DetectionEngine::new(vec![])),
            baseline_engine,
            risk_engine,
            correlation_engine,
            broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
            fleet_registry: Arc::new(
                osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap(),
            ),
            policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        };
        let host_id = Uuid::new_v4();
        // Each event carries a process and a network block: one baseline pair each.
        let events: Vec<CanonicalEvent> = (0..20u32)
            .map(|i| network_connect_event(host_id, 1000 + i, 1_000_000 + i as u64))
            .collect();
        context.ingest(events).await.unwrap();

        assert_eq!(
            commits.load(Ordering::SeqCst),
            1,
            "the whole batch's baseline counts are committed in one transaction"
        );
    }

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
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()),
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

    #[tokio::test]
    async fn skips_malformed_lines_and_ingests_valid_ones() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        std::fs::write(&spool_path, "").unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let cancellation = CancellationToken::new();
        let detection_engine = Arc::new(DetectionEngine::new(vec![]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            Arc::new(osiris_api::LiveEventBroadcaster::new()),
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()),
            Duration::from_millis(20),
            cancellation.clone(),
        ));

        // Mix valid CanonicalEvent JSON with a truncated line and a
        // well-formed-JSON-but-wrong-shape line; the loop must skip both
        // malformed lines without erroring or panicking, and still ingest
        // the two valid events.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&spool_path)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(&sample_event()).unwrap()).unwrap();
        writeln!(file, "{{\"event_id\": \"not-cl").unwrap(); // truncated JSON
        writeln!(file, "{{\"unrelated\": \"shape\"}}").unwrap(); // valid JSON, wrong shape
        let mut second_event = sample_event();
        second_event.timestamp = 2000;
        writeln!(file, "{}", serde_json::to_string(&second_event).unwrap()).unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        cancellation.cancel();
        handle.await.unwrap();

        let results = storage.query(&QueryPlan::new()).unwrap();
        assert_eq!(results.len(), 2);
    }

    fn web_root_shell_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 1,
            event_type: EventType::FileCreate,
            category: Category::File,
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
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", 300, 1),
                pid: 300,
                exe_path: "/usr/bin/curl".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
            parent_process: None,
            thread: None,
            file: Some(FileRef {
                path: "/var/www/html/shell.php".to_string(),
                previous_path: None,
                inode: Some(1),
                device_id: Some(encode_device_id(8, 1)),
                size: None,
                mode: None,
                owner_uid: None,
                owner_gid: None,
                hash: None,
            }),
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

    const WEB_ROOT_RULE: &str = r#"
id: shell_wrote_file_to_web_root
version: 1
severity: HIGH
match:
  - field: event_type
    op: in
    value: ["FILE_CREATE", "FILE_WRITE"]
    reason: "A file was created or written on disk"
  - field: file.path
    op: starts_with
    value: "/var/www/"
    reason: "The file was written inside the web-served directory /var/www/"
  - field: process.exe_path
    op: in
    value: ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget"]
    reason: "The writing process is an interactive shell or download tool, not the web server"
"#;

    #[tokio::test]
    async fn alerts_are_evaluated_and_persisted_end_to_end_through_the_loop() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        std::fs::write(&spool_path, "").unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let cancellation = CancellationToken::new();
        let rule = osiris_detect::Rule::from_yaml_str(WEB_ROOT_RULE, "test.yaml").unwrap();
        let detection_engine = Arc::new(DetectionEngine::new(vec![rule]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            Arc::new(osiris_api::LiveEventBroadcaster::new()),
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()),
            Duration::from_millis(20),
            cancellation.clone(),
        ));

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&spool_path)
            .unwrap();
        writeln!(
            file,
            "{}",
            serde_json::to_string(&web_root_shell_event()).unwrap()
        )
        .unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        cancellation.cancel();
        handle.await.unwrap();

        let alerts = storage.query_alerts(&AlertQueryPlan::new()).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "shell_wrote_file_to_web_root");
    }

    const SEQUENCE_RULE: &str = r#"
id: network_download_then_write
version: 1
severity: HIGH
window: 30000000000
sequence:
  - field: event_type
    op: eq
    value: "NETWORK_CONNECT"
    reason: "The process opened a network connection"
  - field: event_type
    op: in
    value: ["FILE_CREATE", "FILE_WRITE"]
    reason: "The same process then created or wrote a file"
"#;

    fn network_connect_event(host_id: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
        let mut e = sample_event();
        e.host_id = host_id;
        e.timestamp = timestamp;
        e.event_type = EventType::NetworkConnect;
        e.category = Category::Network;
        e.process = Some(ProcessRef {
            process_key: ProcessKey::new(host_id, "b", pid, 1),
            pid,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1,
        });
        e.network = Some(osiris_schema::NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 4444,
            dst_ip: "203.0.113.10".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        e.relationships = vec![osiris_schema::EntityRelationship {
            from: EntityRef::Process {
                process_key: e.process.as_ref().unwrap().process_key,
            },
            to: EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            },
            relation: osiris_schema::Relation::ConnectedTo,
            event_id: e.event_id,
            timestamp,
        }];
        e
    }

    fn file_write_event(host_id: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
        let mut e = web_root_shell_event();
        e.host_id = host_id;
        e.timestamp = timestamp;
        e.process = Some(ProcessRef {
            process_key: ProcessKey::new(host_id, "b", pid, 1),
            pid,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1,
        });
        e.relationships = vec![osiris_schema::EntityRelationship {
            from: EntityRef::Process {
                process_key: e.process.as_ref().unwrap().process_key,
            },
            to: EntityRef::File {
                host_id,
                inode: 1,
                device_id: encode_device_id(8, 1),
            },
            relation: osiris_schema::Relation::Wrote,
            event_id: e.event_id,
            timestamp,
        }];
        e
    }

    /// ARCHITECTURE.md §26's full worked trace, exercised through the real
    /// ingestion loop: a process connects to the network, then writes a
    /// file, within the sequence rule's window. Proves the sequence alert
    /// fires, the relationship edges land in the queryable edge table, a
    /// baseline observation is recorded, and a `RiskScoreRecord` citing the
    /// chain-pattern bonus is queryable afterward.
    #[tokio::test]
    async fn the_full_detection_correlation_baseline_risk_trace_runs_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        std::fs::write(&spool_path, "").unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let cancellation = CancellationToken::new();
        let rule = osiris_detect::Rule::from_yaml_str(SEQUENCE_RULE, "seq.yaml").unwrap();
        let detection_engine = Arc::new(DetectionEngine::new(vec![rule]));
        let (baseline_engine, risk_engine, correlation_engine) = test_engines(dir.path());

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
            detection_engine,
            baseline_engine,
            risk_engine,
            correlation_engine,
            Arc::new(osiris_api::LiveEventBroadcaster::new()),
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()),
            Duration::from_millis(20),
            cancellation.clone(),
        ));

        let host_id = Uuid::new_v4();
        let connect = network_connect_event(host_id, 300, 1_000_000_000);
        let write = file_write_event(host_id, 300, 1_000_000_000 + 5_000_000_000);
        let process_key = connect.process.as_ref().unwrap().process_key;

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&spool_path)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(&connect).unwrap()).unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        writeln!(file, "{}", serde_json::to_string(&write).unwrap()).unwrap();

        tokio::time::sleep(Duration::from_millis(250)).await;
        cancellation.cancel();
        handle.await.unwrap();

        // The sequence rule fired.
        let alerts = storage.query_alerts(&AlertQueryPlan::new()).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "network_download_then_write");

        // The relationships landed as queryable edges.
        let edges = storage
            .query_relationships(&osiris_storage::RelationshipQueryPlan {
                entity: Some(EntityRef::Process { process_key }),
                ..osiris_storage::RelationshipQueryPlan::new()
            })
            .unwrap();
        assert_eq!(edges.len(), 2);

        // A risk score was computed, citing the alert and the chain-pattern
        // bonus.
        let scores = storage
            .query_risk_scores(&osiris_storage::RiskQueryPlan {
                process_key: Some(process_key),
                ..osiris_storage::RiskQueryPlan::new()
            })
            .unwrap();
        assert!(!scores.is_empty());
        let has_chain_bonus = scores.iter().any(|s| {
            s.reasons
                .iter()
                .any(|r| r.label.contains("Network connection"))
        });
        assert!(
            has_chain_bonus,
            "risk score must cite the chain-pattern bonus"
        );
    }
}
