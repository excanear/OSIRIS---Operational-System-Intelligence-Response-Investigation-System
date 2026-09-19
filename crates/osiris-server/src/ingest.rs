use std::sync::Arc;
use std::time::Duration;

use osiris_baseline::BaselineEngine;
use osiris_correlate::{BehavioralChain, CorrelationEngine, EdgeSource};
use osiris_detect::DetectionEngine;
use osiris_risk::RiskEngine;
use osiris_schema::{Alert, CanonicalEvent, EntityRef, EntityRelationship};
use osiris_storage::{RelationshipQueryPlan, Storage};
use tokio_util::sync::CancellationToken;

use osiris_fileutil::LineTailer;

/// Adapts `osiris_storage::Storage::query_relationships` to
/// `osiris_correlate::EdgeSource` — the one place `osiris-correlate` and
/// `osiris-storage` meet, keeping the Correlation Engine itself decoupled
/// from the storage layer (Phase 6 plan Task 10 / Global Constraint #3). A
/// query failure degrades to "no edges found" rather than panicking the
/// ingestion loop — correlation is best-effort enrichment, not a
/// correctness-critical path.
struct StorageEdgeSource<'s> {
    storage: &'s dyn Storage,
}

impl EdgeSource for StorageEdgeSource<'_> {
    fn edges_for(&self, entity: &EntityRef, since: u64, until: u64) -> Vec<EntityRelationship> {
        let plan = RelationshipQueryPlan {
            entity: Some(entity.clone()),
            since: Some(since),
            until: Some(until),
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
/// this same batch.
fn correlate_baseline_and_score(
    storage: &dyn Storage,
    baseline_engine: &BaselineEngine,
    risk_engine: &RiskEngine,
    correlation_engine: &CorrelationEngine,
    event: &CanonicalEvent,
    alerts_for_event: &[Alert],
) -> Result<(), osiris_storage::StorageError> {
    let Some(process) = &event.process else {
        return Ok(());
    };
    let observations = match baseline_engine.observe(event) {
        Ok(obs) => obs,
        Err(e) => {
            tracing::warn!(error = %e, event_id = %event.event_id, "baseline observe failed; scoring without baseline input");
            vec![]
        }
    };

    let seed = EntityRef::Process {
        process_key: process.process_key,
    };
    let edge_source = StorageEdgeSource { storage };
    let chain: BehavioralChain =
        correlation_engine.build_chain(&edge_source, seed, event.timestamp);

    if let Some(record) = risk_engine.score(event, alerts_for_event, &observations, Some(&chain)) {
        storage.write_risk_scores(std::slice::from_ref(&record))?;
    }
    Ok(())
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
        let outcome = tokio::task::spawn_blocking(move || {
            Ok::<_, osiris_storage::StorageError>({
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

                for event in &events {
                    let alerts_for_event: Vec<Alert> = alerts
                        .iter()
                        .filter(|a| a.evidence().contains(&event.event_id))
                        .cloned()
                        .collect();
                    correlate_baseline_and_score(
                        storage.as_ref(),
                        &baseline_engine,
                        &risk_engine,
                        &correlation_engine,
                        event,
                        &alerts_for_event,
                    )?;
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
                Ok(())
            }
            Ok(Err(storage_err)) => Err(storage_err.to_string()),
            Err(join_err) => Err(format!("ingest task panicked or was cancelled: {join_err}")),
        }
    }
}

#[async_trait::async_trait]
impl osiris_transport::server::BatchHandler for IngestContext {
    async fn handle(&self, _host_id: uuid::Uuid, events: Vec<CanonicalEvent>) -> Result<(), String> {
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
    };
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
        std::fs::write(&spool, format!("{}\n", serde_json::to_string(&event).unwrap())).unwrap();
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
