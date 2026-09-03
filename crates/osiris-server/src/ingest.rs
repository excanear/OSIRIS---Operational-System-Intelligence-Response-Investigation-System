use std::sync::Arc;
use std::time::Duration;

use osiris_schema::CanonicalEvent;
use osiris_storage::Storage;
use tokio_util::sync::CancellationToken;

use crate::tailer::SpoolTailer;

/// Tails the Agent's spool file and ingests each new line into Storage —
/// the Phase 1 substitute for the UDS Agent→Server transport's server-side
/// half (plan Global Constraints #3).
pub async fn run_ingestion_loop(
    spool_path: impl Into<std::path::PathBuf>,
    storage: Arc<dyn Storage>,
    poll_interval: Duration,
    cancellation: CancellationToken,
) {
    let mut tailer = SpoolTailer::new(spool_path);
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
                if !events.is_empty() {
                    let storage = storage.clone();
                    let event_count = events.len();
                    match tokio::task::spawn_blocking(move || storage.batch_write(&events)).await {
                        Ok(Ok(_report)) => {}
                        Ok(Err(storage_err)) => {
                            tracing::error!(
                                error = %storage_err,
                                event_count,
                                "batch_write failed; tailer offset already advanced past these events \
                                 — they are permanently lost"
                            );
                        }
                        Err(join_err) => {
                            tracing::error!(
                                error = %join_err,
                                event_count,
                                "batch_write task panicked or was cancelled; tailer offset already \
                                 advanced past these events — they are permanently lost"
                            );
                        }
                    }
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
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage::QueryPlan;
    use osiris_storage_sqlite::SqliteStorage;
    use std::io::Write;
    use uuid::Uuid;

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

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
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
    async fn skips_malformed_lines_and_ingests_valid_ones() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        std::fs::write(&spool_path, "").unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let cancellation = CancellationToken::new();

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
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
}
