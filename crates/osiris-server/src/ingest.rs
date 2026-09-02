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
        if let Ok(lines) = tailer.poll() {
            let events: Vec<CanonicalEvent> =
                lines.iter().filter_map(|line| serde_json::from_str(line).ok()).collect();
            if !events.is_empty() {
                let storage = storage.clone();
                let _ = tokio::task::spawn_blocking(move || storage.batch_write(&events)).await;
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
            event_id: Uuid::now_v7(), schema_version: SCHEMA_VERSION.to_string(),
            host_id, boot_id: "b".to_string(), timestamp: 1000, monotonic_timestamp: 1000,
            event_type: EventType::ProcessExec, category: Category::Process, severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None,
            file: None, network: None, dns: None, device: None, service: None, container: None,
            namespace: None, cgroup: None, kernel: None, source: Source::Synthetic,
            provider: "test".to_string(), raw_event: None, relationships: vec![], tags: vec![],
            risk: None, event_data: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn ingests_spooled_events_into_storage() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        std::fs::write(&spool_path, "").unwrap();
        let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let cancellation = CancellationToken::new();

        let handle = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
            Duration::from_millis(20),
            cancellation.clone(),
        ));

        let mut file = std::fs::OpenOptions::new().append(true).open(&spool_path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&sample_event()).unwrap()).unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        cancellation.cancel();
        handle.await.unwrap();

        let results = storage.query(&QueryPlan::new()).unwrap();
        assert_eq!(results.len(), 1);
    }
}
