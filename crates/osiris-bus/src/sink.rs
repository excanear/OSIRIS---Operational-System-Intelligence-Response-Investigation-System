use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use osiris_schema::CanonicalEvent;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("failed to write to spool file at {path}: {source}")]
    Write { path: PathBuf, #[source] source: std::io::Error },
    #[error("failed to serialize event: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Where the drain loop (bus.rs) forwards each dequeued event. The Phase 1
/// substitute for the real UDS Agent→Server transport (plan Global
/// Constraints #3) is `SpoolFileSink`; `InMemorySink` exists for tests.
#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, event: CanonicalEvent) -> Result<(), SinkError>;
}

/// Appends each event as one NDJSON line to a local file. The Server binary
/// (Task 8) tails this same path and ingests via `Storage::batch_write` —
/// this is the entire Agent→Server "transport" for Phase 1. A tokio Mutex
/// serializes concurrent `send` calls onto one file handle.
pub struct SpoolFileSink {
    path: PathBuf,
    lock: tokio::sync::Mutex<()>,
}

impl SpoolFileSink {
    /// Creates the spool file if it does not already exist (never
    /// truncates an existing one — the Server may already be tailing it).
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self, SinkError> {
        let path = path.into();
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|source| SinkError::Write { path: path.clone(), source })?;
        Ok(Self { path, lock: tokio::sync::Mutex::new(()) })
    }
}

#[async_trait]
impl Sink for SpoolFileSink {
    async fn send(&self, event: CanonicalEvent) -> Result<(), SinkError> {
        let line = serde_json::to_string(&event)?;
        let _guard = self.lock.lock().await;
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .await
            .map_err(|source| SinkError::Write { path: self.path.clone(), source })?;
        file.write_all(line.as_bytes())
            .await
            .map_err(|source| SinkError::Write { path: self.path.clone(), source })?;
        file.write_all(b"\n")
            .await
            .map_err(|source| SinkError::Write { path: self.path.clone(), source })?;
        Ok(())
    }
}

/// Collects sent events in memory — used by bus.rs's own tests and by any
/// later crate's tests that need to observe what the bus forwarded without
/// touching the filesystem.
#[derive(Clone, Default)]
pub struct InMemorySink {
    events: Arc<Mutex<Vec<CanonicalEvent>>>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<CanonicalEvent> {
        // A poisoned lock still holds a fully-formed Vec of whatever was
        // pushed before the panic — for this test-support struct, reading
        // that is more useful than propagating the poison, so recover
        // rather than unwrap.
        self.events.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait]
impl Sink for InMemorySink {
    async fn send(&self, event: CanonicalEvent) -> Result<(), SinkError> {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use uuid::Uuid;

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(), schema_version: SCHEMA_VERSION.to_string(),
            host_id, boot_id: "b".to_string(), timestamp: 1, monotonic_timestamp: 1,
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
    async fn spool_file_sink_appends_one_ndjson_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let sink = SpoolFileSink::open(&path).await.unwrap();
        sink.send(sample_event()).await.unwrap();
        sink.send(sample_event()).await.unwrap();

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: CanonicalEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.event_type, EventType::ProcessExec);
    }

    #[tokio::test]
    async fn spool_file_sink_does_not_truncate_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        {
            let sink = SpoolFileSink::open(&path).await.unwrap();
            sink.send(sample_event()).await.unwrap();
        }
        {
            let sink = SpoolFileSink::open(&path).await.unwrap();
            sink.send(sample_event()).await.unwrap();
        }
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents.lines().count(), 2);
    }

    #[tokio::test]
    async fn in_memory_sink_collects_events_in_order() {
        let sink = InMemorySink::new();
        sink.send(sample_event()).await.unwrap();
        sink.send(sample_event()).await.unwrap();
        assert_eq!(sink.events().len(), 2);
    }
}
