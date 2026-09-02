use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use osiris_schema::{CanonicalEvent, EventType};
use osiris_storage::{QueryPlan, Storage};
use serde::{Deserialize, Serialize};

/// The Phase 1 API surface (ARCHITECTURE.md §14.2, narrowed to `/events`,
/// `/processes`, `/health` per the Phase 1 roadmap line). "Timeline" and
/// "Process Tree" from that line are satisfied by `/events`'s time-range
/// filters and `/processes/{process_key}`'s children list respectively —
/// plan Global Constraints #9, not separate engines/endpoints.
pub fn build_router(storage: Arc<dyn Storage>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/events", get(events_handler))
        .route("/api/v1/processes", get(processes_handler))
        .route("/api/v1/processes/:process_key", get(process_detail_handler))
        .with_state(storage)
}

#[derive(Debug, Serialize)]
struct ApiHealth {
    healthy: bool,
    event_count: u64,
    last_write_at: Option<u64>,
}

async fn health_handler(State(storage): State<Arc<dyn Storage>>) -> Json<ApiHealth> {
    let health = tokio::task::spawn_blocking(move || storage.health()).await.unwrap();
    Json(ApiHealth {
        healthy: health.healthy,
        event_count: health.event_count,
        last_write_at: health.last_write_at,
    })
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    event_type: Option<String>,
    since: Option<u64>,
    until: Option<u64>,
    limit: Option<usize>,
}

async fn events_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<CanonicalEvent>>, (StatusCode, String)> {
    let mut plan = QueryPlan::new();
    if let Some(et) = &q.event_type {
        let parsed: EventType = serde_json::from_str(&format!("\"{}\"", et))
            .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid event_type: {}", et)))?;
        plan.event_type = Some(parsed);
    }
    plan.since = q.since;
    plan.until = q.until;
    if let Some(limit) = q.limit {
        plan.limit = limit;
    }
    let events = tokio::task::spawn_blocking(move || storage.query(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(events))
}

#[derive(Debug, Serialize)]
struct ProcessSummary {
    process_key: String,
    pid: u32,
    exe_path: String,
    timestamp: u64,
}

async fn processes_handler(
    State(storage): State<Arc<dyn Storage>>,
) -> Result<Json<Vec<ProcessSummary>>, (StatusCode, String)> {
    let mut plan = QueryPlan::new();
    plan.event_type = Some(EventType::ProcessExec);
    plan.limit = 1000;
    let events = tokio::task::spawn_blocking(move || storage.query(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<String, ProcessSummary> = HashMap::new();
    for event in events {
        if let Some(process) = &event.process {
            let key = process.process_key.as_hex();
            seen.entry(key.clone()).or_insert_with(|| ProcessSummary {
                process_key: key,
                pid: process.pid,
                exe_path: process.exe_path.clone(),
                timestamp: event.timestamp,
            });
        }
    }
    Ok(Json(seen.into_values().collect()))
}

#[derive(Debug, Serialize)]
struct ProcessDetail {
    process: CanonicalEvent,
    children: Vec<CanonicalEvent>,
}

async fn process_detail_handler(
    State(storage): State<Arc<dyn Storage>>,
    Path(process_key_hex): Path<String>,
) -> Result<Json<ProcessDetail>, (StatusCode, String)> {
    let mut plan = QueryPlan::new();
    plan.event_type = Some(EventType::ProcessExec);
    plan.limit = 10_000;
    let events = tokio::task::spawn_blocking(move || storage.query(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let process = events
        .iter()
        .find(|e| e.process.as_ref().map(|p| p.process_key.as_hex()) == Some(process_key_hex.clone()))
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, format!("process {} not found", process_key_hex)))?;

    let children: Vec<CanonicalEvent> = events
        .into_iter()
        .filter(|e| {
            e.parent_process.as_ref().map(|p| p.process_key.as_hex()) == Some(process_key_hex.clone())
        })
        .collect();

    Ok(Json(ProcessDetail { process, children }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn sample_event(pid: u32, parent_key: Option<ProcessKey>, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(), schema_version: SCHEMA_VERSION.to_string(),
            host_id, boot_id: "b".to_string(), timestamp, monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec, category: Category::Process, severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", pid, timestamp),
                pid, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: timestamp,
            }),
            parent_process: parent_key.map(|k| ProcessRef {
                process_key: k, pid: 0, exe_path: String::new(), cmdline: vec![], exe_hash: None, start_time_mono: 0,
            }),
            thread: None, file: None, network: None, dns: None, device: None,
            service: None, container: None, namespace: None, cgroup: None, kernel: None,
            source: Source::Synthetic, provider: "test".to_string(), raw_event: None,
            relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    fn test_storage() -> (tempfile::TempDir, Arc<dyn Storage>) {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        (dir, Arc::new(storage))
    }

    #[tokio::test]
    async fn health_reports_event_count() {
        let (_dir, storage) = test_storage();
        storage.write(&sample_event(100, None, 1000)).unwrap();
        let Json(health) = health_handler(State(storage)).await;
        assert!(health.healthy);
        assert_eq!(health.event_count, 1);
    }

    #[tokio::test]
    async fn events_endpoint_filters_by_time_range() {
        let (_dir, storage) = test_storage();
        storage.batch_write(&[sample_event(100, None, 1000), sample_event(200, None, 9000)]).unwrap();
        let query = EventsQuery { event_type: None, since: Some(500), until: Some(5000), limit: None };
        let Json(events) = events_handler(State(storage), Query(query)).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.as_ref().unwrap().pid, 100);
    }

    #[tokio::test]
    async fn processes_endpoint_deduplicates_by_process_key() {
        let (_dir, storage) = test_storage();
        storage.write(&sample_event(100, None, 1000)).unwrap();
        let Json(processes) = processes_handler(State(storage)).await.unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 100);
    }

    #[tokio::test]
    async fn process_detail_returns_process_and_its_children() {
        let (_dir, storage) = test_storage();
        let parent = sample_event(100, None, 1000);
        let parent_key = parent.process.as_ref().unwrap().process_key;
        let child = sample_event(200, Some(parent_key), 2000);
        storage.batch_write(&[parent, child]).unwrap();

        let Json(detail) = process_detail_handler(State(storage), Path(parent_key.as_hex()))
            .await
            .unwrap();
        assert_eq!(detail.process.process.unwrap().pid, 100);
        assert_eq!(detail.children.len(), 1);
        assert_eq!(detail.children[0].process.as_ref().unwrap().pid, 200);
    }

    #[tokio::test]
    async fn process_detail_returns_404_for_unknown_key() {
        let (_dir, storage) = test_storage();
        let host_id = Uuid::new_v4();
        let unknown_key = ProcessKey::new(host_id, "b", 999, 999);
        let result = process_detail_handler(State(storage), Path(unknown_key.as_hex())).await;
        assert!(result.is_err());
    }
}
