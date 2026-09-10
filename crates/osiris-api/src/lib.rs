use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use osiris_schema::{Alert, CanonicalEvent, EventType, FileIdentity};
use osiris_storage::{AlertQueryPlan, QueryPlan, Storage};
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
        .route(
            "/api/v1/processes/:process_key",
            get(process_detail_handler),
        )
        .route("/api/v1/alerts", get(alerts_handler))
        .route("/api/v1/files/story", get(file_story_handler))
        .route("/api/v1/network/story", get(network_story_handler))
        .route("/api/v1/identity/story", get(identity_story_handler))
        .route("/api/v1/systemd/story", get(systemd_story_handler))
        .route("/api/v1/containers/story", get(container_story_handler))
        .with_state(storage)
}

#[derive(Debug, Serialize)]
struct ApiHealth {
    healthy: bool,
    event_count: u64,
    last_write_at: Option<u64>,
}

async fn health_handler(State(storage): State<Arc<dyn Storage>>) -> Json<ApiHealth> {
    let health = tokio::task::spawn_blocking(move || storage.health())
        .await
        .unwrap();
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
        let parsed: EventType = serde_json::from_str(&format!("\"{}\"", et)).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid event_type: {}", et),
            )
        })?;
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
        .find(|e| {
            e.process.as_ref().map(|p| p.process_key.as_hex()) == Some(process_key_hex.clone())
        })
        .cloned()
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("process {} not found", process_key_hex),
        ))?;

    let children: Vec<CanonicalEvent> = events
        .into_iter()
        .filter(|e| {
            e.parent_process.as_ref().map(|p| p.process_key.as_hex())
                == Some(process_key_hex.clone())
        })
        .collect();

    Ok(Json(ProcessDetail { process, children }))
}

#[derive(Debug, Deserialize)]
struct AlertsQuery {
    rule_id: Option<String>,
    since: Option<u64>,
    until: Option<u64>,
    limit: Option<usize>,
}

async fn alerts_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<AlertsQuery>,
) -> Result<Json<Vec<Alert>>, (StatusCode, String)> {
    let mut plan = AlertQueryPlan::new();
    plan.rule_id = q.rule_id;
    plan.since = q.since;
    plan.until = q.until;
    if let Some(limit) = q.limit {
        plan.limit = limit;
    }
    let alerts = tokio::task::spawn_blocking(move || storage.query_alerts(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(alerts))
}

#[derive(Debug, Deserialize)]
struct FileStoryQuery {
    path: Option<String>,
    file_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct FileStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

async fn file_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<FileStoryQuery>,
) -> Result<Json<FileStory>, (StatusCode, String)> {
    if q.path.is_none() && q.file_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide path or file_id".to_string(),
        ));
    }

    if let Some(file_id) = &q.file_id {
        if FileIdentity::parse_key(file_id).is_none() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid file_id: {}", file_id),
            ));
        }
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();
        let mut identities: HashSet<FileIdentity> = HashSet::new();

        if let Some(file_id) = &q.file_id {
            if let Some(identity) = FileIdentity::parse_key(file_id) {
                identities.insert(identity);
            }
        }

        if let Some(path) = &q.path {
            let mut plan = QueryPlan::new();
            plan.file_path = Some(path.clone());
            plan.limit = 10_000;
            let path_events = storage.query(&plan)?;
            for e in &path_events {
                if let Some(file) = &e.file {
                    if let Some(id) = FileIdentity::from_file_ref(file) {
                        identities.insert(id);
                    }
                }
            }
            for e in path_events {
                events_by_id.insert(e.event_id, e);
            }
        }

        for identity in &identities {
            let mut plan = QueryPlan::new();
            plan.file_identity = Some(*identity);
            plan.limit = 10_000;
            for e in storage.query(&plan)? {
                events_by_id.insert(e.event_id, e);
            }
        }

        let mut events: Vec<CanonicalEvent> = events_by_id.into_values().collect();
        events.sort_by_key(|a| (a.timestamp, a.event_id));

        let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
        let alerts = if evidence_ids.is_empty() {
            vec![]
        } else {
            let mut alert_plan = AlertQueryPlan::new();
            alert_plan.evidence_event_ids = evidence_ids;
            alert_plan.limit = 10_000;
            storage.query_alerts(&alert_plan)?
        };

        Ok::<_, osiris_storage::StorageError>((events, alerts))
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(FileStory { events, alerts }))
}

#[derive(Debug, Deserialize)]
struct NetworkStoryQuery {
    ip: Option<String>,
    domain: Option<String>,
}

#[derive(Debug, Serialize)]
struct NetworkStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

/// Composed query implementing Phase 3 plan Global Constraints #9: the
/// domain form resolves DNS events for that domain, unions in every network
/// event touching any of their resolved addresses; the IP form matches
/// network events directly and does not reverse-resolve to the DNS side —
/// a deliberate, disclosed asymmetry (see the constraint's full reasoning).
async fn network_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<NetworkStoryQuery>,
) -> Result<Json<NetworkStory>, (StatusCode, String)> {
    if q.ip.is_none() && q.domain.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide ip or domain".to_string(),
        ));
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();

        if let Some(domain) = &q.domain {
            let mut plan = QueryPlan::new();
            plan.dns_domain = Some(domain.clone());
            plan.limit = 10_000;
            let dns_events = storage.query(&plan)?;

            let mut resolved_ips: HashSet<String> = HashSet::new();
            for e in &dns_events {
                if let Some(dns) = &e.dns {
                    resolved_ips.extend(dns.response_ips.iter().cloned());
                }
            }
            for e in dns_events {
                events_by_id.insert(e.event_id, e);
            }
            for ip in &resolved_ips {
                let mut plan = QueryPlan::new();
                plan.network_addr = Some(ip.clone());
                plan.limit = 10_000;
                for e in storage.query(&plan)? {
                    events_by_id.insert(e.event_id, e);
                }
            }
        }

        if let Some(ip) = &q.ip {
            let mut plan = QueryPlan::new();
            plan.network_addr = Some(ip.clone());
            plan.limit = 10_000;
            for e in storage.query(&plan)? {
                events_by_id.insert(e.event_id, e);
            }
        }

        let mut events: Vec<CanonicalEvent> = events_by_id.into_values().collect();
        events.sort_by_key(|a| (a.timestamp, a.event_id));

        let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
        let alerts = if evidence_ids.is_empty() {
            vec![]
        } else {
            let mut alert_plan = AlertQueryPlan::new();
            alert_plan.evidence_event_ids = evidence_ids;
            alert_plan.limit = 10_000;
            storage.query_alerts(&alert_plan)?
        };

        Ok::<_, osiris_storage::StorageError>((events, alerts))
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(NetworkStory { events, alerts }))
}

#[derive(Debug, Deserialize)]
struct IdentityStoryQuery {
    session_id: Option<String>,
    uid: Option<u32>,
}

#[derive(Debug, Serialize)]
struct IdentityStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

/// Composed query implementing Phase 4a plan Global Constraint #10, and
/// ARCHITECTURE.md §12.1's `*_story` shape — the same `{ events, alerts }`
/// response `FileStory` and `NetworkStory` already return, so one Console
/// renderer serves all three.
///
/// The two lookup forms are deliberately asymmetric:
///
/// * **`session_id`** returns every stored event carrying that session.
///   Because the Enrich stage attaches the session to every descendant of
///   the login (plan Global Constraint #5), that single filter returns the
///   genuinely multi-category chain §29's Phase 4 line calls for —
///   identity, process, privilege, file and network together — without any
///   graph walk. No Correlation Engine is involved; this is one indexed
///   column (plan Global Constraint #12).
/// * **`uid`** returns every stored event whose acting user is that uid. It
///   does NOT expand to "and everything in every session that user opened":
///   that second-pass fan-out is unbounded for a long-lived service
///   account, and §12.3's planner that could express it cheaply is Phase 7.
///   Every returned event carries its own session id, so the analyst who
///   wants the session view takes that one extra step deliberately.
///
/// Both may be given at once, in which case they intersect (they are two
/// `AND` clauses of one `QueryPlan`), which is what the single query below
/// gives for free.
async fn identity_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<IdentityStoryQuery>,
) -> Result<Json<IdentityStory>, (StatusCode, String)> {
    if q.session_id.is_none() && q.uid.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide session_id or uid".to_string(),
        ));
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        // Unlike the File and Network stories, this needs no union across
        // several queries: one indexed filter already selects the whole
        // chain, so there is no de-duplication step to perform and the
        // storage layer's own ORDER BY timestamp is the ordering.
        let mut plan = QueryPlan::new();
        plan.session_id = q.session_id.clone();
        plan.user_uid = q.uid;
        plan.limit = 10_000;
        let mut events = storage.query(&plan)?;
        // Storage already orders by timestamp; the secondary event_id key
        // makes the order total for same-timestamp events, matching the
        // File and Network stories exactly.
        events.sort_by_key(|e| (e.timestamp, e.event_id));

        let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
        let alerts = if evidence_ids.is_empty() {
            vec![]
        } else {
            let mut alert_plan = AlertQueryPlan::new();
            alert_plan.evidence_event_ids = evidence_ids;
            alert_plan.limit = 10_000;
            storage.query_alerts(&alert_plan)?
        };

        Ok::<_, osiris_storage::StorageError>((events, alerts))
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(IdentityStory { events, alerts }))
}

#[derive(Debug, Deserialize)]
struct SystemdStoryQuery {
    unit_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct SystemdStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

/// Composed query implementing this phase's Global Constraint #12 and
/// ARCHITECTURE.md §12.1's `*_story` shape. One `unit_name` filter returns
/// a unit's whole observed history regardless of which sensor produced
/// which part of it — Task 4's Normalize populates `service.unit_name`
/// identically for the audit-backed Systemd sensor's `SERVICE_START`/`STOP`
/// events and for Persistence Monitor's unit-*file*-lifecycle events
/// (`SERVICE_CREATE`/`MODIFY`/`DELETE`, `TIMER_CREATE`/`MODIFY`), so this
/// one indexed column already spans both without a union query.
async fn systemd_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<SystemdStoryQuery>,
) -> Result<Json<SystemdStory>, (StatusCode, String)> {
    if q.unit_name.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide unit_name".to_string(),
        ));
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        let mut plan = QueryPlan::new();
        plan.unit_name = q.unit_name.clone();
        plan.limit = 10_000;
        let mut events = storage.query(&plan)?;
        events.sort_by_key(|e| (e.timestamp, e.event_id));

        let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
        let alerts = if evidence_ids.is_empty() {
            vec![]
        } else {
            let mut alert_plan = AlertQueryPlan::new();
            alert_plan.evidence_event_ids = evidence_ids;
            alert_plan.limit = 10_000;
            storage.query_alerts(&alert_plan)?
        };

        Ok::<_, osiris_storage::StorageError>((events, alerts))
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(SystemdStory { events, alerts }))
}

#[derive(Debug, Deserialize)]
struct ContainerStoryQuery {
    container_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ContainerStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

/// Composed query implementing this phase's plan Task 10 and
/// ARCHITECTURE.md §12.1's `*_story` shape. One `container_id` filter
/// returns a container's whole observed history regardless of which
/// mechanism produced which part of it — Task 2's Normalize populates
/// `container.container_id` on the Container sensor's own lifecycle
/// events, and Task 4's `NsCgroupResolver` populates it identically on
/// every other category's events for a containerized process, so this one
/// indexed column already spans both without a union query (the same
/// "one indexed column already spans both" reasoning `systemd_story`
/// established in Phase 4b).
async fn container_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<ContainerStoryQuery>,
) -> Result<Json<ContainerStory>, (StatusCode, String)> {
    if q.container_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide container_id".to_string(),
        ));
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        let mut plan = QueryPlan::new();
        plan.container_id = q.container_id.clone();
        plan.limit = 10_000;
        let mut events = storage.query(&plan)?;
        events.sort_by_key(|e| (e.timestamp, e.event_id));

        let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
        let alerts = if evidence_ids.is_empty() {
            vec![]
        } else {
            let mut alert_plan = AlertQueryPlan::new();
            alert_plan.evidence_event_ids = evidence_ids;
            alert_plan.limit = 10_000;
            storage.query_alerts(&alert_plan)?
        };

        Ok::<_, osiris_storage::StorageError>((events, alerts))
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ContainerStory { events, alerts }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        encode_device_id, Category, FileRef, HostRef, ProcessKey, ProcessRef, Severity, Source,
        SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn sample_event(pid: u32, parent_key: Option<ProcessKey>, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
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
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", pid, timestamp),
                pid,
                exe_path: "/bin/x".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: timestamp,
            }),
            parent_process: parent_key.map(|k| ProcessRef {
                process_key: k,
                pid: 0,
                exe_path: String::new(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 0,
            }),
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

    #[allow(clippy::too_many_arguments)]
    fn file_event(
        event_type: EventType,
        path: &str,
        inode: u64,
        device_id: u64,
        timestamp: u64,
    ) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
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
            process: None,
            parent_process: None,
            thread: None,
            file: Some(FileRef {
                path: path.to_string(),
                previous_path: None,
                inode: Some(inode),
                device_id: Some(device_id),
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

    fn sample_alert(rule_id: &str, evidence: Vec<Uuid>, timestamp: u64) -> Alert {
        Alert::new(
            rule_id,
            1,
            "0".repeat(64),
            Severity::High,
            timestamp,
            Uuid::new_v4(),
            vec!["because".to_string()],
            evidence,
        )
        .unwrap()
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
        storage
            .batch_write(&[sample_event(100, None, 1000), sample_event(200, None, 9000)])
            .unwrap();
        let query = EventsQuery {
            event_type: None,
            since: Some(500),
            until: Some(5000),
            limit: None,
        };
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

    #[tokio::test]
    async fn alerts_endpoint_returns_persisted_alerts() {
        let (_dir, storage) = test_storage();
        let alert = sample_alert("rule_a", vec![Uuid::now_v7()], 1000);
        storage.write_alerts(&[alert]).unwrap();

        let Json(alerts) = alerts_handler(
            State(storage),
            Query(AlertsQuery {
                rule_id: None,
                since: None,
                until: None,
                limit: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "rule_a");
    }

    #[tokio::test]
    async fn alerts_endpoint_filters_by_rule_id() {
        let (_dir, storage) = test_storage();
        storage
            .write_alerts(&[
                sample_alert("rule_a", vec![Uuid::now_v7()], 1000),
                sample_alert("rule_b", vec![Uuid::now_v7()], 2000),
            ])
            .unwrap();

        let Json(alerts) = alerts_handler(
            State(storage),
            Query(AlertsQuery {
                rule_id: Some("rule_a".to_string()),
                since: None,
                until: None,
                limit: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "rule_a");
    }

    #[tokio::test]
    async fn file_story_returns_400_when_neither_param_given() {
        let (_dir, storage) = test_storage();
        let result = file_story_handler(
            State(storage),
            Query(FileStoryQuery {
                path: None,
                file_id: None,
            }),
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn file_story_returns_400_when_file_id_is_malformed() {
        let (_dir, storage) = test_storage();
        let result = file_story_handler(
            State(storage),
            Query(FileStoryQuery {
                path: None,
                file_id: Some("not-a-valid-key".to_string()),
            }),
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("invalid file_id"));
    }

    #[tokio::test]
    async fn file_story_by_path_returns_events_and_citing_alerts() {
        let (_dir, storage) = test_storage();
        let device_id = encode_device_id(8, 1);
        let e1 = file_event(EventType::FileCreate, "/var/www/html/a.php", 1, device_id, 1000);
        let e2 = file_event(EventType::FileWrite, "/var/www/html/a.php", 1, device_id, 2000);
        let unrelated = sample_event(999, None, 500); // process event, must not appear
        storage
            .batch_write(&[e1.clone(), e2.clone(), unrelated])
            .unwrap();

        let alert = sample_alert("rule_a", vec![e1.event_id], 1000);
        storage.write_alerts(&[alert]).unwrap();

        let Json(story) = file_story_handler(
            State(storage),
            Query(FileStoryQuery {
                path: Some("/var/www/html/a.php".to_string()),
                file_id: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 2);
        assert_eq!(story.events[0].event_id, e1.event_id);
        assert_eq!(story.events[1].event_id, e2.event_id);
        assert_eq!(story.alerts.len(), 1);
        assert_eq!(story.alerts[0].rule_id(), "rule_a");
    }

    #[tokio::test]
    async fn file_story_by_path_follows_a_rename_via_identity() {
        let (_dir, storage) = test_storage();
        let device_id = encode_device_id(8, 1);
        let created = file_event(EventType::FileCreate, "/tmp/a.txt", 42, device_id, 1000);
        let renamed = file_event(EventType::FileRename, "/tmp/b.txt", 42, device_id, 2000);
        storage
            .batch_write(&[created.clone(), renamed.clone()])
            .unwrap();

        let Json(story) = file_story_handler(
            State(storage),
            Query(FileStoryQuery {
                path: Some("/tmp/a.txt".to_string()),
                file_id: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 2);
        let ids: Vec<Uuid> = story.events.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&created.event_id));
        assert!(ids.contains(&renamed.event_id));
    }

    #[tokio::test]
    async fn file_story_by_file_id_works_without_a_path() {
        let (_dir, storage) = test_storage();
        let device_id = encode_device_id(8, 1);
        let created = file_event(EventType::FileCreate, "/tmp/a.txt", 42, device_id, 1000);
        let renamed = file_event(EventType::FileRename, "/tmp/b.txt", 42, device_id, 2000);
        storage
            .batch_write(&[created.clone(), renamed.clone()])
            .unwrap();

        let identity = FileIdentity::new(42, device_id);
        let Json(story) = file_story_handler(
            State(storage),
            Query(FileStoryQuery {
                path: None,
                file_id: Some(identity.as_key()),
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 2);
        let ids: Vec<Uuid> = story.events.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&created.event_id));
        assert!(ids.contains(&renamed.event_id));
    }

    fn network_event(
        event_type: EventType,
        src_ip: &str,
        dst_ip: &str,
        timestamp: u64,
    ) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: Category::Network,
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
            network: Some(osiris_schema::NetworkRef {
                src_ip: src_ip.to_string(),
                src_port: 51000,
                dst_ip: dst_ip.to_string(),
                dst_port: 443,
                proto: "tcp".to_string(),
                direction: osiris_schema::NetworkDirection::Outbound,
                bytes: None,
            }),
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

    fn dns_event(query: &str, response_ips: Vec<String>, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::DnsQuery,
            category: Category::Dns,
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
            dns: Some(osiris_schema::DnsRef {
                query: query.to_string(),
                qtype: "A".to_string(),
                response_ips,
                ttl: Some(300),
            }),
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
    async fn network_story_returns_400_when_neither_param_given() {
        let (_dir, storage) = test_storage();
        let result = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery { ip: None, domain: None }),
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn network_story_by_ip_returns_matching_events_and_citing_alerts() {
        let (_dir, storage) = test_storage();
        let connect = network_event(EventType::NetworkConnect, "10.0.0.5", "203.0.113.50", 1000);
        let close = network_event(EventType::NetworkClose, "10.0.0.5", "203.0.113.50", 2000);
        let unrelated = network_event(EventType::NetworkConnect, "10.0.0.7", "198.51.100.1", 500);
        storage
            .batch_write(&[connect.clone(), close.clone(), unrelated])
            .unwrap();
        let alert = sample_alert("dns_query_to_suspicious_tld", vec![connect.event_id], 1000);
        storage.write_alerts(&[alert]).unwrap();

        let Json(story) = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery {
                ip: Some("203.0.113.50".to_string()),
                domain: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 2);
        assert_eq!(story.events[0].event_id, connect.event_id);
        assert_eq!(story.events[1].event_id, close.event_id);
        assert_eq!(story.alerts.len(), 1);
    }

    #[tokio::test]
    async fn network_story_by_domain_follows_the_resolved_ip_to_its_connections() {
        let (_dir, storage) = test_storage();
        let dns = dns_event("cdn-assets.xyz", vec!["203.0.113.50".to_string()], 1000);
        let connect = network_event(EventType::NetworkConnect, "10.0.0.5", "203.0.113.50", 2000);
        let unrelated_dns = dns_event("example.com", vec!["93.184.216.34".to_string()], 500);
        storage
            .batch_write(&[dns.clone(), connect.clone(), unrelated_dns])
            .unwrap();

        let Json(story) = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery {
                ip: None,
                domain: Some("cdn-assets.xyz".to_string()),
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 2);
        let ids: Vec<Uuid> = story.events.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&dns.event_id));
        assert!(ids.contains(&connect.event_id));
    }

    /// Global Constraint #9's disclosed asymmetry: querying by IP alone
    /// does not reverse-resolve to the DNS event that produced it.
    #[tokio::test]
    async fn network_story_by_ip_alone_does_not_include_the_resolving_dns_event() {
        let (_dir, storage) = test_storage();
        let dns = dns_event("cdn-assets.xyz", vec!["203.0.113.50".to_string()], 1000);
        let connect = network_event(EventType::NetworkConnect, "10.0.0.5", "203.0.113.50", 2000);
        storage.batch_write(&[dns, connect.clone()]).unwrap();

        let Json(story) = network_story_handler(
            State(storage),
            Query(NetworkStoryQuery {
                ip: Some("203.0.113.50".to_string()),
                domain: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].event_id, connect.event_id);
    }

    fn session_event(
        event_type: EventType,
        session_id: &str,
        uid: u32,
        remote_addr: Option<&str>,
        timestamp: u64,
    ) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: event_type.category(),
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: Some(osiris_schema::UserRef {
                uid,
                gid: uid,
                euid: uid,
                egid: uid,
                username: Some("alice".to_string()),
                loginuid: Some(1000),
            }),
            session: Some(osiris_schema::SessionRef {
                session_id: session_id.to_string(),
                tty: Some("/dev/pts/0".to_string()),
                remote_addr: remote_addr.map(str::to_string),
                auth_method: Some("sshd".to_string()),
            }),
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", 300, timestamp),
                pid: 300,
                exe_path: "/usr/bin/sudo".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: timestamp,
            }),
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
    async fn identity_story_returns_400_when_neither_param_given() {
        let (_dir, storage) = test_storage();
        let result = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: None,
                uid: None,
            }),
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    /// Global Constraint #10's session form: because Enrich attaches the
    /// session to every descendant event, one session id returns the whole
    /// multi-category chain, time-ordered, plus every citing alert.
    #[tokio::test]
    async fn identity_story_by_session_returns_the_whole_multi_category_chain() {
        let (_dir, storage) = test_storage();
        let login = session_event(EventType::SessionLogin, "3", 0, Some("198.51.100.10"), 1000);
        let exec = session_event(EventType::ProcessExec, "3", 1000, Some("198.51.100.10"), 2000);
        let escalation = session_event(
            EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            3000,
        );
        let other_session = session_event(EventType::SessionLogin, "4", 0, None, 4000);
        storage
            .batch_write(&[
                login.clone(),
                exec.clone(),
                escalation.clone(),
                other_session,
            ])
            .unwrap();
        storage
            .write_alerts(&[sample_alert(
                "privilege_escalation_to_root_in_remote_session",
                vec![escalation.event_id],
                3000,
            )])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: Some("3".to_string()),
                uid: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 3);
        assert_eq!(story.events[0].event_id, login.event_id);
        assert_eq!(story.events[1].event_id, exec.event_id);
        assert_eq!(story.events[2].event_id, escalation.event_id);
        let categories: Vec<Category> = story.events.iter().map(|e| e.category).collect();
        assert!(categories.contains(&Category::Identity));
        assert!(categories.contains(&Category::Process));
        assert!(categories.contains(&Category::Privilege));
        assert_eq!(story.alerts.len(), 1);
    }

    #[tokio::test]
    async fn identity_story_by_uid_returns_that_users_events_and_citing_alerts() {
        let (_dir, storage) = test_storage();
        let root_event = session_event(
            EventType::PrivilegeUidChange,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let alice_event = session_event(
            EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            2000,
        );
        storage
            .batch_write(&[root_event.clone(), alice_event])
            .unwrap();
        storage
            .write_alerts(&[sample_alert("some_rule", vec![root_event.event_id], 1000)])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: None,
                uid: Some(0),
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].event_id, root_event.event_id);
        assert_eq!(story.alerts.len(), 1);
    }

    /// Global Constraint #10's disclosed asymmetry: the uid form does NOT
    /// fan out to every event of every session that user opened. The
    /// analyst who wants that starts from the session id, which every
    /// returned event carries.
    #[tokio::test]
    async fn identity_story_by_uid_does_not_expand_to_the_whole_session() {
        let (_dir, storage) = test_storage();
        // uid 0 logged in; a uid-1000 process then ran in that same session.
        let login_as_root = session_event(
            EventType::SessionLogin,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let alice_exec =
            session_event(EventType::ProcessExec, "3", 1000, Some("198.51.100.10"), 2000);
        storage
            .batch_write(&[login_as_root.clone(), alice_exec])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: None,
                uid: Some(0),
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            story.events.len(),
            1,
            "the uid form must not fan out into the session's other events"
        );
        assert_eq!(story.events[0].event_id, login_as_root.event_id);
        // ...and the session id is right there on it, so the analyst can
        // take the next step themselves.
        assert_eq!(
            story.events[0].session.as_ref().unwrap().session_id,
            "3"
        );
    }

    /// Both forms together intersect rather than union — the same
    /// composition rule every other filter pair in QueryPlan follows.
    #[tokio::test]
    async fn identity_story_with_both_params_intersects_them() {
        let (_dir, storage) = test_storage();
        let alice_in_3 = session_event(EventType::ProcessExec, "3", 1000, None, 1000);
        let root_in_3 = session_event(EventType::ProcessExec, "3", 0, None, 2000);
        let alice_in_4 = session_event(EventType::ProcessExec, "4", 1000, None, 3000);
        storage
            .batch_write(&[alice_in_3.clone(), root_in_3, alice_in_4])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: Some("3".to_string()),
                uid: Some(1000),
            }),
        )
        .await
        .unwrap();
        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].event_id, alice_in_3.event_id);
    }

    #[tokio::test]
    async fn identity_story_returns_an_empty_story_rather_than_404_for_an_unknown_session() {
        let (_dir, storage) = test_storage();
        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: Some("does-not-exist".to_string()),
                uid: None,
            }),
        )
        .await
        .unwrap();
        assert!(story.events.is_empty());
        assert!(story.alerts.is_empty());
    }

    fn systemd_event(unit_name: &str, event_type: EventType, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(700, None, timestamp);
        event.category = Category::Systemd;
        event.event_type = event_type;
        event.service = Some(osiris_schema::ServiceRef {
            unit_name: unit_name.to_string(),
            unit_type: "service".to_string(),
            action: "start".to_string(),
        });
        event
    }

    #[tokio::test]
    async fn systemd_story_returns_400_when_unit_name_is_missing() {
        let (_dir, storage) = test_storage();
        let result = systemd_story_handler(State(storage), Query(SystemdStoryQuery { unit_name: None }))
            .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn systemd_story_returns_every_event_for_the_named_unit() {
        let (_dir, storage) = test_storage();
        let start = systemd_event("backdoor.service", EventType::ServiceStart, 1000);
        let stop = systemd_event("backdoor.service", EventType::ServiceStop, 2000);
        let other_unit = systemd_event("sshd.service", EventType::ServiceStart, 3000);
        storage
            .batch_write(&[start.clone(), stop.clone(), other_unit])
            .unwrap();

        let Json(story) = systemd_story_handler(
            State(storage),
            Query(SystemdStoryQuery {
                unit_name: Some("backdoor.service".to_string()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(story.events.len(), 2);
        let ids: Vec<_> = story.events.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&start.event_id));
        assert!(ids.contains(&stop.event_id));
    }

    #[tokio::test]
    async fn systemd_story_returns_an_empty_story_rather_than_404_for_an_unknown_unit() {
        let (_dir, storage) = test_storage();
        let Json(story) = systemd_story_handler(
            State(storage),
            Query(SystemdStoryQuery {
                unit_name: Some("does-not-exist.service".to_string()),
            }),
        )
        .await
        .unwrap();
        assert!(story.events.is_empty());
        assert!(story.alerts.is_empty());
    }

    fn container_event(container_id: &str, event_type: EventType, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(800, None, timestamp);
        event.category = Category::Container;
        event.event_type = event_type;
        event.container = Some(osiris_schema::ContainerRef {
            container_id: container_id.to_string(),
            image: String::new(),
            runtime: "cgroup".to_string(),
            pod_ref: None,
        });
        event
    }

    #[tokio::test]
    async fn container_story_returns_400_when_container_id_is_missing() {
        let (_dir, storage) = test_storage();
        let result = container_story_handler(
            State(storage),
            Query(ContainerStoryQuery { container_id: None }),
        )
        .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn container_story_returns_every_event_for_the_named_container() {
        let (_dir, storage) = test_storage();
        let id = "a".repeat(64);
        let other_id = "b".repeat(64);
        let create = container_event(&id, EventType::ContainerCreate, 1000);
        let start = container_event(&id, EventType::ContainerStart, 2000);
        let other_container = container_event(&other_id, EventType::ContainerStart, 3000);
        storage
            .batch_write(&[create.clone(), start.clone(), other_container])
            .unwrap();

        let Json(story) = container_story_handler(
            State(storage),
            Query(ContainerStoryQuery {
                container_id: Some(id),
            }),
        )
        .await
        .unwrap();
        assert_eq!(story.events.len(), 2);
        let ids: Vec<_> = story.events.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&create.event_id));
        assert!(ids.contains(&start.event_id));
    }

    #[tokio::test]
    async fn container_story_returns_an_empty_story_rather_than_404_for_an_unknown_container() {
        let (_dir, storage) = test_storage();
        let Json(story) = container_story_handler(
            State(storage),
            Query(ContainerStoryQuery {
                container_id: Some("c".repeat(64)),
            }),
        )
        .await
        .unwrap();
        assert!(story.events.is_empty());
        assert!(story.alerts.is_empty());
    }
}
