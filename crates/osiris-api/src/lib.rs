use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use osiris_correlate::{BehavioralChain, CorrelationEngine, EdgeSource};
use osiris_schema::{Alert, CanonicalEvent, EntityRef, EntityRelationship, EventType, FileIdentity, ProcessKey, RiskScoreRecord};
use osiris_storage::{AlertQueryPlan, QueryPlan, RelationshipQueryPlan, RiskQueryPlan, Storage};
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
        .route("/api/v1/processes/:process_key/story", get(process_story_handler))
        .route("/api/v1/alerts", get(alerts_handler))
        .route("/api/v1/files", get(files_handler))
        .route("/api/v1/files/story", get(file_story_handler))
        .route("/api/v1/network", get(network_handler))
        .route("/api/v1/network/story", get(network_story_handler))
        .route("/api/v1/identity/story", get(identity_story_handler))
        .route("/api/v1/systemd/story", get(systemd_story_handler))
        .route("/api/v1/containers", get(containers_handler))
        .route("/api/v1/containers/story", get(container_story_handler))
        .route("/api/v1/system/story", get(system_story_handler))
        .route("/api/v1/graph", get(graph_handler))
        .route("/api/v1/graph/subgraph", get(subgraph_handler))
        .route("/api/v1/risk", get(risk_handler))
        .route("/api/v1/incidents/:seed_entity/reconstruct", get(reconstruct_incident_handler))
        .with_state(storage)
}

/// Server-side cap on `GET /api/v1/graph`'s `depth` parameter, regardless
/// of what a caller requests — ARCHITECTURE.md §12.5's explicit "never the
/// full graph — always scoped to a seed entity + depth + time range" is
/// enforced here, not just documented.
const MAX_GRAPH_DEPTH: usize = 5;

/// `EventType`'s wire form (`#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`,
/// e.g. `FileWrite` -> `"FILE_WRITE"`) — used by the new Files/Network/
/// Containers list endpoints' `last_event_type`/`status` fields so they
/// match every other place `event_type` appears on the wire.
fn event_type_label(event_type: EventType) -> String {
    serde_json::to_value(event_type)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Adapts `Storage::query_relationships` to `osiris_correlate::EdgeSource`
/// for one bounded API request. Unlike `osiris-server`'s own
/// `StorageEdgeSource` (which lets `CorrelationEngine` compute its window
/// from a seed timestamp), this adapter carries the request's own explicit
/// `since`/`until` and ignores the bounds `CorrelationEngine` would
/// otherwise compute from a seed time — the API's `since`/`until` query
/// parameters are the actual bound a caller asked for, not a symmetric
/// window around one instant.
struct RequestEdgeSource<'s> {
    storage: &'s dyn Storage,
    since: u64,
    until: u64,
}

impl EdgeSource for RequestEdgeSource<'_> {
    fn edges_for(&self, entity: &EntityRef, _since: u64, _until: u64) -> Vec<EntityRelationship> {
        let plan = RelationshipQueryPlan {
            entity: Some(entity.clone()),
            since: Some(self.since),
            until: Some(self.until),
            ..RelationshipQueryPlan::new()
        };
        self.storage.query_relationships(&plan).unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
struct GraphQuery {
    entity: Option<String>,
    depth: Option<usize>,
    since: Option<u64>,
    until: Option<u64>,
}

/// `GET /api/v1/graph` — a bounded subgraph query (§12.5): the Correlation
/// Engine's graph walk, seeded from `entity` (the same tagged string
/// `EntityRef::storage_key()` produces), depth-capped at
/// `MAX_GRAPH_DEPTH` regardless of the request, and time-bounded by
/// `since`/`until` (defaulting to "everything" when omitted, since the
/// depth cap alone already bounds response size).
async fn graph_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<GraphQuery>,
) -> Result<Json<BehavioralChain>, (StatusCode, String)> {
    let Some(entity_key) = q.entity else {
        return Err((StatusCode::BAD_REQUEST, "must provide entity".to_string()));
    };
    let entity = EntityRef::parse_storage_key(&entity_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let depth = q.depth.unwrap_or(MAX_GRAPH_DEPTH).min(MAX_GRAPH_DEPTH);
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(u64::MAX);

    let chain = tokio::task::spawn_blocking(move || {
        let source = RequestEdgeSource {
            storage: storage.as_ref(),
            since,
            until,
        };
        // window_ns is irrelevant here — RequestEdgeSource ignores the
        // bounds CorrelationEngine would compute and always applies the
        // request's own since/until instead (see its doc comment above).
        let engine = CorrelationEngine::new(depth, u64::MAX / 4);
        engine.build_chain(&source, entity, since)
    })
    .await
    .unwrap();

    Ok(Json(chain))
}

const MAX_SUBGRAPH_NODES: usize = 500;

#[derive(Debug, Deserialize)]
struct SubgraphQuery {
    entity: Option<String>,
    depth: Option<usize>,
    max_nodes: Option<usize>,
    since: Option<u64>,
    until: Option<u64>,
}

async fn subgraph_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<SubgraphQuery>,
) -> Result<Json<osiris_investigate::Subgraph>, (StatusCode, String)> {
    let Some(entity_key) = q.entity else {
        return Err((StatusCode::BAD_REQUEST, "must provide entity".to_string()));
    };
    let seed = EntityRef::parse_storage_key(&entity_key).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let depth = q.depth.unwrap_or(MAX_GRAPH_DEPTH).min(MAX_GRAPH_DEPTH);
    let max_nodes = q.max_nodes.unwrap_or(MAX_SUBGRAPH_NODES).min(MAX_SUBGRAPH_NODES);
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(u64::MAX);

    let result = tokio::task::spawn_blocking(move || {
        osiris_investigate::subgraph(storage.as_ref(), seed, depth, max_nodes, since, until)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct RiskQuery {
    process_key: Option<String>,
    event_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReconstructQuery {
    since: Option<u64>,
    until: Option<u64>,
}

/// `GET /api/v1/risk` — queries persisted `RiskScoreRecord`s by
/// `process_key` and/or `event_id` (ARCHITECTURE.md §11.4).
async fn risk_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<RiskQuery>,
) -> Result<Json<Vec<RiskScoreRecord>>, (StatusCode, String)> {
    let mut plan = RiskQueryPlan::new();
    if let Some(pk) = &q.process_key {
        let process_key: ProcessKey = serde_json::from_value(serde_json::Value::String(pk.clone()))
            .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid process_key: {pk}")))?;
        plan.process_key = Some(process_key);
    }
    if let Some(eid) = &q.event_id {
        let event_id: uuid::Uuid = eid
            .parse()
            .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid event_id: {eid}")))?;
        plan.event_id = Some(event_id);
    }

    let records = tokio::task::spawn_blocking(move || storage.query_risk_scores(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(records))
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
    /// Opt-in to §19.2's export regime (`MAX_EVENT_LIMIT` ceiling instead of
    /// `DEFAULT_EVENT_LIMIT`). Global Constraint #9 makes this the
    /// *caller's* explicit choice, so it is deliberately independent of
    /// whether `limit` was supplied — a bare `limit` stays under the
    /// default cap.
    export: Option<bool>,
    /// Free-form OQL (ARCHITECTURE.md §12.3). When both `q` and
    /// `event_type` are given they intersect (`AND`), matching how the old
    /// fixed-field filters composed before this task.
    q: Option<String>,
}

async fn events_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<CanonicalEvent>>, (StatusCode, String)> {
    let mut plan = if let Some(oql) = &q.q {
        osiris_query::EventQueryPlan::with_filter(oql)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        osiris_query::EventQueryPlan::new()
    };

    if let Some(et) = &q.event_type {
        // Validate the sugar param the same way the OQL path would, so a
        // typo here gets the same 400 an OQL typo would.
        serde_json::from_str::<EventType>(&format!("\"{}\"", et)).map_err(|_| {
            (StatusCode::BAD_REQUEST, format!("invalid event_type: {}", et))
        })?;
        let event_type_ast = osiris_query::ast::Ast::Compare {
            field: "event_type".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str(et.clone()),
        };
        plan.filter = Some(match plan.filter {
            Some(existing) => osiris_query::ast::Ast::And(Box::new(existing), Box::new(event_type_ast)),
            None => event_type_ast,
        });
    }
    plan.since = q.since;
    plan.until = q.until;
    if let Some(limit) = q.limit {
        plan.limit = limit;
    }
    plan.export = q.export.unwrap_or(false);

    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
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
struct FileSummary {
    file_id: String,
    path: String,
    host_id: String,
    hostname: String,
    last_event_type: String,
    timestamp: u64,
}

/// `GET /api/v1/files` — ARCHITECTURE.md §16.3's Filesystem list screen.
/// Bounded `category = "FILE"` query + Rust-side dedup keyed by
/// `(host_id, FileIdentity)`, keeping the most-recent event per identity —
/// see this phase's design spec for why this departs from `/processes`'s
/// first-seen semantics. Events with no full `FileIdentity` (missing
/// inode or device_id) are skipped, matching that type's existing
/// `from_file_ref` semantics.
async fn files_handler(
    State(storage): State<Arc<dyn Storage>>,
) -> Result<Json<Vec<FileSummary>>, (StatusCode, String)> {
    let plan = osiris_query::EventQueryPlan {
        filter: Some(osiris_query::ast::Ast::Compare {
            field: "category".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str("FILE".to_string()),
        }),
        limit: 10_000,
        export: true,
        ..osiris_query::EventQueryPlan::new()
    };
    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<(uuid::Uuid, FileIdentity), FileSummary> = HashMap::new();
    for event in events {
        let Some(file) = &event.file else { continue };
        let Some(identity) = FileIdentity::from_file_ref(file) else { continue };
        let key = (event.host_id, identity);
        match seen.get(&key) {
            Some(existing) if existing.timestamp >= event.timestamp => {}
            _ => {
                seen.insert(
                    key,
                    FileSummary {
                        file_id: identity.as_key(),
                        path: file.path.clone(),
                        host_id: event.host_id.to_string(),
                        hostname: event.host.hostname.clone(),
                        last_event_type: event_type_label(event.event_type),
                        timestamp: event.timestamp,
                    },
                );
            }
        }
    }
    Ok(Json(seen.into_values().collect()))
}

async fn file_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<FileStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    if q.path.is_none() && q.file_id.is_none() {
        return Err((StatusCode::BAD_REQUEST, "must provide path or file_id".to_string()));
    }
    let file_id = match &q.file_id {
        Some(raw) => Some(
            FileIdentity::parse_key(raw)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid file_id: {}", raw)))?,
        ),
        None => None,
    };
    let path = q.path.clone();
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::file_story(storage.as_ref(), path.as_deref(), file_id)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}

#[derive(Debug, Serialize)]
struct NetworkSummary {
    host_id: String,
    hostname: String,
    dst_ip: String,
    dst_port: u16,
    proto: String,
    last_event_type: String,
    timestamp: u64,
}

/// `GET /api/v1/network` — ARCHITECTURE.md §16.3's Network list screen.
/// Bounded `category = "NETWORK"` query + Rust-side dedup keyed by
/// `(host_id, dst_ip, dst_port, proto)` — destination-only, deliberately
/// excluding `src_ip`/`src_port` since source port is normally ephemeral
/// (see this phase's design spec). Keeps the most-recent event per group.
async fn network_handler(
    State(storage): State<Arc<dyn Storage>>,
) -> Result<Json<Vec<NetworkSummary>>, (StatusCode, String)> {
    let plan = osiris_query::EventQueryPlan {
        filter: Some(osiris_query::ast::Ast::Compare {
            field: "category".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str("NETWORK".to_string()),
        }),
        limit: 10_000,
        export: true,
        ..osiris_query::EventQueryPlan::new()
    };
    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<(uuid::Uuid, String, u16, String), NetworkSummary> = HashMap::new();
    for event in events {
        let Some(network) = &event.network else { continue };
        let key = (
            event.host_id,
            network.dst_ip.clone(),
            network.dst_port,
            network.proto.clone(),
        );
        match seen.get(&key) {
            Some(existing) if existing.timestamp >= event.timestamp => {}
            _ => {
                seen.insert(
                    key,
                    NetworkSummary {
                        host_id: event.host_id.to_string(),
                        hostname: event.host.hostname.clone(),
                        dst_ip: network.dst_ip.clone(),
                        dst_port: network.dst_port,
                        proto: network.proto.clone(),
                        last_event_type: event_type_label(event.event_type),
                        timestamp: event.timestamp,
                    },
                );
            }
        }
    }
    Ok(Json(seen.into_values().collect()))
}

#[derive(Debug, Deserialize)]
struct NetworkStoryQuery {
    ip: Option<String>,
    domain: Option<String>,
}

/// Composed query implementing Phase 3 plan Global Constraints #9: the
/// domain form resolves DNS events for that domain, unions in every network
/// event touching any of their resolved addresses; the IP form matches
/// network events directly and does not reverse-resolve to the DNS side —
/// a deliberate, disclosed asymmetry (see the constraint's full reasoning).
async fn network_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<NetworkStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    if q.ip.is_none() && q.domain.is_none() {
        return Err((StatusCode::BAD_REQUEST, "must provide ip or domain".to_string()));
    }
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::network_story(storage.as_ref(), q.ip.as_deref(), q.domain.as_deref())
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}

#[derive(Debug, Deserialize)]
struct IdentityStoryQuery {
    session_id: Option<String>,
    uid: Option<u32>,
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
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    if q.session_id.is_none() && q.uid.is_none() {
        return Err((StatusCode::BAD_REQUEST, "must provide session_id or uid".to_string()));
    }
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::identity_story(storage.as_ref(), q.session_id.as_deref(), q.uid)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}

#[derive(Debug, Deserialize)]
struct SystemdStoryQuery {
    unit_name: Option<String>,
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
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let Some(unit_name) = q.unit_name else {
        return Err((StatusCode::BAD_REQUEST, "must provide unit_name".to_string()));
    };
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::systemd_story(storage.as_ref(), &unit_name)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}

#[derive(Debug, Deserialize)]
struct ContainerStoryQuery {
    container_id: Option<String>,
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
#[derive(Debug, Serialize)]
struct ContainerSummary {
    container_id: String,
    host_id: String,
    hostname: String,
    image: String,
    status: String,
    timestamp: u64,
}

/// `GET /api/v1/containers` — ARCHITECTURE.md §16.3's Containers list
/// screen. Bounded `category = "CONTAINER"` query + Rust-side dedup keyed
/// by `container_id` alone (not host-scoped, matching
/// `container_story_handler`'s own existing host-agnostic behavior).
/// `status` is derived from the kept (most-recent) event's `event_type`.
async fn containers_handler(
    State(storage): State<Arc<dyn Storage>>,
) -> Result<Json<Vec<ContainerSummary>>, (StatusCode, String)> {
    let plan = osiris_query::EventQueryPlan {
        filter: Some(osiris_query::ast::Ast::Compare {
            field: "category".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str("CONTAINER".to_string()),
        }),
        limit: 10_000,
        export: true,
        ..osiris_query::EventQueryPlan::new()
    };
    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<String, ContainerSummary> = HashMap::new();
    for event in events {
        let Some(container) = &event.container else { continue };
        let key = container.container_id.clone();
        match seen.get(&key) {
            Some(existing) if existing.timestamp >= event.timestamp => {}
            _ => {
                let status = match event.event_type {
                    EventType::ContainerCreate | EventType::ContainerStart => "RUNNING",
                    EventType::ContainerStop | EventType::ContainerDestroy => "STOPPED",
                    _ => "UNKNOWN",
                };
                seen.insert(
                    key.clone(),
                    ContainerSummary {
                        container_id: key,
                        host_id: event.host_id.to_string(),
                        hostname: event.host.hostname.clone(),
                        image: container.image.clone(),
                        status: status.to_string(),
                        timestamp: event.timestamp,
                    },
                );
            }
        }
    }
    Ok(Json(seen.into_values().collect()))
}

async fn container_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<ContainerStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let Some(container_id) = q.container_id else {
        return Err((StatusCode::BAD_REQUEST, "must provide container_id".to_string()));
    };
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::container_story(storage.as_ref(), &container_id)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}

#[derive(Debug, Deserialize)]
struct SystemStoryQuery {
    host_id: String,
    since: Option<u64>,
    until: Option<u64>,
}

async fn system_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<SystemStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let host_id: uuid::Uuid = q
        .host_id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid host_id: {}", q.host_id)))?;
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(u64::MAX);
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::system_story(storage.as_ref(), host_id, since, until)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}

async fn process_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Path(process_key_hex): Path<String>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let process_key: ProcessKey = serde_json::from_value(serde_json::Value::String(process_key_hex.clone()))
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid process_key: {}", process_key_hex)))?;
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::process_story(storage.as_ref(), process_key)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}

async fn reconstruct_incident_handler(
    State(storage): State<Arc<dyn Storage>>,
    Path(seed_key): Path<String>,
    Query(q): Query<ReconstructQuery>,
) -> Result<Json<osiris_investigate::IncidentReconstruction>, (StatusCode, String)> {
    let seed = EntityRef::parse_storage_key(&seed_key).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(u64::MAX);
    let reconstruction = tokio::task::spawn_blocking(move || {
        osiris_investigate::reconstruct_incident(storage.as_ref(), seed, since, until)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(reconstruction))
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

    #[tokio::test]
    async fn files_endpoint_keeps_the_most_recent_event_per_identity() {
        let (_dir, storage) = test_storage();
        let older = file_event(EventType::FileCreate, "/etc/passwd", 100, 1, 1000);
        let mut newer = older.clone();
        newer.event_id = Uuid::now_v7();
        newer.event_type = EventType::FileWrite;
        newer.timestamp = 2000;
        let host_id = older.host_id;
        let hostname = older.host.hostname.clone();
        storage.batch_write(&[older, newer]).unwrap();

        let Json(files) = files_handler(State(storage)).await.unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_id, "1:100");
        assert_eq!(files[0].path, "/etc/passwd");
        assert_eq!(files[0].host_id, host_id.to_string());
        assert_eq!(files[0].hostname, hostname);
        assert_eq!(files[0].last_event_type, "FILE_WRITE");
        assert_eq!(files[0].timestamp, 2000);
    }

    #[tokio::test]
    async fn files_endpoint_skips_events_without_a_full_file_identity() {
        let (_dir, storage) = test_storage();
        let mut missing_inode = file_event(EventType::FileCreate, "/etc/shadow", 1, 1, 1000);
        missing_inode.file.as_mut().unwrap().inode = None;
        storage.write(&missing_inode).unwrap();

        let Json(files) = files_handler(State(storage)).await.unwrap();

        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn files_endpoint_treats_different_hosts_with_the_same_identity_as_distinct_rows() {
        let (_dir, storage) = test_storage();
        let a = file_event(EventType::FileCreate, "/etc/passwd", 100, 1, 1000);
        let mut b = file_event(EventType::FileCreate, "/etc/passwd", 100, 1, 1000);
        b.host_id = uuid::Uuid::new_v4();
        b.host.host_id = b.host_id;
        storage.batch_write(&[a, b]).unwrap();

        let Json(files) = files_handler(State(storage)).await.unwrap();

        assert_eq!(files.len(), 2);
    }

    fn sensor_health_event(host_id: Uuid, sensor_name: &str, timestamp: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::SensorHealth,
            category: Category::System,
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
            event_data: serde_json::json!({
                "sensor_name": sensor_name,
                "state": {
                    "state": "FAILED",
                    "last_error": "eBPF load failure: verifier rejected program",
                },
                "events_processed": 42,
                "last_event_at": timestamp,
            }),
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
            export: None,
            q: None,
        };
        let Json(events) = events_handler(State(storage), Query(query)).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.as_ref().unwrap().pid, 100);
    }

    #[tokio::test]
    async fn events_endpoint_filters_by_oql_query_string() {
        let (_dir, storage) = test_storage();
        storage.write(&sample_event(1, None, 100)).unwrap();
        storage.write(&sample_event(2, None, 200)).unwrap();
        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: None,
            export: None,
            q: Some("process.pid = 1".to_string()),
        };
        let Json(events) = events_handler(State(storage), Query(q)).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn events_endpoint_filters_by_sensor_health_event_type() {
        let (_dir, storage) = test_storage();
        let host_id = Uuid::new_v4();
        storage
            .write(&sensor_health_event(host_id, "network", 5000))
            .unwrap();
        storage.write(&sample_event(100, None, 1000)).unwrap();

        let q = EventsQuery {
            event_type: Some("SENSOR_HEALTH".to_string()),
            since: None,
            until: None,
            limit: None,
            export: None,
            q: None,
        };
        let Json(events) = events_handler(State(storage), Query(q)).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::SensorHealth);
        assert_eq!(events[0].event_data["sensor_name"], "network");
        assert_eq!(events[0].event_data["state"]["state"], "FAILED");
        assert_eq!(
            events[0].event_data["state"]["last_error"],
            "eBPF load failure: verifier rejected program"
        );
    }

    #[tokio::test]
    async fn events_endpoint_rejects_a_malformed_oql_query_string() {
        let (_dir, storage) = test_storage();
        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: None,
            export: None,
            q: Some("process.pid =".to_string()),
        };
        let err = events_handler(State(storage), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn events_endpoint_rejects_an_unknown_field_in_the_oql_query_string() {
        let (_dir, storage) = test_storage();
        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: None,
            export: None,
            q: Some("bogus_field = 1".to_string()),
        };
        let err = events_handler(State(storage), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("bogus_field"));
    }

    #[tokio::test]
    async fn events_endpoint_limit_alone_stays_under_the_default_cap() {
        use osiris_query::DEFAULT_EVENT_LIMIT;
        let (_dir, storage) = test_storage();
        let batch: Vec<_> = (0..600u32).map(|i| sample_event(i, None, 1000 + i as u64)).collect();
        storage.batch_write(&batch).unwrap();

        // §19.2 / Global Constraint #9: `export` is opt-in. A caller that
        // supplies only `limit` must stay under the *default* cap.
        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: Some(600),
            export: None,
            q: None,
        };
        let Json(events) = events_handler(State(storage), Query(q)).await.unwrap();
        assert_eq!(events.len(), DEFAULT_EVENT_LIMIT);
    }

    #[tokio::test]
    async fn events_endpoint_honors_an_explicit_export_above_the_default_cap() {
        use osiris_query::{DEFAULT_EVENT_LIMIT, MAX_EVENT_LIMIT};
        // 600 is deliberately above the default cap and below the export
        // ceiling, so this test can only pass under export semantics.
        const { assert!(600 > DEFAULT_EVENT_LIMIT && 600 <= MAX_EVENT_LIMIT) };
        let (_dir, storage) = test_storage();
        let batch: Vec<_> = (0..600u32).map(|i| sample_event(i, None, 1000 + i as u64)).collect();
        storage.batch_write(&batch).unwrap();

        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: Some(600),
            export: Some(true),
            q: None,
        };
        let Json(events) = events_handler(State(storage), Query(q)).await.unwrap();
        assert_eq!(events.len(), 600);
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

    #[tokio::test]
    async fn network_endpoint_keeps_the_most_recent_event_per_destination() {
        let (_dir, storage) = test_storage();
        let older = network_event(EventType::NetworkConnect, "10.0.0.5", "93.184.216.34", 1000);
        let mut newer = older.clone();
        newer.event_id = Uuid::now_v7();
        newer.event_type = EventType::NetworkClose;
        newer.timestamp = 2000;
        let host_id = older.host_id;
        storage.batch_write(&[older, newer]).unwrap();

        let Json(rows) = network_handler(State(storage)).await.unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dst_ip, "93.184.216.34");
        assert_eq!(rows[0].dst_port, 443);
        assert_eq!(rows[0].proto, "tcp");
        assert_eq!(rows[0].host_id, host_id.to_string());
        assert_eq!(rows[0].last_event_type, "NETWORK_CLOSE");
        assert_eq!(rows[0].timestamp, 2000);
    }

    #[tokio::test]
    async fn network_endpoint_treats_different_destination_ports_as_distinct_rows() {
        let (_dir, storage) = test_storage();
        let a = network_event(EventType::NetworkConnect, "10.0.0.5", "93.184.216.34", 1000);
        let mut b = a.clone();
        b.event_id = Uuid::now_v7();
        b.network.as_mut().unwrap().dst_port = 8443;
        storage.batch_write(&[a, b]).unwrap();

        let Json(rows) = network_handler(State(storage)).await.unwrap();

        assert_eq!(rows.len(), 2);
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
    async fn containers_endpoint_derives_running_status_from_the_most_recent_event() {
        let (_dir, storage) = test_storage();
        let id = "c".repeat(64);
        let create = container_event(&id, EventType::ContainerCreate, 1000);
        let start = container_event(&id, EventType::ContainerStart, 2000);
        storage.batch_write(&[create, start]).unwrap();

        let Json(rows) = containers_handler(State(storage)).await.unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].container_id, id);
        assert_eq!(rows[0].status, "RUNNING");
        assert_eq!(rows[0].timestamp, 2000);
    }

    #[tokio::test]
    async fn containers_endpoint_derives_stopped_status_from_the_most_recent_event() {
        let (_dir, storage) = test_storage();
        let id = "d".repeat(64);
        let start = container_event(&id, EventType::ContainerStart, 1000);
        let stop = container_event(&id, EventType::ContainerStop, 2000);
        storage.batch_write(&[start, stop]).unwrap();

        let Json(rows) = containers_handler(State(storage)).await.unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "STOPPED");
    }

    #[tokio::test]
    async fn containers_endpoint_dedups_by_container_id_alone_not_host() {
        let (_dir, storage) = test_storage();
        let id = "e".repeat(64);
        let mut on_host_a = container_event(&id, EventType::ContainerStart, 1000);
        let mut on_host_b = container_event(&id, EventType::ContainerStart, 2000);
        on_host_b.host_id = uuid::Uuid::new_v4();
        on_host_b.host.host_id = on_host_b.host_id;
        on_host_a.host_id = uuid::Uuid::new_v4();
        on_host_a.host.host_id = on_host_a.host_id;
        storage.batch_write(&[on_host_a, on_host_b]).unwrap();

        let Json(rows) = containers_handler(State(storage)).await.unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp, 2000);
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

    #[tokio::test]
    async fn graph_returns_400_when_entity_is_missing() {
        let (_dir, storage) = test_storage();
        let err = graph_handler(
            State(storage),
            Query(GraphQuery {
                entity: None,
                depth: None,
                since: None,
                until: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn graph_returns_400_for_an_unparseable_entity_key() {
        let (_dir, storage) = test_storage();
        let err = graph_handler(
            State(storage),
            Query(GraphQuery {
                entity: Some("NOT_A_VALID_KEY".to_string()),
                depth: None,
                since: None,
                until: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn graph_returns_the_bounded_subgraph_seeded_from_the_entity() {
        let (_dir, storage) = test_storage();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 300, 1);
        let process_entity = EntityRef::Process { process_key };
        let ip_entity = EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        };
        storage
            .write_relationships(&[EntityRelationship {
                from: process_entity.clone(),
                to: ip_entity.clone(),
                relation: osiris_schema::Relation::ConnectedTo,
                event_id: Uuid::now_v7(),
                timestamp: 1000,
            }])
            .unwrap();

        let Json(chain) = graph_handler(
            State(storage),
            Query(GraphQuery {
                entity: Some(process_entity.storage_key()),
                depth: None,
                since: None,
                until: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(chain.edges.len(), 1);
        assert_eq!(chain.edges[0].to.storage_key(), ip_entity.storage_key());
    }

    #[tokio::test]
    async fn risk_filters_by_process_key() {
        let (_dir, storage) = test_storage();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 300, 1);
        let other_key = ProcessKey::new(host_id, "b", 301, 1);
        let event_id = Uuid::now_v7();
        storage
            .write_risk_scores(&[
                RiskScoreRecord {
                    event_id,
                    process_key: Some(process_key),
                    host_id,
                    timestamp: 1000,
                    score: 42,
                    severity: Severity::High,
                    reasons: vec![osiris_schema::WeightedReason {
                        label: "because".to_string(),
                        weight: 42,
                        evidence: event_id,
                    }],
                    related_events: vec![event_id],
                },
                RiskScoreRecord {
                    event_id: Uuid::now_v7(),
                    process_key: Some(other_key),
                    host_id,
                    timestamp: 2000,
                    score: 10,
                    severity: Severity::Low,
                    reasons: vec![osiris_schema::WeightedReason {
                        label: "unrelated".to_string(),
                        weight: 10,
                        evidence: Uuid::now_v7(),
                    }],
                    related_events: vec![],
                },
            ])
            .unwrap();

        let Json(records) = risk_handler(
            State(storage),
            Query(RiskQuery {
                process_key: Some(process_key.as_hex()),
                event_id: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].score, 42);
    }

    #[tokio::test]
    async fn risk_returns_400_for_an_invalid_event_id() {
        let (_dir, storage) = test_storage();
        let err = risk_handler(
            State(storage),
            Query(RiskQuery {
                process_key: None,
                event_id: Some("not-a-uuid".to_string()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn process_story_endpoint_returns_the_processs_own_events() {
        let (_dir, storage) = test_storage();
        let event = sample_event(100, None, 1000);
        let process_key = event.process.as_ref().unwrap().process_key;
        storage.write(&event).unwrap();

        let Json(story) = process_story_handler(State(storage), Path(process_key.as_hex())).await.unwrap();
        assert_eq!(story.events.len(), 1);
    }

    #[tokio::test]
    async fn process_story_endpoint_rejects_a_malformed_process_key() {
        let (_dir, storage) = test_storage();
        let err = process_story_handler(State(storage), Path("not-hex".to_string())).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn system_story_endpoint_filters_by_host_and_time_range() {
        let (_dir, storage) = test_storage();
        let event = sample_event(1, None, 500);
        let host_id = event.host_id;
        storage.write(&event).unwrap();
        storage.write(&sample_event(2, None, 5000)).unwrap();

        let q = SystemStoryQuery { host_id: host_id.to_string(), since: Some(0), until: Some(1000) };
        let Json(story) = system_story_handler(State(storage), Query(q)).await.unwrap();
        assert_eq!(story.events.len(), 1);
    }

    #[tokio::test]
    async fn reconstruct_incident_endpoint_returns_a_reconstruction_for_a_known_entity() {
        let (_dir, storage) = test_storage();
        let seed = EntityRef::Ip { addr: "203.0.113.10".to_string() };
        let q = ReconstructQuery { since: Some(0), until: Some(10_000) };
        let Json(reconstruction) =
            reconstruct_incident_handler(State(storage), Path(seed.storage_key()), Query(q))
                .await
                .unwrap();
        assert_eq!(reconstruction.seed, seed);
    }

    #[tokio::test]
    async fn reconstruct_incident_endpoint_rejects_a_malformed_seed_key() {
        let (_dir, storage) = test_storage();
        let q = ReconstructQuery { since: None, until: None };
        let err = reconstruct_incident_handler(State(storage), Path("not-a-key".to_string()), Query(q))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn subgraph_endpoint_bounds_by_node_count() {
        let (_dir, storage) = test_storage();
        let seed = EntityRef::Ip { addr: "10.0.0.1".to_string() };
        let other = EntityRef::Ip { addr: "10.0.0.2".to_string() };
        storage
            .write_relationships(&[EntityRelationship {
                from: seed.clone(),
                to: other,
                relation: osiris_schema::Relation::ConnectedTo,
                event_id: uuid::Uuid::now_v7(),
                timestamp: 100,
            }])
            .unwrap();

        // Uncapped call should return seed + connected entity (>= 2 nodes)
        let q_uncapped = SubgraphQuery { entity: Some(seed.storage_key()), depth: Some(5), max_nodes: Some(100), since: None, until: None };
        let Json(uncapped_result) = subgraph_handler(State(storage.clone()), Query(q_uncapped)).await.unwrap();
        assert!(uncapped_result.nodes.len() >= 2, "uncapped call should return seed + connected entity");

        // Capped call should respect max_nodes=1 bound
        let q_capped = SubgraphQuery { entity: Some(seed.storage_key()), depth: Some(5), max_nodes: Some(1), since: None, until: None };
        let Json(capped_result) = subgraph_handler(State(storage), Query(q_capped)).await.unwrap();
        assert_eq!(capped_result.nodes.len(), 1, "max_nodes=1 should return exactly 1 node");
    }

    #[tokio::test]
    async fn subgraph_endpoint_requires_an_entity_parameter() {
        let (_dir, storage) = test_storage();
        let q = SubgraphQuery { entity: None, depth: None, max_nodes: None, since: None, until: None };
        let err = subgraph_handler(State(storage), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}

pub mod evidence;
pub mod incidents;
pub use incidents::{build_incident_evidence_router, IncidentEvidenceState};
pub mod stream;
pub use stream::{build_stream_router, LiveEventBroadcaster};
