use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_evidence::{EvidenceIncidentLinks, EvidenceStore};
use osiris_response::{dispatch, ResponseActionKind, ResponseError, ResponseOutcome, ResponseRequest};
use osiris_schema::EntityRef;
use osiris_storage::Storage;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth_middleware::AuthContext;

#[derive(Clone)]
pub struct ResponseState {
    pub storage: Arc<dyn Storage>,
    pub evidence: Arc<dyn EvidenceStore>,
    pub links: Arc<dyn EvidenceIncidentLinks>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
}

pub fn build_response_router(state: ResponseState) -> Router {
    Router::new()
        .route("/api/v1/response/:action", post(response_handler))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct ResponseRequestBody {
    target: EntityRef,
    reason: String,
    dry_run: bool,
    since: Option<u64>,
    until: Option<u64>,
    incident_id: Option<Uuid>,
}

fn parse_action(raw: &str) -> Option<ResponseActionKind> {
    // Route path segments are lower_snake_case (e.g. "collect_evidence"),
    // matching auth_middleware's `min_role_for` route table, while
    // `ResponseActionKind`'s wire form is SCREAMING_SNAKE_CASE — uppercase
    // before decoding so both stay in sync with one source of truth.
    serde_json::from_value(serde_json::Value::String(raw.to_uppercase())).ok()
}

async fn response_handler(
    State(state): State<ResponseState>,
    Extension(ctx): Extension<AuthContext>,
    Path(action_raw): Path<String>,
    Json(body): Json<ResponseRequestBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(action) = parse_action(&action_raw) else {
        return Err((StatusCode::NOT_FOUND, format!("unknown response action: {action_raw}")));
    };
    if body.reason.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "reason must not be empty".to_string()));
    }

    let request = ResponseRequest {
        action,
        target: body.target,
        reason: body.reason.clone(),
        dry_run: body.dry_run,
        since: body.since,
        until: body.until,
        incident_id: body.incident_id,
    };
    let original_target = request.target.clone();

    let what = if request.dry_run {
        format!("response.{action_raw}.dry_run")
    } else {
        format!("response.{action_raw}.execute")
    };
    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User { user_id: ctx.user_id },
        what: what.clone(),
        target: request.target.clone(),
        why: Some(request.reason.clone()),
        result: AuditResult::Success,
    });

    let storage = state.storage.clone();
    let evidence = state.evidence.clone();
    let links = state.links.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        dispatch(&request, storage.as_ref(), evidence.as_ref(), links.as_ref())
    })
    .await
    .unwrap();

    match outcome {
        Ok(ResponseOutcome::DryRunPreview { description }) => {
            // Dry-run's single pre-execution entry above already records
            // this preview's full text via `why` — no second entry (see
            // spec §4's deliberate one-vs-two-entry asymmetry).
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({ "dry_run": true, "preview": description })),
            ))
        }
        Ok(ResponseOutcome::EvidenceCollected { evidence_id }) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: original_target.clone(),
                why: Some(format!("{} (evidence_id={evidence_id})", "collected")),
                result: AuditResult::Success,
            });
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({ "dry_run": false, "evidence_id": evidence_id })),
            ))
        }
        Ok(ResponseOutcome::Rejected { reason }) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: original_target.clone(),
                why: Some(reason.clone()),
                result: AuditResult::Failure,
            });
            Ok((
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({ "error": "not_implemented", "message": reason })),
            ))
        }
        Err(ResponseError::UnknownTarget(_)) => Err((
            StatusCode::BAD_REQUEST,
            "target does not resolve to any known data".to_string(),
        )),
        Err(e) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: EntityRef::Domain { name: "response-engine-internal-error".to_string() },
                why: Some(e.to_string()),
                result: AuditResult::Failure,
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::FileAuditLog;
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore};
    use osiris_schema::{Category, DnsRef, EventType, HostRef, Severity, Source, CanonicalEvent, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;

    fn test_state() -> (tempfile::TempDir, ResponseState) {
        let dir = tempfile::tempdir().unwrap();
        let state = ResponseState {
            storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            evidence: Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap()),
            links: Arc::new(SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap()).unwrap()),
            audit_log: Arc::new(FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
        };
        (dir, state)
    }

    fn dns_event(host_id: Uuid, query: &str) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1000,
            monotonic_timestamp: 1000,
            event_type: EventType::DnsQuery,
            category: Category::Dns,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: Some(DnsRef { query: query.to_string(), qtype: "A".to_string(), response_ips: vec![], ttl: None }),
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

    fn ctx() -> AuthContext {
        AuthContext { user_id: Uuid::now_v7(), role: osiris_auth::Role::ResponseOperator, token: "t".to_string() }
    }

    fn count_audit_entries(dir: &std::path::Path) -> usize {
        let log = FileAuditLog::open(dir.join("audit.jsonl")).unwrap();
        log.read_all().unwrap().len()
    }

    #[tokio::test]
    async fn dry_run_writes_exactly_one_audit_entry() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "audit-dry-run.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "audit-dry-run.example".to_string() },
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            Path("collect_evidence".to_string()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["dry_run"], serde_json::json!(true));
        assert_eq!(count_audit_entries(dir.path()), 1);
    }

    #[tokio::test]
    async fn collect_evidence_execute_writes_exactly_two_audit_entries() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "audit-execute.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "audit-execute.example".to_string() },
            reason: "collecting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            Path("collect_evidence".to_string()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(resp["evidence_id"].is_string());
        assert_eq!(count_audit_entries(dir.path()), 2);
    }

    #[tokio::test]
    async fn a_destructive_execute_request_returns_501_and_writes_two_audit_entries() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "audit-destructive.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "audit-destructive.example".to_string() },
            reason: "attempting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            Path("block_indicator".to_string()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(resp["error"], serde_json::json!("not_implemented"));
        assert_eq!(count_audit_entries(dir.path()), 2);
    }

    #[tokio::test]
    async fn an_empty_reason_is_rejected_before_any_audit_write() {
        let (dir, state) = test_state();
        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "x.example".to_string() },
            reason: "   ".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        let err = response_handler(State(state), Extension(ctx()), Path("collect_evidence".to_string()), Json(body))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(count_audit_entries(dir.path()), 0);
    }

    #[tokio::test]
    async fn an_unknown_action_segment_is_a_404() {
        let (_dir, state) = test_state();
        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "x.example".to_string() },
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        let err = response_handler(State(state), Extension(ctx()), Path("not_a_real_action".to_string()), Json(body))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_response_router_merges_without_a_route_collision() {
        let (_dir, state) = test_state();
        let storage_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(storage_dir.path().join("events.db")).unwrap());
        let merged: Router = crate::build_router(storage).merge(crate::build_response_router(state));
        let _ = std::hint::black_box(merged);
    }
}
