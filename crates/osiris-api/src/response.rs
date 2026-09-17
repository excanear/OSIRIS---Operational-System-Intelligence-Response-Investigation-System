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
    //
    // `to_ascii_uppercase` (NOT `to_uppercase`) deliberately — `to_uppercase`
    // is Unicode-aware and can fold non-ASCII characters (e.g. Turkish
    // dotless-ı) onto ASCII letters, which would let a crafted path segment
    // decode to a valid action while looking nothing like it. ASCII-only
    // uppercasing keeps decoding exact-match on the literal bytes.
    serde_json::from_value(serde_json::Value::String(raw.to_ascii_uppercase())).ok()
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
    let original_reason = request.reason.clone();

    // Built from the *decoded* `ResponseActionKind`'s canonical wire form,
    // never from `action_raw` — the raw path segment is attacker-controlled
    // and its case/Unicode form must never leak into the audit trail (Fix 1).
    let what = if request.dry_run {
        format!("response.{}.dry_run", action.wire_form())
    } else {
        format!("response.{}.execute", action.wire_form())
    };

    if request.dry_run {
        // Dry-run has no side effects to protect via a pre-write — nothing
        // is mutated, so there is no crash-survival argument for writing
        // before `dispatch()` runs (unlike the real-execution path below).
        // Exactly one audit entry is written, after the outcome is known,
        // so its `why`/`result` reflect what actually happened rather than
        // the operator's a-priori justification (Fix 3).
        let storage = state.storage.clone();
        let evidence = state.evidence.clone();
        let links = state.links.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            dispatch(&request, storage.as_ref(), evidence.as_ref(), links.as_ref())
        })
        .await
        .unwrap();

        return match outcome {
            Ok(ResponseOutcome::DryRunPreview { description }) => {
                let _ = state.audit_log.append(NewAuditEntry {
                    who: ActorRef::User { user_id: ctx.user_id },
                    what,
                    target: original_target,
                    why: Some(description.clone()),
                    result: AuditResult::Success,
                });
                Ok((
                    StatusCode::OK,
                    Json(serde_json::json!({ "dry_run": true, "preview": description })),
                ))
            }
            Ok(other) => {
                // dispatch()'s dry-run branch only ever returns
                // DryRunPreview or Err; this arm exists solely so the match
                // stays exhaustive if that ever changes.
                let _ = state.audit_log.append(NewAuditEntry {
                    who: ActorRef::User { user_id: ctx.user_id },
                    what,
                    target: original_target,
                    why: Some(format!("dry-run returned an unexpected outcome: {other:?}")),
                    result: AuditResult::Failure,
                });
                Err((StatusCode::INTERNAL_SERVER_ERROR, "unexpected dry-run outcome".to_string()))
            }
            Err(ResponseError::UnknownTarget(_)) => {
                let _ = state.audit_log.append(NewAuditEntry {
                    who: ActorRef::User { user_id: ctx.user_id },
                    what,
                    target: original_target,
                    why: Some("dry-run failed: target does not resolve to any known data".to_string()),
                    result: AuditResult::Failure,
                });
                Err((StatusCode::BAD_REQUEST, "target does not resolve to any known data".to_string()))
            }
            Err(e) => {
                let _ = state.audit_log.append(NewAuditEntry {
                    who: ActorRef::User { user_id: ctx.user_id },
                    what,
                    target: original_target,
                    why: Some(format!("dry-run failed: {e}")),
                    result: AuditResult::Failure,
                });
                Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }
        };
    }

    // Real (non-dry-run) execution: this path has genuine side effects, so
    // the pre-execution write's crash-survival argument (spec §4/§13) holds
    // and its failure must fail closed — no destructive or evidence-mutating
    // action may run without a recorded pre-execution audit entry
    // (ARCHITECTURE.md §17.3) (Fix 4).
    if let Err(e) = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User { user_id: ctx.user_id },
        what: what.clone(),
        target: request.target.clone(),
        why: Some(request.reason.clone()),
        result: AuditResult::Success,
    }) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("audit log write failed: {e}")));
    }

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
            // Unreachable on the non-dry-run path, but keep the match
            // exhaustive rather than panicking.
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: original_target,
                why: Some(description.clone()),
                result: AuditResult::Success,
            });
            Ok((StatusCode::OK, Json(serde_json::json!({ "dry_run": true, "preview": description }))))
        }
        Ok(ResponseOutcome::EvidenceCollected { evidence_id, event_count, truncated }) => {
            if let Err(e) = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: original_target.clone(),
                why: Some(format!(
                    "{original_reason} (evidence_id={evidence_id}, event_count={event_count}, truncated={truncated})"
                )),
                result: AuditResult::Success,
            }) {
                // The action already happened; the caller's request still
                // succeeded — but an operator needs some signal that the
                // closing audit write failed, so it doesn't vanish silently.
                tracing::warn!(error = %e, evidence_id = %evidence_id, "post-execution audit log write failed after CollectEvidence succeeded");
            }
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "dry_run": false,
                    "evidence_id": evidence_id,
                    "event_count": event_count,
                    "truncated": truncated,
                })),
            ))
        }
        Ok(ResponseOutcome::Rejected { reason }) => {
            if let Err(e) = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: original_target.clone(),
                why: Some(reason.clone()),
                result: AuditResult::Failure,
            }) {
                tracing::warn!(error = %e, "post-execution audit log write failed after a Rejected outcome");
            }
            Ok((
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({ "error": "not_implemented", "message": reason })),
            ))
        }
        Err(ResponseError::UnknownTarget(_)) => {
            if let Err(e) = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: original_target,
                why: Some("target does not resolve to any known data".to_string()),
                result: AuditResult::Failure,
            }) {
                tracing::warn!(error = %e, "post-execution audit log write failed after an UnknownTarget error");
            }
            Err((StatusCode::BAD_REQUEST, "target does not resolve to any known data".to_string()))
        }
        Err(e) => {
            if let Err(write_err) = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id: ctx.user_id },
                what,
                target: EntityRef::Domain { name: "response-engine-internal-error".to_string() },
                why: Some(e.to_string()),
                result: AuditResult::Failure,
            }) {
                tracing::warn!(error = %write_err, "post-execution audit log write failed after an internal dispatch() error");
            }
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

    fn last_audit_entry(dir: &std::path::Path) -> osiris_audit::AuditEntry {
        let log = FileAuditLog::open(dir.join("audit.jsonl")).unwrap();
        log.read_all().unwrap().pop().expect("expected at least one audit entry")
    }

    /// Test-only `AuditLog` wrapper that fails the Nth `append` call and
    /// delegates every other call to a real `FileAuditLog` — used to prove
    /// Fix 4's fail-closed behavior for the pre-execution write, and its
    /// fail-open (but logged) behavior for the post-execution write.
    struct FailingAfterNAuditLog {
        inner: FileAuditLog,
        fail_at_call: u32,
        call_count: std::sync::atomic::AtomicU32,
    }

    impl AuditLog for FailingAfterNAuditLog {
        fn append(&self, entry: NewAuditEntry) -> Result<osiris_audit::AuditEntry, osiris_audit::AuditLogError> {
            let n = self.call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if n == self.fail_at_call {
                return Err(osiris_audit::AuditLogError::Write(std::io::Error::other(
                    "simulated audit log failure",
                )));
            }
            self.inner.append(entry)
        }
        fn read_all(&self) -> Result<Vec<osiris_audit::AuditEntry>, osiris_audit::AuditLogError> {
            self.inner.read_all()
        }
        fn verify_chain(&self) -> Result<(), osiris_audit::AuditLogError> {
            self.inner.verify_chain()
        }
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

        // Fix 3: the single entry's `why` carries the real preview text,
        // not the operator's `reason`, and its result reflects success.
        let entry = last_audit_entry(dir.path());
        let preview_text = resp["preview"].as_str().unwrap().to_string();
        assert_eq!(entry.why.as_deref(), Some(preview_text.as_str()));
        assert!(entry.why.as_ref().unwrap().contains("collect evidence for"));
        assert_eq!(entry.result, AuditResult::Success);
    }

    #[tokio::test]
    async fn a_dry_run_against_an_unresolvable_target_writes_one_failure_entry_and_returns_400() {
        let (dir, state) = test_state();
        // No events written — the target never resolves to anything.
        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "never-seen-in-dry-run.example".to_string() },
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        let err = response_handler(State(state), Extension(ctx()), Path("collect_evidence".to_string()), Json(body))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(count_audit_entries(dir.path()), 1);

        let entry = last_audit_entry(dir.path());
        assert_eq!(entry.result, AuditResult::Failure);
        assert!(entry.why.as_deref().unwrap_or("").contains("dry-run failed"));
    }

    #[tokio::test]
    async fn the_audit_what_field_is_the_canonical_action_string_regardless_of_the_raw_path_case() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "case-insensitive.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "case-insensitive.example".to_string() },
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
        };
        // Mixed-case / non-canonical path segment — must not leak into `what`.
        let (status, _resp) = response_handler(
            State(state),
            Extension(ctx()),
            Path("CoLLect_Evidence".to_string()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);

        let entry = last_audit_entry(dir.path());
        assert_eq!(entry.what, "response.COLLECT_EVIDENCE.dry_run");
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

        // Fix 6/7: the response carries event_count/truncated, and the
        // post-execution entry's `why` folds in the operator's own reason
        // plus those two fields (not a literal "collected" constant).
        assert_eq!(resp["event_count"], serde_json::json!(1));
        assert_eq!(resp["truncated"], serde_json::json!(false));
        let entry = last_audit_entry(dir.path());
        let why = entry.why.expect("post-execution entry must have a why");
        assert!(why.starts_with("collecting ("), "why was: {why}");
        assert!(why.contains("event_count=1"));
        assert!(why.contains("truncated=false"));
        assert!(why.contains("evidence_id="));
    }

    #[tokio::test]
    async fn pre_execution_audit_write_failure_prevents_dispatch_and_returns_500() {
        let dir = tempfile::tempdir().unwrap();
        let real_log = FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let failing_log = FailingAfterNAuditLog {
            inner: real_log,
            fail_at_call: 1,
            call_count: std::sync::atomic::AtomicU32::new(0),
        };
        let evidence = Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap());
        let state = ResponseState {
            storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            evidence: evidence.clone(),
            links: Arc::new(SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap()).unwrap()),
            audit_log: Arc::new(failing_log),
        };
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "audit-write-fails.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "audit-write-fails.example".to_string() },
            reason: "collecting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let err = response_handler(State(state), Extension(ctx()), Path("collect_evidence".to_string()), Json(body))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            evidence.list().unwrap().is_empty(),
            "dispatch() must never run when the pre-execution audit write fails"
        );
    }

    #[tokio::test]
    async fn post_execution_audit_write_failure_still_returns_the_successful_result() {
        let dir = tempfile::tempdir().unwrap();
        let real_log = FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let failing_log = FailingAfterNAuditLog {
            inner: real_log,
            fail_at_call: 2,
            call_count: std::sync::atomic::AtomicU32::new(0),
        };
        let evidence = Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap());
        let state = ResponseState {
            storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            evidence: evidence.clone(),
            links: Arc::new(SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap()).unwrap()),
            audit_log: Arc::new(failing_log),
        };
        let host_id = Uuid::new_v4();
        state.storage.write(&dns_event(host_id, "post-write-fails.example")).unwrap();

        let body = ResponseRequestBody {
            target: EntityRef::Domain { name: "post-write-fails.example".to_string() },
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
        // The action already happened (evidence exists); the request still
        // reports success even though the closing audit write failed.
        assert_eq!(status, StatusCode::OK);
        assert!(resp["evidence_id"].is_string());
        assert!(!evidence.list().unwrap().is_empty());
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
