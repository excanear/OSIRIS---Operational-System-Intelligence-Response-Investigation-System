use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_command::CommandAction;
use osiris_evidence::{EvidenceIncidentLinks, EvidenceStore, IncidentStore};
use osiris_response::{
    dispatch, outcome_from_dispatch, resolve_remote_action, ResponseActionKind, ResponseError,
    ResponseOutcome, ResponseRequest,
};
use osiris_schema::EntityRef;
use osiris_storage::Storage;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth_middleware::AuthContext;

#[derive(Clone)]
pub struct ResponseState {
    pub commands: Arc<dyn osiris_response::CommandDispatcher>,
    pub storage: Arc<dyn Storage>,
    pub evidence: Arc<dyn EvidenceStore>,
    pub links: Arc<dyn EvidenceIncidentLinks>,
    pub incidents: Arc<dyn IncidentStore>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
}

pub fn build_response_router(state: ResponseState) -> Router {
    Router::new()
        .route("/api/v1/response/:action", post(response_handler))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct ResponseRequestBody {
    /// Required for every action except `restore_file`.
    #[serde(default)]
    target: Option<EntityRef>,
    reason: String,
    dry_run: bool,
    since: Option<u64>,
    until: Option<u64>,
    incident_id: Option<Uuid>,
    /// `restore_file` only (required there, rejected for every other action).
    #[serde(default)]
    quarantine_id: Option<Uuid>,
    /// `restore_file` only: the host whose vault holds `quarantine_id`.
    #[serde(default)]
    host_id: Option<Uuid>,
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
    tenants: Option<Extension<Arc<dyn osiris_tenancy::TenantStore>>>,
    Path(action_raw): Path<String>,
    Json(body): Json<ResponseRequestBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(action) = parse_action(&action_raw) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("unknown response action: {action_raw}"),
        ));
    };
    if body.reason.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "reason must not be empty".to_string(),
        ));
    }
    let is_remote = matches!(
        action,
        ResponseActionKind::TerminateProcess
            | ResponseActionKind::QuarantineFile
            | ResponseActionKind::RestoreFile
    );
    let restore_target = match (action, body.quarantine_id, body.host_id) {
        (ResponseActionKind::RestoreFile, Some(q), Some(h)) => Some((q, h)),
        (ResponseActionKind::RestoreFile, _, _) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "restore_file requires quarantine_id and host_id".to_string(),
            ));
        }
        (_, None, None) => None,
        _ => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "quarantine_id and host_id are only valid for restore_file".to_string(),
            ));
        }
    };
    let target = match (restore_target, body.target.clone()) {
        (Some(_), Some(_)) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "restore_file must not carry a target".to_string(),
            ));
        }
        // EntityRef has no host/quarantine variant, so the restore audit
        // target is a synthetic Domain encoding `quarantine:<id>@<host>`.
        (Some((q, h)), None) => EntityRef::Domain {
            name: format!("quarantine:{q}@{h}"),
        },
        (None, Some(t)) => t,
        (None, None) => {
            return Err((StatusCode::BAD_REQUEST, "target is required".to_string()));
        }
    };
    let tenants: Option<Arc<dyn osiris_tenancy::TenantStore>> = tenants.map(|Extension(t)| t);

    // A tenant's target resolution and evidence collection only ever see its own
    // hosts' events; a foreign/platform-owned incident answers 404.
    let storage =
        crate::tenant_scope::scoped_storage(state.storage.clone(), ctx.tenant_id, tenants.clone())
            .await?;
    if let (Some(tenant), Some(incident_id)) = (ctx.tenant_id, body.incident_id) {
        let incidents = state.incidents.clone();
        let owned = tokio::task::spawn_blocking(move || incidents.get(incident_id))
            .await
            .unwrap()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .is_some_and(|i| i.tenant_id == Some(tenant));
        if !owned {
            return Err((StatusCode::NOT_FOUND, "incident not found".to_string()));
        }
    }

    let request = ResponseRequest {
        action,
        target,
        reason: body.reason.clone(),
        dry_run: body.dry_run,
        since: body.since,
        until: body.until,
        incident_id: body.incident_id,
        tenant_id: ctx.tenant_id,
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

    if is_remote {
        let remote = RemoteCall {
            state: &state,
            user_id: ctx.user_id,
            tenant_id: ctx.tenant_id,
            tenants,
            storage: storage.clone(),
            request,
            what,
            original_target,
            restore_target,
        };
        return remote.run().await;
    }

    if request.dry_run {
        return local_dry_run(
            &state,
            storage,
            request,
            what,
            ctx.user_id,
            original_target,
            None,
        )
        .await;
    }

    // Real (non-dry-run) execution: this path has genuine side effects, so
    // the pre-execution write's crash-survival argument (spec §4/§13) holds
    // and its failure must fail closed — no destructive or evidence-mutating
    // action may run without a recorded pre-execution audit entry
    // (ARCHITECTURE.md §17.3) (Fix 4).
    if let Err(e) = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User {
            user_id: ctx.user_id,
        },
        what: what.clone(),
        target: request.target.clone(),
        why: Some(request.reason.clone()),
        result: AuditResult::Success,
    }) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit log write failed: {e}"),
        ));
    }

    let storage = storage.clone();
    let evidence = state.evidence.clone();
    let links = state.links.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        dispatch(
            &request,
            storage.as_ref(),
            evidence.as_ref(),
            links.as_ref(),
        )
    })
    .await
    .unwrap();

    match outcome {
        Ok(ResponseOutcome::DryRunPreview { description }) => {
            // Unreachable on the non-dry-run path, but keep the match
            // exhaustive rather than panicking.
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User {
                    user_id: ctx.user_id,
                },
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
        Ok(ResponseOutcome::EvidenceCollected {
            evidence_id,
            event_count,
            truncated,
        }) => {
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
                who: ActorRef::User {
                    user_id: ctx.user_id,
                },
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
        Ok(other) => {
            // Agent-command outcomes are produced only by the remote branch.
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User {
                    user_id: ctx.user_id,
                },
                what,
                target: original_target,
                why: Some(format!("unexpected outcome from dispatch(): {other:?}")),
                result: AuditResult::Failure,
            });
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "unexpected outcome".to_string(),
            ))
        }
        Err(ResponseError::UnknownTarget(_)) => {
            if let Err(e) = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User {
                    user_id: ctx.user_id,
                },
                what,
                target: original_target,
                why: Some("target does not resolve to any known data".to_string()),
                result: AuditResult::Failure,
            }) {
                tracing::warn!(error = %e, "post-execution audit log write failed after an UnknownTarget error");
            }
            Err((
                StatusCode::BAD_REQUEST,
                "target does not resolve to any known data".to_string(),
            ))
        }
        Err(e) => {
            if let Err(write_err) = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User {
                    user_id: ctx.user_id,
                },
                what,
                target: EntityRef::Domain {
                    name: "response-engine-internal-error".to_string(),
                },
                why: Some(e.to_string()),
                result: AuditResult::Failure,
            }) {
                tracing::warn!(error = %write_err, "post-execution audit log write failed after an internal dispatch() error");
            }
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Server-side dry-run preview (no Agent involved). `agent_validated` is
/// `Some(false)` when an Agent-backed action fell back to this preview.
async fn local_dry_run(
    state: &ResponseState,
    storage: Arc<dyn Storage>,
    request: ResponseRequest,
    what: String,
    user_id: Uuid,
    original_target: EntityRef,
    agent_validated: Option<bool>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    // Dry-run has no side effects to protect via a pre-write — nothing
    // is mutated, so there is no crash-survival argument for writing
    // before `dispatch()` runs (unlike the real-execution path below).
    // Exactly one audit entry is written, after the outcome is known,
    // so its `why`/`result` reflect what actually happened rather than
    // the operator's a-priori justification (Fix 3).
    let evidence = state.evidence.clone();
    let links = state.links.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        dispatch(
            &request,
            storage.as_ref(),
            evidence.as_ref(),
            links.as_ref(),
        )
    })
    .await
    .unwrap();

    match outcome {
        Ok(ResponseOutcome::DryRunPreview { description }) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id },
                what,
                target: original_target,
                why: Some(description.clone()),
                result: AuditResult::Success,
            });
            let mut json = serde_json::json!({ "dry_run": true, "preview": description });
            if let Some(validated) = agent_validated {
                json["agent_validated"] = serde_json::json!(validated);
            }
            Ok((StatusCode::OK, Json(json)))
        }
        Ok(other) => {
            // dispatch()'s dry-run branch only ever returns
            // DryRunPreview or Err; this arm exists solely so the match
            // stays exhaustive if that ever changes.
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id },
                what,
                target: original_target,
                why: Some(format!("dry-run returned an unexpected outcome: {other:?}")),
                result: AuditResult::Failure,
            });
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "unexpected dry-run outcome".to_string(),
            ))
        }
        Err(ResponseError::UnknownTarget(_)) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id },
                what,
                target: original_target,
                why: Some("dry-run failed: target does not resolve to any known data".to_string()),
                result: AuditResult::Failure,
            });
            Err((
                StatusCode::BAD_REQUEST,
                "target does not resolve to any known data".to_string(),
            ))
        }
        Err(e) => {
            let _ = state.audit_log.append(NewAuditEntry {
                who: ActorRef::User { user_id },
                what,
                target: original_target,
                why: Some(format!("dry-run failed: {e}")),
                result: AuditResult::Failure,
            });
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

type HandlerResult = Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)>;

/// The HTTP rendering of one `ResponseOutcome`.
struct Mapped {
    status: StatusCode,
    body: serde_json::Value,
    result: AuditResult,
    why: String,
}

fn map_outcome(outcome: ResponseOutcome, dry_run: bool) -> Mapped {
    let err = |status: StatusCode, code: &str, message: &str, why: String| Mapped {
        status,
        body: serde_json::json!({ "error": code, "message": message }),
        result: AuditResult::Failure,
        why,
    };
    match outcome {
        ResponseOutcome::Executed {
            detail,
            quarantine_id,
        } => Mapped {
            status: StatusCode::OK,
            body: serde_json::json!({
                "dry_run": dry_run,
                "ok": true,
                "detail": detail,
                "quarantine_id": quarantine_id,
            }),
            result: AuditResult::Success,
            why: detail,
        },
        ResponseOutcome::DryRunPreview { description } => Mapped {
            status: StatusCode::OK,
            body: serde_json::json!({
                "dry_run": true,
                "agent_validated": true,
                "preview": description,
            }),
            result: AuditResult::Success,
            why: description,
        },
        ResponseOutcome::ExecutionFailed { code, message } => Mapped {
            status: StatusCode::OK,
            body: serde_json::json!({
                "dry_run": dry_run,
                "ok": false,
                "code": code,
                "message": message,
            }),
            result: AuditResult::Failure,
            why: format!("execution failed: {code}: {message}"),
        },
        ResponseOutcome::Refused { reason } => err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused",
            &reason,
            format!("agent refused the command: {reason}"),
        ),
        ResponseOutcome::TimedOut => err(
            StatusCode::GATEWAY_TIMEOUT,
            "timed_out",
            "no result was received from the agent in time; the outcome is unknown and the command may still execute",
            "outcome unknown: no result received from the agent in time; the command may still execute"
                .to_string(),
        ),
        ResponseOutcome::AgentOffline => err(
            StatusCode::CONFLICT,
            "agent_offline",
            "the host's agent has no control connection",
            "agent offline: command not sent".to_string(),
        ),
        ResponseOutcome::ControlDisabled => err(
            StatusCode::CONFLICT,
            "control_disabled",
            "the command channel is not enabled on this server",
            "command channel disabled: command not sent".to_string(),
        ),
        other => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected_outcome",
            "unexpected outcome for an agent command",
            format!("unexpected outcome: {other:?}"),
        ),
    }
}

/// One Agent-backed request (`TerminateProcess`/`QuarantineFile`/`RestoreFile`).
struct RemoteCall<'a> {
    state: &'a ResponseState,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
    tenants: Option<Arc<dyn osiris_tenancy::TenantStore>>,
    storage: Arc<dyn Storage>,
    request: ResponseRequest,
    what: String,
    original_target: EntityRef,
    restore_target: Option<(Uuid, Uuid)>,
}

impl RemoteCall<'_> {
    fn audit(&self, why: String, result: AuditResult) -> Result<(), osiris_audit::AuditLogError> {
        self.state
            .audit_log
            .append(NewAuditEntry {
                who: ActorRef::User {
                    user_id: self.user_id,
                },
                what: self.what.clone(),
                target: self.original_target.clone(),
                why: Some(why),
                result,
            })
            .map(|_| ())
    }

    /// The reason, plus the ids for restore (which has no event-derived
    /// target to show in the audit entry).
    fn base_why(&self) -> String {
        match self.restore_target {
            Some((q, h)) => format!("{} (quarantine_id={q}, host_id={h})", self.request.reason),
            None => self.request.reason.clone(),
        }
    }

    fn audit_or_warn(&self, why: String, result: AuditResult) {
        if let Err(e) = self.audit(why, result) {
            tracing::warn!(error = %e, "post-execution audit log write failed after an agent command");
        }
    }

    /// Resolves the addressee host and command. A tenant user only ever
    /// sees its own hosts, so anything else is a 404.
    async fn resolve(&self) -> Result<(Uuid, CommandAction), (StatusCode, String)> {
        if let Some((quarantine_id, host_id)) = self.restore_target {
            if let Some(tenant) = self.tenant_id {
                let Some(store) = self.tenants.clone() else {
                    return Err((StatusCode::NOT_FOUND, "host not found".to_string()));
                };
                let owner = tokio::task::spawn_blocking(move || store.tenant_of(host_id))
                    .await
                    .unwrap()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                if owner != Some(tenant) {
                    return Err((StatusCode::NOT_FOUND, "host not found".to_string()));
                }
            }
            return Ok((host_id, CommandAction::RestoreFile { quarantine_id }));
        }
        let storage = self.storage.clone();
        let request = self.request.clone();
        let resolved =
            tokio::task::spawn_blocking(move || resolve_remote_action(&request, storage.as_ref()))
                .await
                .unwrap();
        match resolved {
            Ok(v) => Ok(v),
            Err(ResponseError::UnknownTarget(_)) => {
                self.audit_or_warn(
                    "target does not resolve to any known data".to_string(),
                    AuditResult::Failure,
                );
                // Tenant users get 404 (not 400) so a foreign host is
                // indistinguishable from an unknown one (anti-enumeration).
                if self.tenant_id.is_some() {
                    Err((StatusCode::NOT_FOUND, "target not found".to_string()))
                } else {
                    Err((
                        StatusCode::BAD_REQUEST,
                        "target does not resolve to any known data".to_string(),
                    ))
                }
            }
            Err(e) => {
                self.audit_or_warn(
                    format!("target resolution failed: {e}"),
                    AuditResult::Failure,
                );
                Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }
        }
    }

    async fn send(
        &self,
        host: Uuid,
        action: CommandAction,
    ) -> Result<ResponseOutcome, (StatusCode, String)> {
        let result = self
            .state
            .commands
            .dispatch(
                host,
                action,
                self.request.dry_run,
                format!("user:{}", self.user_id),
                self.request.reason.clone(),
            )
            .await;
        outcome_from_dispatch(result).map_err(|m| {
            tracing::warn!(error = %m, "agent command dispatch failed");
            (
                StatusCode::BAD_GATEWAY,
                "command dispatch failed".to_string(),
            )
        })
    }

    async fn run(self) -> HandlerResult {
        let (host, action) = self.resolve().await?;
        if self.request.dry_run {
            self.run_dry(host, action).await
        } else {
            self.run_real(host, action).await
        }
    }

    async fn run_dry(self, host: Uuid, action: CommandAction) -> HandlerResult {
        let outcome = match self.send(host, action).await {
            Ok(o) => o,
            Err((status, msg)) => {
                self.audit_or_warn(format!("dry-run failed: {msg}"), AuditResult::Failure);
                return Ok((
                    status,
                    Json(serde_json::json!({ "error": "dispatch_failed", "message": msg })),
                ));
            }
        };
        if matches!(
            outcome,
            ResponseOutcome::AgentOffline | ResponseOutcome::ControlDisabled
        ) {
            // No Agent to validate with: today's server-side preview.
            // Disabled also yields a 200 preview by design (spec 5.6).
            if let Some((q, h)) = self.restore_target {
                let preview = format!(
                    "would restore quarantined file {q} on host {h} (agent not consulted) - no action taken, dry run",
                );
                self.audit_or_warn(preview.clone(), AuditResult::Success);
                return Ok((
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "dry_run": true,
                        "agent_validated": false,
                        "preview": preview,
                    })),
                ));
            }
            return local_dry_run(
                self.state,
                self.storage,
                self.request,
                self.what,
                self.user_id,
                self.original_target,
                Some(false),
            )
            .await;
        }
        let m = map_outcome(outcome, true);
        let why = if m.status == StatusCode::OK && m.result == AuditResult::Success {
            m.why.clone()
        } else {
            format!("dry-run: {}", m.why)
        };
        self.audit_or_warn(why, m.result);
        Ok((m.status, Json(m.body)))
    }

    async fn run_real(self, host: Uuid, action: CommandAction) -> HandlerResult {
        // Fail closed: no destructive command is sent without a recorded
        // pre-execution audit entry (ARCHITECTURE.md 17.3).
        if let Err(e) = self.audit(self.base_why(), AuditResult::Success) {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("audit log write failed: {e}"),
            ));
        }
        let outcome = match self.send(host, action).await {
            Ok(o) => o,
            Err((status, msg)) => {
                self.audit_or_warn(
                    format!(
                        "{} (dispatch failed: {msg}; outcome unknown)",
                        self.base_why()
                    ),
                    AuditResult::Failure,
                );
                return Ok((
                    status,
                    Json(serde_json::json!({ "error": "dispatch_failed", "message": msg })),
                ));
            }
        };
        let m = map_outcome(outcome, false);
        self.audit_or_warn(format!("{} ({})", self.base_why(), m.why), m.result);
        Ok((m.status, Json(m.body)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::FileAuditLog;
    use osiris_command::{CommandAction, CommandResult};
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore};
    use osiris_response::DispatchError;
    use osiris_schema::{
        CanonicalEvent, Category, DnsRef, EventType, HostRef, Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use osiris_tenancy::TenantStore;

    fn test_state() -> (tempfile::TempDir, ResponseState) {
        test_state_with(Arc::new(osiris_response::DisabledDispatcher))
    }

    fn test_state_with(
        commands: Arc<dyn osiris_response::CommandDispatcher>,
    ) -> (tempfile::TempDir, ResponseState) {
        let dir = tempfile::tempdir().unwrap();
        let state = ResponseState {
            commands,
            storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            evidence: Arc::new(
                SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap())
                    .unwrap(),
            ),
            links: Arc::new(
                SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap())
                    .unwrap(),
            ),
            incidents: Arc::new(
                osiris_evidence::SqliteIncidentStore::open(dir.path().join("incidents.db"))
                    .unwrap(),
            ),
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
            dns: Some(DnsRef {
                query: query.to_string(),
                qtype: "A".to_string(),
                response_ips: vec![],
                ttl: None,
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

    fn ctx() -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::ResponseOperator,
            token: "t".to_string(),
            tenant_id: None,
        }
    }

    fn count_audit_entries(dir: &std::path::Path) -> usize {
        let log = FileAuditLog::open(dir.join("audit.jsonl")).unwrap();
        log.read_all().unwrap().len()
    }

    fn last_audit_entry(dir: &std::path::Path) -> osiris_audit::AuditEntry {
        let log = FileAuditLog::open(dir.join("audit.jsonl")).unwrap();
        log.read_all()
            .unwrap()
            .pop()
            .expect("expected at least one audit entry")
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
        fn append(
            &self,
            entry: NewAuditEntry,
        ) -> Result<osiris_audit::AuditEntry, osiris_audit::AuditLogError> {
            let n = self
                .call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
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
        state
            .storage
            .write(&dns_event(host_id, "audit-dry-run.example"))
            .unwrap();

        let body = ResponseRequestBody {
            target: Some(EntityRef::Domain {
                name: "audit-dry-run.example".to_string(),
            }),
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            None,
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
            target: Some(EntityRef::Domain {
                name: "never-seen-in-dry-run.example".to_string(),
            }),
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let err = response_handler(
            State(state),
            Extension(ctx()),
            None,
            Path("collect_evidence".to_string()),
            Json(body),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(count_audit_entries(dir.path()), 1);

        let entry = last_audit_entry(dir.path());
        assert_eq!(entry.result, AuditResult::Failure);
        assert!(entry
            .why
            .as_deref()
            .unwrap_or("")
            .contains("dry-run failed"));
    }

    #[tokio::test]
    async fn the_audit_what_field_is_the_canonical_action_string_regardless_of_the_raw_path_case() {
        let (dir, state) = test_state();
        let host_id = Uuid::new_v4();
        state
            .storage
            .write(&dns_event(host_id, "case-insensitive.example"))
            .unwrap();

        let body = ResponseRequestBody {
            target: Some(EntityRef::Domain {
                name: "case-insensitive.example".to_string(),
            }),
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        // Mixed-case / non-canonical path segment — must not leak into `what`.
        let (status, _resp) = response_handler(
            State(state),
            Extension(ctx()),
            None,
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
        state
            .storage
            .write(&dns_event(host_id, "audit-execute.example"))
            .unwrap();

        let body = ResponseRequestBody {
            target: Some(EntityRef::Domain {
                name: "audit-execute.example".to_string(),
            }),
            reason: "collecting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            None,
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
        let evidence = Arc::new(
            SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap(),
        );
        let state = ResponseState {
            commands: Arc::new(osiris_response::DisabledDispatcher),
            storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            evidence: evidence.clone(),
            links: Arc::new(
                SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap())
                    .unwrap(),
            ),
            incidents: Arc::new(
                osiris_evidence::SqliteIncidentStore::open(dir.path().join("incidents.db"))
                    .unwrap(),
            ),
            audit_log: Arc::new(failing_log),
        };
        let host_id = Uuid::new_v4();
        state
            .storage
            .write(&dns_event(host_id, "audit-write-fails.example"))
            .unwrap();

        let body = ResponseRequestBody {
            target: Some(EntityRef::Domain {
                name: "audit-write-fails.example".to_string(),
            }),
            reason: "collecting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let err = response_handler(
            State(state),
            Extension(ctx()),
            None,
            Path("collect_evidence".to_string()),
            Json(body),
        )
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
        let evidence = Arc::new(
            SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap(),
        );
        let state = ResponseState {
            commands: Arc::new(osiris_response::DisabledDispatcher),
            storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            evidence: evidence.clone(),
            links: Arc::new(
                SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap())
                    .unwrap(),
            ),
            incidents: Arc::new(
                osiris_evidence::SqliteIncidentStore::open(dir.path().join("incidents.db"))
                    .unwrap(),
            ),
            audit_log: Arc::new(failing_log),
        };
        let host_id = Uuid::new_v4();
        state
            .storage
            .write(&dns_event(host_id, "post-write-fails.example"))
            .unwrap();

        let body = ResponseRequestBody {
            target: Some(EntityRef::Domain {
                name: "post-write-fails.example".to_string(),
            }),
            reason: "collecting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            None,
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
        state
            .storage
            .write(&dns_event(host_id, "audit-destructive.example"))
            .unwrap();

        let body = ResponseRequestBody {
            target: Some(EntityRef::Domain {
                name: "audit-destructive.example".to_string(),
            }),
            reason: "attempting".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let (status, Json(resp)) = response_handler(
            State(state),
            Extension(ctx()),
            None,
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
            target: Some(EntityRef::Domain {
                name: "x.example".to_string(),
            }),
            reason: "   ".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let err = response_handler(
            State(state),
            Extension(ctx()),
            None,
            Path("collect_evidence".to_string()),
            Json(body),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(count_audit_entries(dir.path()), 0);
    }

    #[tokio::test]
    async fn an_unknown_action_segment_is_a_404() {
        let (_dir, state) = test_state();
        let body = ResponseRequestBody {
            target: Some(EntityRef::Domain {
                name: "x.example".to_string(),
            }),
            reason: "checking".to_string(),
            dry_run: true,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        };
        let err = response_handler(
            State(state),
            Extension(ctx()),
            None,
            Path("not_a_real_action".to_string()),
            Json(body),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    type Call = (Uuid, CommandAction, bool, String, String);
    type Reply = Box<dyn Fn(bool) -> Result<CommandResult, DispatchError> + Send + Sync>;

    struct FakeDispatcher {
        calls: std::sync::Mutex<Vec<Call>>,
        reply: Reply,
    }

    impl FakeDispatcher {
        fn new(reply: Reply) -> Arc<Self> {
            Arc::new(Self {
                calls: Default::default(),
                reply,
            })
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl osiris_response::CommandDispatcher for FakeDispatcher {
        async fn dispatch(
            &self,
            host_id: Uuid,
            action: CommandAction,
            dry_run: bool,
            actor: String,
            reason: String,
        ) -> Result<CommandResult, DispatchError> {
            self.calls
                .lock()
                .unwrap()
                .push((host_id, action, dry_run, actor, reason));
            (self.reply)(dry_run)
        }
    }

    fn executed(quarantine_id: Option<Uuid>) -> Result<CommandResult, DispatchError> {
        Ok(CommandResult::Executed {
            detail: osiris_command::ExecDetail {
                summary: "done".to_string(),
                quarantine_id,
                sha256: Some("abc123".to_string()),
                signal: Some("SIGKILL".to_string()),
            },
        })
    }

    fn process_event(host_id: Uuid, pid: u32) -> (CanonicalEvent, osiris_schema::ProcessKey) {
        let key = osiris_schema::ProcessKey::new(host_id, "b", pid, 5);
        let mut e = dns_event(host_id, "unused.example");
        e.dns = None;
        e.timestamp = 5000;
        e.process = Some(osiris_schema::ProcessRef {
            process_key: key,
            pid,
            exe_path: "/bin/evil".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 5,
        });
        (e, key)
    }

    fn file_event(host_id: Uuid) -> CanonicalEvent {
        let mut e = dns_event(host_id, "unused.example");
        e.dns = None;
        e.file = Some(osiris_schema::FileRef {
            path: "/tmp/mal".to_string(),
            previous_path: None,
            inode: Some(11),
            device_id: Some(7),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        e
    }

    fn proc_body(key: osiris_schema::ProcessKey, dry_run: bool) -> ResponseRequestBody {
        ResponseRequestBody {
            target: Some(EntityRef::Process { process_key: key }),
            reason: "contain".to_string(),
            dry_run,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: None,
            host_id: None,
        }
    }

    async fn call(
        state: &ResponseState,
        action: &str,
        body: ResponseRequestBody,
    ) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
        response_handler(
            State(state.clone()),
            Extension(ctx()),
            None,
            Path(action.to_string()),
            Json(body),
        )
        .await
    }

    type ProcSetup = (
        tempfile::TempDir,
        ResponseState,
        osiris_schema::ProcessKey,
        Uuid,
    );

    fn setup_process(fake: Arc<FakeDispatcher>) -> ProcSetup {
        let (dir, state) = test_state_with(fake);
        let host = Uuid::new_v4();
        let (e, key) = process_event(host, 42);
        state.storage.write(&e).unwrap();
        (dir, state, key, host)
    }

    #[tokio::test]
    async fn terminate_executed_is_200_with_two_audit_entries_carrying_the_agent_detail() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (dir, state, key, host) = setup_process(fake.clone());
        let (status, Json(resp)) = call(&state, "terminate_process", proc_body(key, false))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["ok"], serde_json::json!(true));
        assert_eq!(count_audit_entries(dir.path()), 2);
        let why = last_audit_entry(dir.path()).why.unwrap();
        assert!(why.contains("signal=SIGKILL"), "{why}");
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, host);
        assert!(!calls[0].2);
        assert_eq!(
            calls[0].1,
            CommandAction::TerminateProcess {
                pid: 42,
                exe_path: "/bin/evil".to_string(),
                observed_at_ns: 5000
            }
        );
    }

    #[tokio::test]
    async fn quarantine_returns_the_quarantine_id() {
        let qid = Uuid::new_v4();
        let fake = FakeDispatcher::new(Box::new(move |_| executed(Some(qid))));
        let (dir, state) = test_state_with(fake.clone());
        let host = Uuid::new_v4();
        state.storage.write(&file_event(host)).unwrap();
        let mut b = proc_body(osiris_schema::ProcessKey::new(host, "b", 1, 1), false);
        b.target = Some(EntityRef::File {
            host_id: host,
            inode: 11,
            device_id: 7,
        });
        let (status, Json(resp)) = call(&state, "quarantine_file", b).await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["quarantine_id"], serde_json::json!(qid));
        assert!(last_audit_entry(dir.path())
            .why
            .unwrap()
            .contains(&qid.to_string()));
    }

    #[tokio::test]
    async fn agent_failure_is_200_ok_false_with_the_code() {
        let fake = FakeDispatcher::new(Box::new(|_| {
            Ok(CommandResult::Failed {
                code: osiris_command::FailCode::TargetChanged,
                message: "pid reused".to_string(),
            })
        }));
        let (dir, state, key, _) = setup_process(fake);
        let (status, Json(resp)) = call(&state, "terminate_process", proc_body(key, false))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["ok"], serde_json::json!(false));
        assert_eq!(resp["code"], serde_json::json!("TargetChanged"));
        let e = last_audit_entry(dir.path());
        assert_eq!(e.result, AuditResult::Failure);
        assert!(e.why.unwrap().contains("TargetChanged"));
    }

    async fn status_of(reply: Reply, expect_error: &str) -> (StatusCode, tempfile::TempDir) {
        let fake = FakeDispatcher::new(reply);
        let (dir, state, key, _) = setup_process(fake);
        let (status, Json(resp)) = call(&state, "terminate_process", proc_body(key, false))
            .await
            .unwrap();
        assert_eq!(resp["error"], serde_json::json!(expect_error));
        (status, dir)
    }

    #[tokio::test]
    async fn dispatch_errors_map_to_http_statuses() {
        let (s, _) = status_of(Box::new(|_| Err(DispatchError::Offline)), "agent_offline").await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, dir) = status_of(Box::new(|_| Err(DispatchError::TimedOut)), "timed_out").await;
        assert_eq!(s, StatusCode::GATEWAY_TIMEOUT);
        let why = last_audit_entry(dir.path()).why.unwrap();
        assert!(why.contains("unknown"), "{why}");
        assert!(!why.contains("not executed"), "{why}");
        let (s, _) = status_of(
            Box::new(|_| {
                Ok(CommandResult::Refused {
                    reason: osiris_command::Refusal::Replay,
                })
            }),
            "refused",
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        let (s, _) = status_of(
            Box::new(|_| Err(DispatchError::Disabled)),
            "control_disabled",
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, _) = status_of(
            Box::new(|_| Err(DispatchError::Failed("boom".into()))),
            "dispatch_failed",
        )
        .await;
        assert_eq!(s, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn pre_execution_audit_failure_is_500_and_the_agent_is_never_called() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (_d, mut state) = test_state_with(fake.clone());
        state.audit_log = Arc::new(FailingAfterNAuditLog {
            inner: FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
            fail_at_call: 1,
            call_count: std::sync::atomic::AtomicU32::new(0),
        });
        let host = Uuid::new_v4();
        let (e, key) = process_event(host, 42);
        state.storage.write(&e).unwrap();
        let err = call(&state, "terminate_process", proc_body(key, false))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn dry_run_uses_the_agent_when_online() {
        let fake = FakeDispatcher::new(Box::new(|dry| {
            assert!(dry);
            Ok(CommandResult::DryRunOk {
                would_do: "would kill 42".to_string(),
            })
        }));
        let (dir, state, key, _) = setup_process(fake.clone());
        let (status, Json(resp)) = call(&state, "terminate_process", proc_body(key, true))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["agent_validated"], serde_json::json!(true));
        assert_eq!(resp["preview"], serde_json::json!("would kill 42"));
        assert_eq!(fake.call_count(), 1);
        assert_eq!(count_audit_entries(dir.path()), 1);
    }

    #[tokio::test]
    async fn dry_run_falls_back_to_the_server_preview_when_offline() {
        let fake = FakeDispatcher::new(Box::new(|_| Err(DispatchError::Offline)));
        let (dir, state, key, _) = setup_process(fake);
        let (status, Json(resp)) = call(&state, "terminate_process", proc_body(key, true))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["agent_validated"], serde_json::json!(false));
        assert!(resp["preview"]
            .as_str()
            .unwrap()
            .contains("would terminate"));
        assert_eq!(count_audit_entries(dir.path()), 1);
    }

    #[tokio::test]
    async fn the_four_non_activated_actions_are_still_501() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (_dir, state) = test_state_with(fake.clone());
        let host = Uuid::new_v4();
        state.storage.write(&dns_event(host, "x.example")).unwrap();
        for action in [
            "stop_service",
            "block_indicator",
            "isolate_network",
            "disable_persistence",
        ] {
            let mut b = proc_body(osiris_schema::ProcessKey::new(host, "b", 1, 1), false);
            b.target = Some(EntityRef::Domain {
                name: "x.example".to_string(),
            });
            let (status, _) = call(&state, action, b).await.unwrap();
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{action}");
        }
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn a_tenant_user_cannot_address_another_tenants_host() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (dir, state, key, _host) = setup_process(fake.clone());
        let tenants = osiris_tenancy::SqliteTenantStore::open(dir.path().join("t.db")).unwrap();
        let mine = tenants.create_tenant("mine").unwrap();
        // The host belongs to nobody in `mine`.
        let store: Arc<dyn osiris_tenancy::TenantStore> = Arc::new(tenants);
        let mut c = ctx();
        c.tenant_id = Some(mine.tenant_id);
        let err = response_handler(
            State(state),
            Extension(c),
            Some(Extension(store)),
            Path("terminate_process".to_string()),
            Json(proc_body(key, false)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn restore_requires_quarantine_id_and_host_id() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (_dir, state) = test_state_with(fake.clone());
        let mut b = proc_body(
            osiris_schema::ProcessKey::new(Uuid::new_v4(), "b", 1, 1),
            false,
        );
        b.target = None;
        let err = call(&state, "restore_file", b).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn restore_ids_are_rejected_for_other_actions() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (_dir, state, key, _) = setup_process(fake.clone());
        let mut b = proc_body(key, false);
        b.quarantine_id = Some(Uuid::new_v4());
        let err = call(&state, "terminate_process", b).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(fake.call_count(), 0);
    }

    #[tokio::test]
    async fn restore_dispatches_a_restore_command_to_the_given_host() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (dir, state) = test_state_with(fake.clone());
        let host = Uuid::new_v4();
        let qid = Uuid::new_v4();
        let b = ResponseRequestBody {
            target: None,
            reason: "false positive".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: Some(qid),
            host_id: Some(host),
        };
        let (status, _) = call(&state, "restore_file", b).await.unwrap();
        assert_eq!(status, StatusCode::OK);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[0].0, host);
        assert_eq!(
            calls[0].1,
            CommandAction::RestoreFile { quarantine_id: qid }
        );
        assert_eq!(count_audit_entries(dir.path()), 2);
    }

    #[tokio::test]
    async fn restore_with_a_client_target_is_422_and_ids_appear_in_the_audit_why() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (dir, state) = test_state_with(fake.clone());
        let (host, qid) = (Uuid::new_v4(), Uuid::new_v4());
        let mk = |target| ResponseRequestBody {
            target,
            reason: "fp".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: Some(qid),
            host_id: Some(host),
        };
        let err = call(
            &state,
            "restore_file",
            mk(Some(EntityRef::Domain {
                name: "spoof.example".to_string(),
            })),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(fake.call_count(), 0);
        call(&state, "restore_file", mk(None)).await.unwrap();
        let e = last_audit_entry(dir.path());
        let why = e.why.unwrap();
        assert!(why.contains(&qid.to_string()) && why.contains(&host.to_string()));
    }

    #[tokio::test]
    async fn a_tenant_user_restoring_on_a_foreign_host_is_404() {
        let fake = FakeDispatcher::new(Box::new(|_| executed(None)));
        let (dir, state) = test_state_with(fake.clone());
        let tenants = osiris_tenancy::SqliteTenantStore::open(dir.path().join("t.db")).unwrap();
        let mine = tenants.create_tenant("mine").unwrap();
        let store: Arc<dyn osiris_tenancy::TenantStore> = Arc::new(tenants);
        let mut c = ctx();
        c.tenant_id = Some(mine.tenant_id);
        let b = ResponseRequestBody {
            target: None,
            reason: "fp".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            quarantine_id: Some(Uuid::new_v4()),
            host_id: Some(Uuid::new_v4()),
        };
        let err = response_handler(
            State(state),
            Extension(c),
            Some(Extension(store)),
            Path("restore_file".to_string()),
            Json(b),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn the_response_router_merges_without_a_route_collision() {
        let (_dir, state) = test_state();
        let storage_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(storage_dir.path().join("events.db")).unwrap());
        let merged: Router =
            crate::build_router(storage).merge(crate::build_response_router(state));
        let _ = std::hint::black_box(merged);
    }
}
