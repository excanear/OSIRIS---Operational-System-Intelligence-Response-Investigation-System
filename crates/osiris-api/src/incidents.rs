use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog};
use osiris_evidence::{
    EvidenceIncidentLinks, EvidenceStore, Incident, IncidentStatus, IncidentStore,
};
use osiris_schema::EntityRef;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth_middleware::AuthContext;

/// Whether a record owned by `owner` is visible to a caller in `caller`'s
/// tenant. Platform callers (`None`) see everything; a tenant caller sees only
/// its own records — platform-owned (`None`) records are invisible to it.
pub(crate) fn visible_to(owner: Option<Uuid>, caller: Option<Uuid>) -> bool {
    caller.is_none() || owner == caller
}

#[derive(Clone)]
pub struct IncidentEvidenceState {
    pub incidents: Arc<dyn IncidentStore>,
    pub evidence: Arc<dyn EvidenceStore>,
    pub links: Arc<dyn EvidenceIncidentLinks>,
    /// The shared event store; a tenant caller only ever sees it through a
    /// `TenantScopedStorage` (to validate the entities it references).
    pub storage: Arc<dyn osiris_storage::Storage>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
}

pub fn build_incident_evidence_router(state: IncidentEvidenceState) -> Router {
    Router::new()
        .route(
            "/api/v1/incidents",
            get(list_incidents_handler).post(create_incident_handler),
        )
        .route(
            "/api/v1/incidents/:incident_id",
            get(get_incident_handler).patch(patch_incident_handler),
        )
        .route(
            "/api/v1/evidence",
            get(crate::evidence::list_evidence_handler)
                .post(crate::evidence::create_evidence_handler),
        )
        .with_state(state)
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateIncidentBody {
    pub entities: Vec<EntityRef>,
}

fn not_found() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "incident not found".to_string())
}

/// Loads an incident the caller may see; foreign/platform-owned ones answer
/// exactly like a missing one (no existence oracle across tenants).
pub(crate) async fn visible_incident(
    state: &IncidentEvidenceState,
    incident_id: Uuid,
    caller: Option<Uuid>,
) -> Result<Incident, (StatusCode, String)> {
    let incidents = state.incidents.clone();
    let incident = tokio::task::spawn_blocking(move || incidents.get(incident_id))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(not_found)?;
    if visible_to(incident.tenant_id, caller) {
        Ok(incident)
    } else {
        Err(not_found())
    }
}

async fn create_incident_handler(
    State(state): State<IncidentEvidenceState>,
    Extension(ctx): Extension<AuthContext>,
    tenants: Option<Extension<Arc<dyn osiris_tenancy::TenantStore>>>,
    Json(body): Json<CreateIncidentBody>,
) -> Result<Json<Incident>, (StatusCode, String)> {
    if ctx.tenant_id.is_some() {
        let scoped = crate::tenant_scope::scoped_storage(
            state.storage.clone(),
            ctx.tenant_id,
            tenants.map(|Extension(t)| t),
        )
        .await?;
        crate::tenant_scope::ensure_entities_in_scope(scoped, body.entities.clone()).await?;
    }
    let incident = Incident {
        incident_id: Uuid::now_v7(),
        status: IncidentStatus::New,
        entities: body.entities,
        alert_ids: vec![],
        notes: vec![],
        tenant_id: ctx.tenant_id,
    };
    let created = tokio::task::spawn_blocking(move || state.incidents.create(incident))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(created))
}

fn parse_incident_id(raw: &str) -> Result<Uuid, (StatusCode, String)> {
    raw.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid incident_id: {}", raw),
        )
    })
}

async fn get_incident_handler(
    State(state): State<IncidentEvidenceState>,
    Extension(ctx): Extension<AuthContext>,
    Path(incident_id): Path<String>,
) -> Result<Json<Incident>, (StatusCode, String)> {
    let incident_id = parse_incident_id(&incident_id)?;
    Ok(Json(
        visible_incident(&state, incident_id, ctx.tenant_id).await?,
    ))
}

async fn list_incidents_handler(
    State(state): State<IncidentEvidenceState>,
    Extension(ctx): Extension<AuthContext>,
) -> Json<Vec<Incident>> {
    let caller = ctx.tenant_id;
    let incidents = tokio::task::spawn_blocking(move || match caller {
        Some(tenant) => state.incidents.list_for_tenant(tenant),
        None => state.incidents.list(),
    })
    .await
    .unwrap()
    .unwrap_or_default();
    Json(incidents)
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchIncidentBody {
    pub status: IncidentStatus,
    pub why: Option<String>,
}

async fn patch_incident_handler(
    State(state): State<IncidentEvidenceState>,
    Extension(ctx): Extension<AuthContext>,
    Path(incident_id): Path<String>,
    Json(body): Json<PatchIncidentBody>,
) -> Result<Json<Incident>, (StatusCode, String)> {
    let incident_id = parse_incident_id(&incident_id)?;
    visible_incident(&state, incident_id, ctx.tenant_id).await?;
    let updated = tokio::task::spawn_blocking(move || {
        state.incidents.transition_status(
            incident_id,
            body.status,
            ActorRef::User {
                user_id: ctx.user_id,
            },
            body.why,
            state.audit_log.as_ref(),
        )
    })
    .await
    .unwrap();
    match updated {
        Ok(incident) => Ok(Json(incident)),
        Err(osiris_evidence::IncidentStoreError::NotFound) => Err(not_found()),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform_ctx() -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::Admin,
            token: "t".to_string(),
            tenant_id: None,
        }
    }
    use osiris_audit::FileAuditLog;
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
    use osiris_schema::EntityRef;

    fn test_state() -> (tempfile::TempDir, IncidentEvidenceState) {
        let dir = tempfile::tempdir().unwrap();
        let state = IncidentEvidenceState {
            incidents: Arc::new(
                SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap(),
            ),
            evidence: Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap()),
            links: Arc::new(
                SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap(),
            ),
            storage: Arc::new(osiris_storage_sqlite::SqliteStorage::open(dir.path().join("events.db")).unwrap()),
            audit_log: Arc::new(FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
        };
        (dir, state)
    }

    /// `osiris-server`'s `main` composes the whole HTTP surface as
    /// `build_router(storage).merge(build_incident_evidence_router(state))`.
    /// axum panics on a route collision at merge time, so this is a fast
    /// regression guard for that composition (e.g. after an axum/matchit
    /// bump) without waiting for the slow e2e suite. It deliberately does
    /// not bind a socket or issue a request — building the merged Router is
    /// the thing that can panic.
    #[test]
    fn the_two_routers_merge_without_a_route_collision() {
        let (_dir, state) = test_state();
        let storage_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn osiris_storage::Storage> = Arc::new(
            osiris_storage_sqlite::SqliteStorage::open(storage_dir.path().join("events.db"))
                .unwrap(),
        );
        let merged: Router =
            crate::build_router(storage).merge(crate::build_incident_evidence_router(state));
        // Consume it so the construction cannot be optimized away.
        let _ = std::hint::black_box(merged);
    }

    #[tokio::test]
    async fn create_then_get_incident_round_trips() {
        let (_dir, state) = test_state();
        let body = CreateIncidentBody {
            entities: vec![EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            }],
        };
        let Json(created) =
            create_incident_handler(State(state.clone()), Extension(platform_ctx()), None, Json(body))
                .await
                .unwrap();
        assert_eq!(created.status, IncidentStatus::New);

        let Json(found) = get_incident_handler(
            State(state),
            Extension(platform_ctx()),
            Path(created.incident_id.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(found.incident_id, created.incident_id);
    }

    #[tokio::test]
    async fn list_incidents_returns_every_created_incident() {
        let (_dir, state) = test_state();
        let body = CreateIncidentBody {
            entities: vec![EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            }],
        };
        let _ = create_incident_handler(
            State(state.clone()),
            Extension(platform_ctx()),
            None,
            Json(body.clone()),
        )
        .await
        .unwrap();
        let _ =
            create_incident_handler(State(state.clone()), Extension(platform_ctx()), None, Json(body))
                .await
                .unwrap();
        let Json(list) = list_incidents_handler(State(state), Extension(platform_ctx())).await;
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn patch_incident_transitions_status_and_audits_it() {
        let (_dir, state) = test_state();
        let body = CreateIncidentBody {
            entities: vec![EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            }],
        };
        let Json(created) =
            create_incident_handler(State(state.clone()), Extension(platform_ctx()), None, Json(body))
                .await
                .unwrap();

        let patch = PatchIncidentBody {
            status: IncidentStatus::Investigating,
            why: Some("starting triage".to_string()),
        };
        let Json(updated) = patch_incident_handler(
            State(state),
            Extension(platform_ctx()),
            Path(created.incident_id.to_string()),
            Json(patch),
        )
        .await
        .unwrap();
        assert_eq!(updated.status, IncidentStatus::Investigating);
    }

    #[tokio::test]
    async fn patch_incident_returns_404_for_an_unknown_id() {
        let (_dir, state) = test_state();
        let patch = PatchIncidentBody {
            status: IncidentStatus::Resolved,
            why: None,
        };
        let err = patch_incident_handler(
            State(state),
            Extension(platform_ctx()),
            Path(uuid::Uuid::now_v7().to_string()),
            Json(patch),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
