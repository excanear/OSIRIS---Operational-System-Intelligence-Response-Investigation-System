use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::Json;
use osiris_evidence::{Evidence, EvidenceSource, Integrity};
use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthContext;
use crate::incidents::{visible_incident, visible_to, IncidentEvidenceState};

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEvidenceBody {
    pub source: EvidenceSource,
    pub hash: String,
    pub immutable_since: u64,
    pub relationships: Vec<EntityRef>,
    pub supersedes: Option<Uuid>,
    pub incident_id: Option<Uuid>,
}

pub async fn create_evidence_handler(
    State(state): State<IncidentEvidenceState>,
    Extension(ctx): Extension<AuthContext>,
    tenants: Option<Extension<Arc<dyn osiris_tenancy::TenantStore>>>,
    Json(body): Json<CreateEvidenceBody>,
) -> Result<Json<Evidence>, (StatusCode, String)> {
    let caller = ctx.tenant_id;
    if caller.is_some() {
        let scoped = crate::tenant_scope::scoped_storage(
            state.storage.clone(),
            caller,
            tenants.map(|Extension(t)| t),
        )
        .await?;
        crate::tenant_scope::ensure_entities_in_scope(scoped, body.relationships.clone()).await?;
    }
    let integrity = Integrity {
        hash: body.hash,
        immutable_since: body.immutable_since,
    };
    let evidence = Evidence::new(
        body.source,
        body.immutable_since,
        integrity,
        body.relationships,
        body.supersedes,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    .with_tenant(caller);

    // A tenant may only attach evidence to an incident it can see (a foreign
    // or platform-owned one answers 404, like a missing one).
    if let (Some(_), Some(incident_id)) = (caller, body.incident_id) {
        visible_incident(&state, incident_id, caller).await?;
    }

    // A tenant may only supersede its own evidence.
    if let (Some(_), Some(old_id)) = (caller, body.supersedes) {
        let store = state.evidence.clone();
        let old = tokio::task::spawn_blocking(move || store.get(old_id))
            .await
            .unwrap()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if !old.is_some_and(|o| visible_to(o.tenant_id(), caller)) {
            return Err((
                StatusCode::NOT_FOUND,
                "superseded evidence not found".to_string(),
            ));
        }
    }

    let incident_id = body.incident_id;
    let links = state.links.clone();
    let evidence_store = state.evidence.clone();
    let created = tokio::task::spawn_blocking(move || -> Result<Evidence, String> {
        let created = evidence_store.insert(evidence).map_err(|e| e.to_string())?;
        if let Some(incident_id) = incident_id {
            links
                .link(incident_id, created.evidence_id())
                .map_err(|e| e.to_string())?;
        }
        Ok(created)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(created))
}

#[derive(Debug, Deserialize)]
pub struct ListEvidenceQuery {
    pub incident_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceWithIncidents {
    pub evidence: Evidence,
    pub incident_ids: Vec<Uuid>,
}

/// `#[serde(untagged)]` means each variant serializes as its inner value
/// directly — a plain JSON array either way. This keeps the existing
/// `?incident_id=` response byte-for-byte the same `Vec<Evidence>` shape
/// while letting the new unscoped path return the richer
/// `Vec<EvidenceWithIncidents>` shape, both from one handler return type.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ListEvidenceResponse {
    Scoped(Vec<Evidence>),
    All(Vec<EvidenceWithIncidents>),
}

pub async fn list_evidence_handler(
    State(state): State<IncidentEvidenceState>,
    Extension(ctx): Extension<AuthContext>,
    Query(q): Query<ListEvidenceQuery>,
) -> Result<Json<ListEvidenceResponse>, (StatusCode, String)> {
    let caller = ctx.tenant_id;
    match q.incident_id {
        Some(incident_id_str) => {
            let incident_id: Uuid = incident_id_str.parse().map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid incident_id: {}", incident_id_str),
                )
            })?;
            if caller.is_some() {
                visible_incident(&state, incident_id, caller).await?;
            }

            let evidence_list =
                tokio::task::spawn_blocking(move || -> Result<Vec<Evidence>, String> {
                    let evidence_ids = state
                        .links
                        .evidence_ids_for_incident(incident_id)
                        .map_err(|e| e.to_string())?;
                    let mut evidence = Vec::new();
                    for id in evidence_ids {
                        if let Some(record) = state.evidence.get(id).map_err(|e| e.to_string())? {
                            if visible_to(record.tenant_id(), caller) {
                                evidence.push(record);
                            }
                        }
                    }
                    Ok(evidence)
                })
                .await
                .unwrap()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(ListEvidenceResponse::Scoped(evidence_list)))
        }
        None => {
            let all = tokio::task::spawn_blocking(
                move || -> Result<Vec<EvidenceWithIncidents>, String> {
                    let records = match caller {
                        Some(tenant) => state.evidence.list_for_tenant(tenant),
                        None => state.evidence.list(),
                    }
                    .map_err(|e| e.to_string())?;
                    let mut out = Vec::with_capacity(records.len());
                    for evidence in records {
                        let mut incident_ids = state
                            .links
                            .incident_ids_for_evidence(evidence.evidence_id())
                            .map_err(|e| e.to_string())?;
                        if caller.is_some() {
                            // Never disclose the id of an incident the caller cannot see.
                            let mut kept = Vec::with_capacity(incident_ids.len());
                            for id in incident_ids {
                                let owner = state.incidents.get(id).map_err(|e| e.to_string())?;
                                if owner.is_some_and(|i| visible_to(i.tenant_id, caller)) {
                                    kept.push(id);
                                }
                            }
                            incident_ids = kept;
                        }
                        out.push(EvidenceWithIncidents {
                            evidence,
                            incident_ids,
                        });
                    }
                    Ok(out)
                },
            )
            .await
            .unwrap()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(ListEvidenceResponse::All(all)))
        }
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
    use std::sync::Arc;

    use crate::incidents::IncidentEvidenceState;
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

    #[tokio::test]
    async fn create_evidence_links_it_to_an_incident_when_given_one() {
        let (_dir, state) = test_state();
        let incident = state
            .incidents
            .create(osiris_evidence::Incident {
                incident_id: uuid::Uuid::now_v7(),
                status: osiris_evidence::IncidentStatus::New,
                entities: vec![EntityRef::Ip {
                    addr: "203.0.113.10".to_string(),
                }],
                alert_ids: vec![],
                notes: vec![],
                tenant_id: None,
            })
            .unwrap();

        let body = CreateEvidenceBody {
            source: EvidenceSource::EventCapture,
            hash: "abc123".to_string(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: Some(incident.incident_id),
        };
        let Json(created) =
            create_evidence_handler(State(state.clone()), Extension(platform_ctx()), None, Json(body))
                .await
                .unwrap();

        let list_query = ListEvidenceQuery {
            incident_id: Some(incident.incident_id.to_string()),
        };
        let Json(response) =
            list_evidence_handler(State(state), Extension(platform_ctx()), Query(list_query))
                .await
                .unwrap();
        let ListEvidenceResponse::Scoped(list) = response else {
            panic!("expected a scoped response");
        };
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].evidence_id(), created.evidence_id());
    }

    #[tokio::test]
    async fn create_evidence_rejects_an_empty_hash() {
        let (_dir, state) = test_state();
        let body = CreateEvidenceBody {
            source: EvidenceSource::ManualUpload,
            hash: String::new(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: None,
        };
        let err = create_evidence_handler(State(state), Extension(platform_ctx()), None, Json(body))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_evidence_requires_a_valid_incident_id() {
        let (_dir, state) = test_state();
        let q = ListEvidenceQuery {
            incident_id: Some("not-a-uuid".to_string()),
        };
        let err = list_evidence_handler(State(state), Extension(platform_ctx()), Query(q))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_evidence_without_incident_id_returns_all_evidence_with_incident_ids() {
        let (_dir, state) = test_state();
        let incident = state
            .incidents
            .create(osiris_evidence::Incident {
                incident_id: uuid::Uuid::now_v7(),
                status: osiris_evidence::IncidentStatus::New,
                entities: vec![EntityRef::Ip {
                    addr: "203.0.113.10".to_string(),
                }],
                alert_ids: vec![],
                notes: vec![],
                tenant_id: None,
            })
            .unwrap();

        let linked_body = CreateEvidenceBody {
            source: EvidenceSource::EventCapture,
            hash: "linked".to_string(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: Some(incident.incident_id),
        };
        let _ = create_evidence_handler(
            State(state.clone()),
            Extension(platform_ctx()),
            None,
            Json(linked_body),
        )
        .await
        .unwrap();

        let unlinked_body = CreateEvidenceBody {
            source: EvidenceSource::ManualUpload,
            hash: "unlinked".to_string(),
            immutable_since: 2000,
            relationships: vec![],
            supersedes: None,
            incident_id: None,
        };
        let _ = create_evidence_handler(
            State(state.clone()),
            Extension(platform_ctx()),
            None,
            Json(unlinked_body),
        )
        .await
        .unwrap();

        let Json(response) = list_evidence_handler(
            State(state),
            Extension(platform_ctx()),
            Query(ListEvidenceQuery { incident_id: None }),
        )
        .await
        .unwrap();
        let ListEvidenceResponse::All(all) = response else {
            panic!("expected an all-evidence response");
        };

        assert_eq!(all.len(), 2);
        let linked = all
            .iter()
            .find(|item| item.evidence.integrity().hash == "linked")
            .unwrap();
        assert_eq!(linked.incident_ids, vec![incident.incident_id]);
        let unlinked = all
            .iter()
            .find(|item| item.evidence.integrity().hash == "unlinked")
            .unwrap();
        assert!(unlinked.incident_ids.is_empty());
    }

    #[tokio::test]
    async fn list_evidence_scoped_response_shape_is_unchanged() {
        let (_dir, state) = test_state();
        let incident = state
            .incidents
            .create(osiris_evidence::Incident {
                incident_id: uuid::Uuid::now_v7(),
                status: osiris_evidence::IncidentStatus::New,
                entities: vec![EntityRef::Ip {
                    addr: "203.0.113.10".to_string(),
                }],
                alert_ids: vec![],
                notes: vec![],
                tenant_id: None,
            })
            .unwrap();
        let body = CreateEvidenceBody {
            source: EvidenceSource::EventCapture,
            hash: "abc123".to_string(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: Some(incident.incident_id),
        };
        let _ =
            create_evidence_handler(State(state.clone()), Extension(platform_ctx()), None, Json(body))
                .await
                .unwrap();

        let Json(response) = list_evidence_handler(
            State(state),
            Extension(platform_ctx()),
            Query(ListEvidenceQuery {
                incident_id: Some(incident.incident_id.to_string()),
            }),
        )
        .await
        .unwrap();
        let ListEvidenceResponse::Scoped(list) = response else {
            panic!("expected a scoped response");
        };
        let serialized = serde_json::to_value(&list).unwrap();
        assert!(serialized.is_array());
        assert_eq!(serialized[0]["integrity"]["hash"], "abc123");
    }
}
