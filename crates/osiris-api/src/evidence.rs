use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use osiris_evidence::{Evidence, EvidenceSource, Integrity};
use osiris_schema::EntityRef;
use serde::Deserialize;
use uuid::Uuid;

use crate::incidents::IncidentEvidenceState;

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
    Json(body): Json<CreateEvidenceBody>,
) -> Result<Json<Evidence>, (StatusCode, String)> {
    let integrity = Integrity { hash: body.hash, immutable_since: body.immutable_since };
    let evidence = Evidence::new(body.source, body.immutable_since, integrity, body.relationships, body.supersedes)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let incident_id = body.incident_id;
    let links = state.links.clone();
    let evidence_store = state.evidence.clone();
    let created = tokio::task::spawn_blocking(move || -> Result<Evidence, String> {
        let created = evidence_store.insert(evidence).map_err(|e| e.to_string())?;
        if let Some(incident_id) = incident_id {
            links.link(incident_id, created.evidence_id()).map_err(|e| e.to_string())?;
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
    pub incident_id: String,
}

pub async fn list_evidence_handler(
    State(state): State<IncidentEvidenceState>,
    Query(q): Query<ListEvidenceQuery>,
) -> Result<Json<Vec<Evidence>>, (StatusCode, String)> {
    let incident_id: Uuid = q
        .incident_id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid incident_id: {}", q.incident_id)))?;

    let evidence_list = tokio::task::spawn_blocking(move || -> Result<Vec<Evidence>, String> {
        let evidence_ids = state.links.evidence_ids_for_incident(incident_id).map_err(|e| e.to_string())?;
        let mut evidence = Vec::new();
        for id in evidence_ids {
            if let Some(record) = state.evidence.get(id).map_err(|e| e.to_string())? {
                evidence.push(record);
            }
        }
        Ok(evidence)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(evidence_list))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::incidents::IncidentEvidenceState;
    use osiris_audit::FileAuditLog;
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
    use osiris_schema::EntityRef;

    fn test_state() -> (tempfile::TempDir, IncidentEvidenceState) {
        let dir = tempfile::tempdir().unwrap();
        let state = IncidentEvidenceState {
            incidents: Arc::new(SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap()),
            evidence: Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap()),
            links: Arc::new(SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap()),
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
                entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }],
                alert_ids: vec![],
                notes: vec![],
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
        let Json(created) = create_evidence_handler(State(state.clone()), Json(body)).await.unwrap();

        let list_query = ListEvidenceQuery { incident_id: incident.incident_id.to_string() };
        let Json(list) = list_evidence_handler(State(state), Query(list_query)).await.unwrap();
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
        let err = create_evidence_handler(State(state), Json(body)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_evidence_requires_a_valid_incident_id() {
        let (_dir, state) = test_state();
        let q = ListEvidenceQuery { incident_id: "not-a-uuid".to_string() };
        let err = list_evidence_handler(State(state), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
