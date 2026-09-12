use std::path::Path;
use std::sync::Mutex;

use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_schema::EntityRef;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentStatus {
    New,
    Investigating,
    Contained,
    Resolved,
    FalsePositive,
}

/// A control-plane incident record (ARCHITECTURE.md §12.7). `actions` from
/// the architecture's full shape is deliberately omitted — Response Engine
/// is out of scope for this phase (plan Global Constraint #1), so there is
/// nothing to populate it with yet; a later phase adds it back when
/// `osiris-response` exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: Uuid,
    pub status: IncidentStatus,
    pub entities: Vec<EntityRef>,
    pub alert_ids: Vec<Uuid>,
    pub notes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IncidentStoreError {
    #[error("incident store backend error: {0}")]
    Backend(String),
    #[error("incident serialize/deserialize error: {0}")]
    Serialize(String),
    #[error("incident not found")]
    NotFound,
    #[error("incident has no associated entities to audit a transition against")]
    NoEntities,
    #[error("audit log error: {0}")]
    Audit(String),
}

pub trait IncidentStore: Send + Sync {
    fn create(&self, incident: Incident) -> Result<Incident, IncidentStoreError>;
    fn get(&self, incident_id: Uuid) -> Result<Option<Incident>, IncidentStoreError>;
    fn list(&self) -> Result<Vec<Incident>, IncidentStoreError>;

    /// Writes an audit entry via `audit_log` *before* persisting the new
    /// status (plan Global Constraint #8) — if the audit write fails, this
    /// returns `Err` and the incident's persisted status is untouched.
    fn transition_status(
        &self,
        incident_id: Uuid,
        new_status: IncidentStatus,
        actor: ActorRef,
        why: Option<String>,
        audit_log: &dyn AuditLog,
    ) -> Result<Incident, IncidentStoreError>;
}

pub struct SqliteIncidentStore {
    conn: Mutex<Connection>,
}

impl SqliteIncidentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IncidentStoreError> {
        let conn = Connection::open(path).map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                raw_json TEXT NOT NULL
            );",
        )
        .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Persists an incident via upsert (ON CONFLICT ... DO UPDATE). Unlike the append-only
    /// `SqliteEvidenceStore::insert`, this is intentional — incidents are mutable records that
    /// need status updates and other mutations.
    ///
    /// **Residual risk:** if `audit_log.append(...)` succeeds but this fails (e.g., SQLite I/O error),
    /// the audit log holds a Success entry for a status change never persisted — audit/state divergence.
    /// This is accepted (plan constraint only binds forward: audit failure blocks persistence, not reverse).
    fn write_row(&self, incident: &Incident) -> Result<(), IncidentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| IncidentStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json =
            serde_json::to_string(incident).map_err(|e| IncidentStoreError::Serialize(e.to_string()))?;
        conn.execute(
            "INSERT INTO incidents (incident_id, raw_json) VALUES (?1, ?2)
             ON CONFLICT(incident_id) DO UPDATE SET raw_json = excluded.raw_json",
            rusqlite::params![incident.incident_id.to_string(), raw_json],
        )
        .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl IncidentStore for SqliteIncidentStore {
    fn create(&self, incident: Incident) -> Result<Incident, IncidentStoreError> {
        self.write_row(&incident)?;
        Ok(incident)
    }

    fn get(&self, incident_id: Uuid) -> Result<Option<Incident>, IncidentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| IncidentStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json: Option<String> = conn
            .query_row(
                "SELECT raw_json FROM incidents WHERE incident_id = ?1",
                rusqlite::params![incident_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        match raw_json {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| IncidentStoreError::Serialize(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<Incident>, IncidentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| IncidentStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT raw_json FROM incidents")
            .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        let mut incidents = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
            incidents.push(
                serde_json::from_str(&raw_json).map_err(|e| IncidentStoreError::Serialize(e.to_string()))?,
            );
        }
        Ok(incidents)
    }

    fn transition_status(
        &self,
        incident_id: Uuid,
        new_status: IncidentStatus,
        actor: ActorRef,
        why: Option<String>,
        audit_log: &dyn AuditLog,
    ) -> Result<Incident, IncidentStoreError> {
        let mut incident = self.get(incident_id)?.ok_or(IncidentStoreError::NotFound)?;
        let target = incident
            .entities
            .first()
            .cloned()
            .ok_or(IncidentStoreError::NoEntities)?;

        audit_log
            .append(NewAuditEntry {
                who: actor,
                what: format!("incident {} status -> {:?}", incident_id, new_status),
                target,
                why,
                result: AuditResult::Success,
            })
            .map_err(|e| IncidentStoreError::Audit(e.to_string()))?;

        incident.status = new_status;
        self.write_row(&incident)?;
        Ok(incident)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::FileAuditLog;
    use uuid::Uuid;

    fn sample_incident() -> Incident {
        Incident {
            incident_id: Uuid::now_v7(),
            status: IncidentStatus::New,
            entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }],
            alert_ids: vec![],
            notes: vec![],
        }
    }

    #[test]
    fn create_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        let created = store.create(sample_incident()).unwrap();
        let found = store.get(created.incident_id).unwrap().unwrap();
        assert_eq!(found.status, IncidentStatus::New);
    }

    #[test]
    fn list_returns_every_created_incident() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        store.create(sample_incident()).unwrap();
        store.create(sample_incident()).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn transition_status_writes_an_audit_entry_before_persisting() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        let audit_log = FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let created = store.create(sample_incident()).unwrap();

        let updated = store
            .transition_status(
                created.incident_id,
                IncidentStatus::Investigating,
                ActorRef::User { user_id: Uuid::now_v7() },
                Some("starting triage".to_string()),
                &audit_log,
            )
            .unwrap();

        assert_eq!(updated.status, IncidentStatus::Investigating);
        let persisted = store.get(created.incident_id).unwrap().unwrap();
        assert_eq!(persisted.status, IncidentStatus::Investigating);

        let entries = audit_log.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].what.contains("Investigating"));
    }

    #[test]
    fn transition_status_fails_for_an_unknown_incident() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        let audit_log = FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let err = store
            .transition_status(Uuid::now_v7(), IncidentStatus::Resolved, ActorRef::System, None, &audit_log)
            .unwrap_err();
        assert!(matches!(err, IncidentStoreError::NotFound));
    }

    #[test]
    fn transition_status_fails_when_the_incident_has_no_entities() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        let audit_log = FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let no_entities = Incident {
            incident_id: Uuid::now_v7(),
            status: IncidentStatus::New,
            entities: vec![],
            alert_ids: vec![],
            notes: vec![],
        };
        let created = store.create(no_entities).unwrap();
        let err = store
            .transition_status(created.incident_id, IncidentStatus::Investigating, ActorRef::System, None, &audit_log)
            .unwrap_err();
        assert!(matches!(err, IncidentStoreError::NoEntities));
    }
}
