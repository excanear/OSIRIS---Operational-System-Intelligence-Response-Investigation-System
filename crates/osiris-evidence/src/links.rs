use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum LinkStoreError {
    #[error("evidence/incident link store backend error: {0}")]
    Backend(String),
}

/// The many-to-many join between `Evidence` and `Incident`
/// (ARCHITECTURE.md §12.6: "a many-to-many join table, not a foreign key
/// on the evidence record, since one piece of evidence can be relevant to
/// more than one incident").
pub trait EvidenceIncidentLinks: Send + Sync {
    fn link(&self, incident_id: Uuid, evidence_id: Uuid) -> Result<(), LinkStoreError>;
    fn evidence_ids_for_incident(&self, incident_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError>;
    fn incident_ids_for_evidence(&self, evidence_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError>;
}

pub struct SqliteEvidenceIncidentLinks {
    conn: Mutex<Connection>,
}

impl SqliteEvidenceIncidentLinks {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LinkStoreError> {
        let conn = Connection::open(path).map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS evidence_incident_links (
                incident_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, evidence_id)
            );
            CREATE INDEX IF NOT EXISTS idx_links_evidence ON evidence_incident_links(evidence_id);",
        )
        .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

impl EvidenceIncidentLinks for SqliteEvidenceIncidentLinks {
    fn link(&self, incident_id: Uuid, evidence_id: Uuid) -> Result<(), LinkStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LinkStoreError::Backend("poisoned lock".to_string()))?;
        conn.execute(
            "INSERT OR IGNORE INTO evidence_incident_links (incident_id, evidence_id) VALUES (?1, ?2)",
            rusqlite::params![incident_id.to_string(), evidence_id.to_string()],
        )
        .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn evidence_ids_for_incident(&self, incident_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LinkStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT evidence_id FROM evidence_incident_links WHERE incident_id = ?1")
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![incident_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let mut ids = Vec::new();
        for row in rows {
            let s = row.map_err(|e| LinkStoreError::Backend(e.to_string()))?;
            ids.push(s.parse().map_err(|_| LinkStoreError::Backend(format!("invalid uuid '{}'", s)))?);
        }
        Ok(ids)
    }

    fn incident_ids_for_evidence(&self, evidence_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LinkStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT incident_id FROM evidence_incident_links WHERE evidence_id = ?1")
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![evidence_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let mut ids = Vec::new();
        for row in rows {
            let s = row.map_err(|e| LinkStoreError::Backend(e.to_string()))?;
            ids.push(s.parse().map_err(|_| LinkStoreError::Backend(format!("invalid uuid '{}'", s)))?);
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn linking_the_same_evidence_to_two_incidents_is_visible_from_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let links = SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap();
        let evidence_id = Uuid::now_v7();
        let incident_a = Uuid::now_v7();
        let incident_b = Uuid::now_v7();

        links.link(incident_a, evidence_id).unwrap();
        links.link(incident_b, evidence_id).unwrap();

        let incidents = links.incident_ids_for_evidence(evidence_id).unwrap();
        assert_eq!(incidents.len(), 2);
        assert!(incidents.contains(&incident_a));
        assert!(incidents.contains(&incident_b));
    }

    #[test]
    fn evidence_ids_for_incident_returns_every_linked_evidence_record() {
        let dir = tempfile::tempdir().unwrap();
        let links = SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap();
        let incident_id = Uuid::now_v7();
        let evidence_a = Uuid::now_v7();
        let evidence_b = Uuid::now_v7();
        links.link(incident_id, evidence_a).unwrap();
        links.link(incident_id, evidence_b).unwrap();

        let found = links.evidence_ids_for_incident(incident_id).unwrap();
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn linking_the_same_pair_twice_does_not_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let links = SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap();
        let incident_id = Uuid::now_v7();
        let evidence_id = Uuid::now_v7();
        links.link(incident_id, evidence_id).unwrap();
        links.link(incident_id, evidence_id).unwrap();
        assert_eq!(links.evidence_ids_for_incident(incident_id).unwrap().len(), 1);
    }
}
