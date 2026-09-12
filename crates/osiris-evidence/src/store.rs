use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use crate::evidence::Evidence;

#[derive(Debug, thiserror::Error)]
pub enum EvidenceStoreError {
    #[error("evidence store backend error: {0}")]
    Backend(String),
    #[error("evidence serialize/deserialize error: {0}")]
    Serialize(String),
}

/// No `update`/`delete` method exists on this trait anywhere in this
/// crate — append-only is enforced by the trait's shape, not by
/// convention (plan Global Constraint #7).
pub trait EvidenceStore: Send + Sync {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError>;
    fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError>;
}

/// Evidence's own SQLite file, independent of `osiris-storage`
/// (ARCHITECTURE.md §10.3's control-plane store, plan Global Constraint #6).
pub struct SqliteEvidenceStore {
    conn: Mutex<Connection>,
}

impl SqliteEvidenceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvidenceStoreError> {
        let conn = Connection::open(path).map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                raw_json TEXT NOT NULL
            );",
        )
        .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

impl EvidenceStore for SqliteEvidenceStore {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EvidenceStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json =
            serde_json::to_string(&evidence).map_err(|e| EvidenceStoreError::Serialize(e.to_string()))?;
        conn.execute(
            "INSERT INTO evidence (evidence_id, raw_json) VALUES (?1, ?2)",
            rusqlite::params![evidence.evidence_id().to_string(), raw_json],
        )
        .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        Ok(evidence)
    }

    fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EvidenceStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json: Option<String> = conn
            .query_row(
                "SELECT raw_json FROM evidence WHERE evidence_id = ?1",
                rusqlite::params![evidence_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        match raw_json {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| EvidenceStoreError::Serialize(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, EvidenceSource, Integrity};

    fn sample() -> Evidence {
        Evidence::new(
            EvidenceSource::EventCapture,
            1000,
            Integrity { hash: "abc".to_string(), immutable_since: 1000 },
            vec![],
            None,
        )
        .unwrap()
    }

    #[test]
    fn insert_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        let inserted = store.insert(sample()).unwrap();
        let found = store.get(inserted.evidence_id()).unwrap().unwrap();
        assert_eq!(found.evidence_id(), inserted.evidence_id());
    }

    #[test]
    fn get_returns_none_for_an_unknown_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        assert!(store.get(uuid::Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn insert_never_overwrites_an_existing_record() {
        // There is no `update` method on EvidenceStore at all (plan Global
        // Constraint #7) — this test documents that inserting the *same*
        // evidence_id twice is rejected rather than silently replacing it,
        // since `Evidence` always mints a fresh `Uuid::now_v7()` in `new()`
        // and nothing on this trait accepts a caller-supplied id to collide.
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        let evidence = sample();
        store.insert(evidence.clone()).unwrap();
        let err = store.insert(evidence).unwrap_err();
        assert!(matches!(err, EvidenceStoreError::Backend(_)));
    }
}
