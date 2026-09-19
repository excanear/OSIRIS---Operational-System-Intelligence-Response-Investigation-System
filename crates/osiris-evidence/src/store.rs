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

/// Matches `osiris_query::MAX_EVENT_LIMIT`'s value — evidence volume
/// tracks event volume, so the same cap is a reasonable default.
pub const MAX_EVIDENCE_LIMIT: usize = 5_000;

/// No `update`/`delete` method exists on this trait anywhere in this
/// crate — append-only is enforced by the trait's shape, not by
/// convention (plan Global Constraint #7).
pub trait EvidenceStore: Send + Sync {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError>;
    fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError>;
    /// Every evidence record, newest first (`Evidence::timestamp()`
    /// descending), bounded by `MAX_EVIDENCE_LIMIT`. There is no
    /// `raw_json`-adjacent `timestamp` column in the schema (the table
    /// has only `evidence_id`/`raw_json`), so sorting happens in Rust
    /// after deserializing every row rather than via `ORDER BY` — an
    /// acceptable cost at this cap, and avoids a schema migration for a
    /// column that would otherwise duplicate data already in `raw_json`.
    fn list(&self) -> Result<Vec<Evidence>, EvidenceStoreError>;
    /// Like `list`, but only records owned by `tenant_id`, filtered BEFORE the
    /// `MAX_EVIDENCE_LIMIT` cap so other tenants' volume cannot starve it.
    fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<Evidence>, EvidenceStoreError>;
}

/// Evidence's own SQLite file, independent of `osiris-storage`
/// (ARCHITECTURE.md §10.3's control-plane store, plan Global Constraint #6).
pub struct SqliteEvidenceStore {
    conn: Mutex<Connection>,
}

impl SqliteEvidenceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvidenceStoreError> {
        let conn =
            Connection::open(path).map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                raw_json TEXT NOT NULL
            );",
        )
        .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl EvidenceStore for SqliteEvidenceStore {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EvidenceStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json = serde_json::to_string(&evidence)
            .map_err(|e| EvidenceStoreError::Serialize(e.to_string()))?;
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
            Some(json) => {
                Ok(Some(serde_json::from_str(&json).map_err(|e| {
                    EvidenceStoreError::Serialize(e.to_string())
                })?))
            }
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<Evidence>, EvidenceStoreError> {
        self.list_filtered(None)
    }

    fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<Evidence>, EvidenceStoreError> {
        self.list_filtered(Some(tenant_id))
    }
}

impl SqliteEvidenceStore {
    fn list_filtered(&self, tenant: Option<Uuid>) -> Result<Vec<Evidence>, EvidenceStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EvidenceStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT raw_json FROM evidence")
            .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;

        let mut all = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
            let evidence: Evidence = serde_json::from_str(&raw_json)
                .map_err(|e| EvidenceStoreError::Serialize(e.to_string()))?;
            if tenant.is_none() || evidence.tenant_id() == tenant {
                all.push(evidence);
            }
        }
        all.sort_by_key(|e| std::cmp::Reverse(e.timestamp()));
        all.truncate(MAX_EVIDENCE_LIMIT);
        Ok(all)
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
            Integrity {
                hash: "abc".to_string(),
                immutable_since: 1000,
            },
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

    #[test]
    fn list_returns_all_evidence_ordered_by_timestamp_descending() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        let older = Evidence::new(
            EvidenceSource::EventCapture,
            1000,
            Integrity {
                hash: "a".to_string(),
                immutable_since: 1000,
            },
            vec![],
            None,
        )
        .unwrap();
        let newer = Evidence::new(
            EvidenceSource::EventCapture,
            2000,
            Integrity {
                hash: "b".to_string(),
                immutable_since: 2000,
            },
            vec![],
            None,
        )
        .unwrap();
        store.insert(older.clone()).unwrap();
        store.insert(newer.clone()).unwrap();

        let listed = store.list().unwrap();

        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].evidence_id(), newer.evidence_id());
        assert_eq!(listed[1].evidence_id(), older.evidence_id());
    }

    #[test]
    fn list_returns_empty_vec_when_no_evidence_exists() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        assert!(store.list().unwrap().is_empty());
    }
}

#[cfg(test)]
mod tenant_tests {
    use super::*;
    use crate::evidence::{Evidence, EvidenceSource, Integrity};

    fn tagged(ts: u64, tenant: Option<Uuid>) -> Evidence {
        Evidence::new(
            EvidenceSource::EventCapture,
            ts,
            Integrity {
                hash: "h".to_string(),
                immutable_since: ts,
            },
            vec![],
            None,
        )
        .unwrap()
        .with_tenant(tenant)
    }

    #[test]
    fn tenant_tag_round_trips_and_defaults_to_none_for_legacy_rows() {
        let t = Uuid::now_v7();
        let e = tagged(1, Some(t));
        let back: Evidence = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back.tenant_id(), Some(t));
        let mut v = serde_json::to_value(&e).unwrap();
        v.as_object_mut().unwrap().remove("tenant_id");
        let legacy: Evidence = serde_json::from_value(v).unwrap();
        assert_eq!(legacy.tenant_id(), None);
    }

    #[test]
    fn list_for_tenant_returns_only_that_tenants_records_and_is_not_starved() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let mine = store.insert(tagged(1, Some(a))).unwrap();
        store.insert(tagged(2, Some(b))).unwrap();
        store.insert(tagged(3, None)).unwrap();
        let listed = store.list_for_tenant(a).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].evidence_id(), mine.evidence_id());
        assert_eq!(store.list().unwrap().len(), 3);
    }
}
