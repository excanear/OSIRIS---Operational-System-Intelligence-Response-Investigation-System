use osiris_schema::{Alert, CanonicalEvent};
use thiserror::Error;

use crate::plan::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RetentionPolicy, RetentionReport, WriteReport,
};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("serialization error: {0}")]
    Serialize(String),
}

#[derive(Debug, Clone)]
pub struct StorageHealth {
    pub healthy: bool,
    pub event_count: u64,
    pub last_write_at: Option<u64>,
    pub detail: Option<String>,
}

/// Abstract storage interface (ARCHITECTURE.md §10.1). All of Core, API,
/// and CLI query through this trait — never a database-specific client
/// directly — so the backend can change (SQLite -> ClickHouse, §10.2)
/// without touching detection/correlation/query logic. Phase 1 provides
/// exactly one implementation, `osiris-storage-sqlite`. `query` returns a
/// `Vec` rather than the architecture's `QueryResultStream` — a documented
/// Phase 1 simplification (plan Global Constraints #8); streaming is worth
/// adding once result sets are large enough to matter.
pub trait Storage: Send + Sync {
    fn write(&self, event: &CanonicalEvent) -> Result<(), StorageError>;
    fn batch_write(&self, events: &[CanonicalEvent]) -> Result<WriteReport, StorageError>;
    fn query(&self, plan: &QueryPlan) -> Result<Vec<CanonicalEvent>, StorageError>;
    fn delete(&self, criteria: &DeleteCriteria) -> Result<u64, StorageError>;
    fn retention_apply(&self, policy: &RetentionPolicy) -> Result<RetentionReport, StorageError>;
    fn health(&self) -> StorageHealth;

    /// Persists detection results. Alerts are append-only apart from their
    /// `status` field (ARCHITECTURE.md §12.7); a re-written `alert_id` is
    /// ignored and counted as failed, matching `batch_write`'s semantics.
    fn write_alerts(&self, alerts: &[Alert]) -> Result<WriteReport, StorageError>;
    fn query_alerts(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError>;
}
