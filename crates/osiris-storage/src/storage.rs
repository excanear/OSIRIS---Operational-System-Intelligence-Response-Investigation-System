use osiris_schema::{Alert, CanonicalEvent, EntityRelationship, RiskScoreRecord};
use thiserror::Error;
use uuid::Uuid;

use crate::plan::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RelationshipQueryPlan, RetentionPolicy,
    RetentionReport, RiskQueryPlan, WriteReport,
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
    /// The OQL-backed, backend-agnostic query surface (ARCHITECTURE.md
    /// §12.3), additive to `query` above — `query` and its `QueryPlan`
    /// keep serving every existing caller unchanged (plan Global
    /// Constraint #3).
    fn query_events(&self, plan: &osiris_query::EventQueryPlan) -> Result<Vec<CanonicalEvent>, StorageError>;
    /// Looks up one event by its primary key. Added for `osiris-investigate`'s
    /// `reconstruct_incident` (ARCHITECTURE.md §12.1), which must resolve a
    /// `BehavioralChain`'s bare `event_id`s back into real events to bucket
    /// them by category — none of this trait's field-filtering query
    /// methods can do that.
    fn get_event(&self, event_id: Uuid) -> Result<Option<CanonicalEvent>, StorageError>;
    fn delete(&self, criteria: &DeleteCriteria) -> Result<u64, StorageError>;
    fn retention_apply(&self, policy: &RetentionPolicy) -> Result<RetentionReport, StorageError>;
    fn health(&self) -> StorageHealth;

    /// Persists detection results. Alerts are append-only apart from their
    /// `status` field (ARCHITECTURE.md §12.7); a re-written `alert_id` is
    /// ignored and counted as failed, matching `batch_write`'s semantics.
    fn write_alerts(&self, alerts: &[Alert]) -> Result<WriteReport, StorageError>;
    fn query_alerts(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError>;

    /// Persists relationship edges as first-class, queryable rows
    /// (ARCHITECTURE.md §9.4 — "computed once, at enrichment time, and
    /// stored as first-class edges"; Phase 6 plan Task 3 closes the gap
    /// where, before this phase, an edge round-tripped only inside its
    /// owning event's serialized blob). Edges are immutable facts, so this
    /// is insert-only — re-persisting the same edge twice is harmless for
    /// every read-only graph query this trait supports.
    fn write_relationships(&self, edges: &[EntityRelationship]) -> Result<WriteReport, StorageError>;
    fn query_relationships(
        &self,
        plan: &RelationshipQueryPlan,
    ) -> Result<Vec<EntityRelationship>, StorageError>;

    /// Persists/queries Risk Engine output (ARCHITECTURE.md §11.4, Phase 6
    /// plan Task 7). Kept in its own table rather than mutating
    /// `CanonicalEvent.risk` on an already-written event — this trait has
    /// no update-in-place method for events, by design (append-only,
    /// §10.5's spirit).
    fn write_risk_scores(&self, scores: &[RiskScoreRecord]) -> Result<WriteReport, StorageError>;
    fn query_risk_scores(&self, plan: &RiskQueryPlan) -> Result<Vec<RiskScoreRecord>, StorageError>;
}
