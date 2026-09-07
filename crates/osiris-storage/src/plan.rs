use osiris_schema::{EventType, FileIdentity, ProcessKey};
use uuid::Uuid;

/// This phase's minimal query surface (plan Global Constraints #11) — what
/// the API needs and no more: event_type/time-range filtering, a
/// process_key lookup, and the two file lookups the File Story composes.
/// The full OQL planner is Phase 7 scope (ARCHITECTURE.md §12.3).
#[derive(Debug, Clone, Default)]
pub struct QueryPlan {
    pub event_type: Option<EventType>,
    pub process_key: Option<ProcessKey>,
    /// Exact-match on `file.path`. The lookup key an analyst types.
    pub file_path: Option<String>,
    /// Exact-match on `(file.inode, file.device_id)`. The join key that
    /// follows a file across a rename (§9.4, plan Global Constraints #6).
    pub file_identity: Option<FileIdentity>,
    /// Exact-match on `network.src_ip OR network.dst_ip` — an address is
    /// queried without regard to which side of the connection it was on
    /// (Phase 3 plan Global Constraints #9).
    pub network_addr: Option<String>,
    /// Exact-match on `dns.query`.
    pub dns_domain: Option<String>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: usize,
}

impl QueryPlan {
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }
}

/// The alert-query surface. `evidence_event_ids` is what makes a File
/// Story able to attach "every Alert whose evidence references one of these
/// events" (ARCHITECTURE.md §12.1) in one query rather than one per event.
#[derive(Debug, Clone, Default)]
pub struct AlertQueryPlan {
    pub rule_id: Option<String>,
    pub evidence_event_ids: Vec<Uuid>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: usize,
}

impl AlertQueryPlan {
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeleteCriteria {
    pub before_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub max_age_secs: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RetentionReport {
    pub deleted_count: u64,
}

#[derive(Debug, Clone, Default)]
pub struct WriteReport {
    pub written_count: u64,
    pub failed_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_query_plan_defaults_to_limit_100_and_no_filters() {
        let plan = QueryPlan::new();
        assert_eq!(plan.limit, 100);
        assert!(plan.event_type.is_none());
        assert!(plan.file_path.is_none());
        assert!(plan.file_identity.is_none());
        assert!(plan.network_addr.is_none());
        assert!(plan.dns_domain.is_none());
    }

    #[test]
    fn new_alert_query_plan_defaults_to_limit_100_and_no_filters() {
        let plan = AlertQueryPlan::new();
        assert_eq!(plan.limit, 100);
        assert!(plan.rule_id.is_none());
        assert!(plan.evidence_event_ids.is_empty());
        assert!(plan.since.is_none());
        assert!(plan.until.is_none());
    }
}
