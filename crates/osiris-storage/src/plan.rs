use osiris_schema::{EventType, ProcessKey};

/// Phase 1's minimal query surface (plan Global Constraints #8) — covers
/// exactly what the API (Task 8) needs: event_type/time-range filtering
/// and a process_key lookup. The full OQL planner is Phase 7 scope
/// (ARCHITECTURE.md §12.3).
#[derive(Debug, Clone, Default)]
pub struct QueryPlan {
    pub event_type: Option<EventType>,
    pub process_key: Option<ProcessKey>,
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
    fn new_query_plan_defaults_to_limit_100() {
        let plan = QueryPlan::new();
        assert_eq!(plan.limit, 100);
        assert!(plan.event_type.is_none());
    }
}
