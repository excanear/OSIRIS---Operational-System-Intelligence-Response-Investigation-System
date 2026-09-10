use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::event_type::Severity;
use crate::process_key::ProcessKey;

/// One weighted input to a risk score (ARCHITECTURE.md §11.4: "never a bare
/// number" — a score must always be explainable by listing which weighted
/// reasons fired). `evidence` is the `event_id` that reason is grounded in,
/// per §11.4's exact field shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightedReason {
    pub label: String,
    pub weight: i16,
    pub evidence: Uuid,
}

/// A persisted risk score (ARCHITECTURE.md §11.4), deliberately a **new**
/// type rather than a widening of the frozen `RiskAnnotation` (which
/// predates this phase and has a narrower shape: `score: i32`,
/// `reasons: Vec<String>`, `rule_ids: Vec<String>`). Per this repo's
/// precedent of never widening a frozen schema type for one call site,
/// `RiskScoreRecord` is what the Phase 6 Risk Engine (`osiris-risk`)
/// produces and `Storage::write_risk_scores`/`query_risk_scores`
/// (Phase 6 plan Task 7) persist and query, keyed by the `event_id` that
/// triggered the scoring pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreRecord {
    pub event_id: Uuid,
    pub process_key: Option<ProcessKey>,
    pub host_id: Uuid,
    pub timestamp: u64,
    /// Clamped to `0..=100` by the Risk Engine before construction.
    pub score: u8,
    pub severity: Severity,
    /// Never empty — a `RiskScoreRecord` is only ever constructed when
    /// there is at least one weighted reason to cite (mirrors `Alert`'s own
    /// "never a bare/unexplained result" discipline, §11.2).
    pub reasons: Vec<WeightedReason>,
    /// Every distinct `event_id` referenced across `reasons`, deduplicated,
    /// so a consumer doesn't have to re-derive it from `reasons` itself.
    pub related_events: Vec<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_reason_round_trips_through_json() {
        let reason = WeightedReason {
            label: "Rare executable path".to_string(),
            weight: 10,
            evidence: Uuid::now_v7(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let back: WeightedReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back.label, reason.label);
        assert_eq!(back.weight, reason.weight);
        assert_eq!(back.evidence, reason.evidence);
    }

    #[test]
    fn risk_score_record_round_trips_through_json() {
        let host_id = Uuid::new_v4();
        let event_id = Uuid::now_v7();
        let record = RiskScoreRecord {
            event_id,
            process_key: Some(ProcessKey::new(host_id, "boot-1", 42, 99)),
            host_id,
            timestamp: 1_700_000_000_000_000_000,
            score: 42,
            severity: Severity::High,
            reasons: vec![WeightedReason {
                label: "Rare executable path".to_string(),
                weight: 10,
                evidence: event_id,
            }],
            related_events: vec![event_id],
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: RiskScoreRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_id, record.event_id);
        assert_eq!(back.process_key, record.process_key);
        assert_eq!(back.score, record.score);
        assert_eq!(back.severity, record.severity);
        assert_eq!(back.reasons.len(), 1);
        assert_eq!(back.related_events, record.related_events);
    }
}
