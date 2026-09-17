use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseActionKind {
    TerminateProcess,
    StopService,
    QuarantineFile,
    BlockIndicator,
    IsolateNetwork,
    DisablePersistence,
    CollectEvidence,
}

impl ResponseActionKind {
    /// Every kind except `CollectEvidence` is destructive per
    /// ARCHITECTURE.md §13's typed split.
    pub fn destructive(&self) -> bool {
        !matches!(self, ResponseActionKind::CollectEvidence)
    }

    /// Every kind supports dry-run in v1 — it is the one mode every
    /// action, destructive or not, can honor without the Agent command
    /// channel this phase does not build.
    pub fn supports_dry_run(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct ResponseRequest {
    pub action: ResponseActionKind,
    pub target: EntityRef,
    pub reason: String,
    pub dry_run: bool,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub incident_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseOutcome {
    DryRunPreview { description: String },
    EvidenceCollected { evidence_id: Uuid },
    Rejected { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_collect_evidence_is_non_destructive() {
        assert!(!ResponseActionKind::CollectEvidence.destructive());
        for action in [
            ResponseActionKind::TerminateProcess,
            ResponseActionKind::StopService,
            ResponseActionKind::QuarantineFile,
            ResponseActionKind::BlockIndicator,
            ResponseActionKind::IsolateNetwork,
            ResponseActionKind::DisablePersistence,
        ] {
            assert!(action.destructive(), "{action:?} must be destructive");
        }
    }

    #[test]
    fn every_action_supports_dry_run_in_v1() {
        for action in [
            ResponseActionKind::TerminateProcess,
            ResponseActionKind::StopService,
            ResponseActionKind::QuarantineFile,
            ResponseActionKind::BlockIndicator,
            ResponseActionKind::IsolateNetwork,
            ResponseActionKind::DisablePersistence,
            ResponseActionKind::CollectEvidence,
        ] {
            assert!(action.supports_dry_run(), "{action:?} must support dry_run");
        }
    }

    #[test]
    fn action_kind_wire_form_is_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&ResponseActionKind::CollectEvidence).unwrap(),
            "\"COLLECT_EVIDENCE\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseActionKind::TerminateProcess).unwrap(),
            "\"TERMINATE_PROCESS\""
        );
    }
}
