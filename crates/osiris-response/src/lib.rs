use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod query;
mod dispatch;
pub use dispatch::dispatch;

#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    #[error("storage error: {0}")]
    Storage(#[from] osiris_storage::StorageError),
    #[error("evidence store error: {0}")]
    Evidence(#[from] osiris_evidence::EvidenceStoreError),
    #[error("evidence/incident link error: {0}")]
    Link(#[from] osiris_evidence::LinkStoreError),
    #[error("evidence construction error: {0}")]
    EvidenceBuild(#[from] osiris_evidence::EvidenceError),
    #[error("target entity does not resolve to any known data: {0:?}")]
    UnknownTarget(EntityRef),
}

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

    /// The canonical SCREAMING_SNAKE_CASE wire form (matches this enum's
    /// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`). Used anywhere a
    /// caller needs the decoded action's canonical string representation
    /// rather than whatever raw text a client sent — e.g. building an audit
    /// `what` field from a value that can't be spoofed by an unusual-case
    /// or Unicode-folding path segment.
    pub fn wire_form(&self) -> &'static str {
        match self {
            ResponseActionKind::TerminateProcess => "TERMINATE_PROCESS",
            ResponseActionKind::StopService => "STOP_SERVICE",
            ResponseActionKind::QuarantineFile => "QUARANTINE_FILE",
            ResponseActionKind::BlockIndicator => "BLOCK_INDICATOR",
            ResponseActionKind::IsolateNetwork => "ISOLATE_NETWORK",
            ResponseActionKind::DisablePersistence => "DISABLE_PERSISTENCE",
            ResponseActionKind::CollectEvidence => "COLLECT_EVIDENCE",
        }
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
    EvidenceCollected { evidence_id: Uuid, event_count: usize, truncated: bool },
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
    fn wire_form_matches_the_serde_wire_form_for_every_variant() {
        for action in [
            ResponseActionKind::TerminateProcess,
            ResponseActionKind::StopService,
            ResponseActionKind::QuarantineFile,
            ResponseActionKind::BlockIndicator,
            ResponseActionKind::IsolateNetwork,
            ResponseActionKind::DisablePersistence,
            ResponseActionKind::CollectEvidence,
        ] {
            let via_serde = serde_json::to_value(action).unwrap().as_str().unwrap().to_string();
            assert_eq!(action.wire_form(), via_serde);
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
