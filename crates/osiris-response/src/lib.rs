use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod dispatch;
mod query;
mod remote;
pub use dispatch::dispatch;
pub use query::events_for_entity;
pub use remote::{outcome_from_dispatch, remote_action, resolve_remote_action};

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
    RestoreFile,
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
            ResponseActionKind::RestoreFile => "RESTORE_FILE",
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
    /// Owning tenant of the caller; evidence collected is tagged with it.
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseOutcome {
    DryRunPreview {
        description: String,
    },
    EvidenceCollected {
        evidence_id: Uuid,
        event_count: usize,
        truncated: bool,
    },
    Rejected {
        reason: String,
    },
    /// The Agent executed the command.
    Executed {
        detail: String,
        quarantine_id: Option<Uuid>,
    },
    /// The Agent accepted the command but the action failed.
    ExecutionFailed {
        code: String,
        message: String,
    },
    /// The Agent refused the command before acting.
    Refused {
        reason: String,
    },
    /// No result arrived in time. The outcome is unknown: the Agent may
    /// still execute the command shortly after this is reported.
    TimedOut,
    AgentOffline,
    ControlDisabled,
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
            ResponseActionKind::RestoreFile,
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
            let via_serde = serde_json::to_value(action)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
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

/// Why a command could not be dispatched to an Agent.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("the command channel is not enabled")]
    Disabled,
    #[error("host has no control connection")]
    Offline,
    /// NEVER means "not executed": the signed validity window is the wait
    /// timeout plus 5 s, so the Agent may still accept the command for ~5 s
    /// after this is reported and then run it for up to its own execution
    /// timeout. An Agent clock that lags by X also extends validity by X.
    #[error("timed out waiting for the agent's result")]
    TimedOut,
    #[error("command dispatch failed: {0}")]
    Failed(String),
}

/// Sends a signed command to a host's Agent and waits for its result.
#[async_trait::async_trait]
pub trait CommandDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        host_id: Uuid,
        action: osiris_command::CommandAction,
        dry_run: bool,
        actor: String,
        reason: String,
    ) -> Result<osiris_command::CommandResult, DispatchError>;
}

/// Dispatcher used when no control channel is configured.
pub struct DisabledDispatcher;

#[async_trait::async_trait]
impl CommandDispatcher for DisabledDispatcher {
    async fn dispatch(
        &self,
        _host_id: Uuid,
        _action: osiris_command::CommandAction,
        _dry_run: bool,
        _actor: String,
        _reason: String,
    ) -> Result<osiris_command::CommandResult, DispatchError> {
        Err(DispatchError::Disabled)
    }
}
