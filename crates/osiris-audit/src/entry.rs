use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActorRef {
    User { user_id: Uuid },
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
}

/// Caller-supplied fields for a new entry; the log fills in audit_id,
/// timestamp, and the hash chain fields on append (ARCHITECTURE.md §22).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAuditEntry {
    pub who: ActorRef,
    pub what: String,
    pub target: String,
    pub why: Option<String>,
    pub result: AuditResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id: Uuid,
    pub timestamp: u64,
    pub who: ActorRef,
    pub what: String,
    pub target: String,
    pub why: Option<String>,
    pub result: AuditResult,
    pub prev_entry_hash: String,
    pub entry_hash: String,
}
