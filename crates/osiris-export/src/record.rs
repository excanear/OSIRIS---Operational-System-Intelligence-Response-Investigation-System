use osiris_schema::{Alert, CanonicalEvent, Severity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    Events,
    Alerts,
}

#[derive(Debug, Clone)]
// Records are shared as Arc<ExportRecord>, so the variant size gap costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum ExportRecord {
    Event(CanonicalEvent),
    Alert(Alert),
}

impl ExportRecord {
    pub fn stream(&self) -> Stream {
        match self {
            ExportRecord::Event(_) => Stream::Events,
            ExportRecord::Alert(_) => Stream::Alerts,
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            ExportRecord::Event(e) => e.severity,
            ExportRecord::Alert(a) => a.severity(),
        }
    }

    pub fn host_id(&self) -> Uuid {
        match self {
            ExportRecord::Event(e) => e.host_id,
            ExportRecord::Alert(a) => a.host_id(),
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            ExportRecord::Event(e) => e.timestamp,
            ExportRecord::Alert(a) => a.timestamp(),
        }
    }

    /// `event_id` or `alert_id`.
    pub fn id(&self) -> Uuid {
        match self {
            ExportRecord::Event(e) => e.event_id,
            ExportRecord::Alert(a) => a.alert_id(),
        }
    }
}
