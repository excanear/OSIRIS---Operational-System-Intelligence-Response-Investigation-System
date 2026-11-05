use std::sync::Arc;

use async_trait::async_trait;

use crate::error::ExportError;
use crate::record::ExportRecord;

/// Records the destination rejected (OTLP partial success) or truncated (UDP)
/// within an otherwise successful batch.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExportOutcome {
    pub dropped: u64,
    pub truncated: u64,
}

#[async_trait]
pub trait Exporter: Send + Sync {
    fn name(&self) -> &str;
    /// Deliver one batch. `Transient` errors may be retried by the worker.
    async fn export(&self, batch: &[Arc<ExportRecord>]) -> Result<ExportOutcome, ExportError>;
}
