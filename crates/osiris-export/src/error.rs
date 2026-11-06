use thiserror::Error;

/// Result of a failed delivery attempt.
#[derive(Debug, Error)]
pub enum ExportError {
    /// Worth retrying (network error, 5xx, timeout, disk full).
    #[error("transient export error: {0}")]
    Transient(String),
    /// Retrying cannot help; the batch is dropped and counted.
    #[error("permanent export error: {0}")]
    Permanent(String),
}

/// An invalid exporter configuration. The message always names the exporter.
#[derive(Debug, Error)]
#[error("exporter '{name}': {message}")]
pub struct ConfigError {
    pub name: String,
    pub message: String,
}

impl ConfigError {
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
        }
    }
}
