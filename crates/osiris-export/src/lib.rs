//! Server-side exporters (Phase 12a): record, trait and configuration.

pub mod config;
pub mod error;
pub mod exporter;
pub mod record;

pub use config::{
    validate_exporters, CommonOptions, ExporterConfig, Facility, FileConfig, FileFormat, Filter,
    KindConfig, OtlpConfig, SyslogConfig, SyslogFormat, SyslogTransport, WebhookConfig,
};
pub use error::{ConfigError, ExportError};
pub use exporter::{ExportOutcome, Exporter};
pub use record::{ExportRecord, Stream};
