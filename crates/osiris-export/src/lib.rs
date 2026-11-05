//! Server-side exporters (Phase 12a): record, trait and configuration.

pub mod config;
pub mod error;
pub mod exporter;
pub mod format;
pub mod hub;
pub mod record;

pub use config::{
    validate_exporters, CommonOptions, ExporterConfig, Facility, FileConfig, FileFormat, Filter,
    KindConfig, OtlpConfig, SyslogConfig, SyslogFormat, SyslogTransport, WebhookConfig,
};
pub use error::{ConfigError, ExportError};
pub use exporter::{ExportOutcome, Exporter};
pub use format::{
    cef, cef_severity, csv_header, csv_row, ndjson_line, ndjson_value, otlp_logs_body, rfc5424,
    severity_number_otlp, syslog_severity,
};
pub use hub::{ExportHub, ExporterState, ExporterStatus, WorkerSettings};
pub use record::{ExportRecord, Stream};
