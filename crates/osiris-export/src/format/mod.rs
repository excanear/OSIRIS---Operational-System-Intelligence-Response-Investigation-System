//! Pure, deterministic record formatters (spec §5.3). No I/O.

pub mod csv;
pub mod ndjson;
pub mod otlp;
pub mod syslog;

pub use crate::config::Facility;
pub use csv::{csv_header, csv_row};
pub use ndjson::{ndjson_line, ndjson_value};
pub use otlp::otlp_logs_body;
pub use syslog::{cef, rfc5424};

use crate::record::ExportRecord;
use osiris_schema::Severity;
use serde::Serialize;
use time::OffsetDateTime;

/// RFC 5424 severity (critical 2, high 3, medium 4, low 5, info 6).
pub fn syslog_severity(s: Severity) -> u8 {
    match s {
        Severity::Critical => 2,
        Severity::High => 3,
        Severity::Medium => 4,
        Severity::Low => 5,
        Severity::Info => 6,
    }
}

/// CEF severity 0-10 (info 1, low 3, medium 5, high 8, critical 10).
pub fn cef_severity(s: Severity) -> u8 {
    match s {
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 8,
        Severity::Critical => 10,
    }
}

/// OTLP `severityNumber` (info 9, low 10, medium 13, high 17, critical 21).
pub fn severity_number_otlp(s: Severity) -> u8 {
    match s {
        Severity::Info => 9,
        Severity::Low => 10,
        Severity::Medium => 13,
        Severity::High => 17,
        Severity::Critical => 21,
    }
}

pub(crate) fn severity_text(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

/// RFC 3339 UTC with exactly nine fractional digits.
pub fn rfc3339_ns(ns: u64) -> String {
    match OffsetDateTime::from_unix_timestamp_nanos(i128::from(ns)) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            t.nanosecond()
        ),
        Err(_) => "1970-01-01T00:00:00.000000000Z".to_string(),
    }
}

/// The serde string of a unit enum (e.g. `PROCESS_EXEC`).
pub(crate) fn enum_str<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Host display name: the event's hostname; an alert carries only host_id.
pub(crate) fn hostname(rec: &ExportRecord) -> String {
    match rec {
        ExportRecord::Event(e) => e.host.hostname.clone(),
        ExportRecord::Alert(a) => a.host_id().to_string(),
    }
}

/// `event_type` for events, `ALERT` for alerts.
pub(crate) fn msg_id(rec: &ExportRecord) -> String {
    match rec {
        ExportRecord::Event(e) => enum_str(&e.event_type),
        ExportRecord::Alert(_) => "ALERT".to_string(),
    }
}
