//! OTLP/JSON logs body (`ExportLogsServiceRequest`), one `ResourceLogs` per host.

use super::{enum_str, hostname, ndjson::ndjson_line, severity_number_otlp, severity_text};
use crate::record::ExportRecord;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

fn attr(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn log_record(rec: &ExportRecord, include_raw: bool, observed_ns: u64) -> Value {
    let mut attrs = vec![];
    match rec {
        ExportRecord::Event(e) => {
            attrs.push(attr("osiris.record_type", "event"));
            attrs.push(attr("osiris.event_type", &enum_str(&e.event_type)));
            attrs.push(attr("osiris.event_id", &e.event_id.to_string()));
        }
        ExportRecord::Alert(a) => {
            attrs.push(attr("osiris.record_type", "alert"));
            attrs.push(attr("osiris.rule_id", a.rule_id()));
            attrs.push(attr("osiris.alert_id", &a.alert_id().to_string()));
        }
    }
    json!({
        "timeUnixNano": rec.timestamp().to_string(),
        "observedTimeUnixNano": observed_ns.to_string(),
        "severityNumber": severity_number_otlp(rec.severity()),
        "severityText": severity_text(rec.severity()),
        "body": { "stringValue": ndjson_line(rec, include_raw) },
        "attributes": attrs,
    })
}

/// Group `batch` by host (first-seen order) into one `ResourceLogs` each.
pub fn otlp_logs_body(batch: &[Arc<ExportRecord>], include_raw: bool, observed_ns: u64) -> Value {
    let mut groups: Vec<(Uuid, String, Vec<Value>)> = vec![];
    for rec in batch {
        let host_id = rec.host_id();
        let lr = log_record(rec, include_raw, observed_ns);
        match groups.iter_mut().find(|g| g.0 == host_id) {
            Some(g) => g.2.push(lr),
            None => groups.push((host_id, hostname(rec), vec![lr])),
        }
    }
    let resource_logs: Vec<Value> = groups
        .into_iter()
        .map(|(host_id, name, records)| {
            json!({
                "resource": { "attributes": [
                    attr("host.id", &host_id.to_string()),
                    attr("host.name", &name),
                    attr("service.name", "osiris"),
                ]},
                "scopeLogs": [{
                    "scope": { "name": "osiris-export" },
                    "logRecords": records,
                }],
            })
        })
        .collect();
    json!({ "resourceLogs": resource_logs })
}
