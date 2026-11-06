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
    // (host_id, name, name_is_from_event, records); index keeps first-seen order.
    let mut groups: Vec<(Uuid, String, bool, Vec<Value>)> = vec![];
    let mut index: std::collections::HashMap<Uuid, usize> = std::collections::HashMap::new();
    for rec in batch {
        let host_id = rec.host_id();
        let lr = log_record(rec, include_raw, observed_ns);
        let from_event = matches!(rec.as_ref(), ExportRecord::Event(_));
        let i = *index.entry(host_id).or_insert_with(|| {
            groups.push((host_id, hostname(rec), from_event, vec![]));
            groups.len() - 1
        });
        let g = &mut groups[i];
        if from_event && !g.2 {
            // Alerts only know host_id; prefer the first event's hostname.
            g.1 = hostname(rec);
            g.2 = true;
        }
        g.3.push(lr);
    }
    let resource_logs: Vec<Value> = groups
        .into_iter()
        .map(|(host_id, name, _, records)| {
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
