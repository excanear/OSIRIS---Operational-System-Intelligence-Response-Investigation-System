use crate::record::ExportRecord;
use base64::Engine;
use serde_json::{json, Value};

/// The record's own serde JSON plus `record_type`. `raw_event` is removed
/// unless `include_raw`, in which case it becomes a padded standard base64
/// string (not the API's array of numbers).
pub fn ndjson_value(rec: &ExportRecord, include_raw: bool) -> Value {
    let (v, record_type) = match rec {
        ExportRecord::Event(e) => (serde_json::to_value(e), "event"),
        ExportRecord::Alert(a) => (serde_json::to_value(a), "alert"),
    };
    let mut v = v.unwrap_or_else(|_| json!({}));
    if let Value::Object(map) = &mut v {
        map.insert("record_type".into(), json!(record_type));
        if let ExportRecord::Event(e) = rec {
            match (&e.raw_event, include_raw) {
                (Some(raw), true) => {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
                    map.insert("raw_event".into(), Value::String(b64));
                }
                (None, true) => {}
                (_, false) => {
                    map.remove("raw_event");
                }
            }
        }
    }
    v
}

/// One compact JSON line, no trailing newline (JSON escaping guarantees no
/// raw newline inside).
pub fn ndjson_line(rec: &ExportRecord, include_raw: bool) -> String {
    ndjson_value(rec, include_raw).to_string()
}
