//! Structure-agnostic searches over API responses, so scenario tests key on
//! their unique marker rather than on response shapes.
use serde_json::Value;

pub fn contains_str(v: &Value, needle: &str) -> bool {
    match v {
        Value::String(s) => s.contains(needle),
        Value::Array(a) => a.iter().any(|x| contains_str(x, needle)),
        Value::Object(o) => o.values().any(|x| contains_str(x, needle)),
        _ => false,
    }
}

pub fn has_kv(v: &Value, key: &str, want: &Value) -> bool {
    match v {
        Value::Array(a) => a.iter().any(|x| has_kv(x, key, want)),
        Value::Object(o) => o.get(key) == Some(want) || o.values().any(|x| has_kv(x, key, want)),
        _ => false,
    }
}

/// The `id_key` string of every object (at any depth) that has one and
/// contains `needle` somewhere inside it — e.g. the `event_id`s of the
/// events that mention a marker. Alerts cite events only by id, so this is
/// how a scenario ties an alert back to its marker.
pub fn ids_containing(v: &Value, id_key: &str, needle: &str) -> Vec<String> {
    let mut out = vec![];
    collect_ids(v, id_key, needle, &mut out);
    out
}

/// Every object (at any depth) whose `key` equals `want`, whole -- e.g. the
/// `{"sensor_name": "dns", ...}` entry of an AGENT_HEALTH event, or each
/// event of an events response -- so a scenario can check several fields
/// of one object together.
pub fn objects_with<'a>(v: &'a Value, key: &str, want: &Value) -> Vec<&'a Value> {
    let mut out = vec![];
    collect_objects(v, key, want, &mut out);
    out
}

fn collect_objects<'a>(v: &'a Value, key: &str, want: &Value, out: &mut Vec<&'a Value>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| collect_objects(x, key, want, out)),
        Value::Object(o) => {
            if o.get(key) == Some(want) {
                out.push(v);
            }
            o.values().for_each(|x| collect_objects(x, key, want, out));
        }
        _ => {}
    }
}

fn collect_ids(v: &Value, id_key: &str, needle: &str, out: &mut Vec<String>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| collect_ids(x, id_key, needle, out)),
        Value::Object(o) => match o.get(id_key) {
            Some(Value::String(id)) if contains_str(v, needle) => out.push(id.clone()),
            _ => o.values().for_each(|x| collect_ids(x, id_key, needle, out)),
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn contains_str_finds_a_needle_nested_anywhere() {
        let v = json!([{"a": {"b": ["x", "has osiris-abc123 inside"]}}]);
        assert!(contains_str(&v, "osiris-abc123"));
        assert!(!contains_str(&v, "osiris-zzz"));
    }

    #[test]
    fn has_kv_matches_numbers_and_strings_in_nested_objects() {
        let v = json!([{"network": {"dst_port": 4242, "proto": "tcp"}}]);
        assert!(has_kv(&v, "dst_port", &json!(4242)));
        assert!(!has_kv(&v, "dst_port", &json!(4243)));
        assert!(has_kv(&v, "proto", &json!("tcp")));
    }

    #[test]
    fn objects_with_returns_each_matching_object_whole() {
        let health = json!([{"event_data": {"health": {"sensors": [
            {"sensor_name": "network", "state": {"state": "HEALTHY"}},
            {"sensor_name": "dns", "state": {"state": "HEALTHY"}}
        ]}}}]);
        let dns = objects_with(&health, "sensor_name", &json!("dns"));
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0]["state"]["state"], json!("HEALTHY"));
        assert!(objects_with(&health, "sensor_name", &json!("bogus")).is_empty());
    }

    /// Real-Linux finding (Phase 10, GH run 38073738001): an alert carries
    /// only evidence event ids — never the file path — so a scenario must
    /// resolve the marker's event ids first and match alerts on those.
    #[test]
    fn ids_containing_ties_an_alert_back_to_its_marker_event() {
        let events = json!([
            {"event_id": "e-other", "file": {"path": "/var/www/unrelated.php"}},
            {"event_id": "e-marker", "file": {"path": "/var/www/osirisp10abc.php"}}
        ]);
        let ids = ids_containing(&events, "event_id", "osirisp10abc");
        assert_eq!(ids, ["e-marker"]);

        // Shape of the real alert body from the run (trimmed).
        let alerts = json!([{
            "alert_id": "a1",
            "evidence": ["e-marker"],
            "rule_id": "shell_wrote_file_to_web_root"
        }]);
        assert!(
            !contains_str(&alerts, "osirisp10abc"),
            "alerts never echo the path"
        );
        assert!(ids.iter().any(|id| contains_str(&alerts, id)));
    }
}
