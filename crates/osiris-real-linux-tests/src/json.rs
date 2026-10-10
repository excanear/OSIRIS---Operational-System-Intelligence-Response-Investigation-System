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
}
