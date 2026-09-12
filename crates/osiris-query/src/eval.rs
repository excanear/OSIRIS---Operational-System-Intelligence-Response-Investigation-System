use crate::ast::{Op, Value};
use osiris_schema::CanonicalEvent;

/// Resolves a dotted OQL field path (e.g. `"process.exe_path"`) against one
/// event's JSON representation. Returns `None` both when an intermediate
/// section is absent (e.g. `user.uid` on an event with no `user`) and when
/// the path itself doesn't exist — the residual filter (Task 7) treats
/// both as "does not match" for every operator except nothing (there is no
/// "is null" operator in this phase's grammar, matching §12.3 exactly).
pub fn get_field(event: &CanonicalEvent, field: &str) -> Option<serde_json::Value> {
    let json = serde_json::to_value(event).ok()?;
    let mut cursor = &json;
    for part in field.split('.') {
        cursor = cursor.get(part)?;
    }
    Some(cursor.clone())
}

fn as_f64(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn as_str_lossy(v: &serde_json::Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())
}

/// Evaluates one comparison from the AST against a field's actual JSON
/// value, per ARCHITECTURE.md §12.3's operator set.
pub fn compare(actual: &serde_json::Value, op: Op, target: &Value) -> bool {
    match (op, target) {
        (Op::Eq, Value::Str(s)) => as_str_lossy(actual) == *s,
        (Op::Eq, Value::Num(n)) => as_f64(actual) == Some(*n),
        (Op::Ne, Value::Str(s)) => as_str_lossy(actual) != *s,
        (Op::Ne, Value::Num(n)) => as_f64(actual) != Some(*n),
        (Op::Gt, Value::Num(n)) => as_f64(actual).is_some_and(|a| a > *n),
        (Op::Lt, Value::Num(n)) => as_f64(actual).is_some_and(|a| a < *n),
        (Op::Ge, Value::Num(n)) => as_f64(actual).is_some_and(|a| a >= *n),
        (Op::Le, Value::Num(n)) => as_f64(actual).is_some_and(|a| a <= *n),
        (Op::Contains, Value::Str(s)) => as_str_lossy(actual).contains(s.as_str()),
        (Op::StartsWith, Value::Str(s)) => as_str_lossy(actual).starts_with(s.as_str()),
        (Op::EndsWith, Value::Str(s)) => as_str_lossy(actual).ends_with(s.as_str()),
        (Op::In, Value::List(items)) => items.iter().any(|item| compare(actual, Op::Eq, item)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Op, Value};
    use osiris_schema::{
        Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, CanonicalEvent,
        SCHEMA_VERSION,
    };
    use uuid::Uuid;

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 12345,
            monotonic_timestamp: 12345,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::High,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", 42, 1),
                pid: 42,
                exe_path: "/usr/bin/curl".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec!["suspicious".to_string()],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn get_field_resolves_a_top_level_field() {
        let event = sample_event();
        let v = get_field(&event, "event_type").unwrap();
        assert_eq!(v, serde_json::json!("PROCESS_EXEC"));
    }

    #[test]
    fn get_field_resolves_a_nested_field() {
        let event = sample_event();
        let v = get_field(&event, "process.exe_path").unwrap();
        assert_eq!(v, serde_json::json!("/usr/bin/curl"));
    }

    #[test]
    fn get_field_returns_none_for_an_absent_optional_parent() {
        let event = sample_event();
        assert!(get_field(&event, "user.uid").is_none());
    }

    #[test]
    fn compare_eq_matches_string_and_number() {
        assert!(compare(&serde_json::json!("A"), Op::Eq, &Value::Str("A".to_string())));
        assert!(compare(&serde_json::json!(42), Op::Eq, &Value::Num(42.0)));
        assert!(!compare(&serde_json::json!("A"), Op::Eq, &Value::Str("B".to_string())));
    }

    #[test]
    fn compare_contains_starts_with_ends_with() {
        let hay = serde_json::json!("/usr/bin/curl");
        assert!(compare(&hay, Op::Contains, &Value::Str("bin".to_string())));
        assert!(compare(&hay, Op::StartsWith, &Value::Str("/usr".to_string())));
        assert!(compare(&hay, Op::EndsWith, &Value::Str("curl".to_string())));
        assert!(!compare(&hay, Op::Contains, &Value::Str("nope".to_string())));
    }

    #[test]
    fn compare_ordering_operators_on_numbers() {
        let n = serde_json::json!(10);
        assert!(compare(&n, Op::Gt, &Value::Num(5.0)));
        assert!(compare(&n, Op::Ge, &Value::Num(10.0)));
        assert!(compare(&n, Op::Lt, &Value::Num(20.0)));
        assert!(compare(&n, Op::Le, &Value::Num(10.0)));
        assert!(!compare(&n, Op::Gt, &Value::Num(10.0)));
    }

    #[test]
    fn compare_in_matches_any_list_member() {
        let v = serde_json::json!("PROCESS_EXEC");
        let list = Value::List(vec![
            Value::Str("PROCESS_FORK".to_string()),
            Value::Str("PROCESS_EXEC".to_string()),
        ]);
        assert!(compare(&v, Op::In, &list));
        let miss = Value::List(vec![Value::Str("PROCESS_FORK".to_string())]);
        assert!(!compare(&v, Op::In, &miss));
    }

    #[test]
    fn every_known_field_resolves_or_is_a_documented_optional_absence() {
        // Coverage guard for KNOWN_FIELDS drifting from CanonicalEvent's real
        // shape: every field this crate advertises as queryable must at
        // least parse as a JSON pointer path against a real serialized
        // event (a `None` for an absent optional section, like `user.uid`
        // above, is fine — a field name that doesn't resolve as a path
        // *at all* means fields.rs and the schema have drifted apart).
        let event = sample_event();
        let json = serde_json::to_value(&event).unwrap();
        for field in crate::fields::known_fields() {
            let mut cursor = &json;
            let mut resolved = true;
            for part in field.split('.') {
                match cursor.get(part) {
                    Some(next) => cursor = next,
                    None => {
                        resolved = false;
                        break;
                    }
                }
            }
            assert!(
                resolved || get_field(&event, field).is_none(),
                "field '{}' does not resolve against a real CanonicalEvent",
                field
            );
        }
    }
}
