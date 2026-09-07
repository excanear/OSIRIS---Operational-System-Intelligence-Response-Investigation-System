use crate::rule::Operator;

/// Resolves a dotted field path against an event's JSON projection.
/// Matching against the serialized event rather than against
/// `CanonicalEvent`'s Rust fields is what lets a rule name any field in the
/// schema (`file.path`, `process.exe_path`, `event_type`) without this
/// crate hard-coding an accessor per field — and it means rule field names
/// are literally the schema's own JSON names, so §12.3's "field reference
/// generated from the Event Schema so it never drifts" stays achievable.
///
/// An explicit JSON `null` resolves to `None`, not to `Some(null)`: the
/// envelope sets every unused entity ref to `null`, so treating null as
/// present would make `network.dst_ip`-style conditions match on events
/// that have no network context at all.
pub fn field_value<'a>(
    event_json: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = event_json;
    for segment in path.split('.') {
        current = current.get(segment)?;
        if current.is_null() {
            return None;
        }
    }
    Some(current)
}

/// Applies one operator. Every comparison is total: a type mismatch is
/// `false`, never a panic and never a silent coercion that would make a
/// rule match something its author did not write.
pub fn matches(op: Operator, actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match op {
        Operator::Eq => actual == expected,
        Operator::Ne => actual != expected,
        Operator::In => expected
            .as_array()
            .map(|values| values.iter().any(|v| v == actual))
            .unwrap_or(false),
        Operator::Contains | Operator::StartsWith | Operator::EndsWith => {
            let (Some(actual), Some(expected)) = (actual.as_str(), expected.as_str()) else {
                return false;
            };
            match op {
                Operator::Contains => actual.contains(expected),
                Operator::StartsWith => actual.starts_with(expected),
                Operator::EndsWith => actual.ends_with(expected),
                _ => unreachable!("outer match already narrowed to the string operators"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Operator;
    use serde_json::json;

    fn event_json() -> serde_json::Value {
        json!({
            "event_type": "FILE_CREATE",
            "file": { "path": "/var/www/html/shell.php", "inode": 200001 },
            "process": { "exe_path": "/usr/bin/curl", "pid": 300 },
            "network": null,
            "tags": ["A", "B"]
        })
    }

    #[test]
    fn reads_a_top_level_field() {
        assert_eq!(
            field_value(&event_json(), "event_type"),
            Some(&json!("FILE_CREATE"))
        );
    }

    #[test]
    fn reads_a_nested_field_by_dotted_path() {
        assert_eq!(
            field_value(&event_json(), "file.path"),
            Some(&json!("/var/www/html/shell.php"))
        );
        assert_eq!(
            field_value(&event_json(), "process.exe_path"),
            Some(&json!("/usr/bin/curl"))
        );
    }

    #[test]
    fn returns_none_for_a_missing_or_null_field() {
        assert_eq!(field_value(&event_json(), "file.hash"), None);
        assert_eq!(field_value(&event_json(), "nope.at.all"), None);
        // An explicit JSON null is "not present" for matching purposes —
        // otherwise every `network.*` condition would match every process
        // event, where `network` is null.
        assert_eq!(field_value(&event_json(), "network"), None);
        assert_eq!(field_value(&event_json(), "network.dst_ip"), None);
    }

    #[test]
    fn string_operators_compare_strings() {
        let path = json!("/var/www/html/shell.php");
        assert!(matches(Operator::Eq, &path, &json!("/var/www/html/shell.php")));
        assert!(!matches(Operator::Eq, &path, &json!("/etc/passwd")));
        assert!(matches(Operator::Ne, &path, &json!("/etc/passwd")));
        assert!(matches(Operator::StartsWith, &path, &json!("/var/www/")));
        assert!(!matches(Operator::StartsWith, &path, &json!("/home/")));
        assert!(matches(Operator::EndsWith, &path, &json!(".php")));
        assert!(matches(Operator::Contains, &path, &json!("/html/")));
        assert!(!matches(Operator::Contains, &path, &json!("/etc/")));
    }

    #[test]
    fn in_matches_any_member_of_the_expected_array() {
        let exe = json!("/usr/bin/curl");
        assert!(matches(
            Operator::In,
            &exe,
            &json!(["/bin/bash", "/usr/bin/curl"])
        ));
        assert!(!matches(Operator::In, &exe, &json!(["/bin/bash"])));
        // A non-array `value` for `in` is a rule authoring mistake; it must
        // not match rather than being coerced into an equality test.
        assert!(!matches(Operator::In, &exe, &json!("/usr/bin/curl")));
    }

    /// A string operator against a non-string actual value (an integer
    /// inode, say) must be false, never a panic and never a coercion that
    /// makes a rule match something its author did not intend.
    #[test]
    fn string_operators_are_false_against_non_string_values() {
        let inode = json!(200001);
        assert!(!matches(Operator::StartsWith, &inode, &json!("2")));
        assert!(!matches(Operator::Contains, &inode, &json!("0")));
        assert!(!matches(Operator::EndsWith, &inode, &json!("1")));
    }

    #[test]
    fn eq_and_ne_work_on_non_string_values_too() {
        assert!(matches(Operator::Eq, &json!(300), &json!(300)));
        assert!(matches(Operator::Ne, &json!(300), &json!(301)));
    }
}
