use serde::Deserialize;
use sha2::{Digest, Sha256};

use osiris_schema::Severity;

/// The comparison operators this phase supports — a subset of §12.3's OQL
/// operator set, restricted to what single-event matching needs. No regex:
/// an unbounded-backtracking matcher on the ingestion hot path is a
/// denial-of-service surface, and nothing in this phase's rules needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
    In,
}

/// One matchable condition. `reason` is **required**, not optional: it is
/// the explanation that lands in the resulting `Alert.reasons`, one per
/// matched condition, which is how ARCHITECTURE.md §11.2's "not a generic
/// template" requirement is made structural rather than a convention
/// (Phase 2 plan Global Constraints #10).
#[derive(Debug, Clone, Deserialize)]
pub struct Condition {
    /// Dotted path into the event's JSON projection, e.g. `file.path`,
    /// `process.exe_path`, `event_type`.
    pub field: String,
    pub op: Operator,
    pub value: serde_json::Value,
    pub reason: String,
}

/// A compiled detection rule. `content_hash` is the SHA-256 of the exact
/// rule text, stored on every `Alert` this rule produces so an alert always
/// cites the precise rule revision that fired (§11.1).
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub version: u32,
    pub severity: Severity,
    pub match_conditions: Vec<Condition>,
    pub content_hash: String,
}

/// The on-disk YAML shape. A strict subset of §11.1's rule structure:
/// `window`, `sequence`, `scope` and `mitre` are Phase 6 and are rejected
/// rather than silently ignored (serde's default deny-unknown behaviour is
/// off by default, so `deny_unknown_fields` makes that explicit).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    id: String,
    version: u32,
    severity: Severity,
    #[serde(rename = "match")]
    match_conditions: Vec<Condition>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("failed to read rule file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse rule {origin}: {source}")]
    Parse {
        origin: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("rule {origin} has a blank id")]
    BlankId { origin: String },
    #[error("rule {id} has no match conditions — it would fire on everything")]
    NoConditions { id: String },
    #[error("rule {id} condition {index} has a blank reason (ARCHITECTURE.md §11.2 requires one explanation per matched condition)")]
    EmptyReason { id: String, index: usize },
}

impl Rule {
    /// Parses and validates one rule. `origin` is only used in error
    /// messages — it deliberately does not feed the content hash, so
    /// renaming a rule file does not invalidate the alerts citing it.
    pub fn from_yaml_str(yaml: &str, origin: &str) -> Result<Self, RuleError> {
        let parsed: RuleFile =
            serde_yaml::from_str(yaml).map_err(|source| RuleError::Parse {
                origin: origin.to_string(),
                source,
            })?;
        if parsed.id.trim().is_empty() {
            return Err(RuleError::BlankId {
                origin: origin.to_string(),
            });
        }
        if parsed.match_conditions.is_empty() {
            return Err(RuleError::NoConditions { id: parsed.id });
        }
        for (index, condition) in parsed.match_conditions.iter().enumerate() {
            if condition.reason.trim().is_empty() {
                return Err(RuleError::EmptyReason {
                    id: parsed.id.clone(),
                    index,
                });
            }
        }
        let mut hasher = Sha256::new();
        hasher.update(yaml.as_bytes());
        Ok(Self {
            id: parsed.id,
            version: parsed.version,
            severity: parsed.severity,
            match_conditions: parsed.match_conditions,
            content_hash: hex::encode(hasher.finalize()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RULE: &str = r#"
id: shell_wrote_file_to_web_root
version: 1
severity: HIGH
match:
  - field: event_type
    op: in
    value: ["FILE_CREATE", "FILE_WRITE"]
    reason: "A file was created or written on disk"
  - field: file.path
    op: starts_with
    value: "/var/www/"
    reason: "The file was written inside the web-served directory /var/www/"
"#;

    #[test]
    fn parses_a_valid_rule() {
        let rule = Rule::from_yaml_str(VALID_RULE, "test.yaml").expect("must parse");
        assert_eq!(rule.id, "shell_wrote_file_to_web_root");
        assert_eq!(rule.version, 1);
        assert_eq!(rule.severity, osiris_schema::Severity::High);
        assert_eq!(rule.match_conditions.len(), 2);
        assert_eq!(rule.match_conditions[0].op, Operator::In);
        assert_eq!(rule.match_conditions[1].op, Operator::StartsWith);
        assert_eq!(rule.match_conditions[1].field, "file.path");
    }

    /// §11.1 requires an alert to cite the exact rule version that fired,
    /// which means hashing the rule's own text — a version number alone
    /// cannot distinguish an edited rule from its predecessor.
    #[test]
    fn content_hash_is_a_stable_sha256_of_the_rule_text() {
        let a = Rule::from_yaml_str(VALID_RULE, "test.yaml").unwrap();
        let b = Rule::from_yaml_str(VALID_RULE, "other-name.yaml").unwrap();
        assert_eq!(a.content_hash, b.content_hash, "the file name is not content");
        assert_eq!(a.content_hash.len(), 64);

        let edited = VALID_RULE.replace("/var/www/", "/srv/www/");
        let c = Rule::from_yaml_str(&edited, "test.yaml").unwrap();
        assert_ne!(a.content_hash, c.content_hash);
    }

    #[test]
    fn rejects_a_rule_with_no_match_conditions() {
        let yaml = "id: empty\nversion: 1\nseverity: LOW\nmatch: []\n";
        let err = Rule::from_yaml_str(yaml, "empty.yaml").unwrap_err();
        assert!(matches!(err, RuleError::NoConditions { .. }));
    }

    /// The structural half of §11.2: a rule that cannot explain a match is
    /// rejected at load time, so no alert can ever carry a blank reason.
    #[test]
    fn rejects_a_condition_with_a_blank_reason() {
        let yaml = r#"
id: unexplained
version: 1
severity: LOW
match:
  - field: file.path
    op: starts_with
    value: "/var/www/"
    reason: "   "
"#;
        let err = Rule::from_yaml_str(yaml, "unexplained.yaml").unwrap_err();
        assert!(matches!(err, RuleError::EmptyReason { index: 0, .. }));
    }

    #[test]
    fn rejects_a_rule_with_a_blank_id() {
        let yaml = r#"
id: "  "
version: 1
severity: LOW
match:
  - field: file.path
    op: eq
    value: "/x"
    reason: "because"
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "blank.yaml").unwrap_err(),
            RuleError::BlankId { .. }
        ));
    }

    #[test]
    fn rejects_malformed_yaml_naming_the_origin() {
        let err = Rule::from_yaml_str("id: [unclosed", "broken.yaml").unwrap_err();
        assert!(err.to_string().contains("broken.yaml"));
    }

    #[test]
    fn rejects_an_unknown_operator_rather_than_silently_never_matching() {
        let yaml = r#"
id: bad_op
version: 1
severity: LOW
match:
  - field: file.path
    op: regex_matches
    value: ".*"
    reason: "because"
"#;
        assert!(Rule::from_yaml_str(yaml, "bad_op.yaml").is_err());
    }
}
