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

/// A boolean tree of conditions (ARCHITECTURE.md §12.3's AND/OR/NOT/
/// parentheses grammar, compiled directly into a rule's `conditions:`
/// field rather than through a general query-language parser — Phase 6
/// plan Global Constraint #2). Deserialized from one of four YAML shapes:
/// `{field, op, value, reason}` (a leaf match), `{all: [...]}`,
/// `{any: [...]}`, `{not: {...}}`. Order matters for serde's `untagged`
/// resolution: `All`/`Any`/`Not` are tried before `Match` so a node with an
/// `all`/`any`/`not` key is never mistaken for (or forced to also satisfy)
/// `Condition`'s required fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ConditionNode {
    All { all: Vec<ConditionNode> },
    Any { any: Vec<ConditionNode> },
    Not { not: Box<ConditionNode> },
    Match(Condition),
}

/// A compiled detection rule. `content_hash` is the SHA-256 of the exact
/// rule text, stored on every `Alert` this rule produces so an alert always
/// cites the precise rule revision that fired (§11.1). Exactly one of
/// `match_conditions` (non-empty) or `conditions` is populated —
/// `Rule::from_yaml_str` enforces this at load time (Phase 6 plan Global
/// Constraint #10). `window`+`sequence` are either both `None` (a plain
/// single-event rule) or both `Some` (a stateful sequence rule, Phase 6
/// plan Task 8) — never one without the other.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub version: u32,
    pub severity: Severity,
    pub match_conditions: Vec<Condition>,
    pub conditions: Option<ConditionNode>,
    pub content_hash: String,
    /// Sequence correlation window, nanoseconds.
    pub window: Option<u64>,
    pub sequence: Option<Vec<Condition>>,
}

/// The on-disk YAML shape. A strict subset of §11.1's rule structure:
/// `scope` and `mitre` remain unsupported and are rejected rather than
/// silently ignored (serde's default deny-unknown behaviour is off by
/// default, so `deny_unknown_fields` makes that explicit). `conditions`
/// (Phase 6 plan Task 2) and `window`/`sequence` (Task 8) are accepted
/// alongside the existing flat `match`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    id: String,
    version: u32,
    severity: Severity,
    #[serde(rename = "match", default)]
    match_conditions: Vec<Condition>,
    #[serde(default)]
    conditions: Option<ConditionNode>,
    #[serde(default)]
    window: Option<u64>,
    #[serde(default)]
    sequence: Option<Vec<Condition>>,
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
    #[error(
        "rule {id} sets both 'match' and 'conditions' — a rule must use exactly one condition form"
    )]
    ConflictingConditions { id: String },
    #[error("rule {id} condition {index} has a blank reason (ARCHITECTURE.md §11.2 requires one explanation per matched condition)")]
    EmptyReason { id: String, index: usize },
    #[error("rule {id} has a condition in its 'conditions' tree with a blank reason (ARCHITECTURE.md §11.2 requires one explanation per matched condition)")]
    EmptyConditionReason { id: String },
    #[error("rule {id} sets 'sequence' without 'window' — an unbounded sequence window is a resource-bound violation (ARCHITECTURE.md §19.1)")]
    SequenceWithoutWindow { id: String },
    #[error("rule {id} sets 'window' without 'sequence' — 'window' only has meaning for a sequence rule")]
    WindowWithoutSequence { id: String },
    #[error("rule {id} sequence has fewer than 2 steps — a sequence of one step is just a match condition")]
    SequenceTooShort { id: String },
}

fn condition_node_has_blank_reason(node: &ConditionNode) -> bool {
    match node {
        ConditionNode::Match(condition) => condition.reason.trim().is_empty(),
        ConditionNode::All { all } => all.iter().any(condition_node_has_blank_reason),
        ConditionNode::Any { any } => any.iter().any(condition_node_has_blank_reason),
        ConditionNode::Not { not } => condition_node_has_blank_reason(not),
    }
}

impl Rule {
    /// Parses and validates one rule. `origin` is only used in error
    /// messages — it deliberately does not feed the content hash, so
    /// renaming a rule file does not invalidate the alerts citing it.
    pub fn from_yaml_str(yaml: &str, origin: &str) -> Result<Self, RuleError> {
        let parsed: RuleFile = serde_yaml::from_str(yaml).map_err(|source| RuleError::Parse {
            origin: origin.to_string(),
            source,
        })?;
        if parsed.id.trim().is_empty() {
            return Err(RuleError::BlankId {
                origin: origin.to_string(),
            });
        }
        // window/sequence pairing is checked first and independently of
        // match/conditions, so a rule with e.g. both `match` and a lone
        // `window` (no `sequence`) is reported as the specific
        // WindowWithoutSequence mistake rather than the generic
        // ConflictingConditions.
        match (parsed.window, &parsed.sequence) {
            (Some(_), None) => return Err(RuleError::WindowWithoutSequence { id: parsed.id }),
            (None, Some(_)) => return Err(RuleError::SequenceWithoutWindow { id: parsed.id }),
            (Some(_), Some(steps)) if steps.len() < 2 => {
                return Err(RuleError::SequenceTooShort { id: parsed.id })
            }
            (Some(_), Some(steps)) => {
                for (index, condition) in steps.iter().enumerate() {
                    if condition.reason.trim().is_empty() {
                        return Err(RuleError::EmptyReason {
                            id: parsed.id.clone(),
                            index,
                        });
                    }
                }
            }
            (None, None) => {}
        }

        let has_match = !parsed.match_conditions.is_empty();
        let has_conditions = parsed.conditions.is_some();
        let has_sequence = parsed.sequence.is_some();
        if has_match && has_conditions {
            return Err(RuleError::ConflictingConditions { id: parsed.id });
        }
        if (has_match || has_conditions) && has_sequence {
            return Err(RuleError::ConflictingConditions { id: parsed.id });
        }
        if !has_match && !has_conditions && !has_sequence {
            return Err(RuleError::NoConditions { id: parsed.id });
        }
        if has_match {
            for (index, condition) in parsed.match_conditions.iter().enumerate() {
                if condition.reason.trim().is_empty() {
                    return Err(RuleError::EmptyReason {
                        id: parsed.id.clone(),
                        index,
                    });
                }
            }
        }
        if let Some(node) = &parsed.conditions {
            if condition_node_has_blank_reason(node) {
                return Err(RuleError::EmptyConditionReason { id: parsed.id });
            }
        }
        let mut hasher = Sha256::new();
        hasher.update(yaml.as_bytes());
        Ok(Self {
            id: parsed.id,
            version: parsed.version,
            severity: parsed.severity,
            match_conditions: parsed.match_conditions,
            conditions: parsed.conditions,
            content_hash: hex::encode(hasher.finalize()),
            window: parsed.window,
            sequence: parsed.sequence,
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
        assert_eq!(
            a.content_hash, b.content_hash,
            "the file name is not content"
        );
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

    const NESTED_RULE: &str = r#"
id: nested_boolean_rule
version: 1
severity: HIGH
conditions:
  any:
    - all:
        - field: event_type
          op: eq
          value: "FILE_CREATE"
          reason: "A file was created"
        - not:
            field: process.exe_path
            op: eq
            value: "/usr/sbin/nginx"
            reason: "unused — NOT never contributes a reason"
    - field: event_type
      op: eq
      value: "PRIVILEGE_SUDO"
      reason: "A sudo invocation occurred"
"#;

    #[test]
    fn parses_a_nested_all_any_not_condition_tree() {
        let rule = Rule::from_yaml_str(NESTED_RULE, "test.yaml").expect("must parse");
        assert_eq!(rule.id, "nested_boolean_rule");
        assert!(rule.match_conditions.is_empty());
        assert!(rule.conditions.is_some());
    }

    #[test]
    fn rejects_a_rule_that_sets_both_match_and_conditions() {
        let yaml = r#"
id: conflicting
version: 1
severity: LOW
match:
  - field: file.path
    op: eq
    value: "/x"
    reason: "because"
conditions:
  field: file.path
  op: eq
  value: "/x"
  reason: "because"
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "conflicting.yaml").unwrap_err(),
            RuleError::ConflictingConditions { .. }
        ));
    }

    #[test]
    fn rejects_a_conditions_tree_with_a_blank_reason_anywhere_in_it() {
        let yaml = r#"
id: unexplained_tree
version: 1
severity: LOW
conditions:
  all:
    - field: file.path
      op: eq
      value: "/x"
      reason: "because"
    - field: event_type
      op: eq
      value: "FILE_CREATE"
      reason: "   "
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "unexplained_tree.yaml").unwrap_err(),
            RuleError::EmptyConditionReason { .. }
        ));
    }

    const SEQUENCE_RULE: &str = r#"
id: network_download_then_write
version: 1
severity: HIGH
window: 30000000000
sequence:
  - field: event_type
    op: eq
    value: "NETWORK_CONNECT"
    reason: "The process opened a network connection"
  - field: event_type
    op: in
    value: ["FILE_CREATE", "FILE_WRITE"]
    reason: "The same process then created or wrote a file"
"#;

    #[test]
    fn parses_a_sequence_rule_with_a_window() {
        let rule = Rule::from_yaml_str(SEQUENCE_RULE, "test.yaml").expect("must parse");
        assert_eq!(rule.window, Some(30_000_000_000));
        assert_eq!(rule.sequence.as_ref().unwrap().len(), 2);
        assert!(rule.match_conditions.is_empty());
        assert!(rule.conditions.is_none());
    }

    #[test]
    fn rejects_sequence_without_window() {
        let yaml = r#"
id: bad
version: 1
severity: LOW
sequence:
  - field: event_type
    op: eq
    value: "A"
    reason: "r1"
  - field: event_type
    op: eq
    value: "B"
    reason: "r2"
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "bad.yaml").unwrap_err(),
            RuleError::SequenceWithoutWindow { .. }
        ));
    }

    #[test]
    fn rejects_window_without_sequence() {
        let yaml = r#"
id: bad
version: 1
severity: LOW
window: 1000
match:
  - field: event_type
    op: eq
    value: "A"
    reason: "r1"
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "bad.yaml").unwrap_err(),
            RuleError::WindowWithoutSequence { .. }
        ));
    }

    #[test]
    fn rejects_a_sequence_with_fewer_than_two_steps() {
        let yaml = r#"
id: bad
version: 1
severity: LOW
window: 1000
sequence:
  - field: event_type
    op: eq
    value: "A"
    reason: "r1"
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "bad.yaml").unwrap_err(),
            RuleError::SequenceTooShort { .. }
        ));
    }

    #[test]
    fn rejects_a_rule_that_sets_both_match_and_sequence() {
        let yaml = r#"
id: bad
version: 1
severity: LOW
window: 1000
sequence:
  - field: event_type
    op: eq
    value: "A"
    reason: "r1"
  - field: event_type
    op: eq
    value: "B"
    reason: "r2"
match:
  - field: event_type
    op: eq
    value: "C"
    reason: "r3"
"#;
        assert!(matches!(
            Rule::from_yaml_str(yaml, "bad.yaml").unwrap_err(),
            RuleError::ConflictingConditions { .. }
        ));
    }
}
