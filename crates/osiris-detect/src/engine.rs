use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use osiris_schema::{Alert, CanonicalEvent};
use uuid::Uuid;

use crate::eval::{eval_node, field_value, matches};
use crate::rule::{Rule, RuleError};

/// In-progress state for one `(rule_id, subject_key)` pair (Phase 6 plan
/// Task 8). `subject_key` is the triggering event's `process_key` hex, or
/// its `session_id` when no process is present — the same subject-key
/// derivation `derive_subject_key` below implements once and every
/// sequence rule shares.
#[derive(Debug, Clone)]
struct SequenceState {
    next_step: usize,
    started_at: u64,
    event_ids: Vec<Uuid>,
}

/// Derives the entity a sequence rule tracks progress against (Phase 6
/// plan Global Constraint #7): the event's `process_key` when present,
/// else its `session_id`, else `None` — a rule cannot enter sequence state
/// for an event with neither (this is documented, not a silent gap: every
/// `sequence` rule this phase ships targets process-carrying event types).
fn derive_subject_key(event: &CanonicalEvent) -> Option<String> {
    if let Some(process) = &event.process {
        return Some(process.process_key.as_hex());
    }
    event.session.as_ref().map(|s| s.session_id.clone())
}

/// The Detection Engine: compiles the OQL-native YAML rule format (§11.1)
/// into a matcher tree — stateless single-event conditions (flat `match:`
/// or a `conditions:` boolean tree, §12.3) evaluated inline, and stateful
/// `sequence`/`window` conditions tracked in a bounded per-subject state
/// table (Phase 6 plan Task 8), exactly the execution model §11.1
/// describes. Runs on the Server's ingestion path, after each successful
/// `batch_write` — never on the Agent, which must not link this crate at
/// all (§27's privilege boundary).
#[derive(Debug)]
pub struct DetectionEngine {
    rules: Vec<Rule>,
    sequence_state: Mutex<HashMap<(String, String), SequenceState>>,
}

impl DetectionEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            sequence_state: Mutex::new(HashMap::new()),
        }
    }

    /// Loads every `*.yaml`/`*.yml` file in `dir`, sorted by file name so
    /// rule order — and therefore alert order — is deterministic across
    /// runs and platforms (directory iteration order is not).
    pub fn load_from_dir(dir: &Path) -> Result<Self, RuleError> {
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .map_err(|source| RuleError::Read {
                path: dir.display().to_string(),
                source,
            })?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        paths.sort();

        let mut rules = Vec::with_capacity(paths.len());
        for path in paths {
            let origin = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unnamed>")
                .to_string();
            let yaml = std::fs::read_to_string(&path).map_err(|source| RuleError::Read {
                path: path.display().to_string(),
                source,
            })?;
            rules.push(Rule::from_yaml_str(&yaml, &origin)?);
        }
        tracing::info!(rule_count = rules.len(), dir = %dir.display(), "loaded detection rules");
        Ok(Self::new(rules))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluates one event against every rule, returning one `Alert` per
    /// single-event rule whose conditions all matched, plus one `Alert`
    /// per sequence rule that completed its final step on this event.
    pub fn evaluate(&self, event: &CanonicalEvent) -> Vec<Alert> {
        if self.rules.is_empty() {
            return vec![];
        }
        // Serialize once per event, not once per rule.
        let Ok(event_json) = serde_json::to_value(event) else {
            tracing::error!(
                event_id = %event.event_id,
                "could not project event to JSON for rule evaluation; skipping it"
            );
            return vec![];
        };

        let mut alerts: Vec<Alert> = self
            .rules
            .iter()
            .filter(|rule| rule.sequence.is_none())
            .filter_map(|rule| self.evaluate_rule(rule, event, &event_json))
            .collect();
        alerts.extend(self.evaluate_sequence_rules(event, &event_json));
        alerts
    }

    /// Advances (or starts) every sequence rule's per-subject state
    /// against `event`, firing an `Alert` for any rule that just completed
    /// its final step. An event a sequence step doesn't match leaves any
    /// existing in-progress state untouched — steps need not be adjacent —
    /// and state older than the rule's `window` is dropped before being
    /// considered, so a stale, never-completed sequence cannot be revived
    /// by an unrelated later event.
    fn evaluate_sequence_rules(
        &self,
        event: &CanonicalEvent,
        event_json: &serde_json::Value,
    ) -> Vec<Alert> {
        let sequence_rules: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| r.sequence.is_some())
            .collect();
        if sequence_rules.is_empty() {
            return vec![];
        }
        let Some(subject_key) = derive_subject_key(event) else {
            return vec![];
        };

        let mut alerts = Vec::new();
        let mut state_map = match self.sequence_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        for rule in sequence_rules {
            let steps = rule.sequence.as_ref().expect("filtered to Some above");
            let window = rule.window.expect("Rule::from_yaml_str requires both");
            let state_key = (rule.id.clone(), subject_key.clone());

            let stale = state_map
                .get(&state_key)
                .map(|s| event.timestamp.saturating_sub(s.started_at) > window)
                .unwrap_or(false);
            if stale {
                state_map.remove(&state_key);
            }

            let step_index = state_map.get(&state_key).map(|s| s.next_step).unwrap_or(0);
            let condition = &steps[step_index];
            let matched = field_value(event_json, &condition.field)
                .map(|actual| matches(condition.op, actual, &condition.value))
                .unwrap_or(false);
            if !matched {
                continue;
            }

            let entry = state_map.entry(state_key.clone()).or_insert_with(|| SequenceState {
                next_step: 0,
                started_at: event.timestamp,
                event_ids: Vec::with_capacity(steps.len()),
            });
            entry.event_ids.push(event.event_id);
            entry.next_step += 1;

            if entry.next_step == steps.len() {
                let event_ids = entry.event_ids.clone();
                state_map.remove(&state_key);
                let reasons: Vec<String> = steps.iter().map(|c| c.reason.clone()).collect();
                match Alert::new(
                    rule.id.clone(),
                    rule.version,
                    rule.content_hash.clone(),
                    rule.severity,
                    event.timestamp,
                    event.host_id,
                    reasons,
                    event_ids,
                ) {
                    Ok(alert) => alerts.push(alert),
                    Err(e) => {
                        tracing::error!(rule_id = %rule.id, error = %e, "sequence rule completed but produced an invalid alert; dropping it");
                    }
                }
            }
        }
        alerts
    }

    pub fn evaluate_batch(&self, events: &[CanonicalEvent]) -> Vec<Alert> {
        events.iter().flat_map(|e| self.evaluate(e)).collect()
    }

    fn evaluate_rule(
        &self,
        rule: &Rule,
        event: &CanonicalEvent,
        event_json: &serde_json::Value,
    ) -> Option<Alert> {
        let reasons = if let Some(node) = &rule.conditions {
            eval_node(node, event_json)?
        } else {
            let mut reasons = Vec::with_capacity(rule.match_conditions.len());
            for condition in &rule.match_conditions {
                // A missing (or null) field never matches — a file rule
                // must not fire on a process event that carries no `file`
                // at all.
                let actual = field_value(event_json, &condition.field)?;
                if !matches(condition.op, actual, &condition.value) {
                    return None;
                }
                reasons.push(condition.reason.clone());
            }
            reasons
        };
        match Alert::new(
            rule.id.clone(),
            rule.version,
            rule.content_hash.clone(),
            rule.severity,
            event.timestamp,
            event.host_id,
            reasons,
            vec![event.event_id],
        ) {
            Ok(alert) => Some(alert),
            // Unreachable in practice: `Rule::from_yaml_str` rejects a blank
            // id, zero conditions, and blank reasons, and evidence is always
            // exactly one event_id. Logged rather than unwrapped so a future
            // rule-format change surfaces as a visible error, not a panic on
            // the Server's ingestion path.
            Err(e) => {
                tracing::error!(rule_id = %rule.id, error = %e, "rule matched but produced an invalid alert; dropping it");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        EventType, FileRef, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
    };
    use uuid::Uuid;

    const WEB_ROOT_RULE: &str = r#"
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
  - field: process.exe_path
    op: in
    value: ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget"]
    reason: "The writing process is an interactive shell or download tool, not the web server"
"#;

    fn event(event_type: EventType, path: &str, exe_path: &str) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 1,
            event_type,
            category: event_type.category(),
            severity: Severity::Info,
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
                process_key: ProcessKey::new(host_id, "b", 300, 1),
                pid: 300,
                exe_path: exe_path.to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
            parent_process: None,
            thread: None,
            file: Some(FileRef {
                path: path.to_string(),
                previous_path: None,
                inode: Some(200001),
                device_id: Some(osiris_schema::encode_device_id(8, 1)),
                size: None,
                mode: None,
                owner_uid: None,
                owner_gid: None,
                hash: None,
            }),
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
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    fn engine() -> DetectionEngine {
        DetectionEngine::new(vec![
            crate::rule::Rule::from_yaml_str(WEB_ROOT_RULE, "test.yaml").unwrap()
        ])
    }

    #[test]
    fn fires_on_a_shell_writing_into_the_web_root() {
        let event = event(
            EventType::FileCreate,
            "/var/www/html/shell.php",
            "/usr/bin/curl",
        );
        let alerts = engine().evaluate(&event);
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.rule_id(), "shell_wrote_file_to_web_root");
        assert_eq!(alert.rule_version(), 1);
        assert_eq!(alert.severity(), Severity::High);
        assert_eq!(alert.timestamp(), event.timestamp);
        assert_eq!(alert.host_id(), event.host_id);
        assert_eq!(alert.evidence(), &[event.event_id]);
        assert_eq!(alert.rule_content_hash().len(), 64);
    }

    /// §11.2: one reason per matched condition, each specific enough to be
    /// actionable — never "Threat detected".
    #[test]
    fn the_alert_explains_every_matched_condition_specifically() {
        let alerts = engine().evaluate(&event(
            EventType::FileWrite,
            "/var/www/html/shell.php",
            "/bin/bash",
        ));
        let reasons = alerts[0].reasons();
        assert_eq!(reasons.len(), 3);
        assert!(reasons[1].contains("/var/www/"));
        assert!(reasons[2].contains("shell or download tool"));
        assert!(reasons.iter().all(|r| !r.trim().is_empty()));
    }

    #[test]
    fn does_not_fire_when_the_path_is_outside_the_web_root() {
        let alerts = engine().evaluate(&event(
            EventType::FileWrite,
            "/home/user/notes.txt",
            "/bin/bash",
        ));
        assert!(alerts.is_empty());
    }

    #[test]
    fn does_not_fire_when_the_writer_is_the_web_server_itself() {
        let alerts = engine().evaluate(&event(
            EventType::FileWrite,
            "/var/www/html/cache/page.html",
            "/usr/sbin/nginx",
        ));
        assert!(alerts.is_empty());
    }

    #[test]
    fn does_not_fire_on_a_rename_because_the_rule_names_only_create_and_write() {
        let alerts = engine().evaluate(&event(
            EventType::FileRename,
            "/var/www/html/shell.php",
            "/usr/bin/curl",
        ));
        assert!(alerts.is_empty());
    }

    /// A condition naming a field the event doesn't carry must not match —
    /// a process event has no `file`, so a file rule must never fire on it.
    #[test]
    fn does_not_fire_on_an_event_missing_the_referenced_field() {
        let mut process_event = event(EventType::ProcessExec, "/ignored", "/usr/bin/curl");
        process_event.file = None;
        assert!(engine().evaluate(&process_event).is_empty());
    }

    #[test]
    fn evaluate_batch_returns_one_alert_per_matching_event() {
        let events = vec![
            event(EventType::FileCreate, "/var/www/html/a.php", "/usr/bin/curl"),
            event(EventType::FileWrite, "/home/user/notes.txt", "/bin/bash"),
            event(EventType::FileWrite, "/var/www/html/b.php", "/bin/bash"),
        ];
        let alerts = engine().evaluate_batch(&events);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].evidence(), &[events[0].event_id]);
        assert_eq!(alerts[1].evidence(), &[events[2].event_id]);
    }

    #[test]
    fn an_engine_with_no_rules_produces_no_alerts() {
        let engine = DetectionEngine::new(vec![]);
        assert_eq!(engine.rule_count(), 0);
        assert!(engine
            .evaluate(&event(
                EventType::FileCreate,
                "/var/www/html/shell.php",
                "/usr/bin/curl"
            ))
            .is_empty());
    }

    #[test]
    fn loads_every_yaml_rule_in_a_directory_in_a_deterministic_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b_rule.yaml"), WEB_ROOT_RULE).unwrap();
        std::fs::write(
            dir.path().join("a_rule.yml"),
            WEB_ROOT_RULE.replace("id: shell_wrote_file_to_web_root", "id: a_rule"),
        )
        .unwrap();
        // Non-rule files in the directory are ignored, not parsed.
        std::fs::write(dir.path().join("README.md"), "not a rule").unwrap();

        let engine = DetectionEngine::load_from_dir(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 2);
        let alerts = engine.evaluate(&event(
            EventType::FileCreate,
            "/var/www/html/shell.php",
            "/usr/bin/curl",
        ));
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].rule_id(), "a_rule", "rules load in file-name order");
        assert_eq!(alerts[1].rule_id(), "shell_wrote_file_to_web_root");
    }

    #[test]
    fn load_from_dir_reports_the_offending_file_when_a_rule_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.yaml"), "id: [unclosed").unwrap();
        let err = DetectionEngine::load_from_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("broken.yaml"));
    }

    #[test]
    fn load_from_dir_on_a_missing_directory_is_an_error_not_a_silent_empty_engine() {
        let dir = tempfile::tempdir().unwrap();
        assert!(DetectionEngine::load_from_dir(&dir.path().join("nope")).is_err());
    }

    /// The repository's own shipped rule must load and behave — this is the
    /// CI-enforced half of §11.1's "every rule ships with a fixture that
    /// must trigger it, and a negative fixture that must not".
    #[test]
    fn the_shipped_web_root_rule_loads_and_fires_on_its_positive_fixture_only() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/shell_wrote_file_to_web_root.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("shipped rule must exist at {}: {e}", path.display()));
        let engine = DetectionEngine::new(vec![
            crate::rule::Rule::from_yaml_str(&yaml, "shell_wrote_file_to_web_root.yaml").unwrap()
        ]);
        assert_eq!(
            engine
                .evaluate(&event(
                    EventType::FileCreate,
                    "/var/www/html/shell.php",
                    "/usr/bin/curl"
                ))
                .len(),
            1
        );
        assert!(engine
            .evaluate(&event(
                EventType::FileWrite,
                "/home/user/notes.txt",
                "/bin/bash"
            ))
            .is_empty());
    }

    fn dns_event(query: &str, exe_path: &str) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 1,
            event_type: EventType::DnsQuery,
            category: EventType::DnsQuery.category(),
            severity: Severity::Info,
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
                process_key: ProcessKey::new(host_id, "b", 300, 1),
                pid: 300,
                exe_path: exe_path.to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: Some(osiris_schema::DnsRef {
                query: query.to_string(),
                qtype: "A".to_string(),
                response_ips: vec!["203.0.113.50".to_string()],
                ttl: Some(300),
            }),
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
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    /// The repository's own shipped rule must load and behave — this is the
    /// CI-enforced half of §11.1's "every rule ships with a fixture that
    /// must trigger it, and a negative fixture that must not," proving
    /// this phase's dns.*/process.* fields work through the engine
    /// unmodified (Phase 3 plan Global Constraints #12).
    #[test]
    fn the_shipped_dns_suspicious_tld_rule_loads_and_fires_on_its_positive_fixture_only() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/dns_query_to_suspicious_tld.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("shipped rule must exist at {}: {e}", path.display()));
        let engine = DetectionEngine::new(vec![
            crate::rule::Rule::from_yaml_str(&yaml, "dns_query_to_suspicious_tld.yaml").unwrap()
        ]);
        let alerts = engine.evaluate(&dns_event("cdn-assets.xyz", "/usr/bin/curl"));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "dns_query_to_suspicious_tld");

        assert!(engine
            .evaluate(&dns_event("example.com", "/usr/bin/curl"))
            .is_empty());
    }

    /// The rule loaded alongside the Phase 2 rule (via `load_from_dir`) must
    /// not cross-fire on the other rule's positive fixture — proves the two
    /// shipped rules stay independent as `config/rules/` grows.
    #[test]
    fn both_shipped_rules_load_together_without_cross_firing() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        assert!(engine.rule_count() >= 2);

        let dns_alerts = engine.evaluate(&dns_event("cdn-assets.xyz", "/usr/bin/curl"));
        assert_eq!(dns_alerts.len(), 1);
        assert_eq!(dns_alerts[0].rule_id(), "dns_query_to_suspicious_tld");
    }

    fn escalation_event(
        event_type: EventType,
        target_uid: Option<u32>,
        remote_addr: Option<&str>,
    ) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        let mut event = event(event_type, "/unused", "/usr/bin/sudo");
        event.host_id = host_id;
        event.category = event_type.category();
        event.file = None;
        event.user = Some(osiris_schema::UserRef {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            username: Some("alice".to_string()),
            loginuid: Some(1000),
        });
        event.session = Some(osiris_schema::SessionRef {
            session_id: "3".to_string(),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: remote_addr.map(str::to_string),
            auth_method: Some("sshd".to_string()),
        });
        event.event_data = serde_json::json!({
            "comm": "sudo",
            "ppid": 200,
            "uid": 1000,
            "target_uid": target_uid,
            "target_gid": serde_json::Value::Null,
            "success": true,
        });
        event
    }

    #[test]
    fn the_shipped_privilege_escalation_rule_loads_and_fires_on_its_positive_fixture_only() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/privilege_escalation_to_root_in_remote_session.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
        let engine = DetectionEngine::new(vec![Rule::from_yaml_str(
            &yaml,
            "privilege_escalation_to_root_in_remote_session.yaml",
        )
        .expect("the shipped rule must parse")]);

        // Positive: a real escalation to root inside an SSH session.
        let alerts = engine.evaluate(&escalation_event(
            EventType::PrivilegeUidChange,
            Some(0),
            Some("198.51.100.10"),
        ));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "privilege_escalation_to_root_in_remote_session");
        assert_eq!(alerts[0].severity(), Severity::High);
        // §11.2's structural requirement: one specific explanation per
        // matched condition, none of them blank or generic.
        let reasons = alerts[0].reasons();
        assert_eq!(reasons.len(), 3);
        assert!(reasons.iter().all(|r| !r.trim().is_empty()));
        assert!(reasons.iter().any(|r| r.contains("root")));
        assert!(reasons.iter().any(|r| r.contains("remote")));
    }

    /// The negative the whole rule turns on: the same escalation, from a
    /// local console session with no remote address, must NOT fire. This is
    /// what stops the rule alerting on every `sudo` a sysadmin runs at the
    /// keyboard — and it works because `field_value` maps a null
    /// `session.remote_addr` to `None` and `evaluate_rule` short-circuits.
    #[test]
    fn the_privilege_escalation_rule_does_not_fire_on_a_local_escalation() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/privilege_escalation_to_root_in_remote_session.yaml");
        let yaml = std::fs::read_to_string(&path).unwrap();
        let engine = DetectionEngine::new(vec![
            Rule::from_yaml_str(&yaml, "privilege_escalation.yaml").unwrap()
        ]);

        // No remote address at all (a tty1 login).
        assert!(engine
            .evaluate(&escalation_event(EventType::PrivilegeUidChange, Some(0), None))
            .is_empty());

        // No session whatsoever (a daemon escalating outside any login).
        let mut sessionless = escalation_event(EventType::PrivilegeUidChange, Some(0), None);
        sessionless.session = None;
        assert!(engine.evaluate(&sessionless).is_empty());
    }

    #[test]
    fn the_privilege_escalation_rule_does_not_fire_on_a_non_root_or_non_uid_transition() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/privilege_escalation_to_root_in_remote_session.yaml");
        let yaml = std::fs::read_to_string(&path).unwrap();
        let engine = DetectionEngine::new(vec![
            Rule::from_yaml_str(&yaml, "privilege_escalation.yaml").unwrap()
        ]);

        // Escalating to a non-root account is not this rule's concern.
        assert!(engine
            .evaluate(&escalation_event(
                EventType::PrivilegeUidChange,
                Some(48),
                Some("198.51.100.10")
            ))
            .is_empty());

        // A gid change to gid 0 is not a uid escalation, and Task 2 never
        // puts a target_uid on one.
        assert!(engine
            .evaluate(&escalation_event(
                EventType::PrivilegeGidChange,
                None,
                Some("198.51.100.10")
            ))
            .is_empty());

        // A sudo invocation carries no reliable target account (Global
        // Constraint #9), so `event_data.target_uid` is null and the rule
        // must not fire on it — the rule detects the transition, not the
        // intent to make one.
        assert!(engine
            .evaluate(&escalation_event(
                EventType::PrivilegeSudo,
                None,
                Some("198.51.100.10")
            ))
            .is_empty());
    }

    /// All three shipped rules must load together and stay independent as
    /// `config/rules/` grows — the same guard Phase 3 added for two.
    #[test]
    fn all_three_shipped_rules_load_together_without_cross_firing() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        assert!(engine.rule_count() >= 3);

        let alerts = engine.evaluate(&escalation_event(
            EventType::PrivilegeUidChange,
            Some(0),
            Some("198.51.100.10"),
        ));
        assert_eq!(
            alerts.len(),
            1,
            "an escalation event must fire exactly the escalation rule — neither the \
             web-root file rule nor the DNS rule"
        );
        assert_eq!(alerts[0].rule_id(), "privilege_escalation_to_root_in_remote_session");
    }

    fn systemd_start_event(unit_name: &str, remote_addr: Option<&str>) -> CanonicalEvent {
        let mut e = event(EventType::ServiceStart, "/unused", "/usr/lib/systemd/systemd");
        e.file = None;
        e.service = Some(osiris_schema::ServiceRef {
            unit_name: unit_name.to_string(),
            unit_type: "service".to_string(),
            action: "start".to_string(),
        });
        e.session = remote_addr.map(|addr| osiris_schema::SessionRef {
            session_id: "3".to_string(),
            tty: None,
            remote_addr: Some(addr.to_string()),
            auth_method: Some("sshd".to_string()),
        });
        e
    }

    #[test]
    fn the_shipped_systemd_remote_start_rule_loads_and_fires_on_its_positive_fixture_only() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();

        let event = systemd_start_event("backdoor.service", Some("198.51.100.10"));
        let alerts = engine.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "systemd_service_started_in_remote_session");
        assert_eq!(alerts[0].severity(), Severity::High);
        assert_eq!(alerts[0].reasons().len(), 2);
    }

    #[test]
    fn the_shipped_systemd_remote_start_rule_does_not_fire_on_a_local_or_sessionless_start() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();

        // No session at all (a unit started at boot with no D-Bus caller).
        let local = systemd_start_event("cron.service", None);
        assert!(engine.evaluate(&local).is_empty());
    }

    #[test]
    fn the_shipped_systemd_remote_start_rule_does_not_fire_on_a_service_stop() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();

        let mut e = systemd_start_event("backdoor.service", Some("198.51.100.10"));
        e.event_type = EventType::ServiceStop;
        e.category = EventType::ServiceStop.category();
        assert!(engine.evaluate(&e).is_empty());
    }

    /// All four shipped rules must load together and stay independent as
    /// `config/rules/` grows — the same guard Phase 3 added for two and
    /// Phase 4a added for three.
    #[test]
    fn all_four_shipped_rules_load_together_without_cross_firing() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        assert!(engine.rule_count() >= 4);

        let event = systemd_start_event("backdoor.service", Some("198.51.100.10"));
        let alerts = engine.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "systemd_service_started_in_remote_session");
    }

    fn container_start_event(container_id: &str, remote_addr: Option<&str>) -> CanonicalEvent {
        let mut e = event(EventType::ContainerStart, "/unused", "/usr/bin/docker");
        e.file = None;
        e.container = Some(osiris_schema::ContainerRef {
            container_id: container_id.to_string(),
            image: String::new(),
            runtime: "cgroup".to_string(),
            pod_ref: None,
        });
        e.session = remote_addr.map(|addr| osiris_schema::SessionRef {
            session_id: "3".to_string(),
            tty: None,
            remote_addr: Some(addr.to_string()),
            auth_method: Some("sshd".to_string()),
        });
        e
    }

    #[test]
    fn the_shipped_container_remote_start_rule_loads_and_fires_on_its_positive_fixture_only() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();

        let event = container_start_event(&"d".repeat(64), Some("198.51.100.10"));
        let alerts = engine.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "container_started_in_remote_session");
        assert_eq!(alerts[0].severity(), Severity::High);
        assert_eq!(alerts[0].reasons().len(), 2);
    }

    #[test]
    fn the_shipped_container_remote_start_rule_does_not_fire_on_a_local_or_sessionless_start() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();

        // No session at all — the cgroup-only fallback backend could not
        // attribute an actor pid (plan Global Constraint #1).
        let local = container_start_event(&"e".repeat(64), None);
        assert!(engine.evaluate(&local).is_empty());
    }

    #[test]
    fn the_shipped_container_remote_start_rule_does_not_fire_on_a_container_stop() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();

        let mut e = container_start_event(&"f".repeat(64), Some("198.51.100.10"));
        e.event_type = EventType::ContainerStop;
        e.category = EventType::ContainerStop.category();
        assert!(engine.evaluate(&e).is_empty());
    }

    /// All five shipped rules must load together and stay independent as
    /// `config/rules/` grows — the same guard every earlier phase added.
    #[test]
    fn all_five_shipped_rules_load_together_without_cross_firing() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        assert!(engine.rule_count() >= 5);

        let event = container_start_event(&"a".repeat(64), Some("198.51.100.10"));
        let alerts = engine.evaluate(&event);
        assert_eq!(
            alerts.len(),
            1,
            "a container-start event must fire exactly the container rule — none of the \
             file/DNS/privilege/systemd rules"
        );
        assert_eq!(alerts[0].rule_id(), "container_started_in_remote_session");
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

    fn sequence_engine() -> DetectionEngine {
        DetectionEngine::new(vec![Rule::from_yaml_str(SEQUENCE_RULE, "seq.yaml").unwrap()])
    }

    fn network_connect_event(host_id: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
        let mut e = event(EventType::NetworkConnect, "/unused", "/usr/bin/curl");
        e.host_id = host_id;
        e.timestamp = timestamp;
        e.file = None;
        e.process = Some(ProcessRef {
            process_key: ProcessKey::new(host_id, "b", pid, 1),
            pid,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1,
        });
        e.network = Some(osiris_schema::NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 4444,
            dst_ip: "203.0.113.10".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        e
    }

    fn file_write_event(host_id: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
        let mut e = event(EventType::FileCreate, "/tmp/payload", "/usr/bin/curl");
        e.host_id = host_id;
        e.timestamp = timestamp;
        e.process = Some(ProcessRef {
            process_key: ProcessKey::new(host_id, "b", pid, 1),
            pid,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1,
        });
        e
    }

    #[test]
    fn a_sequence_rule_fires_when_both_steps_match_the_same_process_within_the_window() {
        let engine = sequence_engine();
        let host_id = Uuid::new_v4();
        let connect = network_connect_event(host_id, 300, 1_000_000_000);
        let write = file_write_event(host_id, 300, 1_000_000_000 + 5_000_000_000);

        assert!(engine.evaluate(&connect).is_empty());
        let alerts = engine.evaluate(&write);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "network_download_then_write");
        assert_eq!(alerts[0].evidence(), &[connect.event_id, write.event_id]);
        assert_eq!(alerts[0].reasons().len(), 2);
    }

    #[test]
    fn a_sequence_rule_does_not_fire_outside_its_window() {
        let engine = sequence_engine();
        let host_id = Uuid::new_v4();
        let connect = network_connect_event(host_id, 300, 1_000_000_000);
        // 60s later — the rule's window is 30s.
        let write = file_write_event(host_id, 300, 1_000_000_000 + 60_000_000_000);

        assert!(engine.evaluate(&connect).is_empty());
        assert!(engine.evaluate(&write).is_empty());
    }

    #[test]
    fn an_interleaving_unrelated_event_does_not_reset_sequence_progress() {
        let engine = sequence_engine();
        let host_id = Uuid::new_v4();
        let connect = network_connect_event(host_id, 300, 1_000_000_000);
        let unrelated = event(EventType::ProcessExit, "/unused", "/usr/bin/curl");
        let write = file_write_event(host_id, 300, 1_000_000_000 + 2_000_000_000);

        assert!(engine.evaluate(&connect).is_empty());
        assert!(engine.evaluate(&unrelated).is_empty());
        let alerts = engine.evaluate(&write);
        assert_eq!(alerts.len(), 1, "progress must survive an unrelated event in between");
    }

    #[test]
    fn two_different_processes_mid_sequence_do_not_cross_contaminate() {
        let engine = sequence_engine();
        let host_id = Uuid::new_v4();
        let connect_a = network_connect_event(host_id, 300, 1_000_000_000);
        let connect_b = network_connect_event(host_id, 301, 1_000_000_000);
        // Only process 301 (b) completes its sequence.
        let write_b = file_write_event(host_id, 301, 1_000_000_000 + 1_000_000_000);

        assert!(engine.evaluate(&connect_a).is_empty());
        assert!(engine.evaluate(&connect_b).is_empty());
        let alerts = engine.evaluate(&write_b);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].evidence(), &[connect_b.event_id, write_b.event_id]);

        // Process a's sequence is still only half-complete, and must not
        // have been advanced or fired by b's write.
        let write_a = file_write_event(host_id, 300, 1_000_000_000 + 2_000_000_000);
        let alerts_a = engine.evaluate(&write_a);
        assert_eq!(alerts_a.len(), 1, "a's own sequence still completes independently");
        assert_eq!(alerts_a[0].evidence(), &[connect_a.event_id, write_a.event_id]);
    }

    /// The repository's own shipped sequence rule must load and behave —
    /// the CI-enforced half of §11.1's "every rule ships with a fixture
    /// that must trigger it, and a negative fixture that must not,"
    /// extended to a stateful sequence rule for the first time.
    #[test]
    fn the_shipped_network_download_then_write_rule_loads_and_fires_on_its_positive_fixture_only() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        let host_id = Uuid::new_v4();

        // Positive: connect then write, same process, within the window.
        let connect = network_connect_event(host_id, 300, 1_000_000_000);
        let write = file_write_event(host_id, 300, 1_000_000_000 + 5_000_000_000);
        assert!(engine
            .evaluate(&connect)
            .iter()
            .all(|a| a.rule_id() != "network_download_then_write"));
        let alerts = engine.evaluate(&write);
        let matching: Vec<_> = alerts
            .iter()
            .filter(|a| a.rule_id() == "network_download_then_write")
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].severity(), Severity::High);

        // Negative: a write with no preceding connect from a fresh process
        // must not fire the sequence rule.
        let lone_write = file_write_event(Uuid::new_v4(), 400, 1_000_000_000);
        assert!(engine
            .evaluate(&lone_write)
            .iter()
            .all(|a| a.rule_id() != "network_download_then_write"));
    }

    /// All six shipped rules must load together and stay independent as
    /// `config/rules/` grows — the same guard every earlier phase added.
    #[test]
    fn all_six_shipped_rules_load_together_without_cross_firing() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        assert!(engine.rule_count() >= 6);

        let event = container_start_event(&"b".repeat(64), Some("198.51.100.10"));
        let alerts = engine.evaluate(&event);
        assert_eq!(
            alerts.len(),
            1,
            "a container-start event must fire exactly the container rule — none of the \
             file/DNS/privilege/systemd/sequence rules"
        );
        assert_eq!(alerts[0].rule_id(), "container_started_in_remote_session");
    }
}
