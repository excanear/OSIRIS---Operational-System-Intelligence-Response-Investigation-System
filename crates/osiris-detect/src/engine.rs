use std::path::Path;

use osiris_schema::{Alert, CanonicalEvent};

use crate::eval::{field_value, matches};
use crate::rule::{Rule, RuleError};

/// The Phase 2 Detection Engine: stateless, single-event matching over the
/// rules loaded at startup (plan Global Constraints #10). Stateful
/// `sequence`/`window` evaluation and rule hot-reload are Phase 6
/// (ARCHITECTURE.md §11.1/§29). Runs on the Server's ingestion path, after
/// each successful `batch_write` — never on the Agent, which must not link
/// this crate at all (§27's privilege boundary).
#[derive(Debug)]
pub struct DetectionEngine {
    rules: Vec<Rule>,
}

impl DetectionEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
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
    /// rule whose conditions all matched.
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

        self.rules
            .iter()
            .filter_map(|rule| self.evaluate_rule(rule, event, &event_json))
            .collect()
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
        let mut reasons = Vec::with_capacity(rule.match_conditions.len());
        for condition in &rule.match_conditions {
            // A missing (or null) field never matches — a file rule must
            // not fire on a process event that carries no `file` at all.
            let actual = field_value(event_json, &condition.field)?;
            if !matches(condition.op, actual, &condition.value) {
                return None;
            }
            reasons.push(condition.reason.clone());
        }
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
}
