use std::path::Path;

use osiris_schema::{Alert, CanonicalEvent};

use crate::eval::{eval_node, field_value, matches};
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
}
