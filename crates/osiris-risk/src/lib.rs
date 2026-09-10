use std::collections::HashSet;

use osiris_baseline::{Observation, Rarity};
use osiris_correlate::BehavioralChain;
use osiris_schema::{Alert, CanonicalEvent, EntityRef, Relation, RiskScoreRecord, Severity, WeightedReason};
use serde::Deserialize;

/// Per-severity weight table (ARCHITECTURE.md §11.4: "a configurable table
/// (YAML, hot-reloadable, same governance as detection rules) mapping
/// observed conditions to weights"). Defaults are small, explainable
/// numbers consistent with this repo's posture of documenting every
/// numeric default rather than silently tuning one in.
#[derive(Debug, Clone, Deserialize)]
pub struct SeverityWeights {
    #[serde(default = "default_info")]
    pub info: i16,
    #[serde(default = "default_low")]
    pub low: i16,
    #[serde(default = "default_medium")]
    pub medium: i16,
    #[serde(default = "default_high")]
    pub high: i16,
    #[serde(default = "default_critical")]
    pub critical: i16,
}

fn default_info() -> i16 {
    0
}
fn default_low() -> i16 {
    5
}
fn default_medium() -> i16 {
    15
}
fn default_high() -> i16 {
    30
}
fn default_critical() -> i16 {
    50
}

impl Default for SeverityWeights {
    fn default() -> Self {
        Self {
            info: default_info(),
            low: default_low(),
            medium: default_medium(),
            high: default_high(),
            critical: default_critical(),
        }
    }
}

impl SeverityWeights {
    pub fn weight_for(&self, severity: Severity) -> i16 {
        match severity {
            Severity::Info => self.info,
            Severity::Low => self.low,
            Severity::Medium => self.medium,
            Severity::High => self.high,
            Severity::Critical => self.critical,
        }
    }
}

/// The on-disk YAML shape (`config/risk/weights.yaml`), governed the same
/// way detection rules are (§11.1's rule-file governance, extended to
/// risk weights per §11.4).
#[derive(Debug, Clone, Deserialize)]
pub struct RiskConfig {
    #[serde(default)]
    pub severity_weights: SeverityWeights,
    /// Weight added per `New` baseline observation.
    #[serde(default = "default_baseline_new_weight")]
    pub baseline_new_weight: i16,
    /// Weight added per `Rare` baseline observation.
    #[serde(default = "default_baseline_rare_weight")]
    pub baseline_rare_weight: i16,
    /// Weight added once when a process's `BehavioralChain` contains both
    /// a `ConnectedTo` and a `Wrote` edge within the correlation window —
    /// ARCHITECTURE.md §26 step 11's own worked example, "Network
    /// connection followed by file write" (+20).
    #[serde(default = "default_chain_pattern_weight")]
    pub chain_pattern_weight: i16,
}

fn default_baseline_new_weight() -> i16 {
    10
}
fn default_baseline_rare_weight() -> i16 {
    5
}
fn default_chain_pattern_weight() -> i16 {
    20
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            severity_weights: SeverityWeights::default(),
            baseline_new_weight: default_baseline_new_weight(),
            baseline_rare_weight: default_baseline_rare_weight(),
            chain_pattern_weight: default_chain_pattern_weight(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RiskError {
    #[error("failed to read risk config {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse risk config {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
}

fn rarity_label(kind: osiris_baseline::FrequencyKind, rarity: Rarity) -> String {
    let subject = match kind {
        osiris_baseline::FrequencyKind::ParentChildExec => "parent/child process pair",
        osiris_baseline::FrequencyKind::ProcessNetwork => "process/destination pair",
        osiris_baseline::FrequencyKind::ProcessDns => "process/DNS-query pair",
        osiris_baseline::FrequencyKind::UserExe => "user/executable pair",
    };
    match rarity {
        Rarity::New => format!("First-seen {subject} for this host"),
        Rarity::Rare => format!("Rare {subject} for this host"),
        Rarity::Common => format!("Common {subject}"),
    }
}

/// Weighted, explainable Risk Engine (ARCHITECTURE.md §11.4): "never a bare
/// number" — `score()` returns `None` rather than a zero/empty
/// `RiskScoreRecord` when there is nothing at all to report.
#[derive(Debug, Clone)]
pub struct RiskEngine {
    config: RiskConfig,
}

impl RiskEngine {
    pub fn new(config: RiskConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, RiskError> {
        let path_ref = path.as_ref();
        let yaml = std::fs::read_to_string(path_ref).map_err(|source| RiskError::Read {
            path: path_ref.display().to_string(),
            source,
        })?;
        let config: RiskConfig = serde_yaml::from_str(&yaml).map_err(|source| RiskError::Parse {
            path: path_ref.display().to_string(),
            source,
        })?;
        Ok(Self::new(config))
    }

    /// Scores `event` from every weighted input this phase's engines
    /// produce: the `Alert`s that fired on it, the Baseline Engine's
    /// `Observation`s for it, and (if computed) its `BehavioralChain`.
    /// Returns `None` when none of the three inputs contribute a reason —
    /// a `RiskScoreRecord` is only ever constructed non-empty, mirroring
    /// `Alert::new`'s own discipline (§11.2 carried into §11.4).
    pub fn score(
        &self,
        event: &CanonicalEvent,
        alerts: &[Alert],
        observations: &[Observation],
        chain: Option<&BehavioralChain>,
    ) -> Option<RiskScoreRecord> {
        let mut reasons: Vec<WeightedReason> = Vec::new();

        for alert in alerts {
            let weight = self.config.severity_weights.weight_for(alert.severity());
            let label = alert
                .reasons()
                .first()
                .cloned()
                .unwrap_or_else(|| alert.rule_id().to_string());
            let evidence = alert.evidence().first().copied().unwrap_or(event.event_id);
            reasons.push(WeightedReason {
                label,
                weight,
                evidence,
            });
        }

        for observation in observations {
            let weight = match observation.rarity {
                Rarity::New => self.config.baseline_new_weight,
                Rarity::Rare => self.config.baseline_rare_weight,
                Rarity::Common => continue,
            };
            reasons.push(WeightedReason {
                label: rarity_label(observation.kind, observation.rarity),
                weight,
                evidence: event.event_id,
            });
        }

        if let (Some(chain), Some(process)) = (chain, &event.process) {
            let entity = EntityRef::Process {
                process_key: process.process_key,
            };
            if chain.has_relation_touching(&entity, Relation::ConnectedTo)
                && chain.has_relation_touching(&entity, Relation::Wrote)
            {
                reasons.push(WeightedReason {
                    label: "Network connection followed by file write".to_string(),
                    weight: self.config.chain_pattern_weight,
                    evidence: event.event_id,
                });
            }
        }

        if reasons.is_empty() {
            return None;
        }

        let total: i32 = reasons.iter().map(|r| r.weight as i32).sum();
        let score = total.clamp(0, 100) as u8;
        let severity = match score {
            0..=9 => Severity::Info,
            10..=29 => Severity::Low,
            30..=59 => Severity::Medium,
            60..=79 => Severity::High,
            _ => Severity::Critical,
        };

        let mut related: Vec<uuid::Uuid> = reasons.iter().map(|r| r.evidence).collect();
        related.push(event.event_id);
        let mut seen = HashSet::new();
        related.retain(|id| seen.insert(*id));

        Some(RiskScoreRecord {
            event_id: event.event_id,
            process_key: event.process.as_ref().map(|p| p.process_key),
            host_id: event.host_id,
            timestamp: event.timestamp,
            score,
            severity,
            reasons,
            related_events: related,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_baseline::FrequencyKind;
    use osiris_correlate::EdgeSource;
    use osiris_schema::{
        Category, EntityRelationship, EventType, HostRef, ProcessKey, ProcessRef, Source,
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
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 1,
            event_type: EventType::FileCreate,
            category: Category::File,
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
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    fn sample_alert(severity: Severity, event_id: Uuid) -> Alert {
        Alert::new(
            "test_rule",
            1,
            "hash",
            severity,
            1000,
            Uuid::new_v4(),
            vec!["something happened".to_string()],
            vec![event_id],
        )
        .unwrap()
    }

    #[test]
    fn an_event_with_a_high_alert_and_a_new_baseline_observation_sums_correctly() {
        let engine = RiskEngine::new(RiskConfig::default());
        let event = sample_event();
        let alerts = vec![sample_alert(Severity::High, event.event_id)];
        let observations = vec![Observation {
            kind: FrequencyKind::ParentChildExec,
            key: "k".to_string(),
            rarity: Rarity::New,
            count: 1,
        }];

        let record = engine.score(&event, &alerts, &observations, None).unwrap();
        // default high weight 30 + default baseline_new weight 10 = 40
        assert_eq!(record.score, 40);
        assert_eq!(record.severity, Severity::Medium);
        assert_eq!(record.reasons.len(), 2);
    }

    #[test]
    fn score_clamps_at_100_on_an_extreme_input() {
        let engine = RiskEngine::new(RiskConfig::default());
        let event = sample_event();
        let alerts = vec![
            sample_alert(Severity::Critical, event.event_id),
            sample_alert(Severity::Critical, event.event_id),
            sample_alert(Severity::Critical, event.event_id),
        ];

        let record = engine.score(&event, &alerts, &[], None).unwrap();
        assert_eq!(record.score, 100);
        assert_eq!(record.severity, Severity::Critical);
    }

    #[test]
    fn an_event_with_nothing_to_report_returns_none() {
        let engine = RiskEngine::new(RiskConfig::default());
        let event = sample_event();
        let common_observation = Observation {
            kind: FrequencyKind::ParentChildExec,
            key: "k".to_string(),
            rarity: Rarity::Common,
            count: 99,
        };
        assert!(engine
            .score(&event, &[], &[common_observation], None)
            .is_none());
        assert!(engine.score(&event, &[], &[], None).is_none());
    }

    struct FakeEdgeSource {
        edges: Vec<EntityRelationship>,
    }
    impl EdgeSource for FakeEdgeSource {
        fn edges_for(&self, entity: &EntityRef, _since: u64, _until: u64) -> Vec<EntityRelationship> {
            self.edges
                .iter()
                .filter(|e| e.from.storage_key() == entity.storage_key() || e.to.storage_key() == entity.storage_key())
                .cloned()
                .collect()
        }
    }

    #[test]
    fn the_chain_pattern_bonus_fires_only_when_both_edges_are_present_for_the_same_process() {
        let engine = RiskEngine::new(RiskConfig::default());
        let event = sample_event();
        let process_entity = EntityRef::Process {
            process_key: event.process.as_ref().unwrap().process_key,
        };
        let ip = EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        };
        let file = EntityRef::File {
            host_id: event.host_id,
            inode: 1,
            device_id: 2049,
        };
        let edges = vec![
            EntityRelationship {
                from: process_entity.clone(),
                to: ip,
                relation: Relation::ConnectedTo,
                event_id: Uuid::now_v7(),
                timestamp: event.timestamp,
            },
            EntityRelationship {
                from: process_entity.clone(),
                to: file,
                relation: Relation::Wrote,
                event_id: Uuid::now_v7(),
                timestamp: event.timestamp,
            },
        ];
        let source = FakeEdgeSource { edges };
        let correlation_engine = osiris_correlate::CorrelationEngine::new(3, 60_000_000_000);
        let chain = correlation_engine.build_chain(&source, process_entity, event.timestamp);

        let record = engine.score(&event, &[], &[], Some(&chain)).unwrap();
        assert_eq!(record.reasons.len(), 1);
        assert_eq!(record.reasons[0].weight, 20);
        assert!(record.reasons[0].label.contains("Network connection"));
    }

    #[test]
    fn the_chain_pattern_bonus_does_not_fire_with_only_one_of_the_two_edge_kinds() {
        let engine = RiskEngine::new(RiskConfig::default());
        let event = sample_event();
        let process_entity = EntityRef::Process {
            process_key: event.process.as_ref().unwrap().process_key,
        };
        let ip = EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        };
        let edges = vec![EntityRelationship {
            from: process_entity.clone(),
            to: ip,
            relation: Relation::ConnectedTo,
            event_id: Uuid::now_v7(),
            timestamp: event.timestamp,
        }];
        let source = FakeEdgeSource { edges };
        let correlation_engine = osiris_correlate::CorrelationEngine::new(3, 60_000_000_000);
        let chain = correlation_engine.build_chain(&source, process_entity, event.timestamp);

        assert!(engine.score(&event, &[], &[], Some(&chain)).is_none());
    }

    #[test]
    fn load_from_file_parses_a_real_yaml_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("weights.yaml");
        std::fs::write(
            &path,
            "severity_weights:\n  high: 99\nbaseline_new_weight: 7\n",
        )
        .unwrap();
        let engine = RiskEngine::load_from_file(&path).unwrap();
        assert_eq!(engine.config.severity_weights.high, 99);
        assert_eq!(engine.config.baseline_new_weight, 7);
        // Unspecified fields keep their documented defaults.
        assert_eq!(engine.config.severity_weights.low, 5);
        assert_eq!(engine.config.chain_pattern_weight, 20);
    }
}
