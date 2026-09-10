use std::sync::Mutex;

use osiris_schema::CanonicalEvent;
use rusqlite::{params, Connection, OptionalExtension};

/// The frequency dimensions the Baseline Engine tracks (ARCHITECTURE.md
/// §11.5's exact list: "rolling per-host... frequency tables for:
/// (parent_exe, child_exe) pairs, (process_exe, dst_ip/dst_port) pairs,
/// (process_exe, dns_query_domain) pairs, (user, exe_path) pairs").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrequencyKind {
    ParentChildExec,
    ProcessNetwork,
    ProcessDns,
    UserExe,
}

impl FrequencyKind {
    fn as_str(&self) -> &'static str {
        match self {
            FrequencyKind::ParentChildExec => "PARENT_CHILD_EXEC",
            FrequencyKind::ProcessNetwork => "PROCESS_NETWORK",
            FrequencyKind::ProcessDns => "PROCESS_DNS",
            FrequencyKind::UserExe => "USER_EXE",
        }
    }
}

/// ARCHITECTURE.md §11.5's rarity classification: `NEW` = first-seen ever
/// (this phase's simplification of "first-seen within a configurable
/// recent window" — every observed key starts at count 0, so the very
/// first observation is always "recent"); `RARE` = seen more than once but
/// still below `rare_threshold`; `COMMON` = everything else. `UNUSUAL`/
/// `DEVIATING` (statistical-deviation classes) remain explicitly future
/// work per §11.5's own wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rarity {
    New,
    Rare,
    Common,
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub kind: FrequencyKind,
    pub key: String,
    pub rarity: Rarity,
    pub count: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("baseline storage error: {0}")]
    Storage(String),
}

/// Frequency-table Baseline Engine (ARCHITECTURE.md §11.5), backed by its
/// own SQLite table — deliberately not routed through `osiris-storage`'s
/// `Storage` trait, the same "own its own schema" posture `osiris-detect`'s
/// rule loader already has, keeping this crate's dependency footprint to
/// `osiris-schema` + `rusqlite` only.
pub struct BaselineEngine {
    conn: Mutex<Connection>,
    rare_threshold: u64,
}

impl BaselineEngine {
    /// `rare_threshold` defaults to 5 (ARCHITECTURE.md §11.5 names no
    /// concrete number; 5 is a small, easily-explained default consistent
    /// with the repo's "transparent, explainable" scoring posture — every
    /// prior phase's numeric defaults have been similarly small and
    /// documented rather than tuned).
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, BaselineError> {
        Self::open_with_threshold(path, 5)
    }

    pub fn open_with_threshold(
        path: impl AsRef<std::path::Path>,
        rare_threshold: u64,
    ) -> Result<Self, BaselineError> {
        let conn = Connection::open(path).map_err(|e| BaselineError::Storage(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS baseline_frequency (
                kind TEXT NOT NULL,
                key TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (kind, key)
            );",
        )
        .map_err(|e| BaselineError::Storage(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            rare_threshold,
        })
    }

    fn upsert(&self, kind: FrequencyKind, key: &str, timestamp: u64) -> Result<Observation, BaselineError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| BaselineError::Storage("poisoned lock".to_string()))?;
        let existing_count: Option<i64> = conn
            .query_row(
                "SELECT count FROM baseline_frequency WHERE kind = ?1 AND key = ?2",
                params![kind.as_str(), key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| BaselineError::Storage(e.to_string()))?;

        let new_count = existing_count.unwrap_or(0) + 1;
        conn.execute(
            "INSERT INTO baseline_frequency (kind, key, first_seen, last_seen, count)
             VALUES (?1, ?2, ?3, ?3, 1)
             ON CONFLICT(kind, key) DO UPDATE SET last_seen = ?3, count = count + 1",
            params![kind.as_str(), key, timestamp as i64],
        )
        .map_err(|e| BaselineError::Storage(e.to_string()))?;

        let count = new_count as u64;
        let rarity = if count == 1 {
            Rarity::New
        } else if count <= self.rare_threshold {
            Rarity::Rare
        } else {
            Rarity::Common
        };
        Ok(Observation {
            kind,
            key: key.to_string(),
            rarity,
            count,
        })
    }

    /// Derives zero or more `(kind, key)` pairs from `event` and updates
    /// each pair's frequency table, returning one `Observation` per pair
    /// actually derivable from this event's populated fields. An event
    /// missing the fields a dimension needs (e.g., a bare `AGENT_HEALTH`
    /// event with no `process`) simply contributes no observation for that
    /// dimension — never an error.
    pub fn observe(&self, event: &CanonicalEvent) -> Result<Vec<Observation>, BaselineError> {
        let mut observations = Vec::new();

        if let (Some(parent), Some(process)) = (&event.parent_process, &event.process) {
            let key = format!("{}\u{1}{}", parent.exe_path, process.exe_path);
            observations.push(self.upsert(FrequencyKind::ParentChildExec, &key, event.timestamp)?);
        }
        if let (Some(process), Some(network)) = (&event.process, &event.network) {
            let key = format!("{}\u{1}{}:{}", process.exe_path, network.dst_ip, network.dst_port);
            observations.push(self.upsert(FrequencyKind::ProcessNetwork, &key, event.timestamp)?);
        }
        if let (Some(process), Some(dns)) = (&event.process, &event.dns) {
            let key = format!("{}\u{1}{}", process.exe_path, dns.query);
            observations.push(self.upsert(FrequencyKind::ProcessDns, &key, event.timestamp)?);
        }
        if let (Some(user), Some(process)) = (&event.user, &event.process) {
            let key = format!("{}\u{1}{}", user.uid, process.exe_path);
            observations.push(self.upsert(FrequencyKind::UserExe, &key, event.timestamp)?);
        }

        Ok(observations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, HostRef, NetworkDirection, NetworkRef, ProcessKey, ProcessRef,
        Severity, Source, UserRef, SCHEMA_VERSION,
    };
    use uuid::Uuid;

    fn base_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1000,
            monotonic_timestamp: 1000,
            event_type: EventType::ProcessExec,
            category: Category::Process,
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
            process: None,
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

    fn process_ref(exe: &str, host_id: Uuid) -> ProcessRef {
        ProcessRef {
            process_key: ProcessKey::new(host_id, "b", 300, 1),
            pid: 300,
            exe_path: exe.to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1,
        }
    }

    #[test]
    fn the_first_observation_of_a_pair_is_new() {
        let dir = tempfile::tempdir().unwrap();
        let engine = BaselineEngine::open(dir.path().join("baseline.db")).unwrap();
        let mut event = base_event();
        event.parent_process = Some(process_ref("/bin/bash", event.host_id));
        event.process = Some(process_ref("/usr/bin/curl", event.host_id));

        let observations = engine.observe(&event).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, FrequencyKind::ParentChildExec);
        assert_eq!(observations[0].rarity, Rarity::New);
        assert_eq!(observations[0].count, 1);
    }

    #[test]
    fn a_pair_observed_twice_is_rare_below_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let engine = BaselineEngine::open(dir.path().join("baseline.db")).unwrap();
        let mut event = base_event();
        event.parent_process = Some(process_ref("/bin/bash", event.host_id));
        event.process = Some(process_ref("/usr/bin/curl", event.host_id));

        engine.observe(&event).unwrap();
        let second = engine.observe(&event).unwrap();
        assert_eq!(second[0].rarity, Rarity::Rare);
        assert_eq!(second[0].count, 2);
    }

    #[test]
    fn a_pair_observed_beyond_the_threshold_becomes_common() {
        let dir = tempfile::tempdir().unwrap();
        let engine = BaselineEngine::open_with_threshold(dir.path().join("baseline.db"), 2).unwrap();
        let mut event = base_event();
        event.parent_process = Some(process_ref("/bin/bash", event.host_id));
        event.process = Some(process_ref("/usr/bin/curl", event.host_id));

        engine.observe(&event).unwrap(); // count=1, New
        engine.observe(&event).unwrap(); // count=2, Rare (<=2)
        let third = engine.observe(&event).unwrap(); // count=3, Common
        assert_eq!(third[0].rarity, Rarity::Common);
    }

    #[test]
    fn an_event_with_no_relevant_fields_yields_no_observations_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let engine = BaselineEngine::open(dir.path().join("baseline.db")).unwrap();
        let event = base_event(); // no process, no user, no network, no dns

        let observations = engine.observe(&event).unwrap();
        assert!(observations.is_empty());
    }

    #[test]
    fn two_different_pairs_are_tracked_independently() {
        let dir = tempfile::tempdir().unwrap();
        let engine = BaselineEngine::open(dir.path().join("baseline.db")).unwrap();
        let host_id = Uuid::new_v4();

        let mut event_a = base_event();
        event_a.host_id = host_id;
        event_a.parent_process = Some(process_ref("/bin/bash", host_id));
        event_a.process = Some(process_ref("/usr/bin/curl", host_id));
        engine.observe(&event_a).unwrap();
        engine.observe(&event_a).unwrap();

        let mut event_b = base_event();
        event_b.host_id = host_id;
        event_b.parent_process = Some(process_ref("/bin/bash", host_id));
        event_b.process = Some(process_ref("/usr/bin/wget", host_id));
        let observations_b = engine.observe(&event_b).unwrap();

        // event_b's pair is unrelated to event_a's — still New, not
        // contaminated by event_a's two prior observations.
        assert_eq!(observations_b[0].rarity, Rarity::New);
        assert_eq!(observations_b[0].count, 1);
    }

    #[test]
    fn network_dns_and_user_dimensions_are_each_derived_and_updated() {
        let dir = tempfile::tempdir().unwrap();
        let engine = BaselineEngine::open(dir.path().join("baseline.db")).unwrap();
        let host_id = Uuid::new_v4();
        let mut event = base_event();
        event.host_id = host_id;
        event.process = Some(process_ref("/usr/bin/curl", host_id));
        event.network = Some(NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 4444,
            dst_ip: "203.0.113.10".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            bytes: None,
        });
        event.dns = Some(osiris_schema::DnsRef {
            query: "evil.example".to_string(),
            qtype: "A".to_string(),
            response_ips: vec![],
            ttl: None,
        });
        event.user = Some(UserRef {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            username: Some("alice".to_string()),
            loginuid: Some(1000),
        });

        let observations = engine.observe(&event).unwrap();
        let kinds: std::collections::HashSet<_> = observations.iter().map(|o| o.kind).collect();
        assert!(kinds.contains(&FrequencyKind::ProcessNetwork));
        assert!(kinds.contains(&FrequencyKind::ProcessDns));
        assert!(kinds.contains(&FrequencyKind::UserExe));
        assert!(observations.iter().all(|o| o.rarity == Rarity::New));
    }
}
