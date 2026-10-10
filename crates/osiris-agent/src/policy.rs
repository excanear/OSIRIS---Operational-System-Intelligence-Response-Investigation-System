//! Agent-side policy state (Phase 9d-3): the persisted overlay and the live
//! knobs (level filter, heartbeat interval) the pipeline and the heartbeat
//! task read. Sensor on/off lives on `Agent` (it owns the sensors).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use osiris_policy::{allows, includes_argv, EffectivePolicy, TelemetryLevel};
use osiris_schema::{CanonicalEvent, EventType};
use tokio::sync::watch;

pub fn overlay_path(spool_path: &str) -> PathBuf {
    PathBuf::from(format!("{spool_path}.policy.json"))
}

/// `None` when absent, unreadable, unparsable or invalid — the agent then
/// runs on agent.yaml alone and reports no policy, so the server re-sends.
pub fn load_overlay(path: &Path) -> Option<EffectivePolicy> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "cannot read policy overlay; ignoring it");
            return None;
        }
    };
    let policy: EffectivePolicy = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "policy overlay is not valid JSON; ignoring it");
            return None;
        }
    };
    if let Err(e) = policy.validate() {
        tracing::error!(error = %e, path = %path.display(), "policy overlay is invalid; ignoring it");
        return None;
    }
    Some(policy)
}

/// Atomic replace (temp file, fsync, rename), private to the agent user.
/// The empty policy removes the overlay instead of writing it.
pub fn save_overlay(path: &Path, policy: &EffectivePolicy) -> std::io::Result<()> {
    if policy.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(
            serde_json::to_string(policy)
                .expect("policy serializes")
                .as_bytes(),
        )?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

pub struct PolicyRuntime {
    level: AtomicU8,
    base_heartbeat_secs: u64,
    heartbeat_tx: watch::Sender<u64>,
    applied: Mutex<EffectivePolicy>,
}

impl PolicyRuntime {
    pub fn new(base_heartbeat_secs: u64) -> (Self, watch::Receiver<u64>) {
        let base = base_heartbeat_secs.max(1);
        let (heartbeat_tx, rx) = watch::channel(base);
        (
            Self {
                level: AtomicU8::new(0),
                base_heartbeat_secs: base,
                heartbeat_tx,
                applied: Mutex::new(EffectivePolicy::default()),
            },
            rx,
        )
    }

    pub fn allows(&self, t: EventType) -> bool {
        allows(
            TelemetryLevel::from_code(self.level.load(Ordering::Relaxed)),
            t,
        )
    }

    /// Drops the fields of an allowed event that the current level does
    /// not include (today: argv below STANDARD).
    pub fn apply_field_rules(&self, event: &mut CanonicalEvent) {
        let level = TelemetryLevel::from_code(self.level.load(Ordering::Relaxed));
        if !includes_argv(level) {
            for process in [event.process.as_mut(), event.parent_process.as_mut()]
                .into_iter()
                .flatten()
            {
                process.cmdline.clear();
            }
        }
    }

    pub fn applied(&self) -> EffectivePolicy {
        self.applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn policy_hash_hex(&self) -> Option<String> {
        let applied = self.applied();
        (!applied.is_empty()).then(|| applied.hash_hex())
    }

    /// Level and heartbeat only; sensors are switched by `Agent`.
    pub fn set(&self, policy: &EffectivePolicy) {
        self.level.store(
            policy.telemetry_level.map_or(0, TelemetryLevel::code),
            Ordering::Relaxed,
        );
        let secs = policy
            .heartbeat_interval_secs
            .unwrap_or(self.base_heartbeat_secs);
        // Only a changed interval wakes the heartbeat task: waking it restarts
        // its sleep, which would delay the confirming heartbeat by a full
        // interval on every apply.
        self.heartbeat_tx.send_if_modified(|current| {
            let changed = *current != secs;
            *current = secs;
            changed
        });
        *self.applied.lock().unwrap_or_else(|p| p.into_inner()) = policy.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_policy::TelemetryLevel;
    use osiris_schema::EventType;

    fn sample() -> EffectivePolicy {
        let mut p = EffectivePolicy {
            telemetry_level: Some(TelemetryLevel::Minimal),
            heartbeat_interval_secs: Some(30),
            ..Default::default()
        };
        p.sensors.insert("network".into(), false);
        p
    }

    #[test]
    fn overlay_round_trips_and_empty_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = overlay_path(&dir.path().join("spool.ndjson").to_string_lossy());
        assert_eq!(path.file_name().unwrap(), "spool.ndjson.policy.json");
        assert_eq!(load_overlay(&path), None);
        save_overlay(&path, &sample()).unwrap();
        assert_eq!(load_overlay(&path), Some(sample()));
        save_overlay(&path, &EffectivePolicy::default()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_corrupt_or_invalid_overlay_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(load_overlay(&path), None);
        std::fs::write(&path, r#"{"sensors":{"dns":true}}"#).unwrap();
        assert_eq!(load_overlay(&path), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_overlay_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        save_overlay(&path, &sample()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn runtime_filters_by_level_and_publishes_the_heartbeat() {
        let (rt, rx) = PolicyRuntime::new(60);
        assert!(rt.allows(EventType::FileWrite), "no policy = allow all");
        assert_eq!(*rx.borrow(), 60);
        assert_eq!(rt.policy_hash_hex(), None);
        rt.set(&sample());
        assert!(!rt.allows(EventType::FileWrite));
        assert!(rt.allows(EventType::AgentHealth));
        assert_eq!(*rx.borrow(), 30);
        assert_eq!(rt.policy_hash_hex(), Some(sample().hash_hex()));
        rt.set(&EffectivePolicy::default());
        assert_eq!(*rx.borrow(), 60, "unset heartbeat falls back to agent.yaml");
        assert_eq!(rt.policy_hash_hex(), None);
    }

    fn exec_with_argv() -> CanonicalEvent {
        let raw = osiris_sensor_api::RawEvent::ProcessExec(osiris_sensor_api::ProcessExecRaw {
            pid: 1,
            ppid: 0,
            uid: 0,
            exe_path: "/usr/bin/dash".into(),
            comm: "sh".into(),
            cmdline: vec!["/bin/sh".into(), "-c".into(), "secret".into()],
            timestamp_ns: 1,
            start_time_mono: 1,
            source: osiris_sensor_api::RawEventSource::Audit,
        });
        osiris_pipeline::normalize(raw, &crate::agent::tests::test_host(), "b")
    }

    fn cmdline_after(rt: &PolicyRuntime) -> Vec<String> {
        let mut event = exec_with_argv();
        rt.apply_field_rules(&mut event);
        event.process.unwrap().cmdline
    }

    /// ARCHITECTURE.md §6: argv is STANDARD data, so an explicit MINIMAL
    /// policy keeps the PROCESS_EXEC event but not its cmdline.
    #[tokio::test]
    async fn argv_is_stripped_only_below_standard() {
        let (rt, _rx) = PolicyRuntime::new(60);
        assert_eq!(cmdline_after(&rt).len(), 3, "no policy keeps argv");
        rt.set(&sample());
        assert!(cmdline_after(&rt).is_empty(), "MINIMAL strips argv");
        let mut standard = sample();
        standard.telemetry_level = Some(TelemetryLevel::Standard);
        rt.set(&standard);
        assert_eq!(cmdline_after(&rt).len(), 3);
    }

    #[tokio::test]
    async fn an_unchanged_heartbeat_interval_does_not_wake_the_heartbeat_task() {
        let (rt, mut rx) = PolicyRuntime::new(60);
        rt.set(&sample());
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();
        let mut other = sample();
        other.telemetry_level = Some(TelemetryLevel::Forensic);
        rt.set(&other);
        assert!(!rx.has_changed().unwrap(), "still 30 s");
        rt.set(&EffectivePolicy::default());
        assert!(rx.has_changed().unwrap(), "30 s -> 60 s");
        rx.borrow_and_update();
        rt.set(&EffectivePolicy::default());
        assert!(!rx.has_changed().unwrap(), "still 60 s");
    }
}
