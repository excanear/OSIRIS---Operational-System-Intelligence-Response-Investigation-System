use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_fileutil::LineTailer;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::audit_record::{parse_record, IdentityRecord};

struct HealthState {
    state: SensorState,
    events_emitted_total: u64,
    events_dropped_total: u64,
    last_error: Option<String>,
    last_event_at: Option<u64>,
    capability_flags: Vec<String>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            state: SensorState::Starting,
            events_emitted_total: 0,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: None,
            capability_flags: vec![],
        }
    }
}

/// Locks a health mutex, recovering rather than panicking if a prior holder
/// panicked while holding it — the discipline established by
/// `osiris-sensors-process`, `osiris-sensors-fs` and `osiris-generator`.
fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Identity/Session sensor (ARCHITECTURE.md §4.3's Identity/Session
/// row), Phase 4a scope: the Linux Audit backend only, consumed by tailing
/// an auditd-format log file. `utmp`/`wtmp` polling and
/// `/proc/<pid>/loginuid` are NOT implemented — see the plan's Global
/// Constraint #2 for why (a binary, architecture-dependent C-struct layout
/// this codebase would be guessing at; and a per-process lookup rather than
/// an event source). Those are additional `Sensor` implementations behind
/// this same unchanged trait, not a rewrite of this one.
///
/// Per plan Global Constraint #4, this one sensor emits BOTH
/// `RawEvent::Identity` (session lifecycle) and `RawEvent::Privilege`
/// (uid/gid transitions and sudo): §4.3's catalog has no separate Privilege
/// sensor row, and the audit stream carrying `USER_*` carries `USER_CMD`
/// and `SYSCALL` too. That is deliberate, not a leaked responsibility.
///
/// Unlike `FilesystemSensor` there is no `with_audit_key` filter: `USER_*`
/// records carry no `key=` field at all (only `SYSCALL` records do), so a
/// key filter would suppress exactly the identity records this sensor
/// exists for. The record-type match in `parse_record` is the filter.
///
/// Expected audit rules on a real host (the sensor does not install them;
/// that is an operator/packaging concern — the `USER_*` records need no
/// rule at all, since PAM and login emit them unconditionally):
/// ```text
/// -a always,exit -F arch=b64 -S setuid,setgid -F key=osiris_identity
/// ```
pub struct IdentitySensor {
    audit_log_path: PathBuf,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl IdentitySensor {
    pub fn new(audit_log_path: impl Into<PathBuf>) -> Self {
        Self {
            audit_log_path: audit_log_path.into(),
            poll_interval: Duration::from_millis(200),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
}

#[async_trait]
impl Sensor for IdentitySensor {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn capabilities(&self) -> SensorCapabilities {
        if self.audit_log_path.exists() {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: true,
                always_available: false,
                unsupported_reason: None,
            }
        } else {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: false,
                unsupported_reason: Some(format!(
                    "audit log not found at {}",
                    self.audit_log_path.display()
                )),
            }
        }
    }

    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError> {
        self.cancellation = Some(ctx.cancellation.clone());
        lock_health(&self.health).state = SensorState::Starting;

        let caps = self.capabilities();
        if !caps.supported() {
            let reason = caps.unsupported_reason.clone().unwrap_or_default();
            lock_health(&self.health).last_error = Some(reason.clone());
            return Err(SensorError::Unsupported(reason));
        }
        lock_health(&self.health).capability_flags = vec!["audit_fallback".to_string()];

        let path = self.audit_log_path.clone();
        let poll_interval = self.poll_interval;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut tailer = LineTailer::new(path);
            loop {
                if cancellation.is_cancelled() {
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                match tailer.poll() {
                    Ok(lines) => {
                        for line in lines {
                            // Every record is self-contained — no assembler,
                            // no completion timeout, nothing to flush on
                            // shutdown (contrast FilesystemSensor, whose
                            // SYSCALL+PATH+CWD groups span several lines).
                            if let Some(record) = parse_record(&line) {
                                emit(&output, record, &health).await;
                            }
                        }
                    }
                    Err(e) => {
                        let mut h = lock_health(&health);
                        h.state = SensorState::Degraded;
                        h.last_error = Some(e.to_string());
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancellation.cancelled() => {
                        lock_health(&health).state = SensorState::Stopped;
                        return;
                    }
                }
            }
        });
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
        // The polling task is already spawned in initialize(); this sensor
        // has no separate "armed but not running" state, same as
        // ProcessExecSensor and FilesystemSensor.
        lock_health(&self.health).state = SensorState::Healthy;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), SensorError> {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        lock_health(&self.health).state = SensorState::Stopped;
        Ok(())
    }

    fn health(&self) -> SensorHealth {
        let h = lock_health(&self.health);
        SensorHealth {
            name: self.name().to_string(),
            state: h.state,
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
            last_error: h.last_error.clone(),
            last_event_at: h.last_event_at,
            capability_flags: h.capability_flags.clone(),
            p99_emit_latency_us: 0,
        }
    }

    fn metrics(&self) -> SensorMetrics {
        let h = lock_health(&self.health);
        SensorMetrics {
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
        }
    }
}

async fn emit(
    output: &tokio::sync::mpsc::Sender<RawEvent>,
    record: IdentityRecord,
    health: &Mutex<HealthState>,
) {
    let raw = match record {
        IdentityRecord::Identity(i) => RawEvent::Identity(i),
        IdentityRecord::Privilege(p) => RawEvent::Privilege(p),
    };
    let timestamp = raw.timestamp_ns();
    if output.send(raw).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(timestamp);
        h.state = SensorState::Healthy;
    } else {
        lock_health(health).events_dropped_total += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{IdentityOperation, PrivilegeOperation, RawEvent};
    use std::io::Write;
    use tokio::sync::mpsc;

    const USER_LOGIN: &str = r#"type=USER_LOGIN msg=audit(1690000000.123:456): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const SYSCALL_SETUID: &str = r#"type=SYSCALL msg=audit(1690000005.010:470): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=7ffd0e2b1c40 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity""#;

    #[tokio::test]
    async fn reports_unsupported_when_the_audit_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = IdentitySensor::new(dir.path().join("missing.log"));
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        assert!(!caps.ebpf, "no eBPF backend exists this phase");
        assert!(caps
            .unsupported_reason
            .as_deref()
            .unwrap_or_default()
            .contains("audit log not found"));

        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reports_the_audit_fallback_capability_when_the_log_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();
        let sensor = IdentitySensor::new(&path);
        let caps = sensor.capabilities();
        assert!(caps.supported());
        assert!(!caps.ebpf);
        assert!(caps.audit_fallback);
        assert!(!caps.always_available);
        assert_eq!(sensor.name(), "identity");
    }

    /// The whole point of Global Constraint #4: ONE tail over ONE log emits
    /// BOTH families.
    #[tokio::test]
    async fn emits_both_an_identity_and_a_privilege_event_from_one_tailed_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor =
            IdentitySensor::new(&path).with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{USER_LOGIN}").unwrap();
        // A record from another subsystem, interleaved: it must be ignored
        // without disturbing the two that surround it.
        writeln!(
            file,
            r#"type=PROCTITLE msg=audit(1690000005.005:469): proctitle=73756F"#
        )
        .unwrap();
        writeln!(file, "{SYSCALL_SETUID}").unwrap();
        file.flush().unwrap();

        let first = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for the identity event")
            .expect("channel closed unexpectedly");
        match first {
            RawEvent::Identity(raw) => {
                assert_eq!(raw.operation, IdentityOperation::Login);
                assert_eq!(raw.session_id, "3");
                assert_eq!(raw.remote_addr.as_deref(), Some("198.51.100.10"));
            }
            other => panic!("expected RawEvent::Identity first, got {other:?}"),
        }

        let second = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for the privilege event")
            .expect("channel closed unexpectedly");
        match second {
            RawEvent::Privilege(raw) => {
                assert_eq!(raw.operation, PrivilegeOperation::UidChange);
                assert_eq!(raw.target_uid, Some(0));
                assert_eq!(raw.pid, 300);
            }
            other => panic!("expected RawEvent::Privilege second, got {other:?}"),
        }

        sensor.stop().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.events_emitted_total, 2);
        assert_eq!(health.state, SensorState::Stopped);
        assert_eq!(health.capability_flags, vec!["audit_fallback".to_string()]);
        assert_eq!(health.last_event_at, Some(1_690_000_005_010_000_000));
    }

    /// This sensor must never emit any other `RawEvent` variant — the same
    /// single-responsibility assertion the Filesystem and Network sensors'
    /// tests make.
    #[tokio::test]
    async fn emits_nothing_for_a_log_containing_only_other_subsystems_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(
            &path,
            "type=CWD msg=audit(1690000000.123:456): cwd=\"/home/alice\"\n\
             type=PATH msg=audit(1690000000.123:456): item=0 name=\"/tmp/foo\" nametype=CREATE\n\
             not an audit record at all\n",
        )
        .unwrap();

        let mut sensor =
            IdentitySensor::new(&path).with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            received.is_err(),
            "the Identity sensor must emit nothing for records it does not own"
        );
        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 0);
    }
}
