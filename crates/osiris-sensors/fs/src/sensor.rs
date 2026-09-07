use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use osiris_fileutil::LineTailer;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::assembler::AuditEventAssembler;
use crate::audit_record::{parse_record, AuditRecord};

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
/// panicked while holding it — matches the discipline established by
/// `osiris-sensors-process` and `osiris-generator`.
fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Filesystem sensor (ARCHITECTURE.md §4.3's Filesystem row), Phase 2
/// scope: the Audit fallback backend only, consumed by tailing an
/// auditd-format log file (plan Global Constraints #1/#2). eBPF LSM hooks
/// and fanotify are additional `Sensor` implementations behind this same
/// unchanged trait, not a rewrite of this one.
///
/// Expected audit rules on a real host (the sensor does not install them;
/// that is an operator/packaging concern):
/// ```text
/// -a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate \
///    -F dir=/var/www -F perm=wa -F key=osiris_fs
/// -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir \
///    -F dir=/var/www -F key=osiris_fs
/// ```
pub struct FilesystemSensor {
    audit_log_path: PathBuf,
    poll_interval: Duration,
    completion_timeout: Duration,
    audit_key: Option<String>,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl FilesystemSensor {
    pub fn new(audit_log_path: impl Into<PathBuf>) -> Self {
        Self {
            audit_log_path: audit_log_path.into(),
            poll_interval: Duration::from_millis(200),
            // Comfortably longer than one poll, so a group split across two
            // polls is never released mid-way, but short enough that the
            // last operation before a quiet period still surfaces promptly.
            completion_timeout: Duration::from_millis(500),
            audit_key: None,
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn with_completion_timeout(mut self, timeout: Duration) -> Self {
        self.completion_timeout = timeout;
        self
    }

    /// Consume only records tagged with this audit rule `key=`. Without it
    /// the sensor consumes every file syscall record in the log, which on a
    /// busy host means other subsystems' rules too.
    pub fn with_audit_key(mut self, key: impl Into<String>) -> Self {
        self.audit_key = Some(key.into());
        self
    }
}

/// True when this line should be fed to the assembler. A key filter can
/// only be applied to `SYSCALL` records (they are the only records carrying
/// `key=`), so PATH/CWD/other records always pass through — the assembler
/// discards any group whose SYSCALL record never arrived, which is exactly
/// what happens to a filtered-out group.
fn passes_key_filter(line: &str, audit_key: Option<&str>) -> bool {
    let Some(wanted) = audit_key else {
        return true;
    };
    match parse_record(line) {
        Some((_, AuditRecord::Syscall(s))) => s.key.as_deref() == Some(wanted),
        _ => true,
    }
}

#[async_trait]
impl Sensor for FilesystemSensor {
    fn name(&self) -> &'static str {
        "filesystem"
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
        let completion_timeout = self.completion_timeout;
        let audit_key = self.audit_key.clone();
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut tailer = LineTailer::new(path);
            let mut assembler = AuditEventAssembler::new(completion_timeout);
            loop {
                if cancellation.is_cancelled() {
                    // Release whatever group was still open so the last
                    // observed operation isn't silently dropped on shutdown.
                    for raw in assembler.flush() {
                        emit(&output, raw, &health).await;
                    }
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                match tailer.poll() {
                    Ok(lines) => {
                        for line in lines {
                            if !passes_key_filter(&line, audit_key.as_deref()) {
                                continue;
                            }
                            for raw in assembler.offer(&line, Instant::now()) {
                                emit(&output, raw, &health).await;
                            }
                        }
                        for raw in assembler.tick(Instant::now()) {
                            emit(&output, raw, &health).await;
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
                        for raw in assembler.flush() {
                            emit(&output, raw, &health).await;
                        }
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
        // ProcessExecSensor.
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
    raw: osiris_sensor_api::FileEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::File(raw)).await.is_ok() {
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
    use osiris_sensor_api::{FileOperation, RawEvent};
    use std::io::Write;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn reports_unsupported_when_the_audit_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = FilesystemSensor::new(dir.path().join("missing.log"));
        let caps = sensor.capabilities();
        assert!(!caps.supported());
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
    async fn emits_a_create_event_for_an_appended_audit_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor = FilesystemSensor::new(&path)
            .with_poll_interval(Duration::from_millis(20))
            .with_completion_timeout(Duration::from_millis(40));
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
        writeln!(file, r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=257 success=yes exit=3 items=2 ppid=200 pid=300 uid=1000 comm="curl" exe="/usr/bin/curl" key="osiris_fs""#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/var/www/html" inode=200000 dev=08:01 mode=040755 ouid=0 ogid=0 nametype=PARENT"#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=1 name="/var/www/html/shell.php" inode=200001 dev=08:01 mode=0100644 ouid=33 ogid=33 nametype=CREATE"#).unwrap();
        file.flush().unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for a file event")
            .expect("channel closed unexpectedly");
        match received {
            RawEvent::File(raw) => {
                assert_eq!(raw.operation, FileOperation::Create);
                assert_eq!(raw.path, "/var/www/html/shell.php");
                assert_eq!(raw.inode, Some(200001));
                assert_eq!(raw.exe_path, "/usr/bin/curl");
            }
            other => panic!("the Filesystem sensor must only emit File events, got {other:?}"),
        }

        sensor.stop().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.events_emitted_total, 1);
        assert_eq!(health.state, SensorState::Stopped);
    }

    /// The sensor must consume only what its own audit watch rules
    /// produced when a key filter is configured — a busy host's audit log
    /// carries every other subsystem's records too.
    #[tokio::test]
    async fn an_audit_key_filter_excludes_records_from_other_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor = FilesystemSensor::new(&path)
            .with_poll_interval(Duration::from_millis(20))
            .with_completion_timeout(Duration::from_millis(40))
            .with_audit_key("osiris_fs");
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
        // Someone else's rule fired first.
        writeln!(file, r#"type=SYSCALL msg=audit(1690000000.100:400): arch=c000003e syscall=87 success=yes exit=0 items=1 ppid=1 pid=99 uid=0 comm="logrotate" exe="/usr/sbin/logrotate" key="other_rule""#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.100:400): item=0 name="/var/log/old.log" inode=111 dev=08:01 mode=0100644 ouid=0 ogid=0 nametype=DELETE"#).unwrap();
        // Then ours.
        writeln!(file, r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=87 success=yes exit=0 items=1 ppid=200 pid=300 uid=1000 comm="rm" exe="/usr/bin/rm" key="osiris_fs""#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/var/www/html/shell.php" inode=200001 dev=08:01 mode=0100644 ouid=33 ogid=33 nametype=DELETE"#).unwrap();
        file.flush().unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        match received {
            RawEvent::File(raw) => assert_eq!(
                raw.path, "/var/www/html/shell.php",
                "the other rule's event must have been filtered out"
            ),
            other => panic!("expected a File event, got {other:?}"),
        }
        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 1);
    }
}
