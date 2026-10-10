use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use osiris_sensor_api::{
    ProcessExecRaw, RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::assembler::ExecAssembler;
use crate::proc_stat::read_process_start_time;
use osiris_fileutil::LineTailer;

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

/// The Process/Exec sensor (ARCHITECTURE.md §4.3), Phase 1 scope: audit
/// log-file backend only (plan Global Constraints #1/#2 — no eBPF). Each
/// execve SYSCALL record is joined with its EXECVE record for argv
/// (`ExecAssembler`).
pub struct ProcessExecSensor {
    audit_log_path: PathBuf,
    poll_interval: Duration,
    completion_timeout: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl ProcessExecSensor {
    pub fn new(audit_log_path: impl Into<PathBuf>) -> Self {
        Self {
            audit_log_path: audit_log_path.into(),
            poll_interval: Duration::from_millis(200),
            completion_timeout: Duration::from_millis(500),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// How long an execve SYSCALL waits for its EXECVE record before it is
    /// reported without argv (only the last event of a quiet log ever waits:
    /// any later record releases it at once).
    pub fn with_completion_timeout(mut self, timeout: Duration) -> Self {
        self.completion_timeout = timeout;
        self
    }
}

/// Locks a health mutex, recovering rather than panicking if a prior
/// holder panicked while holding the lock (a poisoned lock still holds a
/// perfectly usable HealthState — there's no invariant here that a panic
/// mid-update could violate) — keeps this crate's "no unwrap/expect
/// outside tests" discipline for lock results.
fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[async_trait]
impl Sensor for ProcessExecSensor {
    fn name(&self) -> &'static str {
        "process_exec"
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

        let path = self.audit_log_path.clone();
        let poll_interval = self.poll_interval;
        let completion_timeout = self.completion_timeout;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut tailer = LineTailer::new(path);
            let mut assembler = ExecAssembler::new(completion_timeout);
            loop {
                if cancellation.is_cancelled() {
                    // Report the exec still waiting for its EXECVE record
                    // rather than dropping it on shutdown.
                    if let Some(raw) = assembler.flush() {
                        emit(&output, raw, &health).await;
                    }
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                match tailer.poll() {
                    Ok(lines) => {
                        for line in lines {
                            for raw in assembler.offer(&line, Instant::now()) {
                                emit(&output, raw, &health).await;
                            }
                        }
                        if let Some(raw) = assembler.tick(Instant::now()) {
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
                        if let Some(raw) = assembler.flush() {
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
        // The polling task is already spawned in initialize(); Phase 1
        // keeps start()/initialize() split per the trait contract but does
        // the actual work at initialize() time since there is no separate
        // "armed but not yet running" state this sensor needs.
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
    raw: ProcessExecRaw,
    health: &Mutex<HealthState>,
) {
    let start_time_mono = read_process_start_time(raw.pid).unwrap_or(raw.timestamp_ns);
    let event_ts = raw.timestamp_ns;
    let event = ProcessExecRaw {
        start_time_mono,
        ..raw
    };
    if output.send(RawEvent::ProcessExec(event)).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(event_ts);
        h.state = SensorState::Healthy;
    } else {
        lock_health(health).events_dropped_total += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::RawEvent;
    use std::io::Write;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn sensor_reports_unsupported_when_audit_log_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = ProcessExecSensor::new(dir.path().join("missing.log"));
        let (tx, _rx) = mpsc::channel(16);
        let ctx = SensorContext::new(tx, CancellationToken::new());
        let result = sensor.initialize(ctx).await;
        assert!(result.is_err());
        assert!(!sensor.capabilities().supported());
    }

    #[tokio::test]
    async fn sensor_emits_a_canonical_raw_event_for_an_appended_execve_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor =
            ProcessExecSensor::new(&path).with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        let ctx = SensorContext::new(tx, cancellation.clone());
        sensor.initialize(ctx).await.unwrap();
        sensor.start().await.unwrap();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(
            file,
            r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" key=(null)"#
        )
        .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for event")
            .expect("channel closed unexpectedly");
        match received {
            RawEvent::ProcessExec(raw) => {
                assert_eq!(raw.pid, 5678);
                assert_eq!(raw.exe_path, "/usr/bin/curl");
            }
            other => {
                panic!("the Process/Exec sensor must only emit ProcessExec events, got {other:?}")
            }
        }

        sensor.stop().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.events_emitted_total, 1);
    }

    /// End to end through the sensor task: the real Ubuntu 24.04 records
    /// for `/bin/sh -c 'true <marker>'` yield events that carry argv.
    #[tokio::test]
    async fn sensor_attaches_argv_from_the_real_execve_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();
        let mut sensor = ProcessExecSensor::new(&path)
            .with_poll_interval(Duration::from_millis(20))
            .with_completion_timeout(Duration::from_millis(40));
        let (tx, mut rx) = mpsc::channel(16);
        sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(
            include_str!("../tests/fixtures/ubuntu2404-exec-sh-c-marker.log").as_bytes(),
        )
        .unwrap();
        file.flush().unwrap();

        let mut cmdlines = vec![];
        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
                Ok(Some(RawEvent::ProcessExec(raw))) => cmdlines.push(raw.cmdline),
                other => panic!("expected a ProcessExec event, got {other:?}"),
            }
        }
        sensor.stop().await.unwrap();
        assert_eq!(
            cmdlines[1],
            [
                "/bin/sh",
                "-c",
                "true osirisp10cfe49a0ea24b4218aad021ee0c8b56d2"
            ]
        );
        assert_eq!(cmdlines[0][0], "/bin/bash");
    }
}
