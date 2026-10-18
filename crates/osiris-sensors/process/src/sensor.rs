use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use osiris_ebpf::{probe, DecodeError, DropCounter, ProcessProgram, Record};
use osiris_sensor_api::{
    ProcessExecRaw, RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::assembler::ExecAssembler;
use crate::ebpf_backend::{exec_to_raw, exit_to_raw};
use crate::proc_stat::read_process_start_time;
use osiris_fileutil::LineTailer;

/// How often the eBPF supervisor checks whether the reader thread ended.
const READER_SUPERVISE_INTERVAL: Duration = Duration::from_millis(100);

/// Where to find the process BPF object, and which tgid (the agent's own)
/// the in-kernel self-filter drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfSettings {
    pub object_dir: PathBuf,
    pub self_tgid: u32,
}

struct HealthState {
    state: SensorState,
    /// The state an emitted event (re)asserts: `Healthy`, or `Degraded`
    /// while running on the audit fallback, so a later event never hides
    /// that eBPF failed.
    running_state: SensorState,
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
            running_state: SensorState::Healthy,
            events_emitted_total: 0,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: None,
            capability_flags: vec![],
        }
    }
}

/// The Process/Exec sensor (ARCHITECTURE.md §4.3), with two backends
/// chosen at `initialize`:
///
/// - **eBPF** (when [`EbpfSettings`] are given and the host can load the
///   `osiris-ebpf` process program): exec and exit records from the ring
///   buffer, read on a dedicated thread; health `Healthy`, capability flag
///   `ebpf`.
/// - **audit** log file (the only backend without `EbpfSettings`, exactly
///   as before): each execve SYSCALL record is joined with its EXECVE
///   record for argv (`ExecAssembler`). When eBPF was configured but could
///   not be used it runs as the fallback: health `Degraded`, the reason in
///   `last_error`, capability flag `audit_fallback`. With eBPF unusable and
///   no audit log the sensor is `Failed` with the reason.
pub struct ProcessExecSensor {
    audit_log_path: Option<PathBuf>,
    ebpf: Option<EbpfSettings>,
    poll_interval: Duration,
    completion_timeout: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
    /// BPF-side ring-buffer reservation failures, added to
    /// `events_dropped_total` on every health/metrics read (eBPF only).
    drop_counter: Option<DropCounter>,
}

impl ProcessExecSensor {
    pub fn new(audit_log_path: Option<PathBuf>, ebpf: Option<EbpfSettings>) -> Self {
        Self {
            audit_log_path,
            ebpf,
            poll_interval: Duration::from_millis(200),
            completion_timeout: Duration::from_millis(500),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
            drop_counter: None,
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

    /// Sensor-side drops plus the BPF program's ring-buffer drops.
    fn dropped_total(&self, h: &HealthState) -> u64 {
        let bpf = self.drop_counter.as_ref().map_or(0, DropCounter::get);
        h.events_dropped_total.saturating_add(bpf)
    }

    /// Why the audit backend cannot run, `None` when it can.
    fn audit_unavailable_reason(&self) -> Option<String> {
        match &self.audit_log_path {
            Some(path) if path.exists() => None,
            Some(path) => Some(format!("audit log not found at {}", path.display())),
            None => Some("no audit log path configured".to_string()),
        }
    }

    /// Start the eBPF backend: the reader thread plus an async supervisor
    /// that records how the thread ended (a reader error moves health to
    /// `Failed`, never a silent stop). `Err` (the thread could not be
    /// started; the program is dropped and detached) means fall back.
    fn start_ebpf(
        &mut self,
        prog: ProcessProgram,
        output: mpsc::Sender<RawEvent>,
        cancellation: CancellationToken,
    ) -> Result<(), String> {
        let drop_counter = prog.drop_counter();
        let offset = boot_wall_offset_ns();
        let health = self.health.clone();
        let reader = osiris_ebpf::spawn_reader(prog, cancellation, move |record| {
            on_record(record, offset, &output, &health)
        })
        .map_err(|e| format!("eBPF unavailable: {e}"))?;
        {
            let mut h = lock_health(&self.health);
            h.running_state = SensorState::Healthy;
            h.capability_flags = vec!["ebpf".to_string()];
        }
        self.drop_counter = Some(drop_counter);

        let health = self.health.clone();
        self.task_handle = Some(tokio::spawn(async move {
            while !reader.is_finished() {
                tokio::time::sleep(READER_SUPERVISE_INTERVAL).await;
            }
            let outcome = reader.join();
            let mut h = lock_health(&health);
            match outcome {
                Ok(Ok(())) => h.state = SensorState::Stopped,
                Ok(Err(e)) => {
                    h.state = SensorState::Failed;
                    h.last_error = Some(e.to_string());
                }
                Err(_) => {
                    h.state = SensorState::Failed;
                    h.last_error = Some("eBPF ring-buffer reader thread panicked".to_string());
                }
            }
        }));
        Ok(())
    }

    /// Start the audit log-file backend (the pre-eBPF behaviour).
    fn start_audit(&mut self, path: PathBuf, ctx: SensorContext) {
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
    }
}

/// Probe the host and load the program; `Err` carries every reason found
/// (a missing object is named even when the probe also fails, so the
/// operator sees the configuration problem as well as the host one).
fn load_ebpf(settings: &EbpfSettings) -> Result<ProcessProgram, String> {
    let mut reasons = vec![];
    let object = settings.object_dir.join(osiris_ebpf::loader::OBJECT_FILE);
    if !object.is_file() {
        reasons.push(format!("bpf object file missing: {}", object.display()));
    }
    reasons.extend(probe().reasons);
    if !reasons.is_empty() {
        return Err(format!("eBPF unavailable: {}", reasons.join("; ")));
    }
    ProcessProgram::load(&settings.object_dir, settings.self_tgid)
        .map_err(|e| format!("eBPF unavailable: {e}"))
}

/// realtime − monotonic, in ns: added to a `bpf_ktime_get_ns()` value
/// (CLOCK_MONOTONIC) it gives wall-clock time. Sampled once per reader
/// start, so a later wall-clock step is not followed (as with any
/// monotonic-based timestamp).
#[cfg(target_os = "linux")]
fn boot_wall_offset_ns() -> i128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the
    // call; CLOCK_MONOTONIC is always supported on Linux.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    if rc != 0 {
        return 0;
    }
    wall - (i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec))
}

/// Off Linux a program never loads, so the offset is never used.
#[cfg(not(target_os = "linux"))]
fn boot_wall_offset_ns() -> i128 {
    0
}

/// Reader-thread callback: convert and forward one record. A record that
/// does not decode is counted as dropped. Runs on the reader's own
/// `std::thread`, so blocking on a full channel is backpressure, not a
/// stalled async worker.
fn on_record(
    record: Result<Record, DecodeError>,
    boot_wall_offset_ns: i128,
    output: &mpsc::Sender<RawEvent>,
    health: &Mutex<HealthState>,
) {
    let (event, ts) = match record {
        Ok(Record::Exec(e)) => {
            let raw = exec_to_raw(&e, boot_wall_offset_ns);
            let ts = raw.timestamp_ns;
            (RawEvent::ProcessExec(raw), ts)
        }
        Ok(Record::Exit(e)) => {
            let raw = exit_to_raw(&e, boot_wall_offset_ns);
            let ts = raw.timestamp_ns;
            (RawEvent::ProcessExit(raw), ts)
        }
        Err(_) => {
            lock_health(health).events_dropped_total += 1;
            return;
        }
    };
    let sent = output.blocking_send(event).is_ok();
    let mut h = lock_health(health);
    if sent {
        h.events_emitted_total += 1;
        h.last_event_at = Some(ts);
        h.state = h.running_state;
    } else {
        h.events_dropped_total += 1;
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
        let ebpf_report = self.ebpf.as_ref().map(|_| probe());
        let ebpf = ebpf_report.as_ref().is_some_and(|r| r.supported);
        let audit_reason = self.audit_unavailable_reason();
        let audit_fallback = audit_reason.is_none();
        let unsupported_reason = if ebpf || audit_fallback {
            None
        } else {
            let mut reasons = vec![];
            if let Some(report) = &ebpf_report {
                reasons.push(format!("eBPF unavailable: {}", report.reasons.join("; ")));
            }
            reasons.extend(audit_reason);
            Some(reasons.join("; "))
        };
        SensorCapabilities {
            ebpf,
            audit_fallback,
            always_available: false,
            unsupported_reason,
        }
    }

    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError> {
        self.cancellation = Some(ctx.cancellation.clone());
        lock_health(&self.health).state = SensorState::Starting;
        self.drop_counter = None;

        let mut fallback_reason = None;
        if let Some(settings) = self.ebpf.clone() {
            let started = load_ebpf(&settings).and_then(|prog| {
                self.start_ebpf(prog, ctx.output.clone(), ctx.cancellation.clone())
            });
            match started {
                Ok(()) => return Ok(()),
                Err(reason) => fallback_reason = Some(reason),
            }
        }

        let path = match (&self.audit_log_path, self.audit_unavailable_reason()) {
            (Some(path), None) => path.clone(),
            (_, audit_reason) => {
                let reason = match fallback_reason {
                    // eBPF was configured and there is nothing to fall back to.
                    Some(ebpf_reason) => {
                        let reason = format!(
                            "{ebpf_reason}; no audit fallback: {}",
                            audit_reason.unwrap_or_default()
                        );
                        let mut h = lock_health(&self.health);
                        h.state = SensorState::Failed;
                        h.last_error = Some(reason.clone());
                        reason
                    }
                    // No eBPF configured: today's behaviour.
                    None => {
                        let reason = audit_reason.unwrap_or_default();
                        lock_health(&self.health).last_error = Some(reason.clone());
                        reason
                    }
                };
                return Err(SensorError::Unsupported(reason));
            }
        };

        if let Some(reason) = fallback_reason {
            let mut h = lock_health(&self.health);
            h.running_state = SensorState::Degraded;
            h.last_error = Some(reason);
            h.capability_flags = vec!["audit_fallback".to_string()];
        }
        self.start_audit(path, ctx);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
        // The backend is already running from initialize(); start() only
        // publishes its running state (Healthy, or Degraded on the audit
        // fallback) unless the backend has already moved on (an eBPF reader
        // that failed in between stays Failed).
        let mut h = lock_health(&self.health);
        if h.state == SensorState::Starting {
            h.state = h.running_state;
        }
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
            events_dropped_total: self.dropped_total(&h),
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
            events_dropped_total: self.dropped_total(&h),
        }
    }
}

async fn emit(output: &mpsc::Sender<RawEvent>, raw: ProcessExecRaw, health: &Mutex<HealthState>) {
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
        h.state = h.running_state;
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
        let mut sensor = ProcessExecSensor::new(Some(dir.path().join("missing.log")), None);
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

        let mut sensor = ProcessExecSensor::new(Some(path.clone()), None)
            .with_poll_interval(Duration::from_millis(20));
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
        let mut sensor = ProcessExecSensor::new(Some(path.clone()), None)
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

    const CURL_SYSCALL: &str = r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" key=(null)"#;

    fn ebpf_settings(dir: &std::path::Path) -> EbpfSettings {
        EbpfSettings {
            object_dir: dir.to_path_buf(),
            self_tgid: std::process::id(),
        }
    }

    /// `ebpf` configured, but the object directory is empty: the sensor
    /// falls back to the audit backend, Degraded with the reason.
    #[tokio::test]
    async fn falls_back_to_audit_when_ebpf_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let objects = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();
        let mut sensor =
            ProcessExecSensor::new(Some(path.clone()), Some(ebpf_settings(objects.path())))
                .with_poll_interval(Duration::from_millis(20))
                .with_completion_timeout(Duration::from_millis(40));
        let (tx, mut rx) = mpsc::channel(16);
        sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let health = sensor.health();
        assert_eq!(health.state, SensorState::Degraded);
        assert!(
            health
                .last_error
                .as_deref()
                .is_some_and(|e| e.contains("process.bpf.o")),
            "reason must name the missing object: {:?}",
            health.last_error
        );
        assert!(health
            .capability_flags
            .contains(&"audit_fallback".to_string()));

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{CURL_SYSCALL}").unwrap();
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(RawEvent::ProcessExec(raw))) => {
                assert_eq!(raw.pid, 5678);
                assert_eq!(raw.source, osiris_sensor_api::RawEventSource::Audit);
            }
            other => panic!("expected an audit ProcessExec event, got {other:?}"),
        }
        assert_eq!(
            sensor.health().state,
            SensorState::Degraded,
            "an emitted event must not hide the fallback"
        );
        sensor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn no_ebpf_settings_is_todays_behaviour() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();
        let mut sensor = ProcessExecSensor::new(Some(path), None);
        let caps = sensor.capabilities();
        assert!(caps.audit_fallback && !caps.ebpf);
        let (tx, _rx) = mpsc::channel(16);
        sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await
            .unwrap();
        sensor.start().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.state, SensorState::Healthy);
        assert!(!health
            .capability_flags
            .contains(&"audit_fallback".to_string()));
        assert_eq!(health.last_error, None);
        sensor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn ebpf_unavailable_without_audit_fails() {
        let objects = tempfile::tempdir().unwrap();
        let mut sensor = ProcessExecSensor::new(None, Some(ebpf_settings(objects.path())));
        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
        let health = sensor.health();
        assert_eq!(health.state, SensorState::Failed);
        assert!(
            health
                .last_error
                .as_deref()
                .is_some_and(|e| e.contains("process.bpf.o")),
            "reason must be reported: {:?}",
            health.last_error
        );
    }
}
