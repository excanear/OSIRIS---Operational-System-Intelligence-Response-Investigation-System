use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use osiris_ebpf::{
    boot_wall_offset_ns, decode_fs, kernel_symbols_text, missing_kernel_symbols, probe, AttachKind,
    DecodeError, DropCounter, EbpfSettings, FsEvent, LoadedObject, FS_OBJECT,
};
use osiris_fileutil::LineTailer;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::assembler::AuditEventAssembler;
use crate::audit_record::{parse_record, AuditRecord};
use crate::ebpf_backend::fs_to_raw_indexed;
use crate::exe_index::ExeIndex;
use crate::watch::{resolve_watch_paths, WatchResolution, DEFAULT_WATCH_PATHS};

/// How often the eBPF supervisor checks whether the reader thread ended.
const READER_SUPERVISE_INTERVAL: Duration = Duration::from_millis(100);

/// The real procfs root, used for `exe_path` resolution on the eBPF path.
const PROC_ROOT: &str = "/proc";

/// `WATCH_FLAGS` bit 0: an inode-only (`dev` 0) key exists.
const WATCH_FLAG_INODE_ONLY: u32 = 1;

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
    /// Why eBPF is off while running on the audit fallback; kept so a later
    /// audit tail error is reported next to it, never instead of it.
    fallback_reason: Option<String>,
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
            fallback_reason: None,
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

/// The Filesystem sensor (ARCHITECTURE.md §4.3's Filesystem row), with two
/// backends chosen at `initialize`, like the process sensor's:
///
/// - **eBPF** (when [`EbpfSettings`] are given and the host can load the
///   `osiris-ebpf` fs program): create/write/delete/rename records for the
///   watched directories from the ring buffer, read on a dedicated thread;
///   health `Healthy`, capability flag `ebpf`. Watch paths that cannot be
///   watched are named in `last_error` without degrading health; with none
///   usable eBPF is unusable (Global Constraint #13).
/// - **audit** log file (the only backend without `EbpfSettings`, exactly
///   as before), consumed by tailing an auditd-format log. When eBPF was
///   configured but could not be used it runs as the fallback: health
///   `Degraded`, the reason in `last_error`, flag `audit_fallback`. With
///   eBPF unusable and no audit log, `initialize` returns `Unsupported`
///   with every reason and the sensor is `Failed`.
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
    audit_log_path: Option<PathBuf>,
    ebpf: Option<EbpfSettings>,
    /// Directories the eBPF backend watches; empty means
    /// [`DEFAULT_WATCH_PATHS`].
    watch_paths: Vec<PathBuf>,
    poll_interval: Duration,
    completion_timeout: Duration,
    audit_key: Option<String>,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
    /// BPF-side ring-buffer reservation failures, added to
    /// `events_dropped_total` on every health/metrics read (eBPF only).
    drop_counter: Option<DropCounter>,
}

impl FilesystemSensor {
    pub fn new(
        audit_log_path: Option<PathBuf>,
        ebpf: Option<EbpfSettings>,
        watch_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            audit_log_path,
            ebpf,
            watch_paths,
            drop_counter: None,
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

    /// The configured watch paths, or the defaults when none are.
    fn effective_watch_paths(&self) -> Vec<PathBuf> {
        if self.watch_paths.is_empty() {
            DEFAULT_WATCH_PATHS.iter().map(PathBuf::from).collect()
        } else {
            self.watch_paths.clone()
        }
    }

    /// Start the eBPF backend: the reader thread plus an async supervisor
    /// that records how the thread ended (a reader error moves health to
    /// `Failed`, never a silent stop). `Err` (the thread could not be
    /// started; the program is dropped and detached) means fall back.
    fn start_ebpf(
        &mut self,
        loaded: Loaded,
        exe_index: ExeIndex,
        output: mpsc::Sender<RawEvent>,
        cancellation: CancellationToken,
    ) -> Result<(), String> {
        let Loaded {
            prog,
            watch_skipped,
            attach_skipped,
        } = loaded;
        let drop_counter = prog.drop_counter();
        let health = self.health.clone();
        let proc_root = PathBuf::from(PROC_ROOT);
        // Seeded by the caller off the async workers; owned by the reader
        // thread from here on.
        let mut exe_index = exe_index;
        let reader = osiris_ebpf::spawn_reader(prog, decode_fs, cancellation, move |record| {
            on_record(
                record,
                &boot_wall_offset_ns,
                &proc_root,
                &mut exe_index,
                &output,
                &health,
            )
        })
        .map_err(|e| format!("eBPF unavailable: {e}"))?;
        {
            let mut h = lock_health(&self.health);
            h.running_state = SensorState::Healthy;
            h.capability_flags = vec!["ebpf".to_string()];
            // Unwatched paths and skipped optional attach points are
            // reported but do not degrade health.
            if let Some(notes) = ebpf_start_notes(&watch_skipped, &attach_skipped) {
                h.last_error = Some(notes);
            }
        }
        if !attach_skipped.is_empty() {
            tracing::warn!(
                sensor = "filesystem",
                skipped = %attach_skipped.join("; "),
                "eBPF filesystem backend running without optional attach points"
            );
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
}

/// The fs program, loaded with its watch map and flags populated, plus the
/// watch paths that could not be watched and the optional attach points
/// that were skipped.
struct Loaded {
    prog: LoadedObject,
    watch_skipped: Vec<String>,
    attach_skipped: Vec<String>,
}

/// `last_error` for a running eBPF backend: the watch paths that could not
/// be watched and the optional attach points that were skipped, `None`
/// when there are neither. Neither degrades health.
fn ebpf_start_notes(watch_skipped: &[String], attach_skipped: &[String]) -> Option<String> {
    let mut notes = vec![];
    if !watch_skipped.is_empty() {
        notes.push(format!(
            "fs watch paths skipped: {}",
            watch_skipped.join("; ")
        ));
    }
    if !attach_skipped.is_empty() {
        notes.push(format!(
            "fs optional attach points skipped: {}",
            attach_skipped.join("; ")
        ));
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

/// The exe identity index, scanned on a blocking thread so the scan of the
/// executable directories never stalls an async worker. If that thread
/// panics, an unscanned index is used (it scans on its first miss, on the
/// reader thread).
async fn seed_exe_index() -> ExeIndex {
    tokio::task::spawn_blocking(ExeIndex::with_default_dirs)
        .await
        .unwrap_or_else(|_| ExeIndex::default_dirs_unscanned())
}

/// The fs object is x86_64-only (Global Constraint #6).
fn arch_problem() -> Option<String> {
    cfg!(not(target_arch = "x86_64")).then(|| "fs eBPF object is x86_64-only".to_string())
}

/// Required kprobe symbols of the fs object (Global Constraint #9), taken
/// from the object spec so the two cannot drift apart.
fn required_kprobes() -> Vec<&'static str> {
    FS_OBJECT
        .attach
        .iter()
        .filter(|p| p.required)
        .filter_map(|p| match p.kind {
            AttachKind::KProbe { symbol } => Some(symbol),
            AttachKind::TracePoint { .. } => None,
        })
        .collect()
}

/// Probe the host, resolve the watch paths, load the fs program and fill its
/// `WATCH`/`WATCH_FLAGS` maps. `Err` carries every reason found before
/// loading (a missing object is named even when the probe also fails, so
/// the operator sees the configuration problem as well as the host one).
fn load_ebpf(settings: &EbpfSettings, watch_paths: &[PathBuf]) -> Result<Loaded, String> {
    let mut reasons = vec![];
    let object = settings.object_dir.join(FS_OBJECT.object_file);
    reasons.extend(object_problem(&object));
    reasons.extend(host_problems());
    let WatchResolution {
        keys,
        inode_only,
        skipped,
    } = resolve_watch_paths(watch_paths);
    if keys.is_empty() {
        reasons.push(format!(
            "no usable fs watch path ({})",
            if skipped.is_empty() {
                "none configured".to_string()
            } else {
                skipped.join("; ")
            }
        ));
    }
    if !reasons.is_empty() {
        return Err(format!("eBPF unavailable: {}", reasons.join("; ")));
    }
    let mut prog = LoadedObject::load(&settings.object_dir, &FS_OBJECT, settings.self_tgid)
        .map_err(|e| format!("eBPF unavailable: {e}"))?;
    for key in &keys {
        prog.insert_watch(key.dev, key.ino)
            .map_err(|e| format!("eBPF unavailable: {e}"))?;
    }
    if inode_only {
        prog.set_watch_flags(WATCH_FLAG_INODE_ONLY)
            .map_err(|e| format!("eBPF unavailable: {e}"))?;
    }
    let attach_skipped = prog.skipped_attach_points().to_vec();
    Ok(Loaded {
        prog,
        watch_skipped: skipped,
        attach_skipped,
    })
}

/// Why this host cannot run the fs program, before the object is looked
/// at: the generic eBPF probe, the architecture, and the required kprobe
/// symbols (when the kernel's symbol list is readable). Empty when none.
fn host_problems() -> Vec<String> {
    let mut reasons = probe().reasons;
    reasons.extend(arch_problem());
    if let Some(symbols) = kernel_symbols_text() {
        for name in missing_kernel_symbols(&symbols, &required_kprobes()) {
            reasons.push(format!("required kernel symbol missing: {name}"));
        }
    }
    reasons
}

/// What is wrong with the BPF object path, truthfully: absent, present but
/// not a regular file, or not even stat-able. `None` when it is a regular
/// file. (Same rule as the process sensor's.)
fn object_problem(object: &Path) -> Option<String> {
    match std::fs::metadata(object) {
        Ok(m) if m.is_file() => None,
        Ok(_) => Some(format!(
            "bpf object is not a regular file: {}",
            object.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Some(format!("bpf object file missing: {}", object.display()))
        }
        Err(e) => Some(format!(
            "cannot access bpf object {}: {e}",
            object.display()
        )),
    }
}

/// Reader-thread callback: convert and forward one record on its own. A
/// record that does not decode is counted as dropped.
/// `boot_wall_offset_ns` is called once per decoded record, so the
/// realtime − monotonic offset is current for each event. Runs on the
/// reader's own `std::thread`, so blocking on a full channel is
/// backpressure, not a stalled async worker.
fn on_record(
    record: Result<FsEvent, DecodeError>,
    boot_wall_offset_ns: &dyn Fn() -> i128,
    proc_root: &Path,
    exe_index: &mut ExeIndex,
    output: &mpsc::Sender<RawEvent>,
    health: &Mutex<HealthState>,
) {
    let raw = match record {
        Ok(e) => fs_to_raw_indexed(&e, boot_wall_offset_ns(), proc_root, exe_index),
        Err(_) => {
            lock_health(health).events_dropped_total += 1;
            return;
        }
    };
    let ts = raw.timestamp_ns;
    let sent = output.blocking_send(RawEvent::File(raw)).is_ok();
    let mut h = lock_health(health);
    if sent {
        h.events_emitted_total += 1;
        h.last_event_at = Some(ts);
        h.state = h.running_state;
    } else {
        h.events_dropped_total += 1;
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

impl FilesystemSensor {
    /// Start the audit log-file backend (the pre-eBPF behaviour).
    fn start_audit(&mut self, path: PathBuf, ctx: SensorContext) {
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
                    // observed operation is not silently dropped on shutdown.
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
                        // Never let a tail error hide why eBPF is off.
                        h.last_error = Some(match &h.fallback_reason {
                            Some(reason) => format!("{reason}; audit: {e}"),
                            None => e.to_string(),
                        });
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
    }
}

#[async_trait]
impl Sensor for FilesystemSensor {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn capabilities(&self) -> SensorCapabilities {
        // The same host checks load_ebpf makes (probe, arch, required
        // kernel symbols), so `ebpf: true` is never claimed for a host
        // whose kernel lacks a required kprobe target.
        let ebpf_problems = self.ebpf.as_ref().map(|_| host_problems());
        let ebpf = ebpf_problems.as_ref().is_some_and(Vec::is_empty);
        let audit_reason = self.audit_unavailable_reason();
        let audit_fallback = audit_reason.is_none();
        let unsupported_reason = if ebpf || audit_fallback {
            None
        } else {
            let mut reasons = vec![];
            if let Some(why) = &ebpf_problems {
                reasons.push(format!("eBPF unavailable: {}", why.join("; ")));
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
        {
            // A re-initialize starts from a clean backend selection.
            let mut h = lock_health(&self.health);
            h.state = SensorState::Starting;
            h.running_state = SensorState::Healthy;
            h.last_error = None;
            h.fallback_reason = None;
            h.capability_flags = vec![];
        }
        self.drop_counter = None;

        let mut fallback_reason = None;
        if let Some(settings) = self.ebpf.clone() {
            let watch_paths = self.effective_watch_paths();
            let started = match load_ebpf(&settings, &watch_paths) {
                Ok(loaded) => {
                    let exe_index = seed_exe_index().await;
                    self.start_ebpf(
                        loaded,
                        exe_index,
                        ctx.output.clone(),
                        ctx.cancellation.clone(),
                    )
                }
                Err(reason) => Err(reason),
            };
            // Logged as well as health-visible: the backend choice is the
            // first thing a post-mortem of a real host needs.
            match started {
                Ok(()) => {
                    tracing::info!(
                        sensor = "filesystem",
                        object_dir = %settings.object_dir.display(),
                        "eBPF filesystem backend active"
                    );
                    return Ok(());
                }
                Err(reason) => {
                    tracing::warn!(
                        sensor = "filesystem",
                        reason = %reason,
                        "eBPF filesystem backend unavailable; trying the audit fallback"
                    );
                    fallback_reason = Some(reason);
                }
            }
        }

        let path = match (&self.audit_log_path, self.audit_unavailable_reason()) {
            (Some(path), None) => path.clone(),
            (_, audit_reason) => {
                let audit_reason = audit_reason.unwrap_or_default();
                let reason = match fallback_reason {
                    // eBPF was configured and there is nothing to fall back to.
                    Some(ebpf_reason) => {
                        let reason = format!("{ebpf_reason}; no audit fallback: {audit_reason}");
                        let mut h = lock_health(&self.health);
                        h.state = SensorState::Failed;
                        h.last_error = Some(reason.clone());
                        reason
                    }
                    // No eBPF configured: today's behaviour.
                    None => {
                        lock_health(&self.health).last_error = Some(audit_reason.clone());
                        audit_reason
                    }
                };
                return Err(SensorError::Unsupported(reason));
            }
        };

        {
            let mut h = lock_health(&self.health);
            if let Some(reason) = fallback_reason {
                h.running_state = SensorState::Degraded;
                h.last_error = Some(reason.clone());
                h.fallback_reason = Some(reason);
            }
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

/// Forward one audit event; it (re)asserts the running state, so the
/// fallback stays `Degraded` while it emits.
async fn emit(
    output: &mpsc::Sender<RawEvent>,
    raw: osiris_sensor_api::FileEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::File(raw)).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(timestamp);
        h.state = h.running_state;
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
        let mut sensor = FilesystemSensor::new(Some(dir.path().join("missing.log")), None, vec![]);
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

        let mut sensor = FilesystemSensor::new(Some(path.clone()), None, vec![])
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

        let mut sensor = FilesystemSensor::new(Some(path.clone()), None, vec![])
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

    fn ebpf_settings(dir: &Path) -> EbpfSettings {
        EbpfSettings {
            object_dir: dir.to_path_buf(),
            self_tgid: std::process::id(),
        }
    }

    fn append_audit_group(path: &Path) {
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(file, r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=257 success=yes exit=3 items=2 ppid=200 pid=300 uid=1000 comm="curl" exe="/usr/bin/curl" key="osiris_fs""#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/var/www/html" inode=200000 dev=08:01 mode=040755 ouid=0 ogid=0 nametype=PARENT"#).unwrap();
        writeln!(file, r#"type=PATH msg=audit(1690000000.123:456): item=1 name="/var/www/html/shell.php" inode=200001 dev=08:01 mode=0100644 ouid=33 ogid=33 nametype=CREATE"#).unwrap();
        file.flush().unwrap();
    }

    /// `ebpf` configured, but the object directory holds no `fs.bpf.o`: the
    /// sensor runs the audit tailer, Degraded with the reason, and an
    /// emitted event does not hide the fallback.
    #[tokio::test]
    async fn falls_back_to_audit_when_fs_object_missing() {
        let objects = tempfile::tempdir().unwrap();
        let logs = tempfile::tempdir().unwrap();
        let log = logs.path().join("audit.log");
        std::fs::write(&log, "").unwrap();
        let mut sensor = FilesystemSensor::new(
            Some(log.clone()),
            Some(ebpf_settings(objects.path())),
            vec![],
        )
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
                .is_some_and(|e| e.contains("fs.bpf.o")),
            "reason must name the missing object: {:?}",
            health.last_error
        );
        assert_eq!(health.capability_flags, ["audit_fallback"]);

        append_audit_group(&log);
        match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
            Ok(Some(RawEvent::File(raw))) => {
                assert_eq!(raw.path, "/var/www/html/shell.php");
                assert_eq!(raw.source, osiris_sensor_api::RawEventSource::Audit);
            }
            other => panic!("expected an audit File event, got {other:?}"),
        }
        assert_eq!(
            sensor.health().state,
            SensorState::Degraded,
            "an emitted event must not hide the fallback"
        );
        sensor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn unsupported_without_audit_when_ebpf_fails() {
        let objects = tempfile::tempdir().unwrap();
        let mut sensor = FilesystemSensor::new(None, Some(ebpf_settings(objects.path())), vec![]);
        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        match result {
            Err(SensorError::Unsupported(reason)) => {
                assert!(reason.contains("fs.bpf.o"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        let health = sensor.health();
        assert_eq!(health.state, SensorState::Failed);
        assert!(health
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("fs.bpf.o")));
    }

    #[tokio::test]
    async fn no_ebpf_key_behaves_as_before() {
        let logs = tempfile::tempdir().unwrap();
        let log = logs.path().join("audit.log");
        std::fs::write(&log, "").unwrap();
        let mut sensor = FilesystemSensor::new(Some(log), None, vec![]);
        let caps = sensor.capabilities();
        assert!(caps.audit_fallback && !caps.ebpf && !caps.always_available);
        let (tx, _rx) = mpsc::channel(16);
        sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await
            .unwrap();
        sensor.start().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.state, SensorState::Healthy);
        assert_eq!(health.capability_flags, ["audit_fallback"]);
        assert_eq!(health.last_error, None);
        sensor.stop().await.unwrap();
    }

    #[test]
    fn required_kprobes_come_from_the_object_spec() {
        let k = required_kprobes();
        assert_eq!(k.len(), 7, "{k:?}");
        assert!(k.contains(&"security_file_open"));
        assert!(!k.contains(&"security_file_truncate"), "optional");
    }

    #[test]
    fn skipped_attach_points_reach_last_error_next_to_skipped_watch_paths() {
        assert_eq!(ebpf_start_notes(&[], &[]), None);
        let attach = vec!["kp_file_truncate: security_file_truncate: not present".to_string()];
        assert_eq!(
            ebpf_start_notes(&[], &attach).as_deref(),
            Some(
                "fs optional attach points skipped: \
                 kp_file_truncate: security_file_truncate: not present"
            )
        );
        let watch = vec!["/var/www: not found".to_string()];
        let both = ebpf_start_notes(&watch, &attach).unwrap();
        assert!(
            both.starts_with("fs watch paths skipped: /var/www: not found; "),
            "{both}"
        );
        assert!(both.contains("security_file_truncate"), "{both}");
    }

    /// Off a usable eBPF host, `capabilities()` must not claim eBPF; the
    /// reason lists the same host checks `load_ebpf` makes.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn capabilities_report_host_problems_like_load_ebpf() {
        let dir = tempfile::tempdir().unwrap();
        let sensor = FilesystemSensor::new(None, Some(ebpf_settings(dir.path())), vec![]);
        let caps = sensor.capabilities();
        assert!(!caps.ebpf);
        let reason = caps.unsupported_reason.unwrap();
        for problem in host_problems() {
            assert!(reason.contains(&problem), "{reason} lacks {problem}");
        }
    }

    fn fs_record() -> FsEvent {
        FsEvent {
            kind: osiris_ebpf::FsKind::Create,
            pid: u32::MAX,
            ppid: 1,
            uid: 0,
            ret: 0,
            ktime_ns: 100,
            comm: "touch".to_string(),
            exe: None,
            inode: None,
            path: b"/tmp/x".to_vec(),
            path_truncated: false,
            old_path: None,
            old_path_truncated: false,
        }
    }

    /// The realtime − monotonic offset is resampled for every record (the
    /// net sensor's `ebpf_on_record_resamples_offset`, for fs).
    #[test]
    fn ebpf_on_record_counts_and_resamples() {
        let root = tempfile::tempdir().unwrap();
        let health = Mutex::new(HealthState::default());
        let (tx, mut rx) = mpsc::channel(4);
        let offset = std::cell::Cell::new(1_000i128);
        let sample = || {
            let now = offset.get();
            offset.set(now + 5_000); // the clock steps between records
            now
        };
        on_record(
            Ok(fs_record()),
            &sample,
            root.path(),
            &mut ExeIndex::empty(),
            &tx,
            &health,
        );
        on_record(
            Ok(fs_record()),
            &sample,
            root.path(),
            &mut ExeIndex::empty(),
            &tx,
            &health,
        );
        on_record(
            Err(DecodeError::ShorterThanHeader(3)),
            &sample,
            root.path(),
            &mut ExeIndex::empty(),
            &tx,
            &health,
        );
        let mut stamps = Vec::new();
        while let Ok(RawEvent::File(raw)) = rx.try_recv() {
            assert_eq!(raw.source, osiris_sensor_api::RawEventSource::Ebpf);
            stamps.push(raw.timestamp_ns);
        }
        assert_eq!(stamps, [1_100, 6_100]);
        // A record that does not decode is not stamped, so not sampled.
        assert_eq!(offset.get(), 11_000);
        let h = lock_health(&health);
        assert_eq!(h.events_emitted_total, 2);
        assert_eq!(h.events_dropped_total, 1);
        assert_eq!(h.last_event_at, Some(6_100));
    }

    #[test]
    fn ebpf_on_record_counts_a_closed_channel_as_dropped() {
        let root = tempfile::tempdir().unwrap();
        let health = Mutex::new(HealthState::default());
        let (tx, rx) = mpsc::channel(4);
        drop(rx);
        on_record(
            Ok(fs_record()),
            &|| 0,
            root.path(),
            &mut ExeIndex::empty(),
            &tx,
            &health,
        );
        let h = lock_health(&health);
        assert_eq!(h.events_dropped_total, 1);
        assert_eq!(h.events_emitted_total, 0);
        assert_eq!(h.state, SensorState::Starting);
    }
}
