use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_ebpf::{
    boot_wall_offset_ns, probe, DecodeError, DropCounter, EbpfSettings, LoadedObject, NetEvent,
    NET_OBJECT,
};
use osiris_sensor_api::{
    NetworkEventRaw, RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError,
    SensorHealth, SensorMetrics, SensorState,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ebpf_backend::net_to_raw;
use crate::poller::NetworkPoller;

/// How often the eBPF supervisor checks whether the reader thread ended.
const READER_SUPERVISE_INTERVAL: Duration = Duration::from_millis(100);

/// The real procfs root, used for `exe_path` resolution on the eBPF path
/// when no `network_proc_root` is configured.
const PROC_ROOT: &str = "/proc";

struct HealthState {
    state: SensorState,
    /// The state an emitted event (re)asserts: `Healthy`, or `Degraded`
    /// while running on the procfs fallback, so a later event never hides
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

/// Locks a health mutex, recovering rather than panicking if a prior
/// holder panicked while holding the lock (the HealthState stays usable).
fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Network sensor (ARCHITECTURE.md §4.3's Network row), with two
/// backends chosen at `initialize`, like the process sensor's:
///
/// - **eBPF** (when [`EbpfSettings`] are given and the host can load the
///   `osiris-ebpf` net program): TCP connect/accept/close records from the
///   ring buffer, read on a dedicated thread, with exact direction; health
///   `Healthy`, capability flag `ebpf`.
/// - **procfs** `/proc/net/tcp` poller (the only backend without
///   `EbpfSettings`, exactly as before: flag `always_available`). When eBPF
///   was configured but could not be used it runs as the fallback: health
///   `Degraded`, the reason in `last_error`, flag `procfs_fallback`. With
///   eBPF unusable and no usable `proc_root`, `initialize` returns
///   `Unsupported` with the reason and the sensor is `Failed`.
pub struct NetworkSensor {
    proc_root: Option<PathBuf>,
    ebpf: Option<EbpfSettings>,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
    /// BPF-side ring-buffer reservation failures, added to
    /// `events_dropped_total` on every health/metrics read (eBPF only).
    drop_counter: Option<DropCounter>,
}

impl NetworkSensor {
    pub fn new(proc_root: Option<PathBuf>, ebpf: Option<EbpfSettings>) -> Self {
        Self {
            proc_root,
            ebpf,
            poll_interval: Duration::from_millis(200),
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

    /// Sensor-side drops plus the BPF program's ring-buffer drops.
    fn dropped_total(&self, h: &HealthState) -> u64 {
        let bpf = self.drop_counter.as_ref().map_or(0, DropCounter::get);
        h.events_dropped_total.saturating_add(bpf)
    }

    /// Why the procfs poller cannot run, `None` when it can.
    fn procfs_unavailable_reason(&self) -> Option<String> {
        match &self.proc_root {
            Some(root) if root.join("net").join("tcp").exists() => None,
            Some(root) => Some(format!("net/tcp not found under {}", root.display())),
            None => Some("no network_proc_root configured".to_string()),
        }
    }

    /// Start the eBPF backend: the reader thread plus an async supervisor
    /// that records how the thread ended (a reader error moves health to
    /// `Failed`, never a silent stop). `Err` (the thread could not be
    /// started; the program is dropped and detached) means fall back.
    fn start_ebpf(
        &mut self,
        prog: LoadedObject,
        output: mpsc::Sender<RawEvent>,
        cancellation: CancellationToken,
    ) -> Result<(), String> {
        let drop_counter = prog.drop_counter();
        let health = self.health.clone();
        // A configured proc root is the procfs the poller would read (tests
        // point it at a fixture); otherwise the real one.
        let proc_root = self
            .proc_root
            .clone()
            .unwrap_or_else(|| PathBuf::from(PROC_ROOT));
        let reader =
            osiris_ebpf::spawn_reader(prog, osiris_ebpf::decode_net, cancellation, move |record| {
                on_record(record, &boot_wall_offset_ns, &proc_root, &output, &health)
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

    /// Start the `/proc/net/tcp` poller (the pre-eBPF behaviour).
    fn start_procfs(&mut self, proc_root: PathBuf, ctx: SensorContext) {
        let poll_interval = self.poll_interval;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut poller = NetworkPoller::new(proc_root);
            loop {
                if cancellation.is_cancelled() {
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                for raw in poller.poll(now_ns) {
                    emit(&output, raw, &health).await;
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
    }
}

/// Probe the host and load the net program; `Err` carries every reason
/// found (a missing object is named even when the probe also fails, so the
/// operator sees the configuration problem as well as the host one).
fn load_ebpf(settings: &EbpfSettings) -> Result<LoadedObject, String> {
    let mut reasons = vec![];
    let object = settings.object_dir.join(NET_OBJECT.object_file);
    reasons.extend(object_problem(&object));
    reasons.extend(probe().reasons);
    if !reasons.is_empty() {
        return Err(format!("eBPF unavailable: {}", reasons.join("; ")));
    }
    LoadedObject::load(&settings.object_dir, &NET_OBJECT, settings.self_tgid)
        .map_err(|e| format!("eBPF unavailable: {e}"))
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

/// Reader-thread callback: convert and forward one record, on its own
/// (no CONNECT/CLOSE pairing: a CLOSE may arrive with no open record
/// before it). A record that does not decode is counted as dropped.
/// `boot_wall_offset_ns` is called once per decoded record, so the
/// realtime − monotonic offset is current for each event. Runs on the
/// reader's own `std::thread`, so blocking on a full channel is
/// backpressure, not a stalled async worker.
fn on_record(
    record: Result<NetEvent, DecodeError>,
    boot_wall_offset_ns: &dyn Fn() -> i128,
    proc_root: &Path,
    output: &mpsc::Sender<RawEvent>,
    health: &Mutex<HealthState>,
) {
    let raw = match record {
        Ok(e) => net_to_raw(&e, boot_wall_offset_ns(), proc_root),
        Err(_) => {
            lock_health(health).events_dropped_total += 1;
            return;
        }
    };
    let ts = raw.timestamp_ns;
    let sent = output.blocking_send(RawEvent::Network(raw)).is_ok();
    let mut h = lock_health(health);
    if sent {
        h.events_emitted_total += 1;
        h.last_event_at = Some(ts);
        h.state = h.running_state;
    } else {
        h.events_dropped_total += 1;
    }
}

#[async_trait]
impl Sensor for NetworkSensor {
    fn name(&self) -> &'static str {
        "network"
    }

    fn capabilities(&self) -> SensorCapabilities {
        let ebpf_report = self.ebpf.as_ref().map(|_| probe());
        let ebpf = ebpf_report.as_ref().is_some_and(|r| r.supported);
        // `audit_fallback` specifically means "the real Linux Audit backend
        // is available" (see SensorCapabilities's doc comment) — the procfs
        // poller is not audit-based, so it reports `always_available`.
        let procfs_reason = self.procfs_unavailable_reason();
        let always_available = procfs_reason.is_none();
        let unsupported_reason = if ebpf || always_available {
            None
        } else {
            let mut reasons = vec![];
            if let Some(report) = &ebpf_report {
                reasons.push(format!("eBPF unavailable: {}", report.reasons.join("; ")));
            }
            reasons.extend(procfs_reason);
            Some(reasons.join("; "))
        };
        SensorCapabilities {
            ebpf,
            audit_fallback: false,
            always_available,
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
            h.capability_flags = vec![];
        }
        self.drop_counter = None;

        let mut fallback_reason = None;
        if let Some(settings) = self.ebpf.clone() {
            let started = load_ebpf(&settings).and_then(|prog| {
                self.start_ebpf(prog, ctx.output.clone(), ctx.cancellation.clone())
            });
            // Logged as well as health-visible: the backend choice is the
            // first thing a post-mortem of a real host needs.
            match started {
                Ok(()) => {
                    tracing::info!(
                        sensor = "network",
                        object_dir = %settings.object_dir.display(),
                        "eBPF network backend active"
                    );
                    return Ok(());
                }
                Err(reason) => {
                    tracing::warn!(
                        sensor = "network",
                        reason = %reason,
                        "eBPF network backend unavailable; trying the procfs fallback"
                    );
                    fallback_reason = Some(reason);
                }
            }
        }

        let proc_root = match (&self.proc_root, self.procfs_unavailable_reason()) {
            (Some(root), None) => root.clone(),
            (_, procfs_reason) => {
                let procfs_reason = procfs_reason.unwrap_or_default();
                let reason = match fallback_reason {
                    // eBPF was configured and there is nothing to fall back to.
                    Some(ebpf_reason) => {
                        let reason = format!("{ebpf_reason}; no procfs fallback: {procfs_reason}");
                        let mut h = lock_health(&self.health);
                        h.state = SensorState::Failed;
                        h.last_error = Some(reason.clone());
                        reason
                    }
                    // No eBPF configured: today's behaviour.
                    None => {
                        lock_health(&self.health).last_error = Some(procfs_reason.clone());
                        procfs_reason
                    }
                };
                return Err(SensorError::Unsupported(reason));
            }
        };

        {
            let mut h = lock_health(&self.health);
            match fallback_reason {
                Some(reason) => {
                    h.running_state = SensorState::Degraded;
                    h.last_error = Some(reason);
                    h.capability_flags = vec!["procfs_fallback".to_string()];
                }
                None => h.capability_flags = vec!["always_available".to_string()],
            }
        }
        self.start_procfs(proc_root, ctx);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
        // The backend is already running from initialize(); start() only
        // publishes its running state (Healthy, or Degraded on the procfs
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

/// Forward one procfs event; it (re)asserts the running state, so the
/// fallback stays `Degraded` while it emits.
async fn emit(output: &mpsc::Sender<RawEvent>, raw: NetworkEventRaw, health: &Mutex<HealthState>) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::Network(raw)).await.is_ok() {
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
    use osiris_ebpf::{DecodeError, NetEvent, NetKind, AF_INET, DIR_OUTBOUND};
    use osiris_sensor_api::{RawEvent, RawEventSource, Sensor, SensorContext, SensorState};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    const TCP_ROW: &str = "  0: 0500000A:C738 32671BCB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 100 0 0 10 0\n";

    /// A `/proc`-shaped fixture whose `net/tcp` holds `rows`.
    fn proc_fixture(rows: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(
            dir.path().join("net").join("tcp"),
            format!("{TCP_HEADER}{rows}"),
        )
        .unwrap();
        dir
    }

    fn ebpf_settings(dir: &std::path::Path) -> EbpfSettings {
        EbpfSettings {
            object_dir: dir.to_path_buf(),
            self_tgid: std::process::id(),
        }
    }

    /// An object directory as an 11b-1 install leaves it: the process
    /// object and its sidecar, no `net.bpf.o`.
    fn process_only_objects() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("process.bpf.o"), b"\x7fELF").unwrap();
        std::fs::write(dir.path().join("process.bpf.o.sha256"), b"00\n").unwrap();
        dir
    }

    #[tokio::test]
    async fn reports_unsupported_when_proc_root_net_tcp_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = NetworkSensor::new(Some(dir.path().to_path_buf()), None);
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        assert!(caps
            .unsupported_reason
            .as_deref()
            .unwrap_or_default()
            .contains("net/tcp not found"));

        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn emits_a_connect_event_for_a_new_connection_appearing_in_proc_net_tcp() {
        let dir = proc_fixture("");
        let mut sensor = NetworkSensor::new(Some(dir.path().to_path_buf()), None)
            .with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        // A connection appears on the next poll.
        std::fs::write(
            dir.path().join("net").join("tcp"),
            format!("{TCP_HEADER}{TCP_ROW}"),
        )
        .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for a network event")
            .expect("channel closed unexpectedly");
        match received {
            RawEvent::Network(raw) => {
                assert_eq!(raw.remote_addr, "203.27.103.50");
                assert_eq!(raw.remote_port, 443);
            }
            other => panic!("the Network sensor must only emit Network events, got {other:?}"),
        }

        sensor.stop().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.events_emitted_total, 1);
        assert_eq!(health.state, SensorState::Stopped);
    }

    /// `ebpf` configured but the object directory has no `net.bpf.o`: the
    /// sensor runs the procfs poller, Degraded with the reason, and an
    /// emitted event does not hide the fallback.
    #[tokio::test]
    async fn falls_back_to_procfs_when_net_object_missing() {
        let root = proc_fixture(TCP_ROW);
        let objects = process_only_objects();
        let mut sensor = NetworkSensor::new(
            Some(root.path().to_path_buf()),
            Some(ebpf_settings(objects.path())),
        )
        .with_poll_interval(Duration::from_millis(20));
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
                .is_some_and(|e| e.contains("net.bpf.o")),
            "reason must name the missing object: {:?}",
            health.last_error
        );
        assert_eq!(health.capability_flags, ["procfs_fallback"]);

        match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
            Ok(Some(RawEvent::Network(raw))) => {
                assert_eq!(raw.remote_addr, "203.27.103.50");
                assert_eq!(raw.source, RawEventSource::Procfs);
            }
            other => panic!("expected a procfs Network event, got {other:?}"),
        }
        assert_eq!(
            sensor.health().state,
            SensorState::Degraded,
            "an emitted event must not hide the fallback"
        );
        sensor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn unsupported_without_proc_root_when_ebpf_fails() {
        let objects = process_only_objects();
        let mut sensor = NetworkSensor::new(None, Some(ebpf_settings(objects.path())));
        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        match result {
            Err(SensorError::Unsupported(reason)) => {
                assert!(reason.contains("net.bpf.o"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        let health = sensor.health();
        assert_eq!(health.state, SensorState::Failed);
        assert!(health
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("net.bpf.o")));
    }

    #[tokio::test]
    async fn no_ebpf_key_behaves_as_before() {
        let root = proc_fixture("");
        let mut sensor = NetworkSensor::new(Some(root.path().to_path_buf()), None);
        let caps = sensor.capabilities();
        assert!(caps.always_available && !caps.ebpf && !caps.audit_fallback);
        let (tx, _rx) = mpsc::channel(16);
        sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await
            .unwrap();
        sensor.start().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.state, SensorState::Healthy);
        assert_eq!(health.capability_flags, ["always_available"]);
        assert_eq!(health.last_error, None);
        sensor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn neither_backend_configured_is_unsupported() {
        let mut sensor = NetworkSensor::new(None, None);
        assert!(!sensor.capabilities().supported());
        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(matches!(result, Err(SensorError::Unsupported(_))));
    }

    fn net_record() -> NetEvent {
        NetEvent {
            kind: NetKind::Connect,
            pid: u32::MAX,
            uid: 0,
            ktime_ns: 100,
            comm: "curl".to_string(),
            family: AF_INET,
            lport: 50_000,
            rport: 443,
            direction: DIR_OUTBOUND,
            laddr: [0; 16],
            raddr: [0; 16],
            exe: None,
        }
    }

    /// The realtime − monotonic offset is resampled for every record, so a
    /// wall-clock step (or a resume from suspend) after the reader started
    /// moves the next event's timestamp with it (the process sensor's
    /// `on_record_resamples_the_wall_clock_offset_per_record`, for net).
    #[test]
    fn ebpf_on_record_resamples_offset() {
        let root = tempfile::tempdir().unwrap();
        let health = Mutex::new(HealthState::default());
        let (tx, mut rx) = mpsc::channel(4);
        let offset = std::cell::Cell::new(1_000i128);
        let sample = || {
            let now = offset.get();
            offset.set(now + 5_000); // the clock steps between records
            now
        };
        on_record(Ok(net_record()), &sample, root.path(), &tx, &health);
        on_record(Ok(net_record()), &sample, root.path(), &tx, &health);
        on_record(
            Err(DecodeError::ShorterThanHeader(3)),
            &sample,
            root.path(),
            &tx,
            &health,
        );
        let mut stamps = Vec::new();
        while let Ok(RawEvent::Network(raw)) = rx.try_recv() {
            assert_eq!(raw.source, RawEventSource::Ebpf);
            stamps.push(raw.timestamp_ns);
        }
        // ktime_ns 100 + offset 1_000, then + offset 6_000.
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
        on_record(Ok(net_record()), &|| 0, root.path(), &tx, &health);
        let h = lock_health(&health);
        assert_eq!(h.events_dropped_total, 1);
        assert_eq!(h.events_emitted_total, 0);
        assert_eq!(h.state, SensorState::Starting);
    }
}
