//! `DnsSensor`: the `Sensor` trait around the OS-neutral [`Engine`].
//!
//! On Linux a blocking task (never an async worker thread) owns the
//! `AF_PACKET` socket, feeds packets to the engine, ticks it on every
//! receive (≤ 500 ms apart thanks to the receive timeout) and sends events
//! with `blocking_send`. Socket errors mark the sensor `Failed` and the
//! socket is reopened with exponential backoff. Elsewhere the sensor
//! reports itself unsupported.
//!
//! Query owners come from one of two attribution backends, chosen at
//! `initialize` once the socket is open (GC 10):
//!
//! - **eBPF** (when [`EbpfSettings`] are given and `dns.bpf.o` loads): a
//!   reader thread turns every kernel UDP send to port 53 from the agent's
//!   own network namespace into a [`SendTable`] entry the engine joins with
//!   captured queries. `Healthy`, flag `ebpf_attribution`. A reader failure
//!   mid-run is a one-way latch to `/proc` attribution: `Degraded`, flag
//!   `procfs_attribution`, the reason in `last_error`, until restart.
//! - **`/proc`** (11a's `Attributor`): `Healthy` with flag
//!   `procfs_attribution` without an `ebpf` key; `Degraded` with the reason
//!   in `last_error` when eBPF was configured but cannot be used.
//!
//! The reported state is the worse of the backend's and the window's (parse
//! errors, overflow evictions and capture-socket drops in the last minute),
//! so the capture loop never hides a backend `Degraded`. Capture-socket
//! drops (`PACKET_STATISTICS`, read at most once a second and before the
//! socket is closed) are also added to `events_dropped_total`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use osiris_ebpf::{
    boot_wall_offset_ns, decode_dns, kernel_symbols_text, missing_kernel_symbols, probe,
    DecodeError, DnsSendEvent, DropCounter, EbpfSettings, LoadedObject, ReaderError, DNS_OBJECT,
    DNS_REQUIRED_KPROBES,
};
use osiris_sensor_api::{
    Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::ebpf_backend::{agent_netns_ino, send_from_event};
use crate::engine::{AttributionMode, Engine, EngineMetrics};
use crate::send_table::{lock_table, SendTable, SharedSendTable};

/// First reopen delay after a socket error.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Upper bound of the reopen delay.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long a rise in parse errors / overflow evictions keeps the sensor
/// `Degraded`.
const DEGRADED_WINDOW: Duration = Duration::from_secs(60);
/// How often the eBPF supervisor checks whether the reader thread ended.
const READER_SUPERVISE_INTERVAL: Duration = Duration::from_millis(100);

/// Capability flag: query owners come from kernel send records.
pub const FLAG_EBPF: &str = "ebpf_attribution";
/// Capability flag: query owners come from `/proc` lookups.
pub const FLAG_PROCFS: &str = "procfs_attribution";

/// Reason reported when the `AF_PACKET` socket cannot be opened.
pub fn unsupported_reason_for(errno: i32) -> String {
    // EPERM = 1, EACCES = 13 on Linux.
    match errno {
        1 | 13 => "AF_PACKET needs CAP_NET_RAW".to_string(),
        other => format!("AF_PACKET socket failed: errno {other}"),
    }
}

struct HealthState {
    /// What is reported: the worse of `backend_state` and `window_state`,
    /// or `Starting`/`Failed`/`Stopped` from the capture lifecycle.
    state: SensorState,
    /// The attribution backend's state: `Healthy`, or `Degraded` on the
    /// `/proc` fallback or after the reader latch.
    backend_state: SensorState,
    /// The parse/eviction window's latest verdict.
    window_state: SensorState,
    events_emitted_total: u64,
    events_dropped_total: u64,
    last_error: Option<String>,
    last_event_at: Option<u64>,
    capability_flags: Vec<String>,
    engine: EngineMetrics,
    /// Kernel sends from another network namespace, never inserted (GC 8).
    foreign_netns: u64,
    /// Packets the kernel dropped before the capture socket read them
    /// (`PACKET_STATISTICS` `tp_drops`, accumulated across reads and
    /// sockets). Part of `events_dropped_total`.
    capture_drops: u64,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            state: SensorState::Starting,
            backend_state: SensorState::Healthy,
            window_state: SensorState::Healthy,
            events_emitted_total: 0,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: None,
            capability_flags: vec![],
            engine: EngineMetrics::default(),
            foreign_netns: 0,
            capture_drops: 0,
        }
    }
}

fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn severity(state: SensorState) -> u8 {
    match state {
        SensorState::Failed => 2,
        SensorState::Degraded => 1,
        _ => 0,
    }
}

/// The worse of the backend's and the window's state (Failed > Degraded >
/// Healthy); on a tie, the backend's.
fn reported_state(backend: SensorState, window: SensorState) -> SensorState {
    if severity(window) > severity(backend) {
        window
    } else {
        backend
    }
}

/// Records the chosen attribution backend: its state, its flag (replacing
/// any earlier backend flag, keeping the capture flags) and, when it is a
/// fallback, the reason.
fn set_backend(
    health: &Mutex<HealthState>,
    state: SensorState,
    flag: &str,
    reason: Option<String>,
) {
    let mut h = lock_health(health);
    h.backend_state = state;
    h.capability_flags
        .retain(|f| f != FLAG_EBPF && f != FLAG_PROCFS);
    h.capability_flags.push(flag.to_string());
    if reason.is_some() {
        h.last_error = reason;
    }
}

/// Adds packets the capture socket's kernel queue dropped to the running
/// total, saturating. The kernel resets its counter on every read, so each
/// read's value is added once.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn add_capture_drops(health: &Mutex<HealthState>, drops: u64) {
    let mut h = lock_health(health);
    h.capture_drops = h.capture_drops.saturating_add(drops);
}

/// How often the capture loop reads the socket's drop counter.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CAPTURE_STATS_INTERVAL: Duration = Duration::from_secs(1);

/// Rate limit for reading the capture socket's statistics.
#[derive(Debug, Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct StatsPoll {
    last: Option<Instant>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl StatsPoll {
    /// True (and the read is recorded) when the last read is at least
    /// [`CAPTURE_STATS_INTERVAL`] old.
    fn due(&mut self, now: Instant) -> bool {
        let due = self
            .last
            .is_none_or(|t| now.saturating_duration_since(t) >= CAPTURE_STATS_INTERVAL);
        if due {
            self.last = Some(now);
        }
        due
    }
}

/// Sends `events` in order. On the first failed send, that event and every
/// one after it are counted as dropped and no further send is tried.
/// Returns false on a failure.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn send_all<E>(
    events: Vec<E>,
    health: &Mutex<HealthState>,
    mut send: impl FnMut(E) -> bool,
) -> bool {
    let total = events.len();
    for (i, event) in events.into_iter().enumerate() {
        if !send(event) {
            let lost = (total - i) as u64;
            let mut h = lock_health(health);
            h.events_dropped_total = h.events_dropped_total.saturating_add(lost);
            return false;
        }
    }
    true
}

/// Tracks whether parse errors, overflow evictions or capture drops rose
/// recently.
#[derive(Debug, Default)]
struct DegradeWindow {
    last_bad_total: u64,
    last_bad_at: Option<Instant>,
}

impl DegradeWindow {
    fn observe(&mut self, m: &EngineMetrics, capture_drops: u64, now: Instant) -> SensorState {
        let bad = m
            .parse_errors
            .saturating_add(m.tracker.overflow_evictions)
            .saturating_add(capture_drops);
        if bad > self.last_bad_total {
            self.last_bad_total = bad;
            self.last_bad_at = Some(now);
        }
        match self.last_bad_at {
            Some(at) if now.duration_since(at) < DEGRADED_WINDOW => SensorState::Degraded,
            _ => SensorState::Healthy,
        }
    }
}

/// Capture-loop step: switch the engine to `/proc` the first time the
/// supervisor's latch is seen (GC 10/12).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn apply_latch(engine: &mut Engine, latch: &AtomicBool, latched: &mut bool) {
    if !*latched && latch.load(Ordering::Acquire) {
        engine.latch_procfs();
        *latched = true;
    }
}

/// Capture-loop step: publish the engine counters and the reported state,
/// never overwriting a backend `Degraded` (GC 10). Capture drops count in
/// the window like parse errors.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn publish_engine(
    health: &Mutex<HealthState>,
    metrics: EngineMetrics,
    window: &mut DegradeWindow,
    now: Instant,
) {
    let mut h = lock_health(health);
    let window_state = window.observe(&metrics, h.capture_drops, now);
    h.engine = metrics;
    h.window_state = window_state;
    h.state = reported_state(h.backend_state, window_state);
}

/// Waits for the reader thread to end. A failure (error or panic) is the
/// one-way latch: the flag the capture thread polls is set, and health
/// moves to `Degraded` + `procfs_attribution` with the reason. A clean exit
/// (cancellation) changes nothing.
async fn supervise_reader(
    reader: std::thread::JoinHandle<Result<(), ReaderError>>,
    health: Arc<Mutex<HealthState>>,
    latch: Arc<AtomicBool>,
) {
    while !reader.is_finished() {
        tokio::time::sleep(READER_SUPERVISE_INTERVAL).await;
    }
    let reason = match reader.join() {
        Ok(Ok(())) => return,
        Ok(Err(e)) => format!("eBPF reader failed: {e}; attributing via /proc"),
        Err(_) => "eBPF ring-buffer reader thread panicked; attributing via /proc".to_string(),
    };
    tracing::warn!(sensor = "dns", reason = %reason, "DNS kernel attribution latched to /proc");
    latch.store(true, Ordering::Release);
    set_backend(&health, SensorState::Degraded, FLAG_PROCFS, Some(reason));
    let mut h = lock_health(&health);
    if h.state == SensorState::Healthy {
        h.state = SensorState::Degraded;
    }
}

/// Reader-thread callback: a send from the agent's network namespace
/// becomes a [`SendTable`] entry; others are counted as `foreign_netns`
/// (GC 8), and a record that does not decode is counted as dropped. The
/// exe is resolved before the table lock is taken (no I/O under a lock).
fn on_record(
    record: Result<DnsSendEvent, DecodeError>,
    agent_netns: u32,
    boot_wall_offset_ns: &dyn Fn() -> i128,
    proc_root: &Path,
    table: &SharedSendTable,
    health: &Mutex<HealthState>,
) {
    let event = match record {
        Ok(e) => e,
        Err(_) => {
            lock_health(health).events_dropped_total += 1;
            return;
        }
    };
    if event.netns_ino != agent_netns {
        lock_health(health).foreign_netns += 1;
        return;
    }
    let send = send_from_event(&event, boot_wall_offset_ns(), proc_root);
    lock_table(table).insert(send);
}

/// The dns object is x86_64-only (GC 5).
fn arch_problem() -> Option<String> {
    cfg!(not(target_arch = "x86_64")).then(|| "dns eBPF object is x86_64-only".to_string())
}

/// What is wrong with the BPF object path, truthfully: absent, present but
/// not a regular file, or not even stat-able. `None` when it is a regular
/// file. (Same rule as the other eBPF sensors'.)
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

/// Collect every reason the dns program cannot be used (object, eBPF
/// probe, architecture, required kprobe symbols, the agent's netns), then
/// load it. `Ok` carries the program and the agent's netns inode.
fn load_ebpf(settings: &EbpfSettings) -> Result<(LoadedObject, u32), String> {
    let mut reasons = vec![];
    let object = settings.object_dir.join(DNS_OBJECT.object_file);
    reasons.extend(object_problem(&object));
    reasons.extend(probe().reasons);
    reasons.extend(arch_problem());
    if let Some(symbols) = kernel_symbols_text() {
        for name in missing_kernel_symbols(&symbols, DNS_REQUIRED_KPROBES) {
            reasons.push(format!("required kernel symbol missing: {name}"));
        }
    }
    let netns = agent_netns_ino();
    if netns.is_none() {
        reasons.push("cannot read the agent's network namespace".to_string());
    }
    let netns = match netns {
        Some(ino) if reasons.is_empty() => ino,
        _ => return Err(format!("eBPF unavailable: {}", reasons.join("; "))),
    };
    let prog = LoadedObject::load(&settings.object_dir, &DNS_OBJECT, settings.self_tgid)
        .map_err(|e| format!("eBPF unavailable: {e}"))?;
    Ok((prog, netns))
}

/// Kernel-attribution counters next to the engine's (see
/// [`DnsSensor::engine_metrics`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsAttributionMetrics {
    /// Kernel sends from another network namespace, never inserted.
    pub foreign_netns: u64,
    /// Send-table entries evicted by the per-key or global bound.
    pub send_table_evictions: u64,
    /// Packets without a kernel receive timestamp.
    pub timestamp_fallbacks: u64,
}

/// Passive DNS sensor over `AF_PACKET` (Linux only).
pub struct DnsSensor {
    proc_root: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    interface: Option<String>,
    ebpf: Option<EbpfSettings>,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    supervisor_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
    /// BPF-side ring-buffer reservation failures, added to
    /// `events_dropped_total` (eBPF only).
    drop_counter: Option<DropCounter>,
    send_table: Option<SharedSendTable>,
    /// Set by the reader supervisor on a reader failure; polled by the
    /// capture thread.
    latch: Arc<AtomicBool>,
}

impl DnsSensor {
    /// `interface` `None` captures on all interfaces; `ebpf` `None` keeps
    /// 11a's `/proc` attribution.
    pub fn new(proc_root: PathBuf, interface: Option<String>, ebpf: Option<EbpfSettings>) -> Self {
        Self {
            proc_root,
            interface,
            ebpf,
            cancellation: None,
            task_handle: None,
            supervisor_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
            drop_counter: None,
            send_table: None,
            latch: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The eBPF settings this sensor was built with; `None` means `/proc`
    /// attribution only.
    pub fn ebpf_settings(&self) -> Option<&EbpfSettings> {
        self.ebpf.as_ref()
    }

    /// Latest snapshot of the engine counters (packets, parse errors,
    /// timeouts, unmatched responses, overflow evictions, attribution).
    pub fn engine_metrics(&self) -> EngineMetrics {
        lock_health(&self.health).engine
    }

    /// Kernel-attribution counters: foreign-netns sends, send-table
    /// evictions and receive-timestamp fallbacks.
    pub fn attribution_metrics(&self) -> DnsAttributionMetrics {
        let (foreign_netns, timestamp_fallbacks) = {
            let h = lock_health(&self.health);
            (h.foreign_netns, h.engine.timestamp_fallbacks)
        };
        let send_table_evictions = self
            .send_table
            .as_ref()
            .map_or(0, |t| lock_table(t).counters().evicted);
        DnsAttributionMetrics {
            foreign_netns,
            send_table_evictions,
            timestamp_fallbacks,
        }
    }

    /// Everything lost, in mixed units: sensor-side drops (undecodable
    /// ring-buffer records and events whose channel send failed), packets
    /// the capture socket dropped, and the BPF program's ring-buffer drops.
    fn dropped_total(&self, h: &HealthState) -> u64 {
        let bpf = self.drop_counter.as_ref().map_or(0, DropCounter::get);
        h.events_dropped_total
            .saturating_add(h.capture_drops)
            .saturating_add(bpf)
    }

    /// Choose and start the attribution backend (GC 10), recording it in
    /// health. Called by `initialize` once the capture socket is open.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn start_attribution(&mut self, cancellation: &CancellationToken) -> AttributionMode {
        self.drop_counter = None;
        self.send_table = None;
        self.latch = Arc::new(AtomicBool::new(false));
        let Some(settings) = self.ebpf.clone() else {
            set_backend(&self.health, SensorState::Healthy, FLAG_PROCFS, None);
            return AttributionMode::Procfs;
        };
        let started = load_ebpf(&settings)
            .and_then(|(prog, netns)| self.start_ebpf(prog, netns, cancellation.clone()));
        match started {
            Ok(table) => {
                tracing::info!(
                    sensor = "dns",
                    object_dir = %settings.object_dir.display(),
                    "eBPF DNS attribution active"
                );
                AttributionMode::Kernel(table)
            }
            Err(reason) => {
                tracing::warn!(
                    sensor = "dns",
                    reason = %reason,
                    "eBPF DNS attribution unavailable; attributing via /proc"
                );
                set_backend(
                    &self.health,
                    SensorState::Degraded,
                    FLAG_PROCFS,
                    Some(reason),
                );
                AttributionMode::Procfs
            }
        }
    }

    /// Start the reader thread and its supervisor. Health is set to the
    /// eBPF backend before the supervisor exists, so a latch is never
    /// overwritten. `Err` (the thread could not be started; the program is
    /// dropped and detached) means fall back.
    fn start_ebpf(
        &mut self,
        prog: LoadedObject,
        agent_netns: u32,
        cancellation: CancellationToken,
    ) -> Result<SharedSendTable, String> {
        let drop_counter = prog.drop_counter();
        let table: SharedSendTable = Arc::new(Mutex::new(SendTable::new()));
        let health = self.health.clone();
        let proc_root = self.proc_root.clone();
        let reader_table = table.clone();
        let reader = osiris_ebpf::spawn_reader(prog, decode_dns, cancellation, move |record| {
            on_record(
                record,
                agent_netns,
                &boot_wall_offset_ns,
                &proc_root,
                &reader_table,
                &health,
            )
        })
        .map_err(|e| format!("eBPF unavailable: {e}"))?;
        set_backend(&self.health, SensorState::Healthy, FLAG_EBPF, None);
        self.drop_counter = Some(drop_counter);
        self.send_table = Some(table.clone());
        self.supervisor_handle = Some(tokio::spawn(supervise_reader(
            reader,
            self.health.clone(),
            self.latch.clone(),
        )));
        Ok(table)
    }
}

#[async_trait]
impl Sensor for DnsSensor {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn capabilities(&self) -> SensorCapabilities {
        #[cfg(target_os = "linux")]
        let probe = crate::capture::probe().map_err(unsupported_reason_for);
        #[cfg(not(target_os = "linux"))]
        let probe: Result<(), String> =
            Err("DNS capture needs AF_PACKET, available on Linux only".to_string());
        match probe {
            Ok(()) => SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: true,
                unsupported_reason: None,
            },
            Err(reason) => SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: false,
                unsupported_reason: Some(reason),
            },
        }
    }

    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError> {
        self.cancellation = Some(ctx.cancellation.clone());
        {
            // A re-initialize starts from a clean backend selection.
            let mut h = lock_health(&self.health);
            h.state = SensorState::Starting;
            h.backend_state = SensorState::Healthy;
            h.window_state = SensorState::Healthy;
            h.last_error = None;
            h.capability_flags = vec![];
        }

        let caps = self.capabilities();
        if !caps.supported() {
            let reason = caps.unsupported_reason.clone().unwrap_or_default();
            lock_health(&self.health).last_error = Some(reason.clone());
            return Err(SensorError::Unsupported(reason));
        }

        #[cfg(target_os = "linux")]
        {
            use crate::attribution::Attributor;
            use crate::capture::Capture;
            use crate::engine::{MAX_PENDING, TX_TIMEOUT};

            let capture = Capture::open(self.interface.as_deref()).map_err(|e| {
                let mut h = lock_health(&self.health);
                h.state = SensorState::Failed;
                h.last_error = Some(e.to_string());
                SensorError::InitFailed(e.to_string())
            })?;
            lock_health(&self.health).capability_flags = vec!["af_packet".to_string()];

            let mode = self.start_attribution(&ctx.cancellation);
            let engine = Engine::new(
                Attributor::new(self.proc_root.clone()),
                mode,
                TX_TIMEOUT,
                MAX_PENDING,
            );
            let worker = linux::Worker {
                interface: self.interface.clone(),
                engine,
                latch: self.latch.clone(),
                output: ctx.output,
                cancellation: ctx.cancellation,
                health: self.health.clone(),
            };
            self.task_handle = Some(tokio::task::spawn_blocking(move || worker.run(capture)));
        }
        #[cfg(not(target_os = "linux"))]
        drop(ctx);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
        // The capture thread or the reader supervisor may already have
        // reported `Failed` or `Degraded`; only the initial `Starting`
        // state is promoted here, to the backend's state.
        let mut h = lock_health(&self.health);
        if h.state == SensorState::Starting {
            h.state = reported_state(h.backend_state, h.window_state);
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
        if let Some(handle) = self.supervisor_handle.take() {
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

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::capture::{Capture, Recv, RECV_BUF};
    use crate::engine::wall_ns;
    use osiris_sensor_api::RawEvent;
    use tokio::sync::mpsc::Sender;

    pub(super) struct Worker {
        pub(super) interface: Option<String>,
        pub(super) engine: Engine,
        pub(super) latch: Arc<AtomicBool>,
        pub(super) output: Sender<RawEvent>,
        pub(super) cancellation: CancellationToken,
        pub(super) health: Arc<Mutex<HealthState>>,
    }

    enum Exit {
        Cancelled,
        ChannelClosed,
        SocketError(i32),
    }

    impl Worker {
        /// Blocking capture loop with reopen-on-error; returns on
        /// cancellation or when the event receiver is gone.
        pub(super) fn run(mut self, first: Capture) {
            let mut next = Some(first);
            let mut backoff = BACKOFF_INITIAL;
            let mut buf = vec![0u8; RECV_BUF];
            let mut window = DegradeWindow::default();
            let mut latched = false;
            let mut channel_closed = false;
            while !self.cancellation.is_cancelled() {
                let capture = match next.take() {
                    Some(c) => Ok(c),
                    None => Capture::open(self.interface.as_deref()),
                };
                let error = match capture {
                    Ok(cap) => {
                        match self.capture(&cap, &mut buf, &mut window, &mut latched, &mut backoff)
                        {
                            Exit::Cancelled => break,
                            Exit::ChannelClosed => {
                                channel_closed = true;
                                break;
                            }
                            Exit::SocketError(errno) => {
                                format!("AF_PACKET recv failed: errno {errno}")
                            }
                        }
                    }
                    Err(e) => e.to_string(),
                };
                {
                    let mut h = lock_health(&self.health);
                    h.state = SensorState::Failed;
                    h.last_error = Some(error);
                }
                if self.sleep_or_cancel(backoff) {
                    break;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
            if !channel_closed {
                // Cancelled: flush held and pending transactions once.
                // Best effort: after the first failed send, every
                // remaining event is counted as dropped.
                apply_latch(&mut self.engine, &self.latch, &mut latched);
                let events = self.engine.drain(Instant::now());
                send_all(events, &self.health, |e| self.send(e));
            }
            lock_health(&self.health).state = SensorState::Stopped;
        }

        /// Adds the socket's kernel-side drops since the last read.
        fn read_capture_drops(&self, cap: &Capture) {
            if let Some(drops) = cap.take_drops() {
                add_capture_drops(&self.health, drops);
            }
        }

        fn capture(
            &mut self,
            cap: &Capture,
            buf: &mut [u8],
            window: &mut DegradeWindow,
            latched: &mut bool,
            backoff: &mut Duration,
        ) -> Exit {
            let exit = self.capture_until_exit(cap, buf, window, latched, backoff);
            // The socket is dropped after this: read its last drops.
            self.read_capture_drops(cap);
            exit
        }

        fn capture_until_exit(
            &mut self,
            cap: &Capture,
            buf: &mut [u8],
            window: &mut DegradeWindow,
            latched: &mut bool,
            backoff: &mut Duration,
        ) -> Exit {
            let mut stats = StatsPoll::default();
            loop {
                if self.cancellation.is_cancelled() {
                    return Exit::Cancelled;
                }
                let recv = cap.recv(buf);
                let now = Instant::now();
                if stats.due(now) {
                    self.read_capture_drops(cap);
                }
                apply_latch(&mut self.engine, &self.latch, latched);
                let mut events = match recv {
                    Recv::Packet {
                        len,
                        local_origin,
                        ts_wall_ns,
                    } => {
                        let timestamp_ns = ts_wall_ns.unwrap_or_else(|| {
                            self.engine.record_timestamp_fallback();
                            wall_ns()
                        });
                        let l3 = buf.get(..len).unwrap_or_default();
                        self.engine.on_packet(l3, local_origin, timestamp_ns, now)
                    }
                    Recv::Skip | Recv::Timeout => Vec::new(),
                    Recv::Error(errno) => return Exit::SocketError(errno),
                };
                *backoff = BACKOFF_INITIAL;
                events.extend(self.engine.tick(now));
                publish_engine(&self.health, self.engine.metrics(), window, now);
                if !send_all(events, &self.health, |e| self.send(e)) {
                    return Exit::ChannelClosed;
                }
            }
        }

        /// One `blocking_send`; a failure is counted by [`send_all`].
        fn send(&self, event: RawEvent) -> bool {
            let timestamp = match &event {
                RawEvent::Dns(d) => Some(d.timestamp_ns),
                _ => None,
            };
            if self.output.blocking_send(event).is_ok() {
                let mut h = lock_health(&self.health);
                h.events_emitted_total += 1;
                h.last_event_at = timestamp.or(h.last_event_at);
                true
            } else {
                false
            }
        }

        /// Sleep `d` in short steps; true if cancelled meanwhile.
        fn sleep_or_cancel(&self, d: Duration) -> bool {
            let deadline = Instant::now() + d;
            loop {
                if self.cancellation.is_cancelled() {
                    return true;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return false;
                }
                std::thread::sleep(left.min(Duration::from_millis(100)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::Sensor;

    #[test]
    fn eperm_maps_to_cap_net_raw_reason() {
        assert_eq!(unsupported_reason_for(1), "AF_PACKET needs CAP_NET_RAW");
        assert_eq!(unsupported_reason_for(13), "AF_PACKET needs CAP_NET_RAW");
    }

    #[test]
    fn other_errno_reason() {
        assert_eq!(
            unsupported_reason_for(97),
            "AF_PACKET socket failed: errno 97"
        );
    }

    #[test]
    fn name_is_dns() {
        let s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        assert_eq!(s.name(), "dns");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn capabilities_unsupported_off_linux() {
        let s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        let caps = s.capabilities();
        assert!(!caps.supported());
        assert!(caps
            .unsupported_reason
            .unwrap_or_default()
            .contains("Linux"));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn initialize_unsupported_off_linux() {
        let mut s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let r = s
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(matches!(r, Err(SensorError::Unsupported(_))));
        assert!(s.health().last_error.unwrap_or_default().contains("Linux"));
    }

    #[tokio::test]
    async fn start_does_not_mask_a_capture_failure() {
        let mut s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        lock_health(&s.health).state = SensorState::Failed;
        s.start().await.unwrap();
        assert_eq!(s.health().state, SensorState::Failed);

        let mut s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        s.start().await.unwrap();
        assert_eq!(s.health().state, SensorState::Healthy);
    }

    #[test]
    fn degraded_for_a_minute_after_parse_errors_rise() {
        let mut w = DegradeWindow::default();
        let t0 = Instant::now();
        let mut m = EngineMetrics::default();
        assert_eq!(w.observe(&m, 0, t0), SensorState::Healthy);
        m.parse_errors = 1;
        assert_eq!(w.observe(&m, 0, t0), SensorState::Degraded);
        assert_eq!(
            w.observe(&m, 0, t0 + Duration::from_secs(59)),
            SensorState::Degraded
        );
        assert_eq!(
            w.observe(&m, 0, t0 + Duration::from_secs(61)),
            SensorState::Healthy
        );
        m.tracker.overflow_evictions = 1;
        assert_eq!(
            w.observe(&m, 0, t0 + Duration::from_secs(62)),
            SensorState::Degraded
        );
    }

    #[test]
    fn capture_drops_degrade_for_a_minute() {
        let mut w = DegradeWindow::default();
        let t0 = Instant::now();
        let m = EngineMetrics::default();
        assert_eq!(w.observe(&m, 0, t0), SensorState::Healthy);
        assert_eq!(w.observe(&m, 3, t0), SensorState::Degraded);
        assert_eq!(
            w.observe(&m, 3, t0 + Duration::from_secs(61)),
            SensorState::Healthy
        );
        assert_eq!(
            w.observe(&m, 4, t0 + Duration::from_secs(62)),
            SensorState::Degraded
        );
        // Every term saturates instead of overflowing.
        let big = EngineMetrics {
            parse_errors: u64::MAX,
            ..EngineMetrics::default()
        };
        assert_eq!(w.observe(&big, u64::MAX, t0), SensorState::Degraded);
    }

    #[test]
    fn capture_drops_accumulate_and_saturate() {
        let s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        add_capture_drops(&s.health, 5);
        add_capture_drops(&s.health, 7);
        assert_eq!(lock_health(&s.health).capture_drops, 12);
        lock_health(&s.health).events_dropped_total = 3;
        assert_eq!(s.health().events_dropped_total, 15);
        assert_eq!(s.metrics().events_dropped_total, 15);
        add_capture_drops(&s.health, u64::MAX);
        assert_eq!(lock_health(&s.health).capture_drops, u64::MAX);
        assert_eq!(s.health().events_dropped_total, u64::MAX);
    }

    #[test]
    fn capture_drops_are_published_into_the_window() {
        let health = Mutex::new(HealthState::default());
        let mut window = DegradeWindow::default();
        let now = Instant::now();
        publish_engine(&health, EngineMetrics::default(), &mut window, now);
        assert_eq!(lock_health(&health).state, SensorState::Healthy);
        add_capture_drops(&health, 1);
        publish_engine(&health, EngineMetrics::default(), &mut window, now);
        assert_eq!(lock_health(&health).state, SensorState::Degraded);
    }

    #[test]
    fn capture_stats_are_read_at_most_once_a_second() {
        let mut poll = StatsPoll::default();
        let t0 = Instant::now();
        assert!(poll.due(t0));
        assert!(!poll.due(t0 + Duration::from_millis(999)));
        assert!(poll.due(t0 + Duration::from_secs(1)));
        assert!(!poll.due(t0 + Duration::from_millis(1500)));
    }

    #[test]
    fn a_failed_send_counts_every_remaining_event() {
        use osiris_sensor_api::RawEvent;
        let health = Mutex::new(HealthState::default());
        let events: Vec<RawEvent> = (0..5).map(|_| RawEvent::Dns(sample_event())).collect();
        let mut sent = 0;
        let ok = send_all(events, &health, |_| {
            sent += 1;
            sent <= 2
        });
        assert!(!ok);
        assert_eq!(sent, 3, "no send is attempted after the first failure");
        assert_eq!(lock_health(&health).events_dropped_total, 3);

        let ok = send_all(vec![RawEvent::Dns(sample_event())], &health, |_| true);
        assert!(ok);
        assert_eq!(lock_health(&health).events_dropped_total, 3);
    }

    fn sample_event() -> osiris_sensor_api::DnsEventRaw {
        osiris_sensor_api::DnsEventRaw {
            query: "example.com".into(),
            qtype: "A".into(),
            response_ips: vec![],
            ttl: None,
            pid: None,
            uid: 0,
            exe_path: String::new(),
            comm: String::new(),
            timestamp_ns: 1,
            source: osiris_sensor_api::RawEventSource::Packet,
        }
    }

    fn ebpf_settings(dir: &std::path::Path) -> EbpfSettings {
        EbpfSettings {
            object_dir: dir.to_path_buf(),
            self_tgid: std::process::id(),
        }
    }

    fn flags(s: &DnsSensor) -> Vec<String> {
        s.health().capability_flags
    }

    #[test]
    fn reported_state_is_worse_of_two() {
        use SensorState::{Degraded, Failed, Healthy};
        let cases = [
            (Healthy, Healthy, Healthy),
            (Healthy, Degraded, Degraded),
            (Healthy, Failed, Failed),
            (Degraded, Healthy, Degraded),
            (Degraded, Degraded, Degraded),
            (Degraded, Failed, Failed),
            (Failed, Healthy, Failed),
            (Failed, Degraded, Failed),
            (Failed, Failed, Failed),
        ];
        for (backend, window, want) in cases {
            assert_eq!(
                reported_state(backend, window),
                want,
                "{backend:?}/{window:?}"
            );
        }
    }

    /// `ebpf` configured, but the object directory holds no `dns.bpf.o`:
    /// `/proc` attribution, `Degraded`, the reason names the object. The
    /// backend is chosen by the same call `initialize` makes once the
    /// `AF_PACKET` socket is open (which needs CAP_NET_RAW), so this runs
    /// on every OS; off Linux `initialize` itself stays unsupported
    /// (`initialize_unsupported_off_linux`).
    #[tokio::test]
    async fn falls_back_to_procfs_when_dns_object_missing() {
        let objects = tempfile::tempdir().unwrap();
        let mut s = DnsSensor::new(
            PathBuf::from("/proc"),
            None,
            Some(ebpf_settings(objects.path())),
        );
        let mode = s.start_attribution(&CancellationToken::new());
        assert!(matches!(mode, AttributionMode::Procfs));
        s.start().await.unwrap();
        let h = s.health();
        assert_eq!(h.state, SensorState::Degraded);
        assert!(h.capability_flags.iter().any(|f| f == FLAG_PROCFS));
        assert!(!h.capability_flags.iter().any(|f| f == FLAG_EBPF));
        assert!(
            h.last_error
                .as_deref()
                .is_some_and(|e| e.contains("dns.bpf.o")),
            "reason must name the missing object: {:?}",
            h.last_error
        );
        #[cfg(not(target_arch = "x86_64"))]
        assert!(h
            .last_error
            .unwrap_or_default()
            .contains("dns eBPF object is x86_64-only"));
    }

    #[tokio::test]
    async fn no_ebpf_key_is_procfs_healthy() {
        let mut s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        let mode = s.start_attribution(&CancellationToken::new());
        assert!(matches!(mode, AttributionMode::Procfs));
        s.start().await.unwrap();
        assert_eq!(s.health().state, SensorState::Healthy);
        assert!(flags(&s).iter().any(|f| f == FLAG_PROCFS));
        assert!(!flags(&s).iter().any(|f| f == FLAG_EBPF));
        assert_eq!(s.health().last_error, None);
    }

    #[test]
    fn unusable_netns_is_a_reason() {
        let objects = tempfile::tempdir().unwrap();
        let reason = match load_ebpf(&ebpf_settings(objects.path())) {
            Ok(_) => panic!("an empty object dir must not load"),
            Err(e) => e,
        };
        if crate::ebpf_backend::agent_netns_ino().is_none() {
            assert!(reason.contains("cannot read the agent's network namespace"));
        }
    }

    /// Review Focus #4: the reader dies while a transaction is pending.
    /// The supervisor latches (`Degraded`, `procfs_attribution`, reason in
    /// `last_error`); the capture side switches the engine, so the pending
    /// transaction gets a `/proc` lookup when it closes; and a clean parse
    /// window never brings `Healthy` back.
    #[tokio::test]
    async fn reader_failure_latches_procfs() {
        use crate::engine::tests::{kernel_engine, kq, kr, only_dns};
        use crate::engine::wall_ns;

        let health = Arc::new(Mutex::new(HealthState::default()));
        lock_health(&health).capability_flags = vec!["af_packet".to_string()];
        set_backend(&health, SensorState::Healthy, FLAG_EBPF, None);
        lock_health(&health).state = SensorState::Healthy;
        let latch = Arc::new(AtomicBool::new(false));

        let (mut engine, _table, _proc) = kernel_engine(true);
        let now = Instant::now();
        let base = wall_ns();
        assert!(engine.on_packet(&kq(1), true, base, now).is_empty());

        let reader = std::thread::spawn(|| -> Result<(), ReaderError> {
            Err(ReaderError::Poll(std::io::Error::other("ring buffer gone")))
        });
        supervise_reader(reader, health.clone(), latch.clone()).await;

        assert!(latch.load(Ordering::Acquire));
        {
            let h = lock_health(&health);
            assert_eq!(h.state, SensorState::Degraded);
            assert_eq!(h.capability_flags, ["af_packet", FLAG_PROCFS]);
            assert!(
                h.last_error
                    .as_deref()
                    .is_some_and(|e| e.contains("ring buffer gone")),
                "{:?}",
                h.last_error
            );
        }

        let mut latched = false;
        apply_latch(&mut engine, &latch, &mut latched);
        assert!(latched);
        let ev = only_dns(engine.on_packet(&kr(1), true, base + 1_000_000, now));
        // uid 1000 comes from the fixture's /proc/net/udp row.
        assert_eq!(ev.uid, 1000);
        assert_eq!(engine.metrics().held, 0);

        let mut window = DegradeWindow::default();
        publish_engine(&health, engine.metrics(), &mut window, now);
        assert_eq!(lock_health(&health).state, SensorState::Degraded);
        publish_engine(
            &health,
            engine.metrics(),
            &mut window,
            now + Duration::from_secs(120),
        );
        assert_eq!(lock_health(&health).state, SensorState::Degraded);
    }

    #[test]
    fn a_clean_reader_exit_does_not_latch() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let health = Arc::new(Mutex::new(HealthState::default()));
        set_backend(&health, SensorState::Healthy, FLAG_EBPF, None);
        let latch = Arc::new(AtomicBool::new(false));
        let reader = std::thread::spawn(|| -> Result<(), ReaderError> { Ok(()) });
        rt.block_on(supervise_reader(reader, health.clone(), latch.clone()));
        assert!(!latch.load(Ordering::Acquire));
        assert_eq!(lock_health(&health).backend_state, SensorState::Healthy);
    }

    #[test]
    fn capture_loop_never_overwrites_a_backend_degraded() {
        let health = Arc::new(Mutex::new(HealthState::default()));
        set_backend(
            &health,
            SensorState::Degraded,
            FLAG_PROCFS,
            Some("x".into()),
        );
        let mut window = DegradeWindow::default();
        let m = EngineMetrics::default();
        publish_engine(&health, m, &mut window, Instant::now());
        assert_eq!(lock_health(&health).state, SensorState::Degraded);
    }

    fn dns_event(netns_ino: u32) -> DnsSendEvent {
        DnsSendEvent {
            pid: 10,
            tid: 10,
            uid: 0,
            ktime_ns: 1,
            comm: "dig".into(),
            exe: None,
            netns_ino,
            local: "10.0.0.2:41000".parse().unwrap(),
            remote: "10.0.0.1:53".parse().unwrap(),
        }
    }

    #[test]
    fn on_record_inserts_own_netns_and_counts_the_rest() {
        let proc_root = tempfile::tempdir().unwrap();
        let table: SharedSendTable = Arc::new(Mutex::new(SendTable::new()));
        let health = Mutex::new(HealthState::default());
        let offset = || 0i128;
        on_record(
            Ok(dns_event(7)),
            7,
            &offset,
            proc_root.path(),
            &table,
            &health,
        );
        on_record(
            Ok(dns_event(8)),
            7,
            &offset,
            proc_root.path(),
            &table,
            &health,
        );
        on_record(
            Err(DecodeError::UnknownKind(99)),
            7,
            &offset,
            proc_root.path(),
            &table,
            &health,
        );
        assert_eq!(lock_table(&table).len(), 1);
        let h = lock_health(&health);
        assert_eq!(h.foreign_netns, 1);
        assert_eq!(h.events_dropped_total, 1);
    }

    #[test]
    fn attribution_metrics_surface_counters() {
        let s = DnsSensor::new(PathBuf::from("/proc"), None, None);
        {
            let mut h = lock_health(&s.health);
            h.foreign_netns = 3;
            h.engine.timestamp_fallbacks = 2;
        }
        let m = s.attribution_metrics();
        assert_eq!(m.foreign_netns, 3);
        assert_eq!(m.timestamp_fallbacks, 2);
        assert_eq!(m.send_table_evictions, 0);
    }
}
