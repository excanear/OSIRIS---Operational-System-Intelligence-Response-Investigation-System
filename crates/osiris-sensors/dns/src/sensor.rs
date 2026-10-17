//! `DnsSensor`: the `Sensor` trait around the OS-neutral [`Engine`].
//!
//! On Linux a blocking task (never an async worker thread) owns the
//! `AF_PACKET` socket, feeds packets to the engine, ticks it on every
//! receive (≤ 500 ms apart thanks to the receive timeout) and sends events
//! with `blocking_send`. Socket errors mark the sensor `Failed` and the
//! socket is reopened with exponential backoff. Elsewhere the sensor
//! reports itself unsupported.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use osiris_sensor_api::{
    Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::engine::EngineMetrics;

/// First reopen delay after a socket error.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Upper bound of the reopen delay.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long a rise in parse errors / overflow evictions keeps the sensor
/// `Degraded`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DEGRADED_WINDOW: Duration = Duration::from_secs(60);

/// Reason reported when the `AF_PACKET` socket cannot be opened.
pub fn unsupported_reason_for(errno: i32) -> String {
    // EPERM = 1, EACCES = 13 on Linux.
    match errno {
        1 | 13 => "AF_PACKET needs CAP_NET_RAW".to_string(),
        other => format!("AF_PACKET socket failed: errno {other}"),
    }
}

struct HealthState {
    state: SensorState,
    events_emitted_total: u64,
    events_dropped_total: u64,
    last_error: Option<String>,
    last_event_at: Option<u64>,
    capability_flags: Vec<String>,
    engine: EngineMetrics,
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
            engine: EngineMetrics::default(),
        }
    }
}

fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Tracks whether parse errors or overflow evictions rose recently.
#[derive(Debug, Default)]
struct DegradeWindow {
    last_bad_total: u64,
    last_bad_at: Option<Instant>,
}

impl DegradeWindow {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn observe(&mut self, m: &EngineMetrics, now: Instant) -> SensorState {
        let bad = m.parse_errors + m.tracker.overflow_evictions;
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

/// Passive DNS sensor over `AF_PACKET` (Linux only).
pub struct DnsSensor {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    proc_root: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    interface: Option<String>,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl DnsSensor {
    /// `interface` `None` captures on all interfaces.
    pub fn new(proc_root: PathBuf, interface: Option<String>) -> Self {
        Self {
            proc_root,
            interface,
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    /// Latest snapshot of the engine counters (packets, parse errors,
    /// timeouts, unmatched responses, overflow evictions, attribution).
    pub fn engine_metrics(&self) -> EngineMetrics {
        lock_health(&self.health).engine
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
        lock_health(&self.health).state = SensorState::Starting;

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
            use crate::engine::{Engine, MAX_PENDING, TX_TIMEOUT};

            let capture = Capture::open(self.interface.as_deref()).map_err(|e| {
                let mut h = lock_health(&self.health);
                h.state = SensorState::Failed;
                h.last_error = Some(e.to_string());
                SensorError::InitFailed(e.to_string())
            })?;
            lock_health(&self.health).capability_flags = vec!["af_packet".to_string()];

            let engine = Engine::new(
                Attributor::new(self.proc_root.clone()),
                TX_TIMEOUT,
                MAX_PENDING,
            );
            let worker = linux::Worker {
                interface: self.interface.clone(),
                engine,
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
        // The capture thread may already have reported `Failed` or
        // `Degraded`; only the initial `Starting` state is promoted here.
        let mut h = lock_health(&self.health);
        if h.state == SensorState::Starting {
            h.state = SensorState::Healthy;
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

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::capture::{Capture, Recv, RECV_BUF};
    use crate::engine::Engine;
    use osiris_sensor_api::RawEvent;
    use tokio::sync::mpsc::Sender;

    pub(super) struct Worker {
        pub(super) interface: Option<String>,
        pub(super) engine: Engine,
        pub(super) output: Sender<RawEvent>,
        pub(super) cancellation: CancellationToken,
        pub(super) health: Arc<Mutex<HealthState>>,
    }

    enum Exit {
        Cancelled,
        ChannelClosed,
        SocketError(i32),
    }

    fn wall_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    impl Worker {
        /// Blocking capture loop with reopen-on-error; returns on
        /// cancellation or when the event receiver is gone.
        pub(super) fn run(mut self, first: Capture) {
            let mut next = Some(first);
            let mut backoff = BACKOFF_INITIAL;
            let mut buf = vec![0u8; RECV_BUF];
            let mut window = DegradeWindow::default();
            while !self.cancellation.is_cancelled() {
                let capture = match next.take() {
                    Some(c) => Ok(c),
                    None => Capture::open(self.interface.as_deref()),
                };
                let error = match capture {
                    Ok(cap) => match self.capture(&cap, &mut buf, &mut window, &mut backoff) {
                        Exit::Cancelled | Exit::ChannelClosed => break,
                        Exit::SocketError(errno) => format!("AF_PACKET recv failed: errno {errno}"),
                    },
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
            lock_health(&self.health).state = SensorState::Stopped;
        }

        fn capture(
            &mut self,
            cap: &Capture,
            buf: &mut [u8],
            window: &mut DegradeWindow,
            backoff: &mut Duration,
        ) -> Exit {
            loop {
                if self.cancellation.is_cancelled() {
                    return Exit::Cancelled;
                }
                let recv = cap.recv(buf);
                let now = Instant::now();
                let mut events = match recv {
                    Recv::Packet { len, local_origin } => {
                        let l3 = buf.get(..len).unwrap_or_default();
                        self.engine.on_packet(l3, local_origin, wall_ns(), now)
                    }
                    Recv::Skip | Recv::Timeout => Vec::new(),
                    Recv::Error(errno) => return Exit::SocketError(errno),
                };
                *backoff = BACKOFF_INITIAL;
                events.extend(self.engine.tick(now));
                let metrics = self.engine.metrics();
                {
                    let mut h = lock_health(&self.health);
                    h.engine = metrics;
                    h.state = window.observe(&metrics, now);
                }
                for event in events {
                    if !self.send(event) {
                        return Exit::ChannelClosed;
                    }
                }
            }
        }

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
                lock_health(&self.health).events_dropped_total += 1;
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
        let s = DnsSensor::new(PathBuf::from("/proc"), None);
        assert_eq!(s.name(), "dns");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn capabilities_unsupported_off_linux() {
        let s = DnsSensor::new(PathBuf::from("/proc"), None);
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
        let mut s = DnsSensor::new(PathBuf::from("/proc"), None);
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let r = s
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(matches!(r, Err(SensorError::Unsupported(_))));
        assert!(s.health().last_error.unwrap_or_default().contains("Linux"));
    }

    #[tokio::test]
    async fn start_does_not_mask_a_capture_failure() {
        let mut s = DnsSensor::new(PathBuf::from("/proc"), None);
        lock_health(&s.health).state = SensorState::Failed;
        s.start().await.unwrap();
        assert_eq!(s.health().state, SensorState::Failed);

        let mut s = DnsSensor::new(PathBuf::from("/proc"), None);
        s.start().await.unwrap();
        assert_eq!(s.health().state, SensorState::Healthy);
    }

    #[test]
    fn degraded_for_a_minute_after_parse_errors_rise() {
        let mut w = DegradeWindow::default();
        let t0 = Instant::now();
        let mut m = EngineMetrics::default();
        assert_eq!(w.observe(&m, t0), SensorState::Healthy);
        m.parse_errors = 1;
        assert_eq!(w.observe(&m, t0), SensorState::Degraded);
        assert_eq!(
            w.observe(&m, t0 + Duration::from_secs(59)),
            SensorState::Degraded
        );
        assert_eq!(
            w.observe(&m, t0 + Duration::from_secs(61)),
            SensorState::Healthy
        );
        m.tracker.overflow_evictions = 1;
        assert_eq!(
            w.observe(&m, t0 + Duration::from_secs(62)),
            SensorState::Degraded
        );
    }
}
