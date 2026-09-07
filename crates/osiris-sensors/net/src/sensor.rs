use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::poller::NetworkPoller;

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

fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Network sensor (ARCHITECTURE.md §4.3's Network row), Phase 3 scope:
/// the `/proc/net/tcp` polling fallback backend only (plan Global
/// Constraints #1/#2/#3/#4/#5). eBPF kprobes/tracepoints and conntrack
/// integration are additional/extended `Sensor` behaviour behind this same
/// unchanged trait, not a rewrite.
pub struct NetworkSensor {
    proc_root: PathBuf,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl NetworkSensor {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
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
impl Sensor for NetworkSensor {
    fn name(&self) -> &'static str {
        "network"
    }

    fn capabilities(&self) -> SensorCapabilities {
        if self.proc_root.join("net").join("tcp").exists() {
            // `audit_fallback` specifically means "the real Linux Audit
            // backend is available" (see SensorCapabilities's doc comment)
            // — this sensor is a `/proc/net/tcp` poller, not audit-based,
            // so it reports `always_available` instead.
            SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: true,
                unsupported_reason: None,
            }
        } else {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: false,
                unsupported_reason: Some(format!(
                    "net/tcp not found under {}",
                    self.proc_root.display()
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
        lock_health(&self.health).capability_flags = vec!["always_available".to_string()];

        let proc_root = self.proc_root.clone();
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
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
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
    raw: osiris_sensor_api::NetworkEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::Network(raw)).await.is_ok() {
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
    use osiris_sensor_api::{RawEvent, Sensor, SensorContext, SensorState};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn reports_unsupported_when_proc_root_net_tcp_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = NetworkSensor::new(dir.path());
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
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(
            dir.path().join("net").join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .unwrap();

        let mut sensor = NetworkSensor::new(dir.path()).with_poll_interval(Duration::from_millis(20));
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
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n  0: 0500000A:C738 32671BCB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 100 0 0 10 0\n",
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
}
