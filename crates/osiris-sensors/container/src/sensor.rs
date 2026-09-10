use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::poller::ContainerCgroupPoller;
use crate::target::ContainerCgroupRoot;

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

/// The Container sensor (ARCHITECTURE.md §4.3's Container row), this
/// phase's scope: the cgroup-only fallback backend (Phase 5 plan Global
/// Constraint #1) — the Docker/containerd/CRI-O unix-socket API primary
/// backend is deferred to real-Linux validation, the same posture every
/// earlier phase's hardest backend took (Phase 1's eBPF, Phase 4b's
/// fanotify).
pub struct ContainerSensor {
    cgroup_roots: Vec<ContainerCgroupRoot>,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl ContainerSensor {
    pub fn new(cgroup_roots: Vec<ContainerCgroupRoot>) -> Self {
        Self {
            cgroup_roots,
            poll_interval: Duration::from_secs(15),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    fn any_root_exists(&self) -> bool {
        self.cgroup_roots
            .iter()
            .any(|r| std::path::Path::new(&r.path).exists())
    }
}

#[async_trait]
impl Sensor for ContainerSensor {
    fn name(&self) -> &'static str {
        "container"
    }

    fn capabilities(&self) -> SensorCapabilities {
        if !self.cgroup_roots.is_empty() && self.any_root_exists() {
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
                unsupported_reason: Some(
                    "no configured container_cgroup_roots target currently exists".to_string(),
                ),
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

        let roots = self.cgroup_roots.clone();
        let poll_interval = self.poll_interval;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut poller = ContainerCgroupPoller::new(roots);
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
    raw: osiris_sensor_api::ContainerEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::Container(raw)).await.is_ok() {
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
    use osiris_sensor_api::{ContainerOperation, RawEvent, Sensor, SensorContext};

    #[tokio::test]
    async fn reports_unsupported_when_no_root_path_exists() {
        let mut sensor = ContainerSensor::new(vec![ContainerCgroupRoot {
            path: "/does/not/exist".to_string(),
        }]);
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reports_unsupported_when_no_roots_are_configured_at_all() {
        let mut sensor = ContainerSensor::new(vec![]);
        assert!(!sensor.capabilities().supported());
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        assert!(sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn emits_a_container_event_for_a_cgroup_dir_created_after_startup() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = ContainerSensor::new(vec![ContainerCgroupRoot {
            path: dir.path().to_string_lossy().to_string(),
        }])
        .with_poll_interval(Duration::from_millis(30));
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(60)).await;
        std::fs::create_dir(dir.path().join(format!("docker-{}.scope", "7".repeat(64)))).unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        match received {
            RawEvent::Container(raw) => {
                assert_eq!(raw.operation, ContainerOperation::Create);
                assert!(raw.cgroup_path.contains("docker-"));
            }
            other => panic!("expected RawEvent::Container, got {other:?}"),
        }
        sensor.stop().await.unwrap();
    }
}
