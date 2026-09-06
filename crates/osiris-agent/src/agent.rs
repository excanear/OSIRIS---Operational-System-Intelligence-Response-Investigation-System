use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_bus::{run_drain_loop, EventBus, Sink, SpoolFileSink};
use osiris_generator::{exec_chain_scenario, SyntheticSensor};
use osiris_pipeline::Pipeline;
use osiris_schema::HostRef;
use osiris_selftelemetry::MetricsRegistry;
use osiris_sensor_api::{Sensor, SensorContext, SensorHealth};
use osiris_sensors_process::ProcessExecSensor;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::AgentConfig;
use crate::lifecycle::AgentLifecycle;
use crate::status::{AgentStatus, SkippedSensor};

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("failed to open spool file: {0}")]
    Spool(#[from] osiris_bus::SinkError),
    #[error("failed to bind status endpoint: {0}")]
    Status(std::io::Error),
}

/// The Agent Supervisor (ARCHITECTURE.md §3.1/§3.2), Phase 1 scope: starts
/// every registered sensor whose capabilities() report support, wires
/// their shared output channel through one Pipeline instance into the
/// Event Bus, and serves a local status endpoint. Plan Global Constraints
/// #11: this performs one-shot startup supervision (skip-if-unsupported,
/// aggregate health) but not runtime crash-restart-with-backoff.
pub struct Agent {
    lifecycle: Mutex<AgentLifecycle>,
    sensors: tokio::sync::Mutex<Vec<Box<dyn Sensor>>>,
    skipped_sensors: Mutex<Vec<SkippedSensor>>,
    cancellation: CancellationToken,
    /// JoinHandles for the drain-loop task and the pipeline (raw-event
    /// consumer) task, retained (rather than discarded, as `tokio::spawn`
    /// would otherwise let happen) so `shutdown()` can await them and
    /// guarantee the final drain pass (finding 3) has actually completed —
    /// and therefore that whatever was queued in the bus lanes / raw
    /// channel at shutdown time has been flushed to the sink — before
    /// `shutdown()` returns. `Option` because `JoinHandle` isn't `Clone`
    /// and shutdown only ever runs once; a `tokio::sync::Mutex` because
    /// `shutdown` takes `&self`.
    background_tasks: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// Locks a `Mutex`, recovering rather than panicking if a prior holder
/// panicked while holding it — matches the poison-recovery discipline
/// already established by `osiris-sensors-process` and `osiris-generator`'s
/// `lock_health()` (a poisoned lock here still holds a fully-formed
/// `AgentLifecycle`/`Vec<String>`, so recovering is safe).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Agent {
    pub async fn start(
        config: AgentConfig,
        host: HostRef,
        boot_id: String,
    ) -> Result<Arc<Self>, AgentError> {
        let cancellation = CancellationToken::new();
        let (raw_tx, mut raw_rx) = mpsc::channel(1024);

        let mut candidate_sensors: Vec<Box<dyn Sensor>> = vec![];
        if let Some(path) = &config.audit_log_path {
            candidate_sensors.push(Box::new(ProcessExecSensor::new(path.clone())));
        }
        if config.enable_synthetic {
            let base_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            candidate_sensors.push(Box::new(SyntheticSensor::new(exec_chain_scenario(base_ts))));
        }

        let mut running_sensors: Vec<Box<dyn Sensor>> = vec![];
        let mut skipped: Vec<SkippedSensor> = vec![];
        for mut sensor in candidate_sensors {
            let caps = sensor.capabilities();
            if !caps.supported() {
                let reason = caps
                    .unsupported_reason
                    .unwrap_or_else(|| "unsupported".to_string());
                tracing::warn!(sensor = sensor.name(), reason = %reason, "skipping sensor: unsupported on this host");
                skipped.push(SkippedSensor {
                    name: sensor.name().to_string(),
                    reason,
                });
                continue;
            }
            let ctx = SensorContext::new(raw_tx.clone(), cancellation.clone());
            match sensor.initialize(ctx).await {
                Ok(()) => {
                    if let Err(e) = sensor.start().await {
                        let reason = format!("start failed: {e}");
                        tracing::warn!(sensor = sensor.name(), reason = %reason, "skipping sensor: failed to start");
                        skipped.push(SkippedSensor {
                            name: sensor.name().to_string(),
                            reason,
                        });
                        continue;
                    }
                    running_sensors.push(sensor);
                }
                Err(e) => {
                    let reason = e.to_string();
                    tracing::warn!(sensor = sensor.name(), reason = %reason, "skipping sensor: failed to initialize");
                    skipped.push(SkippedSensor {
                        name: sensor.name().to_string(),
                        reason,
                    });
                }
            }
        }
        drop(raw_tx);

        let metrics = Arc::new(MetricsRegistry::new());
        let (bus, receivers) = EventBus::new(metrics.clone());
        let sink: Arc<dyn Sink> = Arc::new(SpoolFileSink::open(&config.spool_path).await?);
        let drain_handle = tokio::spawn(run_drain_loop(
            receivers,
            sink,
            metrics.clone(),
            cancellation.clone(),
        ));

        let bus = Arc::new(bus);
        let mut pipeline = Pipeline::new(host, boot_id);
        let pipeline_cancellation = cancellation.clone();
        let pipeline_bus = bus.clone();
        let pipeline_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe_raw = raw_rx.recv() => {
                        match maybe_raw {
                            Some(raw) => {
                                let prioritized = pipeline.process(raw);
                                pipeline_bus.enqueue(prioritized);
                            }
                            None => break,
                        }
                    }
                    _ = pipeline_cancellation.cancelled() => break,
                }
            }
        });

        Ok(Arc::new(Self {
            lifecycle: Mutex::new(AgentLifecycle::Running),
            sensors: tokio::sync::Mutex::new(running_sensors),
            skipped_sensors: Mutex::new(skipped),
            cancellation,
            background_tasks: tokio::sync::Mutex::new(vec![pipeline_handle, drain_handle]),
        }))
    }

    pub async fn status_snapshot(&self) -> AgentStatus {
        let lifecycle = *lock(&self.lifecycle);
        let sensors = self.sensors.lock().await;
        let sensor_health: Vec<SensorHealth> = sensors.iter().map(|s| s.health()).collect();
        let skipped_sensors = lock(&self.skipped_sensors).clone();
        AgentStatus {
            lifecycle,
            sensors: sensor_health,
            skipped_sensors,
        }
    }

    pub fn skipped_sensors(&self) -> Vec<SkippedSensor> {
        lock(&self.skipped_sensors).clone()
    }

    pub async fn shutdown(&self) {
        self.cancellation.cancel();
        let mut sensors = self.sensors.lock().await;
        for sensor in sensors.iter_mut() {
            let _ = sensor.stop().await;
        }

        // Await the pipeline and drain-loop tasks so shutdown genuinely
        // waits for the final drain (finding 3) to complete before
        // returning, rather than cancelling and discarding whatever was
        // still queued in the raw channel / bus lanes. Awaited in spawn
        // order: the pipeline task first (it stops consuming raw events
        // and enqueues whatever it already had onto the bus), then the
        // drain-loop task (whose final_drain pass picks up exactly what
        // the pipeline just enqueued) — so nothing in flight at shutdown
        // time is silently dropped.
        let handles: Vec<_> = self.background_tasks.lock().await.drain(..).collect();
        for handle in handles {
            let _ = handle.await;
        }

        *lock(&self.lifecycle) = AgentLifecycle::Stopped;
    }

    pub async fn serve_status(self: Arc<Self>, addr: SocketAddr) -> Result<(), AgentError> {
        crate::status::serve_status(self, addr)
            .await
            .map_err(AgentError::Status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_host() -> HostRef {
        HostRef {
            host_id: Uuid::new_v4(),
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        }
    }

    #[tokio::test]
    async fn starts_with_synthetic_sensor_and_reaches_running() {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            audit_log_path: None,
            enable_synthetic: true,
            spool_path: dir
                .path()
                .join("spool.ndjson")
                .to_string_lossy()
                .to_string(),
            status_addr: "127.0.0.1:0".to_string(),
        };
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.lifecycle, AgentLifecycle::Running);
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "synthetic_generator");

        agent.shutdown().await;
        assert_eq!(
            agent.status_snapshot().await.lifecycle,
            AgentLifecycle::Stopped
        );
    }

    #[tokio::test]
    async fn skips_process_exec_sensor_when_audit_log_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            audit_log_path: Some(dir.path().join("missing.log").to_string_lossy().to_string()),
            enable_synthetic: false,
            spool_path: dir
                .path()
                .join("spool.ndjson")
                .to_string_lossy()
                .to_string(),
            status_addr: "127.0.0.1:0".to_string(),
        };
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 0);

        let skipped = agent.skipped_sensors();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].name, "process_exec");
        assert!(
            skipped[0].reason.contains("audit log not found"),
            "expected the skip reason to explain why, got: {}",
            skipped[0].reason
        );

        // The same skip must be surfaced on the status endpoint's response
        // shape, not just the internal accessor (Global Constraint #11:
        // "health-visible reason").
        assert_eq!(status.skipped_sensors.len(), 1);
        assert_eq!(status.skipped_sensors[0].name, "process_exec");
        assert_eq!(status.skipped_sensors[0].reason, skipped[0].reason);

        agent.shutdown().await;
    }

    #[tokio::test]
    async fn synthetic_events_reach_the_spool_file() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let config = AgentConfig {
            audit_log_path: None,
            enable_synthetic: true,
            spool_path: spool_path.to_string_lossy().to_string(),
            status_addr: "127.0.0.1:0".to_string(),
        };
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 3);
        assert!(contents.contains("\"PROCESS_EXEC\""));
    }
}
