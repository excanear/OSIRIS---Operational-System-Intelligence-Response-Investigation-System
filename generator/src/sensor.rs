use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_sensor_api::{
    ProcessExecRaw, RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
use tokio_util::sync::CancellationToken;

struct HealthState {
    state: SensorState,
    events_emitted_total: u64,
    events_dropped_total: u64,
    last_event_at: Option<u64>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            state: SensorState::Starting,
            events_emitted_total: 0,
            events_dropped_total: 0,
            last_event_at: None,
        }
    }
}

/// Locks a health mutex, recovering rather than panicking if a prior
/// holder panicked while holding the lock (a poisoned lock still holds a
/// perfectly usable HealthState — there's no invariant here that a panic
/// mid-update could violate) — matches osiris-sensors-process's "no
/// unwrap/expect outside tests" discipline for lock results.
fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Emits a fixed, deterministic scenario of ProcessExecRaw events through
/// the real Sensor/Pipeline/Bus path — ARCHITECTURE.md §15's requirement
/// that the generator exercise production code, not a parallel simulation.
/// Emits the whole scenario once (spaced by `emit_interval`), then goes
/// idle rather than looping — deterministic and test-friendly.
pub struct SyntheticSensor {
    scenario: Vec<ProcessExecRaw>,
    emit_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl SyntheticSensor {
    pub fn new(scenario: Vec<ProcessExecRaw>) -> Self {
        Self {
            scenario,
            emit_interval: Duration::from_millis(10),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_emit_interval(mut self, interval: Duration) -> Self {
        self.emit_interval = interval;
        self
    }
}

#[async_trait]
impl Sensor for SyntheticSensor {
    fn name(&self) -> &'static str {
        "synthetic_generator"
    }

    fn capabilities(&self) -> SensorCapabilities {
        SensorCapabilities {
            ebpf: false,
            audit_fallback: false,
            always_available: true,
            unsupported_reason: None,
        }
    }

    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError> {
        self.cancellation = Some(ctx.cancellation.clone());
        lock_health(&self.health).state = SensorState::Starting;

        let scenario = self.scenario.clone();
        let emit_interval = self.emit_interval;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            for raw in scenario {
                if cancellation.is_cancelled() {
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                let ts = raw.timestamp_ns;
                if output.send(RawEvent::ProcessExec(raw)).await.is_ok() {
                    let mut h = lock_health(&health);
                    h.events_emitted_total += 1;
                    h.last_event_at = Some(ts);
                    h.state = SensorState::Healthy;
                } else {
                    lock_health(&health).events_dropped_total += 1;
                }
                tokio::select! {
                    _ = tokio::time::sleep(emit_interval) => {}
                    _ = cancellation.cancelled() => {
                        lock_health(&health).state = SensorState::Stopped;
                        return;
                    }
                }
            }
            lock_health(&health).state = SensorState::Stopped;
        });
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
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
            last_error: None,
            last_event_at: h.last_event_at,
            capability_flags: vec!["synthetic".to_string()],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenarios::exec_chain_scenario;
    use osiris_sensor_api::RawEvent;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn emits_every_event_in_the_scenario_in_order() {
        let mut sensor = SyntheticSensor::new(exec_chain_scenario(1000))
            .with_emit_interval(Duration::from_millis(1));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let mut pids = vec![];
        for _ in 0..3 {
            let raw_event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timed out")
                .expect("channel closed");
            match raw_event {
                RawEvent::ProcessExec(raw) => pids.push(raw.pid),
            }
        }
        assert_eq!(pids, vec![100, 200, 300]);

        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 3);
    }

    #[test]
    fn always_available_regardless_of_host() {
        let sensor = SyntheticSensor::new(vec![]);
        assert!(sensor.capabilities().supported());
    }
}
