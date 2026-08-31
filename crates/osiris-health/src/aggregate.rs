use serde::{Deserialize, Serialize};

use crate::state::{HealthState, SensorHealth};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub state: HealthState,
    pub sensors: Vec<SensorHealth>,
}

/// Aggregates per-sensor health into Agent-level health (ARCHITECTURE.md
/// §23): overall state is the worst state among all sensors.
#[derive(Default)]
pub struct HealthAggregator {
    sensors: Vec<SensorHealth>,
}

impl HealthAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sensor(&mut self, health: SensorHealth) {
        self.sensors.retain(|s| s.sensor_name != health.sensor_name);
        self.sensors.push(health);
    }

    pub fn aggregate(&self) -> AgentHealth {
        let worst = self.sensors.iter()
            .map(|s| &s.state)
            .max_by_key(|state| state.severity_rank())
            .cloned()
            .unwrap_or(HealthState::Healthy);
        AgentHealth { state: worst, sensors: self.sensors.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sensors_is_healthy() {
        let agg = HealthAggregator::new();
        assert_eq!(agg.aggregate().state, HealthState::Healthy);
    }

    #[test]
    fn one_failed_sensor_makes_agent_failed() {
        let mut agg = HealthAggregator::new();
        agg.record_sensor(SensorHealth {
            sensor_name: "exec".into(),
            state: HealthState::Healthy,
            events_processed: 10,
            last_event_at: Some(1),
        });
        agg.record_sensor(SensorHealth {
            sensor_name: "network".into(),
            state: HealthState::Failed { last_error: "eBPF load failure: verifier rejected program".into() },
            events_processed: 0,
            last_event_at: None,
        });
        let health = agg.aggregate();
        assert!(matches!(health.state, HealthState::Failed { .. }));
        assert_eq!(health.sensors.len(), 2);
    }

    #[test]
    fn re_recording_a_sensor_replaces_its_entry() {
        let mut agg = HealthAggregator::new();
        agg.record_sensor(SensorHealth {
            sensor_name: "exec".into(), state: HealthState::Healthy,
            events_processed: 1, last_event_at: Some(1),
        });
        agg.record_sensor(SensorHealth {
            sensor_name: "exec".into(),
            state: HealthState::Degraded { last_error: "queue overflow: dropped 12 events".into() },
            events_processed: 2, last_event_at: Some(2),
        });
        let health = agg.aggregate();
        assert_eq!(health.sensors.len(), 1);
        assert!(matches!(health.sensors[0].state, HealthState::Degraded { .. }));
    }
}
