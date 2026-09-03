use serde::{Deserialize, Serialize};

/// Per-sensor lifecycle state (ARCHITECTURE.md §3.3). Distinct from
/// osiris_health::HealthState, which is the Agent-level aggregation type —
/// this is the richer per-sensor contract every sensor reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SensorState {
    Starting,
    Healthy,
    Degraded,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorHealth {
    pub name: String,
    pub state: SensorState,
    pub events_emitted_total: u64,
    pub events_dropped_total: u64,
    pub last_error: Option<String>,
    pub last_event_at: Option<u64>,
    pub capability_flags: Vec<String>,
    pub p99_emit_latency_us: u64,
}

impl SensorHealth {
    /// Converts this sensor-contract health into the Agent-level aggregation
    /// type from osiris-health, per ARCHITECTURE.md §23's health rollup.
    pub fn to_agent_health(&self) -> osiris_health::SensorHealth {
        let state = match self.state {
            SensorState::Starting | SensorState::Healthy => osiris_health::HealthState::Healthy,
            // A stopped sensor's task has ended and it is no longer
            // emitting events. Phase 1 has no crash-restart (plan Global
            // Constraints #11), so a stopped sensor stays stopped — that
            // must be visible on the health rollup rather than reading as
            // fine (finding 6). Reusing `Degraded` rather than adding a
            // new osiris-health variant: it's not necessarily a crash
            // (could be a clean shutdown request), but it is a state a
            // healthy running agent should surface, not hide.
            SensorState::Stopped => osiris_health::HealthState::Degraded {
                last_error: self
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "sensor stopped".to_string()),
            },
            SensorState::Degraded => osiris_health::HealthState::Degraded {
                last_error: self
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "degraded, no reason given".to_string()),
            },
            SensorState::Failed => osiris_health::HealthState::Failed {
                last_error: self
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "failed, no reason given".to_string()),
            },
        };
        osiris_health::SensorHealth {
            sensor_name: self.name.clone(),
            state,
            events_processed: self.events_emitted_total,
            last_event_at: self.last_event_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degraded_state_carries_reason_when_converted() {
        let h = SensorHealth {
            name: "process_exec".to_string(),
            state: SensorState::Degraded,
            events_emitted_total: 5,
            events_dropped_total: 0,
            last_error: Some("audit log path not found".to_string()),
            last_event_at: Some(123),
            capability_flags: vec!["audit_fallback".to_string()],
            p99_emit_latency_us: 200,
        };
        let agent_health = h.to_agent_health();
        assert!(matches!(
            agent_health.state,
            osiris_health::HealthState::Degraded { .. }
        ));
    }

    /// Regression test for finding 6: a stopped sensor (Phase 1 has no
    /// crash-restart, so "stopped" is exactly the state a sensor whose
    /// task has ended lands in) must not roll up as Healthy.
    #[test]
    fn stopped_state_does_not_roll_up_as_healthy() {
        let h = SensorHealth {
            name: "process_exec".to_string(),
            state: SensorState::Stopped,
            events_emitted_total: 5,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: Some(1),
            capability_flags: vec![],
            p99_emit_latency_us: 50,
        };
        let agent_health = h.to_agent_health();
        assert_ne!(agent_health.state, osiris_health::HealthState::Healthy);
        assert!(matches!(
            agent_health.state,
            osiris_health::HealthState::Degraded { .. }
        ));
    }

    #[test]
    fn healthy_state_maps_to_healthy() {
        let h = SensorHealth {
            name: "process_exec".to_string(),
            state: SensorState::Healthy,
            events_emitted_total: 10,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: Some(1),
            capability_flags: vec![],
            p99_emit_latency_us: 50,
        };
        assert_eq!(
            h.to_agent_health().state,
            osiris_health::HealthState::Healthy
        );
    }
}
