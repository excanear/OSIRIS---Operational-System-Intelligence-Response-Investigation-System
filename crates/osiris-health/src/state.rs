use serde::{Deserialize, Serialize};

/// ARCHITECTURE.md §23: "generic unhealthy" is not an allowed terminal
/// state — Degraded/Failed must carry a reason. Enforced structurally: it
/// is impossible to construct either variant without a `last_error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthState {
    Healthy,
    Degraded { last_error: String },
    Failed { last_error: String },
}

impl HealthState {
    /// Ordering for aggregation: Failed worst, then Degraded, then Healthy.
    pub fn severity_rank(&self) -> u8 {
        match self {
            HealthState::Healthy => 0,
            HealthState::Degraded { .. } => 1,
            HealthState::Failed { .. } => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorHealth {
    pub sensor_name: String,
    pub state: HealthState,
    pub events_processed: u64,
    pub last_event_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_outranks_degraded_outranks_healthy() {
        assert!(
            HealthState::Failed { last_error: "x".into() }.severity_rank()
                > HealthState::Degraded { last_error: "x".into() }.severity_rank()
        );
        assert!(
            HealthState::Degraded { last_error: "x".into() }.severity_rank()
                > HealthState::Healthy.severity_rank()
        );
    }
}
