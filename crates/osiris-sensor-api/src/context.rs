use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

use crate::raw_event::RawEvent;

/// What every Sensor receives at initialize() time (ARCHITECTURE.md §4.1).
/// Phase 1 simplifies TelemetryLevel/sensor-specific-config/CapabilityProbe
/// to what Process/Exec actually needs; later phases widen this struct.
pub struct SensorContext {
    pub output: Sender<RawEvent>,
    pub cancellation: CancellationToken,
}

impl SensorContext {
    pub fn new(output: Sender<RawEvent>, cancellation: CancellationToken) -> Self {
        Self {
            output,
            cancellation,
        }
    }
}
