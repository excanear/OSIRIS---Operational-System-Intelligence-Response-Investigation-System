use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::capabilities::SensorCapabilities;
use crate::context::SensorContext;
use crate::error::SensorError;
use crate::health::SensorHealth;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SensorMetrics {
    pub events_emitted_total: u64,
    pub events_dropped_total: u64,
}

/// Uniform lifecycle contract every sensor implements, regardless of
/// backend (ARCHITECTURE.md §4.1). `#[async_trait]` keeps this
/// dyn-compatible so the Supervisor can hold `Vec<Box<dyn Sensor>>`.
#[async_trait]
pub trait Sensor: Send + Sync {
    fn name(&self) -> &'static str;
    /// Reports what this sensor can do on this host. Called before start(),
    /// so it must not require the sensor to already be running.
    fn capabilities(&self) -> SensorCapabilities;
    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError>;
    async fn start(&mut self) -> Result<(), SensorError>;
    async fn stop(&mut self) -> Result<(), SensorError>;
    fn health(&self) -> SensorHealth;
    fn metrics(&self) -> SensorMetrics;
}
