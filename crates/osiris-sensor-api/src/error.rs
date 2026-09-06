use thiserror::Error;

#[derive(Debug, Error)]
pub enum SensorError {
    #[error("sensor initialization failed: {0}")]
    InitFailed(String),
    #[error("sensor backend unsupported on this host: {0}")]
    Unsupported(String),
    #[error("sensor output channel closed")]
    ChannelClosed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
