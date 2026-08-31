use tracing_subscriber::{fmt, EnvFilter};

/// Initializes structured logging shared by Agent and Server binaries.
/// Level defaults to `default_level`, overridable via `RUST_LOG`.
pub fn init_logging(default_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level.to_string()));
    let _ = fmt().with_env_filter(filter).with_target(true).try_init();
}
