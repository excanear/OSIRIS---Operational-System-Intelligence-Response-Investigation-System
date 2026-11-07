//! Server-side WASM plugins (Phase 12b).

pub mod config;

pub use config::{validate_plugins, ConfigError, PluginConfig, PluginKind};
