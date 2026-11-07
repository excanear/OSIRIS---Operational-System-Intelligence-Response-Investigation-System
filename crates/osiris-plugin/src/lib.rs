//! Server-side WASM plugins (Phase 12b).

pub mod abi;
pub mod config;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
pub mod load;

pub use abi::{parse_output, PluginAlert, PluginOutput};
pub use config::{validate_plugins, ConfigError, PluginConfig, PluginKind};
pub use load::{load_plugin, new_engine, store_limits, HostState, LoadedPlugin};
