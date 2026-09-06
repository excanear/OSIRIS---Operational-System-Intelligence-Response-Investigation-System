pub mod config;
pub mod ingest;
pub mod tailer;

pub use config::{ConfigError, ServerConfig};
pub use ingest::run_ingestion_loop;
pub use tailer::SpoolTailer;
