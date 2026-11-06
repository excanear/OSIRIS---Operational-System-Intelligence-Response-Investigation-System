pub mod api_tls;
pub mod config;
pub mod control;
pub mod cors;
pub mod ingest;
pub mod policy_reconcile;
pub mod storage_backend;

pub use config::{
    exporter_destination, ApiTlsConfig, ClickHouseConfig, ConfigError, ServerConfig, StorageBackend,
};
pub use cors::apply_dev_cors;
pub use ingest::{run_ingestion_context_loop, run_ingestion_loop, IngestContext};
pub use storage_backend::open_storage;

/// Resolves on ctrl-c or (unix) SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
