use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use osiris_api::build_router;
use osiris_detect::DetectionEngine;
use osiris_server::{run_ingestion_loop, ServerConfig};
use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    osiris_selftelemetry::init_logging("info");

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/osiris/server.yaml"));
    let config = match ServerConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config at {}: {}", config_path.display(), e);
            std::process::exit(1);
        }
    };

    let storage: Arc<dyn Storage> = match SqliteStorage::open(&config.db_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("failed to open storage at {}: {}", config.db_path, e);
            std::process::exit(1);
        }
    };

    let detection_engine = match DetectionEngine::load_from_dir(Path::new(&config.rules_dir)) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("failed to load detection rules from {}: {}", config.rules_dir, e);
            std::process::exit(1);
        }
    };

    let cancellation = CancellationToken::new();
    let ingest_storage = storage.clone();
    let spool_path = config.spool_path.clone();
    tokio::spawn(run_ingestion_loop(
        spool_path,
        ingest_storage,
        detection_engine,
        Duration::from_millis(200),
        cancellation.clone(),
    ));

    let addr = match SocketAddr::from_str(&config.listen_addr) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid listen_addr '{}': {}", config.listen_addr, e);
            std::process::exit(1);
        }
    };

    let app = build_router(storage);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
