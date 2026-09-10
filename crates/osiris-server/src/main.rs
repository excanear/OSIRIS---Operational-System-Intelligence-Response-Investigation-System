use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use osiris_api::build_router;
use osiris_baseline::BaselineEngine;
use osiris_correlate::CorrelationEngine;
use osiris_detect::DetectionEngine;
use osiris_risk::RiskEngine;
use osiris_server::{run_ingestion_loop, ServerConfig};
use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;
use tokio_util::sync::CancellationToken;

/// The Correlation Engine's bounded graph-walk parameters (ARCHITECTURE.md
/// §11.3/§19.1: "bounded by depth and time window"). Not yet exposed as
/// config — a documented, small default, the same posture every prior
/// phase's un-configurable numeric defaults took (Phase 6 plan Task 10).
const CORRELATION_MAX_DEPTH: usize = 5;
/// 60 seconds, in nanoseconds — generous relative to the shipped sequence
/// rule's own 30s window, so a chain reliably includes every edge a
/// sequence alert's evidence could reference.
const CORRELATION_WINDOW_NS: u64 = 60_000_000_000;

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

    // Phase 6: Baseline/Risk are new, optional-in-config engines. A
    // missing/invalid config path degrades to "keep running with an engine
    // that has nothing to report" rather than crashing the whole server —
    // the same posture `DetectionEngine::load_from_dir` takes above, since
    // Baseline/Risk enrichment is best-effort relative to the ingestion
    // path's core job of durably storing events.
    let baseline_db_path = config
        .baseline_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/baseline.db".to_string());
    let baseline_engine = match BaselineEngine::open(&baseline_db_path) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::warn!(
                path = %baseline_db_path,
                error = %e,
                "failed to open baseline store; falling back to an in-memory \
                 engine that observes but does not persist across restarts"
            );
            match BaselineEngine::open(":memory:") {
                Ok(e) => Arc::new(e),
                Err(e) => {
                    eprintln!("failed to open even an in-memory baseline store: {e}");
                    std::process::exit(1);
                }
            }
        }
    };

    let risk_weights_path = config
        .risk_weights_path
        .clone()
        .unwrap_or_else(|| "/etc/osiris/risk/weights.yaml".to_string());
    let risk_engine = match RiskEngine::load_from_file(&risk_weights_path) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::warn!(
                path = %risk_weights_path,
                error = %e,
                "failed to load risk weight config; using documented built-in defaults"
            );
            Arc::new(RiskEngine::new(Default::default()))
        }
    };

    let correlation_engine = Arc::new(CorrelationEngine::new(
        CORRELATION_MAX_DEPTH,
        CORRELATION_WINDOW_NS,
    ));

    let cancellation = CancellationToken::new();
    let ingest_storage = storage.clone();
    let spool_path = config.spool_path.clone();
    tokio::spawn(run_ingestion_loop(
        spool_path,
        ingest_storage,
        detection_engine,
        baseline_engine,
        risk_engine,
        correlation_engine,
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
