use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use osiris_api::build_router;
use osiris_api::{auth_gate, build_auth_router, build_tenant_router, AuthState};
use osiris_api::{
    build_incident_evidence_router, build_stream_router, IncidentEvidenceState,
    LiveEventBroadcaster,
};
use osiris_api::{build_response_router, ResponseState};
use osiris_audit::FileAuditLog;
use osiris_auth::SqliteUserStore;
use osiris_baseline::BaselineEngine;
use osiris_correlate::CorrelationEngine;
use osiris_detect::DetectionEngine;
use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
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
            eprintln!(
                "failed to load detection rules from {}: {}",
                config.rules_dir, e
            );
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

    let live_event_broadcaster = Arc::new(LiveEventBroadcaster::new());

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
        live_event_broadcaster.clone(),
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

    let incidents_db_path = config
        .incidents_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/incidents.db".to_string());
    let evidence_db_path = config
        .evidence_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/evidence.db".to_string());
    let links_db_path = config
        .links_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/links.db".to_string());
    let investigate_audit_log_path = config
        .investigate_audit_log_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/investigate-audit.jsonl".to_string());

    // Unlike Baseline/Risk above, the Incident/Evidence/audit stores are
    // core to this phase, not best-effort enrichment: silently degrading to
    // a disabled investigation surface would be worse than refusing to
    // start. So these fail fast — but with an actionable message naming the
    // path and the config key that controls it, never a bare unwrap panic.
    fn open_or_exit<T>(
        opened: Result<T, impl std::fmt::Display>,
        path: &str,
        config_key: &str,
    ) -> T {
        match opened {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    path = %path,
                    config_key = %config_key,
                    error = %e,
                    "failed to open a required investigation store; set the \
                     named config key to a writable path and restart"
                );
                eprintln!(
                    "fatal: failed to open required store at '{path}' \
                     (config key '{config_key}'): {e}"
                );
                std::process::exit(1);
            }
        }
    }

    // Exactly one FileAuditLog instance for this path in this process —
    // FileAuditLog::append is not safe to call concurrently from two
    // separate instances sharing a path (see its own doc comment), so this
    // one Arc is shared between IncidentEvidenceState and AuthState below,
    // never opened a second time.
    let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> = Arc::new(open_or_exit(
        FileAuditLog::open(&investigate_audit_log_path),
        &investigate_audit_log_path,
        "investigate_audit_log_path",
    ));

    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(open_or_exit(
            SqliteIncidentStore::open(&incidents_db_path),
            &incidents_db_path,
            "incidents_db_path",
        )),
        evidence: Arc::new(open_or_exit(
            SqliteEvidenceStore::open(&evidence_db_path),
            &evidence_db_path,
            "evidence_db_path",
        )),
        links: Arc::new(open_or_exit(
            SqliteEvidenceIncidentLinks::open(&links_db_path),
            &links_db_path,
            "links_db_path",
        )),
        audit_log: audit_log.clone(),
    };

    let response_state = ResponseState {
        storage: storage.clone(),
        evidence: incident_evidence_state.evidence.clone(),
        links: incident_evidence_state.links.clone(),
        incidents: incident_evidence_state.incidents.clone(),
        audit_log: audit_log.clone(),
    };

    let users_db_path = config
        .users_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/users.db".to_string());
    let (user_store, bootstrap_admin) = open_or_exit(
        SqliteUserStore::open(&users_db_path),
        &users_db_path,
        "users_db_path",
    );
    if let Some(admin) = bootstrap_admin {
        tracing::warn!(
            username = %admin.username,
            password = %admin.password,
            "created a bootstrap admin user — log in once with this one-time \
             password (never shown again) and create a named account"
        );
    }
    let session_ttl_seconds = config.session_ttl_seconds.unwrap_or(28800);
    let tenants_db_path = config
        .tenants_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/tenants.db".to_string());
    let tenant_store: Arc<dyn osiris_tenancy::TenantStore> = Arc::new(open_or_exit(
        osiris_tenancy::SqliteTenantStore::open(&tenants_db_path),
        &tenants_db_path,
        "tenants_db_path",
    ));
    let auth_state = AuthState {
        users: Arc::new(user_store),
        audit_log: audit_log.clone(),
        session_ttl_seconds,
        tenants: tenant_store.clone(),
    };

    let app = osiris_server::apply_dev_cors(
        build_router(storage)
            .merge(build_incident_evidence_router(incident_evidence_state))
            .merge(build_response_router(response_state))
            .merge(build_stream_router(live_event_broadcaster))
            .merge(build_auth_router(auth_state.clone()))
            .merge(build_tenant_router(auth_state.clone()))
            .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate)),
        config.dev_cors,
    );
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
