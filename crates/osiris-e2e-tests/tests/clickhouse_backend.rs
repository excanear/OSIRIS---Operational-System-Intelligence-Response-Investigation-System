//! Phase 11c: the Server running on the opt-in ClickHouse backend.
//!
//! `#[ignore]`d: it needs a ClickHouse server named by `OSIRIS_CLICKHOUSE_URL`
//! (see `tools/clickhouse/dev-server.sh`) and runs only with
//! `--include-ignored`. It uses a unique database and drops it at the end
//! with a plain `DROP DATABASE` HTTP call through the `reqwest` this crate
//! already has, so the test adds no dependency edge.

use std::sync::Arc;
use std::time::Duration;

use osiris_api::{auth_gate, build_auth_router, build_router, build_tenant_router};
use osiris_auth::{SqliteUserStore, UserStore};
use osiris_baseline::BaselineEngine;
use osiris_correlate::CorrelationEngine;
use osiris_detect::DetectionEngine;
use osiris_risk::RiskEngine;
use osiris_schema::{
    CanonicalEvent, Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION,
};
use osiris_server::{open_storage, run_ingestion_loop, ServerConfig};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn event(host: &HostRef, ts: u64) -> CanonicalEvent {
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: "e2e-boot".to_string(),
        timestamp: ts,
        monotonic_timestamp: ts,
        event_type: EventType::ProcessExec,
        category: Category::Process,
        severity: Severity::Info,
        host: host.clone(),
        user: None,
        session: None,
        process: None,
        parent_process: None,
        thread: None,
        file: None,
        network: None,
        dns: None,
        device: None,
        service: None,
        container: None,
        namespace: None,
        cgroup: None,
        kernel: None,
        source: Source::Synthetic,
        provider: "e2e".to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({}),
    }
}

/// Loads a `ServerConfig` through `ServerConfig::load`, the same validation
/// path the binary uses.
fn load_config(yaml: &str) -> ServerConfig {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.yaml");
    std::fs::write(&path, yaml).unwrap();
    ServerConfig::load(&path).expect("valid server config")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs OSIRIS_CLICKHOUSE_URL"]
async fn server_on_clickhouse_ingests_and_serves_events_through_the_api() {
    let url = std::env::var("OSIRIS_CLICKHOUSE_URL")
        .expect("OSIRIS_CLICKHOUSE_URL must be set to run the ClickHouse tests");
    let database = format!("osiris_e2e_{}", Uuid::new_v4().simple());
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.ndjson");
    std::fs::write(&spool_path, "").unwrap();

    let config = load_config(&format!(
        "db_path: \"{}\"\nspool_path: \"{}\"\nlisten_addr: 127.0.0.1:0\nrules_dir: /unused\n\
         storage_backend: clickhouse\nclickhouse:\n  url: \"{url}\"\n  database: {database}\n",
        dir.path()
            .join("unused.db")
            .to_string_lossy()
            .replace('\\', "/"),
        spool_path.to_string_lossy().replace('\\', "/"),
    ));
    let storage = open_storage(&config).expect("open ClickHouse storage");

    let result = run_scenario(dir.path().to_path_buf(), spool_path, storage).await;

    // Always drop the database, then surface any scenario failure.
    let drop = reqwest::Client::new()
        .post(&url)
        .body(format!("DROP DATABASE IF EXISTS {database} SYNC"))
        .send()
        .await
        .and_then(|r| r.error_for_status());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    drop.expect("drop e2e database");
}

async fn run_scenario(
    dir_path: std::path::PathBuf,
    spool_path: std::path::PathBuf,
    storage: Arc<dyn osiris_storage::Storage>,
) -> Result<(), Box<dyn std::any::Any + Send>> {
    tokio::spawn(async move {
        let cancellation = CancellationToken::new();
        let ingestion = tokio::spawn(run_ingestion_loop(
            spool_path.clone(),
            storage.clone(),
            Arc::new(DetectionEngine::new(vec![])),
            Arc::new(BaselineEngine::open(dir_path.join("baseline.db")).unwrap()),
            Arc::new(RiskEngine::new(Default::default())),
            Arc::new(CorrelationEngine::new(5, 60_000_000_000)),
            Arc::new(osiris_api::LiveEventBroadcaster::new()),
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir_path.join("hosts.db")).unwrap()),
            Duration::from_millis(50),
            cancellation.clone(),
        ));

        let host = HostRef {
            host_id: Uuid::new_v4(),
            hostname: "e2e-ch-host".to_string(),
            distro: "test".to_string(),
            kernel_version: "test".to_string(),
            cloud: None,
        };
        let events: Vec<CanonicalEvent> = (1..=3).map(|i| event(&host, i * 1000)).collect();
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&spool_path)
                .unwrap();
            for e in &events {
                writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
            }
        }

        let (user_store, _bootstrap) = SqliteUserStore::open(dir_path.join("users.db")).unwrap();
        let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
        let token = user_store
            .create_session(admin.user_id, 3600)
            .unwrap()
            .token;
        let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> =
            Arc::new(osiris_audit::FileAuditLog::open(dir_path.join("audit.jsonl")).unwrap());
        let auth_state = osiris_api::AuthState {
            users: Arc::new(user_store),
            audit_log,
            session_ttl_seconds: 3600,
            tenants: Arc::new(
                osiris_tenancy::SqliteTenantStore::open(dir_path.join("tenants.db")).unwrap(),
            ),
        };
        let app = build_router(storage.clone())
            .merge(build_auth_router(auth_state.clone()))
            .merge(build_tenant_router(auth_state.clone()))
            .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let mut ids: Vec<String> = vec![];
        for _ in 0..100 {
            let body: serde_json::Value = client
                .get(format!("http://{addr}/api/v1/events"))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            ids = body
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e["event_id"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if ids.len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        cancellation.cancel();
        let _ = ingestion.await;

        let mut expected: Vec<String> = events.iter().map(|e| e.event_id.to_string()).collect();
        expected.sort();
        ids.sort();
        assert_eq!(ids, expected, "API must serve exactly the ingested events");
    })
    .await
    .map_err(|e| e.into_panic())
}
