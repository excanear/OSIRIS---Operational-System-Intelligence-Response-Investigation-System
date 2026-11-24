//! Phase 12b end to end, in process: a real `IngestContext` with a WASM
//! detection plugin feeds storage and a file exporter; the alert list and the
//! plugin status endpoint are served by the real auth-gated router.

use std::sync::Arc;
use std::time::{Duration, Instant};

use osiris_api::{auth_gate, build_auth_router, build_plugins_router, build_router, PluginsState};
use osiris_audit::FileAuditLog;
use osiris_auth::{SqliteUserStore, UserStore};
use osiris_baseline::BaselineEngine;
use osiris_correlate::CorrelationEngine;
use osiris_detect::DetectionEngine;
use osiris_plugin::{fixtures, PluginConfig, PluginKind, PluginSet};
use osiris_risk::RiskEngine;
use osiris_schema::{
    CanonicalEvent, Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source,
    SCHEMA_VERSION,
};
use osiris_server::IngestContext;
use osiris_storage_sqlite::SqliteStorage;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The `detect_nc` fixture matches `"name":"nc"` in the event JSON.
fn nc_event() -> CanonicalEvent {
    let host_id = Uuid::new_v4();
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id,
        boot_id: "b".to_string(),
        timestamp: 1_700_000_000_000_000_000,
        monotonic_timestamp: 1,
        event_type: EventType::ProcessExec,
        category: Category::Process,
        severity: Severity::Info,
        host: HostRef {
            host_id,
            hostname: "e2e-host".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        },
        user: None,
        session: None,
        process: Some(ProcessRef {
            process_key: ProcessKey::new(host_id, "b", 300, 1),
            pid: 300,
            exe_path: "/usr/bin/nc".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1,
        }),
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
        event_data: serde_json::json!({ "process": { "name": "nc" } }),
    }
}

/// A path as it can sit inside single-quoted YAML on every platform.
fn yaml_path(p: &std::path::Path) -> String {
    p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_alert_reaches_storage_api_and_exporter() {
    let dir = tempfile::tempdir().unwrap();

    // The plugin, loaded exactly as the server loads `config.plugins`.
    let wasm = fixtures::wasm("detect_nc");
    let wasm_path = dir.path().join("hunt.wasm");
    std::fs::write(&wasm_path, &wasm).unwrap();
    let plugins = Arc::new(
        PluginSet::load(&[PluginConfig {
            name: "hunt".into(),
            kind: PluginKind::Detection,
            path: wasm_path,
            sha256: hex::encode(Sha256::digest(&wasm)),
            version: 1,
            fuel_per_event: 10_000_000,
            memory_max_mib: 16,
            enabled: true,
        }])
        .unwrap(),
    );

    // File exporter, built from YAML as the server config would.
    let out = dir.path().join("out.ndjson");
    let yaml = format!(
        "- {{name: sink-file, kind: file, path: '{}', flush_interval_ms: 20}}\n",
        yaml_path(&out),
    );
    let cfgs: Vec<osiris_export::ExporterConfig> = serde_yaml::from_str(&yaml).unwrap();
    let built = osiris_export::build_exporters(&cfgs, "e2e").unwrap();
    let hub = osiris_export::ExportHub::start(built, None, CancellationToken::new());

    // No YAML rules: the only alert can come from the plugin.
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir(&rules_dir).unwrap();
    let storage = Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
    let context = IngestContext {
        storage: storage.clone(),
        detection_engine: Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap()),
        baseline_engine: Arc::new(BaselineEngine::open(dir.path().join("baseline.db")).unwrap()),
        risk_engine: Arc::new(RiskEngine::new(Default::default())),
        correlation_engine: Arc::new(CorrelationEngine::new(5, 60_000_000_000)),
        broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
        fleet_registry: Arc::new(
            osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap(),
        ),
        policy_reconciler: Arc::new(std::sync::OnceLock::new()),
        exporters: Some(hub.clone()),
        plugins: Some(plugins.clone()),
    };

    // Real auth-gated router: alerts list plus the status endpoint.
    let (user_store, _) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let admin_token = user_store
        .create_session(admin.user_id, 3600)
        .unwrap()
        .token;
    let auth_state = osiris_api::AuthState {
        users: Arc::new(user_store),
        audit_log: Arc::new(FileAuditLog::open(dir.path().join("auth-audit.jsonl")).unwrap()),
        session_ttl_seconds: 3600,
        tenants: Arc::new(
            osiris_tenancy::SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap(),
        ),
    };
    let app = build_router(storage)
        .merge(build_auth_router(auth_state.clone()))
        .merge(build_plugins_router(PluginsState {
            plugins: Some(plugins),
        }))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let event = nc_event();
    context.ingest(vec![event.clone()]).await.unwrap();

    let event_id = event.event_id.to_string();
    let rule_id = "plugin:hunt:nc_seen";
    let client = reqwest::Client::new();
    let get_json = |path: &'static str| {
        let client = client.clone();
        let token = admin_token.clone();
        async move {
            client
                .get(format!("http://{api_addr}{path}"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let (alerts, status) = loop {
        let file = std::fs::read_to_string(&out).unwrap_or_default();
        let alerts = get_json("/api/v1/alerts").await;
        let status = get_json("/api/v1/plugins").await;
        let listed = alerts
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x["rule_id"] == rule_id));
        let counted = status["plugins"][0]["alerts"].as_u64().unwrap_or(0) >= 1;
        if file.contains(rule_id) && file.contains(&event_id) && listed && counted {
            break (alerts, status);
        }
        assert!(
            Instant::now() < deadline,
            "timed out; file={file:?} alerts={alerts} status={status}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(alerts.as_array().unwrap().len(), 1, "{alerts}");
    assert_eq!(status["plugins"][0]["name"], "hunt");
    assert_eq!(status["plugins"][0]["kind"], "detection");
    assert_eq!(status["plugins"][0]["calls"], 1);

    // Anonymous callers are refused by the real gate.
    let anon = client
        .get(format!("http://{api_addr}/api/v1/plugins"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 401);

    hub.shutdown().await;
}
