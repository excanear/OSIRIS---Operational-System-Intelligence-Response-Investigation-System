//! Phase 12a end to end, in process: a real `IngestContext` with the shipped
//! rules feeds a real `ExportHub` with a file exporter and an HMAC-signed
//! webhook exporter; the status endpoint is served by the real auth-gated
//! router.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use hmac::{Hmac, Mac};
use osiris_api::{auth_gate, build_auth_router, build_exporters_router, ExportersState};
use osiris_audit::FileAuditLog;
use osiris_auth::{SqliteUserStore, UserStore};
use osiris_baseline::BaselineEngine;
use osiris_correlate::CorrelationEngine;
use osiris_detect::DetectionEngine;
use osiris_risk::RiskEngine;
use osiris_schema::{
    encode_device_id, CanonicalEvent, Category, EventType, FileRef, HostRef, ProcessKey,
    ProcessRef, Severity, Source, SCHEMA_VERSION,
};
use osiris_server::IngestContext;
use osiris_storage_sqlite::SqliteStorage;
use sha2::Sha256;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const HMAC_KEY: &str = "e2e-hmac-key";

/// What the webhook receiver saw.
#[derive(Default)]
struct Received {
    /// Bodies whose `X-Osiris-Signature` matched.
    good: Vec<String>,
    /// Requests with a missing or wrong signature.
    bad: usize,
}

async fn receive(
    State(rx): State<Arc<Mutex<Received>>>,
    headers: HeaderMap,
    body: Bytes,
) -> &'static str {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(HMAC_KEY.as_bytes()).unwrap();
    mac.update(&body);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let got = headers
        .get("x-osiris-signature")
        .and_then(|v| v.to_str().ok());
    let mut rx = rx.lock().unwrap();
    if got == Some(expected.as_str()) {
        rx.good.push(String::from_utf8_lossy(&body).into_owned());
    } else {
        rx.bad += 1;
    }
    "ok"
}

fn shell_in_web_root_event() -> CanonicalEvent {
    let host_id = Uuid::new_v4();
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id,
        boot_id: "b".to_string(),
        timestamp: 1_700_000_000_000_000_000,
        monotonic_timestamp: 1,
        event_type: EventType::FileCreate,
        category: Category::File,
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
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1,
        }),
        parent_process: None,
        thread: None,
        file: Some(FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(1),
            device_id: Some(encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        }),
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

/// A path as it can sit inside single-quoted YAML on every platform.
fn yaml_path(p: &std::path::Path) -> String {
    p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

#[tokio::test(flavor = "multi_thread")]
async fn event_and_alert_reach_file_and_webhook_exporters() {
    let dir = tempfile::tempdir().unwrap();

    // Webhook receiver on loopback.
    let received = Arc::new(Mutex::new(Received::default()));
    let receiver = axum::Router::new()
        .route("/hook", post(receive))
        .with_state(received.clone());
    let rx_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rx_addr = rx_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(rx_listener, receiver).await.unwrap();
    });

    // Exporters, built from YAML exactly as the server config would.
    let out = dir.path().join("out.ndjson");
    let key = dir.path().join("hmac.key");
    std::fs::write(&key, format!("{HMAC_KEY}\n")).unwrap();
    let yaml = format!(
        "- {{name: sink-file, kind: file, path: '{}', flush_interval_ms: 20}}\n\
         - {{name: sink-hook, kind: webhook, url: 'http://{}/hook', hmac_key_file: '{}', flush_interval_ms: 20}}\n",
        yaml_path(&out),
        rx_addr,
        yaml_path(&key),
    );
    let cfgs: Vec<osiris_export::ExporterConfig> = serde_yaml::from_str(&yaml).unwrap();
    let built = osiris_export::build_exporters(&cfgs, "e2e").unwrap();
    let hub = osiris_export::ExportHub::start(built, None, CancellationToken::new());

    // Real ingest context with the shipped rules.
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let context = IngestContext {
        storage: Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap()),
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
    };

    // Real auth-gated router serving the status endpoint.
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
    let app = build_auth_router(auth_state.clone())
        .merge(build_exporters_router(ExportersState {
            hub: Some(hub.clone()),
        }))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let event = shell_in_web_root_event();
    context.ingest(vec![event.clone()]).await.unwrap();

    let event_id = event.event_id.to_string();
    let rule_id = "shell_wrote_file_to_web_root";
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let statuses = loop {
        let file = std::fs::read_to_string(&out).unwrap_or_default();
        let hook = received.lock().unwrap().good.join("");
        let statuses: serde_json::Value = client
            .get(format!("http://{api_addr}/api/v1/exporters"))
            .bearer_auth(&admin_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let sent_ok = statuses["exporters"].as_array().is_some_and(|rows| {
            rows.len() == 2
                && rows
                    .iter()
                    .all(|r| r["sent_records"].as_u64().unwrap_or(0) >= 2)
        });
        let present = |s: &str| s.contains(&event_id) && s.contains(rule_id);
        if present(&file) && present(&hook) && sent_ok {
            break statuses;
        }
        assert!(
            Instant::now() < deadline,
            "timed out; file={file:?} hook={hook:?} status={statuses}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(received.lock().unwrap().bad, 0, "bad HMAC signatures");
    let rows = statuses["exporters"].as_array().unwrap();
    let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["sink-file", "sink-hook"]);
    for r in rows {
        assert_eq!(r["state"], "OK", "{r}");
    }

    // Anonymous callers are refused by the real gate.
    let anon = client
        .get(format!("http://{api_addr}/api/v1/exporters"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 401);

    hub.shutdown().await;
}
