//! Phase 9d-3 end to end: a group policy set through the real authenticated
//! API reaches a real Agent over the real mTLS control channel as a signed
//! `ApplyPolicy` command, is persisted in the Agent's overlay file, and comes
//! back in the next heartbeat as an IN_SYNC host.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use osiris_agent::{Agent, AgentConfig, ControlConfig};
use osiris_api::{
    auth_gate, build_auth_router, build_fleet_router, build_groups_router, build_policy_router,
    build_router, build_tenant_router, AuthState, FleetState, GroupsState, PolicyNotifier,
    PolicyState,
};
use osiris_audit::{AuditLog, FileAuditLog};
use osiris_auth::{SqliteUserStore, UserStore};
use osiris_baseline::BaselineEngine;
use osiris_correlate::CorrelationEngine;
use osiris_detect::DetectionEngine;
use osiris_risk::RiskEngine;
use osiris_schema::HostRef;
use osiris_server::control::HubDispatcher;
use osiris_server::policy_reconcile::PolicyReconciler;
use osiris_server::{run_ingestion_context_loop, IngestContext};
use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;
use osiris_transport::control::{ControlHub, ControlListener};
use osiris_transport::tls;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod common;

/// Bounded poll (`deadline`, 200 ms interval) of `GET /api/v1/hosts/<host>/policy`
/// until `done` accepts the body; panics with the last body on timeout.
async fn poll_host_policy(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    host: &str,
    deadline: Duration,
    done: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let r = client
            .get(format!("{base}/api/v1/hosts/{host}/policy"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = if r.status().is_success() {
            r.json().await.unwrap()
        } else {
            serde_json::Value::Null
        };
        if done(&body) {
            return body;
        }
        if tokio::time::Instant::now() >= end {
            panic!("host policy never converged within {deadline:?}; last body: {body}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_group_policy_reaches_a_real_agent_and_reports_in_sync() {
    let dir = tempfile::tempdir().unwrap();
    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "e2e-policy-host".into(),
        distro: "test".into(),
        kernel_version: "test".into(),
        cloud: None,
    };
    let host_uuid = host.host_id;
    let host_id = host_uuid.to_string();
    let cancel = CancellationToken::new();

    // PKI and command signing key, as the control-channel harness sets them up.
    let pki = common::write_control_pki(dir.path(), host_uuid);
    let keys = dir.path().join("keys");
    osiris_command::keys::write_signing_key(&keys, "command").unwrap();
    let signing_key = osiris_command::keys::load_signing_key(&keys.join("command.key")).unwrap();

    // Real control listener + hub + dispatcher.
    let hub = ControlHub::new();
    let tls_cfg = tls::server_config(
        &pki.join("server.pem"),
        &pki.join("server.key"),
        &pki.join("ca.pem"),
    )
    .unwrap();
    let listener = ControlListener::bind("127.0.0.1:0", tls_cfg, HashSet::new(), hub.clone())
        .await
        .unwrap();
    let control_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(listener.run(cancel.clone()));
    let dispatcher: Arc<dyn osiris_response::CommandDispatcher> = Arc::new(HubDispatcher::new(
        hub.clone(),
        signing_key,
        Duration::from_secs(10),
    ));

    // Stores, ingest stack, reconciler (wired as osiris-server's main.rs does).
    let spool_path = dir.path().join("spool.ndjson");
    let storage: Arc<dyn Storage> =
        Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
    let fleet_db =
        Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
    let registry: Arc<dyn osiris_fleet::HostRegistry> = fleet_db.clone();
    let groups: Arc<dyn osiris_fleet::HostGroupStore> = fleet_db.clone();
    let policies: Arc<dyn osiris_fleet::PolicyStore> = fleet_db;
    let slot = Arc::new(OnceLock::new());
    let ingest = IngestContext {
        storage: storage.clone(),
        detection_engine: Arc::new(DetectionEngine::new(vec![])),
        baseline_engine: Arc::new(BaselineEngine::open(dir.path().join("baseline.db")).unwrap()),
        risk_engine: Arc::new(RiskEngine::new(Default::default())),
        correlation_engine: Arc::new(CorrelationEngine::new(5, 60_000_000_000)),
        broadcaster: Arc::new(osiris_api::LiveEventBroadcaster::new()),
        fleet_registry: registry.clone(),
        policy_reconciler: slot.clone(),
    };
    tokio::spawn(run_ingestion_context_loop(
        spool_path.clone(),
        ingest,
        Duration::from_millis(50),
        cancel.clone(),
    ));

    // Auth + composed router.
    let (user_store, _bootstrap) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let token = user_store
        .create_session(admin.user_id, 3600)
        .unwrap()
        .token;
    let audit_log: Arc<dyn AuditLog + Send + Sync> =
        Arc::new(FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let tenants: Arc<dyn osiris_tenancy::TenantStore> =
        Arc::new(osiris_tenancy::SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap());
    let auth_state = AuthState {
        users: Arc::new(user_store),
        audit_log: audit_log.clone(),
        session_ttl_seconds: 3600,
        tenants: tenants.clone(),
    };
    let reconciler = PolicyReconciler::new(
        registry.clone(),
        policies.clone(),
        tenants.clone(),
        Some(dispatcher),
    );
    let _ = slot.set(reconciler.clone());
    let notifier: Arc<dyn PolicyNotifier> = reconciler;
    let app = build_router(storage.clone())
        .merge(build_auth_router(auth_state.clone()))
        .merge(build_tenant_router(auth_state.clone()))
        .merge(build_fleet_router(FleetState {
            registry: registry.clone(),
            tenants: tenants.clone(),
            groups: groups.clone(),
            policies: policies.clone(),
            notifier: notifier.clone(),
        }))
        .merge(build_groups_router(GroupsState {
            groups: groups.clone(),
            registry: registry.clone(),
            tenants: tenants.clone(),
            audit_log: audit_log.clone(),
            notifier: notifier.clone(),
        }))
        .merge(build_policy_router(PolicyState {
            groups: groups.clone(),
            policies: policies.clone(),
            registry: registry.clone(),
            tenants: tenants.clone(),
            audit_log: audit_log.clone(),
            notifier,
        }))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

    // Real agent, connected over the control channel.
    let mut agent_config = AgentConfig {
        forward: None,
        control: Some(ControlConfig {
            server_addr: control_addr,
            server_name: "localhost".into(),
            ca: pki.join("ca.pem").to_string_lossy().into(),
            cert: pki.join("agent.pem").to_string_lossy().into(),
            key: pki.join("agent.key").to_string_lossy().into(),
            command_public_key: keys.join("command.pub").to_string_lossy().into(),
            vault_dir: dir.path().join("vault").to_string_lossy().into(),
        }),
        cloud_metadata: osiris_agent::CloudMetadataConfig {
            enabled: false,
            ..Default::default()
        },
        k8s_context: osiris_agent::K8sContextConfig {
            enabled: false,
            ..Default::default()
        },
        fleet: osiris_agent::FleetConfig::default(),
        audit_log_path: None,
        fs_audit_log_path: None,
        network_proc_root: None,
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        container_cgroup_roots: vec![],
        proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: None,
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    agent_config.fleet.health_interval_secs = 1;
    let agent = Agent::start(agent_config, host, "e2e-boot".into())
        .await
        .unwrap();
    let overlay = std::path::PathBuf::from(format!("{}.policy.json", spool_path.display()));

    let client = reqwest::Client::new();
    // Host ONLINE: the first heartbeat creates the registry row, which the
    // policy view needs (404 until then).
    poll_host_policy(
        &client,
        &base,
        &token,
        &host_id,
        Duration::from_secs(15),
        |b| b["status"].is_string(),
    )
    .await;
    assert!(hub.connected(host_uuid), "agent never connected");

    // Group, membership, policy.
    let r = client
        .post(format!("{base}/api/v1/groups"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"name": "e2e"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let gid = r.json::<serde_json::Value>().await.unwrap()["group_id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = client
        .put(format!("{base}/api/v1/groups/{gid}/members/{host_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    let r = client
        .put(format!("{base}/api/v1/groups/{gid}/policy"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "telemetry_level": "MINIMAL",
            "sensors": {"network": false},
            "heartbeat_interval_secs": 10
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Converges to IN_SYNC with the applied hash equal to the desired one.
    // The applied hash is only reported by the next heartbeat, and the policy
    // itself sets the heartbeat to its 10 s minimum, so allow that plus slack.
    let body = poll_host_policy(
        &client,
        &base,
        &token,
        &host_id,
        Duration::from_secs(25),
        |b| b["status"] == "IN_SYNC" && b["effective"]["telemetry_level"] == "MINIMAL",
    )
    .await;
    assert_eq!(body["applied_hash"], body["desired_hash"]);
    assert!(body["applied_hash"].is_string());
    assert!(overlay.exists(), "overlay {} missing", overlay.display());
    let desired_with_policy = body["desired_hash"].clone();

    // Clearing the policy converges to the empty-policy hash (an absent
    // policy_hash is stored as that value), and the overlay file is removed.
    let r = client
        .delete(format!("{base}/api/v1/groups/{gid}/policy"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let body = poll_host_policy(
        &client,
        &base,
        &token,
        &host_id,
        Duration::from_secs(15),
        |b| b["status"] == "IN_SYNC" && b["desired_hash"] != desired_with_policy,
    )
    .await;
    assert_eq!(body["applied_hash"], body["desired_hash"]);
    assert!(body["effective"]["telemetry_level"].is_null());
    assert!(!overlay.exists(), "overlay should be deleted");

    agent.shutdown().await;
    cancel.cancel();
}
