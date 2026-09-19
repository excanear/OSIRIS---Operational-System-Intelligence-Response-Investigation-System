//! Tenant isolation through the REAL composed router (same composition as
//! `osiris-server/src/main.rs`): two tenants, one unassigned host, a platform
//! admin, and a tenant Admin per tenant.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use osiris_api::{
    auth_gate, build_auth_router, build_incident_evidence_router, build_response_router,
    build_router, build_stream_router, AuthState, IncidentEvidenceState, LiveEventBroadcaster,
    ResponseState,
};
use osiris_audit::FileAuditLog;
use osiris_auth::{NewUser, Role, SqliteUserStore, UserStore};
use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
use osiris_schema::{
    CanonicalEvent, Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source,
    SCHEMA_VERSION,
};
use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;
use osiris_tenancy::{SqliteTenantStore, TenantStore};
use tower::ServiceExt;
use uuid::Uuid;

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn event_on(host: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host,
        boot_id: "b".to_string(),
        timestamp,
        monotonic_timestamp: timestamp,
        event_type: EventType::ProcessExec,
        category: Category::Process,
        severity: Severity::Info,
        host: HostRef {
            host_id: host,
            hostname: format!("host-{pid}"),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        },
        user: None,
        session: None,
        process: Some(ProcessRef {
            process_key: ProcessKey::new(host, "b", pid, timestamp),
            pid,
            exe_path: "/bin/x".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: timestamp,
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
        provider: "test".to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({}),
    }
}

struct Tenancy {
    _dir: tempfile::TempDir,
    app: axum::Router,
    tenants: Arc<dyn TenantStore>,
    auth_state: AuthState,
    broadcaster: Arc<LiveEventBroadcaster>,
    admin_token: String,
    acme_token: String,
    globex_token: String,
    acme_tenant: Uuid,
    globex_tenant: Uuid,
    acme_host: Uuid,
    globex_host: Uuid,
    unassigned_host: Uuid,
    globex_process_key: String,
}

fn build_app(
    storage: Arc<dyn Storage>,
    incident_evidence_state: IncidentEvidenceState,
    response_state: ResponseState,
    broadcaster: Arc<LiveEventBroadcaster>,
    auth_state: AuthState,
) -> axum::Router {
    build_router(storage)
        .merge(build_incident_evidence_router(incident_evidence_state))
        .merge(build_response_router(response_state))
        .merge(build_stream_router(broadcaster))
        .merge(build_auth_router(auth_state.clone()))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate))
}

fn tenancy() -> Tenancy {
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name);

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(p("events.db")).unwrap());
    let (acme_host, globex_host, unassigned_host) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let t = now_ns();
    let globex_event = event_on(globex_host, 2, t);
    let globex_process_key = globex_event.process.as_ref().unwrap().process_key.as_hex();
    storage
        .batch_write(&[
            event_on(acme_host, 1, t),
            globex_event,
            event_on(unassigned_host, 3, t),
        ])
        .unwrap();

    let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> =
        Arc::new(FileAuditLog::open(p("audit.jsonl")).unwrap());
    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(SqliteIncidentStore::open(p("incidents.db").to_str().unwrap()).unwrap()),
        evidence: Arc::new(SqliteEvidenceStore::open(p("evidence.db").to_str().unwrap()).unwrap()),
        links: Arc::new(SqliteEvidenceIncidentLinks::open(p("links.db").to_str().unwrap()).unwrap()),
        audit_log: audit_log.clone(),
    };
    let response_state = ResponseState {
        storage: storage.clone(),
        evidence: incident_evidence_state.evidence.clone(),
        links: incident_evidence_state.links.clone(),
        audit_log: audit_log.clone(),
    };

    let tenants: Arc<dyn TenantStore> = Arc::new(SqliteTenantStore::open(p("tenants.db")).unwrap());
    let acme = tenants.create_tenant("acme").unwrap();
    let globex = tenants.create_tenant("globex").unwrap();
    tenants.assign_host(acme_host, acme.tenant_id).unwrap();
    tenants.assign_host(globex_host, globex.tenant_id).unwrap();

    let (user_store, _bootstrap) = SqliteUserStore::open(p("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let admin_token = user_store.create_session(admin.user_id, 3600).unwrap().token;
    let tenant_token = |name: &str, tenant: Uuid| {
        let user = user_store
            .create_user(NewUser {
                username: name.to_string(),
                password_hash: osiris_auth::hash_password("password123").unwrap(),
                role: Role::Admin,
                tenant_id: Some(tenant),
            })
            .unwrap();
        user_store.create_session(user.user_id, 3600).unwrap().token
    };
    let acme_token = tenant_token("acme-admin", acme.tenant_id);
    let globex_token = tenant_token("globex-admin", globex.tenant_id);

    let auth_state = AuthState {
        users: Arc::new(user_store),
        audit_log: audit_log.clone(),
        session_ttl_seconds: 3600,
        tenants: tenants.clone(),
    };
    let broadcaster = Arc::new(LiveEventBroadcaster::new());
    let app = build_app(
        storage,
        incident_evidence_state,
        response_state,
        broadcaster.clone(),
        auth_state.clone(),
    );

    Tenancy {
        _dir: dir,
        app,
        tenants,
        auth_state,
        broadcaster,
        admin_token,
        acme_token,
        globex_token,
        acme_tenant: acme.tenant_id,
        globex_tenant: globex.tenant_id,
        acme_host,
        globex_host,
        unassigned_host,
        globex_process_key,
    }
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    let request = match body {
        Some(json) => builder
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

fn host_ids_of(events: &serde_json::Value) -> Vec<String> {
    events
        .as_array()
        .expect("an array response")
        .iter()
        .map(|e| e["host_id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_tenant_user_sees_only_its_own_hosts_events() {
    let t = tenancy();
    let (status, body) = call(&t.app, "GET", "/api/v1/events", Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(host_ids_of(&body), vec![t.acme_host.to_string()]);
    let (_, body) = call(&t.app, "GET", "/api/v1/events", Some(&t.globex_token), None).await;
    assert_eq!(host_ids_of(&body), vec![t.globex_host.to_string()]);
}

#[tokio::test]
async fn a_platform_user_sees_every_host_including_unassigned() {
    let t = tenancy();
    let (status, body) = call(&t.app, "GET", "/api/v1/events", Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let mut hosts = host_ids_of(&body);
    hosts.sort();
    let mut expected = vec![
        t.acme_host.to_string(),
        t.globex_host.to_string(),
        t.unassigned_host.to_string(),
    ];
    expected.sort();
    assert_eq!(hosts, expected);
}

#[tokio::test]
async fn the_hosts_endpoint_lists_only_the_tenants_hosts() {
    let t = tenancy();
    let (status, body) = call(&t.app, "GET", "/api/v1/hosts", Some(&t.globex_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(host_ids_of(&body), vec![t.globex_host.to_string()]);
    let (_, all) = call(&t.app, "GET", "/api/v1/hosts", Some(&t.admin_token), None).await;
    assert_eq!(all.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn a_tenant_user_cannot_read_platform_only_routes_even_as_a_tenant_admin() {
    let t = tenancy();
    for (method, uri) in [
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/evidence"),
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/auth/users"),
        ("POST", "/api/v1/response/collect_evidence"),
    ] {
        let body = (method == "POST").then(|| serde_json::json!({}));
        let (status, _) = call(&t.app, method, uri, Some(&t.acme_token), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri} must be 403 for a tenant user");
    }
    // The same audit route is reachable for the platform admin.
    let (status, _) = call(&t.app, "GET", "/api/v1/audit", Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_process_belonging_to_another_tenant_is_not_readable_by_key() {
    let t = tenancy();
    let uri = format!("/api/v1/processes/{}", t.globex_process_key);
    // The owning tenant and the platform admin can read it...
    let (status, _) = call(&t.app, "GET", &uri, Some(&t.globex_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&t.app, "GET", &uri, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    // ...another tenant gets exactly what a nonexistent process gets (404).
    let (status, _) = call(&t.app, "GET", &uri, Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reassigning_a_host_changes_visibility_immediately() {
    let t = tenancy();
    let (_, before) = call(&t.app, "GET", "/api/v1/events", Some(&t.acme_token), None).await;
    assert_eq!(host_ids_of(&before).len(), 1);
    t.tenants.assign_host(t.globex_host, t.acme_tenant).unwrap();
    let (_, after) = call(&t.app, "GET", "/api/v1/events", Some(&t.acme_token), None).await;
    let mut hosts = host_ids_of(&after);
    hosts.sort();
    let mut expected = vec![t.acme_host.to_string(), t.globex_host.to_string()];
    expected.sort();
    assert_eq!(hosts, expected);
    // globex_tenant / broadcaster are used by later tasks' tests.
    let _ = (t.globex_tenant, &t.broadcaster);
}

#[tokio::test]
async fn a_tenant_with_no_hosts_sees_nothing_not_everything() {
    let t = tenancy();
    let empty = t.tenants.create_tenant("empty-corp").unwrap();
    let user = t
        .auth_state
        .users
        .create_user(NewUser {
            username: "empty-viewer".to_string(),
            password_hash: osiris_auth::hash_password("password123").unwrap(),
            role: Role::Viewer,
            tenant_id: Some(empty.tenant_id),
        })
        .unwrap();
    let token = t.auth_state.users.create_session(user.user_id, 3600).unwrap().token;
    let (status, body) = call(&t.app, "GET", "/api/v1/events", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty(), "no hosts must mean no data");
    let (_, hosts) = call(&t.app, "GET", "/api/v1/hosts", Some(&token), None).await;
    assert!(hosts.as_array().unwrap().is_empty());
}
