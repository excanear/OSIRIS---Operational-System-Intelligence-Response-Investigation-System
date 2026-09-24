//! Tenant isolation through the REAL composed router (same composition as
//! `osiris-server/src/main.rs`): two tenants, one unassigned host, a platform
//! admin, and a tenant Admin per tenant.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use osiris_api::{
    auth_gate, build_auth_router, build_fleet_router, build_incident_evidence_router,
    build_response_router, build_router, build_stream_router, AuthState, FleetState,
    IncidentEvidenceState, LiveEventBroadcaster, ResponseState,
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
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
    acme_process_key: String,
}

fn build_app(
    storage: Arc<dyn Storage>,
    incident_evidence_state: IncidentEvidenceState,
    response_state: ResponseState,
    broadcaster: Arc<LiveEventBroadcaster>,
    auth_state: AuthState,
    fleet_state: FleetState,
) -> axum::Router {
    build_router(storage)
        .merge(build_incident_evidence_router(incident_evidence_state))
        .merge(build_response_router(response_state))
        .merge(build_stream_router(broadcaster))
        .merge(build_auth_router(auth_state.clone()))
        .merge(osiris_api::build_tenant_router(auth_state.clone()))
        .merge(build_fleet_router(fleet_state))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate))
}

fn tenancy() -> Tenancy {
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name);

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(p("events.db")).unwrap());
    let (acme_host, globex_host, unassigned_host) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let t = now_ns();
    let acme_event = event_on(acme_host, 1, t);
    let acme_process_key = acme_event.process.as_ref().unwrap().process_key.as_hex();
    let globex_event = event_on(globex_host, 2, t);
    let globex_process_key = globex_event.process.as_ref().unwrap().process_key.as_hex();
    storage
        .batch_write(&[acme_event, globex_event, event_on(unassigned_host, 3, t)])
        .unwrap();

    let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> =
        Arc::new(FileAuditLog::open(p("audit.jsonl")).unwrap());
    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(
            SqliteIncidentStore::open(p("incidents.db").to_str().unwrap()).unwrap(),
        ),
        evidence: Arc::new(SqliteEvidenceStore::open(p("evidence.db").to_str().unwrap()).unwrap()),
        links: Arc::new(
            SqliteEvidenceIncidentLinks::open(p("links.db").to_str().unwrap()).unwrap(),
        ),
        storage: storage.clone(),
        audit_log: audit_log.clone(),
    };
    let response_state = ResponseState {
        commands: Arc::new(osiris_response::DisabledDispatcher),
        storage: storage.clone(),
        evidence: incident_evidence_state.evidence.clone(),
        links: incident_evidence_state.links.clone(),
        incidents: incident_evidence_state.incidents.clone(),
        audit_log: audit_log.clone(),
    };

    let tenants: Arc<dyn TenantStore> = Arc::new(SqliteTenantStore::open(p("tenants.db")).unwrap());
    let acme = tenants.create_tenant("acme").unwrap();
    let globex = tenants.create_tenant("globex").unwrap();
    tenants.assign_host(acme_host, acme.tenant_id).unwrap();
    tenants.assign_host(globex_host, globex.tenant_id).unwrap();

    let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> =
        Arc::new(osiris_fleet::SqliteHostRegistry::open(p("hosts.db")).unwrap());
    let heartbeat = |host_id: Uuid| osiris_fleet::HostRow {
        host_id,
        hostname: format!("host-{host_id}"),
        distro: "ubuntu-24.04".to_string(),
        kernel_version: "6.8.0".to_string(),
        agent_version: "0.1.0".to_string(),
        enrolled_at: t,
        last_seen: t,
        health_state: osiris_health::HealthState::Healthy,
    };
    fleet_registry
        .upsert_heartbeat(heartbeat(acme_host))
        .unwrap();
    fleet_registry
        .upsert_heartbeat(heartbeat(globex_host))
        .unwrap();
    fleet_registry
        .upsert_heartbeat(heartbeat(unassigned_host))
        .unwrap();

    let (user_store, _bootstrap) = SqliteUserStore::open(p("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let admin_token = user_store
        .create_session(admin.user_id, 3600)
        .unwrap()
        .token;
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
    let fleet_state = FleetState {
        registry: fleet_registry,
        tenants: tenants.clone(),
    };
    let app = build_app(
        storage,
        incident_evidence_state,
        response_state,
        broadcaster.clone(),
        auth_state.clone(),
        fleet_state,
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
        acme_process_key,
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
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
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
    for (method, uri) in [("GET", "/api/v1/auth/users")] {
        let body = (method == "POST").then(|| serde_json::json!({}));
        let (status, _) = call(&t.app, method, uri, Some(&t.acme_token), body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must be 403 for a tenant user"
        );
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
    let token = t
        .auth_state
        .users
        .create_session(user.user_id, 3600)
        .unwrap()
        .token;
    let (status, body) = call(&t.app, "GET", "/api/v1/events", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.as_array().unwrap().is_empty(),
        "no hosts must mean no data"
    );
    let (_, hosts) = call(&t.app, "GET", "/api/v1/hosts", Some(&token), None).await;
    assert!(hosts.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_tenants_websocket_receives_only_its_hosts_events_and_rejects_foreign_host_ids() {
    use futures_util::StreamExt;
    use std::time::Duration;

    let t = tenancy();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = t.app.clone();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("ws://{addr}/api/v1/stream/events?token={}", t.acme_token);
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    // Let the server register the subscription before publishing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    t.broadcaster.publish(&[
        event_on(t.globex_host, 10, now_ns()),
        event_on(t.acme_host, 11, now_ns()),
    ]);
    let message = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("the acme event must arrive")
        .unwrap()
        .unwrap();
    let event: CanonicalEvent = serde_json::from_str(message.to_text().unwrap()).unwrap();
    assert_eq!(event.host_id, t.acme_host);
    // The globex event was filtered out: nothing else arrives.
    assert!(tokio::time::timeout(Duration::from_millis(300), ws.next())
        .await
        .is_err());

    // Asking for another tenant's host is rejected at the handshake with 403.
    let url = format!(
        "ws://{addr}/api/v1/stream/events?token={}&host_id={}",
        t.acme_token, t.globex_host
    );
    match tokio_tungstenite::connect_async(url).await.unwrap_err() {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(response.status(), 403)
        }
        other => panic!("expected an HTTP 403 handshake error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_platform_admin_can_create_a_tenant_assign_and_unassign_a_host() {
    let t = tenancy();
    let (status, body) = call(
        &t.app,
        "POST",
        "/api/v1/tenants",
        Some(&t.admin_token),
        Some(serde_json::json!({ "name": "initech" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tenant_id = Uuid::parse_str(body["tenant_id"].as_str().unwrap()).unwrap();
    let host = Uuid::new_v4();
    let uri = format!("/api/v1/tenants/{tenant_id}/hosts/{host}");

    let (status, _) = call(&t.app, "PUT", &uri, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(t.tenants.hosts_of(tenant_id).unwrap().contains(&host));

    let (status, list) = call(&t.app, "GET", "/api/v1/tenants", Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["name"] == "initech"));

    let (status, _) = call(&t.app, "DELETE", &uri, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(t.tenants.tenant_of(host).unwrap(), None);
}

#[tokio::test]
async fn creating_a_duplicate_tenant_name_is_a_400() {
    let t = tenancy();
    let (status, _) = call(
        &t.app,
        "POST",
        "/api/v1/tenants",
        Some(&t.admin_token),
        Some(serde_json::json!({ "name": "acme" })), // already created by the harness
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_tenant_user_cannot_manage_tenants() {
    let t = tenancy();
    let host = Uuid::new_v4();
    let (status, _) = call(
        &t.app,
        "POST",
        "/api/v1/tenants",
        Some(&t.acme_token),
        Some(serde_json::json!({ "name": "sneaky" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&t.app, "GET", "/api/v1/tenants", Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A tenant Admin must not be able to pull another tenant's host to itself.
    let uri = format!("/api/v1/tenants/{}/hosts/{host}", t.acme_tenant);
    let (status, _) = call(&t.app, "PUT", &uri, Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(t.tenants.tenant_of(host).unwrap(), None);
    assert!(
        !t.tenants
            .list_tenants()
            .unwrap()
            .iter()
            .any(|x| x.name == "sneaky"),
        "a tenant user must not have been able to create a tenant"
    );
}

#[tokio::test]
async fn unassigning_through_the_wrong_tenants_url_is_a_404_and_changes_nothing() {
    let t = tenancy();
    let host = t.globex_host; // assigned to globex
    let wrong = format!("/api/v1/tenants/{}/hosts/{host}", t.acme_tenant);
    let (status, _) = call(&t.app, "DELETE", &wrong, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(t.tenants.tenant_of(host).unwrap(), Some(t.globex_tenant));

    let right = format!("/api/v1/tenants/{}/hosts/{host}", t.globex_tenant);
    let (status, _) = call(&t.app, "DELETE", &right, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(t.tenants.tenant_of(host).unwrap(), None);
}

#[tokio::test]
async fn assigning_a_host_to_an_unknown_tenant_is_404() {
    let t = tenancy();
    let uri = format!(
        "/api/v1/tenants/{}/hosts/{}",
        Uuid::new_v4(),
        Uuid::new_v4()
    );
    let (status, _) = call(&t.app, "PUT", &uri, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn creating_a_user_bound_to_a_tenant_works_and_login_reports_the_tenant() {
    let t = tenancy();
    let (status, _) = call(
        &t.app,
        "POST",
        "/api/v1/auth/users",
        Some(&t.admin_token),
        Some(serde_json::json!({
            "username": "bob", "password": "password123", "role": "VIEWER",
            "tenant_id": t.acme_tenant,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, login) = call(
        &t.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(serde_json::json!({ "username": "bob", "password": "password123" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(login["tenant_id"], serde_json::json!(t.acme_tenant));
    assert_eq!(login["tenant_name"], "acme");

    // A platform user's login carries no tenant.
    let (status, _) = call(
        &t.app,
        "POST",
        "/api/v1/auth/users",
        Some(&t.admin_token),
        Some(
            serde_json::json!({ "username": "plat", "password": "password123", "role": "VIEWER" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, login) = call(
        &t.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(serde_json::json!({ "username": "plat", "password": "password123" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        login["tenant_id"].is_null(),
        "platform login must carry a null tenant_id: {login}"
    );

    let (status, unknown) = call(
        &t.app,
        "POST",
        "/api/v1/auth/users",
        Some(&t.admin_token),
        Some(serde_json::json!({
            "username": "carol", "password": "password123", "role": "VIEWER",
            "tenant_id": Uuid::new_v4(),
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown tenant must be rejected: {unknown}"
    );

    // A tenant Admin cannot mint users (platform-only).
    let (status, _) = call(
        &t.app,
        "POST",
        "/api/v1/auth/users",
        Some(&t.acme_token),
        Some(
            serde_json::json!({ "username": "dave", "password": "password123", "role": "VIEWER" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

fn incident_body() -> serde_json::Value {
    serde_json::json!({ "entities": [{ "kind": "IP", "addr": "203.0.113.10" }] })
}

fn process_incident(process_key: &str) -> serde_json::Value {
    serde_json::json!({ "entities": [{ "kind": "PROCESS", "process_key": process_key }] })
}

#[tokio::test]
async fn a_tenant_cannot_reference_entities_outside_its_own_data() {
    let t = tenancy();
    // Another tenant's process, and an entity that exists nowhere: both 400.
    for body in [process_incident(&t.globex_process_key), incident_body()] {
        let (s, _) = call(
            &t.app,
            "POST",
            "/api/v1/incidents",
            Some(&t.acme_token),
            Some(body),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    // Evidence relationships are held to the same rule.
    let ev = serde_json::json!({
        "source": "MANUAL_UPLOAD", "hash": "abc", "immutable_since": 1, "supersedes": null,
        "relationships": [{ "kind": "PROCESS", "process_key": t.globex_process_key }],
    });
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/evidence",
        Some(&t.acme_token),
        Some(ev),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // The platform is not restricted.
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/incidents",
        Some(&t.admin_token),
        Some(incident_body()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn incidents_are_isolated_per_tenant_and_foreign_ids_look_missing() {
    let t = tenancy();
    let (status, created) = call(
        &t.app,
        "POST",
        "/api/v1/incidents",
        Some(&t.acme_token),
        Some(process_incident(&t.acme_process_key)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let id = created["incident_id"].as_str().unwrap().to_string();
    assert_eq!(created["tenant_id"], t.acme_tenant.to_string());
    let (_, platform) = call(
        &t.app,
        "POST",
        "/api/v1/incidents",
        Some(&t.admin_token),
        Some(incident_body()),
    )
    .await;
    let platform_id = platform["incident_id"].as_str().unwrap().to_string();

    let uri = format!("/api/v1/incidents/{id}");
    let (s, _) = call(&t.app, "GET", &uri, Some(&t.acme_token), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&t.app, "GET", &uri, Some(&t.globex_token), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &t.app,
        "PATCH",
        &uri,
        Some(&t.globex_token),
        Some(serde_json::json!({ "status": "RESOLVED" })),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A platform-owned incident is invisible to a tenant.
    let (s, _) = call(
        &t.app,
        "GET",
        &format!("/api/v1/incidents/{platform_id}"),
        Some(&t.acme_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (_, mine) = call(
        &t.app,
        "GET",
        "/api/v1/incidents",
        Some(&t.acme_token),
        None,
    )
    .await;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    let (_, theirs) = call(
        &t.app,
        "GET",
        "/api/v1/incidents",
        Some(&t.globex_token),
        None,
    )
    .await;
    assert!(theirs.as_array().unwrap().is_empty());
    let (_, all) = call(
        &t.app,
        "GET",
        "/api/v1/incidents",
        Some(&t.admin_token),
        None,
    )
    .await;
    assert_eq!(all.as_array().unwrap().len(), 2);

    // The owning tenant can still transition it.
    let (s, updated) = call(
        &t.app,
        "PATCH",
        &uri,
        Some(&t.acme_token),
        Some(serde_json::json!({ "status": "INVESTIGATING" })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{updated}");
}

#[tokio::test]
async fn evidence_and_links_never_cross_tenants() {
    let t = tenancy();
    let (_, inc) = call(
        &t.app,
        "POST",
        "/api/v1/incidents",
        Some(&t.acme_token),
        Some(process_incident(&t.acme_process_key)),
    )
    .await;
    let inc_id = inc["incident_id"].as_str().unwrap().to_string();
    let ev = |incident: Option<&str>| {
        serde_json::json!({
            "source": "MANUAL_UPLOAD", "hash": "abc", "immutable_since": 1,
            "relationships": [], "supersedes": null, "incident_id": incident,
        })
    };
    // Globex cannot attach evidence to acme's incident.
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/evidence",
        Some(&t.globex_token),
        Some(ev(Some(&inc_id))),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Acme can, and the record is tenant-tagged.
    let (s, created) = call(
        &t.app,
        "POST",
        "/api/v1/evidence",
        Some(&t.acme_token),
        Some(ev(Some(&inc_id))),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{created}");
    let acme_ev = created["evidence_id"].as_str().unwrap().to_string();
    // A tenant cannot supersede another tenant's evidence.
    let mut supersede = ev(None);
    supersede["supersedes"] = serde_json::json!(acme_ev);
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/evidence",
        Some(&t.globex_token),
        Some(supersede),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (_, mine) = call(&t.app, "GET", "/api/v1/evidence", Some(&t.acme_token), None).await;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    assert_eq!(mine[0]["incident_ids"][0], inc_id);
    let (_, theirs) = call(
        &t.app,
        "GET",
        "/api/v1/evidence",
        Some(&t.globex_token),
        None,
    )
    .await;
    assert!(theirs.as_array().unwrap().is_empty());
    let (s, _) = call(
        &t.app,
        "GET",
        &format!("/api/v1/evidence?incident_id={inc_id}"),
        Some(&t.globex_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, all) = call(
        &t.app,
        "GET",
        "/api/v1/evidence",
        Some(&t.admin_token),
        None,
    )
    .await;
    assert_eq!(all.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn the_response_engine_only_sees_the_tenants_own_hosts() {
    let t = tenancy();
    let body = |key: &str| {
        serde_json::json!({
            "target": { "kind": "PROCESS", "process_key": key },
            "reason": "investigating", "dry_run": true,
        })
    };
    // Own process resolves; another tenant's process is "unknown" (400).
    let (s, resp) = call(
        &t.app,
        "POST",
        "/api/v1/response/collect_evidence",
        Some(&t.acme_token),
        Some(body(&t.acme_process_key)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{resp}");
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/response/collect_evidence",
        Some(&t.acme_token),
        Some(body(&t.globex_process_key)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Real collection is tagged with the tenant and invisible to the other one.
    let mut real = body(&t.acme_process_key);
    real["dry_run"] = serde_json::json!(false);
    let (s, resp) = call(
        &t.app,
        "POST",
        "/api/v1/response/collect_evidence",
        Some(&t.acme_token),
        Some(real.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{resp}");
    let (_, mine) = call(&t.app, "GET", "/api/v1/evidence", Some(&t.acme_token), None).await;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    let (_, theirs) = call(
        &t.app,
        "GET",
        "/api/v1/evidence",
        Some(&t.globex_token),
        None,
    )
    .await;
    assert!(theirs.as_array().unwrap().is_empty());

    // A foreign incident cannot be used as a link target.
    let (_, inc) = call(
        &t.app,
        "POST",
        "/api/v1/incidents",
        Some(&t.globex_token),
        Some(process_incident(&t.globex_process_key)),
    )
    .await;
    real["incident_id"] = inc["incident_id"].clone();
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/response/collect_evidence",
        Some(&t.acme_token),
        Some(real),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_tenant_admin_sees_only_its_own_tenants_audit_entries() {
    let t = tenancy();
    let dry_run = |key: &str| {
        serde_json::json!({
            "target": { "kind": "PROCESS", "process_key": key },
            "reason": "investigating", "dry_run": true,
        })
    };
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/response/collect_evidence",
        Some(&t.acme_token),
        Some(dry_run(&t.acme_process_key)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &t.app,
        "POST",
        "/api/v1/response/collect_evidence",
        Some(&t.globex_token),
        Some(dry_run(&t.globex_process_key)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let actors = |body: &serde_json::Value| -> std::collections::HashSet<String> {
        body.as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["who"]["user_id"].as_str().map(str::to_string))
            .collect()
    };
    let (s, acme) = call(&t.app, "GET", "/api/v1/audit", Some(&t.acme_token), None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, globex) = call(&t.app, "GET", "/api/v1/audit", Some(&t.globex_token), None).await;
    let (_, all) = call(&t.app, "GET", "/api/v1/audit", Some(&t.admin_token), None).await;

    assert_eq!(acme.as_array().unwrap().len(), 1);
    assert_eq!(globex.as_array().unwrap().len(), 1);
    assert!(actors(&acme).is_disjoint(&actors(&globex)));
    assert!(
        all.as_array().unwrap().len() >= 2,
        "the platform sees everything"
    );
}
