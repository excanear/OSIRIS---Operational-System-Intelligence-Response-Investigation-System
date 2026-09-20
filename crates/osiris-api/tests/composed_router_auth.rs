//! Proves the *composed* router — assembled exactly the way
//! `osiris-server/src/main.rs` assembles it: all four sub-routers merged,
//! then a single `auth_gate` layer over the whole thing — actually gates
//! requests. Every other test in the workspace exercises one sub-router (or
//! `auth_gate` over stub routes); nothing else exercises the real
//! composition, which is where a merge-order or layer-placement mistake
//! would silently disable authentication for a whole crate's worth of
//! routes.

use std::sync::Arc;

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
use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;
use tower::ServiceExt;

struct Harness {
    _dir: tempfile::TempDir,
    app: axum::Router,
    admin_token: String,
    auth_state: AuthState,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name);

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(p("events.db")).unwrap());
    let storage_for_router = storage.clone();
    let incident_evidence_storage_for_response = storage.clone();
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

    let (user_store, _bootstrap) = SqliteUserStore::open(p("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let admin_token = user_store
        .create_session(admin.user_id, 3600)
        .unwrap()
        .token;

    let auth_state = AuthState {
        users: Arc::new(user_store),
        audit_log: audit_log.clone(),
        session_ttl_seconds: 3600,
        tenants: Arc::new(osiris_tenancy::SqliteTenantStore::open(p("tenants.db")).unwrap()),
    };

    // Reuses the SAME `SqliteEvidenceStore`/`SqliteEvidenceIncidentLinks`
    // instances (and audit_log) the incident/evidence state above built —
    // exactly how `osiris-server/src/main.rs` constructs `ResponseState`,
    // not a separate set of stores.
    let response_state = ResponseState {
        commands: Arc::new(osiris_response::DisabledDispatcher),
        storage: incident_evidence_storage_for_response,
        evidence: incident_evidence_state.evidence.clone(),
        links: incident_evidence_state.links.clone(),
        incidents: incident_evidence_state.incidents.clone(),
        audit_log: audit_log.clone(),
    };

    // The exact composition from `osiris-server/src/main.rs`: build_router,
    // build_incident_evidence_router, build_response_router,
    // build_stream_router, build_auth_router, then the auth_gate layer.
    let app = build_router(storage_for_router)
        .merge(build_incident_evidence_router(incident_evidence_state))
        .merge(build_response_router(response_state))
        .merge(build_stream_router(Arc::new(LiveEventBroadcaster::new())))
        .merge(build_auth_router(auth_state.clone()))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            auth_gate,
        ));

    Harness {
        _dir: dir,
        app,
        admin_token,
        auth_state,
    }
}

#[tokio::test]
async fn health_is_reachable_on_the_composed_router_without_a_token() {
    let h = harness();

    let response = h
        .app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_phase_1_route_is_401_without_a_token_and_200_with_one() {
    let h = harness();

    let anonymous = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/processes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let authenticated = h
        .app
        .oneshot(
            Request::builder()
                .uri("/api/v1/processes")
                .header("Authorization", format!("Bearer {}", h.admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_hosts_route_is_401_without_a_token_and_200_with_one_on_the_composed_router() {
    let h = harness();

    let anonymous = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/hosts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let authenticated = h
        .app
        .oneshot(
            Request::builder()
                .uri("/api/v1/hosts")
                .header("Authorization", format!("Bearer {}", h.admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
}

// --- Fix 2: the real Response Engine route, through the real composed router ---

fn session_for_role(state: &AuthState, username: &str, role: Role) -> String {
    let user = state
        .users
        .create_user(NewUser {
            username: username.to_string(),
            password_hash: osiris_auth::hash_password("password123").unwrap(),
            role,
            tenant_id: None,
        })
        .unwrap();
    state
        .users
        .create_session(user.user_id, 3600)
        .unwrap()
        .token
}

fn collect_evidence_body() -> String {
    serde_json::json!({
        "target": { "kind": "DOMAIN", "name": "never-seen-in-composed-router-test.example" },
        "reason": "composed router auth check",
        "dry_run": true,
        "since": null,
        "until": null,
        "incident_id": null
    })
    .to_string()
}

#[tokio::test]
async fn the_response_route_is_401_without_a_token_on_the_composed_router() {
    let h = harness();

    let response = h
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/response/collect_evidence")
                .header("content-type", "application/json")
                .body(Body::from(collect_evidence_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_response_route_is_403_for_a_role_below_response_operator_on_the_composed_router() {
    let h = harness();
    let analyst_token = session_for_role(&h.auth_state, "composed-analyst", Role::Analyst);

    let response = h
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/response/collect_evidence")
                .header("Authorization", format!("Bearer {analyst_token}"))
                .header("content-type", "application/json")
                .body(Body::from(collect_evidence_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_response_route_is_not_401_or_403_for_the_admin_token_on_the_composed_router() {
    let h = harness();

    // Admin outranks ResponseOperator in `Role`'s declaration-order `Ord`
    // (Viewer < Analyst < ResponseOperator < Admin), so the admin token must
    // clear auth_gate. The bare-storage harness has no matching target, so
    // this dry-run resolves to a 400 ("target does not resolve to any known
    // data") from the real `response_handler` itself — the point here is
    // proving the real auth_gate + real response_handler compose correctly,
    // not exercising a successful dry-run (that's covered in osiris-api's
    // own response.rs unit tests).
    let response = h
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/response/collect_evidence")
                .header("Authorization", format!("Bearer {}", h.admin_token))
                .header("content-type", "application/json")
                .body(Body::from(collect_evidence_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}
