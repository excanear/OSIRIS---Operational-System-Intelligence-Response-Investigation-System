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
    auth_gate, build_auth_router, build_incident_evidence_router, build_router,
    build_stream_router, AuthState, IncidentEvidenceState, LiveEventBroadcaster,
};
use osiris_audit::FileAuditLog;
use osiris_auth::{SqliteUserStore, UserStore};
use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;
use tower::ServiceExt;

struct Harness {
    _dir: tempfile::TempDir,
    app: axum::Router,
    admin_token: String,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name);

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(p("events.db")).unwrap());
    let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> =
        Arc::new(FileAuditLog::open(p("audit.jsonl")).unwrap());

    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(SqliteIncidentStore::open(p("incidents.db").to_str().unwrap()).unwrap()),
        evidence: Arc::new(SqliteEvidenceStore::open(p("evidence.db").to_str().unwrap()).unwrap()),
        links: Arc::new(
            SqliteEvidenceIncidentLinks::open(p("links.db").to_str().unwrap()).unwrap(),
        ),
        audit_log: audit_log.clone(),
    };

    let (user_store, _bootstrap) = SqliteUserStore::open(p("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let admin_token = user_store.create_session(admin.user_id, 3600).unwrap().token;

    let auth_state = AuthState {
        users: Arc::new(user_store),
        audit_log,
        session_ttl_seconds: 3600,
    };

    // The exact composition from `osiris-server/src/main.rs`.
    let app = build_router(storage)
        .merge(build_incident_evidence_router(incident_evidence_state))
        .merge(build_stream_router(Arc::new(LiveEventBroadcaster::new())))
        .merge(build_auth_router(auth_state.clone()))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate));

    Harness {
        _dir: dir,
        app,
        admin_token,
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
