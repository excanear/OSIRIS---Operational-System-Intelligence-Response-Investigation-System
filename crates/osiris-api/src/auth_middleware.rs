use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use osiris_auth::Role;
use uuid::Uuid;

use crate::auth::AuthState;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub role: Role,
    pub token: String,
}

/// The one route whose token may arrive as a `?token=` query parameter
/// instead of an `Authorization` header. Browsers cannot set headers on a
/// native `WebSocket` upgrade, so the Console has no other way to
/// authenticate the Live Events stream. A query-param token is more
/// log-leakage-prone than a header, so this exception is deliberately
/// narrow: exactly this path, and nothing else.
const QUERY_TOKEN_PATH: &str = "/api/v1/stream/events";

/// Extracts the `token` value from a URI query string (`a=1&token=xyz&b=2`).
/// Only the first `token` key is honoured.
fn token_from_query(query: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key == "token" && !value.is_empty() {
            Some(percent_decode(value))
        } else {
            None
        }
    })
}

/// Minimal `application/x-www-form-urlencoded` value decoding (`+` → space,
/// `%XX` → byte). Session tokens are hex/URL-safe in practice, but a client
/// is free to percent-encode them, so decode rather than compare raw.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&value[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The minimum role a request needs, by HTTP method *and* path.
///
/// Method-awareness matters: the same path is Viewer-readable via `GET` and
/// Analyst-only via `POST`/`PATCH`. And `/api/v1/incidents/:incident_id` is
/// an axum *template* — a real request path carries a UUID there, never the
/// literal `:incident_id` — so that route is matched by prefix, not equality.
fn min_role_for(method: &axum::http::Method, path: &str) -> Role {
    use axum::http::Method;

    if path == "/api/v1/audit" || path == "/api/v1/auth/users" {
        return Role::Admin;
    }
    if method == Method::POST && path == "/api/v1/incidents" {
        return Role::Analyst;
    }
    if method == Method::PATCH && path.starts_with("/api/v1/incidents/") {
        return Role::Analyst;
    }
    if method == Method::POST && path == "/api/v1/evidence" {
        return Role::Analyst;
    }
    Role::Viewer
}

pub async fn auth_gate(State(state): State<AuthState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path == "/api/v1/health" || path == "/api/v1/auth/login" {
        return next.run(req).await;
    }

    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string())
        .or_else(|| {
            // Query-param fallback — the Live Events WebSocket route ONLY.
            if path == QUERY_TOKEN_PATH {
                req.uri().query().and_then(token_from_query)
            } else {
                None
            }
        });

    let Some(token) = token else {
        return unauthorized();
    };

    let session = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let token = token.clone();
        move || users.get_session(&token)
    })
    .await
    .unwrap();

    let session = match session {
        Ok(Some(s)) => s,
        _ => return unauthorized(),
    };

    let user = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let user_id = session.user_id;
        move || users.get_user_by_id(user_id)
    })
    .await
    .unwrap();

    let user = match user {
        Ok(Some(u)) => u,
        _ => return unauthorized(),
    };

    if user.role < min_role_for(req.method(), &path) {
        return forbidden();
    }

    req.extensions_mut().insert(AuthContext {
        user_id: user.user_id,
        role: user.role,
        token,
    });

    next.run(req).await
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "forbidden" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use axum::Router;
    use osiris_auth::{NewUser, SqliteUserStore};
    use tower::ServiceExt;

    fn test_state() -> (tempfile::TempDir, tempfile::TempDir, AuthState) {
        let users_dir = tempfile::tempdir().unwrap();
        let (store, _bootstrap) =
            SqliteUserStore::open(users_dir.path().join("users.db")).unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit_log = osiris_audit::FileAuditLog::open(audit_dir.path().join("audit.jsonl")).unwrap();
        let state = AuthState {
            users: std::sync::Arc::new(store),
            audit_log: std::sync::Arc::new(audit_log),
            session_ttl_seconds: 3600,
        };
        (users_dir, audit_dir, state)
    }

    fn protected_app(state: AuthState) -> Router {
        Router::new()
            .route("/api/v1/protected", get(|| async { "ok" }))
            .route("/api/v1/audit", get(|| async { "admin-ok" }))
            .route("/api/v1/stream/events", get(|| async { "stream-ok" }))
            // Stubs that mirror the *shapes* of the real Phase 7a routes, so
            // this exercises `auth_gate` + `min_role_for` against a router
            // that actually matches `/api/v1/incidents/:incident_id`.
            .route(
                "/api/v1/incidents",
                get(|| async { "list-ok" }).post(|| async { "create-ok" }),
            )
            .route(
                "/api/v1/incidents/:incident_id",
                get(|| async { "get-ok" }).patch(|| async { "patch-ok" }),
            )
            .route(
                "/api/v1/evidence",
                get(|| async { "list-ok" }).post(|| async { "create-ok" }),
            )
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth_gate))
            .with_state(state)
    }

    fn session_for_role(state: &AuthState, username: &str, role: Role) -> String {
        let user = state
            .users
            .create_user(NewUser {
                username: username.to_string(),
                password_hash: osiris_auth::hash_password("password123").unwrap(),
                role,
            })
            .unwrap();
        state
            .users
            .create_session(user.user_id, 3600)
            .unwrap()
            .token
    }

    #[tokio::test]
    async fn a_request_with_no_token_is_rejected_with_401() {
        let (_d1, _d2, state) = test_state();
        let app = protected_app(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_valid_token_reaches_a_viewer_level_route() {
        let (_d1, _d2, state) = test_state();
        let admin = state.users.get_user_by_username("admin").unwrap().unwrap();
        let session = state.users.create_session(admin.user_id, 3600).unwrap();
        let app = protected_app(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/protected")
                    .header("Authorization", format!("Bearer {}", session.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_non_admin_token_is_rejected_from_an_admin_only_route_with_403() {
        let (_d1, _d2, state) = test_state();
        let viewer = state
            .users
            .create_user(NewUser {
                username: "viewer1".to_string(),
                password_hash: osiris_auth::hash_password("pw").unwrap(),
                role: Role::Viewer,
            })
            .unwrap();
        let session = state.users.create_session(viewer.user_id, 3600).unwrap();
        let app = protected_app(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/audit")
                    .header("Authorization", format!("Bearer {}", session.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_unknown_token_is_rejected_with_401() {
        let (_d1, _d2, state) = test_state();
        let app = protected_app(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/protected")
                    .header("Authorization", "Bearer not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Fix 1: query-param token, stream route only ---

    #[tokio::test]
    async fn the_stream_route_accepts_a_token_from_the_query_string() {
        let (_d1, _d2, state) = test_state();
        let admin = state.users.get_user_by_username("admin").unwrap().unwrap();
        let session = state.users.create_session(admin.user_id, 3600).unwrap();
        let app = protected_app(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri(format!(
                        "/api/v1/stream/events?host_id=h1&token={}",
                        session.token
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_stream_route_still_401s_on_a_bad_or_missing_query_token() {
        let (_d1, _d2, state) = test_state();
        let app = protected_app(state);

        let bad = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/stream/events?token=not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

        let missing = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/stream/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_query_param_token_fallback_does_not_apply_to_any_other_route() {
        let (_d1, _d2, state) = test_state();
        let admin = state.users.get_user_by_username("admin").unwrap().unwrap();
        let session = state.users.create_session(admin.user_id, 3600).unwrap();
        let app = protected_app(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/api/v1/protected?token={}", session.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Fix 2: method-aware minimum roles ---

    #[test]
    fn min_role_for_is_method_aware_on_the_mutating_investigation_routes() {
        use axum::http::Method;

        // Admin-only, any method.
        assert_eq!(min_role_for(&Method::GET, "/api/v1/audit"), Role::Admin);
        assert_eq!(
            min_role_for(&Method::GET, "/api/v1/auth/users"),
            Role::Admin
        );
        assert_eq!(
            min_role_for(&Method::POST, "/api/v1/auth/users"),
            Role::Admin
        );

        // Mutating investigation routes require Analyst.
        assert_eq!(
            min_role_for(&Method::POST, "/api/v1/incidents"),
            Role::Analyst
        );
        assert_eq!(
            min_role_for(&Method::POST, "/api/v1/evidence"),
            Role::Analyst
        );
        assert_eq!(
            min_role_for(
                &Method::PATCH,
                "/api/v1/incidents/019299f0-0d2b-7c41-9a8e-3d2b4c5e6f70"
            ),
            Role::Analyst
        );

        // Reads of the same routes stay Viewer-level.
        assert_eq!(min_role_for(&Method::GET, "/api/v1/incidents"), Role::Viewer);
        assert_eq!(
            min_role_for(
                &Method::GET,
                "/api/v1/incidents/019299f0-0d2b-7c41-9a8e-3d2b4c5e6f70"
            ),
            Role::Viewer
        );
        assert_eq!(min_role_for(&Method::GET, "/api/v1/evidence"), Role::Viewer);

        // Everything else stays Viewer-level.
        assert_eq!(min_role_for(&Method::GET, "/api/v1/events"), Role::Viewer);
        assert_eq!(
            min_role_for(&Method::GET, "/api/v1/stream/events"),
            Role::Viewer
        );
    }

    #[tokio::test]
    async fn a_viewer_is_forbidden_from_mutating_incidents_and_evidence() {
        let (_d1, _d2, state) = test_state();
        let token = session_for_role(&state, "viewer-mutate", Role::Viewer);
        let app = protected_app(state);

        for (method, uri) in [
            ("POST", "/api/v1/incidents"),
            (
                "PATCH",
                "/api/v1/incidents/019299f0-0d2b-7c41-9a8e-3d2b4c5e6f70",
            ),
            ("POST", "/api/v1/evidence"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method(method)
                        .uri(uri)
                        .header("Authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{method} {uri} should be forbidden for a Viewer"
            );
        }
    }

    #[tokio::test]
    async fn a_viewer_can_still_read_incidents_and_evidence() {
        let (_d1, _d2, state) = test_state();
        let token = session_for_role(&state, "viewer-read", Role::Viewer);
        let app = protected_app(state);

        for uri in [
            "/api/v1/incidents",
            "/api/v1/incidents/019299f0-0d2b-7c41-9a8e-3d2b4c5e6f70",
            "/api/v1/evidence",
        ] {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(uri)
                        .header("Authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "GET {uri} should be allowed for a Viewer");
        }
    }

    #[tokio::test]
    async fn an_analyst_may_mutate_incidents_and_evidence() {
        let (_d1, _d2, state) = test_state();
        let token = session_for_role(&state, "analyst-mutate", Role::Analyst);
        let app = protected_app(state);

        for (method, uri) in [
            ("POST", "/api/v1/incidents"),
            (
                "PATCH",
                "/api/v1/incidents/019299f0-0d2b-7c41-9a8e-3d2b4c5e6f70",
            ),
            ("POST", "/api/v1/evidence"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method(method)
                        .uri(uri)
                        .header("Authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{method} {uri} should be allowed for an Analyst"
            );
        }
    }
}
