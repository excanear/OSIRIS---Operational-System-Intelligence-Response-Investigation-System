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

fn min_role_for(path: &str) -> Role {
    if path == "/api/v1/audit" || path == "/api/v1/auth/users" {
        Role::Admin
    } else {
        Role::Viewer
    }
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
        .map(|t| t.to_string());

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

    if user.role < min_role_for(&path) {
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
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth_gate))
            .with_state(state)
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
}
