use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_auth::{NewUser, Role, UserStore};
use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthContext;

#[derive(Clone)]
pub struct AuthState {
    pub users: Arc<dyn UserStore>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
    pub session_ttl_seconds: u64,
    pub tenants: Arc<dyn osiris_tenancy::TenantStore>,
}

pub fn build_auth_router(state: AuthState) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        .route("/api/v1/auth/me", get(me_handler))
        .route(
            "/api/v1/auth/users",
            post(create_user_handler).get(list_users_handler),
        )
        .route("/api/v1/audit", get(audit_handler))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    role: Role,
    expires_at: u64,
    tenant_id: Option<Uuid>,
    tenant_name: Option<String>,
}

/// A fixed, precomputed Argon2id hash used to give a nonexistent-username
/// login attempt the exact same per-request Argon2id cost (one
/// `verify_password` call) as a wrong-password attempt against a real user —
/// closing the timing side-channel in both directions. Computed once (on
/// first use, across the process's lifetime) and cached, so it must never be
/// regenerated per request: a fresh hash each call would itself reintroduce
/// an asymmetry (hash + verify vs. verify alone).
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        osiris_auth::hash_password("dummy-password-for-timing-parity")
            .expect("hashing a fixed constant string cannot fail")
    })
}

fn audit_login_denied(state: &AuthState, username: &str) {
    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::System,
        what: "login".to_string(),
        target: EntityRef::Domain {
            name: format!("user:{username}"),
        },
        why: Some("invalid credentials".to_string()),
        result: AuditResult::Denied,
    });
}

async fn login_handler(
    State(state): State<AuthState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let denied = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid credentials" })),
        )
    };

    let username = body.username.clone();
    let user = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let username = username.clone();
        move || users.get_user_by_username(&username)
    })
    .await
    .unwrap()
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;

    let Some(user) = user else {
        // No such user: still pay the same Argon2id cost a real verification
        // would, against a fixed *precomputed* dummy hash, so this branch and
        // the wrong-password branch below do exactly one Argon2id operation
        // each and take (near enough) the same amount of time. Without this,
        // an attacker could distinguish "no such user" from "wrong password"
        // purely by timing — the exact enumeration vector this endpoint must
        // not expose. The hash itself MUST be precomputed/cached (see
        // `dummy_password_hash`), not generated fresh per request: a fresh
        // hash-then-verify here would cost 2 Argon2id operations against the
        // real path's 1, reintroducing the asymmetry in the other direction.
        let _ = tokio::task::spawn_blocking(|| {
            osiris_auth::verify_password("this-will-never-match", dummy_password_hash())
        })
        .await;
        audit_login_denied(&state, &username);
        return Err(denied());
    };

    let password = body.password.clone();
    let password_hash = user.password_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        osiris_auth::verify_password(&password, &password_hash)
    })
    .await
    .unwrap()
    .unwrap_or(false);
    if !verified {
        audit_login_denied(&state, &username);
        return Err(denied());
    }

    let session = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let user_id = user.user_id;
        let ttl = state.session_ttl_seconds;
        move || users.create_session(user_id, ttl)
    })
    .await
    .unwrap()
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;

    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User {
            user_id: user.user_id,
        },
        what: "login".to_string(),
        target: EntityRef::Domain {
            name: format!("user:{}", user.username),
        },
        why: None,
        result: AuditResult::Success,
    });

    let tenant_name = tenant_name_of(&state, user.tenant_id).await;

    Ok(Json(LoginResponse {
        token: session.token,
        role: user.role,
        expires_at: session.expires_at,
        tenant_id: user.tenant_id,
        tenant_name,
    }))
}

async fn logout_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
) -> Json<serde_json::Value> {
    let _ = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let token = ctx.token.clone();
        move || users.delete_session(&token)
    })
    .await;

    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User {
            user_id: ctx.user_id,
        },
        what: "logout".to_string(),
        target: EntityRef::Domain {
            name: format!("user:{}", ctx.user_id),
        },
        why: None,
        result: AuditResult::Success,
    });

    Json(serde_json::json!({ "status": "ok" }))
}

/// Display name of a tenant; `None` for a platform user or an unresolvable id.
async fn tenant_name_of(state: &AuthState, tenant_id: Option<Uuid>) -> Option<String> {
    let tid = tenant_id?;
    let tenants = state.tenants.clone();
    tokio::task::spawn_blocking(move || tenants.get_tenant(tid))
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten()
        .map(|t| t.name)
}

#[derive(Debug, Serialize)]
struct MeResponse {
    user_id: Uuid,
    username: String,
    role: Role,
    tenant_id: Option<Uuid>,
    tenant_name: Option<String>,
}

async fn me_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let user = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let user_id = ctx.user_id;
        move || users.get_user_by_id(user_id)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "user not found".to_string()))?;

    let tenant_name = tenant_name_of(&state, user.tenant_id).await;
    Ok(Json(MeResponse {
        user_id: user.user_id,
        username: user.username,
        role: user.role,
        tenant_id: user.tenant_id,
        tenant_name,
    }))
}

/// Minimum accepted password length for a newly created account.
pub const MIN_PASSWORD_LENGTH: usize = 8;

#[derive(Debug, Deserialize)]
struct CreateUserBody {
    username: String,
    password: String,
    role: Role,
    #[serde(default)]
    tenant_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct CreateUserResponse {
    user_id: Uuid,
}

async fn create_user_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<CreateUserBody>,
) -> Result<Json<CreateUserResponse>, (StatusCode, String)> {
    // Defense in depth: minting users is platform-only.
    if ctx.tenant_id.is_some() {
        return Err((StatusCode::FORBIDDEN, "platform users only".to_string()));
    }
    if let Some(tenant_id) = body.tenant_id {
        let tenants = state.tenants.clone();
        let found = tokio::task::spawn_blocking(move || tenants.get_tenant(tenant_id))
            .await
            .unwrap()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if found.is_none() {
            return Err((StatusCode::BAD_REQUEST, "unknown tenant".to_string()));
        }
    }

    // Server-side floor, enforced before any hashing: a client (the CLI, the
    // Console, or curl) must never be the only thing standing between a weak
    // or empty password and a real account.
    if body.password.len() < MIN_PASSWORD_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("password must be at least {MIN_PASSWORD_LENGTH} characters"),
        ));
    }

    let password = body.password.clone();
    let password_hash = tokio::task::spawn_blocking(move || osiris_auth::hash_password(&password))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let created = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let username = body.username.clone();
        let role = body.role;
        let tenant_id = body.tenant_id;
        move || {
            users.create_user(NewUser {
                username,
                password_hash,
                role,
                tenant_id,
            })
        }
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User {
            user_id: ctx.user_id,
        },
        what: "user_create".to_string(),
        target: EntityRef::Domain {
            name: format!("user:{}", created.username),
        },
        why: None,
        result: AuditResult::Success,
    });

    Ok(Json(CreateUserResponse {
        user_id: created.user_id,
    }))
}

#[derive(Debug, Serialize)]
struct UserSummary {
    user_id: Uuid,
    username: String,
    role: Role,
    created_at: u64,
    tenant_id: Option<Uuid>,
}

async fn list_users_handler(
    State(state): State<AuthState>,
) -> Result<Json<Vec<UserSummary>>, (StatusCode, String)> {
    let users = tokio::task::spawn_blocking({
        let users = state.users.clone();
        move || users.list_users()
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        users
            .into_iter()
            .map(|u| UserSummary {
                user_id: u.user_id,
                username: u.username,
                role: u.role,
                created_at: u.created_at,
                tenant_id: u.tenant_id,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

async fn audit_handler(
    State(state): State<AuthState>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<osiris_audit::AuditEntry>>, (StatusCode, String)> {
    let mut entries = state
        .audit_log
        .read_all()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    entries.reverse();
    let limit = q.limit.unwrap_or(100).min(1000);
    entries.truncate(limit);
    Ok(Json(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::FileAuditLog;
    use osiris_auth::SqliteUserStore;

    fn test_state() -> (tempfile::TempDir, tempfile::TempDir, AuthState) {
        let users_dir = tempfile::tempdir().unwrap();
        let (store, _bootstrap) = SqliteUserStore::open(users_dir.path().join("users.db")).unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit_log = FileAuditLog::open(audit_dir.path().join("audit.jsonl")).unwrap();
        let state = AuthState {
            users: Arc::new(store),
            audit_log: Arc::new(audit_log),
            session_ttl_seconds: 3600,
            tenants: Arc::new(
                osiris_tenancy::SqliteTenantStore::open(users_dir.path().join("tenants.db"))
                    .unwrap(),
            ),
        };
        (users_dir, audit_dir, state)
    }

    #[tokio::test]
    async fn login_with_correct_credentials_issues_a_session() {
        let (_d1, _d2, state) = test_state();
        state
            .users
            .create_user(NewUser {
                username: "alice".to_string(),
                password_hash: osiris_auth::hash_password("secret123").unwrap(),
                role: Role::Analyst,
                tenant_id: None,
            })
            .unwrap();

        let result = login_handler(
            State(state.clone()),
            Json(LoginBody {
                username: "alice".to_string(),
                password: "secret123".to_string(),
            }),
        )
        .await;

        let Json(response) = result.unwrap();
        assert!(!response.token.is_empty());
        assert_eq!(response.role, Role::Analyst);
    }

    #[tokio::test]
    async fn login_with_wrong_password_is_denied_and_audited() {
        let (_d1, _d2, state) = test_state();
        state
            .users
            .create_user(NewUser {
                username: "bob".to_string(),
                password_hash: osiris_auth::hash_password("correct").unwrap(),
                role: Role::Viewer,
                tenant_id: None,
            })
            .unwrap();

        let result = login_handler(
            State(state.clone()),
            Json(LoginBody {
                username: "bob".to_string(),
                password: "wrong".to_string(),
            }),
        )
        .await;

        assert!(result.is_err());
        let entries = state.audit_log.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].result, AuditResult::Denied);
    }

    #[tokio::test]
    async fn me_returns_the_authenticated_users_own_profile() {
        let (_d1, _d2, state) = test_state();
        let user = state
            .users
            .create_user(NewUser {
                username: "carol".to_string(),
                password_hash: osiris_auth::hash_password("pw").unwrap(),
                role: Role::Admin,
                tenant_id: None,
            })
            .unwrap();
        let ctx = AuthContext {
            user_id: user.user_id,
            role: user.role,
            token: "irrelevant-for-this-test".to_string(),
            tenant_id: None,
        };

        let Json(me) = me_handler(State(state), Extension(ctx)).await.unwrap();
        assert_eq!(me.username, "carol");
        assert_eq!(me.role, Role::Admin);
        assert_eq!(me.tenant_id, None);
        assert_eq!(me.tenant_name, None);
    }

    #[tokio::test]
    async fn create_user_then_list_users_shows_the_new_user() {
        let (_d1, _d2, state) = test_state();
        let admin_ctx = AuthContext {
            user_id: Uuid::new_v4(),
            role: Role::Admin,
            token: "irrelevant".to_string(),
            tenant_id: None,
        };

        let _ = create_user_handler(
            State(state.clone()),
            Extension(admin_ctx),
            Json(CreateUserBody {
                username: "dave".to_string(),
                password: "a-long-enough-password".to_string(),
                role: Role::ResponseOperator,
                tenant_id: None,
            }),
        )
        .await
        .unwrap();

        let Json(users) = list_users_handler(State(state)).await.unwrap();
        assert!(users
            .iter()
            .any(|u| u.username == "dave" && u.role == Role::ResponseOperator));
    }

    #[tokio::test]
    async fn create_user_rejects_a_password_shorter_than_the_minimum() {
        let (_d1, _d2, state) = test_state();
        let admin_ctx = AuthContext {
            user_id: Uuid::new_v4(),
            role: Role::Admin,
            token: "irrelevant".to_string(),
            tenant_id: None,
        };

        let result = create_user_handler(
            State(state.clone()),
            Extension(admin_ctx),
            Json(CreateUserBody {
                username: "shorty".to_string(),
                password: "short".to_string(),
                role: Role::Viewer,
                tenant_id: None,
            }),
        )
        .await;

        let (status, message) = result
            .err()
            .expect("a 5-character password must be rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("at least 8 characters"), "got: {message}");

        // ...and nothing was created.
        assert!(state
            .users
            .get_user_by_username("shorty")
            .unwrap()
            .is_none());
        let Json(users) = list_users_handler(State(state)).await.unwrap();
        assert!(!users.iter().any(|u| u.username == "shorty"));
    }

    #[tokio::test]
    async fn audit_endpoint_returns_entries_most_recent_first() {
        let (_d1, _d2, state) = test_state();
        state
            .audit_log
            .append(NewAuditEntry {
                who: ActorRef::System,
                what: "first".to_string(),
                target: EntityRef::Domain {
                    name: "x".to_string(),
                },
                why: None,
                result: AuditResult::Success,
            })
            .unwrap();
        state
            .audit_log
            .append(NewAuditEntry {
                who: ActorRef::System,
                what: "second".to_string(),
                target: EntityRef::Domain {
                    name: "x".to_string(),
                },
                why: None,
                result: AuditResult::Success,
            })
            .unwrap();

        let Json(entries) = audit_handler(State(state), Query(AuditQuery { limit: None }))
            .await
            .unwrap();
        assert_eq!(entries[0].what, "second");
        assert_eq!(entries[1].what, "first");
    }
}
