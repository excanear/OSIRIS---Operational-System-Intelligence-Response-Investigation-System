use osiris_auth::Role;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub role: Role,
    pub token: String,
}

/// Placeholder for Task 4's real auth middleware (token extraction, session
/// lookup, and `AuthContext` insertion via `axum::middleware::from_fn_with_state`).
/// Exists only so `lib.rs`'s `pub use auth_middleware::{auth_gate, AuthContext};`
/// compiles ahead of Task 4 landing; it performs no authentication and must
/// not be wired into any router before Task 4 replaces it.
pub async fn auth_gate(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    next.run(request).await
}
