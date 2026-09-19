use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Ordered by increasing privilege — `Ord`'s declaration-order derive is
/// load-bearing: `osiris_api`'s auth gate compares `user.role >= min_role`
/// directly, no separate numeric mapping (design doc §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    Viewer,
    Analyst,
    ResponseOperator,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub created_at: u64,
    /// `None` = platform user (sees every tenant). `Some` = belongs to
    /// exactly one tenant (Phase 8f).
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
}

/// Fields needed to create a user — `SqliteUserStore::create_user` fills in
/// `user_id`/`created_at`.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub user_id: Uuid,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_wire_form_is_screaming_snake_case() {
        assert_eq!(serde_json::to_string(&Role::Viewer).unwrap(), "\"VIEWER\"");
        assert_eq!(
            serde_json::to_string(&Role::ResponseOperator).unwrap(),
            "\"RESPONSE_OPERATOR\""
        );
    }

    #[test]
    fn role_orders_by_increasing_privilege() {
        assert!(Role::Viewer < Role::Analyst);
        assert!(Role::Analyst < Role::ResponseOperator);
        assert!(Role::ResponseOperator < Role::Admin);
    }
}
