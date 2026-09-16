# Phase 8a: RBAC/Auth Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add local username/password authentication (Argon2id, opaque server-revocable sessions) and role-based authorization (`Viewer`/`Analyst`/`ResponseOperator`/`Admin`) gating every `osiris-api` route, closing the gap that today every API route is unauthenticated.

**Architecture:** A new `osiris-auth` crate owns `Role`/`User`/`Session` types, password hashing, and a `SqliteUserStore` (its own `users.db`, following this project's established one-file-per-subsystem-store pattern — see `incidents.db`/`evidence.db`/`baseline.db`). `osiris-api` gets new `/api/v1/auth/*` + `/api/v1/audit` handlers and an `axum::middleware::from_fn_with_state`-based gate wrapping the whole router (login-check exempts only `/health` and `/auth/login`). `osiris-cli` gains `auth login`/`auth logout`/`users create`/`users list` commands and attaches a locally-cached session token to every other command. The Console gains a `Login` screen, an `authStore`, and a route guard.

**Tech Stack:** Rust (`argon2` for password hashing, `rand`+`hex` for opaque tokens, `rusqlite`, `axum::middleware::from_fn_with_state`, `tower::ServiceExt::oneshot` for middleware tests), TypeScript/React (Zustand, `@tanstack/react-query`, `react-router-dom`).

**Spec:** `docs/superpowers/specs/2026-09-16-phase-8a-rbac-auth-foundation-design.md`

## Global Constraints

- `Role` wire form is SCREAMING_SNAKE_CASE (`Viewer` → `"VIEWER"`, `ResponseOperator` → `"RESPONSE_OPERATOR"`), matching every other enum in this codebase. `Role` derives `PartialOrd, Ord` in declaration order `Viewer < Analyst < ResponseOperator < Admin` — a route's `min_role` check is `user.role >= min_role`, no manual numeric mapping.
- Sessions are opaque 256-bit random tokens (32 bytes via `rand::thread_rng().fill_bytes`, hex-encoded via the existing workspace `hex` dependency) — never a JWT. `SqliteUserStore::get_session` deletes-and-returns-`None` for an expired session; callers never see a `Session` whose `expires_at` has passed and never re-check expiry themselves.
- **Exactly one `FileAuditLog` instance per file path per process.** `FileAuditLog`'s own doc comment warns two instances on the same path can silently fork the hash chain under concurrent `append`. `osiris-server`'s `main.rs` already opens `investigate_audit_log_path` once for `IncidentEvidenceState`; Task 5 reuses that same `Arc<dyn AuditLog + Send + Sync>` for the new `AuthState` — it does **not** call `FileAuditLog::open` a second time for the same path.
- The auth gate is a single function (`osiris_api::auth_gate`) applied via one `.layer(axum::middleware::from_fn_with_state(...))` on the fully-merged router in `main.rs` (after `build_router`/`build_incident_evidence_router`/`build_stream_router`/`build_auth_router` are all merged), not scattered per-sub-router `.layer()` calls. Route exemption (`/api/v1/health`, `/api/v1/auth/login`) and the `min_role` table both live inside that one function.
- No new `Storage` trait methods, no changes to the telemetry `events.db` schema — `users.db` is a wholly separate SQLite file, matching `incidents_db_path`/`evidence_db_path`/`baseline_db_path`'s existing `ServerConfig` precedent exactly (optional config field, `main.rs` applies a `/var/lib/osiris/...` default).
- CLI password entry always uses a hidden-input prompt (`rpassword` crate, added as a new workspace dependency) — never a `--password` flag, to keep credentials out of shell history.
- Console session state lives in `sessionStorage` (not `localStorage`), via a new `authStore` — so a session doesn't outlive the browser tab on a shared machine.
- `client.ts`'s `request()` must only add an `Authorization` header when a token is actually present in `authStore` — every existing `client.test.ts` assertion (`expect(fetch).toHaveBeenCalledWith("/api/v1/health")` with **no** second argument) runs with no token set and must keep passing unchanged.

---

## File Structure

**Backend:**
- New crate `crates/osiris-auth/` — `Cargo.toml`, `src/lib.rs`, `src/types.rs` (`Role`, `User`, `NewUser`, `Session`), `src/password.rs` (`hash_password`/`verify_password`), `src/store.rs` (`UserStore` trait, `SqliteUserStore`, `BootstrapAdmin`).
- New: `crates/osiris-api/src/auth.rs` — `AuthState`, all `/api/v1/auth/*` + `/api/v1/audit` handlers, `build_auth_router`.
- New: `crates/osiris-api/src/auth_middleware.rs` — `AuthContext`, `auth_gate`, `min_role_for`.
- Modified: `crates/osiris-api/src/lib.rs` — `pub mod auth; pub use auth::{...}; pub mod auth_middleware; pub use auth_middleware::{...};` near the existing `pub mod evidence;`/`pub mod incidents;` block.
- Modified: `crates/osiris-api/Cargo.toml` — add `osiris-auth`, `serde_json` (already a workspace dep) to `[dependencies]`; add `tower` to `[dev-dependencies]`.
- Modified: `crates/osiris-server/src/config.rs` — add `users_db_path: Option<String>`, `session_ttl_seconds: Option<u64>`.
- Modified: `crates/osiris-server/src/main.rs` — open `SqliteUserStore`, log the bootstrap admin credential once, build `AuthState` sharing the existing `audit_log` `Arc`, merge `build_auth_router`, apply `auth_gate` as the outermost layer.
- Modified: root `Cargo.toml` — add `argon2 = "0.5"`, `rand = "0.8"`, `rpassword = "7"` to `[workspace.dependencies]`.

**CLI:**
- New: `crates/osiris-cli/src/auth.rs` — token file read/write/delete helpers.
- Modified: `crates/osiris-cli/src/main.rs` — `Command::Auth`/`Command::Users` subcommands, `post_json()` helper, `get()` attaches a Bearer token and gives a friendlier 401 message.
- Modified: `crates/osiris-cli/Cargo.toml` — add `rpassword`.

**Console:**
- New: `console/src/store/authStore.ts`, `authStore.test.ts`.
- New: `console/src/screens/auth/Login.tsx`, `Login.test.tsx`.
- Modified: `console/src/api/types.ts` — add `Role`, `LoginResponse`.
- Modified: `console/src/api/client.ts` — `request()` attaches `Authorization` header when a token is present and clears the session on a `401`; add `login()`.
- Modified: `console/src/api/hooks.ts` — add `useLogin()`.
- Modified: `console/src/App.tsx` — add `/login` route + a `RequireAuth` guard wrapping every existing route.

---

### Task 1: `osiris-auth` — types and password hashing

**Files:**
- Create: `crates/osiris-auth/Cargo.toml`
- Create: `crates/osiris-auth/src/lib.rs`
- Create: `crates/osiris-auth/src/types.rs`
- Create: `crates/osiris-auth/src/password.rs`
- Modify: root `Cargo.toml` (add `argon2`, `rand` to `[workspace.dependencies]`; `crates/osiris-auth` is picked up automatically by the existing `"crates/*"` glob member)

**Interfaces:**
- Produces: `osiris_auth::{Role, User, NewUser, Session, hash_password, verify_password, PasswordError}`.
- Consumes: nothing from other tasks — this is the crate's foundation.

- [ ] **Step 1: Add new workspace dependencies**

In the root `Cargo.toml`, add to `[workspace.dependencies]` (alphabetical position doesn't matter, this file isn't sorted):

```toml
argon2 = "0.5"
rand = "0.8"
```

- [ ] **Step 2: Create the crate skeleton**

`crates/osiris-auth/Cargo.toml`:

```toml
[package]
name = "osiris-auth"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
rusqlite = { workspace = true }
argon2 = { workspace = true }
rand = { workspace = true }
hex = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

`crates/osiris-auth/src/lib.rs`:

```rust
mod password;
mod store;
mod types;

pub use password::{hash_password, verify_password, PasswordError};
pub use store::{BootstrapAdmin, SqliteUserStore, UserStore, UserStoreError};
pub use types::{NewUser, Role, Session, User};
```

`crates/osiris-auth/src/store.rs` (placeholder so `lib.rs` compiles until Task 2):

```rust
// Implemented in Task 2.
```

- [ ] **Step 3: Write the failing test for `types.rs`**

Create `crates/osiris-auth/src/types.rs`:

```rust
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
}

/// Fields needed to create a user — `SqliteUserStore::create_user` fills in
/// `user_id`/`created_at`.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
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
```

- [ ] **Step 4: Run the types tests**

Run: `cargo test -p osiris-auth types::tests -- --nocapture`
Expected: PASS (this file has no dependency on unfinished code — write-then-verify here, not red-then-green, since there's nothing to be red about).

- [ ] **Step 5: Write the failing tests for `password.rs`**

Create `crates/osiris-auth/src/password.rs`:

```rust
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("failed to hash password: {0}")]
    Hash(String),
    #[error("failed to parse a stored password hash: {0}")]
    Parse(String),
}

pub fn hash_password(plaintext: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

pub fn verify_password(plaintext: &str, stored_hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(stored_hash).map_err(|e| PasswordError::Parse(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_correct_password_verifies_against_its_own_hash() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
    }

    #[test]
    fn an_incorrect_password_does_not_verify() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn two_hashes_of_the_same_password_differ() {
        // Argon2id salts each hash independently — this is what stops two
        // users with the same password from having identical stored hashes.
        let a = hash_password("shared-password").unwrap();
        let b = hash_password("shared-password").unwrap();
        assert_ne!(a, b);
    }
}
```

- [ ] **Step 6: Run the password tests**

Run: `cargo test -p osiris-auth password::tests -- --nocapture`
Expected: PASS.

- [ ] **Step 7: Run the whole crate's tests and commit**

Run: `cargo test -p osiris-auth`
Expected: all tests pass (the `store` module is still a stub, no tests there yet).

```bash
git add Cargo.toml crates/osiris-auth
git commit -m "feat(auth): add osiris-auth crate with Role/User/Session types and Argon2id password hashing"
```

---

### Task 2: `osiris-auth` — `SqliteUserStore`

**Files:**
- Modify: `crates/osiris-auth/src/store.rs` (replace the Task 1 placeholder)

**Interfaces:**
- Consumes: `crate::types::{Role, User, NewUser, Session}`, `crate::password::hash_password`.
- Produces: `UserStore` trait (`create_user`, `get_user_by_username`, `get_user_by_id`, `list_users`, `create_session`, `get_session`, `delete_session` — all `Send + Sync`, object-safe), `SqliteUserStore::open(path) -> Result<(SqliteUserStore, Option<BootstrapAdmin>), UserStoreError>`, `BootstrapAdmin { username: String, password: String }`, `UserStoreError`. `osiris-api` (Task 3/4) consumes `Arc<dyn UserStore>`.

- [ ] **Step 1: Write the failing tests**

Replace `crates/osiris-auth/src/store.rs` with (tests first, `SqliteUserStore` not yet implemented below them):

```rust
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::password::hash_password;
use crate::types::{NewUser, Role, Session, User};

#[derive(Debug, thiserror::Error)]
pub enum UserStoreError {
    #[error("database error: {0}")]
    Backend(String),
    #[error("username already exists: {0}")]
    DuplicateUsername(String),
}

/// Returned once, only when `SqliteUserStore::open` created the very first
/// (bootstrap) `admin` user on an empty `users` table — the caller
/// (`osiris-server`) logs the plaintext password once at startup; it is
/// never stored or retrievable again.
#[derive(Debug)]
pub struct BootstrapAdmin {
    pub username: String,
    pub password: String,
}

pub trait UserStore: Send + Sync {
    fn create_user(&self, new_user: NewUser) -> Result<User, UserStoreError>;
    fn get_user_by_username(&self, username: &str) -> Result<Option<User>, UserStoreError>;
    fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, UserStoreError>;
    fn list_users(&self) -> Result<Vec<User>, UserStoreError>;
    fn create_session(&self, user_id: Uuid, ttl_seconds: u64) -> Result<Session, UserStoreError>;
    fn get_session(&self, token: &str) -> Result<Option<Session>, UserStoreError>;
    fn delete_session(&self, token: &str) -> Result<(), UserStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_an_empty_database_creates_exactly_one_bootstrap_admin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.db");

        let (store, bootstrap) = SqliteUserStore::open(&path).unwrap();
        let bootstrap = bootstrap.expect("first open of an empty db must return a bootstrap admin");
        assert_eq!(bootstrap.username, "admin");

        let admin = store.get_user_by_username("admin").unwrap().unwrap();
        assert_eq!(admin.role, Role::Admin);
        assert!(crate::password::verify_password(&bootstrap.password, &admin.password_hash).unwrap());

        let (_store2, bootstrap2) = SqliteUserStore::open(&path).unwrap();
        assert!(
            bootstrap2.is_none(),
            "reopening a non-empty users.db must not create a second bootstrap admin"
        );
    }

    #[test]
    fn create_user_rejects_a_duplicate_username() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _bootstrap) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();

        store
            .create_user(NewUser {
                username: "alice".to_string(),
                password_hash: hash_password("pw1").unwrap(),
                role: Role::Viewer,
            })
            .unwrap();

        let err = store
            .create_user(NewUser {
                username: "alice".to_string(),
                password_hash: hash_password("pw2").unwrap(),
                role: Role::Analyst,
            })
            .unwrap_err();
        assert!(matches!(err, UserStoreError::DuplicateUsername(_)));
    }

    #[test]
    fn a_created_session_is_retrievable_by_token_and_matches_the_owning_user() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _bootstrap) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
        let user = store
            .create_user(NewUser {
                username: "bob".to_string(),
                password_hash: hash_password("pw").unwrap(),
                role: Role::Analyst,
            })
            .unwrap();

        let session = store.create_session(user.user_id, 3600).unwrap();
        let fetched = store.get_session(&session.token).unwrap().unwrap();
        assert_eq!(fetched.user_id, user.user_id);
        assert_eq!(fetched.token, session.token);
    }

    #[test]
    fn an_expired_session_is_deleted_and_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _bootstrap) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
        let user = store
            .create_user(NewUser {
                username: "carol".to_string(),
                password_hash: hash_password("pw").unwrap(),
                role: Role::Viewer,
            })
            .unwrap();

        // A 0-second TTL: issued_at == expires_at, so it's already expired
        // by the time get_session runs.
        let session = store.create_session(user.user_id, 0).unwrap();
        assert!(store.get_session(&session.token).unwrap().is_none());

        // The row must actually be gone, not just filtered on read —
        // recreate a session with the identical token would be impossible
        // to observe directly, so assert indirectly: a second get_session
        // call for the same token still returns None (idempotent, not an
        // error from a lingering row).
        assert!(store.get_session(&session.token).unwrap().is_none());
    }

    #[test]
    fn delete_session_revokes_it_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _bootstrap) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
        let user = store
            .create_user(NewUser {
                username: "dave".to_string(),
                password_hash: hash_password("pw").unwrap(),
                role: Role::Viewer,
            })
            .unwrap();
        let session = store.create_session(user.user_id, 3600).unwrap();

        store.delete_session(&session.token).unwrap();

        assert!(store.get_session(&session.token).unwrap().is_none());
    }

    #[test]
    fn list_users_returns_every_created_user_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _bootstrap) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
        store
            .create_user(NewUser {
                username: "erin".to_string(),
                password_hash: hash_password("pw").unwrap(),
                role: Role::Viewer,
            })
            .unwrap();

        let users = store.list_users().unwrap();
        // admin (bootstrap) + erin
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[1].username, "erin");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p osiris-auth store::tests -- --nocapture`
Expected: FAIL to compile — `SqliteUserStore` is not defined yet.

- [ ] **Step 3: Implement `SqliteUserStore`**

Add above the `#[cfg(test)]` block in the same file:

```rust
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn role_to_string(role: Role) -> String {
    serde_json::to_string(&role).unwrap().trim_matches('"').to_string()
}

fn role_from_string(s: &str) -> Role {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or(Role::Viewer)
}

fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
    let user_id: String = row.get(0)?;
    let username: String = row.get(1)?;
    let password_hash: String = row.get(2)?;
    let role: String = row.get(3)?;
    let created_at: i64 = row.get(4)?;
    Ok(User {
        user_id: Uuid::parse_str(&user_id).unwrap_or_else(|_| Uuid::nil()),
        username,
        password_hash,
        role: role_from_string(&role),
        created_at: created_at as u64,
    })
}

pub struct SqliteUserStore {
    conn: Mutex<Connection>,
}

impl SqliteUserStore {
    /// Opens (creating if absent) the users/sessions SQLite store. If the
    /// `users` table is empty, creates a bootstrap `admin` user (role
    /// `Admin`) with a randomly generated password and returns it.
    pub fn open(
        path: impl AsRef<std::path::Path>,
    ) -> Result<(Self, Option<BootstrapAdmin>), UserStoreError> {
        let conn = Connection::open(path).map_err(|e| UserStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| UserStoreError::Backend(e.to_string()))?;

        let store = Self { conn: Mutex::new(conn) };

        let user_count: i64 = {
            let conn = store.conn.lock().unwrap();
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
                .map_err(|e| UserStoreError::Backend(e.to_string()))?
        };

        let bootstrap = if user_count == 0 {
            let mut password_bytes = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut password_bytes);
            let password = hex::encode(password_bytes);
            let password_hash =
                hash_password(&password).map_err(|e| UserStoreError::Backend(e.to_string()))?;
            store.create_user(NewUser {
                username: "admin".to_string(),
                password_hash,
                role: Role::Admin,
            })?;
            Some(BootstrapAdmin {
                username: "admin".to_string(),
                password,
            })
        } else {
            None
        };

        Ok((store, bootstrap))
    }
}

impl UserStore for SqliteUserStore {
    fn create_user(&self, new_user: NewUser) -> Result<User, UserStoreError> {
        let user_id = Uuid::new_v4();
        let created_at = now_unix();
        let role_str = role_to_string(new_user.role);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (user_id, username, password_hash, role, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                user_id.to_string(),
                new_user.username,
                new_user.password_hash,
                role_str,
                created_at as i64
            ],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                UserStoreError::DuplicateUsername(new_user.username.clone())
            } else {
                UserStoreError::Backend(e.to_string())
            }
        })?;
        Ok(User {
            user_id,
            username: new_user.username,
            password_hash: new_user.password_hash,
            role: new_user.role,
            created_at,
        })
    }

    fn get_user_by_username(&self, username: &str) -> Result<Option<User>, UserStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT user_id, username, password_hash, role, created_at FROM users WHERE username = ?1",
            params![username],
            row_to_user,
        )
        .optional()
        .map_err(|e| UserStoreError::Backend(e.to_string()))
    }

    fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, UserStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT user_id, username, password_hash, role, created_at FROM users WHERE user_id = ?1",
            params![user_id.to_string()],
            row_to_user,
        )
        .optional()
        .map_err(|e| UserStoreError::Backend(e.to_string()))
    }

    fn list_users(&self) -> Result<Vec<User>, UserStoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT user_id, username, password_hash, role, created_at \
                 FROM users ORDER BY created_at ASC",
            )
            .map_err(|e| UserStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_user)
            .map_err(|e| UserStoreError::Backend(e.to_string()))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| UserStoreError::Backend(e.to_string()))
    }

    fn create_session(&self, user_id: Uuid, ttl_seconds: u64) -> Result<Session, UserStoreError> {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let issued_at = now_unix();
        let expires_at = issued_at + ttl_seconds;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (token, user_id, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, user_id.to_string(), issued_at as i64, expires_at as i64],
        )
        .map_err(|e| UserStoreError::Backend(e.to_string()))?;
        Ok(Session {
            token,
            user_id,
            issued_at,
            expires_at,
        })
    }

    fn get_session(&self, token: &str) -> Result<Option<Session>, UserStoreError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(String, i64, i64)> = conn
            .query_row(
                "SELECT user_id, issued_at, expires_at FROM sessions WHERE token = ?1",
                params![token],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| UserStoreError::Backend(e.to_string()))?;

        let Some((user_id_str, issued_at, expires_at)) = row else {
            return Ok(None);
        };

        if (expires_at as u64) <= now_unix() {
            conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])
                .map_err(|e| UserStoreError::Backend(e.to_string()))?;
            return Ok(None);
        }

        let user_id =
            Uuid::parse_str(&user_id_str).map_err(|e| UserStoreError::Backend(e.to_string()))?;
        Ok(Some(Session {
            token: token.to_string(),
            user_id,
            issued_at: issued_at as u64,
            expires_at: expires_at as u64,
        }))
    }

    fn delete_session(&self, token: &str) -> Result<(), UserStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])
            .map_err(|e| UserStoreError::Backend(e.to_string()))?;
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p osiris-auth`
Expected: PASS (all `types`, `password`, and `store` tests green).

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-auth/src/store.rs
git commit -m "feat(auth): add SqliteUserStore with bootstrap admin and session management"
```

---

### Task 3: `osiris-api` — auth handlers and router

**Files:**
- Create: `crates/osiris-api/src/auth.rs`
- Modify: `crates/osiris-api/src/lib.rs` (module declaration only — the `pub mod auth;` line and re-export; middleware wiring is Task 4)
- Modify: `crates/osiris-api/Cargo.toml` (add `osiris-auth` dependency)

**Interfaces:**
- Consumes: `osiris_auth::{Role, User, NewUser, Session, UserStore, hash_password, verify_password}`, `osiris_audit::{AuditLog, ActorRef, AuditResult, NewAuditEntry}`, `osiris_schema::EntityRef`.
- Produces: `AuthState { users: Arc<dyn UserStore>, audit_log: Arc<dyn AuditLog + Send + Sync>, session_ttl_seconds: u64 }` (`Clone`), `build_auth_router(state: AuthState) -> Router` registering `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me`, `POST|GET /api/v1/auth/users`, `GET /api/v1/audit`. `logout_handler`/`me_handler`/`create_user_handler` read `axum::Extension<AuthContext>` — Task 4 defines `AuthContext` and is what actually inserts it, so until Task 4 lands these three handlers compile but are unreachable via a real request (acceptable: this task's own tests call handlers directly with a hand-built `Extension`, not through the middleware).

- [ ] **Step 1: Add the `osiris-auth` dependency**

In `crates/osiris-api/Cargo.toml`, add to `[dependencies]`:

```toml
osiris-auth = { path = "../osiris-auth" }
```

- [ ] **Step 2: Write the failing tests**

Create `crates/osiris-api/src/auth.rs`:

```rust
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
        audit_login_denied(&state, &username);
        return Err(denied());
    };

    let verified = osiris_auth::verify_password(&body.password, &user.password_hash).unwrap_or(false);
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

    Ok(Json(LoginResponse {
        token: session.token,
        role: user.role,
        expires_at: session.expires_at,
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

#[derive(Debug, Serialize)]
struct MeResponse {
    user_id: Uuid,
    username: String,
    role: Role,
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

    Ok(Json(MeResponse {
        user_id: user.user_id,
        username: user.username,
        role: user.role,
    }))
}

#[derive(Debug, Deserialize)]
struct CreateUserBody {
    username: String,
    password: String,
    role: Role,
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
    let password_hash =
        osiris_auth::hash_password(&body.password).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let created = tokio::task::spawn_blocking({
        let users = state.users.clone();
        let username = body.username.clone();
        let role = body.role;
        move || {
            users.create_user(NewUser {
                username,
                password_hash,
                role,
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
            })
            .unwrap();
        let ctx = AuthContext {
            user_id: user.user_id,
            role: user.role,
            token: "irrelevant-for-this-test".to_string(),
        };

        let Json(me) = me_handler(State(state), Extension(ctx)).await.unwrap();
        assert_eq!(me.username, "carol");
        assert_eq!(me.role, Role::Admin);
    }

    #[tokio::test]
    async fn create_user_then_list_users_shows_the_new_user() {
        let (_d1, _d2, state) = test_state();
        let admin_ctx = AuthContext {
            user_id: Uuid::new_v4(),
            role: Role::Admin,
            token: "irrelevant".to_string(),
        };

        create_user_handler(
            State(state.clone()),
            Extension(admin_ctx),
            Json(CreateUserBody {
                username: "dave".to_string(),
                password: "pw".to_string(),
                role: Role::ResponseOperator,
            }),
        )
        .await
        .unwrap();

        let Json(users) = list_users_handler(State(state)).await.unwrap();
        assert!(users.iter().any(|u| u.username == "dave" && u.role == Role::ResponseOperator));
    }

    #[tokio::test]
    async fn audit_endpoint_returns_entries_most_recent_first() {
        let (_d1, _d2, state) = test_state();
        state
            .audit_log
            .append(NewAuditEntry {
                who: ActorRef::System,
                what: "first".to_string(),
                target: EntityRef::Domain { name: "x".to_string() },
                why: None,
                result: AuditResult::Success,
            })
            .unwrap();
        state
            .audit_log
            .append(NewAuditEntry {
                who: ActorRef::System,
                what: "second".to_string(),
                target: EntityRef::Domain { name: "x".to_string() },
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
```

- [ ] **Step 3: Add the module declarations to `lib.rs`**

In `crates/osiris-api/src/lib.rs`, near the existing `pub mod evidence;` block:

```rust
pub mod auth;
pub use auth::{build_auth_router, AuthState};
pub mod auth_middleware;
pub use auth_middleware::{auth_gate, AuthContext};
```

Also create `crates/osiris-api/src/auth_middleware.rs` with a minimal stub so this compiles until Task 4:

```rust
use osiris_auth::Role;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub role: Role,
    pub token: String,
}
```

- [ ] **Step 4: Run tests to verify they fail, then pass**

Run: `cargo test -p osiris-api auth::tests -- --nocapture`
Expected: first FAIL to compile (before Step 3's stub exists — if you're following steps strictly, do Step 3 before running this), then PASS once `AuthContext` exists and the handlers above compile.

- [ ] **Step 5: Run the whole crate and commit**

Run: `cargo test -p osiris-api`
Expected: all existing tests still pass, plus the new `auth::tests`.

```bash
git add crates/osiris-api/Cargo.toml crates/osiris-api/src/lib.rs crates/osiris-api/src/auth.rs crates/osiris-api/src/auth_middleware.rs
git commit -m "feat(api): add /api/v1/auth/* and /api/v1/audit handlers"
```

---

### Task 4: `osiris-api` — auth gate middleware

**Files:**
- Modify: `crates/osiris-api/src/auth_middleware.rs` (replace Task 3's stub)
- Modify: `crates/osiris-api/Cargo.toml` (add `tower` to `[dev-dependencies]`)

**Interfaces:**
- Consumes: `osiris_auth::Role`, `crate::auth::AuthState`.
- Produces: `pub async fn auth_gate(State(AuthState), Request, Next) -> Response` — an `axum::middleware::from_fn_with_state`-compatible middleware function; `AuthContext` (already stubbed in Task 3, unchanged here).

- [ ] **Step 1: Add `tower` as a dev-dependency**

In `crates/osiris-api/Cargo.toml`, add to `[dev-dependencies]`:

```toml
tower = { workspace = true }
```

- [ ] **Step 2: Write the failing tests**

Replace `crates/osiris-api/src/auth_middleware.rs` with:

```rust
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-api auth_middleware::tests -- --nocapture`
Expected: FAIL — `auth_gate` doesn't exist yet in this replaced file until the implementation above it is in place (if you pasted the whole file including the implementation in Step 2, skip straight to Step 4; the write-then-verify split here matters less than in earlier tasks since implementation and tests were written together above — still run the command once to confirm a clean baseline before moving on).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p osiris-api auth_middleware::tests -- --nocapture`
Expected: PASS, all 4 tests green.

- [ ] **Step 5: Run the whole crate and commit**

Run: `cargo test -p osiris-api`
Expected: all tests pass.

```bash
git add crates/osiris-api/Cargo.toml crates/osiris-api/src/auth_middleware.rs
git commit -m "feat(api): add the auth_gate middleware (401/403, min_role per route)"
```

---

### Task 5: `osiris-server` — wire authentication into the running server

**Files:**
- Modify: `crates/osiris-server/src/config.rs`
- Modify: `crates/osiris-server/src/main.rs`
- Modify: root `Cargo.toml` (workspace dep, if not already present from Task 1 — it is, this task only consumes it)

**Interfaces:**
- Consumes: `osiris_auth::SqliteUserStore`, `osiris_api::{AuthState, build_auth_router, auth_gate}`.
- Produces: a running server that requires authentication on every route except `/api/v1/health` and `/api/v1/auth/login`, and logs a one-time bootstrap admin credential on first startup.

- [ ] **Step 1: Write the failing config tests**

Add to the `#[cfg(test)] mod tests` block in `crates/osiris-server/src/config.rs`, after the existing `dev_cors_parses_when_present` test:

```rust
    #[test]
    fn users_db_path_and_session_ttl_default_to_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert!(config.users_db_path.is_none());
        assert!(config.session_ttl_seconds.is_none());
    }

    #[test]
    fn users_db_path_and_session_ttl_parse_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\nusers_db_path: /tmp/users.db\nsession_ttl_seconds: 3600\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.users_db_path.as_deref(), Some("/tmp/users.db"));
        assert_eq!(config.session_ttl_seconds, Some(3600));
    }
```

- [ ] **Step 2: Run the config tests to verify they fail**

Run: `cargo test -p osiris-server config:: -- --nocapture`
Expected: FAIL to compile — `ServerConfig` has no `users_db_path`/`session_ttl_seconds` fields yet.

- [ ] **Step 3: Add the fields to `ServerConfig`**

In `crates/osiris-server/src/config.rs`, add to the `ServerConfig` struct (after `dev_cors`):

```rust
    /// Phase 8a: the RBAC/Auth store's own SQLite file (ARCHITECTURE.md
    /// §10.3), independent of `db_path`'s telemetry tables — same posture
    /// `incidents_db_path` etc. already established.
    #[serde(default)]
    pub users_db_path: Option<String>,
    /// Phase 8a: session token lifetime in seconds; `main.rs` defaults to
    /// 28800 (8 hours) when absent.
    #[serde(default)]
    pub session_ttl_seconds: Option<u64>,
```

- [ ] **Step 4: Run the config tests to verify they pass**

Run: `cargo test -p osiris-server config::`
Expected: PASS.

- [ ] **Step 5: Wire authentication into `main.rs`**

In `crates/osiris-server/src/main.rs`:

Add to the `use` block at the top:

```rust
use osiris_api::{build_auth_router, auth_gate, AuthState};
use osiris_auth::SqliteUserStore;
```

Change the audit log construction so it is built **once** and shared (this fixes what would otherwise be a second `FileAuditLog` on the same path — see this plan's Global Constraints). Replace:

```rust
    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(open_or_exit(
            SqliteIncidentStore::open(&incidents_db_path),
            &incidents_db_path,
            "incidents_db_path",
        )),
        evidence: Arc::new(open_or_exit(
            SqliteEvidenceStore::open(&evidence_db_path),
            &evidence_db_path,
            "evidence_db_path",
        )),
        links: Arc::new(open_or_exit(
            SqliteEvidenceIncidentLinks::open(&links_db_path),
            &links_db_path,
            "links_db_path",
        )),
        audit_log: Arc::new(open_or_exit(
            FileAuditLog::open(&investigate_audit_log_path),
            &investigate_audit_log_path,
            "investigate_audit_log_path",
        )),
    };
```

with:

```rust
    // Exactly one FileAuditLog instance for this path in this process —
    // FileAuditLog::append is not safe to call concurrently from two
    // separate instances sharing a path (see its own doc comment), so this
    // one Arc is shared between IncidentEvidenceState and AuthState below,
    // never opened a second time.
    let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> = Arc::new(open_or_exit(
        FileAuditLog::open(&investigate_audit_log_path),
        &investigate_audit_log_path,
        "investigate_audit_log_path",
    ));

    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(open_or_exit(
            SqliteIncidentStore::open(&incidents_db_path),
            &incidents_db_path,
            "incidents_db_path",
        )),
        evidence: Arc::new(open_or_exit(
            SqliteEvidenceStore::open(&evidence_db_path),
            &evidence_db_path,
            "evidence_db_path",
        )),
        links: Arc::new(open_or_exit(
            SqliteEvidenceIncidentLinks::open(&links_db_path),
            &links_db_path,
            "links_db_path",
        )),
        audit_log: audit_log.clone(),
    };

    let users_db_path = config
        .users_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/users.db".to_string());
    let (user_store, bootstrap_admin) = match SqliteUserStore::open(&users_db_path) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(path = %users_db_path, error = %e, "failed to open the user store");
            eprintln!("fatal: failed to open user store at '{users_db_path}': {e}");
            std::process::exit(1);
        }
    };
    if let Some(admin) = bootstrap_admin {
        tracing::warn!(
            username = %admin.username,
            password = %admin.password,
            "created a bootstrap admin user — log in once with this one-time \
             password (never shown again) and create a named account"
        );
    }
    let session_ttl_seconds = config.session_ttl_seconds.unwrap_or(28800);
    let auth_state = AuthState {
        users: Arc::new(user_store),
        audit_log: audit_log.clone(),
        session_ttl_seconds,
    };
```

Then change the final router assembly. Replace:

```rust
    let app = osiris_server::apply_dev_cors(
        build_router(storage)
            .merge(build_incident_evidence_router(incident_evidence_state))
            .merge(build_stream_router(live_event_broadcaster)),
        config.dev_cors,
    );
```

with:

```rust
    let app = osiris_server::apply_dev_cors(
        build_router(storage)
            .merge(build_incident_evidence_router(incident_evidence_state))
            .merge(build_stream_router(live_event_broadcaster))
            .merge(build_auth_router(auth_state.clone()))
            .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate)),
        config.dev_cors,
    );
```

- [ ] **Step 6: Build and run the whole workspace's tests**

Run: `cargo build --workspace`
Expected: builds cleanly.

Run: `cargo test --workspace`
Expected: all tests pass (this task adds no new server-level tests beyond Step 1's config tests — `main.rs` itself has no `#[cfg(test)]` block to extend, matching this file's existing convention of being exercised only via the crates it wires together).

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-server/src/config.rs crates/osiris-server/src/main.rs
git commit -m "feat(server): wire RBAC/Auth into the running server, gate every route"
```

---

### Task 6: `osiris-cli` — `auth login`/`auth logout` and token attachment

**Files:**
- Create: `crates/osiris-cli/src/auth.rs`
- Modify: `crates/osiris-cli/src/main.rs`
- Modify: `crates/osiris-cli/Cargo.toml` (add `rpassword`)
- Modify: root `Cargo.toml` (add `rpassword = "7"` to `[workspace.dependencies]` — if not already added in Task 1's step, add it now)

**Interfaces:**
- Produces: `osiris_cli::auth::{read_token, write_token, delete_token}` (all operate on `~/.osiris/token`, or the `OSIRIS_TOKEN` env var override for `read_token`), `Command::Auth { action: AuthAction }` with `AuthAction::{Login { username: String }, Logout}`, a `post_json()` helper alongside the existing `get()`.
- Consumes: nothing from other CLI tasks; Task 7 consumes `read_token`/`post_json`/`get`.

- [ ] **Step 1: Add the `rpassword` dependency**

If not already present from Task 1, add to root `Cargo.toml`'s `[workspace.dependencies]`:

```toml
rpassword = "7"
```

In `crates/osiris-cli/Cargo.toml`, add to `[dependencies]`:

```toml
rpassword = { workspace = true }
```

- [ ] **Step 2: Write the failing tests for the token file helpers**

Create `crates/osiris-cli/src/auth.rs`:

```rust
use std::path::PathBuf;

fn token_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".osiris").join("token"))
}

/// Reads the cached session token: `OSIRIS_TOKEN` env var takes priority
/// (useful for scripts/CI), falling back to `~/.osiris/token`.
pub fn read_token() -> Option<String> {
    if let Ok(t) = std::env::var("OSIRIS_TOKEN") {
        if !t.is_empty() {
            return Some(t);
        }
    }
    let path = token_path()?;
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn write_token(token: &str) -> std::io::Result<()> {
    let path = token_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME is not set"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn delete_token() {
    if let Some(path) = token_path() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // HOME/OSIRIS_TOKEN are process-global env vars — serialize these tests
    // so they don't race each other under `cargo test`'s default parallelism.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn write_then_read_round_trips_through_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var("OSIRIS_TOKEN");
        std::env::set_var("HOME", dir.path());

        write_token("abc123").unwrap();
        assert_eq!(read_token(), Some("abc123".to_string()));

        delete_token();
        assert_eq!(read_token(), None);

        std::env::remove_var("HOME");
    }

    #[test]
    fn osiris_token_env_var_takes_priority_over_the_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        write_token("from-file").unwrap();
        std::env::set_var("OSIRIS_TOKEN", "from-env");

        assert_eq!(read_token(), Some("from-env".to_string()));

        std::env::remove_var("OSIRIS_TOKEN");
        std::env::remove_var("HOME");
    }
}
```

- [ ] **Step 3: Add `crates/osiris-cli/Cargo.toml`'s dev-dependencies if `tempfile` is missing**

Check `crates/osiris-cli/Cargo.toml` — if it has no `[dev-dependencies]` section with `tempfile`, add:

```toml
[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 4: Run the token tests**

Run: `cargo test -p osiris-cli auth:: -- --test-threads=1`
Expected: PASS (single-threaded because the tests manipulate process-global env vars).

- [ ] **Step 5: Wire `auth.rs` into `lib.rs`, add commands, attach the token**

`crates/osiris-cli/src/lib.rs` currently reads:

```rust
pub mod client;
pub mod hunts;
```

Add `pub mod auth;` to it, matching this exact style:

```rust
pub mod auth;
pub mod client;
pub mod hunts;
```

`main.rs` references it as `osiris_cli::auth::read_token`/`write_token`/`delete_token`, matching the existing `osiris_cli::client::{...}`/`osiris_cli::hunts::template` import style already at the top of `main.rs` — no `mod auth;` line is needed in `main.rs` itself.

Add to the `Command` enum:

```rust
    /// Local session management (Phase 8a).
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
```

Add a new enum alongside `Command`:

```rust
#[derive(Subcommand)]
enum AuthAction {
    /// Log in and cache a session token at ~/.osiris/token.
    Login { username: String },
    /// Revoke the current session and delete the cached token.
    Logout,
}
```

Modify the `get()` helper to attach a Bearer token when one is cached, and give a clearer message on 401:

```rust
fn get(client: &reqwest::blocking::Client, url: String) -> Result<String, String> {
    let mut request = client.get(url);
    if let Some(token) = osiris_cli::auth::read_token() {
        request = request.bearer_auth(token);
    }
    let response = request.send().map_err(|e| format!("request failed: {}", e))?;
    let status = response.status();
    let body = response
        .text()
        .map_err(|e| format!("request failed: {}", e))?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err("not authenticated — run `osiris-cli auth login <username>`".to_string());
    }
    if !status.is_success() {
        return Err(format!("request failed: HTTP {}: {}", status, body));
    }
    Ok(body)
}

fn post_json(
    client: &reqwest::blocking::Client,
    url: String,
    body: serde_json::Value,
) -> Result<String, String> {
    let mut request = client.post(url).json(&body);
    if let Some(token) = osiris_cli::auth::read_token() {
        request = request.bearer_auth(token);
    }
    let response = request.send().map_err(|e| format!("request failed: {}", e))?;
    let status = response.status();
    let resp_body = response
        .text()
        .map_err(|e| format!("request failed: {}", e))?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err("not authenticated — run `osiris-cli auth login <username>`".to_string());
    }
    if !status.is_success() {
        return Err(format!("request failed: HTTP {}: {}", status, resp_body));
    }
    Ok(resp_body)
}
```

Add the `Auth` arm to the `match &cli.command` block in `main()`:

```rust
        Command::Auth { action } => match action {
            AuthAction::Login { username } => {
                let password = rpassword::prompt_password("Password: ").unwrap_or_default();
                let url = format!("{}/api/v1/auth/login", cli.server.trim_end_matches('/'));
                let body = serde_json::json!({ "username": username, "password": password });
                match client.post(&url).json(&body).send() {
                    Ok(resp) => {
                        let status = resp.status();
                        let text = resp.text().unwrap_or_default();
                        if status.is_success() {
                            match serde_json::from_str::<serde_json::Value>(&text) {
                                Ok(v) => {
                                    let token = v.get("token").and_then(|t| t.as_str()).unwrap_or_default();
                                    match osiris_cli::auth::write_token(token) {
                                        Ok(()) => Ok("logged in".to_string()),
                                        Err(e) => Err(format!("login succeeded but failed to save token: {}", e)),
                                    }
                                }
                                Err(e) => Err(format!("unexpected login response: {}", e)),
                            }
                        } else {
                            Err(format!("login failed: HTTP {}: {}", status, text))
                        }
                    }
                    Err(e) => Err(format!("request failed: {}", e)),
                }
            }
            AuthAction::Logout => {
                let url = format!("{}/api/v1/auth/logout", cli.server.trim_end_matches('/'));
                let _ = post_json(&client, url, serde_json::json!({}));
                osiris_cli::auth::delete_token();
                Ok("logged out".to_string())
            }
        },
```

- [ ] **Step 6: Run the whole CLI crate's tests**

Run: `cargo test -p osiris-cli`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/osiris-cli/Cargo.toml crates/osiris-cli/src/auth.rs crates/osiris-cli/src/main.rs crates/osiris-cli/src/lib.rs
git commit -m "feat(cli): add auth login/logout, attach cached session token to every request"
```

---

### Task 7: `osiris-cli` — `users create`/`users list`

**Files:**
- Modify: `crates/osiris-cli/src/main.rs`

**Interfaces:**
- Consumes: `post_json`, `get`, `osiris_cli::auth::read_token` (all from Task 6).
- Produces: `Command::Users { action: UsersAction }` with `UsersAction::{Create { username: String, role: RoleArg }, List}`.

- [ ] **Step 1: Add the `Users` command and `RoleArg`**

Add to the `Command` enum in `crates/osiris-cli/src/main.rs`:

```rust
    /// Admin-only user administration (Phase 8a).
    Users {
        #[command(subcommand)]
        action: UsersAction,
    },
```

Add alongside `AuthAction`:

```rust
#[derive(Clone, clap::ValueEnum)]
enum RoleArg {
    Viewer,
    Analyst,
    ResponseOperator,
    Admin,
}

impl RoleArg {
    fn wire(&self) -> &'static str {
        match self {
            RoleArg::Viewer => "VIEWER",
            RoleArg::Analyst => "ANALYST",
            RoleArg::ResponseOperator => "RESPONSE_OPERATOR",
            RoleArg::Admin => "ADMIN",
        }
    }
}

#[derive(Subcommand)]
enum UsersAction {
    /// Create a new user (requires an Admin session).
    Create {
        username: String,
        #[arg(long, value_enum)]
        role: RoleArg,
    },
    /// List all users (requires an Admin session).
    List,
}
```

- [ ] **Step 2: Add the `Users` arm to the command match**

```rust
        Command::Users { action } => match action {
            UsersAction::Create { username, role } => {
                let password = rpassword::prompt_password("Password for new user: ").unwrap_or_default();
                let url = format!("{}/api/v1/auth/users", cli.server.trim_end_matches('/'));
                let body = serde_json::json!({
                    "username": username,
                    "password": password,
                    "role": role.wire(),
                });
                post_json(&client, url, body)
            }
            UsersAction::List => {
                let url = format!("{}/api/v1/auth/users", cli.server.trim_end_matches('/'));
                get(&client, url)
            }
        },
```

- [ ] **Step 3: Build to verify it compiles**

Run: `cargo build -p osiris-cli`
Expected: builds cleanly (no new automated tests for this task — it's a thin wrapper over Task 6's already-tested `post_json`/`get`; verified manually in Task 8's e2e note below, matching this project's precedent of not writing a live-HTTP test for every CLI subcommand — see `Command::Hunt`'s own lack of a dedicated main.rs test).

- [ ] **Step 4: Commit**

```bash
git add crates/osiris-cli/src/main.rs
git commit -m "feat(cli): add users create/list (Admin-only)"
```

---

### Task 8: Console — Login screen, authStore, and route guard

**Files:**
- Create: `console/src/store/authStore.ts`, `console/src/store/authStore.test.ts`
- Create: `console/src/screens/auth/Login.tsx`, `console/src/screens/auth/Login.test.tsx`
- Modify: `console/src/api/types.ts`
- Modify: `console/src/api/client.ts`
- Modify: `console/src/api/hooks.ts`
- Modify: `console/src/App.tsx`

**Interfaces:**
- Produces: `useAuthStore` (Zustand store: `token`, `role`, `username`, `setSession`, `clearSession`), `Login` screen component, `login()` client function, `useLogin()` hook, a `RequireAuth` route guard in `App.tsx`.
- Consumes: existing `client.ts`'s `apiPost` pattern, existing `hooks.ts`'s `useMutation` pattern (`useCreateIncident` etc.).

- [ ] **Step 1: Write the failing `authStore` tests**

Create `console/src/store/authStore.test.ts`:

```typescript
import { beforeEach, describe, expect, it } from "vitest";
import { useAuthStore } from "./authStore";

describe("authStore", () => {
  beforeEach(() => {
    sessionStorage.clear();
    useAuthStore.getState().clearSession();
  });

  it("starts with no session", () => {
    expect(useAuthStore.getState().token).toBeNull();
    expect(useAuthStore.getState().role).toBeNull();
  });

  it("setSession stores the session and persists it to sessionStorage", () => {
    useAuthStore.getState().setSession({ token: "abc", role: "ADMIN", username: "alice" });

    expect(useAuthStore.getState().token).toBe("abc");
    expect(useAuthStore.getState().role).toBe("ADMIN");
    expect(JSON.parse(sessionStorage.getItem("osiris.session")!)).toEqual({
      token: "abc",
      role: "ADMIN",
      username: "alice",
    });
  });

  it("clearSession removes the session from state and sessionStorage", () => {
    useAuthStore.getState().setSession({ token: "abc", role: "ADMIN", username: "alice" });

    useAuthStore.getState().clearSession();

    expect(useAuthStore.getState().token).toBeNull();
    expect(sessionStorage.getItem("osiris.session")).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- --run authStore`
Expected: FAIL — `./authStore` module doesn't exist yet.

- [ ] **Step 3: Implement `authStore.ts`**

Create `console/src/store/authStore.ts`:

```typescript
import { create } from "zustand";

export type Role = "VIEWER" | "ANALYST" | "RESPONSE_OPERATOR" | "ADMIN";

interface StoredSession {
  token: string;
  role: Role;
  username: string;
}

const STORAGE_KEY = "osiris.session";

function readStoredSession(): StoredSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as StoredSession) : null;
  } catch {
    return null;
  }
}

function writeStoredSession(session: StoredSession | null): void {
  try {
    if (session) {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    } else {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // sessionStorage unavailable (e.g. a private browsing mode) — the
    // session still works for this tab's lifetime via in-memory state.
  }
}

export interface AuthState {
  token: string | null;
  role: Role | null;
  username: string | null;
  setSession: (session: StoredSession) => void;
  clearSession: () => void;
}

const initial = readStoredSession();

export const useAuthStore = create<AuthState>((set) => ({
  token: initial?.token ?? null,
  role: initial?.role ?? null,
  username: initial?.username ?? null,
  setSession: (session) => {
    writeStoredSession(session);
    set({ token: session.token, role: session.role, username: session.username });
  },
  clearSession: () => {
    writeStoredSession(null);
    set({ token: null, role: null, username: null });
  },
}));
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- --run authStore`
Expected: PASS.

- [ ] **Step 5: Add `Role`/`LoginResponse` to `types.ts`**

Add to `console/src/api/types.ts`:

```typescript
export type Role = "VIEWER" | "ANALYST" | "RESPONSE_OPERATOR" | "ADMIN";

export interface LoginResponse {
  token: string;
  role: Role;
  expires_at: number;
}
```

- [ ] **Step 6: Write the failing `client.ts` tests**

Add to `console/src/api/client.test.ts` (near the other `request`-level tests — check the existing file's `describe` grouping and add a new one):

```typescript
describe("authenticated requests", () => {
  beforeEach(() => {
    sessionStorage.clear();
    useAuthStore.getState().clearSession();
  });

  it("attaches an Authorization header when a token is present", async () => {
    useAuthStore.getState().setSession({ token: "tok123", role: "ADMIN", username: "alice" });
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ healthy: true, event_count: 0, last_write_at: 0 }), { status: 200 })
    );

    await fetchHealth();

    expect(fetch).toHaveBeenCalledWith("/api/v1/health", {
      headers: { Authorization: "Bearer tok123" },
    });
  });

  it("clears the session on a 401 response", async () => {
    useAuthStore.getState().setSession({ token: "tok123", role: "ADMIN", username: "alice" });
    vi.mocked(fetch).mockResolvedValueOnce(new Response("", { status: 401 }));

    await expect(fetchHealth()).rejects.toThrow();

    expect(useAuthStore.getState().token).toBeNull();
  });
});
```

Add the needed import at the top of `console/src/api/client.test.ts`:

```typescript
import { useAuthStore } from "../store/authStore";
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `cd console && npm test -- --run client.test`
Expected: FAIL — no `Authorization` header is attached yet, and a 401 doesn't clear the session yet.

- [ ] **Step 8: Implement the `client.ts` changes**

In `console/src/api/client.ts`, add the import:

```typescript
import { useAuthStore } from "../store/authStore";
```

Replace the `request<T>` function body with (only the header-building and the 401 branch are new — the rest is unchanged from today):

```typescript
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const url = `${API_BASE}${path}`;
  const token = useAuthStore.getState().token;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const hasHeaders = Object.keys(headers).length > 0;

  // Preserve the exact fetch() call shape each verb used before headers
  // existed (a bare `fetch(url)` for a headerless GET, `fetch(url,
  // {method})` for a headerless non-GET) whenever there's genuinely nothing
  // to attach — every existing call-site test runs with no token set and
  // asserts on that exact bare shape.
  const response =
    body !== undefined
      ? await fetch(url, { method, headers, body: JSON.stringify(body) })
      : method === "GET"
        ? hasHeaders
          ? await fetch(url, { headers })
          : await fetch(url)
        : hasHeaders
          ? await fetch(url, { method, headers })
          : await fetch(url, { method });

  if (!response.ok) {
    if (response.status === 401) {
      useAuthStore.getState().clearSession();
    }
    let detail = "";
    try {
      detail = await response.text();
    } catch {
      // ignore: fall back to the status-only message below
    }
    const message = detail
      ? `${method} ${path} failed with status ${response.status}: ${detail}`
      : `${method} ${path} failed with status ${response.status}`;
    throw new ApiError(response.status, message);
  }
  return (await response.json()) as T;
}
```

Add near the other `fetch*` functions:

```typescript
export function login(credentials: { username: string; password: string }): Promise<LoginResponse> {
  return apiPost<LoginResponse>("/auth/login", credentials);
}
```

Add `LoginResponse` to the `import type { ... } from "./types"` block at the top of the file.

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cd console && npm test -- --run client.test`
Expected: PASS, and every pre-existing test in this file still passes unchanged (they run with no token set, so `hasHeaders` is `false` and the bare `fetch(url)`/`fetch(url, {method})` shapes are preserved exactly).

- [ ] **Step 10: Add `useLogin()` to `hooks.ts`**

Add to `console/src/api/hooks.ts`:

```typescript
import { useAuthStore } from "../store/authStore";
// (add to the existing import block from "./client" — pull in `login`)

export function useLogin() {
  const setSession = useAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: (credentials: { username: string; password: string }) => login(credentials),
    onSuccess: (data, variables) => {
      setSession({ token: data.token, role: data.role, username: variables.username });
    },
  });
}
```

- [ ] **Step 11: Write the failing `Login` screen test**

Create `console/src/screens/auth/Login.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Login } from "./Login";

vi.mock("../../api/hooks");

describe("Login", () => {
  it("submits the entered username and password", () => {
    const mutate = vi.fn();
    vi.mocked(hooks.useLogin).mockReturnValue({
      mutate,
      isPending: false,
      isError: false,
    } as unknown as ReturnType<typeof hooks.useLogin>);

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Log in" }));

    expect(mutate).toHaveBeenCalledWith(
      { username: "alice", password: "secret" },
      expect.objectContaining({ onSuccess: expect.any(Function) })
    );
  });

  it("shows an error message when the login mutation fails", () => {
    vi.mocked(hooks.useLogin).mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
      isError: true,
    } as unknown as ReturnType<typeof hooks.useLogin>);

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Invalid username or password.");
  });
});
```

- [ ] **Step 12: Run the test to verify it fails**

Run: `cd console && npm test -- --run screens/auth/Login`
Expected: FAIL — `./Login` doesn't exist yet.

- [ ] **Step 13: Implement the `Login` screen**

Create `console/src/screens/auth/Login.tsx`:

```tsx
import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useLogin } from "../../api/hooks";

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const login = useLogin();
  const navigate = useNavigate();

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    login.mutate(
      { username, password },
      {
        onSuccess: () => navigate("/"),
      }
    );
  }

  return (
    <div className="login-screen">
      <h1>OSIRIS</h1>
      <form onSubmit={handleSubmit}>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button type="submit" disabled={login.isPending}>
          Log in
        </button>
        {login.isError && <p role="alert">Invalid username or password.</p>}
      </form>
    </div>
  );
}
```

- [ ] **Step 14: Run the test to verify it passes**

Run: `cd console && npm test -- --run screens/auth/Login`
Expected: PASS.

- [ ] **Step 15: Add the route guard to `App.tsx`**

In `console/src/App.tsx`, add imports:

```tsx
import { Navigate, Outlet } from "react-router-dom";
import { Login } from "./screens/auth/Login";
import { useAuthStore } from "./store/authStore";
```

Add above `export function App()`:

```tsx
function RequireAuth() {
  const token = useAuthStore((s) => s.token);
  return token ? <Outlet /> : <Navigate to="/login" replace />;
}
```

Change the `<Routes>` block from:

```tsx
          <Routes>
            <Route element={<Shell />}>
              <Route path="/" element={<Overview />} />
              ... (every existing route, unchanged)
            </Route>
          </Routes>
```

to:

```tsx
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route element={<RequireAuth />}>
              <Route element={<Shell />}>
                <Route path="/" element={<Overview />} />
                ... (every existing route, unchanged, same indentation shifted one level deeper)
              </Route>
            </Route>
          </Routes>
```

- [ ] **Step 16: Run the full console test suite**

Run: `cd console && npm test -- --run`
Expected: all existing tests still pass, plus the new `authStore`, `client.ts` auth, and `Login` tests. Check `App.test.tsx` in particular — if it renders `<App />` directly and asserts on nav items without first logging in, it will now redirect to `/login` and its assertions will fail; if so, update `App.test.tsx` to call `useAuthStore.getState().setSession(...)` with a fake session before rendering (matching how other tests seed store state), keeping the rest of that test unchanged.

- [ ] **Step 17: Build the Console to catch any type errors**

Run: `cd console && npm run build`
Expected: `tsc` + `vite build` succeed with zero errors.

- [ ] **Step 18: Commit**

```bash
git add console/src/store/authStore.ts console/src/store/authStore.test.ts console/src/screens/auth console/src/api/types.ts console/src/api/client.ts console/src/api/client.test.ts console/src/api/hooks.ts console/src/App.tsx console/src/App.test.tsx
git commit -m "feat(console): add Login screen, authStore, and a route guard"
```

---

## Manual End-to-End Verification (after all 8 tasks land)

1. Start `osiris-server` against a fresh `users.db` path — confirm the bootstrap admin credential is logged exactly once via `tracing::warn!`.
2. `osiris-cli auth login admin` with that password — confirm `~/.osiris/token` is created and a subsequent `osiris-cli health` succeeds.
3. `osiris-cli users create --role viewer analyst1` — confirm it succeeds (the bootstrap admin is authenticated) and prompts for a password.
4. `osiris-cli auth logout`, then `osiris-cli health` again — confirm it now fails with "not authenticated."
5. In the Console: navigate to any route while logged out — confirm redirect to `/login`; log in with the bootstrap admin; confirm redirect to `/`; confirm every existing screen (Processes, Files, Network, etc.) still loads data correctly.
6. `curl -s http://localhost:8080/api/v1/audit -H "Authorization: Bearer <admin token>"` — confirm the login/logout/user_create events from steps 2-4 appear, most-recent-first.
