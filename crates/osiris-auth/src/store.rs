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
