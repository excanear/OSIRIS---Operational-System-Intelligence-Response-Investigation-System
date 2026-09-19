# Phase 8f Multi-Tenant Scoping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Isolate every event-derived API surface (events, processes, files, network, containers, hosts, alerts, risk, graph, stories, live WebSocket) per tenant, with a server-side `host_id -> tenant_id` registry and per-user tenant binding; everything else is platform-only for tenant users.

**Architecture:** New `osiris-tenancy` crate (`tenants.db`). `users.tenant_id` (nullable = platform user). Five storage query plans gain `host_ids: Option<Vec<String>>`, enforced in SQL. A `TenantScopedStorage` decorator (in `osiris-api`) injects the host set into every read; a `ScopedStorage` axum extractor builds it per request from `AuthContext`. `auth_gate` denies tenant users on every route not on an explicit allowlist (deny-by-default).

**Tech Stack:** Rust workspace, axum 0.7, rusqlite 0.31 (bundled), tokio, React/TypeScript console (vitest).

**Spec:** `docs/superpowers/specs/2026-09-18-phase-8f-multi-tenant-scoping-design.md`

## Global Constraints

- A user belongs to at most one tenant; `tenant_id = None` is a platform user who sees everything. Existing roles (`Viewer < Analyst < ResponseOperator < Admin`) apply unchanged inside a tenant.
- A host belongs to at most one tenant (`host_tenants.host_id` PRIMARY KEY). An unassigned host is visible to platform users only.
- Visibility is evaluated per request from the registry, never stored on event rows.
- An empty tenant host set means an EMPTY result, never "no filter" (`host_ids: Some(vec![])` matches nothing).
- Fail closed: an unreadable `TenantStore` fails the request with 500 and never falls back to unscoped storage.
- A resource outside the tenant is indistinguishable from a missing one (`get_event` -> `None`, empty lists). A route a tenant user may not use returns 403.
- Tenant users may only call the routes on the allowlist in Task 5; every other route (incidents CRUD, evidence, audit, response, users, tenants) is platform-only until Phase 8g.
- `host_ids` values are hyphenated UUID strings, exactly as stored in the `host_id` columns (`Uuid::to_string()`).
- Do not scope incidents/evidence/audit/response, no multi-tenant users, no Console tenant-management screen, no tenant stamped on event rows (spec section 6).
- Follow the repo's per-subsystem-store pattern (one SQLite file per subsystem); do not run `cargo fmt` on files you do not otherwise touch (the repo is not fmt-clean).
- Commit messages end with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.
- Adding a field to `AuthState` requires updating ALL `AuthState {` literals (Task 5 lists them); adding `tenant_id` to `NewUser` requires updating ALL `NewUser {` literals (Task 2 lists them).
- Before trusting `cargo test --workspace`, run `cargo build -p osiris-cli -p osiris-server -p osiris-agent` (the e2e tests spawn those binaries).

## File Structure

- Create `crates/osiris-tenancy/{Cargo.toml,src/lib.rs,src/store.rs}` - `Tenant`, `TenantStore`, `SqliteTenantStore`.
- Modify `crates/osiris-auth/src/{types.rs,store.rs}` - `tenant_id` on `User`/`NewUser`, migration.
- Modify `crates/osiris-query/src/plan.rs`, `crates/osiris-storage/src/plan.rs`, `crates/osiris-storage-sqlite/src/sqlite_storage.rs` - `host_ids` plan field + SQL enforcement.
- Create `crates/osiris-api/src/tenant_scope.rs` - `TenantScopedStorage`, `ScopedStorage` extractor, `tenant_hosts` helper.
- Modify `crates/osiris-api/src/{auth_middleware.rs,auth.rs,lib.rs,stream.rs}`, `crates/osiris-api/Cargo.toml`.
- Create `crates/osiris-api/src/tenants.rs` - tenant admin routes.
- Modify `crates/osiris-server/src/{config.rs,main.rs}`, `crates/osiris-cli/src/main.rs`, `console/src/**`, `crates/osiris-e2e-tests/tests/end_to_end.rs`.

---

### Task 1: `osiris-tenancy` crate

**Files:**
- Create: `crates/osiris-tenancy/Cargo.toml`, `crates/osiris-tenancy/src/lib.rs`, `crates/osiris-tenancy/src/store.rs`

**Interfaces:**
- Produces (later tasks rely on these exactly):
  - `pub struct Tenant { pub tenant_id: Uuid, pub name: String, pub created_at: u64 }` (Serialize/Deserialize/Clone/PartialEq)
  - `pub enum TenantStoreError { DuplicateName(String), InvalidName(String), UnknownTenant(Uuid), Backend(String) }`
  - `pub trait TenantStore: Send + Sync { fn create_tenant(&self, name: &str) -> Result<Tenant, TenantStoreError>; fn list_tenants(&self) -> Result<Vec<Tenant>, TenantStoreError>; fn get_tenant(&self, tenant_id: Uuid) -> Result<Option<Tenant>, TenantStoreError>; fn assign_host(&self, host_id: Uuid, tenant_id: Uuid) -> Result<(), TenantStoreError>; fn unassign_host(&self, host_id: Uuid) -> Result<(), TenantStoreError>; fn hosts_of(&self, tenant_id: Uuid) -> Result<HashSet<Uuid>, TenantStoreError>; fn tenant_of(&self, host_id: Uuid) -> Result<Option<Uuid>, TenantStoreError>; }`
  - `pub struct SqliteTenantStore` with `pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, TenantStoreError>`

- [ ] **Step 1: Create the crate manifest**

`crates/osiris-tenancy/Cargo.toml` (the workspace `crates/*` glob already includes it):

```toml
[package]
name = "osiris-tenancy"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
uuid = { workspace = true }
rusqlite = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

`crates/osiris-tenancy/src/lib.rs`:

```rust
//! Tenant registry: which tenants exist and which hosts belong to which
//! tenant (ARCHITECTURE.md §21.5). Pure logic over its own SQLite file
//! (`tenants.db`), same per-subsystem-store pattern as `osiris-auth`.

mod store;

pub use store::{SqliteTenantStore, Tenant, TenantStore, TenantStoreError};
```

- [ ] **Step 2: Write the failing tests**

Create `crates/osiris-tenancy/src/store.rs` containing ONLY the test module first (the types do not exist yet, so it will not compile - that is the red step):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, SqliteTenantStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn create_and_list_tenants_oldest_first() {
        let (_d, s) = store();
        let a = s.create_tenant("acme").unwrap();
        let b = s.create_tenant("globex").unwrap();
        let all = s.list_tenants().unwrap();
        assert_eq!(all.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), vec!["acme", "globex"]);
        assert_eq!(s.get_tenant(a.tenant_id).unwrap().unwrap().name, "acme");
        assert_ne!(a.tenant_id, b.tenant_id);
    }

    #[test]
    fn duplicate_or_blank_names_are_rejected() {
        let (_d, s) = store();
        s.create_tenant("acme").unwrap();
        assert!(matches!(s.create_tenant("acme"), Err(TenantStoreError::DuplicateName(_))));
        assert!(matches!(s.create_tenant("   "), Err(TenantStoreError::InvalidName(_))));
        assert!(matches!(
            s.create_tenant(&"x".repeat(129)),
            Err(TenantStoreError::InvalidName(_))
        ));
    }

    #[test]
    fn assigning_hosts_and_reading_them_back() {
        let (_d, s) = store();
        let t = s.create_tenant("acme").unwrap();
        let h1 = Uuid::new_v4();
        let h2 = Uuid::new_v4();
        s.assign_host(h1, t.tenant_id).unwrap();
        s.assign_host(h2, t.tenant_id).unwrap();
        let hosts = s.hosts_of(t.tenant_id).unwrap();
        assert_eq!(hosts, [h1, h2].into_iter().collect());
        assert_eq!(s.tenant_of(h1).unwrap(), Some(t.tenant_id));
        assert_eq!(s.tenant_of(Uuid::new_v4()).unwrap(), None);
    }

    #[test]
    fn reassigning_a_host_moves_it_to_the_new_tenant() {
        let (_d, s) = store();
        let a = s.create_tenant("acme").unwrap();
        let b = s.create_tenant("globex").unwrap();
        let h = Uuid::new_v4();
        s.assign_host(h, a.tenant_id).unwrap();
        s.assign_host(h, b.tenant_id).unwrap();
        assert!(s.hosts_of(a.tenant_id).unwrap().is_empty());
        assert!(s.hosts_of(b.tenant_id).unwrap().contains(&h));
    }

    #[test]
    fn unassigning_a_host_removes_it() {
        let (_d, s) = store();
        let t = s.create_tenant("acme").unwrap();
        let h = Uuid::new_v4();
        s.assign_host(h, t.tenant_id).unwrap();
        s.unassign_host(h).unwrap();
        assert_eq!(s.tenant_of(h).unwrap(), None);
        // Unassigning an unassigned host is a harmless no-op.
        s.unassign_host(h).unwrap();
    }

    #[test]
    fn assigning_to_an_unknown_tenant_is_an_error() {
        let (_d, s) = store();
        let err = s.assign_host(Uuid::new_v4(), Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, TenantStoreError::UnknownTenant(_)));
    }

    #[test]
    fn reopening_an_existing_database_is_idempotent_and_keeps_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tenants.db");
        let t = {
            let s = SqliteTenantStore::open(&path).unwrap();
            s.create_tenant("acme").unwrap()
        };
        let s = SqliteTenantStore::open(&path).unwrap();
        assert_eq!(s.get_tenant(t.tenant_id).unwrap().unwrap().name, "acme");
    }
}
```

Run: `cargo test -p osiris-tenancy`
Expected: FAIL to compile (`SqliteTenantStore`, `TenantStoreError`, `Uuid` not found).

- [ ] **Step 3: Implement the store**

Prepend to `crates/osiris-tenancy/src/store.rs` (above the test module):

```rust
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_NAME_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub tenant_id: Uuid,
    pub name: String,
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TenantStoreError {
    #[error("tenant name already exists: {0}")]
    DuplicateName(String),
    #[error("invalid tenant name: {0}")]
    InvalidName(String),
    #[error("no such tenant: {0}")]
    UnknownTenant(Uuid),
    #[error("tenant store backend error: {0}")]
    Backend(String),
}

fn backend(e: impl std::fmt::Display) -> TenantStoreError {
    TenantStoreError::Backend(e.to_string())
}

pub trait TenantStore: Send + Sync {
    fn create_tenant(&self, name: &str) -> Result<Tenant, TenantStoreError>;
    fn list_tenants(&self) -> Result<Vec<Tenant>, TenantStoreError>;
    fn get_tenant(&self, tenant_id: Uuid) -> Result<Option<Tenant>, TenantStoreError>;
    /// Assigns (or reassigns) `host_id` to `tenant_id`. A host belongs to at
    /// most one tenant, so this replaces any previous assignment.
    fn assign_host(&self, host_id: Uuid, tenant_id: Uuid) -> Result<(), TenantStoreError>;
    fn unassign_host(&self, host_id: Uuid) -> Result<(), TenantStoreError>;
    fn hosts_of(&self, tenant_id: Uuid) -> Result<HashSet<Uuid>, TenantStoreError>;
    fn tenant_of(&self, host_id: Uuid) -> Result<Option<Uuid>, TenantStoreError>;
}

pub struct SqliteTenantStore {
    conn: Mutex<Connection>,
}

impl SqliteTenantStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, TenantStoreError> {
        let conn = Connection::open(path).map_err(backend)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS host_tenants (
                host_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_host_tenants_tenant ON host_tenants(tenant_id);",
        )
        .map_err(backend)?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn row_to_tenant(row: &rusqlite::Row) -> rusqlite::Result<Tenant> {
    let id: String = row.get(0)?;
    let created_at: i64 = row.get(2)?;
    Ok(Tenant {
        tenant_id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
        name: row.get(1)?,
        created_at: created_at as u64,
    })
}

impl TenantStore for SqliteTenantStore {
    fn create_tenant(&self, name: &str) -> Result<Tenant, TenantStoreError> {
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(TenantStoreError::InvalidName(name.to_string()));
        }
        let tenant = Tenant {
            tenant_id: Uuid::new_v4(),
            name: name.to_string(),
            created_at: now_unix(),
        };
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        conn.execute(
            "INSERT INTO tenants (tenant_id, name, created_at) VALUES (?1, ?2, ?3)",
            params![tenant.tenant_id.to_string(), tenant.name, tenant.created_at as i64],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                TenantStoreError::DuplicateName(tenant.name.clone())
            } else {
                backend(e)
            }
        })?;
        Ok(tenant)
    }

    fn list_tenants(&self) -> Result<Vec<Tenant>, TenantStoreError> {
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        let mut stmt = conn
            .prepare("SELECT tenant_id, name, created_at FROM tenants ORDER BY created_at ASC, name ASC")
            .map_err(backend)?;
        let rows = stmt.query_map([], row_to_tenant).map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn get_tenant(&self, tenant_id: Uuid) -> Result<Option<Tenant>, TenantStoreError> {
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        let mut stmt = conn
            .prepare("SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1")
            .map_err(backend)?;
        let mut rows = stmt
            .query_map(params![tenant_id.to_string()], row_to_tenant)
            .map_err(backend)?;
        rows.next().transpose().map_err(backend)
    }

    fn assign_host(&self, host_id: Uuid, tenant_id: Uuid) -> Result<(), TenantStoreError> {
        if self.get_tenant(tenant_id)?.is_none() {
            return Err(TenantStoreError::UnknownTenant(tenant_id));
        }
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        conn.execute(
            "INSERT INTO host_tenants (host_id, tenant_id) VALUES (?1, ?2) \
             ON CONFLICT(host_id) DO UPDATE SET tenant_id = excluded.tenant_id",
            params![host_id.to_string(), tenant_id.to_string()],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn unassign_host(&self, host_id: Uuid) -> Result<(), TenantStoreError> {
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        conn.execute("DELETE FROM host_tenants WHERE host_id = ?1", params![host_id.to_string()])
            .map_err(backend)?;
        Ok(())
    }

    fn hosts_of(&self, tenant_id: Uuid) -> Result<HashSet<Uuid>, TenantStoreError> {
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        let mut stmt = conn
            .prepare("SELECT host_id FROM host_tenants WHERE tenant_id = ?1")
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![tenant_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(backend)?;
        let mut out = HashSet::new();
        for row in rows {
            if let Ok(id) = Uuid::parse_str(&row.map_err(backend)?) {
                out.insert(id);
            }
        }
        Ok(out)
    }

    fn tenant_of(&self, host_id: Uuid) -> Result<Option<Uuid>, TenantStoreError> {
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        let mut stmt = conn
            .prepare("SELECT tenant_id FROM host_tenants WHERE host_id = ?1")
            .map_err(backend)?;
        let mut rows = stmt
            .query_map(params![host_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(backend)?;
        match rows.next().transpose().map_err(backend)? {
            Some(s) => Ok(Uuid::parse_str(&s).ok()),
            None => Ok(None),
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p osiris-tenancy` then `cargo clippy -p osiris-tenancy --all-targets`
Expected: 7 passed, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-tenancy Cargo.lock
git commit -m "feat(tenancy): tenant registry crate with host assignment

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: `tenant_id` on users

**Files:**
- Modify: `crates/osiris-auth/src/types.rs`, `crates/osiris-auth/src/store.rs`
- Modify (add `tenant_id: None,` to each `NewUser {` literal): `crates/osiris-api/src/auth.rs` (4 literals, ~lines 260, 363, 389, 416), `crates/osiris-api/src/auth_middleware.rs` (2, ~235, 292), `crates/osiris-api/tests/composed_router_auth.rs` (1, ~176), plus the bootstrap literal inside `store.rs::open`. Run `grep -rn "NewUser {" --include=*.rs crates` and update every hit (compiler will flag any missed).

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `User { .., pub tenant_id: Option<Uuid> }`, `NewUser { .., pub tenant_id: Option<Uuid> }`. `UserStore` trait signatures unchanged.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `crates/osiris-auth/src/store.rs`:

```rust
    #[test]
    fn a_user_created_with_a_tenant_round_trips_it() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
        let tenant = Uuid::new_v4();
        let created = store
            .create_user(NewUser {
                username: "alice".to_string(),
                password_hash: "h".to_string(),
                role: Role::Analyst,
                tenant_id: Some(tenant),
            })
            .unwrap();
        assert_eq!(created.tenant_id, Some(tenant));
        let fetched = store.get_user_by_id(created.user_id).unwrap().unwrap();
        assert_eq!(fetched.tenant_id, Some(tenant));
        let by_name = store.get_user_by_username("alice").unwrap().unwrap();
        assert_eq!(by_name.tenant_id, Some(tenant));
    }

    #[test]
    fn the_bootstrap_admin_is_a_platform_user_without_a_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = SqliteUserStore::open(dir.path().join("users.db")).unwrap();
        let admin = store.get_user_by_username("admin").unwrap().unwrap();
        assert_eq!(admin.tenant_id, None);
    }

    #[test]
    fn opening_a_pre_tenant_database_adds_the_column_and_keeps_users_as_platform() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.db");
        {
            // The schema exactly as Phase 8a created it (no tenant_id column).
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                INSERT INTO users VALUES ('11111111-1111-1111-1111-111111111111','legacy','h','ADMIN',1);",
            )
            .unwrap();
        }
        let (store, bootstrap) = SqliteUserStore::open(&path).unwrap();
        assert!(bootstrap.is_none(), "an existing user means no bootstrap admin");
        let legacy = store.get_user_by_username("legacy").unwrap().unwrap();
        assert_eq!(legacy.tenant_id, None);
        // And reopening again (column already present) is a no-op.
        let (_store2, _) = SqliteUserStore::open(&path).unwrap();
    }
```

Run: `cargo test -p osiris-auth`
Expected: FAIL to compile (`tenant_id` is not a field).

- [ ] **Step 2: Implement**

`crates/osiris-auth/src/types.rs`: add to `User` after `created_at`:

```rust
    /// `None` = platform user (sees every tenant). `Some` = belongs to
    /// exactly one tenant (Phase 8f).
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
```

and to `NewUser` after `role`:

```rust
    pub tenant_id: Option<Uuid>,
```

`crates/osiris-auth/src/store.rs`:

1. `row_to_user`: read column 5 and set the field:

```rust
    let tenant_id: Option<String> = row.get(5)?;
    Ok(User {
        user_id: Uuid::parse_str(&user_id).unwrap_or_else(|_| Uuid::nil()),
        username,
        password_hash,
        role: role_from_string(&role),
        created_at: created_at as u64,
        tenant_id: tenant_id.and_then(|s| Uuid::parse_str(&s).ok()),
    })
```

2. In `open`, extend the `users` CREATE TABLE with `tenant_id TEXT` after `created_at INTEGER NOT NULL,` (new databases), and immediately after the `execute_batch(...)` call add the guarded migration for old databases:

```rust
        let has_tenant_column: bool = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(users)")
                .map_err(|e| UserStoreError::Backend(e.to_string()))?;
            let names = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| UserStoreError::Backend(e.to_string()))?;
            let mut found = false;
            for name in names {
                if name.map_err(|e| UserStoreError::Backend(e.to_string()))? == "tenant_id" {
                    found = true;
                }
            }
            found
        };
        if !has_tenant_column {
            conn.execute("ALTER TABLE users ADD COLUMN tenant_id TEXT", [])
                .map_err(|e| UserStoreError::Backend(e.to_string()))?;
        }
```

(the `CREATE TABLE IF NOT EXISTS users` for a NEW database now includes the column, so the PRAGMA check finds it and skips the ALTER).

3. The three user SELECTs (`get_user_by_username`, `get_user_by_id`, `list_users`): append `, tenant_id` to the selected column list (after `created_at`).
4. `create_user`: INSERT gets the sixth column/param and the returned `User` carries it:

```rust
        conn.execute(
            "INSERT INTO users (user_id, username, password_hash, role, created_at, tenant_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                user_id.to_string(),
                new_user.username,
                new_user.password_hash,
                role_str,
                created_at as i64,
                new_user.tenant_id.map(|t| t.to_string())
            ],
        )
```
and `Ok(User { .., created_at, tenant_id: new_user.tenant_id })`.
5. The bootstrap `NewUser { .. }` literal in `open` gets `tenant_id: None,`.
6. Update every other `NewUser {` literal listed under Files with `tenant_id: None,`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p osiris-auth -p osiris-api` and `cargo clippy -p osiris-auth -p osiris-api --all-targets`
Expected: all pass (osiris-auth incl. the 3 new tests), clippy clean.

- [ ] **Step 4: Commit**

```bash
git add -A crates/osiris-auth crates/osiris-api
git commit -m "feat(auth): optional tenant_id on users with guarded migration

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: `host_ids` on the query plans, enforced in SQL

**Files:**
- Modify: `crates/osiris-query/src/plan.rs` (`EventQueryPlan`), `crates/osiris-storage/src/plan.rs` (`QueryPlan`, `AlertQueryPlan`, `RelationshipQueryPlan`, `RiskQueryPlan`), `crates/osiris-storage-sqlite/src/sqlite_storage.rs`

**Interfaces:**
- Produces: on each of the five plan structs a new public field `pub host_ids: Option<Vec<String>>` (hyphenated UUID strings). `None` = no restriction; `Some(vec![])` = matches nothing. All five derive `Default`, so existing `..X::new()` / `..Default::default()` literals keep working; any literal that lists every field must gain `host_ids: None` (compiler will flag).

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module of `crates/osiris-storage-sqlite/src/sqlite_storage.rs`:

```rust
    fn event_on(host: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
        let mut e = sample_event(pid, timestamp);
        e.host_id = host;
        e.host.host_id = host;
        e
    }

    #[test]
    fn host_ids_restricts_query_and_query_events_and_empty_matches_nothing() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        storage
            .batch_write(&[event_on(a, 1, 100), event_on(b, 2, 200), event_on(a, 3, 300)])
            .unwrap();

        let only_a = storage
            .query(&QueryPlan { host_ids: Some(vec![a.to_string()]), ..QueryPlan::new() })
            .unwrap();
        assert_eq!(only_a.len(), 2);
        assert!(only_a.iter().all(|e| e.host_id == a));

        let none = storage
            .query(&QueryPlan { host_ids: Some(vec![]), ..QueryPlan::new() })
            .unwrap();
        assert!(none.is_empty(), "an empty host set must match nothing, not everything");

        let both = storage
            .query(&QueryPlan {
                host_ids: Some(vec![a.to_string(), b.to_string()]),
                ..QueryPlan::new()
            })
            .unwrap();
        assert_eq!(both.len(), 3);

        let ev_a = storage
            .query_events(&osiris_query::EventQueryPlan {
                host_ids: Some(vec![a.to_string()]),
                ..osiris_query::EventQueryPlan::new()
            })
            .unwrap();
        assert_eq!(ev_a.len(), 2);
        assert!(ev_a.iter().all(|e| e.host_id == a));
        let ev_none = storage
            .query_events(&osiris_query::EventQueryPlan {
                host_ids: Some(vec![]),
                ..osiris_query::EventQueryPlan::new()
            })
            .unwrap();
        assert!(ev_none.is_empty());
    }

    #[test]
    fn host_ids_combines_with_an_or_filter_that_defeats_other_pushdown() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        storage.batch_write(&[event_on(a, 1, 100), event_on(b, 2, 200)]).unwrap();
        let plan = osiris_query::EventQueryPlan {
            host_ids: Some(vec![a.to_string()]),
            ..osiris_query::EventQueryPlan::with_filter(
                "event_type = \"PROCESS_EXEC\" OR event_type = \"FILE_WRITE\"",
            )
            .unwrap()
        };
        let got = storage.query_events(&plan).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id, a);
    }

    #[test]
    fn host_ids_restricts_alerts_and_risk_scores() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let alert = |host: Uuid| {
            osiris_schema::Alert::new(
                "r1", 1, "deadbeef", osiris_schema::Severity::High, 10, host,
                vec!["x".to_string()], vec![Uuid::now_v7()],
            )
            .unwrap()
        };
        storage.write_alerts(&[alert(a), alert(b)]).unwrap();
        let got = storage
            .query_alerts(&AlertQueryPlan { host_ids: Some(vec![a.to_string()]), ..AlertQueryPlan::new() })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id(), a);
        assert!(storage
            .query_alerts(&AlertQueryPlan { host_ids: Some(vec![]), ..AlertQueryPlan::new() })
            .unwrap()
            .is_empty());

        let mut ra = sample_risk_record(None, 10);
        ra.host_id = a;
        let mut rb = sample_risk_record(None, 20);
        rb.host_id = b;
        storage.write_risk_scores(&[ra, rb]).unwrap();
        let got = storage
            .query_risk_scores(&RiskQueryPlan { host_ids: Some(vec![b.to_string()]), ..RiskQueryPlan::new() })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id, b);
    }

    #[test]
    fn host_ids_restricts_relationships_through_the_source_event() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let ev_a = event_on(a, 1, 100);
        let ev_b = event_on(b, 2, 200);
        storage.batch_write(&[ev_a.clone(), ev_b.clone()]).unwrap();
        let edge = |event: &CanonicalEvent| EntityRelationship {
            from: EntityRef::Ip { addr: "10.0.0.1".to_string() },
            to: EntityRef::Ip { addr: "203.0.113.10".to_string() },
            relation: Relation::ConnectedTo,
            event_id: event.event_id,
            timestamp: event.timestamp,
        };
        storage.write_relationships(&[edge(&ev_a), edge(&ev_b)]).unwrap();
        let got = storage
            .query_relationships(&RelationshipQueryPlan {
                host_ids: Some(vec![a.to_string()]),
                ..RelationshipQueryPlan::new()
            })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].event_id, ev_a.event_id);
        assert!(storage
            .query_relationships(&RelationshipQueryPlan { host_ids: Some(vec![]), ..RelationshipQueryPlan::new() })
            .unwrap()
            .is_empty());
    }
```

(If `EntityRelationship`, `EntityRef`, `Relation`, `AlertQueryPlan`, `RiskQueryPlan`, `RelationshipQueryPlan` are not already imported in the test module, add them to its `use` lines - the existing relationship tests already import them, so reuse those imports.)

Run: `cargo test -p osiris-storage-sqlite host_ids`
Expected: FAIL to compile (`host_ids` field missing).

- [ ] **Step 2: Add the plan field**

In `crates/osiris-query/src/plan.rs` `EventQueryPlan` and in `crates/osiris-storage/src/plan.rs` `QueryPlan`, `AlertQueryPlan`, `RelationshipQueryPlan`, `RiskQueryPlan`, add (last field of each struct):

```rust
    /// Tenant scoping (Phase 8f): when `Some`, only rows whose `host_id` is in
    /// this list are returned; `Some(vec![])` matches nothing. Hyphenated UUID
    /// strings, exactly as stored.
    pub host_ids: Option<Vec<String>>,
```

Fix any struct literal that lists every field of one of these plans by adding `host_ids: None` (the compiler flags them; most use `..X::new()`/`..Default::default()` and need nothing).

- [ ] **Step 3: Enforce it in SQLite**

In `crates/osiris-storage-sqlite/src/sqlite_storage.rs`, add a helper above `impl SqliteStorage`:

```rust
/// Appends the tenant host restriction to a WHERE clause already in progress:
/// ` AND <column> IN (?,..)`, or ` AND 1=0` for an empty list (an empty host
/// set must match nothing, never everything).
fn push_host_filter(
    sql: &mut String,
    params: &mut Vec<Box<dyn rusqlite::ToSql>>,
    column: &str,
    host_ids: &Option<Vec<String>>,
) {
    let Some(ids) = host_ids else { return };
    if ids.is_empty() {
        sql.push_str(" AND 1=0");
        return;
    }
    sql.push_str(&format!(" AND {column} IN ({})", vec!["?"; ids.len()].join(",")));
    for id in ids {
        params.push(Box::new(id.clone()));
    }
}
```

Call it (before the `since` handling / `ORDER BY`) in:
- `query`: `push_host_filter(&mut sql, &mut sql_params, "host_id", &plan.host_ids);`
- `query_alerts`: `push_host_filter(&mut sql, &mut sql_params, "a.host_id", &plan.host_ids);` (place it after the `if !plan.evidence_event_ids.is_empty() {..} else {..}` block so the WHERE already exists).
- `query_risk_scores`: column `"host_id"`.
- `query_events_batched`: after the `if let Some(filter) = &plan.filter { .. }` block and before the `since` handling, `push_host_filter(&mut base_sql, &mut base_params, "host_id", &plan.host_ids);`
- `query_relationships`: a sub-select variant, after the entity block:

```rust
        if let Some(ids) = &plan.host_ids {
            if ids.is_empty() {
                sql.push_str(" AND 1=0");
            } else {
                sql.push_str(&format!(
                    " AND event_id IN (SELECT event_id FROM events WHERE host_id IN ({}))",
                    vec!["?"; ids.len()].join(",")
                ));
                for id in ids {
                    sql_params.push(Box::new(id.clone()));
                }
            }
        }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p osiris-storage-sqlite -p osiris-query -p osiris-storage` then `cargo build --workspace` (any other crate with a fully-listed plan literal fails here; fix with `host_ids: None`) and `cargo clippy -p osiris-storage-sqlite --all-targets`
Expected: all pass, including the 4 new tests; workspace builds.

- [ ] **Step 5: Commit**

```bash
git add -A crates
git commit -m "feat(storage): host_ids restriction on every query plan, enforced in SQL

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: `TenantScopedStorage` decorator

**Files:**
- Create: `crates/osiris-api/src/tenant_scope.rs`
- Modify: `crates/osiris-api/src/lib.rs` (add `pub mod tenant_scope;` next to the other `pub mod` lines at the bottom), `crates/osiris-api/Cargo.toml` (add `osiris-tenancy = { path = "../osiris-tenancy" }` under `[dependencies]`)

**Interfaces:**
- Consumes: Task 3's `host_ids` plan fields.
- Produces: `pub struct TenantScopedStorage`; `TenantScopedStorage::new(inner: Arc<dyn Storage>, hosts: HashSet<Uuid>) -> Self`; it implements `osiris_storage::Storage`. (The `ScopedStorage` extractor is added to this same file in Task 6.)

Behavior: every read merges the tenant host list into the plan's `host_ids`, INTERSECTING with any list the caller already set (the decorator only ever narrows); `get_event` returns `None` for foreign hosts; every write/delete/retention returns `StorageError::Backend("tenant-scoped storage is read-only".into())`; `health` delegates.

- [ ] **Step 1: Write the failing tests**

Create `crates/osiris-api/src/tenant_scope.rs` with only the test module (red step):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, CanonicalEvent, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source,
        SCHEMA_VERSION,
    };
    use osiris_storage::{QueryPlan, RiskQueryPlan};
    use osiris_storage_sqlite::SqliteStorage;

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
                hostname: "h".to_string(),
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

    struct Fixture {
        _dir: tempfile::TempDir,
        inner: Arc<dyn Storage>,
        a: Uuid,
        b: Uuid,
        unassigned: Uuid,
        ev_a: CanonicalEvent,
        ev_b: CanonicalEvent,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let (a, b, unassigned) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let ev_a = event_on(a, 1, 100);
        let ev_b = event_on(b, 2, 200);
        let ev_u = event_on(unassigned, 3, 300);
        storage.batch_write(&[ev_a.clone(), ev_b.clone(), ev_u]).unwrap();
        Fixture { _dir: dir, inner: Arc::new(storage), a, b, unassigned, ev_a, ev_b }
    }

    fn scoped(f: &Fixture, hosts: &[Uuid]) -> TenantScopedStorage {
        TenantScopedStorage::new(f.inner.clone(), hosts.iter().copied().collect())
    }

    #[test]
    fn query_and_query_events_only_return_the_tenants_hosts() {
        let f = fixture();
        let s = scoped(&f, &[f.a]);
        let got = s.query(&QueryPlan::new()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id, f.a);
        let got = s.query_events(&osiris_query::EventQueryPlan::new()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id, f.a);
    }

    #[test]
    fn an_empty_host_set_yields_nothing_never_everything() {
        let f = fixture();
        let s = scoped(&f, &[]);
        assert!(s.query(&QueryPlan::new()).unwrap().is_empty());
        assert!(s.query_events(&osiris_query::EventQueryPlan::new()).unwrap().is_empty());
        assert!(s.query_alerts(&AlertQueryPlan::new()).unwrap().is_empty());
        assert!(s.query_risk_scores(&RiskQueryPlan::new()).unwrap().is_empty());
        assert!(s.query_relationships(&RelationshipQueryPlan::new()).unwrap().is_empty());
    }

    #[test]
    fn a_caller_supplied_host_list_can_only_be_narrowed_never_widened() {
        let f = fixture();
        let s = scoped(&f, &[f.a]);
        // Caller asks for tenant host + a foreign host: only the tenant's survives.
        let got = s
            .query(&QueryPlan {
                host_ids: Some(vec![f.a.to_string(), f.b.to_string()]),
                ..QueryPlan::new()
            })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_id, f.a);
        // Caller asks ONLY for a foreign host: empty, not the foreign data.
        let got = s
            .query(&QueryPlan { host_ids: Some(vec![f.b.to_string()]), ..QueryPlan::new() })
            .unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn get_event_hides_events_from_other_hosts() {
        let f = fixture();
        let s = scoped(&f, &[f.a]);
        assert!(s.get_event(f.ev_a.event_id).unwrap().is_some());
        assert!(s.get_event(f.ev_b.event_id).unwrap().is_none());
        assert!(s.get_event(Uuid::new_v4()).unwrap().is_none());
        assert!(f.unassigned != f.a);
    }

    #[test]
    fn writes_deletes_and_retention_are_refused() {
        let f = fixture();
        let s = scoped(&f, &[f.a]);
        assert!(s.write(&f.ev_a).is_err());
        assert!(s.batch_write(&[f.ev_a.clone()]).is_err());
        assert!(s.write_alerts(&[]).is_err());
        assert!(s.write_relationships(&[]).is_err());
        assert!(s.write_risk_scores(&[]).is_err());
        assert!(s.delete(&osiris_storage::DeleteCriteria::default()).is_err());
        assert!(s.retention_apply(&osiris_storage::RetentionPolicy::default()).is_err());
    }

    #[test]
    fn health_delegates_to_the_inner_storage() {
        let f = fixture();
        assert_eq!(scoped(&f, &[f.a]).health().healthy, f.inner.health().healthy);
    }
}
```

Run: `cargo test -p osiris-api tenant_scope`
Expected: FAIL to compile (`TenantScopedStorage` not defined). If `DeleteCriteria`/`RetentionPolicy` do not derive `Default`, construct them with the fields their definitions in `crates/osiris-storage/src/plan.rs` require (read that file); the assertion is only that the call returns `Err`.

- [ ] **Step 2: Implement the decorator**

Prepend to `crates/osiris-api/src/tenant_scope.rs`:

```rust
//! Tenant isolation for event-derived reads (Phase 8f). `TenantScopedStorage`
//! decorates a `Storage` so every read is restricted to one tenant's hosts;
//! the restriction is pushed into SQL through each plan's `host_ids`.

use std::collections::HashSet;
use std::sync::Arc;

use osiris_schema::{Alert, CanonicalEvent, EntityRelationship, RiskScoreRecord};
use osiris_storage::{
    AlertQueryPlan, DeleteCriteria, QueryPlan, RelationshipQueryPlan, RetentionPolicy,
    RetentionReport, RiskQueryPlan, Storage, StorageError, StorageHealth, WriteReport,
};
use uuid::Uuid;

fn read_only() -> StorageError {
    StorageError::Backend("tenant-scoped storage is read-only".to_string())
}

pub struct TenantScopedStorage {
    inner: Arc<dyn Storage>,
    hosts: HashSet<Uuid>,
}

impl TenantScopedStorage {
    pub fn new(inner: Arc<dyn Storage>, hosts: HashSet<Uuid>) -> Self {
        Self { inner, hosts }
    }

    /// The effective host list for a plan: the tenant's hosts, intersected
    /// with whatever the caller already asked for. The decorator can only
    /// narrow a query, never widen it.
    fn effective(&self, requested: &Option<Vec<String>>) -> Option<Vec<String>> {
        let allowed: Vec<String> = self.hosts.iter().map(|h| h.to_string()).collect();
        match requested {
            None => Some(allowed),
            Some(want) => Some(want.iter().filter(|h| allowed.contains(h)).cloned().collect()),
        }
    }
}

impl Storage for TenantScopedStorage {
    fn write(&self, _event: &CanonicalEvent) -> Result<(), StorageError> {
        Err(read_only())
    }
    fn batch_write(&self, _events: &[CanonicalEvent]) -> Result<WriteReport, StorageError> {
        Err(read_only())
    }
    fn query(&self, plan: &QueryPlan) -> Result<Vec<CanonicalEvent>, StorageError> {
        let mut plan = plan.clone();
        plan.host_ids = self.effective(&plan.host_ids);
        self.inner.query(&plan)
    }
    fn query_events(&self, plan: &osiris_query::EventQueryPlan) -> Result<Vec<CanonicalEvent>, StorageError> {
        let mut plan = plan.clone();
        plan.host_ids = self.effective(&plan.host_ids);
        self.inner.query_events(&plan)
    }
    fn get_event(&self, event_id: Uuid) -> Result<Option<CanonicalEvent>, StorageError> {
        Ok(self
            .inner
            .get_event(event_id)?
            .filter(|event| self.hosts.contains(&event.host_id)))
    }
    fn delete(&self, _criteria: &DeleteCriteria) -> Result<u64, StorageError> {
        Err(read_only())
    }
    fn retention_apply(&self, _policy: &RetentionPolicy) -> Result<RetentionReport, StorageError> {
        Err(read_only())
    }
    fn health(&self) -> StorageHealth {
        self.inner.health()
    }
    fn write_alerts(&self, _alerts: &[Alert]) -> Result<WriteReport, StorageError> {
        Err(read_only())
    }
    fn query_alerts(&self, plan: &AlertQueryPlan) -> Result<Vec<Alert>, StorageError> {
        let mut plan = plan.clone();
        plan.host_ids = self.effective(&plan.host_ids);
        self.inner.query_alerts(&plan)
    }
    fn write_relationships(&self, _edges: &[EntityRelationship]) -> Result<WriteReport, StorageError> {
        Err(read_only())
    }
    fn query_relationships(&self, plan: &RelationshipQueryPlan) -> Result<Vec<EntityRelationship>, StorageError> {
        let mut plan = plan.clone();
        plan.host_ids = self.effective(&plan.host_ids);
        self.inner.query_relationships(&plan)
    }
    fn write_risk_scores(&self, _scores: &[RiskScoreRecord]) -> Result<WriteReport, StorageError> {
        Err(read_only())
    }
    fn query_risk_scores(&self, plan: &RiskQueryPlan) -> Result<Vec<RiskScoreRecord>, StorageError> {
        let mut plan = plan.clone();
        plan.host_ids = self.effective(&plan.host_ids);
        self.inner.query_risk_scores(&plan)
    }
}
```

Add `pub mod tenant_scope;` to the bottom of `crates/osiris-api/src/lib.rs`. If any plan struct is not `Clone`, add `#[derive(Clone)]` to it (they are plain data). If `Storage` has a method not listed above (compare against `crates/osiris-storage/src/storage.rs`), implement it as a delegate for reads or `Err(read_only())` for writes.

- [ ] **Step 3: Run tests**

Run: `cargo test -p osiris-api tenant_scope` then `cargo clippy -p osiris-api --all-targets`
Expected: 6 passed, clippy clean.

- [ ] **Step 4: Commit**

```bash
git add -A crates/osiris-api Cargo.lock
git commit -m "feat(api): TenantScopedStorage decorator restricting reads to a tenant's hosts

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Gate: tenant on `AuthContext`, deny-by-default allowlist

**Files:**
- Modify: `crates/osiris-api/src/auth.rs` (`AuthState`), `crates/osiris-api/src/auth_middleware.rs`
- Modify (add `tenants: Arc::new(<a SqliteTenantStore>)` to each `AuthState {` literal): `crates/osiris-api/src/auth.rs` (test ~line 350), `crates/osiris-api/src/auth_middleware.rs` (test ~196), `crates/osiris-api/tests/composed_router_auth.rs` (~56), `crates/osiris-e2e-tests/tests/end_to_end.rs` (~46), `crates/osiris-server/src/main.rs` (~232; the real wiring lands in Task 8, here use a temp path placeholder ONLY if needed to compile - see Step 3).

**Interfaces:**
- Consumes: `osiris_tenancy::{TenantStore, SqliteTenantStore}` (Task 1), `User.tenant_id` (Task 2).
- Produces:
  - `AuthState { pub users, pub audit_log, pub session_ttl_seconds, pub tenants: Arc<dyn osiris_tenancy::TenantStore> }`
  - `AuthContext { pub user_id: Uuid, pub role: Role, pub token: String, pub tenant_id: Option<Uuid> }`
  - request extension `Arc<dyn TenantStore>` inserted by `auth_gate` for every authenticated request
  - `pub(crate) fn tenant_route_allowed(method: &axum::http::Method, path: &str) -> bool`

- [ ] **Step 1: Write the failing tests**

In the `tests` module of `crates/osiris-api/src/auth_middleware.rs` add (reusing that module's existing `test_state()`/`protected_app`/request helpers; read them first and follow their style for building a request with a bearer token and creating a user + session with `NewUser`):

```rust
    #[test]
    fn tenant_users_may_only_use_the_event_derived_get_allowlist() {
        use axum::http::Method;
        for path in [
            "/api/v1/health", "/api/v1/auth/me", "/api/v1/events", "/api/v1/processes",
            "/api/v1/processes/abc", "/api/v1/processes/abc/story", "/api/v1/alerts",
            "/api/v1/files", "/api/v1/files/story", "/api/v1/network", "/api/v1/network/story",
            "/api/v1/identity/story", "/api/v1/systemd/story", "/api/v1/hosts",
            "/api/v1/containers", "/api/v1/containers/story", "/api/v1/system/story",
            "/api/v1/graph", "/api/v1/graph/subgraph", "/api/v1/risk",
            "/api/v1/incidents/PROCESS:abc/reconstruct", "/api/v1/stream/events",
        ] {
            assert!(tenant_route_allowed(&Method::GET, path), "GET {path} must be allowed");
        }
        assert!(tenant_route_allowed(&Method::POST, "/api/v1/auth/logout"));
        for (m, path) in [
            (Method::GET, "/api/v1/incidents"),
            (Method::GET, "/api/v1/incidents/123"),
            (Method::POST, "/api/v1/incidents"),
            (Method::PATCH, "/api/v1/incidents/123"),
            (Method::GET, "/api/v1/evidence"),
            (Method::POST, "/api/v1/evidence"),
            (Method::GET, "/api/v1/audit"),
            (Method::POST, "/api/v1/response/collect_evidence"),
            (Method::GET, "/api/v1/auth/users"),
            (Method::POST, "/api/v1/auth/users"),
            (Method::GET, "/api/v1/tenants"),
            (Method::PUT, "/api/v1/tenants/x/hosts/y"),
            (Method::POST, "/api/v1/events"),
            (Method::GET, "/api/v1/something-new"),
        ] {
            assert!(!tenant_route_allowed(&m, path), "{m} {path} must be denied");
        }
    }
```

Then extend the same test module's `protected_app` with one more stub route (add before the `.route_layer(..)` line):

```rust
            .route("/api/v1/events", get(|| async { "events-ok" }))
```

and add this helper and these tests:

```rust
    fn session_for_tenant_user(state: &AuthState, username: &str, role: Role, tenant: Uuid) -> String {
        let user = state
            .users
            .create_user(NewUser {
                username: username.to_string(),
                password_hash: osiris_auth::hash_password("password123").unwrap(),
                role,
                tenant_id: Some(tenant),
            })
            .unwrap();
        state.users.create_session(user.user_id, 3600).unwrap().token
    }

    async fn status_of(app: &Router, uri: &str, token: &str) -> StatusCode {
        app.clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(uri)
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn a_tenant_user_reaches_allowlisted_routes_but_nothing_else_even_as_admin() {
        let (_d1, _d2, state) = test_state();
        let token = session_for_tenant_user(&state, "acme-admin", Role::Admin, Uuid::new_v4());
        let app = protected_app(state);
        assert_eq!(status_of(&app, "/api/v1/events", &token).await, StatusCode::OK);
        // Tenant-ness, not role, is what denies these: the caller is an Admin.
        assert_eq!(status_of(&app, "/api/v1/audit", &token).await, StatusCode::FORBIDDEN);
        assert_eq!(status_of(&app, "/api/v1/incidents", &token).await, StatusCode::FORBIDDEN);
        assert_eq!(
            status_of(&app, "/api/v1/protected", &token).await,
            StatusCode::FORBIDDEN,
            "a route that is not on the allowlist is denied by default"
        );
    }

    #[tokio::test]
    async fn a_platform_admin_still_reaches_platform_only_and_unlisted_routes() {
        let (_d1, _d2, state) = test_state();
        let admin = state.users.get_user_by_username("admin").unwrap().unwrap();
        let token = state.users.create_session(admin.user_id, 3600).unwrap().token;
        let app = protected_app(state);
        assert_eq!(status_of(&app, "/api/v1/audit", &token).await, StatusCode::OK);
        assert_eq!(status_of(&app, "/api/v1/protected", &token).await, StatusCode::OK);
        assert_eq!(status_of(&app, "/api/v1/events", &token).await, StatusCode::OK);
    }
```

(That `AuthContext.tenant_id` reaches handlers is proven end to end by Task 6's composed-router tests, where a tenant user's `ScopedStorage` sees only its hosts.)

Run: `cargo test -p osiris-api tenant_route_allowed`
Expected: FAIL to compile.

- [ ] **Step 2: Implement**

`crates/osiris-api/src/auth.rs` - add to `AuthState`:

```rust
    pub tenants: Arc<dyn osiris_tenancy::TenantStore>,
```

`crates/osiris-api/src/auth_middleware.rs`:

1. Add `pub tenant_id: Option<Uuid>,` to `AuthContext`.
2. Add the allowlist function (above `auth_gate`):

```rust
/// Routes a TENANT user (a user bound to a tenant) may call. Everything not
/// listed is platform-only until Phase 8g scopes incidents/evidence/audit/
/// response: the default is DENY, so a route added later stays platform-only
/// until someone deliberately allowlists it (and makes it tenant-aware).
pub(crate) fn tenant_route_allowed(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;

    if method == Method::POST && path == "/api/v1/auth/logout" {
        return true;
    }
    if method != Method::GET {
        return false;
    }
    const EXACT: &[&str] = &[
        "/api/v1/health",
        "/api/v1/auth/me",
        "/api/v1/events",
        "/api/v1/processes",
        "/api/v1/alerts",
        "/api/v1/files",
        "/api/v1/files/story",
        "/api/v1/network",
        "/api/v1/network/story",
        "/api/v1/identity/story",
        "/api/v1/systemd/story",
        "/api/v1/hosts",
        "/api/v1/containers",
        "/api/v1/containers/story",
        "/api/v1/system/story",
        "/api/v1/graph",
        "/api/v1/graph/subgraph",
        "/api/v1/risk",
        "/api/v1/stream/events",
    ];
    if EXACT.contains(&path) {
        return true;
    }
    // /api/v1/processes/:process_key and /api/v1/processes/:process_key/story
    if let Some(rest) = path.strip_prefix("/api/v1/processes/") {
        return !rest.is_empty();
    }
    // /api/v1/incidents/:seed_entity/reconstruct is event-derived (a graph walk),
    // unlike the incident CRUD routes, which stay platform-only.
    if let Some(rest) = path.strip_prefix("/api/v1/incidents/") {
        return rest.ends_with("/reconstruct") && rest.len() > "/reconstruct".len();
    }
    false
}
```

3. In `auth_gate`, after `if user.role < min_role_for(..) { return forbidden(); }` add:

```rust
    if user.tenant_id.is_some() && !tenant_route_allowed(req.method(), &path) {
        return forbidden();
    }
```
and change the extension insertion to:

```rust
    req.extensions_mut().insert(AuthContext {
        user_id: user.user_id,
        role: user.role,
        token,
        tenant_id: user.tenant_id,
    });
    req.extensions_mut().insert(state.tenants.clone());
```

4. Every other place that constructs `AuthContext { .. }` (tests in `auth.rs`, `response.rs`, `incidents.rs`, `evidence.rs`, e.g. `AuthContext { user_id, role, token }`) gets `tenant_id: None,`. `grep -rn "AuthContext {" --include=*.rs crates`.

- [ ] **Step 3: Fix the five `AuthState` literals**

In each test/harness literal add `tenants: Arc::new(osiris_tenancy::SqliteTenantStore::open(<tempdir>.join("tenants.db")).unwrap()),` using the temp directory that literal's function already has (the harnesses already create one). Add `osiris-tenancy` as a dependency of `osiris-e2e-tests` (`crates/osiris-e2e-tests/Cargo.toml`, path dep). For `crates/osiris-server/src/main.rs` add the real wiring now instead of a placeholder: add `osiris-tenancy = { path = "../osiris-tenancy" }` to `crates/osiris-server/Cargo.toml`, and in `main.rs` before `auth_state`:

```rust
    let tenants_db_path = config
        .tenants_db_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/tenants.db".to_string());
    let tenant_store: Arc<dyn osiris_tenancy::TenantStore> = Arc::new(open_or_exit(
        osiris_tenancy::SqliteTenantStore::open(&tenants_db_path),
        &tenants_db_path,
        "tenants_db_path",
    ));
```
with `tenants: tenant_store.clone(),` in the `AuthState` literal, and in `crates/osiris-server/src/config.rs` add `pub tenants_db_path: Option<String>,` next to `users_db_path` (`#[serde(default)]` if that struct uses it for `users_db_path`; mirror exactly how `users_db_path` is declared) and update any `ServerConfig {` literal the compiler flags with `tenants_db_path: None`. Add a config test mirroring `users_db_path_and_session_ttl_default_to_none_when_absent` asserting `tenants_db_path` is `None` when absent and parses when present.

- [ ] **Step 4: Run tests**

Run: `cargo test -p osiris-api -p osiris-server -p osiris-auth -p osiris-tenancy` and `cargo clippy -p osiris-api -p osiris-server --all-targets`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A crates
git commit -m "feat(api): tenant on AuthContext and deny-by-default route allowlist for tenant users

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: `ScopedStorage` extractor and handler swap

**Files:**
- Modify: `crates/osiris-api/src/tenant_scope.rs` (add extractor), `crates/osiris-api/src/lib.rs` (swap 20 handler extractors + test call sites)
- Test: `crates/osiris-api/tests/composed_router_tenancy.rs` (new)

**Interfaces:**
- Consumes: `AuthContext.tenant_id` and the `Arc<dyn TenantStore>` request extension (Task 5), `TenantScopedStorage` (Task 4).
- Produces: `pub struct ScopedStorage(pub Arc<dyn Storage>)` implementing `axum::extract::FromRequestParts<Arc<dyn Storage>>`.

Semantics: no `AuthContext` extension, or `tenant_id == None` -> the shared storage unchanged (platform / unauthenticated unit tests). `tenant_id == Some` -> load `hosts_of(tenant_id)` on `spawn_blocking`; a missing `TenantStore` extension or a failing lookup -> `500` (fail closed).

- [ ] **Step 1: Write the failing composed-router test**

Create `crates/osiris-api/tests/composed_router_tenancy.rs` with the full harness and tests below (the composition is copied from `composed_router_auth.rs` / `osiris-server/src/main.rs`; Task 8 later adds `.merge(build_tenant_router(..))` to `build_app` and its tests to this same file).

```rust
//! Tenant isolation through the REAL composed router (same composition as
//! `osiris-server/src/main.rs`): two tenants, one unassigned host, a platform
//! admin, and a tenant Admin per tenant.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
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
}

fn build_app(
    storage: Arc<dyn Storage>,
    incident_evidence_state: IncidentEvidenceState,
    response_state: ResponseState,
    broadcaster: Arc<LiveEventBroadcaster>,
    auth_state: AuthState,
) -> axum::Router {
    build_router(storage)
        .merge(build_incident_evidence_router(incident_evidence_state))
        .merge(build_response_router(response_state))
        .merge(build_stream_router(broadcaster))
        .merge(build_auth_router(auth_state.clone()))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate))
}

fn tenancy() -> Tenancy {
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name);

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(p("events.db")).unwrap());
    let (acme_host, globex_host, unassigned_host) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let t = now_ns();
    let globex_event = event_on(globex_host, 2, t);
    let globex_process_key = globex_event.process.as_ref().unwrap().process_key.as_hex();
    storage
        .batch_write(&[
            event_on(acme_host, 1, t),
            globex_event,
            event_on(unassigned_host, 3, t),
        ])
        .unwrap();

    let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> =
        Arc::new(FileAuditLog::open(p("audit.jsonl")).unwrap());
    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(SqliteIncidentStore::open(p("incidents.db").to_str().unwrap()).unwrap()),
        evidence: Arc::new(SqliteEvidenceStore::open(p("evidence.db").to_str().unwrap()).unwrap()),
        links: Arc::new(SqliteEvidenceIncidentLinks::open(p("links.db").to_str().unwrap()).unwrap()),
        audit_log: audit_log.clone(),
    };
    let response_state = ResponseState {
        storage: storage.clone(),
        evidence: incident_evidence_state.evidence.clone(),
        links: incident_evidence_state.links.clone(),
        audit_log: audit_log.clone(),
    };

    let tenants: Arc<dyn TenantStore> = Arc::new(SqliteTenantStore::open(p("tenants.db")).unwrap());
    let acme = tenants.create_tenant("acme").unwrap();
    let globex = tenants.create_tenant("globex").unwrap();
    tenants.assign_host(acme_host, acme.tenant_id).unwrap();
    tenants.assign_host(globex_host, globex.tenant_id).unwrap();

    let (user_store, _bootstrap) = SqliteUserStore::open(p("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let admin_token = user_store.create_session(admin.user_id, 3600).unwrap().token;
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
    let app = build_app(
        storage,
        incident_evidence_state,
        response_state,
        broadcaster.clone(),
        auth_state.clone(),
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
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
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
    for (method, uri) in [
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/evidence"),
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/auth/users"),
        ("POST", "/api/v1/response/collect_evidence"),
    ] {
        let body = (method == "POST").then(|| serde_json::json!({}));
        let (status, _) = call(&t.app, method, uri, Some(&t.acme_token), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri} must be 403 for a tenant user");
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
    let token = t.auth_state.users.create_session(user.user_id, 3600).unwrap().token;
    let (status, body) = call(&t.app, "GET", "/api/v1/events", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty(), "no hosts must mean no data");
    let (_, hosts) = call(&t.app, "GET", "/api/v1/hosts", Some(&token), None).await;
    assert!(hosts.as_array().unwrap().is_empty());
}
```

Run: `cargo test -p osiris-api --test composed_router_tenancy`
Expected: FAIL (a tenant sees all three hosts' events: `ScopedStorage` does not exist yet). The harness compiles as soon as Task 5's `AuthState.tenants` exists; if `osiris_tenancy` is not visible to the test crate, it is already a normal dependency of `osiris-api` (Task 4), so integration tests can use it.

- [ ] **Step 2: Implement the extractor**

Append to `crates/osiris-api/src/tenant_scope.rs` (above the tests):

```rust
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use osiris_tenancy::TenantStore;

use crate::auth_middleware::AuthContext;

/// Extractor handing a handler the storage it must use for THIS request:
/// the shared storage for platform users, a `TenantScopedStorage` for tenant
/// users. Handlers take `ScopedStorage(storage): ScopedStorage` instead of
/// `State<Arc<dyn Storage>>`, so a handler cannot forget to scope.
pub struct ScopedStorage(pub Arc<dyn Storage>);

/// Resolves the calling tenant user's host set: `Ok(None)` for a platform (or
/// unauthenticated-in-tests) request, `Ok(Some(hosts))` for a tenant user,
/// and a 500 (never an unscoped fallback) when the registry cannot answer.
pub(crate) async fn tenant_hosts(
    parts: &Parts,
) -> Result<Option<HashSet<Uuid>>, (StatusCode, String)> {
    let Some(ctx) = parts.extensions.get::<AuthContext>() else {
        return Ok(None);
    };
    let Some(tenant_id) = ctx.tenant_id else {
        return Ok(None);
    };
    let Some(tenants) = parts.extensions.get::<Arc<dyn TenantStore>>().cloned() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "tenant registry unavailable".to_string(),
        ));
    };
    let hosts = tokio::task::spawn_blocking(move || tenants.hosts_of(tenant_id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "tenant lookup failed".to_string()))?
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "tenant lookup failed".to_string()))?;
    Ok(Some(hosts))
}

#[axum::async_trait]
impl FromRequestParts<Arc<dyn Storage>> for ScopedStorage {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<dyn Storage>,
    ) -> Result<Self, Self::Rejection> {
        match tenant_hosts(parts).await? {
            None => Ok(ScopedStorage(state.clone())),
            Some(hosts) => Ok(ScopedStorage(Arc::new(TenantScopedStorage::new(state.clone(), hosts)))),
        }
    }
}
```

- [ ] **Step 3: Swap the handlers**

In `crates/osiris-api/src/lib.rs`:
1. Replace all 20 occurrences of `State(storage): State<Arc<dyn Storage>>` in handler signatures with `ScopedStorage(storage): ScopedStorage` (the count before the edit: `grep -c "State(storage): State<Arc<dyn Storage>>" crates/osiris-api/src/lib.rs` = 20).
2. Add `use crate::tenant_scope::ScopedStorage;` and remove `State` from the `axum::extract` import if it becomes unused.
3. The `#[cfg(test)]` module calls handlers directly, e.g. `files_handler(State(storage))`. Replace `State(` with `ScopedStorage(` at those call sites (only inside `mod tests`; leave `Query(..)`/`Path(..)` untouched). `sed -n '/^mod tests/,$p'` scoped replacement is fine; the compiler flags any straggler. `ScopedStorage` is a tuple struct, so `ScopedStorage(storage)` constructs it directly.
4. `build_router` keeps `.with_state(storage)` (the extractor's state type is still `Arc<dyn Storage>`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p osiris-api` (all existing handler unit tests still pass with `ScopedStorage(..)`), `cargo clippy -p osiris-api --all-targets`.
Expected: the 7 composed-router tenancy tests and every pre-existing osiris-api test pass.

- [ ] **Step 5: Commit**

```bash
git add -A crates/osiris-api
git commit -m "feat(api): ScopedStorage extractor isolates every event-derived handler per tenant

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 7: WebSocket tenant filtering

**Files:**
- Modify: `crates/osiris-api/src/stream.rs`
- Test: `crates/osiris-api/src/stream.rs` (existing test module) and a case in `composed_router_tenancy.rs`

**Interfaces:**
- Consumes: `tenant_hosts` (Task 6), `AuthContext` (Task 5).
- Produces: `stream_events_handler` restricts a tenant user's subscription to the tenant's hosts.

Rules: platform / no-auth -> behavior unchanged. Tenant user: a requested `host_id` not in the tenant's set -> `403`; the effective filter is `AND(user_filter, host_id IN tenant_hosts)`; an empty host set -> a filter that matches nothing. The set is a snapshot taken at connect time (documented limitation: a reassignment mid-connection applies at the next connect).

- [ ] **Step 1: Write the failing tests**

In `stream.rs`'s test module add a pure-function test for the filter builder, and (using the existing WS test harness style in that module - it already starts a real listener and connects with `tokio-tungstenite`) a test that a tenant-scoped connection receives only its hosts' events. Because `stream.rs`'s harness has no auth layer, exercise the tenant path by extracting the pure function:

```rust
    #[test]
    fn tenant_filter_ands_the_hosts_onto_the_callers_filter() {
        let a = Uuid::new_v4();
        let hosts: HashSet<Uuid> = [a].into_iter().collect();
        let user = Ast::Compare {
            field: "event_type".to_string(),
            op: Op::Eq,
            value: Value::Str("PROCESS_EXEC".to_string()),
        };
        let combined = tenant_filter(Some(user.clone()), &hosts);
        // Matches an event from the tenant's host with the right type...
        assert!(osiris_query::eval_ast(&combined, &sample_event(a, EventType::ProcessExec)));
        // ...but not one from a foreign host, nor a wrong type on the tenant host.
        assert!(!osiris_query::eval_ast(&combined, &sample_event(Uuid::new_v4(), EventType::ProcessExec)));
        assert!(!osiris_query::eval_ast(&combined, &sample_event(a, EventType::FileWrite)));
    }

    #[test]
    fn an_empty_tenant_host_set_matches_nothing() {
        let combined = tenant_filter(None, &HashSet::new());
        assert!(!osiris_query::eval_ast(&combined, &sample_event(Uuid::new_v4(), EventType::ProcessExec)));
    }

    #[test]
    fn a_requested_host_outside_the_tenant_is_rejected() {
        let a = Uuid::new_v4();
        let hosts: HashSet<Uuid> = [a].into_iter().collect();
        assert!(host_allowed(&hosts, &a.to_string()));
        assert!(!host_allowed(&hosts, &Uuid::new_v4().to_string()));
        assert!(!host_allowed(&hosts, "not-a-uuid"));
    }
```

(`eval_ast`'s exact signature: read `osiris_query`'s export - the existing stream tests call it with `(&ast, &event)`; mirror them. If `sample_event` takes different arguments than `(host_id, event_type)`, use its real signature - it is defined in this module: `fn sample_event(host_id: Uuid, event_type: EventType)`.)

Add to `composed_router_tenancy.rs` this real end-to-end WebSocket test (`tokio-tungstenite` and `futures-util` are already dev-dependencies of `osiris-api`):

```rust
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
    assert!(tokio::time::timeout(Duration::from_millis(300), ws.next()).await.is_err());

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
```

Run: `cargo test -p osiris-api stream`
Expected: FAIL to compile (`tenant_filter`, `host_allowed` not defined).

- [ ] **Step 2: Implement**

In `stream.rs` add:

```rust
use std::collections::HashSet;

/// `AND`s the tenant's host restriction onto the caller's own filter. An empty
/// host set yields a list that matches nothing (`In` against an empty list).
pub(crate) fn tenant_filter(user_filter: Option<Ast>, hosts: &HashSet<Uuid>) -> Ast {
    let host_ast = Ast::Compare {
        field: "host_id".to_string(),
        op: Op::In,
        value: Value::List(hosts.iter().map(|h| Value::Str(h.to_string())).collect()),
    };
    match user_filter {
        Some(user) => Ast::And(Box::new(user), Box::new(host_ast)),
        None => host_ast,
    }
}

/// Whether a `host_id` the client asked for belongs to the tenant.
pub(crate) fn host_allowed(hosts: &HashSet<Uuid>, requested: &str) -> bool {
    Uuid::parse_str(requested).map(|id| hosts.contains(&id)).unwrap_or(false)
}
```

Change `stream_events_handler` to also take `parts`-level tenant info. Because it already has `headers: HeaderMap`, add an `axum::extract::Extension`-free approach: take `request extensions` via a leading extractor. Concretely, add these two extractors to its signature (before `Query`):

```rust
    ctx: Option<axum::Extension<crate::auth_middleware::AuthContext>>,
    tenants: Option<axum::Extension<Arc<dyn osiris_tenancy::TenantStore>>>,
```
and after the mutual-exclusion check and before building `filter`, resolve the tenant set:

```rust
    let tenant_hosts: Option<HashSet<Uuid>> = match ctx.and_then(|axum::Extension(c)| c.tenant_id) {
        None => None,
        Some(tenant_id) => {
            let Some(axum::Extension(tenants)) = tenants else {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "tenant registry unavailable".to_string()));
            };
            let hosts = tokio::task::spawn_blocking(move || tenants.hosts_of(tenant_id))
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "tenant lookup failed".to_string()))?
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "tenant lookup failed".to_string()))?;
            Some(hosts)
        }
    };
    if let (Some(hosts), Some(requested)) = (&tenant_hosts, &params.host_id) {
        if !host_allowed(hosts, requested) {
            return Err((StatusCode::FORBIDDEN, "host not in your tenant".to_string()));
        }
    }
```
then, after `filter` is computed (existing code) and before `ws.on_upgrade`:

```rust
    let filter = match &tenant_hosts {
        Some(hosts) => Some(tenant_filter(filter, hosts)),
        None => filter,
    };
```
(`params.host_id` is moved into the existing `filter` computation - clone it before that with `let requested_host = params.host_id.clone();` and use `requested_host` in the check above.) Add `osiris-tenancy` usage (already a dependency from Task 4).

- [ ] **Step 3: Run tests**

Run: `cargo test -p osiris-api` and `cargo clippy -p osiris-api --all-targets`
Expected: all pass, including the new stream and composed-router WS tests.

- [ ] **Step 4: Commit**

```bash
git add -A crates/osiris-api
git commit -m "feat(stream): restrict the live events WebSocket to the tenant's hosts

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 8: Tenant admin API, user-tenant binding, login fields

**Files:**
- Create: `crates/osiris-api/src/tenants.rs`
- Modify: `crates/osiris-api/src/lib.rs` (`pub mod tenants; pub use tenants::build_tenant_router;`), `crates/osiris-api/src/auth.rs` (`CreateUserBody`, `LoginResponse`, `list_users` summary), `crates/osiris-api/src/auth_middleware.rs` (`min_role_for`), `crates/osiris-server/src/main.rs` (merge the tenant router)
- Test: `crates/osiris-api/tests/composed_router_tenancy.rs`

**Interfaces:**
- Consumes: `AuthState.tenants`, `TenantStore` (Tasks 1, 5).
- Produces:
  - `pub fn build_tenant_router(state: AuthState) -> Router` with `POST/GET /api/v1/tenants`, `PUT/DELETE /api/v1/tenants/:tenant_id/hosts/:host_id`
  - `CreateUserBody` gains `tenant_id: Option<Uuid>`; `LoginResponse` gains `tenant_id: Option<Uuid>` and `tenant_name: Option<String>`
  - `min_role_for`: every `/api/v1/tenants*` path requires `Role::Admin`. (Tenant users never reach these: Task 5's allowlist already 403s them, and Admin tenant users are additionally blocked because `tenant_route_allowed` is false. Platform-Admin only is therefore enforced by role + allowlist together.)

Rules to enforce in handlers: creating a user with a `tenant_id` requires that tenant to exist (`400` otherwise); a caller with a tenant (`ctx.tenant_id.is_some()`) can never reach these handlers (defense in depth: still check and return `403` if `ctx.tenant_id.is_some()`); audit-log every tenant create and host assign/unassign with `what` = `"tenant_create"`, `"tenant_assign_host"`, `"tenant_unassign_host"` and `target: EntityRef::Domain { name: format!("tenant:{name-or-id}") }` (same `ActorRef::User`/`AuditResult::Success` shape as `user_create` in `auth.rs`).

- [ ] **Step 1: Write the failing tests**

In `composed_router_tenancy.rs`, first change `build_app` so it also merges the tenant router (same order as `main.rs`): add `.merge(osiris_api::build_tenant_router(auth_state.clone()))` right after `.merge(build_auth_router(auth_state.clone()))`. Then add:

```rust
#[tokio::test]
async fn a_platform_admin_can_create_a_tenant_assign_and_unassign_a_host() {
    let t = tenancy();
    let (status, body) = call(
        &t.app, "POST", "/api/v1/tenants", Some(&t.admin_token),
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
    assert!(list.as_array().unwrap().iter().any(|x| x["name"] == "initech"));

    let (status, _) = call(&t.app, "DELETE", &uri, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(t.tenants.tenant_of(host).unwrap(), None);
}

#[tokio::test]
async fn creating_a_duplicate_tenant_name_is_a_400() {
    let t = tenancy();
    let (status, _) = call(
        &t.app, "POST", "/api/v1/tenants", Some(&t.admin_token),
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
        &t.app, "POST", "/api/v1/tenants", Some(&t.acme_token),
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
}

#[tokio::test]
async fn assigning_a_host_to_an_unknown_tenant_is_404() {
    let t = tenancy();
    let uri = format!("/api/v1/tenants/{}/hosts/{}", Uuid::new_v4(), Uuid::new_v4());
    let (status, _) = call(&t.app, "PUT", &uri, Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn creating_a_user_bound_to_a_tenant_works_and_login_reports_the_tenant() {
    let t = tenancy();
    let (status, _) = call(
        &t.app, "POST", "/api/v1/auth/users", Some(&t.admin_token),
        Some(serde_json::json!({
            "username": "bob", "password": "password123", "role": "VIEWER",
            "tenant_id": t.acme_tenant,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, login) = call(
        &t.app, "POST", "/api/v1/auth/login", None,
        Some(serde_json::json!({ "username": "bob", "password": "password123" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(login["tenant_id"], serde_json::json!(t.acme_tenant));
    assert_eq!(login["tenant_name"], "acme");

    // A platform user's login carries no tenant.
    let (status, unknown) = call(
        &t.app, "POST", "/api/v1/auth/users", Some(&t.admin_token),
        Some(serde_json::json!({
            "username": "carol", "password": "password123", "role": "VIEWER",
            "tenant_id": Uuid::new_v4(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown tenant must be rejected: {unknown}");

    // A tenant Admin cannot mint users (platform-only).
    let (status, _) = call(
        &t.app, "POST", "/api/v1/auth/users", Some(&t.acme_token),
        Some(serde_json::json!({ "username": "dave", "password": "password123", "role": "VIEWER" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
```

Run: `cargo test -p osiris-api --test composed_router_tenancy`
Expected: the 5 new tests FAIL (`build_tenant_router` does not exist yet / routes 404).

- [ ] **Step 2: Implement the tenant router**

Create `crates/osiris-api/src/tenants.rs` following the shape of `auth.rs` (state = `AuthState`, handlers take `State(state)`, `Extension(ctx)`). Complete code:

```rust
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditResult, NewAuditEntry};
use osiris_schema::EntityRef;
use osiris_tenancy::{Tenant, TenantStoreError};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthState;
use crate::auth_middleware::AuthContext;

pub fn build_tenant_router(state: AuthState) -> Router {
    Router::new()
        .route("/api/v1/tenants", get(list_tenants_handler).post(create_tenant_handler))
        .route(
            "/api/v1/tenants/:tenant_id/hosts/:host_id",
            put(assign_host_handler).delete(unassign_host_handler),
        )
        .with_state(state)
}

/// Defense in depth: the auth gate already 403s tenant users on these
/// routes, but a tenant user must never manage tenants even if the gate's
/// allowlist were ever loosened.
fn platform_only(ctx: &AuthContext) -> Result<(), (StatusCode, String)> {
    if ctx.tenant_id.is_some() {
        return Err((StatusCode::FORBIDDEN, "platform users only".to_string()));
    }
    Ok(())
}

fn store_error(e: TenantStoreError) -> (StatusCode, String) {
    match e {
        TenantStoreError::DuplicateName(_) | TenantStoreError::InvalidName(_) => {
            (StatusCode::BAD_REQUEST, e.to_string())
        }
        TenantStoreError::UnknownTenant(_) => (StatusCode::NOT_FOUND, e.to_string()),
        TenantStoreError::Backend(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

fn audit(state: &AuthState, ctx: &AuthContext, what: &str, target: String) {
    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User { user_id: ctx.user_id },
        what: what.to_string(),
        target: EntityRef::Domain { name: target },
        why: None,
        result: AuditResult::Success,
    });
}

#[derive(Debug, Deserialize)]
struct CreateTenantBody {
    name: String,
}

async fn create_tenant_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<CreateTenantBody>,
) -> Result<Json<Tenant>, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    let tenant = tokio::task::spawn_blocking(move || tenants.create_tenant(&body.name))
        .await
        .unwrap()
        .map_err(store_error)?;
    audit(&state, &ctx, "tenant_create", format!("tenant:{}", tenant.name));
    Ok(Json(tenant))
}

async fn list_tenants_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<Tenant>>, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    let all = tokio::task::spawn_blocking(move || tenants.list_tenants())
        .await
        .unwrap()
        .map_err(store_error)?;
    Ok(Json(all))
}

async fn assign_host_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
    Path((tenant_id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    tokio::task::spawn_blocking(move || tenants.assign_host(host_id, tenant_id))
        .await
        .unwrap()
        .map_err(store_error)?;
    audit(&state, &ctx, "tenant_assign_host", format!("tenant:{tenant_id}/host:{host_id}"));
    Ok(StatusCode::NO_CONTENT)
}

async fn unassign_host_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
    Path((tenant_id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    tokio::task::spawn_blocking(move || tenants.unassign_host(host_id))
        .await
        .unwrap()
        .map_err(store_error)?;
    audit(&state, &ctx, "tenant_unassign_host", format!("tenant:{tenant_id}/host:{host_id}"));
    Ok(StatusCode::NO_CONTENT)
}
```

(`osiris-tenancy` is already a dependency; `osiris-schema`/`osiris-audit` are too.)

- [ ] **Step 3: Gate, user binding, login fields**

1. `auth_middleware.rs::min_role_for`: extend the first `if` so `path == "/api/v1/tenants" || path.starts_with("/api/v1/tenants/")` also returns `Role::Admin`.
2. `auth.rs`:
   - `CreateUserBody` gets `#[serde(default)] tenant_id: Option<Uuid>,`. In `create_user_handler`, before creating the user: `platform_only`-equivalent check (`if ctx.tenant_id.is_some() { return Err(FORBIDDEN) }`), and when `body.tenant_id` is `Some(t)`, `spawn_blocking(get_tenant)` and return `400 "unknown tenant"` if `None`. Pass `tenant_id: body.tenant_id` into `NewUser`.
   - `LoginResponse` gets `tenant_id: Option<Uuid>` and `tenant_name: Option<String>`; in `login_handler` after the session is created, when `user.tenant_id` is `Some`, look the tenant up via `state.tenants.get_tenant(..)` (on `spawn_blocking`, ignore lookup failure by returning `tenant_name: None`) and fill both.
   - `UserSummary` gets `tenant_id: Option<Uuid>` filled from `User.tenant_id`.
3. `crates/osiris-server/src/main.rs`: `use osiris_api::build_tenant_router;` and `.merge(build_tenant_router(auth_state.clone()))` next to `.merge(build_auth_router(auth_state.clone()))`. Also merge it in the `composed_router_tenancy.rs` harness (Task 6) and in `crates/osiris-e2e-tests/tests/end_to_end.rs`'s composition (mirror `main.rs`'s exact order).

- [ ] **Step 4: Run tests**

Run: `cargo test -p osiris-api -p osiris-server` and `cargo clippy -p osiris-api -p osiris-server --all-targets`
Expected: all pass, including the 5 new tests.

- [ ] **Step 5: Commit**

```bash
git add -A crates
git commit -m "feat(api): tenant admin routes, tenant-bound user creation, tenant in login response

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 9: CLI and Console

**Files:**
- Modify: `crates/osiris-cli/src/main.rs`
- Modify: `console/src/store/authStore.ts`, `console/src/api/types.ts`, `console/src/api/hooks.ts` (~line 229), `console/src/app/navItems.ts`, `console/src/app/Shell.tsx`
- Test: `console/src/store/authStore.test.ts`, `console/src/App.test.tsx` (extend), CLI unit test if the crate has a parsing test module

**Interfaces:**
- Consumes: Task 8's API (`/api/v1/tenants*`, `tenant_id` on user creation, `tenant_id`/`tenant_name` on login).
- Produces: CLI `tenants create <name>`, `tenants list`, `tenants assign-host <tenant_id> <host_id>`, `tenants unassign-host <tenant_id> <host_id>`, `users create --tenant <uuid>`; Console shows the tenant name and hides platform-only nav items from tenant users.

- [ ] **Step 1: CLI**

In `crates/osiris-cli/src/main.rs`:
- Add `tenant: Option<String>` (`#[arg(long)]`) to `UsersAction::Create` and include it in the JSON body only when present: after building `body`, `if let Some(t) = tenant { body["tenant_id"] = serde_json::Value::String(t); }` (make `body` `let mut`).
- Add a top-level `Tenants { #[command(subcommand)] action: TenantsAction }` command and:

```rust
#[derive(Subcommand)]
enum TenantsAction {
    /// Create a tenant (requires a platform Admin session).
    Create { name: String },
    /// List tenants (requires a platform Admin session).
    List,
    /// Assign a host to a tenant (requires a platform Admin session).
    AssignHost { tenant_id: String, host_id: String },
    /// Remove a host's tenant assignment (requires a platform Admin session).
    UnassignHost { tenant_id: String, host_id: String },
}
```
- Handler (mirrors `Command::Users`, all requests send the token, i.e. the final `true`). The CLI's `get`/`post_json` helpers exist; for `PUT`/`DELETE` add two small helpers next to `post_json` following the same shape (reqwest blocking `put`/`delete`, bearer token attached when the flag is true, non-2xx -> `Err(body)`); read `post_json` first and copy its structure exactly:

```rust
        Command::Tenants { action } => {
            let base = cli.server.trim_end_matches('/').to_string();
            match action {
                TenantsAction::Create { name } => post_json(
                    &client,
                    format!("{base}/api/v1/tenants"),
                    serde_json::json!({ "name": name }),
                    true,
                ),
                TenantsAction::List => get(&client, format!("{base}/api/v1/tenants"), true),
                TenantsAction::AssignHost { tenant_id, host_id } => put_empty(
                    &client,
                    format!("{base}/api/v1/tenants/{tenant_id}/hosts/{host_id}"),
                    true,
                ),
                TenantsAction::UnassignHost { tenant_id, host_id } => delete_empty(
                    &client,
                    format!("{base}/api/v1/tenants/{tenant_id}/hosts/{host_id}"),
                    true,
                ),
            }
        }
```
where `put_empty`/`delete_empty` return `Ok("ok".to_string())` on a 2xx. Add a parsing test if the crate already tests clap parsing (`grep -n "try_parse_from" crates/osiris-cli/src`); otherwise `cargo run -p osiris-cli -- tenants --help` is the check.

Run: `cargo build -p osiris-cli && cargo clippy -p osiris-cli --all-targets`
Expected: builds clean.

- [ ] **Step 2: Console tests first**

`console/src/store/authStore.test.ts` add:

```ts
  it("stores and clears the tenant alongside the session", () => {
    useAuthStore.getState().setSession({
      token: "abc", role: "ADMIN", username: "alice", tenantId: "t1", tenantName: "Acme",
    });
    expect(useAuthStore.getState().tenantId).toBe("t1");
    expect(useAuthStore.getState().tenantName).toBe("Acme");
    useAuthStore.getState().clearSession();
    expect(useAuthStore.getState().tenantId).toBeNull();
    expect(useAuthStore.getState().tenantName).toBeNull();
  });
```

`console/src/App.test.tsx` add (inside `describe("App")`):

```tsx
  it("shows the tenant name and hides platform-only screens from a tenant user", () => {
    useAuthStore.getState().setSession({
      token: "t", role: "ADMIN", username: "u", tenantId: "t1", tenantName: "Acme",
    });
    render(<App />);
    const nav = screen.getByRole("navigation", { name: "main" });
    expect(within(nav).getByText("Acme")).toBeInTheDocument();
    expect(within(nav).queryByText("Incidents")).not.toBeInTheDocument();
    expect(within(nav).queryByText("Evidence")).not.toBeInTheDocument();
    expect(within(nav).getByText("Alerts")).toBeInTheDocument();
  });
```
(The existing test that asserts exactly fourteen nav links keeps working: `beforeEach` logs in as a platform user with no tenant.)

Run: `cd console && npx vitest run src/store/authStore.test.ts src/App.test.tsx`
Expected: FAIL (`tenantId` not on the store).

- [ ] **Step 3: Console implementation**

`console/src/store/authStore.ts`: add optional fields to `StoredSession` and full state:

```ts
interface StoredSession {
  token: string;
  role: Role;
  username: string;
  tenantId?: string | null;
  tenantName?: string | null;
}
```
`AuthState` gets `tenantId: string | null; tenantName: string | null;`; initial values `initial?.tenantId ?? null` / `initial?.tenantName ?? null`; `setSession` sets `tenantId: session.tenantId ?? null, tenantName: session.tenantName ?? null`; `clearSession` sets both to `null`.

`console/src/api/types.ts`: `LoginResponse` gains `tenant_id?: string | null; tenant_name?: string | null;`.

`console/src/api/hooks.ts` (~line 229): pass them through:
```ts
      setSession({
        token: data.token,
        role: data.role,
        username: variables.username,
        tenantId: data.tenant_id ?? null,
        tenantName: data.tenant_name ?? null,
      });
```

`console/src/app/navItems.ts`: add `platformOnly?: boolean;` to `NavItem`, and `platformOnly: true` on the `Incidents` and `Evidence` entries.

`console/src/app/Shell.tsx`:
```tsx
import { NavLink, Outlet } from "react-router-dom";
import { useAuthStore } from "../store/authStore";
import { NAV_ITEMS } from "./navItems";

export function Shell() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const tenantName = useAuthStore((s) => s.tenantName);
  const items = NAV_ITEMS.filter((item) => !(tenantId && item.platformOnly));
  return (
    <div>
      <nav aria-label="main">
        <div>OSIRIS</div>
        {tenantId && <div>{tenantName ?? "Tenant"}</div>}
        <ul>
          {items.map((item) =>
            item.enabled ? (
              <li key={item.path}>
                <NavLink to={item.path} end={item.path === "/"}>
                  {item.label}
                </NavLink>
              </li>
            ) : (
              <li key={item.path} aria-disabled="true">
                {item.label}
              </li>
            )
          )}
        </ul>
      </nav>
      <main>
        <Outlet />
      </main>
    </div>
  );
}
```

Run: `cd console && npx vitest run && npm run build`
Expected: all console tests pass (existing 221 + the 2 new), build clean.

- [ ] **Step 4: Commit**

```bash
git add -A crates/osiris-cli console
git commit -m "feat(cli,console): tenant management commands and tenant-aware Console shell

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 10: Whole-workspace verification

**Files:** none (verification only; fix any breakage in the task that owns the broken code and re-run).

- [ ] **Step 1: Rebuild the subprocess binaries the e2e tests spawn**

Run: `cargo build -p osiris-cli -p osiris-server -p osiris-agent`
Expected: builds clean.

- [ ] **Step 2: Full Rust suite**

Run: `cargo test --workspace`
Expected: 0 failures. The 8 existing `osiris-e2e-tests` scenarios must still pass: they compose the real authenticated router, and Task 5 gave their `AuthState` a tenant store. Tenant isolation through the real composition is proven by `composed_router_tenancy.rs` (Tasks 6-8) rather than a ninth e2e scenario.

- [ ] **Step 3: Lints on the touched crates**

Run: `cargo clippy -p osiris-tenancy -p osiris-auth -p osiris-query -p osiris-storage -p osiris-storage-sqlite -p osiris-api -p osiris-server -p osiris-cli --all-targets`
Expected: zero warnings (do not run `cargo fmt` repo-wide; it is not clean on master).

- [ ] **Step 4: Console suite and build**

Run: `cd console && npx vitest run && npm run build`
Expected: all tests pass, build clean.

---

## Self-Review (spec coverage)

| Spec requirement | Task |
|---|---|
| Server-side host->tenant registry (`osiris-tenancy`, `tenants.db`) | 1 |
| `users.tenant_id`, guarded migration, platform = NULL | 2 |
| `AuthContext.tenant_id`; session/user carry tenant | 5 |
| Scoped reads for query/query_events/alerts/risk/relationships/get_event; writes refused; empty set = nothing | 3 (SQL), 4 (decorator) |
| Extractor building the per-request storage; 20 handlers swapped; fail closed 500 | 6 |
| `/hosts` filtered | 6 (via query_events) |
| WebSocket per-connection filter, foreign `host_id` 403 | 7 |
| Deny-by-default; platform-only routes; allowlist test | 5 |
| Tenant admin API + audit entries; create user with tenant; login returns tenant | 8 |
| CLI `tenants ...`, `users create --tenant` | 9 |
| Console tenant name + hide platform-only nav | 9 |
| Composed-router isolation tests (real composition, incl. WebSocket and tenant admin routes) | 6, 7, 8 |
| Whole-workspace verification | 10 |

Spec deviation, recorded (Ruling): the spec described a `Scope::{Any, PlatformOnly}` value returned by `min_role_for` plus a test walking registered routes. The plan implements the same guarantee more strongly as an explicit *allowlist* (`tenant_route_allowed`, Task 5): tenant users are denied everything not listed, so an unlisted route is platform-only by construction and no route-walking test is needed. Also recorded (Ruling): the spec's "E2E gains a second tenant" is met by `composed_router_tenancy.rs`, which drives the real `main.rs` composition with two tenants, an unassigned host, the WebSocket and the tenant admin routes; the 8 existing e2e scenarios stay authenticated and green (Task 10). A ninth subprocess-level scenario would duplicate that coverage. Also recorded: legacy query plans get `host_ids` pushed into SQL (spec said "add `host_id IN set`" without saying how; a post-filter after `LIMIT` would under-return).

Known limits (not tasks): a tenant's host set is snapshotted per request (WebSocket: per connection); SQLite's bound-parameter cap (32766) bounds a single tenant's host count.
