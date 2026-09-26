# Phase 9d-2 — Host Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operator-managed, tenant-scoped host groups over the 9d-1 fleet registry — store, API, CLI, Console screens, and a `?group=` filter on Hosts.

**Architecture:** Groups live in `osiris-fleet`, in the same `hosts.db` and on the same `SqliteHostRegistry` connection (one struct implements both `HostRegistry` and the new `HostGroupStore`), so membership has a real foreign key to `hosts`. Tenant scope is enforced inside every SQL statement via `(?N IS NULL OR tenant_id = ?N)`. A new `osiris-api` groups router (behind `auth_gate`) adds CRUD + membership routes; `/api/v1/hosts` gains a `groups` field and `?group=` filter. CLI and Console mirror the API.

**Tech Stack:** Rust (axum 0.7, rusqlite 0.31 bundled, tokio, serde, thiserror, uuid v4), clap CLI, React + TypeScript + React Query + Vitest/Testing Library console.

**Spec:** `docs/superpowers/specs/2026-09-26-phase-9d2-host-groups-design.md`

## Global Constraints

* Tables, exactly: `host_groups(group_id TEXT PRIMARY KEY, name TEXT NOT NULL, tenant_id TEXT NULL, created_at INTEGER NOT NULL)`, unique index `idx_host_groups_scope_name ON host_groups(COALESCE(tenant_id, ''), name)`, `host_group_members(group_id TEXT NOT NULL REFERENCES host_groups(group_id) ON DELETE CASCADE, host_id TEXT NOT NULL REFERENCES hosts(host_id), added_at INTEGER NOT NULL, PRIMARY KEY (group_id, host_id))`, index `idx_host_group_members_host ON host_group_members(host_id)`.
* `PRAGMA foreign_keys = ON` on every open; `hosts.db` `PRAGMA user_version` = `1` (`osiris_fleet::SCHEMA_VERSION`); a stored version greater than that fails the open with `FleetError::UnsupportedSchema(v)`.
* Group name: trimmed; 1–64 chars (`chars().count()`); no `char::is_control`; unique per tenant and among platform groups.
* Scope: `GroupScope::Tenant(t)` restricts every store query to `tenant_id = t` in SQL; out-of-scope group = `GroupError::NotFound`. `GroupScope::Platform` sees all.
* Routes (axum 0.7 `:param` syntax): `GET|POST /api/v1/groups`, `GET|PATCH|DELETE /api/v1/groups/:group_id`, `PUT|DELETE /api/v1/groups/:group_id/members/:host_id`. Min role: GET/HEAD = Viewer, everything else under `/api/v1/groups` = Admin.
* Error bodies, exactly: 404 `group not found`; 409 `a group with this name already exists`; 422 `unknown host`; 422 `unknown tenant`; 400 `tenant_id is not allowed for tenant users`; 400 for invalid name carries the validation message; 500 `internal error` (store text only in logs).
* Audit `what` values: `group_create`, `group_rename`, `group_delete`, `group_member_add`, `group_member_remove`; targets `EntityRef::Domain { name: "group:<group_id>" }` or `"group:<group_id>/host:<host_id>"`; only on success.
* The groups router and the fleet router are merged **before** `.layer(from_fn_with_state(auth_state, auth_gate))` everywhere a composed router is built.
* Before any commit: `cargo build -p osiris-cli -p osiris-server -p osiris-agent`, `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. Console tasks also: in `console/`, `npx vitest run` and `npm run build`.
* Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
* Subagent model: `sonnet` (haiku is org-blocked on this account). Tasks 2 and 3 touch the tenant boundary → their reviews run on `opus`.

## Review Focus

1. A tenant user requesting a **platform** group or another tenant's group by exact `group_id` (detail, rename, delete, member add/remove, `/hosts?group=`) gets 404, never 403 or data — Task 1 (store) and Task 2 (API) tests.
2. A host added to tenant A's group and later **reassigned to tenant B** disappears from A's group detail, A's `member_count`, and A's `/hosts?group=` result without any cleanup job — Task 2 test `a_host_reassigned_to_another_tenant_vanishes_from_the_old_tenants_group`.
3. Path shapes near the new tenant allowlist entries (`/api/v1/groups//members/x`, `/api/v1/groups/x/members/`, `/api/v1/groups/x/members/y/z`, `/api/v1/groups/x/other`, `PUT /api/v1/groups/x`) are denied for tenant users — Task 2 unit test `tenant_group_allowlist_accepts_only_exact_shapes`.
4. Names that collide only after trimming (`"prod "` vs `"prod"`) → 409; a 64-char multibyte name is accepted and 65 rejected — Task 1 tests.
5. A 9d-1-era `hosts.db` (user_version 0, existing host rows) opens, keeps its rows, and gets group tables; the shared connection really enforces foreign keys (unknown host rejected, cascade on delete) — Task 1 tests.

---

### Task 1: `osiris-fleet` — schema versioning, foreign keys, `HostGroupStore`

**Files:**
- Modify: `crates/osiris-fleet/src/lib.rs` (open(), `FleetError`, `SCHEMA_VERSION`, module + re-exports)
- Create: `crates/osiris-fleet/src/groups.rs`

**Interfaces:**
- Consumes: existing `SqliteHostRegistry { conn: Mutex<Connection> }`, `to_stored_i64`, `HostRegistry::upsert_heartbeat`.
- Produces (re-exported from `osiris_fleet`): `SCHEMA_VERSION: i64 = 1`; `FleetError::UnsupportedSchema(i64)`; `GroupScope { Platform, Tenant(Uuid) }` (Copy); `HostGroup { group_id: Uuid, name: String, tenant_id: Option<Uuid>, created_at: u64, member_count: u64 }` (Serialize, Clone, PartialEq); `GroupRef { group_id: Uuid, name: String }` (Serialize, Clone, PartialEq); `GroupError { InvalidName(String), NotFound, DuplicateName, UnknownHost, Backend(String) }`; `validate_group_name(&str) -> Result<String, GroupError>`; `MAX_GROUP_NAME_CHARS = 64`; trait `HostGroupStore` (signatures below) implemented by `SqliteHostRegistry`.

- [ ] **Step 1: Schema/open changes in `lib.rs`**

Add the error variant and constant, and replace `open`'s body. Keep the existing `hosts` column list exactly as it is today.

```rust
#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("io: {0}")]
    Io(String),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("hosts.db schema version {0} is newer than this build supports ({SCHEMA_VERSION})")]
    UnsupportedSchema(i64),
}

/// `PRAGMA user_version` of `hosts.db`. 0 = a 9d-1-era file (hosts table only,
/// never stamped); 1 = hosts + host groups (Phase 9d-2).
pub const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    distro TEXT NOT NULL,
    kernel_version TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    enrolled_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    health_state TEXT NOT NULL,
    cloud_provider TEXT,
    cloud_instance_id TEXT,
    cloud_region TEXT
);
CREATE TABLE IF NOT EXISTS host_groups (
    group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tenant_id TEXT NULL,
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_groups_scope_name
    ON host_groups(COALESCE(tenant_id, ''), name);
CREATE TABLE IF NOT EXISTS host_group_members (
    group_id TEXT NOT NULL REFERENCES host_groups(group_id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(host_id),
    added_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_host_group_members_host ON host_group_members(host_id);
";

impl SqliteHostRegistry {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FleetError> {
        let conn = Connection::open(path)?;
        // Per-connection and OFF by default in SQLite: without it the
        // members' ON DELETE CASCADE and the unknown-host rejection silently
        // do nothing.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(FleetError::UnsupportedSchema(version));
        }
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
    // row_from unchanged
}
```

At the top of `lib.rs` add:

```rust
mod groups;
pub use groups::{
    validate_group_name, GroupError, GroupRef, GroupScope, HostGroup, HostGroupStore,
    MAX_GROUP_NAME_CHARS,
};
```

- [ ] **Step 2: Write the failing tests in `crates/osiris-fleet/src/groups.rs`**

Create the file with only the test module first (plus `use` lines needed to compile the tests once Step 4 lands). The tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FleetError, HostRegistry, HostRow, SqliteHostRegistry, SCHEMA_VERSION};
    use osiris_health::HealthState;

    fn open(dir: &tempfile::TempDir) -> SqliteHostRegistry {
        SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()
    }

    fn seed_host(reg: &SqliteHostRegistry) -> Uuid {
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(HostRow {
            host_id,
            hostname: format!("h-{host_id}"),
            distro: "ubuntu-24.04".into(),
            kernel_version: "6.8.0".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: 1_000,
            last_seen: 1_000,
            health_state: HealthState::Healthy,
            cloud_provider: None,
            cloud_instance_id: None,
            cloud_region: None,
        })
        .unwrap();
        host_id
    }

    const P: GroupScope = GroupScope::Platform;

    #[test]
    fn create_get_list_rename_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let g = reg.create(&P, None, "  prod  ").unwrap();
        assert_eq!(g.name, "prod");
        assert_eq!(g.tenant_id, None);
        assert_eq!(g.member_count, 0);
        assert!(g.created_at > 0);
        assert_eq!(reg.get(&P, g.group_id).unwrap(), g);
        assert_eq!(reg.list(&P).unwrap(), vec![g.clone()]);
        let renamed = reg.rename(&P, g.group_id, "production").unwrap();
        assert_eq!(renamed.name, "production");
        reg.delete(&P, g.group_id).unwrap();
        assert_eq!(reg.get(&P, g.group_id), Err(GroupError::NotFound));
        assert_eq!(reg.delete(&P, g.group_id), Err(GroupError::NotFound));
    }

    #[test]
    fn list_is_sorted_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        reg.create(&P, None, "web").unwrap();
        reg.create(&P, None, "db").unwrap();
        let names: Vec<String> = reg.list(&P).unwrap().into_iter().map(|g| g.name).collect();
        assert_eq!(names, vec!["db".to_string(), "web".to_string()]);
    }

    #[test]
    fn duplicate_names_conflict_within_a_scope_including_after_trimming() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let t = Uuid::new_v4();
        reg.create(&P, None, "prod").unwrap();
        // Platform groups have tenant_id NULL: the COALESCE index must still
        // make them collide.
        assert_eq!(reg.create(&P, None, "prod "), Err(GroupError::DuplicateName));
        reg.create(&GroupScope::Tenant(t), None, "prod").unwrap();
        assert_eq!(
            reg.create(&GroupScope::Tenant(t), None, "prod"),
            Err(GroupError::DuplicateName)
        );
        // Same name in a different tenant is fine.
        reg.create(&GroupScope::Tenant(Uuid::new_v4()), None, "prod").unwrap();
        let other = reg.create(&P, None, "staging").unwrap();
        assert_eq!(
            reg.rename(&P, other.group_id, "prod"),
            Err(GroupError::DuplicateName)
        );
    }

    #[test]
    fn name_validation() {
        assert!(matches!(validate_group_name(""), Err(GroupError::InvalidName(_))));
        assert!(matches!(validate_group_name("   "), Err(GroupError::InvalidName(_))));
        assert!(matches!(validate_group_name("a\u{7}b"), Err(GroupError::InvalidName(_))));
        let max = "é".repeat(MAX_GROUP_NAME_CHARS);
        assert_eq!(validate_group_name(&max).unwrap(), max);
        let too_long = "é".repeat(MAX_GROUP_NAME_CHARS + 1);
        assert!(matches!(validate_group_name(&too_long), Err(GroupError::InvalidName(_))));
    }

    #[test]
    fn tenant_scope_is_enforced_for_every_operation() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let host = seed_host(&reg);
        let platform_group = reg.create(&P, None, "platform").unwrap();
        let b_group = reg.create(&GroupScope::Tenant(b), None, "b").unwrap();
        let sa = GroupScope::Tenant(a);
        for gid in [platform_group.group_id, b_group.group_id] {
            assert_eq!(reg.get(&sa, gid), Err(GroupError::NotFound));
            assert_eq!(reg.rename(&sa, gid, "x"), Err(GroupError::NotFound));
            assert_eq!(reg.add_member(&sa, gid, host), Err(GroupError::NotFound));
            assert_eq!(reg.remove_member(&sa, gid, host), Err(GroupError::NotFound));
            assert_eq!(reg.members(&sa, gid), Err(GroupError::NotFound));
            assert_eq!(reg.delete(&sa, gid), Err(GroupError::NotFound));
        }
        assert_eq!(reg.list(&sa).unwrap(), vec![]);
        // Platform sees both, and nothing was modified by the tenant attempts.
        assert_eq!(reg.list(&P).unwrap().len(), 2);
        assert_eq!(reg.get(&P, b_group.group_id).unwrap().name, "b");
    }

    #[test]
    fn a_tenant_scoped_create_ignores_the_passed_tenant_id() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let g = reg.create(&GroupScope::Tenant(a), Some(b), "x").unwrap();
        assert_eq!(g.tenant_id, Some(a));
        let pg = reg.create(&P, Some(b), "y").unwrap();
        assert_eq!(pg.tenant_id, Some(b));
    }

    #[test]
    fn members_add_is_idempotent_remove_of_non_member_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let host = seed_host(&reg);
        let g = reg.create(&P, None, "g").unwrap();
        reg.add_member(&P, g.group_id, host).unwrap();
        reg.add_member(&P, g.group_id, host).unwrap();
        assert_eq!(reg.members(&P, g.group_id).unwrap(), vec![host]);
        assert_eq!(reg.get(&P, g.group_id).unwrap().member_count, 1);
        reg.remove_member(&P, g.group_id, host).unwrap();
        reg.remove_member(&P, g.group_id, host).unwrap();
        assert_eq!(reg.members(&P, g.group_id).unwrap(), vec![]);
    }

    #[test]
    fn adding_an_unregistered_host_is_unknown_host_proving_foreign_keys_are_on() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let g = reg.create(&P, None, "g").unwrap();
        assert_eq!(
            reg.add_member(&P, g.group_id, Uuid::new_v4()),
            Err(GroupError::UnknownHost)
        );
    }

    #[test]
    fn deleting_a_group_cascades_its_memberships() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let host = seed_host(&reg);
        let g = reg.create(&P, None, "g").unwrap();
        reg.add_member(&P, g.group_id, host).unwrap();
        reg.delete(&P, g.group_id).unwrap();
        let conn = reg.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM host_group_members", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        // The host itself is untouched.
        drop(conn);
        assert!(HostRegistry::get(&reg, host).unwrap().is_some());
    }

    #[test]
    fn groups_of_respects_scope_and_sorts_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let t = Uuid::new_v4();
        let host = seed_host(&reg);
        let other_host = seed_host(&reg);
        let web = reg.create(&P, None, "web").unwrap();
        let db = reg.create(&P, None, "db").unwrap();
        let tg = reg.create(&GroupScope::Tenant(t), None, "tenant-g").unwrap();
        for g in [&web, &db] {
            reg.add_member(&P, g.group_id, host).unwrap();
        }
        reg.add_member(&P, tg.group_id, host).unwrap();
        reg.add_member(&P, web.group_id, other_host).unwrap();

        let all = reg.groups_of(&P, &[host]).unwrap();
        let names: Vec<&str> = all[&host].iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["db", "tenant-g", "web"]);
        assert!(!all.contains_key(&other_host), "only the requested hosts are returned");

        let scoped = reg.groups_of(&GroupScope::Tenant(t), &[host]).unwrap();
        assert_eq!(
            scoped[&host],
            vec![GroupRef { group_id: tg.group_id, name: "tenant-g".into() }]
        );
    }

    #[test]
    fn a_9d1_era_database_opens_keeps_its_hosts_and_gains_group_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE hosts (
                    host_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, distro TEXT NOT NULL,
                    kernel_version TEXT NOT NULL, agent_version TEXT NOT NULL,
                    enrolled_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                    health_state TEXT NOT NULL, cloud_provider TEXT,
                    cloud_instance_id TEXT, cloud_region TEXT);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO hosts VALUES (?1,'old','d','k','0.1.0',5,5,'{\"state\":\"HEALTHY\"}',NULL,NULL,NULL)",
                [Uuid::new_v4().to_string()],
            )
            .unwrap();
        }
        let reg = SqliteHostRegistry::open(&path).unwrap();
        assert_eq!(reg.list().unwrap().len(), 1);
        reg.create(&P, None, "new").unwrap();
        let v: i64 = reg
            .conn
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn a_newer_schema_version_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.db");
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        assert!(matches!(
            SqliteHostRegistry::open(&path),
            Err(FleetError::UnsupportedSchema(99))
        ));
    }
}
```

`HostRegistry::get(&reg, host)` is fully qualified because `SqliteHostRegistry` now has two `get` methods, one per trait. Use the same fully-qualified form anywhere both traits are in scope and a call is ambiguous.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p osiris-fleet`
Expected: compile failure (`HostGroupStore`, `GroupScope`, … not defined).

- [ ] **Step 4: Implement `groups.rs`** (above the test module)

```rust
//! Host groups (Phase 9d-2): operator-managed, tenant-scoped named sets of
//! registered hosts. Implemented on `SqliteHostRegistry` itself so the
//! membership table's foreign key to `hosts` is real (same database, same
//! connection). Tenant scope is part of every SQL statement:
//! `(?N IS NULL OR tenant_id = ?N)` with `?N` bound from `GroupScope` —
//! never a post-fetch filter.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use uuid::Uuid;

use crate::{to_stored_i64, SqliteHostRegistry};

pub const MAX_GROUP_NAME_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupScope {
    Platform,
    Tenant(Uuid),
}

impl GroupScope {
    /// Bound into `(?N IS NULL OR tenant_id = ?N)`: `None` = unrestricted.
    fn tenant_param(&self) -> Option<String> {
        match self {
            GroupScope::Platform => None,
            GroupScope::Tenant(t) => Some(t.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostGroup {
    pub group_id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    /// Nanoseconds since the Unix epoch, server clock.
    pub created_at: u64,
    pub member_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupRef {
    pub group_id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    #[error("{0}")]
    InvalidName(String),
    #[error("group not found")]
    NotFound,
    #[error("a group with this name already exists")]
    DuplicateName,
    #[error("unknown host")]
    UnknownHost,
    #[error("group store: {0}")]
    Backend(String),
}

pub trait HostGroupStore: Send + Sync {
    /// Under `Tenant(t)` the group always belongs to `t` and `tenant_id` is
    /// ignored; under `Platform`, `tenant_id` (None = platform group) is used.
    fn create(
        &self,
        scope: &GroupScope,
        tenant_id: Option<Uuid>,
        name: &str,
    ) -> Result<HostGroup, GroupError>;
    fn list(&self, scope: &GroupScope) -> Result<Vec<HostGroup>, GroupError>;
    fn get(&self, scope: &GroupScope, group_id: Uuid) -> Result<HostGroup, GroupError>;
    fn rename(&self, scope: &GroupScope, group_id: Uuid, name: &str)
        -> Result<HostGroup, GroupError>;
    fn delete(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError>;
    fn add_member(&self, scope: &GroupScope, group_id: Uuid, host_id: Uuid)
        -> Result<(), GroupError>;
    fn remove_member(&self, scope: &GroupScope, group_id: Uuid, host_id: Uuid)
        -> Result<(), GroupError>;
    fn members(&self, scope: &GroupScope, group_id: Uuid) -> Result<Vec<Uuid>, GroupError>;
    fn groups_of(
        &self,
        scope: &GroupScope,
        host_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<GroupRef>>, GroupError>;
}

pub fn validate_group_name(raw: &str) -> Result<String, GroupError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(GroupError::InvalidName("name must not be empty".into()));
    }
    if name.chars().count() > MAX_GROUP_NAME_CHARS {
        return Err(GroupError::InvalidName(format!(
            "name must be at most {MAX_GROUP_NAME_CHARS} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(GroupError::InvalidName(
            "name must not contain control characters".into(),
        ));
    }
    Ok(name.to_string())
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn backend(e: rusqlite::Error) -> GroupError {
    GroupError::Backend(e.to_string())
}

fn map_write_err(e: rusqlite::Error) -> GroupError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e {
        match f.extended_code {
            rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE => return GroupError::DuplicateName,
            rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY => return GroupError::UnknownHost,
            _ => {}
        }
    }
    backend(e)
}

fn parse_uuid(idx: usize, s: &str) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

const GROUP_COLUMNS: &str = "g.group_id, g.name, g.tenant_id, g.created_at, \
     (SELECT COUNT(*) FROM host_group_members m WHERE m.group_id = g.group_id)";

fn group_from(r: &rusqlite::Row) -> rusqlite::Result<HostGroup> {
    let group_id: String = r.get(0)?;
    let tenant_id: Option<String> = r.get(2)?;
    Ok(HostGroup {
        group_id: parse_uuid(0, &group_id)?,
        name: r.get(1)?,
        tenant_id: tenant_id.map(|t| parse_uuid(2, &t)).transpose()?,
        created_at: r.get::<_, i64>(3)? as u64,
        member_count: r.get::<_, i64>(4)? as u64,
    })
}

fn get_in_scope(conn: &Connection, scope: &GroupScope, group_id: Uuid) -> Result<HostGroup, GroupError> {
    conn.query_row(
        &format!(
            "SELECT {GROUP_COLUMNS} FROM host_groups g
             WHERE g.group_id = ?1 AND (?2 IS NULL OR g.tenant_id = ?2)"
        ),
        params![group_id.to_string(), scope.tenant_param()],
        group_from,
    )
    .optional()
    .map_err(backend)?
    .ok_or(GroupError::NotFound)
}

impl HostGroupStore for SqliteHostRegistry {
    fn create(&self, scope: &GroupScope, tenant_id: Option<Uuid>, name: &str) -> Result<HostGroup, GroupError> {
        let name = validate_group_name(name)?;
        let owner = match scope {
            GroupScope::Tenant(t) => Some(*t),
            GroupScope::Platform => tenant_id,
        };
        let group = HostGroup {
            group_id: Uuid::new_v4(),
            name,
            tenant_id: owner,
            created_at: now_ns(),
            member_count: 0,
        };
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO host_groups (group_id, name, tenant_id, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                group.group_id.to_string(),
                group.name,
                group.tenant_id.map(|t| t.to_string()),
                to_stored_i64(group.created_at),
            ],
        )
        .map_err(map_write_err)?;
        Ok(group)
    }

    fn list(&self, scope: &GroupScope) -> Result<Vec<HostGroup>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {GROUP_COLUMNS} FROM host_groups g
                 WHERE (?1 IS NULL OR g.tenant_id = ?1)
                 ORDER BY g.name, g.group_id"
            ))
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![scope.tenant_param()], group_from)
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        Ok(rows)
    }

    fn get(&self, scope: &GroupScope, group_id: Uuid) -> Result<HostGroup, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)
    }

    fn rename(&self, scope: &GroupScope, group_id: Uuid, name: &str) -> Result<HostGroup, GroupError> {
        let name = validate_group_name(name)?;
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let n = conn
            .execute(
                "UPDATE host_groups SET name = ?3 WHERE group_id = ?1 AND (?2 IS NULL OR tenant_id = ?2)",
                params![group_id.to_string(), scope.tenant_param(), name],
            )
            .map_err(map_write_err)?;
        if n == 0 {
            return Err(GroupError::NotFound);
        }
        get_in_scope(&conn, scope, group_id)
    }

    fn delete(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let n = conn
            .execute(
                "DELETE FROM host_groups WHERE group_id = ?1 AND (?2 IS NULL OR tenant_id = ?2)",
                params![group_id.to_string(), scope.tenant_param()],
            )
            .map_err(backend)?;
        if n == 0 {
            return Err(GroupError::NotFound);
        }
        Ok(())
    }

    fn add_member(&self, scope: &GroupScope, group_id: Uuid, host_id: Uuid) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        conn.execute(
            "INSERT INTO host_group_members (group_id, host_id, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id, host_id) DO NOTHING",
            params![group_id.to_string(), host_id.to_string(), to_stored_i64(now_ns())],
        )
        .map_err(map_write_err)?;
        Ok(())
    }

    fn remove_member(&self, scope: &GroupScope, group_id: Uuid, host_id: Uuid) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        conn.execute(
            "DELETE FROM host_group_members WHERE group_id = ?1 AND host_id = ?2",
            params![group_id.to_string(), host_id.to_string()],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn members(&self, scope: &GroupScope, group_id: Uuid) -> Result<Vec<Uuid>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        let mut stmt = conn
            .prepare("SELECT host_id FROM host_group_members WHERE group_id = ?1 ORDER BY host_id")
            .map_err(backend)?;
        let ids = stmt
            .query_map(params![group_id.to_string()], |r| {
                let s: String = r.get(0)?;
                parse_uuid(0, &s)
            })
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        Ok(ids)
    }

    fn groups_of(&self, scope: &GroupScope, host_ids: &[Uuid]) -> Result<HashMap<Uuid, Vec<GroupRef>>, GroupError> {
        let wanted: HashSet<Uuid> = host_ids.iter().copied().collect();
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT m.host_id, g.group_id, g.name
                 FROM host_group_members m JOIN host_groups g ON g.group_id = m.group_id
                 WHERE (?1 IS NULL OR g.tenant_id = ?1)
                 ORDER BY g.name, g.group_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![scope.tenant_param()], |r| {
                let host: String = r.get(0)?;
                let gid: String = r.get(1)?;
                Ok((parse_uuid(0, &host)?, GroupRef { group_id: parse_uuid(1, &gid)?, name: r.get(2)? }))
            })
            .map_err(backend)?;
        let mut out: HashMap<Uuid, Vec<GroupRef>> = HashMap::new();
        for row in rows {
            let (host, group) = row.map_err(backend)?;
            if wanted.contains(&host) {
                out.entry(host).or_default().push(group);
            }
        }
        Ok(out)
    }
}
```

Note: the existing `hosts` rows' `get` on `HostRegistry` and `HostGroupStore::get` share a name — existing `lib.rs` tests calling `reg.get(id)` may now be ambiguous if `HostGroupStore` is in scope there; qualify them as `HostRegistry::get(&reg, id)` only if the compiler complains.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-fleet`
Expected: all existing 11 + 12 new tests PASS.

- [ ] **Step 6: Workspace gates and commit**

Run the Global Constraints gate commands (build binaries, fmt, clippy `-D warnings`, `cargo test --workspace`). Commit:

```bash
git add crates/osiris-fleet
git commit -m "feat(fleet): host groups store with tenant scope in SQL, FK + user_version (Phase 9d-2)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `osiris-api` — groups router, authorization rules, server wiring

**Files:**
- Create: `crates/osiris-api/src/groups.rs`
- Modify: `crates/osiris-api/src/lib.rs` (module + re-export next to `pub mod fleet;`)
- Modify: `crates/osiris-api/src/fleet.rs` (extract `host_status`, make `now_ns` `pub(crate)`)
- Modify: `crates/osiris-api/src/auth_middleware.rs` (`min_role_for`, `tenant_route_allowed`, tests)
- Modify: `crates/osiris-server/src/main.rs` (one `Arc<SqliteHostRegistry>` shared as both traits; merge groups router)
- Modify: `crates/osiris-api/tests/composed_router_auth.rs`, `crates/osiris-api/tests/composed_router_tenancy.rs` (merge groups router before `auth_gate`; new tests)

**Interfaces:**
- Consumes (Task 1): `osiris_fleet::{GroupError, GroupScope, HostGroup, HostGroupStore, HostRegistry, SqliteHostRegistry}`; existing `crate::tenant_scope::hosts_of_tenant(Option<Uuid>, Option<Arc<dyn TenantStore>>) -> Result<Option<HashSet<Uuid>>, (StatusCode, String)>`; `AuthContext { user_id, role, token, tenant_id }`; `osiris_audit::{AuditLog, NewAuditEntry, ActorRef, AuditResult}`; `osiris_schema::EntityRef`.
- Produces: `pub struct GroupsState { pub groups: Arc<dyn HostGroupStore>, pub registry: Arc<dyn HostRegistry>, pub tenants: Arc<dyn TenantStore>, pub audit_log: Arc<dyn AuditLog + Send + Sync> }`; `pub fn build_groups_router(state: GroupsState) -> Router` (both re-exported from `osiris_api`); in `fleet.rs`: `pub(crate) fn host_status(last_seen: u64, now_ns: u64) -> &'static str` and `pub(crate) fn now_ns() -> u64`. JSON: group = `{group_id, name, tenant_id, created_at, member_count}`; detail = group fields + `members: [{host_id, hostname, status, agent_version, last_seen}]` sorted by hostname then host_id.

- [ ] **Step 1: `fleet.rs` extraction (no behavior change)**

```rust
pub(crate) fn host_status(last_seen: u64, now_ns: u64) -> &'static str {
    if now_ns.saturating_sub(last_seen) <= 3 * EXPECTED_HEARTBEAT_INTERVAL_NS {
        "ONLINE"
    } else {
        "STALE"
    }
}
```

`to_summary` uses `status: host_status(row.last_seen, now_ns).to_string()`; `fn now_ns()` becomes `pub(crate) fn now_ns()`. Existing fleet tests must still pass unchanged.

- [ ] **Step 2: Failing authorization unit tests in `auth_middleware.rs`'s test module**

```rust
#[test]
fn groups_routes_need_viewer_to_read_and_admin_to_write() {
    use axum::http::Method;
    assert_eq!(min_role_for(&Method::GET, "/api/v1/groups"), Role::Viewer);
    assert_eq!(min_role_for(&Method::HEAD, "/api/v1/groups/x"), Role::Viewer);
    assert_eq!(min_role_for(&Method::POST, "/api/v1/groups"), Role::Admin);
    assert_eq!(min_role_for(&Method::PATCH, "/api/v1/groups/x"), Role::Admin);
    assert_eq!(min_role_for(&Method::DELETE, "/api/v1/groups/x"), Role::Admin);
    assert_eq!(min_role_for(&Method::PUT, "/api/v1/groups/x/members/y"), Role::Admin);
    assert_eq!(min_role_for(&Method::DELETE, "/api/v1/groups/x/members/y"), Role::Admin);
}

#[test]
fn tenant_group_allowlist_accepts_only_exact_shapes() {
    use axum::http::Method;
    let allowed = [
        (Method::GET, "/api/v1/groups"),
        (Method::HEAD, "/api/v1/groups"),
        (Method::GET, "/api/v1/groups/g1"),
        (Method::POST, "/api/v1/groups"),
        (Method::PATCH, "/api/v1/groups/g1"),
        (Method::DELETE, "/api/v1/groups/g1"),
        (Method::PUT, "/api/v1/groups/g1/members/h1"),
        (Method::DELETE, "/api/v1/groups/g1/members/h1"),
    ];
    for (m, p) in allowed {
        assert!(tenant_route_allowed(&m, p), "{m} {p} should be allowed");
    }
    let denied = [
        (Method::GET, "/api/v1/groups/g1/members/h1"),
        (Method::GET, "/api/v1/groups/g1/other"),
        (Method::POST, "/api/v1/groups/g1"),
        (Method::PATCH, "/api/v1/groups"),
        (Method::PATCH, "/api/v1/groups/g1/members/h1"),
        (Method::PUT, "/api/v1/groups/g1"),
        (Method::PUT, "/api/v1/groups//members/h1"),
        (Method::PUT, "/api/v1/groups/g1/members/"),
        (Method::PUT, "/api/v1/groups/g1/members/h1/z"),
        (Method::DELETE, "/api/v1/groups"),
        (Method::DELETE, "/api/v1/groups/g1/x/h1"),
        (Method::PUT, "/api/v1/tenants/t/hosts/h"),
        (Method::DELETE, "/api/v1/tenants/t/hosts/h"),
    ];
    for (m, p) in denied {
        assert!(!tenant_route_allowed(&m, p), "{m} {p} should be denied");
    }
}
```

Run: `cargo test -p osiris-api --lib auth_middleware` → Expected: FAIL.

- [ ] **Step 3: Implement the rules**

In `min_role_for`, directly after the Admin-only block for audit/users/tenants:

```rust
    if path == "/api/v1/groups" || path.starts_with("/api/v1/groups/") {
        return if method == Method::GET || method == Method::HEAD {
            Role::Viewer
        } else {
            Role::Admin
        };
    }
```

In `tenant_route_allowed`, after the `one_segment` closure add:

```rust
    // /api/v1/groups/:group_id/members/:host_id — exactly two non-empty
    // segments, nothing after the host id.
    let group_member = || {
        path.strip_prefix("/api/v1/groups/")
            .and_then(|rest| rest.split_once("/members/"))
            .is_some_and(|(g, h)| {
                !g.is_empty() && !g.contains('/') && !h.is_empty() && !h.contains('/')
            })
    };
```

Change the POST branch to also allow `|| path == "/api/v1/groups"`; the PATCH branch to `return one_segment("/api/v1/incidents/") || one_segment("/api/v1/groups/");`; and insert before the `if method != Method::GET && method != Method::HEAD` line:

```rust
    if method == Method::PUT {
        return group_member();
    }
    if method == Method::DELETE {
        return one_segment("/api/v1/groups/") || group_member();
    }
```

Add `"/api/v1/groups"` to `EXACT`, and before the final `false`:

```rust
    // /api/v1/groups/:group_id (the handler scopes it to the tenant).
    if one_segment("/api/v1/groups/") {
        return true;
    }
```

Update the doc comment above `tenant_route_allowed` to mention groups. Run the Step 2 tests → PASS; run the whole `auth_middleware` test module → PASS.

- [ ] **Step 4: Failing handler tests at the bottom of `groups.rs`**

Handlers are called directly (this crate's convention — see `fleet.rs` tests). Helpers and tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::FileAuditLog;
    use osiris_fleet::{HostRow, SqliteHostRegistry};
    use osiris_health::HealthState;
    use osiris_tenancy::SqliteTenantStore;

    struct Fx {
        _dir: tempfile::TempDir,
        state: GroupsState,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let state = GroupsState {
            groups: db.clone(),
            registry: db,
            tenants: Arc::new(SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap()),
            audit_log: Arc::new(FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
        };
        Fx { _dir: dir, state }
    }

    fn host(state: &GroupsState, name: &str) -> Uuid {
        let host_id = Uuid::new_v4();
        state
            .registry
            .upsert_heartbeat(HostRow {
                host_id,
                hostname: name.into(),
                distro: "d".into(),
                kernel_version: "k".into(),
                agent_version: "0.1.0".into(),
                enrolled_at: now_ns(),
                last_seen: now_ns(),
                health_state: HealthState::Healthy,
                cloud_provider: None,
                cloud_instance_id: None,
                cloud_region: None,
            })
            .unwrap();
        host_id
    }

    fn ctx(tenant_id: Option<Uuid>) -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::Admin,
            token: "t".into(),
            tenant_id,
        }
    }

    async fn create(state: &GroupsState, c: &AuthContext, name: &str, tenant_id: Option<Uuid>) -> Result<HostGroup, ApiError> {
        create_group(
            Extension(c.clone()),
            State(state.clone()),
            Json(CreateGroupBody { name: name.into(), tenant_id }),
        )
        .await
        .map(|(_, Json(g))| g)
    }

    #[tokio::test]
    async fn platform_admin_full_lifecycle_with_audit() {
        let f = fx();
        let admin = ctx(None);
        let h = host(&f.state, "web-1");
        let g = create(&f.state, &admin, "web", None).await.unwrap();
        add_member(Extension(admin.clone()), State(f.state.clone()), Path((g.group_id, h))).await.unwrap();
        let Json(detail) = get_group(Extension(admin.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap();
        assert_eq!(detail.group.member_count, 1);
        assert_eq!(detail.members[0].hostname, "web-1");
        assert_eq!(detail.members[0].status, "ONLINE");
        let Json(renamed) = rename_group(Extension(admin.clone()), State(f.state.clone()), Path(g.group_id), Json(RenameGroupBody { name: "frontend".into() })).await.unwrap();
        assert_eq!(renamed.name, "frontend");
        remove_member(Extension(admin.clone()), State(f.state.clone()), Path((g.group_id, h))).await.unwrap();
        delete_group(Extension(admin.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap();
        let whats: Vec<String> = f.state.audit_log.read_all().unwrap().into_iter().map(|e| e.what).collect();
        assert_eq!(whats, vec!["group_create", "group_member_add", "group_rename", "group_member_remove", "group_delete"]);
    }

    #[tokio::test]
    async fn store_errors_map_to_the_spec_statuses_and_bodies() {
        let f = fx();
        let admin = ctx(None);
        create(&f.state, &admin, "web", None).await.unwrap();
        assert_eq!(create(&f.state, &admin, "web", None).await.unwrap_err(), (StatusCode::CONFLICT, "a group with this name already exists".to_string()));
        assert_eq!(create(&f.state, &admin, "  ", None).await.unwrap_err().0, StatusCode::BAD_REQUEST);
        let missing = Uuid::new_v4();
        assert_eq!(get_group(Extension(admin.clone()), State(f.state.clone()), Path(missing)).await.unwrap_err(), (StatusCode::NOT_FOUND, "group not found".to_string()));
        let g = create(&f.state, &admin, "db", None).await.unwrap();
        assert_eq!(add_member(Extension(admin.clone()), State(f.state.clone()), Path((g.group_id, Uuid::new_v4()))).await.unwrap_err(), (StatusCode::UNPROCESSABLE_ENTITY, "unknown host".to_string()));
    }

    #[tokio::test]
    async fn tenant_users_cannot_see_or_touch_other_tenants_or_platform_groups() {
        let f = fx();
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let platform = create(&f.state, &ctx(None), "p", None).await.unwrap();
        let b_group = create(&f.state, &ctx(Some(b)), "b-group", None).await.unwrap();
        let ta = ctx(Some(a));
        let Json(list) = list_groups(Extension(ta.clone()), State(f.state.clone())).await.unwrap();
        assert!(list.is_empty());
        for gid in [platform.group_id, b_group.group_id] {
            let nf = (StatusCode::NOT_FOUND, "group not found".to_string());
            assert_eq!(get_group(Extension(ta.clone()), State(f.state.clone()), Path(gid)).await.unwrap_err(), nf);
            assert_eq!(rename_group(Extension(ta.clone()), State(f.state.clone()), Path(gid), Json(RenameGroupBody { name: "x".into() })).await.unwrap_err(), nf);
            assert_eq!(delete_group(Extension(ta.clone()), State(f.state.clone()), Path(gid)).await.unwrap_err(), nf);
            assert_eq!(remove_member(Extension(ta.clone()), State(f.state.clone()), Path((gid, Uuid::new_v4()))).await.unwrap_err(), nf);
        }
    }

    #[tokio::test]
    async fn a_tenant_cannot_add_another_tenants_host_and_gets_the_unknown_host_body() {
        let f = fx();
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let mine = host(&f.state, "mine");
        let theirs = host(&f.state, "theirs");
        let unassigned = host(&f.state, "unassigned");
        f.state.tenants.assign_host(mine, a).unwrap();
        f.state.tenants.assign_host(theirs, b).unwrap();
        let ta = ctx(Some(a));
        let g = create(&f.state, &ta, "mine", None).await.unwrap();
        let unknown = (StatusCode::UNPROCESSABLE_ENTITY, "unknown host".to_string());
        assert_eq!(add_member(Extension(ta.clone()), State(f.state.clone()), Path((g.group_id, theirs))).await.unwrap_err(), unknown);
        assert_eq!(add_member(Extension(ta.clone()), State(f.state.clone()), Path((g.group_id, unassigned))).await.unwrap_err(), unknown);
        // Even a platform admin cannot put a foreign host into a tenant's group.
        assert_eq!(add_member(Extension(ctx(None)), State(f.state.clone()), Path((g.group_id, theirs))).await.unwrap_err(), unknown);
        assert_eq!(add_member(Extension(ta.clone()), State(f.state.clone()), Path((g.group_id, mine))).await.unwrap(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn a_host_reassigned_to_another_tenant_vanishes_from_the_old_tenants_group() {
        let f = fx();
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let h = host(&f.state, "moving");
        f.state.tenants.assign_host(h, a).unwrap();
        let ta = ctx(Some(a));
        let g = create(&f.state, &ta, "g", None).await.unwrap();
        add_member(Extension(ta.clone()), State(f.state.clone()), Path((g.group_id, h))).await.unwrap();
        f.state.tenants.assign_host(h, b).unwrap();
        let Json(detail) = get_group(Extension(ta.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap();
        assert!(detail.members.is_empty());
        assert_eq!(detail.group.member_count, 0);
        let Json(list) = list_groups(Extension(ta.clone()), State(f.state.clone())).await.unwrap();
        assert_eq!(list[0].member_count, 0);
    }

    #[tokio::test]
    async fn tenant_id_in_the_body_is_400_for_tenant_users_and_checked_for_platform() {
        let f = fx();
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        assert_eq!(create(&f.state, &ctx(Some(a)), "x", Some(a)).await.unwrap_err(), (StatusCode::BAD_REQUEST, "tenant_id is not allowed for tenant users".to_string()));
        assert_eq!(create(&f.state, &ctx(None), "x", Some(Uuid::new_v4())).await.unwrap_err(), (StatusCode::UNPROCESSABLE_ENTITY, "unknown tenant".to_string()));
        let g = create(&f.state, &ctx(None), "x", Some(a)).await.unwrap();
        assert_eq!(g.tenant_id, Some(a));
        let Json(list) = list_groups(Extension(ctx(Some(a))), State(f.state.clone())).await.unwrap();
        assert_eq!(list.len(), 1, "a platform-created tenant group is visible to that tenant");
    }

    #[tokio::test]
    async fn failed_mutations_are_not_audited() {
        let f = fx();
        let _ = create(&f.state, &ctx(None), "", None).await;
        let _ = delete_group(Extension(ctx(None)), State(f.state.clone()), Path(Uuid::new_v4())).await;
        assert!(f.state.audit_log.read_all().unwrap().is_empty());
    }
}
```

Run: `cargo test -p osiris-api --lib groups` → Expected: compile FAIL.

- [ ] **Step 5: Implement `groups.rs`** (above the test module)

```rust
//! Host groups API (Phase 9d-2). Every handler derives a `GroupScope` from
//! the caller (`tenant_id: Some(t)` → `Tenant(t)`, `None` → `Platform`) and
//! hands it to the store, which enforces it in SQL. Tenant callers
//! additionally only ever see members that are *currently* hosts of their
//! tenant (a host reassigned elsewhere leaves a stale, invisible row).

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_fleet::{GroupError, GroupScope, HostGroup, HostGroupStore, HostRegistry};
use osiris_schema::EntityRef;
use osiris_tenancy::TenantStore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthContext;
use crate::fleet::{host_status, now_ns};

type ApiError = (StatusCode, String);

#[derive(Clone)]
pub struct GroupsState {
    pub groups: Arc<dyn HostGroupStore>,
    pub registry: Arc<dyn HostRegistry>,
    pub tenants: Arc<dyn TenantStore>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
}

pub fn build_groups_router(state: GroupsState) -> Router {
    Router::new()
        .route("/api/v1/groups", get(list_groups).post(create_group))
        .route(
            "/api/v1/groups/:group_id",
            get(get_group).patch(rename_group).delete(delete_group),
        )
        .route(
            "/api/v1/groups/:group_id/members/:host_id",
            put(add_member).delete(remove_member),
        )
        .with_state(state)
}

fn scope_of(ctx: &AuthContext) -> GroupScope {
    match ctx.tenant_id {
        Some(t) => GroupScope::Tenant(t),
        None => GroupScope::Platform,
    }
}

fn internal(cause: String) -> ApiError {
    tracing::error!(error = %cause, "groups handler failure");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
}

fn group_error(e: GroupError) -> ApiError {
    match e {
        GroupError::InvalidName(m) => (StatusCode::BAD_REQUEST, m),
        GroupError::NotFound => (StatusCode::NOT_FOUND, e.to_string()),
        GroupError::DuplicateName => (StatusCode::CONFLICT, e.to_string()),
        GroupError::UnknownHost => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
        GroupError::Backend(m) => internal(m),
    }
}

async fn run<T, F>(f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, GroupError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal(e.to_string()))?
        .map_err(group_error)
}

fn audit(state: &GroupsState, ctx: &AuthContext, what: &str, target: String) {
    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User { user_id: ctx.user_id },
        what: what.to_string(),
        target: EntityRef::Domain { name: target },
        why: None,
        result: AuditResult::Success,
    });
}

/// `Some(set)` for a tenant caller (its current hosts), `None` for platform.
async fn caller_hosts(state: &GroupsState, ctx: &AuthContext) -> Result<Option<HashSet<Uuid>>, ApiError> {
    crate::tenant_scope::hosts_of_tenant(ctx.tenant_id, Some(state.tenants.clone())).await
}

fn retain_allowed(members: Vec<Uuid>, allowed: Option<&HashSet<Uuid>>) -> Vec<Uuid> {
    match allowed {
        Some(set) => members.into_iter().filter(|h| set.contains(h)).collect(),
        None => members,
    }
}

#[derive(Debug, Deserialize)]
struct CreateGroupBody {
    name: String,
    #[serde(default)]
    tenant_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct RenameGroupBody {
    name: String,
}

#[derive(Debug, Serialize)]
struct GroupMember {
    host_id: Uuid,
    hostname: String,
    status: &'static str,
    agent_version: String,
    last_seen: u64,
}

#[derive(Debug, Serialize)]
struct GroupDetail {
    #[serde(flatten)]
    group: HostGroup,
    members: Vec<GroupMember>,
}

async fn list_groups(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
) -> Result<Json<Vec<HostGroup>>, ApiError> {
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    let mut groups = run(move || store.list(&scope)).await?;
    if let Some(allowed) = caller_hosts(&state, &ctx).await? {
        for g in groups.iter_mut() {
            let store = state.groups.clone();
            let gid = g.group_id;
            let members = run(move || store.members(&scope, gid)).await?;
            g.member_count = retain_allowed(members, Some(&allowed)).len() as u64;
        }
    }
    Ok(Json(groups))
}

async fn create_group(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
    Json(body): Json<CreateGroupBody>,
) -> Result<(StatusCode, Json<HostGroup>), ApiError> {
    match (ctx.tenant_id, body.tenant_id) {
        (Some(_), Some(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "tenant_id is not allowed for tenant users".to_string(),
            ))
        }
        (None, Some(t)) => {
            let tenants = state.tenants.clone();
            let exists = tokio::task::spawn_blocking(move || tenants.get_tenant(t))
                .await
                .map_err(|e| internal(e.to_string()))?
                .map_err(|e| internal(e.to_string()))?
                .is_some();
            if !exists {
                return Err((StatusCode::UNPROCESSABLE_ENTITY, "unknown tenant".to_string()));
            }
        }
        _ => {}
    }
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    let (name, tenant_id) = (body.name, body.tenant_id);
    let group = run(move || store.create(&scope, tenant_id, &name)).await?;
    audit(&state, &ctx, "group_create", format!("group:{}", group.group_id));
    Ok((StatusCode::CREATED, Json(group)))
}

async fn get_group(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupDetail>, ApiError> {
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    let (mut group, members) =
        run(move || Ok((store.get(&scope, group_id)?, store.members(&scope, group_id)?))).await?;
    let allowed = caller_hosts(&state, &ctx).await?;
    let members = retain_allowed(members, allowed.as_ref());
    let registry = state.registry.clone();
    let rows = tokio::task::spawn_blocking(move || {
        members
            .into_iter()
            .map(|h| registry.get(h))
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|e| internal(e.to_string()))?
    .map_err(|e| internal(e.to_string()))?;
    let now = now_ns();
    let mut members: Vec<GroupMember> = rows
        .into_iter()
        .flatten()
        .map(|r| GroupMember {
            host_id: r.host_id,
            hostname: r.hostname,
            status: host_status(r.last_seen, now),
            agent_version: r.agent_version,
            last_seen: r.last_seen,
        })
        .collect();
    members.sort_by(|a, b| a.hostname.cmp(&b.hostname).then(a.host_id.cmp(&b.host_id)));
    group.member_count = members.len() as u64;
    Ok(Json(GroupDetail { group, members }))
}

async fn rename_group(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
    Path(group_id): Path<Uuid>,
    Json(body): Json<RenameGroupBody>,
) -> Result<Json<HostGroup>, ApiError> {
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    let group = run(move || store.rename(&scope, group_id, &body.name)).await?;
    audit(&state, &ctx, "group_rename", format!("group:{group_id}"));
    Ok(Json(group))
}

async fn delete_group(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
    Path(group_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    run(move || store.delete(&scope, group_id)).await?;
    audit(&state, &ctx, "group_delete", format!("group:{group_id}"));
    Ok(StatusCode::NO_CONTENT)
}

async fn add_member(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
    Path((group_id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    let group = run(move || store.get(&scope, group_id)).await?;
    // The *group's* tenant bounds its members, whoever the caller is.
    if let Some(owner) = group.tenant_id {
        let allowed =
            crate::tenant_scope::hosts_of_tenant(Some(owner), Some(state.tenants.clone())).await?;
        if !allowed.is_some_and(|s| s.contains(&host_id)) {
            return Err(group_error(GroupError::UnknownHost));
        }
    }
    let store = state.groups.clone();
    run(move || store.add_member(&scope, group_id, host_id)).await?;
    audit(&state, &ctx, "group_member_add", format!("group:{group_id}/host:{host_id}"));
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
    Path((group_id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    run(move || store.remove_member(&scope, group_id, host_id)).await?;
    audit(&state, &ctx, "group_member_remove", format!("group:{group_id}/host:{host_id}"));
    Ok(StatusCode::NO_CONTENT)
}
```

In `lib.rs`, next to `pub mod fleet;`: `pub mod groups;` and `pub use groups::{build_groups_router, GroupsState};`. If `osiris-health` is not in `osiris-api`'s `[dev-dependencies]`/`[dependencies]` already, it is (9d-1 added it) — use it for the tests.

Run: `cargo test -p osiris-api --lib groups` → PASS.

- [ ] **Step 6: Wire `main.rs`**

Replace the `fleet_registry` construction (around `main.rs:142`) with one shared instance:

```rust
    let fleet_db = Arc::new(open_or_exit(
        osiris_fleet::SqliteHostRegistry::open(&hosts_db_path),
        &hosts_db_path,
        "hosts_db_path",
    ));
    let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> = fleet_db.clone();
    let group_store: Arc<dyn osiris_fleet::HostGroupStore> = fleet_db;
```

and in the router chain directly after `.merge(osiris_api::build_fleet_router(...))` (before `.layer(... auth_gate)`):

```rust
            .merge(osiris_api::build_groups_router(osiris_api::GroupsState {
                groups: group_store.clone(),
                registry: fleet_registry.clone(),
                tenants: <the same tenant store expression passed to FleetState>,
                audit_log: audit_log.clone(),
            }))
```

(Read `main.rs:410-425` and reuse exactly the `tenants:` expression the `FleetState` literal uses.)

- [ ] **Step 7: Composed-router tests**

**`composed_router_tenancy.rs` harness changes:**

- Import `build_groups_router, GroupsState` from `osiris_api`.
- Replace the `fleet_registry` construction in `tenancy()` with one shared instance:

```rust
    let fleet_db = Arc::new(osiris_fleet::SqliteHostRegistry::open(p("hosts.db")).unwrap());
    let fleet_registry: Arc<dyn osiris_fleet::HostRegistry> = fleet_db.clone();
```

  (the existing three `upsert_heartbeat` calls stay as they are).
- After `fleet_state` is built:

```rust
    let groups_state = GroupsState {
        groups: fleet_db.clone(),
        registry: fleet_db.clone(),
        tenants: tenants.clone(),
        audit_log: audit_log.clone(),
    };
```

- `build_app` gains a last parameter `groups_state: GroupsState`, and its chain gains `.merge(build_groups_router(groups_state))` right after `.merge(build_fleet_router(fleet_state))` and before `.layer(...)`. Pass `groups_state` at the one `build_app(...)` call site.

New tests at the end of `composed_router_tenancy.rs` (error bodies are plain text, so `call` returns `Value::Null` for them — assert statuses here; the handler unit tests pin the bodies):

```rust
#[tokio::test]
async fn tenant_groups_are_isolated_through_the_real_gate() {
    let t = tenancy();
    let (status, group) = call(
        &t.app,
        "POST",
        "/api/v1/groups",
        Some(&t.acme_token),
        Some(serde_json::json!({ "name": "acme-web" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let gid = group["group_id"].as_str().unwrap().to_string();
    assert_eq!(group["tenant_id"], t.acme_tenant.to_string());

    let own = format!("/api/v1/groups/{gid}/members/{}", t.acme_host);
    let (status, _) = call(&t.app, "PUT", &own, Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let foreign = format!("/api/v1/groups/{gid}/members/{}", t.globex_host);
    let (status, _) = call(&t.app, "PUT", &foreign, Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let detail_uri = format!("/api/v1/groups/{gid}");
    let (status, detail) = call(&t.app, "GET", &detail_uri, Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["members"][0]["host_id"], t.acme_host.to_string());
    assert_eq!(detail["member_count"], 1);

    let (status, _) = call(&t.app, "GET", &detail_uri, Some(&t.globex_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&t.app, "DELETE", &detail_uri, Some(&t.globex_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, list) = call(&t.app, "GET", "/api/v1/groups", Some(&t.globex_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().unwrap().is_empty());

    let (status, list) = call(&t.app, "GET", "/api/v1/groups", Some(&t.admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().unwrap().iter().any(|g| g["name"] == "acme-web"));

    // A malformed id passes the gate's shape check and is rejected by the
    // handler's `Path<Uuid>` extractor.
    let (status, _) =
        call(&t.app, "GET", "/api/v1/groups/not-a-uuid", Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenant_group_route_shapes_outside_the_allowlist_are_403() {
    let t = tenancy();
    let (g, h) = (Uuid::new_v4(), t.acme_host);
    for (method, uri) in [
        ("PUT", format!("/api/v1/groups/{g}/members/{h}/extra")),
        ("GET", format!("/api/v1/groups/{g}/other")),
        ("PUT", format!("/api/v1/groups/{g}")),
        ("PUT", format!("/api/v1/tenants/{}/hosts/{h}", t.acme_tenant)),
    ] {
        let (status, _) = call(&t.app, method, &uri, Some(&t.acme_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
}

#[tokio::test]
async fn a_tenant_user_passing_tenant_id_on_create_gets_400() {
    let t = tenancy();
    let (status, _) = call(
        &t.app,
        "POST",
        "/api/v1/groups",
        Some(&t.acme_token),
        Some(serde_json::json!({ "name": "x", "tenant_id": t.acme_tenant })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
```

**`composed_router_auth.rs` harness changes:** import `build_groups_router, GroupsState`; in `harness()` open the fleet db once (`let fleet_db = Arc::new(osiris_fleet::SqliteHostRegistry::open(p("hosts.db")).unwrap());`), use `fleet_db.clone()` for `FleetState.registry`, and add `.merge(build_groups_router(GroupsState { groups: fleet_db.clone(), registry: fleet_db, tenants: auth_state.tenants.clone(), audit_log: audit_log.clone() }))` right after `.merge(build_fleet_router(fleet_state))`. Update the composition comment to list `build_groups_router`. New test:

```rust
#[tokio::test]
async fn groups_reads_need_viewer_and_writes_need_admin_on_the_composed_router() {
    let h = harness();
    let viewer = session_for_role(&h.auth_state, "composed-viewer", Role::Viewer);
    let send = |method: &str, token: &str, body: Option<&str>| {
        let mut b = Request::builder()
            .method(method)
            .uri("/api/v1/groups")
            .header("Authorization", format!("Bearer {token}"));
        let body = match body {
            Some(json) => {
                b = b.header("content-type", "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        h.app.clone().oneshot(b.body(body).unwrap())
    };
    assert_eq!(send("GET", &viewer, None).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        send("POST", &viewer, Some(r#"{"name":"web"}"#)).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send("POST", &h.admin_token, Some(r#"{"name":"web"}"#)).await.unwrap().status(),
        StatusCode::CREATED
    );
}
```

- [ ] **Step 8: Gates and commit**

Run the Global Constraints gates. Commit:

```bash
git add crates/osiris-api crates/osiris-server
git commit -m "feat(api): host groups routes with tenant scoping, allowlist and audit (Phase 9d-2)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: `/api/v1/hosts` — `groups` field and `?group=` filter

**Files:**
- Modify: `crates/osiris-api/src/fleet.rs`
- Modify: every `FleetState { ... }` literal: `crates/osiris-server/src/main.rs`, `crates/osiris-api/tests/composed_router_auth.rs`, `crates/osiris-api/tests/composed_router_tenancy.rs`, `crates/osiris-e2e-tests/tests/end_to_end.rs` (find all with `grep -rn "FleetState {" crates`)

**Interfaces:**
- Consumes: Task 1 `HostGroupStore::{members, groups_of}`, `GroupRef`, `GroupError::NotFound`; Task 2's shared `Arc<SqliteHostRegistry>` pattern in `main.rs` (`group_store`).
- Produces: `FleetState { registry, tenants, groups: Arc<dyn HostGroupStore> }`; `HostSummary.groups: Vec<GroupRef>` (JSON `[{group_id, name}]`, sorted by name); `GET /api/v1/hosts?group=<uuid>`.

- [ ] **Step 1: Failing tests in `fleet.rs`'s test module**

Update the `state()` helper so `registry` and `groups` share one `Arc<SqliteHostRegistry>`, and every existing `hosts_handler(Extension(..), State(..))` call gains a third argument `Query(HostsQuery::default())`. New tests:

```rust
    #[tokio::test]
    async fn each_host_lists_its_groups_sorted_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let h = Uuid::new_v4();
        s.registry.upsert_heartbeat(row(h, 1_000)).unwrap();
        let web = s.groups.create(&GroupScope::Platform, None, "web").unwrap();
        let db = s.groups.create(&GroupScope::Platform, None, "db").unwrap();
        s.groups.add_member(&GroupScope::Platform, web.group_id, h).unwrap();
        s.groups.add_member(&GroupScope::Platform, db.group_id, h).unwrap();
        let Json(rows) = hosts_handler(Extension(platform_ctx()), State(s), Query(HostsQuery::default())).await.unwrap();
        let names: Vec<&str> = rows[0].groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["db", "web"]);
    }

    #[tokio::test]
    async fn the_group_filter_returns_only_members() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let (inside, outside) = (Uuid::new_v4(), Uuid::new_v4());
        s.registry.upsert_heartbeat(row(inside, 1_000)).unwrap();
        s.registry.upsert_heartbeat(row(outside, 1_000)).unwrap();
        let g = s.groups.create(&GroupScope::Platform, None, "g").unwrap();
        s.groups.add_member(&GroupScope::Platform, g.group_id, inside).unwrap();
        let Json(rows) = hosts_handler(Extension(platform_ctx()), State(s), Query(HostsQuery { group: Some(g.group_id) })).await.unwrap();
        let ids: Vec<String> = rows.iter().map(|r| r.host_id.clone()).collect();
        assert_eq!(ids, vec![inside.to_string()]);
    }

    #[tokio::test]
    async fn filtering_by_an_out_of_scope_or_missing_group_is_404() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let t = s.tenants.create_tenant("acme").unwrap().tenant_id;
        let platform_group = s.groups.create(&GroupScope::Platform, None, "p").unwrap();
        for gid in [platform_group.group_id, Uuid::new_v4()] {
            let err = hosts_handler(Extension(tenant_ctx(t)), State(s.clone()), Query(HostsQuery { group: Some(gid) })).await.unwrap_err();
            assert_eq!(err, (StatusCode::NOT_FOUND, "group not found".to_string()));
        }
    }

    #[tokio::test]
    async fn a_tenant_sees_only_its_own_groups_on_its_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let t = s.tenants.create_tenant("acme").unwrap().tenant_id;
        let h = Uuid::new_v4();
        s.registry.upsert_heartbeat(row(h, 1_000)).unwrap();
        s.tenants.assign_host(h, t).unwrap();
        let platform_group = s.groups.create(&GroupScope::Platform, None, "platform-g").unwrap();
        let tenant_group = s.groups.create(&GroupScope::Tenant(t), None, "acme-g").unwrap();
        s.groups.add_member(&GroupScope::Platform, platform_group.group_id, h).unwrap();
        s.groups.add_member(&GroupScope::Platform, tenant_group.group_id, h).unwrap();
        let Json(rows) = hosts_handler(Extension(tenant_ctx(t)), State(s), Query(HostsQuery::default())).await.unwrap();
        let names: Vec<&str> = rows[0].groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["acme-g"]);
    }
```

`FleetState` must derive/keep `Clone` (it already does). Run `cargo test -p osiris-api --lib fleet` → FAIL.

- [ ] **Step 2: Implement**

```rust
use axum::extract::Query;
use osiris_fleet::{GroupError, GroupRef, GroupScope, HostGroupStore};
use serde::Deserialize;

#[derive(Clone)]
pub struct FleetState {
    pub registry: Arc<dyn HostRegistry>,
    pub tenants: Arc<dyn TenantStore>,
    pub groups: Arc<dyn HostGroupStore>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct HostsQuery {
    pub group: Option<Uuid>,
}
```

`HostSummary` gains `groups: Vec<GroupRef>` (last field); `to_summary` initializes it to `Vec::new()`. `hosts_handler` gains `Query(query): Query<HostsQuery>` as its last extractor and, after the tenant `retain`:

```rust
    let scope = match ctx.tenant_id {
        Some(t) => GroupScope::Tenant(t),
        None => GroupScope::Platform,
    };
    if let Some(group_id) = query.group {
        let groups = state.groups.clone();
        let members: std::collections::HashSet<Uuid> =
            tokio::task::spawn_blocking(move || groups.members(&scope, group_id))
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map_err(|e| match e {
                    GroupError::NotFound => (StatusCode::NOT_FOUND, e.to_string()),
                    other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                })?
                .into_iter()
                .collect();
        rows.retain(|r| members.contains(&r.host_id));
    }
    let ids: Vec<Uuid> = rows.iter().map(|r| r.host_id).collect();
    let groups = state.groups.clone();
    let mut by_host = tokio::task::spawn_blocking(move || groups.groups_of(&scope, &ids))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
```

and build the summaries as:

```rust
    let now = now_ns();
    let mut summaries: Vec<HostSummary> = rows
        .into_iter()
        .map(|r| {
            let groups = by_host.remove(&r.host_id).unwrap_or_default();
            let mut summary = to_summary(r, now);
            summary.groups = groups;
            summary
        })
        .collect();
```

(the existing sort stays). A malformed `?group=` is rejected by axum's `Query` extractor with 400 before the handler runs.

Update every `FleetState { ... }` literal listed under **Files** with `groups:` set to the same `Arc<SqliteHostRegistry>` used for `registry` (in `main.rs`: `group_store.clone()`).

Run `cargo test -p osiris-api --lib fleet` → PASS.

- [ ] **Step 3: Composed-router test**

In `composed_router_tenancy.rs` (after also adding `groups: fleet_db.clone()` to the harness's `FleetState` literal, and the same in `composed_router_auth.rs`):

```rust
#[tokio::test]
async fn hosts_group_filter_is_tenant_scoped_through_the_gate() {
    let t = tenancy();
    let (_, group) = call(
        &t.app,
        "POST",
        "/api/v1/groups",
        Some(&t.acme_token),
        Some(serde_json::json!({ "name": "acme-web" })),
    )
    .await;
    let gid = group["group_id"].as_str().unwrap().to_string();
    let member = format!("/api/v1/groups/{gid}/members/{}", t.acme_host);
    call(&t.app, "PUT", &member, Some(&t.acme_token), None).await;

    let uri = format!("/api/v1/hosts?group={gid}");
    let (status, hosts) = call(&t.app, "GET", &uri, Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let rows = hosts.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["host_id"], t.acme_host.to_string());
    assert_eq!(rows[0]["groups"][0]["name"], "acme-web");

    let (status, _) = call(&t.app, "GET", &uri, Some(&t.globex_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) =
        call(&t.app, "GET", "/api/v1/hosts?group=not-a-uuid", Some(&t.acme_token), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
```

- [ ] **Step 4: Gates and commit**

```bash
git add crates
git commit -m "feat(api): hosts carry their groups and accept ?group= (Phase 9d-2)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: CLI `groups` subcommands

**Files:**
- Modify: `crates/osiris-cli/src/main.rs`

**Interfaces:**
- Consumes: Task 2 routes; existing helpers `get`, `post_json`, `put_empty`, `delete_empty`, `percent_encode`; `Cli` (`#[derive(Parser)]`, `main.rs:9-14`).
- Produces: `osiris-cli groups {list|create <name> [--tenant <id>]|show <group_id>|rename <group_id> <name>|delete <group_id>|add-host <group_id> <host_id>|remove-host <group_id> <host_id>}`.

- [ ] **Step 1: Failing parse tests** — add at the end of `main.rs`:

```rust
#[cfg(test)]
mod groups_cli_tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("osiris-cli").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn every_groups_subcommand_parses() {
        assert!(matches!(parse(&["groups", "list"]).command, Command::Groups { action: GroupsAction::List }));
        match parse(&["groups", "create", "web", "--tenant", "t1"]).command {
            Command::Groups { action: GroupsAction::Create { name, tenant } } => {
                assert_eq!(name, "web");
                assert_eq!(tenant.as_deref(), Some("t1"));
            }
            _ => panic!("wrong variant"),
        }
        assert!(matches!(parse(&["groups", "show", "g"]).command, Command::Groups { action: GroupsAction::Show { .. } }));
        assert!(matches!(parse(&["groups", "rename", "g", "n"]).command, Command::Groups { action: GroupsAction::Rename { .. } }));
        assert!(matches!(parse(&["groups", "delete", "g"]).command, Command::Groups { action: GroupsAction::Delete { .. } }));
        assert!(matches!(parse(&["groups", "add-host", "g", "h"]).command, Command::Groups { action: GroupsAction::AddHost { .. } }));
        assert!(matches!(parse(&["groups", "remove-host", "g", "h"]).command, Command::Groups { action: GroupsAction::RemoveHost { .. } }));
    }
}
```

(Check the actual field name holding the subcommand on `Cli` — adjust `.command` if it differs.) Run `cargo test -p osiris-cli groups_cli_tests` → FAIL.

- [ ] **Step 2: Implement**

Command variant next to `Tenants`:

```rust
    /// Host groups (Phase 9d-2). Reads need a Viewer session, changes an Admin.
    Groups {
        #[command(subcommand)]
        action: GroupsAction,
    },
```

```rust
#[derive(Subcommand)]
enum GroupsAction {
    /// List groups visible to this session.
    List,
    /// Create a group; platform Admins may bind it to a tenant.
    Create {
        name: String,
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Show a group and its members.
    Show { group_id: String },
    /// Rename a group.
    Rename { group_id: String, name: String },
    /// Delete a group (its memberships go with it; hosts are untouched).
    Delete { group_id: String },
    /// Add a registered host to a group.
    AddHost { group_id: String, host_id: String },
    /// Remove a host from a group.
    RemoveHost { group_id: String, host_id: String },
}
```

Refactor `post_json` into a shared `send_json(request: RequestBuilder, body, attach_token)` (the body of today's `post_json` from `.json(&body)` on) and make `post_json` call `send_json(client.post(url).json(&body), attach_token)`; add `patch_json` calling `send_json(client.patch(url).json(&body), attach_token)`. Dispatch arm:

```rust
        Command::Groups { action } => {
            let base = cli.server.trim_end_matches('/').to_string();
            let group_url = |id: &str| format!("{base}/api/v1/groups/{}", percent_encode(id));
            match action {
                GroupsAction::List => get(&client, format!("{base}/api/v1/groups"), true),
                GroupsAction::Create { name, tenant } => {
                    let mut body = serde_json::json!({ "name": name });
                    if let Some(t) = tenant {
                        body["tenant_id"] = serde_json::Value::String(t.clone());
                    }
                    post_json(&client, format!("{base}/api/v1/groups"), body, true)
                }
                GroupsAction::Show { group_id } => get(&client, group_url(group_id), true),
                GroupsAction::Rename { group_id, name } => patch_json(
                    &client,
                    group_url(group_id),
                    serde_json::json!({ "name": name }),
                    true,
                ),
                GroupsAction::Delete { group_id } => delete_empty(&client, group_url(group_id), true),
                GroupsAction::AddHost { group_id, host_id } => put_empty(
                    &client,
                    format!("{}/members/{}", group_url(group_id), percent_encode(host_id)),
                    true,
                ),
                GroupsAction::RemoveHost { group_id, host_id } => delete_empty(
                    &client,
                    format!("{}/members/{}", group_url(group_id), percent_encode(host_id)),
                    true,
                ),
            }
        }
```

Match whatever borrow form (`&cli.command` vs by value) the existing `Command::Tenants` arm uses. Run the tests → PASS.

- [ ] **Step 3: Gates and commit**

```bash
git add crates/osiris-cli
git commit -m "feat(cli): groups subcommands (Phase 9d-2)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Console — Groups screens, Hosts column and filter

**Files:**
- Modify: `console/src/api/types.ts`, `console/src/api/client.ts`, `console/src/api/hooks.ts`
- Modify: `console/src/App.tsx`, `console/src/app/navItems.ts`
- Modify: `console/src/screens/hosts/HostList.tsx`, `console/src/screens/hosts/HostList.test.tsx`
- Create: `console/src/screens/groups/GroupList.tsx`, `GroupList.test.tsx`, `GroupDetail.tsx`, `GroupDetail.test.tsx`, `groupErrors.ts`
- Test: `console/src/api/client.test.ts` (new cases)

**Interfaces:**
- Consumes: Task 2/3 JSON shapes (Global Constraints + Task 2 **Produces**); `useAuthStore` (`role: Role | null`, `tenantId: string | null`); `ApiError(status, message)`.
- Produces: TS types `GroupRef`, `HostGroup`, `GroupMember`, `GroupDetail`; `HostSummary.groups: GroupRef[]`; client fns `fetchGroups`, `fetchGroup`, `createGroup`, `renameGroup`, `deleteGroup`, `addGroupMember`, `removeGroupMember`, `fetchHosts(group?)`; hooks `useGroups`, `useGroup`, `useCreateGroup`, `useRenameGroup`, `useDeleteGroup`, `useAddGroupMember`, `useRemoveGroupMember`, `useHosts(group?)`.

- [ ] **Step 1: Types**

```ts
export interface GroupRef {
  group_id: string;
  name: string;
}

export interface HostGroup {
  group_id: string;
  name: string;
  tenant_id: string | null;
  created_at: number;
  member_count: number;
}

export interface GroupMember {
  host_id: string;
  hostname: string;
  status: "ONLINE" | "STALE";
  agent_version: string;
  last_seen: number;
}

export interface GroupDetail extends HostGroup {
  members: GroupMember[];
}
```

`HostSummary` gains `groups: GroupRef[];`. Fix existing test fixtures that build `HostSummary` objects if TypeScript complains (add `groups: []`).

- [ ] **Step 2: Failing client tests** — add the new functions to `client.test.ts`'s import list and append inside its `describe("api client", ...)` (the file stubs `fetch` in `beforeEach`; no token is set, so non-GET calls without a body use the bare `{ method }` shape):

```ts
  it("fetchHosts with a group adds an encoded group query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
    await fetchHosts("g 1");
    expect(fetch).toHaveBeenCalledWith("/api/v1/hosts?group=g%201");
  });

  it("createGroup POSTs the name as JSON", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ group_id: "g", name: "web" }), { status: 201 })
    );
    await createGroup({ name: "web" });
    expect(fetch).toHaveBeenCalledWith("/api/v1/groups", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "web" }),
    });
  });

  it("deleteGroup issues DELETE and resolves to undefined on 204", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 204 }));
    await expect(deleteGroup("g")).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledWith("/api/v1/groups/g", { method: "DELETE" });
  });

  it("addGroupMember and removeGroupMember hit the member route", async () => {
    vi.mocked(fetch).mockImplementation(async () => new Response(null, { status: 204 }));
    await addGroupMember("g", "h");
    expect(fetch).toHaveBeenCalledWith("/api/v1/groups/g/members/h", { method: "PUT" });
    await removeGroupMember("g", "h");
    expect(fetch).toHaveBeenCalledWith("/api/v1/groups/g/members/h", { method: "DELETE" });
  });

  it("a 409 rejects with an ApiError carrying the status", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("a group with this name already exists", { status: 409 })
    );
    await expect(createGroup({ name: "web" })).rejects.toMatchObject({ status: 409 });
    await expect(createGroup({ name: "web" })).rejects.toBeInstanceOf(ApiError);
  });
```

(`mockResolvedValue` reuses one `Response` whose body can only be read once — the 409 test calls `createGroup` twice, so use `mockImplementation(async () => new Response(...))` there too if the second read fails.) Run `npx vitest run src/api/client.test.ts` → FAIL.

- [ ] **Step 3: Client implementation**

In `request<T>`, right after the `if (!response.ok) { ... }` block and before `return (await response.json()) as T;`:

```ts
  if (response.status === 204) {
    return undefined as T;
  }
```

Add:

```ts
function apiPut<T>(path: string): Promise<T> {
  return request<T>("PUT", path);
}

function apiDelete<T>(path: string): Promise<T> {
  return request<T>("DELETE", path);
}

export function fetchHosts(group?: string): Promise<HostSummary[]> {
  return apiGet<HostSummary[]>(group ? `/hosts?group=${encodeURIComponent(group)}` : "/hosts");
}

export function fetchGroups(): Promise<HostGroup[]> {
  return apiGet<HostGroup[]>("/groups");
}

export function fetchGroup(groupId: string): Promise<GroupDetail> {
  return apiGet<GroupDetail>(`/groups/${encodeURIComponent(groupId)}`);
}

export function createGroup(body: { name: string }): Promise<HostGroup> {
  return apiPost<HostGroup>("/groups", body);
}

export function renameGroup(groupId: string, name: string): Promise<HostGroup> {
  return apiPatch<HostGroup>(`/groups/${encodeURIComponent(groupId)}`, { name });
}

export function deleteGroup(groupId: string): Promise<void> {
  return apiDelete<void>(`/groups/${encodeURIComponent(groupId)}`);
}

export function addGroupMember(groupId: string, hostId: string): Promise<void> {
  return apiPut<void>(
    `/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(hostId)}`
  );
}

export function removeGroupMember(groupId: string, hostId: string): Promise<void> {
  return apiDelete<void>(
    `/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(hostId)}`
  );
}
```

(Replace the existing `fetchHosts` rather than adding a second one.) Run client tests → PASS.

- [ ] **Step 4: Hooks** (`hooks.ts`)

```ts
export function useHosts(group?: string) {
  return useQuery({
    queryKey: ["hosts", group ?? "all"],
    queryFn: () => fetchHosts(group),
  });
}

export function useGroups() {
  return useQuery({ queryKey: ["groups"], queryFn: fetchGroups });
}

export function useGroup(groupId: string) {
  return useQuery({
    queryKey: ["group", groupId],
    queryFn: () => fetchGroup(groupId),
    enabled: groupId.length > 0,
  });
}

function useInvalidateGroups() {
  const queryClient = useQueryClient();
  return (groupId?: string) => {
    queryClient.invalidateQueries({ queryKey: ["groups"] });
    queryClient.invalidateQueries({ queryKey: ["hosts"] });
    if (groupId) queryClient.invalidateQueries({ queryKey: ["group", groupId] });
  };
}

export function useCreateGroup() {
  const invalidate = useInvalidateGroups();
  return useMutation({
    mutationFn: (name: string) => createGroup({ name }),
    onSuccess: () => invalidate(),
  });
}

export function useRenameGroup(groupId: string) {
  const invalidate = useInvalidateGroups();
  return useMutation({
    mutationFn: (name: string) => renameGroup(groupId, name),
    onSuccess: () => invalidate(groupId),
  });
}

export function useDeleteGroup(groupId: string) {
  const invalidate = useInvalidateGroups();
  return useMutation({
    mutationFn: () => deleteGroup(groupId),
    onSuccess: () => invalidate(groupId),
  });
}

export function useAddGroupMember(groupId: string) {
  const invalidate = useInvalidateGroups();
  return useMutation({
    mutationFn: (hostId: string) => addGroupMember(groupId, hostId),
    onSuccess: () => invalidate(groupId),
  });
}

export function useRemoveGroupMember(groupId: string) {
  const invalidate = useInvalidateGroups();
  return useMutation({
    mutationFn: (hostId: string) => removeGroupMember(groupId, hostId),
    onSuccess: () => invalidate(groupId),
  });
}
```

Add the new client functions to the import list.

- [ ] **Step 5: `groupErrors.ts`**

```ts
import { ApiError } from "../../api/client";

export function groupErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 409) return "A group with this name already exists.";
    if (error.status === 422) return "Unknown host.";
    if (error.status === 404) return "Group not found.";
    if (error.status === 403) return "You do not have permission to change groups.";
    if (error.status === 400) return error.message;
  }
  return error instanceof Error ? error.message : "Request failed.";
}
```

- [ ] **Step 6: Failing screen tests**

`console/src/screens/groups/GroupList.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { GroupList } from "./GroupList";

vi.mock("../../api/hooks");

function query(overrides: Record<string, unknown>) {
  return { data: undefined, isLoading: false, isError: false, error: null, ...overrides } as never;
}

function mutation(overrides: Record<string, unknown> = {}) {
  return { mutate: vi.fn(), isPending: false, isError: false, error: null, ...overrides };
}

const group = { group_id: "g1", name: "web", tenant_id: null, created_at: 1_000_000, member_count: 2 };

function renderList() {
  return render(
    <MemoryRouter>
      <GroupList />
    </MemoryRouter>
  );
}

describe("GroupList", () => {
  beforeEach(() => {
    useAuthStore.setState({ role: "ADMIN", tenantId: null });
    vi.mocked(hooks.useCreateGroup).mockReturnValue(mutation() as never);
  });

  it("shows a loading state", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ isLoading: true }));
    renderList();
    expect(screen.getByText("Loading groups…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ isError: true, error: new Error("boom") }));
    renderList();
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    expect(screen.getByText("No groups yet.")).toBeInTheDocument();
  });

  it("links each group to its detail and shows a Tenant column to platform users", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [group] }));
    renderList();
    expect(screen.getByRole("link", { name: "web" })).toHaveAttribute("href", "/groups/g1");
    expect(screen.getByRole("columnheader", { name: "Tenant" })).toBeInTheDocument();
    expect(screen.getByText("platform")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("hides the Tenant column from tenant users", () => {
    useAuthStore.setState({ role: "ADMIN", tenantId: "t1" });
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [group] }));
    renderList();
    expect(screen.queryByRole("columnheader", { name: "Tenant" })).not.toBeInTheDocument();
  });

  it("lets an Admin create a group", () => {
    const create = mutation();
    vi.mocked(hooks.useCreateGroup).mockReturnValue(create as never);
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    fireEvent.click(screen.getByRole("button", { name: "New group" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "db" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(create.mutate).toHaveBeenCalledWith("db", expect.anything());
  });

  it("shows the duplicate-name message on a 409", () => {
    vi.mocked(hooks.useCreateGroup).mockReturnValue(
      mutation({ isError: true, error: new ApiError(409, "x") }) as never
    );
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    fireEvent.click(screen.getByRole("button", { name: "New group" }));
    expect(screen.getByRole("alert")).toHaveTextContent("A group with this name already exists.");
  });

  it("hides New group from non-Admins", () => {
    useAuthStore.setState({ role: "VIEWER", tenantId: null });
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    expect(screen.queryByRole("button", { name: "New group" })).not.toBeInTheDocument();
  });
});
```

`console/src/screens/groups/GroupDetail.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { GroupDetail } from "./GroupDetail";

vi.mock("../../api/hooks");

function query(overrides: Record<string, unknown>) {
  return { data: undefined, isLoading: false, isError: false, error: null, ...overrides } as never;
}

function mutation() {
  return { mutate: vi.fn(), isPending: false, isError: false, error: null };
}

const detail = {
  group_id: "g1",
  name: "web",
  tenant_id: null,
  created_at: 1,
  member_count: 1,
  members: [
    { host_id: "h1", hostname: "web-1", status: "ONLINE", agent_version: "0.1.0", last_seen: 1_000_000 },
  ],
};

const host = (host_id: string, hostname: string) => ({
  host_id,
  hostname,
  distro: "d",
  kernel_version: "k",
  agent_version: "0.1.0",
  enrolled_at: 1,
  last_seen: 1,
  status: "ONLINE",
  cloud_provider: null,
  cloud_instance_id: null,
  cloud_region: null,
  groups: [],
});

function setup(role: "ADMIN" | "VIEWER" = "ADMIN", groupResult = query({ data: detail })) {
  useAuthStore.setState({ role, tenantId: null });
  const m = { rename: mutation(), del: mutation(), add: mutation(), remove: mutation() };
  vi.mocked(hooks.useGroup).mockReturnValue(groupResult);
  vi.mocked(hooks.useHosts).mockReturnValue(query({ data: [host("h1", "web-1"), host("h2", "db-1")] }));
  vi.mocked(hooks.useRenameGroup).mockReturnValue(m.rename as never);
  vi.mocked(hooks.useDeleteGroup).mockReturnValue(m.del as never);
  vi.mocked(hooks.useAddGroupMember).mockReturnValue(m.add as never);
  vi.mocked(hooks.useRemoveGroupMember).mockReturnValue(m.remove as never);
  render(
    <MemoryRouter initialEntries={["/groups/g1"]}>
      <Routes>
        <Route path="/groups/:groupId" element={<GroupDetail />} />
      </Routes>
    </MemoryRouter>
  );
  return m;
}

describe("GroupDetail", () => {
  it("shows Group not found on a 404", () => {
    setup("ADMIN", query({ isError: true, error: new ApiError(404, "x") }));
    expect(screen.getByRole("alert")).toHaveTextContent("Group not found.");
  });

  it("lists members and lets an Admin remove one", () => {
    const m = setup();
    expect(screen.getByText("web-1")).toBeInTheDocument();
    expect(screen.getByText("ONLINE")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(m.remove.mutate).toHaveBeenCalledWith("h1");
  });

  it("offers only non-members in Add host", () => {
    const m = setup();
    expect(screen.getByRole("option", { name: "db-1" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "web-1" })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Add host"), { target: { value: "h2" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(m.add.mutate).toHaveBeenCalledWith("h2", expect.anything());
  });

  it("renames", () => {
    const m = setup();
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "frontend" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(m.rename.mutate).toHaveBeenCalledWith("frontend", expect.anything());
  });

  it("asks for confirmation before deleting", () => {
    const m = setup();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(m.del.mutate).not.toHaveBeenCalled();
    expect(screen.getByText("Delete group web?")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirm delete" }));
    expect(m.del.mutate).toHaveBeenCalled();
  });

  it("is read-only for non-Admins", () => {
    setup("VIEWER");
    for (const name of ["Rename", "Delete", "Remove", "Add"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
    expect(screen.queryByLabelText("Add host")).not.toBeInTheDocument();
  });
});
```

Run `npx vitest run src/screens/groups` → FAIL.

- [ ] **Step 7: Implement `GroupList.tsx`**

```tsx
import { useState } from "react";
import { Link } from "react-router-dom";
import { useCreateGroup, useGroups } from "../../api/hooks";
import { useAuthStore } from "../../store/authStore";
import { groupErrorMessage } from "./groupErrors";

export function GroupList() {
  const groups = useGroups();
  const create = useCreateGroup();
  const isAdmin = useAuthStore((s) => s.role) === "ADMIN";
  const isPlatform = useAuthStore((s) => s.tenantId) === null;
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const rows = groups.data ?? [];

  return (
    <div>
      <h1>Groups</h1>
      {isAdmin && !creating && (
        <button type="button" onClick={() => setCreating(true)}>
          New group
        </button>
      )}
      {isAdmin && creating && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate(name, {
              onSuccess: () => {
                setName("");
                setCreating(false);
              },
            });
          }}
        >
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <button type="submit" disabled={create.isPending}>
            Create
          </button>
          <button type="button" onClick={() => setCreating(false)}>
            Cancel
          </button>
          {create.isError && <p role="alert">{groupErrorMessage(create.error)}</p>}
        </form>
      )}
      {groups.isLoading && <p>Loading groups…</p>}
      {groups.isError && <p role="alert">Failed to load groups: {groupErrorMessage(groups.error)}</p>}
      {!groups.isLoading && !groups.isError && rows.length === 0 && <p>No groups yet.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              {isPlatform && <th>Tenant</th>}
              <th>Members</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => (
              <tr key={g.group_id}>
                <td>
                  <Link to={`/groups/${encodeURIComponent(g.group_id)}`}>{g.name}</Link>
                </td>
                {isPlatform && <td>{g.tenant_id ?? "platform"}</td>}
                <td>{g.member_count}</td>
                <td>{new Date(g.created_at / 1_000_000).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 8: Implement `GroupDetail.tsx`**

```tsx
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  useAddGroupMember,
  useDeleteGroup,
  useGroup,
  useHosts,
  useRemoveGroupMember,
  useRenameGroup,
} from "../../api/hooks";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { groupErrorMessage } from "./groupErrors";

export function GroupDetail() {
  const { groupId = "" } = useParams();
  const navigate = useNavigate();
  const group = useGroup(groupId);
  const hosts = useHosts();
  const rename = useRenameGroup(groupId);
  const del = useDeleteGroup(groupId);
  const add = useAddGroupMember(groupId);
  const remove = useRemoveGroupMember(groupId);
  const isAdmin = useAuthStore((s) => s.role) === "ADMIN";
  const [editing, setEditing] = useState(false);
  const [newName, setNewName] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [hostToAdd, setHostToAdd] = useState("");

  if (group.isLoading) return <p>Loading group…</p>;
  if (group.isError) {
    const notFound = group.error instanceof ApiError && group.error.status === 404;
    return <p role="alert">{notFound ? "Group not found." : groupErrorMessage(group.error)}</p>;
  }
  const g = group.data;
  if (!g) return null;
  const memberIds = new Set(g.members.map((m) => m.host_id));
  const candidates = (hosts.data ?? []).filter((h) => !memberIds.has(h.host_id));
  const mutationError = rename.error ?? del.error ?? add.error ?? remove.error;

  return (
    <div>
      {!editing && <h1>{g.name}</h1>}
      {isAdmin && !editing && (
        <button
          type="button"
          onClick={() => {
            setNewName(g.name);
            setEditing(true);
          }}
        >
          Rename
        </button>
      )}
      {editing && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            rename.mutate(newName, { onSuccess: () => setEditing(false) });
          }}
        >
          <label>
            Name
            <input value={newName} onChange={(e) => setNewName(e.target.value)} />
          </label>
          <button type="submit">Save</button>
          <button type="button" onClick={() => setEditing(false)}>
            Cancel
          </button>
        </form>
      )}
      {isAdmin && !confirmingDelete && (
        <button type="button" onClick={() => setConfirmingDelete(true)}>
          Delete
        </button>
      )}
      {isAdmin && confirmingDelete && (
        <div>
          <p>Delete group {g.name}?</p>
          <button type="button" onClick={() => del.mutate(undefined, { onSuccess: () => navigate("/groups") })}>
            Confirm delete
          </button>
          <button type="button" onClick={() => setConfirmingDelete(false)}>
            Cancel
          </button>
        </div>
      )}
      {mutationError && <p role="alert">{groupErrorMessage(mutationError)}</p>}

      <h2>Members ({g.member_count})</h2>
      {g.members.length === 0 && <p>No members.</p>}
      {g.members.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Status</th>
              <th>Agent version</th>
              <th>Last Seen</th>
              {isAdmin && <th />}
            </tr>
          </thead>
          <tbody>
            {g.members.map((m) => (
              <tr key={m.host_id}>
                <td>{m.hostname}</td>
                <td>{m.status}</td>
                <td>{m.agent_version}</td>
                <td>{new Date(m.last_seen / 1_000_000).toLocaleString()}</td>
                {isAdmin && (
                  <td>
                    <button type="button" onClick={() => remove.mutate(m.host_id)}>
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {isAdmin && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (hostToAdd) add.mutate(hostToAdd, { onSuccess: () => setHostToAdd("") });
          }}
        >
          <label>
            Add host
            <select value={hostToAdd} onChange={(e) => setHostToAdd(e.target.value)}>
              <option value="">Select a host…</option>
              {candidates.map((h) => (
                <option key={h.host_id} value={h.host_id}>
                  {h.hostname}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={!hostToAdd}>
            Add
          </button>
        </form>
      )}
    </div>
  );
}
```

Run `npx vitest run src/screens/groups` → PASS.

- [ ] **Step 9: Routes and nav**

`App.tsx`: import both screens and add after the `/hosts` route:

```tsx
                <Route path="/groups" element={<GroupList />} />
                <Route path="/groups/:groupId" element={<GroupDetail />} />
```

`navItems.ts`: after the Hosts entry add `{ label: "Groups", path: "/groups", enabled: true },`. If a nav test snapshots the item list, update it.

- [ ] **Step 10: Hosts screen — failing tests then implementation**

Add `groups: []` to every existing host fixture in `HostList.test.tsx`, then append:

```tsx
  it("shows each host's groups as links to the group", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "host-a", distro: "d", kernel_version: "k", agent_version: "0.1.0", enrolled_at: 1, last_seen: 1, status: "ONLINE", cloud_provider: null, cloud_instance_id: null, cloud_region: null, groups: [{ group_id: "g1", name: "web" }] },
        ],
      })
    );
    renderWithRouter();
    expect(screen.getByRole("columnheader", { name: "Groups" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web" })).toHaveAttribute("href", "/groups/g1");
  });

  it("passes ?group= to useHosts and shows a clearable banner", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "host-a", distro: "d", kernel_version: "k", agent_version: "0.1.0", enrolled_at: 1, last_seen: 1, status: "ONLINE", cloud_provider: null, cloud_instance_id: null, cloud_region: null, groups: [{ group_id: "g1", name: "web" }] },
        ],
      })
    );
    render(
      <MemoryRouter initialEntries={["/hosts?group=g1"]}>
        <HostList />
      </MemoryRouter>
    );
    expect(hooks.useHosts).toHaveBeenCalledWith("g1");
    expect(screen.getByText(/Filtered by group web/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Clear filter" })).toHaveAttribute("href", "/hosts");
  });

  it("calls useHosts without a group and shows no banner when unfiltered", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(hooks.useHosts).toHaveBeenCalledWith(undefined);
    expect(screen.queryByText(/Filtered by group/)).not.toBeInTheDocument();
  });
```

Run `npx vitest run src/screens/hosts` → FAIL. Then replace `HostList.tsx`'s component (keep the header comment and `formatCloud`, update the comment to mention groups):

```tsx
import { Link, useSearchParams } from "react-router-dom";
import { useHosts } from "../../api/hooks";
import type { HostSummary } from "../../api/types";

// (existing header comment + formatCloud unchanged)

export function HostList() {
  const [params] = useSearchParams();
  const groupFilter = params.get("group") ?? undefined;
  const hosts = useHosts(groupFilter);
  const rows = hosts.data ?? [];
  const filterName = groupFilter
    ? (rows.flatMap((r) => r.groups).find((g) => g.group_id === groupFilter)?.name ?? groupFilter)
    : undefined;

  return (
    <div>
      <h1>Hosts</h1>
      {groupFilter && (
        <p>
          Filtered by group {filterName} <Link to="/hosts">Clear filter</Link>
        </p>
      )}
      {hosts.isLoading && <p>Loading hosts…</p>}
      {hosts.isError && (
        <p role="alert">Failed to load hosts: {(hosts.error as Error).message}</p>
      )}
      {!hosts.isLoading && !hosts.isError && rows.length === 0 && <p>No hosts found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Distro</th>
              <th>Kernel</th>
              <th>Agent version</th>
              <th>Enrolled</th>
              <th>Last Seen</th>
              <th>Status</th>
              <th>Cloud</th>
              <th>Groups</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.host_id}>
                <td>
                  <Link to={`/timeline?host=${encodeURIComponent(row.host_id)}`}>{row.hostname}</Link>
                </td>
                <td>{row.distro}</td>
                <td>{row.kernel_version}</td>
                <td>{row.agent_version}</td>
                <td>{new Date(row.enrolled_at / 1_000_000).toLocaleString()}</td>
                <td>{new Date(row.last_seen / 1_000_000).toLocaleString()}</td>
                <td>{row.status}</td>
                <td>{formatCloud(row)}</td>
                <td>
                  {row.groups.map((g, i) => (
                    <span key={g.group_id}>
                      {i > 0 && ", "}
                      <Link to={`/groups/${encodeURIComponent(g.group_id)}`}>{g.name}</Link>
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

Run `npx vitest run src/screens/hosts` → PASS. (`formatCloud` keeps its `HostSummary` parameter type, so the type import stays.)

- [ ] **Step 11: Gates and commit**

In `console/`: `npx vitest run` and `npm run build` — all green. Then the Rust gates are unaffected but run `cargo fmt --all -- --check` for safety. Commit:

```bash
git add console
git commit -m "feat(console): Groups screens, Groups column and ?group= filter on Hosts (Phase 9d-2)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: End-to-end scenario

**Files:**
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs`

**Interfaces:**
- Consumes: the 9d-1 scenario `an_agent_health_event_makes_the_host_appear_online_in_the_fleet_registry` (`end_to_end.rs:2370`) — its real-Agent setup (`fleet.health_interval_secs = 1`), ingestion loop, `mint_admin_session()`, composed router order; Tasks 2–3 (`build_groups_router`, `GroupsState`, `FleetState.groups`).

- [ ] **Step 1: Write the scenario**

New test `a_host_added_to_a_group_is_returned_by_the_group_filter_and_leaves_it_when_removed`, built by copying the 9d-1 scenario's setup (same real Agent, same bounded 10s/100ms poll until the host is ONLINE in `GET /api/v1/hosts`), with the router additionally merging `build_groups_router(GroupsState { groups, registry, tenants, audit_log })` right after the fleet router, before `auth_gate` — `groups` and `registry` are the same `Arc<SqliteHostRegistry>`. Then, with the admin bearer token:
1. `POST /api/v1/groups {"name":"e2e"}` → 201; read `group_id`.
2. `PUT /api/v1/groups/<gid>/members/<host_id>` → 204.
3. `GET /api/v1/hosts?group=<gid>` → exactly one row, that host, `status == "ONLINE"`, `groups[0].name == "e2e"`.
4. `GET /api/v1/groups/<gid>` → `member_count == 1`, `members[0].host_id == host_id`.
5. `DELETE /api/v1/groups/<gid>/members/<host_id>` → 204; `GET /api/v1/hosts?group=<gid>` → empty array.
6. `agent.shutdown().await`.

If the setup duplicated from the 9d-1 scenario exceeds ~40 lines, extract the shared part (agent config + spawn + ingestion loop + router + server bind + poll-until-online) into one helper used by both scenarios rather than copying it.

- [ ] **Step 2: Run it**

Run: `cargo build -p osiris-cli -p osiris-server -p osiris-agent && cargo test -p osiris-e2e-tests --test end_to_end`
Expected: all scenarios PASS, including the new one.

- [ ] **Step 3: Gates and commit**

```bash
git add crates/osiris-e2e-tests
git commit -m "test(e2e): host group membership through /api/v1/hosts?group= (Phase 9d-2)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 4: Docs touch-up** (same commit is fine)

In `docs/ROADMAP-REMAINING.md` §9d, change the "Entregar (9d-2/9d-3)" bullet to record 9d-2 as delivered (host groups: API, CLI, Console, `?group=` filter) and leave 9d-3 (policy distribution to groups via 9c) as the remaining item.
