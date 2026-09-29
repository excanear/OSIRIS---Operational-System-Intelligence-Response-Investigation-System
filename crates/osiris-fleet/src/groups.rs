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
    #[error("{0}")]
    InvalidPolicy(String),
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
    fn rename(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        name: &str,
    ) -> Result<HostGroup, GroupError>;
    fn delete(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError>;
    fn add_member(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        host_id: Uuid,
    ) -> Result<(), GroupError>;
    fn remove_member(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        host_id: Uuid,
    ) -> Result<(), GroupError>;
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

pub(crate) fn get_in_scope(
    conn: &Connection,
    scope: &GroupScope,
    group_id: Uuid,
) -> Result<HostGroup, GroupError> {
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
    fn create(
        &self,
        scope: &GroupScope,
        tenant_id: Option<Uuid>,
        name: &str,
    ) -> Result<HostGroup, GroupError> {
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

    fn rename(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        name: &str,
    ) -> Result<HostGroup, GroupError> {
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

    fn add_member(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        host_id: Uuid,
    ) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        conn.execute(
            "INSERT INTO host_group_members (group_id, host_id, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id, host_id) DO NOTHING",
            params![
                group_id.to_string(),
                host_id.to_string(),
                to_stored_i64(now_ns())
            ],
        )
        .map_err(map_write_err)?;
        Ok(())
    }

    fn remove_member(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        host_id: Uuid,
    ) -> Result<(), GroupError> {
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

    fn groups_of(
        &self,
        scope: &GroupScope,
        host_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<GroupRef>>, GroupError> {
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
                Ok((
                    parse_uuid(0, &host)?,
                    GroupRef {
                        group_id: parse_uuid(1, &gid)?,
                        name: r.get(2)?,
                    },
                ))
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
            applied_policy_hash: None,
        })
        .unwrap();
        host_id
    }

    const P: GroupScope = GroupScope::Platform;

    #[test]
    fn create_get_list_rename_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let g = HostGroupStore::create(&reg, &P, None, "  prod  ").unwrap();
        assert_eq!(g.name, "prod");
        assert_eq!(g.tenant_id, None);
        assert_eq!(g.member_count, 0);
        assert!(g.created_at > 0);
        assert_eq!(HostGroupStore::get(&reg, &P, g.group_id).unwrap(), g);
        assert_eq!(HostGroupStore::list(&reg, &P).unwrap(), vec![g.clone()]);
        let renamed = reg.rename(&P, g.group_id, "production").unwrap();
        assert_eq!(renamed.name, "production");
        reg.delete(&P, g.group_id).unwrap();
        assert_eq!(
            HostGroupStore::get(&reg, &P, g.group_id),
            Err(GroupError::NotFound)
        );
        assert_eq!(reg.delete(&P, g.group_id), Err(GroupError::NotFound));
    }

    #[test]
    fn list_is_sorted_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        reg.create(&P, None, "web").unwrap();
        reg.create(&P, None, "db").unwrap();
        let names: Vec<String> = HostGroupStore::list(&reg, &P)
            .unwrap()
            .into_iter()
            .map(|g| g.name)
            .collect();
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
        assert_eq!(
            reg.create(&P, None, "prod "),
            Err(GroupError::DuplicateName)
        );
        reg.create(&GroupScope::Tenant(t), None, "prod").unwrap();
        assert_eq!(
            reg.create(&GroupScope::Tenant(t), None, "prod"),
            Err(GroupError::DuplicateName)
        );
        // Same name in a different tenant is fine.
        reg.create(&GroupScope::Tenant(Uuid::new_v4()), None, "prod")
            .unwrap();
        let other = reg.create(&P, None, "staging").unwrap();
        assert_eq!(
            reg.rename(&P, other.group_id, "prod"),
            Err(GroupError::DuplicateName)
        );
    }

    #[test]
    fn name_validation() {
        assert!(matches!(
            validate_group_name(""),
            Err(GroupError::InvalidName(_))
        ));
        assert!(matches!(
            validate_group_name("   "),
            Err(GroupError::InvalidName(_))
        ));
        assert!(matches!(
            validate_group_name("a\u{7}b"),
            Err(GroupError::InvalidName(_))
        ));
        let max = "é".repeat(MAX_GROUP_NAME_CHARS);
        assert_eq!(validate_group_name(&max).unwrap(), max);
        let too_long = "é".repeat(MAX_GROUP_NAME_CHARS + 1);
        assert!(matches!(
            validate_group_name(&too_long),
            Err(GroupError::InvalidName(_))
        ));
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
            assert_eq!(
                HostGroupStore::get(&reg, &sa, gid),
                Err(GroupError::NotFound)
            );
            assert_eq!(reg.rename(&sa, gid, "x"), Err(GroupError::NotFound));
            assert_eq!(reg.add_member(&sa, gid, host), Err(GroupError::NotFound));
            assert_eq!(reg.remove_member(&sa, gid, host), Err(GroupError::NotFound));
            assert_eq!(reg.members(&sa, gid), Err(GroupError::NotFound));
            assert_eq!(reg.delete(&sa, gid), Err(GroupError::NotFound));
        }
        assert_eq!(HostGroupStore::list(&reg, &sa).unwrap(), vec![]);
        // Platform sees both, and nothing was modified by the tenant attempts.
        assert_eq!(HostGroupStore::list(&reg, &P).unwrap().len(), 2);
        assert_eq!(
            HostGroupStore::get(&reg, &P, b_group.group_id)
                .unwrap()
                .name,
            "b"
        );
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
        assert_eq!(
            HostGroupStore::get(&reg, &P, g.group_id)
                .unwrap()
                .member_count,
            1
        );
        reg.remove_member(&P, g.group_id, host).unwrap();
        reg.remove_member(&P, g.group_id, host).unwrap();
        assert_eq!(reg.members(&P, g.group_id).unwrap(), Vec::<Uuid>::new());
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
        let tg = reg
            .create(&GroupScope::Tenant(t), None, "tenant-g")
            .unwrap();
        for g in [&web, &db] {
            reg.add_member(&P, g.group_id, host).unwrap();
        }
        reg.add_member(&P, tg.group_id, host).unwrap();
        reg.add_member(&P, web.group_id, other_host).unwrap();

        let all = reg.groups_of(&P, &[host]).unwrap();
        let names: Vec<&str> = all[&host].iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["db", "tenant-g", "web"]);
        assert!(
            !all.contains_key(&other_host),
            "only the requested hosts are returned"
        );

        let scoped = reg.groups_of(&GroupScope::Tenant(t), &[host]).unwrap();
        assert_eq!(
            scoped[&host],
            vec![GroupRef {
                group_id: tg.group_id,
                name: "tenant-g".into()
            }]
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
        assert_eq!(HostRegistry::list(&reg).unwrap().len(), 1);
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
