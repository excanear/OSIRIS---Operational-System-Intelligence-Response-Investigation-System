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
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
            params![
                tenant.tenant_id.to_string(),
                tenant.name,
                tenant.created_at as i64
            ],
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
            .prepare(
                "SELECT tenant_id, name, created_at FROM tenants ORDER BY created_at ASC, name ASC",
            )
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
        conn.execute(
            "DELETE FROM host_tenants WHERE host_id = ?1",
            params![host_id.to_string()],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn hosts_of(&self, tenant_id: Uuid) -> Result<HashSet<Uuid>, TenantStoreError> {
        let conn = self.conn.lock().map_err(|_| backend("poisoned lock"))?;
        let mut stmt = conn
            .prepare("SELECT host_id FROM host_tenants WHERE tenant_id = ?1")
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![tenant_id.to_string()], |row| {
                row.get::<_, String>(0)
            })
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
        assert_eq!(
            all.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            vec!["acme", "globex"]
        );
        assert_eq!(s.get_tenant(a.tenant_id).unwrap().unwrap().name, "acme");
        assert_ne!(a.tenant_id, b.tenant_id);
    }

    #[test]
    fn duplicate_or_blank_names_are_rejected() {
        let (_d, s) = store();
        s.create_tenant("acme").unwrap();
        assert!(matches!(
            s.create_tenant("acme"),
            Err(TenantStoreError::DuplicateName(_))
        ));
        assert!(matches!(
            s.create_tenant("   "),
            Err(TenantStoreError::InvalidName(_))
        ));
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
