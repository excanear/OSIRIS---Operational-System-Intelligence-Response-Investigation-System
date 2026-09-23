use std::sync::Mutex;

use osiris_health::HealthState;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("io: {0}")]
    Io(String),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("serde: {0}")]
    Serde(String),
}

impl From<rusqlite::Error> for FleetError {
    fn from(e: rusqlite::Error) -> Self {
        FleetError::Sqlite(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostRow {
    pub host_id: Uuid,
    pub hostname: String,
    pub distro: String,
    pub kernel_version: String,
    pub agent_version: String,
    pub enrolled_at: u64,
    pub last_seen: u64,
    pub health_state: HealthState,
}

pub trait HostRegistry: Send + Sync {
    fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError>;
    fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError>;
    fn list(&self) -> Result<Vec<HostRow>, FleetError>;
}

pub struct SqliteHostRegistry {
    conn: Mutex<Connection>,
}

impl SqliteHostRegistry {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FleetError> {
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hosts (
                host_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                distro TEXT NOT NULL,
                kernel_version TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                enrolled_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                health_state TEXT NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn row_from(r: &rusqlite::Row) -> rusqlite::Result<HostRow> {
        let host_id: String = r.get(0)?;
        let health_json: String = r.get(7)?;
        Ok(HostRow {
            host_id: Uuid::parse_str(&host_id).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
            hostname: r.get(1)?,
            distro: r.get(2)?,
            kernel_version: r.get(3)?,
            agent_version: r.get(4)?,
            enrolled_at: r.get::<_, i64>(5)? as u64,
            last_seen: r.get::<_, i64>(6)? as u64,
            health_state: serde_json::from_str(&health_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        })
    }
}

impl HostRegistry for SqliteHostRegistry {
    fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let health_json = serde_json::to_string(&row.health_state)
            .map_err(|e| FleetError::Serde(e.to_string()))?;
        conn.execute(
            "INSERT INTO hosts (host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
             ON CONFLICT(host_id) DO UPDATE SET
                hostname = excluded.hostname,
                distro = excluded.distro,
                kernel_version = excluded.kernel_version,
                agent_version = excluded.agent_version,
                last_seen = MAX(hosts.last_seen, excluded.last_seen),
                health_state = excluded.health_state",
            params![
                row.host_id.to_string(),
                row.hostname,
                row.distro,
                row.kernel_version,
                row.agent_version,
                row.last_seen as i64,
                health_json,
            ],
        )?;
        Ok(())
    }

    fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        Ok(conn
            .query_row(
                "SELECT host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state
                 FROM hosts WHERE host_id = ?1",
                params![host_id.to_string()],
                Self::row_from,
            )
            .optional()?)
    }

    fn list(&self) -> Result<Vec<HostRow>, FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(
            "SELECT host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state FROM hosts",
        )?;
        let rows = stmt
            .query_map([], Self::row_from)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_health::HealthState;
    use uuid::Uuid;

    fn row(host_id: Uuid, last_seen: u64) -> HostRow {
        HostRow {
            host_id,
            hostname: "h1".into(),
            distro: "ubuntu-24.04".into(),
            kernel_version: "6.8.0".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: last_seen,
            last_seen,
            health_state: HealthState::Healthy,
        }
    }

    #[test]
    fn list_on_an_empty_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        assert_eq!(reg.list().unwrap(), vec![]);
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(row(host_id, 1_000)).unwrap();
        let got = reg.get(host_id).unwrap().unwrap();
        assert_eq!(got.host_id, host_id);
        assert_eq!(got.last_seen, 1_000);
        assert_eq!(got.enrolled_at, 1_000);
    }

    #[test]
    fn a_second_upsert_bumps_last_seen_but_never_enrolled_at() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(row(host_id, 1_000)).unwrap();
        let mut second = row(host_id, 5_000);
        second.enrolled_at = 5_000; // a buggy caller passing the wrong enrolled_at must still be ignored
        second.hostname = "h1-renamed".into();
        reg.upsert_heartbeat(second).unwrap();
        let got = reg.get(host_id).unwrap().unwrap();
        assert_eq!(got.last_seen, 5_000);
        assert_eq!(
            got.enrolled_at, 1_000,
            "enrolled_at must never move after the first upsert"
        );
        assert_eq!(
            got.hostname, "h1-renamed",
            "other fields do update on every heartbeat"
        );
    }

    #[test]
    fn an_out_of_order_older_heartbeat_never_regresses_last_seen() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(row(host_id, 5_000)).unwrap();
        reg.upsert_heartbeat(row(host_id, 1_000)).unwrap(); // arrives later, but is an OLDER event
        let got = reg.get(host_id).unwrap().unwrap();
        assert_eq!(
            got.last_seen, 5_000,
            "last_seen is the max timestamp ever seen, not the most recently upserted"
        );
    }

    #[test]
    fn list_returns_every_distinct_host() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        reg.upsert_heartbeat(row(a, 1_000)).unwrap();
        reg.upsert_heartbeat(row(b, 2_000)).unwrap();
        let mut ids: Vec<Uuid> = reg.list().unwrap().into_iter().map(|r| r.host_id).collect();
        ids.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn get_of_an_unknown_host_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        assert_eq!(reg.get(Uuid::new_v4()).unwrap(), None);
    }
}
