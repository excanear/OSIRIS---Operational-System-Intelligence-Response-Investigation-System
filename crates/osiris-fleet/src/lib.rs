use std::sync::Mutex;

use osiris_health::HealthState;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

mod groups;
pub use groups::{
    validate_group_name, GroupError, GroupRef, GroupScope, HostGroup, HostGroupStore,
    MAX_GROUP_NAME_CHARS,
};
mod policies;
pub use policies::{DeliveryResult, DeliveryRow, PolicyStore};

#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("io: {0}")]
    Io(String),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error(
        "hosts.db schema version {0} is newer than this build supports ({})",
        SCHEMA_VERSION
    )]
    UnsupportedSchema(i64),
}

/// `PRAGMA user_version` of `hosts.db`. 0 = a 9d-1-era file (hosts table only,
/// never stamped); 1 = hosts + host groups (Phase 9d-2); 2 = + group
/// policies, applied hash and delivery state (Phase 9d-3).
pub const SCHEMA_VERSION: i64 = 2;

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
    /// Nanoseconds since the Unix epoch (server-clamped: the ingest hook
    /// caps the agent-supplied timestamp at the server's own clock before it
    /// ever reaches the registry, so this can never be ahead of `now`).
    pub enrolled_at: u64,
    /// Nanoseconds since the Unix epoch (server-clamped, same as `enrolled_at`).
    pub last_seen: u64,
    pub health_state: HealthState,
    pub cloud_provider: Option<String>,
    pub cloud_instance_id: Option<String>,
    pub cloud_region: Option<String>,
    /// Lowercase hex of the policy the agent last reported applying.
    /// `None` = no policy (either none resolved, or the agent hasn't said).
    pub applied_policy_hash: Option<String>,
}

/// Converts an agent-supplied timestamp into the signed representation SQLite
/// stores it as. `u64` values above `i64::MAX` are clamped rather than cast
/// (a raw `as i64` wraps negative, which would silently corrupt
/// `last_seen`/`enrolled_at` ordering and the freshness gate below).
fn to_stored_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub trait HostRegistry: Send + Sync {
    fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError>;
    fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError>;
    fn list(&self) -> Result<Vec<HostRow>, FleetError>;
}

pub struct SqliteHostRegistry {
    conn: Mutex<Connection>,
}

pub(crate) const SCHEMA_V1: &str = "
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

const SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS group_policies (
    group_id TEXT PRIMARY KEY REFERENCES host_groups(group_id) ON DELETE CASCADE,
    policy_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_policy_delivery (
    host_id TEXT PRIMARY KEY REFERENCES hosts(host_id),
    desired_hash TEXT NOT NULL,
    last_sent_at INTEGER NOT NULL,
    last_result TEXT NOT NULL,
    last_error TEXT NULL
);
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
        conn.execute_batch(SCHEMA_V1)?;
        if version < 2 {
            // v1 -> v2 as one unit: a crash mid-way leaves user_version < 2
            // and the next open redoes it (every step is idempotent).
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(SCHEMA_V2)?;
            let has_column: i64 = tx.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('hosts') WHERE name = 'applied_policy_hash'",
                [],
                |r| r.get(0),
            )?;
            if has_column == 0 {
                tx.execute(
                    "ALTER TABLE hosts ADD COLUMN applied_policy_hash TEXT NULL",
                    [],
                )?;
            }
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            tx.commit()?;
        }
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
            cloud_provider: r.get(8)?,
            cloud_instance_id: r.get(9)?,
            cloud_region: r.get(10)?,
            applied_policy_hash: r.get(11)?,
        })
    }
}

impl HostRegistry for SqliteHostRegistry {
    fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let health_json = serde_json::to_string(&row.health_state)
            .map_err(|e| FleetError::Serde(e.to_string()))?;
        conn.execute(
            "INSERT INTO hosts (host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state, cloud_provider, cloud_instance_id, cloud_region, applied_policy_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(host_id) DO UPDATE SET
                hostname = excluded.hostname,
                distro = excluded.distro,
                kernel_version = excluded.kernel_version,
                agent_version = excluded.agent_version,
                last_seen = MAX(hosts.last_seen, excluded.last_seen),
                health_state = excluded.health_state,
                cloud_provider = excluded.cloud_provider,
                cloud_instance_id = excluded.cloud_instance_id,
                cloud_region = excluded.cloud_region,
                applied_policy_hash = excluded.applied_policy_hash
             WHERE excluded.last_seen >= hosts.last_seen",
            params![
                row.host_id.to_string(),
                row.hostname,
                row.distro,
                row.kernel_version,
                row.agent_version,
                to_stored_i64(row.last_seen),
                health_json,
                row.cloud_provider,
                row.cloud_instance_id,
                row.cloud_region,
                row.applied_policy_hash,
            ],
        )?;
        Ok(())
    }

    fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        Ok(conn
            .query_row(
                "SELECT host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state, cloud_provider, cloud_instance_id, cloud_region, applied_policy_hash
                 FROM hosts WHERE host_id = ?1",
                params![host_id.to_string()],
                Self::row_from,
            )
            .optional()?)
    }

    fn list(&self) -> Result<Vec<HostRow>, FleetError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(
            "SELECT host_id, hostname, distro, kernel_version, agent_version, enrolled_at, last_seen, health_state, cloud_provider, cloud_instance_id, cloud_region, applied_policy_hash FROM hosts",
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
            cloud_provider: None,
            cloud_instance_id: None,
            cloud_region: None,
            applied_policy_hash: None,
        }
    }

    #[test]
    fn list_on_an_empty_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        assert_eq!(HostRegistry::list(&reg).unwrap(), vec![]);
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        reg.upsert_heartbeat(row(host_id, 1_000)).unwrap();
        let got = HostRegistry::get(&reg, host_id).unwrap().unwrap();
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
        let got = HostRegistry::get(&reg, host_id).unwrap().unwrap();
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
        let got = HostRegistry::get(&reg, host_id).unwrap().unwrap();
        assert_eq!(
            got.last_seen, 5_000,
            "last_seen is the max timestamp ever seen, not the most recently upserted"
        );
    }

    #[test]
    fn an_out_of_order_older_heartbeat_never_overwrites_other_columns() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        let mut failed = row(host_id, 5_000);
        failed.health_state = HealthState::Failed {
            last_error: "x".into(),
        };
        reg.upsert_heartbeat(failed).unwrap();

        let mut stale_healthy = row(host_id, 1_000); // arrives later, but is an OLDER event
        stale_healthy.health_state = HealthState::Healthy;
        reg.upsert_heartbeat(stale_healthy).unwrap();

        let got = HostRegistry::get(&reg, host_id).unwrap().unwrap();
        assert_eq!(
            got.last_seen, 5_000,
            "last_seen must not regress on an out-of-order older heartbeat"
        );
        assert!(
            matches!(got.health_state, HealthState::Failed { .. }),
            "health_state must not be overwritten by a stale, out-of-order heartbeat: got {:?}",
            got.health_state
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
        let mut ids: Vec<Uuid> = HostRegistry::list(&reg)
            .unwrap()
            .into_iter()
            .map(|r| r.host_id)
            .collect();
        ids.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn get_of_an_unknown_host_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        assert_eq!(HostRegistry::get(&reg, Uuid::new_v4()).unwrap(), None);
    }

    #[test]
    fn cloud_fields_round_trip_and_update_like_other_mutable_columns() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        let mut first = row(host_id, 1_000);
        first.cloud_provider = Some("aws".into());
        first.cloud_instance_id = Some("i-0abc".into());
        first.cloud_region = Some("us-east-1".into());
        reg.upsert_heartbeat(first).unwrap();

        let got = HostRegistry::get(&reg, host_id).unwrap().unwrap();
        assert_eq!(got.cloud_provider.as_deref(), Some("aws"));
        assert_eq!(got.cloud_instance_id.as_deref(), Some("i-0abc"));
        assert_eq!(got.cloud_region.as_deref(), Some("us-east-1"));

        // A later, fresher heartbeat updates cloud fields exactly like the
        // other mutable columns (hostname etc.), under the same freshness gate.
        let mut second = row(host_id, 2_000);
        second.cloud_provider = Some("azure".into());
        second.cloud_instance_id = None;
        second.cloud_region = None;
        reg.upsert_heartbeat(second).unwrap();
        let got = HostRegistry::get(&reg, host_id).unwrap().unwrap();
        assert_eq!(got.cloud_provider.as_deref(), Some("azure"));
        assert_eq!(got.cloud_instance_id, None);
        assert_eq!(got.cloud_region, None);
    }

    #[test]
    fn a_timestamp_above_i64_max_does_not_produce_a_negative_stored_value() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap();
        let host_id = Uuid::new_v4();
        // Above i64::MAX: a raw `as i64` cast would wrap negative.
        let huge = u64::MAX;
        reg.upsert_heartbeat(row(host_id, huge)).unwrap();
        let got = HostRegistry::get(&reg, host_id).unwrap().unwrap();
        assert!(
            got.last_seen > 0,
            "last_seen must not wrap negative for a u64 above i64::MAX, got {}",
            got.last_seen
        );
        assert!(
            got.enrolled_at > 0,
            "enrolled_at must not wrap negative for a u64 above i64::MAX, got {}",
            got.enrolled_at
        );
    }
}
