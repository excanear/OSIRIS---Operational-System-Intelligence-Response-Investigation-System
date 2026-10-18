//! Group policies and per-host delivery state (Phase 9d-3), on the same
//! hosts.db connection as the registry and groups.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_policy::{GroupPolicy, GroupPolicyInput};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::groups::get_in_scope;
use crate::{to_stored_i64, GroupError, GroupScope, SqliteHostRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryResult {
    Executed,
    Refused,
    Failed,
    Offline,
    TimedOut,
}

impl DeliveryResult {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryResult::Executed => "EXECUTED",
            DeliveryResult::Refused => "REFUSED",
            DeliveryResult::Failed => "FAILED",
            DeliveryResult::Offline => "OFFLINE",
            DeliveryResult::TimedOut => "TIMED_OUT",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Executed,
            Self::Refused,
            Self::Failed,
            Self::Offline,
            Self::TimedOut,
        ]
        .into_iter()
        .find(|r| r.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryRow {
    pub host_id: Uuid,
    pub desired_hash: String,
    /// ns since the Unix epoch, server clock.
    pub last_sent_at: u64,
    pub last_result: DeliveryResult,
    pub last_error: Option<String>,
}

pub trait PolicyStore: Send + Sync {
    fn get_policy(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
    ) -> Result<Option<GroupPolicy>, GroupError>;
    fn set_policy(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        policy: &GroupPolicy,
        updated_by: &str,
    ) -> Result<(), GroupError>;
    fn clear_policy(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError>;
    /// Raw, unscoped: every policy of every group `host_id` belongs to.
    fn policies_for_host(&self, host_id: Uuid) -> Result<Vec<GroupPolicyInput>, GroupError>;
    fn all_host_policies(&self) -> Result<HashMap<Uuid, Vec<GroupPolicyInput>>, GroupError>;
    fn hosts_of_group_raw(&self, group_id: Uuid) -> Result<Vec<Uuid>, GroupError>;
    fn record_delivery(&self, row: &DeliveryRow) -> Result<(), GroupError>;
    fn delivery(&self, host_id: Uuid) -> Result<Option<DeliveryRow>, GroupError>;
    fn all_deliveries(&self) -> Result<HashMap<Uuid, DeliveryRow>, GroupError>;
}

fn backend(e: impl std::fmt::Display) -> GroupError {
    GroupError::Backend(e.to_string())
}

fn uuid_at(r: &rusqlite::Row, idx: usize) -> rusqlite::Result<Uuid> {
    let s: String = r.get(idx)?;
    Uuid::parse_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn policy_input(r: &rusqlite::Row, base: usize) -> rusqlite::Result<GroupPolicyInput> {
    let tenant: Option<String> = r.get(base + 1)?;
    let json: String = r.get(base + 2)?;
    Ok(GroupPolicyInput {
        group_id: uuid_at(r, base)?,
        group_tenant: tenant
            .map(|t| Uuid::parse_str(&t))
            .transpose()
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    base + 1,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        policy: serde_json::from_str(&json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                base + 2,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })?,
    })
}

fn delivery_from(r: &rusqlite::Row) -> rusqlite::Result<DeliveryRow> {
    let result: String = r.get(3)?;
    Ok(DeliveryRow {
        host_id: uuid_at(r, 0)?,
        desired_hash: r.get(1)?,
        last_sent_at: r.get::<_, i64>(2)? as u64,
        last_result: DeliveryResult::parse(&result).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                format!("bad delivery result {result}").into(),
            )
        })?,
        last_error: r.get(4)?,
    })
}

const HOST_POLICIES: &str = "SELECT m.host_id, p.group_id, g.tenant_id, p.policy_json
     FROM host_group_members m
     JOIN group_policies p ON p.group_id = m.group_id
     JOIN host_groups g ON g.group_id = m.group_id";

impl PolicyStore for SqliteHostRegistry {
    fn get_policy(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
    ) -> Result<Option<GroupPolicy>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        let json: Option<String> = conn
            .query_row(
                "SELECT policy_json FROM group_policies WHERE group_id = ?1",
                params![group_id.to_string()],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        json.map(|j| serde_json::from_str(&j).map_err(backend))
            .transpose()
    }

    fn set_policy(
        &self,
        scope: &GroupScope,
        group_id: Uuid,
        policy: &GroupPolicy,
        updated_by: &str,
    ) -> Result<(), GroupError> {
        policy
            .validate()
            .map_err(|e| GroupError::InvalidPolicy(e.to_string()))?;
        let json = serde_json::to_string(policy).map_err(backend)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        conn.execute(
            "INSERT INTO group_policies (group_id, policy_json, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id) DO UPDATE SET policy_json = excluded.policy_json,
                 updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            params![group_id.to_string(), json, to_stored_i64(now), updated_by],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn clear_policy(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        conn.execute(
            "DELETE FROM group_policies WHERE group_id = ?1",
            params![group_id.to_string()],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn policies_for_host(&self, host_id: Uuid) -> Result<Vec<GroupPolicyInput>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare(&format!("{HOST_POLICIES} WHERE m.host_id = ?1"))
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![host_id.to_string()], |r| policy_input(r, 1))
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        Ok(rows)
    }

    fn all_host_policies(&self) -> Result<HashMap<Uuid, Vec<GroupPolicyInput>>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(HOST_POLICIES).map_err(backend)?;
        let rows = stmt
            .query_map([], |r| Ok((uuid_at(r, 0)?, policy_input(r, 1)?)))
            .map_err(backend)?;
        let mut out: HashMap<Uuid, Vec<GroupPolicyInput>> = HashMap::new();
        for row in rows {
            let (host, input) = row.map_err(backend)?;
            out.entry(host).or_default().push(input);
        }
        Ok(out)
    }

    fn hosts_of_group_raw(&self, group_id: Uuid) -> Result<Vec<Uuid>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare("SELECT host_id FROM host_group_members WHERE group_id = ?1 ORDER BY host_id")
            .map_err(backend)?;
        let ids = stmt
            .query_map(params![group_id.to_string()], |r| uuid_at(r, 0))
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        Ok(ids)
    }

    fn record_delivery(&self, row: &DeliveryRow) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO host_policy_delivery (host_id, desired_hash, last_sent_at, last_result, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(host_id) DO UPDATE SET desired_hash = excluded.desired_hash,
                 last_sent_at = excluded.last_sent_at, last_result = excluded.last_result,
                 last_error = excluded.last_error",
            params![row.host_id.to_string(), row.desired_hash, to_stored_i64(row.last_sent_at), row.last_result.as_str(), row.last_error],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn delivery(&self, host_id: Uuid) -> Result<Option<DeliveryRow>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT host_id, desired_hash, last_sent_at, last_result, last_error FROM host_policy_delivery WHERE host_id = ?1",
            params![host_id.to_string()],
            delivery_from,
        )
        .optional()
        .map_err(backend)
    }

    fn all_deliveries(&self) -> Result<HashMap<Uuid, DeliveryRow>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare("SELECT host_id, desired_hash, last_sent_at, last_result, last_error FROM host_policy_delivery")
            .map_err(backend)?;
        let rows = stmt.query_map([], delivery_from).map_err(backend)?;
        let mut out = HashMap::new();
        for row in rows {
            let d = row.map_err(backend)?;
            out.insert(d.host_id, d);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FleetError, GroupScope, HostGroupStore, HostRegistry, HostRow, SqliteHostRegistry,
        SCHEMA_VERSION,
    };
    use osiris_health::HealthState;
    use osiris_policy::{GroupPolicy, TelemetryLevel};

    const P: GroupScope = GroupScope::Platform;

    fn open(dir: &tempfile::TempDir) -> SqliteHostRegistry {
        SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()
    }

    fn row(host_id: Uuid, last_seen: u64, hash: Option<&str>) -> HostRow {
        HostRow {
            host_id,
            hostname: "h".into(),
            distro: "d".into(),
            kernel_version: "k".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: last_seen,
            last_seen,
            health_state: HealthState::Healthy,
            cloud_provider: None,
            cloud_instance_id: None,
            cloud_region: None,
            applied_policy_hash: hash.map(str::to_string),
        }
    }

    fn level(l: TelemetryLevel) -> GroupPolicy {
        GroupPolicy {
            telemetry_level: Some(l),
            ..Default::default()
        }
    }

    #[test]
    fn set_get_clear_round_trip_and_scope() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let t = Uuid::new_v4();
        let g = reg.create(&GroupScope::Tenant(t), None, "g").unwrap();
        assert_eq!(reg.get_policy(&P, g.group_id).unwrap(), None);
        reg.set_policy(
            &GroupScope::Tenant(t),
            g.group_id,
            &level(TelemetryLevel::Standard),
            "u",
        )
        .unwrap();
        assert_eq!(
            reg.get_policy(&P, g.group_id).unwrap(),
            Some(level(TelemetryLevel::Standard))
        );
        let other = GroupScope::Tenant(Uuid::new_v4());
        assert_eq!(
            reg.get_policy(&other, g.group_id),
            Err(GroupError::NotFound)
        );
        assert_eq!(
            reg.set_policy(&other, g.group_id, &level(TelemetryLevel::Minimal), "u"),
            Err(GroupError::NotFound)
        );
        assert_eq!(
            reg.clear_policy(&other, g.group_id),
            Err(GroupError::NotFound)
        );
        reg.clear_policy(&GroupScope::Tenant(t), g.group_id)
            .unwrap();
        assert_eq!(reg.get_policy(&P, g.group_id).unwrap(), None);
    }

    #[test]
    fn an_invalid_policy_is_rejected_by_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let g = reg.create(&P, None, "g").unwrap();
        let mut bad = GroupPolicy::default();
        bad.sensors.insert("bogus".into(), true);
        assert_eq!(
            reg.set_policy(&P, g.group_id, &bad, "u"),
            Err(GroupError::InvalidPolicy("unknown sensor: bogus".into()))
        );
        let mut good = GroupPolicy::default();
        good.sensors.insert("dns".into(), false);
        assert!(reg.set_policy(&P, g.group_id, &good, "u").is_ok());
    }

    #[test]
    fn policies_for_host_is_raw_and_carries_group_tenants() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let h = Uuid::new_v4();
        reg.upsert_heartbeat(row(h, 1, None)).unwrap();
        let t = Uuid::new_v4();
        let pg = reg.create(&P, None, "p").unwrap();
        let tg = reg.create(&GroupScope::Tenant(t), None, "t").unwrap();
        let bare = reg.create(&P, None, "no-policy").unwrap();
        for g in [&pg, &tg, &bare] {
            reg.add_member(&P, g.group_id, h).unwrap();
        }
        reg.set_policy(&P, pg.group_id, &level(TelemetryLevel::Minimal), "u")
            .unwrap();
        reg.set_policy(&P, tg.group_id, &level(TelemetryLevel::Forensic), "u")
            .unwrap();
        let mut got = reg.policies_for_host(h).unwrap();
        got.sort_by_key(|i| i.group_tenant.is_some());
        assert_eq!(got.len(), 2, "groups without a policy contribute nothing");
        assert_eq!(got[0].group_tenant, None);
        assert_eq!(got[1].group_tenant, Some(t));
        assert_eq!(reg.all_host_policies().unwrap()[&h].len(), 2);
        assert_eq!(reg.hosts_of_group_raw(pg.group_id).unwrap(), vec![h]);
    }

    #[test]
    fn deleting_a_group_deletes_its_policy() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let g = reg.create(&P, None, "g").unwrap();
        reg.set_policy(&P, g.group_id, &level(TelemetryLevel::Minimal), "u")
            .unwrap();
        reg.delete(&P, g.group_id).unwrap();
        let n: i64 = reg
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM group_policies", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn applied_hash_obeys_the_freshness_gate() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let h = Uuid::new_v4();
        reg.upsert_heartbeat(row(h, 100, Some("new"))).unwrap();
        reg.upsert_heartbeat(row(h, 50, Some("old"))).unwrap();
        assert_eq!(
            HostRegistry::get(&reg, h)
                .unwrap()
                .unwrap()
                .applied_policy_hash
                .as_deref(),
            Some("new")
        );
        reg.upsert_heartbeat(row(h, 200, None)).unwrap();
        assert_eq!(
            HostRegistry::get(&reg, h)
                .unwrap()
                .unwrap()
                .applied_policy_hash,
            None
        );
    }

    #[test]
    fn deliveries_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let h = Uuid::new_v4();
        reg.upsert_heartbeat(row(h, 1, None)).unwrap();
        let d = DeliveryRow {
            host_id: h,
            desired_hash: "abc".into(),
            last_sent_at: 7,
            last_result: DeliveryResult::Refused,
            last_error: Some("replay".into()),
        };
        reg.record_delivery(&d).unwrap();
        assert_eq!(reg.delivery(h).unwrap(), Some(d.clone()));
        let d2 = DeliveryRow {
            last_result: DeliveryResult::Executed,
            last_error: None,
            last_sent_at: 9,
            ..d
        };
        reg.record_delivery(&d2).unwrap();
        assert_eq!(reg.all_deliveries().unwrap()[&h], d2);
    }

    #[test]
    fn a_v1_database_migrates_to_v2_keeping_groups_and_members() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.db");
        let h = Uuid::new_v4();
        let gid;
        {
            // Build a genuine v1 file: v1 schema, one host, one group with a member, user_version 1.
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
            conn.execute_batch(crate::SCHEMA_V1).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO hosts VALUES (?1,'old','d','k','0.1.0',5,5,'{\"state\":\"HEALTHY\"}',NULL,NULL,NULL)",
                [h.to_string()],
            ).unwrap();
            gid = Uuid::new_v4();
            conn.execute(
                "INSERT INTO host_groups VALUES (?1,'g',NULL,1)",
                [gid.to_string()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO host_group_members VALUES (?1,?2,1)",
                [gid.to_string(), h.to_string()],
            )
            .unwrap();
        }
        let reg = SqliteHostRegistry::open(&path).unwrap();
        assert_eq!(HostGroupStore::get(&reg, &P, gid).unwrap().member_count, 1);
        assert_eq!(
            HostRegistry::get(&reg, h)
                .unwrap()
                .unwrap()
                .applied_policy_hash,
            None
        );
        reg.set_policy(&P, gid, &level(TelemetryLevel::Minimal), "u")
            .unwrap();
        let v: i64 = reg
            .conn
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        drop(reg);
        SqliteHostRegistry::open(&path).unwrap(); // reopening a v2 file is idempotent
    }

    #[test]
    fn a_version_3_database_still_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.db");
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 3)
            .unwrap();
        assert!(matches!(
            SqliteHostRegistry::open(&path),
            Err(FleetError::UnsupportedSchema(3))
        ));
    }
}
