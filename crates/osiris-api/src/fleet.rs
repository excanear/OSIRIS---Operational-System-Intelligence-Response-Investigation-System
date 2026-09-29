//! `GET /api/v1/hosts` — ARCHITECTURE.md §21.2's Fleet Manager, backed by
//! the real `osiris_fleet::HostRegistry` (Phase 9d-1) rather than a scan
//! over recent events. A host row only exists once its agent has sent at
//! least one `AGENT_HEALTH` heartbeat (Task 3), and `status` is derived
//! from how long ago `last_seen` was relative to `now`, not from a
//! time-windowed event scan.

use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthContext;
use osiris_fleet::{GroupError, GroupRef, GroupScope, HostGroupStore, HostRegistry, HostRow};
use osiris_tenancy::TenantStore;

/// A host is considered `ONLINE` if its `last_seen` heartbeat is no older
/// than three missed heartbeat intervals (Phase 9d-1 design doc §3); beyond
/// that it is `STALE`. `HostRow.last_seen`/`enrolled_at` are epoch
/// nanoseconds (they come from `CanonicalEvent.timestamp`), so this
/// threshold is nanoseconds too.
const EXPECTED_HEARTBEAT_INTERVAL_NS: u64 = 60 * 1_000_000_000;

#[derive(Clone)]
pub struct FleetState {
    pub registry: Arc<dyn HostRegistry>,
    pub tenants: Arc<dyn TenantStore>,
    pub groups: Arc<dyn HostGroupStore>,
}

pub fn build_fleet_router(state: FleetState) -> Router {
    Router::new()
        .route("/api/v1/hosts", get(hosts_handler))
        .with_state(state)
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct HostsQuery {
    pub group: Option<Uuid>,
}

#[derive(Debug, Serialize, PartialEq)]
struct HostSummary {
    host_id: String,
    hostname: String,
    distro: String,
    kernel_version: String,
    agent_version: String,
    enrolled_at: u64,
    last_seen: u64,
    status: String,
    cloud_provider: Option<String>,
    cloud_instance_id: Option<String>,
    cloud_region: Option<String>,
    groups: Vec<GroupRef>,
}

pub(crate) fn host_status(last_seen: u64, now_ns: u64) -> &'static str {
    if now_ns.saturating_sub(last_seen) <= 3 * EXPECTED_HEARTBEAT_INTERVAL_NS {
        "ONLINE"
    } else {
        "STALE"
    }
}

fn to_summary(row: HostRow, now_ns: u64) -> HostSummary {
    HostSummary {
        host_id: row.host_id.to_string(),
        hostname: row.hostname,
        distro: row.distro,
        kernel_version: row.kernel_version,
        agent_version: row.agent_version,
        enrolled_at: row.enrolled_at,
        last_seen: row.last_seen,
        status: host_status(row.last_seen, now_ns).to_string(),
        cloud_provider: row.cloud_provider,
        cloud_instance_id: row.cloud_instance_id,
        cloud_region: row.cloud_region,
        groups: Vec::new(),
    }
}

pub(crate) fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// `GET /api/v1/hosts` — one row per host in the fleet registry, scoped to
/// the caller's tenant (a platform caller with `tenant_id: None` sees every
/// host; a tenant caller sees only hosts assigned to it, never an
/// unassigned/platform-owned host). Sorted most-recently-seen first,
/// ties broken by `host_id` ascending for deterministic output.
async fn hosts_handler(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<FleetState>,
    Query(query): Query<HostsQuery>,
) -> Result<Json<Vec<HostSummary>>, (StatusCode, String)> {
    let scope =
        crate::tenant_scope::hosts_of_tenant(ctx.tenant_id, Some(state.tenants.clone())).await?;
    let registry = state.registry.clone();
    let mut rows = tokio::task::spawn_blocking(move || registry.list())
        .await
        .map_err(|e| crate::groups::internal(e.to_string()))?
        .map_err(|e| crate::groups::internal(e.to_string()))?;
    if let Some(allowed) = scope {
        rows.retain(|r| allowed.contains(&r.host_id));
    }

    let group_scope = match ctx.tenant_id {
        Some(t) => GroupScope::Tenant(t),
        None => GroupScope::Platform,
    };
    if let Some(group_id) = query.group {
        let groups = state.groups.clone();
        let members: std::collections::HashSet<Uuid> =
            tokio::task::spawn_blocking(move || groups.members(&group_scope, group_id))
                .await
                .map_err(|e| crate::groups::internal(e.to_string()))?
                .map_err(|e| match e {
                    GroupError::NotFound => (StatusCode::NOT_FOUND, e.to_string()),
                    other => crate::groups::internal(other.to_string()),
                })?
                .into_iter()
                .collect();
        rows.retain(|r| members.contains(&r.host_id));
    }
    let ids: Vec<Uuid> = rows.iter().map(|r| r.host_id).collect();
    let groups = state.groups.clone();
    let mut by_host = tokio::task::spawn_blocking(move || groups.groups_of(&group_scope, &ids))
        .await
        .map_err(|e| crate::groups::internal(e.to_string()))?
        .map_err(|e| crate::groups::internal(e.to_string()))?;

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
    summaries.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then(a.host_id.cmp(&b.host_id))
    });
    Ok(Json(summaries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_fleet::FleetError;
    use osiris_tenancy::SqliteTenantStore;
    use uuid::Uuid;

    /// A `HostRegistry` whose `list()` always fails, carrying a message that
    /// must never reach a caller (Minor 1 of the final review: 500 bodies
    /// must be exactly `internal error`, cause only in logs).
    struct FailingRegistry;

    impl HostRegistry for FailingRegistry {
        fn upsert_heartbeat(&self, _row: HostRow) -> Result<(), FleetError> {
            unimplemented!()
        }
        fn get(&self, _host_id: Uuid) -> Result<Option<HostRow>, FleetError> {
            unimplemented!()
        }
        fn list(&self) -> Result<Vec<HostRow>, FleetError> {
            Err(FleetError::Sqlite("secret sqlite text".into()))
        }
    }

    fn row(host_id: Uuid, last_seen: u64) -> HostRow {
        HostRow {
            host_id,
            hostname: "h1".into(),
            distro: "ubuntu-24.04".into(),
            kernel_version: "6.8.0".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: last_seen,
            last_seen,
            health_state: osiris_health::HealthState::Healthy,
            cloud_provider: None,
            cloud_instance_id: None,
            cloud_region: None,
            applied_policy_hash: None,
        }
    }

    fn state(dir: &std::path::Path) -> FleetState {
        let fleet_db =
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.join("hosts.db")).unwrap());
        FleetState {
            registry: fleet_db.clone(),
            tenants: Arc::new(SqliteTenantStore::open(dir.join("tenants.db")).unwrap()),
            groups: fleet_db,
        }
    }

    fn platform_ctx() -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::Admin,
            token: "t".to_string(),
            tenant_id: None,
        }
    }

    fn tenant_ctx(tenant_id: Uuid) -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::Viewer,
            token: "t".to_string(),
            tenant_id: Some(tenant_id),
        }
    }

    #[test]
    fn online_exactly_at_the_boundary_stale_one_ns_past_it() {
        let now = 10 * EXPECTED_HEARTBEAT_INTERVAL_NS;
        let at_boundary = row(Uuid::new_v4(), now - 3 * EXPECTED_HEARTBEAT_INTERVAL_NS);
        let past_boundary = row(Uuid::new_v4(), now - 3 * EXPECTED_HEARTBEAT_INTERVAL_NS - 1);
        assert_eq!(to_summary(at_boundary, now).status, "ONLINE");
        assert_eq!(to_summary(past_boundary, now).status, "STALE");
    }

    #[tokio::test]
    async fn an_empty_registry_returns_an_empty_array() {
        let dir = tempfile::tempdir().unwrap();
        let Json(rows) = hosts_handler(
            Extension(platform_ctx()),
            State(state(dir.path())),
            Query(HostsQuery::default()),
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 0);
    }

    #[tokio::test]
    async fn a_host_summary_carries_its_cloud_fields() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let host_id = Uuid::new_v4();
        let mut with_cloud = row(host_id, 1_000);
        with_cloud.cloud_provider = Some("aws".into());
        with_cloud.cloud_instance_id = Some("i-0abc".into());
        with_cloud.cloud_region = Some("us-east-1".into());
        s.registry.upsert_heartbeat(with_cloud).unwrap();

        let Json(rows) = hosts_handler(
            Extension(platform_ctx()),
            State(s),
            Query(HostsQuery::default()),
        )
        .await
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cloud_provider.as_deref(), Some("aws"));
        assert_eq!(rows[0].cloud_instance_id.as_deref(), Some("i-0abc"));
        assert_eq!(rows[0].cloud_region.as_deref(), Some("us-east-1"));
    }

    #[tokio::test]
    async fn a_host_summary_has_null_cloud_fields_when_on_prem() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let host_id = Uuid::new_v4();
        s.registry.upsert_heartbeat(row(host_id, 1_000)).unwrap();

        let Json(rows) = hosts_handler(
            Extension(platform_ctx()),
            State(s),
            Query(HostsQuery::default()),
        )
        .await
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cloud_provider, None);
        assert_eq!(rows[0].cloud_instance_id, None);
        assert_eq!(rows[0].cloud_region, None);
    }

    #[tokio::test]
    async fn a_tenant_user_only_sees_its_own_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let tenant_id = s.tenants.create_tenant("acme").unwrap().tenant_id;
        let mine = Uuid::new_v4();
        let theirs = Uuid::new_v4();
        s.registry.upsert_heartbeat(row(mine, 1_000)).unwrap();
        s.registry.upsert_heartbeat(row(theirs, 1_000)).unwrap();
        s.tenants.assign_host(mine, tenant_id).unwrap();
        // `theirs` stays unassigned (platform-owned), which per
        // `hosts_of_tenant`'s existing contract must also be invisible
        // to a tenant-scoped caller.

        let Json(rows) = hosts_handler(
            Extension(tenant_ctx(tenant_id)),
            State(s),
            Query(HostsQuery::default()),
        )
        .await
        .unwrap();

        let ids: Vec<String> = rows.iter().map(|r| r.host_id.clone()).collect();
        assert!(ids.contains(&mine.to_string()));
        assert!(!ids.contains(&theirs.to_string()));
    }

    #[tokio::test]
    async fn each_host_lists_its_groups_sorted_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let s = state(dir.path());
        let h = Uuid::new_v4();
        s.registry.upsert_heartbeat(row(h, 1_000)).unwrap();
        let web = s.groups.create(&GroupScope::Platform, None, "web").unwrap();
        let db = s.groups.create(&GroupScope::Platform, None, "db").unwrap();
        s.groups
            .add_member(&GroupScope::Platform, web.group_id, h)
            .unwrap();
        s.groups
            .add_member(&GroupScope::Platform, db.group_id, h)
            .unwrap();
        let Json(rows) = hosts_handler(
            Extension(platform_ctx()),
            State(s),
            Query(HostsQuery::default()),
        )
        .await
        .unwrap();
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
        s.groups
            .add_member(&GroupScope::Platform, g.group_id, inside)
            .unwrap();
        let Json(rows) = hosts_handler(
            Extension(platform_ctx()),
            State(s),
            Query(HostsQuery {
                group: Some(g.group_id),
            }),
        )
        .await
        .unwrap();
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
            let err = hosts_handler(
                Extension(tenant_ctx(t)),
                State(s.clone()),
                Query(HostsQuery { group: Some(gid) }),
            )
            .await
            .unwrap_err();
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
        let platform_group = s
            .groups
            .create(&GroupScope::Platform, None, "platform-g")
            .unwrap();
        let tenant_group = s
            .groups
            .create(&GroupScope::Tenant(t), None, "acme-g")
            .unwrap();
        s.groups
            .add_member(&GroupScope::Platform, platform_group.group_id, h)
            .unwrap();
        s.groups
            .add_member(&GroupScope::Platform, tenant_group.group_id, h)
            .unwrap();
        let Json(rows) = hosts_handler(
            Extension(tenant_ctx(t)),
            State(s),
            Query(HostsQuery::default()),
        )
        .await
        .unwrap();
        let names: Vec<&str> = rows[0].groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["acme-g"]);
    }

    #[tokio::test]
    async fn a_store_failure_is_a_generic_500_that_does_not_leak_the_backend_error() {
        let dir = tempfile::tempdir().unwrap();
        let fleet_db =
            Arc::new(osiris_fleet::SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let s = FleetState {
            registry: Arc::new(FailingRegistry),
            tenants: Arc::new(SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap()),
            groups: fleet_db,
        };
        let err = hosts_handler(
            Extension(platform_ctx()),
            State(s),
            Query(HostsQuery::default()),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string()
            )
        );
        assert!(!err.1.contains("secret sqlite text"));
    }
}
