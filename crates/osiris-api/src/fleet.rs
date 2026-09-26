//! `GET /api/v1/hosts` — ARCHITECTURE.md §21.2's Fleet Manager, backed by
//! the real `osiris_fleet::HostRegistry` (Phase 9d-1) rather than a scan
//! over recent events. A host row only exists once its agent has sent at
//! least one `AGENT_HEALTH` heartbeat (Task 3), and `status` is derived
//! from how long ago `last_seen` was relative to `now`, not from a
//! time-windowed event scan.

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth_middleware::AuthContext;
use osiris_fleet::{HostRegistry, HostRow};
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
}

pub fn build_fleet_router(state: FleetState) -> Router {
    Router::new()
        .route("/api/v1/hosts", get(hosts_handler))
        .with_state(state)
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
}

fn to_summary(row: HostRow, now_ns: u64) -> HostSummary {
    let status = if now_ns.saturating_sub(row.last_seen) <= 3 * EXPECTED_HEARTBEAT_INTERVAL_NS {
        "ONLINE"
    } else {
        "STALE"
    };
    HostSummary {
        host_id: row.host_id.to_string(),
        hostname: row.hostname,
        distro: row.distro,
        kernel_version: row.kernel_version,
        agent_version: row.agent_version,
        enrolled_at: row.enrolled_at,
        last_seen: row.last_seen,
        status: status.to_string(),
        cloud_provider: row.cloud_provider,
        cloud_instance_id: row.cloud_instance_id,
        cloud_region: row.cloud_region,
    }
}

fn now_ns() -> u64 {
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
) -> Result<Json<Vec<HostSummary>>, (StatusCode, String)> {
    let scope =
        crate::tenant_scope::hosts_of_tenant(ctx.tenant_id, Some(state.tenants.clone())).await?;
    let registry = state.registry.clone();
    let mut rows = tokio::task::spawn_blocking(move || registry.list())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(allowed) = scope {
        rows.retain(|r| allowed.contains(&r.host_id));
    }
    let now = now_ns();
    let mut summaries: Vec<HostSummary> = rows.into_iter().map(|r| to_summary(r, now)).collect();
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
    use osiris_tenancy::SqliteTenantStore;
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
            health_state: osiris_health::HealthState::Healthy,
            cloud_provider: None,
            cloud_instance_id: None,
            cloud_region: None,
        }
    }

    fn state(dir: &std::path::Path) -> FleetState {
        FleetState {
            registry: Arc::new(
                osiris_fleet::SqliteHostRegistry::open(dir.join("hosts.db")).unwrap(),
            ),
            tenants: Arc::new(SqliteTenantStore::open(dir.join("tenants.db")).unwrap()),
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
        let Json(rows) = hosts_handler(Extension(platform_ctx()), State(state(dir.path())))
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

        let Json(rows) = hosts_handler(Extension(platform_ctx()), State(s))
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

        let Json(rows) = hosts_handler(Extension(platform_ctx()), State(s))
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

        let Json(rows) = hosts_handler(Extension(tenant_ctx(tenant_id)), State(s))
            .await
            .unwrap();

        let ids: Vec<String> = rows.iter().map(|r| r.host_id.clone()).collect();
        assert!(ids.contains(&mine.to_string()));
        assert!(!ids.contains(&theirs.to_string()));
    }
}
