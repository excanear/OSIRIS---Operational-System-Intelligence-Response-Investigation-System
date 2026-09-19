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
    /// Precomputed once: the tenant's hosts as strings, and as a set for the
    /// intersection with a caller-supplied host list.
    allowed: Vec<String>,
    allowed_set: HashSet<String>,
}

impl TenantScopedStorage {
    pub fn new(inner: Arc<dyn Storage>, hosts: HashSet<Uuid>) -> Self {
        let allowed: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        let allowed_set: HashSet<String> = allowed.iter().cloned().collect();
        Self { inner, hosts, allowed, allowed_set }
    }

    /// The effective host list for a plan: the tenant's hosts, intersected
    /// with whatever the caller already asked for. The decorator can only
    /// narrow a query, never widen it.
    fn effective(&self, requested: &Option<Vec<String>>) -> Option<Vec<String>> {
        match requested {
            None => Some(self.allowed.clone()),
            Some(want) => Some(want.iter().filter(|h| self.allowed_set.contains(*h)).cloned().collect()),
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
    let tenants = parts.extensions.get::<Arc<dyn TenantStore>>().cloned();
    hosts_of_tenant(ctx.tenant_id, tenants).await
}

/// Same contract as `tenant_hosts`, for handlers that already hold the caller's
/// tenant id and the registry (the response handler).
pub(crate) async fn hosts_of_tenant(
    tenant_id: Option<Uuid>,
    tenants: Option<Arc<dyn TenantStore>>,
) -> Result<Option<HashSet<Uuid>>, (StatusCode, String)> {
    let Some(tenant_id) = tenant_id else {
        return Ok(None);
    };
    let Some(tenants) = tenants else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "tenant registry unavailable".to_string(),
        ));
    };
    let lookup_failed = |cause: String| {
        tracing::error!(error = %cause, "tenant host lookup failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "tenant lookup failed".to_string())
    };
    let hosts = tokio::task::spawn_blocking(move || tenants.hosts_of(tenant_id))
        .await
        .map_err(|e| lookup_failed(e.to_string()))?
        .map_err(|e| lookup_failed(e.to_string()))?;
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
        ev_a: CanonicalEvent,
        ev_b: CanonicalEvent,
        ev_u: CanonicalEvent,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        let (a, b, unassigned) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let ev_a = event_on(a, 1, 100);
        let ev_b = event_on(b, 2, 200);
        let ev_u = event_on(unassigned, 3, 300);
        storage.batch_write(&[ev_a.clone(), ev_b.clone(), ev_u.clone()]).unwrap();
        Fixture { _dir: dir, inner: Arc::new(storage), a, b, ev_a, ev_b, ev_u }
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
        assert!(s.get_event(f.ev_u.event_id).unwrap().is_none());
    }

    #[test]
    fn writes_deletes_and_retention_are_refused() {
        let f = fixture();
        let s = scoped(&f, &[f.a]);
        assert!(s.write(&f.ev_a).is_err());
        assert!(s.batch_write(std::slice::from_ref(&f.ev_a)).is_err());
        assert!(s.write_alerts(&[]).is_err());
        assert!(s.write_relationships(&[]).is_err());
        assert!(s.write_risk_scores(&[]).is_err());
        assert!(s.delete(&osiris_storage::DeleteCriteria { before_timestamp: 0 }).is_err());
        assert!(s.retention_apply(&osiris_storage::RetentionPolicy { max_age_secs: 0 }).is_err());
    }

    #[test]
    fn health_delegates_to_the_inner_storage() {
        let f = fixture();
        assert_eq!(scoped(&f, &[f.a]).health().healthy, f.inner.health().healthy);
    }
}
