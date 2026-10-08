//! Group policy routes and the host effective-policy view (Phase 9d-3).
//! Group policies are resolved in the caller's `GroupScope` first (missing
//! or foreign group -> 404, before any validation, so a 400-vs-404 split
//! never reveals another tenant's group). The host view resolves with the
//! host's *current* tenant, so a tenant policy never applies to a host that
//! has left that tenant.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_fleet::{
    DeliveryResult, DeliveryRow, GroupError, GroupScope, HostGroupStore, HostRegistry, PolicyStore,
};
use osiris_policy::{FieldSource, GroupPolicy, PolicyTier};
use osiris_schema::EntityRef;
use osiris_tenancy::TenantStore;
use serde_json::json;
use uuid::Uuid;

use crate::auth_middleware::AuthContext;
use crate::groups::{group_error, internal, scope_of};

type ApiError = (StatusCode, String);

/// Told which hosts' effective policy may have changed. Implementations must
/// return immediately (the real one spawns reconciliation).
pub trait PolicyNotifier: Send + Sync {
    fn hosts_changed(&self, hosts: Vec<Uuid>);
    /// Whether the server can push policy at all (a control channel exists).
    fn managed(&self) -> bool;
}

/// No control channel: nothing is pushed and every host reads `UNMANAGED`.
pub struct NoopPolicyNotifier;

impl PolicyNotifier for NoopPolicyNotifier {
    fn hosts_changed(&self, _hosts: Vec<Uuid>) {}
    fn managed(&self) -> bool {
        false
    }
}

#[derive(Clone)]
pub struct PolicyState {
    pub groups: Arc<dyn HostGroupStore>,
    pub policies: Arc<dyn PolicyStore>,
    pub registry: Arc<dyn HostRegistry>,
    pub tenants: Arc<dyn TenantStore>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
    pub notifier: Arc<dyn PolicyNotifier>,
}

pub fn build_policy_router(state: PolicyState) -> Router {
    Router::new()
        .route(
            "/api/v1/groups/:group_id/policy",
            get(get_group_policy)
                .put(put_group_policy)
                .delete(delete_group_policy),
        )
        .route("/api/v1/hosts/:host_id/policy", get(get_host_policy))
        .with_state(state)
}

pub(crate) fn policy_status(
    managed: bool,
    desired: &str,
    applied: Option<&str>,
    delivery: Option<&DeliveryRow>,
) -> &'static str {
    if !managed {
        return "UNMANAGED";
    }
    let empty = osiris_policy::empty_policy_hash_hex();
    if applied.unwrap_or(&empty) == desired {
        return "IN_SYNC";
    }
    match delivery {
        Some(d)
            if d.desired_hash == desired
                && matches!(
                    d.last_result,
                    DeliveryResult::Refused | DeliveryResult::Failed
                ) =>
        {
            "FAILED"
        }
        _ => "PENDING",
    }
}

async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, GroupError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal(e.to_string()))?
        .map_err(group_error)
}

fn audit_with_why(
    state: &PolicyState,
    ctx: &AuthContext,
    what: &str,
    target: String,
    why: Option<String>,
) {
    let _ = state.audit_log.append(NewAuditEntry {
        who: ActorRef::User {
            user_id: ctx.user_id,
        },
        what: what.to_string(),
        target: EntityRef::Domain { name: target },
        why,
        result: AuditResult::Success,
    });
}

/// Best effort: the change is already stored and audited, so a failed member
/// lookup is logged, not returned. The members converge on their next heartbeat.
async fn notify_group_members(state: &PolicyState, group_id: Uuid) {
    let policies = state.policies.clone();
    match tokio::task::spawn_blocking(move || policies.hosts_of_group_raw(group_id)).await {
        Ok(Ok(hosts)) => state.notifier.hosts_changed(hosts),
        Ok(Err(e)) => tracing::error!(
            %group_id, error = %e,
            "cannot list group members to push the policy change; they converge on their next heartbeat"
        ),
        Err(e) => tracing::error!(
            %group_id, error = %e,
            "group member lookup task failed; members converge on their next heartbeat"
        ),
    }
}

async fn get_group_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<PolicyState>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = scope_of(&ctx);
    let policies = state.policies.clone();
    let policy = blocking(move || policies.get_policy(&scope, group_id)).await?;
    Ok(Json(json!({ "policy": policy })))
}

async fn put_group_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<PolicyState>,
    Path(group_id): Path<Uuid>,
    Json(policy): Json<GroupPolicy>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = scope_of(&ctx);
    // Visibility first: a missing or foreign group is 404 whatever the body.
    let groups = state.groups.clone();
    blocking(move || groups.get(&scope, group_id).map(|_| ())).await?;
    policy
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let policies = state.policies.clone();
    let (stored, by) = (policy.clone(), ctx.user_id.to_string());
    blocking(move || policies.set_policy(&scope, group_id, &stored, &by)).await?;
    audit_with_why(
        &state,
        &ctx,
        "group_policy_set",
        format!("group:{group_id}"),
        serde_json::to_string(&policy).ok(),
    );
    notify_group_members(&state, group_id).await;
    Ok(Json(json!({ "policy": policy })))
}

async fn delete_group_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<PolicyState>,
    Path(group_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let scope = scope_of(&ctx);
    let policies = state.policies.clone();
    blocking(move || policies.clear_policy(&scope, group_id)).await?;
    audit_with_why(
        &state,
        &ctx,
        "group_policy_clear",
        format!("group:{group_id}"),
        None,
    );
    notify_group_members(&state, group_id).await;
    Ok(StatusCode::NO_CONTENT)
}

fn not_found_host() -> ApiError {
    (StatusCode::NOT_FOUND, "host not found".to_string())
}

fn source_json(
    src: &FieldSource,
    caller_is_tenant: bool,
    names: &HashMap<Uuid, Option<String>>,
) -> serde_json::Value {
    if src.tier == PolicyTier::Platform && caller_is_tenant {
        return json!({ "tier": "PLATFORM" });
    }
    json!({
        "tier": src.tier,
        "group_id": src.group_id,
        "group_name": names.get(&src.group_id).cloned().flatten(),
    })
}

async fn get_host_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<PolicyState>,
    Path(host_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let visible =
        crate::tenant_scope::hosts_of_tenant(ctx.tenant_id, Some(state.tenants.clone())).await?;
    if visible.is_some_and(|set| !set.contains(&host_id)) {
        return Err(not_found_host());
    }
    let registry = state.registry.clone();
    let row = tokio::task::spawn_blocking(move || registry.get(host_id))
        .await
        .map_err(|e| internal(e.to_string()))?
        .map_err(|e| internal(e.to_string()))?
        .ok_or_else(not_found_host)?;

    let tenants = state.tenants.clone();
    let host_tenant = tokio::task::spawn_blocking(move || tenants.tenant_of(host_id))
        .await
        .map_err(|e| internal(e.to_string()))?
        .map_err(|e| internal(e.to_string()))?;
    let policies = state.policies.clone();
    let (inputs, delivery) = blocking(move || {
        Ok((
            policies.policies_for_host(host_id)?,
            policies.delivery(host_id)?,
        ))
    })
    .await?;
    let resolved = osiris_policy::resolve(host_tenant, &inputs);
    let desired = resolved.effective.hash_hex();

    let mut ids: Vec<Uuid> = resolved
        .level_source
        .iter()
        .chain(resolved.sensor_sources.values())
        .chain(resolved.heartbeat_source.iter())
        .map(|s| s.group_id)
        .collect();
    ids.sort();
    ids.dedup();
    let groups = state.groups.clone();
    let names: HashMap<Uuid, Option<String>> = blocking(move || {
        ids.into_iter()
            .map(|id| {
                let name = match groups.get(&GroupScope::Platform, id) {
                    Ok(g) => Some(g.name),
                    Err(GroupError::NotFound) => None,
                    Err(e) => return Err(e),
                };
                Ok((id, name))
            })
            .collect()
    })
    .await?;

    let tenant_caller = ctx.tenant_id.is_some();
    let sensors: serde_json::Map<String, serde_json::Value> = resolved
        .sensor_sources
        .iter()
        .map(|(n, s)| (n.clone(), source_json(s, tenant_caller, &names)))
        .collect();
    let status = policy_status(
        state.notifier.managed(),
        &desired,
        row.applied_policy_hash.as_deref(),
        delivery.as_ref(),
    );
    Ok(Json(json!({
        "host_id": host_id,
        "effective": resolved.effective,
        "sources": {
            "telemetry_level": resolved.level_source.as_ref().map(|s| source_json(s, tenant_caller, &names)),
            "sensors": sensors,
            "heartbeat_interval_secs": resolved.heartbeat_source.as_ref().map(|s| source_json(s, tenant_caller, &names)),
        },
        "desired_hash": desired,
        "applied_hash": row.applied_policy_hash,
        "status": status,
        "last_delivery": delivery.map(|d| json!({
            "sent_at": d.last_sent_at,
            "result": d.last_result,
            "error": d.last_error,
        })),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_fleet::{GroupScope, HostRow, SqliteHostRegistry};
    use serde_json::json;

    struct Recorder(std::sync::Mutex<Vec<Uuid>>, bool);
    impl PolicyNotifier for Recorder {
        fn hosts_changed(&self, hosts: Vec<Uuid>) {
            self.0.lock().unwrap().extend(hosts);
        }
        fn managed(&self) -> bool {
            self.1
        }
    }

    struct Fx {
        _dir: tempfile::TempDir,
        state: PolicyState,
        notes: Arc<Recorder>,
    }

    fn fx(managed: bool) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let notes = Arc::new(Recorder(Default::default(), managed));
        let state = PolicyState {
            groups: db.clone(),
            policies: db.clone(),
            registry: db,
            tenants: Arc::new(
                osiris_tenancy::SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap(),
            ),
            audit_log: Arc::new(
                osiris_audit::FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
            ),
            notifier: notes.clone(),
        };
        Fx {
            _dir: dir,
            state,
            notes,
        }
    }

    fn heartbeat(state: &PolicyState, host_id: Uuid, last_seen: u64, applied: Option<String>) {
        state
            .registry
            .upsert_heartbeat(HostRow {
                host_id,
                hostname: "h".into(),
                distro: "d".into(),
                kernel_version: "k".into(),
                agent_version: "0.1.0".into(),
                enrolled_at: last_seen,
                last_seen,
                health_state: osiris_health::HealthState::Healthy,
                cloud_provider: None,
                cloud_instance_id: None,
                cloud_region: None,
                applied_policy_hash: applied,
            })
            .unwrap();
    }

    fn host(state: &PolicyState) -> Uuid {
        let h = Uuid::new_v4();
        heartbeat(state, h, crate::fleet::now_ns(), None);
        h
    }

    fn ctx(tenant_id: Option<Uuid>) -> AuthContext {
        AuthContext {
            user_id: Uuid::now_v7(),
            role: osiris_auth::Role::Admin,
            token: "t".into(),
            tenant_id,
        }
    }

    fn body(v: serde_json::Value) -> Json<GroupPolicy> {
        Json(serde_json::from_value(v).unwrap())
    }

    async fn put(
        f: &Fx,
        c: &AuthContext,
        g: Uuid,
        v: serde_json::Value,
    ) -> Result<Json<serde_json::Value>, ApiError> {
        put_group_policy(
            Extension(c.clone()),
            State(f.state.clone()),
            Path(g),
            body(v),
        )
        .await
    }

    async fn view(f: &Fx, c: &AuthContext, h: Uuid) -> Result<Json<serde_json::Value>, ApiError> {
        get_host_policy(Extension(c.clone()), State(f.state.clone()), Path(h)).await
    }

    #[tokio::test]
    async fn put_get_delete_policy_with_audit_and_notification() {
        let f = fx(true);
        let admin = ctx(None);
        let h = host(&f.state);
        let g = f
            .state
            .groups
            .create(&GroupScope::Platform, None, "g")
            .unwrap();
        f.state
            .groups
            .add_member(&GroupScope::Platform, g.group_id, h)
            .unwrap();
        let Json(v) = put(
            &f,
            &admin,
            g.group_id,
            json!({"telemetry_level": "MINIMAL"}),
        )
        .await
        .unwrap();
        assert_eq!(v["policy"]["telemetry_level"], "MINIMAL");
        let Json(v) = get_group_policy(
            Extension(admin.clone()),
            State(f.state.clone()),
            Path(g.group_id),
        )
        .await
        .unwrap();
        assert_eq!(v["policy"]["telemetry_level"], "MINIMAL");
        assert_eq!(*f.notes.0.lock().unwrap(), vec![h]);
        assert_eq!(
            delete_group_policy(
                Extension(admin.clone()),
                State(f.state.clone()),
                Path(g.group_id)
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        let Json(v) = get_group_policy(
            Extension(admin.clone()),
            State(f.state.clone()),
            Path(g.group_id),
        )
        .await
        .unwrap();
        assert!(v["policy"].is_null());
        assert_eq!(*f.notes.0.lock().unwrap(), vec![h, h]);
        let whats: Vec<String> = f
            .state
            .audit_log
            .read_all()
            .unwrap()
            .into_iter()
            .map(|e| e.what)
            .collect();
        assert_eq!(whats, vec!["group_policy_set", "group_policy_clear"]);
    }

    /// Delegates to the real store but cannot list a group's members.
    struct NoMemberLookup(Arc<SqliteHostRegistry>);
    impl PolicyStore for NoMemberLookup {
        fn get_policy(
            &self,
            scope: &GroupScope,
            group_id: Uuid,
        ) -> Result<Option<GroupPolicy>, GroupError> {
            self.0.get_policy(scope, group_id)
        }
        fn set_policy(
            &self,
            scope: &GroupScope,
            group_id: Uuid,
            policy: &GroupPolicy,
            updated_by: &str,
        ) -> Result<(), GroupError> {
            self.0.set_policy(scope, group_id, policy, updated_by)
        }
        fn clear_policy(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError> {
            self.0.clear_policy(scope, group_id)
        }
        fn policies_for_host(
            &self,
            host_id: Uuid,
        ) -> Result<Vec<osiris_policy::GroupPolicyInput>, GroupError> {
            self.0.policies_for_host(host_id)
        }
        fn all_host_policies(
            &self,
        ) -> Result<HashMap<Uuid, Vec<osiris_policy::GroupPolicyInput>>, GroupError> {
            self.0.all_host_policies()
        }
        fn hosts_of_group_raw(&self, _group_id: Uuid) -> Result<Vec<Uuid>, GroupError> {
            Err(GroupError::Backend("disk I/O error".into()))
        }
        fn record_delivery(&self, row: &DeliveryRow) -> Result<(), GroupError> {
            self.0.record_delivery(row)
        }
        fn delivery(&self, host_id: Uuid) -> Result<Option<DeliveryRow>, GroupError> {
            self.0.delivery(host_id)
        }
        fn all_deliveries(&self) -> Result<HashMap<Uuid, DeliveryRow>, GroupError> {
            self.0.all_deliveries()
        }
    }

    #[tokio::test]
    async fn a_failed_member_lookup_after_a_committed_change_still_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let notes = Arc::new(Recorder(Default::default(), true));
        let f = Fx {
            state: PolicyState {
                groups: db.clone(),
                policies: Arc::new(NoMemberLookup(db.clone())),
                registry: db.clone(),
                tenants: Arc::new(
                    osiris_tenancy::SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap(),
                ),
                audit_log: Arc::new(
                    osiris_audit::FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
                ),
                notifier: notes.clone(),
            },
            notes,
            _dir: dir,
        };
        let admin = ctx(None);
        let g = db.create(&GroupScope::Platform, None, "g").unwrap();
        let Json(v) = put(
            &f,
            &admin,
            g.group_id,
            json!({"telemetry_level": "MINIMAL"}),
        )
        .await
        .expect("stored and audited, so the PUT succeeds");
        assert_eq!(v["policy"]["telemetry_level"], "MINIMAL");
        assert_eq!(
            delete_group_policy(
                Extension(admin.clone()),
                State(f.state.clone()),
                Path(g.group_id)
            )
            .await
            .expect("cleared and audited, so the DELETE succeeds"),
            StatusCode::NO_CONTENT
        );
        assert!(f.notes.0.lock().unwrap().is_empty());
        assert_eq!(f.state.audit_log.read_all().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn invalid_policies_are_400_with_the_validation_message() {
        let f = fx(true);
        let g = f
            .state
            .groups
            .create(&GroupScope::Platform, None, "g")
            .unwrap();
        assert_eq!(
            put(
                &f,
                &ctx(None),
                g.group_id,
                json!({"sensors": {"dns": true}})
            )
            .await
            .unwrap_err(),
            (StatusCode::BAD_REQUEST, "unknown sensor: dns".to_string())
        );
        assert_eq!(
            put(
                &f,
                &ctx(None),
                g.group_id,
                json!({"heartbeat_interval_secs": 5})
            )
            .await
            .unwrap_err(),
            (
                StatusCode::BAD_REQUEST,
                "heartbeat_interval_secs must be between 10 and 3600".to_string()
            )
        );
        assert!(f.state.audit_log.read_all().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_tenant_policy_never_applies_to_another_tenants_host() {
        let f = fx(true);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let h = host(&f.state);
        f.state.tenants.assign_host(h, a).unwrap();
        let g = f
            .state
            .groups
            .create(&GroupScope::Tenant(a), None, "g")
            .unwrap();
        f.state
            .groups
            .add_member(&GroupScope::Tenant(a), g.group_id, h)
            .unwrap();
        let _ = put(
            &f,
            &ctx(Some(a)),
            g.group_id,
            json!({"telemetry_level": "FORENSIC"}),
        )
        .await
        .unwrap();
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["effective"]["telemetry_level"], "FORENSIC");
        f.state.tenants.assign_host(h, b).unwrap();
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert!(v["effective"]["telemetry_level"].is_null());
    }

    #[tokio::test]
    async fn tenants_see_platform_sources_as_opaque_and_their_own_by_name() {
        let f = fx(true);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let h = host(&f.state);
        f.state.tenants.assign_host(h, a).unwrap();
        let p = f
            .state
            .groups
            .create(&GroupScope::Platform, None, "P")
            .unwrap();
        f.state
            .groups
            .add_member(&GroupScope::Platform, p.group_id, h)
            .unwrap();
        let _ = put(
            &f,
            &ctx(None),
            p.group_id,
            json!({"telemetry_level": "MINIMAL"}),
        )
        .await
        .unwrap();
        let web = f
            .state
            .groups
            .create(&GroupScope::Tenant(a), None, "web")
            .unwrap();
        f.state
            .groups
            .add_member(&GroupScope::Tenant(a), web.group_id, h)
            .unwrap();
        let _ = put(
            &f,
            &ctx(Some(a)),
            web.group_id,
            json!({"heartbeat_interval_secs": 30}),
        )
        .await
        .unwrap();

        let Json(v) = view(&f, &ctx(Some(a)), h).await.unwrap();
        assert_eq!(v["sources"]["telemetry_level"], json!({"tier": "PLATFORM"}));
        assert_eq!(v["sources"]["heartbeat_interval_secs"]["tier"], "TENANT");
        assert_eq!(v["sources"]["heartbeat_interval_secs"]["group_name"], "web");
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["sources"]["telemetry_level"]["group_name"], "P");
        assert_eq!(
            v["sources"]["telemetry_level"]["group_id"],
            p.group_id.to_string()
        );
    }

    #[tokio::test]
    async fn host_policy_view_scoping_and_status() {
        let f = fx(false);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let h = host(&f.state);
        f.state.tenants.assign_host(h, a).unwrap();
        let not_found = (StatusCode::NOT_FOUND, "host not found".to_string());
        assert_eq!(view(&f, &ctx(Some(b)), h).await.unwrap_err(), not_found);
        assert_eq!(
            view(&f, &ctx(None), Uuid::new_v4()).await.unwrap_err(),
            not_found
        );
        assert_eq!(
            view(&f, &ctx(None), h).await.unwrap().0["status"],
            "UNMANAGED"
        );

        let f = fx(true);
        let h = host(&f.state);
        let g = f
            .state
            .groups
            .create(&GroupScope::Platform, None, "g")
            .unwrap();
        f.state
            .groups
            .add_member(&GroupScope::Platform, g.group_id, h)
            .unwrap();
        let _ = put(
            &f,
            &ctx(None),
            g.group_id,
            json!({"telemetry_level": "MINIMAL"}),
        )
        .await
        .unwrap();
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["status"], "PENDING");
        let desired = v["desired_hash"].as_str().unwrap().to_string();
        heartbeat(
            &f.state,
            h,
            crate::fleet::now_ns() + 1,
            Some(desired.clone()),
        );
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["status"], "IN_SYNC");
        assert_eq!(v["applied_hash"], desired);
    }

    #[tokio::test]
    async fn a_policy_on_another_tenants_group_is_404() {
        let f = fx(true);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let g = f
            .state
            .groups
            .create(&GroupScope::Tenant(a), None, "g")
            .unwrap();
        let nf = (StatusCode::NOT_FOUND, "group not found".to_string());
        let tb = ctx(Some(b));
        assert_eq!(
            get_group_policy(
                Extension(tb.clone()),
                State(f.state.clone()),
                Path(g.group_id)
            )
            .await
            .unwrap_err(),
            nf
        );
        assert_eq!(
            put(&f, &tb, g.group_id, json!({"telemetry_level": "MINIMAL"}))
                .await
                .unwrap_err(),
            nf
        );
        assert_eq!(
            delete_group_policy(Extension(tb), State(f.state.clone()), Path(g.group_id))
                .await
                .unwrap_err(),
            nf
        );
    }

    #[test]
    fn status_rules() {
        let empty = osiris_policy::empty_policy_hash_hex();
        let d = |hash: &str, r| DeliveryRow {
            host_id: Uuid::nil(),
            desired_hash: hash.into(),
            last_sent_at: 0,
            last_result: r,
            last_error: None,
        };
        assert_eq!(policy_status(false, "x", None, None), "UNMANAGED");
        assert_eq!(policy_status(true, &empty, None, None), "IN_SYNC");
        assert_eq!(policy_status(true, "x", Some("x"), None), "IN_SYNC");
        assert_eq!(policy_status(true, "x", None, None), "PENDING");
        assert_eq!(
            policy_status(true, "x", None, Some(&d("x", DeliveryResult::Refused))),
            "FAILED"
        );
        assert_eq!(
            policy_status(true, "x", None, Some(&d("old", DeliveryResult::Failed))),
            "PENDING"
        );
        assert_eq!(
            policy_status(true, "x", None, Some(&d("x", DeliveryResult::Offline))),
            "PENDING"
        );
    }

    #[tokio::test]
    async fn an_invalid_policy_on_another_tenants_group_is_404_not_400() {
        let f = fx(true);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let g = f
            .state
            .groups
            .create(&GroupScope::Tenant(a), None, "g")
            .unwrap();
        let nf = (StatusCode::NOT_FOUND, "group not found".to_string());
        let bad = json!({"sensors": {"dns": true}});
        assert_eq!(
            put(&f, &ctx(Some(b)), g.group_id, bad.clone())
                .await
                .unwrap_err(),
            nf
        );
        assert_eq!(
            put(&f, &ctx(None), Uuid::new_v4(), bad.clone())
                .await
                .unwrap_err(),
            nf
        );
        assert_eq!(
            put(&f, &ctx(Some(a)), g.group_id, bad).await.unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        assert!(f.state.audit_log.read_all().unwrap().is_empty());
    }
}
