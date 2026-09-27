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

pub(crate) fn internal(cause: String) -> ApiError {
    tracing::error!(error = %cause, "groups handler failure");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error".to_string(),
    )
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
        who: ActorRef::User {
            user_id: ctx.user_id,
        },
        what: what.to_string(),
        target: EntityRef::Domain { name: target },
        why: None,
        result: AuditResult::Success,
    });
}

/// `Some(set)` for a tenant caller (its current hosts), `None` for platform.
async fn caller_hosts(
    state: &GroupsState,
    ctx: &AuthContext,
) -> Result<Option<HashSet<Uuid>>, ApiError> {
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
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "unknown tenant".to_string(),
                ));
            }
        }
        _ => {}
    }
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    let (name, tenant_id) = (body.name, body.tenant_id);
    let group = run(move || store.create(&scope, tenant_id, &name)).await?;
    audit(
        &state,
        &ctx,
        "group_create",
        format!("group:{}", group.group_id),
    );
    Ok((StatusCode::CREATED, Json(group)))
}

async fn get_group(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<GroupsState>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupDetail>, ApiError> {
    let scope = scope_of(&ctx);
    let store = state.groups.clone();
    let (mut group, members) = run(move || {
        Ok((
            store.get(&scope, group_id)?,
            store.members(&scope, group_id)?,
        ))
    })
    .await?;
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
    let mut group = run(move || store.rename(&scope, group_id, &body.name)).await?;
    if let Some(allowed) = caller_hosts(&state, &ctx).await? {
        let store = state.groups.clone();
        let members = run(move || store.members(&scope, group_id)).await?;
        group.member_count = retain_allowed(members, Some(&allowed)).len() as u64;
    }
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
    audit(
        &state,
        &ctx,
        "group_member_add",
        format!("group:{group_id}/host:{host_id}"),
    );
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
    audit(
        &state,
        &ctx,
        "group_member_remove",
        format!("group:{group_id}/host:{host_id}"),
    );
    Ok(StatusCode::NO_CONTENT)
}

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

    async fn create(
        state: &GroupsState,
        c: &AuthContext,
        name: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<HostGroup, ApiError> {
        create_group(
            Extension(c.clone()),
            State(state.clone()),
            Json(CreateGroupBody {
                name: name.into(),
                tenant_id,
            }),
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
        add_member(
            Extension(admin.clone()),
            State(f.state.clone()),
            Path((g.group_id, h)),
        )
        .await
        .unwrap();
        let Json(detail) = get_group(
            Extension(admin.clone()),
            State(f.state.clone()),
            Path(g.group_id),
        )
        .await
        .unwrap();
        assert_eq!(detail.group.member_count, 1);
        assert_eq!(detail.members[0].hostname, "web-1");
        assert_eq!(detail.members[0].status, "ONLINE");
        let Json(renamed) = rename_group(
            Extension(admin.clone()),
            State(f.state.clone()),
            Path(g.group_id),
            Json(RenameGroupBody {
                name: "frontend".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(renamed.name, "frontend");
        remove_member(
            Extension(admin.clone()),
            State(f.state.clone()),
            Path((g.group_id, h)),
        )
        .await
        .unwrap();
        delete_group(
            Extension(admin.clone()),
            State(f.state.clone()),
            Path(g.group_id),
        )
        .await
        .unwrap();
        let whats: Vec<String> = f
            .state
            .audit_log
            .read_all()
            .unwrap()
            .into_iter()
            .map(|e| e.what)
            .collect();
        assert_eq!(
            whats,
            vec![
                "group_create",
                "group_member_add",
                "group_rename",
                "group_member_remove",
                "group_delete"
            ]
        );
    }

    #[tokio::test]
    async fn store_errors_map_to_the_spec_statuses_and_bodies() {
        let f = fx();
        let admin = ctx(None);
        create(&f.state, &admin, "web", None).await.unwrap();
        assert_eq!(
            create(&f.state, &admin, "web", None).await.unwrap_err(),
            (
                StatusCode::CONFLICT,
                "a group with this name already exists".to_string()
            )
        );
        assert_eq!(
            create(&f.state, &admin, "  ", None).await.unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        let missing = Uuid::new_v4();
        assert_eq!(
            get_group(
                Extension(admin.clone()),
                State(f.state.clone()),
                Path(missing)
            )
            .await
            .unwrap_err(),
            (StatusCode::NOT_FOUND, "group not found".to_string())
        );
        let g = create(&f.state, &admin, "db", None).await.unwrap();
        assert_eq!(
            add_member(
                Extension(admin.clone()),
                State(f.state.clone()),
                Path((g.group_id, Uuid::new_v4()))
            )
            .await
            .unwrap_err(),
            (StatusCode::UNPROCESSABLE_ENTITY, "unknown host".to_string())
        );
    }

    #[tokio::test]
    async fn tenant_users_cannot_see_or_touch_other_tenants_or_platform_groups() {
        let f = fx();
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let platform = create(&f.state, &ctx(None), "p", None).await.unwrap();
        let b_group = create(&f.state, &ctx(Some(b)), "b-group", None)
            .await
            .unwrap();
        let ta = ctx(Some(a));
        let Json(list) = list_groups(Extension(ta.clone()), State(f.state.clone()))
            .await
            .unwrap();
        assert!(list.is_empty());
        for gid in [platform.group_id, b_group.group_id] {
            let nf = (StatusCode::NOT_FOUND, "group not found".to_string());
            assert_eq!(
                get_group(Extension(ta.clone()), State(f.state.clone()), Path(gid))
                    .await
                    .unwrap_err(),
                nf
            );
            assert_eq!(
                rename_group(
                    Extension(ta.clone()),
                    State(f.state.clone()),
                    Path(gid),
                    Json(RenameGroupBody { name: "x".into() })
                )
                .await
                .unwrap_err(),
                nf
            );
            assert_eq!(
                delete_group(Extension(ta.clone()), State(f.state.clone()), Path(gid))
                    .await
                    .unwrap_err(),
                nf
            );
            assert_eq!(
                remove_member(
                    Extension(ta.clone()),
                    State(f.state.clone()),
                    Path((gid, Uuid::new_v4()))
                )
                .await
                .unwrap_err(),
                nf
            );
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
        assert_eq!(
            add_member(
                Extension(ta.clone()),
                State(f.state.clone()),
                Path((g.group_id, theirs))
            )
            .await
            .unwrap_err(),
            unknown
        );
        assert_eq!(
            add_member(
                Extension(ta.clone()),
                State(f.state.clone()),
                Path((g.group_id, unassigned))
            )
            .await
            .unwrap_err(),
            unknown
        );
        // Even a platform admin cannot put a foreign host into a tenant's group.
        assert_eq!(
            add_member(
                Extension(ctx(None)),
                State(f.state.clone()),
                Path((g.group_id, theirs))
            )
            .await
            .unwrap_err(),
            unknown
        );
        assert_eq!(
            add_member(
                Extension(ta.clone()),
                State(f.state.clone()),
                Path((g.group_id, mine))
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
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
        add_member(
            Extension(ta.clone()),
            State(f.state.clone()),
            Path((g.group_id, h)),
        )
        .await
        .unwrap();
        f.state.tenants.assign_host(h, b).unwrap();
        let Json(detail) = get_group(
            Extension(ta.clone()),
            State(f.state.clone()),
            Path(g.group_id),
        )
        .await
        .unwrap();
        assert!(detail.members.is_empty());
        assert_eq!(detail.group.member_count, 0);
        let Json(list) = list_groups(Extension(ta.clone()), State(f.state.clone()))
            .await
            .unwrap();
        assert_eq!(list[0].member_count, 0);
    }

    #[tokio::test]
    async fn tenant_id_in_the_body_is_400_for_tenant_users_and_checked_for_platform() {
        let f = fx();
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        assert_eq!(
            create(&f.state, &ctx(Some(a)), "x", Some(a))
                .await
                .unwrap_err(),
            (
                StatusCode::BAD_REQUEST,
                "tenant_id is not allowed for tenant users".to_string()
            )
        );
        assert_eq!(
            create(&f.state, &ctx(None), "x", Some(Uuid::new_v4()))
                .await
                .unwrap_err(),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "unknown tenant".to_string()
            )
        );
        let g = create(&f.state, &ctx(None), "x", Some(a)).await.unwrap();
        assert_eq!(g.tenant_id, Some(a));
        let Json(list) = list_groups(Extension(ctx(Some(a))), State(f.state.clone()))
            .await
            .unwrap();
        assert_eq!(
            list.len(),
            1,
            "a platform-created tenant group is visible to that tenant"
        );
    }

    #[tokio::test]
    async fn rename_re_filters_member_count_for_a_tenant_whose_host_was_reassigned() {
        let f = fx();
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let h = host(&f.state, "moving");
        f.state.tenants.assign_host(h, a).unwrap();
        let ta = ctx(Some(a));
        let g = create(&f.state, &ta, "g", None).await.unwrap();
        add_member(
            Extension(ta.clone()),
            State(f.state.clone()),
            Path((g.group_id, h)),
        )
        .await
        .unwrap();
        f.state.tenants.assign_host(h, b).unwrap();
        let Json(renamed) = rename_group(
            Extension(ta.clone()),
            State(f.state.clone()),
            Path(g.group_id),
            Json(RenameGroupBody { name: "g2".into() }),
        )
        .await
        .unwrap();
        assert_eq!(renamed.member_count, 0);
    }

    #[tokio::test]
    async fn failed_mutations_are_not_audited() {
        let f = fx();
        let _ = create(&f.state, &ctx(None), "", None).await;
        let _ = delete_group(
            Extension(ctx(None)),
            State(f.state.clone()),
            Path(Uuid::new_v4()),
        )
        .await;
        assert!(f.state.audit_log.read_all().unwrap().is_empty());
    }
}
