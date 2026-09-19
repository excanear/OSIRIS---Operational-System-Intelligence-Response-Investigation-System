use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditResult, NewAuditEntry};
use osiris_schema::EntityRef;
use osiris_tenancy::{Tenant, TenantStoreError};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthState;
use crate::auth_middleware::AuthContext;

pub fn build_tenant_router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/api/v1/tenants",
            get(list_tenants_handler).post(create_tenant_handler),
        )
        .route(
            "/api/v1/tenants/:tenant_id/hosts/:host_id",
            put(assign_host_handler).delete(unassign_host_handler),
        )
        .with_state(state)
}

/// Defense in depth: the auth gate already 403s tenant users on these
/// routes, but a tenant user must never manage tenants even if the gate's
/// allowlist were ever loosened.
fn platform_only(ctx: &AuthContext) -> Result<(), (StatusCode, String)> {
    if ctx.tenant_id.is_some() {
        return Err((StatusCode::FORBIDDEN, "platform users only".to_string()));
    }
    Ok(())
}

fn store_error(e: TenantStoreError) -> (StatusCode, String) {
    match e {
        TenantStoreError::DuplicateName(_) | TenantStoreError::InvalidName(_) => {
            (StatusCode::BAD_REQUEST, e.to_string())
        }
        TenantStoreError::UnknownTenant(_) => (StatusCode::NOT_FOUND, e.to_string()),
        TenantStoreError::Backend(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

fn audit(state: &AuthState, ctx: &AuthContext, what: &str, target: String) {
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

#[derive(Debug, Deserialize)]
struct CreateTenantBody {
    name: String,
}

async fn create_tenant_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<CreateTenantBody>,
) -> Result<Json<Tenant>, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    let tenant = tokio::task::spawn_blocking(move || tenants.create_tenant(&body.name))
        .await
        .unwrap()
        .map_err(store_error)?;
    audit(
        &state,
        &ctx,
        "tenant_create",
        format!("tenant:{}", tenant.name),
    );
    Ok(Json(tenant))
}

async fn list_tenants_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<Tenant>>, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    let all = tokio::task::spawn_blocking(move || tenants.list_tenants())
        .await
        .unwrap()
        .map_err(store_error)?;
    Ok(Json(all))
}

async fn assign_host_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
    Path((tenant_id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    tokio::task::spawn_blocking(move || tenants.assign_host(host_id, tenant_id))
        .await
        .unwrap()
        .map_err(store_error)?;
    audit(
        &state,
        &ctx,
        "tenant_assign_host",
        format!("tenant:{tenant_id}/host:{host_id}"),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn unassign_host_handler(
    State(state): State<AuthState>,
    Extension(ctx): Extension<AuthContext>,
    Path((tenant_id, host_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    platform_only(&ctx)?;
    let tenants = state.tenants.clone();
    // The host must actually belong to the tenant named in the URL.
    let owner = {
        let tenants = tenants.clone();
        tokio::task::spawn_blocking(move || tenants.tenant_of(host_id))
            .await
            .unwrap()
            .map_err(store_error)?
    };
    if owner != Some(tenant_id) {
        return Err((
            StatusCode::NOT_FOUND,
            "host is not assigned to that tenant".to_string(),
        ));
    }
    tokio::task::spawn_blocking(move || tenants.unassign_host(host_id))
        .await
        .unwrap()
        .map_err(store_error)?;
    audit(
        &state,
        &ctx,
        "tenant_unassign_host",
        format!("tenant:{tenant_id}/host:{host_id}"),
    );
    Ok(StatusCode::NO_CONTENT)
}
