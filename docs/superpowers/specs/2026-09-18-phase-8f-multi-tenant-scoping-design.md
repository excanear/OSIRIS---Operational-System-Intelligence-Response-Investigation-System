# Phase 8f: Multi-Tenant Scoping — Design

Date: 2026-09-18. Status: approved in chat (3 design sections), pending written-spec review.
Source: ARCHITECTURE.md §21.5 (Centralized SOC: RBAC "extends with a `tenant_id`/`host_group` scoping
dimension when multi-tenancy is needed, not a new authz system"), §14.3 (RBAC), §93 (Phase 8).
Predecessors: 8a (RBAC/auth, `auth_gate`, `min_role_for`), 8c (Host Registry).

## 1. Scope

Phase 8 decomposition: 8a RBAC/auth, 8b Response Engine v1, 8c Host Registry, 8d Cloud metadata,
8e Kubernetes context, **8f (this phase): tenant scoping of event-derived data**, 8g (follow-up) scoping
of Server-owned state (incidents, evidence, audit, response).

Decisions made during brainstorming:
1. **Event → tenant attribution is server-side** (`host_id → tenant_id` registry), not agent-asserted.
   The Agent→Server transport is a local spool file with no agent authentication, so an agent
   claiming its own tenant would be unverifiable.
2. **A user belongs to at most one tenant; a user with no tenant is a platform user** who sees all
   tenants and is the only one who manages tenants and host assignment. Existing roles
   (Viewer < Analyst < ResponseOperator < Admin) apply unchanged within a tenant.
3. **Two-step delivery.** 8f isolates every event-derived surface. Incidents, evidence, audit and
   response are `PlatformOnly` (403 for tenant users) until 8g, so isolation is never silently partial.
4. **Enforcement is one decorator over `Storage`**, applied per request, not per-handler filtering
   and not a `tenant_id` column stamped on rows (a reassigned host would need a rewrite).

## 2. Data model

New crate `osiris-tenancy` (pure logic, one SQLite file `tenants.db`, same per-subsystem-store
pattern as `users.db`/`incidents.db`):
- `Tenant { tenant_id: Uuid, name: String, created_at: u64 }`, `name` unique.
- Table `host_tenants(host_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)`: a host belongs to at most one
  tenant; reassignment is an `UPDATE`.
- `trait TenantStore`: `create_tenant`, `list_tenants`, `assign_host`, `unassign_host`,
  `hosts_of(tenant_id) -> HashSet<Uuid>`, `tenant_of(host_id) -> Option<Uuid>`. SQLite impl
  `SqliteTenantStore`. Migrations are guarded and idempotent.

`osiris-auth`:
- `users.tenant_id TEXT NULL` via a guarded `ALTER TABLE` (existing idiom). Existing users stay
  `NULL` = platform.
- The session and `AuthContext` (`crates/osiris-api/src/auth_middleware.rs`) carry
  `tenant_id: Option<Uuid>`.
- User creation accepts an optional `tenant_id`; only a platform Admin may create users or set it.

Visibility semantics: a tenant user sees only events whose `host_id` is assigned to their tenant. An
unassigned host is visible to platform users only. Reassigning a host changes visibility
retroactively (the filter is evaluated per request, not stored on rows).

## 3. Enforcement

`crates/osiris-api/src/tenant_scope.rs`:
- `ScopedStorage` is an axum extractor (`FromRequestParts`) that reads `AuthContext` and returns an
  `Arc<dyn Storage>`. Platform user → the shared storage unchanged. Tenant user →
  `TenantScopedStorage` holding the tenant's host set, read from the `TenantStore` once per request.
- `TenantScopedStorage` implements `Storage`:
  - `query`, `query_alerts`, `query_risk_scores`: add `host_id IN set`.
  - `query_events`: AND a `host_id` membership node into the `EventQueryPlan` AST (reusing OQL).
  - `get_event`: `None` when the event's host is outside the set (indistinguishable from absent).
  - `query_relationships`: resolve each edge's `event_id` to its host and drop edges outside the set.
  - `write`, `batch_write`, `write_alerts`, `write_relationships`, `write_risk_scores`, `delete`,
    `retention_apply`: return an error (read handlers never call them).
  - An empty host set yields an empty result, never "no filter".
- All ~20 handlers switch from `State<Arc<dyn Storage>>` to `ScopedStorage` (mechanical).
- `/api/v1/hosts` filters its rows by the host set. `/api/v1/health` is unchanged.
- WebSocket `/api/v1/stream/events`: `LiveEventBroadcaster` gets the host set at subscribe time and
  filters per connection; a requested `host_id` outside the set → 403.
- **Deny-by-default:** `min_role_for` returns a role and a `Scope::{Any, PlatformOnly}`. Incidents,
  evidence, audit, response, users and tenants are `PlatformOnly`; a tenant user gets 403. A test
  walks every registered route and fails if any has no declared scope.
- Failure handling: an unreadable `TenantStore` fails the request closed with 500 and never falls
  back to the unscoped storage. A resource outside the tenant returns 404 (not 403) so its existence
  is not revealed; a `PlatformOnly` route returns 403 (the route itself is not secret).

## 4. Surfaces added

- API (platform Admin only): `POST/GET /api/v1/tenants`, `PUT/DELETE /api/v1/tenants/:id/hosts/:host_id`.
- CLI: `tenants create|list`, `tenants assign-host`, `users create --tenant`.
- Console: tenant users do not see `PlatformOnly` menu items; the tenant name shows in the header.
  No tenant-management screen this phase.
- Server `main.rs` wires `SqliteTenantStore` (`tenants_db_path`, default `/var/lib/osiris/tenants.db`)
  into the composed router and `AuthState`.

## 5. Testing

- `osiris-tenancy`: store CRUD, name uniqueness, host reassignment, idempotent migration.
- `TenantScopedStorage`: per filtered method a two-tenants-plus-unassigned-host test; empty set →
  empty result; also run against a real `SqliteStorage`, not only a mock.
- Composed router (style of `composed_router_auth.rs`): tenant A user gets A's data and none of B's on
  every event route; 403 on `PlatformOnly` routes; platform user sees all; unassigned host hidden
  from tenants.
- Route-scope coverage test (above).
- WebSocket: tenant client receives only its hosts' events; foreign `host_id` → 403.
- E2E: the existing scenario gains a second tenant. All `osiris-e2e-tests` composition stays
  authenticated as in 8a.

## 6. Non-goals (explicit)

Scoping incidents/evidence/audit/response (8g); a user in several tenants; tenant-management Console
screen; `tenant_id` stamped on events or rows; per-tenant quotas; automatic host→tenant assignment;
OIDC/SAML.

## 7. Risks for the final review

The WebSocket path (the only surface filtered in a different code path); any handler reaching storage
outside the extractor; relationship-edge filtering via `event_id` (cost on large edge sets).
