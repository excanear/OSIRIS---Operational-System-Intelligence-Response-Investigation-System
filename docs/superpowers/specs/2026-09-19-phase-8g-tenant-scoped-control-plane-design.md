# Phase 8g — Tenant scoping of Server-owned state (incidents, evidence, response)

## Goal
Phase 8f isolated event-derived data. Incidents, evidence and the response
engine were left platform-only (`tenant_route_allowed` denies them). 8g makes
them tenant-aware and allowlists them for tenant users.

## Design (approved by standing autonomy directive; recommended options)
- **Ownership tag, not separate DBs.** `Incident` and `Evidence` gain
  `tenant_id: Option<Uuid>` (`#[serde(default)]`, so existing rows deserialize
  as `None` = platform-owned). Same per-subsystem SQLite files.
- **Visibility rule.** Platform users see everything. A tenant user sees only
  records whose `tenant_id` equals theirs; `None`-tagged records are invisible
  to tenants. A foreign/invisible record answers **404**, never 403 (no
  existence oracle).
- **Creation.** Records created by a tenant user are tagged with their tenant.
  Platform-created records stay `None`.
- **Listing** is filtered inside the stores (`list_for_tenant`) *before* the
  5,000 cap, so one tenant cannot starve another's listing.
- **Links.** Linking evidence to an incident requires the caller to be able to
  see the incident; a tenant may only link evidence it owns to incidents it
  owns (else 404). `?incident_id=` evidence listing verifies incident
  visibility and filters each evidence record.
- **Response engine.** `dispatch` runs against a `TenantScopedStorage` for
  tenant callers (target resolution and collected events cannot leave the
  tenant's hosts); collected evidence is tagged with the tenant;
  `incident_id` must be visible to the caller. Uniform `ResponseOperator`
  role requirement unchanged.
- **Audit stays platform-only** (`/api/v1/audit`, tenant admin routes). The
  log is a single hash-chained file spanning tenants and platform events
  (logins, tenant admin); per-tenant audit views are deferred.
- **Route allowlist.** `tenant_route_allowed` additionally permits
  `/api/v1/incidents*`, `/api/v1/evidence` (GET/POST/PATCH as applicable) and
  `POST /api/v1/response/*`. `min_role_for` is unchanged.

## Non-goals / deferred
Per-tenant audit view; validating that an incident's `entities` belong to the
tenant's hosts (they are references only; reads are scoped); Console changes
beyond un-hiding Incidents/Evidence for tenants.

## Testing
Store-level `list_for_tenant`; handler-level cross-tenant 404s; response
tenant scoping; composed-router test proving tenant user 200 on own /
404 on foreign, and `/audit` still 403.
