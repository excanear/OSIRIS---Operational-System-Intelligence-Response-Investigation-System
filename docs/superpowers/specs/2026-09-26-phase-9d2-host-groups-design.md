# Phase 9d-2 — Host Groups (Fleet Manager, part 2)

Status: approved in brainstorming (2026-09-26). Predecessor: Phase 9d-1 (`2026-09-22-phase-9d1-fleet-manager-design.md`, agent registry + heartbeat). Successor: Phase 9d-3 (policy distribution to groups via the 9c command channel).

## 1. Context and goal

`ARCHITECTURE.md` §21.2 describes Fleet Manager as four pieces: agent registry, host groups, policy distribution, and an API/Console surface. 9d-1 shipped the registry (`osiris-fleet`'s `HostRegistry`, `hosts.db`, `GET /api/v1/hosts`). This phase ships **host groups**: operator-managed, named sets of registered hosts, scoped to a tenant (or to the platform), managed via API, CLI and a new Console screen. Groups are the targeting unit Phase 9d-3's policy distribution will use; this phase adds no policy, no command, and no agent change.

Success: an Admin can create a group, add/remove registered hosts, see each member's live ONLINE/STALE status, and filter the Hosts screen by group — and a tenant user can never see, touch, or infer the existence of another tenant's groups or hosts.

## 2. Decisions (from brainstorming)

| # | Decision | Chosen |
|---|---|---|
| D1 | Split of remaining Fleet Manager | 9d-2 = groups; 9d-3 = policy distribution to groups |
| D2 | Membership model | Manual (explicit add/remove), a host may belong to many groups |
| D3 | Tenancy | Each group belongs to exactly one tenant, or to the platform (`tenant_id` NULL) |
| D4 | Console scope | New Groups screen (list + detail/management) + Groups column and `?group=` filter on Hosts |
| D5 | Storage location | Inside `osiris-fleet`, same `hosts.db` and SQLite connection as `SqliteHostRegistry` (approach A) |

## 3. Data model (`osiris-fleet`)

### 3.1 Schema

Created in `hosts.db` alongside the existing `hosts` table, by the same open path:

```sql
CREATE TABLE IF NOT EXISTS host_groups (
    group_id   TEXT PRIMARY KEY,   -- UUID v4, server-generated
    name       TEXT NOT NULL,
    tenant_id  TEXT NULL,          -- UUID; NULL = platform group
    created_at INTEGER NOT NULL    -- ns since Unix epoch, server clock
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_groups_scope_name
    ON host_groups(COALESCE(tenant_id, ''), name);

CREATE TABLE IF NOT EXISTS host_group_members (
    group_id TEXT NOT NULL REFERENCES host_groups(group_id) ON DELETE CASCADE,
    host_id  TEXT NOT NULL REFERENCES hosts(host_id),
    added_at INTEGER NOT NULL,     -- ns since Unix epoch, server clock
    PRIMARY KEY (group_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_host_group_members_host ON host_group_members(host_id);
```

- `PRAGMA foreign_keys = ON` is executed on every connection open. SQLite defaults it OFF; without it the cascade and the unknown-host rejection silently do nothing. A test must prove both are enforced.
- The unique index uses `COALESCE(tenant_id, '')` because SQLite treats NULLs as distinct in UNIQUE constraints; without it two platform groups could share a name.
- **Schema versioning:** `hosts.db` gains `PRAGMA user_version`. Open logic: read `user_version`; run the idempotent `CREATE ... IF NOT EXISTS` batch (hosts + groups); set `user_version = 1`. A 9d-1-era `hosts.db` (user_version 0, `hosts` table present, no group tables) opens cleanly, keeps its rows, and gains the group tables. A `user_version` greater than the known maximum fails the open with a clear error (never silently downgrade). This closes 9d-1's deferred "no `user_version`" minor.

### 3.2 Validation

- `name`: trimmed; 1–64 Unicode scalar values after trimming; no control characters (`char::is_control`). Stored trimmed.
- Uniqueness: per tenant, and among platform groups (index above). The same name may exist in different tenants.
- `group_id`, `tenant_id`, `host_id` are UUIDs; path parameters that do not parse as UUIDs are rejected by the API with 400 before reaching the store.

### 3.3 Store interface

```rust
pub enum GroupScope { Platform, Tenant(Uuid) }

pub struct HostGroup {
    pub group_id: Uuid,
    pub name: String,
    pub tenant_id: Option<Uuid>,
    pub created_at: u64,        // ns since Unix epoch
    pub member_count: u64,
}

pub struct GroupRef { pub group_id: Uuid, pub name: String }

pub trait HostGroupStore: Send + Sync {
    fn create(&self, scope: &GroupScope, tenant_id: Option<Uuid>, name: &str) -> Result<HostGroup, GroupError>;
    fn list(&self, scope: &GroupScope) -> Result<Vec<HostGroup>, GroupError>;
    fn get(&self, scope: &GroupScope, group_id: Uuid) -> Result<HostGroup, GroupError>;
    fn rename(&self, scope: &GroupScope, group_id: Uuid, name: &str) -> Result<HostGroup, GroupError>;
    fn delete(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError>;
    fn add_member(&self, scope: &GroupScope, group_id: Uuid, host_id: Uuid) -> Result<(), GroupError>;
    fn remove_member(&self, scope: &GroupScope, group_id: Uuid, host_id: Uuid) -> Result<(), GroupError>;
    fn members(&self, scope: &GroupScope, group_id: Uuid) -> Result<Vec<Uuid>, GroupError>;
    fn groups_of(&self, scope: &GroupScope, host_ids: &[Uuid]) -> Result<HashMap<Uuid, Vec<GroupRef>>, GroupError>;
}

pub enum GroupError { InvalidName(String), NotFound, DuplicateName, UnknownHost, Backend(String) }
```

Scope semantics — enforced **inside the SQL**, never by post-filtering:

- `GroupScope::Tenant(t)`: every query carries `WHERE tenant_id = t`. A `group_id` that exists but belongs to another tenant or the platform yields `NotFound` (indistinguishable from nonexistent). `create` ignores its `tenant_id` argument and always uses `t`.
- `GroupScope::Platform`: sees and manages every group. `create` uses the `tenant_id` argument (`None` = platform group).
- `add_member` is idempotent (`INSERT OR IGNORE`); `remove_member` of a non-member is a no-op success (the group itself must still be in scope, else `NotFound`).
- `add_member` of a `host_id` not present in `hosts` → `UnknownHost` (foreign-key failure mapped).
- `delete` removes the group and, via cascade, its memberships. Hosts are never deleted by this phase.
- `DuplicateName` maps the unique-index violation on create and rename.

`SqliteHostGroupStore` shares the single `Mutex<Connection>` with `SqliteHostRegistry` (one opened `hosts.db` handle serving both traits — e.g. one `SqliteFleetDb` struct implementing both `HostRegistry` and `HostGroupStore`), so the foreign key to `hosts` is real and there is one writer. `main.rs` constructs it once and hands the same `Arc` to the ingest hook, the fleet router and the groups router.

The **tenant-ownership check for members is not in the store** (it lives in `tenants.db`); see §4.3.

## 4. API (`osiris-api`)

### 4.1 Routes

New `build_groups_router(state)` merged in `main.rs` (and in the composed-router test harnesses and e2e) **before** `.layer(auth_gate)`, exactly like `build_fleet_router`.

| Method | Path | Min role | Behavior |
|---|---|---|---|
| GET | `/api/v1/groups` | Viewer | `[{group_id, name, tenant_id, created_at, member_count}]`, sorted by name then group_id |
| POST | `/api/v1/groups` | Admin | body `{name, tenant_id?}` → 201 + group |
| GET | `/api/v1/groups/{group_id}` | Viewer | group + `members: [{host_id, hostname, status, agent_version, last_seen}]` (status per 9d-1's ONLINE/STALE rule) |
| PATCH | `/api/v1/groups/{group_id}` | Admin | body `{name}` → 200 + group |
| DELETE | `/api/v1/groups/{group_id}` | Admin | 204 |
| PUT | `/api/v1/groups/{group_id}/members/{host_id}` | Admin | 204 (idempotent) |
| DELETE | `/api/v1/groups/{group_id}/members/{host_id}` | Admin | 204 (idempotent) |

`GET /api/v1/hosts` changes (additive, backward compatible):
- each row gains `groups: [{group_id, name}]` — only groups in the caller's scope, sorted by name;
- optional `?group={group_id}` filter: only hosts that are members of that group. A group out of scope or nonexistent → 404 (same body as the groups routes). Tenant host filtering still applies on top.

### 4.2 Authorization

- `min_role_for`: `GET`/`HEAD` on `/api/v1/groups` and `/api/v1/groups/{id}` → Viewer; every other method under `/api/v1/groups` → Admin.
- `tenant_route_allowed` gains **exact** entries (default-deny stays): GET/HEAD `/api/v1/groups` and `/api/v1/groups/{one segment}`; POST `/api/v1/groups`; PATCH and DELETE `/api/v1/groups/{one segment}`; PUT and DELETE `/api/v1/groups/{one segment}/members/{one segment}`. No generic prefix match. PUT/DELETE are new methods in the allowlist and must be limited to exactly these shapes.
- Scope derivation: `AuthContext.tenant_id = Some(t)` → `GroupScope::Tenant(t)`; `None` → `GroupScope::Platform`.
- `tenant_id` in the POST body: from a tenant user → **400** (`tenant_id is not allowed for tenant users`) — explicit rather than silently ignored; from a platform Admin → must name an existing tenant (checked via `TenantStore`), else 422 `unknown tenant`.

### 4.3 Member tenant check

`PUT .../members/{host_id}`:
1. Group must be in scope (store `get` → else 404).
2. If the **group** has `tenant_id = Some(t)`: the host must be in `hosts_of_tenant(t)` (existing helper in `tenant_scope.rs`); otherwise **422 `unknown host`** — identical body to a host absent from the registry, so a tenant cannot probe for other tenants' hosts. Platform groups accept any registered host.
3. `add_member` (foreign key → 422 `unknown host`).

Because steps 2 and 3 span two databases, a host could change tenant between them. Reads therefore re-filter: for a tenant-owned group, `GET /groups/{id}` members, `member_count`, `/hosts?group=` and the `groups` field only include hosts currently in that tenant's host set. A stale membership row is harmless and invisible; it becomes visible again only if the host returns to that tenant. (Platform callers see raw membership.)

### 4.4 Errors

| Status | When | Body |
|---|---|---|
| 400 | invalid name; malformed UUID in path; `tenant_id` in body from tenant user | message |
| 404 | group nonexistent or out of scope | `group not found` |
| 409 | duplicate name in scope | `a group with this name already exists` |
| 422 | host not registered or not in the group's tenant; unknown tenant on create | `unknown host` / `unknown tenant` |
| 500 | store/tenant-store failure | generic message; SQLite text only in server logs |

All store calls run in `tokio::task::spawn_blocking`; `JoinError` → 500 and logged.

### 4.5 Audit

Every successful mutation appends an `osiris_audit::NewAuditEntry` via `audit_log.append`, following `tenants.rs`'s `audit(...)` helper: actions `group.create`, `group.rename`, `group.delete`, `group.member_add`, `group.member_remove`; target includes the group_id (and host_id for member actions). Failed attempts rejected with 4xx are not audited (same as tenant administration).

## 5. CLI (`osiris-cli`)

New `group` subcommand family, mirroring `tenant`:

```
osiris group list
osiris group create <name> [--tenant <tenant_id>]
osiris group show <group_id>
osiris group rename <group_id> <name>
osiris group delete <group_id>
osiris group add-host <group_id> <host_id>
osiris group remove-host <group_id> <host_id>
```

Path segments are percent-encoded (existing helper). Output format matches existing `tenant list`/`hosts`-style tables.

## 6. Console

### 6.1 Groups screen

- Nav entry "Groups" next to "Hosts"; routes `/groups` and `/groups/:groupId`.
- **List:** table — name, tenant (column shown only to platform users; "platform" when NULL), members, created. Row click → detail. "New group" button (Admin only) opens an inline form with the name field; submit → POST, invalidate list.
- **Detail:** header with name; Admin-only **Rename** (inline field → PATCH) and **Delete** (in-page two-step confirmation, never `window.confirm`). Members table — hostname, status (ONLINE/STALE badge as on Hosts), agent version, last seen, Admin-only **Remove** per row. Admin-only **Add host**: a select of registry hosts (from `/api/v1/hosts`, already tenant-filtered) not yet in the group → PUT.
- Admin-ness from `/api/v1/auth/me`'s role. Non-Admins see everything read-only. The API remains the enforcement point.
- Errors map to inline messages: 409 "a group with this name already exists", 422 "unknown host", 404 → "group not found" empty state.
- Data via React Query as in existing screens; mutations invalidate `groups` list, the group detail, and `hosts`.

### 6.2 Hosts screen

- New **Groups** column: group names as links to `/groups/:groupId`.
- `?group=<id>` URL parameter passed through to the API; when active, a banner "Filtered by group <name> ✕" clears it.

## 7. Testing

- **Store (`osiris-fleet`):** create/rename/delete; duplicate name → `DuplicateName` within a tenant and among platform groups (COALESCE case); same name allowed across tenants; `Tenant(A)` cannot get/rename/delete/add/remove/list B's or platform groups (`NotFound`); `create` under `Tenant(t)` ignores the passed tenant_id; add unknown host → `UnknownHost` (proves foreign keys ON); delete cascades memberships (proves cascade); add is idempotent; `groups_of` respects scope; name validation edge cases (empty, whitespace-only, 64 vs 65 chars, control char); opening a 9d-1-era `hosts.db` (user_version 0, hosts rows) preserves rows and adds group tables; future `user_version` fails open.
- **API handlers:** role matrix per route; tenant isolation for every route (another tenant's group → 404; platform group invisible to tenant); cross-tenant host add → 422 with the same body as unregistered host; tenant POST with `tenant_id` → 400; platform POST with unknown tenant → 422; re-filtering after a host changes tenant; `/hosts?group=` and `groups` field scoped; audit entries for each mutation; malformed UUID → 400.
- **Composed router** (`composed_router_auth.rs`, `composed_router_tenancy.rs`): new routes behind the real `auth_gate`; tenant PUT/DELETE allowed only on the exact shapes (e.g. `/api/v1/groups/x/members/y/z` and `/api/v1/groups/x/other` denied).
- **CLI:** clap parsing for each `group` subcommand.
- **Console:** list render; create/rename/delete/add/remove flows with a mocked API client; Admin-only controls hidden for Viewer; error messages; Hosts Groups column links and `?group=` banner.
- **e2e:** real Agent heartbeats register the host → create group → add host → `/hosts?group=` returns it ONLINE with its group in `groups` → remove → filter returns empty.

## 8. Review focus

1. Cross-tenant leakage by `group_id`: scope must be in the SQL of every store method, not applied after fetching.
2. Tenant boundary on member add (§4.3) and the read-side re-filter for hosts that changed tenant.
3. `tenant_route_allowed`: only the exact new method+path shapes; PUT/DELETE newly allowed must not open anything else.
4. `PRAGMA foreign_keys = ON` actually in effect on the shared connection (cascade and unknown-host both tested).
5. `user_version` migration: 9d-1 databases open and keep data; unknown future version refuses.

## 9. Non-Goals (deferred)

- Policy distribution (telemetry level / sensor config push) and any new `CommandAction` — Phase 9d-3.
- Dynamic / rule-based group membership.
- Per-host or per-group staleness threshold.
- Nested groups.
- Group-level RBAC (users restricted to a group).
- Automatic membership cleanup on host removal (the registry never removes hosts yet).
- Bulk member add/remove endpoints.
