# Phase 8a — Multi-Tenant RBAC/Auth Foundation — Design

**Status:** approved (autonomous execution per standing user instruction, 2026-09-16 — see project memory `feedback-osiris-workflow`)
**Parent:** Phase 8 — Kubernetes/Cloud/Multi-host (`ARCHITECTURE.md` §29/§93), decomposed into 8a–8e. This is 8a, the prerequisite sub-phase: everything else in Phase 8 that needs authorization (8b Response Engine, 8c Fleet Manager) builds on this.
**Pre-agreed context:** `ARCHITECTURE.md` §14.3 (AuthN/AuthZ), §22 (Audit System, already implemented as `osiris-audit`), §10.3 (control-plane store), §21.5 (multi-tenant is an additive `tenant_id` dimension later, not a new authz system — explicitly deferred here, see Non-Goals).

## 1. Scope

Add local username/password authentication and role-based authorization to `osiris-api`, gating every route. Today all API routes are unauthenticated `GET`s — this phase closes that gap and lays the groundwork 8b's destructive Response Engine actions require (RBAC-gated dispatch, per §13).

## 2. Architecture

New crate `osiris-auth`, following this project's established one-crate-per-subsystem-store pattern (mirrors `osiris-evidence`'s `SqliteIncidentStore`/`IncidentStore` trait split, not a shared generic storage crate):

- `Role` enum: `Viewer`, `Analyst`, `ResponseOperator`, `Admin` (SCREAMING_SNAKE_CASE wire form, matching every other enum in this codebase, e.g. `EventType`). Ordered by increasing privilege for a route's `min_role` check (`role as u8 >= min_role as u8`); v1 has no route requiring more than `Viewer` except `/api/v1/audit` (`Admin`) — `Analyst`/`ResponseOperator` are defined now so 8b doesn't need to touch this enum.
- `User { user_id: Uuid, username: String, password_hash: String, role: Role, created_at: u64 }`.
- `Session { token: String, user_id: Uuid, issued_at: u64, expires_at: u64 }` — opaque 256-bit random token (32 bytes via `rand`, hex-encoded), not a JWT, matching §14.3's explicit v1 choice for immediate server-side revocability.
- `UserStore` trait + `SqliteUserStore` impl, own SQLite file (`users.db`, own `users`/`sessions` tables) — a separate control-plane-style store, matching this project's existing `incidents.db`/`evidence.db`/`links.db`/`baseline.db` precedent (§10.3's "separate `.db` files, still zero operational overhead") rather than inventing one shared control-plane database in this phase.
- Password hashing: `argon2` crate, Argon2id, default (OWASP-recommended) parameters.
- Session TTL: fixed 8 hours from issuance (`session_ttl_seconds` config field, default 28800) — no refresh-token complexity in v1.
- **First-run bootstrap:** if `SqliteUserStore::open()` finds an empty `users` table, it creates one `admin` user (role `Admin`) with a randomly generated password (24 random bytes, base64url-encoded) and returns it to the caller, who logs it once via `tracing::warn!` at server startup, clearly labeled as a one-time bootstrap credential to rotate. This avoids a chicken-and-egg problem (no CLI-direct-to-SQLite path exists in this codebase — `osiris-cli` talks to the API over HTTP, confirmed in `crates/osiris-cli/src/client.rs`) without needing an unauthenticated user-creation endpoint.

## 3. API changes (`osiris-api`)

New `auth` module:
- `POST /api/v1/auth/login { username, password } -> { token, role, expires_at }` — Argon2id verify, issue session, audit entry (`ActorRef::User{user_id}`, `AuditResult::Success`) on success; on failure, `ActorRef::System` with the attempted username in `why` (no user_id available), `AuditResult::Denied` — closes §22's named "auth failures" requirement.
- `POST /api/v1/auth/logout` — revokes the caller's session (deletes the row), audited.
- `GET /api/v1/auth/me -> { user_id, username, role }` — lets the Console bootstrap UI state without re-parsing the token client-side.
- `POST /api/v1/auth/users` (Admin-only) `{ username, password, role } -> { user_id }` — create additional users; audited.
- `GET /api/v1/auth/users` (Admin-only) — list users (no password hashes in the response).
- `GET /api/v1/audit` (Admin-only) — read-only paginated exposure of the existing `FileAuditLog`, per §22's explicit requirement (this endpoint was named in the architecture doc but never built).

`AuthLayer` (`tower::Layer`) wraps the whole router except `/api/v1/health` and `/api/v1/auth/login`:
- Extracts `Authorization: Bearer <token>`; missing/unknown/expired → `401 { "error": "unauthorized" }`.
- Valid session but role below the route's declared `min_role` → `403 { "error": "forbidden" }`.
- On success, injects `AuthContext { user_id, role }` into request extensions — every existing handler ignores it (nothing beyond `Viewer` is required today), but 8b's Response Engine and 8c's Fleet Manager mutation endpoints read this same extension rather than rebuilding an authz mechanism (matches §21.5's explicit instruction: "not a new authz system").
- A route's `min_role` is declared once, alongside its registration, as a small `(path, method) -> Role` table — independent of handler logic, matching §14.3's explicit requirement that "every RBAC decision is itself evaluable independent of any handler logic."
- All pre-existing GET routes get `min_role: Viewer` (i.e., any authenticated user can read investigation data — matches the roles' intent: `Viewer` is the read-only baseline, higher roles are additive for write/response actions in later sub-phases).

## 4. `osiris-cli` changes

- `osiris-cli auth login` — prompts for username/password (password via a hidden-input prompt, not a flag, to keep it out of shell history), calls `/auth/login`, writes the token to `~/.osiris/token` (created with `0600` permissions on Unix).
- `osiris-cli auth logout` — calls `/auth/logout`, deletes the local token file.
- Every other existing CLI command's HTTP client reads `~/.osiris/token` (or an `OSIRIS_TOKEN` env var override) if present and attaches `Authorization: Bearer <token>`; a `401` response from any command now prints "not authenticated — run `osiris-cli auth login`" instead of the raw HTTP error.
- `osiris-cli users create`/`users list` — thin wrappers over the new Admin-only endpoints, for creating users beyond the bootstrap admin.

## 5. Console changes

- New `Login` screen (username/password form), matching existing screen structure/styling conventions.
- New `authStore` (Zustand, matching the existing `uiStore` pattern) holds `{ token, role, username }` in memory, persisted to `sessionStorage` (not `localStorage` — a deliberate choice so a session doesn't silently outlive the browser tab on a shared machine).
- `client.ts`'s fetch wrapper adds the `Authorization` header to every request; any `401` clears `authStore` and redirects to `/login`.
- App shell: every route except `/login` requires `authStore.token` to be set, else redirect to `/login`.
- **Explicitly deferred:** no dedicated "Manage Users" Console screen this phase — `osiris-cli users create`/`users list` covers user administration for now, matching this project's established backend-then-Console-as-fast-follow pattern (e.g. Phase 7a→7b). Add one later only if the CLI proves insufficient in practice.

## 6. Error handling

- `401` for missing/invalid/expired token (Console: redirect to login; CLI: prompt to log in).
- `403` for a valid session below the route's `min_role`.
- Login failure (wrong username/password) always returns a generic `401 { "error": "invalid credentials" }` regardless of which part was wrong (no username enumeration), and is audited as `AuditResult::Denied`.
- Session cleanup: `SqliteUserStore` opportunistically deletes expired sessions on every `login`/session lookup call (no separate cron/background task needed at this scale).

## 7. Testing

- `osiris-auth`: unit tests for password hashing/verification, session issuance/expiry/revocation, bootstrap-admin-created-once-and-only-once-on-empty-table.
- `osiris-api`: integration tests for the `AuthLayer` (401 on missing/expired token, 403 on insufficient role, 200 with valid token; every pre-existing route still works once a valid token is supplied — a regression guard, since this phase changes the auth requirement of every existing endpoint).
- `osiris-cli`: unit tests for token-file read/attach logic (no live server needed, matching this crate's existing test style — see `client.rs`'s URL-building unit tests).
- Console: RTL tests for `Login` screen, `authStore`, and the fetch wrapper's 401-redirect behavior, matching the existing screen test conventions (`ProcessList.test.tsx` etc.).
- Manual e2e: login via CLI, confirm a previously-open route now requires the token; login via Console, confirm redirect-to-login on an expired/cleared session.

## 8. Non-Goals (explicitly deferred)

- **`tenant_id`/multi-tenant row-level scoping** — per §21.5, this is an additive dimension on the same RBAC roles "when multi-tenancy is needed," not required by anything built so far (single Server, single organization, today). Deferred until an actual multi-tenant requirement exists.
- **OIDC/SAML** — §14.3 explicitly scopes this to a later enterprise-deployment addition behind the same auth middleware interface; local Argon2id auth is the full v1 requirement.
- **Password reset / self-service account management / MFA** — not named in §14.3's v1 scope; `Admin`-created accounts and CLI-driven creation are sufficient for the current single-operator deployment model.
- **A Console "Manage Users" screen** — see §5 above.
- **Migrating existing alerts/risk_scores/rules-as-data into a shared control-plane store** — §10.3 names this store as eventually holding rules/incidents/alerts/evidence/audit/agent-registry, but today those already work via their own existing per-subsystem SQLite files (`events.db`, `incidents.db`, `evidence.db`). This phase adds `users.db` following that same established per-subsystem-store pattern; consolidating everything into one literal "control-plane store" is not required by anything in Phase 8 and is out of scope here.
