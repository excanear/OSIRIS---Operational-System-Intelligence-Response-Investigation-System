# Phase 7b-1: Web Console Foundation — Design

**Companion:** this spec covers only the foundation slice of the Web Console
(ARCHITECTURE.md §16). The full Console has 13 screens (§16.3); this phase
ships the app shell plus the two simplest screens (Overview, Sensors) and
the plumbing every later screen depends on. The remaining screens are
scoped into three follow-on sub-phases:

- **7b-2 Event Exploration** — Live Events, Process Explorer, Filesystem,
  Network, Containers, Timeline (share the virtualized-table and timeline
  components).
- **7b-3 Triage/Cases** — Alerts, Incidents, Evidence.
- **7b-4 Hunting + Entity Graph** — Threat Hunting, Entity Graph (the query
  builder and force-directed graph rendering, the most novel/complex UI
  work, deliberately last).

This is the same shape of split the project already used for Phase 4
(4a/4b) and Phase 7 itself (7a/7b): independent-enough pieces, ordered so
later phases build on infrastructure the earlier ones establish.

## Why start with Foundation, Overview, Sensors

Every other screen needs the app shell (routing, nav, layout, shared
state store) and the API-client pattern to exist first. Overview and
Sensors are the cheapest real screens to validate that plumbing against —
both are read-only, low-interaction, and (per the backend investigation
below) require zero backend changes beyond one CORS addition.

## Backend state investigated (no new backend endpoints needed)

- No auth/RBAC/session middleware exists in `osiris-api` today (grepped
  `crates/osiris-api/src/*.rs` — the only "session" hits are
  `SessionRef`/`session_id` on host login events, unrelated to Console
  user auth). ARCHITECTURE.md §14.3's RBAC is not yet built.
- No OpenAPI/utoipa instrumentation exists on `osiris-api` — §26's
  "OpenAPI-generated API client" is aspirational, not yet true.
- No static-asset serving or CORS layer exists on `osiris-server`.
- `EventType::AgentHealth` / `EventType::SensorHealth` already exist in
  `osiris-schema` (`Category::System`), and `/api/v1/events` already
  supports an `event_type` filter (and free-form OQL via `q`). So the
  Sensors screen's per-agent/per-sensor rollup can be computed **client-side**
  from `GET /api/v1/events?event_type=SensorHealth` (latest event per
  `(host, sensor_name)`, worst-state-wins — mirroring
  `osiris-health::HealthAggregator`'s own logic) without any new backend
  endpoint. The Agent-side `HealthAggregator` aggregates for Agent-local
  reporting; the Console does the equivalent aggregation across the
  events already flowing through the pipeline.
- Existing endpoints Overview needs already exist: `/api/v1/health`
  (storage health + event_count), `/api/v1/events`, `/api/v1/alerts`,
  `/api/v1/incidents` (list, from `osiris-api/src/incidents.rs`).

## Explicitly out of scope for 7b-1 (deferred, not forgotten)

- **Auth/login.** No backend auth exists; the Console calls the API
  directly, unauthenticated, matching the rest of the system today. A
  real login screen requires backend auth/RBAC work first — that's a
  future phase spanning both `osiris-api` and the Console, not something
  to half-build here.
- **Generated OpenAPI client.** The API client is hand-written
  TypeScript (`console/src/api/`) for the handful of endpoints this
  phase needs. Instrumenting `osiris-api` with utoipa/aide and generating
  a TS client from a real OpenAPI spec is a separate future task, taken
  on when the endpoint count justifies the investment.
- **Production static serving.** `osiris-server` does not embed/serve
  `console/dist/` in this phase. Dev only: Vite dev server with a proxy.
  Wiring `ServeDir` (or equivalent) into `osiris-server` for a real build
  artifact is a future task.
- **Playwright e2e.** Vitest + React Testing Library only. Browser e2e is
  deferred until there are enough real user flows (7b-2+) to make it
  worth the infra.
- **The other 11 screens** — 7b-2/7b-3/7b-4 as above.

## Stack (ARCHITECTURE.md §16.1)

- **Vite + React + TypeScript**, new `console/` directory at repo root
  (already reserved in ARCHITECTURE.md §24's module structure).
- **TanStack Query** for all REST data-fetching/caching.
- **Zustand** for cross-cutting UI state (selected entity, active time
  range, active filters) — created now even though no 7b-1 screen needs
  cross-screen selection sharing yet, because §16.1 requires it before
  Process Explorer/Timeline/Entity Graph (7b-2/7b-4) can share a
  selection, and the store's shape is cheap to get right early and
  expensive to retrofit once multiple screens read from it.
- **react-router** for screen routing.
- Dark-first, information-dense, monospace/technical typography for data
  fields, fixed left-nav enumerating all 13 §16.3 screens (11 of them
  disabled/"coming soon" until their sub-phase ships) — per §16.2's
  explicit "not a general admin-dashboard template" direction.

## Screens and components (this phase)

- **App shell**: root layout, fixed left-nav (all 13 screens listed;
  Overview and Sensors are the only enabled links), `ErrorBoundary`
  around the routed content.
- **API client** (`console/src/api/`): typed `fetch` wrappers + TanStack
  Query hooks for `GET /api/v1/health`, `GET /api/v1/events` (with
  `event_type` param support), `GET /api/v1/alerts`, `GET
  /api/v1/incidents`.
- **Overview screen**: storage health (from `/health`), and aggregate
  counts (events, alerts, incidents) from the respective list endpoints.
- **Sensors screen**: per-agent/per-sensor health table, derived
  client-side from `SensorHealth`/`AgentHealth` events as described
  above — sensor name, state (Healthy/Degraded/Failed), last-event time,
  `last_error` when present (§23's "no generic unhealthy" requirement
  surfaces directly since the schema already carries it).
- **CORS**: `osiris-server` gets a dev-only permissive CORS layer (via
  `tower-http::cors`) gated behind a debug/dev config flag or `cfg!` —
  never enabled unconditionally in a way that would ship an open-CORS
  production server. Exact gating mechanism (env var vs. config flag) is
  an implementation-time decision, not a design fork.

## Error handling

- Network/5xx failures surface as an inline error state per-screen (TanStack
  Query's per-query error state), never a blank screen or uncaught
  exception.
- The root `ErrorBoundary` catches render-time exceptions in routed
  content and shows a fallback, isolated from the nav shell so navigation
  still works after a screen-level crash.

## Testing

- **Vitest + React Testing Library**: API client tests (mocked `fetch`),
  render tests for Overview, Sensors, and the shell/nav.
- No Playwright in this phase (see Explicitly out of scope).

## File structure

```
console/
├── src/
│   ├── app/          # root layout, routing, ErrorBoundary
│   ├── api/           # fetch wrappers + TanStack Query hooks
│   ├── screens/
│   │   ├── overview/
│   │   └── sensors/
│   ├── components/    # shared shell/nav components
│   └── store/         # Zustand cross-cutting UI state
├── vite.config.ts     # dev proxy: /api/* -> osiris-server
├── package.json
└── tsconfig.json
```

## Done criteria

`npm run build` and `npm test` (Vitest) pass in `console/`; `npm run
lint` (ESLint) passes; Overview and Sensors render real data against a
running `osiris-server` in dev (Vite proxy + the new CORS layer);
`cargo test --workspace` still passes after the CORS addition; no other
screen route does anything but show "coming soon"; nothing in this phase
touches `osiris-api`'s handlers, `osiris-query`, `osiris-investigate`, or
`osiris-evidence` — this is additive to `osiris-server`'s router
construction only.
