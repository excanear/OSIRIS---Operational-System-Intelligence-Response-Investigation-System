# Phase 7b-3: Entity Graph, Timeline, Threat Hunting, Evidence — Design

**Continues 7b-2's renumbering.** 7b-2's spec deferred Live Events,
Filesystem, Network, Containers, Timeline, Threat Hunting, and Entity
Graph as "all need new backend work." Re-investigating each of those
against the actual current API (not the original architecture-time
assumptions) found that most of them don't:

- **Entity Graph**: `GET /api/v1/graph/subgraph` already exists (built in
  Phase 7a) — zero new backend work, only a frontend graph-rendering
  library.
- **Timeline**: `GET /api/v1/system/story` already exists (Phase 7a's
  "System Story," `osiris_investigate::system_story`) — zero new backend
  work.
- **Threat Hunting**: the CLI's `osiris hunt` command has no dedicated
  server endpoint at all — `hunt_url()` in `osiris-cli` just builds a
  `GET /api/v1/events?q=<OQL>` URL, the same endpoint the Console already
  calls via `fetchEvents`. Zero new backend work; only a small additive
  change to the existing client function (support the `q` param it
  doesn't yet expose) plus a UI wrapper.
- **Evidence (standalone)**: the one real gap. `EvidenceStore` only has
  `insert`/`get` — no way to list all evidence. This is the only backend
  change in this phase.
- **Filesystem, Network, Containers, Live Events** remain out of scope —
  see "Explicitly out of scope" below. They still need new backend work
  (list/rollup endpoints of undecided shape, and a WebSocket subsystem
  respectively) and are deferred to later phases.

This phase's own name reflects the actual grouping: three
zero-backend-change screens plus one small, well-scoped backend addition
— not "the WebSocket phase" and not "everything §16.3 didn't cover yet."

## Why this slice

Same discipline 7b-2 established: group phases by backend cost, not by
the original architecture-time bucket. Entity Graph, Timeline, and
Threat Hunting are essentially free (existing engine capability, no new
data model); Evidence's gap is small and shaped exactly like list
endpoints already built (`/api/v1/processes`, `/api/v1/incidents`). This
keeps the phase's risk profile close to 7b-1/7b-2's, saving the one
genuinely novel subsystem (Live Events / WebSocket streaming) for its own
dedicated design pass.

## Backend state investigated

Existing, reused as-is:

- `GET /api/v1/graph/subgraph?entity=<KIND:value>&depth=&max_nodes=&since=&until=`
  → `Subgraph { nodes: Vec<GraphNode{id, kind}>, edges: Vec<GraphEdge{from,
  to, relation, event_id, timestamp}>, truncated: bool }`
  (`osiris_investigate::subgraph`, capped by `MAX_SUBGRAPH_NODES`/
  `MAX_GRAPH_DEPTH`). `entity` is `EntityRef::storage_key()`'s format —
  `PROCESS:<hex>`, `FILE:<host>:<inode>:<device>`, `IP:<addr>`,
  `DOMAIN:<name>`, `USER:<host>:<uid>`, `CONTAINER:<id>`, `SESSION:<id>`.
- `GET /api/v1/system/story?host_id=<uuid>&since=&until=` → the existing
  `Story` type (already modeled in the Console from 7b-2's Process
  Explorer work), assembled from every event on that host in the range.
  `host_id` is mandatory; `since`/`until` default to the full range
  (`0`/`u64::MAX`) when omitted.
- `GET /api/v1/events?q=<OQL>&since=&until=&limit=&export=` → the same
  endpoint `fetchEvents` already calls, just missing the `q` passthrough
  today.

**Investigated gap:** `EvidenceStore` trait (`crates/osiris-evidence/src/store.rs`)
has only `insert`/`get` — no list-all method. `list_evidence_handler`
today hard-requires `incident_id` and 400s without it. This is the one
backend change this phase makes.

**Investigated cross-screen defect (pre-existing, not new):**
`uiStore.selectedEntity` (Zustand store, 7b-1) is already written to by
`ProcessDetailScreen.tsx` — but with the bare `processKey` hex string, not
an `EntityRef::storage_key()`-formatted string (`PROCESS:<hex>`). Since
this phase is the store's first real *reader* (Entity Graph consuming a
pivoted-from entity), the stored format must be standardized now: every
writer of `selectedEntity` stores the full `KIND:value` key. This means
correcting `ProcessDetailScreen.tsx`'s existing `selectEntity(processKey)`
call to `selectEntity(\`PROCESS:${processKey}\`)` as part of this phase,
alongside the new writes from Incident detail (`IP:${addr}` /
`DOMAIN:${name}` per entity).

## Explicitly out of scope for 7b-3 (deferred, not forgotten)

- **Live Events.** No WebSocket infrastructure exists anywhere in the
  codebase — no `axum::extract::ws` usage, no event-broadcast/fan-out
  mechanism from the ingestion pipeline to live connections. This is a
  genuinely new subsystem (transport, backpressure, reconnection) and
  gets its own dedicated design pass rather than being bundled here.
- **Filesystem, Network, Containers list screens.** Their *detail*
  endpoints already exist (`/api/v1/files/story`, `/network/story`,
  `/containers/story`), but whether their *list* view needs a rolled-up
  resource endpoint (like `/processes` groups by `process_key`) or can
  reuse `/events` with a category filter is an open design question,
  deliberately not resolved here to keep this phase's scope to already-
  answered questions.
- **Evidence creation from the standalone screen.** The new `/api/v1/evidence`
  (no `incident_id`) is list-only. Creation stays exclusive to Incident
  Detail (`POST /api/v1/evidence` with `incident_id` set) — evidence
  conceptually still "belongs to" the incident-creation flow; this phase
  doesn't re-open that business rule.
- **A visual query-builder for Threat Hunting.** Free-text OQL + saved
  templates only. A structured filter-builder UI is a materially larger
  scope, deferred until real usage shows it's needed.
- **Swim-lane Timeline visualization** (ARCHITECTURE.md §16.1's
  category-colored, multi-lane custom component). This phase ships a
  chronological list with category badges instead — the swim-lane
  component is deferred until there's real data to validate the visual
  design against.
- **A "full graph" mode for Entity Graph.** `/api/v1/graph/subgraph`
  always requires a seed entity; there is no whole-graph view, and none
  is added here.

## Screens and components (this phase)

### Entity Graph (`/graph` route)

- **New dependency:** `react-force-graph` (force-directed, WebGL/Canvas-
  backed, interactive zoom/pan out of the box).
- **Data:** `useSubgraph(entityKey, { depth?, maxNodes?, since?, until? })`
  wraps `GET /api/v1/graph/subgraph`. Client-side types mirror
  `GraphNode`/`GraphEdge`/`Subgraph` exactly.
- **Rendering:** maps `{from, to}` → `react-force-graph`'s `{source,
  target}` link shape; node color keyed by `kind`. A `truncated: true`
  banner is shown, not hidden, per the backend's own doc comment intent
  ("never silently clipped").
- **Entry points:**
  - Manual: a text input accepting a raw `KIND:value` entity key, with
    inline format validation before the request fires (matches
    `EntityRef::parse_storage_key`'s accepted shapes) rather than relying
    solely on the backend's 400.
  - Pivot: a "View in Entity Graph" link/button on Process Explorer's
    detail screen (its own process entity) and on Incident detail's
    entity list (each IP/Domain entity) call
    `useUiStore.getState().selectEntity(entityKey)` (now
    correctly `KIND:value`-formatted, see the cross-screen defect above)
    and navigate to `/graph`. On mount, Entity Graph reads
    `selectedEntity` if present and auto-loads it; otherwise it shows the
    empty manual-entry state.
- **Error handling:** invalid manual entry is caught client-side before
  the request; a 400 from an unknown `kind` prefix or malformed value
  surfaces via `ApiError`'s existing body-text plumbing (7b-2's final-
  review fix).

### Timeline (`/timeline` route)

- **Data:** `useSystemStory(hostId, { since?, until? })` wraps `GET
  /api/v1/system/story`. Reuses the existing `Story` type.
- **Host selection:** a `<select>` populated from the distinct `host_id`s
  already present in Sensors' loaded health-rollup data (`useHealth`,
  from 7b-1) — no new fetch. The query is `enabled: false` (no request
  fired) until a host is chosen.
- **Time range:** optional numeric since/until inputs (nanoseconds,
  matching the backend's own unit and default-to-full-range behavior),
  plus a "last 1 hour" quick-select button mirroring Alerts' `since`
  pattern from 7b-2's final review fix.
- **Rendering:** a chronological list (reusing the Story-rendering
  pattern already built for `ProcessDetailScreen.tsx`), each row tagged
  with a color/badge keyed by `CanonicalEvent.category`. No swim-lane
  component this phase (see "Explicitly out of scope").
- **Error handling:** no host selected → disabled state, no query;
  otherwise standard `ApiError` surfacing.

### Threat Hunting (`/hunting` route)

- **Client change:** `fetchEvents`/`useEvents` (in `client.ts`/`hooks.ts`)
  gain an optional `q` (raw OQL) param, additive only — no existing call
  site's behavior changes, since none currently passes `q`.
- **Templates:** the three existing `.oql` files under `hunts/` at the
  repo root (`network-download-then-write.oql`,
  `shell-wrote-file-to-web-root.oql`,
  `container-started-in-remote-session.oql` — the same files the CLI
  embeds via `include_str!`) are imported directly into the Console via
  Vite's `?raw` import suffix. Single source of truth between CLI and
  Console; no content duplication.
- **UI:** a template `<select>` that fills a `<textarea>` (freely
  editable after selection or typed from scratch), optional
  since/until/limit inputs, a "Run" button, and a results table reusing
  the existing events-list rendering.
- **Error handling:** a malformed OQL query 400s from the backend's own
  parser (Phase 7a's `osiris-query`, already descriptive) — surfaced via
  `ApiError`'s body text.

### Evidence (`/evidence` route)

- **Backend change:** `EvidenceStore` trait gains
  `fn list(&self) -> Result<Vec<Evidence>, EvidenceStoreError>`;
  `SqliteEvidenceStore` implements it as `SELECT * FROM evidence ORDER BY
  timestamp DESC LIMIT 5000`, bounded by a new `MAX_EVIDENCE_LIMIT: usize
  = 5_000` constant (matching `osiris_query::MAX_EVENT_LIMIT`'s value,
  since evidence volume tracks event volume). `list_evidence_handler` (`crates/osiris-api/src/evidence.rs`):
  when `incident_id` is present, behavior is unchanged (today's scoped
  path, response shape untouched — no existing consumer, i.e. Incident
  Detail's nested evidence list, is affected); when absent, calls the new
  `list()` and, for each record, `links.incident_ids_for_evidence(id)`
  (already exists) to attach linked incident IDs. The unscoped response
  is a new wrapper shape, `EvidenceWithIncidents { evidence: Evidence,
  incident_ids: Vec<Uuid> }` — a new type, since `Evidence` itself has no
  incident awareness (linkage lives only in `EvidenceIncidentLinks`).
- **Frontend:** `useAllEvidence()` wraps the unscoped call. A read-only
  table (source, timestamp, integrity summary, linked entities), with an
  incident column linking to `/incidents/:id` per linked incident id
  ("—" when the list is empty). No creation form (see "Explicitly out of
  scope").
- **Error handling:** standard `ApiError` surfacing, matching every other
  list screen.

## Nav/routing wiring

All four routes already exist as disabled `NAV_ITEMS` entries pointing at
`ComingSoon` (`/graph`, `/timeline`, `/hunting`, `/evidence` — paths were
fixed at 7b-1's nav scaffold time). This phase flips each to
`enabled: true` and swaps in the real screen component, following the
same sequential `App.tsx`/`navItems.ts`/`App.test.tsx` edit pattern
7b-1 (Tasks 6-8) and 7b-2 (Tasks 4-8) already used successfully.

## Error handling (general)

Same posture as 7b-1/7b-2: TanStack Query's per-query error state
surfaces network/5xx failures inline per screen/section; the existing
root `ErrorBoundary` continues to catch render-time exceptions.

## Testing

- **Vitest + React Testing Library**, matching prior phases: hook tests
  (mocked `fetch`) for `useSubgraph`, `useSystemStory`, the extended
  `useEvents`/`fetchEvents`, and `useAllEvidence`; screen tests per
  screen covering loading/error/empty/populated states.
- **Entity Graph specifics:** manual-entry validation, the truncated
  banner, and a render test that the pivot buttons on Process
  Explorer/Incident detail call `selectEntity` with the corrected
  `KIND:value` format and navigate to `/graph`.
- **Timeline specifics:** host-dropdown-drives-query-params test, the
  "last 1 hour" quick-select, category-badge rendering.
- **Threat Hunting specifics:** template-select fills the textarea, a
  template-import smoke test (non-empty content for each of the three
  `.oql` files, mirroring the CLI's own
  `every_known_template_is_non_empty` coverage), run → results render.
- **Evidence specifics:** row rendering with and without linked incident
  ids.
- **Backend:** a new `SqliteEvidenceStore::list()` unit test; a handler
  test asserting the unscoped `/api/v1/evidence` call returns all
  evidence with correct `incident_ids`, and that the scoped
  (`?incident_id=`) call's response shape is unchanged.
- No Playwright this phase (same rationale as 7b-1/7b-2 — still not
  enough real user flows to justify the infra).

## File structure (additions to 7b-1/7b-2's `console/`)

```
console/
├── src/
│   ├── api/
│   │   ├── types.ts        # + GraphNode, GraphEdge, Subgraph,
│   │   │                   #   EvidenceWithIncidents
│   │   ├── client.ts       # + fetchSubgraph, fetchSystemStory,
│   │   │                   #   fetchAllEvidence; fetchEvents gains `q` param
│   │   └── hooks.ts        # + useSubgraph, useSystemStory, useAllEvidence;
│   │                       #   useEvents gains `q` param
│   ├── screens/
│   │   ├── graph/
│   │   │   └── EntityGraph.tsx
│   │   ├── timeline/
│   │   │   └── Timeline.tsx
│   │   ├── hunting/
│   │   │   └── ThreatHunting.tsx
│   │   ├── evidence/
│   │   │   └── EvidenceList.tsx
│   │   ├── processes/
│   │   │   └── ProcessDetailScreen.tsx   # corrected selectEntity() format
│   │   └── incidents/
│   │       └── IncidentDetailScreen.tsx  # + selectEntity() calls per entity
│   └── app/
│       └── navItems.ts     # Entity Graph, Timeline, Threat Hunting,
│                            #   Evidence: enabled: true
crates/
├── osiris-evidence/src/store.rs   # EvidenceStore::list()
└── osiris-api/src/evidence.rs     # unscoped list_evidence_handler path
```

## Done criteria

`npm run build`, `npm test` (Vitest), and `npm run lint` pass in
`console/`; `cargo test --workspace` and `cargo clippy --workspace
--all-targets -- -D warnings` pass with the `osiris-evidence`/`osiris-api`
changes included; Entity Graph renders a subgraph both from manual entry
and from a pivot link (Process Explorer, Incident detail) with the
corrected `selectedEntity` format; Timeline renders a host's chronological
story with category badges and a working time-range control; Threat
Hunting runs both a template-selected and a freehand OQL query against
real data; Evidence's standalone screen lists all evidence with correct
incident links, without touching Incident Detail's existing nested
evidence list/create behavior; Live Events, Filesystem, Network, and
Containers still show "coming soon" and remain non-interactive nav
entries.
