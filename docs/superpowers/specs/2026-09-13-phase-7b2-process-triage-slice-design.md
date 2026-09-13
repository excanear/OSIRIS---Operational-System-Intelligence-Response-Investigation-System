# Phase 7b-2: Process/Triage Slice — Design

**Revises 7b-1's forward plan.** The 7b-1 design spec sketched three
follow-on phases — 7b-2 "Event Exploration" (Live Events, Process
Explorer, Filesystem, Network, Containers, Timeline), 7b-3 "Triage/Cases"
(Alerts, Incidents, Evidence), 7b-4 "Hunting + Entity Graph". This phase
cuts across that split instead: it picks the screens that need **zero new
backend work** regardless of which old bucket they came from — Process
Explorer (from old 7b-2) plus Alerts and Incidents/Evidence (from old
7b-3) — and defers everything that needs new backend engineering first
(a WebSocket stream for Live Events, list endpoints for
Filesystem/Network/Containers, a timeline endpoint, a graph-rendering
library for Entity Graph). Those deferred screens become 7b-3/7b-4+,
renumbered from here rather than from 7b-1's original sketch.

## Why this slice

7b-1 established the pattern (app shell, typed API client, per-screen
folders, Vitest+RTL) with two read-only, no-detail-view screens. This
phase is the natural next step in complexity — introducing list→detail
routing and a first write path (status transitions, evidence/incident
creation) — while staying frontend-only, matching 7b-1's own discipline
of not mixing Console work with new backend engineering in the same
phase.

## Backend state investigated (no new backend endpoints needed)

Every endpoint this phase needs already exists and was built/reviewed in
Phase 7a:

- `GET /api/v1/processes` → `Vec<ProcessSummary>` (process_key, pid,
  exe_path, timestamp).
- `GET /api/v1/processes/:process_key` → `ProcessDetail { process:
  CanonicalEvent, children: Vec<CanonicalEvent> }`.
- `GET /api/v1/processes/:process_key/story` → the investigation Story
  (citing events/alerts).
- `GET /api/v1/alerts?rule_id=&since=` → `Vec<Alert>`.
- `GET /api/v1/incidents` → `Vec<Incident>`; `POST /api/v1/incidents`
  (body: `{ entities: Vec<EntityRef> }`) → `Incident` (starts at status
  `New`).
- `GET /api/v1/incidents/:incident_id` → `Incident`; `PATCH
  /api/v1/incidents/:incident_id` (body: `{ status: IncidentStatus, why:
  Option<String> }`) → `Incident`, via `IncidentStore::transition_status`
  (audit-logged).
- `GET /api/v1/evidence?incident_id=` → `Vec<Evidence>` (evidence linked
  to that incident, via `EvidenceIncidentLinks`); `POST /api/v1/evidence`
  (body includes optional `incident_id`) → `Evidence`, linking it at
  creation time if given.

**Investigated gap:** `/api/v1/evidence` has no "list all" mode — it
requires `incident_id`. There is no global evidence-browsing endpoint.
This directly shapes the Evidence design decision below.

**Investigated gap:** `Incident.notes: Vec<String>` exists on the record
but no endpoint appends to it. Only the status transition is a supported
mutation. Incident detail shows existing notes read-only.

## Explicitly out of scope for 7b-2 (deferred, not forgotten)

- **A standalone Evidence screen.** No global list-all-evidence endpoint
  exists. Evidence is shown and created only inside Incident detail, in
  its natural context (`GET/POST /api/v1/evidence?incident_id=`). The
  "Evidence" nav item stays disabled/"coming soon" until a future phase
  adds a global list endpoint and a real standalone browse experience.
- **Alert mutation (acknowledge/dismiss).** `/api/v1/alerts` is GET-only
  today. Adding alert-state mutation is new backend work, deferred.
- **Incident note-taking.** No backend endpoint supports it (see above).
- **A general `EntityRef` picker.** Of `EntityRef`'s 7 variants (Process,
  File, Ip, Domain, User, Container, Session), only `Ip { addr: String }`
  and `Domain { name: String }` are practical for a human to type by
  hand — the rest need opaque IDs (a `ProcessKey`, a `host_id` UUID +
  inode) with no existing picker UI to source them from. Incident
  creation in this phase supports IP/Domain entities only; a fuller
  picker (e.g. reusing Process Explorer's list to source a `ProcessKey`)
  is future scope once more screens exist to source IDs from.
- **Cross-screen "Create Incident" quick-actions** (e.g. a button on
  Process Explorer's detail view pre-filling a Process entity). Kept out
  to avoid cross-screen navigation-with-prefilled-state logic this phase;
  incident creation lives entirely on the Incidents list screen.
- **Live Events, Filesystem, Network, Containers, Timeline, Threat
  Hunting, Entity Graph** — all need new backend work (a WebSocket
  stream, list endpoints, a timeline data source, or a graph-rendering
  library) and become 7b-3/7b-4+.

## Screens and components (this phase)

### Process Explorer

- **List** (`/processes` route): table from `GET /api/v1/processes`,
  columns process_key/pid/exe_path/timestamp, sorted by timestamp desc,
  with a client-side text filter on `exe_path`. Selecting a row navigates
  to the detail route.
- **Detail** (`/processes/:processKey` route): fetches `GET
  /api/v1/processes/:processKey` (own exec event + children) and `GET
  /api/v1/processes/:processKey/story` (citing events/alerts) together;
  renders the process's own fields, a children list, and the story's
  narrative content.
- **uiStore wiring**: selecting a process (list row click, or landing
  directly on the detail route) calls `useUiStore.getState().selectEntity(processKey)`
  in addition to navigating. The URL remains the source of truth for
  what's shown (deep-linkable, survives refresh); the store write is
  forward-looking only — no screen in this phase reads `selectedEntity`
  back. This is the store's first real consumer, per 7b-1's design intent.
- This is also the first screen with a **list→detail routing pattern**,
  which Incidents (below) reuses, and which later screens (Filesystem,
  Network) will follow too.

### Alerts

- **Single list screen** (`/alerts` route, no detail view — an Alert's
  own fields are sufficient inline; deeper investigation happens via
  Process Explorer/Incidents, not by drilling into the Alert record
  itself).
- **Data**: `GET /api/v1/alerts` with `rule_id` and `since` as optional
  filter controls (both server-supported).
- **Read-only.** No mutation, no backend changes.
- Columns: rule_id, severity, status, host_id, reasons (joined, or the
  first with a "+N more" suffix), timestamp, evidence count
  (`evidence.len()`). Correction from an earlier design pass: `Alert`
  (`crates/osiris-schema/src/alert.rs`) has no `entities` field — only
  `rule_id`/`rule_version`/`rule_content_hash`/`severity`/`status`/
  `timestamp`/`host_id`/`reasons`/`evidence` (the last being matched
  `event_id`s, not entities). No pagination beyond whatever `/alerts`
  returns natively (matches 7b-1's Sensors screen precedent).

### Incidents (+ Evidence, folded in)

- **List** (`/incidents` route): table from `GET /api/v1/incidents` —
  incident_id, status, entity count, alert count. Selecting a row
  navigates to the detail route.
- **New Incident form**, on the list screen: repeatable rows of {kind:
  IP | Domain, value: string}, submitted as `POST /api/v1/incidents`
  with `entities: Vec<EntityRef>` built from those rows (`{kind: "IP",
  addr: value}` / `{kind: "DOMAIN", name: value}`). On success, navigate
  to the new incident's detail route.
- **Detail** (`/incidents/:incidentId` route): fetches `GET
  /api/v1/incidents/:incidentId`; shows status, entities, linked
  alert_ids, and existing notes (read-only — see the investigated gap
  above). A status-transition control (a dropdown of `IncidentStatus`
  values + an optional `why` reason field) calls `PATCH
  /api/v1/incidents/:incidentId`.
- **Evidence, nested in the same detail view**: `GET
  /api/v1/evidence?incident_id=:incidentId` lists linked evidence
  (source, hash, integrity, relationships); a small form posts `POST
  /api/v1/evidence` with `incident_id` set to the current incident,
  linking new evidence at creation time. No separate Evidence screen or
  route this phase (see "Explicitly out of scope").

## Error handling

Same posture as 7b-1: TanStack Query's per-query error state surfaces
network/5xx failures inline per screen/section (never a blank screen);
the existing root `ErrorBoundary` (from 7b-1) continues to catch
render-time exceptions in routed content. Form submission failures
(incident creation, evidence creation, status transition) surface
inline near the form, not as a full-screen error — a failed mutation
should never lose the user's in-progress form input.

## Testing

- **Vitest + React Testing Library**, matching 7b-1: API client tests
  (mocked `fetch`) for the new endpoints/hooks, render tests per screen
  covering loading/error/empty/populated states, and specifically for
  Incidents: the status-transition control, the evidence list+create
  form, and the new-incident form's IP/Domain entity construction.
- No Playwright this phase (still deferred per 7b-1's rationale — not
  enough real user flows yet to justify the infra even after this
  phase's additions).
- No backend test changes needed — no backend code changes this phase.

## File structure (additions to 7b-1's `console/`)

```
console/
├── src/
│   ├── api/
│   │   ├── types.ts        # + ProcessSummary, ProcessDetail, Incident,
│   │   │                   #   IncidentStatus, Evidence, EntityRef
│   │   ├── client.ts       # + fetchProcesses, fetchProcess, fetchProcessStory,
│   │   │                   #   fetchAlerts (extend with rule_id/since),
│   │   │                   #   fetchIncidents (already exists, unchanged),
│   │   │                   #   fetchIncident, createIncident, patchIncidentStatus,
│   │   │                   #   fetchEvidence, createEvidence
│   │   └── hooks.ts        # + useProcesses, useProcess, useProcessStory,
│   │                       #   useIncident, useCreateIncident,
│   │                       #   usePatchIncidentStatus, useEvidence, useCreateEvidence
│   ├── screens/
│   │   ├── processes/
│   │   │   ├── ProcessList.tsx
│   │   │   └── ProcessDetail.tsx
│   │   ├── alerts/
│   │   │   └── Alerts.tsx
│   │   └── incidents/
│   │       ├── IncidentList.tsx      # includes the new-incident form
│   │       ├── IncidentDetail.tsx    # includes the nested Evidence list+form
│   │       └── EntityRefInput.tsx    # shared IP/Domain entity-row input
│   └── app/
│       └── navItems.ts     # Process Explorer, Alerts, Incidents: enabled: true
```

## Done criteria

`npm run build`, `npm test` (Vitest), and `npm run lint` pass in
`console/`; Process Explorer's list and detail (including its `story`
data and uiStore write) render against a running `osiris-server` in dev;
Alerts filters by `rule_id`/`since` correctly; Incidents supports the
full loop — list, create (IP/Domain entities), detail view, status
transition, and nested evidence list+create — all against real
`osiris-api` endpoints with no backend code touched; `cargo test
--workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
remain green (trivially, since nothing in `crates/` changes this phase);
the CI job 7b-1 added now exercises this phase's code too; Evidence, and
the other 7 §16.3 screens not covered here, still show "coming soon" and
are non-interactive nav entries.
