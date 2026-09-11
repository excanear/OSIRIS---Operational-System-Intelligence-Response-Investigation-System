# Phase 7a — Investigation/Evidence/Hunting Backend — Design Spec

**Status:** approved for implementation planning
**Spec:** `ARCHITECTURE.md` §9.4 (relationships/edge table), §11.3-11.4 (Correlation/Risk engines, reused not replaced), §12 (Investigation/DFIR Architecture — 12.1 Investigation Engine, 12.2 Threat Hunting workspace, 12.3 OQL, 12.5 Entity Graph, 12.6 Evidence Engine, 12.7 Alert Center/Incident Management), §19.2 (query performance budgets), §29 Phase 7 scope line.
**Companion:** this spec covers only the backend half of Phase 7. The Web Console (§16) is Phase 7b, a separate spec/plan, and depends on the API surface this phase produces.

## Why this is split from 7b

Phase 7 as scoped in `ARCHITECTURE.md` §29 bundles a Rust backend (Investigation Engine, Evidence Engine, OQL, Threat Hunting, Entity Graph v2) with a TypeScript/React Console — two independent subsystems in different stacks, the same shape of split the project already made for Phase 4 (4a identity/privilege vs. 4b persistence). 7a is backend-only and produces the API surface 7b consumes; 7b cannot start meaningfully before 7a's endpoints exist.

## Scope

In scope for 7a:
- `osiris-query`: OQL parser + backend-agnostic `EventQueryPlan` + SQLite translation.
- `osiris-investigate`: Investigation Engine — `process_story`, `file_story`, `network_story`, `identity_story`, `systemd_story`, `container_story`, `system_story`, `reconstruct_incident`; Entity Graph v2 bounded subgraph.
- `osiris-evidence`: Evidence Engine (append-only `Evidence` records) and `Incident` CRUD/state machine.
- Threat Hunting: `osiris hunt` CLI verb + saved OQL query templates, reusing `osiris-query` directly — no new engine (§12.2).
- API endpoints for all of the above in `osiris-api`.

Explicitly out of scope (deferred, decided during brainstorming):
- **Response Engine**, including its non-destructive `CollectEvidence` scaffolding mentioned in §13's "v1 scope" language. `ARCHITECTURE.md` §29 lists Response Engine's milestone only under Phase 8; 7a does not introduce `osiris-response` or any `ResponseAction` type. Evidence records in 7a are produced directly by the Investigation Engine and API handlers, not by a Response Engine action.
- **ClickHouse storage backend** (§10.2) — confirmed not yet introduced anywhere in the workspace; `osiris-query`'s SQLite translation is the only backend needed now. The AST→`EventQueryPlan` boundary is kept backend-agnostic per §12.3 so ClickHouse remains a pure additive translation layer later, but building it is not this phase's work.
- **Web Console** (§16) — Phase 7b.
- Replacing the four existing typed storage plans (`QueryPlan`, `AlertQueryPlan`, `RelationshipQueryPlan`, `RiskQueryPlan`) used internally by `osiris-detect`/`osiris-correlate`/`osiris-risk`/`osiris-baseline`. These stay exactly as they are; `EventQueryPlan` is a fifth, additive plan type for the analyst-facing free-query surface only.

## Architecture and Components

Three new crates, all additive — no Phase 0-6 crate's public API changes.

### `osiris-query` — OQL parser + planner

- Grammar (EBNF, documented formally in `docs/QUERY_LANGUAGE.md`): field-comparison expressions combined with `AND`/`OR`/`NOT`, operators `= != > < >= <= CONTAINS STARTS_WITH ENDS_WITH IN`, parentheses for grouping.
- Hand-written recursive-descent parser produces an AST.
- AST compiles into `EventQueryPlan` — a backend-agnostic filter/aggregation tree (distinct from and unrelated to the four existing typed `*QueryPlan` structs in `osiris-storage`).
- Field reference is generated from `osiris-schema` (the Event Schema v1 envelope, entities, event types) so the set of queryable fields never drifts out of sync with the schema — generation happens at build time or via a checked-in generated file with a CI check that it matches the schema, matching the dependency-graph CI enforcement pattern already used in this workspace (§27, `tools/check-dep-graph.sh`).
- `osiris-storage-sqlite` gains `fn query_events(&self, plan: &EventQueryPlan) -> Result<QueryResultStream, StorageError>`, translating the plan into parameterized SQL (never string-interpolated — the plan tree is walked to build a parameterized query, closing off SQL injection by construction).
- Every compiled plan carries an enforced row-count and time-range cap (§19.2) unless the caller explicitly requests streaming "export" mode; caps are enforced in `osiris-query`'s plan compiler, not left to each backend to remember.

### `osiris-investigate` — Investigation Engine

- Each `*_story` operation is a fixed, named composition (not a free-form query) as specified in §12.1: it assembles the entity's own timeline (via `osiris-query`'s `EventQueryPlan`), its graph edges (via the existing `RelationshipQueryPlan`), and every `Alert` whose evidence references one of those events (via the existing `AlertQueryPlan`'s `evidence_event_ids`), returned as one time-ordered structure.
- `file_story`, `network_story`, `identity_story`, `systemd_story`, `container_story` are refactored from their current ad-hoc handler implementations in `osiris-api` into reusable functions in this crate, preserving their existing behavior/tests while routing their event lookups through the new `EventQueryPlan` path instead of the fixed-field `QueryPlan` they use today. `osiris-api`'s handlers become thin wrappers calling into `osiris-investigate`.
- `process_story` and `system_story` are net new, built the same way.
- `reconstruct_incident(seed_entity, time_range)`: walks `osiris-correlate`'s `BehavioralChain` forward and backward in time from the seed entity within the given range, buckets the chain's events by `category` in temporal order into the staged view `INITIAL EVENT → EXECUTION → FILESYSTEM → NETWORK → PRIVILEGE → PERSISTENCE → IMPACT`. Every bucket entry cites its source `event_id`(s) — this is what makes "every conclusion must have evidence" (§44) structural.
- Entity Graph v2: a new function/endpoint returning a generic `{nodes: [...], edges: [...]}` subgraph, bounded by both depth **and** total node count (the existing `/api/v1/graph`'s `BehavioralChain` response is depth-bounded only and is left untouched — it continues to serve callers that want the correlation-specific chain shape).

### `osiris-evidence` — Evidence Engine + Incident Management

- `Evidence { evidence_id, source: enum, timestamp, integrity: { sha256_or_content_hash, immutable_since }, relationships: Vec<EntityRef>, incident_id: Option<Uuid> }`, append-only: the storage layer exposes insert only, no update/delete; correcting a record means inserting a new one with a `supersedes: Option<Uuid>` link to the record it replaces.
- `Incident { incident_id, status: {NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE}, entities, alerts, evidence, notes, actions: [] (always empty in 7a — Response Engine is out of scope), timeline_cache: Option<...> }`, a control-plane record, CRUD'd through the API.
- Evidence↔Incident is a many-to-many join table (one evidence record can belong to more than one incident), not a foreign key on the evidence record.
- Every `Incident` status transition writes a pre-transition audit entry via `osiris-audit` (WHO/WHAT/WHEN/WHY) before the transition is committed; if the audit write fails, the transition fails — consistent with how the rest of the system treats audit as non-optional.

### Threat Hunting

Not a crate. `osiris-cli` gains an `osiris hunt` subcommand that accepts an OQL string (or `--template <name>`) and runs it through `osiris-query` directly, printing results the same way `osiris events` does. Saved query templates for the master prompt §41 example patterns live as static files (same pattern as `rules/`, e.g. a new `hunts/` directory of named OQL query files) — no new engine, no new storage.

### API surface (`osiris-api`)

New/changed routes:
```text
GET  /api/v1/events?q=<OQL>              (replaces fixed-field-only filtering with full OQL; existing exact-match query params remain supported as sugar compiled to the same EventQueryPlan)
GET  /api/v1/processes/{process_key}/story   (new)
GET  /api/v1/system/story                    (new)
GET  /api/v1/incidents/{seed_entity}/reconstruct  (new — reconstruct_incident)
GET  /api/v1/graph/subgraph                  (new — Entity Graph v2, {nodes, edges}, depth+node-count bounded)
GET  /api/v1/incidents            POST /api/v1/incidents
GET  /api/v1/incidents/{id}       PATCH /api/v1/incidents/{id}   (status transitions, audited)
GET  /api/v1/evidence             POST /api/v1/evidence
```
Existing story endpoints (`/api/v1/files/story`, `/api/v1/network/story`, `/api/v1/identity/story`, `/api/v1/systemd/story`, `/api/v1/containers/story`) keep their routes and response shapes; only their internal implementation moves into `osiris-investigate`.

## Data Flow

`osiris hunt` / `GET /api/v1/events?q=<OQL>` / an internal Investigation Engine call → OQL string → `osiris-query` parses → AST → validates fields against the schema-generated field reference → compiles to `EventQueryPlan` → `Storage::query_events(plan)` (SQLite translates to parameterized SQL, enforcing the row/time-range cap) → `QueryResultStream` → API paginates/streams as JSON.

For a Story or `reconstruct_incident`, `osiris-investigate` issues several such queries (plus calls into the existing `RelationshipQueryPlan`/`AlertQueryPlan`) and assembles one time-ordered structure where every entry cites its source `event_id`(s).

## Error Handling

- OQL syntax error: parser returns position + expected-token; API responds 400 with a human-readable message pointing at the failure.
- Unknown field: 400 listing valid fields from the schema-generated reference (never a hand-maintained list that can drift).
- Row/time-range cap exceeded: rejected unless the caller explicitly requests streaming export mode (§19.2).
- Evidence Engine: append-only enforced at the storage layer — no UPDATE/DELETE path exists in the API or the `Storage` trait extension for evidence; "correcting" evidence is always a new row with `supersedes`.
- Incident status transition: audit write happens before the transition commits; audit failure fails the transition.

## Testing

- OQL grammar unit tests: one case per operator, per `AND`/`OR`/`NOT` precedence, per nested parentheses.
- Schema-generated round-trip fixtures: AST → `EventQueryPlan` → SQL, proving every Event Schema field is queryable.
- Integration tests translating representative OQL queries against SQLite and checking real results, reusing `osiris-generator` scenarios already established in prior phases.
- Investigation Engine tests per Story (all 8, including the 5 refactored) using generator fixtures — refactored stories must match their current behavior exactly; the 3 new ones get fresh fixtures.
- Evidence Engine tests proving no update/delete path is reachable through the API — only insert with optional `supersedes`.
- Entity Graph v2 tests against a synthetic dense graph proving both depth and node-count bounds are enforced.
- One final e2e test proving the Phase 7a vertical slice end-to-end, matching the pattern of the final e2e test in every prior phase.

## Exit Criterion

`cargo test --workspace` passes with zero warnings under `cargo clippy --workspace --all-targets -- -D warnings`, `bash tools/check-dep-graph.sh` passes, `osiris-query`/`osiris-investigate`/`osiris-evidence` exist and are used by `osiris-api`/`osiris-cli` as described above, the 5 existing story endpoints are behaviorally unchanged from an API consumer's perspective, and no `osiris-response` crate or `ResponseAction` type is introduced. Phase 7b (Web Console) is a separate plan that consumes the API surface this phase produces.
