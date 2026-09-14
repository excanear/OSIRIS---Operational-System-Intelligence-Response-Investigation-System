# Phase 7b-3: Entity Graph, Timeline, Threat Hunting, Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four functional Console screens — Entity Graph, Timeline,
Threat Hunting, and Evidence (standalone, read-only) — plus the one
backend change any of them need: a global (unscoped) `GET
/api/v1/evidence` list.

**Architecture:** Almost entirely a frontend extension of the 7b-1/7b-2
Console, mirroring three already-existing backend capabilities
(`/graph/subgraph`, `/system/story`, OQL-filtered `/events`) with new
screens. The one real backend change is additive: `EvidenceStore` gains a
`list()` method, and the existing `list_evidence_handler` grows an
unscoped branch alongside its existing `incident_id`-scoped one (which
stays byte-for-byte the same). A pre-existing cross-screen defect
(`uiStore.selectedEntity` stored in the wrong format) is fixed as
groundwork before Entity Graph becomes its first real reader.

**Tech Stack:** Same as 7b-1/7b-2 — Vite, React 18, TypeScript 5, TanStack
Query v5, Zustand, react-router-dom v6, Vitest + React Testing Library,
ESLint + Prettier — plus one new frontend dependency,
`react-force-graph-2d`, for the Entity Graph screen. Backend: Rust/axum,
touching `osiris-evidence` and `osiris-api` only.

**Spec:** `docs/superpowers/specs/2026-09-13-phase-7b3-graph-timeline-hunting-evidence-design.md`

## Global Constraints

- The only backend change this phase makes: `EvidenceStore::list()` (new
  trait method + `SqliteEvidenceStore` impl) and
  `list_evidence_handler`'s unscoped branch. `GET
  /api/v1/evidence?incident_id=<id>`'s existing response shape (a bare
  `Vec<Evidence>`) is unchanged; only the *absent*-`incident_id` case is
  new, returning `Vec<EvidenceWithIncidents>` instead of a 400. No other
  endpoint, route, or handler changes. `cargo test --workspace` and
  `cargo clippy --workspace --all-targets -- -D warnings` must stay green.
- `MAX_EVIDENCE_LIMIT: usize = 5_000` (matching
  `osiris_query::MAX_EVENT_LIMIT`'s value) bounds the unscoped list;
  sorted by `Evidence::timestamp()` descending, newest first.
- `react-force-graph-2d` (the 2D-only member of the `react-force-graph`
  family — same maintainer, lighter bundle than the combined 2D+3D+VR
  package) is the only new npm dependency. Pin the exact version resolved
  at implementation time (`^1.29.1` as of this plan's writing).
- Entity Graph has no "full graph" mode — `/api/v1/graph/subgraph` always
  requires a seed `entity` key. No screen in this phase adds one.
- Threat Hunting is free-text OQL plus saved templates only — no visual
  query-builder UI.
- Timeline ships a chronological list with category badges, not a
  swim-lane visualization (deferred; ARCHITECTURE.md §16.1's swim-lane
  component is out of scope this phase).
- Evidence (standalone) is list/view-only. No creation form. Creation
  stays exclusive to Incident Detail (`POST /api/v1/evidence` with
  `incident_id` set), unchanged from 7b-2.
- `uiStore.selectedEntity` (Zustand, from 7b-1) must hold the full
  `EntityRef::storage_key()`-formatted string (`KIND:value`, e.g.
  `PROCESS:<hex>`, `IP:<addr>`) everywhere it is written — this phase
  corrects `ProcessDetailScreen.tsx`'s pre-existing call (which stored
  the bare hex) and adds the same convention to `IncidentDetailScreen.tsx`.
- `CanonicalEvent` gains an optional `category?: string` field (matching
  the backend's `Category` enum, serialized `SCREAMING_SNAKE_CASE`).
  Optional, not required, so every existing `CanonicalEvent` test fixture
  across `hooks.test.tsx`, `ProcessDetailScreen.test.tsx`,
  `rollup.test.ts`, and `Sensors.test.tsx` — none of which set this field
  — keeps type-checking, matching 7b-2's precedent for `process?`/
  `parent_process?`.
- No Playwright/e2e — Vitest + React Testing Library only.
- `npm run build`, `npm test`, and `npm run lint` must pass in `console/`
  after every frontend task; `cargo test --workspace` and `cargo clippy
  --workspace --all-targets -- -D warnings` must pass after the one
  backend task.
- Numeric timestamps are nanoseconds since the Unix epoch everywhere,
  matching `CanonicalEvent.timestamp`'s convention (established in
  7b-1/7b-2) — never seconds or milliseconds.
- Dark-first, information-dense, monospace-for-data-fields visual
  direction continues unchanged.

---

### Task 1: Backend — Evidence global list endpoint

**Files:**
- Modify: `crates/osiris-evidence/src/store.rs` (add `list()` to
  `EvidenceStore` trait + `SqliteEvidenceStore` impl, `MAX_EVIDENCE_LIMIT`
  constant)
- Modify: `crates/osiris-api/src/evidence.rs` (`ListEvidenceQuery.incident_id`
  becomes `Option<String>`; add `EvidenceWithIncidents`,
  `ListEvidenceResponse`; rewrite `list_evidence_handler`; update the two
  existing tests for the new `Option`-wrapped field and enum-wrapped
  response)

**Interfaces:**
- Consumes: nothing from other tasks (independent, backend-only).
- Produces: `EvidenceStore::list(&self) -> Result<Vec<Evidence>,
  EvidenceStoreError>` (crate `osiris-evidence`); the unscoped `GET
  /api/v1/evidence` (no `incident_id`) now returns
  `Vec<{evidence: Evidence, incident_ids: Vec<Uuid>}>` (JSON) instead of
  400. Tasks 5 and 10 (Console's Evidence data layer and screen) consume
  this wire shape.

- [ ] **Step 1: Write the failing tests for `SqliteEvidenceStore::list()`**

In `crates/osiris-evidence/src/store.rs`, add these tests inside the
existing `#[cfg(test)] mod tests` block, after `insert_never_overwrites_an_existing_record`:

```rust
    #[test]
    fn list_returns_all_evidence_ordered_by_timestamp_descending() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        let older = Evidence::new(
            EvidenceSource::EventCapture,
            1000,
            Integrity { hash: "a".to_string(), immutable_since: 1000 },
            vec![],
            None,
        )
        .unwrap();
        let newer = Evidence::new(
            EvidenceSource::EventCapture,
            2000,
            Integrity { hash: "b".to_string(), immutable_since: 2000 },
            vec![],
            None,
        )
        .unwrap();
        store.insert(older.clone()).unwrap();
        store.insert(newer.clone()).unwrap();

        let listed = store.list().unwrap();

        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].evidence_id(), newer.evidence_id());
        assert_eq!(listed[1].evidence_id(), older.evidence_id());
    }

    #[test]
    fn list_returns_empty_vec_when_no_evidence_exists() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        assert!(store.list().unwrap().is_empty());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p osiris-evidence list_returns`
Expected: FAIL — compile error, `list` is not a method of
`SqliteEvidenceStore`/`EvidenceStore`.

- [ ] **Step 3: Implement `EvidenceStore::list()`**

In `crates/osiris-evidence/src/store.rs`, change the trait from:

```rust
pub trait EvidenceStore: Send + Sync {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError>;
    fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError>;
}
```

to:

```rust
/// Matches `osiris_query::MAX_EVENT_LIMIT`'s value — evidence volume
/// tracks event volume, so the same cap is a reasonable default.
pub const MAX_EVIDENCE_LIMIT: usize = 5_000;

pub trait EvidenceStore: Send + Sync {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError>;
    fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError>;
    /// Every evidence record, newest first (`Evidence::timestamp()`
    /// descending), bounded by `MAX_EVIDENCE_LIMIT`. There is no
    /// `raw_json`-adjacent `timestamp` column in the schema (the table
    /// has only `evidence_id`/`raw_json`), so sorting happens in Rust
    /// after deserializing every row rather than via `ORDER BY` — an
    /// acceptable cost at this cap, and avoids a schema migration for a
    /// column that would otherwise duplicate data already in `raw_json`.
    fn list(&self) -> Result<Vec<Evidence>, EvidenceStoreError>;
}
```

Then add the implementation to `impl EvidenceStore for SqliteEvidenceStore`
(after the existing `get` method):

```rust
    fn list(&self) -> Result<Vec<Evidence>, EvidenceStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EvidenceStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT raw_json FROM evidence")
            .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;

        let mut all = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
            let evidence: Evidence =
                serde_json::from_str(&raw_json).map_err(|e| EvidenceStoreError::Serialize(e.to_string()))?;
            all.push(evidence);
        }
        all.sort_by(|a, b| b.timestamp().cmp(&a.timestamp()));
        all.truncate(MAX_EVIDENCE_LIMIT);
        Ok(all)
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p osiris-evidence list_returns`
Expected: PASS (both new tests).

- [ ] **Step 5: Write the failing tests for the unscoped handler**

In `crates/osiris-api/src/evidence.rs`, first update the two *existing*
tests that construct `ListEvidenceQuery` directly, since its field is
about to become `Option<String>`. Change:

```rust
        let list_query = ListEvidenceQuery { incident_id: incident.incident_id.to_string() };
```

to:

```rust
        let list_query = ListEvidenceQuery { incident_id: Some(incident.incident_id.to_string()) };
```

and change:

```rust
        let q = ListEvidenceQuery { incident_id: "not-a-uuid".to_string() };
```

to:

```rust
        let q = ListEvidenceQuery { incident_id: Some("not-a-uuid".to_string()) };
```

The `create_evidence_links_it_to_an_incident_when_given_one` test also
destructures the scoped response directly (`let Json(list) = ...`); update
it to unwrap the new enum wrapper:

```rust
        let Json(created) = create_evidence_handler(State(state.clone()), Json(body)).await.unwrap();

        let list_query = ListEvidenceQuery { incident_id: Some(incident.incident_id.to_string()) };
        let Json(list) = list_evidence_handler(State(state), Query(list_query)).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].evidence_id(), created.evidence_id());
```

to:

```rust
        let Json(created) = create_evidence_handler(State(state.clone()), Json(body)).await.unwrap();

        let list_query = ListEvidenceQuery { incident_id: Some(incident.incident_id.to_string()) };
        let Json(response) = list_evidence_handler(State(state), Query(list_query)).await.unwrap();
        let ListEvidenceResponse::Scoped(list) = response else {
            panic!("expected a scoped response");
        };
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].evidence_id(), created.evidence_id());
```

Then add these two new tests at the end of the `mod tests` block:

```rust
    #[tokio::test]
    async fn list_evidence_without_incident_id_returns_all_evidence_with_incident_ids() {
        let (_dir, state) = test_state();
        let incident = state
            .incidents
            .create(osiris_evidence::Incident {
                incident_id: uuid::Uuid::now_v7(),
                status: osiris_evidence::IncidentStatus::New,
                entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }],
                alert_ids: vec![],
                notes: vec![],
            })
            .unwrap();

        let linked_body = CreateEvidenceBody {
            source: EvidenceSource::EventCapture,
            hash: "linked".to_string(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: Some(incident.incident_id),
        };
        create_evidence_handler(State(state.clone()), Json(linked_body)).await.unwrap();

        let unlinked_body = CreateEvidenceBody {
            source: EvidenceSource::ManualUpload,
            hash: "unlinked".to_string(),
            immutable_since: 2000,
            relationships: vec![],
            supersedes: None,
            incident_id: None,
        };
        create_evidence_handler(State(state.clone()), Json(unlinked_body)).await.unwrap();

        let Json(response) =
            list_evidence_handler(State(state), Query(ListEvidenceQuery { incident_id: None }))
                .await
                .unwrap();
        let ListEvidenceResponse::All(all) = response else {
            panic!("expected an all-evidence response");
        };

        assert_eq!(all.len(), 2);
        let linked = all.iter().find(|item| item.evidence.integrity().hash == "linked").unwrap();
        assert_eq!(linked.incident_ids, vec![incident.incident_id]);
        let unlinked = all.iter().find(|item| item.evidence.integrity().hash == "unlinked").unwrap();
        assert!(unlinked.incident_ids.is_empty());
    }

    #[tokio::test]
    async fn list_evidence_scoped_response_shape_is_unchanged() {
        let (_dir, state) = test_state();
        let incident = state
            .incidents
            .create(osiris_evidence::Incident {
                incident_id: uuid::Uuid::now_v7(),
                status: osiris_evidence::IncidentStatus::New,
                entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }],
                alert_ids: vec![],
                notes: vec![],
            })
            .unwrap();
        let body = CreateEvidenceBody {
            source: EvidenceSource::EventCapture,
            hash: "abc123".to_string(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: Some(incident.incident_id),
        };
        create_evidence_handler(State(state.clone()), Json(body)).await.unwrap();

        let Json(response) = list_evidence_handler(
            State(state),
            Query(ListEvidenceQuery { incident_id: Some(incident.incident_id.to_string()) }),
        )
        .await
        .unwrap();
        let ListEvidenceResponse::Scoped(list) = response else {
            panic!("expected a scoped response");
        };
        let serialized = serde_json::to_value(&list).unwrap();
        assert!(serialized.is_array());
        assert_eq!(serialized[0]["integrity"]["hash"], "abc123");
    }
```

- [ ] **Step 6: Run the tests to verify they fail**

Run: `cargo test -p osiris-api evidence::`
Expected: FAIL — compile errors (`ListEvidenceQuery.incident_id` is still
`String`, `ListEvidenceResponse`/`EvidenceWithIncidents` don't exist,
`state.evidence.list()` doesn't exist yet on the handler side either).

- [ ] **Step 7: Implement the handler changes**

In `crates/osiris-api/src/evidence.rs`, change the query struct from:

```rust
#[derive(Debug, Deserialize)]
pub struct ListEvidenceQuery {
    pub incident_id: String,
}
```

to:

```rust
#[derive(Debug, Deserialize)]
pub struct ListEvidenceQuery {
    pub incident_id: Option<String>,
}
```

Add these two new types immediately above `list_evidence_handler`:

```rust
#[derive(Debug, Serialize)]
pub struct EvidenceWithIncidents {
    pub evidence: Evidence,
    pub incident_ids: Vec<Uuid>,
}

/// `#[serde(untagged)]` means each variant serializes as its inner value
/// directly — a plain JSON array either way. This keeps the existing
/// `?incident_id=` response byte-for-byte the same `Vec<Evidence>` shape
/// while letting the new unscoped path return the richer
/// `Vec<EvidenceWithIncidents>` shape, both from one handler return type.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ListEvidenceResponse {
    Scoped(Vec<Evidence>),
    All(Vec<EvidenceWithIncidents>),
}
```

Add `Serialize` to the existing `use serde::Deserialize;` import line —
change it to `use serde::{Deserialize, Serialize};`.

Then replace `list_evidence_handler` entirely:

```rust
pub async fn list_evidence_handler(
    State(state): State<IncidentEvidenceState>,
    Query(q): Query<ListEvidenceQuery>,
) -> Result<Json<ListEvidenceResponse>, (StatusCode, String)> {
    match q.incident_id {
        Some(incident_id_str) => {
            let incident_id: Uuid = incident_id_str
                .parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid incident_id: {}", incident_id_str)))?;

            let evidence_list = tokio::task::spawn_blocking(move || -> Result<Vec<Evidence>, String> {
                let evidence_ids = state.links.evidence_ids_for_incident(incident_id).map_err(|e| e.to_string())?;
                let mut evidence = Vec::new();
                for id in evidence_ids {
                    if let Some(record) = state.evidence.get(id).map_err(|e| e.to_string())? {
                        evidence.push(record);
                    }
                }
                Ok(evidence)
            })
            .await
            .unwrap()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(ListEvidenceResponse::Scoped(evidence_list)))
        }
        None => {
            let all = tokio::task::spawn_blocking(move || -> Result<Vec<EvidenceWithIncidents>, String> {
                let records = state.evidence.list().map_err(|e| e.to_string())?;
                let mut out = Vec::with_capacity(records.len());
                for evidence in records {
                    let incident_ids =
                        state.links.incident_ids_for_evidence(evidence.evidence_id()).map_err(|e| e.to_string())?;
                    out.push(EvidenceWithIncidents { evidence, incident_ids });
                }
                Ok(out)
            })
            .await
            .unwrap()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(ListEvidenceResponse::All(all)))
        }
    }
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p osiris-api evidence::`
Expected: PASS (all tests in the module, including the 2 new ones and the
2 updated existing ones).

- [ ] **Step 9: Run the full workspace check**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: both pass.

- [ ] **Step 10: Commit**

```bash
git add crates/osiris-evidence/src/store.rs crates/osiris-api/src/evidence.rs
git commit -m "feat(api): add an unscoped GET /api/v1/evidence list, keeping the incident_id-scoped path unchanged"
```

---

### Task 2: Console — Entity Graph data layer + `entityKey` util

**Files:**
- Modify: `console/src/api/types.ts` (add `EntityKind`, `Relation`,
  `GraphNode`, `GraphEdge`, `Subgraph`)
- Modify: `console/src/api/client.ts` (add `fetchSubgraph`)
- Modify: `console/src/api/hooks.ts` (add `useSubgraph`)
- Create: `console/src/api/entityKey.ts` (`entityRefToStorageKey`,
  `describeEntityRef`, `isValidEntityKey`, `KNOWN_ENTITY_KINDS`)
- Test: `console/src/api/client.test.ts` (extend)
- Test: `console/src/api/hooks.test.tsx` (extend)
- Test: `console/src/api/entityKey.test.ts` (new)
- Modify: `console/package.json` (add `react-force-graph-2d` dependency)

**Interfaces:**
- Consumes: `EntityRef` type from `./types` (7b-2, Task 3 of that plan).
- Produces: types `EntityKind`, `Relation`, `GraphNode`, `GraphEdge`,
  `Subgraph` from `./types`; `fetchSubgraph(entity: string, params?:
  {depth?: number; maxNodes?: number; since?: number; until?: number}):
  Promise<Subgraph>` from `./client`; `useSubgraph(entity: string,
  params?: {...})` from `./hooks`; `entityRefToStorageKey(entity:
  EntityRef): string`, `describeEntityRef(entity: EntityRef): string`,
  `isValidEntityKey(key: string): boolean` from `./entityKey`. Task 6
  consumes `entityRefToStorageKey`/`describeEntityRef`; Task 7 (Entity
  Graph screen) consumes `useSubgraph`/`isValidEntityKey`.

- [ ] **Step 1: Add `react-force-graph-2d` as a dependency**

Run: `cd console && npm install react-force-graph-2d@^1.29.1`
Expected: `console/package.json`'s `dependencies` gains
`"react-force-graph-2d": "^1.29.1"` and `console/package-lock.json`
updates.

- [ ] **Step 2: Add the new types**

In `console/src/api/types.ts`, add at the end of the file:

```typescript
export type EntityKind = "PROCESS" | "FILE" | "IP" | "DOMAIN" | "USER" | "CONTAINER" | "SESSION";

export type Relation =
  | "SPAWNED"
  | "EXECUTED_AS"
  | "WROTE"
  | "READ"
  | "CONNECTED_TO"
  | "RESOLVED_TO"
  | "BELONGS_TO_CONTAINER"
  | "BELONGS_TO_POD"
  | "RUNS_IN_CGROUP"
  | "TRIGGERED_BY_SESSION";

export interface GraphNode {
  id: string;
  kind: EntityKind;
}

export interface GraphEdge {
  from: string;
  to: string;
  relation: Relation;
  event_id: string;
  timestamp: number;
}

export interface Subgraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}
```

- [ ] **Step 3: Write the failing test for `entityKey.ts`**

Create `console/src/api/entityKey.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { describeEntityRef, entityRefToStorageKey, isValidEntityKey } from "./entityKey";
import type { EntityRef } from "./types";

describe("entityRefToStorageKey", () => {
  it("formats a PROCESS entity", () => {
    const entity: EntityRef = { kind: "PROCESS", process_key: "abc123" };
    expect(entityRefToStorageKey(entity)).toBe("PROCESS:abc123");
  });

  it("formats a FILE entity", () => {
    const entity: EntityRef = { kind: "FILE", host_id: "h1", inode: 42, device_id: 7 };
    expect(entityRefToStorageKey(entity)).toBe("FILE:h1:42:7");
  });

  it("formats an IP entity", () => {
    const entity: EntityRef = { kind: "IP", addr: "203.0.113.10" };
    expect(entityRefToStorageKey(entity)).toBe("IP:203.0.113.10");
  });

  it("formats a DOMAIN entity", () => {
    const entity: EntityRef = { kind: "DOMAIN", name: "example.com" };
    expect(entityRefToStorageKey(entity)).toBe("DOMAIN:example.com");
  });

  it("formats a USER entity", () => {
    const entity: EntityRef = { kind: "USER", host_id: "h1", uid: 1000 };
    expect(entityRefToStorageKey(entity)).toBe("USER:h1:1000");
  });

  it("formats a CONTAINER entity", () => {
    const entity: EntityRef = { kind: "CONTAINER", container_id: "c1" };
    expect(entityRefToStorageKey(entity)).toBe("CONTAINER:c1");
  });

  it("formats a SESSION entity", () => {
    const entity: EntityRef = { kind: "SESSION", session_id: "s1" };
    expect(entityRefToStorageKey(entity)).toBe("SESSION:s1");
  });
});

describe("describeEntityRef", () => {
  it("describes an IP entity readably", () => {
    const entity: EntityRef = { kind: "IP", addr: "203.0.113.10" };
    expect(describeEntityRef(entity)).toBe("IP 203.0.113.10");
  });
});

describe("isValidEntityKey", () => {
  it("accepts a known-kind key with a non-empty value", () => {
    expect(isValidEntityKey("IP:203.0.113.10")).toBe(true);
    expect(isValidEntityKey("PROCESS:abc123")).toBe(true);
  });

  it("rejects an unknown kind prefix", () => {
    expect(isValidEntityKey("BOGUS:value")).toBe(false);
  });

  it("rejects a key with no colon", () => {
    expect(isValidEntityKey("IP203.0.113.10")).toBe(false);
  });

  it("rejects a key with an empty value", () => {
    expect(isValidEntityKey("IP:")).toBe(false);
  });

  it("accepts a value that itself contains colons (e.g. FILE)", () => {
    expect(isValidEntityKey("FILE:h1:42:7")).toBe(true);
  });
});
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd console && npm test -- entityKey`
Expected: FAIL — `./entityKey` module doesn't exist yet.

- [ ] **Step 5: Implement `entityKey.ts`**

Create `console/src/api/entityKey.ts`:

```typescript
import type { EntityRef } from "./types";

export const KNOWN_ENTITY_KINDS = ["PROCESS", "FILE", "IP", "DOMAIN", "USER", "CONTAINER", "SESSION"] as const;

export function entityRefToStorageKey(entity: EntityRef): string {
  switch (entity.kind) {
    case "PROCESS":
      return `PROCESS:${entity.process_key}`;
    case "FILE":
      return `FILE:${entity.host_id}:${entity.inode}:${entity.device_id}`;
    case "IP":
      return `IP:${entity.addr}`;
    case "DOMAIN":
      return `DOMAIN:${entity.name}`;
    case "USER":
      return `USER:${entity.host_id}:${entity.uid}`;
    case "CONTAINER":
      return `CONTAINER:${entity.container_id}`;
    case "SESSION":
      return `SESSION:${entity.session_id}`;
  }
}

export function describeEntityRef(entity: EntityRef): string {
  switch (entity.kind) {
    case "PROCESS":
      return `Process ${entity.process_key}`;
    case "FILE":
      return `File ${entity.host_id}:${entity.inode}`;
    case "IP":
      return `IP ${entity.addr}`;
    case "DOMAIN":
      return `Domain ${entity.name}`;
    case "USER":
      return `User ${entity.host_id}:${entity.uid}`;
    case "CONTAINER":
      return `Container ${entity.container_id}`;
    case "SESSION":
      return `Session ${entity.session_id}`;
  }
}

export function isValidEntityKey(key: string): boolean {
  const separatorIndex = key.indexOf(":");
  if (separatorIndex === -1) {
    return false;
  }
  const kind = key.slice(0, separatorIndex);
  const value = key.slice(separatorIndex + 1);
  return (KNOWN_ENTITY_KINDS as readonly string[]).includes(kind) && value.length > 0;
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd console && npm test -- entityKey`
Expected: PASS (all tests).

- [ ] **Step 7: Write the failing test for `fetchSubgraph`**

In `console/src/api/client.test.ts`, add the import `fetchSubgraph` to the
existing import block from `"./client"`, then add this test before the
closing `});` of `describe("api client", ...)`:

```typescript
  it("fetchSubgraph calls /api/v1/graph/subgraph with the entity and optional params", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ nodes: [], edges: [], truncated: false }), { status: 200 })
    );

    await fetchSubgraph("IP:203.0.113.10", { depth: 3, maxNodes: 100, since: 1000, until: 2000 });

    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/graph/subgraph?entity=IP%3A203.0.113.10&depth=3&max_nodes=100&since=1000&until=2000"
    );
  });

  it("fetchSubgraph with no optional params only sends entity", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ nodes: [], edges: [], truncated: false }), { status: 200 })
    );

    await fetchSubgraph("IP:203.0.113.10");

    expect(fetch).toHaveBeenCalledWith("/api/v1/graph/subgraph?entity=IP%3A203.0.113.10");
  });
```

- [ ] **Step 8: Run the test to verify it fails**

Run: `cd console && npm test -- client.test`
Expected: FAIL — `fetchSubgraph` doesn't exist yet.

- [ ] **Step 9: Implement `fetchSubgraph`**

In `console/src/api/client.ts`, add `GraphNode`, `GraphEdge`, `Subgraph`
(only `Subgraph` is actually referenced by name; `GraphNode`/`GraphEdge`
are used transitively through it) to the `import type { ... } from
"./types"` block, then add at the end of the file:

```typescript
export function fetchSubgraph(
  entity: string,
  params: { depth?: number; maxNodes?: number; since?: number; until?: number } = {}
): Promise<Subgraph> {
  const search = new URLSearchParams();
  search.set("entity", entity);
  if (params.depth !== undefined) {
    search.set("depth", String(params.depth));
  }
  if (params.maxNodes !== undefined) {
    search.set("max_nodes", String(params.maxNodes));
  }
  if (params.since !== undefined) {
    search.set("since", String(params.since));
  }
  if (params.until !== undefined) {
    search.set("until", String(params.until));
  }
  return apiGet<Subgraph>(`/graph/subgraph?${search.toString()}`);
}
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `cd console && npm test -- client.test`
Expected: PASS (all tests, including the 2 new ones).

- [ ] **Step 11: Write the failing test for `useSubgraph`**

In `console/src/api/hooks.test.tsx`, add `useSubgraph` to the existing
import from `"./hooks"`, then add these tests before the closing `});`
of `describe("api hooks", ...)`:

```tsx
  it("useSubgraph forwards the entity and params to fetchSubgraph", async () => {
    const spy = vi.spyOn(client, "fetchSubgraph").mockResolvedValue({ nodes: [], edges: [], truncated: false });

    const { result } = renderHook(() => useSubgraph("IP:203.0.113.10", { depth: 2 }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("IP:203.0.113.10", { depth: 2 });
  });

  it("useSubgraph does not fire when the entity is an empty string", () => {
    const spy = vi.spyOn(client, "fetchSubgraph").mockResolvedValue({ nodes: [], edges: [], truncated: false });

    const { result } = renderHook(() => useSubgraph(""), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });
```

- [ ] **Step 12: Run the tests to verify they fail**

Run: `cd console && npm test -- hooks.test`
Expected: FAIL — `useSubgraph` doesn't exist yet.

- [ ] **Step 13: Implement `useSubgraph`**

In `console/src/api/hooks.ts`, add `fetchSubgraph` to the existing import
from `"./client"`, then add at the end of the file:

```typescript
export function useSubgraph(
  entity: string,
  params: { depth?: number; maxNodes?: number; since?: number; until?: number } = {}
) {
  return useQuery({
    queryKey: [
      "subgraph",
      entity,
      params.depth ?? "default",
      params.maxNodes ?? "default",
      params.since ?? "all-time",
      params.until ?? "all-time",
    ],
    queryFn: () => fetchSubgraph(entity, params),
    enabled: entity.length > 0,
  });
}
```

- [ ] **Step 14: Run the tests to verify they pass**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (all tests).

- [ ] **Step 15: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 16: Commit**

```bash
git add console/package.json console/package-lock.json console/src/api/
git commit -m "feat(console): add Entity Graph data layer and the entityKey storage-key util"
```

---

### Task 3: Console — Timeline data layer

**Files:**
- Modify: `console/src/api/types.ts` (add `category?: string` to
  `CanonicalEvent`)
- Modify: `console/src/api/client.ts` (add `fetchSystemStory`)
- Modify: `console/src/api/hooks.ts` (add `useSystemStory`)
- Test: `console/src/api/client.test.ts` (extend)
- Test: `console/src/api/hooks.test.tsx` (extend)

**Interfaces:**
- Consumes: `Story` type from `./types` (7b-2, Task 1 of that plan).
- Produces: `fetchSystemStory(hostId: string, params?: {since?: number;
  until?: number}): Promise<Story>` from `./client`; `useSystemStory(hostId:
  string, params?: {...})` from `./hooks`. Task 8 (Timeline screen)
  consumes both.

- [ ] **Step 1: Add the optional `category` field**

In `console/src/api/types.ts`, change `CanonicalEvent` from:

```typescript
export interface CanonicalEvent {
  event_id: string;
  event_type: string;
  timestamp: number;
  host: {
    host_id: string;
    hostname: string;
  };
  process?: ProcessRef | null;
  parent_process?: ProcessRef | null;
  event_data: unknown;
}
```

to:

```typescript
export interface CanonicalEvent {
  event_id: string;
  event_type: string;
  timestamp: number;
  host: {
    host_id: string;
    hostname: string;
  };
  process?: ProcessRef | null;
  parent_process?: ProcessRef | null;
  category?: string;
  event_data: unknown;
}
```

- [ ] **Step 2: Write the failing test for `fetchSystemStory`**

In `console/src/api/client.test.ts`, add `fetchSystemStory` to the
existing import from `"./client"`, then add this test before the closing
`});` of `describe("api client", ...)`:

```typescript
  it("fetchSystemStory calls /api/v1/system/story with host_id and optional since/until", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));

    await fetchSystemStory("host-1", { since: 1000, until: 2000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/system/story?host_id=host-1&since=1000&until=2000");
  });

  it("fetchSystemStory with no optional params only sends host_id", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));

    await fetchSystemStory("host-1");

    expect(fetch).toHaveBeenCalledWith("/api/v1/system/story?host_id=host-1");
  });
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd console && npm test -- client.test`
Expected: FAIL — `fetchSystemStory` doesn't exist yet.

- [ ] **Step 4: Implement `fetchSystemStory`**

In `console/src/api/client.ts`, add at the end of the file:

```typescript
export function fetchSystemStory(hostId: string, params: { since?: number; until?: number } = {}): Promise<Story> {
  const search = new URLSearchParams();
  search.set("host_id", hostId);
  if (params.since !== undefined) {
    search.set("since", String(params.since));
  }
  if (params.until !== undefined) {
    search.set("until", String(params.until));
  }
  return apiGet<Story>(`/system/story?${search.toString()}`);
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd console && npm test -- client.test`
Expected: PASS (all tests, including the 2 new ones).

- [ ] **Step 6: Write the failing test for `useSystemStory`**

In `console/src/api/hooks.test.tsx`, add `useSystemStory` to the existing
import from `"./hooks"`, then add these tests before the closing `});`
of `describe("api hooks", ...)`:

```tsx
  it("useSystemStory forwards hostId and params to fetchSystemStory", async () => {
    const spy = vi.spyOn(client, "fetchSystemStory").mockResolvedValue({ events: [], alerts: [] });

    const { result } = renderHook(() => useSystemStory("host-1", { since: 1000 }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("host-1", { since: 1000 });
  });

  it("useSystemStory does not fire when hostId is an empty string", () => {
    const spy = vi.spyOn(client, "fetchSystemStory").mockResolvedValue({ events: [], alerts: [] });

    const { result } = renderHook(() => useSystemStory(""), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `cd console && npm test -- hooks.test`
Expected: FAIL — `useSystemStory` doesn't exist yet.

- [ ] **Step 8: Implement `useSystemStory`**

In `console/src/api/hooks.ts`, add `fetchSystemStory` to the existing
import from `"./client"`, then add at the end of the file:

```typescript
export function useSystemStory(hostId: string, params: { since?: number; until?: number } = {}) {
  return useQuery({
    queryKey: ["system-story", hostId, params.since ?? "all-time", params.until ?? "all-time"],
    queryFn: () => fetchSystemStory(hostId, params),
    enabled: hostId.length > 0,
  });
}
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (all tests).

- [ ] **Step 10: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 11: Commit**

```bash
git add console/src/api/
git commit -m "feat(console): add Timeline data layer (system story) and CanonicalEvent.category"
```

---

### Task 4: Console — Threat Hunting data layer + hunt templates

**Files:**
- Modify: `console/vite.config.ts` (`server.fs.allow` to permit importing
  files from the repo root's `hunts/` directory)
- Modify: `console/tsconfig.json` (add `"vite/client"` to `types`, needed
  for TypeScript to recognize `*?raw` imports)
- Modify: `console/src/api/client.ts` (extend `fetchEvents` with `q`,
  `until`, `limit` params)
- Modify: `console/src/api/hooks.ts` (extend `useEvents` with `q`,
  `until`, `limit`, `enabled` options)
- Create: `console/src/screens/hunting/templates.ts` (imports the 3
  `.oql` files from `hunts/` via Vite's `?raw` suffix)
- Test: `console/src/api/client.test.ts` (extend)
- Test: `console/src/api/hooks.test.tsx` (extend)
- Test: `console/src/screens/hunting/templates.test.ts` (new)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: extended `fetchEvents(params?: {eventType?: string; since?:
  number; until?: number; limit?: number; q?: string}): Promise<CanonicalEvent[]>`
  from `./client`; extended `useEvents(eventType?: string, options?:
  {since?: number; until?: number; limit?: number; q?: string; enabled?:
  boolean})` from `./hooks`; `HUNT_TEMPLATES: HuntTemplate[]` (with
  `{name: string; label: string; query: string}` shape) from
  `./screens/hunting/templates`. Task 9 (Threat Hunting screen) consumes
  all three.

- [ ] **Step 1: Allow Vite to read files from the repo root**

In `console/vite.config.ts`, change:

```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
```

to:

```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    // Vite's dev server (and Vitest, which shares this config) refuses to
    // serve files outside the project root by default. The three saved
    // hunt templates live in the repo's own `hunts/` directory (one level
    // up), the same source the CLI embeds via `include_str!` — this
    // widens the allowlist to include it, not the whole filesystem.
    fs: {
      allow: [".."],
    },
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
```

- [ ] **Step 2: Add `vite/client` types**

In `console/tsconfig.json`, change:

```json
    "types": ["vitest/globals", "@testing-library/jest-dom"]
```

to:

```json
    "types": ["vite/client", "vitest/globals", "@testing-library/jest-dom"]
```

- [ ] **Step 3: Write the failing test for the hunt templates module**

Create `console/src/screens/hunting/templates.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { HUNT_TEMPLATES } from "./templates";

describe("HUNT_TEMPLATES", () => {
  it("has exactly the 3 templates the CLI also embeds, each non-empty", () => {
    expect(HUNT_TEMPLATES.map((template) => template.name)).toEqual([
      "network-download-then-write",
      "shell-wrote-file-to-web-root",
      "container-started-in-remote-session",
    ]);
    for (const template of HUNT_TEMPLATES) {
      expect(template.query.trim().length).toBeGreaterThan(0);
      expect(template.label.trim().length).toBeGreaterThan(0);
    }
  });

  it("includes the network-download-then-write template's known OQL content", () => {
    const template = HUNT_TEMPLATES.find((t) => t.name === "network-download-then-write");
    expect(template?.query).toContain("NETWORK_CONNECT");
  });
});
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd console && npm test -- templates`
Expected: FAIL — `./templates` module doesn't exist yet.

- [ ] **Step 5: Implement the templates module**

Create `console/src/screens/hunting/templates.ts`:

```typescript
// The .oql files under hunts/ (repo root) are the CLI's own saved hunt
// templates (osiris-cli's `hunts::template`, embedded there via
// `include_str!`). Importing the same files here via Vite's `?raw` suffix
// keeps one source of truth between the CLI and the Console.
import containerStartedInRemoteSession from "../../../../hunts/container-started-in-remote-session.oql?raw";
import networkDownloadThenWrite from "../../../../hunts/network-download-then-write.oql?raw";
import shellWroteFileToWebRoot from "../../../../hunts/shell-wrote-file-to-web-root.oql?raw";

export interface HuntTemplate {
  name: string;
  label: string;
  query: string;
}

export const HUNT_TEMPLATES: HuntTemplate[] = [
  {
    name: "network-download-then-write",
    label: "Network download then write",
    query: networkDownloadThenWrite.trim(),
  },
  {
    name: "shell-wrote-file-to-web-root",
    label: "Shell wrote file to web root",
    query: shellWroteFileToWebRoot.trim(),
  },
  {
    name: "container-started-in-remote-session",
    label: "Container started in remote session",
    query: containerStartedInRemoteSession.trim(),
  },
];
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd console && npm test -- templates`
Expected: PASS (both tests).

- [ ] **Step 7: Write the failing tests for the extended `fetchEvents`/`useEvents`**

In `console/src/api/client.test.ts`, add this test immediately after the
existing `fetchEvents` test(s):

```typescript
  it("fetchEvents with q, until, and limit adds all three query params", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents({ q: 'event_type = "FILE_WRITE"', until: 2000, limit: 50 });

    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/events?q=event_type+%3D+%22FILE_WRITE%22&until=2000&limit=50'
    );
  });
```

In `console/src/api/hooks.test.tsx`, add this test immediately after the
existing `useEvents` test(s):

```tsx
  it("useEvents forwards q, until, limit, and enabled to fetchEvents/useQuery", async () => {
    const spy = vi.spyOn(client, "fetchEvents").mockResolvedValue([]);

    const { result } = renderHook(
      () => useEvents(undefined, { q: 'event_type = "FILE_WRITE"', until: 2000, limit: 50, enabled: true }),
      { wrapper }
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({
      eventType: undefined,
      since: undefined,
      until: 2000,
      limit: 50,
      q: 'event_type = "FILE_WRITE"',
    });
  });

  it("useEvents does not fire when enabled is explicitly false", () => {
    const spy = vi.spyOn(client, "fetchEvents").mockResolvedValue([]);

    const { result } = renderHook(() => useEvents(undefined, { enabled: false }), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });
```

- [ ] **Step 8: Run the tests to verify they fail**

Run: `cd console && npm test -- client.test && cd console && npm test -- hooks.test`
Expected: FAIL — `fetchEvents`/`useEvents` don't accept `q`/`until`/
`limit`/`enabled` yet, so the new assertions don't match.

- [ ] **Step 9: Implement the extended `fetchEvents`**

In `console/src/api/client.ts`, change:

```typescript
export function fetchEvents(
  params: { eventType?: string; since?: number } = {}
): Promise<CanonicalEvent[]> {
  const search = new URLSearchParams();
  if (params.eventType) {
    search.set("event_type", params.eventType);
  }
  if (params.since !== undefined) {
    // `since` mirrors CanonicalEvent.timestamp (nanoseconds since the Unix
    // epoch, per crates/osiris-schema/src/envelope.rs and every sensor's
    // `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()`), not
    // seconds or milliseconds.
    search.set("since", String(params.since));
  }
  const queryString = search.toString();
  return apiGet<CanonicalEvent[]>(`/events${queryString ? `?${queryString}` : ""}`);
}
```

to:

```typescript
export function fetchEvents(
  params: { eventType?: string; since?: number; until?: number; limit?: number; q?: string } = {}
): Promise<CanonicalEvent[]> {
  const search = new URLSearchParams();
  if (params.eventType) {
    search.set("event_type", params.eventType);
  }
  if (params.since !== undefined) {
    // `since`/`until` mirror CanonicalEvent.timestamp (nanoseconds since
    // the Unix epoch, per crates/osiris-schema/src/envelope.rs and every
    // sensor's `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()`),
    // not seconds or milliseconds.
    search.set("since", String(params.since));
  }
  if (params.until !== undefined) {
    search.set("until", String(params.until));
  }
  if (params.limit !== undefined) {
    search.set("limit", String(params.limit));
  }
  if (params.q) {
    search.set("q", params.q);
  }
  const queryString = search.toString();
  return apiGet<CanonicalEvent[]>(`/events${queryString ? `?${queryString}` : ""}`);
}
```

- [ ] **Step 10: Run the client test to verify it passes**

Run: `cd console && npm test -- client.test`
Expected: PASS (all tests, including the new one; the existing
`eventType`/`since`-only tests are unaffected since `until`/`limit`/`q`
stay unset for them).

- [ ] **Step 11: Implement the extended `useEvents`**

In `console/src/api/hooks.ts`, change:

```typescript
export function useEvents(eventType?: string, options: { since?: number } = {}) {
  const { since } = options;
  return useQuery({
    queryKey: ["events", eventType ?? "all", since ?? "all-time"],
    queryFn: () => fetchEvents({ eventType, since }),
  });
}
```

to:

```typescript
export function useEvents(
  eventType?: string,
  options: { since?: number; until?: number; limit?: number; q?: string; enabled?: boolean } = {}
) {
  const { since, until, limit, q, enabled } = options;
  return useQuery({
    queryKey: [
      "events",
      eventType ?? "all",
      since ?? "all-time",
      until ?? "all-time",
      limit ?? "default",
      q ?? "none",
    ],
    queryFn: () => fetchEvents({ eventType, since, until, limit, q }),
    enabled: enabled ?? true,
  });
}
```

- [ ] **Step 12: Run the tests to verify they pass**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (all tests, including the 2 new ones; the existing
`Sensors.tsx`-driving `useEvents("SENSOR_HEALTH", { since })` call
continues to compile and behave identically — `enabled` defaults to
`true`, matching prior behavior).

- [ ] **Step 13: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass. `npm run build`'s `tsc -b` step confirms the `*?raw`
imports in `templates.ts` type-check under the new `vite/client` types
entry.

- [ ] **Step 14: Commit**

```bash
git add console/vite.config.ts console/tsconfig.json console/src/api/ console/src/screens/hunting/
git commit -m "feat(console): extend events data layer with q/until/limit/enabled, add hunt templates"
```

---

### Task 5: Console — Evidence (standalone) data layer

**Files:**
- Modify: `console/src/api/types.ts` (add `EvidenceWithIncidents`)
- Modify: `console/src/api/client.ts` (add `fetchAllEvidence`)
- Modify: `console/src/api/hooks.ts` (add `useAllEvidence`)
- Test: `console/src/api/client.test.ts` (extend)
- Test: `console/src/api/hooks.test.tsx` (extend)

**Interfaces:**
- Consumes: `Evidence` type from `./types` (7b-2, Task 3).
- Produces: `EvidenceWithIncidents` type from `./types`;
  `fetchAllEvidence(): Promise<EvidenceWithIncidents[]>` from `./client`;
  `useAllEvidence()` from `./hooks`. Task 10 (Evidence screen) consumes
  all three.

- [ ] **Step 1: Add the new type**

In `console/src/api/types.ts`, add at the end of the file:

```typescript
export interface EvidenceWithIncidents {
  evidence: Evidence;
  incident_ids: string[];
}
```

- [ ] **Step 2: Write the failing test for `fetchAllEvidence`**

In `console/src/api/client.test.ts`, add `fetchAllEvidence` to the
existing import from `"./client"`, then add this test before the closing
`});` of `describe("api client", ...)`:

```typescript
  it("fetchAllEvidence calls /api/v1/evidence with no query params", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAllEvidence();

    expect(fetch).toHaveBeenCalledWith("/api/v1/evidence");
  });

  it("fetchAllEvidence parses the {evidence, incident_ids} wire shape", async () => {
    const row = {
      evidence: {
        evidence_id: "e1",
        source: "MANUAL_UPLOAD",
        timestamp: 1000,
        integrity: { hash: "abc", immutable_since: 1000 },
        relationships: [],
        supersedes: null,
      },
      incident_ids: ["i1"],
    };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([row]), { status: 200 }));

    const result = await fetchAllEvidence();

    expect(result).toEqual([row]);
  });
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd console && npm test -- client.test`
Expected: FAIL — `fetchAllEvidence` doesn't exist yet.

- [ ] **Step 4: Implement `fetchAllEvidence`**

In `console/src/api/client.ts`, add `EvidenceWithIncidents` to the
`import type { ... } from "./types"` block, then add at the end of the
file:

```typescript
export function fetchAllEvidence(): Promise<EvidenceWithIncidents[]> {
  return apiGet<EvidenceWithIncidents[]>("/evidence");
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd console && npm test -- client.test`
Expected: PASS (all tests, including the 2 new ones).

- [ ] **Step 6: Write the failing test for `useAllEvidence`**

In `console/src/api/hooks.test.tsx`, add `useAllEvidence` to the existing
import from `"./hooks"`, then add this test before the closing `});` of
`describe("api hooks", ...)`:

```tsx
  it("useAllEvidence resolves with fetchAllEvidence's result", async () => {
    const row = {
      evidence: {
        evidence_id: "e1",
        source: "MANUAL_UPLOAD" as const,
        timestamp: 1000,
        integrity: { hash: "abc", immutable_since: 1000 },
        relationships: [],
        supersedes: null,
      },
      incident_ids: ["i1"],
    };
    vi.spyOn(client, "fetchAllEvidence").mockResolvedValue([row]);

    const { result } = renderHook(() => useAllEvidence(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([row]);
  });
```

- [ ] **Step 7: Run the test to verify it fails**

Run: `cd console && npm test -- hooks.test`
Expected: FAIL — `useAllEvidence` doesn't exist yet.

- [ ] **Step 8: Implement `useAllEvidence`**

In `console/src/api/hooks.ts`, add `fetchAllEvidence` to the existing
import from `"./client"`, then add at the end of the file:

```typescript
export function useAllEvidence() {
  return useQuery({
    queryKey: ["evidence", "all"],
    queryFn: fetchAllEvidence,
  });
}
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (all tests).

- [ ] **Step 10: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 11: Commit**

```bash
git add console/src/api/
git commit -m "feat(console): add standalone Evidence data layer"
```

---

### Task 6: Console — correct `uiStore` entity-key format, wire Incident entity pivots

**Files:**
- Modify: `console/src/screens/processes/ProcessDetailScreen.tsx` (fix
  `selectEntity` call format, add a pivot link)
- Modify: `console/src/screens/processes/ProcessDetailScreen.test.tsx`
  (update the existing format-sensitive assertion, add a pivot-link test)
- Modify: `console/src/screens/incidents/IncidentDetailScreen.tsx` (render
  each entity with a pivot link instead of just a count)
- Modify: `console/src/screens/incidents/IncidentDetailScreen.test.tsx`
  (add an entity-pivot test)

**Interfaces:**
- Consumes: `entityRefToStorageKey`, `describeEntityRef` from
  `../../api/entityKey` (Task 2); `useUiStore` from `../../store/uiStore`
  (7b-1).
- Produces: nothing new for later tasks — this task's effect is entirely
  correcting/extending existing screens so Task 7 (Entity Graph) has a
  correctly-formatted `selectedEntity` to read from two real pivot
  sources.

- [ ] **Step 1: Update the existing format-sensitive test**

In `console/src/screens/processes/ProcessDetailScreen.test.tsx`, change:

```tsx
    expect(useUiStore.getState().selectedEntity).toBe("abc123");
```

to:

```tsx
    expect(useUiStore.getState().selectedEntity).toBe("PROCESS:abc123");
```

Then add this test at the end of the `describe("ProcessDetailScreen", ...)`
block:

```tsx
  it("renders a link to view the process in Entity Graph", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcess>);
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcessStory>
    );
    renderAt("abc123");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd console && npm test -- ProcessDetailScreen`
Expected: FAIL — `selectedEntity` is still the bare hex, and the pivot
link doesn't exist yet.

- [ ] **Step 3: Implement the fix and the pivot link**

In `console/src/screens/processes/ProcessDetailScreen.tsx`, change the
import line from:

```tsx
import { useEffect } from "react";
import { useParams } from "react-router-dom";
```

to:

```tsx
import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";
```

Change the effect from:

```tsx
  useEffect(() => {
    selectEntity(processKey);
    return () => selectEntity(null);
  }, [processKey, selectEntity]);
```

to:

```tsx
  useEffect(() => {
    // uiStore.selectedEntity must always hold the full
    // EntityRef::storage_key()-formatted string (KIND:value) — Entity
    // Graph (§16.3) reads this value directly as its seed entity.
    selectEntity(`PROCESS:${processKey}`);
    return () => selectEntity(null);
  }, [processKey, selectEntity]);
```

Add the pivot link inside the `<section aria-label="process detail">`,
immediately after the `</dl>` closing tag:

```tsx
          </dl>
          <Link to="/graph">View in Entity Graph</Link>
          <h2>Children ({detail.data.children.length})</h2>
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd console && npm test -- ProcessDetailScreen`
Expected: PASS (all tests).

- [ ] **Step 5: Write the failing test for Incident entity pivots**

In `console/src/screens/incidents/IncidentDetailScreen.test.tsx`, add
`useUiStore` import:

```tsx
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { IncidentDetailScreen } from "./IncidentDetailScreen";
```

becomes:

```tsx
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { IncidentDetailScreen } from "./IncidentDetailScreen";
```

Add a `beforeEach` at the top of the `describe("IncidentDetailScreen", ...)`
block:

```tsx
describe("IncidentDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("shows loading states for incident and evidence", () => {
```

Then add this test at the end of the `describe` block:

```tsx
  it("renders each entity with a pivot link that writes its storage key to uiStore", () => {
    vi.mocked(hooks.useIncident).mockReturnValue(
      mockQueryResult({
        data: {
          incident_id: "i1",
          status: "NEW",
          entities: [{ kind: "IP", addr: "203.0.113.10" }],
          alert_ids: [],
          notes: [],
        },
      }) as ReturnType<typeof hooks.useIncident>
    );
    vi.mocked(hooks.useEvidence).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvidence>);
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>);
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.useCreateEvidence>);
    renderAt("i1");

    expect(screen.getByText("IP 203.0.113.10")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");

    link.click();

    expect(useUiStore.getState().selectedEntity).toBe("IP:203.0.113.10");
  });
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd console && npm test -- IncidentDetailScreen`
Expected: FAIL — entities still render only as a count, no pivot link.

- [ ] **Step 7: Implement the entity list + pivot links**

In `console/src/screens/incidents/IncidentDetailScreen.tsx`, change the
import block from:

```tsx
import { useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import {
  useCreateEvidence,
  useEvidence,
  useIncident,
  usePatchIncidentStatus,
} from "../../api/hooks";
import type { IncidentStatus } from "../../api/types";
```

to:

```tsx
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import {
  useCreateEvidence,
  useEvidence,
  useIncident,
  usePatchIncidentStatus,
} from "../../api/hooks";
import { describeEntityRef, entityRefToStorageKey } from "../../api/entityKey";
import type { IncidentStatus } from "../../api/types";
import { useUiStore } from "../../store/uiStore";
```

Add `const selectEntity = useUiStore((state) => state.selectEntity);`
immediately after the existing `const createEvidence = useCreateEvidence(incidentId);`
line.

Change:

```tsx
            <dt>Entities</dt>
            <dd>{incident.data.entities.length}</dd>
```

to:

```tsx
            <dt>Entities</dt>
            <dd>
              {incident.data.entities.length === 0 ? (
                "0"
              ) : (
                <ul>
                  {incident.data.entities.map((entity, index) => (
                    <li key={index}>
                      {describeEntityRef(entity)}{" "}
                      <Link to="/graph" onClick={() => selectEntity(entityRefToStorageKey(entity))}>
                        View in Entity Graph
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </dd>
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd console && npm test -- IncidentDetailScreen`
Expected: PASS (all tests).

- [ ] **Step 9: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 10: Commit**

```bash
git add console/src/screens/processes/ProcessDetailScreen.tsx console/src/screens/processes/ProcessDetailScreen.test.tsx console/src/screens/incidents/IncidentDetailScreen.tsx console/src/screens/incidents/IncidentDetailScreen.test.tsx
git commit -m "fix(console): store selectedEntity as a KIND:value storage key, add Entity Graph pivots"
```

---

### Task 7: Console — Entity Graph screen

**Files:**
- Create: `console/src/screens/graph/EntityGraph.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/graph/EntityGraph.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useSubgraph`, `isValidEntityKey` (Task 2); `useUiStore`
  (7b-1, corrected format from Task 6).
- Produces: `EntityGraph` component from `./EntityGraph`, mounted at
  `/graph`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/graph/EntityGraph.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { EntityGraph } from "./EntityGraph";

vi.mock("../../api/hooks");
vi.mock("react-force-graph-2d", () => ({
  default: (props: { graphData: { nodes: unknown[]; links: unknown[] } }) => (
    <div data-testid="force-graph" data-node-count={props.graphData.nodes.length} data-link-count={props.graphData.links.length} />
  ),
}));

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useSubgraph>;
}

describe("EntityGraph", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("shows the empty manual-entry state when no entity is selected", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({}));
    render(<EntityGraph />);
    expect(screen.getByLabelText("Entity key")).toHaveValue("");
  });

  it("auto-loads the pivoted-from entity from uiStore on mount", () => {
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({}));

    render(<EntityGraph />);

    expect(screen.getByLabelText("Entity key")).toHaveValue("IP:203.0.113.10");
    expect(hooks.useSubgraph).toHaveBeenCalledWith("IP:203.0.113.10");
  });

  it("rejects an invalid manual entry without calling useSubgraph with it", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({}));
    render(<EntityGraph />);

    fireEvent.change(screen.getByLabelText("Entity key"), { target: { value: "not-a-valid-key" } });
    fireEvent.click(screen.getByText("Load"));

    expect(screen.getByRole("alert")).toHaveTextContent("not a valid entity key");
  });

  it("shows a loading state while the subgraph is loading", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({ isLoading: true }));
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);
    expect(screen.getByText("Loading graph…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows a truncated banner when the subgraph was clipped", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(
      mockQueryResult({ data: { nodes: [], edges: [], truncated: true } })
    );
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);
    expect(screen.getByRole("status")).toHaveTextContent("truncated");
  });

  it("renders the force graph with the mapped nodes/links once loaded", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(
      mockQueryResult({
        data: {
          nodes: [
            { id: "IP:203.0.113.10", kind: "IP" },
            { id: "PROCESS:abc123", kind: "PROCESS" },
          ],
          edges: [
            { from: "PROCESS:abc123", to: "IP:203.0.113.10", relation: "CONNECTED_TO", event_id: "e1", timestamp: 1000 },
          ],
          truncated: false,
        },
      })
    );
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);

    const graph = screen.getByTestId("force-graph");
    expect(graph).toHaveAttribute("data-node-count", "2");
    expect(graph).toHaveAttribute("data-link-count", "1");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- EntityGraph`
Expected: FAIL — `./EntityGraph` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/graph/EntityGraph.tsx`:

```tsx
import { useEffect, useState, type FormEvent } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { useSubgraph } from "../../api/hooks";
import { isValidEntityKey } from "../../api/entityKey";
import { useUiStore } from "../../store/uiStore";

export function EntityGraph() {
  const selectedEntity = useUiStore((state) => state.selectedEntity);
  const [entityInput, setEntityInput] = useState(selectedEntity ?? "");
  const [activeEntity, setActiveEntity] = useState(selectedEntity ?? "");
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    if (selectedEntity) {
      setEntityInput(selectedEntity);
      setActiveEntity(selectedEntity);
    }
    // Reacts only to a change in the pivoted-from entity — deliberately
    // omits entityInput/activeEntity from deps so typing in the manual
    // field is never clobbered by a stale selectedEntity re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEntity]);

  const subgraph = useSubgraph(activeEntity);

  function handleLoad(event: FormEvent) {
    event.preventDefault();
    if (!isValidEntityKey(entityInput)) {
      setValidationError(`"${entityInput}" is not a valid entity key (expected KIND:value)`);
      return;
    }
    setValidationError(null);
    setActiveEntity(entityInput);
  }

  const graphData = subgraph.data
    ? {
        nodes: subgraph.data.nodes,
        links: subgraph.data.edges.map((edge) => ({ ...edge, source: edge.from, target: edge.to })),
      }
    : { nodes: [], links: [] };

  return (
    <div>
      <h1>Entity Graph</h1>
      <form onSubmit={handleLoad}>
        <input
          type="text"
          aria-label="Entity key"
          placeholder="KIND:value, e.g. IP:203.0.113.10"
          value={entityInput}
          onChange={(event) => setEntityInput(event.target.value)}
        />
        <button type="submit">Load</button>
      </form>
      {validationError && <p role="alert">{validationError}</p>}
      {activeEntity && subgraph.isLoading && <p>Loading graph…</p>}
      {activeEntity && subgraph.isError && (
        <p role="alert">Failed to load graph: {(subgraph.error as Error).message}</p>
      )}
      {subgraph.data?.truncated && (
        <p role="status">Graph truncated — not all reachable nodes are shown.</p>
      )}
      {activeEntity && subgraph.data && (
        <div style={{ height: 600 }}>
          <ForceGraph2D graphData={graphData} nodeId="id" nodeLabel="id" nodeAutoColorBy="kind" />
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- EntityGraph`
Expected: PASS (7 tests).

- [ ] **Step 5: Wire it into the route table**

In `console/src/App.tsx`, add the import in alphabetical position:

```tsx
import { Alerts } from "./screens/alerts/Alerts";
import { ComingSoon } from "./screens/ComingSoon";
import { EntityGraph } from "./screens/graph/EntityGraph";
import { IncidentDetailScreen } from "./screens/incidents/IncidentDetailScreen";
```

and change:

```tsx
              <Route path="/graph" element={<ComingSoon label="Entity Graph" />} />
```

to:

```tsx
              <Route path="/graph" element={<EntityGraph />} />
```

- [ ] **Step 6: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Entity Graph", path: "/graph", enabled: false },
```

to:

```typescript
  { label: "Entity Graph", path: "/graph", enabled: true },
```

- [ ] **Step 7: Update `App.test.tsx` for the newly-enabled Entity Graph link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly five nav links, for Overview, Process Explorer, Alerts, Incidents, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(5);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Alerts",
      "Incidents",
      "Sensors",
    ]);
  });
```

with:

```tsx
  it("renders exactly six nav links, for Overview, Process Explorer, Alerts, Incidents, Entity Graph, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(6);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Alerts",
      "Incidents",
      "Entity Graph",
      "Sensors",
    ]);
  });
```

- [ ] **Step 8: Run the full test suite**

Run: `cd console && npm test`
Expected: PASS (all tests). `App.test.tsx` mounts the real `EntityGraph`,
which calls the real (unmocked) `useSubgraph` — since no `selectedEntity`
is set and `enabled: entity.length > 0` gates it, this renders the empty
manual-entry state without firing a request, matching the pattern already
accepted for `Overview`/`ProcessList` in prior phases.

- [ ] **Step 9: Verify build and lint**

Run: `cd console && npm run build && npm run lint`
Expected: both succeed.

- [ ] **Step 10: Commit**

```bash
git add console/src/screens/graph/ console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Entity Graph screen"
```

---

### Task 8: Console — Timeline screen

**Files:**
- Create: `console/src/screens/timeline/Timeline.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/timeline/Timeline.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useEvents` (Task 4), `useSystemStory` (Task 3),
  `rollupSensorHealth` from `../sensors/rollup` (7b-1).
- Produces: `Timeline` component from `./Timeline`, mounted at
  `/timeline`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/timeline/Timeline.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Timeline } from "./Timeline";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  };
}

const sensorHealthEvent = (hostId: string) => ({
  event_id: `sh-${hostId}`,
  event_type: "SENSOR_HEALTH",
  timestamp: 1000,
  host: { host_id: hostId, hostname: hostId },
  event_data: { sensor_name: "process", state: { state: "HEALTHY" }, events_processed: 1, last_event_at: 1000 },
});

describe("Timeline", () => {
  it("shows a host dropdown populated from sensor health events, with none selected by default", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ data: [sensorHealthEvent("host-a"), sensorHealthEvent("host-b")] }) as ReturnType<
        typeof hooks.useEvents
      >
    );
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);

    expect(screen.getByLabelText("Host")).toHaveValue("");
    expect(screen.getByRole("option", { name: "host-a" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "host-b" })).toBeInTheDocument();
  });

  it("prompts to select a host when none is chosen", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvents>);
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);

    expect(screen.getByText("Select a host to load its timeline.")).toBeInTheDocument();
  });

  it("forwards the selected host and time range to useSystemStory", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ data: [sensorHealthEvent("host-a")] }) as ReturnType<typeof hooks.useEvents>
    );
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);
    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "host-a" } });
    fireEvent.change(screen.getByLabelText("Since (nanoseconds)"), { target: { value: "1000" } });
    fireEvent.change(screen.getByLabelText("Until (nanoseconds)"), { target: { value: "2000" } });

    expect(hooks.useSystemStory).toHaveBeenLastCalledWith("host-a", { since: 1000, until: 2000 });
  });

  it("renders events chronologically with a category badge", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ data: [sensorHealthEvent("host-a")] }) as ReturnType<typeof hooks.useEvents>
    );
    vi.mocked(hooks.useSystemStory).mockReturnValue(
      mockQueryResult({
        data: {
          events: [
            { event_id: "e2", event_type: "FILE_WRITE", timestamp: 2000, host: { host_id: "host-a", hostname: "h" }, category: "FILE", event_data: {} },
            { event_id: "e1", event_type: "PROCESS_EXEC", timestamp: 1000, host: { host_id: "host-a", hostname: "h" }, category: "PROCESS", event_data: {} },
          ],
          alerts: [],
        },
      }) as ReturnType<typeof hooks.useSystemStory>
    );

    render(<Timeline />);
    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "host-a" } });

    const items = screen.getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("PROCESS");
    expect(items[0]).toHaveTextContent("PROCESS_EXEC");
    expect(items[1]).toHaveTextContent("FILE");
    expect(items[1]).toHaveTextContent("FILE_WRITE");
  });

  it("applies the last-1-hour quick-select to the since field", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvents>);
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);
    fireEvent.click(screen.getByText("Last 1 hour"));

    expect(screen.getByLabelText("Since (nanoseconds)")).not.toHaveValue("");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- Timeline`
Expected: FAIL — `./Timeline` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/timeline/Timeline.tsx`:

```tsx
import { useMemo, useState } from "react";
import { useEvents, useSystemStory } from "../../api/hooks";
import { rollupSensorHealth } from "../sensors/rollup";

const ONE_HOUR_NS = 3_600 * 1_000_000_000;

export function Timeline() {
  const [hostId, setHostId] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");

  // Same staleness guard as Sensors.tsx (7b-1): GET /events defaults to
  // ORDER BY timestamp ASC with a 500-row cap, so bound the window used
  // to discover known hosts to a recent range.
  const healthSince = useMemo(() => Date.now() * 1_000_000 - ONE_HOUR_NS, []);
  const healthEvents = useEvents("SENSOR_HEALTH", { since: healthSince });
  const hostIds = useMemo(() => {
    const rows = healthEvents.data ? rollupSensorHealth(healthEvents.data) : [];
    return Array.from(new Set(rows.map((row) => row.hostId))).sort();
  }, [healthEvents.data]);

  const parsedSince = since ? Number(since) : undefined;
  const parsedUntil = until ? Number(until) : undefined;
  const story = useSystemStory(hostId, { since: parsedSince, until: parsedUntil });

  function setLastHour() {
    setSince(String(Date.now() * 1_000_000 - ONE_HOUR_NS));
    setUntil("");
  }

  return (
    <div>
      <h1>Timeline</h1>
      <label>
        Host
        <select aria-label="Host" value={hostId} onChange={(event) => setHostId(event.target.value)}>
          <option value="">Select a host…</option>
          {hostIds.map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
      </label>
      <input
        type="text"
        aria-label="Since (nanoseconds)"
        placeholder="Since (ns)"
        value={since}
        onChange={(event) => setSince(event.target.value)}
      />
      <input
        type="text"
        aria-label="Until (nanoseconds)"
        placeholder="Until (ns)"
        value={until}
        onChange={(event) => setUntil(event.target.value)}
      />
      <button type="button" onClick={setLastHour}>
        Last 1 hour
      </button>
      {!hostId && <p>Select a host to load its timeline.</p>}
      {hostId && story.isLoading && <p>Loading timeline…</p>}
      {hostId && story.isError && (
        <p role="alert">Failed to load timeline: {(story.error as Error).message}</p>
      )}
      {hostId && story.data && story.data.events.length === 0 && <p>No events in range.</p>}
      {hostId && story.data && story.data.events.length > 0 && (
        <ul>
          {story.data.events
            .slice()
            .sort((a, b) => a.timestamp - b.timestamp)
            .map((event) => (
              <li key={event.event_id}>
                <span>{event.category ?? "UNKNOWN"}</span> {event.event_type} @ {event.timestamp}
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- Timeline`
Expected: PASS (5 tests).

- [ ] **Step 5: Wire it into the route table**

In `console/src/App.tsx`, add the import in alphabetical position:

```tsx
import { Sensors } from "./screens/sensors/Sensors";
import { Timeline } from "./screens/timeline/Timeline";
```

and change:

```tsx
              <Route path="/timeline" element={<ComingSoon label="Timeline" />} />
```

to:

```tsx
              <Route path="/timeline" element={<Timeline />} />
```

- [ ] **Step 6: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Timeline", path: "/timeline", enabled: false },
```

to:

```typescript
  { label: "Timeline", path: "/timeline", enabled: true },
```

- [ ] **Step 7: Update `App.test.tsx` for the newly-enabled Timeline link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly six nav links, for Overview, Process Explorer, Alerts, Incidents, Entity Graph, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(6);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Alerts",
      "Incidents",
      "Entity Graph",
      "Sensors",
    ]);
  });
```

with:

```tsx
  it("renders exactly seven nav links, for Overview, Process Explorer, Timeline, Alerts, Incidents, Entity Graph, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(7);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Timeline",
      "Alerts",
      "Incidents",
      "Entity Graph",
      "Sensors",
    ]);
  });
```

(`Timeline`'s `NAV_ITEMS` array position is between Process Explorer and
Alerts — see `navItems.ts`'s declaration order — which is why it slots in
there rather than at the end.)

- [ ] **Step 8: Run the full test suite**

Run: `cd console && npm test`
Expected: PASS (all tests).

- [ ] **Step 9: Verify build and lint**

Run: `cd console && npm run build && npm run lint`
Expected: both succeed.

- [ ] **Step 10: Commit**

```bash
git add console/src/screens/timeline/ console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Timeline screen"
```

---

### Task 9: Console — Threat Hunting screen

**Files:**
- Create: `console/src/screens/hunting/ThreatHunting.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/hunting/ThreatHunting.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useEvents` (Task 4), `HUNT_TEMPLATES` (Task 4).
- Produces: `ThreatHunting` component from `./ThreatHunting`, mounted at
  `/hunting`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/hunting/ThreatHunting.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ThreatHunting } from "./ThreatHunting";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useEvents>;
}

describe("ThreatHunting", () => {
  it("does not run a query before Run is clicked", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);
    expect(hooks.useEvents).toHaveBeenLastCalledWith(undefined, expect.objectContaining({ enabled: false }));
  });

  it("disables Run while the query textarea is empty", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);
    expect(screen.getByText("Run")).toBeDisabled();
  });

  it("selecting a template fills the textarea with its content", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("Template"), { target: { value: "network-download-then-write" } });

    expect(screen.getByLabelText("OQL query")).toHaveValue('event_type = "NETWORK_CONNECT" OR event_type = "FILE_WRITE"');
  });

  it("runs the typed query and enables useEvents with q set", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("OQL query"), { target: { value: 'event_type = "FILE_WRITE"' } });
    fireEvent.click(screen.getByText("Run"));

    expect(hooks.useEvents).toHaveBeenLastCalledWith(
      undefined,
      expect.objectContaining({ q: 'event_type = "FILE_WRITE"', enabled: true })
    );
  });

  it("renders results once the query has run", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({
        data: [
          { event_id: "e1", event_type: "FILE_WRITE", timestamp: 1000, host: { host_id: "h1", hostname: "host-a" }, event_data: {} },
        ],
      })
    );
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("OQL query"), { target: { value: 'event_type = "FILE_WRITE"' } });
    fireEvent.click(screen.getByText("Run"));

    expect(screen.getByText("FILE_WRITE")).toBeInTheDocument();
    expect(screen.getByText("host-a")).toBeInTheDocument();
  });

  it("shows a query error via ApiError's surfaced message", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("GET /events failed with status 400: unexpected token") })
    );
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("OQL query"), { target: { value: "not valid oql" } });
    fireEvent.click(screen.getByText("Run"));

    expect(screen.getByRole("alert")).toHaveTextContent("unexpected token");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- ThreatHunting`
Expected: FAIL — `./ThreatHunting` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/hunting/ThreatHunting.tsx`:

```tsx
import { useState, type ChangeEvent, type FormEvent } from "react";
import { useEvents } from "../../api/hooks";
import { HUNT_TEMPLATES } from "./templates";

export function ThreatHunting() {
  const [query, setQuery] = useState("");
  const [ranQuery, setRanQuery] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [limit, setLimit] = useState("");

  const results = useEvents(undefined, {
    q: ranQuery || undefined,
    since: since ? Number(since) : undefined,
    until: until ? Number(until) : undefined,
    limit: limit ? Number(limit) : undefined,
    enabled: ranQuery.length > 0,
  });

  function handleTemplateSelect(event: ChangeEvent<HTMLSelectElement>) {
    const template = HUNT_TEMPLATES.find((t) => t.name === event.target.value);
    if (template) {
      setQuery(template.query);
    }
  }

  function handleRun(event: FormEvent) {
    event.preventDefault();
    setRanQuery(query);
  }

  return (
    <div>
      <h1>Threat Hunting</h1>
      <form onSubmit={handleRun}>
        <label>
          Template
          <select aria-label="Template" defaultValue="" onChange={handleTemplateSelect}>
            <option value="">Choose a template…</option>
            {HUNT_TEMPLATES.map((template) => (
              <option key={template.name} value={template.name}>
                {template.label}
              </option>
            ))}
          </select>
        </label>
        <textarea
          aria-label="OQL query"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <input
          type="text"
          aria-label="Since (nanoseconds)"
          placeholder="Since (ns)"
          value={since}
          onChange={(event) => setSince(event.target.value)}
        />
        <input
          type="text"
          aria-label="Until (nanoseconds)"
          placeholder="Until (ns)"
          value={until}
          onChange={(event) => setUntil(event.target.value)}
        />
        <input
          type="text"
          aria-label="Limit"
          placeholder="Limit"
          value={limit}
          onChange={(event) => setLimit(event.target.value)}
        />
        <button type="submit" disabled={!query.trim()}>
          Run
        </button>
      </form>
      {ranQuery && results.isLoading && <p>Running query…</p>}
      {ranQuery && results.isError && (
        <p role="alert">Query failed: {(results.error as Error).message}</p>
      )}
      {ranQuery && results.data && results.data.length === 0 && <p>No matching events.</p>}
      {ranQuery && results.data && results.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Event type</th>
              <th>Timestamp</th>
              <th>Host</th>
            </tr>
          </thead>
          <tbody>
            {results.data.map((event) => (
              <tr key={event.event_id}>
                <td>{event.event_type}</td>
                <td>{event.timestamp}</td>
                <td>{event.host.hostname}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- ThreatHunting`
Expected: PASS (6 tests).

- [ ] **Step 5: Wire it into the route table**

In `console/src/App.tsx`, add the import in alphabetical position:

```tsx
import { Sensors } from "./screens/sensors/Sensors";
import { ThreatHunting } from "./screens/hunting/ThreatHunting";
import { Timeline } from "./screens/timeline/Timeline";
```

and change:

```tsx
              <Route path="/hunting" element={<ComingSoon label="Threat Hunting" />} />
```

to:

```tsx
              <Route path="/hunting" element={<ThreatHunting />} />
```

- [ ] **Step 6: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Threat Hunting", path: "/hunting", enabled: false },
```

to:

```typescript
  { label: "Threat Hunting", path: "/hunting", enabled: true },
```

- [ ] **Step 7: Update `App.test.tsx` for the newly-enabled Threat Hunting link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly seven nav links, for Overview, Process Explorer, Timeline, Alerts, Incidents, Entity Graph, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(7);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Timeline",
      "Alerts",
      "Incidents",
      "Entity Graph",
      "Sensors",
    ]);
  });
```

with:

```tsx
  it("renders exactly eight nav links, for Overview, Process Explorer, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(8);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Timeline",
      "Alerts",
      "Incidents",
      "Threat Hunting",
      "Entity Graph",
      "Sensors",
    ]);
  });
```

- [ ] **Step 8: Run the full test suite**

Run: `cd console && npm test`
Expected: PASS (all tests).

- [ ] **Step 9: Verify build and lint**

Run: `cd console && npm run build && npm run lint`
Expected: both succeed.

- [ ] **Step 10: Commit**

```bash
git add console/src/screens/hunting/ThreatHunting.tsx console/src/screens/hunting/ThreatHunting.test.tsx console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Threat Hunting screen"
```

---

### Task 10: Console — Evidence (standalone) screen

**Files:**
- Create: `console/src/screens/evidence/EvidenceList.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/evidence/EvidenceList.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useAllEvidence` (Task 5).
- Produces: `EvidenceList` component from `./EvidenceList`, mounted at
  `/evidence`. Named `EvidenceList` (not `Evidence`) to avoid colliding
  with the `Evidence` type from `api/types`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/evidence/EvidenceList.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { EvidenceList } from "./EvidenceList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useAllEvidence>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <EvidenceList />
    </MemoryRouter>
  );
}

describe("EvidenceList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading evidence…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No evidence recorded.")).toBeInTheDocument();
  });

  it("renders a row per evidence record with a linked incident", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(
      mockQueryResult({
        data: [
          {
            evidence: {
              evidence_id: "e1",
              source: "MANUAL_UPLOAD",
              timestamp: 1000,
              integrity: { hash: "abc123", immutable_since: 1000 },
              relationships: [],
              supersedes: null,
            },
            incident_ids: ["i1"],
          },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByText("MANUAL_UPLOAD")).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "i1" });
    expect(link).toHaveAttribute("href", "/incidents/i1");
  });

  it("shows a dash for evidence with no linked incident", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(
      mockQueryResult({
        data: [
          {
            evidence: {
              evidence_id: "e1",
              source: "EVENT_CAPTURE",
              timestamp: 1000,
              integrity: { hash: "abc123", immutable_since: 1000 },
              relationships: [],
              supersedes: null,
            },
            incident_ids: [],
          },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- EvidenceList`
Expected: FAIL — `./EvidenceList` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/evidence/EvidenceList.tsx`:

```tsx
import { Link } from "react-router-dom";
import { useAllEvidence } from "../../api/hooks";

export function EvidenceList() {
  const evidence = useAllEvidence();
  const rows = evidence.data ?? [];

  return (
    <div>
      <h1>Evidence</h1>
      {evidence.isLoading && <p>Loading evidence…</p>}
      {evidence.isError && (
        <p role="alert">Failed to load evidence: {(evidence.error as Error).message}</p>
      )}
      {!evidence.isLoading && !evidence.isError && rows.length === 0 && <p>No evidence recorded.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Timestamp</th>
              <th>Hash</th>
              <th>Incidents</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.evidence.evidence_id}>
                <td>{row.evidence.source}</td>
                <td>{row.evidence.timestamp}</td>
                <td>{row.evidence.integrity.hash}</td>
                <td>
                  {row.incident_ids.length === 0
                    ? "—"
                    : row.incident_ids.map((id, index) => (
                        <span key={id}>
                          {index > 0 && ", "}
                          <Link to={`/incidents/${id}`}>{id}</Link>
                        </span>
                      ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- EvidenceList`
Expected: PASS (5 tests).

- [ ] **Step 5: Wire it into the route table**

In `console/src/App.tsx`, add the import in alphabetical position:

```tsx
import { EntityGraph } from "./screens/graph/EntityGraph";
import { EvidenceList } from "./screens/evidence/EvidenceList";
```

and change:

```tsx
              <Route path="/evidence" element={<ComingSoon label="Evidence" />} />
```

to:

```tsx
              <Route path="/evidence" element={<EvidenceList />} />
```

- [ ] **Step 6: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Evidence", path: "/evidence", enabled: false },
```

to:

```typescript
  { label: "Evidence", path: "/evidence", enabled: true },
```

- [ ] **Step 7: Update `App.test.tsx` for the newly-enabled Evidence link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly eight nav links, for Overview, Process Explorer, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(8);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Timeline",
      "Alerts",
      "Incidents",
      "Threat Hunting",
      "Entity Graph",
      "Sensors",
    ]);
  });
```

with:

```tsx
  it("renders exactly nine nav links, for Overview, Process Explorer, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, Evidence, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(9);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Process Explorer",
      "Timeline",
      "Alerts",
      "Incidents",
      "Threat Hunting",
      "Entity Graph",
      "Evidence",
      "Sensors",
    ]);
  });
```

- [ ] **Step 8: Run the full test suite**

Run: `cd console && npm test`
Expected: PASS (all tests).

- [ ] **Step 9: Verify build and lint**

Run: `cd console && npm run build && npm run lint`
Expected: both succeed.

- [ ] **Step 10: Commit**

```bash
git add console/src/screens/evidence/ console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the standalone Evidence screen"
```

---

### Task 11: Manual e2e smoke verification

**Files:** none (no code changes — verification only, matching 7b-1's
and 7b-2's own Task 9 precedent).

**Interfaces:**
- Consumes: everything from Tasks 1-10.
- Produces: a verification report appended to the SDD ledger (or, if run
  outside that process, reported directly) — no code artifact.

- [ ] **Step 1: Build the backend binaries**

Run: `cargo build -p osiris-cli -p osiris-server`
Expected: builds cleanly (e2e-style manual checks below need these
pre-built, matching 7b-1/7b-2's own noted quirk).

- [ ] **Step 2: Start the server against a scratch config**

Reuse or recreate a scratch server config with `dev_cors: true` and all
of `incidents_db_path`/`evidence_db_path`/`links_db_path`/
`investigate_audit_log_path`/`baseline_db_path` pointed at writable
scratch paths (per 7b-1/7b-2's ledger notes — the minimal config fails
fast without these). Start it:

Run: `cargo run --bin osiris-server -- --config <scratch-config-path>` (background)
Expected: server listens on the configured address without error.

- [ ] **Step 3: Seed data for each new screen's verification**

Using the same temporary `#[ignore]`d-test-then-revert approach 7b-1/7b-2
used (or any other write path already in the system, e.g. `osiris hunt`
against real sensor output if available), seed:
- At least 2 events forming a graph relationship (e.g. a `PROCESS_EXEC`
  followed by a `NETWORK_CONNECT` from the same process, so `ConnectedTo`
  edges exist) for Entity Graph.
- At least 2 events on the same `host_id` across a time range, for
  Timeline.
- At least 1 `FILE_WRITE` event, for Threat Hunting's
  `network-download-then-write`/`shell-wrote-file-to-web-root` templates
  to plausibly match (or confirm empty-results renders correctly if none
  match).
- At least 1 evidence record linked to an incident and 1 unlinked (via
  `POST /api/v1/incidents` then `POST /api/v1/evidence` with and without
  `incident_id`), for Evidence.

Revert/clean up any temporary test code used to seed this data, and
confirm `git status --porcelain` is empty afterward.

- [ ] **Step 4: Start the Console dev server**

Run: `cd console && npm run dev` (background)
Expected: Vite serves on its default port with the `/api` proxy active.

- [ ] **Step 5: Verify each new/changed backend path directly over HTTP**

Using the exact Vite-proxy path the Console's `fetch()` calls use
(`http://localhost:<vite-port>/api/v1/...`), matching 7b-1/7b-2's own
precedent when the Chrome browser extension isn't connected this session:

- `GET /api/v1/graph/subgraph?entity=<seeded entity key>` → a `Subgraph`
  with the expected nodes/edges and `truncated: false`.
- `GET /api/v1/system/story?host_id=<seeded host>` → a `Story` containing
  the seeded events.
- `GET /api/v1/events?q=event_type+%3D+%22FILE_WRITE%22` → the seeded
  `FILE_WRITE` event(s).
- `GET /api/v1/evidence` (no `incident_id`) → both seeded evidence
  records, the linked one carrying its `incident_ids`, the unlinked one
  with an empty array.
- `GET /api/v1/evidence?incident_id=<seeded incident>` → confirms this
  path's response shape is still a bare array (not the new
  `{evidence, incident_ids}` wrapper) — i.e. Incident Detail's existing
  nested evidence list is unaffected.

- [ ] **Step 6: Visual confirmation, if the Chrome browser extension is connected**

If available this session, open each of the 4 screens
(`/graph`, `/timeline`, `/hunting`, `/evidence`) in the browser via the
Console dev server and confirm: Entity Graph renders the force-directed
graph canvas for the seeded entity; Timeline's host dropdown lists the
seeded host and renders its events; Threat Hunting's template dropdown
fills the textarea and Run displays results; Evidence lists both seeded
records with the linked one showing a working `/incidents/:id` link. If
the extension isn't connected, log this as an explicitly disclosed gap
(matching 7b-1/7b-2's own precedent) rather than silently skipping it —
the HTTP-level checks in Step 5 already prove the real network/data path
each screen depends on.

- [ ] **Step 7: Stop both background processes cleanly**

Stop the Console dev server and `osiris-server` processes started in
Steps 2 and 4. Confirm no orphaned processes remain.

- [ ] **Step 8: Record the verification outcome**

If running under superpowers:subagent-driven-development, append the
outcome (what was checked, what passed, any disclosed gaps) to this
plan's SDD ledger, following the exact format 7b-1/7b-2's Task 9 entries
used. No `git commit` — this task produces no code changes.

---

## Done criteria

`npm run build`, `npm test` (Vitest, 100+ tests including this phase's
additions), and `npm run lint` pass in `console/`; `cargo test
--workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
pass with the `osiris-evidence`/`osiris-api` changes included; Entity
Graph renders a subgraph both from manual entry and from a pivot link
(Process Explorer detail, Incident detail) with the corrected
`uiStore.selectedEntity` format; Timeline renders a host's chronological
story with category badges and a working time-range control, sourcing
its host list from Sensors' already-loaded health data; Threat Hunting
runs both a template-selected and a freehand OQL query against real
`/api/v1/events?q=` data; Evidence's standalone screen lists all evidence
with correct incident links via the new unscoped endpoint, without
changing Incident Detail's existing nested evidence list/create behavior
or its wire shape; Live Events, Filesystem, Network, and Containers still
show "coming soon" and remain non-interactive nav entries.
