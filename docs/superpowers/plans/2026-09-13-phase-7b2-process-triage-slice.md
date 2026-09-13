# Phase 7b-2: Process/Triage Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three functional Console screens — Process Explorer (list +
detail), Alerts (read-only list), and Incidents (list + creation + detail
with status transition and nested Evidence) — against the existing
`osiris-api` surface, with no backend changes.

**Architecture:** Pure frontend extension of the 7b-1 Console. Every
endpoint needed already exists from Phase 7a. Process Explorer and
Incidents introduce a list→detail routing pattern (new for this phase);
Alerts stays a single filterable list like 7b-1's Sensors screen. Evidence
has no standalone screen — it's fetched/created only inside Incident
detail. The existing Zustand `uiStore` gets its first real write
(`selectEntity`) from Process Explorer's detail screen.

**Tech Stack:** Same as 7b-1 — Vite, React 18, TypeScript 5, TanStack
Query v5 (including `useMutation`/`useQueryClient` for writes, not used
in 7b-1), Zustand, react-router-dom v6, Vitest + React Testing Library,
ESLint + Prettier. No backend crates touched.

**Spec:** `docs/superpowers/specs/2026-09-13-phase-7b2-process-triage-slice-design.md`

## Global Constraints

- No backend endpoint is added, removed, or changed in behavior. Every
  endpoint this phase needs already exists: `GET /api/v1/processes`,
  `GET /api/v1/processes/:process_key`, `GET
  /api/v1/processes/:process_key/story`, `GET /api/v1/alerts`, `GET
  /api/v1/incidents`, `POST /api/v1/incidents`, `GET
  /api/v1/incidents/:incident_id`, `PATCH /api/v1/incidents/:incident_id`,
  `GET /api/v1/evidence?incident_id=`, `POST /api/v1/evidence`.
  `cargo test --workspace` and `cargo clippy --workspace --all-targets --
  -D warnings` must stay green (trivially — no `crates/` file changes
  this phase).
- Evidence has no standalone screen or route. It is shown and created
  only inside Incident detail. The "Evidence" nav item stays `enabled:
  false` ("coming soon").
- Incident creation supports only `EntityRef` kinds `IP` (`{kind: "IP",
  addr: string}`) and `DOMAIN` (`{kind: "DOMAIN", name: string}`). The
  other 5 `EntityRef` kinds (Process, File, User, Container, Session)
  are not creatable from the UI this phase.
- Alerts is read-only. No mutation, no acknowledge/dismiss UI.
- No cross-screen quick-actions — Process Explorer does not link to
  incident creation. Incident creation lives entirely on the Incidents
  list screen.
- `Incident.notes` is displayed read-only. No note-taking UI — no
  backend endpoint supports adding notes.
- Dark-first, information-dense, monospace-for-data-fields visual
  direction continues unchanged — no new design system, no light theme.
- No Playwright/e2e — Vitest + React Testing Library only.
- `npm run build`, `npm test`, and `npm run lint` must pass in `console/`
  after every task.
- Numeric timestamps sent to the backend (e.g. `immutable_since`) are
  nanoseconds since the Unix epoch, matching `CanonicalEvent.timestamp`'s
  convention (established in 7b-1's final review fix for `since`) — never
  seconds or milliseconds.

---

### Task 1: API types + Process Explorer data layer

**Files:**
- Modify: `console/src/api/types.ts` (add `ProcessRef`, extend
  `CanonicalEvent` with optional `process`/`parent_process`, add
  `ProcessSummary`, `ProcessDetail`, `Alert`, `Story`)
- Modify: `console/src/api/client.ts` (add `fetchProcesses`,
  `fetchProcess`, `fetchProcessStory`)
- Modify: `console/src/api/hooks.ts` (add `useProcesses`, `useProcess`,
  `useProcessStory`)
- Test: `console/src/api/client.test.ts` (extend)
- Test: `console/src/api/hooks.test.tsx` (extend)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: types `ProcessRef`, `ProcessSummary`, `ProcessDetail`,
  `Alert`, `Story` from `./types`; functions `fetchProcesses(): Promise<ProcessSummary[]>`,
  `fetchProcess(processKey: string): Promise<ProcessDetail>`,
  `fetchProcessStory(processKey: string): Promise<Story>` from `./client`;
  hooks `useProcesses()`, `useProcess(processKey: string)`,
  `useProcessStory(processKey: string)` from `./hooks`. Tasks 4-5 (Process
  Explorer screens) consume these.

- [ ] **Step 1: Add the new types**

In `console/src/api/types.ts`, add after the existing `CanonicalEvent`
interface:

```typescript
export interface ProcessRef {
  process_key: string;
  pid: number;
  exe_path: string;
  cmdline: string[];
  exe_hash: string | null;
  start_time_mono: number;
}
```

Then change the existing `CanonicalEvent` interface from:

```typescript
export interface CanonicalEvent {
  event_id: string;
  event_type: string;
  timestamp: number;
  host: {
    host_id: string;
    hostname: string;
  };
  event_data: unknown;
}
```

to (adding two optional fields — optional, not required, so 7b-1's
existing `CanonicalEvent` test fixtures in `rollup.test.ts` and
`Sensors.test.tsx`, which don't set these fields, keep type-checking):

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

Then add at the end of the file:

```typescript
export interface ProcessSummary {
  process_key: string;
  pid: number;
  exe_path: string;
  timestamp: number;
}

export interface ProcessDetail {
  process: CanonicalEvent;
  children: CanonicalEvent[];
}

export type AlertSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "SUPPRESSED";

export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_version: number;
  rule_content_hash: string;
  severity: AlertSeverity;
  status: AlertStatus;
  timestamp: number;
  host_id: string;
  reasons: string[];
  evidence: string[];
}

export interface Story {
  events: CanonicalEvent[];
  alerts: Alert[];
}
```

- [ ] **Step 2: Write the failing tests for the client functions**

In `console/src/api/client.test.ts`, add to the import line:

```typescript
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchAlerts, fetchEvents, fetchHealth, fetchIncidents } from "./client";
```

becomes:

```typescript
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  fetchAlerts,
  fetchEvents,
  fetchHealth,
  fetchIncidents,
  fetchProcess,
  fetchProcesses,
  fetchProcessStory,
} from "./client";
```

Add these tests before the closing `});` of the `describe("api client", ...)` block:

```typescript
  it("fetchProcesses calls /api/v1/processes", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchProcesses();

    expect(fetch).toHaveBeenCalledWith("/api/v1/processes");
  });

  it("fetchProcess calls /api/v1/processes/:processKey", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ process: {}, children: [] }), { status: 200 })
    );

    await fetchProcess("abc123");

    expect(fetch).toHaveBeenCalledWith("/api/v1/processes/abc123");
  });

  it("fetchProcessStory calls /api/v1/processes/:processKey/story", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 })
    );

    await fetchProcessStory("abc123");

    expect(fetch).toHaveBeenCalledWith("/api/v1/processes/abc123/story");
  });
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd console && npm test -- client.test`
Expected: FAIL — `fetchProcesses`/`fetchProcess`/`fetchProcessStory` don't exist yet.

- [ ] **Step 4: Implement the client functions**

In `console/src/api/client.ts`, change the import line from:

```typescript
import type { ApiHealth, CanonicalEvent } from "./types";
```

to:

```typescript
import type { ApiHealth, CanonicalEvent, ProcessDetail, ProcessSummary, Story } from "./types";
```

Then add at the end of the file:

```typescript
export function fetchProcesses(): Promise<ProcessSummary[]> {
  return apiGet<ProcessSummary[]>("/processes");
}

export function fetchProcess(processKey: string): Promise<ProcessDetail> {
  return apiGet<ProcessDetail>(`/processes/${encodeURIComponent(processKey)}`);
}

export function fetchProcessStory(processKey: string): Promise<Story> {
  return apiGet<Story>(`/processes/${encodeURIComponent(processKey)}/story`);
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd console && npm test -- client.test`
Expected: PASS (all tests, including the 3 new ones).

- [ ] **Step 6: Write the failing tests for the hooks**

In `console/src/api/hooks.test.tsx`, change the import line from:

```tsx
import { useAlerts, useEvents, useHealth, useIncidents } from "./hooks";
```

to:

```tsx
import { useAlerts, useEvents, useHealth, useIncidents, useProcess, useProcesses, useProcessStory } from "./hooks";
```

Add these tests before the closing `});` of the `describe("api hooks", ...)` block:

```tsx
  it("useProcesses resolves with fetchProcesses's result", async () => {
    vi.spyOn(client, "fetchProcesses").mockResolvedValue([
      { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 },
    ]);

    const { result } = renderHook(() => useProcesses(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([
      { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 },
    ]);
  });

  it("useProcess forwards the processKey to fetchProcess", async () => {
    const spy = vi.spyOn(client, "fetchProcess").mockResolvedValue({
      process: { event_id: "e1", event_type: "PROCESS_EXEC", timestamp: 1000, host: { host_id: "h1", hostname: "h" }, event_data: {} },
      children: [],
    });

    const { result } = renderHook(() => useProcess("abc123"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("abc123");
  });

  it("useProcessStory forwards the processKey to fetchProcessStory", async () => {
    const spy = vi.spyOn(client, "fetchProcessStory").mockResolvedValue({ events: [], alerts: [] });

    const { result } = renderHook(() => useProcessStory("abc123"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("abc123");
  });
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `cd console && npm test -- hooks.test`
Expected: FAIL — `useProcesses`/`useProcess`/`useProcessStory` don't exist yet.

- [ ] **Step 8: Implement the hooks**

In `console/src/api/hooks.ts`, change the import line from:

```typescript
import { fetchAlerts, fetchEvents, fetchHealth, fetchIncidents } from "./client";
```

to:

```typescript
import { fetchAlerts, fetchEvents, fetchHealth, fetchIncidents, fetchProcess, fetchProcesses, fetchProcessStory } from "./client";
```

Then add at the end of the file:

```typescript
export function useProcesses() {
  return useQuery({
    queryKey: ["processes"],
    queryFn: fetchProcesses,
  });
}

export function useProcess(processKey: string) {
  return useQuery({
    queryKey: ["process", processKey],
    queryFn: () => fetchProcess(processKey),
  });
}

export function useProcessStory(processKey: string) {
  return useQuery({
    queryKey: ["process-story", processKey],
    queryFn: () => fetchProcessStory(processKey),
  });
}
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (all tests, including the 3 new ones).

- [ ] **Step 10: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 11: Commit**

```bash
git add console/src/api/
git commit -m "feat(console): add Process Explorer data layer (types, client, hooks)"
```

---

### Task 2: API types + Alerts data layer

**Files:**
- Modify: `console/src/api/client.ts` (extend `fetchAlerts` with filter params)
- Modify: `console/src/api/hooks.ts` (extend `useAlerts` with filter params)
- Test: `console/src/api/client.test.ts` (extend)
- Test: `console/src/api/hooks.test.tsx` (fix the existing `useAlerts` test's fixture, which used a loosely-typed `{id: "a1"}` object that no longer matches the now-strongly-typed `Alert[]` return type)

**Interfaces:**
- Consumes: `Alert` type from `./types` (Task 1).
- Produces: `fetchAlerts(params?: {ruleId?: string; since?: number}): Promise<Alert[]>` from `./client` (signature-compatible with the existing zero-arg call sites in `Overview.tsx`); `useAlerts(params?: {ruleId?: string; since?: number})` from `./hooks`. Task 6 (Alerts screen) consumes the filtered form.

- [ ] **Step 1: Write the failing tests for the client function**

In `console/src/api/client.test.ts`, add these tests immediately after
the existing `"fetchAlerts calls /api/v1/alerts"` test:

```typescript
  it("fetchAlerts with a ruleId adds the rule_id query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts({ ruleId: "rule_a" });

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts?rule_id=rule_a");
  });

  it("fetchAlerts with a since adds the since query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts({ since: 1000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts?since=1000");
  });

  it("fetchAlerts with a ruleId and since combines both query params", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts({ ruleId: "rule_a", since: 1000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts?rule_id=rule_a&since=1000");
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd console && npm test -- client.test`
Expected: FAIL — `fetchAlerts` doesn't accept params yet, so the mock's
assertion (URL with a query string) doesn't match the actual call (plain
`/api/v1/alerts`).

- [ ] **Step 3: Implement the extended fetchAlerts**

In `console/src/api/client.ts`, change:

```typescript
export function fetchAlerts(): Promise<unknown[]> {
  return apiGet<unknown[]>("/alerts");
}
```

to:

```typescript
export function fetchAlerts(params: { ruleId?: string; since?: number } = {}): Promise<Alert[]> {
  const search = new URLSearchParams();
  if (params.ruleId) {
    search.set("rule_id", params.ruleId);
  }
  if (params.since !== undefined) {
    search.set("since", String(params.since));
  }
  const queryString = search.toString();
  return apiGet<Alert[]>(`/alerts${queryString ? `?${queryString}` : ""}`);
}
```

Update the import line at the top of the file from:

```typescript
import type { ApiHealth, CanonicalEvent, ProcessDetail, ProcessSummary, Story } from "./types";
```

to:

```typescript
import type { Alert, ApiHealth, CanonicalEvent, ProcessDetail, ProcessSummary, Story } from "./types";
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd console && npm test -- client.test`
Expected: PASS (all tests, including the 3 new ones and the original
zero-arg `fetchAlerts` test, unchanged).

- [ ] **Step 5: Fix the existing useAlerts hook test's fixture**

In `console/src/api/hooks.test.tsx`, the existing test uses a fixture
(`{ id: "a1" }`) that doesn't match the `Alert` interface and will fail
`tsc -b` now that `fetchAlerts` returns `Promise<Alert[]>`. Change:

```tsx
  it("useAlerts resolves with fetchAlerts's result", async () => {
    vi.spyOn(client, "fetchAlerts").mockResolvedValue([{ id: "a1" }]);

    const { result } = renderHook(() => useAlerts(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([{ id: "a1" }]);
  });
```

to:

```tsx
  it("useAlerts resolves with fetchAlerts's result", async () => {
    const alert = {
      alert_id: "a1",
      rule_id: "rule_a",
      rule_version: 1,
      rule_content_hash: "hash",
      severity: "HIGH" as const,
      status: "OPEN" as const,
      timestamp: 1000,
      host_id: "host-1",
      reasons: ["suspicious activity"],
      evidence: ["evt-1"],
    };
    vi.spyOn(client, "fetchAlerts").mockResolvedValue([alert]);

    const { result } = renderHook(() => useAlerts(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([alert]);
  });

  it("useAlerts forwards ruleId and since to fetchAlerts", async () => {
    const spy = vi.spyOn(client, "fetchAlerts").mockResolvedValue([]);

    const { result } = renderHook(() => useAlerts({ ruleId: "rule_a", since: 1000 }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({ ruleId: "rule_a", since: 1000 });
  });
```

- [ ] **Step 6: Run the tests to verify they fail (compile error until Step 7)**

Run: `cd console && npm test -- hooks.test`
Expected: the new `useAlerts forwards ruleId and since` test FAILs
(`useAlerts` doesn't accept params yet — the spy is called with no
arguments, not `{ ruleId: "rule_a", since: 1000 }`).

- [ ] **Step 7: Implement the extended useAlerts**

In `console/src/api/hooks.ts`, change:

```typescript
export function useAlerts() {
  return useQuery({
    queryKey: ["alerts"],
    queryFn: fetchAlerts,
  });
}
```

to:

```typescript
export function useAlerts(params: { ruleId?: string; since?: number } = {}) {
  const { ruleId, since } = params;
  return useQuery({
    queryKey: ["alerts", ruleId ?? "all", since ?? "all-time"],
    queryFn: () => fetchAlerts({ ruleId, since }),
  });
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (all tests).

- [ ] **Step 9: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass. `Overview.tsx`'s existing zero-arg `useAlerts()` call
still compiles and behaves identically (default `params = {}` produces
the same query key/URL as before).

- [ ] **Step 10: Commit**

```bash
git add console/src/api/
git commit -m "feat(console): extend Alerts data layer with rule_id/since filters"
```

---

### Task 3: API types + Incidents/Evidence data layer

**Files:**
- Modify: `console/src/api/types.ts` (add `EntityRef`, `IncidentStatus`,
  `Incident`, `EvidenceSource`, `Integrity`, `Evidence`,
  `CreateEvidenceBody`)
- Modify: `console/src/api/client.ts` (add `apiPost`/`apiPatch` helpers;
  extend `fetchIncidents`'s return type; add `fetchIncident`,
  `createIncident`, `patchIncidentStatus`, `fetchEvidence`,
  `createEvidence`)
- Modify: `console/src/api/hooks.ts` (add `useIncident`,
  `useCreateIncident`, `usePatchIncidentStatus`, `useEvidence`,
  `useCreateEvidence`)
- Test: `console/src/api/client.test.ts` (extend)
- Test: `console/src/api/hooks.test.tsx` (fix the existing `useIncidents`
  test's fixture, same reason as Task 2's `useAlerts` fix)

**Interfaces:**
- Consumes: nothing new from earlier tasks (independent of Tasks 1-2's
  Process/Alerts types).
- Produces: types `EntityRef`, `IncidentStatus`, `Incident`,
  `EvidenceSource`, `Integrity`, `Evidence`, `CreateEvidenceBody` from
  `./types`; functions `fetchIncident(incidentId: string): Promise<Incident>`,
  `createIncident(entities: EntityRef[]): Promise<Incident>`,
  `patchIncidentStatus(incidentId: string, status: IncidentStatus, why?: string): Promise<Incident>`,
  `fetchEvidence(incidentId: string): Promise<Evidence[]>`,
  `createEvidence(body: CreateEvidenceBody): Promise<Evidence>` from
  `./client`; hooks `useIncident(incidentId: string)`,
  `useCreateIncident()`, `usePatchIncidentStatus(incidentId: string)`,
  `useEvidence(incidentId: string)`,
  `useCreateEvidence(incidentId: string)` from `./hooks`. Tasks 7-8
  (Incidents screens) consume these.

- [ ] **Step 1: Add the new types**

In `console/src/api/types.ts`, add at the end of the file:

```typescript
export type EntityRef =
  | { kind: "PROCESS"; process_key: string }
  | { kind: "FILE"; host_id: string; inode: number; device_id: number }
  | { kind: "IP"; addr: string }
  | { kind: "DOMAIN"; name: string }
  | { kind: "USER"; host_id: string; uid: number }
  | { kind: "CONTAINER"; container_id: string }
  | { kind: "SESSION"; session_id: string };

export type IncidentStatus = "NEW" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";

export interface Incident {
  incident_id: string;
  status: IncidentStatus;
  entities: EntityRef[];
  alert_ids: string[];
  notes: string[];
}

export type EvidenceSource = "EVENT_CAPTURE" | "FILE_SNAPSHOT" | "MANUAL_UPLOAD";

export interface Integrity {
  hash: string;
  immutable_since: number;
}

export interface Evidence {
  evidence_id: string;
  source: EvidenceSource;
  timestamp: number;
  integrity: Integrity;
  relationships: EntityRef[];
  supersedes: string | null;
}

export interface CreateEvidenceBody {
  source: EvidenceSource;
  hash: string;
  immutable_since: number;
  relationships: EntityRef[];
  supersedes?: string | null;
  incident_id?: string | null;
}
```

- [ ] **Step 2: Write the failing tests for the client functions**

In `console/src/api/client.test.ts`, change the import line to add the
new functions:

```typescript
import {
  ApiError,
  fetchAlerts,
  fetchEvents,
  fetchHealth,
  fetchIncidents,
  fetchProcess,
  fetchProcesses,
  fetchProcessStory,
} from "./client";
```

becomes:

```typescript
import {
  ApiError,
  createEvidence,
  createIncident,
  fetchAlerts,
  fetchEvents,
  fetchEvidence,
  fetchHealth,
  fetchIncident,
  fetchIncidents,
  fetchProcess,
  fetchProcesses,
  fetchProcessStory,
  patchIncidentStatus,
} from "./client";
```

Add these tests before the closing `});` of the `describe("api client", ...)` block:

```typescript
  it("fetchIncident calls /api/v1/incidents/:incidentId", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] }),
        { status: 200 }
      )
    );

    await fetchIncident("i1");

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents/i1");
  });

  it("createIncident POSTs to /api/v1/incidents with the entities body", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] }),
        { status: 200 }
      )
    );

    await createIncident([{ kind: "IP", addr: "203.0.113.10" }]);

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entities: [{ kind: "IP", addr: "203.0.113.10" }] }),
    });
  });

  it("patchIncidentStatus PATCHes /api/v1/incidents/:incidentId with status and why", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ incident_id: "i1", status: "INVESTIGATING", entities: [], alert_ids: [], notes: [] }),
        { status: 200 }
      )
    );

    await patchIncidentStatus("i1", "INVESTIGATING", "starting investigation");

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents/i1", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "INVESTIGATING", why: "starting investigation" }),
    });
  });

  it("fetchEvidence calls /api/v1/evidence with the incident_id query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvidence("i1");

    expect(fetch).toHaveBeenCalledWith("/api/v1/evidence?incident_id=i1");
  });

  it("createEvidence POSTs to /api/v1/evidence with the given body", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          evidence_id: "e1",
          source: "MANUAL_UPLOAD",
          timestamp: 1000,
          integrity: { hash: "abc", immutable_since: 1000 },
          relationships: [],
          supersedes: null,
        }),
        { status: 200 }
      )
    );

    const body = {
      source: "MANUAL_UPLOAD" as const,
      hash: "abc",
      immutable_since: 1000,
      relationships: [],
      supersedes: null,
      incident_id: "i1",
    };
    await createEvidence(body);

    expect(fetch).toHaveBeenCalledWith("/api/v1/evidence", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  });

  it("fetchIncidents parses a real Incident shape", async () => {
    const incident = { incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([incident]), { status: 200 }));

    const incidents = await fetchIncidents();

    expect(incidents).toEqual([incident]);
  });
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd console && npm test -- client.test`
Expected: FAIL — `fetchIncident`/`createIncident`/`patchIncidentStatus`/`fetchEvidence`/`createEvidence` don't exist yet.

- [ ] **Step 4: Implement the client functions**

In `console/src/api/client.ts`, update the import line to add the new
types:

```typescript
import type { Alert, ApiHealth, CanonicalEvent, ProcessDetail, ProcessSummary, Story } from "./types";
```

becomes:

```typescript
import type {
  Alert,
  ApiHealth,
  CanonicalEvent,
  CreateEvidenceBody,
  EntityRef,
  Evidence,
  Incident,
  IncidentStatus,
  ProcessDetail,
  ProcessSummary,
  Story,
} from "./types";
```

Add `apiPost`/`apiPatch` helpers immediately after the existing `apiGet`
function:

```typescript
async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new ApiError(response.status, `POST ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new ApiError(response.status, `PATCH ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}
```

Change `fetchIncidents`'s return type from `unknown[]` to `Incident[]`:

```typescript
export function fetchIncidents(): Promise<unknown[]> {
  return apiGet<unknown[]>("/incidents");
}
```

becomes:

```typescript
export function fetchIncidents(): Promise<Incident[]> {
  return apiGet<Incident[]>("/incidents");
}
```

Add at the end of the file:

```typescript
export function fetchIncident(incidentId: string): Promise<Incident> {
  return apiGet<Incident>(`/incidents/${encodeURIComponent(incidentId)}`);
}

export function createIncident(entities: EntityRef[]): Promise<Incident> {
  return apiPost<Incident>("/incidents", { entities });
}

export function patchIncidentStatus(
  incidentId: string,
  status: IncidentStatus,
  why?: string
): Promise<Incident> {
  return apiPatch<Incident>(`/incidents/${encodeURIComponent(incidentId)}`, { status, why });
}

export function fetchEvidence(incidentId: string): Promise<Evidence[]> {
  return apiGet<Evidence[]>(`/evidence?incident_id=${encodeURIComponent(incidentId)}`);
}

export function createEvidence(body: CreateEvidenceBody): Promise<Evidence> {
  return apiPost<Evidence>("/evidence", body);
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd console && npm test -- client.test`
Expected: PASS (all tests, including the 6 new ones).

- [ ] **Step 6: Fix the existing useIncidents hook test's fixture**

In `console/src/api/hooks.test.tsx`, the existing test uses `{ id: "i1" }`
which doesn't match `Incident` and will fail `tsc -b` now that
`fetchIncidents` returns `Promise<Incident[]>`. Change:

```tsx
  it("useIncidents resolves with fetchIncidents's result", async () => {
    vi.spyOn(client, "fetchIncidents").mockResolvedValue([{ id: "i1" }]);

    const { result } = renderHook(() => useIncidents(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([{ id: "i1" }]);
  });
```

to:

```tsx
  it("useIncidents resolves with fetchIncidents's result", async () => {
    const incident = { incident_id: "i1", status: "NEW" as const, entities: [], alert_ids: [], notes: [] };
    vi.spyOn(client, "fetchIncidents").mockResolvedValue([incident]);

    const { result } = renderHook(() => useIncidents(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([incident]);
  });
```

- [ ] **Step 7: Write the failing tests for the new hooks**

In `console/src/api/hooks.test.tsx`, change the import line from:

```tsx
import { useAlerts, useEvents, useHealth, useIncidents, useProcess, useProcesses, useProcessStory } from "./hooks";
```

to:

```tsx
import {
  useAlerts,
  useCreateEvidence,
  useCreateIncident,
  useEvents,
  useEvidence,
  useHealth,
  useIncident,
  useIncidents,
  usePatchIncidentStatus,
  useProcess,
  useProcesses,
  useProcessStory,
} from "./hooks";
```

Add these tests before the closing `});` of the `describe("api hooks", ...)` block:

```tsx
  it("useIncident forwards the incidentId to fetchIncident", async () => {
    const incident = { incident_id: "i1", status: "NEW" as const, entities: [], alert_ids: [], notes: [] };
    const spy = vi.spyOn(client, "fetchIncident").mockResolvedValue(incident);

    const { result } = renderHook(() => useIncident("i1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("i1");
  });

  it("useCreateIncident calls createIncident with the given entities", async () => {
    const incident = { incident_id: "i1", status: "NEW" as const, entities: [], alert_ids: [], notes: [] };
    const spy = vi.spyOn(client, "createIncident").mockResolvedValue(incident);

    const { result } = renderHook(() => useCreateIncident(), { wrapper });
    await result.current.mutateAsync([{ kind: "IP", addr: "203.0.113.10" }]);

    expect(spy).toHaveBeenCalledWith([{ kind: "IP", addr: "203.0.113.10" }]);
  });

  it("usePatchIncidentStatus calls patchIncidentStatus with the incidentId, status, and why", async () => {
    const incident = { incident_id: "i1", status: "INVESTIGATING" as const, entities: [], alert_ids: [], notes: [] };
    const spy = vi.spyOn(client, "patchIncidentStatus").mockResolvedValue(incident);

    const { result } = renderHook(() => usePatchIncidentStatus("i1"), { wrapper });
    await result.current.mutateAsync({ status: "INVESTIGATING", why: "starting" });

    expect(spy).toHaveBeenCalledWith("i1", "INVESTIGATING", "starting");
  });

  it("useEvidence forwards the incidentId to fetchEvidence", async () => {
    const spy = vi.spyOn(client, "fetchEvidence").mockResolvedValue([]);

    const { result } = renderHook(() => useEvidence("i1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("i1");
  });

  it("useCreateEvidence calls createEvidence with the incidentId merged into the body", async () => {
    const evidence = {
      evidence_id: "e1",
      source: "MANUAL_UPLOAD" as const,
      timestamp: 1000,
      integrity: { hash: "abc", immutable_since: 1000 },
      relationships: [],
      supersedes: null,
    };
    const spy = vi.spyOn(client, "createEvidence").mockResolvedValue(evidence);

    const { result } = renderHook(() => useCreateEvidence("i1"), { wrapper });
    await result.current.mutateAsync({
      source: "MANUAL_UPLOAD",
      hash: "abc",
      immutable_since: 1000,
      relationships: [],
      supersedes: null,
    });

    expect(spy).toHaveBeenCalledWith({
      source: "MANUAL_UPLOAD",
      hash: "abc",
      immutable_since: 1000,
      relationships: [],
      supersedes: null,
      incident_id: "i1",
    });
  });
```

- [ ] **Step 8: Run the tests to verify they fail**

Run: `cd console && npm test -- hooks.test`
Expected: FAIL — the new hooks don't exist yet.

- [ ] **Step 9: Implement the new hooks**

In `console/src/api/hooks.ts`, change the import line at the top from:

```typescript
import { useQuery } from "@tanstack/react-query";
import { fetchAlerts, fetchEvents, fetchHealth, fetchIncidents, fetchProcess, fetchProcesses, fetchProcessStory } from "./client";
```

to:

```typescript
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createEvidence,
  createIncident,
  fetchAlerts,
  fetchEvents,
  fetchEvidence,
  fetchHealth,
  fetchIncident,
  fetchIncidents,
  fetchProcess,
  fetchProcesses,
  fetchProcessStory,
  patchIncidentStatus,
} from "./client";
import type { CreateEvidenceBody, EntityRef, IncidentStatus } from "./types";
```

Add at the end of the file:

```typescript
export function useIncident(incidentId: string) {
  return useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => fetchIncident(incidentId),
  });
}

export function useCreateIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (entities: EntityRef[]) => createIncident(entities),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function usePatchIncidentStatus(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ status, why }: { status: IncidentStatus; why?: string }) =>
      patchIncidentStatus(incidentId, status, why),
    onSuccess: (updated) => {
      queryClient.setQueryData(["incident", incidentId], updated);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function useEvidence(incidentId: string) {
  return useQuery({
    queryKey: ["evidence", incidentId],
    queryFn: () => fetchEvidence(incidentId),
  });
}

export function useCreateEvidence(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: Omit<CreateEvidenceBody, "incident_id">) =>
      createEvidence({ ...body, incident_id: incidentId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["evidence", incidentId] });
    },
  });
}
```

- [ ] **Step 10: Run the tests to verify they pass**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (all tests).

- [ ] **Step 11: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 12: Commit**

```bash
git add console/src/api/
git commit -m "feat(console): add Incidents/Evidence data layer"
```

---

### Task 4: Process Explorer — list screen

**Files:**
- Create: `console/src/screens/processes/ProcessList.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/processes/ProcessList.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useProcesses` from `../../api/hooks` (Task 1).
- Produces: `ProcessList` component from `./ProcessList`, mounted at
  `/processes`. Task 5 adds the detail route this list links to.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/processes/ProcessList.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ProcessList } from "./ProcessList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useProcesses>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <ProcessList />
    </MemoryRouter>
  );
}

describe("ProcessList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading processes…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No processes found.")).toBeInTheDocument();
  });

  it("renders a row per process, linking to its detail route", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(
      mockQueryResult({
        data: [{ process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 }],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "/usr/bin/curl" });
    expect(link).toHaveAttribute("href", "/processes/abc123");
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("filters rows by exe_path text", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(
      mockQueryResult({
        data: [
          { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 },
          { process_key: "def456", pid: 43, exe_path: "/usr/bin/wget", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by exe path"), { target: { value: "curl" } });

    expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    expect(screen.queryByText("/usr/bin/wget")).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- ProcessList`
Expected: FAIL — `./ProcessList` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/processes/ProcessList.tsx`:

```tsx
import { useState } from "react";
import { Link } from "react-router-dom";
import { useProcesses } from "../../api/hooks";

export function ProcessList() {
  const processes = useProcesses();
  const [filter, setFilter] = useState("");

  const rows = (processes.data ?? []).filter((process) =>
    process.exe_path.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <h1>Process Explorer</h1>
      <input
        type="text"
        placeholder="Filter by exe path"
        aria-label="Filter by exe path"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {processes.isLoading && <p>Loading processes…</p>}
      {processes.isError && (
        <p role="alert">Failed to load processes: {(processes.error as Error).message}</p>
      )}
      {!processes.isLoading && !processes.isError && rows.length === 0 && <p>No processes found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>PID</th>
              <th>Exe path</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((process) => (
              <tr key={process.process_key}>
                <td>{process.pid}</td>
                <td>
                  <Link to={`/processes/${process.process_key}`}>{process.exe_path}</Link>
                </td>
                <td>{process.timestamp}</td>
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

Run: `cd console && npm test -- ProcessList`
Expected: PASS (5 tests).

- [ ] **Step 5: Wire it into the route table**

In `console/src/App.tsx`, change the import block from:

```tsx
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { ComingSoon } from "./screens/ComingSoon";
import { Overview } from "./screens/overview/Overview";
import { Sensors } from "./screens/sensors/Sensors";
```

to:

```tsx
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { ComingSoon } from "./screens/ComingSoon";
import { Overview } from "./screens/overview/Overview";
import { ProcessList } from "./screens/processes/ProcessList";
import { Sensors } from "./screens/sensors/Sensors";
```

and change:

```tsx
              <Route path="/processes" element={<ComingSoon label="Process Explorer" />} />
```

to:

```tsx
              <Route path="/processes" element={<ProcessList />} />
```

- [ ] **Step 6: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Process Explorer", path: "/processes", enabled: false },
```

to:

```typescript
  { label: "Process Explorer", path: "/processes", enabled: true },
```

- [ ] **Step 7: Update App.test.tsx for the now-enabled Process Explorer link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly two nav links, for Overview and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(2);
    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Sensors"]);
  });
```

with:

```tsx
  it("renders exactly three nav links, for Overview, Process Explorer, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(3);
    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Process Explorer", "Sensors"]);
  });
```

- [ ] **Step 8: Run the full test suite**

Run: `cd console && npm test`
Expected: PASS (all tests). `App.test.tsx` mounts the real `ProcessList`,
which calls the real (unmocked) `useProcesses` inside `App.test.tsx`'s
render — same pre-existing pattern already accepted for `Overview` in
7b-1 (a failed `fetch` in the test environment doesn't hang the test;
`App.test.tsx` only asserts nav/heading text, not loaded data).

- [ ] **Step 9: Verify build and lint**

Run: `cd console && npm run build && npm run lint`
Expected: both succeed.

- [ ] **Step 10: Commit**

```bash
git add console/src/screens/processes/ProcessList.tsx console/src/screens/processes/ProcessList.test.tsx console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Process Explorer list screen"
```

---

### Task 5: Process Explorer — detail screen

**Files:**
- Create: `console/src/screens/processes/ProcessDetailScreen.tsx`
- Modify: `console/src/App.tsx`
- Test: `console/src/screens/processes/ProcessDetailScreen.test.tsx`

**Interfaces:**
- Consumes: `useProcess`, `useProcessStory` from `../../api/hooks`
  (Task 1); `useUiStore` from `../../store/uiStore` (7b-1, Task 4 of that
  plan).
- Produces: `ProcessDetailScreen` component from `./ProcessDetailScreen`,
  mounted at `/processes/:processKey`. Named `ProcessDetailScreen` (not
  `ProcessDetail`) to avoid colliding with the `ProcessDetail` type from
  `api/types`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/processes/ProcessDetailScreen.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { ProcessDetailScreen } from "./ProcessDetailScreen";

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

function renderAt(processKey: string) {
  return render(
    <MemoryRouter initialEntries={[`/processes/${processKey}`]}>
      <Routes>
        <Route path="/processes/:processKey" element={<ProcessDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ProcessDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("shows loading states for both process and story", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcess>);
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcessStory>
    );
    renderAt("abc123");
    expect(screen.getByText("Loading process…")).toBeInTheDocument();
    expect(screen.getByText("Loading story…")).toBeInTheDocument();
  });

  it("shows the process's children and the story's alerts once loaded", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(
      mockQueryResult({
        data: {
          process: {
            event_id: "e1",
            event_type: "PROCESS_EXEC",
            timestamp: 1000,
            host: { host_id: "h1", hostname: "h" },
            process: { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", cmdline: [], exe_hash: null, start_time_mono: 1 },
            event_data: {},
          },
          children: [
            {
              event_id: "e2",
              event_type: "PROCESS_EXEC",
              timestamp: 2000,
              host: { host_id: "h1", hostname: "h" },
              process: { process_key: "def456", pid: 43, exe_path: "/usr/bin/child", cmdline: [], exe_hash: null, start_time_mono: 2 },
              event_data: {},
            },
          ],
        },
      }) as ReturnType<typeof hooks.useProcess>
    );
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({
        data: {
          events: [],
          alerts: [
            {
              alert_id: "a1",
              rule_id: "rule_a",
              rule_version: 1,
              rule_content_hash: "hash",
              severity: "HIGH",
              status: "OPEN",
              timestamp: 1000,
              host_id: "h1",
              reasons: ["suspicious"],
              evidence: ["e1"],
            },
          ],
        },
      }) as ReturnType<typeof hooks.useProcessStory>
    );
    renderAt("abc123");

    expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    expect(screen.getByText("Children (1)")).toBeInTheDocument();
    expect(screen.getByText("/usr/bin/child")).toBeInTheDocument();
    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("writes the processKey to uiStore.selectedEntity on mount and clears it on unmount", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcess>);
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcessStory>
    );
    const { unmount } = renderAt("abc123");

    expect(useUiStore.getState().selectedEntity).toBe("abc123");

    unmount();

    expect(useUiStore.getState().selectedEntity).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- ProcessDetailScreen`
Expected: FAIL — `./ProcessDetailScreen` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/processes/ProcessDetailScreen.tsx`:

```tsx
import { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useProcess, useProcessStory } from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";

export function ProcessDetailScreen() {
  const { processKey = "" } = useParams<{ processKey: string }>();
  const detail = useProcess(processKey);
  const story = useProcessStory(processKey);
  const selectEntity = useUiStore((state) => state.selectEntity);

  useEffect(() => {
    selectEntity(processKey);
    return () => selectEntity(null);
  }, [processKey, selectEntity]);

  return (
    <div>
      <h1>Process {processKey}</h1>
      {detail.isLoading && <p>Loading process…</p>}
      {detail.isError && <p role="alert">Failed to load process: {(detail.error as Error).message}</p>}
      {detail.data && (
        <section aria-label="process detail">
          <dl>
            <dt>PID</dt>
            <dd>{detail.data.process.process?.pid ?? "—"}</dd>
            <dt>Exe path</dt>
            <dd>{detail.data.process.process?.exe_path ?? "—"}</dd>
          </dl>
          <h2>Children ({detail.data.children.length})</h2>
          <ul>
            {detail.data.children.map((child) => (
              <li key={child.event_id}>{child.process?.exe_path ?? child.event_id}</li>
            ))}
          </ul>
        </section>
      )}
      {story.isLoading && <p>Loading story…</p>}
      {story.isError && <p role="alert">Failed to load story: {(story.error as Error).message}</p>}
      {story.data && (
        <section aria-label="process story">
          <h2>Related alerts ({story.data.alerts.length})</h2>
          <ul>
            {story.data.alerts.map((alert) => (
              <li key={alert.alert_id}>
                {alert.rule_id}: {alert.reasons.join("; ")}
              </li>
            ))}
          </ul>
          <h2>Events ({story.data.events.length})</h2>
        </section>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- ProcessDetailScreen`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire the detail route into App.tsx**

In `console/src/App.tsx`, change the import block from:

```tsx
import { ProcessList } from "./screens/processes/ProcessList";
```

to:

```tsx
import { ProcessDetailScreen } from "./screens/processes/ProcessDetailScreen";
import { ProcessList } from "./screens/processes/ProcessList";
```

and change:

```tsx
              <Route path="/processes" element={<ProcessList />} />
```

to:

```tsx
              <Route path="/processes" element={<ProcessList />} />
              <Route path="/processes/:processKey" element={<ProcessDetailScreen />} />
```

- [ ] **Step 6: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass. No `App.test.tsx` changes needed — the new route
isn't a nav item, so the nav-link-count assertion is unaffected.

- [ ] **Step 7: Commit**

```bash
git add console/src/screens/processes/ProcessDetailScreen.tsx console/src/screens/processes/ProcessDetailScreen.test.tsx console/src/App.tsx
git commit -m "feat(console): add the Process Explorer detail screen"
```

---

### Task 6: Alerts screen

**Files:**
- Create: `console/src/screens/alerts/Alerts.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/alerts/Alerts.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useAlerts` from `../../api/hooks` (Task 2).
- Produces: `Alerts` component from `./Alerts`, mounted at `/alerts`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/alerts/Alerts.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Alerts } from "./Alerts";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useAlerts>;
}

describe("Alerts", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ isLoading: true }));
    render(<Alerts />);
    expect(screen.getByText("Loading alerts…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    render(<Alerts />);
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [] }));
    render(<Alerts />);
    expect(screen.getByText("No alerts found.")).toBeInTheDocument();
  });

  it("renders a row per alert", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(
      mockQueryResult({
        data: [
          {
            alert_id: "a1",
            rule_id: "rule_a",
            rule_version: 1,
            rule_content_hash: "hash",
            severity: "HIGH",
            status: "OPEN",
            timestamp: 1000,
            host_id: "host-1",
            reasons: ["suspicious activity"],
            evidence: ["e1", "e2"],
          },
        ],
      })
    );
    render(<Alerts />);

    expect(screen.getByText("rule_a")).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText("OPEN")).toBeInTheDocument();
    expect(screen.getByText("suspicious activity")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("filters by rule ID via useAlerts", () => {
    const spy = vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [] }));
    render(<Alerts />);

    fireEvent.change(screen.getByLabelText("Filter by rule ID"), { target: { value: "rule_a" } });

    expect(spy).toHaveBeenLastCalledWith({ ruleId: "rule_a" });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- Alerts.test`
Expected: FAIL — `./Alerts` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/alerts/Alerts.tsx`:

```tsx
import { useState } from "react";
import { useAlerts } from "../../api/hooks";

export function Alerts() {
  const [ruleId, setRuleId] = useState("");
  const alerts = useAlerts({ ruleId: ruleId || undefined });
  const rows = alerts.data ?? [];

  return (
    <div>
      <h1>Alerts</h1>
      <input
        type="text"
        placeholder="Filter by rule ID"
        aria-label="Filter by rule ID"
        value={ruleId}
        onChange={(event) => setRuleId(event.target.value)}
      />
      {alerts.isLoading && <p>Loading alerts…</p>}
      {alerts.isError && <p role="alert">Failed to load alerts: {(alerts.error as Error).message}</p>}
      {!alerts.isLoading && !alerts.isError && rows.length === 0 && <p>No alerts found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Host</th>
              <th>Reasons</th>
              <th>Timestamp</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((alert) => (
              <tr key={alert.alert_id}>
                <td>{alert.rule_id}</td>
                <td>{alert.severity}</td>
                <td>{alert.status}</td>
                <td>{alert.host_id}</td>
                <td>{alert.reasons.join("; ")}</td>
                <td>{alert.timestamp}</td>
                <td>{alert.evidence.length}</td>
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

Run: `cd console && npm test -- Alerts.test`
Expected: PASS (5 tests).

- [ ] **Step 5: Wire it into the route table**

In `console/src/App.tsx`, change the import block from:

```tsx
import { ComingSoon } from "./screens/ComingSoon";
```

to (keep `ComingSoon` — still used by other routes):

```tsx
import { Alerts } from "./screens/alerts/Alerts";
import { ComingSoon } from "./screens/ComingSoon";
```

and change:

```tsx
              <Route path="/alerts" element={<ComingSoon label="Alerts" />} />
```

to:

```tsx
              <Route path="/alerts" element={<Alerts />} />
```

- [ ] **Step 6: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Alerts", path: "/alerts", enabled: false },
```

to:

```typescript
  { label: "Alerts", path: "/alerts", enabled: true },
```

- [ ] **Step 7: Update App.test.tsx for the now-enabled Alerts link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly three nav links, for Overview, Process Explorer, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(3);
    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Process Explorer", "Sensors"]);
  });
```

with:

```tsx
  it("renders exactly four nav links, for Overview, Process Explorer, Alerts, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(4);
    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Process Explorer", "Alerts", "Sensors"]);
  });
```

- [ ] **Step 8: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add console/src/screens/alerts/ console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Alerts screen"
```

---

### Task 7: Incidents — list screen with creation form

**Files:**
- Create: `console/src/screens/incidents/EntityRefInput.tsx`
- Create: `console/src/screens/incidents/IncidentList.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/incidents/EntityRefInput.test.tsx`
- Test: `console/src/screens/incidents/IncidentList.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useIncidents`, `useCreateIncident` from `../../api/hooks`
  (Task 3); `EntityRef` type from `../../api/types` (Task 3).
- Produces: `EntityRefRow` type, `EntityRefInput` component,
  `entityRefRowsToEntityRefs(rows: EntityRefRow[]): EntityRef[]` from
  `./EntityRefInput`; `IncidentList` component from `./IncidentList`,
  mounted at `/incidents`. Task 8 (Incident detail) does not consume
  `EntityRefInput` — it's list-screen-only.

- [ ] **Step 1: Write the failing test for EntityRefInput**

Create `console/src/screens/incidents/EntityRefInput.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { EntityRefInput, entityRefRowsToEntityRefs, type EntityRefRow } from "./EntityRefInput";

describe("entityRefRowsToEntityRefs", () => {
  it("converts an IP row to an EntityRef", () => {
    const rows: EntityRefRow[] = [{ kind: "IP", value: "203.0.113.10" }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "IP", addr: "203.0.113.10" }]);
  });

  it("converts a DOMAIN row to an EntityRef", () => {
    const rows: EntityRefRow[] = [{ kind: "DOMAIN", value: "evil.example" }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "DOMAIN", name: "evil.example" }]);
  });

  it("drops rows with a blank value", () => {
    const rows: EntityRefRow[] = [{ kind: "IP", value: "  " }, { kind: "IP", value: "203.0.113.10" }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "IP", addr: "203.0.113.10" }]);
  });

  it("trims whitespace from the value", () => {
    const rows: EntityRefRow[] = [{ kind: "DOMAIN", value: "  evil.example  " }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "DOMAIN", name: "evil.example" }]);
  });
});

describe("EntityRefInput", () => {
  it("renders one kind selector and value input per row", () => {
    render(<EntityRefInput rows={[{ kind: "IP", value: "" }]} onChange={vi.fn()} />);
    expect(screen.getByLabelText("Entity 1 kind")).toBeInTheDocument();
    expect(screen.getByLabelText("Entity 1 value")).toBeInTheDocument();
  });

  it("calls onChange with an added row when Add entity is clicked", () => {
    const onChange = vi.fn();
    render(<EntityRefInput rows={[{ kind: "IP", value: "" }]} onChange={onChange} />);
    screen.getByText("Add entity").click();
    expect(onChange).toHaveBeenCalledWith([
      { kind: "IP", value: "" },
      { kind: "IP", value: "" },
    ]);
  });

  it("calls onChange with the row removed when Remove is clicked", () => {
    const onChange = vi.fn();
    render(
      <EntityRefInput
        rows={[{ kind: "IP", value: "a" }, { kind: "DOMAIN", value: "b" }]}
        onChange={onChange}
      />
    );
    screen.getAllByText("Remove")[0].click();
    expect(onChange).toHaveBeenCalledWith([{ kind: "DOMAIN", value: "b" }]);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- EntityRefInput`
Expected: FAIL — `./EntityRefInput` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/incidents/EntityRefInput.tsx`:

```tsx
import type { EntityRef } from "../../api/types";

export interface EntityRefRow {
  kind: "IP" | "DOMAIN";
  value: string;
}

export interface EntityRefInputProps {
  rows: EntityRefRow[];
  onChange: (rows: EntityRefRow[]) => void;
}

export function EntityRefInput({ rows, onChange }: EntityRefInputProps) {
  function updateRow(index: number, patch: Partial<EntityRefRow>) {
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }

  function removeRow(index: number) {
    onChange(rows.filter((_, i) => i !== index));
  }

  function addRow() {
    onChange([...rows, { kind: "IP", value: "" }]);
  }

  return (
    <fieldset>
      <legend>Entities</legend>
      {rows.map((row, index) => (
        <div key={index}>
          <select
            aria-label={`Entity ${index + 1} kind`}
            value={row.kind}
            onChange={(event) => updateRow(index, { kind: event.target.value as "IP" | "DOMAIN" })}
          >
            <option value="IP">IP</option>
            <option value="DOMAIN">Domain</option>
          </select>
          <input
            type="text"
            aria-label={`Entity ${index + 1} value`}
            value={row.value}
            onChange={(event) => updateRow(index, { value: event.target.value })}
          />
          <button type="button" onClick={() => removeRow(index)}>
            Remove
          </button>
        </div>
      ))}
      <button type="button" onClick={addRow}>
        Add entity
      </button>
    </fieldset>
  );
}

export function entityRefRowsToEntityRefs(rows: EntityRefRow[]): EntityRef[] {
  return rows
    .filter((row) => row.value.trim().length > 0)
    .map((row) =>
      row.kind === "IP"
        ? { kind: "IP" as const, addr: row.value.trim() }
        : { kind: "DOMAIN" as const, name: row.value.trim() }
    );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- EntityRefInput`
Expected: PASS (7 tests).

- [ ] **Step 5: Write the failing test for IncidentList**

Create `console/src/screens/incidents/IncidentList.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { IncidentList } from "./IncidentList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useIncidents>;
}

function mockMutationResult(overrides: Record<string, unknown>) {
  return {
    mutateAsync: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
    ...overrides,
  } as unknown as ReturnType<typeof hooks.useCreateIncident>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <IncidentList />
    </MemoryRouter>
  );
}

describe("IncidentList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ isLoading: true }));
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({}));
    renderWithRouter();
    expect(screen.getByText("Loading incidents…")).toBeInTheDocument();
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [] }));
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({}));
    renderWithRouter();
    expect(screen.getByText("No incidents found.")).toBeInTheDocument();
  });

  it("renders a row per incident, linking to its detail route", () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(
      mockQueryResult({
        data: [{ incident_id: "i1", status: "NEW", entities: [{ kind: "IP", addr: "1.2.3.4" }], alert_ids: [], notes: [] }],
      })
    );
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({}));
    renderWithRouter();

    const link = screen.getByRole("link", { name: "NEW" });
    expect(link).toHaveAttribute("href", "/incidents/i1");
  });

  it("submits the entity rows via useCreateIncident.mutateAsync", async () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [] }));
    const mutateAsync = vi.fn().mockResolvedValue({ incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] });
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({ mutateAsync }));
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Entity 1 value"), { target: { value: "203.0.113.10" } });
    screen.getByText("Create incident").click();

    await vi.waitFor(() => expect(mutateAsync).toHaveBeenCalledWith([{ kind: "IP", addr: "203.0.113.10" }]));
  });
});
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd console && npm test -- IncidentList`
Expected: FAIL — `./IncidentList` module doesn't exist yet.

- [ ] **Step 7: Write the implementation**

Create `console/src/screens/incidents/IncidentList.tsx`:

```tsx
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useCreateIncident, useIncidents } from "../../api/hooks";
import { EntityRefInput, entityRefRowsToEntityRefs, type EntityRefRow } from "./EntityRefInput";

export function IncidentList() {
  const incidents = useIncidents();
  const createIncident = useCreateIncident();
  const navigate = useNavigate();
  const [rows, setRows] = useState<EntityRefRow[]>([{ kind: "IP", value: "" }]);
  const listRows = incidents.data ?? [];

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const entities = entityRefRowsToEntityRefs(rows);
    const created = await createIncident.mutateAsync(entities);
    navigate(`/incidents/${created.incident_id}`);
  }

  return (
    <div>
      <h1>Incidents</h1>
      <form onSubmit={handleSubmit}>
        <h2>New incident</h2>
        <EntityRefInput rows={rows} onChange={setRows} />
        <button type="submit" disabled={createIncident.isPending}>
          Create incident
        </button>
        {createIncident.isError && (
          <p role="alert">Failed to create incident: {(createIncident.error as Error).message}</p>
        )}
      </form>
      {incidents.isLoading && <p>Loading incidents…</p>}
      {incidents.isError && (
        <p role="alert">Failed to load incidents: {(incidents.error as Error).message}</p>
      )}
      {!incidents.isLoading && !incidents.isError && listRows.length === 0 && <p>No incidents found.</p>}
      {listRows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Entities</th>
              <th>Alerts</th>
            </tr>
          </thead>
          <tbody>
            {listRows.map((incident) => (
              <tr key={incident.incident_id}>
                <td>
                  <Link to={`/incidents/${incident.incident_id}`}>{incident.status}</Link>
                </td>
                <td>{incident.entities.length}</td>
                <td>{incident.alert_ids.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd console && npm test -- IncidentList`
Expected: PASS (4 tests).

- [ ] **Step 9: Wire it into the route table**

In `console/src/App.tsx`, change the import block from:

```tsx
import { Alerts } from "./screens/alerts/Alerts";
import { ComingSoon } from "./screens/ComingSoon";
```

to:

```tsx
import { Alerts } from "./screens/alerts/Alerts";
import { ComingSoon } from "./screens/ComingSoon";
import { IncidentList } from "./screens/incidents/IncidentList";
```

and change:

```tsx
              <Route path="/incidents" element={<ComingSoon label="Incidents" />} />
```

to:

```tsx
              <Route path="/incidents" element={<IncidentList />} />
```

- [ ] **Step 10: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Incidents", path: "/incidents", enabled: false },
```

to:

```typescript
  { label: "Incidents", path: "/incidents", enabled: true },
```

- [ ] **Step 11: Update App.test.tsx for the now-enabled Incidents link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly four nav links, for Overview, Process Explorer, Alerts, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(4);
    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Process Explorer", "Alerts", "Sensors"]);
  });
```

with:

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

- [ ] **Step 12: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 13: Commit**

```bash
git add console/src/screens/incidents/EntityRefInput.tsx console/src/screens/incidents/EntityRefInput.test.tsx console/src/screens/incidents/IncidentList.tsx console/src/screens/incidents/IncidentList.test.tsx console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Incidents list screen with a creation form"
```

---

### Task 8: Incidents — detail screen with status transition and nested Evidence

**Files:**
- Create: `console/src/screens/incidents/IncidentDetailScreen.tsx`
- Modify: `console/src/App.tsx`
- Test: `console/src/screens/incidents/IncidentDetailScreen.test.tsx`

**Interfaces:**
- Consumes: `useIncident`, `usePatchIncidentStatus`, `useEvidence`,
  `useCreateEvidence` from `../../api/hooks` (Task 3); `IncidentStatus`
  type from `../../api/types` (Task 3).
- Produces: `IncidentDetailScreen` component from
  `./IncidentDetailScreen`, mounted at `/incidents/:incidentId`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/incidents/IncidentDetailScreen.test.tsx`:

```tsx
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { IncidentDetailScreen } from "./IncidentDetailScreen";

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

function mockMutationResult(overrides: Record<string, unknown>) {
  return {
    mutateAsync: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
    ...overrides,
  };
}

function renderAt(incidentId: string) {
  return render(
    <MemoryRouter initialEntries={[`/incidents/${incidentId}`]}>
      <Routes>
        <Route path="/incidents/:incidentId" element={<IncidentDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("IncidentDetailScreen", () => {
  it("shows loading states for incident and evidence", () => {
    vi.mocked(hooks.useIncident).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useIncident>);
    vi.mocked(hooks.useEvidence).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useEvidence>);
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>);
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.useCreateEvidence>);
    renderAt("i1");
    expect(screen.getByText("Loading incident…")).toBeInTheDocument();
    expect(screen.getByText("Loading evidence…")).toBeInTheDocument();
  });

  it("shows the incident's status, entity/alert counts, notes, and evidence once loaded", () => {
    vi.mocked(hooks.useIncident).mockReturnValue(
      mockQueryResult({
        data: {
          incident_id: "i1",
          status: "NEW",
          entities: [{ kind: "IP", addr: "1.2.3.4" }],
          alert_ids: ["a1"],
          notes: ["initial triage note"],
        },
      }) as ReturnType<typeof hooks.useIncident>
    );
    vi.mocked(hooks.useEvidence).mockReturnValue(
      mockQueryResult({
        data: [
          {
            evidence_id: "e1",
            source: "MANUAL_UPLOAD",
            timestamp: 1000,
            integrity: { hash: "abc123", immutable_since: 1000 },
            relationships: [],
            supersedes: null,
          },
        ],
      }) as ReturnType<typeof hooks.useEvidence>
    );
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>);
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.useCreateEvidence>);
    renderAt("i1");

    const detail = screen.getByRole("region", { name: "incident detail" });
    expect(within(detail).getByText("NEW")).toBeInTheDocument();
    expect(screen.getByText("initial triage note")).toBeInTheDocument();
    expect(screen.getByText("MANUAL_UPLOAD — abc123")).toBeInTheDocument();
  });

  it("submits a status transition via usePatchIncidentStatus.mutateAsync", async () => {
    vi.mocked(hooks.useIncident).mockReturnValue(
      mockQueryResult({
        data: { incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] },
      }) as ReturnType<typeof hooks.useIncident>
    );
    vi.mocked(hooks.useEvidence).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvidence>);
    const mutateAsync = vi.fn().mockResolvedValue({});
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(
      mockMutationResult({ mutateAsync }) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>
    );
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.useCreateEvidence>);
    renderAt("i1");

    screen.getByText("Update status").click();

    await vi.waitFor(() =>
      expect(mutateAsync).toHaveBeenCalledWith({ status: "INVESTIGATING", why: undefined })
    );
  });

  it("submits new evidence via useCreateEvidence.mutateAsync", async () => {
    vi.mocked(hooks.useIncident).mockReturnValue(
      mockQueryResult({
        data: { incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] },
      }) as ReturnType<typeof hooks.useIncident>
    );
    vi.mocked(hooks.useEvidence).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvidence>);
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>);
    const mutateAsync = vi.fn().mockResolvedValue({});
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(
      mockMutationResult({ mutateAsync }) as unknown as ReturnType<typeof hooks.useCreateEvidence>
    );
    renderAt("i1");

    fireEvent.change(screen.getByLabelText("Evidence hash"), { target: { value: "abc123" } });
    screen.getByText("Add evidence").click();

    await vi.waitFor(() =>
      expect(mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ source: "MANUAL_UPLOAD", hash: "abc123", relationships: [], supersedes: null })
      )
    );
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- IncidentDetailScreen`
Expected: FAIL — `./IncidentDetailScreen` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/incidents/IncidentDetailScreen.tsx`:

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

const INCIDENT_STATUSES: IncidentStatus[] = [
  "NEW",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "FALSE_POSITIVE",
];

export function IncidentDetailScreen() {
  const { incidentId = "" } = useParams<{ incidentId: string }>();
  const incident = useIncident(incidentId);
  const evidence = useEvidence(incidentId);
  const patchStatus = usePatchIncidentStatus(incidentId);
  const createEvidence = useCreateEvidence(incidentId);

  const [nextStatus, setNextStatus] = useState<IncidentStatus>("INVESTIGATING");
  const [why, setWhy] = useState("");
  const [hash, setHash] = useState("");
  const evidenceRows = evidence.data ?? [];

  async function handleStatusSubmit(event: FormEvent) {
    event.preventDefault();
    await patchStatus.mutateAsync({ status: nextStatus, why: why || undefined });
  }

  async function handleEvidenceSubmit(event: FormEvent) {
    event.preventDefault();
    await createEvidence.mutateAsync({
      source: "MANUAL_UPLOAD",
      hash,
      // Nanoseconds since the Unix epoch, matching CanonicalEvent.timestamp's
      // convention — never seconds or milliseconds.
      immutable_since: Date.now() * 1_000_000,
      relationships: [],
      supersedes: null,
    });
    setHash("");
  }

  return (
    <div>
      <h1>Incident {incidentId}</h1>
      {incident.isLoading && <p>Loading incident…</p>}
      {incident.isError && (
        <p role="alert">Failed to load incident: {(incident.error as Error).message}</p>
      )}
      {incident.data && (
        <section aria-label="incident detail">
          <dl>
            <dt>Status</dt>
            <dd>{incident.data.status}</dd>
            <dt>Entities</dt>
            <dd>{incident.data.entities.length}</dd>
            <dt>Alerts</dt>
            <dd>{incident.data.alert_ids.length}</dd>
          </dl>
          <h2>Notes</h2>
          {incident.data.notes.length === 0 ? (
            <p>No notes.</p>
          ) : (
            <ul>
              {incident.data.notes.map((note, index) => (
                <li key={index}>{note}</li>
              ))}
            </ul>
          )}
        </section>
      )}
      <form onSubmit={handleStatusSubmit}>
        <h2>Change status</h2>
        <select
          aria-label="New status"
          value={nextStatus}
          onChange={(event) => setNextStatus(event.target.value as IncidentStatus)}
        >
          {INCIDENT_STATUSES.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
        <input
          type="text"
          aria-label="Reason"
          placeholder="Reason (optional)"
          value={why}
          onChange={(event) => setWhy(event.target.value)}
        />
        <button type="submit" disabled={patchStatus.isPending}>
          Update status
        </button>
        {patchStatus.isError && (
          <p role="alert">Failed to update status: {(patchStatus.error as Error).message}</p>
        )}
      </form>
      <section aria-label="evidence">
        <h2>Evidence</h2>
        {evidence.isLoading && <p>Loading evidence…</p>}
        {evidence.isError && (
          <p role="alert">Failed to load evidence: {(evidence.error as Error).message}</p>
        )}
        {!evidence.isLoading && !evidence.isError && evidenceRows.length === 0 && (
          <p>No evidence recorded.</p>
        )}
        {evidenceRows.length > 0 && (
          <ul>
            {evidenceRows.map((item) => (
              <li key={item.evidence_id}>
                {item.source} — {item.integrity.hash}
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={handleEvidenceSubmit}>
          <h3>Record evidence</h3>
          <input
            type="text"
            aria-label="Evidence hash"
            placeholder="Integrity hash"
            value={hash}
            onChange={(event) => setHash(event.target.value)}
            required
          />
          <button type="submit" disabled={createEvidence.isPending}>
            Add evidence
          </button>
          {createEvidence.isError && (
            <p role="alert">Failed to record evidence: {(createEvidence.error as Error).message}</p>
          )}
        </form>
      </section>
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- IncidentDetailScreen`
Expected: PASS (4 tests).

- [ ] **Step 5: Wire the detail route into App.tsx**

In `console/src/App.tsx`, change the import block from:

```tsx
import { IncidentList } from "./screens/incidents/IncidentList";
```

to:

```tsx
import { IncidentDetailScreen } from "./screens/incidents/IncidentDetailScreen";
import { IncidentList } from "./screens/incidents/IncidentList";
```

and change:

```tsx
              <Route path="/incidents" element={<IncidentList />} />
```

to:

```tsx
              <Route path="/incidents" element={<IncidentList />} />
              <Route path="/incidents/:incidentId" element={<IncidentDetailScreen />} />
```

- [ ] **Step 6: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass. No `App.test.tsx` changes needed — the new route
isn't a nav item.

- [ ] **Step 7: Commit**

```bash
git add console/src/screens/incidents/IncidentDetailScreen.tsx console/src/screens/incidents/IncidentDetailScreen.test.tsx console/src/App.tsx
git commit -m "feat(console): add the Incidents detail screen with status transition and nested Evidence"
```

---

### Task 9: Manual end-to-end smoke verification

This task has no code changes — it confirms the whole stack (Process
Explorer, Alerts, Incidents/Evidence) works together against a real
`osiris-server`, since Tasks 1-8's automated tests each verify one layer
in isolation (mocked `fetch`/hooks). Reuses the same scratch-config
approach 7b-1's Task 9 established (`dev_cors: true`, plus
`baseline_db_path`/`incidents_db_path`/`evidence_db_path`/`links_db_path`/
`investigate_audit_log_path` all pointed at writable paths — the minimal
config from `config.rs`'s tests alone fails fast without these).

**Files:** none.

- [ ] **Step 1: Start osiris-server with dev_cors enabled**

Reuse or recreate a scratch config with `dev_cors: true` and all the
store paths above pointed at writable locations, then run:

```bash
cargo run --bin osiris-server -- path/to/that/config.yaml
```

Expected: server starts and binds to its `listen_addr` (e.g.
`127.0.0.1:8080`, matching `console/vite.config.ts`'s hard-coded proxy
target).

- [ ] **Step 2: Insert synthetic PROCESS_EXEC events for Process Explorer**

Stop the server. Add a temporary test to `crates/osiris-api/src/lib.rs`'s
`mod tests` block (mirroring 7b-1's Task 9 pattern), pointed at the same
`db_path` the server config from Step 1 uses. Reuse the existing
`sample_event(pid: u32, parent_key: Option<ProcessKey>, timestamp: u64)`
fixture (already in this file's `mod tests`, confirmed present as of
7b-1/7a — it builds a full `PROCESS_EXEC` `CanonicalEvent` with a real
`process: Some(ProcessRef {..})`) to seed one parent and one child
process, so Process Explorer's list, detail, and children-list all have
something to show:

```rust
    #[test]
    #[ignore]
    fn temporary_seed_process_events_for_manual_smoke_test() {
        let storage = SqliteStorage::open("/path/to/the/same/db_path/from/step/1").unwrap();
        let parent = sample_event(4242, None, 1000);
        let parent_key = parent.process.as_ref().unwrap().process_key.clone();
        storage.write(&parent).unwrap();
        storage.write(&sample_event(4243, Some(parent_key), 2000)).unwrap();
    }
```

Run: `cargo test -p osiris-api temporary_seed_process_events_for_manual_smoke_test -- --ignored --nocapture`

Then delete the temporary test — it must not be committed. Restart the
server afterward so it re-reads the now-seeded database.

- [ ] **Step 3: Start the Console dev server**

```bash
cd console && npm run dev
```

- [ ] **Step 4: Verify Process Explorer, Alerts, and Incidents in a browser**

Open the printed URL (typically `http://localhost:5173`). Confirm:
- Process Explorer lists the seeded process; clicking it navigates to
  its detail route and shows its PID/exe path and an (empty, since no
  alerts were seeded) related-alerts section.
- Alerts shows an empty state (no alerts seeded) without erroring.
- Incidents shows an empty state; using the "New incident" form with an
  IP entity (e.g. `203.0.113.10`) successfully creates an incident and
  navigates to its detail page; the detail page's status-transition
  control successfully changes status; the "Record evidence" form
  successfully adds evidence and it appears in the list without a page
  reload (TanStack Query cache invalidation working).
- No CORS errors appear in the browser console for any of the three
  screens.

- [ ] **Step 5: Report the result**

No commit for this task — record in the PR/handoff notes (or directly to
the user) that the manual smoke check passed, including which
config/db path was used and which of the four confirmations in Step 4
succeeded, since this is the only step in the plan not captured by an
automated test.

---
