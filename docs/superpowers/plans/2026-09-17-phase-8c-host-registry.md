# Phase 8c — Host Registry (v1, read-only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a read-only Host Registry: `GET /api/v1/hosts` aggregates already-ingested events into one row per recently-active `host_id`, and a new Console `HostList` screen links into the existing Timeline screen (now deep-linkable via a `?host=` param) instead of a new Detail screen.

**Architecture:** One new handler in `osiris-api` (`hosts_handler`), following the exact pattern `containers_handler`/`files_handler`/`network_handler` already use (bounded `EventQueryPlan` query + Rust-side dedup by key), but time-windowed to recent activity (`since`/`until`, defaulting to the last 24h) rather than an unbounded historical scan, since "is this host currently part of the fleet" is inherently a recency question. No new backend work for detail — `GET /api/v1/system/story?host_id=` already exists and already backs the Timeline screen; Timeline gains a `?host=` URL param that pre-selects a host on mount.

**Tech Stack:** Rust workspace, axum, `osiris_query::EventQueryPlan`; React + TypeScript Console, React Query, react-router-dom.

**Spec:** `docs/superpowers/specs/2026-09-17-phase-8c-host-registry-design.md`

## Global Constraints

- `GET /api/v1/hosts` is time-windowed (`since` defaults to `now_ns() - 24h`, `until` defaults to `u64::MAX`), NOT an unbounded historical scan — this is a deliberate departure from the Files/Network/Containers list-endpoint precedent, not an oversight (spec §2).
- `status` is `"ONLINE"` if `now_ns() - last_seen <= 5 * 60 * 1_000_000_000` (5 minutes), else `"STALE"` — a v1 heuristic based on event recency, not a real heartbeat protocol.
- No `cloud` field in the response (spec §2, §7) — nothing populates it yet.
- No new Console Detail screen — HostList links to `/timeline?host=<host_id>` (URL-encoded), and Timeline reads that param to pre-select its existing host dropdown state.
- `min_role: Viewer` on `GET /api/v1/hosts` — no `auth_middleware.rs` change needed (the existing `min_role_for` already defaults unmatched paths to `Role::Viewer`); this plan's Task 1 includes a regression-guard assertion that no more-specific existing rule shadows `/api/v1/hosts`, not a new rule.

---

### Task 1: `GET /api/v1/hosts` backend endpoint

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (add `hosts_handler`, `HostSummary`, `HostsQuery`, a `now_ns()` helper, and the router registration)

**Interfaces:**
- Consumes: `osiris_storage::Storage::query_events(&EventQueryPlan)` (existing); `osiris_query::{EventQueryPlan, MAX_EVENT_LIMIT}` (existing); `osiris_schema::CanonicalEvent`'s `host_id: Uuid` and `host: HostRef { hostname, distro, kernel_version, .. }` fields (existing, unchanged).
- Produces: `GET /api/v1/hosts?since=<u64>&until=<u64>` → `Vec<HostSummary>` JSON, sorted by `last_seen` descending. Consumed by Task 2's Console `fetchHosts()`.

- [ ] **Step 1: Write the failing tests**

Open `crates/osiris-api/src/lib.rs` and find its `#[cfg(test)] mod tests` block (it already exists, near the end of the file — search for `mod tests` and add the new tests inside it, alongside the existing `containers_handler`/`files_handler` tests, for consistency with this file's established test placement). Add these tests (they will fail to compile until Step 3 adds the handler):

```rust
    fn host_event(host_id: uuid::Uuid, hostname: &str, timestamp: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: uuid::Uuid::now_v7(),
            schema_version: osiris_schema::SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: osiris_schema::Category::Process,
            severity: osiris_schema::Severity::Info,
            host: osiris_schema::HostRef {
                host_id,
                hostname: hostname.to_string(),
                distro: "ubuntu-22.04".to_string(),
                kernel_version: "5.15.0".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: osiris_schema::Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    fn now_ns_for_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[tokio::test]
    async fn hosts_endpoint_returns_one_row_per_host_most_recent_first() {
        let (_dir, storage) = test_storage();
        let host_a = uuid::Uuid::new_v4();
        let host_b = uuid::Uuid::new_v4();
        let now = now_ns_for_test();
        // host_a: two events, keep the later one (5s ago).
        storage.write(&host_event(host_a, "host-a", now - 10_000_000_000)).unwrap();
        storage.write(&host_event(host_a, "host-a", now - 5_000_000_000)).unwrap();
        // host_b: one event, 2s ago — more recent than host_a's kept event.
        storage.write(&host_event(host_b, "host-b", now - 2_000_000_000)).unwrap();

        let Json(rows) = hosts_handler(State(storage), Query(HostsQuery { since: None, until: None })).await.unwrap();

        assert_eq!(rows.len(), 2, "one row per distinct host_id");
        assert_eq!(rows[0].hostname, "host-b", "most-recently-active host first");
        assert_eq!(rows[1].hostname, "host-a");
        let kept_a = rows.iter().find(|r| r.hostname == "host-a").unwrap();
        assert_eq!(kept_a.last_seen, now - 5_000_000_000, "kept the more recent of host_a's two events");
    }

    #[tokio::test]
    async fn hosts_endpoint_excludes_events_outside_the_since_until_window() {
        let (_dir, storage) = test_storage();
        let host_id = uuid::Uuid::new_v4();
        let now = now_ns_for_test();
        storage.write(&host_event(host_id, "old-host", now - 48 * 3_600_000_000_000)).unwrap();

        // Default window (no since/until given) is the last 24h — this
        // event is 48h old, so it must not appear.
        let Json(rows) = hosts_handler(State(storage.clone()), Query(HostsQuery { since: None, until: None })).await.unwrap();
        assert_eq!(rows.len(), 0);

        // Explicitly widening the window includes it.
        let Json(rows) = hosts_handler(State(storage), Query(HostsQuery { since: Some(0), until: None })).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn hosts_endpoint_marks_status_online_within_five_minutes_and_stale_beyond_it() {
        let (_dir, storage) = test_storage();
        let online_host = uuid::Uuid::new_v4();
        let stale_host = uuid::Uuid::new_v4();
        let now = now_ns_for_test();
        storage.write(&host_event(online_host, "online-host", now - 60 * 1_000_000_000)).unwrap(); // 60s ago
        storage.write(&host_event(stale_host, "stale-host", now - 10 * 60 * 1_000_000_000)).unwrap(); // 10 min ago

        let Json(rows) = hosts_handler(State(storage), Query(HostsQuery { since: Some(0), until: None })).await.unwrap();

        let online = rows.iter().find(|r| r.hostname == "online-host").unwrap();
        let stale = rows.iter().find(|r| r.hostname == "stale-host").unwrap();
        assert_eq!(online.status, "ONLINE");
        assert_eq!(stale.status, "STALE");
    }

    #[test]
    fn no_existing_min_role_for_rule_shadows_the_hosts_path() {
        // Regression guard for this plan's own Global Constraint: /api/v1/hosts
        // must fall through to the default Role::Viewer, not get accidentally
        // caught by an existing more-specific rule (e.g. a prefix match).
        // This test lives here (not auth_middleware.rs) because it's this
        // task's own claim being checked, not a new RBAC rule being added.
        use osiris_auth::Role;
        assert_eq!(
            crate::auth_middleware::min_role_for(&axum::http::Method::GET, "/api/v1/hosts"),
            Role::Viewer
        );
    }
```

This reuses the existing `fn test_storage() -> (tempfile::TempDir, Arc<dyn Storage>)` helper already in this file's test module (confirmed present, ~line 1034) — the tests above already destructure its `(_dir, storage)` tuple return correctly.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p osiris-api hosts_endpoint`
Expected: FAIL — `hosts_handler`, `HostSummary`, `HostsQuery` don't exist yet (compile error).

- [ ] **Step 3: Implement the handler**

Add to `crates/osiris-api/src/lib.rs`, near `containers_handler` (same file, keep related list-endpoint handlers grouped, matching this file's existing organization):

```rust
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

const HOST_ONLINE_THRESHOLD_NS: u64 = 5 * 60 * 1_000_000_000;
const HOST_REGISTRY_DEFAULT_WINDOW_NS: u64 = 24 * 3_600 * 1_000_000_000;

#[derive(Debug, Deserialize)]
struct HostsQuery {
    since: Option<u64>,
    until: Option<u64>,
}

#[derive(Debug, Serialize)]
struct HostSummary {
    host_id: String,
    hostname: String,
    distro: String,
    kernel_version: String,
    last_seen: u64,
    status: String,
}

/// `GET /api/v1/hosts` — ARCHITECTURE.md §21.2's Fleet Manager, scoped to
/// its read-only v1 slice (2026-09-17 phase-8c-host-registry-design.md
/// §1): one row per distinct `host_id` any recent event carried, dedup
/// keyed by `host_id` keeping the most-recent event, `status` a recency
/// heuristic (not a real heartbeat — no AGENT_HEALTH event is emitted by
/// anything today). Time-windowed to `since`/`until` (default: the last
/// 24h) rather than an unbounded historical scan, deliberately unlike
/// `containers_handler`'s sibling shape — see this handler's own design
/// doc §2 for why a fleet registry's correctness depends on recency, not
/// full history.
async fn hosts_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<HostsQuery>,
) -> Result<Json<Vec<HostSummary>>, (StatusCode, String)> {
    let now = now_ns();
    let since = q.since.unwrap_or_else(|| now.saturating_sub(HOST_REGISTRY_DEFAULT_WINDOW_NS));
    let until = q.until.unwrap_or(u64::MAX);
    let plan = osiris_query::EventQueryPlan {
        filter: None,
        since: Some(since),
        until: Some(until),
        limit: osiris_query::MAX_EVENT_LIMIT,
        export: true,
        ..osiris_query::EventQueryPlan::new()
    };
    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();
    for event in events {
        match seen.get(&event.host_id) {
            Some(existing) if existing.timestamp >= event.timestamp => {}
            _ => {
                seen.insert(event.host_id, event);
            }
        }
    }

    let mut rows: Vec<HostSummary> = seen
        .into_values()
        .map(|event| {
            let status = if now.saturating_sub(event.timestamp) <= HOST_ONLINE_THRESHOLD_NS {
                "ONLINE"
            } else {
                "STALE"
            };
            HostSummary {
                host_id: event.host_id.to_string(),
                hostname: event.host.hostname,
                distro: event.host.distro,
                kernel_version: event.host.kernel_version,
                last_seen: event.timestamp,
                status: status.to_string(),
            }
        })
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.last_seen));
    Ok(Json(rows))
}
```

Register the route in `build_router` (in the same file, the function starting `pub fn build_router`), adding one line grouped with the other list endpoints:

```rust
        .route("/api/v1/hosts", get(hosts_handler))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p osiris-api`
Expected: PASS — full `osiris-api` suite green, including the 4 new tests.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): add GET /api/v1/hosts host registry endpoint"
```

---

### Task 2: Console `HostList` screen, Timeline deep-link, wiring, verification

**Files:**
- Modify: `console/src/api/types.ts` (add `HostSummary` interface)
- Modify: `console/src/api/client.ts` (add `fetchHosts`)
- Modify: `console/src/api/hooks.ts` (add `useHosts`)
- Create: `console/src/screens/hosts/HostList.tsx`
- Create: `console/src/screens/hosts/HostList.test.tsx`
- Modify: `console/src/screens/timeline/Timeline.tsx` (read `?host=` search param)
- Modify: `console/src/screens/timeline/Timeline.test.tsx` (add a regression test for the new param)
- Modify: `console/src/app/navItems.ts` (add the "Hosts" nav entry)
- Modify: `console/src/App.tsx` (add the `/hosts` route)
- Modify: `console/src/App.test.tsx` (update the nav-link-count assertion)

**Interfaces:**
- Consumes: Task 1's `GET /api/v1/hosts` response shape (`{ host_id, hostname, distro, kernel_version, last_seen, status }[]`).
- Produces: `HostList` screen at `/hosts`; `Timeline` now accepts an optional `?host=<host_id>` URL param.

- [ ] **Step 1: Add the `HostSummary` type**

In `console/src/api/types.ts`, add (near the other `*Summary` interfaces, e.g. right after `ContainerSummary`):

```typescript
export interface HostSummary {
  host_id: string;
  hostname: string;
  distro: string;
  kernel_version: string;
  last_seen: number;
  status: "ONLINE" | "STALE";
}
```

- [ ] **Step 2: Add `fetchHosts` and a client test**

In `console/src/api/client.ts`, add the `HostSummary` import to the existing type-import block at the top of the file (alongside `ContainerSummary` etc.), then add near `fetchContainers`:

```typescript
export function fetchHosts(): Promise<HostSummary[]> {
  return apiGet<HostSummary[]>("/hosts");
}
```

In `console/src/api/client.test.ts`, add a test right after the existing `fetchContainers` test (confirmed present, ~line 369), matching its exact shape (this file has no shared mock-helper function — each test inlines `vi.mocked(fetch).mockResolvedValue(...)` directly):

```typescript
  it("fetchHosts calls /api/v1/hosts", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
    await fetchHosts();
    expect(fetch).toHaveBeenCalledWith("/api/v1/hosts");
  });
```

Add `fetchHosts` to this test file's top-level import list alongside the other `fetch*` imports (the same list `fetchContainers` is already in, ~line 8).

- [ ] **Step 3: Add `useHosts` hook**

In `console/src/api/hooks.ts`, add `fetchHosts` to the existing import list from `./client`, then add near `useContainers`:

```typescript
export function useHosts() {
  return useQuery({
    queryKey: ["hosts"],
    queryFn: fetchHosts,
  });
}
```

- [ ] **Step 4: Write `HostList.tsx` and its test (TDD: test first)**

Create `console/src/screens/hosts/HostList.test.tsx`:

```typescript
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { HostList } from "./HostList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useHosts>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <HostList />
    </MemoryRouter>
  );
}

describe("HostList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading hosts…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No hosts found.")).toBeInTheDocument();
  });

  it("renders a row per host, linking to Timeline pre-filtered by host", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "host-a", distro: "ubuntu-22.04", kernel_version: "5.15.0", last_seen: 1000, status: "ONLINE" },
        ],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "host-a" });
    expect(link).toHaveAttribute(
      "href",
      "/timeline?host=11111111-1111-1111-1111-111111111111"
    );
    expect(screen.getByText("ubuntu-22.04")).toBeInTheDocument();
    expect(screen.getByText("ONLINE")).toBeInTheDocument();
  });
});
```

- [ ] **Step 5: Run to verify it fails**

Run: `cd console && npm test -- --run HostList`
Expected: FAIL — `HostList` module doesn't exist.

- [ ] **Step 6: Implement `HostList.tsx`**

Create `console/src/screens/hosts/HostList.tsx`:

```typescript
import { Link } from "react-router-dom";
import { useHosts } from "../../api/hooks";

export function HostList() {
  const hosts = useHosts();
  const rows = hosts.data ?? [];

  return (
    <div>
      <h1>Hosts</h1>
      {hosts.isLoading && <p>Loading hosts…</p>}
      {hosts.isError && (
        <p role="alert">Failed to load hosts: {(hosts.error as Error).message}</p>
      )}
      {!hosts.isLoading && !hosts.isError && rows.length === 0 && <p>No hosts found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Distro</th>
              <th>Kernel</th>
              <th>Last Seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.host_id}>
                <td>
                  <Link to={`/timeline?host=${encodeURIComponent(row.host_id)}`}>{row.hostname}</Link>
                </td>
                <td>{row.distro}</td>
                <td>{row.kernel_version}</td>
                <td>{row.last_seen}</td>
                <td>{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 7: Run to verify it passes**

Run: `cd console && npm test -- --run HostList`
Expected: PASS (4 tests)

- [ ] **Step 8: Add the Timeline `?host=` deep-link (TDD: test first)**

**Important, confirmed by reading the current file:** none of `Timeline.test.tsx`'s 5 existing tests wrap `<Timeline />` in a `MemoryRouter` — the file imports nothing from `react-router-dom` today. Adding `useSearchParams` to `Timeline.tsx` in Step 10 will make every one of those 5 tests fail (a component calling `useSearchParams` outside a Router context throws) unless this step also wraps them. Fix this properly here, not just for the one new test.

Rewrite `console/src/screens/timeline/Timeline.test.tsx`'s top (imports and the `render(<Timeline />)` call sites) as follows — add a `renderWithRouter` helper (matching `ContainerList.test.tsx`'s own existing convention for this exact problem) and replace every one of the 5 existing `render(<Timeline />)` calls with `renderWithRouter()`:

```typescript
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
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

function renderWithRouter(initialEntries: string[] = ["/timeline"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <Timeline />
    </MemoryRouter>
  );
}
```

Then, in every one of the 5 existing `it(...)` blocks, change `render(<Timeline />);` to `renderWithRouter();` — leave the rest of each test's body (the mock setup, the assertions) exactly as it is today. Do not change the `sensorHealthEvent` helper or anything else in the file.

Finally, add this new test at the end of the `describe("Timeline", ...)` block, right before its closing `});`:

```typescript
  it("pre-selects the host from a ?host= URL search param", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvents>);
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    renderWithRouter(["/timeline?host=host-a"]);

    expect(hooks.useSystemStory).toHaveBeenLastCalledWith("host-a", { since: undefined, until: undefined });
  });
```

- [ ] **Step 9: Run to verify it fails**

Run: `cd console && npm test -- --run Timeline`
Expected: FAIL — specifically the new test (`useSystemStory` gets called with `""`, not `"host-a"`, since `Timeline.tsx` doesn't yet read the `host` param). The 5 pre-existing tests should already PASS after Step 8's `renderWithRouter` rewrite alone (that rewrite is a pure refactor of how they render, not a behavior change) — if any of those 5 fail at this point, the rewrite introduced a mistake; fix it before proceeding, since Step 8 must be a no-op for existing behavior.

- [ ] **Step 10: Implement the Timeline change**

In `console/src/screens/timeline/Timeline.tsx`, add the import and initialize `hostId` from the search param:

```typescript
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useEvents, useSystemStory } from "../../api/hooks";
import { parseOptionalNumber } from "../../api/numeric";
import { rollupSensorHealth } from "../sensors/rollup";

const ONE_HOUR_NS = 3_600 * 1_000_000_000;

export function Timeline() {
  const [searchParams] = useSearchParams();
  const [hostId, setHostId] = useState(searchParams.get("host") ?? "");
```

(Replace only the top of the file through the `useState("")` line — leave every line below `const [hostId, setHostId] = useState(...)` untouched. `useState`'s initializer runs once on mount, which is exactly "pre-select on arrival, let the user still change it afterward via the dropdown" — no `useEffect` needed.)

- [ ] **Step 11: Run to verify it passes**

Run: `cd console && npm test -- --run Timeline`
Expected: PASS — all 6 tests (5 pre-existing + 1 new), confirming the change is additive: a plain `/timeline` visit (Step 8's `renderWithRouter()` default of `["/timeline"]`) still starts with `hostId = ""` exactly as before, since `searchParams.get("host")` is `null` there and `?? ""` preserves the old default.

- [ ] **Step 12: Wire the route and nav**

In `console/src/app/navItems.ts`, add one entry after `"Timeline"` (order doesn't have to be Timeline-adjacent, but grouping a fleet-oriented screen near the other list-style screens like `"Containers"` is also reasonable — place it directly after `"Containers"` and before `"Timeline"`, matching this plan's own framing of Hosts as a list screen, not an investigation-flow screen):

```typescript
  { label: "Hosts", path: "/hosts", enabled: true },
```

In `console/src/App.tsx`, add the import:

```typescript
import { HostList } from "./screens/hosts/HostList";
```

(insert alphabetically among the existing screen imports, matching this file's existing import ordering) and add the route inside the existing `<Route element={<Shell />}>` block, near `<Route path="/containers" element={<ContainerList />} />`:

```typescript
                <Route path="/hosts" element={<HostList />} />
```

- [ ] **Step 13: Update `App.test.tsx`'s nav assertions**

In `console/src/App.test.tsx`, update the third test (`"renders exactly thirteen nav links..."`) to fourteen, inserting `"Hosts"` into the expected array in the same position `navItems.ts` now has it (right after `"Containers"`):

```typescript
  it("renders exactly fourteen nav links, for Overview, Live Events, Process Explorer, Filesystem, Network, Containers, Hosts, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, Evidence, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(14);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Live Events",
      "Process Explorer",
      "Filesystem",
      "Network",
      "Containers",
      "Hosts",
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

(Keep the rest of that test's body, e.g. any trailing `within(...)` checks in the original, unchanged — only the count and the array contents change. Read the current test first to preserve anything not shown in this excerpt.)

- [ ] **Step 14: Run the full console suite**

Run: `cd console && npm test -- --run`
Expected: PASS — every test file green, including all changes above.

- [ ] **Step 15: Run the full console build**

Run: `cd console && npm run build`
Expected: clean, zero TypeScript errors.

- [ ] **Step 16: Run the full backend workspace suite once more**

Run: `cargo test --workspace` (from the repository root)
Expected: PASS — confirms Task 1's backend change and Task 2's frontend-only change didn't regress anything else.

- [ ] **Step 17: Commit**

```bash
git add console/src/api/types.ts console/src/api/client.ts console/src/api/client.test.ts console/src/api/hooks.ts console/src/screens/hosts/HostList.tsx console/src/screens/hosts/HostList.test.tsx console/src/screens/timeline/Timeline.tsx console/src/screens/timeline/Timeline.test.tsx console/src/app/navItems.ts console/src/App.tsx console/src/App.test.tsx
git commit -m "feat(console): add Hosts list screen and Timeline host deep-link"
```

---

## Self-Review Notes

- **Spec coverage:** §2 (query shape, dedup, status heuristic) → Task 1. §3 (endpoint, RBAC) → Task 1 Step 3 + the `min_role_for` regression-guard test. §4 (Console list screen, Timeline reuse via `?host=`, no new Detail screen, no `EntityRef::Host`) → Task 2. §5 (error handling) → covered implicitly by reusing axum's existing `Query`/`Json` extractor behavior, no bespoke code needed. §6 (testing) → Task 1 Step 1's 4 tests, Task 2's HostList + Timeline tests. §7 (Non-Goals) → no tasks for any of them, by design.
- **Two named "verify before assuming" items carried from the spec into task text rather than guessed:** Task 1 Step 1 says to find and reuse this file's actual existing `Storage`-constructing test helper by its real name (not invented here) since this plan wasn't able to grep its exact identifier while accounting for every possible existing helper name; Task 2 Step 2 says the same for `client.test.ts`'s mock-fetch helper. Both are small, low-risk lookups the implementer resolves in seconds by reading the file, not open-ended ambiguity.
- **Type/name consistency check:** `HostSummary` (Rust struct in Task 1, TypeScript interface in Task 2) has the same five fields in the same shapes (`host_id`/`hostname`/`distro`/`kernel_version` as strings, `last_seen` as a number, `status` as one of two literal strings) in both places. `useHosts`/`fetchHosts`/`HostList` naming matches the established `useContainers`/`fetchContainers`/`ContainerList` convention exactly, so a reader already familiar with this codebase's other list screens can predict every name before reading the code.
