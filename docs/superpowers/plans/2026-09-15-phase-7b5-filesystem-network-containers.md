# Phase 7b-5: Filesystem, Network, Containers List/Detail Screens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship three new backend list endpoints (`GET /api/v1/files`, `/network`, `/containers`) and six new Console screens (List + Detail per resource), replacing the disabled `ComingSoon` placeholders for Filesystem, Network, and Containers.

**Architecture:** Each new backend endpoint follows `network_story.rs`'s existing `EventQueryPlan`/`Ast::Compare`/`storage.query_events()` pattern (not `processes_handler`'s simpler `osiris_storage::QueryPlan`), filtering by `category` and doing an in-handler `HashMap` dedup that keeps the **most-recent** event per identity. Detail screens need **zero new backend work** — `/files/story`, `/network/story`, `/containers/story` already exist and already accept exactly the identity each List row carries; only the Console's `client.ts`/`hooks.ts` are missing fetch/hook wrappers for them.

**Tech Stack:** Rust (axum, serde, `osiris_query::EventQueryPlan`), TypeScript/React (`@tanstack/react-query`, `react-router-dom`, Vitest + React Testing Library).

**Spec:** `docs/superpowers/specs/2026-09-14-phase-7b5-filesystem-network-containers-design.md`

## Global Constraints

- No new `Storage` trait methods — every new handler is a bounded `EventQueryPlan` query + Rust-side dedup in the API handler, matching `/processes`'s and `/network/story`'s existing precedent.
- Query shape: `Ast::Compare { field: "category", op: Op::Eq, value: Value::Str("FILE"|"NETWORK"|"CONTAINER") }`, `limit: 10_000`, `export: true` — same bounds `network_addr_plan` already uses.
- Dedup keeps the **most-recent** event per identity (highest `timestamp`), not first-seen — a deliberate departure from `/processes`'s first-seen semantics.
- Known accepted limitation (not fixed this phase): dedup happens over a bounded, unordered-by-recency event window, so an identity whose events fall outside the window can be missing from the list. Every new List screen's comment must carry this caveat, matching `ProcessList.tsx`'s own comment.
- Identity per resource: Files use `(host_id, FileIdentity)`; Network uses `(host_id, dst_ip, dst_port, proto)` (destination-only, no source port); Containers use `container_id` alone (not host-scoped, matching `container_story_handler`'s existing host-agnostic behavior).
- No new TypeScript `Story` types — `Story { events, alerts }` already exists in `console/src/api/types.ts` and is reused for File/Network/Container stories unchanged.
- All three pivot links use an explicit `onClick={() => selectEntity(...)}` on the "View in Entity Graph" link, matching `ProcessDetailScreen.tsx`'s established pattern (not a mount-effect-only approach).
- `FileIdentity::as_key()` format is `"<device_id>:<inode>"` (device_id first). `EntityRef::File::storage_key()` format is `"FILE:<host_id>:<inode>:<device_id>"` (inode first, after host_id). These two orders differ — do not assume they match when building the File pivot link.

---

## File Structure

**Backend — all in `crates/osiris-api/src/lib.rs`** (matching this file's existing per-endpoint style — no shared abstraction extracted):
- New: `FileSummary` struct + `files_handler` fn, placed immediately before `file_story_handler`.
- New: `NetworkSummary` struct + `network_handler` fn, placed immediately before `network_story_handler`.
- New: `ContainerSummary` struct + `containers_handler` fn, placed immediately before `container_story_handler`.
- New: one shared private `event_type_label(EventType) -> String` helper, placed near `MAX_GRAPH_DEPTH` (top of file, before the first handler that needs it).
- Modified: `build_router` — 3 new `.route()` lines.
- Modified: `#[cfg(test)] mod tests` — new tests using the already-existing `file_event`/`network_event`/`container_event` fixtures.

**Frontend:**
- Modified: `console/src/api/types.ts` — add `FileSummary`, `NetworkSummary`, `ContainerSummary`.
- Modified: `console/src/api/client.ts` — add `fetchFiles`, `fetchNetwork`, `fetchContainers`, `fetchFileStory`, `fetchNetworkStory`, `fetchContainerStory`.
- Modified: `console/src/api/hooks.ts` — add `useFiles`, `useNetwork`, `useContainers`, `useFileStory`, `useNetworkStory`, `useContainerStory`.
- New: `console/src/screens/files/FileList.tsx`, `FileList.test.tsx`, `FileDetailScreen.tsx`, `FileDetailScreen.test.tsx`.
- New: `console/src/screens/network/NetworkList.tsx`, `NetworkList.test.tsx`, `NetworkDetailScreen.tsx`, `NetworkDetailScreen.test.tsx`.
- New: `console/src/screens/containers/ContainerList.tsx`, `ContainerList.test.tsx`, `ContainerDetailScreen.tsx`, `ContainerDetailScreen.test.tsx`.
- Modified: `console/src/App.tsx` — swap 3 `ComingSoon` routes for real List screens, add 3 new Detail routes.
- Modified: `console/src/app/navItems.ts` — flip `enabled: false` → `true` for Filesystem/Network/Containers.

---

### Task 1: Backend — Files list endpoint

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (add struct/handler before `file_story_handler`, add route, add tests to `mod tests`)

**Interfaces:**
- Produces: `FileSummary { file_id: String, path: String, host_id: String, hostname: String, last_event_type: String, timestamp: u64 }`, `async fn files_handler(State<Arc<dyn Storage>>) -> Result<Json<Vec<FileSummary>>, (StatusCode, String)>`, route `GET /api/v1/files`, private helper `fn event_type_label(event_type: EventType) -> String`.
- Consumes: `osiris_schema::{EventType, FileIdentity}`, `osiris_query::EventQueryPlan`/`ast::{Ast, Op, Value}` (fully-qualified, no new `use` — matches `events_handler`'s existing convention in this file), `Storage::query_events`, existing test fixtures `file_event`, `test_storage`.

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `crates/osiris-api/src/lib.rs` (anywhere after the `file_event` fixture, e.g. right after it):

```rust
#[tokio::test]
async fn files_endpoint_keeps_the_most_recent_event_per_identity() {
    let (_dir, storage) = test_storage();
    let older = file_event(EventType::FileCreate, "/etc/passwd", 100, 1, 1000);
    let mut newer = older.clone();
    newer.event_type = EventType::FileWrite;
    newer.timestamp = 2000;
    let host_id = older.host_id;
    let hostname = older.host.hostname.clone();
    storage.batch_write(&[older, newer]).unwrap();

    let Json(files) = files_handler(State(storage)).await.unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].file_id, "1:100");
    assert_eq!(files[0].path, "/etc/passwd");
    assert_eq!(files[0].host_id, host_id.to_string());
    assert_eq!(files[0].hostname, hostname);
    assert_eq!(files[0].last_event_type, "FILE_WRITE");
    assert_eq!(files[0].timestamp, 2000);
}

#[tokio::test]
async fn files_endpoint_skips_events_without_a_full_file_identity() {
    let (_dir, storage) = test_storage();
    let mut missing_inode = file_event(EventType::FileCreate, "/etc/shadow", 1, 1, 1000);
    missing_inode.file.as_mut().unwrap().inode = None;
    storage.write(&missing_inode).unwrap();

    let Json(files) = files_handler(State(storage)).await.unwrap();

    assert!(files.is_empty());
}

#[tokio::test]
async fn files_endpoint_treats_different_hosts_with_the_same_identity_as_distinct_rows() {
    let (_dir, storage) = test_storage();
    let a = file_event(EventType::FileCreate, "/etc/passwd", 100, 1, 1000);
    let mut b = file_event(EventType::FileCreate, "/etc/passwd", 100, 1, 1000);
    b.host_id = uuid::Uuid::new_v4();
    b.host.host_id = b.host_id;
    storage.batch_write(&[a, b]).unwrap();

    let Json(files) = files_handler(State(storage)).await.unwrap();

    assert_eq!(files.len(), 2);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p osiris-api files_endpoint -- --nocapture`
Expected: FAIL with "cannot find function `files_handler`" (and `FileSummary` unresolved) — the handler doesn't exist yet.

- [ ] **Step 3: Add the `event_type_label` helper**

Add near `MAX_GRAPH_DEPTH` (top of `crates/osiris-api/src/lib.rs`, before the first handler that uses it):

```rust
/// `EventType`'s wire form (`#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`,
/// e.g. `FileWrite` -> `"FILE_WRITE"`) — used by the new Files/Network/
/// Containers list endpoints' `last_event_type`/`status` fields so they
/// match every other place `event_type` appears on the wire.
fn event_type_label(event_type: EventType) -> String {
    serde_json::to_value(event_type)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}
```

- [ ] **Step 4: Implement `FileSummary` and `files_handler`**

Add immediately before `file_story_handler` in `crates/osiris-api/src/lib.rs`:

```rust
#[derive(Debug, Serialize)]
struct FileSummary {
    file_id: String,
    path: String,
    host_id: String,
    hostname: String,
    last_event_type: String,
    timestamp: u64,
}

/// `GET /api/v1/files` — ARCHITECTURE.md §16.3's Filesystem list screen.
/// Bounded `category = "FILE"` query + Rust-side dedup keyed by
/// `(host_id, FileIdentity)`, keeping the most-recent event per identity —
/// see this phase's design spec for why this departs from `/processes`'s
/// first-seen semantics. Events with no full `FileIdentity` (missing
/// inode or device_id) are skipped, matching that type's existing
/// `from_file_ref` semantics.
async fn files_handler(
    State(storage): State<Arc<dyn Storage>>,
) -> Result<Json<Vec<FileSummary>>, (StatusCode, String)> {
    let plan = osiris_query::EventQueryPlan {
        filter: Some(osiris_query::ast::Ast::Compare {
            field: "category".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str("FILE".to_string()),
        }),
        limit: 10_000,
        export: true,
        ..osiris_query::EventQueryPlan::new()
    };
    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<(uuid::Uuid, FileIdentity), FileSummary> = HashMap::new();
    for event in events {
        let Some(file) = &event.file else { continue };
        let Some(identity) = FileIdentity::from_file_ref(file) else { continue };
        let key = (event.host_id, identity);
        match seen.get(&key) {
            Some(existing) if existing.timestamp >= event.timestamp => {}
            _ => {
                seen.insert(
                    key,
                    FileSummary {
                        file_id: identity.as_key(),
                        path: file.path.clone(),
                        host_id: event.host_id.to_string(),
                        hostname: event.host.hostname.clone(),
                        last_event_type: event_type_label(event.event_type),
                        timestamp: event.timestamp,
                    },
                );
            }
        }
    }
    Ok(Json(seen.into_values().collect()))
}
```

- [ ] **Step 5: Register the route**

In `build_router`, add a line right after `.route("/api/v1/alerts", get(alerts_handler))` and before `.route("/api/v1/files/story", get(file_story_handler))`:

```rust
.route("/api/v1/files", get(files_handler))
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p osiris-api files_endpoint -- --nocapture`
Expected: PASS, 3 tests.

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): add GET /api/v1/files list endpoint"
```

---

### Task 2: Backend — Network list endpoint

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (add struct/handler before `network_story_handler`, add route, add tests)

**Interfaces:**
- Produces: `NetworkSummary { host_id: String, hostname: String, dst_ip: String, dst_port: u16, proto: String, last_event_type: String, timestamp: u64 }`, `async fn network_handler(...) -> Result<Json<Vec<NetworkSummary>>, ...>`, route `GET /api/v1/network`.
- Consumes: `event_type_label` (Task 1), existing test fixture `network_event`.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`, near the `network_event` fixture:

```rust
#[tokio::test]
async fn network_endpoint_keeps_the_most_recent_event_per_destination() {
    let (_dir, storage) = test_storage();
    let older = network_event(EventType::NetworkConnect, "10.0.0.5", "93.184.216.34", 1000);
    let mut newer = older.clone();
    newer.event_type = EventType::NetworkClose;
    newer.timestamp = 2000;
    let host_id = older.host_id;
    storage.batch_write(&[older, newer]).unwrap();

    let Json(rows) = network_handler(State(storage)).await.unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].dst_ip, "93.184.216.34");
    assert_eq!(rows[0].dst_port, 443);
    assert_eq!(rows[0].proto, "tcp");
    assert_eq!(rows[0].host_id, host_id.to_string());
    assert_eq!(rows[0].last_event_type, "NETWORK_CLOSE");
    assert_eq!(rows[0].timestamp, 2000);
}

#[tokio::test]
async fn network_endpoint_treats_different_destination_ports_as_distinct_rows() {
    let (_dir, storage) = test_storage();
    let a = network_event(EventType::NetworkConnect, "10.0.0.5", "93.184.216.34", 1000);
    let mut b = a.clone();
    b.network.as_mut().unwrap().dst_port = 8443;
    storage.batch_write(&[a, b]).unwrap();

    let Json(rows) = network_handler(State(storage)).await.unwrap();

    assert_eq!(rows.len(), 2);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p osiris-api network_endpoint -- --nocapture`
Expected: FAIL — `network_handler`/`NetworkSummary` unresolved.

- [ ] **Step 3: Implement `NetworkSummary` and `network_handler`**

Add immediately before `network_story_handler`:

```rust
#[derive(Debug, Serialize)]
struct NetworkSummary {
    host_id: String,
    hostname: String,
    dst_ip: String,
    dst_port: u16,
    proto: String,
    last_event_type: String,
    timestamp: u64,
}

/// `GET /api/v1/network` — ARCHITECTURE.md §16.3's Network list screen.
/// Bounded `category = "NETWORK"` query + Rust-side dedup keyed by
/// `(host_id, dst_ip, dst_port, proto)` — destination-only, deliberately
/// excluding `src_ip`/`src_port` since source port is normally ephemeral
/// (see this phase's design spec). Keeps the most-recent event per group.
async fn network_handler(
    State(storage): State<Arc<dyn Storage>>,
) -> Result<Json<Vec<NetworkSummary>>, (StatusCode, String)> {
    let plan = osiris_query::EventQueryPlan {
        filter: Some(osiris_query::ast::Ast::Compare {
            field: "category".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str("NETWORK".to_string()),
        }),
        limit: 10_000,
        export: true,
        ..osiris_query::EventQueryPlan::new()
    };
    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<(uuid::Uuid, String, u16, String), NetworkSummary> = HashMap::new();
    for event in events {
        let Some(network) = &event.network else { continue };
        let key = (
            event.host_id,
            network.dst_ip.clone(),
            network.dst_port,
            network.proto.clone(),
        );
        match seen.get(&key) {
            Some(existing) if existing.timestamp >= event.timestamp => {}
            _ => {
                seen.insert(
                    key,
                    NetworkSummary {
                        host_id: event.host_id.to_string(),
                        hostname: event.host.hostname.clone(),
                        dst_ip: network.dst_ip.clone(),
                        dst_port: network.dst_port,
                        proto: network.proto.clone(),
                        last_event_type: event_type_label(event.event_type),
                        timestamp: event.timestamp,
                    },
                );
            }
        }
    }
    Ok(Json(seen.into_values().collect()))
}
```

- [ ] **Step 4: Register the route**

In `build_router`, add right after `.route("/api/v1/files", get(files_handler))` (Task 1) and before `.route("/api/v1/files/story", get(file_story_handler))` — or equivalently, right before `.route("/api/v1/network/story", get(network_story_handler))`:

```rust
.route("/api/v1/network", get(network_handler))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-api network_endpoint -- --nocapture`
Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): add GET /api/v1/network list endpoint"
```

---

### Task 3: Backend — Containers list endpoint

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (add struct/handler before `container_story_handler`, add route, add tests)

**Interfaces:**
- Produces: `ContainerSummary { container_id: String, host_id: String, hostname: String, image: String, status: String, timestamp: u64 }` (status is `"RUNNING"` or `"STOPPED"`), `async fn containers_handler(...) -> Result<Json<Vec<ContainerSummary>>, ...>`, route `GET /api/v1/containers`.
- Consumes: `event_type_label` (Task 1, not used for `status` but available), existing test fixture `container_event`.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`, near the `container_event` fixture:

```rust
#[tokio::test]
async fn containers_endpoint_derives_running_status_from_the_most_recent_event() {
    let (_dir, storage) = test_storage();
    let id = "c".repeat(64);
    let create = container_event(&id, EventType::ContainerCreate, 1000);
    let start = container_event(&id, EventType::ContainerStart, 2000);
    storage.batch_write(&[create, start]).unwrap();

    let Json(rows) = containers_handler(State(storage)).await.unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].container_id, id);
    assert_eq!(rows[0].status, "RUNNING");
    assert_eq!(rows[0].timestamp, 2000);
}

#[tokio::test]
async fn containers_endpoint_derives_stopped_status_from_the_most_recent_event() {
    let (_dir, storage) = test_storage();
    let id = "d".repeat(64);
    let start = container_event(&id, EventType::ContainerStart, 1000);
    let stop = container_event(&id, EventType::ContainerStop, 2000);
    storage.batch_write(&[start, stop]).unwrap();

    let Json(rows) = containers_handler(State(storage)).await.unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "STOPPED");
}

#[tokio::test]
async fn containers_endpoint_dedups_by_container_id_alone_not_host() {
    let (_dir, storage) = test_storage();
    let id = "e".repeat(64);
    let mut on_host_a = container_event(&id, EventType::ContainerStart, 1000);
    let mut on_host_b = container_event(&id, EventType::ContainerStart, 2000);
    on_host_b.host_id = uuid::Uuid::new_v4();
    on_host_b.host.host_id = on_host_b.host_id;
    on_host_a.host_id = uuid::Uuid::new_v4();
    on_host_a.host.host_id = on_host_a.host_id;
    storage.batch_write(&[on_host_a, on_host_b]).unwrap();

    let Json(rows) = containers_handler(State(storage)).await.unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].timestamp, 2000);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p osiris-api containers_endpoint -- --nocapture`
Expected: FAIL — `containers_handler`/`ContainerSummary` unresolved.

- [ ] **Step 3: Implement `ContainerSummary` and `containers_handler`**

Add immediately before `container_story_handler`:

```rust
#[derive(Debug, Serialize)]
struct ContainerSummary {
    container_id: String,
    host_id: String,
    hostname: String,
    image: String,
    status: String,
    timestamp: u64,
}

/// `GET /api/v1/containers` — ARCHITECTURE.md §16.3's Containers list
/// screen. Bounded `category = "CONTAINER"` query + Rust-side dedup keyed
/// by `container_id` alone (not host-scoped, matching
/// `container_story_handler`'s own existing host-agnostic behavior).
/// `status` is derived from the kept (most-recent) event's `event_type`.
async fn containers_handler(
    State(storage): State<Arc<dyn Storage>>,
) -> Result<Json<Vec<ContainerSummary>>, (StatusCode, String)> {
    let plan = osiris_query::EventQueryPlan {
        filter: Some(osiris_query::ast::Ast::Compare {
            field: "category".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str("CONTAINER".to_string()),
        }),
        limit: 10_000,
        export: true,
        ..osiris_query::EventQueryPlan::new()
    };
    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut seen: HashMap<String, ContainerSummary> = HashMap::new();
    for event in events {
        let Some(container) = &event.container else { continue };
        let key = container.container_id.clone();
        match seen.get(&key) {
            Some(existing) if existing.timestamp >= event.timestamp => {}
            _ => {
                let status = match event.event_type {
                    EventType::ContainerCreate | EventType::ContainerStart => "RUNNING",
                    EventType::ContainerStop | EventType::ContainerDestroy => "STOPPED",
                    _ => "UNKNOWN",
                };
                seen.insert(
                    key.clone(),
                    ContainerSummary {
                        container_id: key,
                        host_id: event.host_id.to_string(),
                        hostname: event.host.hostname.clone(),
                        image: container.image.clone(),
                        status: status.to_string(),
                        timestamp: event.timestamp,
                    },
                );
            }
        }
    }
    Ok(Json(seen.into_values().collect()))
}
```

- [ ] **Step 4: Register the route**

In `build_router`, add right before `.route("/api/v1/containers/story", get(container_story_handler))`:

```rust
.route("/api/v1/containers", get(containers_handler))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-api containers_endpoint -- --nocapture`
Expected: PASS, 3 tests.

- [ ] **Step 6: Run the full backend suite**

Run: `cargo test --workspace`
Expected: all tests PASS (confirms the 3 new routes don't collide and every existing handler is unaffected).

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): add GET /api/v1/containers list endpoint"
```

---

### Task 4: Console data layer — types, client, hooks for all three resources

**Files:**
- Modify: `console/src/api/types.ts`
- Modify: `console/src/api/client.ts`
- Modify: `console/src/api/hooks.ts`
- Test: `console/src/api/client.test.ts`
- Test: `console/src/api/hooks.test.tsx`

**Interfaces:**
- Consumes: `Story` (existing type), `apiGet` (existing helper in `client.ts`), `useQuery` (existing import in `hooks.ts`).
- Produces: types `FileSummary`, `NetworkSummary`, `ContainerSummary`; client fns `fetchFiles(): Promise<FileSummary[]>`, `fetchNetwork(): Promise<NetworkSummary[]>`, `fetchContainers(): Promise<ContainerSummary[]>`, `fetchFileStory(fileId: string): Promise<Story>`, `fetchNetworkStory(ip: string): Promise<Story>`, `fetchContainerStory(containerId: string): Promise<Story>`; hooks `useFiles()`, `useNetwork()`, `useContainers()`, `useFileStory(fileId: string)`, `useNetworkStory(ip: string)`, `useContainerStory(containerId: string)`. Tasks 5–7 (screens) consume all of these.

- [ ] **Step 1: Add the three summary types**

In `console/src/api/types.ts`, add after `ProcessDetail` (before the `AlertSeverity` block):

```ts
export interface FileSummary {
  file_id: string;
  path: string;
  host_id: string;
  hostname: string;
  last_event_type: string;
  timestamp: number;
}

export interface NetworkSummary {
  host_id: string;
  hostname: string;
  dst_ip: string;
  dst_port: number;
  proto: string;
  last_event_type: string;
  timestamp: number;
}

export interface ContainerSummary {
  container_id: string;
  host_id: string;
  hostname: string;
  image: string;
  status: "RUNNING" | "STOPPED";
  timestamp: number;
}
```

- [ ] **Step 2: Write the failing client tests**

In `console/src/api/client.test.ts`, add (following the existing `vi.stubGlobal("fetch", vi.fn())` pattern already in that file's `beforeEach`):

```ts
it("fetchFiles calls /api/v1/files", async () => {
  vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
  await fetchFiles();
  expect(fetch).toHaveBeenCalledWith("/api/v1/files");
});

it("fetchNetwork calls /api/v1/network", async () => {
  vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
  await fetchNetwork();
  expect(fetch).toHaveBeenCalledWith("/api/v1/network");
});

it("fetchContainers calls /api/v1/containers", async () => {
  vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
  await fetchContainers();
  expect(fetch).toHaveBeenCalledWith("/api/v1/containers");
});

it("fetchFileStory calls /api/v1/files/story with an encoded file_id", async () => {
  vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));
  await fetchFileStory("1:100");
  expect(fetch).toHaveBeenCalledWith("/api/v1/files/story?file_id=1%3A100");
});

it("fetchNetworkStory calls /api/v1/network/story with the ip", async () => {
  vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));
  await fetchNetworkStory("93.184.216.34");
  expect(fetch).toHaveBeenCalledWith("/api/v1/network/story?ip=93.184.216.34");
});

it("fetchContainerStory calls /api/v1/containers/story with the container_id", async () => {
  vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));
  await fetchContainerStory("abc123");
  expect(fetch).toHaveBeenCalledWith("/api/v1/containers/story?container_id=abc123");
});
```

Add the new imports to that file's existing `import { ... } from "./client"` line.

- [ ] **Step 2b: Run tests to verify they fail**

Run: `cd console && npx vitest run src/api/client.test.ts`
Expected: FAIL — `fetchFiles` etc. are not exported.

- [ ] **Step 3: Implement the client functions**

In `console/src/api/client.ts`, add `FileSummary`, `NetworkSummary`, `ContainerSummary` to the `import type { ... } from "./types"` block, then add after `fetchProcessStory`:

```ts
export function fetchFiles(): Promise<FileSummary[]> {
  return apiGet<FileSummary[]>("/files");
}

export function fetchNetwork(): Promise<NetworkSummary[]> {
  return apiGet<NetworkSummary[]>("/network");
}

export function fetchContainers(): Promise<ContainerSummary[]> {
  return apiGet<ContainerSummary[]>("/containers");
}

export function fetchFileStory(fileId: string): Promise<Story> {
  return apiGet<Story>(`/files/story?file_id=${encodeURIComponent(fileId)}`);
}

export function fetchNetworkStory(ip: string): Promise<Story> {
  return apiGet<Story>(`/network/story?ip=${encodeURIComponent(ip)}`);
}

export function fetchContainerStory(containerId: string): Promise<Story> {
  return apiGet<Story>(`/containers/story?container_id=${encodeURIComponent(containerId)}`);
}
```

- [ ] **Step 4: Run client tests to verify they pass**

Run: `cd console && npx vitest run src/api/client.test.ts`
Expected: PASS.

- [ ] **Step 5: Write the failing hook tests**

In `console/src/api/hooks.test.tsx`, add (following the existing `vi.spyOn(client, "fetchXxx")` + `renderHook` pattern):

```tsx
it("useFiles resolves with fetchFiles's result", async () => {
  vi.spyOn(client, "fetchFiles").mockResolvedValue([
    { file_id: "1:100", path: "/etc/passwd", host_id: "h1", hostname: "host-a", last_event_type: "FILE_WRITE", timestamp: 1000 },
  ]);
  const { result } = renderHook(() => useFiles(), { wrapper });
  await waitFor(() => expect(result.current.isSuccess).toBe(true));
  expect(result.current.data).toHaveLength(1);
});

it("useNetwork resolves with fetchNetwork's result", async () => {
  vi.spyOn(client, "fetchNetwork").mockResolvedValue([
    { host_id: "h1", hostname: "host-a", dst_ip: "93.184.216.34", dst_port: 443, proto: "tcp", last_event_type: "NETWORK_CLOSE", timestamp: 1000 },
  ]);
  const { result } = renderHook(() => useNetwork(), { wrapper });
  await waitFor(() => expect(result.current.isSuccess).toBe(true));
  expect(result.current.data).toHaveLength(1);
});

it("useContainers resolves with fetchContainers's result", async () => {
  vi.spyOn(client, "fetchContainers").mockResolvedValue([
    { container_id: "abc", host_id: "h1", hostname: "host-a", image: "nginx", status: "RUNNING", timestamp: 1000 },
  ]);
  const { result } = renderHook(() => useContainers(), { wrapper });
  await waitFor(() => expect(result.current.isSuccess).toBe(true));
  expect(result.current.data).toHaveLength(1);
});

it("useFileStory is disabled until a non-empty fileId is given", () => {
  const spy = vi.spyOn(client, "fetchFileStory");
  const { result } = renderHook(() => useFileStory(""), { wrapper });
  expect(result.current.fetchStatus).toBe("idle");
  expect(spy).not.toHaveBeenCalled();
});

it("useNetworkStory resolves with fetchNetworkStory's result", async () => {
  vi.spyOn(client, "fetchNetworkStory").mockResolvedValue({ events: [], alerts: [] });
  const { result } = renderHook(() => useNetworkStory("93.184.216.34"), { wrapper });
  await waitFor(() => expect(result.current.isSuccess).toBe(true));
  expect(result.current.data).toEqual({ events: [], alerts: [] });
});

it("useContainerStory resolves with fetchContainerStory's result", async () => {
  vi.spyOn(client, "fetchContainerStory").mockResolvedValue({ events: [], alerts: [] });
  const { result } = renderHook(() => useContainerStory("abc"), { wrapper });
  await waitFor(() => expect(result.current.isSuccess).toBe(true));
  expect(result.current.data).toEqual({ events: [], alerts: [] });
});
```

Add the new hook names to that file's existing `import { ... } from "./hooks"` line.

- [ ] **Step 5b: Run tests to verify they fail**

Run: `cd console && npx vitest run src/api/hooks.test.tsx`
Expected: FAIL — `useFiles` etc. are not exported.

- [ ] **Step 6: Implement the hooks**

In `console/src/api/hooks.ts`, add the six new fetch functions to the existing `import { ... } from "./client"` block, then add after `useProcessStory`:

```ts
export function useFiles() {
  return useQuery({
    queryKey: ["files"],
    queryFn: fetchFiles,
  });
}

export function useNetwork() {
  return useQuery({
    queryKey: ["network"],
    queryFn: fetchNetwork,
  });
}

export function useContainers() {
  return useQuery({
    queryKey: ["containers"],
    queryFn: fetchContainers,
  });
}

export function useFileStory(fileId: string) {
  return useQuery({
    queryKey: ["file-story", fileId],
    queryFn: () => fetchFileStory(fileId),
    enabled: fileId.length > 0,
  });
}

export function useNetworkStory(ip: string) {
  return useQuery({
    queryKey: ["network-story", ip],
    queryFn: () => fetchNetworkStory(ip),
    enabled: ip.length > 0,
  });
}

export function useContainerStory(containerId: string) {
  return useQuery({
    queryKey: ["container-story", containerId],
    queryFn: () => fetchContainerStory(containerId),
    enabled: containerId.length > 0,
  });
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd console && npx vitest run src/api/client.test.ts src/api/hooks.test.tsx`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add console/src/api/types.ts console/src/api/client.ts console/src/api/hooks.ts console/src/api/client.test.ts console/src/api/hooks.test.tsx
git commit -m "feat(console): add data layer for Files, Network, Containers"
```

---

### Task 5: Console — Filesystem List + Detail screens

**Files:**
- Create: `console/src/screens/files/FileList.tsx`
- Create: `console/src/screens/files/FileList.test.tsx`
- Create: `console/src/screens/files/FileDetailScreen.tsx`
- Create: `console/src/screens/files/FileDetailScreen.test.tsx`

**Interfaces:**
- Consumes: `useFiles`, `useFileStory` (Task 4), `useUiStore` (existing, `console/src/store/uiStore.ts`).
- Produces: `FileList`, `FileDetailScreen` React components, consumed by Task 8's `App.tsx` wiring.

- [ ] **Step 1: Write the failing FileList test**

Create `console/src/screens/files/FileList.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { FileList } from "./FileList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useFiles>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <FileList />
    </MemoryRouter>
  );
}

describe("FileList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading files…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No files found.")).toBeInTheDocument();
  });

  it("renders a row per file, linking to its detail route with host_id in the query string", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(
      mockQueryResult({
        data: [
          { file_id: "1:100", path: "/etc/passwd", host_id: "h1", hostname: "host-a", last_event_type: "FILE_WRITE", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "/etc/passwd" });
    expect(link).toHaveAttribute("href", "/files/1:100?host_id=h1");
    expect(screen.getByText("host-a")).toBeInTheDocument();
    expect(screen.getByText("FILE_WRITE")).toBeInTheDocument();
  });

  it("filters rows by path text", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(
      mockQueryResult({
        data: [
          { file_id: "1:100", path: "/etc/passwd", host_id: "h1", hostname: "host-a", last_event_type: "FILE_WRITE", timestamp: 1000 },
          { file_id: "1:200", path: "/tmp/x", host_id: "h1", hostname: "host-a", last_event_type: "FILE_CREATE", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by path"), { target: { value: "passwd" } });

    expect(screen.getByText("/etc/passwd")).toBeInTheDocument();
    expect(screen.queryByText("/tmp/x")).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd console && npx vitest run src/screens/files/FileList.test.tsx`
Expected: FAIL — module `./FileList` does not exist.

- [ ] **Step 3: Implement FileList**

Create `console/src/screens/files/FileList.tsx`:

```tsx
import { useState } from "react";
import { Link } from "react-router-dom";
import { useFiles } from "../../api/hooks";

export function FileList() {
  // GET /api/v1/files (files_handler in crates/osiris-api/src/lib.rs) dedups
  // by (host_id, FileIdentity) over a bounded 10_000-event query window,
  // unordered by recency (query_events has no ORDER BY timestamp guarantee)
  // — on a very high-volume host, a file whose events fall outside that
  // window could be missing even if it's still active. Same posture
  // ProcessList.tsx's own comment takes for /processes; not fixed here.
  const files = useFiles();
  const [filter, setFilter] = useState("");

  const rows = (files.data ?? []).filter((file) =>
    file.path.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <h1>Filesystem</h1>
      <input
        type="text"
        placeholder="Filter by path"
        aria-label="Filter by path"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {files.isLoading && <p>Loading files…</p>}
      {files.isError && <p role="alert">Failed to load files: {(files.error as Error).message}</p>}
      {!files.isLoading && !files.isError && rows.length === 0 && <p>No files found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Path</th>
              <th>Host</th>
              <th>Last event</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((file) => (
              <tr key={file.file_id}>
                <td>
                  <Link to={`/files/${file.file_id}?host_id=${file.host_id}`}>{file.path}</Link>
                </td>
                <td>{file.hostname}</td>
                <td>{file.last_event_type}</td>
                <td>{file.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd console && npx vitest run src/screens/files/FileList.test.tsx`
Expected: PASS.

- [ ] **Step 5: Write the failing FileDetailScreen test**

Create `console/src/screens/files/FileDetailScreen.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { FileDetailScreen } from "./FileDetailScreen";

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

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/files/:fileId" element={<FileDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("FileDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("shows a loading state", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100?host_id=h1");
    expect(screen.getByText("Loading story…")).toBeInTheDocument();
  });

  it("renders the story's alerts and events once loaded", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
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
      }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100?host_id=h1");

    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("shows the Entity Graph pivot link and writes the composed FILE key when host_id is present", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100?host_id=h1");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");
    expect(useUiStore.getState().selectedEntity).toBe("FILE:h1:100:1");

    link.click();
    expect(useUiStore.getState().selectedEntity).toBe("FILE:h1:100:1");
  });

  it("omits the Entity Graph pivot link when host_id is absent", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100");

    expect(screen.queryByRole("link", { name: "View in Entity Graph" })).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd console && npx vitest run src/screens/files/FileDetailScreen.test.tsx`
Expected: FAIL — module `./FileDetailScreen` does not exist.

- [ ] **Step 7: Implement FileDetailScreen**

Create `console/src/screens/files/FileDetailScreen.tsx`:

```tsx
import { useEffect } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useFileStory } from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";

export function FileDetailScreen() {
  const { fileId = "" } = useParams<{ fileId: string }>();
  const [searchParams] = useSearchParams();
  const hostId = searchParams.get("host_id");
  const story = useFileStory(fileId);
  const selectEntity = useUiStore((state) => state.selectEntity);

  // FileIdentity::as_key() (crates/osiris-schema/src/file_identity.rs)
  // formats fileId as "<device_id>:<inode>" — device_id first. But
  // EntityRef::File::storage_key() (crates/osiris-schema/src/relationships.rs)
  // formats as "FILE:<host_id>:<inode>:<device_id>" — inode first. The two
  // orders differ, so the split parts must be swapped when composing the key.
  const [deviceId, inode] = fileId.split(":");
  const entityKey = hostId && deviceId && inode ? `FILE:${hostId}:${inode}:${deviceId}` : null;

  useEffect(() => {
    if (!entityKey) {
      return undefined;
    }
    selectEntity(entityKey);
    return () => selectEntity(null);
  }, [entityKey, selectEntity]);

  return (
    <div>
      <h1>File {fileId}</h1>
      {entityKey && (
        <Link to="/graph" onClick={() => selectEntity(entityKey)}>
          View in Entity Graph
        </Link>
      )}
      {story.isLoading && <p>Loading story…</p>}
      {story.isError && <p role="alert">Failed to load story: {(story.error as Error).message}</p>}
      {story.data && (
        <section aria-label="file story">
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

- [ ] **Step 8: Run test to verify it passes**

Run: `cd console && npx vitest run src/screens/files/FileDetailScreen.test.tsx`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add console/src/screens/files
git commit -m "feat(console): add Filesystem List and Detail screens"
```

---

### Task 6: Console — Network List + Detail screens

**Files:**
- Create: `console/src/screens/network/NetworkList.tsx`
- Create: `console/src/screens/network/NetworkList.test.tsx`
- Create: `console/src/screens/network/NetworkDetailScreen.tsx`
- Create: `console/src/screens/network/NetworkDetailScreen.test.tsx`

**Interfaces:**
- Consumes: `useNetwork`, `useNetworkStory` (Task 4), `useUiStore` (existing).
- Produces: `NetworkList`, `NetworkDetailScreen`, consumed by Task 8.

- [ ] **Step 1: Write the failing NetworkList test**

Create `console/src/screens/network/NetworkList.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { NetworkList } from "./NetworkList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useNetwork>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <NetworkList />
    </MemoryRouter>
  );
}

describe("NetworkList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading network connections…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No network connections found.")).toBeInTheDocument();
  });

  it("renders a row per destination, linking to its detail route", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "h1", hostname: "host-a", dst_ip: "93.184.216.34", dst_port: 443, proto: "tcp", last_event_type: "NETWORK_CLOSE", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "93.184.216.34:443" });
    expect(link).toHaveAttribute("href", "/network/93.184.216.34");
    expect(screen.getByText("tcp")).toBeInTheDocument();
    expect(screen.getByText("host-a")).toBeInTheDocument();
  });

  it("filters rows by destination text", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "h1", hostname: "host-a", dst_ip: "93.184.216.34", dst_port: 443, proto: "tcp", last_event_type: "NETWORK_CLOSE", timestamp: 1000 },
          { host_id: "h1", hostname: "host-a", dst_ip: "10.0.0.9", dst_port: 22, proto: "tcp", last_event_type: "NETWORK_CONNECT", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by destination"), { target: { value: "93.184" } });

    expect(screen.getByText("93.184.216.34:443")).toBeInTheDocument();
    expect(screen.queryByText("10.0.0.9:22")).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd console && npx vitest run src/screens/network/NetworkList.test.tsx`
Expected: FAIL — module `./NetworkList` does not exist.

- [ ] **Step 3: Implement NetworkList**

Create `console/src/screens/network/NetworkList.tsx`:

```tsx
import { useState } from "react";
import { Link } from "react-router-dom";
import { useNetwork } from "../../api/hooks";

export function NetworkList() {
  // GET /api/v1/network (network_handler in crates/osiris-api/src/lib.rs)
  // dedups by (host_id, dst_ip, dst_port, proto) over a bounded
  // 10_000-event query window, unordered by recency (query_events has no
  // ORDER BY timestamp guarantee) — on a very high-volume host, a
  // destination whose events fall outside that window could be missing
  // even if still active. Same posture ProcessList.tsx's own comment
  // takes for /processes; not fixed here.
  const network = useNetwork();
  const [filter, setFilter] = useState("");

  const rows = (network.data ?? []).filter((row) =>
    `${row.dst_ip}:${row.dst_port}`.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <h1>Network</h1>
      <input
        type="text"
        placeholder="Filter by destination"
        aria-label="Filter by destination"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {network.isLoading && <p>Loading network connections…</p>}
      {network.isError && (
        <p role="alert">Failed to load network connections: {(network.error as Error).message}</p>
      )}
      {!network.isLoading && !network.isError && rows.length === 0 && <p>No network connections found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Destination</th>
              <th>Proto</th>
              <th>Host</th>
              <th>Last event</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.host_id}:${row.dst_ip}:${row.dst_port}:${row.proto}`}>
                <td>
                  <Link to={`/network/${row.dst_ip}`}>{`${row.dst_ip}:${row.dst_port}`}</Link>
                </td>
                <td>{row.proto}</td>
                <td>{row.hostname}</td>
                <td>{row.last_event_type}</td>
                <td>{row.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd console && npx vitest run src/screens/network/NetworkList.test.tsx`
Expected: PASS.

- [ ] **Step 5: Write the failing NetworkDetailScreen test**

Create `console/src/screens/network/NetworkDetailScreen.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { NetworkDetailScreen } from "./NetworkDetailScreen";

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

function renderAt(ip: string) {
  return render(
    <MemoryRouter initialEntries={[`/network/${ip}`]}>
      <Routes>
        <Route path="/network/:ip" element={<NetworkDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("NetworkDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("writes the IP key to uiStore.selectedEntity on mount and clears it on unmount", () => {
    vi.mocked(hooks.useNetworkStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useNetworkStory>
    );
    const { unmount } = renderAt("93.184.216.34");

    expect(useUiStore.getState().selectedEntity).toBe("IP:93.184.216.34");

    unmount();
    expect(useUiStore.getState().selectedEntity).toBeNull();
  });

  it("renders the story's alerts and events once loaded", () => {
    vi.mocked(hooks.useNetworkStory).mockReturnValue(
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
      }) as ReturnType<typeof hooks.useNetworkStory>
    );
    renderAt("93.184.216.34");

    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("explicitly writes the IP key when the pivot link is clicked", () => {
    vi.mocked(hooks.useNetworkStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useNetworkStory>
    );
    renderAt("93.184.216.34");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");

    link.click();
    expect(useUiStore.getState().selectedEntity).toBe("IP:93.184.216.34");
  });
});
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd console && npx vitest run src/screens/network/NetworkDetailScreen.test.tsx`
Expected: FAIL — module `./NetworkDetailScreen` does not exist.

- [ ] **Step 7: Implement NetworkDetailScreen**

Create `console/src/screens/network/NetworkDetailScreen.tsx`:

```tsx
import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { useNetworkStory } from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";

export function NetworkDetailScreen() {
  const { ip = "" } = useParams<{ ip: string }>();
  const story = useNetworkStory(ip);
  const selectEntity = useUiStore((state) => state.selectEntity);

  useEffect(() => {
    selectEntity(`IP:${ip}`);
    return () => selectEntity(null);
  }, [ip, selectEntity]);

  return (
    <div>
      <h1>Network {ip}</h1>
      <Link to="/graph" onClick={() => selectEntity(`IP:${ip}`)}>
        View in Entity Graph
      </Link>
      {story.isLoading && <p>Loading story…</p>}
      {story.isError && <p role="alert">Failed to load story: {(story.error as Error).message}</p>}
      {story.data && (
        <section aria-label="network story">
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

- [ ] **Step 8: Run test to verify it passes**

Run: `cd console && npx vitest run src/screens/network/NetworkDetailScreen.test.tsx`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add console/src/screens/network
git commit -m "feat(console): add Network List and Detail screens"
```

---

### Task 7: Console — Containers List + Detail screens

**Files:**
- Create: `console/src/screens/containers/ContainerList.tsx`
- Create: `console/src/screens/containers/ContainerList.test.tsx`
- Create: `console/src/screens/containers/ContainerDetailScreen.tsx`
- Create: `console/src/screens/containers/ContainerDetailScreen.test.tsx`

**Interfaces:**
- Consumes: `useContainers`, `useContainerStory` (Task 4), `useUiStore` (existing).
- Produces: `ContainerList`, `ContainerDetailScreen`, consumed by Task 8.

- [ ] **Step 1: Write the failing ContainerList test**

Create `console/src/screens/containers/ContainerList.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ContainerList } from "./ContainerList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useContainers>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <ContainerList />
    </MemoryRouter>
  );
}

describe("ContainerList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading containers…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No containers found.")).toBeInTheDocument();
  });

  it("renders a row per container, linking to its detail route", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(
      mockQueryResult({
        data: [{ container_id: "abc123", host_id: "h1", hostname: "host-a", image: "nginx:latest", status: "RUNNING", timestamp: 1000 }],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "abc123" });
    expect(link).toHaveAttribute("href", "/containers/abc123");
    expect(screen.getByText("nginx:latest")).toBeInTheDocument();
    expect(screen.getByText("RUNNING")).toBeInTheDocument();
  });

  it("filters rows by image or container_id text", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(
      mockQueryResult({
        data: [
          { container_id: "abc123", host_id: "h1", hostname: "host-a", image: "nginx:latest", status: "RUNNING", timestamp: 1000 },
          { container_id: "def456", host_id: "h1", hostname: "host-a", image: "redis:7", status: "STOPPED", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by image or container ID"), { target: { value: "nginx" } });

    expect(screen.getByText("abc123")).toBeInTheDocument();
    expect(screen.queryByText("def456")).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd console && npx vitest run src/screens/containers/ContainerList.test.tsx`
Expected: FAIL — module `./ContainerList` does not exist.

- [ ] **Step 3: Implement ContainerList**

Create `console/src/screens/containers/ContainerList.tsx`:

```tsx
import { useState } from "react";
import { Link } from "react-router-dom";
import { useContainers } from "../../api/hooks";

export function ContainerList() {
  // GET /api/v1/containers (containers_handler in
  // crates/osiris-api/src/lib.rs) dedups by container_id alone over a
  // bounded 10_000-event query window, unordered by recency (query_events
  // has no ORDER BY timestamp guarantee) — on a very high-volume host, a
  // container whose events fall outside that window could be missing even
  // if still active. Same posture ProcessList.tsx's own comment takes for
  // /processes; not fixed here.
  const containers = useContainers();
  const [filter, setFilter] = useState("");

  const rows = (containers.data ?? []).filter((row) => {
    const needle = filter.toLowerCase();
    return row.image.toLowerCase().includes(needle) || row.container_id.toLowerCase().includes(needle);
  });

  return (
    <div>
      <h1>Containers</h1>
      <input
        type="text"
        placeholder="Filter by image or container ID"
        aria-label="Filter by image or container ID"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {containers.isLoading && <p>Loading containers…</p>}
      {containers.isError && (
        <p role="alert">Failed to load containers: {(containers.error as Error).message}</p>
      )}
      {!containers.isLoading && !containers.isError && rows.length === 0 && <p>No containers found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Container ID</th>
              <th>Image</th>
              <th>Host</th>
              <th>Status</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.container_id}>
                <td>
                  <Link to={`/containers/${row.container_id}`}>{row.container_id}</Link>
                </td>
                <td>{row.image}</td>
                <td>{row.hostname}</td>
                <td>{row.status}</td>
                <td>{row.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd console && npx vitest run src/screens/containers/ContainerList.test.tsx`
Expected: PASS.

- [ ] **Step 5: Write the failing ContainerDetailScreen test**

Create `console/src/screens/containers/ContainerDetailScreen.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { ContainerDetailScreen } from "./ContainerDetailScreen";

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

function renderAt(containerId: string) {
  return render(
    <MemoryRouter initialEntries={[`/containers/${containerId}`]}>
      <Routes>
        <Route path="/containers/:containerId" element={<ContainerDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ContainerDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("writes the CONTAINER key to uiStore.selectedEntity on mount and clears it on unmount", () => {
    vi.mocked(hooks.useContainerStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useContainerStory>
    );
    const { unmount } = renderAt("abc123");

    expect(useUiStore.getState().selectedEntity).toBe("CONTAINER:abc123");

    unmount();
    expect(useUiStore.getState().selectedEntity).toBeNull();
  });

  it("renders the story's alerts and events once loaded", () => {
    vi.mocked(hooks.useContainerStory).mockReturnValue(
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
      }) as ReturnType<typeof hooks.useContainerStory>
    );
    renderAt("abc123");

    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("explicitly writes the CONTAINER key when the pivot link is clicked", () => {
    vi.mocked(hooks.useContainerStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useContainerStory>
    );
    renderAt("abc123");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");

    link.click();
    expect(useUiStore.getState().selectedEntity).toBe("CONTAINER:abc123");
  });
});
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd console && npx vitest run src/screens/containers/ContainerDetailScreen.test.tsx`
Expected: FAIL — module `./ContainerDetailScreen` does not exist.

- [ ] **Step 7: Implement ContainerDetailScreen**

Create `console/src/screens/containers/ContainerDetailScreen.tsx`:

```tsx
import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { useContainerStory } from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";

export function ContainerDetailScreen() {
  const { containerId = "" } = useParams<{ containerId: string }>();
  const story = useContainerStory(containerId);
  const selectEntity = useUiStore((state) => state.selectEntity);

  useEffect(() => {
    selectEntity(`CONTAINER:${containerId}`);
    return () => selectEntity(null);
  }, [containerId, selectEntity]);

  return (
    <div>
      <h1>Container {containerId}</h1>
      <Link to="/graph" onClick={() => selectEntity(`CONTAINER:${containerId}`)}>
        View in Entity Graph
      </Link>
      {story.isLoading && <p>Loading story…</p>}
      {story.isError && <p role="alert">Failed to load story: {(story.error as Error).message}</p>}
      {story.data && (
        <section aria-label="container story">
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

- [ ] **Step 8: Run test to verify it passes**

Run: `cd console && npx vitest run src/screens/containers/ContainerDetailScreen.test.tsx`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add console/src/screens/containers
git commit -m "feat(console): add Containers List and Detail screens"
```

---

### Task 8: Wire up routes and navigation, run full suites, manual e2e smoke verification

**Files:**
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`

**Interfaces:**
- Consumes: `FileList`/`FileDetailScreen` (Task 5), `NetworkList`/`NetworkDetailScreen` (Task 6), `ContainerList`/`ContainerDetailScreen` (Task 7).

- [ ] **Step 1: Update imports and routes in `App.tsx`**

In `console/src/App.tsx`, replace the three `ComingSoon` imports/usages. Remove `import { ComingSoon } from "./screens/ComingSoon";` only if nothing else in the file still uses it (grep the file first — `ComingSoon` is a generic placeholder that may still be imported for other unrelated disabled routes; if so, keep the import and only remove the three routes below).

Add these imports (alongside the existing screen imports, alphabetically):

```tsx
import { ContainerDetailScreen } from "./screens/containers/ContainerDetailScreen";
import { ContainerList } from "./screens/containers/ContainerList";
import { FileDetailScreen } from "./screens/files/FileDetailScreen";
import { FileList } from "./screens/files/FileList";
import { NetworkDetailScreen } from "./screens/network/NetworkDetailScreen";
import { NetworkList } from "./screens/network/NetworkList";
```

Replace:

```tsx
<Route path="/files" element={<ComingSoon label="Filesystem" />} />
<Route path="/network" element={<ComingSoon label="Network" />} />
<Route path="/containers" element={<ComingSoon label="Containers" />} />
```

with:

```tsx
<Route path="/files" element={<FileList />} />
<Route path="/files/:fileId" element={<FileDetailScreen />} />
<Route path="/network" element={<NetworkList />} />
<Route path="/network/:ip" element={<NetworkDetailScreen />} />
<Route path="/containers" element={<ContainerList />} />
<Route path="/containers/:containerId" element={<ContainerDetailScreen />} />
```

- [ ] **Step 2: Enable the nav items**

In `console/src/app/navItems.ts`, change:

```ts
{ label: "Filesystem", path: "/files", enabled: false },
{ label: "Network", path: "/network", enabled: false },
{ label: "Containers", path: "/containers", enabled: false },
```

to:

```ts
{ label: "Filesystem", path: "/files", enabled: true },
{ label: "Network", path: "/network", enabled: true },
{ label: "Containers", path: "/containers", enabled: true },
```

- [ ] **Step 3: Run the full console suite**

Run: `cd console && npx vitest run`
Expected: all tests PASS, including every test written in Tasks 4–7.

- [ ] **Step 4: Run the full backend suite**

Run: `cargo test --workspace`
Expected: all tests PASS.

- [ ] **Step 5: Manual e2e smoke verification**

Start the backend (`cargo run -p osiris-server`, or the project's existing dev-run command) and the console dev server (`cd console && npm run dev`), then in a browser:
1. Confirm "Filesystem", "Network", "Containers" now appear as enabled nav links (not disabled placeholders).
2. Visit `/files`: confirm the list loads without a console error (empty state is fine if no FILE-category events exist in the dev database).
3. Visit `/network` and `/containers`: same check.
4. If any FILE/NETWORK/CONTAINER events exist in the dev database (seed one via the existing e2e test harness or a synthetic event if needed), click through a row to its Detail screen, confirm the story section renders, and confirm "View in Entity Graph" navigates to `/graph` with the entity pre-selected (for Files, only when the row's `host_id` was present, per Task 5's `?host_id=` query param).

- [ ] **Step 6: Commit**

```bash
git add console/src/App.tsx console/src/app/navItems.ts
git commit -m "feat(console): wire up Filesystem, Network, Containers screens and enable nav"
```

---

## Self-Review Notes

- **Spec coverage:** every spec section has a task — backend endpoints (Tasks 1–3), identity/dedup rules (Tasks 1–3), data layer (Task 4), List/Detail screens per resource (Tasks 5–7), routing/nav (Task 8), manual e2e (Task 8 Step 5). The bounded-window caveat is carried into every new List screen's comment (Tasks 5–7). Out-of-scope items (pagination, storage-side rollup, retrofitting `/processes`) are intentionally not tasked, matching the spec's own "Out of scope" section.
- **Type consistency:** `FileSummary`/`NetworkSummary`/`ContainerSummary` field names and types are identical across the Rust struct (Tasks 1–3), the TypeScript interface (Task 4), and every screen's usage (Tasks 5–7) — verified field-by-field against the spec's own struct definitions.
- **No placeholders:** every step has full, runnable code — no "similar to Task N" shortcuts (each screen's near-identical code is written out in full since Tasks 5–7's implementers only see their own task).
