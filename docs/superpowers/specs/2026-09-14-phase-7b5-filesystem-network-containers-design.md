# Phase 7b-5: Filesystem, Network, Containers List/Detail Screens — Design Spec

## Context

`ARCHITECTURE.md` §16.3's Screen↔API mapping table has named `/files`, `/network`, and `/containers` list endpoints since it was written, but none of the three exist — only the scoped `*_story` lookups (`/files/story`, `/network/story`, `/containers/story`) do, each requiring a caller to already know a specific path/file_id, ip/domain, or container_id. Console screens for Filesystem/Network/Containers have sat behind disabled `ComingSoon` nav placeholders since Phase 7b-1. Phase 7b-3's brainstorming deliberately deferred designing these, noting the backend list-endpoint shape was still an open question. This spec answers that question and covers all three resources in one phase, since they share the same open question and are each roughly `/processes`-sized.

## The list-endpoint design question, resolved

`/processes` (`processes_handler`, `crates/osiris-api/src/lib.rs`) is the only existing "list" precedent: a bounded `query`/`query_events` fetch followed by Rust-side dedup keyed by identity (`process_key`), keeping the **first**-seen event per key. No dedicated storage-side grouping/distinct method exists anywhere in the `Storage` trait — `/processes`'s own rollup is entirely an API-handler concern, undocumented in `ARCHITECTURE.md`.

This phase builds three new endpoints (`GET /api/v1/files`, `/network`, `/containers`) following that same pattern — bounded query + Rust-side dedup in the API handler, no new `Storage` trait methods — with two deliberate departures from `/processes`'s exact precedent, both decided during brainstorming:

1. **Most-recent event per identity, not first-seen.** A file's row should reflect its latest known state (most recent write), not merely when it was first noticed — more useful for an analyst, and lets Containers derive a lifecycle status from the kept event.
2. **`category`-based OQL filtering, not enumerating event types.** `osiris_query`'s `KNOWN_FIELDS` already includes `category`, and `Category::File`/`Category::Network`/`Category::Container` already exist — a single `category = "FILE"` (etc.) filter via `EventQueryPlan` covers every relevant event type without hand-listing 4-10 `EventType` variants per resource. This is a small, unforced improvement over `/processes`'s own event-type-only filtering, not a requirement `/processes` itself needs retrofitted.

**Known inherited limitation** (explicitly not solved this phase, matching `/processes`'s own documented limitation in `ProcessList.tsx`'s existing comment): dedup happens over a *bounded* event window (`limit: 10_000`, `export: true`, unordered by recency — `query_events` has no `ORDER BY timestamp` guarantee), so on a very high-volume host, an identity whose events fall outside that window could be missing from the list even if it's still active. Fixing this would need a `since`/pagination parameter or a storage-side rollup query — out of scope here, same posture `ProcessList.tsx`'s own comment already takes for `/processes`.

## Identity per resource

- **Files**: `FileIdentity { inode, device_id }` (`crates/osiris-schema/src/file_identity.rs`) — already exists, built via `FileIdentity::from_file_ref(&file_ref)` (`None` when either half is missing, e.g. an audit `PATH` record with `nametype=UNKNOWN`; such events are skipped, matching the type's existing semantics). Dedup key for the **list** is `(host_id, FileIdentity)` — per-host, since two different hosts' matching inode/device numbers are unrelated files. `FileIdentity::as_key()` (`"<device_id>:<inode>"`) is the exact string `GET /files/story?file_id=` already parses — no new key format needed.
- **Network**: no existing identity type. New dedup key, decided during brainstorming: `(host_id, dst_ip, dst_port, proto)` — destination-only, deliberately excluding `src_ip`/`src_port` (source port is normally ephemeral; including it would make nearly every connection look "new," defeating the point of a rolled-up inventory). No new schema type is introduced for this — it's a plain tuple comparison inside the one handler that needs it. Clicking through to Network Detail passes the plain `dst_ip` value directly to the existing `GET /network/story?ip=` (already unions `src_ip OR dst_ip` matches — confirmed in `crates/osiris-investigate/src/network_story.rs`'s `network_addr_plan`), so no composed key is needed for navigation either.
- **Containers**: `container_id` (a plain string on `ContainerRef`) — already the exact identity `GET /containers/story?container_id=` expects. Dedup key is `container_id` alone, **not** host-scoped — this matches `container_story_handler`'s own existing host-agnostic behavior (it has no `host_id` parameter at all), so the list and its detail lookup stay consistent with each other rather than introducing a new host-scoping the story endpoint doesn't share.

## Backend

Three independent additions to `crates/osiris-api/src/lib.rs`, each its own route + response type + handler — no shared abstraction extracted, matching this file's existing per-endpoint style (`processes_handler`, `container_story_handler`, etc. don't share a base either).

### `GET /api/v1/files`

```rust
#[derive(Debug, Serialize)]
struct FileSummary {
    file_id: String,      // FileIdentity::as_key()
    path: String,
    host_id: String,
    hostname: String,
    last_event_type: String,
    timestamp: u64,
}
```
Query: `Ast::Compare{field:"category", op:Eq, value:Str("FILE")}`, `limit: 10_000`, `export: true` (matching `network_addr_plan`'s existing precedent for "give me everything reasonably"). Dedup: group by `(event.host_id, FileIdentity::from_file_ref(&file_ref))`, skipping events where the identity is `None`; within each group keep the event with the highest `timestamp`. `path`/`last_event_type`/`timestamp` come from that kept event.

### `GET /api/v1/network`

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
```
Query: `category = "NETWORK"`, same bounds. Dedup: group by `(event.host_id, network.dst_ip, network.dst_port, network.proto)`, keep highest-`timestamp` event per group.

### `GET /api/v1/containers`

```rust
#[derive(Debug, Serialize)]
struct ContainerSummary {
    container_id: String,
    host_id: String,
    hostname: String,
    image: String,
    status: String,   // "RUNNING" | "STOPPED"
    timestamp: u64,
}
```
Query: `category = "CONTAINER"`, same bounds. Dedup: group by `container.container_id` alone, keep highest-`timestamp` event per group. `status` is derived from that kept event's `event_type`: `CONTAINER_CREATE`/`CONTAINER_START` → `"RUNNING"`; `CONTAINER_STOP`/`CONTAINER_DESTROY` → `"STOPPED"`.

## Console

### Routes

```
/files                      → FileList (existing nav item, currently disabled ComingSoon)
/files/:fileId               → FileDetailScreen (new; not a nav item, same as /processes/:processKey)
/network                     → NetworkList (existing nav item, currently disabled ComingSoon)
/network/:ip                 → NetworkDetailScreen (new)
/containers                  → ContainerList (existing nav item, currently disabled ComingSoon)
/containers/:containerId     → ContainerDetailScreen (new)
```
`Filesystem`, `Network`, `Containers` nav items already exist in `navItems.ts` at `enabled: false` — this phase flips each to `true` and swaps its `ComingSoon` route for the real list screen, identical to how Phase 7b-4 enabled `Live Events`. No nav-array reordering.

### List screens

Each mirrors `ProcessList.tsx`'s exact existing shape — own inline `<table>`, a single text filter input, loading/error/empty states, no shared table component:
- **FileList**: columns Path | Host | Last event | Timestamp. Filter by path substring. Row links to `/files/${file_id}?host_id=${host_id}` (the `host_id` query param exists solely so `FileDetailScreen` can construct its Entity Graph pivot link — the detail fetch itself never reads it).
- **NetworkList**: columns Destination (`${dst_ip}:${dst_port}`) | Proto | Host | Last event | Timestamp. Filter by destination substring. Row links to `/network/${dst_ip}`.
- **ContainerList**: columns Container ID | Image | Host | Status | Timestamp. Filter by image/container_id substring. Row links to `/containers/${container_id}`.

Each screen's data-fetching hook documents the same bounded-window caveat `ProcessList.tsx`'s own comment already carries (copied forward, not dropped).

### Detail screens

Each mirrors `ProcessDetailScreen.tsx`'s *story*-rendering half exactly — there is no separate "detail" resource endpoint for these three (unlike Process, which has both `/processes/:key` and `/processes/:key/story`; files/network/containers only ever had `*_story`). Loading/error states, then:
```
Related alerts (N)
  - one <li> per alert (rule_id + reasons), matching ProcessDetailScreen exactly
Events (N)
```
- **FileDetailScreen**: reads `fileId` from the route param, optional `host_id` from the query string (`useSearchParams`). Calls `fetchFileStory(fileId)` → `GET /files/story?file_id=${fileId}`. If `host_id` is present, renders a "View in Entity Graph" link using `FILE:${hostId}:${inode}:${deviceId}` — but since the route only carries `file_id` (`"<device_id>:<inode>"`), the link uses `FileIdentity.parse_key`'s equivalent split client-side to extract `device_id`/`inode` from `fileId`, combined with the query-string `host_id`. If `host_id` is absent (e.g., the URL was opened directly), the pivot link is omitted rather than constructing an invalid entity key.
- **NetworkDetailScreen**: reads `ip` from the route param. Calls `fetchNetworkStory({ip})` → `GET /network/story?ip=${ip}`. Renders a "View in Entity Graph" link using `IP:${ip}` (no `host_id` needed — `EntityRef::Ip` has no host component).
- **ContainerDetailScreen**: reads `containerId` from the route param. Calls `fetchContainerStory(containerId)` → `GET /containers/story?container_id=${containerId}`. Renders a "View in Entity Graph" link using `CONTAINER:${containerId}`.

All three pivot links follow `ProcessDetailScreen.tsx`'s existing exact pattern: an explicit `onClick={() => selectEntity(...)}` on the link (not relying on a mount-effect, per 7b-3's final-review fix establishing this as the correct pattern over the fragile mount-effect-timing approach it replaced).

### Data layer additions (`console/src/api/types.ts`, `client.ts`, `hooks.ts`)

New types: `FileSummary`, `NetworkSummary`, `ContainerSummary` (mirroring the Rust response shapes exactly, `snake_case` fields matching every other type in `types.ts`). New client functions: `fetchFiles()`, `fetchNetwork()`, `fetchContainers()` (list, no params — matching `fetchProcesses()`'s exact shape) and `fetchFileStory(fileId)`, `fetchNetworkStory({ip})`, `fetchContainerStory(containerId)` (each a thin `apiGet` wrapper, matching `fetchProcessStory`/`fetchSystemStory`'s existing pattern). New hooks: `useFiles()`, `useNetwork()`, `useContainers()`, `useFileStory(fileId)`, `useNetworkStory(ip)`, `useContainerStory(containerId)` — plain `useQuery` wrappers, matching every existing hook in `hooks.ts`.

## Testing

Backend: unit tests per handler covering (a) dedup keeps the most-recent event per identity, not the first, (b) events with no valid identity are skipped (Files only — Network/Containers always have their identity fields when the category matches), (c) Containers' status derivation for both RUNNING and STOPPED cases, (d) the response shape (field names/types) matches the TypeScript types above. Console: hook tests (mocking `fetch`, matching `client.test.ts`/`hooks.test.tsx`'s existing patterns) for the 6 new client functions and 6 new hooks; screen tests (mocking the hooks module, matching `ProcessList.test.tsx`/`EvidenceList.test.tsx`'s existing patterns) for loading/error/empty/populated states and the Entity Graph pivot link's presence/absence logic (specifically FileDetailScreen's `host_id`-present-vs-absent case). No Playwright/e2e — Vitest + React Testing Library only, plus one manual e2e smoke-verification task at the end, matching every prior phase's closing task.

## Out of scope (explicitly deferred, not blocking this phase)

- **Pagination/since-filtering for the three new list endpoints** — the bounded-window dedup limitation inherited from `/processes` is accepted as-is this phase, same posture `/processes` itself has taken since Phase 7b-1.
- **A storage-side rollup/distinct query method** on the `Storage` trait — would solve the above properly, but is a bigger, separate design question not needed to ship these three screens today.
- **`/processes` itself gaining `category`-based filtering or most-recent-event semantics** — this phase's two departures (category filter, most-recent) apply only to the three new endpoints. Retrofitting `/processes` to match is a separate, optional follow-up, not bundled here to keep this phase's diff scoped to net-new code.
