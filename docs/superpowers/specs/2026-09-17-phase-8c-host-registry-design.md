# Phase 8c — Host Registry (v1, read-only) — Design

**Status:** approved (autonomous execution per standing user instruction — see project memory `feedback-osiris-workflow`)
**Parent:** Phase 8 — Kubernetes/Cloud/Multi-host (`ARCHITECTURE.md` §29/§93, §21.2's "Fleet management"). This is 8c, scoped down from §21.2's literal description during brainstorming — see §1 below.
**Pre-agreed context:** `ARCHITECTURE.md` §21.1 (multi-host is claimed to be "only configuration" once Agents point at a Server), §21.2 (Fleet management: agent registry + policy distribution), §3.1 item 4 (Agent health reporting, "forwarded to the Server as `AGENT_HEALTH` events" — not actually implemented, see below), §9.2 (`HostRef` schema, already stable).

## 1. Scope — why this is narrower than §21.2's literal description

§21.2 describes Fleet Manager as: an agent registry (enrollment status, last-seen, version, health) plus policy distribution to a fleet of remote Agents, plus an API/Console surface. Investigating the current codebase before designing turned up two facts that make that literal scope premature:

1. **No real Agent↔Server network transport exists yet.** `crates/osiris-agent/src/agent.rs` writes events to a local `SpoolFileSink` (a plain file), and `osiris-server`'s `run_ingestion_loop` tails that same file path — both processes share one file on one host. §21.1's "multi-host is just configuration" describes an *architected possibility* (§8.3 names an mTLS/TCP transport option) that has never been built. There is nothing to "distribute policy" over remotely, and nothing to "enroll" — enrollment/mTLS client-cert issuance is machine-to-machine auth (§14.3) for a transport that doesn't exist.
2. **`AGENT_HEALTH`/`AGENT_START`/`AGENT_STOP`/`SENSOR_HEALTH` event types exist in the schema (`osiris-schema/src/event_type.rs`) but nothing emits them as stored events.** The Agent's real sensor-health rollup (`SensorHealth`, `crates/osiris-sensor-api`) is only exposed locally via the Agent's own status endpoint (what `osiris-cli status`/`osiris-cli sensors` read) — it never becomes a `CanonicalEvent` that reaches Storage. Confirmed independently: the Console's existing Timeline and Sensors screens both query `GET /events?event_type=SENSOR_HEALTH` for host/sensor discovery, and that query returns nothing against a real Agent today — a pre-existing, out-of-scope gap this phase does not fix, but does route around (see §2).

Building the remote transport (mTLS, enrollment, machine auth) is its own architecturally significant project, not a natural slice of "add a host list screen." This phase therefore ships the part of Fleet Management that delivers real value **today**, over data that already exists: a read-only **Host Registry** — one row per distinct `host_id` any stored event has ever carried, aggregated from the events table itself, no new event types, no new transport, no enrollment. Policy distribution and true agent enrollment become explicit Non-Goals (§6), matching the same "ship the real value now, defer what needs infrastructure that doesn't exist" reframing Phase 8b applied to the Response Engine's destructive-action dispatch.

## 2. Architecture

No new crate. One new handler in `osiris-api` (matching Phase 7b-5's `/files`, `/network`, `/containers` list-endpoint precedent in `crates/osiris-api/src/lib.rs`), reusing `osiris_query::EventQueryPlan`/`storage.query_events`.

**Why the query shape differs from the Files/Network/Containers precedent:** those three answer "every distinct entity ever seen" (an unbounded-history, category-filtered scan). A host registry answers a different question — "which hosts are part of the fleet *right now*" — where recency is the entire point, not an afterthought. An unbounded historical scan inherits this codebase's known bounded-window truncation risk (`storage.query_events` scans oldest-first up to `MAX_EVENT_LIMIT`; Phase 8b's final review flagged the same class of issue as an Important finding for `CollectEvidence`). For a registry whose value is "is this host currently alive," being time-windowed to recent activity is strictly the correct design, not a workaround:

```rust
struct HostSummary {
    host_id: String,
    hostname: String,
    distro: String,
    kernel_version: String,
    last_seen: u64,       // event.timestamp of the most recent event from this host
    status: String,       // "ONLINE" | "STALE" — see below
}

async fn hosts_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<HostsQuery>,   // { since: Option<u64>, until: Option<u64> }
) -> Result<Json<Vec<HostSummary>>, (StatusCode, String)>
```

- `since` defaults to `now_ns() - 24h` (a fleet registry cares about recent activity, not full history); `until` defaults to `u64::MAX`. Both are accepted as explicit overrides for the same reason `network_story`/`reconstruct_incident` accept `since`/`until` — an operator narrowing or widening the window is a legitimate, supported use, not a hidden implementation detail.
- Query: `EventQueryPlan { filter: None, since: Some(since), until: Some(until), limit: MAX_EVENT_LIMIT, export: true }` — no category filter, since every event (regardless of category) carries `host: HostRef`.
- Dedup: `HashMap<Uuid, HostSummary>` keyed by `host_id`, keeping the event with the greatest `timestamp` per host — same pattern `containers_handler`/`files_handler`/`network_handler` already use, mirrored exactly (see `crates/osiris-api/src/lib.rs`'s existing `containers_handler` for the reference shape).
- `status`: `"ONLINE"` if `now_ns() - last_seen <= 5 * 60 * 1_000_000_000` (5 minutes), else `"STALE"`. This is an explicit v1 heuristic — "an event arrived recently" — not a real heartbeat/liveness protocol (which would require the AGENT_HEALTH machinery §1 explains doesn't exist). Documented as a known simplification, not silently presented as more authoritative than it is.
- Response sorted by `last_seen` descending (most-recently-active fleet member first), matching the sort-order fix Phase 7b-5's final review already applied to the sibling list endpoints (nondeterministic `HashMap` iteration order must not leak into the API response).

**`cloud: Option<CloudContext>`** (also on `HostRef`) is deliberately NOT included in `HostSummary` for v1 — no sensor populates it yet (§21.4 is its own unbuilt future phase), so it would always be `null` today; adding the field now is speculative and gets added when `CloudMetadataProvider` ships, not before.

## 3. API

`GET /api/v1/hosts?since=<u64>&until=<u64>` — `min_role: Viewer` (read-only investigative data, same as `/files`/`/network`/`/containers`; no `min_role_for` change needed beyond the existing default-to-Viewer fallthrough — confirm no more-specific rule already shadows this path before merging into `main.rs`'s router, the same check every prior phase's RBAC addition has made).

No detail endpoint is added. `GET /api/v1/system/story?host_id=<uuid>&since=&until=` already exists (`crates/osiris-api/src/lib.rs`'s `system_story_handler`, built in an earlier phase) and returns the full per-host event `Story` — exactly what a "host detail" view needs. This mirrors Phase 7b-5's own precedent precisely: new List endpoints, zero new backend work for Detail because the `*_story` endpoint already existed.

## 4. Console

One new screen, `HostList` (`console/src/screens/hosts/HostList.tsx`), following the existing `ContainerList`/`FileList`/`NetworkList` shape: a table of `HostSummary` rows (hostname, distro, kernel, last seen, status badge), nav entry added alongside the existing `Sensors` route in `App.tsx`.

**Detail: reuse the existing Timeline screen, not a new screen.** `console/src/screens/timeline/Timeline.tsx` already renders a full per-host `Story` via `useSystemStory(hostId, {since, until})` — it is already, functionally, a host-detail view; it just currently has no way to arrive pre-selected. Two small, additive changes (not present in `Timeline.tsx` today):
- `Timeline` reads an optional `host` URL search param (`useSearchParams`) on mount and uses it to initialize `hostId`'s `useState` (falling back to `""`/the existing dropdown-driven flow when absent — fully backward compatible, no existing behavior changes for a plain `/timeline` visit).
- `HostList`'s row links to `` `/timeline?host=${encodeURIComponent(host.host_id)}` `` (`encodeURIComponent`, matching this codebase's uniform convention for interpolating sensor-sourced values into a URL, established as a fix in Phase 7b-5's own final review).

No `EntityRef::Host` variant is added to `osiris-schema` for this — `EntityRef`'s 7 variants are schema-frozen except when a real cross-cutting need (Entity Graph pivot, evidence targeting) requires one, per this codebase's established "schema-frozen unless genuinely needed" precedent (see Phase 4b's e2e test comment on the same subject). A plain URL query param is sufficient here and simpler than inventing a pivot mechanism for a one-screen link.

**A related, valuable, but explicitly out-of-scope observation, noted for a future follow-up:** Timeline's and Sensors' existing host-discovery dropdowns query `GET /events?event_type=SENSOR_HEALTH`, which (per §1) returns nothing against a real Agent. `GET /api/v1/hosts` would be a strictly better, already-correct source for that dropdown's options. Swapping it is a natural, cheap fast-follow — not required for this phase to be complete, and deliberately not bundled in here to keep this phase's diff focused on what it set out to build (a registry endpoint + list screen), not an unrelated pre-existing bug in a screen this phase doesn't otherwise touch.

## 5. Error handling

- No auth/role errors beyond the standard `auth_gate` 401/403 (Viewer minimum, same as every other list endpoint).
- No new error cases: an empty/never-populated events table simply yields `[]`, not an error (matches every sibling list endpoint's existing behavior for the empty case).
- Malformed `since`/`until` query params: axum's `Query` extractor already 400s cleanly for a non-numeric value, matching how `network_story_handler`/`reconstruct_incident_handler`'s query extraction behaves today — no bespoke handling needed.

## 6. Testing

- `osiris-api`: a handler-level test (calling `hosts_handler` directly, matching this codebase's established handler-unit-test convention — see `containers_handler`'s own tests) proving: (a) two events from different hosts within the window both appear, most-recently-active first; (b) an event outside the `[since, until]` window is excluded; (c) `status` is `"ONLINE"` for an event within the 5-minute threshold and `"STALE"` for one older than it — no clock-injection seam exists anywhere in this codebase (confirmed against `osiris-auth`'s session-TTL handling, which just calls `SystemTime::now()` directly), so tests compute their fixture timestamps relative to a real `SystemTime::now()` call made in the test itself (e.g. `now_ns() - 60s` for the ONLINE case, `now_ns() - 10*60s` for the STALE case) rather than inventing a new mockable-clock abstraction for this one handler; (d) the same `host_id` appearing in two events keeps only the most-recent one's `HostSummary`.
- Console: RTL tests for `HostList` (renders rows, status badge, link target includes `?host=`) matching `ContainerList.test.tsx`'s existing shape, plus a small addition to `Timeline.test.tsx` proving a `?host=` search param pre-selects that host on mount (and that its absence leaves the existing dropdown-driven behavior unchanged — a regression guard, since `Timeline.tsx` is being modified, not just extended in a new file).

## 7. Non-Goals (explicitly deferred)

- **Real Agent enrollment / machine-to-machine auth (§14.3's mTLS story).** Needs the transport this phase explicitly does not build.
- **Policy distribution to remote Agents** (telemetry-level/sensor-config push, §21.2's other named capability). Same reason.
- **Real Agent↔Server network transport** (mTLS/TCP, replacing the current same-host spool-file sharing). This is the actual prerequisite for everything §21.2 literally describes; it is its own future architectural phase, not a Fleet-Manager sub-task.
- **Emitting real `AGENT_HEALTH`/`AGENT_START`/`AGENT_STOP`/`SENSOR_HEALTH` events from the Agent's Supervisor into the pipeline.** `status`'s "ONLINE/STALE" heuristic in this phase is inferred from any event's mere presence, not a real heartbeat. Wiring the Agent to actually emit these (so `status` could reflect true health, not just "something happened recently") is a natural, separately-scoped follow-up.
- **Swapping Timeline's/Sensors' existing `SENSOR_HEALTH`-based host-discovery dropdown to use the new `/api/v1/hosts` endpoint.** Noted in §4 as a valuable, cheap fast-follow; not bundled into this phase.
- **A Console "Host Detail" screen distinct from Timeline.** §4 explains why reusing Timeline is the right v1 answer.
- **`cloud: Option<CloudContext>` in the registry response.** Add when §21.4's `CloudMetadataProvider` actually populates it; a permanently-`null` field today would be speculative.
