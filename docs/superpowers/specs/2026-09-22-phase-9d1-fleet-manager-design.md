# Phase 9d-1 — Fleet Manager: real agent registry + health heartbeat — Design

**Status:** approved (autonomous execution per standing user instruction — see project memory `feedback-osiris-workflow`)
**Parent:** `ARCHITECTURE.md` §21.2 ("Fleet management"), roadmap item 9d in `docs/ROADMAP-REMAINING.md`. This is 9d-1, scoped down from §21.2's full description during brainstorming (2026-09-22) — see §1.
**Pre-agreed context:** Phase 8c's `GET /api/v1/hosts` (design: `docs/superpowers/specs/2026-09-17-phase-8c-host-registry-design.md`) shipped a read-only heuristic explicitly flagged as a stand-in, because at the time no real transport and no `AGENT_HEALTH` events existed. Phase 9a (agent↔server mTLS transport) and Phase 9c-1 (signed command channel) have since shipped. `osiris-health`'s `AgentHealth`/`HealthAggregator` (schema for aggregated sensor health) and `EventType::AgentHealth` (in `osiris-schema`) have existed since an earlier phase but are unwired — nothing in `osiris-agent` ever constructs a `HealthAggregator` or emits an `AGENT_HEALTH` event. `osiris-agent/src/agent.rs:270` already polls every sensor's `SensorHealth` each tick (for the local `osiris-cli status`/`sensors` UDS endpoint) — the raw ingredient already exists, it just never leaves the host.

## 1. Scope — why this is narrower than §21.2's literal description

§21.2 describes Fleet Manager as: an agent registry (enrollment, last-seen, version, health) + host groups + policy distribution (telemetry level / sensor config push) + API/Console surface. That is four separable pieces. This phase (9d-1) ships only the first: **a real agent registry backed by a genuine health heartbeat**, replacing Phase 8c's "any event in the last 24h" heuristic. Host groups and policy distribution are explicit Non-Goals (§7) for a follow-up phase (9d-2/9d-3), the same way Phase 9c drew its v1 line at destructive actions over the command channel and left non-destructive uses for later.

**Why this slice first, and why it doesn't reuse the 9c-1 command channel:** the 9c-1 control channel (mTLS, persistent connection, signed commands) is opt-in — it only connects when `control` is configured on both agent and server, because it was purpose-built for destructive response actions and their heavier security posture (replay protection, per-action guards). Making fleet registry/heartbeat depend on it would silently exclude every host that hasn't opted into destructive response actions from the Fleet Manager entirely — wrong for a feature whose whole point is "which hosts are part of my fleet." Heartbeat therefore rides the same path every other sensor event already takes: the normal event pipeline, decoupled from any optional feature.

## 2. Architecture

### 2.1 Agent side — emit `AGENT_HEALTH` periodically

A new periodic task in `osiris-agent`'s `Agent::start` (alongside the existing sensor supervision loop), interval controlled by a new `fleet.health_interval` config knob (default 60s, mirroring the shape of `ControlConfig`/`CloudMetadataConfig`'s existing per-feature config sections in `crates/osiris-agent/src/config.rs`):

1. Poll every sensor's `SensorHealth` — the same call `agent.rs:270` already makes.
2. Feed each into `osiris_health::HealthAggregator::record_sensor` (constructed once, reused per tick — the aggregator already exists, this wires its first real caller) and call `.aggregate()` to get an `AgentHealth { state, sensors }`.
3. Build one `CanonicalEvent` with `event_type: EventType::AgentHealth`, `category: Category::System` (already `EventType::AgentHealth.category()`'s existing mapping), `host: HostRef { .. }` populated the same way every other event's `HostRef` is (existing `normalize.rs` logic — hostname/distro/kernel_version are already known to the agent process, no new lookup needed), and `event_data: serde_json::json!({ "agent_version": env!("CARGO_PKG_VERSION"), "health": <AgentHealth> })`. `agent_version` reuses the exact same `CARGO_PKG_VERSION` constant already sent in the 9c-1 control channel's `Hello` handshake (`crates/osiris-transport/src/control.rs:459`) — same source of truth, no drift.
4. Push it into the same pipeline every sensor event already goes through (`event_data` is the schema's documented "typed per event_type, kept untyped here deliberately" escape hatch — `crates/osiris-schema/src/envelope.rs:48-51` — so no `CanonicalEvent` field addition, no touching the ~8 existing event-construction sites `normalize.rs` already has for other fields).

No change to `HostRef` (no `agent_version` field added there) — deliberately, to avoid the same "every sensor's construction site must set a new field by hand" blast radius this project already flagged as a drift risk for `category` (Phase 7b-6) and is still watching (follow-up: `CanonicalEvent.category == event_type.category()` invariant, closed 2026-09-19). `agent_version` lives only in `AGENT_HEALTH`'s `event_data`, the one place it's actually produced.

### 2.2 Server side — a new store + an upsert hook at the one real choke point

New crate `osiris-fleet` (one-crate-per-subsystem, matching `osiris-auth`/`osiris-tenancy`/`osiris-evidence`'s existing pattern):

```rust
pub struct HostRow {
    pub host_id: Uuid,
    pub hostname: String,
    pub distro: String,
    pub kernel_version: String,
    pub agent_version: String,
    pub enrolled_at: u64,   // first AGENT_HEALTH ever seen for this host_id — never overwritten
    pub last_seen: u64,     // event.timestamp of the most recent AGENT_HEALTH
    pub health_state: osiris_health::HealthState,
}

pub trait HostRegistry: Send + Sync {
    fn upsert_heartbeat(&self, row: HostRow) -> Result<(), FleetError>;
    fn get(&self, host_id: Uuid) -> Result<Option<HostRow>, FleetError>;
    fn list(&self) -> Result<Vec<HostRow>, FleetError>;
}

pub struct SqliteHostRegistry { /* hosts.db, same per-subsystem-store pattern as incidents.db/tenants.db/users.db */ }
```

`upsert_heartbeat` is a single `INSERT ... ON CONFLICT(host_id) DO UPDATE` (matching `SqliteTenantStore::assign_host`'s existing idiom at `crates/osiris-tenancy/src/store.rs:147-148`), except `enrolled_at` is only set on the `INSERT` branch (`ON CONFLICT DO UPDATE SET ... ` simply omits `enrolled_at` from its `SET` list) — this is what gives "enrollment" real meaning: the first time a `host_id` is ever seen, not a rolling window.

**Hook point:** `IngestContext::ingest` (`crates/osiris-server/src/ingest.rs:106`) is the single method both ingestion paths — the same-host spool tailer (`run_ingestion_loop`) and the remote mTLS listener (the `handle` trait impl at `ingest.rs:190-196`) — already funnel through. `IngestContext` gains a new required field `fleet_registry: Arc<dyn HostRegistry>`. After the existing storage write, `ingest` filters the batch for `event_type == EventType::AgentHealth`, and for each one calls `fleet_registry.upsert_heartbeat(...)` built from that event's `host: HostRef` + `event_data`. This covers both ingestion paths for free, exactly the way Phase 9c-1's `LiveEventBroadcaster` hook and Phase 8f's `TenantScopedStorage` decorator each found and reused this same choke point.

Every existing call site constructing `IngestContext`/`run_ingestion_loop` (tests included) needs the new field threaded through — an accepted, known cost in this codebase (same shape as Phase 9c-1 Task 5's `ResponseState.commands` field addition, or Phase 8f's `host_ids` threading).

### 2.3 `GET /api/v1/hosts` — same path, new backing store

`HostSummary` gains `agent_version: String` and `enrolled_at: u64`. The handler stops querying `storage.query_events` entirely and instead calls `fleet_registry.list()`, filtered to the caller's tenant host set (reusing `hosts_of_tenant`/`tenant_hosts` from `crates/osiris-api/src/tenant_scope.rs:142-165` exactly as it's already used elsewhere — a `HashSet<Uuid>` intersection against the registry rows, not a new scoping mechanism).

`status` becomes a real heartbeat check instead of a truncation-prone heuristic: `"ONLINE"` if `now_ns() - last_seen <= 3 * fleet.health_interval` (tolerates up to 2 missed heartbeats before flagging stale; the multiplier is a server-side constant, not read from the agent's own configured interval, since the server has no reliable way to know what interval a given remote agent is actually configured with — see §5), else `"STALE"`. No more `"UNKNOWN"` truncation case (Phase 8c's `MAX_EVENT_LIMIT`-truncation problem) — a registry lookup by `host_id` is O(1), not a bounded scan over a growing events table.

`since`/`until` query params are dropped from this endpoint — they existed only to bound the old heuristic's scan and have no meaning against a registry table. `distro`/`kernel_version` continue to come from the same source (the event's `HostRef`), just sourced from `AGENT_HEALTH` events specifically now instead of "whichever event happened to be most recent."

## 3. Console

No new screen. `console/src/screens/hosts/HostList.tsx` (Phase 8c) gains two columns (`agent_version`, `enrolled_at` formatted as a date) and its `status` badge continues to work unchanged (the API still returns `"ONLINE"`/`"STALE"`, just computed more reliably). `types.ts`/`client.ts`/`hooks.ts` gain the two new `HostSummary` fields. The existing `since`/`until` `TimeRangeFilter` on this screen (added in the 2026-09-19 leftovers batch) is removed along with the query params it drove, since the new endpoint doesn't accept them.

## 4. Error handling

- **Registry upsert failure inside `IngestContext::ingest`:** logs `tracing::warn!` and continues — does not fail the batch or block storage of the underlying events. The fleet registry is an auxiliary, best-effort side table, never a gate on the primary telemetry path (same principle as Phase 9c-1's post-execution audit-write handling: `crates/osiris-agent/src/control.rs`'s `tracing::warn!` on a non-fatal audit failure).
- **Agent-side emission failure** (e.g. pipeline momentarily full): the periodic health task behaves like any other event producer — subject to the same bus/priority/backpressure policy already governing every sensor (§9 of `ARCHITECTURE.md`), no special-casing.
- **Malformed/missing `event_data` on an `AGENT_HEALTH` event** (should not happen from this codebase's own agent, but a hostile or buggy remote agent could send one): `upsert_heartbeat`'s caller skips that single event (logs a warning with `host_id`) rather than failing the whole batch — one bad heartbeat must not block ingestion of every other host's events in the same batch.

## 5. Known limitations, stated up front (not deferred silently)

- **`3 * fleet.health_interval` is a server-side constant, not per-agent-aware.** If an operator configures a much longer `health_interval` on one agent, that host will flap ONLINE→STALE→ONLINE relative to the server's fixed multiplier. Acceptable for v1 — a per-host configurable staleness threshold is a natural, cheap follow-up once host groups/policy distribution (9d-2+) exist to carry such a setting.
- **A host that never emits `AGENT_HEALTH` never appears in the registry**, including during the version-skew window right after this phase ships (an agent binary built before 9d-1 has no health task at all). This is accepted, not a migration this phase handles — every agent built from this phase forward emits it; an old agent binary simply needs upgrading, the same expectation every other agent-side schema/behavior change in this project's history has carried (e.g. Phase 9a's transport, Phase 9c-1's command handler).
- **e2e test fixtures that construct a fake/minimal agent must be updated to emit at least one `AGENT_HEALTH` event**, or they'll fail to appear via `/api/v1/hosts` post-migration. Flagged here so the implementation plan accounts for it, not discovered mid-Task the way Phase 7b-4's e2e call-site gap was.

## 6. Testing

- `osiris-fleet`: unit tests for `SqliteHostRegistry` — `upsert_heartbeat` twice for the same `host_id` updates `last_seen`/`health_state` but leaves `enrolled_at` unchanged from the first call; `get`/`list` round-trip; `list` on an empty store returns `[]`.
- `osiris-server`: a test on `IngestContext::ingest` (extending the existing test module in `ingest.rs`) proving a batch containing one `AGENT_HEALTH` event results in exactly one registry row with the right `agent_version`/`health_state`, and that the underlying event is still written to `Storage` unchanged (the registry side effect is additive, not a replacement of normal ingestion).
- `osiris-agent`: a test that the new periodic task, given a fixed set of sensors with known `SensorHealth` values, produces one `AGENT_HEALTH` `CanonicalEvent` per tick with the aggregated worst-state and every sensor's health present in `event_data` (matching `HealthAggregator::aggregate`'s existing, already-tested worst-state-wins logic — this test proves the *wiring*, not re-testing the aggregator itself).
- `osiris-api`: handler tests for the rewritten `hosts_handler` — ONLINE/STALE threshold at exactly `3 * health_interval`; a tenant-scoped request only sees its own hosts (extends `composed_router_tenancy.rs`'s existing pattern); response includes `agent_version`/`enrolled_at`; an empty registry returns `[]` not an error.
- Console: `HostList.test.tsx` updated for the two new columns; e2e (`osiris-e2e-tests`) scenarios that assert on `/api/v1/hosts` updated to first emit/ingest an `AGENT_HEALTH` event for the hosts they expect to see (per §5's migration note).

## 7. Non-Goals (explicitly deferred to 9d-2/9d-3)

- **Host groups** (§21.2's grouping concept) — no group model, no group-scoped anything in this phase.
- **Policy distribution** (telemetry level / sensor config push to a group of agents via the command channel) — this phase only builds the registry the distribution mechanism would eventually target; no command is added to `CommandAction`, no config-push wire format is designed.
- **A manual enrollment-approval workflow** (an agent showing as PENDING until an admin approves it). This phase's enrollment is automatic-on-first-heartbeat, trusting the mTLS certificate already issued via `osiris pki issue-agent` as the security boundary — consistent with how every other machine-to-machine trust decision in this codebase already works (the cert issuance *is* the approval step).
- **Per-host configurable staleness threshold** — noted in §5 as a natural follow-up once 9d-2/9d-3's policy distribution exists to carry it.
- **Console UI for anything beyond the two new `HostList` columns** — no new screen, no group management UI (there's nothing to manage yet).
