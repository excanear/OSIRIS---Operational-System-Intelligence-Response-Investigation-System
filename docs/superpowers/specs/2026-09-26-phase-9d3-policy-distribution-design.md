# Phase 9d-3 — Group Policy Distribution (Fleet Manager, part 3)

Status: approved in brainstorming (2026-09-26). Predecessors: 9c-1 (signed command channel), 9d-1 (fleet registry + `AGENT_HEALTH` heartbeat), 9d-2 (tenant-scoped host groups). This phase completes `ARCHITECTURE.md` §21.2's Fleet Manager: pushing telemetry-level / sensor-config changes to a group of agents instead of one at a time.

## 1. Goal

An Admin attaches a **policy** to a host group — telemetry level, per-sensor on/off, heartbeat interval — and every member agent converges on the resulting **effective policy**, live (no agent restart), including agents that were offline when the policy changed. Operators can see, per host, what is effective, why (which group set each field), and whether the agent has applied it.

## 2. Decisions (from brainstorming)

| # | Decision | Chosen |
|---|---|---|
| D1 | Policy content | Telemetry level (applied as an agent-side event-type filter), per-sensor enable/disable, heartbeat interval. §6's fine per-sensor capability matrix is deferred (needs eBPF-era sensors). |
| D2 | Delivery | Desired state + reconciliation: server stores policies; agent reports the hash of its applied policy in each heartbeat; on mismatch the server sends a signed `ApplyPolicy` over the 9c channel. |
| D3 | Multi-group conflicts | Explicit per-policy `priority`, resolved field by field. |
| D4 | Authority | Tenant Admins set policy on their tenant's groups; platform Admins on platform groups; any field set by a platform group beats every tenant group (priority only orders within a tier). |
| D5 | Agent application | Persisted overlay file, applied live; `agent.yaml` stays the base (approach A). Reconciliation keyed by content hash. |

## 3. Policy model (`osiris-policy`, new crate shared by server and agent)

### 3.1 Types

```rust
pub enum TelemetryLevel { Minimal, Standard, Detailed, Forensic }   // serde SCREAMING_SNAKE_CASE

pub struct GroupPolicy {
    pub telemetry_level: Option<TelemetryLevel>,
    pub sensors: BTreeMap<String, bool>,          // sensor name -> enabled
    pub heartbeat_interval_secs: Option<u64>,
    pub priority: i32,                            // default 0
}

pub enum PolicyTier { Platform, Tenant }

pub struct FieldSource { pub group_id: Uuid, pub tier: PolicyTier }

pub struct EffectivePolicy {
    pub telemetry_level: Option<TelemetryLevel>,
    pub sensors: BTreeMap<String, bool>,
    pub heartbeat_interval_secs: Option<u64>,
}

pub struct ResolvedPolicy {
    pub effective: EffectivePolicy,
    pub level_source: Option<FieldSource>,
    pub sensor_sources: BTreeMap<String, FieldSource>,
    pub heartbeat_source: Option<FieldSource>,
}
```

### 3.2 Validation (`GroupPolicy::validate`)

- Sensor names must be one of `KNOWN_SENSORS = ["container", "filesystem", "identity", "network", "persistence", "process_exec", "systemd"]` (the `Sensor::name()` values that exist today). Unknown → error `unknown sensor: <name>`.
- `heartbeat_interval_secs`, when set: `10..=3600`, else error `heartbeat_interval_secs must be between 10 and 3600`.
- A policy with no field set (no level, empty sensors, no heartbeat) is valid; it contributes only nothing (use DELETE to remove a policy).

### 3.3 Level → allowed event types

Cumulative. `ALWAYS_ALLOWED` = `AgentHealth`, `SensorHealth`, `AgentStart`, `AgentStop` — passed at every level, never filtered.

- **Minimal:** `ProcessExec`, `ProcessExit`, `PrivilegeUidChange`, `PrivilegeGidChange`, `PrivilegeCapabilityChange`, `PrivilegeSudo`, `PrivilegeSetuid`, `SessionLogin`, `SessionLogout`, `PersistenceCreated`, `PersistenceModified`, `PersistenceRemoved`, `ServiceCreate`, `ServiceModify`, `ServiceDelete`, `ModuleLoad`, `ModuleUnload`, `ContainerCreate`, `ContainerStart`, `ContainerStop`, `ContainerDestroy`, `LsmDenial`.
- **Standard:** Minimal + `ProcessFork`, `SessionCreate`, `SessionTerminate`, `ServiceStart`, `ServiceStop`, `TimerCreate`, `TimerModify`, `NetworkConnect`, `NetworkAccept`, `NetworkClose`, `DnsQuery`, `FileCreate`, `FileDelete`, `FileRename`, `FileMove`, `FileExecute`, `FilePermissionChange`, `FileOwnerChange`.
- **Detailed:** Standard + `FileModify`, `FileWrite`, `FileAttributeChange`, `SocketCreate`, `SocketBind`, `SocketListen`, `CapabilityUse`.
- **Forensic:** every `EventType`.

`pub fn allows(level: Option<TelemetryLevel>, t: EventType) -> bool` — `None` (no policy) allows everything (today's behavior). The implementation uses an exhaustive `match` on `EventType` (no `_ =>` arm) so a future `EventType` variant forces an explicit level decision at compile time.

### 3.4 Resolution (`resolve`, pure)

Input: the host's tenant (`Option<Uuid>`), and every `(group_id, group_tenant: Option<Uuid>, GroupPolicy)` for groups the host is a member of (raw membership — independent of any caller).

1. Discard tenant groups whose `group_tenant` ≠ the host's current tenant (stale membership after reassignment). Platform groups (`group_tenant = None`) always count.
2. Order: platform tier first, then tenant tier; within a tier by `priority` descending, then `group_id` ascending.
3. For each field independently — the level, each sensor name, the heartbeat — the value is the first definition in that order; record its `FieldSource`.

### 3.5 Hash

`policy_hash(&EffectivePolicy) -> [u8; 32]` = SHA-256 of a canonical byte encoding: tag `b"osiris-policy-v1\0"`, then level (`0` absent, `1..=4` Minimal..Forensic), then sensor count (u32 BE) and each `(name len u32 BE, name bytes, enabled u8)` in `BTreeMap` order, then heartbeat (`0u8` absent / `1u8` + u64 BE). The empty policy hashes to a fixed constant (`EMPTY_POLICY_HASH`). Hex (lowercase) is the wire form in JSON.

## 4. Server

### 4.1 Storage (`osiris-fleet`, `hosts.db` schema v2)

```sql
CREATE TABLE IF NOT EXISTS group_policies (
    group_id    TEXT PRIMARY KEY REFERENCES host_groups(group_id) ON DELETE CASCADE,
    policy_json TEXT NOT NULL,       -- GroupPolicy (priority included)
    updated_at  INTEGER NOT NULL,    -- ns, server clock
    updated_by  TEXT NOT NULL        -- user_id
);
ALTER TABLE hosts ADD COLUMN applied_policy_hash TEXT NULL;   -- hex; from heartbeat
CREATE TABLE IF NOT EXISTS host_policy_delivery (
    host_id      TEXT PRIMARY KEY REFERENCES hosts(host_id),
    desired_hash TEXT NOT NULL,
    last_sent_at INTEGER NOT NULL,   -- ns
    last_result  TEXT NOT NULL,      -- EXECUTED | REFUSED | FAILED | OFFLINE | TIMED_OUT
    last_error   TEXT NULL
);
```

- **Migration:** `SCHEMA_VERSION` becomes 2. Open: read `user_version`; >2 → `UnsupportedSchema`; run the v1 batch (idempotent) for v0/v1 files; if `< 2`, inside **one transaction**: create the two tables, `ALTER TABLE hosts ADD COLUMN applied_policy_hash` (only if the column is absent — check `pragma_table_info`), set `user_version = 2`, commit. A 9d-2 (v1) database opens with groups and members intact.
- `upsert_heartbeat` writes `applied_policy_hash` under the existing freshness gate (`WHERE excluded.last_seen >= hosts.last_seen`), same as the other mutable columns. `HostRow` gains `applied_policy_hash: Option<String>`.
- Store trait `PolicyStore` (implemented by `SqliteHostRegistry`, same connection): `get_policy(scope, group_id) -> Option<GroupPolicy>` (group must be in scope else `NotFound`), `set_policy(scope, group_id, &GroupPolicy, updated_by)`, `clear_policy(scope, group_id)`, `policies_for_host(host_id) -> Vec<(group_id, group_tenant, GroupPolicy)>` (raw, unscoped — used only by server-side resolution), `hosts_of_group_raw(group_id) -> Vec<Uuid>`, `record_delivery(host_id, desired_hash, result, error)`, `delivery(host_id) -> Option<DeliveryRow>`.

### 4.2 API (`osiris-api`)

| Method | Path | Min role | Behavior |
|---|---|---|---|
| GET | `/api/v1/groups/:group_id/policy` | Viewer | `{"policy": GroupPolicy \| null}`; group out of scope → 404 `group not found` |
| PUT | `/api/v1/groups/:group_id/policy` | Admin | body `GroupPolicy`; 400 with the validation message on invalid; 200 + stored policy; triggers reconciliation of the group's hosts |
| DELETE | `/api/v1/groups/:group_id/policy` | Admin | 204 (idempotent); triggers reconciliation |
| GET | `/api/v1/hosts/:host_id/policy` | Viewer | effective policy view (below); host not visible to caller → 404 `host not found` |

Host policy view:

```json
{ "host_id": "...",
  "effective": { "telemetry_level": "STANDARD", "sensors": {"network": false}, "heartbeat_interval_secs": 30 },
  "sources": { "telemetry_level": {"tier": "PLATFORM"},
               "sensors": {"network": {"tier": "TENANT", "group_id": "...", "group_name": "web"}},
               "heartbeat_interval_secs": {"tier": "TENANT", "group_id": "...", "group_name": "web"} },
  "desired_hash": "hex", "applied_hash": "hex|null",
  "status": "IN_SYNC|PENDING|FAILED|UNMANAGED",
  "last_delivery": { "sent_at": 0, "result": "FAILED", "error": "..." } | null }
```

- **Platform sources are opaque to tenant callers:** `{"tier": "PLATFORM"}` only — no group id or name (9d-2's rule that platform groups are invisible to tenants). Platform callers see id and name for every source.
- `status`: `UNMANAGED` if the server has no control channel configured; else `IN_SYNC` if `applied_hash == desired_hash` (a missing `applied_hash` equals `EMPTY_POLICY_HASH`); else `FAILED` if the last delivery for this `desired_hash` ended REFUSED/FAILED; else `PENDING`.
- `/api/v1/hosts` rows gain `policy_status` (same values) — computed in bulk, not one resolution query per host.
- Authorization: `min_role_for` — GET/HEAD Viewer, PUT/DELETE Admin for `/api/v1/groups/{g}/policy`; GET Viewer for `/api/v1/hosts/{h}/policy`. `tenant_route_allowed` gains exact shapes only: GET/HEAD/PUT/DELETE `/api/v1/groups/{one segment}/policy`, GET/HEAD `/api/v1/hosts/{one segment}/policy`.
- Audit: `group_policy_set` (target `group:<id>`, `why` = the canonical policy JSON), `group_policy_clear`. Success only.
- Errors: 500 bodies are exactly `internal error` (cause only logged), via the shared helper from 9d-2.

### 4.3 Reconciliation (`osiris-server`, `PolicyReconciler`)

- Holds: the fleet store (registry + groups + policies), the tenant store, `Option<Arc<dyn CommandDispatcher>>` (the 9c `HubDispatcher`; `None` when control is disabled).
- `reconcile_host(host_id)`:
  1. If no dispatcher → return (status reads `UNMANAGED`).
  2. Resolve the effective policy (host's current tenant + `policies_for_host`); compute `desired_hash`.
  3. If the host's registry `applied_hash` (missing = empty hash) equals `desired_hash` → return.
  4. If `delivery(host_id)` has the same `desired_hash` and `now - last_sent_at < 60s` → return (backoff).
  5. Dispatch `CommandAction::ApplyPolicy` with actor `policy-reconciler`, reason `effective policy <first 12 hex of hash>`, `dry_run = false`; record the outcome (`EXECUTED`/`REFUSED`/`FAILED` from `CommandResult`; `OFFLINE`/`TIMED_OUT`/`FAILED` from `DispatchError`) with `last_sent_at = now`.
- Triggers: (a) the ingest `AGENT_HEALTH` hook, after the registry upsert, per heartbeat host; (b) PUT/DELETE policy → every raw member of the group; (c) 9d-2 member add/remove on a group that has a policy → that host.
- Always spawned (`tokio::spawn`) — never on the ingest or HTTP response path; a per-host in-flight guard (`Mutex<HashSet<Uuid>>`) prevents concurrent sends to one host.

## 5. Command channel (`osiris-command`)

```rust
CommandAction::ApplyPolicy { policy: PolicyPayload }

pub struct PolicyPayload {
    pub telemetry_level: Option<TelemetryLevel>,
    pub sensors: Vec<(String, bool)>,     // sorted by name, unique
    pub heartbeat_interval_secs: Option<u64>,
    pub policy_hash: [u8; 32],
}
```

- `canonical_bytes`: action tag `4`, then the §3.5 policy encoding, then the 32 hash bytes. Every field is covered by the signature.
- `run_command` routes it to `ActionExecutor::apply_policy(&PolicyPayload, dry_run)`. Guard rules (signature, host, expiry, TTL, replay) apply unchanged; the pid/path protected-target checks do not apply.
- Agent-side validation before any effect: payload converts to `EffectivePolicy` (sorted/unique sensors, known names, heartbeat range) and `policy_hash(&effective) == payload.policy_hash`; otherwise `Failed { code: InvalidRequest, message }` and nothing is applied. (Add `FailCode::InvalidRequest` if absent.)
- `dry_run` → `DryRunOk { would_do }` describing the diff against the current applied policy.
- Existing executors/fakes gain `apply_policy`; non-agent fakes return a fixed `Executed`.

## 6. Agent (`osiris-agent`)

### 6.1 Overlay persistence

- Path: `{spool_path}.policy.json` (same convention as the replay store `{spool_path}.command_seen`).
- Content: the `EffectivePolicy` JSON. Write: temp file in the same dir → fsync → rename; mode 0600 on Unix.
- On `ApplyPolicy`: validate → persist → apply live. On startup: load the overlay **before** starting sensors and apply it (level, sensors, heartbeat). Unreadable / invalid JSON / failed validation → `tracing::error!`, ignore it, run with `agent.yaml` only, report the empty hash (the server then re-sends).

### 6.2 Live application

- **Level:** a shared `AtomicU8` (0 = no policy, 1..=4) read by a new filter stage in the agent's pipeline, after normalize and before the bus. Filtered events are dropped and counted (`events_dropped_by_policy` in self-telemetry). `ALWAYS_ALLOWED` types are never dropped.
- **Sensors:** a `SensorManager` inside `Agent` owns the running sensors and a factory built from `agent.yaml` (the same path-driven construction `Agent::start` uses today, refactored into a function keyed by sensor name). `set_enabled(name, false)` stops and drops a running sensor; `set_enabled(name, true)` constructs, initializes and starts it if `agent.yaml` configures it, else leaves it reported as unavailable (not an error). Startup constructs only sensors that are configured AND not disabled by the overlay. Shutdown drains through the manager (keep 9d-1's rule: never hold the sensors lock across a background-task await).
- **Heartbeat:** the 9d-1 heartbeat task reads its interval from a `tokio::sync::watch::Receiver<u64>`; policy updates send on the channel; `agent.yaml`'s `fleet.health_interval_secs` is the value when the policy leaves it unset.
- Result: `Executed { detail }` with a short summary ("level STANDARD; network off; heartbeat 30s").

### 6.3 Heartbeat reporting

`AGENT_HEALTH` `event_data` gains `"policy_hash": "<hex>" | null` (null = no overlay). The server ingest hook passes it to the registry upsert. A heartbeat without the field (older agent) is treated as the empty hash.

## 7. CLI

```
osiris-cli groups policy show <group_id>
osiris-cli groups policy set <group_id> [--level minimal|standard|detailed|forensic]
                                        [--sensor NAME=on|off ...] [--heartbeat SECS] [--priority N]
osiris-cli groups policy clear <group_id>
osiris-cli hosts policy <host_id>
```

`set` sends the full `GroupPolicy` (fields not given are unset — `set` replaces, it does not patch).

## 8. Console

- **Group detail → Policy section:** level select (4 levels + "Not set"), per-sensor tri-state (On / Off / Not set) for the 7 sensors, heartbeat and priority inputs; Save / Remove policy for Admins only; read-only otherwise. Saving a policy that turns any sensor off or sets the level below Standard shows an in-page confirmation ("This reduces visibility on N hosts") before the PUT. API 400 messages shown inline.
- **Hosts screen:** a Policy column with the `policy_status` badge; clicking opens the host's effective policy (field, value, source; last delivery and error).

## 9. Testing

- `osiris-policy`: level table (each level includes the previous; `ALWAYS_ALLOWED` pass at Minimal; `None` allows all); validation errors; resolution (platform beats tenant regardless of priority; priority within tier; tie by group_id; fields independent; stale tenant group ignored); hash determinism and `EMPTY_POLICY_HASH`.
- `osiris-command`: `ApplyPolicy` canonical bytes stable; altering any field (level, a sensor, heartbeat, hash) breaks verification; hash mismatch / unknown sensor / out-of-range heartbeat → `Failed` with no executor side effect.
- `osiris-fleet`: v1→v2 migration keeps groups/members and adds tables/column; v2 reopen idempotent; policy cascades with group; `applied_policy_hash` obeys the freshness gate; tenant scope on get/set/clear.
- `osiris-agent`: filter drops by level and never drops `ALWAYS_ALLOWED`; `set_enabled` stops and restarts a real sensor; overlay persisted and reloaded on restart; corrupt overlay ignored with empty hash reported; heartbeat interval change takes effect; heartbeat carries `policy_hash`.
- `osiris-api`/`osiris-server`: role + tenant matrix for the new routes (through the real gate); tenant sees platform source as opaque; reconciler sends only on mismatch, respects the 60s backoff, records outcomes, and is a no-op (`UNMANAGED`) without a dispatcher; PUT triggers reconciliation of members.
- e2e: real Agent with the control channel → platform Admin sets a group policy (Minimal + `network` off + heartbeat 10) → agent applies it, its next heartbeat reports the hash, host `status` becomes `IN_SYNC` → clear policy → returns to empty hash / `IN_SYNC`.

## 10. Review focus

1. A tenant affecting hosts outside its tenant (resolution must count only the host's current-tenant groups plus platform groups; API scope on policy routes).
2. Signature coverage: every `PolicyPayload` field in `canonical_bytes`.
3. The level filter must never drop `ALWAYS_ALLOWED` events (heartbeats drive the registry and reconciliation).
4. Reconciliation loops or storms (refusing agent, many hosts on one PUT) — backoff + in-flight guard.
5. Partial application (persisted vs live state) and startup ordering (overlay before sensors).
6. Migration v1→v2 atomicity and idempotence.

## 11. Non-Goals

- §6's per-sensor capability matrix (argv depth, hash-on-exec, env capture…).
- Entity-scoped or time-boxed levels ("FORENSIC for PID tree X for 30 min").
- Event-budget estimation before applying a policy (§22).
- Local `agent.yaml` hot-reload via inotify.
- Policy version history / rollback UI; scheduled policies.
