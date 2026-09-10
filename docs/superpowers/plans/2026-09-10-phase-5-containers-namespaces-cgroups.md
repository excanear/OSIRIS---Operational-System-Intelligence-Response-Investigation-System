# Phase 5: Containers/Namespaces/Cgroups Implementation Plan

Mirrors the task granularity/process established by phase-4b
(`2026-09-08-phase-4b-systemd-persistence.md`): each task is
write-failing-test -> run to see it fail -> implement -> run to see it pass
-> `cargo build --workspace` + `cargo test --workspace` +
`cargo clippy --workspace --all-targets -- -D warnings` -> commit.

## Global Constraints — scope decisions made for this plan

1. **Container Sensor implements the cgroup-only fallback backend fully this
   phase; the Docker/containerd/CRI-O unix-socket API primary backend is
   explicitly deferred**, tracked as a follow-up for real-Linux validation.
   This is the same pattern every prior phase's plan established for its
   hardest backend: Phase 1's Process/Exec sensor shipped audit-only (eBPF
   stubbed), Phase 4b's Persistence Monitor shipped periodic-scan-only
   (fanotify stubbed). A live Docker/containerd HTTP-over-unix-socket client
   needs `#[cfg(unix)]`-gated code this dev workstation (Windows) cannot
   build or test, so implementing it now would be unverifiable here and
   would violate this repo's "every task ends green on a real `cargo build
   --workspace`" discipline. `ARCHITECTURE.md` §4.3's fallback-first
   justification directly supports this: "every sensor... has a non-eBPF
   path from day one, even if the MVP implements only the eBPF path first."
   Read literally in reverse for Container (whose *primary* is the harder
   backend and whose *fallback* is the portable one), the fallback is what
   ships production-quality now.

2. **Namespace and Cgroup are resolution logic feeding Enrich, not
   sensors**, exactly as `ARCHITECTURE.md` §4.3's catalog rows describe
   (Namespace: "resolved at exec time, cached... no dedicated sensor";
   Cgroup: "primary backend = procfs + cgroup v2 files, fallback = cgroup
   v1 walk" — a resolution mechanism, not a lifecycle-emitting sensor like
   Systemd/Persistence). Implemented as `NsCgroupResolver` in
   `osiris-pipeline`, invoked from `enrich()` for every event that carries
   a process, populating `CanonicalEvent.namespace`/`.cgroup` and (when the
   cgroup path matches a known container-cgroup naming convention) also
   `.container` plus a `BELONGS_TO_CONTAINER` edge.

3. **cgroup v1 vs v2 both read from the single `/proc/<pid>/cgroup` file**
   (the real Linux ABI is one file either way — v2 prints one `0::<path>`
   line, v1 prints one line per controller). `CgroupVersion` is derived
   from which shape the file's lines take: exactly one line starting with
   `0::` -> `V2`; one or more colon-delimited-with-nonzero-hierarchy-id
   lines -> `V1`; anything else (missing file, unrecognized shape) ->
   `Unknown`, cgroup omitted. No `cgroup.events`/pressure-file parsing this
   phase (those carry PSI/liveness data, not identity — out of scope for
   "resolve which container/cgroup a process belongs to").

4. **`RunsInCgroup` relation (already frozen in `osiris-schema` since Phase
   0) is not emitted this phase.** `EntityRef` (frozen, Phase 0) has no
   `Cgroup` variant — only `Process | File | Ip | Domain | User | Container
   | Session` — and per this codebase's repeated precedent (Phase 3 Global
   Constraint: "no `Process -> Domain` edge: the frozen `Relation` enum has
   no fitting variant... solve it in the consuming crate or defer, never
   widen a frozen schema type for one call site"), a cgroup identity that
   already resolves to a container is represented via `BELONGS_TO_CONTAINER`
   instead. A cgroup that does **not** resolve to a recognizable container
   (a bare systemd/user slice) has no container entity to cite either, so
   emitting `RunsInCgroup` there would need a fabricated target. Deferred to
   a phase that widens `EntityRef` deliberately (Phase 6+), not silently
   worked around here.

5. **Container identity extraction is pattern-based on the cgroup path**,
   the same "no live daemon required" approach the fallback backend uses
   end-to-end. Recognized patterns (`container_id_from_cgroup_path`):
   - `.../docker-<64-hex>.scope` (dockerd via systemd cgroup driver)
   - `.../docker/<64-hex>` (dockerd via cgroupfs driver, v1)
   - `.../cri-containerd-<64-hex>.scope` (containerd via systemd driver)
   - `.../kubepods*/.../<64-hex>` (any Kubernetes pod's container, either
     driver)
   A path matching none of these yields `None` — no container context is
   attached, honestly, rather than guessed.

6. **No image/pod metadata from the fallback backend.** Per the catalog's
   own words ("cgroup-only correlation (no container metadata)"),
   `ContainerRef.image` is `""` and `ContainerRef.pod_ref` is `None` when
   derived from cgroup-path correlation alone; `ContainerRef.runtime` is
   `"cgroup"` (an honest label for "correlated via cgroup path, not queried
   from a runtime API" — parallel to `NetworkEventRaw`'s `proto: String`
   precedent of "kept as a string rather than an enum so a later backend
   extends the value set without a breaking type change").

7. **The Container Sensor's own scan-and-diff produces `CONTAINER_CREATE`/
   `START`/`STOP`/`DESTROY` lifecycle events** (one cgroup directory
   appearing under a watched container-cgroup root = Create+Start observed
   together, since a one-shot poll cannot distinguish "just created" from
   "just started" — disclosed via `event_data.observed_transition`, the
   same disclosed-ambiguity pattern Phase 4b's Global Constraint #5 used
   for `TIMER_MODIFY` standing in for a deleted timer). A directory
   disappearing = Stop+Destroy observed together, same reasoning. This is
   the honest limit of periodic polling, exactly as documented for every
   earlier phase's poller.

8. **`NsCgroupResolver`'s cache has no eviction this phase** (same MVP
   posture as `ProcessResolver`/`SessionResolver`'s existing in-memory maps
   — no bound is enforced by those either; unbounded-growth hardening is
   tracked as a pre-existing, not newly-introduced, gap).

9. **The one new detection rule mirrors the Phase 4b systemd rule's
   "actor plus artifact" shape**: a container starting inside a session
   opened from a remote address (`event_type eq CONTAINER_START` AND
   `session.remote_addr ne ""`) — MITRE T1610 (Deploy Container), reached
   the same way Phase 4b's rule reached T1543.002 over T1021.004. Neither
   half is suspicious alone (containers start constantly via CI/orchestration;
   remote sessions are ordinary) — the pairing is what's rare enough for a
   `HIGH` rule.

10. **`osiris-detect`'s `field_value`/`engine::evaluate_rule` need no
    changes.** They already walk `CanonicalEvent`'s serialized JSON by
    dotted path (confirmed by reading `crates/osiris-detect/src/eval.rs`),
    so `container.container_id`, `cgroup.cgroup_path`, etc. are usable in a
    rule's `field:` the moment `normalize`/`enrich` populate them — the
    same "for free" extensibility Phase 4b's rule already relied on for
    `session.remote_addr`.

11. **CLI**: no prior phase actually shipped a `*_story` CLI subcommand
    (confirmed by reading `crates/osiris-cli/src/main.rs` in full — only
    `status`/`health`/`events`/`processes` exist). This plan adds
    `osiris container-story <container_id>` as the CLI's first `*_story`
    subcommand, following the exact `get()`+table/json-format pattern the
    existing `events`/`processes` subcommands use, satisfying this phase's
    explicit CLI-integration requirement without inventing a pattern no
    other command follows.

## Task 1: `osiris-sensor-api` — `RawEvent::Container`

**Files:** `crates/osiris-sensor-api/src/raw_event.rs`

Add:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerOperation { Create, Start, Stop, Destroy }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEventRaw {
    pub operation: ContainerOperation,
    pub container_id: String,
    pub image: String,           // "" for cgroup-only correlation (Global Constraint #6)
    pub runtime: String,         // "cgroup" this phase (Global Constraint #6)
    pub cgroup_path: String,
    pub pid: Option<u32>,        // the container's init pid, when derivable
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}
```
Add `RawEventSource::ContainerApi` variant (parallel to schema's existing
`Source::ContainerApi`, unused by any sensor yet — this phase's fallback
sensor uses `RawEventSource::Procfs`, honestly, since it reads cgroupfs;
`ContainerApi` is added now so the deferred primary backend (Global
Constraint #1) is a value change, not a type change, when implemented).
Add `RawEvent::Container(ContainerEventRaw)` variant; extend
`RawEvent::timestamp_ns()`'s match.

Tests (in the same file's `#[cfg(test)] mod tests`): round-trip through
JSON; `timestamp_ns()` covers the new variant; a `Destroy` event round-trips
with `pid: None` (the container's process may already be reaped).

**Verify:** `cargo test -p osiris-sensor-api`, `cargo build --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`. Commit:
`feat(sensor-api): RawEvent::Container`.

## Task 2: `osiris-pipeline` — `normalize_container_event`

**Files:** `crates/osiris-pipeline/src/normalize.rs`

Add `normalize_container_event(raw: ContainerEventRaw, host, boot_id) ->
CanonicalEvent`, dispatched from `normalize()`'s match. Mirrors
`normalize_persistence_event`'s posture: no process/session identity
attached here (Enrich resolves it, since the sensor only has a pid
*candidate*, not an observed exec) — `process` stays `None` if
`raw.pid` is `None`, else a `provisional_process(raw.pid, "", ...)` exactly
like `normalize_systemd_event` does for systemd's own pid. `event_type`
maps 1:1 from `ContainerOperation` (`Create`->`ContainerCreate`, etc.),
`category: Category::Container`, `container: Some(ContainerRef { container_id,
image, runtime, pod_ref })`, `cgroup: Some(CgroupRef { cgroup_path,
cgroup_id: 0, version: CgroupVersion::Unknown })` (the sensor's scan
doesn't independently determine v1/v2 for its own emitted event — that's
`NsCgroupResolver`'s job for *other* events' per-process enrichment;
`cgroup_id: 0`/`Unknown` here is an honest "not resolved by this backend"
rather than a fabricated value — disclosed via `event_data`).
`event_data` carries `pod_name`/`pod_namespace`/`observed_transition`
(Global Constraint #7's disclosure) and `audit_serial: null` (n/a, kept out
entirely — no precedent field to null out).

Tests: one test per `ContainerOperation` variant confirming `event_type`/
`category`/`container.container_id`/`container.runtime` are set correctly;
a test confirming `process` is `None` when `raw.pid` is `None` and a
provisional process is present when it is `Some`.

**Verify + commit:** `feat(pipeline): normalize container events`.

## Task 3: `osiris-pipeline` — `NsCgroupResolver` + `container_id_from_cgroup_path`

**Files:** new `crates/osiris-pipeline/src/ns_cgroup_resolver.rs`, wired
into `crates/osiris-pipeline/src/lib.rs`'s `mod` list.

```rust
pub struct NsCgroupResolver {
    proc_root: PathBuf,
    cache: HashMap<u32, Option<(NamespaceRef, CgroupRef, Option<ContainerRef>)>>,
}
impl NsCgroupResolver {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self;
    /// Reads {proc_root}/{pid}/cgroup (and, best-effort, {proc_root}/{pid}/ns/*
    /// if present) once per pid, caches the result (Global Constraint #8),
    /// and returns it. `None` when the process directory/cgroup file isn't
    /// readable (already exited, or proc_root doesn't model this pid) —
    /// never a fabricated context.
    pub fn resolve(&mut self, pid: u32) -> Option<(NamespaceRef, CgroupRef, Option<ContainerRef>)>;
}

/// Pure parser: one cgroup v2 `0::<path>` line -> (path, V2); one or more
/// v1 `<hierarchy-id>:<controllers>:<path>` lines -> (first path, V1);
/// anything else -> None (Global Constraint #3).
pub fn parse_cgroup_file(contents: &str) -> Option<(String, CgroupVersion)>;

/// Pure parser (Global Constraint #5).
pub fn container_id_from_cgroup_path(path: &str) -> Option<String>;
```

Namespace reading: `{proc_root}/{pid}/ns/{pid,net,mnt,user,ipc,uts,cgroup}`
are real symlinks on Linux whose target is `<kind>:[<inode>]`; read via
`std::fs::read_link` when the path exists, parsed by a pure
`parse_ns_target(text: &str) -> Option<u64>` helper. When a given `ns/*`
entry is missing/unreadable, that one field defaults to `0` (an honest
"not resolved" sentinel — `NamespaceRef`'s fields are plain `u64`, not
`Option<u64>`, a frozen-schema constraint from Phase 0, so `0` is the only
non-fabricating choice available, same reasoning `PersistenceEventRaw`'s
removed-file `None` uses where the type allows `Option`).

Tests (all via `tempfile::tempdir()`-backed fake proc roots — no real
`/proc`, no real symlinks required for the cgroup-file-based tests, so
these run identically on this Windows dev workstation and on Linux CI):
- `parse_cgroup_file` unit tests: a v2 single-line file, a v1 multi-line
  file, an empty/garbage file -> `None`.
- `container_id_from_cgroup_path` unit tests: one per Global Constraint
  #5 pattern, plus a non-matching path -> `None`.
- `NsCgroupResolver::resolve` integration test: write a fake
  `{tmp}/12345/cgroup` file with a v2 docker-cgroup line, call
  `resolve(12345)`, assert the returned `CgroupRef`/`ContainerRef` are
  correct; call `resolve(12345)` again and assert the second call doesn't
  re-read the file (mutate the file between calls, assert the *cached*
  value is still returned — proves Global Constraint #8's caching).
- `resolve` returns `None` for a pid with no `{proc_root}/{pid}/cgroup`
  file at all.
- One `#[cfg(unix)]`-gated test creates a real `ns/net` symlink via
  `std::os::unix::fs::symlink` and asserts `parse_ns_target` integration
  works end-to-end on a real Linux-shaped layout (skipped at compile time
  on Windows, so it does not block this workstation's build/test/clippy
  gate — it will run on Linux CI).

**Verify + commit:** `feat(pipeline): NsCgroupResolver and cgroup-path container-id correlation`.

## Task 4: `osiris-pipeline` — wire `NsCgroupResolver` into `enrich()`

**Files:** `crates/osiris-pipeline/src/enrich.rs`, `pipeline.rs`

`Pipeline` gains an `ns_cgroup: NsCgroupResolver` field, constructed in
`Pipeline::new` with a default `proc_root` of `"/proc"`, and a
`with_proc_root(mut self, root: impl Into<PathBuf>) -> Self` builder
(mirrors `PersistenceSensor::with_poll_interval`'s pattern) so tests/e2e
can point it at a fake root without touching every existing `Pipeline::new`
call site. `enrich()` gains a `ns_cgroup: &mut NsCgroupResolver` parameter.

New `enrich_container_context(event, ns_cgroup)`: for any event carrying
`event.process` (any category — this runs for every event, not just
`Category::Container`, since the point is per-process context on
everything), calls `ns_cgroup.resolve(pid)`; if it returns `Some`, sets
`event.namespace`/`event.cgroup` (only when not already set — a
`CONTAINER_*` event from Task 2 already carries its own `cgroup`, and this
must not clobber it) and, if a `ContainerRef` was resolved and
`event.container` is still `None`, sets it and pushes a
`BELONGS_TO_CONTAINER` edge (`Process -> Container`, Global Constraint #4).

Tests: a process-exec event whose fake proc root resolves to a
docker-cgroup path gets `.namespace`/`.cgroup`/`.container` populated and
one `BELONGS_TO_CONTAINER` edge; an event whose pid resolves to no cgroup
file is untouched (no panic, no fabricated context); a `CONTAINER_START`
event's own `cgroup` from Task 2 is not overwritten by the resolver.

**Verify + commit:** `feat(pipeline): container-aware enrichment (namespace/cgroup context, BELONGS_TO_CONTAINER edges)`.

## Task 5: `osiris-sensors-container` — the cgroup-scan Container sensor

**Files:** new crate `crates/osiris-sensors/container/{Cargo.toml,src/lib.rs,src/target.rs,src/poller.rs,src/sensor.rs}`,
added to root `Cargo.toml`'s `[workspace.members]`.

`target.rs`: `ContainerCgroupRoot { pub path: String }` — one or more
directories to scan (real deployment: `/sys/fs/cgroup` and/or
`/sys/fs/cgroup/system.slice`); `candidate_container_dirs(root) ->
Vec<PathBuf>` walks one level of subdirectories under `root` (non-recursive
— container cgroups are typically one or two levels under a known slice;
kept simple and matching Persistence's "candidate_paths" scope discipline)
and filters to ones whose name is recognized by
`osiris_pipeline::container_id_from_cgroup_path` (re-exported or
duplicated as a small standalone copy — **decision: duplicate the ~15-line
pure function** rather than adding a pipeline dependency to a sensor crate,
since `osiris-pipeline` is Agent-side but *conceptually* downstream of
sensors in the data-flow direction, and Phase 4b's own `osiris-fileutil`
extraction precedent (Task 2) shows this codebase's convention for
genuinely-shared logic is a shared *leaf* crate, not a sensor depending on
the pipeline. A leaf reuse via `osiris-fileutil` is used here instead:
`container_id_from_cgroup_path` moves to `osiris-fileutil`, and both
`osiris-pipeline` and `osiris-sensors-container` depend on it — avoiding
duplication for real, not just by policy).

`poller.rs`: `ContainerCgroupPoller`, scan-and-diff exactly like
`PersistencePoller` (first tick seeds a silent baseline, Global Constraint
#7's Create+Start / Stop+Destroy pairing on subsequent ticks).

`sensor.rs`: `ContainerSensor` — same `Sensor` impl shape as
`PersistenceSensor` (`capabilities()` -> `always_available: true` iff at
least one configured root exists on disk, matching
`PersistenceSensor::any_target_exists`'s exact pattern; `initialize`
spawns a poll-loop task; health/metrics identical shape).

Tests: unit tests on the poller (tempdir-backed, one per lifecycle
transition, mirroring `PersistencePoller`'s five tests), sensor-level
tests mirroring `PersistenceSensor`'s three (`reports_unsupported_when_no_target_path_exists`,
`reports_unsupported_when_no_targets_are_configured_at_all`,
`emits_a_container_event_for_a_cgroup_dir_created_after_startup`).

**Verify + commit:** `feat(fileutil,sensors): move container_id_from_cgroup_path to osiris-fileutil; osiris-sensors-container, the cgroup-scan Container sensor`.

## Task 6: `osiris-storage` + `osiris-storage-sqlite` — `container_id` query filter

**Files:** `crates/osiris-storage/src/plan.rs`, `crates/osiris-storage-sqlite/src/sqlite_storage.rs`

Add `QueryPlan.container_id: Option<String>` (exact-match on
`container.container_id`, doc comment mirroring `unit_name`'s). SQLite:
new `container_id TEXT` column, `ALTER TABLE` migration entry (same
`("container_id", "ALTER TABLE events ADD COLUMN container_id TEXT")`
pattern as `unit_name`'s), index, insert-param, and `WHERE container_id = ?`
filter clause — identical shape to the existing `unit_name` code, same
call sites.

Tests: `query_filters_by_container_id` (mirrors
`query_filters_by_unit_name`, including the "an event with no container at
all must never match" case), plus a migration test mirroring the existing
`unit_name`-migration test (pre-Phase-5 schema -> migrated schema still
filters correctly).

**Verify + commit:** `feat(storage): container_id query filter`.

## Task 7: `osiris-agent` — config + sensor/pipeline wiring

**Files:** `crates/osiris-agent/src/config.rs`, `crates/osiris-agent/src/agent.rs`

`AgentConfig` gains (both `#[serde(default)]`, same pattern as every prior
phase's additions): `container_cgroup_roots: Vec<osiris_sensors_container::ContainerCgroupRoot>`
and `proc_root: Option<String>` (defaults to `/proc` when absent, feeding
`Pipeline::with_proc_root` — **this is also the fix for Phase 4b's own
sensors never having had an injectable proc root**, not a regression: no
earlier sensor reads `/proc` directly by pid, so this is new surface, not
a changed one).

`Agent::start`: `if !config.container_cgroup_roots.is_empty() {
candidate_sensors.push(Box::new(ContainerSensor::new(config.container_cgroup_roots.clone()))) }`
— identical shape to the `persistence_watch_paths` wiring immediately
above it. `Pipeline::new(...).with_proc_root(config.proc_root.clone().unwrap_or_else(|| "/proc".to_string()))`.

Config-loading tests mirroring `config.rs`'s existing "defaults to empty"/
"loads when configured" pairs for `persistence_watch_paths`.

**Verify + commit:** `feat(agent): wire ContainerSensor and proc_root into startup`.

## Task 8: `generator` + `osiris-agent` — the `container_deploy_in_remote_session` scenario

**Files:** `generator/src/scenarios.rs`, `crates/osiris-agent/src/agent.rs` (new `match` arm)

New `container_deploy_in_remote_session_scenario(base_ts_ns) -> Vec<RawEvent>`:
sshd exec -> login (SSH_SESSION_ID/SSH_REMOTE_ADDR, same constants Phase
4a/4b's scenarios reuse) -> bash exec -> dockerd-equivalent
`RawEvent::Container(ContainerEventRaw { operation: Create, ... })` ->
`RawEvent::Container(ContainerEventRaw { operation: Start, pid: Some(<container init pid>), ... })`
-> logout. Mirrors `persistence_via_systemd_service_scenario`'s shape
exactly (same session constants, same exec chain prefix), swapping the
systemd unit-install/start pair for a container create/start pair.
`Agent::start`'s synthetic-scenario `match` gets a
`Some("container_deploy_in_remote_session") => container_deploy_in_remote_session_scenario(base_ts)`
arm.

Tests: a scenario-shape unit test in `generator/src/scenarios.rs` (event
count, category membership, session-id/remote-addr on the login, the two
Container events' `container_id`/`operation` correctness) mirroring the
existing scenario tests' structure exactly.

**Verify + commit:** `feat(generator,agent): container_deploy_in_remote_session scenario and ContainerSensor wiring`.

## Task 9: `config/rules` — the fifth shipped detection rule

**Files:** new `config/rules/container_started_in_remote_session.yaml`

Mirrors `systemd_service_started_in_remote_session.yaml`'s exact structure
(Global Constraint #9): `event_type eq CONTAINER_START` AND
`session.remote_addr ne ""`, `severity: HIGH`, header comment documenting
the MITRE mapping (T1610, reached over T1021.004) and the null-handling
precedent it relies on.

Test: extend `crates/osiris-detect`'s existing rule-loading test (the one
that asserts `rule_count() >= N` against the real `config/rules` dir via
`load_from_dir`, per this phase's required-reading note about using
`load_from_dir` consistently — confirmed as the established pattern from
commit `63d94ed`) to assert `>= 5`, plus one focused unit test evaluating
this specific rule against a matching and a non-matching synthetic event.

**Verify + commit:** `feat(rules): ship the container-started-in-a-remote-session rule`.

## Task 10: `osiris-api` — `GET /api/v1/containers/story?container_id=…`

**Files:** `crates/osiris-api/src/lib.rs`

`ContainerStoryQuery { container_id: Option<String> }`,
`ContainerStory { events: Vec<CanonicalEvent>, alerts: Vec<Alert> }`,
`container_story_handler` — byte-for-byte the same shape as
`systemd_story_handler` (Task 10 of the Phase 4b plan), swapping
`plan.unit_name` for `plan.container_id`. Route:
`.route("/api/v1/containers/story", get(container_story_handler))`.

Tests mirroring `systemd_story_returns_400_when_unit_name_is_missing` /
`_returns_every_event_for_the_named_unit` / `_returns_an_empty_story_rather_than_404`,
adapted to `container_id`.

**Verify + commit:** `feat(api): GET /api/v1/containers/story`.

## Task 11: `osiris-cli` — `container-story` subcommand

**Files:** `crates/osiris-cli/src/main.rs`

New `Command::ContainerStory { container_id: String }` variant; a `get()`
call to `{server}/api/v1/containers/story?container_id=<id>` (percent-
encoding not needed — container ids are hex strings). Table-format falls
through to the existing "print raw JSON" branch (same as `Status`/`Health`
today — only `Events` gets bespoke table formatting; this phase does not
add a second bespoke table formatter, matching the CLI's own established
minimal-surface discipline per Global Constraint #11).

Test: a `crates/osiris-cli/src/lib.rs`-level unit test for the URL-building
helper (mirrors `events_url`'s existing test), since `main.rs`'s `main()`
itself isn't unit-testable (same pre-existing structure).

**Verify + commit:** `feat(cli): container-story subcommand`.

## Task 12: `tools/check-dep-graph.sh`

Add `check_forbidden osiris-sensors-container osiris-server osiris-api`,
matching the line already present for every other sensor crate (§27
enforcement). Run the script directly to confirm PASS.

**Verify + commit:** `chore(ci): enforce dependency boundary for osiris-sensors-container`.

## Task 13: `osiris-e2e-tests` — prove the container vertical slice end-to-end

**Files:** `crates/osiris-e2e-tests/tests/end_to_end.rs`

New `container_deploy_in_remote_session_scenario_flows_end_to_end_and_triggers_detection`,
structurally identical to Phase 4b's own e2e test (Task 11 there): start
an `Agent` with `enable_synthetic: true, synthetic_scenario:
Some("container_deploy_in_remote_session")`, run `run_ingestion_loop`
against the real `config/rules` dir (now asserting `rule_count() >= 5`),
assert on storage directly (event count/categories, the two `CONTAINER_*`
events' fields, session propagation, the new `container_id` filter), then
over real HTTP: `/api/v1/alerts` (exactly the new container rule plus
Phase 4a's escalation rule, same "no cross-firing" assertion shape),
`/api/v1/containers/story?container_id=...`, and the real CLI binary
regression check (`osiris events` still returns every event).

Additionally assert the container-aware Entity Graph: the container's
`ProcessExec`/other in-container events carry a `BELONGS_TO_CONTAINER`
edge and `event.container.container_id` matches the scenario's container
id — this is the one assertion with no Phase-4b analogue, proving Task 4's
enrichment wiring works on a real ingested dataset, not just in
`osiris-pipeline`'s own unit tests.

**Verify + commit:** `test(e2e): prove the Phase 5 container/namespace/cgroup vertical slice end-to-end`.

## Final Self-Review

Whole-branch pass (per repo convention) checking specifically for:
cross-file provenance mismatches (every place `raw_event: None`/`source`/
`provider` strings are set for `CONTAINER_*` events, consistent with every
other category's convention); plan-vs-doc-comment mismatches; missing
sensor-start coverage at the Agent level (confirm `ContainerSensor` is
actually constructed in `Agent::start`, not just defined — the exact bug
Phase 4b's own final review caught for its two sensors); the §27
dependency-boundary rule (`tools/check-dep-graph.sh` passes, and
`osiris-sensors-container`/`osiris-pipeline` never appear in
`cargo tree -p osiris-server`/`-p osiris-api`); `cargo clippy --workspace
--all-targets -- -D warnings` clean; full `cargo build --workspace` and
`cargo test --workspace` clean. Fix-wave commit(s) as needed, following
the exact `fix(...)`-prefixed commit-message convention every prior
phase's final review used.
